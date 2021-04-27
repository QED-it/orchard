use std::{collections::BTreeMap, marker::PhantomData};

use super::{EccInstructions, FixedPoints};
use crate::constants::{self, FixedBase, Name};
use ff::PrimeField;
use halo2::{
    arithmetic::{CurveAffine, FieldExt},
    circuit::{Cell, Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Permutation, Selector},
    poly::Rotation,
};

mod add;
mod add_complete;
mod double;
mod mul;
mod mul_fixed;
mod mul_fixed_short;
mod util;
mod witness_point;
mod witness_scalar_fixed;
mod witness_scalar_fixed_short;

/// A structure containing a cell and its assigned value.
#[derive(Clone, Debug)]
pub struct CellValue<T> {
    /// The cell of this `CellValue`
    pub cell: Cell,
    /// The value assigned to this `CellValue`
    pub value: Option<T>,
}

impl<T> CellValue<T> {
    /// Construct a `CellValue`.
    pub fn new(cell: Cell, value: Option<T>) -> Self {
        CellValue { cell, value }
    }
}

/// A curve point represented in affine (x, y) coordinates. Each coordinate is
/// assigned to a cell.
#[derive(Clone, Debug)]
pub struct EccPoint<F: FieldExt> {
    /// x-coordinate
    pub x: CellValue<F>,
    /// y-coordinate
    pub y: CellValue<F>,
}

/// Configuration for the ECC chip
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct EccConfig {
    /// Advice column for scalar decomposition into bits
    pub bits: Column<Advice>,
    /// Holds a point (x_p, y_p)
    pub P: (Column<Advice>, Column<Advice>),
    /// A pair (lambda1, lambda2) representing gradients
    pub lambda: (Column<Advice>, Column<Advice>),
    /// Advice columns needed by instructions in the ECC chip.
    pub extras: [Column<Advice>; 5],

    /// Coefficients of interpolation polynomials for x-coordinates (used in fixed-base scalar multiplication)
    pub lagrange_coeffs: [Column<Fixed>; constants::H],
    /// Fixed z such that y + z = u^2 some square, and -y + z is a non-square. (Used in fixed-base scalar multiplication)
    pub fixed_z: Column<Fixed>,
    /// Fixed column used in scalar decomposition for variable-base scalar mul
    pub mul_decompose: Column<Fixed>,

    /// Point doubling
    pub q_double: Selector,
    /// Incomplete addition
    pub q_add: Selector,
    /// Complete addition
    pub q_add_complete: Selector,
    /// Variable-base scalar multiplication (hi half)
    pub q_mul_hi: Selector,
    /// Variable-base scalar multiplication (lo half)
    pub q_mul_lo: Selector,
    /// Variable-base scalar multiplication (final scalar)
    pub q_mul_decompose: Selector,
    /// Fixed-base full-width scalar multiplication
    pub q_mul_fixed: Selector,
    /// Fixed-base signed short scalar multiplication
    pub q_mul_fixed_short: Selector,
    /// Witness point
    pub q_point: Selector,
    /// Witness full-width scalar for fixed-base scalar mul
    pub q_scalar_fixed: Selector,
    /// Witness signed short scalar for full-width fixed-base scalar mul
    pub q_scalar_fixed_short: Selector,
    /// Copy bits of decomposed scalars
    pub perm_bits: Permutation,
    /// Copy between (x_p, y_p) and (x_a, y_a)
    pub perm_sum: Permutation,
}

/// A chip implementing EccInstructions
#[derive(Debug)]
pub struct EccChip<C: CurveAffine> {
    pub config: EccConfig,
    pub loaded: EccLoaded<C>,
    pub _marker: PhantomData<C>,
}

#[derive(Copy, Clone, Debug)]
pub enum OrchardFixedBases<C: CurveAffine> {
    CommitIvkR(constants::CommitIvkR<C>),
    NoteCommitR(constants::NoteCommitR<C>),
    NullifierK(constants::NullifierK<C>),
    ValueCommitR(constants::ValueCommitR<C>),
    ValueCommitV(constants::ValueCommitV<C>),
}

impl<C: CurveAffine> Name for OrchardFixedBases<C> {
    fn name(&self) -> &[u8] {
        match self {
            Self::CommitIvkR(base) => base.name(),
            Self::NoteCommitR(base) => base.name(),
            Self::NullifierK(base) => base.name(),
            Self::ValueCommitR(base) => base.name(),
            Self::ValueCommitV(base) => base.name(),
        }
    }
}

impl<C: CurveAffine> PartialEq for OrchardFixedBases<C> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl<C: CurveAffine> Eq for OrchardFixedBases<C> {}

impl<C: CurveAffine> PartialOrd for OrchardFixedBases<C> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.name().partial_cmp(other.name())
    }
}

impl<C: CurveAffine> Ord for OrchardFixedBases<C> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name().cmp(other.name())
    }
}

#[derive(Clone, Debug)]
/// For each Orchard fixed base, we precompute:
/// - coefficients for x-coordinate interpolation polynomials, and
/// - z-values such that y + z = u^2 some square while -y + z is non-square.
pub struct EccLoaded<C: CurveAffine> {
    lagrange_coeffs: BTreeMap<OrchardFixedBases<C>, Vec<Vec<C::Base>>>,
    lagrange_coeffs_short: BTreeMap<OrchardFixedBases<C>, Vec<Vec<C::Base>>>,
    z: BTreeMap<OrchardFixedBases<C>, [u64; constants::NUM_WINDOWS]>,
    z_short: BTreeMap<OrchardFixedBases<C>, [u64; constants::NUM_WINDOWS_SHORT]>,
    u: BTreeMap<OrchardFixedBases<C>, Vec<Vec<C::Base>>>,
    u_short: BTreeMap<OrchardFixedBases<C>, Vec<Vec<C::Base>>>,
}

impl<C: CurveAffine> EccLoaded<C> {
    fn lagrange_coeffs(&self, point: OrchardFixedBases<C>) -> Option<Vec<Vec<C::Base>>> {
        self.lagrange_coeffs.get(&point).cloned()
    }

    fn lagrange_coeffs_short(&self, point: OrchardFixedBases<C>) -> Option<Vec<Vec<C::Base>>> {
        self.lagrange_coeffs_short.get(&point).cloned()
    }

    fn z(&self, point: OrchardFixedBases<C>) -> Option<[u64; constants::NUM_WINDOWS]> {
        self.z.get(&point).cloned()
    }

    fn z_short(&self, point: OrchardFixedBases<C>) -> Option<[u64; constants::NUM_WINDOWS_SHORT]> {
        self.z_short.get(&point).cloned()
    }

    fn u(&self, point: OrchardFixedBases<C>) -> Option<Vec<Vec<C::Base>>> {
        self.u.get(&point).cloned()
    }

    fn u_short(&self, point: OrchardFixedBases<C>) -> Option<Vec<Vec<C::Base>>> {
        self.u_short.get(&point).cloned()
    }
}

impl<C: CurveAffine> FixedPoints<C> for OrchardFixedBases<C> {}

impl<C: CurveAffine> Chip<C::Base> for EccChip<C> {
    type Config = EccConfig;
    type Loaded = EccLoaded<C>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &self.loaded
    }
}

impl<C: CurveAffine> EccChip<C> {
    pub fn construct(
        config: <Self as Chip<C::Base>>::Config,
        loaded: <Self as Chip<C::Base>>::Loaded,
    ) -> Self {
        Self {
            config,
            loaded,
            _marker: PhantomData,
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<C::Base>,
        bits: Column<Advice>,
        P: (Column<Advice>, Column<Advice>),
        lambda: (Column<Advice>, Column<Advice>),
        extras: [Column<Advice>; 5],
    ) -> <Self as Chip<C::Base>>::Config {
        let q_double = meta.selector();
        let q_add = meta.selector();
        let q_add_complete = meta.selector();
        let q_mul_hi = meta.selector();
        let q_mul_lo = meta.selector();
        let q_mul_decompose = meta.selector();
        let q_mul_fixed = meta.selector();
        let q_mul_fixed_short = meta.selector();
        let q_point = meta.selector();
        let q_scalar_fixed = meta.selector();
        let q_scalar_fixed_short = meta.selector();

        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let fixed_z = meta.fixed_column();
        let mul_decompose = meta.fixed_column();

        // Set up permutations
        let perm_bits = Permutation::new(meta, &[bits.into()]);
        let perm_sum = Permutation::new(
            meta,
            &[
                P.0.into(),
                P.1.into(),
                bits.into(),
                extras[0].into(),
                extras[1].into(),
                extras[2].into(),
            ],
        );
        // Create witness point gate
        {
            let q_point = meta.query_selector(q_point, Rotation::cur());
            let P = (
                meta.query_advice(P.0, Rotation::cur()),
                meta.query_advice(P.1, Rotation::cur()),
            );
            witness_point::create_gate::<C>(meta, q_point, P.0, P.1);
        }

        // Create witness scalar_fixed gate
        {
            let q_scalar_fixed = meta.query_selector(q_scalar_fixed, Rotation::cur());
            let k = meta.query_advice(bits, Rotation::cur());
            witness_scalar_fixed::create_gate(meta, q_scalar_fixed, k);
        }

        // Create witness scalar_fixed_short gate
        {
            let q_scalar_fixed_short = meta.query_selector(q_scalar_fixed_short, Rotation::cur());
            let k = meta.query_advice(bits, Rotation::cur());
            witness_scalar_fixed_short::create_gate(meta, q_scalar_fixed_short, k);
        }

        // Create point doubling gate
        {
            let q_double = meta.query_selector(q_double, Rotation::cur());
            let x_a = meta.query_advice(extras[0], Rotation::cur());
            let y_a = meta.query_advice(extras[1], Rotation::cur());
            let x_p = meta.query_advice(P.0, Rotation::cur());
            let y_p = meta.query_advice(P.1, Rotation::cur());

            double::create_gate(meta, q_double, x_a, y_a, x_p, y_p);
        }

        // Create point addition gate
        {
            let q_add = meta.query_selector(q_add, Rotation::cur());
            let x_p = meta.query_advice(P.0, Rotation::cur());
            let y_p = meta.query_advice(P.1, Rotation::cur());
            let x_q = meta.query_advice(extras[0], Rotation::cur());
            let y_q = meta.query_advice(extras[1], Rotation::cur());
            let x_a = meta.query_advice(extras[0], Rotation::next());
            let y_a = meta.query_advice(extras[1], Rotation::next());

            add::create_gate(meta, q_add, x_p, y_p, x_q, y_q, x_a, y_a);
        }

        // Create complete point addition gate
        {
            let q_add_complete = meta.query_selector(q_add_complete, Rotation::cur());
            let x_p = meta.query_advice(P.0, Rotation::cur());
            let y_p = meta.query_advice(P.1, Rotation::cur());
            let x_q = meta.query_advice(extras[0], Rotation::cur());
            let y_q = meta.query_advice(extras[1], Rotation::cur());
            let x_r = meta.query_advice(extras[0], Rotation::next());
            let y_r = meta.query_advice(extras[1], Rotation::next());
            let lambda_cur = meta.query_advice(lambda.0, Rotation::cur());

            let a = meta.query_advice(extras[2], Rotation::cur());
            let b = meta.query_advice(extras[3], Rotation::cur());
            let c = meta.query_advice(extras[4], Rotation::cur());
            let d = meta.query_advice(lambda.1, Rotation::cur());

            // \alpha = (x_q - x_p)^{-1}
            let alpha = meta.query_advice(extras[2], Rotation::next());
            // \beta = x_p^{-1}
            let beta = meta.query_advice(extras[3], Rotation::next());
            // \gamma = x_q^{-1}
            let gamma = meta.query_advice(extras[4], Rotation::next());
            // \delta = (y_p + y_q)^{-1}
            let delta = meta.query_advice(lambda.1, Rotation::next());

            add_complete::create_gate(
                meta,
                q_add_complete,
                a,
                b,
                c,
                d,
                alpha,
                beta,
                gamma,
                delta,
                lambda_cur,
                x_p,
                y_p,
                x_q,
                y_q,
                x_r,
                y_r,
            );
        }

        // Create fixed-base full-width scalar mul gate
        {
            let q_mul_fixed = meta.query_selector(q_mul_fixed, Rotation::cur());
            let x_p = meta.query_advice(P.0, Rotation::cur());
            let y_p = meta.query_advice(P.1, Rotation::cur());
            let k = meta.query_advice(bits, Rotation::cur());
            let u = meta.query_advice(extras[2], Rotation::cur());
            let z = meta.query_fixed(fixed_z, Rotation::cur());

            mul_fixed::create_gate(meta, lagrange_coeffs, q_mul_fixed, x_p, y_p, k, u, z);
        }

        // Create fixed-base short signed scalar mul gate
        {
            let q_mul_fixed_short = meta.query_selector(q_mul_fixed_short, Rotation::cur());
            let s = meta.query_advice(bits, Rotation::cur());
            let y_a = meta.query_advice(extras[1], Rotation::cur());
            let y_p = meta.query_advice(P.1, Rotation::cur());

            mul_fixed_short::create_gate(meta, q_mul_fixed_short, s, y_a, y_p);
        }

        // Create variable-base scalar mul gate (hi half)
        {
            let q_mul = meta.query_selector(q_mul_hi, Rotation::cur());

            let z_cur = meta.query_advice(bits, Rotation::cur());
            let z_prev = meta.query_advice(bits, Rotation::prev());
            let x_a_cur = meta.query_advice(extras[0], Rotation::cur());
            let x_a_next = meta.query_advice(extras[0], Rotation::next());
            let x_p_cur = meta.query_advice(P.0, Rotation::cur());
            let x_p_next = meta.query_advice(P.0, Rotation::next());
            let y_p_cur = meta.query_advice(P.1, Rotation::cur());
            let y_p_next = meta.query_advice(P.1, Rotation::next());
            let lambda1_cur = meta.query_advice(lambda.0, Rotation::cur());
            let lambda2_cur = meta.query_advice(lambda.1, Rotation::cur());
            let lambda1_next = meta.query_advice(lambda.0, Rotation::next());
            let lambda2_next = meta.query_advice(lambda.1, Rotation::next());

            mul::create_gate(
                meta,
                q_mul,
                z_cur,
                z_prev,
                x_a_cur,
                x_a_next,
                x_p_cur,
                x_p_next,
                y_p_cur,
                y_p_next,
                lambda1_cur,
                lambda2_cur,
                lambda1_next,
                lambda2_next,
            )
        }

        // Create variable-base scalar mul gate (lo half)
        {
            let q_mul = meta.query_selector(q_mul_lo, Rotation::cur());

            let z_cur = meta.query_advice(extras[1], Rotation::cur());
            let z_prev = meta.query_advice(extras[1], Rotation::prev());
            let x_a_cur = meta.query_advice(extras[2], Rotation::cur());
            let x_a_next = meta.query_advice(extras[2], Rotation::next());
            let x_p_cur = meta.query_advice(P.0, Rotation::cur());
            let x_p_next = meta.query_advice(P.0, Rotation::next());
            let y_p_cur = meta.query_advice(P.1, Rotation::cur());
            let y_p_next = meta.query_advice(P.1, Rotation::next());
            let lambda1_cur = meta.query_advice(extras[3], Rotation::cur());
            let lambda2_cur = meta.query_advice(extras[4], Rotation::cur());
            let lambda1_next = meta.query_advice(extras[3], Rotation::next());
            let lambda2_next = meta.query_advice(extras[4], Rotation::next());

            mul::create_gate(
                meta,
                q_mul,
                z_cur,
                z_prev,
                x_a_cur,
                x_a_next,
                x_p_cur,
                x_p_next,
                y_p_cur,
                y_p_next,
                lambda1_cur,
                lambda2_cur,
                lambda1_next,
                lambda2_next,
            )
        }

        // Create scalar decomposition gate for complete addition part of variable-base scalar mul
        {
            let q_mul_decompose = meta.query_selector(q_mul_decompose, Rotation::cur());
            let z_cur = meta.query_advice(bits, Rotation::cur());
            let z_prev = meta.query_advice(bits, Rotation::prev());

            mul::create_decompose_gate(meta, q_mul_decompose, z_cur, z_prev)
        }

        // Create final scalar check gate for variable-base scalar mul
        {
            let mul_decompose = meta.query_fixed(mul_decompose, Rotation::cur());
            let z_cur = meta.query_advice(bits, Rotation::cur());

            mul::create_final_scalar_gate::<C>(meta, mul_decompose, z_cur)
        }

        EccConfig {
            bits,
            P,
            lambda,
            extras,
            lagrange_coeffs,
            mul_decompose,
            fixed_z,
            q_double,
            q_add,
            q_add_complete,
            q_mul_hi,
            q_mul_lo,
            q_mul_decompose,
            q_mul_fixed,
            q_mul_fixed_short,
            q_point,
            q_scalar_fixed,
            q_scalar_fixed_short,
            perm_bits,
            perm_sum,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn load() -> <Self as Chip<C::Base>>::Loaded {
        let mut lagrange_coeffs = BTreeMap::<OrchardFixedBases<C>, Vec<Vec<C::Base>>>::new();
        let mut lagrange_coeffs_short = BTreeMap::<OrchardFixedBases<C>, Vec<Vec<C::Base>>>::new();
        let mut z = BTreeMap::<OrchardFixedBases<C>, [u64; constants::NUM_WINDOWS]>::new();
        let mut z_short =
            BTreeMap::<OrchardFixedBases<C>, [u64; constants::NUM_WINDOWS_SHORT]>::new();
        let mut u = BTreeMap::<OrchardFixedBases<C>, Vec<Vec<C::Base>>>::new();
        let mut u_short = BTreeMap::<OrchardFixedBases<C>, Vec<Vec<C::Base>>>::new();

        let bases: [(
            OrchardFixedBases<C>,
            [u64; constants::NUM_WINDOWS],
            [[[u8; 32]; constants::H]; constants::NUM_WINDOWS],
        ); 5] = [
            (
                OrchardFixedBases::CommitIvkR(constants::commit_ivk_r::generator()),
                constants::commit_ivk_r::Z,
                constants::commit_ivk_r::U,
            ),
            (
                OrchardFixedBases::NoteCommitR(constants::note_commit_r::generator()),
                constants::note_commit_r::Z,
                constants::note_commit_r::U,
            ),
            (
                OrchardFixedBases::NullifierK(constants::nullifier_k::generator()),
                constants::nullifier_k::Z,
                constants::nullifier_k::U,
            ),
            (
                OrchardFixedBases::ValueCommitR(constants::value_commit_r::generator()),
                constants::value_commit_r::Z,
                constants::value_commit_r::U,
            ),
            (
                OrchardFixedBases::ValueCommitV(constants::value_commit_v::generator()),
                constants::value_commit_v::Z,
                constants::value_commit_v::U,
            ),
        ];

        for base in bases.iter() {
            let inner = match base.0 {
                OrchardFixedBases::CommitIvkR(inner) => inner.0,
                OrchardFixedBases::NoteCommitR(inner) => inner.0,
                OrchardFixedBases::NullifierK(inner) => inner.0,
                OrchardFixedBases::ValueCommitR(inner) => inner.0,
                OrchardFixedBases::ValueCommitV(inner) => inner.0,
            };
            lagrange_coeffs.insert(
                base.0,
                inner
                    .compute_lagrange_coeffs(constants::NUM_WINDOWS)
                    .iter()
                    .map(|window| window.to_vec())
                    .collect(),
            );
            z.insert(base.0, base.1);
            u.insert(
                base.0,
                base.2
                    .iter()
                    .map(|window_us| {
                        window_us
                            .iter()
                            .map(|u| C::Base::from_bytes(&u).unwrap())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            );
        }

        // We use fixed-base scalar multiplication with signed short exponent
        // for `ValueCommitV`.
        {
            let inner = constants::value_commit_v::generator();
            let value_commit_v = OrchardFixedBases::ValueCommitV(inner);

            lagrange_coeffs_short.insert(
                value_commit_v,
                inner
                    .0
                    .compute_lagrange_coeffs(constants::NUM_WINDOWS_SHORT)
                    .iter()
                    .map(|window| window.to_vec())
                    .collect(),
            );
            z_short.insert(value_commit_v, constants::value_commit_v::Z_SHORT);
            u_short.insert(
                value_commit_v,
                constants::value_commit_v::U_SHORT
                    .iter()
                    .map(|window_us| {
                        window_us
                            .iter()
                            .map(|u| C::Base::from_bytes(&u).unwrap())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            );
        }

        EccLoaded {
            lagrange_coeffs,
            lagrange_coeffs_short,
            z,
            z_short,
            u,
            u_short,
        }
    }
}

/// A full-width scalar used for variable-base scalar multiplication.
/// This is decomposed in chunks of `window_width` bits in little-endian order.
/// For example, if `window_width` = 3, we will have [k_0, k_1, ..., k_n]
/// where `scalar = k_0 + k_1 * (2^3) + ... + k_n * (2^3)^n`.
#[derive(Clone, Debug)]
pub struct EccScalarFixed<C: CurveAffine> {
    value: Option<C::Scalar>,
    k_bits: Vec<CellValue<C::Base>>,
}

/// A signed short scalar used for variable-base scalar multiplication.
/// This is decomposed in chunks of `window_width` bits in little-endian order.
/// For example, if `window_width` = 3, we will have [k_0, k_1, ..., k_n]
/// where `scalar = k_0 + k_1 * (2^3) + ... + k_n * (2^3)^n`.
#[derive(Clone, Debug)]
pub struct EccScalarFixedShort<C: CurveAffine> {
    magnitude: Option<C::Scalar>,
    sign: CellValue<C::Base>,
    k_bits: Vec<CellValue<C::Base>>,
}

/// A fixed point representing one of the Orchard fixed bases. Contains:
/// - coefficients for x-coordinate interpolation polynomials, and
/// - z-values such that y + z = u^2 some square while -y + z is non-square.
#[derive(Clone, Debug)]
pub struct EccFixedPoint<C: CurveAffine> {
    fixed_point: OrchardFixedBases<C>,
    lagrange_coeffs: Option<Vec<Vec<C::Base>>>,
    lagrange_coeffs_short: Option<Vec<Vec<C::Base>>>,
    z: Option<[u64; constants::NUM_WINDOWS]>,
    z_short: Option<[u64; constants::NUM_WINDOWS_SHORT]>,
    u: Option<Vec<Vec<C::Base>>>,
    u_short: Option<Vec<Vec<C::Base>>>,
}

impl<C: CurveAffine> EccInstructions<C> for EccChip<C> {
    type ScalarFixed = EccScalarFixed<C>;
    type ScalarFixedShort = EccScalarFixedShort<C>;
    type Point = EccPoint<C::Base>;
    type X = CellValue<C::Base>;
    type FixedPoint = EccFixedPoint<C>;
    type FixedPoints = OrchardFixedBases<C>;

    fn witness_scalar_fixed(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C::Scalar>,
    ) -> Result<Self::ScalarFixed, Error> {
        let config = self.config();

        let scalar = layouter.assign_region(
            || "witness scalar for fixed-base mul",
            |mut region| {
                witness_scalar_fixed::assign_region(
                    value,
                    C::Scalar::NUM_BITS as usize,
                    0,
                    &mut region,
                    config.clone(),
                )
            },
        )?;

        Ok(scalar)
    }

    fn witness_scalar_fixed_short(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C::Scalar>,
    ) -> Result<Self::ScalarFixedShort, Error> {
        let config = self.config();

        let scalar = layouter.assign_region(
            || "witness scalar for fixed-base mul",
            |mut region| {
                witness_scalar_fixed_short::assign_region(value, 0, &mut region, config.clone())
            },
        )?;

        Ok(scalar)
    }

    fn witness_point(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C>,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        let point = layouter.assign_region(
            || "witness point",
            |mut region| witness_point::assign_region(value, 0, &mut region, config.clone()),
        )?;

        Ok(point)
    }

    fn extract_p(point: &Self::Point) -> &Self::X {
        &point.x
    }

    fn get_fixed(&self, fixed_point: Self::FixedPoints) -> Result<Self::FixedPoint, Error> {
        let loaded = self.loaded();

        let lagrange_coeffs = loaded.lagrange_coeffs(fixed_point);
        let lagrange_coeffs_short = loaded.lagrange_coeffs_short(fixed_point);
        let z = loaded.z(fixed_point);
        let z_short = loaded.z_short(fixed_point);
        let u = loaded.u(fixed_point);
        let u_short = loaded.u_short(fixed_point);

        Ok(EccFixedPoint {
            fixed_point,
            lagrange_coeffs,
            lagrange_coeffs_short,
            z,
            z_short,
            u,
            u_short,
        })
    }

    fn add(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        let point = layouter.assign_region(
            || "point addition",
            |mut region| add::assign_region::<C>(a, b, 0, &mut region, config.clone()),
        )?;

        Ok(point)
    }

    fn add_complete(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        let point = layouter.assign_region(
            || "point addition",
            |mut region| add_complete::assign_region::<C>(a, b, 0, &mut region, config.clone()),
        )?;

        Ok(point)
    }

    fn mul(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: C::Scalar,
        base: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        let point = layouter.assign_region(
            || "variable-base mul",
            |mut region| mul::assign_region::<C>(scalar, base, 0, &mut region, config.clone()),
        )?;

        Ok(point)
    }

    fn mul_fixed(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: &Self::ScalarFixed,
        base: &Self::FixedPoint,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        let point = layouter.assign_region(
            || format!("Multiply {:?}", base.fixed_point),
            |mut region| {
                mul_fixed::assign_region::<C>(scalar, base, 0, &mut region, config.clone())
            },
        )?;

        Ok(point)
    }

    fn mul_fixed_short(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: &Self::ScalarFixedShort,
        base: &Self::FixedPoint,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        let point = layouter.assign_region(
            || format!("Multiply {:?}", base.fixed_point),
            |mut region| {
                mul_fixed_short::assign_region::<C>(scalar, base, 0, &mut region, config.clone())
            },
        )?;

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use crate::constants;
    use group::{Curve, Group};
    use halo2::{
        arithmetic::{CurveAffine, FieldExt},
        circuit::layouter::SingleChipLayouter,
        dev::MockProver,
        pasta::pallas,
        plonk::{Assignment, Circuit, ConstraintSystem, Error},
    };

    use super::super::EccInstructions;
    use super::{EccChip, EccConfig, OrchardFixedBases};

    struct MyCircuit<C: CurveAffine> {
        _marker: std::marker::PhantomData<C>,
    }

    #[allow(non_snake_case)]
    impl<C: CurveAffine> Circuit<C::Base> for MyCircuit<C> {
        type Config = EccConfig;

        fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
            let bits = meta.advice_column();
            let P = (meta.advice_column(), meta.advice_column());
            let lambda = (meta.advice_column(), meta.advice_column());
            let extras = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            EccChip::<C>::configure(meta, bits, P, lambda, extras)
        }

        fn synthesize(
            &self,
            cs: &mut impl Assignment<C::Base>,
            config: Self::Config,
        ) -> Result<(), Error> {
            let loaded = EccChip::<C>::load();
            let chip = EccChip::construct(config, loaded);
            let mut layouter = SingleChipLayouter::new(cs)?;

            // Generate a random point
            let point_val = C::CurveExt::random(rand::rngs::OsRng).to_affine(); // P
            let point = chip.witness_point(&mut layouter, Some(point_val))?;

            // Check doubled point [2]P
            let real_doubled = point_val * C::Scalar::from_u64(2); // [2]P
            let doubled = chip.add(&mut layouter, &point, &point)?;
            if let (Some(x), Some(y)) = (doubled.x.value, doubled.y.value) {
                assert_eq!(real_doubled.to_affine(), C::from_xy(x, y).unwrap());
            }

            let real_added = point_val * C::Scalar::from_u64(3); // [3]P

            // Check incomplete addition point [3]P
            {
                let added = chip.add(&mut layouter, &point, &doubled)?;
                if let (Some(x), Some(y)) = (added.x.value, added.y.value) {
                    assert_eq!(real_added.to_affine(), C::from_xy(x, y).unwrap());
                }
            }

            // Check complete addition point [3]P
            {
                let added_complete = chip.add_complete(&mut layouter, &point, &doubled)?;
                if let (Some(x), Some(y)) = (added_complete.x.value, added_complete.y.value) {
                    if C::from_xy(x, y).is_some().into() {
                        assert_eq!(real_added.to_affine(), C::from_xy(x, y).unwrap());
                    }
                }
            }

            // Check fixed-base scalar multiplication
            {
                let scalar_fixed = C::Scalar::rand();
                let nullifier_k = constants::nullifier_k::generator();
                let base = nullifier_k.0.value();
                let real_mul_fixed = base * scalar_fixed;

                let scalar_fixed = chip.witness_scalar_fixed(&mut layouter, Some(scalar_fixed))?;
                let nullifier_k = chip.get_fixed(OrchardFixedBases::NullifierK(nullifier_k))?;
                let mul_fixed = chip.mul_fixed(&mut layouter, &scalar_fixed, &nullifier_k)?;
                if let (Some(x), Some(y)) = (mul_fixed.x.value, mul_fixed.y.value) {
                    assert_eq!(real_mul_fixed.to_affine(), C::from_xy(x, y).unwrap());
                }
            }

            // Check short signed fixed-base scalar multiplication
            {
                let scalar_fixed_short = C::Scalar::from_u64(rand::random::<u64>());
                let value_commit_v = constants::value_commit_v::generator();
                let real_mul_fixed_short = value_commit_v.0.value() * scalar_fixed_short;

                let scalar_fixed_short =
                    chip.witness_scalar_fixed_short(&mut layouter, Some(scalar_fixed_short))?;
                let value_commit_v =
                    chip.get_fixed(OrchardFixedBases::ValueCommitV(value_commit_v))?;
                let mul_fixed_short =
                    chip.mul_fixed_short(&mut layouter, &scalar_fixed_short, &value_commit_v)?;
                if let (Some(x), Some(y)) = (mul_fixed_short.x.value, mul_fixed_short.y.value) {
                    assert_eq!(real_mul_fixed_short.to_affine(), C::from_xy(x, y).unwrap());
                }
            }

            // Check variable-base scalar multiplication
            {
                let scalar_val = C::Scalar::rand();
                let real_mul = point_val * scalar_val;

                let mul = chip.mul(&mut layouter, scalar_val, &point)?;
                if let (Some(x), Some(y)) = (mul.x.value, mul.y.value) {
                    assert_eq!(real_mul.to_affine(), C::from_xy(x, y).unwrap());
                }
            }

            Ok(())
        }
    }

    #[test]
    fn ecc() {
        let k = 11;
        let circuit = MyCircuit::<pallas::Affine> {
            _marker: std::marker::PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}
