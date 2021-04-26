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

// mod add;
// mod add_complete;
// mod double;
// mod mul;
// mod mul_fixed;
// mod mul_fixed_short;
// mod util;
// mod witness_point;
// mod witness_scalar_fixed;
// mod witness_scalar_fixed_short;

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

    /// Point doubling
    pub q_double: Selector,
    /// Incomplete addition
    pub q_add: Selector,
    /// Complete addition
    pub q_add_complete: Selector,
    /// Variable-base scalar multiplication
    pub q_mul: Selector,
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
        let q_mul = meta.selector();
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

        // Set up permutations
        let perm_bits = Permutation::new(meta, &[bits.into()]);
        let perm_sum = Permutation::new(
            meta,
            &[
                P.0.into(),
                P.1.into(),
                extras[0].into(),
                extras[1].into(),
                extras[2].into(),
            ],
        );

        // TODO: Create witness point gate

        // TODO: Create witness scalar_fixed gate

        // TODO: Create witness scalar_fixed_short gate

        // TODO: Create point doubling gate

        // TODO: Create point addition gate

        // TODO: Create complete point addition gate

        // TODO: Create fixed-base full-width scalar mul gate

        // TODO: Create fixed-base short signed scalar mul gate

        // TODO: Create variable-base scalar mul gate

        EccConfig {
            bits,
            P,
            lambda,
            extras,
            lagrange_coeffs,
            fixed_z,
            q_double,
            q_add,
            q_add_complete,
            q_mul,
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

        todo!()
    }

    fn witness_scalar_fixed_short(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C::Scalar>,
    ) -> Result<Self::ScalarFixedShort, Error> {
        let config = self.config();

        todo!()
    }

    fn witness_point(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C>,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        todo!()
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

        todo!()
    }

    fn add_complete(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        todo!()
    }

    fn mul(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: C::Scalar,
        base: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        todo!()
    }

    fn mul_fixed(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: &Self::ScalarFixed,
        base: &Self::FixedPoint,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        todo!()
    }

    fn mul_fixed_short(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: &Self::ScalarFixedShort,
        base: &Self::FixedPoint,
    ) -> Result<Self::Point, Error> {
        let config = self.config();

        todo!()
    }
}
