use crate::primitives::sinsemilla::{K, S_PERSONALIZATION};
use halo2::{
    arithmetic::{CurveAffine, CurveExt, FieldExt},
    circuit::{Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

use ff::Field;
use group::Curve;

/// Table containing independent generators S[0..2^k]
#[derive(Clone, Debug)]
pub(super) struct GeneratorTableConfig {
    table_idx: Column<Fixed>,
    table_x: Column<Fixed>,
    table_y: Column<Fixed>,
}

pub(super) struct GeneratorTableChip<C: CurveAffine> {
    config: GeneratorTableConfig,
    marker: PhantomData<C>,
}

impl<C: CurveAffine> Chip<C::Base> for GeneratorTableChip<C> {
    type Config = GeneratorTableConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<C: CurveAffine> GeneratorTableChip<C> {
    pub fn construct(config: <Self as Chip<C::Base>>::Config) -> Self {
        Self {
            config,
            marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<C::Base>,
        q_sinsemilla: Selector,
        lookup: (Column<Fixed>, Column<Fixed>, Column<Fixed>),
        bits: Column<Advice>,
        x_a: Column<Advice>,
        x_p: Column<Advice>,
        lambda: (Column<Advice>, Column<Advice>),
    ) -> <Self as Chip<C::Base>>::Config {
        let sinsemilla_cur = meta.query_selector(q_sinsemilla, Rotation::cur());

        let table_idx_cur = meta.query_fixed(lookup.0, Rotation::cur());
        let table_x_cur = meta.query_fixed(lookup.1, Rotation::cur());
        let table_y_cur = meta.query_fixed(lookup.2, Rotation::cur());

        let bits = meta.query_advice(bits, Rotation::cur());
        let x_a_cur = meta.query_advice(x_a, Rotation::cur());
        let x_p_cur = meta.query_advice(x_p, Rotation::cur());
        let lambda1_cur = meta.query_advice(lambda.0, Rotation::cur());
        let lambda2_cur = meta.query_advice(lambda.1, Rotation::cur());
        let y_a_cur = (lambda1_cur.clone() + lambda2_cur)
            * (x_a_cur.clone()
                - (lambda1_cur.clone() * lambda1_cur.clone() - x_a_cur.clone() - x_p_cur.clone()))
            * C::Base::TWO_INV;

        // y_p = y_a - lambda1 ⋅ (x_a - x_p)
        let y_p = y_a_cur - lambda1_cur * (x_a_cur - x_p_cur.clone());

        let init_p = get_s_by_idx::<C>(0).to_affine().coordinates().unwrap();

        // Lookup expressions default to the first entry when `q_sinsemilla`
        // is not enabled.
        let m = sinsemilla_cur.clone() * bits
            + (Expression::Constant(C::Base::one()) - sinsemilla_cur.clone()) * C::Base::zero();
        let x_p = sinsemilla_cur.clone() * x_p_cur
            + (Expression::Constant(C::Base::one()) - sinsemilla_cur.clone()) * *init_p.x();
        let y_p = sinsemilla_cur.clone() * y_p
            + (Expression::Constant(C::Base::one()) - sinsemilla_cur) * *init_p.y();

        meta.lookup(&[m, x_p, y_p], &[table_idx_cur, table_x_cur, table_y_cur]);

        GeneratorTableConfig {
            table_idx: lookup.0,
            table_x: lookup.1,
            table_y: lookup.2,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<C::Base>,
    ) -> Result<<Self as Chip<C::Base>>::Loaded, Error> {
        let config = self.config();

        layouter.assign_region(
            || "generator_table",
            |mut gate| {
                // We generate the row values lazily (we only need them during keygen).
                let mut rows = config.generate::<C>();

                for index in 0..(1 << K) {
                    let mut row = None;
                    gate.assign_fixed(
                        || "table_idx",
                        config.table_idx,
                        index,
                        || {
                            row = rows.next();
                            row.map(|(idx, _, _)| idx).ok_or(Error::SynthesisError)
                        },
                    )?;
                    gate.assign_fixed(
                        || "table_x",
                        config.table_x,
                        index,
                        || row.map(|(_, x, _)| x).ok_or(Error::SynthesisError),
                    )?;
                    gate.assign_fixed(
                        || "table_y",
                        config.table_y,
                        index,
                        || row.map(|(_, _, y)| y).ok_or(Error::SynthesisError),
                    )?;
                }
                Ok(())
            },
        )
    }
}

impl GeneratorTableConfig {
    // Generates S[0..2^k] as 2^k independent, verifiably random generators of the group.
    // Loads these generators into a lookup table along with their indices.
    // Uses SWU hash-to-curve.
    fn generate<C: CurveAffine>(&self) -> impl Iterator<Item = (C::Base, C::Base, C::Base)> {
        let init = get_s_by_idx::<C>(0).to_affine().coordinates().unwrap();

        (1..=(1 << K)).scan(
            (C::Base::default(), *init.x(), *init.y()),
            move |(idx, x, y), i| {
                // We computed this table row in the previous iteration.
                let res = (*idx, *x, *y);

                // i holds the zero-indexed row number for the next table row.
                *idx = C::Base::from_u64(i as u64);

                let new = get_s_by_idx::<C>(i).to_affine().coordinates().unwrap();

                *x = *new.x();
                *y = *new.y();

                Some(res)
            },
        )
    }
}

/// Get generator S by index
pub fn get_s_by_idx<C: CurveAffine>(idx: u32) -> C::Curve {
    let hash = C::CurveExt::hash_to_curve(S_PERSONALIZATION);
    hash(&idx.to_le_bytes())
}
