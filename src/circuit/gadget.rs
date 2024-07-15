//! Common gadgets and functions used in the Orchard circuit.

use ff::Field;
use pasta_curves::pallas;

use halo2_proofs::{
    circuit::Value,
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{self, Advice, Assigned, Column},
};

use crate::note::AssetBase;

pub(in crate::circuit) mod add_chip;

/// An instruction set for adding two circuit words (field elements).
pub(in crate::circuit) trait AddInstruction<F: Field>: Chip<F> {
    /// Constraints `a + b` and returns the sum.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, plonk::Error>;
}
/// Witnesses the given value in a standalone region.
///
/// Usages of this helper are technically superfluous, as the single-cell region is only
/// ever used in equality constraints. We could eliminate them with a
/// [write-on-copy abstraction](https://github.com/zcash/halo2/issues/334).
pub(in crate::circuit) fn assign_free_advice<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V, F>, plonk::Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(
        || "load private",
        |mut region| region.assign_advice(|| "load private", column, 0, || value),
    )
}

/// Witnesses is_native_asset.
pub(in crate::circuit) fn assign_is_native_asset<F: Field>(
    layouter: impl Layouter<F>,
    column: Column<Advice>,
    asset: Value<AssetBase>,
) -> Result<AssignedCell<pasta_curves::Fp, F>, plonk::Error>
where
    Assigned<F>: for<'v> From<&'v pasta_curves::Fp>,
{
    assign_free_advice(
        layouter,
        column,
        asset.map(|asset| {
            if bool::from(asset.is_native()) {
                pallas::Base::one()
            } else {
                pallas::Base::zero()
            }
        }),
    )
}

/// Witnesses split_flag.
pub(in crate::circuit) fn assign_split_flag<F: Field>(
    layouter: impl Layouter<F>,
    column: Column<Advice>,
    split_flag: Value<bool>,
) -> Result<AssignedCell<pasta_curves::Fp, F>, plonk::Error>
where
    Assigned<F>: for<'v> From<&'v pasta_curves::Fp>,
{
    assign_free_advice(
        layouter,
        column,
        split_flag.map(|split_flag| {
            if split_flag {
                pallas::Base::one()
            } else {
                pallas::Base::zero()
            }
        }),
    )
}
