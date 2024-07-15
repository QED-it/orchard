//! Common gadgets and functions used in the Orchard circuit.

use ff::Field;
use halo2_gadgets::{
    ecc::{chip::EccPoint, EccInstructions, FixedPointBaseField, Point},
    poseidon::{
        primitives::{self as poseidon, ConstantLength},
        Hash as PoseidonHash, PoseidonSpongeInstructions,
    },
};
use pasta_curves::pallas;

use crate::constants::{NullifierK, OrchardFixedBases};
use crate::note::AssetBase;
use halo2_proofs::{
    circuit::Value,
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{self, Advice, Assigned, Column},
};

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

/// `DeriveNullifier` from [Section 4.16: Note Commitments and Nullifiers].
///
/// [Section 4.16: Note Commitments and Nullifiers]: https://zips.z.cash/protocol/protocol.pdf#commitmentsandnullifiers
#[allow(clippy::too_many_arguments)]
pub(in crate::circuit) fn derive_nullifier<
    PoseidonChip: PoseidonSpongeInstructions<pallas::Base, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>,
    AddChip: AddInstruction<pallas::Base>,
    EccChip: EccInstructions<
        pallas::Affine,
        FixedPoints = OrchardFixedBases,
        Point = EccPoint,
        Var = AssignedCell<pallas::Base, pallas::Base>,
    >,
>(
    layouter: &mut impl Layouter<pallas::Base>,
    poseidon_chip: PoseidonChip,
    add_chip: AddChip,
    ecc_chip: EccChip,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: &AssignedCell<pallas::Base, pallas::Base>,
    cm: &Point<pallas::Affine, EccChip>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<Point<pallas::Affine, EccChip>, plonk::Error> {
    // hash = poseidon_hash(nk, rho)
    let hash = {
        let poseidon_message = [nk, rho];
        let poseidon_hasher =
            PoseidonHash::init(poseidon_chip, layouter.namespace(|| "Poseidon init"))?;
        poseidon_hasher.hash(
            layouter.namespace(|| "Poseidon hash (nk, rho)"),
            poseidon_message,
        )?
    };

    // Add hash output to psi.
    // `scalar` = poseidon_hash(nk, rho) + psi.
    let scalar = add_chip.add(
        layouter.namespace(|| "scalar = poseidon_hash(nk, rho) + psi"),
        &hash,
        psi,
    )?;

    // Multiply scalar by NullifierK
    // `product` = [poseidon_hash(nk, rho) + psi] NullifierK.
    //
    let product = {
        let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
        nullifier_k.mul(
            layouter.namespace(|| "[poseidon_output + psi] NullifierK"),
            scalar,
        )?
    };

    // Add cm to multiplied fixed base
    // nf = cm + [poseidon_output + psi] NullifierK
    cm.add(layouter.namespace(|| "nf"), &product)
}
