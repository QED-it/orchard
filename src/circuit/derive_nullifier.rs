//! Derive nullifier logic for the Orchard circuit.

use halo2_gadgets::{
    ecc::{chip::EccPoint, EccInstructions, FixedPointBaseField, Point},
    poseidon::{
        primitives::{self as poseidon, ConstantLength},
        Hash as PoseidonHash, PoseidonSpongeInstructions,
    },
};
use pasta_curves::pallas;

use crate::{
    circuit::gadget::AddInstruction,
    constants::{NullifierK, OrchardFixedBases},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk,
};

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
