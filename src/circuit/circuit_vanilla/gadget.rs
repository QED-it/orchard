//! Gadgets used in the Orchard circuit (Vanilla variation).

use pasta_curves::pallas;

use super::AddInstruction;
use crate::constants::OrchardFixedBases;
use halo2_gadgets::{
    ecc::{chip::EccPoint, EccInstructions, Point, X},
    poseidon::{
        primitives::{self as poseidon, ConstantLength},
        PoseidonSpongeInstructions,
    },
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
) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
    crate::circuit::gadget::derive_nullifier(
        layouter,
        poseidon_chip,
        add_chip,
        ecc_chip,
        rho,
        psi,
        cm,
        nk,
    )
    .map(|res| res.extract_p())
}

pub(in crate::circuit) use super::commit_ivk::gadgets::commit_ivk;
pub(in crate::circuit) use super::note_commit::gadgets::note_commit;
pub(in crate::circuit) use super::value_commit_orchard::gadgets::value_commit_orchard;
