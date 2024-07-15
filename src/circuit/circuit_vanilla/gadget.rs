//! Gadgets used in the Orchard circuit (Vanilla variation).

use pasta_curves::pallas;

use super::{add_chip, commit_ivk::CommitIvkChip, note_commit::NoteCommitChip, AddInstruction};
use crate::constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccPoint},
        EccInstructions, Point, X,
    },
    poseidon::{
        primitives::{self as poseidon, ConstantLength},
        PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
    },
    sinsemilla::{chip::SinsemillaChip, merkle::chip::MerkleChip},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk,
};

impl super::Config {
    pub(super) fn add_chip(&self) -> add_chip::AddChip {
        add_chip::AddChip::construct(self.add_config.clone())
    }

    pub(super) fn commit_ivk_chip(&self) -> CommitIvkChip {
        CommitIvkChip::construct(self.commit_ivk_config.clone())
    }

    pub(super) fn ecc_chip(&self) -> EccChip<OrchardFixedBases> {
        EccChip::construct(self.ecc_config.clone())
    }

    pub(super) fn sinsemilla_chip_1(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_1.clone())
    }

    pub(super) fn sinsemilla_chip_2(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_2.clone())
    }

    pub(super) fn merkle_chip_1(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_1.clone())
    }

    pub(super) fn merkle_chip_2(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_2.clone())
    }

    pub(super) fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }

    pub(super) fn note_commit_chip_new(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.new_note_commit_config.clone())
    }

    pub(super) fn note_commit_chip_old(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.old_note_commit_config.clone())
    }
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
