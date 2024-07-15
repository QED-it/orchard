//! Gadgets used in the Orchard circuit (ZSA variation).

use group::Curve;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;

use super::{add_chip, commit_ivk::CommitIvkChip, note_commit::NoteCommitChip, AddInstruction};
use crate::constants::{NullifierK, OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains};
use halo2_gadgets::{
    ecc::{chip::EccChip, chip::EccPoint, EccInstructions, FixedPointBaseField, Point, X},
    poseidon::{
        primitives::{self as poseidon, ConstantLength},
        Hash as PoseidonHash, PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
    },
    sinsemilla::{chip::SinsemillaChip, merkle::chip::MerkleChip},
    utilities::{cond_swap::CondSwapChip, lookup_range_check::PallasLookupRangeCheck45BConfig},
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

    pub(super) fn ecc_chip(&self) -> EccChip<OrchardFixedBases, PallasLookupRangeCheck45BConfig> {
        EccChip::construct(self.ecc_config.clone())
    }

    pub(super) fn sinsemilla_chip_1(
        &self,
    ) -> SinsemillaChip<
        OrchardHashDomains,
        OrchardCommitDomains,
        OrchardFixedBases,
        PallasLookupRangeCheck45BConfig,
    > {
        SinsemillaChip::construct(self.sinsemilla_config_1.clone())
    }

    pub(super) fn sinsemilla_chip_2(
        &self,
    ) -> SinsemillaChip<
        OrchardHashDomains,
        OrchardCommitDomains,
        OrchardFixedBases,
        PallasLookupRangeCheck45BConfig,
    > {
        SinsemillaChip::construct(self.sinsemilla_config_2.clone())
    }

    pub(super) fn merkle_chip_1(
        &self,
    ) -> MerkleChip<
        OrchardHashDomains,
        OrchardCommitDomains,
        OrchardFixedBases,
        PallasLookupRangeCheck45BConfig,
    > {
        MerkleChip::construct(self.merkle_config_1.clone())
    }

    pub(super) fn merkle_chip_2(
        &self,
    ) -> MerkleChip<
        OrchardHashDomains,
        OrchardCommitDomains,
        OrchardFixedBases,
        PallasLookupRangeCheck45BConfig,
    > {
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

    pub(super) fn cond_swap_chip(&self) -> CondSwapChip<pallas::Base> {
        CondSwapChip::construct(self.cond_swap_config.clone())
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
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_chip: PoseidonChip,
    add_chip: AddChip,
    ecc_chip: EccChip,
    cond_swap_chip: CondSwapChip<pallas::Base>,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: &AssignedCell<pallas::Base, pallas::Base>,
    cm: &Point<pallas::Affine, EccChip>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
    split_flag: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
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
        let nullifier_k = FixedPointBaseField::from_inner(ecc_chip.clone(), NullifierK);
        nullifier_k.mul(
            layouter.namespace(|| "[poseidon_output + psi] NullifierK"),
            scalar,
        )?
    };

    // Add cm to multiplied fixed base
    // nf = cm + [poseidon_output + psi] NullifierK
    let nf = cm.add(layouter.namespace(|| "nf"), &product)?;

    // Add NullifierL to nf
    // split_note_nf = NullifierL + nf
    let nullifier_l = Point::new_from_constant(
        ecc_chip.clone(),
        layouter.namespace(|| "witness NullifierL constant"),
        pallas::Point::hash_to_curve("z.cash:Orchard")(b"L").to_affine(),
    )?;
    let split_note_nf = nullifier_l.add(layouter.namespace(|| "split_note_nf"), &nf)?;

    // Select the desired nullifier according to split_flag
    Ok(Point::from_inner(
        ecc_chip,
        cond_swap_chip.mux_on_points(
            layouter.namespace(|| "mux on nf"),
            &split_flag,
            nf.inner(),
            split_note_nf.inner(),
        )?,
    )
    .extract_p())
}

pub(in crate::circuit) use super::commit_ivk::gadgets::commit_ivk;
pub(in crate::circuit) use super::note_commit::gadgets::note_commit;
pub(in crate::circuit) use super::value_commit_orchard::gadgets::value_commit_orchard;
