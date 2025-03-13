use alloc::vec::Vec;

use halo2_proofs::plonk;
use rand::{CryptoRng, RngCore};

use crate::{
    builder::SpendInfo,
    circuit::{Circuit, Instance, ProvingKey, Witnesses},
    domain::OrchardDomainCommon,
    note::Rho,
    orchard_flavor::OrchardFlavor,
    Note, Proof,
};

impl<D: OrchardDomainCommon> super::Bundle<D> {
    /// Adds a proof to this PCZT bundle.
    pub fn create_proof<FL: OrchardFlavor, R: RngCore + CryptoRng>(
        &mut self,
        pk: &ProvingKey,
        rng: R,
    ) -> Result<(), ProverError> {
        // If we have no actions, we don't need a proof (and if we still have no actions
        // by the time we come to transaction extraction, we will end up with a `None`
        // bundle that doesn't even hold a proof field).
        if self.actions.is_empty() {
            return Ok(());
        }

        let circuits = self
            .actions
            .iter()
            .map(|action| {
                let fvk = action
                    .spend
                    .fvk
                    .clone()
                    .ok_or(ProverError::MissingFullViewingKey)?;

                let asset = action.asset().ok_or(ProverError::MissingAsset)?;

                let note = Note::from_parts(
                    action
                        .spend
                        .recipient
                        .ok_or(ProverError::MissingRecipient)?,
                    action.spend.value.ok_or(ProverError::MissingValue)?,
                    asset,
                    action.spend.rho.ok_or(ProverError::MissingRho)?,
                    action.spend.rseed.ok_or(ProverError::MissingRandomSeed)?,
                )
                .into_option()
                .ok_or(ProverError::InvalidSpendNote)?;

                let merkle_path = action
                    .spend
                    .witness
                    .clone()
                    .ok_or(ProverError::MissingWitness)?;

                let spend = SpendInfo::new(
                    fvk,
                    note,
                    merkle_path,
                    action
                        .spend
                        .split_flag
                        .ok_or(ProverError::MissingSplitFlag)?,
                )
                .ok_or(ProverError::WrongFvkForNote)?;

                let output_note = Note::from_parts(
                    action
                        .output
                        .recipient
                        .ok_or(ProverError::MissingRecipient)?,
                    action.output.value.ok_or(ProverError::MissingValue)?,
                    asset,
                    Rho::from_nf_old(action.spend.nullifier),
                    action.output.rseed.ok_or(ProverError::MissingRandomSeed)?,
                )
                .into_option()
                .ok_or(ProverError::InvalidOutputNote)?;

                let alpha = action
                    .spend
                    .alpha
                    .ok_or(ProverError::MissingSpendAuthRandomizer)?;
                let rcv = action.rcv.ok_or(ProverError::MissingValueCommitTrapdoor)?;

                Witnesses::from_action_context(spend, output_note, alpha, rcv)
                    .ok_or(ProverError::RhoMismatch)
                    .map(|witnesses| Circuit::<FL> {
                        witnesses,
                        phantom: std::marker::PhantomData,
                    })
            })
            .collect::<Result<Vec<_>, ProverError>>()?;

        let instances = self
            .actions
            .iter()
            .map(|action| {
                Instance::from_parts(
                    self.anchor,
                    action.cv_net.clone(),
                    action.spend.nullifier,
                    action.spend.rk.clone(),
                    action.output.cmx,
                    self.flags,
                )
            })
            .collect::<Vec<_>>();

        let proof =
            Proof::create(pk, &circuits, &instances, rng).map_err(ProverError::ProofFailed)?;

        self.zkproof = Some(proof);

        Ok(())
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum ProverError {
    /// The output note's components do not produce a valid note commitment.
    InvalidOutputNote,
    /// The spent note's components do not produce a valid note commitment.
    InvalidSpendNote,
    /// The Prover role requires `fvk` to be set.
    MissingFullViewingKey,
    /// The Prover role requires all `rseed` fields to be set.
    MissingRandomSeed,
    /// The Prover role requires all `recipient` fields to be set.
    MissingRecipient,
    /// The Prover role requires `rho` to be set.
    MissingRho,
    /// The Prover role requires `alpha` to be set.
    MissingSpendAuthRandomizer,
    /// The Prover role requires all `value` fields to be set.
    MissingValue,
    /// The Prover role requires all `asset` fields to be set.
    MissingAsset,
    /// The Prover role requires `rcv` to be set.
    MissingValueCommitTrapdoor,
    /// The Prover role requires `witness` to be set.
    MissingWitness,
    /// The Prover role requires `split_flag` to be set.
    MissingSplitFlag,
    /// An error occurred while creating the proof.
    ProofFailed(plonk::Error),
    /// The `rho` of the `output_note` is not equal to the nullifier of the spent note.
    RhoMismatch,
    /// The provided `fvk` does not own the spent note.
    WrongFvkForNote,
}
