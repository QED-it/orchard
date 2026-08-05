//! The Orchard Action circuit implementation.
//!
//! This module defines the common structures, traits and implementations for the
//! Orchard Action circuit, supporting both the standard ("Vanilla") and ZSA variations.

use alloc::vec::Vec;

use group::{Curve, GroupEncoding};
use halo2_proofs::{
    plonk::{
        self, Advice, BatchVerifier, Column, Instance as InstanceColumn, Selector, SingleVerifier,
    },
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{arithmetic::CurveAffine, pallas, vesta};
use rand::RngCore;

use crate::{
    builder::SpendInfo,
    bundle::Flags,
    circuit::{
        commit_ivk::CommitIvkConfig, gadget::add_chip::AddConfig, note_commit::NoteCommitConfig,
    },
    circuit_version::OrchardCircuitVersion,
    constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains},
    note::{nullifier::Nullifier, ExtractedNoteCommitment, Note, Rho},
    primitives::redpallas::{SpendAuth, VerificationKey},
    tree::Anchor,
    value::{ValueCommitTrapdoor, ValueCommitment},
};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        CircuitVersion, NonIdentityPoint,
    },
    poseidon::Pow5Config as PoseidonConfig,
    sinsemilla::{chip::SinsemillaConfig, merkle::chip::MerkleConfig},
    utilities::lookup_range_check::PallasLookupRangeCheck,
};

mod circuit_vanilla;
mod circuit_zsa;

use circuit_vanilla::CircuitVanilla;
use circuit_zsa::CircuitZsa;

#[cfg(not(feature = "unstable-voting-circuits"))]
pub(in crate::circuit) mod commit_ivk;
#[cfg(feature = "unstable-voting-circuits")]
pub mod commit_ivk;
pub(in crate::circuit) mod derive_nullifier;
pub mod gadget;
#[cfg(not(feature = "unstable-voting-circuits"))]
pub(in crate::circuit) mod note_commit;
#[cfg(feature = "unstable-voting-circuits")]
pub mod note_commit;
pub(in crate::circuit) mod orchard_sinsemilla_chip;
pub(in crate::circuit) mod value_commit_orchard;

pub use crate::Proof;

/// Size of the Orchard circuit.
const K: u32 = 11;

// Absolute offsets for public inputs.
const ANCHOR: usize = 0;
const CV_NET_X: usize = 1;
const CV_NET_Y: usize = 2;
const NF_OLD: usize = 3;
const RK_X: usize = 4;
const RK_Y: usize = 5;
const CMX: usize = 6;
const ENABLE_SPEND: usize = 7;
const ENABLE_OUTPUT: usize = 8;
const DISABLE_CROSS_ADDRESS: usize = 9;
const ENABLE_ZSA: usize = 10;

/// Configuration needed to use the Orchard Action circuit.
#[derive(Clone, Debug)]
pub struct Config<Lookup: PallasLookupRangeCheck> {
    primary: Column<InstanceColumn>,
    q_orchard: Selector,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig<OrchardFixedBases, Lookup>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_config_1:
        MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
    merkle_config_2:
        MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
    sinsemilla_config_1:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
    sinsemilla_config_2:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
    commit_ivk_config: CommitIvkConfig,
    old_note_commit_config: NoteCommitConfig<Lookup>,
    new_note_commit_config: NoteCommitConfig<Lookup>,
}

impl OrchardCircuitVersion {
    /// Whether this circuit version enforces the `disableCrossAddress` public input.
    ///
    /// Statements with `disableCrossAddress = 1` can be proven and verified only with
    /// keys for a circuit version that constrains the flag. [`PostNu6_3`] constrains it;
    /// older circuit versions leave it unconstrained, so they cannot enforce — and must
    /// not be asked to attest to — the restriction.
    ///
    /// [`PostNu6_3`]: OrchardCircuitVersion::PostNu6_3
    pub fn supports_cross_address_restriction(self) -> bool {
        match self {
            OrchardCircuitVersion::InsecurePreNu6_2 | OrchardCircuitVersion::FixedPostNu6_2 => {
                false
            }
            OrchardCircuitVersion::PostNu6_3 | OrchardCircuitVersion::ZSA => true,
        }
    }

    /// The corresponding `halo2_gadgets` variable-base scalar-mul circuit version.
    fn halo2_version(self) -> CircuitVersion {
        match self {
            OrchardCircuitVersion::InsecurePreNu6_2 => CircuitVersion::InsecureUnanchoredBase,
            OrchardCircuitVersion::FixedPostNu6_2
            | OrchardCircuitVersion::PostNu6_3
            | OrchardCircuitVersion::ZSA => CircuitVersion::AnchoredBase,
        }
    }

    fn is_zsa(self) -> bool {
        self == OrchardCircuitVersion::ZSA
    }
}

/// The Orchard Action circuit.
#[derive(Clone, Debug)]
pub enum Circuit {
    /// The Vanilla Orchard Action circuit.
    /// It is used with all [`OrchardCircuitVersion`] except [`OrchardCircuitVersion::ZSA`].
    OrchardVanilla(CircuitVanilla),
    /// The ZSA Orchard Action circuit.
    /// It is used only with [`OrchardCircuitVersion::ZSA`].
    OrchardZSA(CircuitZsa),
}

impl Circuit {
    /// Returns the [`OrchardCircuitVersion`] this circuit instance is configured for.
    ///
    /// # Errors
    ///
    /// Returns [`plonk::Error::Synthesis`] if the variant and its inner circuit version are
    /// inconsistent: a `Circuit::OrchardVanilla` carrying [`OrchardCircuitVersion::ZSA`], or a
    /// `Circuit::OrchardZSA` not carrying it.
    fn circuit_version(&self) -> Result<OrchardCircuitVersion, plonk::Error> {
        match self {
            Circuit::OrchardVanilla(circuit) => {
                if circuit.circuit_version == OrchardCircuitVersion::ZSA {
                    return Err(plonk::Error::Synthesis);
                }
                Ok(circuit.circuit_version)
            }
            Circuit::OrchardZSA(circuit) => {
                if circuit.common_witnesses.circuit_version != OrchardCircuitVersion::ZSA {
                    return Err(plonk::Error::Synthesis);
                }
                Ok(circuit.common_witnesses.circuit_version)
            }
        }
    }
}

impl Circuit {
    /// Returns an empty circuit with all private witnesses unknown.
    ///
    /// This is used for circuit shape-dependent operations, such as generating keys
    /// or rendering the circuit layout, where witness values are not required but the
    /// selected circuit version still determines the configured constraints.
    fn empty(circuit_version: OrchardCircuitVersion) -> Self {
        if circuit_version.is_zsa() {
            Circuit::OrchardZSA(CircuitZsa::empty())
        } else {
            Circuit::OrchardVanilla(CircuitVanilla::empty(circuit_version))
        }
    }

    /// This constructor is public to enable creation of custom builders.
    /// If you are not creating a custom builder, use [`Builder`] to compose
    /// and authorize a transaction.
    ///
    /// Constructs a `Circuit` for the given `circuit_version` from the following components:
    /// - `spend`: [`SpendInfo`] of the note spent in scope of the action
    /// - `output_note`: a note created in scope of the action
    /// - `alpha`: a scalar used for randomization of the action spend validating key
    /// - `rcv`: trapdoor for the action value commitment
    ///
    /// Returns `None` if the `rho` of the `output_note` is not equal
    /// to the nullifier of the spent note.
    ///
    /// [`SpendInfo`]: crate::builder::SpendInfo
    /// [`Builder`]: crate::builder::Builder
    pub fn from_action_context(
        spend: SpendInfo,
        output_note: Note,
        alpha: pallas::Scalar,
        rcv: ValueCommitTrapdoor,
        circuit_version: OrchardCircuitVersion,
    ) -> Option<Circuit> {
        (Rho::from_nf_old(spend.note.nullifier(&spend.fvk)) == output_note.rho()).then(|| {
            Self::from_action_context_unchecked(spend, output_note, alpha, rcv, circuit_version)
        })
    }

    pub(crate) fn from_action_context_unchecked(
        spend: SpendInfo,
        output_note: Note,
        alpha: pallas::Scalar,
        rcv: ValueCommitTrapdoor,
        circuit_version: OrchardCircuitVersion,
    ) -> Circuit {
        if circuit_version.is_zsa() {
            Circuit::OrchardZSA(CircuitZsa::from_action_context_unchecked(
                spend,
                output_note,
                alpha,
                rcv,
                circuit_version,
            ))
        } else {
            Circuit::OrchardVanilla(CircuitVanilla::from_action_context_unchecked(
                spend,
                output_note,
                alpha,
                rcv,
                circuit_version,
            ))
        }
    }

    /// Returns the inner [`CircuitVanilla`], or `None` if this is a `Circuit::OrchardZSA`.
    fn as_vanilla(&self) -> Option<&CircuitVanilla> {
        match self {
            Circuit::OrchardVanilla(circuit) => Some(circuit),
            Circuit::OrchardZSA(_) => None,
        }
    }

    /// Returns the inner [`CircuitZsa`], or `None` if this is a `Circuit::OrchardVanilla`.
    fn as_zsa(&self) -> Option<&CircuitZsa> {
        match self {
            Circuit::OrchardZSA(circuit) => Some(circuit),
            Circuit::OrchardVanilla(_) => None,
        }
    }
}

/// Cells carrying the addresses of an action's spent and newly created notes, returned
/// from the shared synthesis logic so that circuit versions can impose additional
/// constraints on them.
struct AddressPoints<Lookup: PallasLookupRangeCheck> {
    g_d_old: NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>,
    pk_d_old: NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>,
    g_d_new: NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>,
    pk_d_new: NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>,
}

/// The verifying key for the Orchard Action circuit.
///
/// Build with [`VerifyingKey::build`] for an explicit circuit version.
#[derive(Debug)]
pub struct VerifyingKey {
    pub(crate) params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub(crate) vk: plonk::VerifyingKey<vesta::Affine>,
    circuit_version: OrchardCircuitVersion,
}

impl VerifyingKey {
    /// Builds the verifying key for the given circuit version.
    ///
    /// See [`OrchardCircuitVersion`] for which version to use.
    pub fn build(circuit_version: OrchardCircuitVersion) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let vk = match Circuit::empty(circuit_version) {
            Circuit::OrchardVanilla(circuit) => plonk::keygen_vk(&params, &circuit).unwrap(),
            Circuit::OrchardZSA(circuit) => plonk::keygen_vk(&params, &circuit).unwrap(),
        };

        VerifyingKey {
            params,
            vk,
            circuit_version,
        }
    }

    /// The circuit version this verifying key was built for.
    pub fn circuit_version(&self) -> OrchardCircuitVersion {
        self.circuit_version
    }

    /// Returns whether this verifying key supports the cross-address restriction.
    pub fn supports_cross_address_restriction(&self) -> bool {
        self.circuit_version.supports_cross_address_restriction()
    }
}

/// The proving key for the Orchard Action circuit.
///
/// Build with [`ProvingKey::build`] for an explicit circuit version.
/// The resulting proofs verify only under a compatible [`VerifyingKey`].
#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
    circuit_version: OrchardCircuitVersion,
}

impl ProvingKey {
    /// Builds the proving key for the given circuit version.
    ///
    /// See [`OrchardCircuitVersion`] for which version to use.
    pub fn build(circuit_version: OrchardCircuitVersion) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let pk = match Circuit::empty(circuit_version) {
            Circuit::OrchardVanilla(circuit) => {
                let vk = plonk::keygen_vk(&params, &circuit).unwrap();
                plonk::keygen_pk(&params, vk, &circuit).unwrap()
            }
            Circuit::OrchardZSA(circuit) => {
                let vk = plonk::keygen_vk(&params, &circuit).unwrap();
                plonk::keygen_pk(&params, vk, &circuit).unwrap()
            }
        };

        ProvingKey {
            params,
            pk,
            circuit_version,
        }
    }

    /// The circuit version this proving key produces proofs for.
    pub fn circuit_version(&self) -> OrchardCircuitVersion {
        self.circuit_version
    }

    /// Returns whether this proving key supports the cross-address restriction.
    pub fn supports_cross_address_restriction(&self) -> bool {
        self.circuit_version.supports_cross_address_restriction()
    }
}

/// Public inputs to the Orchard Action circuit.
///
/// The `enable_zsa` field was introduced with the ZSA feature; it did not exist before.
/// In vanilla Orchard, `enable_zsa` is always false, so this method always appends a zero to the
/// instance vector. Since halo2_proofs pads instance values with zero, old proofs (without this
/// extra entry) and new proofs behave identically.
///
/// # Invariants
///
/// Every `Instance` has a non-identity `rk`.
#[derive(Clone, Debug)]
pub struct Instance {
    anchor: Anchor,
    cv_net: ValueCommitment,
    nf_old: Nullifier,
    rk: VerificationKey<SpendAuth>,
    cmx: ExtractedNoteCommitment,
    enable_spend: bool,
    enable_output: bool,
    cross_address_disabled: bool,
    enable_zsa: bool,
}

impl Instance {
    /// Constructs an [`Instance`] from its constituent parts.
    ///
    /// This API can be used in combination with [`Proof::verify`] to build verification
    /// pipelines for many proofs, where you don't want to pass around the full bundle.
    /// Use [`Bundle::verify_proof`] instead if you have the full bundle.
    ///
    /// The provided [`Flags`] are encoded into the spend/output enable public inputs and
    /// the `disableCrossAddress` public input, which is set to the negation of
    /// [`Flags::cross_address_enabled`]. If cross-address transfers are disabled,
    /// callers must use a proving or verifying key whose circuit version supports the
    /// cross-address restriction; [`Proof::create`], [`Proof::verify`], and
    /// [`crate::bundle::BatchValidator`] enforce this.
    ///
    /// Returns `None` if `rk` is the identity [`pasta_curves::pallas::Point`].
    /// zcashd v6.12.1 and Zebra 4.3.1 both added a consensus rule rejecting
    /// transactions whose Orchard actions have an identity `rk`; the Zcash
    /// protocol specification will be updated to match, and this crate
    /// aligns with that rule.
    ///
    /// See:
    /// - <https://zodl.com/zcashd-zebra-april-2026-disclosure/>
    /// - <https://zfnd.org/zebra-4-3-1-critical-security-fixes-dockerized-mining-and-ci-hardening/>
    ///
    /// [`Bundle::verify_proof`]: crate::Bundle::verify_proof
    pub fn from_parts(
        anchor: Anchor,
        cv_net: ValueCommitment,
        nf_old: Nullifier,
        rk: VerificationKey<SpendAuth>,
        cmx: ExtractedNoteCommitment,
        flags: Flags,
    ) -> Option<Self> {
        (!rk.is_identity()).then_some(Instance {
            anchor,
            cv_net,
            nf_old,
            rk,
            cmx,
            enable_spend: flags.spends_enabled(),
            enable_output: flags.outputs_enabled(),
            cross_address_disabled: !flags.cross_address_enabled(),
            enable_zsa: flags.zsa_enabled(),
        })
    }

    /// Returns the Merkle tree anchor of this instance.
    pub(crate) fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// Returns the commitment to the net value of this instance.
    pub(crate) fn cv_net(&self) -> &ValueCommitment {
        &self.cv_net
    }

    /// Returns the nullifier of the note being spent by this instance.
    pub(crate) fn nf_old(&self) -> &Nullifier {
        &self.nf_old
    }

    /// Returns the randomized verification key of this instance.
    pub(crate) fn rk(&self) -> &VerificationKey<SpendAuth> {
        &self.rk
    }

    /// Returns the commitment to the new note being created by this instance.
    pub(crate) fn cmx(&self) -> &ExtractedNoteCommitment {
        &self.cmx
    }

    /// Returns whether the spend is enabled for this instance.
    pub(crate) fn enable_spend(&self) -> bool {
        self.enable_spend
    }

    /// Returns whether the output is enabled for this instance.
    pub(crate) fn enable_output(&self) -> bool {
        self.enable_output
    }

    /// Returns whether cross-address transfers are disabled for this instance.
    pub(crate) fn cross_address_disabled(&self) -> bool {
        self.cross_address_disabled
    }

    /// Returns whether zsa are enabled for this instance.
    pub(crate) fn enable_zsa(&self) -> bool {
        self.enable_zsa
    }

    /// Note: Before the ZSA feature was introduced, this method returned a 10-element instance slice.
    /// With ZSA, it now returns 11 elements, the last one corresponding to `enable_zsa`.
    /// In vanilla Orchard, `enable_zsa` is always false, so this extra element is always zero.
    /// Since halo2_proofs pads instance values with zero, old proofs (without this element)
    /// and new proofs behave identically.
    fn to_halo2_instance(&self) -> [[vesta::Scalar; 11]; 1] {
        let mut instance = [vesta::Scalar::zero(); 11];

        instance[ANCHOR] = self.anchor.inner();
        instance[CV_NET_X] = self.cv_net.x();
        instance[CV_NET_Y] = self.cv_net.y();
        instance[NF_OLD] = self.nf_old.inner();

        let rk = pallas::Point::from_bytes(&self.rk.clone().into())
            .expect("the cached byte encoding of a VerificationKey<_> is canonical")
            .to_affine()
            .coordinates()
            .expect("rk is non-identity by construction");

        instance[RK_X] = *rk.x();
        instance[RK_Y] = *rk.y();
        instance[CMX] = self.cmx.inner();
        instance[ENABLE_SPEND] = vesta::Scalar::from(u64::from(self.enable_spend));
        instance[ENABLE_OUTPUT] = vesta::Scalar::from(u64::from(self.enable_output));
        // Instance columns are zero-padded over the evaluation domain, so for statements
        // where this flag is false, this encoding is commitment-identical to the historical
        // nine-row encoding. Pre-NU 6.3 circuits leave this row unconstrained, which is why
        // restricted statements must never reach those keys (see `Proof::create` and
        // `Proof::verify`).
        instance[DISABLE_CROSS_ADDRESS] =
            vesta::Scalar::from(u64::from(self.cross_address_disabled));
        instance[ENABLE_ZSA] = vesta::Scalar::from(u64::from(self.enable_zsa));

        [instance]
    }
}

impl Proof {
    /// Creates a proof for the given circuits and instances.
    ///
    /// The resulting proof verifies only under a compatible [`VerifyingKey`] (see
    /// [`OrchardCircuitVersion`]).
    ///
    /// Returns [`plonk::Error::Synthesis`] if any circuit's version does not match `pk`'s
    /// version, since `pk` could not produce a valid proof for it.
    ///
    /// Returns [`plonk::Error::InvalidInstances`] if any instance has
    /// `disableCrossAddress = 1` and `pk` is not an
    /// [`OrchardCircuitVersion::PostNu6_3`] or an [`OrchardCircuitVersion::ZSA`] proving key.
    ///
    /// All instances of a bundle carry the same `disableCrossAddress` value; that uniformity
    /// is the bundle layer's invariant, and is not checked here.
    pub fn create(
        pk: &ProvingKey,
        circuits: &[Circuit],
        instances: &[Instance],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error> {
        for circuit in circuits {
            if circuit.circuit_version()? != pk.circuit_version {
                return Err(plonk::Error::Synthesis);
            }
        }

        if instances.iter().any(Instance::cross_address_disabled)
            && !pk.supports_cross_address_restriction()
        {
            return Err(plonk::Error::InvalidInstances);
        }

        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);

        if pk.circuit_version.is_zsa() {
            let circuits: Vec<_> = circuits
                .iter()
                .map(|c| c.as_zsa().expect("checked above").clone())
                .collect();
            plonk::create_proof(
                &pk.params,
                &pk.pk,
                &circuits,
                &instances,
                &mut rng,
                &mut transcript,
            )?;
        } else {
            let circuits: Vec<_> = circuits
                .iter()
                .map(|c| c.as_vanilla().expect("checked above").clone())
                .collect();
            plonk::create_proof(
                &pk.params,
                &pk.pk,
                &circuits,
                &instances,
                &mut rng,
                &mut transcript,
            )?;
        };

        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    ///
    /// # Errors
    ///
    /// Returns [`plonk::Error::InvalidInstances`] if any instance has
    /// `disableCrossAddress = 1` and `vk` is not an
    /// [`OrchardCircuitVersion::PostNu6_3`] or an [`OrchardCircuitVersion::ZSA`] verifying key.
    ///
    /// Also returns an error if proof verification fails.
    pub fn verify(&self, vk: &VerifyingKey, instances: &[Instance]) -> Result<(), plonk::Error> {
        if instances.iter().any(Instance::cross_address_disabled)
            && !vk.supports_cross_address_restriction()
        {
            return Err(plonk::Error::InvalidInstances);
        }

        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &instances, &mut transcript)
    }

    /// Adds this proof to the given batch for verification with the given instances.
    ///
    /// Internal to [`BatchValidator`], which is the only public batch path. A raw batch
    /// does not know which [`VerifyingKey`] it will be finalized with, so it cannot enforce
    /// that instances disabling cross-address transfers are only finalized with a key whose
    /// circuit version constrains the `disableCrossAddress` public input (see
    /// [`OrchardCircuitVersion::supports_cross_address_restriction`]). [`BatchValidator`]
    /// binds its key at construction and rejects such bundles in [`add_bundle`] before they
    /// reach this method; exposing this directly would let a caller sidestep that check by
    /// finalizing the batch against an unsupported key.
    ///
    /// [`BatchValidator`]: crate::bundle::BatchValidator
    /// [`add_bundle`]: crate::bundle::BatchValidator::add_bundle
    pub(crate) fn add_to_batch(
        &self,
        batch: &mut BatchVerifier<vesta::Affine>,
        instances: Vec<Instance>,
    ) {
        let instances = instances
            .iter()
            .map(|i| {
                i.to_halo2_instance()
                    .into_iter()
                    .map(|c| c.into_iter().collect())
                    .collect()
            })
            .collect();

        batch.add_proof(instances, self.0.clone());
    }
}

#[cfg(all(test, feature = "verifier-fingerprint"))]
mod fingerprint;

#[cfg(test)]
mod tests {

    mod from_parts_rk_identity {
        use ff::{Field as _, PrimeField as _};
        use pasta_curves::pallas;

        use super::super::Instance;
        use crate::{
            bundle::Flags,
            note::{AssetBase, ExtractedNoteCommitment, Nullifier},
            primitives::redpallas::{self, SpendAuth},
            tree::Anchor,
            value::{ValueCommitTrapdoor, ValueCommitment, ValueSum},
        };

        /// Non-rk fields for `Instance`. Distinct non-zero patterns avoid
        /// accidental overlap with sentinel values. See the analogous helper
        /// in `src/action.rs` for notes on which of these fields have
        /// consensus-level validity checks elsewhere in the pipeline.
        fn dummy_other_fields() -> (Anchor, ValueCommitment, Nullifier, ExtractedNoteCommitment) {
            let anchor = Anchor::from_bytes([6u8; 32]).unwrap();
            let cv_net = ValueCommitment::derive(
                ValueSum::from_raw(42),
                ValueCommitTrapdoor::zero(),
                AssetBase::zatoshi(),
            );
            let nf_old = Nullifier::from_bytes(&[1u8; 32]).unwrap();
            let cmx = ExtractedNoteCommitment::from_bytes(&[2u8; 32]).unwrap();
            (anchor, cv_net, nf_old, cmx)
        }

        fn identity_rk() -> redpallas::VerificationKey<SpendAuth> {
            redpallas::VerificationKey::<SpendAuth>::try_from([0u8; 32])
                .expect("plain redpallas accepts the identity encoding")
        }

        fn non_identity_rk() -> redpallas::VerificationKey<SpendAuth> {
            let ask_bytes: [u8; 32] = pallas::Scalar::ONE.to_repr();
            let ask = redpallas::SigningKey::<SpendAuth>::try_from(ask_bytes)
                .expect("1 is a valid scalar");
            (&ask).into()
        }

        #[test]
        fn rejects_identity_rk() {
            let (anchor, cv_net, nf_old, cmx) = dummy_other_fields();
            let result =
                Instance::from_parts(anchor, cv_net, nf_old, identity_rk(), cmx, Flags::ENABLED);
            assert!(result.is_none());
        }

        #[test]
        fn accepts_non_identity_rk() {
            let (anchor, cv_net, nf_old, cmx) = dummy_other_fields();
            let rk = non_identity_rk();
            let instance =
                Instance::from_parts(anchor, cv_net, nf_old, rk.clone(), cmx, Flags::ENABLED)
                    .expect("non-identity rk must be accepted");
            assert_eq!(instance.rk(), &rk);
        }
    }
}
