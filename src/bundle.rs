//! Structs related to bundles of Orchard actions.

use alloc::vec::Vec;

pub mod burn_validation;
pub mod commitments;

#[cfg(feature = "circuit")]
mod batch;
#[cfg(feature = "circuit")]
pub use batch::BatchValidator;

use core::fmt;

use blake2b_simd::Hash as Blake2bHash;
use nonempty::NonEmpty;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};

#[cfg(feature = "std")]
use memuse::DynamicUsage;
use rand_core::{CryptoRng, RngCore};
use crate::{
    action::Action,
    address::Address,
    bundle::commitments::{hash_action_group, hash_bundle_auth_data, hash_bundle_txid_data},
    flavor::OrchardZSA,
    keys::{IncomingViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey},
    note::{AssetBase, Note},
    primitives::{
        redpallas::{self, Binding},
        OrchardDomain, OrchardPrimitives,
    },
    sighash_kind::{OrchardBindingSig, OrchardSighashKind, OrchardSpendAuthSig},
    tree::Anchor,
    value::{NoteValue, Sign, ValueCommitTrapdoor, ValueCommitment, ValueSum},
    Proof,
};
#[cfg(feature = "circuit")]
use crate::circuit::{Instance, VerifyingKey};

#[cfg(feature = "circuit")]
impl<A, Pr: OrchardPrimitives> Action<A, Pr> {
    /// Prepares the public instance for this action, for creating and verifying the
    /// bundle proof.
    pub fn to_instance(&self, flags: Flags, anchor: Anchor) -> Instance {
        Instance {
            anchor,
            cv_net: self.cv_net().clone(),
            nf_old: *self.nullifier(),
            rk: self.rk().clone(),
            cmx: *self.cmx(),
            enable_spend: flags.spends_enabled,
            enable_output: flags.outputs_enabled,
            enable_zsa: flags.zsa_enabled,
        }
    }
}

/// Orchard-specific flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    /// Flag denoting whether Orchard spends are enabled in the transaction.
    ///
    /// If `false`, spent notes within [`Action`]s in the transaction's [`ActionGroup`] are
    /// guaranteed to be dummy notes. If `true`, the spent notes may be either real or
    /// dummy notes.
    spends_enabled: bool,
    /// Flag denoting whether Orchard outputs are enabled in the transaction.
    ///
    /// If `false`, created notes within [`Action`]s in the transaction's [`ActionGroup`] are
    /// guaranteed to be dummy notes. If `true`, the created notes may be either real or
    /// dummy notes.
    outputs_enabled: bool,
    /// Flag denoting whether ZSA functionality is enabled in the transaction.
    ///
    /// If `false`, all notes within [`Action`]s in the transaction's [`ActionGroup`] are
    /// guaranteed to be notes with zatoshi asset. If `true`, `Action`s may use any asset.
    ///
    /// This field was introduced with the ZSA feature; older Orchard versions did not
    /// include it. Because halo2_proofs zero-extends instance values, old proofs are interpreted
    /// with this flag equal to zero (`false`), so adding it does not break consensus.
    zsa_enabled: bool,
    /// Flag denoting whether Asset Swaps are enabled.
    ///
    /// If `false`, [`ActionGroup`] is guaranteed to contain only one ['ActionGroup'].
    swaps_enabled: bool,
}

const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
const FLAG_ZSA_ENABLED: u8 = 0b0000_0100;
const FLAG_SWAPS_ENABLED: u8 = 0b0000_1000;
const FLAGS_EXPECTED_UNSET: u8 =
    !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED | FLAG_ZSA_ENABLED | FLAG_SWAPS_ENABLED);

impl Flags {
    /// Construct a set of flags from its constituent parts
    pub(crate) const fn from_parts(
        spends_enabled: bool,
        outputs_enabled: bool,
        zsa_enabled: bool,
        swaps_enabled: bool,
    ) -> Self {
        Flags {
            spends_enabled,
            outputs_enabled,
            zsa_enabled,
            swaps_enabled,
        }
    }

    /// The flag set with both spends and outputs enabled, and ZSA and swaps disabled.
    pub const ENABLED: Flags = Flags {
        spends_enabled: true,
        outputs_enabled: true,
        zsa_enabled: false,
        swaps_enabled: false,
    };

    /// The flags set with spends, outputs and ZSA enabled. Swaps are disabled.
    pub const ENABLED_WITH_ZSA: Flags = Flags {
        spends_enabled: true,
        outputs_enabled: true,
        zsa_enabled: true,
        swaps_enabled: false,
    };

    /// The flags set with spends, outputs, ZSA and swaps enabled.
    pub const ENABLED_WITH_SWAPS: Flags = Flags {
        spends_enabled: true,
        outputs_enabled: true,
        zsa_enabled: true,
        swaps_enabled: true,
    };

    /// The flag set with spends, ZSA and swaps disabled.
    pub const SPENDS_DISABLED: Flags = Flags {
        spends_enabled: false,
        outputs_enabled: true,
        zsa_enabled: false,
        swaps_enabled: false,
    };

    /// The flag set with spends disabled and ZSA enabled. Swaps are disabled.
    pub const SPENDS_DISABLED_WITH_ZSA: Flags = Flags {
        spends_enabled: false,
        outputs_enabled: true,
        zsa_enabled: true,
        swaps_enabled: false,
    };

    /// The flag set with outputs disabled and ZSA and swaps disabled.
    pub const OUTPUTS_DISABLED: Flags = Flags {
        spends_enabled: true,
        outputs_enabled: false,
        zsa_enabled: false,
        swaps_enabled: false,
    };

    /// Flag denoting whether Orchard spends are enabled in the transaction.
    ///
    /// If `false`, spent notes within [`Action`]s in the transaction's [`ActionGroup`] are
    /// guaranteed to be dummy notes. If `true`, the spent notes may be either real or
    /// dummy notes.
    pub fn spends_enabled(&self) -> bool {
        self.spends_enabled
    }

    /// Flag denoting whether Orchard outputs are enabled in the transaction.
    ///
    /// If `false`, created notes within [`Action`]s in the transaction's [`ActionGroup`] are
    /// guaranteed to be dummy notes. If `true`, the created notes may be either real or
    /// dummy notes.
    pub fn outputs_enabled(&self) -> bool {
        self.outputs_enabled
    }

    /// Flag denoting whether ZSA functionality is enabled in the transaction.
    ///
    /// If `false`, all notes within [`Action`]s in the transaction's [`ActionGroup`] are
    /// guaranteed to be notes with zatoshi asset. If `true`, `Action`s may use any asset.
    pub fn zsa_enabled(&self) -> bool {
        self.zsa_enabled
    }

    /// Serialize flags to a byte as defined in [Zcash Protocol Spec § 7.1: Transaction
    /// Encoding And Consensus][txencoding].
    ///
    /// [txencoding]: https://zips.z.cash/protocol/protocol.pdf#txnencoding
    pub fn to_byte(&self) -> u8 {
        let mut value = 0u8;
        if self.spends_enabled {
            value |= FLAG_SPENDS_ENABLED;
        }
        if self.outputs_enabled {
            value |= FLAG_OUTPUTS_ENABLED;
        }
        if self.zsa_enabled {
            value |= FLAG_ZSA_ENABLED;
        }
        if self.swaps_enabled {
            value |= FLAG_SWAPS_ENABLED;
        }
        value
    }

    /// Parses flags from a single byte as defined in [Zcash Protocol Spec § 7.1:
    /// Transaction Encoding And Consensus][txencoding].
    ///
    /// Returns `None` if unexpected bits are set in the flag byte.
    ///
    /// [txencoding]: https://zips.z.cash/protocol/protocol.pdf#txnencoding
    pub fn from_byte(value: u8) -> Option<Self> {
        // https://p.z.cash/TCR:bad-txns-v5-reserved-bits-nonzero
        if value & FLAGS_EXPECTED_UNSET == 0 {
            Some(Self {
                spends_enabled: value & FLAG_SPENDS_ENABLED != 0,
                outputs_enabled: value & FLAG_OUTPUTS_ENABLED != 0,
                zsa_enabled: value & FLAG_ZSA_ENABLED != 0,
                swaps_enabled: value & FLAG_SWAPS_ENABLED != 0,
            })
        } else {
            None
        }
    }
}

/// Defines the authorization type of an Orchard bundle.
pub trait Authorization: fmt::Debug {
    /// The authorization type of an Orchard action.
    type SpendAuth: fmt::Debug;

    /// Return the proof component of the authorizing data.
    fn proof(&self) -> Option<&Proof>;
}

/// A bundle of actions to be applied to the ledger.
#[derive(Clone)]
pub struct ActionGroup<A: Authorization, Pr: OrchardPrimitives> {
    /// The list of actions that make up this action group.
    actions: NonEmpty<Action<A::SpendAuth, Pr>>,
    /// Orchard-specific transaction-level flags for this action group.
    flags: Flags,
    /// Assets intended for burning
    burn: Vec<(AssetBase, NoteValue)>,
    /// The root of the Orchard commitment tree that this action group commits to.
    anchor: Anchor,
    /// Block height after which this Action Group's Actions are invalid by consensus.
    ///
    /// An `expiry_height` set to 0, indicates no expiry.
    expiry_height: u32,
    /// The authorization for this Action Group.
    authorization: A,
}

impl<A: Authorization, Pr: OrchardPrimitives> fmt::Debug for ActionGroup<A, Pr> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Helper struct for debug-printing actions without exposing `NonEmpty`.
        struct Actions<'a, A, Pr: OrchardPrimitives>(&'a NonEmpty<Action<A, Pr>>);
        impl<A: fmt::Debug, Pr: OrchardPrimitives> fmt::Debug for Actions<'_, A, Pr> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        f.debug_struct("Bundle")
            .field("actions", &Actions(&self.actions))
            .field("flags", &self.flags)
            .field("anchor", &self.anchor)
            .field("authorization", &self.authorization)
            .finish()
    }
}

impl<A: Authorization, Pr: OrchardPrimitives> ActionGroup<A, Pr> {
    /// Constructs an `ActionGroup` from its constituent parts.
    pub fn from_parts(
        actions: NonEmpty<Action<A::SpendAuth, Pr>>,
        flags: Flags,
        burn: Vec<(AssetBase, NoteValue)>,
        anchor: Anchor,
        expiry_height: u32,
        authorization: A,
    ) -> Self {
        ActionGroup {
            actions,
            flags,
            burn,
            anchor,
            expiry_height,
            authorization,
        }
    }

    /// Returns the list of actions that make up this action group.
    pub fn actions(&self) -> &NonEmpty<Action<A::SpendAuth, Pr>> {
        &self.actions
    }

    /// Returns the Orchard-specific transaction-level flags for this action group.
    pub fn flags(&self) -> &Flags {
        &self.flags
    }

    /// Returns assets intended for burning
    pub fn burn(&self) -> &Vec<(AssetBase, NoteValue)> {
        &self.burn
    }

    /// Returns the root of the Orchard commitment tree that this action group commits to.
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// Returns the expiry height for this action group.
    pub fn expiry_height(&self) -> u32 {
        self.expiry_height
    }

    /// Returns the authorization for this action group.
    ///
    /// In the case of a `Bundle<Authorized>`, this is the proof and binding signature.
    pub fn authorization(&self) -> &A {
        &self.authorization
    }

    /// Transitions this action group from one authorization state to another.
    pub fn map_authorization<R, U: Authorization>(
        self,
        context: &mut R,
        mut spend_auth: impl FnMut(&mut R, &A, A::SpendAuth) -> U::SpendAuth,
        step: impl FnOnce(&mut R, A) -> U,
    ) -> ActionGroup<U, Pr> {
        let authorization = self.authorization;
        ActionGroup {
            actions: self
                .actions
                .map(|a| a.map(|a_auth| spend_auth(context, &authorization, a_auth))),
            flags: self.flags,
            burn: self.burn,
            anchor: self.anchor,
            expiry_height: self.expiry_height,
            authorization: step(context, authorization),
        }
    }

    /// Transitions this action group from one authorization state to another.
    pub fn try_map_authorization<R, U: Authorization, E>(
        self,
        context: &mut R,
        mut spend_auth: impl FnMut(&mut R, &A, A::SpendAuth) -> Result<U::SpendAuth, E>,
        step: impl FnOnce(&mut R, A) -> Result<U, E>,
    ) -> Result<ActionGroup<U, Pr>, E> {
        let authorization = self.authorization;
        let new_actions = self
            .actions
            .into_iter()
            .map(|a| a.try_map(|a_auth| spend_auth(context, &authorization, a_auth)))
            .collect::<Result<Vec<_>, E>>()?;

        Ok(ActionGroup {
            actions: NonEmpty::from_vec(new_actions).unwrap(),
            flags: self.flags,
            burn: self.burn,
            anchor: self.anchor,
            expiry_height: self.expiry_height,
            authorization: step(context, authorization)?,
        })
    }

    #[cfg(feature = "circuit")]
    pub(crate) fn to_instances(&self) -> Vec<Instance> {
        self.actions
            .iter()
            .map(|a| a.to_instance(self.flags, self.anchor))
            .collect()
    }

    /// Performs trial decryption of each action in the action group with each of the
    /// specified incoming viewing keys, and returns a vector of each decrypted
    /// note plaintext contents along with the index of the action from which it
    /// was derived.
    pub fn decrypt_outputs_with_keys(
        &self,
        keys: &[IncomingViewingKey],
    ) -> Vec<(usize, IncomingViewingKey, Note, Address, [u8; 512])> {
        let prepared_keys: Vec<_> = keys
            .iter()
            .map(|ivk| (ivk, PreparedIncomingViewingKey::new(ivk)))
            .collect();
        self.actions
            .iter()
            .enumerate()
            .filter_map(|(idx, action)| {
                let domain = OrchardDomain::for_action(action);
                prepared_keys.iter().find_map(|(ivk, prepared_ivk)| {
                    try_note_decryption(&domain, prepared_ivk, action)
                        .map(|(n, a, m)| (idx, (*ivk).clone(), n, a, m))
                })
            })
            .collect()
    }

    /// Performs trial decryption of the action at `action_idx` in the action group with the
    /// specified incoming viewing key, and returns the decrypted note plaintext
    /// contents if successful.
    pub fn decrypt_output_with_key(
        &self,
        action_idx: usize,
        key: &IncomingViewingKey,
    ) -> Option<(Note, Address, [u8; 512])> {
        let prepared_ivk = PreparedIncomingViewingKey::new(key);
        self.actions.get(action_idx).and_then(move |action| {
            let domain = OrchardDomain::for_action(action);
            try_note_decryption(&domain, &prepared_ivk, action)
        })
    }

    /// Performs trial decryption of each action in the action group with each of the
    /// specified outgoing viewing keys, and returns a vector of each decrypted
    /// note plaintext contents along with the index of the action from which it
    /// was derived.
    pub fn recover_outputs_with_ovks(
        &self,
        keys: &[OutgoingViewingKey],
    ) -> Vec<(usize, OutgoingViewingKey, Note, Address, [u8; 512])> {
        self.actions
            .iter()
            .enumerate()
            .filter_map(|(idx, action)| {
                let domain = OrchardDomain::for_action(action);
                keys.iter().find_map(move |key| {
                    try_output_recovery_with_ovk(
                        &domain,
                        key,
                        action,
                        action.cv_net(),
                        &action.encrypted_note().out_ciphertext,
                    )
                    .map(|(n, a, m)| (idx, key.clone(), n, a, m))
                })
            })
            .collect()
    }

    /// Attempts to decrypt the action at the specified index with the specified
    /// outgoing viewing key, and returns the decrypted note plaintext contents
    /// if successful.
    pub fn recover_output_with_ovk(
        &self,
        action_idx: usize,
        key: &OutgoingViewingKey,
    ) -> Option<(Note, Address, [u8; 512])> {
        self.actions.get(action_idx).and_then(move |action| {
            let domain = OrchardDomain::for_action(action);
            try_output_recovery_with_ovk(
                &domain,
                key,
                action,
                action.cv_net(),
                &action.encrypted_note().out_ciphertext,
            )
        })
    }
}

impl<A: Authorization> ActionGroup<A, OrchardZSA> {
    /// Computes a commitment to the effects of this action group.
    ///
    /// This is used for the swap setting, with multiple action groups.
    pub fn action_group_commitment(&self) -> BundleCommitment {
        BundleCommitment(hash_action_group(self))
    }
}

/// Marker type for a bundle that contains no authorizing data.
#[derive(Clone, Debug)]
pub struct EffectsOnly;

impl Authorization for EffectsOnly {
    type SpendAuth = ();

    /// Return the proof component of the authorizing data.
    fn proof(&self) -> Option<&Proof> {
        None
    }
}

/// Authorizing data for a bundle of actions, ready to be committed to the ledger.
#[derive(Debug, Clone)]
pub struct Authorized {
    proof: Proof,
    binding_signature: OrchardBindingSig,
}

impl Authorization for Authorized {
    type SpendAuth = OrchardSpendAuthSig;

    /// Return the proof component of the authorizing data.
    fn proof(&self) -> Option<&Proof> {
        Some(&self.proof)
    }
}

impl Authorized {
    /// Constructs the authorizing data for a bundle of actions from its constituent parts.
    pub fn from_parts(proof: Proof, binding_signature: OrchardBindingSig) -> Self {
        Authorized {
            proof,
            binding_signature,
        }
    }

    /// Return the proof component of the authorizing data.
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Return the binding signature.
    pub fn binding_signature(&self) -> &OrchardBindingSig {
        &self.binding_signature
    }
}

impl<Pr: OrchardPrimitives> ActionGroup<Authorized, Pr> {
    /// Verifies the proof for this bundle.
    #[cfg(feature = "circuit")]
    pub fn verify_proof(&self, vk: &VerifyingKey) -> Result<(), halo2_proofs::plonk::Error> {
        self.authorization()
            .proof()
            .verify(vk, &self.to_instances())
    }
}

#[cfg(feature = "std")]
impl<Pr: OrchardPrimitives> DynamicUsage for ActionGroup<Authorized, Pr> {
    fn dynamic_usage(&self) -> usize {
        self.actions.tail.dynamic_usage() + self.authorization.proof.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let bounds = (
            self.actions.tail.dynamic_usage_bounds(),
            self.authorization.proof.dynamic_usage_bounds(),
        );
        (
            bounds.0 .0 + bounds.1 .0,
            bounds.0 .1.zip(bounds.1 .1).map(|(a, b)| a + b),
        )
    }
}

/// A bundle to be applied to the ledger.
#[derive(Debug)]
pub struct Bundle<A: Authorization, V, Pr: OrchardPrimitives> {
    /// The list of action groups that make up this bundle.
    action_groups: Vec<ActionGroup<A, Pr>>,
    /// The net value moved out of this bundle.
    ///
    /// This is the sum of Orchard spends minus the sum of Orchard outputs, across action groups.
    value_balance: V,
    /// The binding signature for the bundle.
    binding_signature: Option<OrchardBindingSig>,
}

impl<V, Pr: OrchardPrimitives> Bundle<Authorized, V, Pr> {
    /// Computes a commitment to the authorizing data within for this bundle.
    ///
    /// This together with `Bundle::commitment` bind the entire bundle.
    /// The `sighash_info_for_kind` closure returns the `SighashInfo` encoding
    /// for a given [`OrchardSighashKind`].
    pub fn authorizing_commitment(
        &self,
        sighash_info_for_kind: impl Fn(&OrchardSighashKind) -> Vec<u8>,
    ) -> BundleAuthorizingCommitment {
        BundleAuthorizingCommitment(hash_bundle_auth_data(self, sighash_info_for_kind))
    }
}

impl<A: Authorization, V, Pr: OrchardPrimitives> Bundle<A, V, Pr> {
    /// Constructs a `Bundle` from its constituent parts.
    pub fn from_parts(
        action_groups: Vec<ActionGroup<A, Pr>>,
        value_balance: V,
        binding_signature: Option<OrchardBindingSig>,
    ) -> Self {
        Bundle {
            action_groups,
            value_balance,
            binding_signature,
        }
    }

    /// Construct a new bundle by applying a transformation that might fail
    /// to the value balance.
    pub fn try_map_value_balance<V0, E, F: FnOnce(V) -> Result<V0, E>>(
        self,
        f: F,
    ) -> Result<Bundle<A, V0, Pr>, E> {
        Ok(Bundle {
            action_groups: self.action_groups,
            value_balance: f(self.value_balance)?,
            binding_signature: self.binding_signature,
        })
    }
}

impl<V: Copy + Into<i64>> Bundle<ActionGroupAuthorized, V, OrchardZSA> {
    /// Prepares the binding signature for the bundle from the action groups and binding signature keys.
    ///
    /// The keys and the action groups should be in the same order.
    pub fn compute_binding_signature<R: RngCore + CryptoRng>(
        &self,
        rng: R,
        bsks: Vec<redpallas::SigningKey<Binding>>,
    ) -> Self {
        assert_eq!(self.action_groups().len(), bsks.len());
        // Evaluate the swap bsk by summing the bsk of each action group.
        let bsk = bsks
            .into_iter()
            .map(ValueCommitTrapdoor::from_bsk)
            .sum::<ValueCommitTrapdoor>()
            .into_bsk();
        // Evaluate the swap sighash
        let sighash: [u8; 32] = self.commitment().into();

        // Evaluate the swap binding signature which is equal to the signature of the swap sigash
        // with the swap binding signature key bsk.
        let binding_signature =
            OrchardBindingSig::new(OrchardSighashKind::AllEffecting, bsk.sign(rng, &sighash));
        // Create the swap bundle
        Bundle::from_parts(
            self.action_groups.clone(),
            self.value_balance,
            Some(binding_signature),
        )
    }
}

impl<A: Authorization, V: Copy + Into<i64>, Pr: OrchardPrimitives> Bundle<A, V, Pr> {
    /// Computes a commitment to the effects of this bundle, suitable for inclusion within
    /// a transaction ID.
    pub fn commitment(&self) -> BundleCommitment {
        BundleCommitment(hash_bundle_txid_data(self))
    }

    /// Returns the transaction binding validating key for this bundle.
    ///
    /// This can be used to validate the [`Authorized::binding_signature`] returned from
    /// [`ActionGroup::authorization`].
    pub fn binding_validating_key(&self) -> redpallas::VerificationKey<Binding> {
        let actions = self
            .action_groups
            .iter()
            .flat_map(|ag| ag.actions())
            .collect::<Vec<_>>();

        let burn = self
            .action_groups
            .iter()
            .flat_map(|ag| ag.burn().iter().cloned())
            .collect::<Vec<_>>();

        derive_bvk(
            NonEmpty::from_vec(actions).expect("SwapBundle must have at least one action"),
            self.value_balance,
            &burn,
        )
    }
}

#[cfg(feature = "std")]
impl<V: DynamicUsage, Pr: OrchardPrimitives> DynamicUsage for Bundle<Authorized, V, Pr> {
    fn dynamic_usage(&self) -> usize {
        self.action_groups.dynamic_usage() + self.value_balance.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let bounds = (
            self.action_groups.dynamic_usage_bounds(),
            self.value_balance.dynamic_usage_bounds(),
        );
        (
            bounds.0 .0 + bounds.1 .0,
            bounds.0 .1.zip(bounds.1 .1).map(|(a, b)| a + b),
        )
    }
}

impl<A: Authorization, V, Pr: OrchardPrimitives> Bundle<A, V, Pr> {
    /// Returns the list of action groups that make up this bundle.
    pub fn action_groups(&self) -> &Vec<ActionGroup<A, Pr>> {
        &self.action_groups
    }

    /// The net value moved out of this bundle.
    ///
    /// This is the sum of Orchard spends minus the sum of Orchard outputs.
    pub fn value_balance(&self) -> &V {
        &self.value_balance
    }

    /// The binding signature of this bundle. Returns `None` if the bundle is not yet bound.
    pub fn binding_signature(&self) -> Option<&OrchardBindingSig> {
        self.binding_signature.as_ref()
    }
}

pub(crate) fn derive_bvk<'a, A: 'a, V: Clone + Into<i64>, Pr: 'a + OrchardPrimitives>(
    actions: impl IntoIterator<Item = &'a Action<A, Pr>>,
    value_balance: V,
    burn: &[(AssetBase, NoteValue)],
) -> redpallas::VerificationKey<Binding> {
    derive_bvk_raw(
        actions.into_iter().map(|a| a.cv_net()),
        ValueSum::from_raw_inner(value_balance.into()),
        burn,
    )
}

pub(crate) fn derive_bvk_raw<'a>(
    cv_nets: impl IntoIterator<Item = &'a ValueCommitment>,
    value_balance: ValueSum,
    burn: &[(AssetBase, NoteValue)],
) -> redpallas::VerificationKey<Binding> {
    // https://p.z.cash/TCR:bad-txns-orchard-binding-signature-invalid?partial
    (cv_nets.into_iter().sum::<ValueCommitment>()
        - ValueCommitment::derive(
            value_balance,
            ValueCommitTrapdoor::zero(),
            AssetBase::zatoshi(),
        )
        - burn
            .iter()
            .map(|(asset, value)| {
                ValueCommitment::derive(
                    ValueSum::from_magnitude_sign(value.inner(), Sign::Positive),
                    ValueCommitTrapdoor::zero(),
                    *asset,
                )
            })
            .sum::<ValueCommitment>())
    .into_bvk()
}

/// Authorizing data for an action group, ready to be sent to the matcher.
#[derive(Debug, Clone)]
pub struct ActionGroupAuthorized {
    proof: Proof,
}

impl Authorization for ActionGroupAuthorized {
    type SpendAuth = OrchardSpendAuthSig;

    /// Return the proof component of the authorizing data.
    fn proof(&self) -> Option<&Proof> {
        Some(&self.proof)
    }
}

impl ActionGroupAuthorized {
    /// Constructs the authorizing data for an action group from its proof.
    pub fn from_parts(proof: Proof) -> Self {
        ActionGroupAuthorized { proof }
    }
}

#[cfg(feature = "circuit")]
impl<D: OrchardPrimitives> ActionGroup<ActionGroupAuthorized, D> {
    /// Verifies the proof for this bundle.
    pub fn verify_proof(&self, vk: &VerifyingKey) -> Result<(), halo2_proofs::plonk::Error> {
        self.authorization()
            .proof()
            .unwrap()
            .verify(vk, &self.to_instances())
    }
}

/// A commitment to a bundle of actions.
///
/// This commitment is non-malleable, in the sense that a bundle's commitment will only
/// change if the effects of the bundle are altered.
#[derive(Debug)]
pub struct BundleCommitment(pub Blake2bHash);

impl From<BundleCommitment> for [u8; 32] {
    fn from(commitment: BundleCommitment) -> Self {
        // The commitment uses BLAKE2b-256.
        commitment.0.as_bytes().try_into().unwrap()
    }
}

/// A commitment to the authorizing data within a bundle of actions.
#[derive(Debug)]
pub struct BundleAuthorizingCommitment(pub Blake2bHash);

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use alloc::vec::Vec;

    use group::ff::FromUniformBytes;
    use nonempty::NonEmpty;
    use pasta_curves::pallas;
    use rand::{rngs::StdRng, SeedableRng};

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::{
        note::{
            asset_base::testing::{arb_asset_base, arb_zsa_asset_base},
            AssetBase,
        },
        primitives::{redpallas::testing::arb_binding_signing_key, OrchardPrimitives},
        sighash_kind::{OrchardBindingSig, OrchardSighashKind, OrchardSpendAuthSig},
        value::{
            testing::{arb_note_value, arb_note_value_bounded},
            NoteValue, ValueSum, MAX_NOTE_VALUE,
        },
        Anchor, Proof,
    };

    use super::{Action, ActionGroup, Authorized, Flags};

    pub use crate::action::testing::ActionArb;

    /// Marker type for a bundle that contains no authorizing data.
    pub type Unauthorized = super::EffectsOnly;

    /// `BundleArb` adapts `arb_...` functions for both Vanilla and ZSA Orchard protocol variations
    /// in property-based testing, addressing proptest crate limitations.
    #[derive(Debug)]
    pub struct BundleArb<Pr: OrchardPrimitives> {
        phantom: core::marker::PhantomData<Pr>,
    }

    impl<Pr: OrchardPrimitives + Default> BundleArb<Pr> {
        /// Generate an unauthorized action having spend and output values less than MAX_NOTE_VALUE / n_actions.
        pub fn arb_unauthorized_action_n(
            n_actions: usize,
            flags: Flags,
        ) -> impl Strategy<Value = (ValueSum, Action<(), Pr>)> {
            let spend_value_gen = if flags.spends_enabled {
                Strategy::boxed(arb_note_value_bounded(MAX_NOTE_VALUE / n_actions as u64))
            } else {
                Strategy::boxed(Just(NoteValue::zero()))
            };

            spend_value_gen.prop_flat_map(move |spend_value| {
                let output_value_gen = if flags.outputs_enabled {
                    Strategy::boxed(arb_note_value_bounded(MAX_NOTE_VALUE / n_actions as u64))
                } else {
                    Strategy::boxed(Just(NoteValue::zero()))
                };

                output_value_gen.prop_flat_map(move |output_value| {
                    arb_asset_base().prop_flat_map(move |asset| {
                        let value_sum = spend_value - output_value;
                        ActionArb::arb_unauthorized_action(spend_value, output_value, asset)
                            .prop_map(move |a| (value_sum, a))
                    })
                })
            })
        }

        /// Generate an authorized action having spend and output values less than MAX_NOTE_VALUE / n_actions.
        pub fn arb_action_n(
            n_actions: usize,
            flags: Flags,
        ) -> impl Strategy<Value = (ValueSum, Action<OrchardSpendAuthSig, Pr>)> {
            let spend_value_gen = if flags.spends_enabled {
                Strategy::boxed(arb_note_value_bounded(MAX_NOTE_VALUE / n_actions as u64))
            } else {
                Strategy::boxed(Just(NoteValue::zero()))
            };

            spend_value_gen.prop_flat_map(move |spend_value| {
                let output_value_gen = if flags.outputs_enabled {
                    Strategy::boxed(arb_note_value_bounded(MAX_NOTE_VALUE / n_actions as u64))
                } else {
                    Strategy::boxed(Just(NoteValue::zero()))
                };

                output_value_gen.prop_flat_map(move |output_value| {
                    arb_asset_base().prop_flat_map(move |asset| {
                        let value_sum = spend_value - output_value;
                        ActionArb::arb_action(spend_value, output_value, asset)
                            .prop_map(move |a| (value_sum, a))
                    })
                })
            })
        }

        prop_compose! {
            /// Create an arbitrary vector of assets to burn.
            pub fn arb_asset_to_burn()
            (
                asset_base in arb_zsa_asset_base(),
                value in arb_note_value()
            ) -> (AssetBase, NoteValue) {
                (asset_base, value)
            }
        }

        prop_compose! {
            /// Create an arbitrary set of flags.
            pub fn arb_flags()(spends_enabled in prop::bool::ANY, outputs_enabled in prop::bool::ANY, zsa_enabled in prop::bool::ANY, swaps_enabled in prop::bool::ANY) -> Flags {
                Flags::from_parts(spends_enabled, outputs_enabled, zsa_enabled, swaps_enabled)
            }
        }

        prop_compose! {
            fn arb_base()(bytes in prop::array::uniform32(0u8..)) -> pallas::Base {
                // Instead of rejecting out-of-range bytes, let's reduce them.
                let mut buf = [0; 64];
                buf[..32].copy_from_slice(&bytes);
                pallas::Base::from_uniform_bytes(&buf)
            }
        }

        prop_compose! {
            /// Generate an arbitrary unauthorized bundle. This bundle does not
            /// necessarily respect consensus rules; for that use
            /// [`crate::builder::testing::arb_bundle`]
            pub fn arb_unauthorized_bundle(n_actions: usize)
            (
                flags in Self::arb_flags(),
            )
            (
                acts in vec(Self::arb_unauthorized_action_n(n_actions, flags), n_actions),
                anchor in Self::arb_base().prop_map(Anchor::from),
                flags in Just(flags),
                burn in vec(Self::arb_asset_to_burn(), 1usize..10)
            ) -> ActionGroup<Unauthorized, Pr> {
                let (_, actions): (Vec<ValueSum>, Vec<Action<_, _>>) = acts.into_iter().unzip();

                ActionGroup::from_parts(
                    NonEmpty::from_vec(actions).unwrap(),
                    flags,
                    burn,
                    anchor,
                    0,
                    super::EffectsOnly,
                )
            }
        }

        prop_compose! {
            /// Generate an arbitrary bundle with fake authorization data. This bundle does not
            /// necessarily respect consensus rules; for that use
            /// [`crate::builder::testing::arb_bundle`]
            pub fn arb_bundle(n_actions: usize)
            (
                flags in Self::arb_flags(),
            )
            (
                acts in vec(Self::arb_action_n(n_actions, flags), n_actions),
                anchor in Self::arb_base().prop_map(Anchor::from),
                sk in arb_binding_signing_key(),
                rng_seed in prop::array::uniform32(prop::num::u8::ANY),
                fake_proof in vec(prop::num::u8::ANY, 1973),
                fake_sighash in prop::array::uniform32(prop::num::u8::ANY),
                flags in Just(flags),
                burn in vec(Self::arb_asset_to_burn(), 1usize..10)
            ) -> ActionGroup<Authorized, Pr> {
                let (_, actions): (Vec<ValueSum>, Vec<Action<_, _>, >) = acts.into_iter().unzip();
                let rng = StdRng::from_seed(rng_seed);

                ActionGroup::from_parts(
                    NonEmpty::from_vec(actions).unwrap(),
                    flags,
                    burn,
                    anchor,
                    0,
                    Authorized {
                        proof: Proof::new(fake_proof),
                        binding_signature: OrchardBindingSig::new(OrchardSighashKind::AllEffecting, sk.sign(rng, &fake_sighash)),
                    },
                )
            }
        }
    }
}
