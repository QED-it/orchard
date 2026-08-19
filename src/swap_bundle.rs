//! Structs related to swap bundles.

use crate::{
    bundle::{
        commitments::{hash_bundle_txid_data, hash_bundle_auth_data},
        Authorized, Authorization, ActionGroup, BundleAuthorizingCommitment, BundleCommitment,
    },
    flavor::OrchardZSA,
    note::AssetBase,
    primitives::{
        redpallas::{self, Binding},
        OrchardPrimitives,
    },
    sighash_kind::{OrchardSighashKind, OrchardBindingSig, OrchardSpendAuthSig},
    value::{NoteValue, Sign, ValueCommitment, ValueCommitTrapdoor, ValueSum},
    Action, Proof,
};
use alloc::vec::Vec;
use nonempty::NonEmpty;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "circuit")]
use memuse::DynamicUsage;

#[cfg(feature = "circuit")]
use crate::circuit::VerifyingKey;

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
