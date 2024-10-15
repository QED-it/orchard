//! Structs related to swap bundles.

use crate::{
    bundle::commitments::hash_action_groups_txid_data,
    bundle::{derive_bvk, ActionGroupAuthorized, Bundle, BundleCommitment},
    note::AssetBase,
    orchard_flavor::OrchardZSA,
    primitives::redpallas::{self, Binding},
    value::{NoteValue, ValueCommitTrapdoor},
    Proof,
};

use crate::builder::{BuildError, InProgress, InProgressSignatures, Unauthorized, Unproven};
use crate::bundle::Authorization;
use crate::circuit::ProvingKey;
use crate::keys::SpendAuthorizingKey;
use k256::elliptic_curve::rand_core::{CryptoRng, RngCore};

/// An action group.
#[derive(Debug)]
pub struct ActionGroup<A: Authorization, V> {
    /// The action group main content.
    action_group: Bundle<A, V, OrchardZSA>,
    /// The action group timelimit.
    timelimit: u32,
    /// The binding signature key for the action group.
    ///
    /// During the building of the action group, this key is not set.
    /// Once the action group is finalized (it contains a proof and for each action, a spend
    /// authorizing signature), the key is set.
    bsk: Option<redpallas::SigningKey<Binding>>,
}

impl<A: Authorization, V> ActionGroup<A, V> {
    /// Constructs an `ActionGroup` from its constituent parts.
    pub fn from_parts(
        action_group: Bundle<A, V, OrchardZSA>,
        timelimit: u32,
        bsk: Option<redpallas::SigningKey<Binding>>,
    ) -> Self {
        ActionGroup {
            action_group,
            timelimit,
            bsk,
        }
    }

    /// Returns the action group's main content.
    pub fn action_group(&self) -> &Bundle<A, V, OrchardZSA> {
        &self.action_group
    }

    /// Returns the action group's timelimit.
    pub fn timelimit(&self) -> u32 {
        self.timelimit
    }

    /// TODO
    pub fn remove_bsk(&mut self) {
        self.bsk = None;
    }
}

impl<S: InProgressSignatures, V> ActionGroup<InProgress<Unproven<OrchardZSA>, S>, V> {
    /// Creates the proof for this action group.
    pub fn create_proof(
        self,
        pk: &ProvingKey,
        mut rng: impl RngCore,
    ) -> Result<ActionGroup<InProgress<Proof, S>, V>, BuildError> {
        let new_action_group = self.action_group.create_proof(pk, &mut rng)?;
        Ok(ActionGroup {
            action_group: new_action_group,
            timelimit: self.timelimit,
            bsk: self.bsk,
        })
    }
}

impl<V> ActionGroup<InProgress<Proof, Unauthorized>, V> {
    /// Applies signatures to this action group, in order to authorize it.
    pub fn apply_signatures<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        sighash: [u8; 32],
        signing_keys: &[SpendAuthorizingKey],
    ) -> Result<ActionGroup<ActionGroupAuthorized, V>, BuildError> {
        let (bsk, action_group) = signing_keys
            .iter()
            .fold(
                self.action_group
                    .prepare_for_action_group(&mut rng, sighash),
                |partial, ask| partial.sign(&mut rng, ask),
            )
            .finalize()?;
        Ok(ActionGroup {
            action_group,
            timelimit: self.timelimit,
            bsk: Some(bsk),
        })
    }
}

impl<A: Authorization, V: Copy + Into<i64>> ActionGroup<A, V> {
    /// Computes a commitment to the effects of this bundle, suitable for inclusion within
    /// a transaction ID.
    pub fn commitment(&self) -> BundleCommitment {
        BundleCommitment(hash_action_groups_txid_data(
            vec![self],
            *self.action_group.value_balance(),
        ))
    }
}

/// A swap bundle to be applied to the ledger.
#[derive(Debug)]
pub struct SwapBundle<V> {
    /// The list of action groups that make up this swap bundle.
    action_groups: Vec<ActionGroup<ActionGroupAuthorized, V>>,
    /// The net value moved out of this swap.
    ///
    /// This is the sum of Orchard spends minus the sum of Orchard outputs.
    value_balance: V,
    /// The binding signature for this swap.
    binding_signature: redpallas::Signature<Binding>,
}

impl<V: Copy + Into<i64> + std::iter::Sum> SwapBundle<V> {
    /// Constructs a `Bundle` from its constituent parts.
    pub fn new<R: RngCore + CryptoRng>(
        rng: R,
        action_groups: Vec<ActionGroup<ActionGroupAuthorized, V>>,
    ) -> Self {
        let value_balance = action_groups
            .iter()
            .map(|a| *a.action_group().value_balance())
            .sum();
        let bsk = action_groups
            .iter()
            .map(|a| ValueCommitTrapdoor::from_bsk(a.bsk.unwrap()))
            .sum::<ValueCommitTrapdoor>()
            .into_bsk();
        let sighash: [u8; 32] = BundleCommitment(hash_action_groups_txid_data(
            action_groups.iter().collect(),
            value_balance,
        ))
        .into();
        let binding_signature = bsk.sign(rng, &sighash);
        // TODO Remove bsk for each action_group
        SwapBundle {
            action_groups,
            value_balance,
            binding_signature,
        }
    }
}

impl<V> SwapBundle<V> {
    /// Returns the list of action groups that make up this swap bundle.
    pub fn action_groups(&self) -> &Vec<ActionGroup<ActionGroupAuthorized, V>> {
        &self.action_groups
    }

    /// Returns the binding signature of this swap bundle.
    pub fn binding_signature(&self) -> &redpallas::Signature<Binding> {
        &self.binding_signature
    }
}

impl<V: Copy + Into<i64>> SwapBundle<V> {
    /// Computes a commitment to the effects of this swap bundle, suitable for inclusion
    /// within a transaction ID.
    pub fn commitment(&self) -> BundleCommitment {
        BundleCommitment(hash_action_groups_txid_data(
            self.action_groups.iter().collect(),
            self.value_balance,
        ))
    }

    /// Returns the transaction binding validating key for this swap bundle.
    pub fn binding_validating_key(&self) -> redpallas::VerificationKey<Binding> {
        let actions = self
            .action_groups
            .iter()
            .flat_map(|ag| ag.action_group().actions())
            .collect::<Vec<_>>();
        derive_bvk(
            actions,
            self.value_balance,
            std::iter::empty::<(AssetBase, NoteValue)>(),
        )
    }
}
