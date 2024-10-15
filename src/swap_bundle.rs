//! Structs related to swap bundles.

use crate::{
    bundle::commitments::hash_action_groups_txid_data,
    bundle::{derive_bvk, ActionGroupAuthorized, Bundle, BundleCommitment},
    note::AssetBase,
    orchard_flavor::OrchardZSA,
    primitives::redpallas::{self, Binding},
    value::{NoteValue, ValueCommitTrapdoor},
};

use k256::elliptic_curve::rand_core::{CryptoRng, RngCore};

/// A swap bundle to be applied to the ledger.
#[derive(Clone, Debug)]
pub struct SwapBundle<V> {
    /// The list of action groups that make up this swap bundle.
    action_groups: Vec<Bundle<ActionGroupAuthorized, V, OrchardZSA>>,
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
        action_groups: Vec<Bundle<ActionGroupAuthorized, V, OrchardZSA>>,
    ) -> Self {
        let value_balance = action_groups.iter().map(|a| *a.value_balance()).sum();
        let bsk = action_groups
            .iter()
            .map(|a| ValueCommitTrapdoor::from_bsk(a.authorization().bsk()))
            .sum::<ValueCommitTrapdoor>()
            .into_bsk();
        let sighash: [u8; 32] = BundleCommitment(hash_action_groups_txid_data(
            action_groups.iter().collect(),
            value_balance,
        ))
        .into();
        let binding_signature = bsk.sign(rng, &sighash);
        SwapBundle {
            action_groups,
            value_balance,
            binding_signature,
        }
    }
}

impl<V> SwapBundle<V> {
    /// Returns the list of action groups that make up this swap bundle.
    pub fn action_groups(&self) -> &Vec<Bundle<ActionGroupAuthorized, V, OrchardZSA>> {
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
            .flat_map(|ag| ag.actions())
            .collect::<Vec<_>>();
        derive_bvk(
            actions,
            self.value_balance,
            std::iter::empty::<(AssetBase, NoteValue)>(),
        )
    }
}
