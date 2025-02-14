//! Structs related to swap bundles.

use crate::{
    builder::{BuildError, InProgress, InProgressSignatures, Unauthorized, Unproven},
    bundle::commitments::{hash_action_group, hash_swap_bundle},
    bundle::{derive_bvk, Authorization, Bundle, BundleCommitment},
    circuit::{ProvingKey, VerifyingKey},
    domain::OrchardDomainCommon,
    keys::SpendAuthorizingKey,
    note::AssetBase,
    orchard_flavor::OrchardZSA,
    primitives::redpallas::{self, Binding, SpendAuth},
    value::{NoteValue, ValueCommitTrapdoor},
    Proof,
};

use k256::elliptic_curve::rand_core::{CryptoRng, RngCore};

/// An action group.
#[derive(Debug, Clone)]
pub struct ActionGroup<A: Authorization, V> {
    /// The action group main content.
    action_group: Bundle<A, V, OrchardZSA>,
    /// The action group timelimit.
    timelimit: u32,
    /// The binding signature key for the action group.
    ///
    /// During the building of the action group, this key is not set.
    /// Once the action group is finalized (it contains a spend authorizing signature for each
    /// action and a proof), the key is set.
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

    /// Returns the action group's binding signature key.
    pub fn bsk(&self) -> Option<&redpallas::SigningKey<Binding>> {
        self.bsk.as_ref()
    }

    /// Remove bsk from this action group
    ///
    /// When creating a SwapBundle from a list of action groups, we evaluate the binding signature
    /// by signing the sighash with the sum of the bsk of each action group.
    /// Then, we remove the bsk of each action group as it is no longer needed.
    fn remove_bsk(&mut self) {
        self.bsk = None;
    }
}

impl<S: InProgressSignatures, V> ActionGroup<InProgress<Unproven, S>, V> {
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
        action_group_digest: [u8; 32],
        signing_keys: &[SpendAuthorizingKey],
    ) -> Result<ActionGroup<ActionGroupAuthorized, V>, BuildError> {
        let (bsk, action_group) = signing_keys
            .iter()
            .fold(
                self.action_group
                    .prepare_for_action_group(&mut rng, action_group_digest),
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
    /// Computes a commitment to the content of this action group.
    pub fn commitment(&self) -> BundleCommitment {
        BundleCommitment(hash_action_group(self))
    }
}

/// A swap bundle to be applied to the ledger.
#[derive(Debug, Clone)]
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

impl<V> SwapBundle<V> {

    /// Constructs a `SwapBundle` from its constituent parts.
    pub fn from_parts(
        action_groups: Vec<ActionGroup<ActionGroupAuthorized, V>>,
        value_balance: V,
        binding_signature: redpallas::Signature<Binding>,
    ) -> Self {
        SwapBundle {
            action_groups,
            value_balance,
            binding_signature,
        }
    }
}


impl<V: Copy + Into<i64> + std::iter::Sum> SwapBundle<V> {
    /// Constructs a `SwapBundle` from its action groups.
    pub fn new<R: RngCore + CryptoRng>(
        rng: R,
        mut action_groups: Vec<ActionGroup<ActionGroupAuthorized, V>>,
    ) -> Self {
        // Evaluate the swap value balance by summing the value balance of each action group.
        let value_balance = action_groups
            .iter()
            .map(|a| *a.action_group().value_balance())
            .sum();
        // Evaluate the swap bsk by summing the bsk of each action group.
        let bsk = action_groups
            .iter_mut()
            .map(|ag| {
                let bsk = ValueCommitTrapdoor::from_bsk(ag.bsk.unwrap());
                // Remove the bsk of each action group as it is no longer needed.
                ag.remove_bsk();
                bsk
            })
            .sum::<ValueCommitTrapdoor>()
            .into_bsk();
        // Evaluate the swap sighash
        let sighash: [u8; 32] = BundleCommitment(hash_swap_bundle(
            action_groups.iter().collect(),
            value_balance,
        ))
        .into();
        // Evaluate the swap binding signature which is equal to the signature of the swap sigash
        // with the swap binding signature key bsk.
        let binding_signature = bsk.sign(rng, &sighash);
        // Create the swap bundle
        SwapBundle {
            action_groups,
            value_balance,
            binding_signature,
        }
    }
}

/// Authorizing data for an action group, ready to be sent to the matcher.
#[derive(Debug, Clone)]
pub struct ActionGroupAuthorized {
    proof: Proof,
}

impl Authorization for ActionGroupAuthorized {
    type SpendAuth = redpallas::Signature<SpendAuth>;
}

impl ActionGroupAuthorized {
    /// Constructs the authorizing data for an action group from its proof.
    pub fn from_parts(proof: Proof) -> Self {
        ActionGroupAuthorized { proof }
    }

    /// Return the proof component of the authorizing data.
    pub fn proof(&self) -> &Proof {
        &self.proof
    }
}

impl<V, D: OrchardDomainCommon> Bundle<ActionGroupAuthorized, V, D> {
    /// Verifies the proof for this bundle.
    pub fn verify_proof(&self, vk: &VerifyingKey) -> Result<(), halo2_proofs::plonk::Error> {
        self.authorization()
            .proof()
            .verify(vk, &self.to_instances())
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

    /// The net value moved out of this swap.
    ///
    /// This is the sum of Orchard spends minus the sum of Orchard outputs.
    pub fn value_balance(&self) -> &V {
        &self.value_balance
    }
}

impl<V: Copy + Into<i64>> SwapBundle<V> {
    /// Computes a commitment to the effects of this swap bundle, suitable for inclusion
    /// within a transaction ID.
    pub fn commitment(&self) -> BundleCommitment {
        BundleCommitment(hash_swap_bundle(
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
