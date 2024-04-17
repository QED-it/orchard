use memuse::DynamicUsage;

use crate::{
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::OrchardDomain,
    primitives::redpallas::{self, SpendAuth},
    value::ValueCommitment,
};

/// An action applied to the global ledger.
///
/// Externally, this both creates a note (adding a commitment to the global ledger),
/// and consumes some note created prior to this action (adding a nullifier to the
/// global ledger).
///
/// Internally, this may both consume a note and create a note, or it may do only one of
/// the two. TODO: Determine which is more efficient (circuit size vs bundle size).
#[derive(Debug, Clone)]
pub struct Action<A, D: OrchardDomain> {
    /// The nullifier of the note being spent.
    nf: Nullifier,
    /// The randomized verification key for the note being spent.
    rk: redpallas::VerificationKey<SpendAuth>,
    /// A commitment to the new note being created.
    cmx: ExtractedNoteCommitment,
    /// The transmitted note ciphertext.
    encrypted_note: TransmittedNoteCiphertext<D>,
    /// A commitment to the net value created or consumed by this action.
    cv_net: ValueCommitment,
    /// The authorization for this action.
    authorization: A,
}

impl<A, D: OrchardDomain> Action<A, D> {
    /// Constructs an `Action` from its constituent parts.
    pub fn from_parts(
        nf: Nullifier,
        rk: redpallas::VerificationKey<SpendAuth>,
        cmx: ExtractedNoteCommitment,
        encrypted_note: TransmittedNoteCiphertext<D>,
        cv_net: ValueCommitment,
        authorization: A,
    ) -> Self {
        Action {
            nf,
            rk,
            cmx,
            encrypted_note,
            cv_net,
            authorization,
        }
    }

    /// Returns the nullifier of the note being spent.
    pub fn nullifier(&self) -> &Nullifier {
        &self.nf
    }

    /// Returns the randomized verification key for the note being spent.
    pub fn rk(&self) -> &redpallas::VerificationKey<SpendAuth> {
        &self.rk
    }

    /// Returns the commitment to the new note being created.
    pub fn cmx(&self) -> &ExtractedNoteCommitment {
        &self.cmx
    }

    /// Returns the encrypted note ciphertext.
    pub fn encrypted_note(&self) -> &TransmittedNoteCiphertext<D> {
        &self.encrypted_note
    }

    /// Returns the commitment to the net value created or consumed by this action.
    pub fn cv_net(&self) -> &ValueCommitment {
        &self.cv_net
    }

    /// Returns the authorization for this action.
    pub fn authorization(&self) -> &A {
        &self.authorization
    }

    /// Transitions this action from one authorization state to another.
    pub fn map<U>(self, step: impl FnOnce(A) -> U) -> Action<U, D> {
        Action {
            nf: self.nf,
            rk: self.rk,
            cmx: self.cmx,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(self.authorization),
        }
    }

    /// Transitions this action from one authorization state to another.
    pub fn try_map<U, E>(self, step: impl FnOnce(A) -> Result<U, E>) -> Result<Action<U, D>, E> {
        Ok(Action {
            nf: self.nf,
            rk: self.rk,
            cmx: self.cmx,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(self.authorization)?,
        })
    }
}

impl<D: OrchardDomain> DynamicUsage for Action<redpallas::Signature<SpendAuth>, D> {
    #[inline(always)]
    fn dynamic_usage(&self) -> usize {
        0
    }

    #[inline(always)]
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub(crate) mod testing {
    use rand::{rngs::StdRng, SeedableRng};
    use reddsa::orchard::SpendAuth;

    use proptest::prelude::*;

    use crate::note::asset_base::testing::arb_asset_base;
    use crate::{
        note::{
            commitment::ExtractedNoteCommitment, nullifier::testing::arb_nullifier,
            testing::arb_note, TransmittedNoteCiphertext,
        },
        note_encryption::OrchardDomain,
        primitives::redpallas::{
            self,
            testing::{arb_spendauth_signing_key, arb_spendauth_verification_key},
        },
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };

    use super::Action;

    /// `ActionArb` serves as a utility structure in property-based testing, designed specifically to adapt
    /// `arb_...` functions for compatibility with both variations of the Orchard protocol: Vanilla and ZSA.
    /// This adaptation is necessary due to the proptest crate's limitation, which prevents the direct
    /// transformation of `arb_...` functions into generic forms suitable for testing different protocol
    /// flavors.
    #[derive(Debug)]
    pub struct ActionArb<D: OrchardDomain> {
        phantom: std::marker::PhantomData<D>,
    }

    impl<D: OrchardDomain> ActionArb<D> {
        prop_compose! {
            /// Generate an action without authorization data.
            pub fn arb_unauthorized_action(spend_value: NoteValue, output_value: NoteValue)(
                nf in arb_nullifier(),
                rk in arb_spendauth_verification_key(),
                note in arb_note(output_value),
                asset in arb_asset_base()
            ) -> Action<(), D> {
                let cmx = ExtractedNoteCommitment::from(note.commitment());
                let cv_net = ValueCommitment::derive(
                    spend_value - output_value,
                    ValueCommitTrapdoor::zero(),
                    asset
                );
                // FIXME: make a real one from the note.
                let encrypted_note = TransmittedNoteCiphertext::<D> {
                    epk_bytes: [0u8; 32],
                    enc_ciphertext: D::NoteCiphertextBytes::from(vec![0u8; D::ENC_CIPHERTEXT_SIZE].as_ref()),
                    out_ciphertext: [0u8; 80]
                };
                Action {
                    nf,
                    rk,
                    cmx,
                    encrypted_note,
                    cv_net,
                    authorization: ()
                }
            }
        }

        prop_compose! {
            /// Generate an action with invalid (random) authorization data.
            pub fn arb_action(spend_value: NoteValue, output_value: NoteValue)(
                nf in arb_nullifier(),
                sk in arb_spendauth_signing_key(),
                note in arb_note(output_value),
                rng_seed in prop::array::uniform32(prop::num::u8::ANY),
                fake_sighash in prop::array::uniform32(prop::num::u8::ANY),
                asset in arb_asset_base()
            ) -> Action<redpallas::Signature<SpendAuth>, D> {
                let cmx = ExtractedNoteCommitment::from(note.commitment());
                let cv_net = ValueCommitment::derive(
                    spend_value - output_value,
                    ValueCommitTrapdoor::zero(),
                    asset
                );

                // FIXME: make a real one from the note.
                let encrypted_note = TransmittedNoteCiphertext::<D> {
                    epk_bytes: [0u8; 32],
                    enc_ciphertext: D::NoteCiphertextBytes::from(vec![0u8; D::ENC_CIPHERTEXT_SIZE].as_ref()),
                    out_ciphertext: [0u8; 80]
                };

                let rng = StdRng::from_seed(rng_seed);

                Action {
                    nf,
                    rk: redpallas::VerificationKey::from(&sk),
                    cmx,
                    encrypted_note,
                    cv_net,
                    authorization: sk.sign(rng, &fake_sighash),
                }
            }
        }
    }
}
