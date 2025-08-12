//! This module implements the note encryption and commitment logic specific for the `OrchardZSA`
//! flavor.

use blake2b_simd::Hash as Blake2bHash;
use zcash_note_encryption::note_bytes::NoteBytesData;

use crate::{
    bundle::{
        commitments::{
            hash_action_group, hasher,
            ZCASH_ORCHARD_ACTION_GROUPS_SIGS_HASH_PERSONALIZATION,
            ZCASH_ORCHARD_HASH_PERSONALIZATION, ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION,
        },
        Authorization, Authorized,
    },
    note::{AssetBase, Note},
    orchard_flavor::OrchardZSA,
    primitives::{
        orchard_primitives::OrchardPrimitives,
        zcash_note_encryption_domain::{
            build_base_note_plaintext_bytes, Memo, COMPACT_NOTE_SIZE_VANILLA,
            COMPACT_NOTE_SIZE_ZSA, NOTE_VERSION_BYTE_V3,
        },
    },
    Bundle,
};

impl OrchardPrimitives for OrchardZSA {
    const COMPACT_NOTE_SIZE: usize = COMPACT_NOTE_SIZE_ZSA;

    type NotePlaintextBytes = NoteBytesData<{ Self::NOTE_PLAINTEXT_SIZE }>;
    type NoteCiphertextBytes = NoteBytesData<{ Self::ENC_CIPHERTEXT_SIZE }>;
    type CompactNotePlaintextBytes = NoteBytesData<{ Self::COMPACT_NOTE_SIZE }>;
    type CompactNoteCiphertextBytes = NoteBytesData<{ Self::COMPACT_NOTE_SIZE }>;

    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes {
        let mut np = build_base_note_plaintext_bytes(NOTE_VERSION_BYTE_V3, note);

        np[COMPACT_NOTE_SIZE_VANILLA..COMPACT_NOTE_SIZE_ZSA]
            .copy_from_slice(&note.asset().to_bytes());
        np[COMPACT_NOTE_SIZE_ZSA..].copy_from_slice(memo);

        NoteBytesData(np)
    }

    fn extract_asset(plaintext: &Self::CompactNotePlaintextBytes) -> Option<AssetBase> {
        let bytes = plaintext.as_ref()[COMPACT_NOTE_SIZE_VANILLA..COMPACT_NOTE_SIZE_ZSA]
            .try_into()
            .unwrap();

        AssetBase::from_bytes(bytes).into()
    }

    /// Evaluate `orchard_digest` for the bundle as defined in
    /// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
    ///
    /// [zip246]: https://zips.z.cash/zip-0246
    fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
        bundle: &Bundle<A, V, OrchardZSA>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        let action_group_hash = hash_action_group(bundle);
        h.update(action_group_hash.as_bytes());
        h.update(&(*bundle.value_balance()).into().to_le_bytes());
        h.finalize()
    }

    /// Evaluate `orchard_auth_digest` for the bundle as defined in
    /// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
    ///
    /// [zip246]: https://zips.z.cash/zip-0246
    fn hash_bundle_auth_data<V>(bundle: &Bundle<Authorized, V, OrchardZSA>) -> Blake2bHash {
        let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
        let mut agh = hasher(ZCASH_ORCHARD_ACTION_GROUPS_SIGS_HASH_PERSONALIZATION);
        agh.update(bundle.authorization().proof().unwrap().as_ref());
        for action in bundle.actions().iter() {
            agh.update(&<[u8; 64]>::from(action.authorization()));
        }
        h.update(agh.finalize().as_bytes());
        h.update(&<[u8; 64]>::from(
            bundle.authorization().binding_signature(),
        ));
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use rand::rngs::OsRng;

    use zcash_note_encryption::{
        note_bytes::NoteBytesData, try_compact_note_decryption, try_note_decryption,
        try_output_recovery_with_ovk, Domain, EphemeralKeyBytes,
    };

    use crate::{
        action::Action,
        address::Address,
        keys::{
            DiversifiedTransmissionKey, Diversifier, EphemeralSecretKey, IncomingViewingKey,
            OutgoingViewingKey, PreparedIncomingViewingKey,
        },
        note::{
            testing::arb_note, AssetBase, ExtractedNoteCommitment, Note, Nullifier, RandomSeed,
            Rho, TransmittedNoteCiphertext,
        },
        orchard_flavor::OrchardZSA,
        primitives::{
            compact_action::CompactAction,
            orchard_domain::OrchardDomain,
            redpallas,
            zcash_note_encryption_domain::{
                parse_note_plaintext_without_memo, parse_note_version, prf_ock_orchard,
            },
        },
        value::{NoteValue, ValueCommitment},
    };

    type OrchardDomainZSA = OrchardDomain<OrchardZSA>;

    proptest! {
        #[test]
        fn encoding_roundtrip(
            note in arb_note(NoteValue::from_raw(100)),
        ) {
            let memo = &crate::test_vectors::note_encryption_zsa::TEST_VECTORS[0].memo;
            let rho = note.rho();

            // Encode.
            let plaintext = OrchardDomainZSA::note_plaintext_bytes(&note, memo);

            // Decode.
            let domain = OrchardDomainZSA::for_rho(rho);
            let (compact, parsed_memo) = domain.split_plaintext_at_memo(&plaintext).unwrap();

            assert!(parse_note_version(compact.as_ref()).is_some());

            let (parsed_note, parsed_recipient) = parse_note_plaintext_without_memo::<OrchardZSA, _>(rho, &compact,
                |diversifier| {
                    assert_eq!(diversifier, &note.recipient().diversifier());
                    Some(*note.recipient().pk_d())
                }
            ).expect("Plaintext parsing failed");

            // Check.
            assert_eq!(parsed_note, note);
            assert_eq!(parsed_recipient, note.recipient());
            assert_eq!(&parsed_memo, memo);
        }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption_zsa::TEST_VECTORS;

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            // Recipient key material
            let ivk = PreparedIncomingViewingKey::new(
                &IncomingViewingKey::from_bytes(&tv.incoming_viewing_key).unwrap(),
            );
            let ovk = OutgoingViewingKey::from(tv.ovk);
            let d = Diversifier::from_bytes(tv.default_d);
            let pk_d = DiversifiedTransmissionKey::from_bytes(&tv.default_pk_d).unwrap();

            // Received Action
            let cv_net = ValueCommitment::from_bytes(&tv.cv_net).unwrap();
            let nf_old = Nullifier::from_bytes(&tv.nf_old).unwrap();
            let rho = Rho::from_nf_old(nf_old);
            let cmx = ExtractedNoteCommitment::from_bytes(&tv.cmx).unwrap();

            let esk = EphemeralSecretKey::from_bytes(&tv.esk).unwrap();
            let ephemeral_key = EphemeralKeyBytes(tv.ephemeral_key);

            // Details about the expected note
            let value = NoteValue::from_raw(tv.v);
            let rseed = RandomSeed::from_bytes(tv.rseed, &rho).unwrap();

            //
            // Test the individual components
            //

            let shared_secret = esk.agree(&pk_d);
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = shared_secret.kdf_orchard(&ephemeral_key);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ock = prf_ock_orchard(&ovk, &cv_net, &cmx.to_bytes(), &ephemeral_key);
            assert_eq!(ock.as_ref(), tv.ock);

            let recipient = Address::from_parts(d, pk_d);

            let asset = AssetBase::from_bytes(&tv.asset).unwrap();

            let note = Note::from_parts(recipient, value, asset, rho, rseed).unwrap();
            assert_eq!(ExtractedNoteCommitment::from(note.commitment()), cmx);

            let action = Action::from_parts(
                // nf_old is the nullifier revealed by the receiving Action.
                nf_old,
                // We don't need a valid rk for this test.
                redpallas::VerificationKey::dummy(),
                cmx,
                TransmittedNoteCiphertext::<OrchardZSA> {
                    epk_bytes: ephemeral_key.0,
                    enc_ciphertext: NoteBytesData(tv.c_enc),
                    out_ciphertext: tv.c_out,
                },
                cv_net.clone(),
                (),
            );

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            let domain = OrchardDomain::for_rho(rho);

            match try_note_decryption(&domain, &ivk, &action) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_compact_note_decryption(&domain, &ivk, &CompactAction::from(&action)) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                }
                None => panic!("Compact note decryption failed"),
            }

            match try_output_recovery_with_ovk(&domain, &ovk, &action, &cv_net, &tv.c_out) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            //
            // Test encryption
            //

            let ne = zcash_note_encryption::NoteEncryption::<OrchardDomainZSA>::new_with_esk(
                esk,
                Some(ovk),
                note,
                tv.memo,
            );

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }
}
