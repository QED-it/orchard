//! This module implements the note encryption and commitment logic specific for the
//! `OrchardVanilla` flavor.

use alloc::vec::Vec;
use blake2b_simd::Hash as Blake2bHash;
use zcash_note_encryption::note_bytes::NoteBytesData;

use crate::{
    bundle::{commitments::hasher, Authorization, Authorized, CommitmentError, TxVersion},
    flavor::OrchardVanilla,
    note::{AssetBase, Note, NoteVersion},
    primitives::{
        orchard_primitives::OrchardPrimitives,
        zcash_note_encryption_domain::{
            build_base_note_plaintext_bytes, Memo, COMPACT_NOTE_SIZE_VANILLA, MEMO_SIZE,
        },
    },
    sighash_kind::OrchardSighashKind,
    Bundle,
};

impl OrchardPrimitives for OrchardVanilla {
    const COMPACT_NOTE_SIZE: usize = COMPACT_NOTE_SIZE_VANILLA;
    const BASE_PROOF_SIZE: usize = 2720;
    const PER_ACTION_PROOF_SIZE: usize = 2272;

    type NotePlaintextBytes = NoteBytesData<{ Self::NOTE_PLAINTEXT_SIZE }>;
    type NoteCiphertextBytes = NoteBytesData<{ Self::ENC_CIPHERTEXT_SIZE }>;
    type CompactNotePlaintextBytes = NoteBytesData<{ Self::COMPACT_NOTE_SIZE }>;
    type CompactNoteCiphertextBytes = NoteBytesData<{ Self::COMPACT_NOTE_SIZE }>;

    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes {
        // The note plaintext lead byte follows the version recorded by the note
        // (0x02 for ZIP 212 V2 notes, 0x03 for ZIP 2005 Ironwood V3 notes); the
        // domain policy only constrains parsing and decryption.
        let mut np = build_base_note_plaintext_bytes(note.version().lead_byte(), note);

        np[COMPACT_NOTE_SIZE_VANILLA..].copy_from_slice(memo);

        NoteBytesData(np)
    }

    fn extract_asset(_plaintext: &Self::CompactNotePlaintextBytes) -> Option<AssetBase> {
        Some(AssetBase::zatoshi())
    }

    /// Evaluate `orchard_digest` for the bundle as defined in
    /// [ZIP-244: Transaction Identifier Non-Malleability][zip244].
    ///
    /// The bundle's own [`BundleVersion`] and `tx_version` select the commitment
    /// personalizations (Orchard v5, Orchard v6 or Ironwood v6) and the anchor
    /// placement: in the v5 format the anchor is included here, in the v6 formats it is
    /// included by `hash_bundle_auth_data` instead.
    ///
    /// [zip244]: https://zips.z.cash/zip-0244
    /// [`BundleVersion`]: crate::bundle::BundleVersion
    fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
        bundle: &Bundle<A, V, OrchardVanilla>,
        tx_version: TxVersion,
    ) -> Result<Blake2bHash, CommitmentError> {
        let format = bundle
            .bundle_version()
            .value_pool()
            .commitment_format(tx_version)?;
        let personalizations = format.personalizations();
        let mut h = hasher(personalizations.bundle);

        let mut ch = hasher(personalizations.actions_compact);
        let mut mh = hasher(personalizations.actions_memos);
        let mut nh = hasher(personalizations.actions_noncompact);

        for action in bundle.actions().iter() {
            ch.update(&action.nullifier().to_bytes());
            ch.update(&action.cmx().to_bytes());
            ch.update(&action.encrypted_note().epk_bytes);
            ch.update(&action.encrypted_note().enc_ciphertext.as_ref()[..Self::COMPACT_NOTE_SIZE]);

            mh.update(
                &action.encrypted_note().enc_ciphertext.as_ref()
                    [Self::COMPACT_NOTE_SIZE..Self::COMPACT_NOTE_SIZE + MEMO_SIZE],
            );

            nh.update(&action.cv_net().to_bytes());
            nh.update(&<[u8; 32]>::from(action.rk()));
            nh.update(
                &action.encrypted_note().enc_ciphertext.as_ref()
                    [Self::COMPACT_NOTE_SIZE + MEMO_SIZE..],
            );
            nh.update(&action.encrypted_note().out_ciphertext);
        }

        h.update(ch.finalize().as_bytes());
        h.update(mh.finalize().as_bytes());
        h.update(nh.finalize().as_bytes());

        h.update(&[bundle.flag_byte()]);
        h.update(&(*bundle.value_balance()).into().to_le_bytes());
        if format.includes_anchor_in_txid_digest() {
            h.update(&bundle.anchor().to_bytes());
        }
        Ok(h.finalize())
    }

    /// Evaluate `orchard_auth_digest` for the bundle as defined in
    /// [ZIP-244: Transaction Identifier Non-Malleability][zip244].
    ///
    /// In the v6 formats this digest also includes the bundle anchor bytes (in the v5
    /// format they are included by `hash_bundle_txid_data` instead).
    ///
    /// # Panics
    ///
    /// Panics if any signature in the bundle uses a sighash kind different from
    /// `OrchardSighashKind::AllEffecting`. For the Orchard and Ironwood pools, this is
    /// the only defined sighash kind.
    ///
    /// [zip244]: https://zips.z.cash/zip-0244
    fn hash_bundle_auth_data<V>(
        bundle: &Bundle<Authorized, V, OrchardVanilla>,
        tx_version: TxVersion,
        _sighash_info_for_kind: impl Fn(&OrchardSighashKind) -> Vec<u8>,
    ) -> Result<Blake2bHash, CommitmentError> {
        let format = bundle
            .bundle_version()
            .value_pool()
            .commitment_format(tx_version)?;
        let mut h = hasher(format.personalizations().auth);
        h.update(bundle.authorization().proof().as_ref());
        for action in bundle.actions().iter() {
            assert_eq!(
                *action.authorization().sighash_kind(),
                OrchardSighashKind::AllEffecting
            );
            h.update(&<[u8; 64]>::from(action.authorization().sig()));
        }
        assert_eq!(
            *bundle.authorization().binding_signature().sighash_kind(),
            OrchardSighashKind::AllEffecting
        );
        h.update(&<[u8; 64]>::from(
            bundle.authorization().binding_signature().sig(),
        ));
        if format.includes_anchor_in_authorizing_digest() {
            h.update(&bundle.anchor().to_bytes());
        }
        Ok(h.finalize())
    }

    /// Accepts the plaintext if its lead byte matches the expected version's
    /// lead byte, and records the note with that version.
    fn parse_note_version(expected: NoteVersion, plaintext: &[u8]) -> Option<NoteVersion> {
        (plaintext.first().copied() == Some(expected.lead_byte())).then_some(expected)
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
        flavor::OrchardVanilla,
        keys::{
            DiversifiedTransmissionKey, Diversifier, EphemeralSecretKey, IncomingViewingKey,
            OutgoingViewingKey, PreparedIncomingViewingKey,
        },
        note::{
            testing::arb_zatoshi_note, AssetBase, ExtractedNoteCommitment, Note, NoteVersion,
            Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext,
        },
        primitives::{
            compact_action::CompactAction,
            orchard_domain::{IronwoodDomain, OrchardDomain},
            redpallas,
            zcash_note_encryption_domain::{parse_note_plaintext_without_memo, prf_ock_orchard},
            OrchardPrimitives,
        },
        value::{NoteValue, ValueCommitment},
    };

    type OrchardDomainVanilla = OrchardDomain<OrchardVanilla>;

    proptest! {
        #[test]
        fn encoding_roundtrip(
            note in arb_zatoshi_note(),
        ) {
            let memo = &crate::test_vectors::note_encryption_vanilla::TEST_VECTORS[0].memo;
            let rho = note.rho();

            // Encode.
            let plaintext = OrchardDomainVanilla::note_plaintext_bytes(&note, memo);

            // Decode.
            let domain = OrchardDomainVanilla::for_rho(rho);
            let (compact, parsed_memo) = domain.split_plaintext_at_memo(&plaintext).unwrap();

            assert!(<OrchardVanilla as OrchardPrimitives>::parse_note_version(
                NoteVersion::V2,
                compact.as_ref()
            )
            .is_some());

            let (parsed_note, parsed_recipient) = parse_note_plaintext_without_memo::<OrchardVanilla, _>(rho, &compact,
                NoteVersion::V2,
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
        let test_vectors = crate::test_vectors::note_encryption_vanilla::TEST_VECTORS;

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

            let asset = AssetBase::zatoshi();

            let note =
                Note::from_parts(recipient, value, asset, rho, rseed, NoteVersion::V2).unwrap();
            assert_eq!(ExtractedNoteCommitment::from(note.commitment()), cmx);

            let action = Action::from_parts(
                // nf_old is the nullifier revealed by the receiving Action.
                nf_old,
                // We don't need a real rk for this test.
                redpallas::VerificationKey::dummy(),
                cmx,
                TransmittedNoteCiphertext::<OrchardVanilla> {
                    epk_bytes: ephemeral_key.0,
                    enc_ciphertext: NoteBytesData(tv.c_enc),
                    out_ciphertext: tv.c_out,
                },
                cv_net.clone(),
                (),
            ).expect("a key returned by VerificationKey::dummy() is vanishingly unlikely to be the identity");

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            let domain = OrchardDomainVanilla::for_rho(rho);

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

            let ne = zcash_note_encryption::NoteEncryption::<OrchardDomainVanilla>::new_with_esk(
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

    /// Builds a V3 (Ironwood, ZIP 2005) note encrypted with the vanilla note
    /// plaintext format, for exercising the version-policy domains.
    fn v3_encrypted_action() -> (
        Action<(), OrchardVanilla>,
        PreparedIncomingViewingKey,
        Note,
        Address,
        [u8; 512],
    ) {
        use crate::keys::{Scope, SpendingKey};

        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let incoming_viewing_key = fvk.to_ivk(Scope::External);
        let prepared_ivk = PreparedIncomingViewingKey::new(&incoming_viewing_key);
        let recipient = fvk.address_at(0u32, Scope::External);
        let nf_old = Nullifier::dummy(&mut rng);
        let rho = Rho::from_nf_old(nf_old);
        let note = Note::new(
            recipient,
            NoteValue::from_raw(5),
            AssetBase::zatoshi(),
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let memo = [7u8; 512];
        let cv_net = ValueCommitment::derive(
            crate::value::ValueSum::from_raw_inner(5),
            crate::value::ValueCommitTrapdoor::zero(),
            AssetBase::zatoshi(),
        );
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let encryptor = zcash_note_encryption::NoteEncryption::<IronwoodDomain>::new(
            Some(fvk.to_ovk(Scope::External)),
            note,
            memo,
        );
        let encrypted_note = TransmittedNoteCiphertext::<OrchardVanilla> {
            epk_bytes: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng),
        };
        let action = Action::from_parts(
            nf_old,
            redpallas::VerificationKey::dummy(),
            cmx,
            encrypted_note,
            cv_net,
            (),
        )
        .expect("a dummy verification key is unlikely to be the identity");

        (action, prepared_ivk, note, recipient, memo)
    }

    #[test]
    fn domains_accept_only_their_note_plaintext_versions() {
        use crate::keys::Scope;

        let mut rng = OsRng;
        let sk = crate::keys::SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_nf_old(Nullifier::dummy(&mut rng));
        let memo = [0u8; 512];

        let note_v2 = Note::new(
            recipient,
            NoteValue::from_raw(5),
            AssetBase::zatoshi(),
            rho,
            NoteVersion::V2,
            &mut rng,
        );
        let note_v3 = Note::new(
            recipient,
            NoteValue::from_raw(5),
            AssetBase::zatoshi(),
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let orchard_domain = OrchardDomainVanilla::for_rho(rho);
        let ironwood_domain = IronwoodDomain::for_rho(rho);

        let np_v2 = OrchardDomainVanilla::note_plaintext_bytes(&note_v2, &memo);
        let np_v3 = IronwoodDomain::note_plaintext_bytes(&note_v3, &memo);
        let pk_d = recipient.pk_d();

        assert_eq!(
            orchard_domain
                .parse_note_plaintext_without_memo_ovk(
                    pk_d,
                    &orchard_domain.split_plaintext_at_memo(&np_v2).unwrap().0
                )
                .map(|(note, _)| note),
            Some(note_v2)
        );
        assert_eq!(
            ironwood_domain
                .parse_note_plaintext_without_memo_ovk(
                    pk_d,
                    &ironwood_domain.split_plaintext_at_memo(&np_v3).unwrap().0
                )
                .map(|(note, _)| note),
            Some(note_v3)
        );
        assert!(orchard_domain
            .parse_note_plaintext_without_memo_ovk(
                pk_d,
                &orchard_domain.split_plaintext_at_memo(&np_v3).unwrap().0
            )
            .is_none());
        assert!(ironwood_domain
            .parse_note_plaintext_without_memo_ovk(
                pk_d,
                &ironwood_domain.split_plaintext_at_memo(&np_v2).unwrap().0
            )
            .is_none());
    }

    #[test]
    fn ironwood_domain_decrypts_v3_encrypted_outputs() {
        let (action, ivk, note, recipient, memo) = v3_encrypted_action();
        let domain = IronwoodDomain::for_action(&action);

        assert_eq!(
            try_note_decryption(&domain, &ivk, &action),
            Some((note, recipient, memo))
        );
    }

    #[test]
    fn orchard_domain_rejects_v3_encrypted_outputs() {
        let (action, ivk, _, _, _) = v3_encrypted_action();
        let domain = OrchardDomainVanilla::for_action(&action);

        assert!(try_note_decryption(&domain, &ivk, &action).is_none());
    }

    #[test]
    fn ironwood_domain_decrypts_v3_compact_outputs() {
        let (action, ivk, note, recipient, _) = v3_encrypted_action();
        let domain = IronwoodDomain::for_action(&action);
        let compact = CompactAction::from(&action);

        assert_eq!(
            try_compact_note_decryption(&domain, &ivk, &compact),
            Some((note, recipient))
        );
    }
}
