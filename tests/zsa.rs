mod builder;

use crate::builder::{build_merkle_tree, verify_bundle};
use incrementalmerkletree::bridgetree::BridgeTree;
use incrementalmerkletree::{Hashable, Tree};
use orchard::builder::{InProgress, Unproven};
use orchard::bundle::Authorized;
use orchard::issuance::{IssueBundle, Signed, Unauthorized};
use orchard::keys::{IssuerAuthorizingKey, IssuerValidatingKey};
use orchard::note::{ExtractedNoteCommitment, NoteType};
use orchard::note_encryption::OrchardDomain;
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::{
    builder::Builder,
    bundle::Flags,
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    value::NoteValue,
    Address, Anchor, Bundle, Note,
};
use rand::rngs::OsRng;
use zcash_note_encryption::try_note_decryption;

fn verify_issuing_bundle(bundle: &IssueBundle<Signed>) {
    let sighash: [u8; 32] = bundle.commitment().into();
    assert_eq!(
        bundle
            .ik()
            .verify(&sighash, bundle.authorization().signature()),
        Ok(())
    );
}

fn prepare_keys() -> (
    ProvingKey,
    VerifyingKey,
    SpendingKey,
    FullViewingKey,
    Address,
    IssuerAuthorizingKey,
    IssuerValidatingKey,
) {
    let pk = ProvingKey::build();
    let vk = VerifyingKey::build();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    let isk = IssuerAuthorizingKey::from(&sk);
    let ik = IssuerValidatingKey::from(&isk);
    (pk, vk, sk, fvk, recipient, isk, ik)
}

fn sign_issuing_bundle(
    unauthorized: IssueBundle<Unauthorized>,
    mut rng: OsRng,
    isk: IssuerAuthorizingKey,
) -> IssueBundle<Signed> {
    let sighash = unauthorized.commitment().into();
    let proven = unauthorized.prepare(sighash);
    proven.sign(&mut rng, &isk).unwrap()
}

fn sign_shielded_bundle(
    builder: Builder,
    mut rng: OsRng,
    pk: ProvingKey,
    sk: SpendingKey,
) -> Bundle<Authorized, i64> {
    let unauthorized = builder.build(&mut rng).unwrap();
    let sighash = unauthorized.commitment().into();
    let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
    proven
        .apply_signatures(&mut rng, sighash, &[SpendAuthorizingKey::from(&sk)])
        .unwrap()
}

pub fn build_merkle_tree_2_leaves(note1: &Note, note2: &Note) -> (MerklePath, MerklePath, Anchor) {
    let mut tree = BridgeTree::<MerkleHashOrchard, 32>::new(0);

    // Add first leaf
    let cmx1: ExtractedNoteCommitment = note1.commitment().into();
    let leaf1 = MerkleHashOrchard::from_cmx(&cmx1);
    tree.append(&leaf1);
    let position1 = tree.witness().unwrap();

    // Add second leaf
    let cmx2: ExtractedNoteCommitment = note2.commitment().into();
    let leaf2 = MerkleHashOrchard::from_cmx(&cmx2);
    tree.append(&leaf2);
    let position2 = tree.witness().unwrap();

    let root = tree.root(0).unwrap();
    let anchor = root.into();

    // Calculate first path
    let auth_path1 = tree.authentication_path(position1, &root).unwrap();
    let merkle_path1 = MerklePath::from_parts(
        u64::from(position1).try_into().unwrap(),
        auth_path1[..].try_into().unwrap(),
    );

    // Calculate second path
    let auth_path2 = tree.authentication_path(position2, &root).unwrap();
    let merkle_path2 = MerklePath::from_parts(
        u64::from(position2).try_into().unwrap(),
        auth_path2[..].try_into().unwrap(),
    );

    assert_eq!(anchor, merkle_path1.root(cmx1));
    assert_eq!(anchor, merkle_path2.root(cmx2));
    (merkle_path1, merkle_path2, anchor)
}

/// Issue single ZSA note and spend it
#[test]
fn e2e_1zsa_to_1zsa() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr = "zsa_asset";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add output ZSA note
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(50),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    // Take first note from first action
    let note = issuing_bundle.actions().first().unwrap().notes().first();

    let (merkle_path, anchor) = build_merkle_tree(note);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add single ZSA spend
        assert_eq!(builder.add_spend(fvk, *note, merkle_path), Ok(()));
        // and single ZSA output
        assert_eq!(
            builder.add_recipient(None, recipient, note.value(), note.note_type(), None),
            Ok(())
        );
        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue single ZSA note and split it into 2 notes
#[test]
fn e2e_1zsa_to_2zsa() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr = "zsa_asset";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add output ZSA note
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(42),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    // Take first note from first action
    let note = issuing_bundle.actions().first().unwrap().notes().first();

    let (merkle_path, anchor) = build_merkle_tree(note);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add single ZSA spend
        assert_eq!(builder.add_spend(fvk, *note, merkle_path), Ok(()));
        // and 2 ZSA outputs
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(40),
                note.note_type(),
                None
            ),
            Ok(())
        );
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(2),
                note.note_type(),
                None
            ),
            Ok(())
        );
        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue 2 ZSA notes and join them into a single note
#[test]
fn e2e_2zsa_to_1zsa() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr = "zsa_asset";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add 2 output ZSA notes
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(40),
            false,
            &mut rng,
        )
        .is_ok());
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(2),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    // Take notes from first action
    let note1 = issuing_bundle
        .actions()
        .first()
        .unwrap()
        .notes()
        .get(0)
        .unwrap();
    let note2 = issuing_bundle
        .actions()
        .first()
        .unwrap()
        .notes()
        .get(1)
        .unwrap();

    let (merkle_path1, merkle_path2, anchor) = build_merkle_tree_2_leaves(note1, note2);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add 2 ZSA spends
        assert_eq!(builder.add_spend(fvk.clone(), *note1, merkle_path1), Ok(()));
        assert_eq!(builder.add_spend(fvk, *note2, merkle_path2), Ok(()));
        // and single ZSA output
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(42),
                note1.note_type(),
                None
            ),
            Ok(())
        );
        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue 2 ZSA notes and send them as 2 notes with different denomination
#[test]
fn e2e_2zsa_to_2zsa() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr = "zsa_asset";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add 2 output ZSA notes
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(40),
            false,
            &mut rng,
        )
        .is_ok());
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(2),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    // Take notes from first action
    let note1 = issuing_bundle
        .actions()
        .first()
        .unwrap()
        .notes()
        .get(0)
        .unwrap();
    let note2 = issuing_bundle
        .actions()
        .first()
        .unwrap()
        .notes()
        .get(1)
        .unwrap();

    let (merkle_path1, merkle_path2, anchor) = build_merkle_tree_2_leaves(note1, note2);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add 2 ZSA spends
        assert_eq!(builder.add_spend(fvk.clone(), *note1, merkle_path1), Ok(()));
        assert_eq!(builder.add_spend(fvk, *note2, merkle_path2), Ok(()));
        // and 2 ZSA outputs with different denominations
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(41),
                note1.note_type(),
                None
            ),
            Ok(())
        );
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(1),
                note1.note_type(),
                None
            ),
            Ok(())
        );
        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue single ZSA note and spend it, mixed with native notes (shielding)
#[test]
fn e2e_1zsa_to_1zsa_with_native_shielding() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr = "zsa_asset";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add output ZSA note
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(50),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    // Take first note from first action
    let note = issuing_bundle.actions().first().unwrap().notes().first();

    let (merkle_path, anchor) = build_merkle_tree(note);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add single ZSA spend
        assert_eq!(builder.add_spend(fvk, *note, merkle_path), Ok(()));
        // and single ZSA output
        assert_eq!(
            builder.add_recipient(None, recipient, note.value(), note.note_type(), None),
            Ok(())
        );

        // Add native output
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(100),
                NoteType::native(),
                None
            ),
            Ok(())
        );

        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue single ZSA note and spend it, mixed with native notes (shielded to shielded)
#[test]
fn e2e_1zsa_to_1zsa_with_native_shielded() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr = "zsa_asset";

    // Create a shielding bundle

    let shielding_bundle: Bundle<_, i64> = {
        // Use the empty tree.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new(Flags::from_parts(false, true), anchor);
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(100),
                NoteType::native(),
                None
            ),
            Ok(())
        );
        let unauthorized = builder.build(&mut rng).unwrap();
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        proven.apply_signatures(&mut rng, sighash, &[]).unwrap()
    };
    let ivk = fvk.to_ivk(Scope::External);
    let (native_note, _, _) = shielding_bundle
        .actions()
        .iter()
        .find_map(|action| {
            let domain = OrchardDomain::for_action(action);
            try_note_decryption(&domain, &ivk, action)
        })
        .unwrap();

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add output ZSA note
    assert!(unauthorized
        .add_recipient(
            asset_descr.to_string(),
            recipient,
            NoteValue::from_raw(50),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    // Take first note from first action
    let note = issuing_bundle.actions().first().unwrap().notes().first();

    let (merkle_path, native_merkle_path, anchor) = build_merkle_tree_2_leaves(note, &native_note);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add single ZSA spend
        assert_eq!(builder.add_spend(fvk.clone(), *note, merkle_path), Ok(()));
        // and single ZSA output
        assert_eq!(
            builder.add_recipient(None, recipient, note.value(), note.note_type(), None),
            Ok(())
        );

        // Add native input
        assert_eq!(
            builder.add_spend(fvk, native_note, native_merkle_path),
            Ok(())
        );
        // Add native output
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(100),
                NoteType::native(),
                None
            ),
            Ok(())
        );

        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue 2 ZSA notes of different asset types
#[test]
fn e2e_2zsa_to_2zsa_with_different_types() {
    let mut rng = OsRng;
    let (pk, vk, sk, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr1 = "zsa_asset";
    let asset_descr2 = "zsa_asset2";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add 2 output ZSA notes
    assert!(unauthorized
        .add_recipient(
            asset_descr1.to_string(),
            recipient,
            NoteValue::from_raw(40),
            false,
            &mut rng,
        )
        .is_ok());
    assert!(unauthorized
        .add_recipient(
            asset_descr2.to_string(),
            recipient,
            NoteValue::from_raw(2),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    let note1 = issuing_bundle
        .actions()
        .get(0)
        .unwrap()
        .notes()
        .get(0)
        .unwrap();
    let note2 = issuing_bundle
        .actions()
        .get(1)
        .unwrap()
        .notes()
        .get(0)
        .unwrap();

    let (merkle_path1, merkle_path2, anchor) = build_merkle_tree_2_leaves(note1, note2);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let shielded_bundle: Bundle<_, i64> = {
        let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
        // Add 2 ZSA spends
        assert_eq!(builder.add_spend(fvk.clone(), *note1, merkle_path1), Ok(()));
        assert_eq!(builder.add_spend(fvk, *note2, merkle_path2), Ok(()));
        // and 2 ZSA outputs with different denominations
        assert_eq!(
            builder.add_recipient(None, recipient, note1.value(), note1.note_type(), None),
            Ok(())
        );
        assert_eq!(
            builder.add_recipient(None, recipient, note2.value(), note2.note_type(), None),
            Ok(())
        );
        sign_shielded_bundle(builder, rng, pk, sk)
    };

    // Verify the shielded bundle
    verify_bundle(&shielded_bundle, &vk);
}

/// Issue 2 ZSA notes of different asset types
#[test]
#[should_panic]
fn e2e_2zsa_to_2zsa_with_different_types_wrong_denomination() {
    let mut rng = OsRng;
    let (_, _, _, fvk, recipient, isk, ik) = prepare_keys();
    let asset_descr1 = "zsa_asset";
    let asset_descr2 = "zsa_asset2";

    // Create a issuance bundle
    let mut unauthorized = IssueBundle::new(ik);

    // Add 2 output ZSA notes
    assert!(unauthorized
        .add_recipient(
            asset_descr1.to_string(),
            recipient,
            NoteValue::from_raw(40),
            false,
            &mut rng,
        )
        .is_ok());
    assert!(unauthorized
        .add_recipient(
            asset_descr2.to_string(),
            recipient,
            NoteValue::from_raw(2),
            false,
            &mut rng,
        )
        .is_ok());

    let issuing_bundle = sign_issuing_bundle(unauthorized, rng, isk);

    let note1 = issuing_bundle
        .actions()
        .get(0)
        .unwrap()
        .notes()
        .get(0)
        .unwrap();
    let note2 = issuing_bundle
        .actions()
        .get(1)
        .unwrap()
        .notes()
        .get(0)
        .unwrap();

    let (merkle_path1, merkle_path2, anchor) = build_merkle_tree_2_leaves(note1, note2);

    verify_issuing_bundle(&issuing_bundle);

    // Create a shielded bundle spending the previous output
    let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
    // Add 2 ZSA spends
    assert_eq!(builder.add_spend(fvk.clone(), *note1, merkle_path1), Ok(()));
    assert_eq!(builder.add_spend(fvk, *note2, merkle_path2), Ok(()));
    // and 2 ZSA outputs with different denominations
    assert_eq!(
        builder.add_recipient(
            None,
            recipient,
            NoteValue::from_raw(41),
            note1.note_type(),
            None
        ),
        Ok(())
    );
    assert_eq!(
        builder.add_recipient(
            None,
            recipient,
            NoteValue::from_raw(1),
            note2.note_type(),
            None
        ),
        Ok(())
    );
    let _result: Bundle<InProgress<Unproven, orchard::builder::Unauthorized>, i64> =
        builder.build(&mut rng).unwrap();
}
