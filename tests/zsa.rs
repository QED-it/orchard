mod builder;

use crate::builder::verify_bundle;
use bridgetree::BridgeTree;
use incrementalmerkletree::Hashable;
use orchard::bundle::Authorized;
use orchard::issuance::{verify_issue_bundle, IssueBundle, IssueInfo, Signed, Unauthorized};
use orchard::keys::{IssuanceAuthorizingKey, IssuanceValidatingKey};
use orchard::note::{AssetBase, ExtractedNoteCommitment, Nullifier};

use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::{
    builder::{Builder, BundleType},
    circuit::{ProvingKey, VerifyingKey},
    domain::OrchardDomain,
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    orchard_flavor::OrchardZSA,
    value::NoteValue,
    Address, Anchor, Bundle, Note,
};
use rand::rngs::OsRng;
use std::collections::HashSet;
use zcash_note_encryption_zsa::try_note_decryption;

#[derive(Debug)]
struct Keychain {
    pk: ProvingKey,
    vk: VerifyingKey,
    sk: SpendingKey,
    fvk: FullViewingKey,
    isk: IssuanceAuthorizingKey,
    ik: IssuanceValidatingKey,
    recipient: Address,
}

impl Keychain {
    fn pk(&self) -> &ProvingKey {
        &self.pk
    }
    fn sk(&self) -> &SpendingKey {
        &self.sk
    }
    fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }
    fn isk(&self) -> &IssuanceAuthorizingKey {
        &self.isk
    }
    fn ik(&self) -> &IssuanceValidatingKey {
        &self.ik
    }
}

fn prepare_keys(seed: u8) -> Keychain {
    // FIXME: consider adding test for OrchardDomainVanilla as well
    let pk = ProvingKey::build::<OrchardZSA>();
    let vk = VerifyingKey::build::<OrchardZSA>();

    let sk = SpendingKey::from_bytes([seed; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    let isk = IssuanceAuthorizingKey::from_bytes([seed + 1; 32]).unwrap();
    let ik = IssuanceValidatingKey::from(&isk);
    Keychain {
        pk,
        vk,
        sk,
        fvk,
        isk,
        ik,
        recipient,
    }
}

fn sign_issue_bundle(
    unauthorized: IssueBundle<Unauthorized>,
    isk: &IssuanceAuthorizingKey,
) -> IssueBundle<Signed> {
    let sighash = unauthorized.commitment().into();
    let proven = unauthorized.prepare(sighash);
    proven.sign(isk).unwrap()
}

fn build_and_sign_bundle(
    builder: Builder,
    mut rng: OsRng,
    pk: &ProvingKey,
    sk: &SpendingKey,
) -> Bundle<Authorized, i64, OrchardZSA> {
    let unauthorized = builder.build(&mut rng).unwrap().0;
    let sighash = unauthorized.commitment().into();
    let proven = unauthorized.create_proof(pk, &mut rng).unwrap();
    proven
        .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(sk)])
        .unwrap()
}

fn build_merkle_paths(notes: Vec<&Note>) -> (Vec<MerklePath>, Anchor) {
    let mut tree = BridgeTree::<MerkleHashOrchard, u32, 32>::new(100);

    let mut commitments = vec![];
    let mut positions = vec![];

    // Add leaves
    for note in notes {
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        commitments.push(cmx);
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        tree.append(leaf);
        positions.push(tree.mark().unwrap());
    }

    let root = tree.root(0).unwrap();
    let anchor = root.into();

    // Calculate paths
    let mut merkle_paths = vec![];
    for (position, commitment) in positions.iter().zip(commitments.iter()) {
        let auth_path = tree.witness(*position, 0).unwrap();
        let merkle_path = MerklePath::from_parts(
            u64::from(*position).try_into().unwrap(),
            auth_path[..].try_into().unwrap(),
        );
        merkle_paths.push(merkle_path.clone());
        assert_eq!(anchor, merkle_path.root(*commitment));
    }

    (merkle_paths, anchor)
}

fn issue_zsa_notes(
    asset_descr: &[u8],
    keys: &Keychain,
    first_nullifier: Nullifier,
) -> (Note, Note, Note) {
    let mut rng = OsRng;
    // Create a issuance bundle
    let unauthorized_asset = IssueBundle::new(
        keys.ik().clone(),
        asset_descr.to_owned(),
        Some(IssueInfo {
            recipient: keys.recipient,
            value: NoteValue::from_raw(40),
        }),
        true,
        first_nullifier,
        &mut rng,
    );

    assert!(unauthorized_asset.is_ok());

    let (mut unauthorized, _) = unauthorized_asset.unwrap();

    assert!(unauthorized
        .add_recipient(
            asset_descr,
            keys.recipient,
            NoteValue::from_raw(2),
            false,
            &mut rng,
        )
        .is_ok());

    let issue_bundle = sign_issue_bundle(unauthorized, keys.isk());

    // Take notes from first action
    let notes = issue_bundle.get_all_notes();
    let reference_note = notes[0];
    let note1 = notes[1];
    let note2 = notes[2];

    verify_reference_note(
        reference_note,
        AssetBase::derive(&keys.ik().clone(), asset_descr),
    );

    assert!(verify_issue_bundle(
        &issue_bundle,
        issue_bundle.commitment().into(),
        &HashSet::new(),
    )
    .is_ok());

    (*reference_note, *note1, *note2)
}

fn create_native_note(keys: &Keychain) -> Note {
    let mut rng = OsRng;

    let shielding_bundle: Bundle<_, i64, OrchardZSA> = {
        // Use the empty tree.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new(BundleType::Coinbase, anchor);
        assert_eq!(
            builder.add_output(
                None,
                keys.recipient,
                NoteValue::from_raw(100),
                AssetBase::native(),
                None
            ),
            Ok(())
        );
        let unauthorized = builder.build(&mut rng).unwrap().0;
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(keys.pk(), &mut rng).unwrap();
        proven.apply_signatures(rng, sighash, &[]).unwrap()
    };
    let ivk = keys.fvk().to_ivk(Scope::External);
    let (native_note, _, _) = shielding_bundle
        .actions()
        .iter()
        .find_map(|action| {
            let domain = OrchardDomain::for_action(action);
            try_note_decryption(&domain, &PreparedIncomingViewingKey::new(&ivk), action)
        })
        .unwrap();

    native_note
}

struct TestSpendInfo {
    note: Note,
    merkle_path: MerklePath,
}

impl TestSpendInfo {
    fn merkle_path(&self) -> &MerklePath {
        &self.merkle_path
    }
}

struct TestOutputInfo {
    value: NoteValue,
    asset: AssetBase,
    recipient: Address,
}

fn build_and_verify_bundle(
    spends: Vec<&TestSpendInfo>,
    outputs: Vec<TestOutputInfo>,
    assets_to_burn: Vec<(AssetBase, NoteValue)>,
    anchor: Anchor,
    expected_num_actions: usize,
    keys: &Keychain,
) -> Result<(), String> {
    let rng = OsRng;
    let shielded_bundle: Bundle<_, i64, OrchardZSA> = {
        let mut builder = Builder::new(BundleType::DEFAULT_ZSA, anchor);

        spends
            .iter()
            .try_for_each(|spend| {
                builder.add_spend(keys.fvk().clone(), spend.note, spend.merkle_path().clone())
            })
            .map_err(|err| err.to_string())?;
        outputs
            .iter()
            .try_for_each(|output| {
                builder.add_output(None, output.recipient, output.value, output.asset, None)
            })
            .map_err(|err| err.to_string())?;
        assets_to_burn
            .into_iter()
            .try_for_each(|(asset, value)| builder.add_burn(asset, value))
            .map_err(|err| err.to_string())?;
        build_and_sign_bundle(builder, rng, keys.pk(), keys.sk())
    };

    // Verify the shielded bundle, currently without the proof.
    verify_bundle(&shielded_bundle, &keys.vk, true);
    assert_eq!(shielded_bundle.actions().len(), expected_num_actions);
    assert!(verify_unique_spent_nullifiers(&shielded_bundle));
    Ok(())
}

fn verify_unique_spent_nullifiers(bundle: &Bundle<Authorized, i64, OrchardZSA>) -> bool {
    let mut unique_nulifiers = Vec::new();
    let spent_nullifiers = bundle
        .actions()
        .iter()
        .map(|action| *action.nullifier())
        .collect::<Vec<_>>();
    spent_nullifiers.iter().enumerate().all(|(i, item)| {
        unique_nulifiers.push(*item);
        // Check if the item is already in the unique_nullifiers vector by checking that the first
        // position of the item is equal to the current index i.
        unique_nulifiers.iter().position(|x| x == item) == Some(i)
    })
}

/// Validation for reference note
///
/// The following checks are performed:
/// - the note value of the reference note is equal to 0
/// - the asset of the reference note is equal to the provided asset
/// - the recipient of the reference note is equal to the reference recipient
fn verify_reference_note(note: &Note, asset: AssetBase) {
    let reference_sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let reference_fvk = FullViewingKey::from(&reference_sk);
    let reference_recipient = reference_fvk.address_at(0u32, Scope::External);
    assert_eq!(note.value(), NoteValue::from_raw(0));
    assert_eq!(note.asset(), asset);
    assert_eq!(note.recipient(), reference_recipient);
}

/// Issue several ZSA and native notes and spend them in different combinations, e.g. split and join
#[test]
fn zsa_issue_and_transfer() {
    // --------------------------- Setup -----------------------------------------

    let keys = prepare_keys(5);
    let keys2 = prepare_keys(10);
    let keys3 = prepare_keys(15);

    let native_note: Note = create_native_note(&keys);

    // Prepare ZSA
    let asset_descr = b"zsa_asset".to_vec();

    let (reference_note, zsa_note_1, zsa_note_2) =
        issue_zsa_notes(&asset_descr, &keys, native_note.nullifier(keys.fvk()));
    verify_reference_note(&reference_note, zsa_note_1.asset());

    let (reference_note, zsa_note_t7, _) =
        issue_zsa_notes(b"zsa_asset2", &keys, native_note.nullifier(keys.fvk()));
    verify_reference_note(&reference_note, zsa_note_t7.asset());

    let (merkle_paths, anchor) =
        build_merkle_paths(vec![&zsa_note_1, &zsa_note_2, &zsa_note_t7, &native_note]);
    let merkle_path1 = merkle_paths[0].clone();
    let merkle_path2 = merkle_paths[1].clone();
    let merkle_path_t7 = merkle_paths[2].clone();
    let native_merkle_path = merkle_paths[3].clone();

    let zsa_spend_1 = TestSpendInfo {
        note: zsa_note_1,
        merkle_path: merkle_path1,
    };
    let zsa_spend_2 = TestSpendInfo {
        note: zsa_note_2,
        merkle_path: merkle_path2,
    };
    let zsa_spend_t7: TestSpendInfo = TestSpendInfo {
        note: zsa_note_t7,
        merkle_path: merkle_path_t7,
    };
    let native_spend: TestSpendInfo = TestSpendInfo {
        note: native_note,
        merkle_path: native_merkle_path,
    };

    // --------------------------- Tests -----------------------------------------

    // 1. Spend single ZSA note
    build_and_verify_bundle(
        vec![&zsa_spend_1],
        vec![TestOutputInfo {
            value: zsa_spend_1.note.value(),
            asset: zsa_spend_1.note.asset(),
            recipient: keys2.recipient,
        }],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 2. Split single ZSA note into 3 notes
    let delta_1 = 2; // arbitrary number for value manipulation
    let delta_2 = 5; // arbitrary number for value manipulation
    build_and_verify_bundle(
        vec![&zsa_spend_1],
        vec![
            TestOutputInfo {
                value: NoteValue::from_raw(zsa_spend_1.note.value().inner() - delta_1 - delta_2),
                asset: zsa_spend_1.note.asset(),
                recipient: keys.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_1),
                asset: zsa_spend_1.note.asset(),
                recipient: keys2.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_2),
                asset: zsa_spend_1.note.asset(),
                recipient: keys3.recipient,
            },
        ],
        vec![],
        anchor,
        3,
        &keys,
    )
    .unwrap();

    // 3. Join 2 ZSA notes into a single note
    build_and_verify_bundle(
        vec![&zsa_spend_1, &zsa_spend_2],
        vec![TestOutputInfo {
            value: NoteValue::from_raw(
                zsa_spend_1.note.value().inner() + zsa_spend_2.note.value().inner(),
            ),
            asset: zsa_spend_1.note.asset(),
            recipient: keys2.recipient,
        }],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 4. Take 2 ZSA notes and send them as 2 notes with different denomination
    build_and_verify_bundle(
        vec![&zsa_spend_1, &zsa_spend_2],
        vec![
            TestOutputInfo {
                value: NoteValue::from_raw(zsa_spend_1.note.value().inner() - delta_1),
                asset: zsa_spend_1.note.asset(),
                recipient: keys2.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(zsa_spend_2.note.value().inner() + delta_1),
                asset: zsa_spend_2.note.asset(),
                recipient: keys.recipient,
            },
        ],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 5. Spend single ZSA note, mixed with native note (shielding)
    build_and_verify_bundle(
        vec![&zsa_spend_1],
        vec![
            TestOutputInfo {
                value: zsa_spend_1.note.value(),
                asset: zsa_spend_1.note.asset(),
                recipient: keys2.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(100),
                asset: AssetBase::native(),
                recipient: keys2.recipient,
            },
        ],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 6. Spend single ZSA note, mixed with native note (shielded to shielded)
    build_and_verify_bundle(
        vec![&zsa_spend_1, &native_spend],
        vec![
            TestOutputInfo {
                value: zsa_spend_1.note.value(),
                asset: zsa_spend_1.note.asset(),
                recipient: keys2.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(native_spend.note.value().inner() - delta_1 - delta_2),
                asset: AssetBase::native(),
                recipient: keys.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_1),
                asset: AssetBase::native(),
                recipient: keys2.recipient,
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_2),
                asset: AssetBase::native(),
                recipient: keys3.recipient,
            },
        ],
        vec![],
        anchor,
        4,
        &keys,
    )
    .unwrap();

    // 7. Spend ZSA notes of different asset types
    build_and_verify_bundle(
        vec![&zsa_spend_t7, &zsa_spend_2],
        vec![
            TestOutputInfo {
                value: zsa_spend_t7.note.value(),
                asset: zsa_spend_t7.note.asset(),
                recipient: keys2.recipient,
            },
            TestOutputInfo {
                value: zsa_spend_2.note.value(),
                asset: zsa_spend_2.note.asset(),
                recipient: keys2.recipient,
            },
        ],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 8. Same but wrong denomination
    let result = std::panic::catch_unwind(|| {
        build_and_verify_bundle(
            vec![&zsa_spend_t7, &zsa_spend_2],
            vec![
                TestOutputInfo {
                    value: NoteValue::from_raw(zsa_spend_t7.note.value().inner() + delta_1),
                    asset: zsa_spend_t7.note.asset(),
                    recipient: keys2.recipient,
                },
                TestOutputInfo {
                    value: NoteValue::from_raw(zsa_spend_2.note.value().inner() - delta_1),
                    asset: zsa_spend_2.note.asset(),
                    recipient: keys2.recipient,
                },
            ],
            vec![],
            anchor,
            2,
            &keys,
        )
        .unwrap();
    });
    assert!(result.is_err());

    // 9. Burn ZSA assets
    build_and_verify_bundle(
        vec![&zsa_spend_1],
        vec![],
        vec![(zsa_spend_1.note.asset(), zsa_spend_1.note.value())],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 10. Burn a partial amount of the ZSA assets
    let value_to_burn = 3;
    let value_to_transfer = zsa_spend_1.note.value().inner() - value_to_burn;

    build_and_verify_bundle(
        vec![&zsa_spend_1],
        vec![TestOutputInfo {
            value: NoteValue::from_raw(value_to_transfer),
            asset: zsa_spend_1.note.asset(),
            recipient: keys.recipient,
        }],
        vec![(zsa_spend_1.note.asset(), NoteValue::from_raw(value_to_burn))],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 11. Try to burn native asset - should fail
    let result = build_and_verify_bundle(
        vec![&native_spend],
        vec![],
        vec![(AssetBase::native(), native_spend.note.value())],
        anchor,
        2,
        &keys,
    );
    match result {
        Ok(_) => panic!("Test should fail"),
        Err(error) => assert_eq!(error, "Burning is only possible for non-native assets"),
    }

    // 12. Try to burn zero value - should fail
    let result = build_and_verify_bundle(
        vec![&zsa_spend_1],
        vec![TestOutputInfo {
            value: zsa_spend_1.note.value(),
            asset: zsa_spend_1.note.asset(),
            recipient: keys.recipient,
        }],
        vec![(zsa_spend_1.note.asset(), NoteValue::from_raw(0))],
        anchor,
        2,
        &keys,
    );
    match result {
        Ok(_) => panic!("Test should fail"),
        Err(error) => assert_eq!(error, "Burning is not possible for zero values"),
    }
}
