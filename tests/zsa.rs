#![cfg(all(feature = "zsa-issuance", feature = "circuit"))]

mod builder;
mod common;

use crate::builder::verify_bundle;
use crate::common::{
    Keychain, TestOutputInfo, TestSpendInfo, issue_zsa_notes, verify_reference_note,
    create_zatoshi_note, prepare_keys,
};

use orchard::{
    builder::{BuildError, Builder, BundleType},
    bundle::{burn_validation::BurnError, Authorized, Bundle},
    circuit::{ProvingKey, VerifyingKey},
    flavor::OrchardZSA,
    keys::{SpendAuthorizingKey, SpendingKey},
    note::AssetBase,
    value::NoteValue,
    Anchor,
};
use rand::rngs::OsRng;

fn build_and_sign_bundle(
    builder: Builder,
    mut rng: OsRng,
    pk: &ProvingKey,
    sk: &SpendingKey,
) -> Bundle<Authorized, i64, OrchardZSA> {
    let (unauthorized, value_balance, _) =
        builder.build::<i64, OrchardZSA>(&mut rng).unwrap().unwrap();
    let sighash = Bundle::from_parts(vec![unauthorized.clone()], value_balance, None)
        .commitment()
        .into();
    let proven = unauthorized.create_proof(pk, &mut rng).unwrap();
    let action_group = proven
        .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(sk)])
        .unwrap();
    let binding_sig = action_group.authorization().binding_signature();

    Bundle::from_parts(
        vec![action_group.clone()],
        value_balance,
        Some(binding_sig.clone()),
    )
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
                builder.add_output(
                    None,
                    output.recipient,
                    output.value,
                    output.asset,
                    [0u8; 512],
                )
            })
            .map_err(|err| err.to_string())?;
        assets_to_burn
            .into_iter()
            .try_for_each(|(asset, value)| builder.add_burn(asset, value))
            .map_err(|err| err.to_string())?;
        build_and_sign_bundle(builder, rng, keys.pk(), keys.sk())
    };

    // Verify the shielded bundle, currently without the proof.
    verify_bundle(&shielded_bundle, keys.vk(), true);
    assert_eq!(
        shielded_bundle
            .action_groups()
            .first()
            .unwrap()
            .actions()
            .len(),
        expected_num_actions
    );
    assert!(common::verify_unique_spent_nullifiers(
        shielded_bundle.action_groups().first().unwrap()
    ));
    Ok(())
}

/// Issue several ZSA and zatoshi notes and spend them in different combinations, e.g. split and join
#[test]
fn zsa_issue_and_transfer() {
    // --------------------------- Setup -----------------------------------------

    let pk = ProvingKey::build::<OrchardZSA>();
    let vk = VerifyingKey::build::<OrchardZSA>();

    let keys = prepare_keys(&pk, &vk, 5);
    let keys2 = prepare_keys(&pk, &vk, 10);
    let keys3 = prepare_keys(&pk, &vk, 15);

    let zatoshi_note = create_zatoshi_note(&keys);

    // Prepare ZSA
    let (reference_note, zsa_note1_asset1, zsa_note2_asset1) =
        issue_zsa_notes(b"zsa_asset", &keys, &zatoshi_note.nullifier(keys.fvk()));
    verify_reference_note(&reference_note, zsa_note1_asset1.asset());

    let (reference_note_asset2, zsa_note_asset2, _) =
        issue_zsa_notes(b"zsa_asset2", &keys, &zatoshi_note.nullifier(keys.fvk()));
    verify_reference_note(&reference_note_asset2, zsa_note_asset2.asset());

    let asset1 = zsa_note1_asset1.asset();
    let asset2 = zsa_note_asset2.asset();

    // Create Merkle tree
    let (merkle_paths, anchor) = common::build_merkle_paths(vec![
        &zsa_note1_asset1,
        &zsa_note2_asset1,
        &zatoshi_note,
        &zsa_note_asset2,
    ]);

    let zsa_spend1_asset1 = TestSpendInfo {
        note: zsa_note1_asset1,
        merkle_path: merkle_paths.first().unwrap().clone(),
    };
    let zsa_spend2_asset1 = TestSpendInfo {
        note: zsa_note2_asset1,
        merkle_path: merkle_paths.get(1).unwrap().clone(),
    };
    let zatoshi_spend: TestSpendInfo = TestSpendInfo {
        note: zatoshi_note,
        merkle_path: merkle_paths.get(2).unwrap().clone(),
    };
    let zsa_spend_asset2 = TestSpendInfo {
        note: zsa_note_asset2,
        merkle_path: merkle_paths.get(3).unwrap().clone(),
    };

    // --------------------------- Tests -----------------------------------------

    // 1. Spend single ZSA note
    build_and_verify_bundle(
        vec![&zsa_spend1_asset1],
        vec![TestOutputInfo {
            value: zsa_spend1_asset1.note.value(),
            asset: asset1,
            recipient: *keys2.recipient(),
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
        vec![&zsa_spend1_asset1],
        vec![
            TestOutputInfo {
                value: NoteValue::from_raw(
                    zsa_spend1_asset1.note.value().inner() - delta_1 - delta_2,
                ),
                asset: asset1,
                recipient: *keys.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_1),
                asset: asset1,
                recipient: *keys2.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_2),
                asset: asset1,
                recipient: *keys3.recipient(),
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
        vec![&zsa_spend1_asset1, &zsa_spend2_asset1],
        vec![TestOutputInfo {
            value: NoteValue::from_raw(
                zsa_spend1_asset1.note.value().inner() + zsa_spend2_asset1.note.value().inner(),
            ),
            asset: asset1,
            recipient: *keys2.recipient(),
        }],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 4. Take 2 ZSA notes and send them as 2 notes with different denomination
    build_and_verify_bundle(
        vec![&zsa_spend1_asset1, &zsa_spend2_asset1],
        vec![
            TestOutputInfo {
                value: NoteValue::from_raw(zsa_spend1_asset1.note.value().inner() - delta_1),
                asset: asset1,
                recipient: *keys2.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(zsa_spend2_asset1.note.value().inner() + delta_1),
                asset: asset1,
                recipient: *keys.recipient(),
            },
        ],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 5. Spend single ZSA note, mixed with zatoshi note (shielding)
    build_and_verify_bundle(
        vec![&zsa_spend1_asset1],
        vec![
            TestOutputInfo {
                value: zsa_spend1_asset1.note.value(),
                asset: asset1,
                recipient: *keys2.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(100),
                asset: AssetBase::zatoshi(),
                recipient: *keys2.recipient(),
            },
        ],
        vec![],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 6. Spend single ZSA note, mixed with zatoshi note (shielded to shielded)
    build_and_verify_bundle(
        vec![&zsa_spend1_asset1, &zatoshi_spend],
        vec![
            TestOutputInfo {
                value: zsa_spend1_asset1.note.value(),
                asset: asset1,
                recipient: *keys2.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(zatoshi_spend.note.value().inner() - delta_1 - delta_2),
                asset: AssetBase::zatoshi(),
                recipient: *keys.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_1),
                asset: AssetBase::zatoshi(),
                recipient: *keys2.recipient(),
            },
            TestOutputInfo {
                value: NoteValue::from_raw(delta_2),
                asset: AssetBase::zatoshi(),
                recipient: *keys3.recipient(),
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
        vec![&zsa_spend_asset2, &zsa_spend2_asset1],
        vec![
            TestOutputInfo {
                value: zsa_spend_asset2.note.value(),
                asset: asset2,
                recipient: *keys2.recipient(),
            },
            TestOutputInfo {
                value: zsa_spend2_asset1.note.value(),
                asset: asset1,
                recipient: *keys2.recipient(),
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
            vec![&zsa_spend_asset2, &zsa_spend2_asset1],
            vec![
                TestOutputInfo {
                    value: NoteValue::from_raw(zsa_spend_asset2.note.value().inner() + delta_1),
                    asset: asset2,
                    recipient: *keys2.recipient(),
                },
                TestOutputInfo {
                    value: NoteValue::from_raw(zsa_spend2_asset1.note.value().inner() - delta_1),
                    asset: asset1,
                    recipient: *keys2.recipient(),
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
        vec![&zsa_spend1_asset1],
        vec![],
        vec![(asset1, zsa_spend1_asset1.note.value())],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 10. Burn a partial amount of the ZSA assets
    let value_to_burn = 3;
    let value_to_transfer = zsa_spend1_asset1.note.value().inner() - value_to_burn;

    build_and_verify_bundle(
        vec![&zsa_spend1_asset1],
        vec![TestOutputInfo {
            value: NoteValue::from_raw(value_to_transfer),
            asset: asset1,
            recipient: *keys.recipient(),
        }],
        vec![(
            zsa_spend1_asset1.note.asset(),
            NoteValue::from_raw(value_to_burn),
        )],
        anchor,
        2,
        &keys,
    )
    .unwrap();

    // 11. Try to burn zatoshi asset - should fail
    let result = build_and_verify_bundle(
        vec![&zatoshi_spend],
        vec![],
        vec![(AssetBase::zatoshi(), zatoshi_spend.note.value())],
        anchor,
        2,
        &keys,
    );
    match result {
        Ok(_) => panic!("Test should fail"),
        Err(error) => assert_eq!(error, BuildError::Burn(BurnError::ZatoshiAsset).to_string()),
    }

    // 12. Try to burn zero value - should fail
    let result = build_and_verify_bundle(
        vec![&zsa_spend1_asset1],
        vec![TestOutputInfo {
            value: zsa_spend1_asset1.note.value(),
            asset: asset1,
            recipient: *keys.recipient(),
        }],
        vec![(asset1, NoteValue::from_raw(0))],
        anchor,
        2,
        &keys,
    );
    match result {
        Ok(_) => panic!("Test should fail"),
        Err(error) => assert_eq!(error, BuildError::Burn(BurnError::ZeroAmount).to_string()),
    }
}
