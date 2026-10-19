#![cfg(all(feature = "zsa-issuance", feature = "circuit"))]

mod builder;
mod common;

use crate::builder::{verify_swap_bundle, verify_action_group};
use crate::common::{
    Keychain, TestOutputInfo, TestSpendInfo, create_zatoshi_note, issue_zsa_notes, prepare_keys,
    build_merkle_paths, verify_unique_spent_nullifiers,
};

use rand_core::OsRng;
use orchard::{
    Bundle,
    circuit::{ProvingKey, VerifyingKey},
    flavor::OrchardZSA,
    issuance::ReferenceKeys,
    note::AssetBase,
    value::NoteValue,
    ActionGroup, Anchor,
};
use orchard::builder::{Builder, BundleType};
use orchard::bundle::ActionGroupAuthorized;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use orchard::primitives::redpallas::{Binding, SigningKey};

#[derive(Eq, PartialEq, Debug)]
struct TestSwapIO {
    asset: AssetBase,
    quantity: NoteValue,
}

struct TestSwapOrder {
    proposed_input: TestSwapIO,
    desired_output: TestSwapIO,
    bsk: SigningKey<Binding>,
    value_balance: i64,
    action_group: ActionGroup<ActionGroupAuthorized, OrchardZSA>,
}

fn build_and_sign_for_swap(
    builder: Builder,
    timelimit: u32,
    mut rng: OsRng,
    pk: &ProvingKey,
    sk: &SpendingKey,
) -> (
    (
        ActionGroup<ActionGroupAuthorized, OrchardZSA>,
        SigningKey<Binding>,
    ),
    i64,
) {
    let (unauthorized, value_balance, _) = builder
        .build_action_group_check::<i64>(&mut rng, timelimit)
        .unwrap()
        .unwrap();
    let action_group_digest = unauthorized.action_group_commitment().into();
    let proven = unauthorized.create_proof(pk, &mut rng).unwrap();

    (
        proven
            .apply_signatures_for_action_group(
                rng,
                action_group_digest,
                &[SpendAuthorizingKey::from(sk)],
            )
            .unwrap(),
        value_balance,
    )
}

#[allow(clippy::type_complexity)]
fn build_and_verify_action_group(
    spends: Vec<&TestSpendInfo>,
    outputs: Vec<TestOutputInfo>,
    reference_notes: Vec<&TestSpendInfo>,
    anchor: Anchor,
    timelimit: u32,
    expected_num_actions: usize,
    keys: &Keychain,
) -> Result<
    (
        ActionGroup<ActionGroupAuthorized, OrchardZSA>,
        SigningKey<Binding>,
        i64,
    ),
    String,
> {
    let rng = OsRng;
    let ((shielded_action_group, bsk), value_balance) = {
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
                builder.add_output(None, output.recipient, output.value, output.asset, [0; 512])
            })
            .map_err(|err| err.to_string())?;
        reference_notes
            .iter()
            .try_for_each(|spend| {
                builder.add_reference_note(
                    ReferenceKeys::fvk(),
                    spend.note.create_split_note(&mut OsRng),
                    spend.merkle_path().clone(),
                )
            })
            .map_err(|err| err.to_string())?;

        build_and_sign_for_swap(builder, timelimit, rng, keys.pk(), keys.sk())
    };

    verify_action_group(&shielded_action_group, keys.vk());
    assert_eq!(shielded_action_group.actions().len(), expected_num_actions);
    assert!(verify_unique_spent_nullifiers(&shielded_action_group));
    Ok((shielded_action_group, bsk, value_balance))
}

/// Create several action groups and combine them to create some swap bundles.
#[test]
fn action_group_and_swap_bundle() {
    // ----- Setup -----

    let pk = ProvingKey::build::<OrchardZSA>();
    let vk = VerifyingKey::build::<OrchardZSA>();

    // Create notes for user1
    let keys1 = prepare_keys(&pk, &vk, 5);

    let user1_zatoshi_note1 = create_zatoshi_note(&keys1);
    let user1_zatoshi_note2 = create_zatoshi_note(&keys1);

    let asset_descr1 = b"zsa_asset1".to_vec();
    let (asset1_reference_note, asset1_note1, asset1_note2) = issue_zsa_notes(
        &asset_descr1,
        &keys1,
        &user1_zatoshi_note1.nullifier(keys1.fvk()),
    );

    // Create notes for user2
    let keys2 = prepare_keys(&pk, &vk, 10);

    let asset_descr2 = b"zsa_asset2".to_vec();
    let (asset2_reference_note, asset2_note1, asset2_note2) = issue_zsa_notes(
        &asset_descr2,
        &keys2,
        &user1_zatoshi_note2.nullifier(keys1.fvk()),
    );

    let user2_zatoshi_note1 = create_zatoshi_note(&keys2);
    let user2_zatoshi_note2 = create_zatoshi_note(&keys2);

    // Create matcher keys
    let matcher_keys = prepare_keys(&pk, &vk, 15);

    // Create Merkle tree with all notes
    let (merkle_paths, anchor) = build_merkle_paths(vec![
        &asset1_note1,
        &asset1_note2,
        &user1_zatoshi_note1,
        &user1_zatoshi_note2,
        &asset2_note1,
        &asset2_note2,
        &user2_zatoshi_note1,
        &user2_zatoshi_note2,
        &asset1_reference_note,
        &asset2_reference_note,
    ]);

    assert_eq!(merkle_paths.len(), 10);
    let merkle_path_asset1_note1 = merkle_paths[0].clone();
    let merkle_path_asset1_note2 = merkle_paths[1].clone();
    let merkle_path_user1_zatoshi_note1 = merkle_paths[2].clone();
    let merkle_path_user1_zatoshi_note2 = merkle_paths[3].clone();
    let merkle_path_asset2_note1 = merkle_paths[4].clone();
    let merkle_path_asset2_note2 = merkle_paths[5].clone();
    let merkle_path_user2_zatoshi_note1 = merkle_paths[6].clone();
    let merkle_path_user2_zatoshi_note2 = merkle_paths[7].clone();
    let merkle_path_asset1_reference_note = merkle_paths[8].clone();
    let merkle_path_asset2_reference_note = merkle_paths[9].clone();

    // Create TestSpendInfo
    let asset1_spend1 = TestSpendInfo {
        note: asset1_note1,
        merkle_path: merkle_path_asset1_note1,
    };
    let asset1_spend2 = TestSpendInfo {
        note: asset1_note2,
        merkle_path: merkle_path_asset1_note2,
    };
    let user1_zatoshi_note1_spend = TestSpendInfo {
        note: user1_zatoshi_note1,
        merkle_path: merkle_path_user1_zatoshi_note1,
    };
    let user1_zatoshi_note2_spend = TestSpendInfo {
        note: user1_zatoshi_note2,
        merkle_path: merkle_path_user1_zatoshi_note2,
    };
    let asset2_spend1 = TestSpendInfo {
        note: asset2_note1,
        merkle_path: merkle_path_asset2_note1,
    };
    let asset2_spend2 = TestSpendInfo {
        note: asset2_note2,
        merkle_path: merkle_path_asset2_note2,
    };
    let user2_zatoshi_note1_spend = TestSpendInfo {
        note: user2_zatoshi_note1,
        merkle_path: merkle_path_user2_zatoshi_note1,
    };
    let user2_zatoshi_note2_spend = TestSpendInfo {
        note: user2_zatoshi_note2,
        merkle_path: merkle_path_user2_zatoshi_note2,
    };
    let asset1_reference_spend_note = TestSpendInfo {
        note: asset1_reference_note,
        merkle_path: merkle_path_asset1_reference_note,
    };
    let asset2_reference_spend_note = TestSpendInfo {
        note: asset2_reference_note,
        merkle_path: merkle_path_asset2_reference_note,
    };

    // ----- Test 1: custom assets swap -----
    // User1:
    // - spends 10 asset1
    // - receives 20 asset2
    // - pays 5 zatoshi as fees
    // User2:
    // - spends 20 asset2
    // - receives 10 asset1
    // - pays 5 zatoshi as fees
    // Matcher:
    // - receives 5 zatoshi as fees from user1 and user2
    // 5 zatoshi are remaining for miner fees

    {
        const ISSUED_ASSET_QUANTITY: u64 = 42;
        const ZATOSHI_CREATED_PER_NOTE: u64 = 100;
        const ASSET1_QUANTITY: u64 = 10;
        const ASSET2_QUANTITY: u64 = 20;
        const USER1_ZATOSHI: u64 = 5;
        const USER2_ZATOSHI: u64 = 5;
        const MATCHER_FEE: u64 = 5;
        const MINER_FEE: u64 = 5;

        let user1_proposed_input = TestSwapIO {
            asset: asset1_note1.asset(),
            quantity: NoteValue::from_raw(ASSET1_QUANTITY),
        };

        let user1_desired_output = TestSwapIO {
            asset: asset2_note1.asset(),
            quantity: NoteValue::from_raw(ASSET2_QUANTITY),
        };

        let user2_proposed_input = TestSwapIO {
            asset: asset2_note1.asset(),
            quantity: NoteValue::from_raw(ASSET2_QUANTITY),
        };

        let user2_desired_output = TestSwapIO {
            asset: asset1_note1.asset(),
            quantity: NoteValue::from_raw(ASSET1_QUANTITY),
        };

        // User 1 creates ActionGroup
        let (action_group1, bsk1, bal1) = build_and_verify_action_group(
            vec![
                &asset1_spend1,             // 40 asset1
                &asset1_spend2,             // 2 asset1
                &user1_zatoshi_note1_spend, // 100 zatoshi
                &user1_zatoshi_note2_spend, // 100 zatoshi
            ],
            vec![
                // User1 would like to swap 10 asset1.
                // Thus, he would like to keep 40+2-10=32 asset1.
                TestOutputInfo {
                    value: NoteValue::from_raw(ISSUED_ASSET_QUANTITY - ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys1.recipient(),
                },
                // User1 would like to receive 20 asset2.
                TestOutputInfo {
                    value: NoteValue::from_raw(ASSET2_QUANTITY),
                    asset: asset2_note1.asset(),
                    recipient: *keys1.recipient(),
                },
                // User1 would like to pay 5 ZEC as a fee.
                // Thus, he would like to keep 100+100-5=195 ZEC.
                TestOutputInfo {
                    value: NoteValue::from_raw(2 * ZATOSHI_CREATED_PER_NOTE - USER1_ZATOSHI),
                    asset: AssetBase::zatoshi(),
                    recipient: *keys1.recipient(),
                },
            ],
            // We must provide a reference note for asset2 because we have no spend note for this asset.
            // This note will not be spent. It is only used to check the correctness of asset2.
            vec![&asset2_reference_spend_note],
            anchor,
            0,
            5,
            &keys1,
        )
        .unwrap();

        let user1_swap_order = TestSwapOrder {
            proposed_input: user1_proposed_input,
            desired_output: user1_desired_output,
            bsk: bsk1,
            value_balance: bal1, // this is the zec allocated for the (matcher and miner) fees.
            action_group: action_group1,
        };

        // User 2 creates ActionGroup
        let (action_group2, bsk2, bal2) = build_and_verify_action_group(
            vec![
                &asset2_spend1,             // 40 asset2
                &asset2_spend2,             // 2 asset2
                &user2_zatoshi_note1_spend, // 100 zatoshi
            ],
            vec![
                // User2 would like to spend 20 asset2.
                // Thus, he would like to keep 40+2-20=22 asset2.
                TestOutputInfo {
                    value: NoteValue::from_raw(ISSUED_ASSET_QUANTITY - ASSET2_QUANTITY),
                    asset: asset2_note1.asset(),
                    recipient: *keys2.recipient(),
                },
                // User2 would like to receive 10 asset1.
                TestOutputInfo {
                    value: NoteValue::from_raw(ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys2.recipient(),
                },
                // User2 would like to pay 5 zatoshi as a fee.
                // Thus, he would like to keep 100-5=95 zatoshi.
                TestOutputInfo {
                    value: NoteValue::from_raw(ZATOSHI_CREATED_PER_NOTE - USER2_ZATOSHI),
                    asset: AssetBase::zatoshi(),
                    recipient: *keys2.recipient(),
                },
            ],
            // We must provide a reference note for asset1 because we have no spend note for this asset.
            // This note will not be spent. It is only used to check the correctness of asset1.
            vec![&asset1_reference_spend_note],
            anchor,
            0,
            4,
            &keys2,
        )
        .unwrap();

        let user2_swap_order = TestSwapOrder {
            proposed_input: user2_proposed_input,
            desired_output: user2_desired_output,
            bsk: bsk2,
            value_balance: bal2,
            action_group: action_group2,
        };

        // The matcher first checks that the proposed input and desired output of user1 and user2 match.
        assert_eq!(
            user1_swap_order.proposed_input,
            user2_swap_order.desired_output
        );
        assert_eq!(
            user1_swap_order.desired_output,
            user2_swap_order.proposed_input
        );

        // The matcher checks there is enough ZEC to both get its own fee and pay a fee to the miners.
        assert!(USER1_ZATOSHI + USER2_ZATOSHI - MATCHER_FEE >= MINER_FEE);

        // Matcher creates ActionGroup
        let (action_group_matcher, bsk_matcher, bal_matcher) = build_and_verify_action_group(
            // The matcher spends nothing.
            vec![],
            // The matcher collects 5 zatoshi as a fee from user1 and user2.
            // The 5 zatoshi remaining from user1 and user2 are miner fees.
            vec![TestOutputInfo {
                value: NoteValue::from_raw(MATCHER_FEE),
                asset: AssetBase::zatoshi(),
                recipient: *matcher_keys.recipient(),
            }],
            // No reference note needed
            vec![],
            anchor,
            0,
            2,
            &matcher_keys,
        )
        .unwrap();

        // Matcher creates a Bundle from the three previous ActionGroups
        let bundle = Bundle::from_parts(
            vec![
                user1_swap_order.action_group,
                user2_swap_order.action_group,
                action_group_matcher,
            ],
            user1_swap_order.value_balance + user2_swap_order.value_balance + bal_matcher,
            None,
        );

        // Add the binding signature to the bundle.
        let swap_bundle = bundle.compute_binding_signature(
            OsRng,
            vec![user1_swap_order.bsk, user2_swap_order.bsk, bsk_matcher],
        );
        verify_swap_bundle(
            &swap_bundle,
            vec![&keys1.vk(), &keys2.vk(), &matcher_keys.vk()],
        );
    }

    // ----- Test 2: custom asset / ZEC swap -----
    // User1:
    // - spends 10 asset1
    // - receives 150 ZEC
    // User2:
    // - spends 150 ZEC
    // - receives 10 asset1
    // - pays 15 ZEC as fees
    // Matcher:
    // - receives 10 ZEC as fees from user2
    // 5 ZEC are remaining for miner fees

    {
        const ISSUED_ASSET_QUANTITY: u64 = 42;
        const ZATOSHI_CREATED_PER_NOTE: u64 = 100;
        const ASSET1_QUANTITY: u64 = 10;
        const USER2_SWAPPED_ZATOSHI: u64 = 150;

        const MATCHER_FEE: u64 = 10;
        const MINER_FEE: u64 = 5;

        let user1_proposed_input = TestSwapIO {
            asset: asset1_note1.asset(),
            quantity: NoteValue::from_raw(ASSET1_QUANTITY),
        };

        let user1_desired_output = TestSwapIO {
            asset: AssetBase::zatoshi(),
            quantity: NoteValue::from_raw(USER2_SWAPPED_ZATOSHI),
        };

        let user2_proposed_input = TestSwapIO {
            asset: AssetBase::zatoshi(),
            quantity: NoteValue::from_raw(USER2_SWAPPED_ZATOSHI),
        };

        let user2_desired_output = TestSwapIO {
            asset: asset1_note1.asset(),
            quantity: NoteValue::from_raw(ASSET1_QUANTITY),
        };

        // User 1 creates ActionGroup
        let (action_group1, bsk1, bal1) = build_and_verify_action_group(
            vec![
                &asset1_spend1, // 40 asset1
                &asset1_spend2, // 2 asset1
            ],
            vec![
                // User1 would like to spend 10 asset1.
                // Thus, he would like to keep 40+2-10=32 asset1.
                TestOutputInfo {
                    value: NoteValue::from_raw(ISSUED_ASSET_QUANTITY - ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys1.recipient(),
                },
                // User1 would like to receive 150 ZEC.
                TestOutputInfo {
                    value: NoteValue::from_raw(USER2_SWAPPED_ZATOSHI),
                    asset: AssetBase::zatoshi(),
                    recipient: *keys1.recipient(),
                },
            ],
            // No need of reference note for receiving ZEC
            vec![],
            anchor,
            0,
            3,
            &keys1,
        )
        .unwrap();

        let user1_swap_order = TestSwapOrder {
            proposed_input: user1_proposed_input,
            desired_output: user1_desired_output,
            bsk: bsk1,
            value_balance: bal1,
            action_group: action_group1,
        };

        // User 2 creates ActionGroup
        let (action_group2, bsk2, bal2) = build_and_verify_action_group(
            vec![
                &user2_zatoshi_note1_spend, // 100 ZEC
                &user2_zatoshi_note2_spend, // 100 ZEC
            ],
            vec![
                // User2 would like to send 150 ZEC to user1 and pays 15 ZEC as fees .
                // Thus, he would like to keep 100+100-150-15=35 ZEC.
                TestOutputInfo {
                    value: NoteValue::from_raw(
                        2 * ZATOSHI_CREATED_PER_NOTE
                            - USER2_SWAPPED_ZATOSHI
                            - MATCHER_FEE
                            - MINER_FEE,
                    ),
                    asset: AssetBase::zatoshi(),
                    recipient: *keys2.recipient(),
                },
                // User2 would like to receive 10 asset1.
                TestOutputInfo {
                    value: NoteValue::from_raw(ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys2.recipient(),
                },
            ],
            // We must provide a reference note for asset1 because we have no spend note for this asset.
            // This note will not be spent. It is only used to check the correctness of asset1.
            vec![&asset1_reference_spend_note],
            anchor,
            0,
            3,
            &keys2,
        )
        .unwrap();

        let user2_swap_order = TestSwapOrder {
            proposed_input: user2_proposed_input,
            desired_output: user2_desired_output,
            bsk: bsk2,
            value_balance: bal2,
            action_group: action_group2,
        };

        // Matcher creates action group
        let (action_group_matcher, bsk_matcher, bal_matcher) = build_and_verify_action_group(
            // The matcher spends nothing.
            vec![],
            // The matcher receives 10 ZEC as a fee from user2.
            // The 5 ZEC remaining from user2 are miner fees.
            vec![TestOutputInfo {
                value: NoteValue::from_raw(MATCHER_FEE),
                asset: AssetBase::zatoshi(),
                recipient: *matcher_keys.recipient(),
            }],
            // No reference note needed
            vec![],
            anchor,
            0,
            2,
            &matcher_keys,
        )
        .unwrap();

        // 4. Matcher creates a Bundle from the three previous ActionGroups
        let bundle = Bundle::from_parts(
            vec![
                user1_swap_order.action_group,
                user2_swap_order.action_group,
                action_group_matcher,
            ],
            user1_swap_order.value_balance + user2_swap_order.value_balance + bal_matcher,
            None,
        );

        // Add the binding signature to the bundle.
        let swap_bundle = bundle.compute_binding_signature(
            OsRng,
            vec![user1_swap_order.bsk, user2_swap_order.bsk, bsk_matcher],
        );
        verify_swap_bundle(
            &swap_bundle,
            vec![&keys1.vk(), &keys2.vk(), &matcher_keys.vk()],
        );
    }

    // ----- Test 3: ZSA transfer with Swaps activated -----
    // User1 would like to send 30 asset1 to User2
    {
        const ISSUED_ASSET_QUANTITY: u64 = 42;
        const ASSET1_QUANTITY: u64 = 30;

        // User 1 creates ActionGroup
        let (action_group, bsk1, bal1) = build_and_verify_action_group(
            vec![
                &asset1_spend1, // 40 asset1
                &asset1_spend2, // 2 asset1
            ],
            vec![
                TestOutputInfo {
                    value: NoteValue::from_raw(ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys2.recipient(),
                },
                TestOutputInfo {
                    value: NoteValue::from_raw(ISSUED_ASSET_QUANTITY - ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys1.recipient(),
                },
            ],
            // No reference note needed
            vec![],
            anchor,
            0,
            2,
            &keys1,
        )
        .unwrap();

        // 2. Create a Bundle from the ActionGroup

        let bundle = Bundle::from_parts(vec![action_group.clone()], bal1, None);

        let swap_bundle = bundle.compute_binding_signature(OsRng, vec![bsk1]);
        verify_swap_bundle(&swap_bundle, vec![&keys1.vk()]);
    }
}

#[test]
#[should_panic(expected = "InvalidSignature")]
fn invalid_swap_bundle() {
    // ----- Setup -----

    let pk = ProvingKey::build::<OrchardZSA>();
    let vk = VerifyingKey::build::<OrchardZSA>();

    // Create notes for user1
    let keys1 = prepare_keys(&pk, &vk, 5);

    let user1_zatoshi_note1 = create_zatoshi_note(&keys1);
    let user1_zatoshi_note2 = create_zatoshi_note(&keys1);

    let asset_descr1 = b"zsa_asset1".to_vec();
    let (asset1_reference_note, asset1_note1, asset1_note2) = issue_zsa_notes(
        &asset_descr1,
        &keys1,
        &user1_zatoshi_note1.nullifier(keys1.fvk()),
    );

    // Create notes for user2
    let keys2 = prepare_keys(&pk, &vk, 10);

    let asset_descr2 = b"zsa_asset2".to_vec();
    let (asset2_reference_note, asset2_note1, asset2_note2) = issue_zsa_notes(
        &asset_descr2,
        &keys2,
        &user1_zatoshi_note2.nullifier(keys1.fvk()),
    );

    let user2_zatoshi_note1 = create_zatoshi_note(&keys2);

    // Create matcher keys
    let matcher_keys = prepare_keys(&pk, &vk, 15);

    // Create Merkle tree with all notes
    let (merkle_paths, anchor) = build_merkle_paths(vec![
        &asset1_note1,
        &asset1_note2,
        &user1_zatoshi_note1,
        &user1_zatoshi_note2,
        &asset2_note1,
        &asset2_note2,
        &user2_zatoshi_note1,
        &asset1_reference_note,
        &asset2_reference_note,
    ]);

    assert_eq!(merkle_paths.len(), 9);
    let merkle_path_asset1_note1 = merkle_paths[0].clone();
    let merkle_path_asset1_note2 = merkle_paths[1].clone();
    let merkle_path_user1_zatoshi_note1 = merkle_paths[2].clone();
    let merkle_path_user1_zatoshi_note2 = merkle_paths[3].clone();
    let merkle_path_asset2_note1 = merkle_paths[4].clone();
    let merkle_path_asset2_note2 = merkle_paths[5].clone();
    let merkle_path_user2_zatoshi_note1 = merkle_paths[6].clone();
    let merkle_path_asset1_reference_note = merkle_paths[7].clone();
    let merkle_path_asset2_reference_note = merkle_paths[8].clone();

    // Create TestSpendInfo
    let asset1_spend1 = TestSpendInfo {
        note: asset1_note1,
        merkle_path: merkle_path_asset1_note1,
    };
    let asset1_spend2 = TestSpendInfo {
        note: asset1_note2,
        merkle_path: merkle_path_asset1_note2,
    };
    let user1_zatoshi_note1_spend = TestSpendInfo {
        note: user1_zatoshi_note1,
        merkle_path: merkle_path_user1_zatoshi_note1,
    };
    let user1_zatoshi_note2_spend = TestSpendInfo {
        note: user1_zatoshi_note2,
        merkle_path: merkle_path_user1_zatoshi_note2,
    };
    let asset2_spend1 = TestSpendInfo {
        note: asset2_note1,
        merkle_path: merkle_path_asset2_note1,
    };
    let asset2_spend2 = TestSpendInfo {
        note: asset2_note2,
        merkle_path: merkle_path_asset2_note2,
    };
    let user2_zatoshi_note1_spend = TestSpendInfo {
        note: user2_zatoshi_note1,
        merkle_path: merkle_path_user2_zatoshi_note1,
    };
    let asset1_reference_spend_note = TestSpendInfo {
        note: asset1_reference_note,
        merkle_path: merkle_path_asset1_reference_note,
    };
    let asset2_reference_spend_note = TestSpendInfo {
        note: asset2_reference_note,
        merkle_path: merkle_path_asset2_reference_note,
    };

    // ----- Test: Provide Matcher with invalid swap order -----
    // User1:
    // - spends 10 asset1
    // - receives 20 asset2
    // - pays 5 zatoshi as fees, but mentions 10 zatoshi in the swap order (invalid)
    // User2:
    // - spends 20 asset2
    // - receives 10 asset1
    // - pays 5 zatoshi as fees
    // Matcher:
    // - tries to receive 10 zatoshi as fees from user1 and user2
    // 5 zatoshi are remaining for miner fees

    {
        const ISSUED_ASSET_QUANTITY: u64 = 42;
        const ZATOSHI_CREATED_PER_NOTE: u64 = 100;
        const ASSET1_QUANTITY: u64 = 10;
        const ASSET2_QUANTITY: u64 = 20;
        const USER1_ZATOSHI: u64 = 5;
        const USER2_ZATOSHI: u64 = 5;
        const MATCHER_FEE: u64 = 10;

        let user1_proposed_input = TestSwapIO {
            asset: asset1_note1.asset(),
            quantity: NoteValue::from_raw(ASSET1_QUANTITY),
        };

        let user1_desired_output = TestSwapIO {
            asset: asset2_note1.asset(),
            quantity: NoteValue::from_raw(ASSET2_QUANTITY),
        };

        let user2_proposed_input = TestSwapIO {
            asset: asset2_note1.asset(),
            quantity: NoteValue::from_raw(ASSET2_QUANTITY),
        };

        let user2_desired_output = TestSwapIO {
            asset: asset1_note1.asset(),
            quantity: NoteValue::from_raw(ASSET1_QUANTITY),
        };

        // 1. Create and verify ActionGroup for user1
        let (action_group1, bsk1, _bal1) = build_and_verify_action_group(
            vec![
                &asset1_spend1,             // 40 asset1
                &asset1_spend2,             // 2 asset1
                &user1_zatoshi_note1_spend, // 100 ZEC
                &user1_zatoshi_note2_spend, // 100 ZEC
            ],
            vec![
                // User1 would like to spend 10 asset1.
                // Thus, he would like to keep 40+2-10=32 asset1.
                TestOutputInfo {
                    value: NoteValue::from_raw(ISSUED_ASSET_QUANTITY - ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys1.recipient(),
                },
                // User1 would like to receive 20 asset2.
                TestOutputInfo {
                    value: NoteValue::from_raw(ASSET2_QUANTITY),
                    asset: asset2_note1.asset(),
                    recipient: *keys1.recipient(),
                },
                // User1 would like to pay 5 zatoshi as a fee.
                // Thus, he would like to keep 100+100-5=195 zatoshi.
                TestOutputInfo {
                    value: NoteValue::from_raw(2 * ZATOSHI_CREATED_PER_NOTE - USER1_ZATOSHI),
                    asset: AssetBase::zatoshi(),
                    recipient: *keys1.recipient(),
                },
            ],
            // We must provide a reference note for asset2 because we have no spend note for this asset.
            // This note will not be spent. It is only used to check the correctness of asset2.
            vec![&asset2_reference_spend_note],
            anchor,
            0,
            5,
            &keys1,
        )
        .unwrap();

        let user1_swap_order = TestSwapOrder {
            proposed_input: user1_proposed_input,
            desired_output: user1_desired_output,
            bsk: bsk1,
            value_balance: 10, // User1 mentions 10 zatoshi in the swap order, but only pays 5 zatoshi as fees in the ActionGroup.
            action_group: action_group1,
        };

        // 2. Create and verify ActionGroup for user2
        let (action_group2, bsk2, bal2) = build_and_verify_action_group(
            vec![
                &asset2_spend1,             // 40 asset2
                &asset2_spend2,             // 2 asset2
                &user2_zatoshi_note1_spend, // 100 ZEC
            ],
            vec![
                // User2 would like to spend 20 asset2.
                // Thus, he would like to keep 40+2-20=22 asset2.
                TestOutputInfo {
                    value: NoteValue::from_raw(ISSUED_ASSET_QUANTITY - ASSET2_QUANTITY),
                    asset: asset2_note1.asset(),
                    recipient: *keys2.recipient(),
                },
                // User2 would like to receive 10 asset1.
                TestOutputInfo {
                    value: NoteValue::from_raw(ASSET1_QUANTITY),
                    asset: asset1_note1.asset(),
                    recipient: *keys2.recipient(),
                },
                // User2 would like to pay 5 ZEC as a fee.
                // Thus, he would like to keep 100-5=95 ZEC.
                TestOutputInfo {
                    value: NoteValue::from_raw(ZATOSHI_CREATED_PER_NOTE - USER2_ZATOSHI),
                    asset: AssetBase::zatoshi(),
                    recipient: *keys2.recipient(),
                },
            ],
            // We must provide a reference note for asset1 because we have no spend note for this asset.
            // This note will not be spent. It is only used to check the correctness of asset1.
            vec![&asset1_reference_spend_note],
            anchor,
            0,
            4,
            &keys2,
        )
        .unwrap();

        let user2_swap_order = TestSwapOrder {
            proposed_input: user2_proposed_input,
            desired_output: user2_desired_output,
            bsk: bsk2,
            value_balance: bal2,
            action_group: action_group2,
        };

        // The matcher first checks that the proposed input and desired output of user1 and user2 match.
        assert_eq!(
            user1_swap_order.proposed_input,
            user2_swap_order.desired_output
        );
        assert_eq!(
            user1_swap_order.desired_output,
            user2_swap_order.proposed_input
        );

        // 3. Matcher fees action group
        let (action_group_matcher, bsk_matcher, bal_matcher) = build_and_verify_action_group(
            // The matcher spends nothing.
            vec![],
            // The matcher receives 10 ZEC as a fee from user1 and user2.
            // The 5 ZEC remaining from user1 and user2 are miner fees.
            // This is based on the values in the swap orders (which is incorrectly provided by user1)
            vec![TestOutputInfo {
                value: NoteValue::from_raw(MATCHER_FEE),
                asset: AssetBase::zatoshi(),
                recipient: *matcher_keys.recipient(),
            }],
            // No reference note needed
            vec![],
            anchor,
            0,
            2,
            &matcher_keys,
        )
        .unwrap();

        // 4. Matcher creates a Bundle from the three previous ActionGroups
        let bundle = Bundle::from_parts(
            vec![
                user1_swap_order.action_group,
                user2_swap_order.action_group,
                action_group_matcher,
            ],
            user1_swap_order.value_balance + user2_swap_order.value_balance + bal_matcher,
            None,
        );

        // Add the binding signature to the bundle.
        let swap_bundle = bundle.compute_binding_signature(
            OsRng,
            vec![user1_swap_order.bsk, user2_swap_order.bsk, bsk_matcher],
        );
        // This should panic, as value balances will not match.
        verify_swap_bundle(
            &swap_bundle,
            vec![&keys1.vk(), &keys2.vk(), &matcher_keys.vk()],
        );
    }
}
