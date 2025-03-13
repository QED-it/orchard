use bridgetree::BridgeTree;
use incrementalmerkletree::Hashable;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{Authorized, Flags},
    circuit::{ProvingKey, VerifyingKey},
    domain::OrchardDomain,
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{AssetBase, ExtractedNoteCommitment},
    orchard_flavor::{OrchardFlavor, OrchardVanilla, OrchardZSA},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Anchor, Bundle, Note,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zcash_note_encryption_zsa::try_note_decryption;

pub fn verify_bundle<FL: OrchardFlavor>(
    bundle: &Bundle<Authorized, i64, FL>,
    vk: &VerifyingKey,
    verify_proof: bool,
) {
    if verify_proof {
        assert!(matches!(bundle.verify_proof(vk), Ok(())));
    }
    let sighash: [u8; 32] = bundle.commitment().into();
    let bvk = bundle.binding_validating_key();
    for action in bundle.actions() {
        assert_eq!(action.rk().verify(&sighash, action.authorization()), Ok(()));
    }
    assert_eq!(
        bvk.verify(&sighash, bundle.authorization().binding_signature()),
        Ok(())
    );
}

pub fn build_merkle_path(note: &Note) -> (MerklePath, Anchor) {
    // Use the tree with a single leaf.
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let mut tree = BridgeTree::<MerkleHashOrchard, u32, 32>::new(100);
    tree.append(leaf);
    let position = tree.mark().unwrap();
    let root = tree.root(0).unwrap();
    let auth_path = tree.witness(position, 0).unwrap();
    let merkle_path = MerklePath::from_parts(
        u64::from(position).try_into().unwrap(),
        auth_path[..].try_into().unwrap(),
    );
    let anchor = root.into();
    assert_eq!(anchor, merkle_path.root(cmx));
    (merkle_path, anchor)
}

trait BundleOrchardFlavor: OrchardFlavor {
    const DEFAULT_BUNDLE_TYPE: BundleType;
    const SPENDS_DISABLED_FLAGS: Flags;
}

impl BundleOrchardFlavor for OrchardVanilla {
    const DEFAULT_BUNDLE_TYPE: BundleType = BundleType::DEFAULT_VANILLA;
    const SPENDS_DISABLED_FLAGS: Flags = Flags::SPENDS_DISABLED_WITHOUT_ZSA;
}

impl BundleOrchardFlavor for OrchardZSA {
    const DEFAULT_BUNDLE_TYPE: BundleType = BundleType::DEFAULT_ZSA;
    const SPENDS_DISABLED_FLAGS: Flags = Flags::SPENDS_DISABLED_WITH_ZSA;
}

fn bundle_chain<FL: BundleOrchardFlavor>() -> ([u8; 32], [u8; 32]) {
    let mut rng = StdRng::seed_from_u64(1u64);
    let pk = ProvingKey::build::<FL>();
    let vk = VerifyingKey::build::<FL>();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    // Create a shielding bundle.
    let (shielding_bundle, orchard_digest_1): (Bundle<_, i64, FL>, [u8; 32]) = {
        // Use the empty tree.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new(
            BundleType::Transactional {
                flags: FL::SPENDS_DISABLED_FLAGS,
                bundle_required: false,
            },
            anchor,
        );
        let note_value = NoteValue::from_raw(5000);
        assert_eq!(
            builder.add_output(None, recipient, note_value, AssetBase::native(), None),
            Ok(())
        );
        let (unauthorized, bundle_meta) = builder.build(&mut rng).unwrap();

        assert_eq!(
            unauthorized
                .decrypt_output_with_key(
                    bundle_meta
                        .output_action_index(0)
                        .expect("Output 0 can be found"),
                    &fvk.to_ivk(Scope::External)
                )
                .map(|(note, _, _)| note.value()),
            Some(note_value)
        );

        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        (
            proven.apply_signatures(rng.clone(), sighash, &[]).unwrap(),
            sighash,
        )
    };

    // Verify the shielding bundle.
    verify_bundle(&shielding_bundle, &vk, true);

    let note = {
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        shielding_bundle
            .actions()
            .iter()
            .find_map(|action| {
                let domain = OrchardDomain::for_action(action);
                try_note_decryption(&domain, &ivk, action)
            })
            .unwrap()
            .0
    };

    // Test that spend adding attempt fails when spends are disabled.
    // Note: We do not need a separate positive test for spends enabled
    // as the following code adds spends with spends enabled.
    {
        let (merkle_path, anchor) = build_merkle_path(&note);

        let mut builder = Builder::new(
            BundleType::Transactional {
                // Intentionally testing with SPENDS_DISABLED_WITHOUT_ZSA as SPENDS_DISABLED_WITH_ZSA is already
                // tested above (for OrchardZSA case). Both should work.
                flags: Flags::SPENDS_DISABLED_WITHOUT_ZSA,
                bundle_required: false,
            },
            anchor,
        );

        assert!(builder.add_spend(fvk.clone(), note, merkle_path).is_err());
    }

    // Create a shielded bundle spending the previous output.
    let (shielded_bundle, orchard_digest_2): (Bundle<_, i64, FL>, [u8; 32]) = {
        let (merkle_path, anchor) = build_merkle_path(&note);

        let mut builder = Builder::new(FL::DEFAULT_BUNDLE_TYPE, anchor);
        assert_eq!(builder.add_spend(fvk, note, merkle_path), Ok(()));
        assert_eq!(
            builder.add_output(
                None,
                recipient,
                NoteValue::from_raw(5000),
                AssetBase::native(),
                None
            ),
            Ok(())
        );
        let (unauthorized, _) = builder.build(&mut rng).unwrap();
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        (
            proven
                .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sk)])
                .unwrap(),
            sighash,
        )
    };

    // Verify the shielded bundle.
    verify_bundle(&shielded_bundle, &vk, true);
    (orchard_digest_1, orchard_digest_2)
}

#[test]
fn bundle_chain_vanilla() {
    let (orchard_digest_1, orchard_digest_2) = bundle_chain::<OrchardVanilla>();
    assert_eq!(
        orchard_digest_1,
        // orchard_digest` taken from the `zcash/orchard` repository at commit `4fa6d3b`
        // This ensures backward compatibility.
        [
            239, 27, 83, 1, 224, 201, 57, 243, 162, 28, 61, 74, 175, 165, 5, 165, 23, 3, 16, 239,
            164, 29, 156, 180, 9, 60, 96, 117, 122, 187, 40, 103,
        ]
    );
    assert_eq!(
        orchard_digest_2,
        // orchard_digest` taken from the `zcash/orchard` repository at commit `4fa6d3b`
        // This ensures backward compatibility.
        [
            145, 227, 149, 34, 67, 111, 65, 185, 177, 236, 106, 137, 179, 71, 80, 137, 26, 12, 12,
            0, 8, 156, 182, 125, 146, 250, 92, 189, 42, 246, 130, 99,
        ]
    );
}

#[test]
fn bundle_chain_zsa() {
    let (orchard_digest_1, orchard_digest_2) = bundle_chain::<OrchardZSA>();
    assert_eq!(
        orchard_digest_1,
        // Locks the `orchard_digest` for OrchardZSA
        [
            183, 144, 252, 84, 122, 85, 49, 92, 222, 26, 48, 167, 119, 46, 202, 16, 232, 238, 88,
            43, 78, 172, 131, 24, 200, 91, 55, 47, 236, 192, 213, 218,
        ]
    );
    assert_eq!(
        orchard_digest_2,
        // Locks the `orchard_digest` for OrchardZSA
        [
            100, 230, 90, 215, 65, 57, 186, 251, 141, 79, 52, 169, 96, 216, 183, 104, 8, 12, 97,
            221, 232, 57, 97, 184, 158, 105, 235, 73, 79, 173, 32, 15,
        ]
    );
}
