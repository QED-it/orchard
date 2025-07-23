use incrementalmerkletree::{Hashable, Marking, Retention};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{Authorized, Flags},
    circuit::{ProvingKey, VerifyingKey},
    domain::{OrchardDomain, OrchardDomainCommon},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{AssetBase, ExtractedNoteCommitment},
    orchard_flavor::{OrchardFlavor, OrchardVanilla, OrchardZSA},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Anchor, Bundle, Note,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use zcash_note_encryption::try_note_decryption;

pub fn verify_bundle<D: OrchardDomainCommon>(
    bundle: &Bundle<Authorized, i64, D>,
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
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
        ShardTree::new(MemoryShardStore::empty(), 100);
    tree.append(
        leaf,
        Retention::Checkpoint {
            id: 0,
            marking: Marking::Marked,
        },
    )
    .unwrap();
    let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
    let position = tree.max_leaf_position(None).unwrap().unwrap();
    let merkle_path = tree
        .witness_at_checkpoint_id(position, &0)
        .unwrap()
        .unwrap();
    assert_eq!(root, merkle_path.root(MerkleHashOrchard::from_cmx(&cmx)));

    (merkle_path.into(), root.into())
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
            builder.add_output(None, recipient, note_value, AssetBase::native(), [0u8; 512]),
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
                [0u8; 512]
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
        // orchard_digest` taken from the `zcash/orchard` repository at commit `4ac248d0` (v0.11.0)
        // This ensures backward compatibility.
        [
            165, 242, 106, 135, 168, 224, 110, 252, 175, 110, 63, 29, 78, 243, 33, 14, 152, 202,
            209, 47, 68, 32, 138, 96, 79, 213, 218, 93, 45, 87, 221, 174,
        ]
    );
    assert_eq!(
        orchard_digest_2,
        // orchard_digest` taken from the `zcash/orchard` repository at commit `4ac248d0` (v0.11.0)
        // This ensures backward compatibility.
        [
            74, 174, 42, 41, 68, 92, 171, 110, 10, 148, 217, 61, 68, 50, 49, 1, 1, 180, 221, 210,
            97, 237, 25, 198, 195, 77, 19, 160, 186, 172, 8, 26,
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
            91, 237, 87, 13, 4, 177, 79, 132, 174, 177, 176, 63, 166, 154, 29, 229, 99, 49, 72,
            101, 55, 69, 78, 56, 57, 28, 205, 138, 97, 168, 78, 225
        ]
    );
    assert_eq!(
        orchard_digest_2,
        // Locks the `orchard_digest` for OrchardZSA
        [
            191, 8, 231, 227, 224, 191, 161, 187, 34, 255, 170, 233, 177, 167, 2, 137, 48, 244, 16,
            204, 168, 182, 96, 243, 82, 138, 63, 106, 129, 251, 188, 181
        ]
    );
}
