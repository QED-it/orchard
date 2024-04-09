use bridgetree::BridgeTree;
use incrementalmerkletree::Hashable;
use orchard::{
    builder::Builder,
    bundle::{Authorized, Flags},
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{AssetBase, ExtractedNoteCommitment},
    note_encryption::OrchardType,
    note_encryption_zsa::OrchardDomainZSA,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Anchor, Bundle, Note,
};
use rand::rngs::OsRng;
use zcash_note_encryption_zsa::try_note_decryption;

type OrchardZSA = OrchardType<OrchardDomainZSA>;

pub fn verify_bundle(
    bundle: &Bundle<Authorized, i64, OrchardDomainZSA>,
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

#[test]
fn bundle_chain() {
    let mut rng = OsRng;
    let pk = ProvingKey::build();
    let vk = VerifyingKey::build();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    // Create a shielding bundle.
    let shielding_bundle: Bundle<_, i64, OrchardDomainZSA> = {
        // Use the empty tree.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new(Flags::from_parts(false, true, false), anchor);
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(5000),
                AssetBase::native(),
                None
            ),
            Ok(())
        );
        let unauthorized = builder.build(&mut rng).unwrap();
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        proven.apply_signatures(rng, sighash, &[]).unwrap()
    };

    // Verify the shielding bundle.
    verify_bundle(&shielding_bundle, &vk, true);

    // Create a shielded bundle spending the previous output.
    let shielded_bundle: Bundle<_, i64, OrchardDomainZSA> = {
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        let (note, _, _) = shielding_bundle
            .actions()
            .iter()
            .find_map(|action| {
                let domain = OrchardZSA::for_action(action);
                try_note_decryption(&domain, &ivk, action)
            })
            .unwrap();

        let (merkle_path, anchor) = build_merkle_path(&note);

        let mut builder = Builder::new(Flags::from_parts(true, true, false), anchor);
        assert_eq!(builder.add_spend(fvk, note, merkle_path), Ok(()));
        assert_eq!(
            builder.add_recipient(
                None,
                recipient,
                NoteValue::from_raw(5000),
                AssetBase::native(),
                None
            ),
            Ok(())
        );
        let unauthorized = builder.build(&mut rng).unwrap();
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        proven
            .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sk)])
            .unwrap()
    };

    // Verify the shielded bundle.
    verify_bundle(&shielded_bundle, &vk, true);
}
