#![cfg(all(feature = "zsa-issuance", feature = "circuit"))]

use nonempty::NonEmpty;
use rand_core::OsRng;
use orchard::{
    builder::{Builder, BundleType},
    circuit::{ProvingKey, VerifyingKey},
    flavor::OrchardZSA,
    issuance::{
        auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr},
        compute_asset_desc_hash, verify_issue_bundle, AwaitingNullifier, IssueBundle, IssueInfo,
        ReferenceKeys, Signed,
    },
    keys::{FullViewingKey, PreparedIncomingViewingKey, SpendingKey},
    note::{AssetBase, AssetId, ExtractedNoteCommitment, Nullifier},
    primitives::OrchardDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    ActionGroup, Address, Anchor, Bundle, Note,
};

use incrementalmerkletree::{Hashable, Marking, Retention};
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use zcash_note_encryption::try_note_decryption;
use zip32::Scope;
use orchard::bundle::Authorization;
use std::collections::HashSet;

pub(crate) struct TestSpendInfo {
    pub(crate) note: Note,
    pub(crate) merkle_path: MerklePath,
}

impl TestSpendInfo {
    pub(crate) fn merkle_path(&self) -> &MerklePath {
        &self.merkle_path
    }
}

pub(crate) struct TestOutputInfo {
    pub(crate) value: NoteValue,
    pub(crate) asset: AssetBase,
    pub(crate) recipient: Address,
}

#[derive(Debug)]
pub(crate) struct Keychain<'a> {
    pk: &'a ProvingKey,
    vk: &'a VerifyingKey,
    sk: SpendingKey,
    fvk: FullViewingKey,
    isk: IssueAuthKey<ZSASchnorr>,
    ik: IssueValidatingKey<ZSASchnorr>,
    recipient: Address,
}

impl Keychain<'_> {
    pub(crate) fn pk(&self) -> &ProvingKey {
        self.pk
    }
    pub(crate) fn vk(&self) -> &VerifyingKey {
        self.vk
    }
    pub(crate) fn sk(&self) -> &SpendingKey {
        &self.sk
    }
    pub(crate) fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }
    pub(crate) fn isk(&self) -> &IssueAuthKey<ZSASchnorr> {
        &self.isk
    }
    pub(crate) fn ik(&self) -> &IssueValidatingKey<ZSASchnorr> {
        &self.ik
    }
    pub(crate) fn recipient(&self) -> &Address {
        &self.recipient
    }
}

pub(crate) fn prepare_keys<'a>(pk: &'a ProvingKey, vk: &'a VerifyingKey, seed: u8) -> Keychain<'a> {
    let sk = SpendingKey::from_bytes([seed; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    let isk = IssueAuthKey::from_bytes(&[seed.wrapping_add(1); 32]).expect("valid issuance key");
    let ik = IssueValidatingKey::from(&isk);
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

/// Creates a note of ZEC with value 100 zatoshis, using the provided keys.
pub(crate) fn create_zatoshi_note(keys: &Keychain) -> Note {
    const ZATOSHI_VAL: u64 = 100;

    let mut rng = OsRng;

    let shielding_bundle: ActionGroup<_, OrchardZSA> = {
        // Use the empty tree.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new(BundleType::Coinbase, anchor);
        assert_eq!(
            builder.add_output(
                None,
                keys.recipient,
                NoteValue::from_raw(ZATOSHI_VAL),
                AssetBase::zatoshi(),
                [0u8; 512]
            ),
            Ok(())
        );
        let (unauthorized, value_balance, _) =
            builder.build::<i64, OrchardZSA>(&mut rng).unwrap().unwrap();
        let sighash = Bundle::from_parts(vec![unauthorized.clone()], value_balance, None)
            .commitment()
            .into();
        let proven = unauthorized.create_proof(keys.pk(), &mut rng).unwrap();
        proven.apply_signatures(rng, sighash, &[]).unwrap()
    };
    let ivk = keys.fvk().to_ivk(Scope::External);
    let (zatoshi_note, _, _) = shielding_bundle
        .actions()
        .iter()
        .find_map(|action| {
            let domain = OrchardDomain::for_action(action);
            try_note_decryption(&domain, &PreparedIncomingViewingKey::new(&ivk), action)
        })
        .unwrap();

    zatoshi_note
}

/// Issues two notes of the asset with values 40 and 2, and a reference note with value 0.
pub(crate) fn issue_zsa_notes(
    asset_descr: &[u8],
    keys: &Keychain,
    first_nullifier: &Nullifier,
) -> (Note, Note, Note) {
    const NOTE1_VAL: u64 = 40;
    const NOTE2_VAL: u64 = 2;

    let mut rng = OsRng;
    // Create an issuance bundle
    let asset_desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(asset_descr).unwrap());
    let (mut awaiting_nullifier_bundle, _) = IssueBundle::new(
        keys.ik().clone(),
        asset_desc_hash,
        Some(IssueInfo {
            recipient: keys.recipient,
            value: NoteValue::from_raw(NOTE1_VAL),
        }),
        true,
        &mut rng,
    );

    assert!(awaiting_nullifier_bundle
        .add_recipient(
            asset_desc_hash,
            keys.recipient,
            NoteValue::from_raw(NOTE2_VAL),
            false,
            &mut rng,
        )
        .is_ok());

    let issue_bundle =
        sign_issue_bundle(awaiting_nullifier_bundle, keys.isk(), first_nullifier, rng);

    // Take notes from first action
    let notes = issue_bundle.get_all_notes();
    let reference_note = notes[0];
    let note1 = notes[1];
    let note2 = notes[2];

    verify_reference_note(
        reference_note,
        AssetBase::custom(&AssetId::new_v0(keys.ik(), &asset_desc_hash)),
    );

    assert!(verify_issue_bundle(
        &issue_bundle,
        issue_bundle.commitment().into(),
        |_| None,
        first_nullifier
    )
    .is_ok());

    (*reference_note, *note1, *note2)
}

fn sign_issue_bundle(
    awaiting_nullifier_bundle: IssueBundle<AwaitingNullifier>,
    isk: &IssueAuthKey<ZSASchnorr>,
    first_nullifier: &Nullifier,
    rng: OsRng,
) -> IssueBundle<Signed> {
    let awaiting_sighash_bundle = awaiting_nullifier_bundle.update_rho(first_nullifier, rng);
    let sighash = awaiting_sighash_bundle.commitment().into();
    let prepared_bundle = awaiting_sighash_bundle.prepare(sighash);
    prepared_bundle.sign(isk).unwrap()
}

/// Validation for reference note
///
/// The following checks are performed:
/// - the note value of the reference note is equal to 0
/// - the asset of the reference note is equal to the provided asset
/// - the recipient of the reference note is equal to the reference recipient
fn verify_reference_note(note: &Note, asset: AssetBase) {
    assert_eq!(note.value(), NoteValue::from_raw(0));
    assert_eq!(note.asset(), asset);
    assert_eq!(note.recipient(), ReferenceKeys::recipient());
}

pub(crate) fn build_merkle_paths(notes: Vec<&Note>) -> (Vec<MerklePath>, Anchor) {
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
        ShardTree::new(MemoryShardStore::empty(), 100);

    let max_index = (notes.len() as u32) - 1;

    let mut commitments = vec![];
    let mut positions = vec![];

    // Add leaves
    for (index, note) in notes.iter().enumerate() {
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        commitments.push(cmx);
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: index as u32,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        positions.push(tree.max_leaf_position(None).unwrap().unwrap());
    }

    let root = tree.root_at_checkpoint_id(&(max_index)).unwrap().unwrap();

    // Calculate paths
    let mut merkle_paths: Vec<MerklePath> = vec![];
    for (position, commitment) in positions.iter().zip(commitments.iter()) {
        let merkle_path = tree
            .witness_at_checkpoint_id(*position, &max_index)
            .unwrap()
            .unwrap();

        assert_eq!(
            root,
            merkle_path.root(MerkleHashOrchard::from_cmx(commitment))
        );

        merkle_paths.push(merkle_path.into());
    }

    (merkle_paths, root.into())
}

pub fn verify_unique_spent_nullifiers<A: Authorization>(
    bundle: &ActionGroup<A, OrchardZSA>,
) -> bool {
    let mut seen = HashSet::new();
    bundle
        .actions()
        .iter()
        .all(|action| seen.insert(action.nullifier().to_bytes()))
}
