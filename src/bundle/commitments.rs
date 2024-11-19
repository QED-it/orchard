//! Utility functions for computing bundle commitments

use blake2b_simd::{Hash as Blake2bHash, Params, State};

use crate::{
    bundle::{Authorization, Authorized, Bundle},
    issuance::{IssueAuth, IssueBundle, Signed},
    note_encryption::{OrchardDomainCommon, MEMO_SIZE},
    orchard_flavor::{OrchardVanilla, OrchardZSA},
};

const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
const ZCASH_ORCHARD_ACTION_GROUPS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActGHash";
const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";
const ZCASH_ORCHARD_ZSA_BURN_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcBurnHash";
const ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION: &[u8; 16] = b"ZTxIdSAIssueHash";
const ZCASH_ORCHARD_ZSA_ISSUE_ACTION_PERSONALIZATION: &[u8; 16] = b"ZTxIdIssuActHash";
const ZCASH_ORCHARD_ZSA_ISSUE_NOTE_PERSONALIZATION: &[u8; 16] = b"ZTxIdIAcNoteHash";
const ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION: &[u8; 16] = b"ZTxAuthZSAOrHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Manages the evaluation of `orchard_digest`.
pub trait OrchardHash {
    /// OrchardDomain of the bundle (OrchardVanilla or OrchardZSA)
    type OrchardDomain: OrchardDomainCommon;

    /// Evaluate `orchard_digest` for the bundle as defined in
    /// [ZIP-226: Transfer and Burn of Zcash Shielded Assets][zip226]
    ///
    /// [zip226]: https://zips.z.cash/zip-0226
    fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
        bundle: &Bundle<A, V, Self::OrchardDomain>,
    ) -> Blake2bHash;
}

impl OrchardHash for OrchardVanilla {
    type OrchardDomain = OrchardVanilla;

    fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
        bundle: &Bundle<A, V, Self::OrchardDomain>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            ch.update(&action.nullifier().to_bytes());
            ch.update(&action.cmx().to_bytes());
            ch.update(&action.encrypted_note().epk_bytes);
            ch.update(
                &action.encrypted_note().enc_ciphertext.as_ref()
                    [..OrchardVanilla::COMPACT_NOTE_SIZE],
            );

            mh.update(
                &action.encrypted_note().enc_ciphertext.as_ref()[OrchardVanilla::COMPACT_NOTE_SIZE
                    ..OrchardVanilla::COMPACT_NOTE_SIZE + MEMO_SIZE],
            );

            nh.update(&action.cv_net().to_bytes());
            nh.update(&<[u8; 32]>::from(action.rk()));
            nh.update(
                &action.encrypted_note().enc_ciphertext.as_ref()
                    [OrchardVanilla::COMPACT_NOTE_SIZE + MEMO_SIZE..],
            );
            nh.update(&action.encrypted_note().out_ciphertext);
        }

        h.update(ch.finalize().as_bytes());
        h.update(mh.finalize().as_bytes());
        h.update(nh.finalize().as_bytes());

        h.update(&[bundle.flags().to_byte()]);
        h.update(&(*bundle.value_balance()).into().to_le_bytes());
        h.update(&bundle.anchor().to_bytes());
        h.finalize()
    }
}

impl OrchardHash for OrchardZSA {
    type OrchardDomain = OrchardZSA;

    fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
        bundle: &Bundle<A, V, Self::OrchardDomain>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        let mut ag = hasher(ZCASH_ORCHARD_ACTION_GROUPS_HASH_PERSONALIZATION);
        let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            ch.update(&action.nullifier().to_bytes());
            ch.update(&action.cmx().to_bytes());
            ch.update(&action.encrypted_note().epk_bytes);
            ch.update(
                &action.encrypted_note().enc_ciphertext.as_ref()[..OrchardZSA::COMPACT_NOTE_SIZE],
            );

            mh.update(
                &action.encrypted_note().enc_ciphertext.as_ref()
                    [OrchardZSA::COMPACT_NOTE_SIZE..OrchardZSA::COMPACT_NOTE_SIZE + MEMO_SIZE],
            );

            nh.update(&action.cv_net().to_bytes());
            nh.update(&<[u8; 32]>::from(action.rk()));
            nh.update(
                &action.encrypted_note().enc_ciphertext.as_ref()
                    [OrchardZSA::COMPACT_NOTE_SIZE + MEMO_SIZE..],
            );
            nh.update(&action.encrypted_note().out_ciphertext);
        }

        ag.update(ch.finalize().as_bytes());
        ag.update(mh.finalize().as_bytes());
        ag.update(nh.finalize().as_bytes());
        ag.update(&[bundle.flags().to_byte()]);
        ag.update(&bundle.anchor().to_bytes());
        ag.update(&[0, 0, 0, 0]); // timeLimit is always equal to 0

        h.update(ag.finalize().as_bytes());

        let mut burn_hasher = hasher(ZCASH_ORCHARD_ZSA_BURN_HASH_PERSONALIZATION);
        for burn_item in &bundle.burn {
            burn_hasher.update(&burn_item.0.to_bytes());
            burn_hasher.update(&burn_item.1.to_bytes());
        }
        h.update(burn_hasher.finalize().as_bytes());

        h.update(&(*bundle.value_balance()).into().to_le_bytes());
        h.finalize()
    }
}

/// Evaluate `orchard_digest` for the bundle as defined in
/// [ZIP-226: Transfer and Burn of Zcash Shielded Assets][zip226]
///
/// [zip226]: https://zips.z.cash/zip-0226
pub(crate) fn hash_bundle_txid_data<
    A: Authorization,
    V: Copy + Into<i64>,
    D: OrchardDomainCommon + OrchardHash<OrchardDomain = D>,
>(
    bundle: &Bundle<A, V, D>,
) -> Blake2bHash {
    D::hash_bundle_txid_data(bundle)
}

/// Construct the commitment for the bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION).finalize()
}

/// Construct the commitment to the authorizing data of an
/// authorized bundle as defined in [ZIP-244: Transaction
/// Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub(crate) fn hash_bundle_auth_data<V, D: OrchardDomainCommon>(
    bundle: &Bundle<Authorized, V, D>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
    h.update(bundle.authorization().proof().as_ref());
    for action in bundle.actions().iter() {
        h.update(&<[u8; 64]>::from(action.authorization()));
    }
    h.update(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));
    h.finalize()
}

/// Construct the commitment for an absent bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_auth_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION).finalize()
}

/// Construct the commitment for an absent issue bundle as defined in
/// [ZIP-227: Issuance of Zcash Shielded Assets][zip227]
///
/// [zip227]: https://qed-it.github.io/zips/zip-0227
pub fn hash_issue_bundle_auth_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION).finalize()
}

/// Construct the commitment for an absent issue bundle as defined in
/// [ZIP-227: Issuance of Zcash Shielded Assets][zip227]
///
/// [zip227]: https://qed-it.github.io/zips/zip-0227
pub fn hash_issue_bundle_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION).finalize()
}

/// Construct the commitment for the issue bundle
pub(crate) fn hash_issue_bundle_txid_data<A: IssueAuth>(bundle: &IssueBundle<A>) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION);
    let mut ia = hasher(ZCASH_ORCHARD_ZSA_ISSUE_ACTION_PERSONALIZATION);

    for action in bundle.actions() {
        let mut ind = hasher(ZCASH_ORCHARD_ZSA_ISSUE_NOTE_PERSONALIZATION);
        for note in action.notes().iter() {
            ind.update(&note.recipient().to_raw_address_bytes());
            ind.update(&note.value().to_bytes());
            ind.update(&note.asset().to_bytes());
            ind.update(&note.rho().to_bytes());
            ind.update(note.rseed().as_bytes());
        }
        ia.update(ind.finalize().as_bytes());
        ia.update(action.asset_desc());
        ia.update(&[u8::from(action.is_finalized())]);
    }
    h.update(ia.finalize().as_bytes());
    h.update(&bundle.ik().to_bytes());
    h.finalize()
}

/// Construct the commitment to the authorizing data of an
/// authorized issue bundle
pub(crate) fn hash_issue_bundle_auth_data(bundle: &IssueBundle<Signed>) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION);
    h.update(&<[u8; 64]>::from(bundle.authorization().signature()));
    h.finalize()
}
