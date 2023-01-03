//! Utility functions for computing bundle commitments

use blake2b_simd::{Hash as Blake2bHash, Params, State};

use crate::bundle::{Authorization, Authorized, Bundle};
use crate::issuance::{IssueAuth, IssueBundle, Signed};

const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
const ZCASH_ORCHARD_ACTIONS_ASSETID_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActAHash";
const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";
const ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcZSAIssue";
const ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION: &[u8; 16] = b"ZTxAuthZSAOrHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Write disjoint parts of each Orchard shielded action as 3 separate hashes:
/// * \[(nullifier, cmx, ephemeral_key, enc_ciphertext\[..52\])*\] personalized
///   with ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized
///   with ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, rk, enc_ciphertext\[564..\], out_ciphertext)*\] personalized
///   with ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION
/// as defined in [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// Then, hash these together along with (flags, value_balance_orchard, anchor_orchard),
/// personalized with ZCASH_ORCHARD_ACTIONS_HASH_PERSONALIZATION
///
/// [zip244]: https://zips.z.cash/zip-0244
pub(crate) fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
    bundle: &Bundle<A, V>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
    //let mut ah = hasher(ZCASH_ORCHARD_ACTIONS_ASSETID_HASH_PERSONALIZATION);
    let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

    for action in bundle.actions().iter() {
        ch.update(&action.nullifier().to_bytes());
        ch.update(&action.cmx().to_bytes());
        ch.update(&action.encrypted_note().epk_bytes);

        // two lines
        ch.update(&action.encrypted_note().enc_ciphertext.0[..52]);

        mh.update(&action.encrypted_note().enc_ciphertext.0[52..564]);

        nh.update(&action.cv_net().to_bytes());
        nh.update(&<[u8; 32]>::from(action.rk()));

        //one line
        nh.update(&action.encrypted_note().enc_ciphertext.0[564..]);
        nh.update(&action.encrypted_note().out_ciphertext);

        //TODO: extract into specific domain implementation
        // match &action.encrypted_note().enc_ciphertext {
        //     NoteCiphertextBytes::V2(ncx) => {
        //         ch.update(&ncx[..52]);
        //         mh.update(&ncx[52..564]);
        //         nh.update(&ncx[564..]);
        //     }
        //     NoteCiphertextBytes::V3(ncx) => {
        //         v3_flag = true;
        //         ch.update(&ncx[..52]);
        //         ah.update(&ncx[52..84]);
        //         mh.update(&ncx[84..596]);
        //         nh.update(&ncx[596..]);
        //     }
        // }
    }

    h.update(ch.finalize().as_bytes());
    // if v3_flag {
    //     h.update(ah.finalize().as_bytes());
    // }
    h.update(mh.finalize().as_bytes());
    h.update(nh.finalize().as_bytes());
    h.update(&[bundle.flags().to_byte()]);
    h.update(&(*bundle.value_balance()).into().to_le_bytes());
    h.update(&bundle.anchor().to_bytes());
    h.finalize()
}

/// Construct the commitment for the absent bundle as defined in
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
pub(crate) fn hash_bundle_auth_data<V>(bundle: &Bundle<Authorized, V>) -> Blake2bHash {
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

/// Construct the commitment for the issue bundle
pub(crate) fn hash_issue_bundle_txid_data<A: IssueAuth>(bundle: &IssueBundle<A>) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION);

    for action in bundle.actions().iter() {
        for note in action.notes().iter() {
            h.update(&note.recipient().to_raw_address_bytes());
            h.update(&note.value().to_bytes());
            h.update(&note.asset().to_bytes());
            h.update(&note.rho().to_bytes());
            h.update(note.rseed().as_bytes());
        }
        h.update(action.asset_desc().as_bytes());
        h.update(&[u8::from(action.is_finalized())]);
    }
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
