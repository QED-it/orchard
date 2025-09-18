//! Utility functions for computing bundle commitments

use alloc::{collections::BTreeMap, vec::Vec};
use blake2b_simd::{Hash as Blake2bHash, Params, State};

use crate::{
    bundle::{Authorization, Authorized, Bundle},
    issuance::{IssueAuth, IssueBundle, Signed},
    issuance_sighash_versioning::IssueSighashVersion,
    orchard_sighash_versioning::OrchardSighashVersion,
    primitives::OrchardPrimitives,
};

pub(crate) const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
pub(crate) const ZCASH_ORCHARD_ACTION_GROUPS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActGHash";
pub(crate) const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] =
    b"ZTxIdOrcActCHash";
pub(crate) const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION_V6: &[u8; 16] =
    b"ZTxId6OActC_Hash";
pub(crate) const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
pub(crate) const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] =
    b"ZTxIdOrcActNHash";
pub(crate) const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION_V6: &[u8; 16] =
    b"ZTxId6OActN_Hash";
pub(crate) const ZCASH_ORCHARD_ZSA_BURN_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcBurnHash";
pub(crate) const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";
pub(crate) const ZCASH_ORCHARD_ACTION_GROUPS_SIGS_HASH_PERSONALIZATION: &[u8; 16] =
    b"ZTxAuthOrcAGHash";

const ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION: &[u8; 16] = b"ZTxIdSAIssueHash";
const ZCASH_ORCHARD_ZSA_ISSUE_ACTION_PERSONALIZATION: &[u8; 16] = b"ZTxIdIssuActHash";
const ZCASH_ORCHARD_ZSA_ISSUE_NOTE_PERSONALIZATION: &[u8; 16] = b"ZTxIdIAcNoteHash";
const ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION: &[u8; 16] = b"ZTxAuthZSAOrHash";

pub(crate) fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Evaluate `orchard_digest` for the bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
/// for OrchardVanilla and as defined in
/// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
/// for OrchardZSA
///
/// [zip244]: https://zips.z.cash/zip-0244
/// [zip246]: https://zips.z.cash/zip-0246
pub(crate) fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>, P: OrchardPrimitives>(
    bundle: &Bundle<A, V, P>,
) -> Blake2bHash {
    P::hash_bundle_txid_data(bundle)
}

/// Construct the commitment for the absent bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION).finalize()
}

/// Construct the `orchard_auth_digest` commitment to the authorizing data of an
/// authorized bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
/// for OrchardVanilla and as defined in
/// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
/// for OrchardZSA
///
/// [zip244]: https://zips.z.cash/zip-0244
/// [zip246]: https://zips.z.cash/zip-0246
pub(crate) fn hash_bundle_auth_data<V, P: OrchardPrimitives>(
    bundle: &Bundle<Authorized, V, P>,
    version_to_bytes: BTreeMap<OrchardSighashVersion, Vec<u8>>,
) -> Blake2bHash {
    P::hash_bundle_auth_data(bundle, version_to_bytes)
}

/// Construct the `orchard_auth_digest` commitment for an absent bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_auth_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION).finalize()
}

/// Construct the `issuance_digest` commitment for an absent issue bundle as defined in
/// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
///
/// [zip246]: https://zips.z.cash/zip-0246
pub fn hash_issue_bundle_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION).finalize()
}

/// Construct the `issuance_digest` commitment for the issue bundle as defined in
/// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
///
/// [zip246]: https://zips.z.cash/zip-0246
pub(crate) fn hash_issue_bundle_txid_data<A: IssueAuth>(bundle: &IssueBundle<A>) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_ZSA_ISSUE_PERSONALIZATION);

    let ik_encoding = bundle.ik().encode();
    h.update(&get_compact_size(ik_encoding.len()));
    h.update(&ik_encoding);

    let mut ia = hasher(ZCASH_ORCHARD_ZSA_ISSUE_ACTION_PERSONALIZATION);
    for action in bundle.actions() {
        ia.update(action.asset_desc_hash());

        let mut ind = hasher(ZCASH_ORCHARD_ZSA_ISSUE_NOTE_PERSONALIZATION);
        for note in action.notes().iter() {
            ind.update(&note.recipient().to_raw_address_bytes());
            ind.update(&note.value().to_bytes());
            ind.update(&note.rho().to_bytes());
            ind.update(note.rseed().as_bytes());
        }
        ia.update(ind.finalize().as_bytes());
        ia.update(&[u8::from(action.is_finalized())]);
    }
    h.update(ia.finalize().as_bytes());
    h.finalize()
}

/// Construct the `issuance_auth_digest` commitment for an absent issue bundle as defined in
/// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
///
/// [zip246]: https://zips.z.cash/zip-0246
pub fn hash_issue_bundle_auth_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION).finalize()
}

/// Construct the `issuance_auth_digest` commitment to the authorizing data of an
/// authorized issue bundle as defined in
/// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
///
/// [zip246]: https://zips.z.cash/zip-0246
pub(crate) fn hash_issue_bundle_auth_data(
    bundle: &IssueBundle<Signed>,
    version_to_bytes: BTreeMap<IssueSighashVersion, Vec<u8>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION);
    let version_bytes = version_to_bytes
        .get(bundle.authorization().signature().version())
        .expect("Unknown issue sighash version.");
    h.update(&get_compact_size(version_bytes.len()));
    h.update(version_bytes);

    let sig_enc = bundle.authorization().signature().sig().encode();
    assert_eq!(sig_enc.len(), 65);
    assert_eq!(sig_enc[0], 0x00); // ZIP-230: algorithm byte must be 0x00
    h.update(&get_compact_size(sig_enc.len()));
    h.update(&sig_enc);
    h.finalize()
}

/// Encodes a size in the CompactSize format.
///
/// This implementation is inspired from `zcash_encoding::CompactSize::write` [code]
/// We cannot use zcash_encoding crate to avoid circular dependency.
///
/// [code]: https://github.com/zcash/librustzcash/blob/8be259c579762f1b0f569453a20c0d0dbeae6c07/components/zcash_encoding/src/lib.rs#L93
pub fn get_compact_size(size: usize) -> Vec<u8> {
    match size {
        s if s < 253 => vec![s as u8],
        s if s <= 0xFFFF => [&[253_u8], &(s as u16).to_le_bytes()[..]].concat(),
        s if s <= 0xFFFFFFFF => [&[254_u8], &(s as u32).to_le_bytes()[..]].concat(),
        s => [&[255_u8], &(s as u64).to_le_bytes()[..]].concat(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        builder::{Builder, BundleType, UnauthorizedBundle},
        bundle::{
            commitments::{get_compact_size, hash_bundle_auth_data, hash_bundle_txid_data},
            Authorized, Bundle,
        },
        circuit::ProvingKey,
        keys::{FullViewingKey, Scope, SpendingKey},
        note::AssetBase,
        orchard_flavor::{OrchardFlavor, OrchardVanilla, OrchardZSA},
        orchard_sighash_versioning::test_utils::orchard_version_to_bytes_map,
        value::NoteValue,
        Anchor,
    };
    use alloc::collections::BTreeMap;
    use rand::{rngs::StdRng, SeedableRng};

    fn generate_bundle<FL: OrchardFlavor>(bundle_type: BundleType) -> UnauthorizedBundle<i64, FL> {
        let rng = StdRng::seed_from_u64(5);

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);

        let mut builder = Builder::new(bundle_type, Anchor::from_bytes([0; 32]).unwrap());
        builder
            .add_output(
                None,
                recipient,
                NoteValue::from_raw(10),
                AssetBase::native(),
                [0u8; 512],
            )
            .unwrap();

        builder
            .add_output(
                None,
                recipient,
                NoteValue::from_raw(20),
                AssetBase::native(),
                [0u8; 512],
            )
            .unwrap();

        builder.build::<i64, FL>(rng).unwrap().0
    }

    /// Verify that the hash for an Orchard Vanilla bundle matches a fixed reference value
    /// to ensure consistency.
    #[test]
    fn test_hash_bundle_txid_data_for_orchard_vanilla() {
        let bundle = generate_bundle::<OrchardVanilla>(BundleType::DEFAULT_VANILLA);
        let sighash = hash_bundle_txid_data(&bundle);
        assert_eq!(
            sighash.to_hex().as_str(),
            // Bundle hash for Orchard (vanilla) generated using
            // Zcash/Orchard commit: 4ac248d0 (v0.11.0)
            "0ac1e319f6761a8561b7bd3fc0907a5c73ed5590a6c210c4d39ffae1d5741875"
        );
    }

    /// Verify that the hash for an OrchardZSA bundle matches a fixed reference value
    /// to ensure consistency.
    #[test]
    fn test_hash_bundle_txid_data_for_orchard_zsa() {
        let bundle = generate_bundle::<OrchardZSA>(BundleType::DEFAULT_ZSA);
        let sighash = hash_bundle_txid_data(&bundle);
        assert_eq!(
            sighash.to_hex().as_str(),
            "f84871d872081fa7744cbaf575e342cf81951a9b17818264170243d1551a99ea"
        );
    }

    fn generate_auth_bundle<FL: OrchardFlavor>(
        bundle_type: BundleType,
    ) -> Bundle<Authorized, i64, FL> {
        let mut rng = StdRng::seed_from_u64(6);
        let pk = ProvingKey::build::<FL>();
        let bundle = generate_bundle(bundle_type)
            .create_proof(&pk, &mut rng)
            .unwrap();
        let sighash = bundle.commitment().into();
        bundle.prepare(rng, sighash).finalize().unwrap()
    }

    /// Verify that the authorizing data commitment for an Orchard Vanilla bundle matches a fixed
    /// reference value to ensure consistency.
    #[test]
    fn test_hash_bundle_auth_data_for_orchard_vanilla() {
        let bundle = generate_auth_bundle::<OrchardVanilla>(BundleType::DEFAULT_VANILLA);
        let orchard_auth_digest = hash_bundle_auth_data(&bundle, BTreeMap::new());
        assert_eq!(
            orchard_auth_digest.to_hex().as_str(),
            // Bundle hash for Orchard (vanilla) generated using
            // Zcash/Orchard commit: 4ac248d0 (v0.11.0)
            "5f3bcf759cddf19170ec47a882a470b5767d66c95fc72ffc360f31324474a06b"
        );
    }

    /// Verify that the authorizing data commitment for an OrchardZSA bundle matches a fixed
    /// reference value to ensure consistency.
    #[test]
    fn test_hash_bundle_auth_data_for_orchard_zsa() {
        let bundle = generate_auth_bundle::<OrchardZSA>(BundleType::DEFAULT_ZSA);
        let orchard_auth_digest = hash_bundle_auth_data(&bundle, orchard_version_to_bytes_map());
        assert_eq!(
            orchard_auth_digest.to_hex().as_str(),
            "48b277d8019c194da3882454ab6e0a2c8eb08cfb062e2285fe5bde1eb27ae98d"
        );
    }

    #[test]
    fn test_compact_size() {
        assert_eq!(get_compact_size(0), vec![0]);
        assert_eq!(get_compact_size(1), vec![1]);
        assert_eq!(get_compact_size(252), vec![252]);
        assert_eq!(get_compact_size(253), vec![253, 253, 0]);
        assert_eq!(get_compact_size(254), vec![253, 254, 0]);
        assert_eq!(get_compact_size(255), vec![253, 255, 0]);
        assert_eq!(get_compact_size(65535), vec![253, 255, 255]);
        assert_eq!(get_compact_size(65536), vec![254, 0, 0, 1, 0]);
        assert_eq!(get_compact_size(65537), vec![254, 1, 0, 1, 0]);
        assert_eq!(get_compact_size(33554432), vec![254, 0, 0, 0, 2]);
    }
}
