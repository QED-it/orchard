//! The OrchardPrimitives trait represents the difference between the `OrchardVanilla` and the
//! `OrchardZSA` commitment, encryption and decryption procedures.

use alloc::vec::Vec;
use core::fmt;

use blake2b_simd::Hash as Blake2bHash;
use zcash_note_encryption::{note_bytes::NoteBytes, AEAD_TAG_SIZE};

use crate::{
    bundle::{Authorization, Authorized, CommitmentError, TxVersion},
    note::{AssetBase, NoteVersion},
    primitives::zcash_note_encryption_domain::{Memo, MEMO_SIZE},
    sighash_kind::OrchardSighashKind,
    Bundle, Note,
};

/// Represents the Orchard protocol domain specifics required for commitment, note encryption and
/// decryption.
pub trait OrchardPrimitives: fmt::Debug + Clone {
    /// The size of a compact note, specific to the Orchard protocol.
    const COMPACT_NOTE_SIZE: usize;

    /// The size of a note plaintext, including memo and other metadata.
    const NOTE_PLAINTEXT_SIZE: usize = Self::COMPACT_NOTE_SIZE + MEMO_SIZE;

    /// The size of an encrypted note ciphertext, accounting for additional AEAD tag space.
    const ENC_CIPHERTEXT_SIZE: usize = Self::NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

    /// Fixed base overhead (in bytes) of a proof, independent of the number of actions.
    ///
    /// Together with `PER_ACTION_PROOF_SIZE`, determines the canonical proof length via
    /// BASE_PROOF_SIZE + PER_ACTION_PROOF_SIZE * num_actions.
    const BASE_PROOF_SIZE: usize;

    /// Per-action contribution (in bytes) to the proof size.
    ///
    /// See [`BASE_PROOF_SIZE`][Self::BASE_PROOF_SIZE].
    const PER_ACTION_PROOF_SIZE: usize;

    /// The raw bytes of a note plaintext.
    type NotePlaintextBytes: NoteBytes;
    /// The raw bytes of an encrypted note plaintext.
    type NoteCiphertextBytes: NoteBytes;
    /// The raw bytes of a compact note.
    type CompactNotePlaintextBytes: NoteBytes;
    /// The raw bytes of an encrypted compact note.
    type CompactNoteCiphertextBytes: NoteBytes;

    /// Builds NotePlaintextBytes from Note and Memo.
    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes;

    /// Extracts the asset from the note plaintext.
    fn extract_asset(plaintext: &Self::CompactNotePlaintextBytes) -> Option<AssetBase>;

    /// Evaluate `orchard_digest` for the bundle as defined in
    /// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
    /// for OrchardVanilla (and Ironwood) and as defined in
    /// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
    /// for OrchardZSA
    ///
    /// The bundle's own [`BundleVersion`] and `tx_version` select the commitment
    /// personalizations and the anchor placement. Returns
    /// [`CommitmentError::InvalidTransactionVersion`] if `tx_version` is not valid for the
    /// bundle's [`BundleVersion`] (e.g. an Ironwood or OrchardZSA bundle committed for a v5
    /// transaction).
    ///
    /// [zip244]: https://zips.z.cash/zip-0244
    /// [zip246]: https://zips.z.cash/zip-0246
    /// [`BundleVersion`]: crate::bundle::BundleVersion
    fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
        bundle: &Bundle<A, V, Self>,
        tx_version: TxVersion,
    ) -> Result<Blake2bHash, CommitmentError>;

    /// Evaluate `orchard_auth_digest` for the bundle as defined in
    /// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
    /// for OrchardVanilla (and Ironwood) and as defined in
    /// [ZIP-246: Digests for the Version 6 Transaction Format][zip246]
    /// for OrchardZSA
    ///
    /// The `sighash_info_for_kind` closure returns the `SighashInfo` encoding
    /// for a given [`OrchardSighashKind`].
    ///
    /// Returns [`CommitmentError::InvalidTransactionVersion`] if `tx_version` is not valid
    /// for the bundle's [`BundleVersion`].
    ///
    /// [zip244]: https://zips.z.cash/zip-0244
    /// [zip246]: https://zips.z.cash/zip-0246
    /// [`BundleVersion`]: crate::bundle::BundleVersion
    fn hash_bundle_auth_data<V>(
        bundle: &Bundle<Authorized, V, Self>,
        tx_version: TxVersion,
        sighash_info_for_kind: impl Fn(&OrchardSighashKind) -> Vec<u8>,
    ) -> Result<Blake2bHash, CommitmentError>;

    /// Validates the note plaintext lead byte for this flavor and returns the
    /// [`NoteVersion`] to record on the parsed note, or `None` if the plaintext
    /// is not valid for this flavor under the expected version.
    ///
    /// - For `OrchardVanilla`, the lead byte must equal `expected.lead_byte()`
    ///   (`0x02` for [ZIP 212] V2 notes, `0x03` for [ZIP 2005] Ironwood V3
    ///   notes), and the note is recorded with that version.
    /// - For `OrchardZSA`, the plaintext must use the [ZIP 226] format (lead
    ///   byte `0x03` followed by an asset encoding), and the note is always
    ///   recorded as [`NoteVersion::V2`]: ZSA keeps the ZIP 212 rcm derivation,
    ///   and its `0x03` lead byte is part of the ZSA plaintext encoding, not a
    ///   ZIP 2005 version marker.
    ///
    /// [ZIP 212]: https://zips.z.cash/zip-0212
    /// [ZIP 226]: https://zips.z.cash/zip-0226
    /// [ZIP 2005]: https://zips.z.cash/zip-2005
    fn parse_note_version(expected: NoteVersion, plaintext: &[u8]) -> Option<NoteVersion>;
}
