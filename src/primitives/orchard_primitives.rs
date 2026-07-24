//! The OrchardPrimitives trait represents the difference between the `OrchardVanilla` and the
//! `OrchardZSA` commitment, encryption and decryption procedures.

use core::fmt;

use zcash_note_encryption::{note_bytes::NoteBytes, AEAD_TAG_SIZE};

use crate::{
    bundle::BundleVersion,
    note_encryption::{Memo, MEMO_SIZE},
    Note,
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

    /// Returns true if the bundle version is equal to
    /// - (Orchard, *) or (Ironwood, V3) for OrchardVanilla, or
    /// - (Ironwood, ZSA) for OrchardZSA.
    fn is_valid_bundle_version(bundle_version: BundleVersion) -> bool;
}
