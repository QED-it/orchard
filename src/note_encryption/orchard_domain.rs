//! Represents the Orchard protocol domain specifics required for note encryption and decryption.
//!
//! Defines OrchardDomain triat with the constants and methods needed to handle the
//! various sizes and types of note components. Actually this trait represents the difference
//! between both Vanilla and ZSA variantions of the Orchard protocol.

use core::fmt;

use zcash_note_encryption_zsa::{AEAD_TAG_SIZE, MEMO_SIZE};

use crate::{action::Action, note::Rho, Note};

use super::{
    action::CompactAction,
    note_bytes::{NoteByteConcat, NoteByteReader, NoteByteWriter},
    Memo,
};

/// Represents the Orchard protocol domain specifics required for note encryption and decryption.
pub trait OrchardDomain: fmt::Debug + Clone {
    /// The size of a compact note, specific to the Orchard protocol.
    // 52 for Vanuilla, 84 for ZSA
    const COMPACT_NOTE_SIZE: usize;

    /// The size of a note plaintext, including memo and other metadata.
    // + 512 (564 for Vanilla, 596 for ZSA)
    const NOTE_PLAINTEXT_SIZE: usize = Self::COMPACT_NOTE_SIZE + MEMO_SIZE;

    /// The size of an encrypted note ciphertext, accounting for additional AEAD tag space.
    // + 16 (580 for Vanilla, 612 for ZSA)
    const ENC_CIPHERTEXT_SIZE: usize = Self::NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

    /// A type to represent the raw bytes of a note plaintext.
    type NotePlaintextBytes: NoteByteWriter;
    /// A type to represent the raw bytes of an encrypted note plaintext.
    type NoteCiphertextBytes: NoteByteWriter + NoteByteConcat;
    /// A type to represent the raw bytes of a compact note.
    type CompactNotePlaintextBytes: NoteByteWriter;
    /// A type to represent the raw bytes of an encrypted compact note.
    type CompactNoteCiphertextBytes: NoteByteReader;

    /// Builds NotePlaintextBytes from Note and Memo.
    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes;
}

/// Orchard-specific note encryption logic.
#[derive(Debug, Clone)]
pub struct OrchardDomainBase<D: OrchardDomain> {
    /// Represents a nullifier which is used to prevent double spending within the Orchard protocol.
    pub rho: Rho,
    phantom: std::marker::PhantomData<fn() -> D>,
}

impl<D: OrchardDomain> OrchardDomainBase<D> {
    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<T>(act: &Action<T, D>) -> Self {
        Self {
            rho: act.rho(),
            phantom: Default::default(),
        }
    }

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_compact_action(act: &CompactAction<D>) -> Self {
        Self {
            rho: act.rho(),
            phantom: Default::default(),
        }
    }

    /// Constructs a domain from a rho.
    #[cfg(test)]
    pub fn for_rho(rho: Rho) -> Self {
        Self {
            rho,
            phantom: Default::default(),
        }
    }
}
