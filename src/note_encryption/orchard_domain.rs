use core::fmt;

use zcash_note_encryption_zsa::{AEAD_TAG_SIZE, MEMO_SIZE};

use crate::{action::Action, note::Nullifier, Note};

use super::{
    note_bytes::{NoteByteReader, NoteByteWriter},
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
    type NoteCiphertextBytes: NoteByteReader;
    /// A type to represent the raw bytes of a compact note.
    type CompactNotePlaintextBytes: NoteByteWriter;
    /// A type to represent the raw bytes of an encrypted compact note.
    type CompactNoteCiphertextBytes: NoteByteReader;

    /// Builds NotePlaintextBytes from Note and Memo.
    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes;
}

/// Orchard-specific note encryption logic.
#[derive(Debug, Clone)]
pub struct OrchardDomainContext<D: OrchardDomain> {
    /// Represents a nullifier which is used to prevent double spending within the Orchard protocol.
    pub rho: Nullifier,
    phantom: std::marker::PhantomData<D>,
}

impl<D: OrchardDomain> OrchardDomainContext<D> {
    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<A>(act: &Action<A, D>) -> Self {
        Self::for_nullifier(*act.nullifier())
    }

    /// Constructs a domain from a nullifier.
    // FIXME: is this used only in tests?
    pub fn for_nullifier(nullifier: Nullifier) -> Self {
        Self {
            rho: nullifier,
            phantom: Default::default(),
        }
    }
}
