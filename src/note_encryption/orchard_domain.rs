//! The OrchardDomain trait represents the difference between the `OrchardVanilla` and the `OrchardZSA`
//! encryption and decryption procedures.

use core::fmt;

use zcash_note_encryption_zsa::{AEAD_TAG_SIZE, MEMO_SIZE};

use crate::{action::Action, note::Rho, Note};

use super::{compact_action::CompactAction, domain::Memo};

/// Represents a fixed-size array of bytes for note components.
#[derive(Clone, Copy, Debug)]
pub struct NoteBytesData<const N: usize>(pub [u8; N]);

impl<const N: usize> AsRef<[u8]> for NoteBytesData<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for NoteBytesData<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// FIXME: consider implementing and using TryFrom instead
impl<const N: usize> From<&[u8]> for NoteBytesData<N> {
    fn from(s: &[u8]) -> Self {
        Self(s.try_into().unwrap())
    }
}

impl<const N: usize> From<(&[u8], &[u8])> for NoteBytesData<N> {
    fn from(s: (&[u8], &[u8])) -> Self {
        Self([s.0, s.1].concat().try_into().unwrap())
    }
}

/// Provides a unified interface for handling fixed-size byte arrays used in Orchard note encryption.
pub trait NoteBytes:
    AsRef<[u8]>
    + AsMut<[u8]>
    + for<'a> From<&'a [u8]>
    + for<'a> From<(&'a [u8], &'a [u8])>
    + Clone
    + Copy
{
}

impl<const N: usize> NoteBytes for NoteBytesData<N> {}

/// Represents the Orchard protocol domain specifics required for note encryption and decryption.
pub trait OrchardDomain: fmt::Debug + Clone {
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

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    fn for_action<T>(act: &Action<T, Self>) -> OrchardDomainBase<Self> {
        OrchardDomainBase::<Self> {
            rho: act.rho(),
            phantom: Default::default(),
        }
    }

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    fn for_compact_action(act: &CompactAction<Self>) -> OrchardDomainBase<Self> {
        OrchardDomainBase::<Self> {
            rho: act.rho(),
            phantom: Default::default(),
        }
    }

    /// Constructs a domain from a rho.
    #[cfg(test)]
    fn for_rho(rho: Rho) -> OrchardDomainBase<Self> {
        OrchardDomainBase::<Self> {
            rho,
            phantom: Default::default(),
        }
    }
}

/// Orchard-specific note encryption logic.
#[derive(Debug, Clone)]
pub struct OrchardDomainBase<D: OrchardDomain> {
    /// A parameter needed to generate the nullifier.
    pub rho: Rho,
    phantom: std::marker::PhantomData<D>,
}

/*
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
*/
