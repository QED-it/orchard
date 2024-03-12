use std::fmt;

use super::{
    Action, EphemeralKeyBytes, ExtractedNoteCommitment, Nullifier, OrchardDomain,
    OrchardDomainContext, ShieldedOutput,
};

impl<A, D: OrchardDomain> ShieldedOutput<OrchardDomainContext<D>> for Action<A, D> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> Option<D::NoteCiphertextBytes> {
        Some(self.encrypted_note().enc_ciphertext)
    }

    // FIXME: split at COMPACT_NOTE_SIZE - is this correct?
    fn enc_ciphertext_compact(&self) -> D::CompactNoteCiphertextBytes {
        self.encrypted_note().enc_ciphertext.as_ref()[..D::COMPACT_NOTE_SIZE]
            .try_into()
            .unwrap()
    }
}

/// A compact Action for light clients.
pub struct CompactAction<D: OrchardDomain> {
    nullifier: Nullifier,
    cmx: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: D::CompactNoteCiphertextBytes,
}

impl<D: OrchardDomain> fmt::Debug for CompactAction<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompactAction")
    }
}

impl<A, D: OrchardDomain> From<&Action<A, D>> for CompactAction<D>
where
    Action<A, D>: ShieldedOutput<OrchardDomainContext<D>>,
{
    fn from(action: &Action<A, D>) -> Self {
        CompactAction {
            nullifier: *action.nullifier(),
            cmx: *action.cmx(),
            ephemeral_key: action.ephemeral_key(),
            enc_ciphertext: action.enc_ciphertext_compact(),
        }
    }
}

impl<D: OrchardDomain> ShieldedOutput<OrchardDomainContext<D>> for CompactAction<D> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key.0)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }

    fn enc_ciphertext(&self) -> Option<D::NoteCiphertextBytes> {
        None
    }

    fn enc_ciphertext_compact(&self) -> D::CompactNoteCiphertextBytes {
        self.enc_ciphertext
    }
}

impl<D: OrchardDomain> CompactAction<D> {
    /// Create a CompactAction from its constituent parts
    pub fn from_parts(
        nullifier: Nullifier,
        cmx: ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: D::CompactNoteCiphertextBytes,
    ) -> Self {
        Self {
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext,
        }
    }

    ///Returns the nullifier of the note being spent.
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }
}
