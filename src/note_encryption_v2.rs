//! In-band secret distribution for Orchard bundles.

use zcash_note_encryption_zsa::{AEAD_TAG_SIZE, MEMO_SIZE};

use crate::{
    note_encryption::{
        build_base_note_plaintext_bytes, define_note_byte_types, Memo, OrchardDomain,
        COMPACT_NOTE_SIZE_V2,
    },
    Note,
};

define_note_byte_types!(COMPACT_NOTE_SIZE_V2);

#[derive(Debug, Clone)]
struct OrchardDomainV2;

impl OrchardDomain for OrchardDomainV2 {
    const COMPACT_NOTE_SIZE: usize = COMPACT_NOTE_SIZE;

    type NotePlaintextBytes = NotePlaintextBytes;
    type NoteCiphertextBytes = NoteCiphertextBytes;
    type CompactNotePlaintextBytes = CompactNotePlaintextBytes;
    type CompactNoteCiphertextBytes = CompactNoteCiphertextBytes;

    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes {
        let mut np = build_base_note_plaintext_bytes(0x02, note);

        np[COMPACT_NOTE_SIZE_V2..].copy_from_slice(memo);

        NotePlaintextBytes(np)
    }
}
