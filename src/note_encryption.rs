//! In-band secret distribution for Orchard bundles.
//!
//! This module handles the encryption and decryption of notes within the Orchard protocol,
//! It includes functionality for handling both the standard "Vanilla" variantion and the ZSA
//! variantion, with different implementations for each. The different implementations are
//! organized into separate submodules.

use blake2b_simd::Params;

use zcash_note_encryption_zsa::{EphemeralKeyBytes, OutgoingCipherKey, MEMO_SIZE};

use crate::{
    keys::{DiversifiedTransmissionKey, Diversifier, OutgoingViewingKey},
    note::{AssetBase, RandomSeed, Rho},
    value::{NoteValue, ValueCommitment},
    Address, Note,
};

pub mod compact_action;
pub mod domain;
mod note_bytes;
mod orchard_domain;
pub mod orchard_domain_vanilla;
pub mod orchard_domain_zsa;

pub use orchard_domain::{OrchardDomain, OrchardDomainBase};

const PRF_OCK_ORCHARD_PERSONALIZATION: &[u8; 16] = b"Zcash_Orchardock";

const NOTE_VERSION_SIZE: usize = 1;
const NOTE_DIVERSIFIER_SIZE: usize = 11;
const NOTE_VALUE_SIZE: usize = 8;
const NOTE_RSEED_SIZE: usize = 32; // rseed (or rcm prior to ZIP 212)

const NOTE_VERSION_OFFSET: usize = 0;
const NOTE_DIVERSIFIER_OFFSET: usize = NOTE_VERSION_OFFSET + NOTE_VERSION_SIZE;
const NOTE_VALUE_OFFSET: usize = NOTE_DIVERSIFIER_OFFSET + NOTE_DIVERSIFIER_SIZE;
const NOTE_RSEED_OFFSET: usize = NOTE_VALUE_OFFSET + NOTE_VALUE_SIZE;

/// The size of a Vanilla compact note.
const COMPACT_NOTE_SIZE_VANILLA: usize =
    NOTE_VERSION_SIZE + NOTE_DIVERSIFIER_SIZE + NOTE_VALUE_SIZE + NOTE_RSEED_SIZE;

/// The size of the encoding of a ZSA asset id.
const ZSA_ASSET_SIZE: usize = 32;

/// The size of a ZSA compact note.
const COMPACT_NOTE_SIZE_ZSA: usize = COMPACT_NOTE_SIZE_VANILLA + ZSA_ASSET_SIZE;

type Memo = [u8; MEMO_SIZE];

// FIXME: consider returning enum instead of u8
/// Retrieves the version of the note plaintext.
/// Returns `Some(u8)` if the version is recognized, otherwise `None`.
fn note_version(plaintext: &[u8]) -> Option<u8> {
    plaintext.first().and_then(|version| match *version {
        0x02 | 0x03 => Some(*version),
        _ => None,
    })
}

// Constructs a note plaintext bytes array given note information.
fn build_base_note_plaintext_bytes<const NOTE_PLAINTEXT_SIZE: usize>(
    version: u8,
    note: &Note,
) -> [u8; NOTE_PLAINTEXT_SIZE] {
    let mut np = [0; NOTE_PLAINTEXT_SIZE];

    np[NOTE_VERSION_OFFSET] = version;
    np[NOTE_DIVERSIFIER_OFFSET..NOTE_VALUE_OFFSET]
        .copy_from_slice(note.recipient().diversifier().as_array());
    np[NOTE_VALUE_OFFSET..NOTE_RSEED_OFFSET].copy_from_slice(&note.value().to_bytes());
    np[NOTE_RSEED_OFFSET..COMPACT_NOTE_SIZE_VANILLA].copy_from_slice(note.rseed().as_bytes());

    np
}

/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
fn prf_ock_orchard(
    ovk: &OutgoingViewingKey,
    cv: &ValueCommitment,
    cmx_bytes: &[u8; 32],
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Params::new()
            .hash_length(32)
            .personal(PRF_OCK_ORCHARD_PERSONALIZATION)
            .to_state()
            .update(ovk.as_ref())
            .update(&cv.to_bytes())
            .update(cmx_bytes)
            .update(ephemeral_key.as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

// FIXME: return None for unseccessfull try_into instead of doing unwrap?
/// Parses the note plaintext (excluding the memo) and extracts the note and address if valid.
/// Domain-specific requirements:
/// - If the note version is 3, the `plaintext` must contain a valid encoding of a ZSA asset type.
fn parse_note_plaintext_without_memo<Bytes: AsRef<[u8]>, F>(
    rho: Rho,
    plaintext: &Bytes,
    get_validated_pk_d: F,
) -> Option<(Note, Address)>
where
    F: FnOnce(&Diversifier) -> Option<DiversifiedTransmissionKey>,
{
    // The unwraps below are guaranteed to succeed by the assertion above
    let diversifier = Diversifier::from_bytes(
        plaintext.as_ref()[NOTE_DIVERSIFIER_OFFSET..NOTE_VALUE_OFFSET]
            .try_into()
            .unwrap(),
    );

    let value = NoteValue::from_bytes(
        plaintext.as_ref()[NOTE_VALUE_OFFSET..NOTE_RSEED_OFFSET]
            .try_into()
            .unwrap(),
    );

    let rseed = Option::from(RandomSeed::from_bytes(
        plaintext.as_ref()[NOTE_RSEED_OFFSET..COMPACT_NOTE_SIZE_VANILLA]
            .try_into()
            .unwrap(),
        &rho,
    ))?;

    let pk_d = get_validated_pk_d(&diversifier)?;
    let recipient = Address::from_parts(diversifier, pk_d);

    let asset = match note_version(plaintext.as_ref())? {
        0x02 => AssetBase::native(),
        0x03 => {
            let bytes = plaintext.as_ref()[COMPACT_NOTE_SIZE_VANILLA..COMPACT_NOTE_SIZE_ZSA]
                .try_into()
                .unwrap();
            AssetBase::from_bytes(bytes).unwrap()
        }
        _ => panic!("invalid note version"),
    };

    let note = Option::from(Note::from_parts(recipient, value, asset, rho, rseed))?;
    Some((note, recipient))
}
