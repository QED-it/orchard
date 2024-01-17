//! In-band secret distribution for Orchard bundles.

use blake2b_simd::{Hash, Params};
use core::fmt;
use group::ff::PrimeField;

use zcash_note_encryption_zsa::{
    BatchDomain, Domain, EphemeralKeyBytes, OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput,
    MEMO_SIZE, OUT_PLAINTEXT_SIZE,
};

use crate::{
    action::Action,
    keys::{
        DiversifiedTransmissionKey, Diversifier, EphemeralPublicKey, EphemeralSecretKey,
        OutgoingViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, SharedSecret,
    },
    note::{AssetBase, ExtractedNoteCommitment, Nullifier, RandomSeed},
    value::{NoteValue, ValueCommitment},
    Address, Note,
};

const PRF_OCK_ORCHARD_PERSONALIZATION: &[u8; 16] = b"Zcash_Orchardock";

const NOTE_VERSION_SIZE: usize = 1;
const NOTE_DIVERSIFIER_SIZE: usize = 11;
const NOTE_VALUE_SIZE: usize = 8;
const NOTE_RSEED_SIZE: usize = 32; // rseed (or rcm prior to ZIP 212)

const NOTE_VERSION_OFFSET: usize = 0;
const NOTE_DIVERSIFIER_OFFSET: usize = NOTE_VERSION_OFFSET + NOTE_VERSION_SIZE;
const NOTE_VALUE_OFFSET: usize = NOTE_DIVERSIFIER_OFFSET + NOTE_DIVERSIFIER_SIZE;
const NOTE_RSEED_OFFSET: usize = NOTE_VALUE_OFFSET + NOTE_VALUE_SIZE;

/// The size of a v2 compact note.
pub const COMPACT_NOTE_SIZE_V2: usize =
    NOTE_VERSION_SIZE + NOTE_DIVERSIFIER_SIZE + NOTE_VALUE_SIZE + NOTE_RSEED_SIZE;

/// The size of the encoding of a ZSA asset id.
const ZSA_ASSET_SIZE: usize = 32;

/// The size of a v3 compact note.
pub const COMPACT_NOTE_SIZE_V3: usize = COMPACT_NOTE_SIZE_V2 + ZSA_ASSET_SIZE;

pub(crate) type Memo = [u8; MEMO_SIZE];

macro_rules! define_note_byte_types {
    ($COMPACT_NOTE_SIZE:ident) => {
        const COMPACT_NOTE_SIZE: usize = $COMPACT_NOTE_SIZE;

        /// The size of [`NotePlaintextBytes`].
        pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + MEMO_SIZE;
        /// The size of an encrypted note plaintext.
        pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

        /// a type to represent the raw bytes of a note plaintext.
        #[derive(Clone, Debug)]
        pub struct NotePlaintextBytes(pub [u8; NOTE_PLAINTEXT_SIZE]);

        /// a type to represent the raw bytes of an encrypted note plaintext.
        #[derive(Clone, Copy, Debug)]
        pub struct NoteCiphertextBytes(pub [u8; ENC_CIPHERTEXT_SIZE]);

        /// a type to represent the raw bytes of a compact note.
        #[derive(Clone, Debug)]
        pub struct CompactNotePlaintextBytes(pub [u8; COMPACT_NOTE_SIZE]);

        /// a type to represent the raw bytes of an encrypted compact note.
        #[derive(Clone, Copy, Debug)]
        pub struct CompactNoteCiphertextBytes(pub [u8; COMPACT_NOTE_SIZE]);

        impl AsRef<[u8]> for NotePlaintextBytes {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl AsMut<[u8]> for NotePlaintextBytes {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl From<&[u8]> for NotePlaintextBytes {
            fn from(s: &[u8]) -> Self
            where
                Self: Sized,
            {
                NotePlaintextBytes(s.try_into().unwrap())
            }
        }

        impl AsRef<[u8]> for NoteCiphertextBytes {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl From<&[u8]> for NoteCiphertextBytes {
            fn from(s: &[u8]) -> Self
            where
                Self: Sized,
            {
                NoteCiphertextBytes(s.try_into().unwrap())
            }
        }

        impl AsRef<[u8]> for CompactNotePlaintextBytes {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl AsMut<[u8]> for CompactNotePlaintextBytes {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl From<&[u8]> for CompactNotePlaintextBytes {
            fn from(s: &[u8]) -> Self
            where
                Self: Sized,
            {
                CompactNotePlaintextBytes(s.try_into().unwrap())
            }
        }

        impl AsRef<[u8]> for CompactNoteCiphertextBytes {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl From<&[u8]> for CompactNoteCiphertextBytes {
            fn from(s: &[u8]) -> Self
            where
                Self: Sized,
            {
                CompactNoteCiphertextBytes(s.try_into().unwrap())
            }
        }
    };
}

pub(crate) use define_note_byte_types;

/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_ock_orchard(
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

/// note_version will return the version of the note plaintext.
pub fn note_version(plaintext: &[u8]) -> Option<u8> {
    match plaintext[0] {
        0x02 => Some(0x02),
        0x03 => Some(0x03),
        _ => None,
    }
}

pub(crate) fn build_base_note_plaintext_bytes<const NOTE_PLAINTEXT_SIZE: usize>(
    version: u8,
    note: &Note,
) -> [u8; NOTE_PLAINTEXT_SIZE] {
    let mut np = [0; NOTE_PLAINTEXT_SIZE];

    np[NOTE_VERSION_OFFSET] = version;
    np[NOTE_DIVERSIFIER_OFFSET..NOTE_VALUE_OFFSET]
        .copy_from_slice(note.recipient().diversifier().as_array());
    np[NOTE_VALUE_OFFSET..NOTE_RSEED_OFFSET].copy_from_slice(&note.value().to_bytes());
    np[NOTE_RSEED_OFFSET..COMPACT_NOTE_SIZE_V2].copy_from_slice(note.rseed().as_bytes());

    np
}

/// FIXME: add doc
pub trait OrchardDomain: fmt::Debug + Clone {
    /// The size of a compact note.
    const COMPACT_NOTE_SIZE: usize;

    /// A type to represent the raw bytes of a note plaintext.
    type NotePlaintextBytes: AsRef<[u8]> + AsMut<[u8]> + for<'a> From<&'a [u8]>;
    /// A type to represent the raw bytes of an encrypted note plaintext.
    type NoteCiphertextBytes: AsRef<[u8]> + for<'a> From<&'a [u8]> + Clone + Copy;
    /// A type to represent the raw bytes of a compact note.
    type CompactNotePlaintextBytes: AsRef<[u8]> + AsMut<[u8]> + for<'a> From<&'a [u8]>;
    /// A type to represent the raw bytes of an encrypted compact note.
    type CompactNoteCiphertextBytes: AsRef<[u8]> + for<'a> From<&'a [u8]> + Clone + Copy;

    /// Builds NotePlaintextBytes from Note and Memo.
    fn build_note_plaintext_bytes(note: &Note, memo: &Memo) -> Self::NotePlaintextBytes;
}

/// Orchard-specific note encryption logic.
#[derive(Debug, Clone)]
pub struct OrchardType<D: OrchardDomain> {
    rho: Nullifier,
    phantom: std::marker::PhantomData<D>,
}

impl<D: OrchardDomain> OrchardType<D> {
    /// Domain-specific requirements:
    /// - If the note version is 3, the `plaintext` must contain a valid encoding of a ZSA asset type.
    pub fn orchard_parse_note_plaintext_without_memo<F>(
        domain: &Self,
        plaintext: &D::CompactNotePlaintextBytes,
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
            plaintext.as_ref()[NOTE_RSEED_OFFSET..COMPACT_NOTE_SIZE_V2]
                .try_into()
                .unwrap(),
            &domain.rho,
        ))?;

        let pk_d = get_validated_pk_d(&diversifier)?;
        let recipient = Address::from_parts(diversifier, pk_d);

        let asset = match note_version(plaintext.as_ref())? {
            0x02 => AssetBase::native(),
            0x03 => {
                let bytes = plaintext.as_ref()[COMPACT_NOTE_SIZE_V2..COMPACT_NOTE_SIZE_V3]
                    .try_into()
                    .unwrap();
                AssetBase::from_bytes(bytes).unwrap()
            }
            _ => panic!("invalid note version"),
        };

        let note = Option::from(Note::from_parts(recipient, value, asset, domain.rho, rseed))?;
        Some((note, recipient))
    }

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<A>(act: &Action<A, D>) -> Self {
        Self::for_nullifier(*act.nullifier())
    }

    /// Constructs a domain from a nullifier.
    // FIXME: is this unused?
    pub fn for_nullifier(nullifier: Nullifier) -> Self {
        Self {
            rho: nullifier,
            phantom: Default::default(),
        }
    }
}

impl<D: OrchardDomain> Domain for OrchardType<D> {
    type EphemeralSecretKey = EphemeralSecretKey;
    type EphemeralPublicKey = EphemeralPublicKey;
    type PreparedEphemeralPublicKey = PreparedEphemeralPublicKey;
    type SharedSecret = SharedSecret;
    type SymmetricKey = Hash;
    type Note = Note;
    type Recipient = Address;
    type DiversifiedTransmissionKey = DiversifiedTransmissionKey;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = ValueCommitment;
    type ExtractedCommitment = ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = Memo;

    type NotePlaintextBytes = D::NotePlaintextBytes;
    type NoteCiphertextBytes = D::NoteCiphertextBytes;
    type CompactNotePlaintextBytes = D::CompactNotePlaintextBytes;
    type CompactNoteCiphertextBytes = D::CompactNoteCiphertextBytes;

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        Some(note.esk())
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        PreparedEphemeralPublicKey::new(epk)
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        esk.derive_public(note.recipient().g_d())
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        esk.agree(pk_d)
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        epk.agree(ivk)
    }

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey {
        secret.kdf_orchard(ephemeral_key)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> D::NotePlaintextBytes {
        D::build_note_plaintext_bytes(note, memo)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        prf_ock_orchard(ovk, cv, cmstar_bytes, ephemeral_key)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut op = [0; OUT_PLAINTEXT_SIZE];
        op[..32].copy_from_slice(&note.recipient().pk_d().to_bytes());
        op[32..].copy_from_slice(&esk.0.to_repr());
        OutPlaintextBytes(op)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk.to_bytes()
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        EphemeralPublicKey::from_bytes(&ephemeral_key.0).into()
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.commitment().into()
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &D::CompactNotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        Self::orchard_parse_note_plaintext_without_memo(self, plaintext, |diversifier| {
            Some(DiversifiedTransmissionKey::derive(ivk, diversifier))
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &D::CompactNotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        Self::orchard_parse_note_plaintext_without_memo(self, plaintext, |_| Some(*pk_d))
    }

    // FIXME: consider implementing and using:
    // OrchardDomain::split_note_plaintext(plaintext: &Self::NotePlaintextBytes) -> (Self::CompactNotePlaintextBytes, Memo)
    fn extract_memo(
        &self,
        plaintext: &D::NotePlaintextBytes,
    ) -> (Self::CompactNotePlaintextBytes, Self::Memo) {
        let (compact, memo) = plaintext.as_ref().split_at(D::COMPACT_NOTE_SIZE);
        (compact.try_into().unwrap(), memo.try_into().unwrap())
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        DiversifiedTransmissionKey::from_bytes(out_plaintext.0[0..32].try_into().unwrap()).into()
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        EphemeralSecretKey::from_bytes(out_plaintext.0[32..OUT_PLAINTEXT_SIZE].try_into().unwrap())
            .into()
    }
}

impl<D: OrchardDomain> BatchDomain for OrchardType<D> {
    fn batch_kdf<'a>(
        items: impl Iterator<Item = (Option<Self::SharedSecret>, &'a EphemeralKeyBytes)>,
    ) -> Vec<Option<Self::SymmetricKey>> {
        let (shared_secrets, ephemeral_keys): (Vec<_>, Vec<_>) = items.unzip();

        SharedSecret::batch_to_affine(shared_secrets)
            .zip(ephemeral_keys.into_iter())
            .map(|(secret, ephemeral_key)| {
                secret.map(|dhsecret| SharedSecret::kdf_orchard_inner(dhsecret, ephemeral_key))
            })
            .collect()
    }
}

impl<A, D: OrchardDomain> ShieldedOutput<OrchardType<D>> for Action<A, D> {
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
    Action<A, D>: ShieldedOutput<OrchardType<D>>,
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

impl<D: OrchardDomain> ShieldedOutput<OrchardType<D>> for CompactAction<D> {
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
