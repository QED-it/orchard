//! In-band secret distribution for Orchard bundles.

use blake2b_simd::{Hash, Params};
use core::fmt;
use group::ff::PrimeField;
use zcash_note_encryption::{BatchDomain, Domain, EphemeralKeyBytes, OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE, OUT_PLAINTEXT_SIZE};

use crate::note::NoteType;
use crate::{
    action::Action,
    keys::{
        DiversifiedTransmissionKey, Diversifier, EphemeralPublicKey, EphemeralSecretKey,
        IncomingViewingKey, OutgoingViewingKey, SharedSecret,
    },
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed},
    spec::diversify_hash,
    value::{NoteValue, ValueCommitment},
    Address, Note,
};

const PRF_OCK_ORCHARD_PERSONALIZATION: &[u8; 16] = b"Zcash_Orchardock";

// TODO: VA: Need to remove redundant definitions here, and move them from the top if Orchard domain specific
/// The size of the encoding of a ZSA asset type.
const ZSA_TYPE_SIZE: usize = 32;
/// The size of the encoding of the note plaintext post ZSA.
const ZSA_NOTE_PLAINTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + ZSA_TYPE_SIZE;
/// The size of the encrypted ciphertext of the ZSA variant of a note.
const ZSA_ENC_CIPHERTEXT_SIZE: usize = ENC_CIPHERTEXT_SIZE + ZSA_TYPE_SIZE;
/// The size of the ZSA variant of a compact note.
const COMPACT_ZSA_NOTE_SIZE: usize = COMPACT_NOTE_SIZE + ZSA_TYPE_SIZE;
/// The size of the memo.
const MEMO_SIZE: usize = NOTE_PLAINTEXT_SIZE - COMPACT_NOTE_SIZE;
/// The size of the AEAD tag.
const AEAD_TAG_SIZE: usize = ZSA_ENC_CIPHERTEXT_SIZE - ZSA_NOTE_PLAINTEXT_SIZE;

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

// TODO: VA: Needs updating
/// Domain-specific requirements:
/// - If the note version is 3, the `plaintext` must contain a valid encoding of a ZSA asset type.
fn orchard_parse_note_plaintext_without_memo<F>(
    domain: &OrchardDomain,
    plaintext: &[u8],
    get_validated_pk_d: F,
) -> Option<(Note, Address)>
where
    F: FnOnce(&Diversifier) -> Option<DiversifiedTransmissionKey>,
{
    assert!(plaintext.len() == COMPACT_NOTE_SIZE || plaintext.len() == COMPACT_ZSA_NOTE_SIZE ||
        plaintext.len() == NOTE_PLAINTEXT_SIZE || plaintext.len() == ZSA_NOTE_PLAINTEXT_SIZE);

    // Check note plaintext version
    // and parse the asset type accordingly.
    let note_type = parse_version_and_asset_type(plaintext)?;

    // The unwraps below are guaranteed to succeed by the assertion above
    let diversifier = Diversifier::from_bytes(plaintext[1..12].try_into().unwrap());
    let value = NoteValue::from_bytes(plaintext[12..20].try_into().unwrap());
    let rseed = Option::from(RandomSeed::from_bytes(
        plaintext[20..COMPACT_NOTE_SIZE].try_into().unwrap(),
        &domain.rho,
    ))?;

    let pk_d = get_validated_pk_d(&diversifier)?;

    let recipient = Address::from_parts(diversifier, pk_d);

    let note = Option::from(Note::from_parts(recipient, value, note_type, domain.rho, rseed))?;
    Some((note, recipient))
}

fn parse_version_and_asset_type(plaintext: &[u8]) -> Option<NoteType> {
    match plaintext[0] {
        0x02 if plaintext.len() == COMPACT_NOTE_SIZE || plaintext.len() == NOTE_PLAINTEXT_SIZE => Some(NoteType::native()),
        0x03 if plaintext.len() == COMPACT_ZSA_NOTE_SIZE || plaintext.len() == ZSA_NOTE_PLAINTEXT_SIZE => {
            let bytes = &plaintext[COMPACT_NOTE_SIZE..COMPACT_ZSA_NOTE_SIZE]
                .try_into()
                .unwrap();
            NoteType::from_bytes(bytes).into()
        }
        _ => None,
    }
}

/// Orchard-specific note encryption logic.
#[derive(Debug)]
pub struct OrchardDomain {
    rho: Nullifier,
}

/// Newtype for encoding the note plaintext post ZSA.
// pub struct NotePlaintextZSA (pub [u8; ZSA_NOTE_PLAINTEXT_SIZE]);
#[derive(Clone, Debug)]
pub enum NotePlaintextZSA {
    /// Variant for old note plaintexts.
    V2OLD([u8; NOTE_PLAINTEXT_SIZE]),
    /// Variant for the new note plaintexts post ZSA.
    V3ZSA([u8; ZSA_NOTE_PLAINTEXT_SIZE]),
}

impl AsMut<[u8]> for NotePlaintextZSA {
    fn as_mut(&mut self) -> &mut [u8] {
        let ptr: &mut [u8];
        match self {
            NotePlaintextZSA::V2OLD(x) => ptr = x,
            NotePlaintextZSA::V3ZSA(x) => ptr = x,
        }
        ptr
    }
}

/// Newtype for encoding the encrypted note ciphertext post ZSA.
// pub struct EncNoteCiphertextZSA (pub [u8; ZSA_ENC_CIPHERTEXT_SIZE]);
#[derive(Clone, Debug)]
pub enum EncNoteCiphertextZSA {
    /// Variant for old encrypted note ciphertexts.
    V2OLD([u8; ENC_CIPHERTEXT_SIZE]),
    /// Variant for new encrypted note ciphertexts post ZSA.
    V3ZSA([u8; ZSA_ENC_CIPHERTEXT_SIZE]),
}

impl From<(NotePlaintextZSA,[u8; AEAD_TAG_SIZE])> for EncNoteCiphertextZSA {
    fn from((np,t): (NotePlaintextZSA, [u8; AEAD_TAG_SIZE])) -> Self {
        match np {
            NotePlaintextZSA::V2OLD(npx) => {
                let mut nc = [0u8; ENC_CIPHERTEXT_SIZE];
                nc[..NOTE_PLAINTEXT_SIZE].copy_from_slice(&npx);
                nc[NOTE_PLAINTEXT_SIZE..].copy_from_slice(&t);
                EncNoteCiphertextZSA::V2OLD(nc)
            },
            NotePlaintextZSA::V3ZSA(npx) => {
                let mut nc = [0u8; ZSA_ENC_CIPHERTEXT_SIZE];
                nc[..ZSA_NOTE_PLAINTEXT_SIZE].copy_from_slice(&npx);
                nc[ZSA_NOTE_PLAINTEXT_SIZE..].copy_from_slice(&t);
                EncNoteCiphertextZSA::V3ZSA(nc)
            },
        }
    }
}

impl AsRef<[u8]> for EncNoteCiphertextZSA {
    fn as_ref(&self) -> &[u8] {
        match self {
            EncNoteCiphertextZSA::V2OLD(x) => x,
            EncNoteCiphertextZSA::V3ZSA(x) => x,
        }
    }
}

/// Newtype for encoding a compact note post ZSA.
// pub struct CompactNoteZSA (pub [u8; COMPACT_ZSA_NOTE_SIZE]);
#[derive(Clone, Debug)]
pub enum CompactNoteZSA {
    /// Variant for old compact notes.
    V2OLD([u8; COMPACT_NOTE_SIZE]),
    /// Variant for new compact notes post ZSA.
    V3ZSA([u8; COMPACT_ZSA_NOTE_SIZE]),
}

impl AsMut<[u8]> for CompactNoteZSA {
    fn as_mut(&mut self) -> &mut [u8] {
        let ptr: &mut [u8];
        match self {
            CompactNoteZSA::V2OLD(x) => ptr = x,
            CompactNoteZSA::V3ZSA(x) => ptr = x,
        }
        ptr
    }
}

impl From<NotePlaintextZSA> for CompactNoteZSA {
    fn from(np: NotePlaintextZSA) -> Self {
        match np {
            NotePlaintextZSA::V2OLD(npx) => {
                let mut cnp = [0u8; COMPACT_NOTE_SIZE];
                cnp.copy_from_slice(&npx[..COMPACT_NOTE_SIZE]);
                CompactNoteZSA::V2OLD(cnp)
            },
            NotePlaintextZSA::V3ZSA(npx) => {
                let mut cnp = [0u8; COMPACT_ZSA_NOTE_SIZE];
                cnp.copy_from_slice(&npx[..COMPACT_ZSA_NOTE_SIZE]);
                CompactNoteZSA::V3ZSA(cnp)
            }
        }
    }
}

impl OrchardDomain {
    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<T>(act: &Action<T>) -> Self {
        OrchardDomain {
            rho: *act.nullifier(),
        }
    }

    /// Constructs a domain from a nullifier.
    pub fn for_nullifier(nullifier: Nullifier) -> Self {
        OrchardDomain { rho: nullifier }
    }
}

impl Domain for OrchardDomain {
    type EphemeralSecretKey = EphemeralSecretKey;
    type EphemeralPublicKey = EphemeralPublicKey;
    type PreparedEphemeralPublicKey = EphemeralPublicKey;
    type SharedSecret = SharedSecret;
    type SymmetricKey = Hash;
    type Note = Note;
    type NotePlaintextBytes = NotePlaintextZSA;
    type EncNoteCiphertextBytes = EncNoteCiphertextZSA;
    type CompactNotePlaintextBytes = CompactNoteZSA;
    type CompactEncNoteCiphertextBytes = CompactNoteZSA;
    type Recipient = Address;
    type DiversifiedTransmissionKey = DiversifiedTransmissionKey;
    type IncomingViewingKey = IncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = ValueCommitment;
    type ExtractedCommitment = ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = [u8; MEMO_SIZE]; // TODO use a more interesting type

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        Some(note.esk())
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        epk
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

    fn note_plaintext_bytes(
        note: &Self::Note,
        _: &Self::Recipient,
        memo: &Self::Memo,
    ) -> NotePlaintextZSA {

        let mut np = [0u8; ZSA_NOTE_PLAINTEXT_SIZE];
        np[0] = 0x03;
        np[1..12].copy_from_slice(note.recipient().diversifier().as_array());
        np[12..20].copy_from_slice(&note.value().to_bytes());
        np[20..52].copy_from_slice(note.rseed().as_bytes());
        let zsa_type = note.note_type().to_bytes();
        np[52..84].copy_from_slice(&zsa_type);
        np[84..].copy_from_slice(memo);
        NotePlaintextZSA::V3ZSA(np)
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
        plaintext: &CompactNoteZSA,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let ptr: &[u8];
        match plaintext {
            CompactNoteZSA::V2OLD(x) => ptr = x,
            CompactNoteZSA::V3ZSA(x) => ptr = x,
        }
        orchard_parse_note_plaintext_without_memo(self, ptr, |diversifier| {
            Some(DiversifiedTransmissionKey::derive(ivk, diversifier))
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        esk: &Self::EphemeralSecretKey,
        ephemeral_key: &EphemeralKeyBytes,
        plaintext: &CompactNoteZSA,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let ptr: &[u8];
        match plaintext {
            CompactNoteZSA::V2OLD(x) => ptr = x,
            CompactNoteZSA::V3ZSA(x) => ptr = x,
        }
        orchard_parse_note_plaintext_without_memo(self, ptr, |diversifier| {
            if esk
                .derive_public(diversify_hash(diversifier.as_array()))
                .to_bytes()
                .0
                == ephemeral_key.0
            {
                Some(*pk_d)
            } else {
                None
            }
        })
    }

    fn extract_memo(&self, plaintext: &NotePlaintextZSA) -> Self::Memo {
        let mut memo = [0u8; MEMO_SIZE];
        match plaintext {
            NotePlaintextZSA::V2OLD(np) => memo.copy_from_slice(&np[COMPACT_NOTE_SIZE..]),
            NotePlaintextZSA::V3ZSA(np) => memo.copy_from_slice(&np[COMPACT_ZSA_NOTE_SIZE..]),
        }
        memo
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        DiversifiedTransmissionKey::from_bytes(out_plaintext.0[0..32].try_into().unwrap()).into()
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        EphemeralSecretKey::from_bytes(out_plaintext.0[32..OUT_PLAINTEXT_SIZE].try_into().unwrap())
            .into()
    }

    fn separate_tag_from_ciphertext(enc_ciphertext: &Self::EncNoteCiphertextBytes) -> (Self::NotePlaintextBytes, [u8; AEAD_TAG_SIZE]) {
        match enc_ciphertext {
            EncNoteCiphertextZSA::V2OLD(ncx) => {
                let mut np = [0u8; NOTE_PLAINTEXT_SIZE];
                let mut tag = [0u8; AEAD_TAG_SIZE];

                np.copy_from_slice(&ncx[..NOTE_PLAINTEXT_SIZE]);
                tag.copy_from_slice(&ncx[NOTE_PLAINTEXT_SIZE..]);

                (NotePlaintextZSA::V2OLD(np), tag)
            },
            EncNoteCiphertextZSA::V3ZSA(ncx) => {
                let mut np = [0u8; ZSA_NOTE_PLAINTEXT_SIZE];
                let mut tag = [0u8; AEAD_TAG_SIZE];

                np.copy_from_slice(&ncx[..ZSA_NOTE_PLAINTEXT_SIZE]);
                tag.copy_from_slice(&ncx[ZSA_NOTE_PLAINTEXT_SIZE..]);

                (NotePlaintextZSA::V3ZSA(np), tag)
            },
        }

    }

    fn convert_to_compact_plaintext_type(enc_ciphertext: &Self::CompactEncNoteCiphertextBytes) -> Self::CompactNotePlaintextBytes {
        match enc_ciphertext {
            CompactNoteZSA::V2OLD(comp) => {
                let mut comp_new = [0u8; COMPACT_NOTE_SIZE];
                comp_new.copy_from_slice(comp);
                CompactNoteZSA::V2OLD(comp_new)
            },
            CompactNoteZSA::V3ZSA(comp) => {
                let mut comp_new = [0u8; COMPACT_ZSA_NOTE_SIZE];
                comp_new.copy_from_slice(comp);
                CompactNoteZSA::V3ZSA(comp_new)
            },
        }
    }
}

impl BatchDomain for OrchardDomain {
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

fn get_note_version(plaintext: &NotePlaintextZSA) -> Option<u8> {
    match plaintext {
        NotePlaintextZSA::V2OLD(x) if x[0] == 0x02 => Some(0x02),
        NotePlaintextZSA::V3ZSA(x) if x[0] == 0x03 => Some(0x03),
        _ => None,
    }
}

/// Implementation of in-band secret distribution for Orchard bundles.
pub type OrchardNoteEncryption = zcash_note_encryption::NoteEncryption<OrchardDomain>;

impl<T> ShieldedOutput<OrchardDomain> for Action<T> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> Option<EncNoteCiphertextZSA> {
        let result = self.encrypted_note().enc_ciphertext.clone();
        Some(result)
    }

    fn enc_ciphertext_compact(&self) -> CompactNoteZSA {
        match self.encrypted_note().enc_ciphertext {
            EncNoteCiphertextZSA::V2OLD(ncx) => {
                let mut enc_ct_comp = [0u8; COMPACT_NOTE_SIZE];
                enc_ct_comp.copy_from_slice(&ncx[..COMPACT_NOTE_SIZE]);
                CompactNoteZSA::V2OLD(enc_ct_comp)
            },
            EncNoteCiphertextZSA::V3ZSA(ncx) => {
                let mut enc_ct_comp = [0u8; COMPACT_ZSA_NOTE_SIZE];
                enc_ct_comp.copy_from_slice(&ncx[..COMPACT_ZSA_NOTE_SIZE]);
                CompactNoteZSA::V3ZSA(enc_ct_comp)
            },
        }
    }
}

/// A compact Action for light clients.
pub struct CompactAction {
    nullifier: Nullifier,
    cmx: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: CompactNoteZSA,
}

impl fmt::Debug for CompactAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompactAction")
    }
}

impl<T> From<&Action<T>> for CompactAction {
    fn from(action: &Action<T>) -> Self {
        let comp_ciphertext: CompactNoteZSA = match action.encrypted_note().enc_ciphertext {
            EncNoteCiphertextZSA::V2OLD(ncx) => {
                let mut comp_x = [0u8; COMPACT_NOTE_SIZE];
                comp_x.copy_from_slice(&ncx[..COMPACT_NOTE_SIZE]);
                CompactNoteZSA::V2OLD(comp_x)
            },
            EncNoteCiphertextZSA::V3ZSA(ncx) => {
                let mut comp_x = [0u8; COMPACT_ZSA_NOTE_SIZE];
                comp_x.copy_from_slice(&ncx[..COMPACT_ZSA_NOTE_SIZE]);
                CompactNoteZSA::V3ZSA(comp_x)
            },
        };
        CompactAction {
            nullifier: *action.nullifier(),
            cmx: *action.cmx(),
            ephemeral_key: action.ephemeral_key(),
            enc_ciphertext: comp_ciphertext,
        }
    }
}

impl ShieldedOutput<OrchardDomain> for CompactAction {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key.0)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }

    fn enc_ciphertext(&self) -> Option<EncNoteCiphertextZSA> {
        None
    }

    fn enc_ciphertext_compact(&self) -> CompactNoteZSA {
        let result = self.enc_ciphertext.clone();
        result
    }
}

impl CompactAction {
    /// Create a CompactAction from its constituent parts
    pub fn from_parts(
        nullifier: Nullifier,
        cmx: ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: CompactNoteZSA,
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use zcash_note_encryption::{
        try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ovk, Domain,
        EphemeralKeyBytes,
    };

    use super::{prf_ock_orchard, CompactAction, OrchardDomain, OrchardNoteEncryption};
    use crate::note::NoteType;
    use crate::{
        action::Action,
        keys::{
            DiversifiedTransmissionKey, Diversifier, EphemeralSecretKey, IncomingViewingKey,
            OutgoingViewingKey,
        },
        note::{
            testing::arb_note, ExtractedNoteCommitment, Nullifier, RandomSeed,
            TransmittedNoteCiphertext,
        },
        note_encryption::get_note_version,
        primitives::redpallas,
        value::{NoteValue, ValueCommitment},
        Address, Note,
    };

    use super::orchard_parse_note_plaintext_without_memo;

    proptest! {
    #[test]
    fn test_encoding_roundtrip(
        note in arb_note(NoteValue::from_raw(10)),
    ) {
        let memo = &crate::test_vectors::note_encryption::test_vectors()[0].memo;

        // Encode.
        let plaintext = OrchardDomain::note_plaintext_bytes(&note, &note.recipient(), memo);

        // Decode.
        let domain = OrchardDomain { rho: note.rho() };
        let parsed_version = get_note_version(&plaintext).unwrap();
        let parsed_memo = domain.extract_memo(&plaintext);

        let (parsed_note, parsed_recipient) = orchard_parse_note_plaintext_without_memo(&domain, &plaintext.0,
            |diversifier| {
                assert_eq!(diversifier, &note.recipient().diversifier());
                Some(*note.recipient().pk_d())
            }
        ).expect("Plaintext parsing failed");

        // Check.
        assert_eq!(parsed_note, note);
        assert_eq!(parsed_recipient, note.recipient());

        if parsed_note.note_type().is_native().into() {
            assert_eq!(parsed_version, 0x02);
            assert_eq!(&parsed_memo, memo);
        } else {
            assert_eq!(parsed_version, 0x03);
            let mut short_memo = *memo;
            short_memo[512 - 32..].copy_from_slice(&[0; 32]);
            assert_eq!(parsed_memo, short_memo);
        }
    }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::test_vectors();

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            // Recipient key material
            let ivk = IncomingViewingKey::from_bytes(&tv.incoming_viewing_key).unwrap();
            let ovk = OutgoingViewingKey::from(tv.ovk);
            let d = Diversifier::from_bytes(tv.default_d);
            let pk_d = DiversifiedTransmissionKey::from_bytes(&tv.default_pk_d).unwrap();

            // Received Action
            let cv_net = ValueCommitment::from_bytes(&tv.cv_net).unwrap();
            let rho = Nullifier::from_bytes(&tv.rho).unwrap();
            let cmx = ExtractedNoteCommitment::from_bytes(&tv.cmx).unwrap();

            let esk = EphemeralSecretKey::from_bytes(&tv.esk).unwrap();
            let ephemeral_key = EphemeralKeyBytes(tv.ephemeral_key);

            // Details about the expected note
            let value = NoteValue::from_raw(tv.v);
            let rseed = RandomSeed::from_bytes(tv.rseed, &rho).unwrap();

            //
            // Test the individual components
            //

            let shared_secret = esk.agree(&pk_d);
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = shared_secret.kdf_orchard(&ephemeral_key);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ock = prf_ock_orchard(&ovk, &cv_net, &cmx.to_bytes(), &ephemeral_key);
            assert_eq!(ock.as_ref(), tv.ock);

            let recipient = Address::from_parts(d, pk_d);

            let note_type = match tv.note_type {
                None => NoteType::native(),
                Some(type_bytes) => NoteType::from_bytes(&type_bytes).unwrap(),
            };

            let note = Note::from_parts(recipient, value, note_type, rho, rseed).unwrap();
            assert_eq!(ExtractedNoteCommitment::from(note.commitment()), cmx);

            let action = Action::from_parts(
                // rho is the nullifier in the receiving Action.
                rho,
                // We don't need a valid rk for this test.
                redpallas::VerificationKey::dummy(),
                cmx,
                TransmittedNoteCiphertext {
                    epk_bytes: ephemeral_key.0,
                    enc_ciphertext: tv.c_enc,
                    out_ciphertext: tv.c_out,
                },
                cv_net.clone(),
                (),
            );

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            let domain = OrchardDomain { rho };

            match try_note_decryption(&domain, &ivk, &action) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_compact_note_decryption(&domain, &ivk, &CompactAction::from(&action)) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                }
                None => assert!(tv.note_type.is_some(), "Compact note decryption failed"),
                // Ignore that ZSA notes are not detected in compact decryption.
            }

            match try_output_recovery_with_ovk(&domain, &ovk, &action, &cv_net, &tv.c_out) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            //
            // Test encryption
            //

            let ne = OrchardNoteEncryption::new_with_esk(esk, Some(ovk), note, recipient, tv.memo);

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }
}
