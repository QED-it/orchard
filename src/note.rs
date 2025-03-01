//! Data structures used for note construction.
use blake2b_simd::Params;
use core::fmt;
use memuse::DynamicUsage;

use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas;
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, CtOption};

use crate::{
    domain::OrchardDomainCommon,
    keys::{EphemeralSecretKey, FullViewingKey, Scope, SpendingKey},
    spec::{to_base, to_scalar, NonZeroPallasScalar, PrfExpand},
    value::NoteValue,
    Address,
};

pub(crate) mod commitment;
pub use self::commitment::{ExtractedNoteCommitment, NoteCommitment};

pub(crate) mod nullifier;
pub use self::nullifier::Nullifier;

const ZSA_ISSUE_NOTE_RHO_PERSONALIZATION: &[u8; 16] = b"ZSA_IssueNoteRho";

/// The randomness used to construct a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rho(pallas::Base);

// We know that `pallas::Base` doesn't allocate internally.
memuse::impl_no_dynamic_usage!(Rho);

impl Rho {
    /// Deserialize the rho value from a byte array.
    ///
    /// This should only be used in cases where the components of a `Note` are being serialized and
    /// stored individually. Use [`Action::rho`] or [`CompactAction::rho`] to obtain the [`Rho`]
    /// value otherwise.
    ///
    /// [`Action::rho`]: crate::action::Action::rho
    /// [`CompactAction::rho`]: crate::domain::CompactAction::rho
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(Rho)
    }

    /// Serialize the rho value to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }

    /// Constructs the [`Rho`] value to be used to construct a new note from the revealed nullifier
    /// of the note being spent in the [`Action`] under construction.
    ///
    /// [`Action`]: crate::action::Action
    pub(crate) fn from_nf_old(nf: Nullifier) -> Self {
        Rho(nf.0)
    }

    pub(crate) fn into_inner(self) -> pallas::Base {
        self.0
    }

    /// When creating an issuance note, the rho value is initialized with the Pallas base element zero.
    /// This value will be updated later by calling `update_rho` method on the `IssueBundle`.
    pub(crate) fn zero() -> Self {
        Rho(pallas::Base::zero())
    }
}

pub(crate) mod asset_base;
pub use self::asset_base::AssetBase;

/// The ZIP 212 seed randomness for a note.
#[derive(Copy, Clone, Debug)]
pub struct RandomSeed([u8; 32]);

impl RandomSeed {
    pub(crate) fn random(rng: &mut impl RngCore, rho: &Rho) -> Self {
        loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let rseed = RandomSeed::from_bytes(bytes, rho);
            if rseed.is_some().into() {
                break rseed.unwrap();
            }
        }
    }

    /// Reads a note's random seed from bytes, given the note's rho value.
    ///
    /// Returns `None` if the rho value is not for the same note as the seed.
    pub fn from_bytes(rseed: [u8; 32], rho: &Rho) -> CtOption<Self> {
        let rseed = RandomSeed(rseed);
        let esk = rseed.esk_inner(rho);
        CtOption::new(rseed, esk.is_some())
    }

    /// Returns the byte array corresponding to this seed.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    pub(crate) fn psi(&self, rho: &Rho) -> pallas::Base {
        to_base(PrfExpand::PSI.with(&self.0, &rho.to_bytes()))
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    fn esk_inner(&self, rho: &Rho) -> CtOption<NonZeroPallasScalar> {
        NonZeroPallasScalar::from_scalar(to_scalar(
            PrfExpand::ORCHARD_ESK.with(&self.0, &rho.to_bytes()),
        ))
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    fn esk(&self, rho: &Rho) -> NonZeroPallasScalar {
        // We can't construct a RandomSeed for which this unwrap fails.
        self.esk_inner(rho).unwrap()
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    pub(crate) fn rcm(&self, rho: &Rho) -> commitment::NoteCommitTrapdoor {
        commitment::NoteCommitTrapdoor(to_scalar(
            PrfExpand::ORCHARD_RCM.with(&self.0, &rho.to_bytes()),
        ))
    }
}

impl ConditionallySelectable for RandomSeed {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let result: Vec<u8> =
            a.0.iter()
                .zip(b.0.iter())
                .map(|(a_i, b_i)| u8::conditional_select(a_i, b_i, choice))
                .collect();
        RandomSeed(<[u8; 32]>::try_from(result).unwrap())
    }
}

/// A discrete amount of funds received by an address.
#[derive(Debug, Copy, Clone)]
pub struct Note {
    /// The recipient of the funds.
    recipient: Address,
    /// The value of this note.
    value: NoteValue,
    /// The asset id of this note.
    asset: AssetBase,
    /// A unique creation ID for this note.
    ///
    /// This is produced from the nullifier of the note that will be spent in the [`Action`] that
    /// creates this note.
    ///
    /// [`Action`]: crate::action::Action
    rho: Rho,
    /// The seed randomness for various note components.
    rseed: RandomSeed,
    /// The seed randomness for split notes.
    ///
    /// If it is not a split note, this field is `None`.
    rseed_split_note: CtOption<RandomSeed>,
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        // Notes are canonically defined by their commitments.
        ExtractedNoteCommitment::from(self.commitment())
            .eq(&ExtractedNoteCommitment::from(other.commitment()))
    }
}

impl Eq for Note {}

impl Note {
    /// Creates a `Note` from its component parts.
    ///
    /// Returns `None` if a valid [`NoteCommitment`] cannot be derived from the note.
    ///
    /// # Caveats
    ///
    /// This low-level constructor enforces that the provided arguments produce an
    /// internally valid `Note`. However, it allows notes to be constructed in a way that
    /// violates required security checks for note decryption, as specified in
    /// [Section 4.19] of the Zcash Protocol Specification. Users of this constructor
    /// should only call it with note components that have been fully validated by
    /// decrypting a received note according to [Section 4.19].
    ///
    /// [Section 4.19]: https://zips.z.cash/protocol/protocol.pdf#saplingandorchardinband
    pub fn from_parts(
        recipient: Address,
        value: NoteValue,
        asset: AssetBase,
        rho: Rho,
        rseed: RandomSeed,
    ) -> CtOption<Self> {
        let note = Note {
            recipient,
            value,
            asset,
            rho,
            rseed,
            rseed_split_note: CtOption::new(rseed, 0u8.into()),
        };
        CtOption::new(note, note.commitment_inner().is_some())
    }

    /// Generates a new note.
    ///
    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    pub(crate) fn new(
        recipient: Address,
        value: NoteValue,
        asset: AssetBase,
        rho: Rho,
        mut rng: impl RngCore,
    ) -> Self {
        loop {
            let note = Note::from_parts(
                recipient,
                value,
                asset,
                rho,
                RandomSeed::random(&mut rng, &rho),
            );
            if note.is_some().into() {
                break note.unwrap();
            }
        }
    }

    /// Generates a dummy spent note.
    ///
    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    pub(crate) fn dummy(
        rng: &mut impl RngCore,
        rho: Option<Rho>,
        asset: AssetBase,
    ) -> (SpendingKey, FullViewingKey, Self) {
        let sk = SpendingKey::random(rng);
        let fvk: FullViewingKey = (&sk).into();
        let recipient = fvk.address_at(0u32, Scope::External);

        let note = Note::new(
            recipient,
            NoteValue::zero(),
            asset,
            rho.unwrap_or_else(|| Rho::from_nf_old(Nullifier::dummy(rng))),
            rng,
        );

        (sk, fvk, note)
    }

    /// Returns the recipient of this note.
    pub fn recipient(&self) -> Address {
        self.recipient
    }

    /// Returns the value of this note.
    pub fn value(&self) -> NoteValue {
        self.value
    }

    /// Returns the note type of this note.
    pub fn asset(&self) -> AssetBase {
        self.asset
    }

    /// Returns the rseed value of this note.
    pub fn rseed(&self) -> &RandomSeed {
        &self.rseed
    }

    /// Returns the rseed_split_note value of this note.
    pub fn rseed_split_note(&self) -> CtOption<RandomSeed> {
        self.rseed_split_note
    }

    /// Derives the ephemeral secret key for this note.
    pub(crate) fn esk(&self) -> EphemeralSecretKey {
        EphemeralSecretKey(self.rseed.esk(&self.rho))
    }

    /// Returns rho of this note.
    pub fn rho(&self) -> Rho {
        self.rho
    }

    /// Derives the commitment to this note.
    ///
    /// Defined in [Zcash Protocol Spec § 3.2: Notes][notes].
    ///
    /// [notes]: https://zips.z.cash/protocol/nu5.pdf#notes
    pub fn commitment(&self) -> NoteCommitment {
        // `Note` will always have a note commitment by construction.
        self.commitment_inner().unwrap()
    }

    /// Derives the commitment to this note.
    ///
    /// This is the internal fallible API, used to check at construction time that the
    /// note has a commitment. Once you have a [`Note`] object, use `note.commitment()`
    /// instead.
    ///
    /// Defined in [Zcash Protocol Spec § 3.2: Notes][notes].
    ///
    /// [notes]: https://zips.z.cash/protocol/nu5.pdf#notes
    fn commitment_inner(&self) -> CtOption<NoteCommitment> {
        let g_d = self.recipient.g_d();

        NoteCommitment::derive(
            g_d.to_bytes(),
            self.recipient.pk_d().to_bytes(),
            self.value,
            self.asset,
            self.rho.0,
            self.rseed.psi(&self.rho),
            self.rseed.rcm(&self.rho),
        )
    }

    /// Derives the nullifier for this note.
    pub fn nullifier(&self, fvk: &FullViewingKey) -> Nullifier {
        let selected_rseed = self.rseed_split_note.unwrap_or(self.rseed);

        Nullifier::derive(
            fvk.nk(),
            self.rho.0,
            selected_rseed.psi(&self.rho),
            self.commitment(),
            self.rseed_split_note.is_some(),
        )
    }

    /// Create a split note which has the same values than the input note except for
    /// `rseed_split_note` which is equal to a random seed.
    pub fn create_split_note(self, rng: &mut impl RngCore) -> Self {
        Note {
            rseed_split_note: CtOption::new(RandomSeed::random(rng, &self.rho), 1u8.into()),
            ..self
        }
    }

    /// Update the rho value of the issuance note (see
    /// [ZIP-227: Issuance of Zcash Shielded Assets][zip227]).
    ///
    /// [zip227]: https://zips.z.cash/zip-0227
    pub(crate) fn update_rho_for_issuance_note(
        &mut self,
        nullifier: &Nullifier,
        index_action: u32,
        index_note: u32,
    ) {
        self.rho = rho_for_issuance_note(nullifier, index_action, index_note);
    }
}

/// Evaluate the rho value of the issuance note (see
/// [ZIP-227: Issuance of Zcash Shielded Assets][zip227]).
///
/// [zip227]: https://zips.z.cash/zip-0227
pub(crate) fn rho_for_issuance_note(
    nullifier: &Nullifier,
    index_action: u32,
    index_note: u32,
) -> Rho {
    Rho(to_base(
        Params::new()
            .hash_length(64)
            .personal(ZSA_ISSUE_NOTE_RHO_PERSONALIZATION)
            .to_state()
            .update(&nullifier.to_bytes())
            .update(&[0x84])
            .update(index_action.to_le_bytes().as_ref())
            .update(index_note.to_le_bytes().as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    ))
}

/// An encrypted note.
#[derive(Clone)]
pub struct TransmittedNoteCiphertext<D: OrchardDomainCommon> {
    /// The serialization of the ephemeral public key
    pub epk_bytes: [u8; 32],
    /// The encrypted note ciphertext
    pub enc_ciphertext: D::NoteCiphertextBytes,
    /// An encrypted value that allows the holder of the outgoing cipher
    /// key for the note to recover the note plaintext.
    pub out_ciphertext: [u8; 80],
}

impl<D: OrchardDomainCommon> fmt::Debug for TransmittedNoteCiphertext<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransmittedNoteCiphertext")
            .field("epk_bytes", &self.epk_bytes)
            .field("enc_ciphertext", &hex::encode(self.enc_ciphertext))
            .field("out_ciphertext", &hex::encode(self.out_ciphertext))
            .finish()
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use proptest::prelude::*;

    use crate::note::asset_base::testing::arb_asset_base;
    use crate::note::AssetBase;
    use crate::value::testing::arb_note_value;
    use crate::{
        address::testing::arb_address, note::nullifier::testing::arb_nullifier, value::NoteValue,
    };

    use subtle::CtOption;

    use super::{Note, RandomSeed, Rho};

    prop_compose! {
        /// Generate an arbitrary random seed
        pub(crate) fn arb_rseed()(elems in prop::array::uniform32(prop::num::u8::ANY)) -> RandomSeed {
            RandomSeed(elems)
        }
    }

    prop_compose! {
        /// Generate an arbitrary note
        pub fn arb_note(value: NoteValue)(
            recipient in arb_address(),
            rho in arb_nullifier().prop_map(Rho::from_nf_old),
            rseed in arb_rseed(),
            asset in arb_asset_base(),
        ) -> Note {
            Note {
                recipient,
                value,
                asset,
                rho,
                rseed,
                rseed_split_note: CtOption::new(rseed, 0u8.into()),
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary native note
        pub fn arb_native_note()(
            recipient in arb_address(),
            value in arb_note_value(),
            rho in arb_nullifier().prop_map(Rho::from_nf_old),
            rseed in arb_rseed(),
        ) -> Note {
            Note {
                recipient,
                value,
                asset: AssetBase::native(),
                rho,
                rseed,
                rseed_split_note: CtOption::new(rseed, 0u8.into())
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary zsa note
        pub fn arb_zsa_note(asset: AssetBase)(
            recipient in arb_address(),
            value in arb_note_value(),
            rho in arb_nullifier().prop_map(Rho::from_nf_old),
            rseed in arb_rseed(),
        ) -> Note {
            Note {
                recipient,
                value,
                asset,
                rho,
                rseed,
                rseed_split_note: CtOption::new(rseed, 0u8.into()),
            }
        }
    }
}
