use core::iter;

use bitvec::{array::BitArray, order::Lsb0};
use group::ff::{PrimeField, PrimeFieldBits};
use halo2_gadgets::sinsemilla::primitives as sinsemilla;
use pasta_curves::pallas;
use subtle::{ConstantTimeEq, CtOption};

use crate::{
    constants::{
        fixed_bases::{NOTE_COMMITMENT_PERSONALIZATION, NOTE_ZSA_COMMITMENT_PERSONALIZATION},
        L_ORCHARD_BASE,
    },
    note::asset_base::AssetBase,
    spec::extract_p,
    value::NoteValue,
};

#[derive(Clone, Debug)]
pub(crate) struct NoteCommitTrapdoor(pub(super) pallas::Scalar);

impl NoteCommitTrapdoor {
    pub(crate) fn inner(&self) -> pallas::Scalar {
        self.0
    }
}

/// A commitment to a note.
#[derive(Clone, Debug)]
pub struct NoteCommitment(pub(super) pallas::Point);

impl NoteCommitment {
    pub(crate) fn inner(&self) -> pallas::Point {
        self.0
    }
}

impl NoteCommitment {
    /// $NoteCommit^Orchard$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.4: Sinsemilla commitments][concretesinsemillacommit].
    ///
    /// [concretesinsemillacommit]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
    pub(super) fn derive(
        g_d: [u8; 32],
        pk_d: [u8; 32],
        v: NoteValue,
        asset: AssetBase,
        rho: pallas::Base,
        psi: pallas::Base,
        rcm: NoteCommitTrapdoor,
    ) -> CtOption<Self> {
        let g_d_bits = BitArray::<_, Lsb0>::new(g_d);
        let pk_d_bits = BitArray::<_, Lsb0>::new(pk_d);
        let v_bits = v.to_le_bits();
        let rho_bits = rho.to_le_bits();
        let psi_bits = psi.to_le_bits();

        let zec_note_bits = iter::empty()
            .chain(g_d_bits.iter().by_vals())
            .chain(pk_d_bits.iter().by_vals())
            .chain(v_bits.iter().by_vals())
            .chain(rho_bits.iter().by_vals().take(L_ORCHARD_BASE))
            .chain(psi_bits.iter().by_vals().take(L_ORCHARD_BASE));

        let type_bits = BitArray::<_, Lsb0>::new(asset.to_bytes());
        let zsa_note_bits = iter::empty()
            .chain(g_d_bits.iter().by_vals())
            .chain(pk_d_bits.iter().by_vals())
            .chain(v_bits.iter().by_vals())
            .chain(rho_bits.iter().by_vals().take(L_ORCHARD_BASE))
            .chain(psi_bits.iter().by_vals().take(L_ORCHARD_BASE))
            .chain(type_bits.iter().by_vals());

        let zec_domain = sinsemilla::CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
        let zsa_domain = sinsemilla::CommitDomain::new(NOTE_ZSA_COMMITMENT_PERSONALIZATION);

        let zec_hash_point = zec_domain.hash_to_point_inner(zec_note_bits);
        let zsa_hash_point = zsa_domain.hash_to_point_inner(zsa_note_bits);

        let zec_blind = zec_domain.blinding_factor(&rcm.0);
        let zsa_blind = zsa_domain.blinding_factor(&rcm.0);

        if asset.is_native().into() {
            CtOption::<pallas::Point>::from(zec_hash_point)
                .map(|p| p + zec_blind)
                .map(NoteCommitment)
        } else {
            CtOption::<pallas::Point>::from(zsa_hash_point)
                .map(|p| p + zsa_blind)
                .map(NoteCommitment)
        }
    }
}

/// The x-coordinate of the commitment to a note.
#[derive(Copy, Clone, Debug)]
pub struct ExtractedNoteCommitment(pub(super) pallas::Base);

impl ExtractedNoteCommitment {
    /// Deserialize the extracted note commitment from a byte array.
    ///
    /// This method enforces the [consensus rule][cmxcanon] that the
    /// byte representation of cmx MUST be canonical.
    ///
    /// [cmxcanon]: https://zips.z.cash/protocol/protocol.pdf#actionencodingandconsensus
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(ExtractedNoteCommitment)
    }

    /// Serialize the value commitment to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl From<NoteCommitment> for ExtractedNoteCommitment {
    fn from(cm: NoteCommitment) -> Self {
        ExtractedNoteCommitment(extract_p(&cm.0))
    }
}

impl ExtractedNoteCommitment {
    pub(crate) fn inner(&self) -> pallas::Base {
        self.0
    }
}

impl From<&ExtractedNoteCommitment> for [u8; 32] {
    fn from(cmx: &ExtractedNoteCommitment) -> Self {
        cmx.to_bytes()
    }
}

impl ConstantTimeEq for ExtractedNoteCommitment {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ExtractedNoteCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ExtractedNoteCommitment {}
