use core::iter;

use bitvec::{array::BitArray, order::Lsb0};
use group::ff::{PrimeField, PrimeFieldBits};
use halo2_gadgets::sinsemilla::primitives as sinsemilla;
use halo2_gadgets::sinsemilla::primitives::append_hash_to_point;
use pasta_curves::pallas;
use subtle::{ConstantTimeEq, CtOption};

use crate::{
    constants::{
        fixed_bases::{NOTE_COMMITMENT_PERSONALIZATION, NOTE_ZSA_COMMITMENT_PERSONALIZATION},
        sinsemilla::K,
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

        let remaining_bits =
            (g_d_bits.len() + pk_d_bits.len() + v_bits.len() + 2 * L_ORCHARD_BASE) % K;

        let (psi_bits_left, psi_bits_right) = psi_bits.split_at(L_ORCHARD_BASE - remaining_bits);

        let common_bits = iter::empty()
            .chain(g_d_bits.iter().by_vals())
            .chain(pk_d_bits.iter().by_vals())
            .chain(v_bits.iter().by_vals())
            .chain(rho_bits.iter().by_vals().take(L_ORCHARD_BASE))
            .chain(psi_bits_left.iter().by_vals());

        let zec_suffix = psi_bits_right.iter().by_vals().take(remaining_bits);
        let type_bits = BitArray::<_, Lsb0>::new(asset.to_bytes());
        let zsa_suffix = iter::empty()
            .chain(psi_bits_right.iter().by_vals().take(remaining_bits))
            .chain(type_bits.iter().by_vals());

        Self::double_constant_time_commit(
            NOTE_COMMITMENT_PERSONALIZATION,
            NOTE_ZSA_COMMITMENT_PERSONALIZATION,
            common_bits,
            zec_suffix,
            zsa_suffix,
            rcm,
            asset.is_native().into(),
        )
    }

    /// Evaluates `SinsemillaCommit_{rcm}(personalization1, common_bits||suffix1)` and
    /// `SinsemillaCommit_{rcm}(personalization2, common_bits||suffix2)` and returns the commit
    /// corresponding to the choice.
    ///
    /// We would like to have a constant time implementation even if suffix1 and suffix2 have not
    /// the same length.
    /// `common_bits` must be a multiple of K bits
    fn double_constant_time_commit(
        personalization1: &str,
        personalization2: &str,
        common_bits: impl Iterator<Item = bool>,
        suffix1: impl Iterator<Item = bool>,
        suffix2: impl Iterator<Item = bool>,
        rcm: NoteCommitTrapdoor,
        choice: bool,
    ) -> CtOption<Self> {
        // Select the desired personalization
        let domain = if choice {
            sinsemilla::CommitDomain::new(personalization1)
        } else {
            sinsemilla::CommitDomain::new(personalization2)
        };
        // Evaluate the hash on the `common_bits`
        let common_hash = domain.hash_to_point_inner(common_bits);
        // Continue to evaluate the hash from the previous hash with each possible suffix
        // We would like to have a constant time implementation. Hence, we have to evaluate the
        // hash for the both suffixes
        let hash1 = append_hash_to_point(common_hash, suffix1);
        let hash2 = append_hash_to_point(common_hash, suffix2);
        // Select the desired hash
        let note_hash = if choice { hash1 } else { hash2 };
        // Evaluate the commitment from this hash point
        domain
            .commit_from_hash_point(note_hash, &rcm.0)
            .map(NoteCommitment)
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
