//! Structs and logic related to aggregated information about an asset.

use crate::{value::NoteValue, Note};

/// Represents aggregated information about an asset, including its supply, finalization status,
/// and reference note.
///
/// - For bundles or global state, the reference note is always [`Note`].
/// - For actions, the reference note may be [`Option<Note>`] because some actions do not include it.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct AssetInfo<R> {
    /// The amount of the asset.
    pub amount: NoteValue,

    /// Whether or not the asset is finalized.
    pub is_finalized: bool,

    /// A reference note, which may be [`Note`] (for bundles/global state)
    /// or [`Option<Note>`] (for actions).
    pub reference_note: R,
}

/// For bundles and global state, the reference note is always provided.
pub type BundleAssetInfo = AssetInfo<Note>;

/// For actions, the reference note may be omitted if this asset is already known.
pub type ActionAssetInfo = AssetInfo<Option<Note>>;

impl BundleAssetInfo {
    /// Creates a new [`AssetInfo`] instance for an `IssueBundle`,
    /// where a reference note is always specified.
    pub fn new(amount: NoteValue, is_finalized: bool, reference_note: Note) -> Self {
        Self {
            amount,
            is_finalized,
            reference_note,
        }
    }
}

impl ActionAssetInfo {
    /// Creates a new [`AssetInfo`] instance for an `IssueAction`,
    /// where the reference note can be omitted if this is not the first issuance.
    pub fn new(amount: NoteValue, is_finalized: bool, reference_note: Option<Note>) -> Self {
        Self {
            amount,
            is_finalized,
            reference_note,
        }
    }
}
