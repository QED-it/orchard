//! Structs and logic related to aggregated information about an asset.

use crate::{value::NoteValue, Note};

/// Represents aggregated information about an asset, including its supply, finalization status,
/// and reference note.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct AssetInfo {
    /// The amount of the asset.
    pub amount: NoteValue,

    /// Whether or not the asset is finalized.
    pub is_finalized: bool,

    /// A reference note
    pub reference_note: Note,
}

impl AssetInfo {
    /// Creates a new [`AssetInfo`] instance.
    pub fn new(amount: NoteValue, is_finalized: bool, reference_note: Note) -> Self {
        Self {
            amount,
            is_finalized,
            reference_note,
        }
    }
}
