//! Structs and logic related to supply information management for assets.

use crate::{value::NoteValue, Note};

/// Represents the amount of an asset, its finalization status and reference note.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct AssetSupply {
    /// The amount of the asset.
    pub amount: NoteValue,

    /// Whether or not the asset is finalized.
    pub is_finalized: bool,

    /// The reference note, `None` if this `AssetSupply` instance is created from an issue bundle that does not include
    /// a reference note (a non-first issuance)
    pub reference_note: Option<Note>,
}

impl AssetSupply {
    /// Creates a new AssetSupply instance with the given amount, finalization status and reference
    /// note.
    pub fn new(amount: NoteValue, is_finalized: bool, reference_note: Option<Note>) -> Self {
        Self {
            amount,
            is_finalized,
            reference_note,
        }
    }
}
