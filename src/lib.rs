//! # orchard
//!
//! ## Nomenclature
//!
//! All types in the `orchard` crate, unless otherwise specified, are Orchard-specific
//! types. For example, [`Address`] is documented as being a shielded payment address; we
//! implicitly mean it is an Orchard payment address (as opposed to e.g. a Sapling payment
//! address, which is also shielded).

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;

mod action;
mod address;
pub mod asset_record;
pub mod builder;
pub mod bundle;
#[cfg(feature = "circuit")]
pub mod circuit;
mod constants;
pub mod issuance;
pub mod issuance_auth;
pub mod keys;
pub mod note;
pub mod orchard_flavor;
pub mod pczt;
pub mod primitives;
mod spec;
pub mod tree;
pub mod value;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

pub use action::Action;
pub use address::Address;
pub use bundle::Bundle;
pub use constants::reference_keys::ReferenceKeys;
pub use constants::MERKLE_DEPTH_ORCHARD as NOTE_COMMITMENT_TREE_DEPTH;
pub use note::{
    commitment::{ExtractedNoteCommitment, NoteCommitment},
    Note,
};
pub use tree::Anchor;

/// A proof of the validity of an Orchard [`Bundle`].
///
/// [`Bundle`]: crate::bundle::Bundle
#[derive(Clone)]
pub struct Proof(Vec<u8>);

impl core::fmt::Debug for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_tuple("Proof").field(&self.0).finish()
        } else {
            // By default, only show the proof length, not its contents.
            f.debug_tuple("Proof")
                .field(&format_args!("{} bytes", self.0.len()))
                .finish()
        }
    }
}

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl memuse::DynamicUsage for Proof {
    fn dynamic_usage(&self) -> usize {
        self.0.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.0.dynamic_usage_bounds()
    }
}

impl Proof {
    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}
