use std::collections::HashSet;

use super::{verify_issue_bundle, AssetBase, IssueBundle, Signed};

/// Batch validation context for Issuance.
///
#[derive(Debug, Default)]
pub struct BatchValidator {
    bundles: Vec<(IssueBundle<Signed>, [u8; 32])>,
}

impl BatchValidator {
    /// Constructs a new batch validation context.
    pub fn new() -> Self {
        BatchValidator { bundles: vec![] }
    }

    /// Adds bundle to the validator.
    pub fn add_bundle(&mut self, bundle: &IssueBundle<Signed>, sighash: [u8; 32]) {
        self.bundles.push((bundle.clone(), sighash))
    }

    /// Batch-validates the accumulated bundles.
    ///
    /// Returns `true` if every bundle added to the batch validator is valid, or `false`
    /// if one or more are invalid.
    pub fn validate(self) -> bool {
        // FIXME: take/save finalization set from/to the global state
        let finalized = HashSet::<AssetBase>::new();

        // FIXME: process resulting supply_info
        self.bundles
            .into_iter()
            .all(|(bundle, sighash)| verify_issue_bundle(&bundle, sighash, &finalized).is_ok())
    }
}
