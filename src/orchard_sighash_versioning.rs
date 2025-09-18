//! This module defines the versioning for Orchard signatures.

use crate::primitives::redpallas::{Binding, SigType, Signature, SpendAuth};

/// The Orchard Sighash version.
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum OrchardSighashVersion {
    /// Unknown version.
    UNKNOWN = u8::MAX,
    /// Version V0.
    V0 = 0,
}

/// Converts an unsigned 8-bit integer into an `Option<OrchardSighashVersion>`.
pub fn orchard_sighash_version_from_u8(n: u8) -> Option<OrchardSighashVersion> {
    match n {
        0 => Some(OrchardSighashVersion::V0),
        u8::MAX => Some(OrchardSighashVersion::UNKNOWN),
        _ => None,
    }
}

/// The Orchard versioned signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OrchardVersionedSig<T: SigType> {
    version: OrchardSighashVersion,
    sig: Signature<T>,
}

impl<T: SigType> OrchardVersionedSig<T> {
    /// Constructs an `OrchardVersionedSig` from its constituent parts.
    pub fn new(version: OrchardSighashVersion, sig: Signature<T>) -> Self {
        Self { version, sig }
    }

    /// Returns the version of the signature.
    pub fn version(&self) -> &OrchardSighashVersion {
        &self.version
    }

    /// Returns the signature.
    pub fn sig(&self) -> &Signature<T> {
        &self.sig
    }
}

/// A versioned Orchard SpendAuth signature.
pub type VerSpendAuthSig = OrchardVersionedSig<SpendAuth>;

/// A versioned Orchard binding signature.
pub type VerBindingSig = OrchardVersionedSig<Binding>;

#[cfg(test)]
pub mod test_utils {
    use super::OrchardSighashVersion;
    use alloc::{collections::BTreeMap, vec::Vec};

    pub fn orchard_version_to_bytes_map() -> BTreeMap<OrchardSighashVersion, Vec<u8>> {
        let mut map = BTreeMap::new();
        map.insert(OrchardSighashVersion::V0, vec![0]);
        map
    }
}
