//! This module defines the versioning for Orchard signatures.

use crate::primitives::redpallas::{Binding, SigType, Signature, SpendAuth};

/// The Orchard Sighash version.
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum OrchardSighashVersion {
    /// Version V0.
    V0 = 0,
    /// Unknown version.
    UNKNOWN = u8::MAX,
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
