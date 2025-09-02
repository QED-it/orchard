//! Versioned signatures for OrchardZSA.
//!
//! This module defines [`VersionedSig`], which pairs a signature with a [`SighashVersion`],
//! as specified in [ZIP-246]. It supports binding, spend authorization, and issuance
//! authorization (BIP-340 Schnorr) signatures.
//!
//! # Example
//! ```
//! use rand::rngs::OsRng;
//! use orchard::issuance_auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr};
//! use orchard::sighash_version::{VerBIP340IssueAuthSig, ORCHARD_ISSUE_SIGHASH_V0};
//!
//! let mut rng = OsRng;
//! let isk = IssueAuthKey::<ZSASchnorr>::random(&mut rng);
//! let ik = IssueValidatingKey::from(&isk);
//! let msg = [1u8; 32];
//!
//! let sig = isk.try_sign(&msg).unwrap();
//! let ver_sig = VerBIP340IssueAuthSig::new(ORCHARD_ISSUE_SIGHASH_V0, sig);
//!
//! ik.verify(&msg, ver_sig.sig()).unwrap();
//! ```
//!
//! [ZIP-246]: https://zips.z.cash/zip-0246

use alloc::vec::Vec;

use crate::{
    issuance_auth::{IssueAuthSig, ZSASchnorr},
    pczt::ParseError,
    primitives::redpallas::{self, Binding, SpendAuth},
};

/// A versioned signature as per [ZIP-246].
///
/// [ZIP-246]: https://zips.z.cash/zip-0246
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSig<S> {
    version: SighashVersion,
    sig: S,
}

impl<S> VersionedSig<S> {
    /// Constructs a new `VersionedSig` with the given version and signature.
    pub fn new(version: SighashVersion, sig: S) -> Self {
        Self { version, sig }
    }

    /// Returns the version.
    pub fn version(&self) -> &SighashVersion {
        &self.version
    }

    /// Returns the signature.
    pub fn sig(&self) -> &S {
        &self.sig
    }
}

/// A versioned binding signature.
pub type VerBindingSig = VersionedSig<redpallas::Signature<Binding>>;

/// A versioned SpendAuth signature.
pub type VerSpendAuthSig = VersionedSig<redpallas::Signature<SpendAuth>>;

impl VerSpendAuthSig {
    /// Parses a `VerSpendAuthSig` from its raw bytes components.
    ///
    /// Returns an error when `version_bytes` is empty.
    pub fn parse(version_bytes: Vec<u8>, sig_bytes: [u8; 64]) -> Result<Self, ParseError> {
        let version =
            SighashVersion::from_bytes(&version_bytes).ok_or(ParseError::InvalidSighashVersion)?;
        Ok(Self {
            version,
            sig: sig_bytes.into(),
        })
    }
}

/// A versioned Issuance authorization signature based on BIP 340 Schnorr.
pub type VerBIP340IssueAuthSig = VersionedSig<IssueAuthSig<ZSASchnorr>>;

/// The sighash version and associated data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SighashVersion {
    version: u8,
    associated_data: Vec<u8>,
}

impl SighashVersion {
    /// Constructs a `SighashVersion` from raw bytes.
    ///
    /// Returns `None` if `bytes` is empty.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.split_first().map(|(&version, info)| Self {
            version,
            associated_data: info.to_vec(),
        })
    }

    /// Returns the raw bytes of the `SighashVersion`.
    pub fn to_bytes(&self) -> Vec<u8> {
        [vec![self.version], self.associated_data.clone()].concat()
    }
}

/// The `SighashVersion` for OrchardZSA binding,authorizing and issuance authorization signatures.
///
/// It is also the default `SighashVersion` used for Vanilla transactions.
pub const ORCHARD_ISSUE_SIGHASH_V0: SighashVersion = SighashVersion {
    version: 0x00,
    associated_data: vec![],
};

#[cfg(test)]
mod tests {
    use super::SighashVersion;
    use rand::Rng;

    #[test]
    fn sighash_version_from_to_bytes_roundtrip() {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 10] = rng.gen();
        let sighash_version = SighashVersion::from_bytes(&bytes).unwrap();
        assert_eq!(bytes[0], sighash_version.version);
        assert_eq!(bytes[1..], sighash_version.associated_data);

        let sighash_version_bytes = sighash_version.to_bytes();
        assert_eq!(bytes, sighash_version_bytes.as_slice());
    }
}
