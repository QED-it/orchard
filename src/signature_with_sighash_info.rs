//! Defines `SighashInfo` and signatures with `SighashInfo`.

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
    version: SighashInfo,
    sig: S,
}

impl<S> VersionedSig<S> {
    /// Constructs a new `VersionedSig` with the given version and signature.
    pub fn new(version: SighashInfo, sig: S) -> Self {
        Self { version, sig }
    }

    /// Returns the version.
    pub fn version(&self) -> &SighashInfo {
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
            SighashInfo::from_bytes(&version_bytes).ok_or(ParseError::InvalidSighashInfo)?;
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
pub struct SighashInfo {
    version: u8,
    associated_data: Vec<u8>,
}

impl SighashInfo {
    /// Constructs a `SighashInfo` from raw bytes.
    ///
    /// Returns `None` if `bytes` is empty.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.split_first().map(|(&version, info)| Self {
            version,
            associated_data: info.to_vec(),
        })
    }

    /// Returns the raw bytes of the `SighashInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        [vec![self.version], self.associated_data.clone()].concat()
    }
}

/// The `SighashInfo` for OrchardZSA binding,authorizing and issuance authorization signatures.
///
/// It is also the default `SighashInfo` used for Vanilla transactions.
pub const ORCHARD_ISSUE_INFO_V0: SighashInfo = SighashInfo {
    version: 0x00,
    associated_data: vec![],
};

#[cfg(test)]
mod tests {
    use super::SighashInfo;
    use rand::Rng;

    #[test]
    fn sighash_info_from_to_bytes_roundtrip() {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 10] = rng.gen();
        let sighash_info = SighashInfo::from_bytes(&bytes).unwrap();
        assert_eq!(bytes[0], sighash_info.version);
        assert_eq!(bytes[1..], sighash_info.associated_data);

        let sighash_info_bytes = sighash_info.to_bytes();
        assert_eq!(bytes, sighash_info_bytes.as_slice());
    }
}
