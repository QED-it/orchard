//! Defines `SighashInfo` and signatures with `SighashInfo`.

use alloc::vec::Vec;

use crate::{
    issuance_auth::{IssueAuthSig, ZSASchnorr},
    pczt::ParseError,
    primitives::redpallas::{self, Binding, SpendAuth},
};

/// The sighash version and associated information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SighashInfo {
    version: u8,
    associated_information: Vec<u8>,
}

impl SighashInfo {
    /// Constructs a `SighashInfo` from raw bytes.
    ///
    /// Returns `None` if `bytes` is empty.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let version = bytes[0];
        let associated_information = bytes[1..].to_vec();
        Some(Self {
            version,
            associated_information,
        })
    }

    /// Returns the raw bytes of the `SighashInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.associated_information.len());
        result.push(self.version);
        result.extend_from_slice(&self.associated_information);
        result
    }
}

/// The `SighashInfo` for OrchardZSA binding,authorizing and issuance authorization signatures.
///
/// It is also the default `SighashInfo` used for Vanilla transactions.
pub(crate) const ORCHARD_INFO_V0: SighashInfo = SighashInfo {
    version: 0x00,
    associated_information: vec![],
};

/// Signature with `SighashInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigWithInfo<S> {
    info: SighashInfo,
    sig: S,
}

impl<S> SigWithInfo<S> {
    /// Constructs a new `SigWithInfo` with the default `SighashInfo` and the given signature.
    pub fn new_with_default_info(sig: S) -> Self {
        Self {
            info: ORCHARD_INFO_V0,
            sig,
        }
    }

    /// Constructs a new `SigWithInfo` with the given `SighashInfo` and signature.
    pub fn new(info: SighashInfo, sig: S) -> Self {
        Self { info, sig }
    }

    /// Returns the `SighashInfo`.
    pub fn info(&self) -> &SighashInfo {
        &self.info
    }

    /// Returns the signature.
    pub fn sig(&self) -> &S {
        &self.sig
    }
}

/// Binding signature with its `SighashInfo`.
pub type BindingSigWithInfo = SigWithInfo<redpallas::Signature<Binding>>;

/// Authorizing signature with its `SighashInfo`.
pub type SpendAuthSigWithInfo = SigWithInfo<redpallas::Signature<SpendAuth>>;

impl SpendAuthSigWithInfo {
    /// Parses a `SpendAuthSigWithInfo` from its raw bytes components.
    ///
    /// Returns an error when `info` is empty.
    pub fn parse(info_bytes: Vec<u8>, sig_bytes: [u8; 64]) -> Result<Self, ParseError> {
        let info = SighashInfo::from_bytes(&info_bytes).ok_or(ParseError::InvalidSighashInfo)?;
        Ok(Self {
            info,
            sig: sig_bytes.into(),
        })
    }
}

/// Issuance authorization signature based on BIP 340 Schnorr with its `SighashInfo`.
pub type BIP340IssueAuthSigWithInfo = SigWithInfo<IssueAuthSig<ZSASchnorr>>;

#[cfg(test)]
mod tests {
    use super::{SighashInfo, ORCHARD_INFO_V0};
    use rand::Rng;

    #[test]
    fn default_sighash_info() {
        let bytes = ORCHARD_INFO_V0.to_bytes();
        assert_eq!(bytes, [0u8; 1]);
    }

    #[test]
    fn sighash_info_from_to_bytes_roundtrip() {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 10] = rng.gen();
        let sighash_info = SighashInfo::from_bytes(&bytes).unwrap();
        assert_eq!(bytes[0], sighash_info.version);
        assert_eq!(bytes[1..], sighash_info.associated_information);

        let sighash_info_bytes = sighash_info.to_bytes();
        assert_eq!(bytes, sighash_info_bytes.as_slice());
    }
}
