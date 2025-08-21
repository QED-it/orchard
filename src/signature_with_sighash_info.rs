//! Defines `SighashInfo` and signatures with `SighashInfo`.

use alloc::vec::Vec;

use crate::primitives::redpallas::{self, Binding, SigType, SpendAuth};

/// The sighash version and associated information
#[derive(Debug, Clone)]
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

/// The `SighashInfo` for OrchardZSA binding/authorizing signatures.
///
/// It is also the default `SighashInfo` used for Vanilla transactions.
pub(crate) const ORCHARD_SIG_V0: SighashInfo = SighashInfo {
    version: 0x00,
    associated_information: vec![],
};

/// Redpallas signature with SighashInfo.
#[derive(Debug, Clone)]
pub struct SignatureWithSighashInfo<T: SigType> {
    info: SighashInfo,
    signature: redpallas::Signature<T>,
}

impl<T: SigType> SignatureWithSighashInfo<T> {
    /// Constructs a new `SignatureWithSighashInfo` with the default `SighashInfo` and the given
    /// signature.
    pub fn new_with_default_sighash_info(signature: redpallas::Signature<T>) -> Self {
        Self {
            info: ORCHARD_SIG_V0,
            signature,
        }
    }

    /// Constructs a new `SignatureWithSighashInfo` with the given `SighashInfo` and signature.
    pub fn new(info: SighashInfo, signature: redpallas::Signature<T>) -> Self {
        Self { info, signature }
    }

    /// Returns the `SighashInfo`.
    pub fn sighash_info(&self) -> &SighashInfo {
        &self.info
    }

    /// Returns the signature.
    pub fn signature(&self) -> &redpallas::Signature<T> {
        &self.signature
    }
}

/// Binding signature containing the sighash information and the signature itself.
pub type BindingSignatureWithSighashInfo = SignatureWithSighashInfo<Binding>;

/// Authorizing signature containing the sighash information and the signature itself.
pub type SpendAuthSignatureWithSighashInfo = SignatureWithSighashInfo<SpendAuth>;

#[cfg(test)]
mod tests {
    use super::{SighashInfo, ORCHARD_SIG_V0};
    use rand::Rng;

    #[test]
    fn default_sighash_info() {
        let bytes = ORCHARD_SIG_V0.to_bytes();
        assert_eq!(bytes, [0u8; 1]);
    }

    #[test]
    fn sighash_info_from_to_bytes() {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 10] = rng.gen();
        let sighash_info = SighashInfo::from_bytes(&bytes).unwrap();
        assert_eq!(bytes[0], sighash_info.version);
        assert_eq!(bytes[1..], sighash_info.associated_information);

        let sighash_info_bytes = sighash_info.to_bytes();
        assert_eq!(bytes, sighash_info_bytes.as_slice());
    }
}
