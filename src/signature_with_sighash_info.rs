//! Defines `SighashInfo` and signatures with `SighashInfo`.

use alloc::vec::Vec;

use crate::primitives::redpallas::{self, Binding, SpendAuth};

/// The sighash version and associated information
#[derive(Debug, Clone)]
pub(crate) struct SighashInfo {
    version: u8,
    associated_information: Vec<u8>,
}

/// The sighash version and associated information for Orchard binding/authorizing signatures.
pub(crate) const ORCHARD_SIG_V0: SighashInfo = SighashInfo {
    version: 0x00,
    associated_information: vec![],
};

/// Binding signature containing the sighash information and the signature itself.
#[derive(Debug, Clone)]
pub struct BindingSignatureWithSighashInfo {
    /// The sighash information for the binding signature.
    info: SighashInfo,
    /// The binding signature.
    signature: redpallas::Signature<Binding>,
}

impl BindingSignatureWithSighashInfo {
    pub(crate) fn new(info: SighashInfo, signature: redpallas::Signature<Binding>) -> Self {
        BindingSignatureWithSighashInfo { info, signature }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        [self.info.version]
            .into_iter()
            .chain(self.info.associated_information.clone().into_iter())
            .chain(<[u8; 64]>::from(&self.signature).into_iter())
            .collect::<Vec<u8>>()
    }

    /// Returns the binding signature.
    pub fn signature(&self) -> &redpallas::Signature<Binding> {
        &self.signature
    }
}

/// Authorizing signature containing the sighash information and the signature itself.
#[derive(Debug, Clone)]
pub struct SpendAuthSignatureWithSighashInfo {
    /// The sighash information for the authorizing signature.
    info: SighashInfo,
    /// The authorizing signature.
    signature: redpallas::Signature<SpendAuth>,
}

impl SpendAuthSignatureWithSighashInfo {
    pub(crate) fn new(info: SighashInfo, signature: redpallas::Signature<SpendAuth>) -> Self {
        SpendAuthSignatureWithSighashInfo { info, signature }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        [self.info.version]
            .into_iter()
            .chain(self.info.associated_information.clone().into_iter())
            .chain(<[u8; 64]>::from(&self.signature).into_iter())
            .collect::<Vec<u8>>()
    }

    /// Returns the authorizing signature.
    pub fn signature(&self) -> &redpallas::Signature<SpendAuth> {
        &self.signature
    }
}
