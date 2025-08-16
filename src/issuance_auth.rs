//! Issuance logic for Zcash Shielded Assets (ZSAs).
//!
//! This module provides the structures and methods necessary for handling issuance authorization
//! signatures and the issuance keys.

use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};

use k256::{
    schnorr,
    schnorr::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        VerifyingKey,
    },
    NonZeroScalar,
};
use rand_core::CryptoRngCore;

use crate::{
    issuance::{self},
    zip32::{self, ExtendedSpendingKey},
};

// Preserve '::' which specifies the EXTERNAL 'zip32' crate
#[rustfmt::skip]
pub use ::zip32::{AccountId, ChildIndex, DiversifierIndex, Scope, hardened_only};
use crate::issuance::Error;

const ZIP32_PURPOSE: u32 = 32;
const ZIP32_PURPOSE_FOR_ISSUANCE: u32 = 227;

/// Enumeration of the supported issuance authorization signature schemes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum IssuanceAuthSigSchemeID {
    /// The OrchardZSA issuance authorization signature scheme, based on the BIP 340 Schnorr    
    /// signature scheme, defined in [ZIP 227][issueauthsigscheme].    
    ///    
    /// [issueauthsigscheme]: https://zips.z.cash/zip-0227#orchard-zsa-issuance-authorization-signature-scheme    
    ZSASchnorrSigSchemeID = 0x00,
}

impl IssuanceAuthSigSchemeID {
    /// Returns the details of the issuance authorization signature scheme.
    pub(crate) fn details(&self) -> impl IssuanceAuthSigScheme {
        match self {
            IssuanceAuthSigSchemeID::ZSASchnorrSigSchemeID => ZSASchnorrSigScheme,
        }
    }
}

/// An issuance authorization key, from is used to sign the issuance authorization signatures.
///
/// This is denoted by `isk` as defined in [ZIP 227][issuancekeycomponents].
///
/// [issuancekeycomponents]: https://zips.z.cash/zip-0227#issuance-key-derivation
#[derive(Clone)]
pub struct IssuanceAuthorizingKey {
    scheme: IssuanceAuthSigSchemeID,
    bytes: Vec<u8>,
}

/// A key used to validate issuance authorization signatures, denoted by `ik`.
///
/// Defined in [ZIP 227: Issuance of Zcash Shielded Assets § Issuance Key Generation][IssuanceZSA].
///
/// [IssuanceZSA]: https://zips.z.cash/zip-0227#issuance-key-derivation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceValidatingKey {
    scheme: IssuanceAuthSigSchemeID,
    bytes: Vec<u8>,
}

/// An issuance authorization signature `issueAuthSig`,
///
/// as defined in [ZIP 227][issueauthsig].
///
/// [issueauthsig]: https://zips.z.cash/zip-0227#issuance-authorization-signature-scheme
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceAuthorizationSignature {
    scheme: IssuanceAuthSigSchemeID,
    bytes: Vec<u8>,
}

/// Internal trait that defines the common interface for issuance authorization signature schemes.
pub(crate) trait IssuanceAuthSigScheme {
    const ALGORITHM_BYTE: u8;
    const ISK_LENGTH: usize;
    const IK_LENGTH: usize;
    const SIG_LENGTH: usize;

    type IskType;
    type IkType;
    type IssueAuthSigType;

    fn isk_to_bytes(&self, isk: &Self::IskType) -> Vec<u8>;
    fn isk_from_bytes(&self, bytes: &[u8]) -> Option<Self::IskType>;
    fn ik_to_bytes(&self, ik: &Self::IkType) -> Vec<u8>;
    fn ik_from_bytes(&self, bytes: &[u8]) -> Option<Self::IkType>;
    fn sig_to_bytes(&self, sig: Self::IssueAuthSigType) -> Vec<u8>;
    fn sig_from_bytes(&self, bytes: &[u8]) -> Option<Self::IssueAuthSigType>;

    fn ik_from_isk(&self, isk: Self::IskType) -> Self::IkType;
    fn try_sign(
        &self,
        isk: &Self::IskType,
        msg: &[u8; 32],
    ) -> Result<Self::IssueAuthSigType, issuance::Error>;
    fn verify(
        &self,
        ik: &Self::IkType,
        msg: &[u8],
        signature: &Self::IssueAuthSigType,
    ) -> Result<(), issuance::Error>;
}

/// The Orchard-ZSA issuance authorization signature scheme, based on BIP 340 Schnorr.
#[derive(Debug)]
pub struct ZSASchnorrSigScheme;

impl IssuanceAuthSigScheme for ZSASchnorrSigScheme {
    const ALGORITHM_BYTE: u8 = IssuanceAuthSigSchemeID::ZSASchnorrSigSchemeID as u8;
    const ISK_LENGTH: usize = 32;
    const IK_LENGTH: usize = 32;
    const SIG_LENGTH: usize = 64;

    type IskType = NonZeroScalar;
    type IkType = VerifyingKey;
    type IssueAuthSigType = schnorr::Signature;

    fn isk_to_bytes(&self, isk: &Self::IskType) -> Vec<u8> {
        isk.to_bytes().to_vec()
    }

    fn isk_from_bytes(&self, bytes: &[u8]) -> Option<Self::IskType> {
        NonZeroScalar::try_from(bytes).ok()
    }

    fn ik_to_bytes(&self, ik: &Self::IkType) -> Vec<u8> {
        ik.to_bytes().to_vec()
    }

    fn ik_from_bytes(&self, bytes: &[u8]) -> Option<Self::IkType> {
        VerifyingKey::from_bytes(bytes).ok()
    }

    fn sig_to_bytes(&self, sig: Self::IssueAuthSigType) -> Vec<u8> {
        sig.to_bytes().to_vec()
    }

    fn sig_from_bytes(&self, bytes: &[u8]) -> Option<Self::IssueAuthSigType> {
        schnorr::Signature::try_from(bytes).ok()
    }

    fn ik_from_isk(&self, isk: Self::IskType) -> Self::IkType {
        *schnorr::SigningKey::from(isk).verifying_key()
    }

    fn try_sign(
        &self,
        isk: &Self::IskType,
        msg: &[u8; 32],
    ) -> Result<Self::IssueAuthSigType, Error> {
        schnorr::SigningKey::from(*isk)
            .sign_prehash(msg)
            .map_err(|_| issuance::Error::IssueBundleInvalidSignature)
    }

    fn verify(
        &self,
        ik: &Self::IkType,
        msg: &[u8],
        sig: &Self::IssueAuthSigType,
    ) -> Result<(), Error> {
        ik.verify_prehash(msg, sig)
            .map_err(|_| issuance::Error::IssueBundleInvalidSignature)
    }
}

impl IssuanceAuthorizingKey {
    /// Generates a random issuance key.
    ///
    /// This is only used when generating a random AssetBase.
    /// Real issuance keys should be derived according to [ZIP 32].
    ///
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub(crate) fn random(scheme: IssuanceAuthSigSchemeID, rng: &mut impl CryptoRngCore) -> Self {
        match scheme {
            //TODO: VA: This is not done the trait way. Should it be?
            IssuanceAuthSigSchemeID::ZSASchnorrSigSchemeID => Self {
                scheme,
                bytes: NonZeroScalar::random(rng).to_bytes().to_vec(),
            },
        }
    }

    /// Constructs an issuance authorizing key from the provided bytes.
    ///
    /// Returns `None` if the bytes do not correspond to a valid issuance authorizing key.
    pub fn from_bytes(scheme: IssuanceAuthSigSchemeID, bytes: &[u8]) -> Option<Self> {
        scheme.details().isk_from_bytes(bytes).map(|_| Self {
            scheme,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the raw bytes of the issuance key.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derives the Orchard-ZSA issuance key for the given seed, coin type, and account.
    pub fn from_zip32_seed(
        seed: &[u8],
        coin_type: u32,
        account: u32,
    ) -> Result<Self, zip32::Error> {
        // Call zip32 logic
        let path = &[
            ChildIndex::hardened(ZIP32_PURPOSE_FOR_ISSUANCE),
            ChildIndex::hardened(coin_type),
            ChildIndex::hardened(account),
        ];

        // we are reusing zip32 logic for deriving the key, zip32 should be updated as discussed
        let &isk_bytes = ExtendedSpendingKey::<zip32::Issuance>::from_path(seed, path)?
            .sk()
            .to_bytes();

        // TODO: VA: This is hardcoded to the ZSASchnorr scheme ID.
        IssuanceAuthorizingKey::from_bytes(
            IssuanceAuthSigSchemeID::ZSASchnorrSigSchemeID,
            &isk_bytes,
        )
        .ok_or(zip32::Error::InvalidSpendingKey)
    }

    /// Sign the provided message using the `IssuanceAuthorizingKey`.
    /// Only supports signing of messages of length 32 bytes, since we will only be using it to sign 32 byte SIGHASH values.
    pub fn try_sign(
        &self,
        msg: &[u8; 32],
    ) -> Result<IssuanceAuthorizationSignature, issuance::Error> {
        let details = self.scheme.details();
        let bytes = details
            .isk_from_bytes(&self.bytes)
            .ok_or(issuance::Error::InvalidIssuanceAuthorizingKey)
            .and_then(|isk| details.try_sign(&isk, msg))
            .map(|sig| details.sig_to_bytes(sig))?;
        Ok(IssuanceAuthorizationSignature {
            scheme: self.scheme,
            bytes,
        })
    }
}

impl Debug for IssuanceAuthorizingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IssuanceAuthorizingKey")
            .field(&self.scheme)
            .field(&self.bytes)
            .finish()
    }
}

impl From<&IssuanceAuthorizingKey> for IssuanceValidatingKey {
    fn from(isk: &IssuanceAuthorizingKey) -> Self {
        let details = isk.scheme.details();
        let bytes = details
            .ik_to_bytes(&details.ik_from_isk(details.isk_from_bytes(isk.to_bytes()).unwrap()));
        Self {
            scheme: isk.scheme,
            bytes,
        }
    }
}

impl IssuanceValidatingKey {
    /// Converts this issuance validating key to its serialized form,
    /// in big-endian order as defined in BIP 340.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Constructs an Orchard issuance validating key from the provided bytes.
    /// The bytes are assumed to be encoded in big-endian order.
    ///
    /// Returns `None` if the bytes do not correspond to a valid key.
    pub fn from_bytes(scheme: IssuanceAuthSigSchemeID, bytes: &[u8]) -> Option<Self> {
        scheme.details().ik_from_bytes(bytes).map(|_| Self {
            scheme,
            bytes: bytes.to_vec(),
        })
    }

    /// Verifies a purported `signature` over `msg` made by this verification key.
    pub fn verify(
        &self,
        msg: &[u8],
        signature: &IssuanceAuthorizationSignature,
    ) -> Result<(), issuance::Error> {
        if signature.scheme != self.scheme {
            return Err(issuance::Error::IssueBundleInvalidSignature);
        }
        let vk = VerifyingKey::from_bytes(&self.bytes)
            .map_err(|_| issuance::Error::InvalidIssuanceValidatingKey)?;
        vk.verify_prehash(
            msg,
            &schnorr::Signature::try_from(signature.bytes.as_slice()).unwrap(),
        )
        .map_err(|_| issuance::Error::IssueBundleInvalidSignature)
    }
}

impl IssuanceAuthorizationSignature {
    /// Serialize the issuance authorization signature to its canonical byte representation.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Deserialize the issuance authorization signature from its canonical byte representation.
    pub fn from_bytes(scheme: IssuanceAuthSigSchemeID, bytes: &[u8]) -> Option<Self> {
        scheme.details().ik_from_bytes(bytes).map(|_| Self {
            scheme,
            bytes: bytes.to_vec(),
        })
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use super::{IssuanceAuthorizingKey, IssuanceValidatingKey};

    use crate::issuance_auth::IssuanceAuthSigSchemeID::ZSASchnorrSigSchemeID;
    use proptest::prelude::*;

    prop_compose! {
        /// Generate a uniformly distributed Orchard issuance authorizing key.
        pub fn arb_issuance_authorizing_key()(
            key in prop::array::uniform32(prop::num::u8::ANY)
                .prop_map(|b| IssuanceAuthorizingKey::from_bytes(ZSASchnorrSigSchemeID, &b))
                .prop_filter(
                    "Values must be valid Orchard-ZSA issuance authorizing keys.",
                    |opt| opt.is_some()
                )
        ) -> IssuanceAuthorizingKey {
            key.unwrap()
        }
    }

    prop_compose! {
        /// Generate a uniformly distributed RedDSA issuance validating key.
        pub fn arb_issuance_validating_key()(isk in arb_issuance_authorizing_key()) -> IssuanceValidatingKey {
            IssuanceValidatingKey::from(&isk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance_auth::IssuanceAuthSigSchemeID::ZSASchnorrSigSchemeID;
    use rand::rngs::OsRng;

    #[test]
    fn issuance_authorizing_key_from_bytes_fail_on_zero() {
        // isk must not be the zero scalar for the ZSA Schnorr scheme.
        let zero_bytes = [0u8; 32];
        let isk = IssuanceAuthorizingKey::from_bytes(ZSASchnorrSigSchemeID, &zero_bytes);
        assert!(isk.is_none());
    }

    #[test]
    fn issuance_authorizing_key_from_bytes_to_bytes_roundtrip() {
        let scheme = ZSASchnorrSigSchemeID;
        let isk = IssuanceAuthorizingKey::random(scheme, &mut OsRng);
        let isk_bytes = isk.to_bytes();
        let isk_roundtrip = IssuanceAuthorizingKey::from_bytes(scheme, isk_bytes).unwrap();
        assert_eq!(isk_bytes, isk_roundtrip.to_bytes());
    }

    #[test]
    fn issuance_auth_sig_test_vectors() {
        for tv in crate::test_vectors::issuance_auth_sig::TEST_VECTORS {
            let isk = IssuanceAuthorizingKey::from_bytes(ZSASchnorrSigSchemeID, &tv.isk).unwrap();

            let ik = IssuanceValidatingKey::from(&isk);
            assert_eq!(ik.to_bytes(), &tv.ik);

            let message = tv.msg;

            let sig = isk.try_sign(&message).unwrap();
            let sig_bytes = sig.to_bytes();
            assert_eq!(sig_bytes, &tv.sig);

            assert!(ik.verify(&message, &sig).is_ok());
        }
    }
}
