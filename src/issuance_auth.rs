//! Issuance logic for Zcash Shielded Assets (ZSAs).
//!
//! This module provides the structures and methods necessary for handling issuance authorization
//! signatures and the issuance keys.

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
    issuance::{self, IssuanceAuthorizationSignature},
    zip32::{self, ExtendedSpendingKey},
};

// Preserve '::' which specifies the EXTERNAL 'zip32' crate
#[rustfmt::skip]
pub use ::zip32::{AccountId, ChildIndex, DiversifierIndex, Scope, hardened_only};

const ZIP32_PURPOSE: u32 = 32;
const ZIP32_PURPOSE_FOR_ISSUANCE: u32 = 227;

/// An issuance key, from which all key material is derived.
///
/// $\mathsf{isk}$ as defined in [ZIP 227][issuancekeycomponents].
///
/// [issuancekeycomponents]: https://zips.z.cash/zip-0227#issuance-key-derivation
#[derive(Copy, Clone)]
pub struct IssuanceAuthorizingKey {
    bytes: [u8; 32],
}

impl IssuanceAuthorizingKey {
    /// Generates a random issuance key.
    ///
    /// This is only used when generating a random AssetBase.
    /// Real issuance keys should be derived according to [ZIP 32].
    ///
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub(crate) fn random(rng: &mut impl CryptoRngCore) -> Self {
        IssuanceAuthorizingKey {
            bytes: NonZeroScalar::random(rng).to_bytes().into(),
        }
    }

    /// Constructs an Orchard issuance key from uniformly-random bytes.
    ///
    /// Returns `None` if the bytes do not correspond to a valid Orchard issuance key.
    pub fn from_bytes(isk_bytes: [u8; 32]) -> Option<Self> {
        NonZeroScalar::try_from(&isk_bytes as &[u8])
            .ok()
            .map(|isk| IssuanceAuthorizingKey {
                bytes: isk.to_bytes().into(),
            })
    }

    /// Returns the raw bytes of the issuance key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
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

        IssuanceAuthorizingKey::from_bytes(isk_bytes).ok_or(zip32::Error::InvalidSpendingKey)
    }

    /// Sign the provided message using the `IssuanceAuthorizingKey`.
    /// Only supports signing of messages of length 32 bytes, since we will only be using it to sign 32 byte SIGHASH values.
    pub fn try_sign(
        &self,
        msg: &[u8; 32],
    ) -> Result<IssuanceAuthorizationSignature, issuance::Error> {
        schnorr::SigningKey::from_bytes(&self.bytes as &[u8])
            .map_err(|_| issuance::Error::InvalidIssuanceAuthorizingKey)?
            .sign_prehash(msg)
            .map(|sig| IssuanceAuthorizationSignature {
                bytes: sig.to_bytes(),
            })
            .map_err(|_| issuance::Error::IssueBundleInvalidSignature)
    }
}

impl Debug for IssuanceAuthorizingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IssuanceAuthorizingKey")
            .field(&self.bytes)
            .finish()
    }
}

/// A key used to validate issuance authorization signatures.
///
/// Defined in [ZIP 227: Issuance of Zcash Shielded Assets § Issuance Key Generation][IssuanceZSA].
///
/// [IssuanceZSA]: https://zips.z.cash/zip-0227#issuance-key-derivation
#[derive(Debug, Clone)]
pub struct IssuanceValidatingKey {
    bytes: [u8; 32],
}

impl From<&IssuanceAuthorizingKey> for IssuanceValidatingKey {
    fn from(isk: &IssuanceAuthorizingKey) -> Self {
        IssuanceValidatingKey {
            bytes: schnorr::SigningKey::from_bytes(&isk.bytes)
                .unwrap()
                .verifying_key()
                .to_bytes()
                .into(),
        }
    }
}

impl PartialEq for IssuanceValidatingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Eq for IssuanceValidatingKey {}

impl IssuanceValidatingKey {
    /// Converts this issuance validating key to its serialized form,
    /// in big-endian order as defined in BIP 340.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Constructs an Orchard issuance validating key from the provided bytes.
    /// The bytes are assumed to be encoded in big-endian order.
    ///
    /// Returns `None` if the bytes do not correspond to a valid key.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        VerifyingKey::from_bytes(bytes)
            .ok()
            .map(|vk| IssuanceValidatingKey {
                bytes: vk.to_bytes().into(),
            })
    }

    /// Verifies a purported `signature` over `msg` made by this verification key.
    pub fn verify(
        &self,
        msg: &[u8],
        signature: &IssuanceAuthorizationSignature,
    ) -> Result<(), issuance::Error> {
        let vk = VerifyingKey::from_bytes(&self.bytes)
            .map_err(|_| issuance::Error::InvalidIssuanceValidatingKey)?;
        vk.verify_prehash(
            msg,
            &schnorr::Signature::try_from(signature.bytes.as_slice()).unwrap(),
        )
        .map_err(|_| issuance::Error::IssueBundleInvalidSignature)
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use super::{IssuanceAuthorizingKey, IssuanceValidatingKey};

    use proptest::prelude::*;

    prop_compose! {
        /// Generate a uniformly distributed Orchard issuance authorizing key.
        pub fn arb_issuance_authorizing_key()(
            key in prop::array::uniform32(prop::num::u8::ANY)
                .prop_map(IssuanceAuthorizingKey::from_bytes)
                .prop_filter(
                    "Values must correspond to valid Orchard-ZSA issuance keys.",
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
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn issuance_authorizing_key_from_bytes_fail_on_zero() {
        // isk must not be the zero scalar.
        let isk = IssuanceAuthorizingKey::from_bytes([0; 32]);
        assert!(isk.is_none());
    }

    #[test]
    fn issuance_authorizing_key_from_bytes_to_bytes_roundtrip() {
        let isk = IssuanceAuthorizingKey::random(&mut OsRng);
        let isk_bytes = isk.to_bytes();
        let isk_roundtrip = IssuanceAuthorizingKey::from_bytes(isk_bytes).unwrap();
        assert_eq!(isk_bytes, isk_roundtrip.to_bytes());
    }

    #[test]
    fn issuance_auth_sig_test_vectors() {
        for tv in crate::test_vectors::issuance_auth_sig::TEST_VECTORS {
            let isk = IssuanceAuthorizingKey::from_bytes(tv.isk).unwrap();

            let ik = IssuanceValidatingKey::from(&isk);
            assert_eq!(ik.to_bytes(), tv.ik);

            let message = tv.msg;

            let signature = isk.try_sign(&message).unwrap();
            let sig_bytes: [u8; 64] = signature.to_bytes();
            assert_eq!(sig_bytes, tv.sig);

            assert!(ik.verify(&message, &signature).is_ok());
        }
    }
}
