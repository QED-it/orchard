//! Issuance authorization logic for Zcash Shielded Assets (ZSAs).
//!
//! This module provides types and methods for working with issuance authorizing keys, validating
//! keys, and authorization signatures, as defined in [ZIP 227].
//!
//! # Example
//! ```
//! use rand::rngs::OsRng;
//! use orchard::issuance_auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr};
//!
//! let mut rng = OsRng;
//! let isk = IssueAuthKey::<ZSASchnorr>::random(&mut rng);
//! let ik = IssueValidatingKey::from(&isk);
//! let msg = [1u8; 32];
//! let sig = isk.try_sign(&msg).unwrap();
//! ik.verify(&msg, &sig).unwrap();
//! ```
//!
//! [ZIP 227]: https://zips.z.cash/zip-0227

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
    issuance::Error,
    zip32::{self, ExtendedSpendingKey},
};

// Preserve '::' which specifies the EXTERNAL 'zip32' crate
#[rustfmt::skip]
pub use ::zip32::{AccountId, ChildIndex, DiversifierIndex, Scope, hardened_only};

const ZIP32_PURPOSE_FOR_ISSUANCE: u32 = 227;

/// Trait that defines the common interface for issuance authorization signature schemes.
pub trait IssueAuthSigScheme {
    /// The byte corresponding to this signature scheme, used to encode the issuance validating key
    /// and issuance authorization signature.
    const ALGORITHM_BYTE: u8;

    /// The type of the issuance authorizing key.
    type IskType;
    /// The type of the issuance validating key.
    type IkType: Clone;
    /// The type of the issuance authorization signature.
    type IssueAuthSigType: Clone;

    /// Serialization for the issuance authorizing key.
    fn isk_to_bytes(isk: &Self::IskType) -> Vec<u8>;
    /// Deserialization for the issuance authorizing key.
    fn isk_from_bytes(bytes: &[u8]) -> Option<Self::IskType>;
    /// Serialization for the issuance validating key.
    fn ik_to_bytes(ik: &Self::IkType) -> Vec<u8>;
    /// Deserialization for the issuance validating key.
    fn ik_from_bytes(bytes: &[u8]) -> Option<Self::IkType>;
    /// Serialization for the issuance authorization signature.
    fn sig_to_bytes(sig: &Self::IssueAuthSigType) -> Vec<u8>;
    /// Deserialization for the issuance authorization signature.
    fn sig_from_bytes(bytes: &[u8]) -> Option<Self::IssueAuthSigType>;

    /// Generates a random issuance authorizing key, for testing purposes.
    fn random_isk(rng: &mut impl CryptoRngCore) -> Self::IskType;

    /// Derives the issuance validating key from the issuance authorizing key.
    fn ik_from_isk(isk: &Self::IskType) -> Self::IkType;

    /// Signs a 32-byte message using the issuance authorizing key.
    ///
    /// Only supports signing of messages of length 32 bytes, since we will only be using it
    /// to sign 32 byte SIGHASH values.
    fn try_sign(isk: &Self::IskType, msg: &[u8; 32]) -> Result<Self::IssueAuthSigType, Error>;

    /// Verifies a signature over a message using the issuance validating key.
    fn verify(
        ik: &Self::IkType,
        msg: &[u8],
        signature: &Self::IssueAuthSigType,
    ) -> Result<(), Error>;
}

/// An issuance authorizing key.
///
/// This is denoted by `isk` as defined in [ZIP 227][issuancekeycomponents].
///
/// [issuancekeycomponents]: https://zips.z.cash/zip-0227#issuance-key-derivation
#[derive(Clone)]
pub struct IssueAuthKey<S: IssueAuthSigScheme>(S::IskType);

/// An issuance validating key which is used to validate issuance authorization signatures.
///
/// This is denoted by `ik` and defined in [ZIP 227: Issuance of Zcash Shielded Assets § Issuance Key Generation][IssuanceZSA].
///
/// [IssuanceZSA]: https://zips.z.cash/zip-0227#issuance-key-derivation
#[derive(Clone)]
pub struct IssueValidatingKey<S: IssueAuthSigScheme>(S::IkType);

/// An issuance authorization signature `issueAuthSig`,
///
/// as defined in [ZIP 227][issueauthsig].
///
/// [issueauthsig]: https://zips.z.cash/zip-0227#issuance-authorization-signature-scheme
#[derive(Debug)]
pub struct IssueAuthSig<S: IssueAuthSigScheme>(S::IssueAuthSigType);

/// The Orchard-ZSA issuance authorization signature scheme, based on BIP 340 Schnorr.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZSASchnorr;

impl IssueAuthSigScheme for ZSASchnorr {
    const ALGORITHM_BYTE: u8 = 0x00;

    type IskType = NonZeroScalar;
    type IkType = VerifyingKey;
    type IssueAuthSigType = schnorr::Signature;

    fn isk_to_bytes(isk: &Self::IskType) -> Vec<u8> {
        isk.to_bytes().to_vec()
    }

    fn isk_from_bytes(bytes: &[u8]) -> Option<Self::IskType> {
        NonZeroScalar::try_from(bytes).ok()
    }

    fn ik_to_bytes(ik: &Self::IkType) -> Vec<u8> {
        ik.to_bytes().to_vec()
    }

    fn ik_from_bytes(bytes: &[u8]) -> Option<Self::IkType> {
        VerifyingKey::from_bytes(bytes).ok()
    }

    fn sig_to_bytes(sig: &Self::IssueAuthSigType) -> Vec<u8> {
        sig.to_bytes().to_vec()
    }

    fn sig_from_bytes(bytes: &[u8]) -> Option<Self::IssueAuthSigType> {
        schnorr::Signature::try_from(bytes).ok()
    }

    fn random_isk(rng: &mut impl CryptoRngCore) -> Self::IskType {
        NonZeroScalar::random(rng)
    }

    fn ik_from_isk(&isk: &Self::IskType) -> Self::IkType {
        *schnorr::SigningKey::from(isk).verifying_key()
    }

    fn try_sign(isk: &Self::IskType, msg: &[u8; 32]) -> Result<Self::IssueAuthSigType, Error> {
        schnorr::SigningKey::from(*isk)
            .sign_prehash(msg)
            .map_err(|_| Error::InvalidIssueBundleSig)
    }

    fn verify(ik: &Self::IkType, msg: &[u8], sig: &Self::IssueAuthSigType) -> Result<(), Error> {
        ik.verify_prehash(msg, sig)
            .map_err(|_| Error::InvalidIssueBundleSig)
    }
}

impl<S: IssueAuthSigScheme> IssueAuthKey<S> {
    /// Constructs an issuance authorizing key from the provided bytes.
    ///
    /// Returns `None` if the bytes do not correspond to a valid issuance authorizing key.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        S::isk_from_bytes(bytes).map(Self)
    }

    /// Returns the raw bytes of the issuance key.
    pub fn to_bytes(&self) -> Vec<u8> {
        S::isk_to_bytes(&self.0)
    }

    /// Generates a random issuance authorizing key.
    ///
    /// This is only used when generating a random AssetBase.
    /// Real issuance keys should be derived according to [ZIP 32].
    ///
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(S::random_isk(rng))
    }

    /// Derives the Orchard-ZSA issuance key for the given seed, coin type, and account.
    pub fn from_zip32_seed(
        seed: &[u8],
        coin_type: u32,
        account: u32,
    ) -> Result<Self, zip32::Error> {
        if account != 0 {
            return Err(zip32::Error::NonZeroAccount);
        }

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

        Self::from_bytes(&isk_bytes).ok_or(zip32::Error::InvalidSpendingKey)
    }

    /// Sign the provided message using the `IssueAuthKey`.
    /// Only supports signing of messages of length 32 bytes, since we will only be using it to sign 32 byte SIGHASH values.
    pub fn try_sign(&self, msg: &[u8; 32]) -> Result<IssueAuthSig<S>, Error> {
        S::try_sign(&self.0, msg).map(IssueAuthSig)
    }
}

impl<S: IssueAuthSigScheme> Debug for IssueAuthKey<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IssueAuthKey")
            .field(&self.to_bytes())
            .finish()
    }
}

impl<S: IssueAuthSigScheme> From<&IssueAuthKey<S>> for IssueValidatingKey<S> {
    fn from(isk: &IssueAuthKey<S>) -> Self {
        Self(S::ik_from_isk(&isk.0))
    }
}

impl<S: IssueAuthSigScheme> IssueValidatingKey<S> {
    /// Converts this issuance validating key to its serialized form,
    /// in big-endian order as defined in BIP 340.
    pub fn to_bytes(&self) -> Vec<u8> {
        S::ik_to_bytes(&self.0)
    }

    /// Constructs an Orchard issuance validating key from the provided bytes.
    /// The bytes are assumed to be encoded in big-endian order.
    ///
    /// Returns `None` if the bytes do not correspond to a valid key.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        S::ik_from_bytes(bytes).map(Self)
    }

    /// Encodes the issuance validating key into a byte vector, in the manner defined in [ZIP 227][issuancekeycomponents].
    ///
    /// [issuancekeycomponents]: https://zips.z.cash/zip-0227#derivation-of-issuance-validating-key
    pub fn encode(&self) -> Vec<u8> {
        let ik_bytes = S::ik_to_bytes(&self.0);
        let mut encoded = Vec::with_capacity(1 + ik_bytes.len());
        encoded.push(S::ALGORITHM_BYTE);
        encoded.extend(ik_bytes);
        encoded
    }

    /// Decodes an issuance validating key from the byte representation defined in [ZIP 227][issuancekeycomponents].
    ///
    /// [issuancekeycomponents]: https://zips.z.cash/zip-0227#derivation-of-issuance-validating-key
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (&algorithm_byte, key_bytes) = bytes
            .split_first()
            .ok_or(Error::InvalidIssueValidatingKey)?;

        if algorithm_byte != S::ALGORITHM_BYTE {
            return Err(Error::InvalidIssueValidatingKey);
        }

        Self::from_bytes(key_bytes).ok_or(Error::InvalidIssueValidatingKey)
    }

    /// Verifies a purported `signature` over `msg` made by this verification key.
    pub fn verify(&self, msg: &[u8], sig: &IssueAuthSig<S>) -> Result<(), Error> {
        S::verify(&self.0, msg, &sig.0)
    }
}

impl<S: IssueAuthSigScheme> Debug for IssueValidatingKey<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IssueValidatingKey")
            .field(&self.to_bytes())
            .finish()
    }
}

impl<S: IssueAuthSigScheme> PartialEq for IssueValidatingKey<S> {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl<S: IssueAuthSigScheme> Eq for IssueValidatingKey<S> {}

impl<S: IssueAuthSigScheme> IssueAuthSig<S> {
    /// Serialize the issuance authorization signature to its canonical byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        S::sig_to_bytes(&self.0)
    }

    /// Deserialize the issuance authorization signature from its canonical byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        S::sig_from_bytes(bytes).map(Self)
    }

    /// Encodes the issuance authorization signature into a byte vector, in the manner
    /// defined in [ZIP 227][issueauthsig].
    ///
    /// [issueauthsig]: https://zips.z.cash/zip-0227#issuance-authorization-signing-and-validation
    pub fn encode(&self) -> Vec<u8> {
        let sig_bytes = S::sig_to_bytes(&self.0);
        let mut encoded = Vec::with_capacity(1 + sig_bytes.len());
        encoded.push(S::ALGORITHM_BYTE);
        encoded.extend(sig_bytes);
        encoded
    }

    /// Decodes an issuance authorization signature from the byte representation defined
    /// in [ZIP 227][issueauthsig].
    ///
    /// [issueauthsig]: https://zips.z.cash/zip-0227#issuance-authorization-signing-and-validation
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (&algorithm_byte, key_bytes) =
            bytes.split_first().ok_or(Error::InvalidIssueBundleSig)?;

        if algorithm_byte != S::ALGORITHM_BYTE {
            return Err(Error::InvalidIssueBundleSig);
        }

        Self::from_bytes(key_bytes).ok_or(Error::InvalidIssueBundleSig)
    }
}

impl<S: IssueAuthSigScheme> Clone for IssueAuthSig<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S: IssueAuthSigScheme> PartialEq for IssueAuthSig<S> {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl<S: IssueAuthSigScheme> Eq for IssueAuthSig<S> {}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use super::{IssueAuthKey, IssueValidatingKey, ZSASchnorr};

    use proptest::prelude::*;

    prop_compose! {
        /// Generate a uniformly distributed Orchard issuance authorizing key.
        pub fn arb_issuance_authorizing_key()(
            key in prop::array::uniform32(prop::num::u8::ANY)
                .prop_map(|key| IssueAuthKey::from_bytes(&key))
                .prop_filter(
                    "Values must be valid Orchard-ZSA issuance authorizing keys.",
                    |opt| opt.is_some()
                )
        ) -> IssueAuthKey<ZSASchnorr> {
            key.unwrap()
        }
    }

    prop_compose! {
        /// Generate a uniformly distributed issuance validating key.
        pub fn arb_issuance_validating_key()(isk in arb_issuance_authorizing_key()) -> IssueValidatingKey<ZSASchnorr> {
            IssueValidatingKey::from(&isk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn issuance_authorizing_key_from_bytes_fail_on_zero() {
        // isk must not be the zero scalar for the ZSA Schnorr scheme.
        let zero_bytes = [0u8; 32];
        let isk = IssueAuthKey::<ZSASchnorr>::from_bytes(&zero_bytes);
        assert!(isk.is_none());
    }

    #[test]
    fn issuance_authorizing_key_from_bytes_to_bytes_roundtrip() {
        let isk: IssueAuthKey<ZSASchnorr> = IssueAuthKey::random(&mut OsRng);
        let isk_bytes = isk.to_bytes();
        let isk_roundtrip = IssueAuthKey::<ZSASchnorr>::from_bytes(&isk_bytes).unwrap();
        assert_eq!(isk_bytes, isk_roundtrip.to_bytes());
    }

    #[test]
    fn issuance_auth_sig_test_vectors() {
        for tv in crate::test_vectors::issuance_auth_sig::TEST_VECTORS {
            let isk = IssueAuthKey::<ZSASchnorr>::from_bytes(&tv.isk).unwrap();

            let ik = IssueValidatingKey::from(&isk);
            assert_eq!(ik.to_bytes(), &tv.ik);

            let message = tv.msg;

            let sig = isk.try_sign(&message).unwrap();
            let sig_bytes = sig.to_bytes();
            assert_eq!(sig_bytes, &tv.sig);

            assert!(ik.verify(&message, &sig).is_ok());
        }
    }
}
