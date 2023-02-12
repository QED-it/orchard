use group::GroupEncoding;
use halo2_proofs::arithmetic::CurveExt;
use pasta_curves::pallas;
use std::hash::{Hash, Hasher};
use blake2b_simd::{Hash as Blake2bHash, Params};


use subtle::{Choice, ConstantTimeEq, CtOption};

use crate::constants::fixed_bases::{VALUE_COMMITMENT_PERSONALIZATION, VALUE_COMMITMENT_V_BYTES, ZSA_ASSET_BASE_PERSONALIZATION};
use crate::keys::IssuanceValidatingKey;

/// Note type identifier.
#[derive(Clone, Copy, Debug, Eq)]
pub struct AssetId(pallas::Point);

pub const MAX_ASSET_DESCRIPTION_SIZE: usize = 512;

/// Personalization for the ZSA asset digest generator
pub const ZSA_ASSET_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZZSA-AssetDigest";

/// AssetDigest for the ZSA asset
pub fn asset_digest(
    asset_id: Vec<u8>,
) -> Blake2bHash {
    Params::new()
        .hash_length(32)
        .personal(ZSA_ASSET_DIGEST_PERSONALIZATION)
        .to_state()
        .update(&asset_id)
        .finalize()
}

// the hasher used to derive the assetID
fn zsa_value_base(msg: &[u8]) -> pallas::Point {
    pallas::Point::hash_to_curve(ZSA_ASSET_BASE_PERSONALIZATION)(msg)
}

impl AssetId {
    /// Deserialize the asset_id from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Point::from_bytes(bytes).map(AssetId)
    }

    /// Serialize the asset_id to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }


    /// Note type derivation$.
    ///
    /// Defined in [Transfer and Burn of Zcash Shielded Assets][AssetBase].
    ///
    /// [notetypes]: https://qed-it.github.io/zips/draft-ZIP-0226.html#asset-base
    ///
    /// # Panics
    ///
    /// Panics if `asset_desc` is empty or greater than `MAX_ASSET_DESCRIPTION_SIZE`.
    #[allow(non_snake_case)]
    pub fn derive(ik: &IssuanceValidatingKey, asset_desc: &str) -> Self {
        assert!(is_asset_desc_of_valid_size(asset_desc));

        // EncodeAssetId(ik, asset_desc) = ik || asset_desc
        let EncodeAssetId = [&ik.to_bytes(), asset_desc.as_bytes()].concat();

        // AssetDigest : BLAKE2b-256(EncodeAssetId)
        let AssetDigest = asset_digest(EncodeAssetId);

        //AssetBase : ZSAValueBase(AssetDigest)
        AssetId(zsa_value_base(AssetDigest.as_bytes()))
    }

    /// Note type for the "native" currency (zec), maintains backward compatibility with Orchard untyped notes.
    pub fn native() -> Self {
        // TODO: should we rename "VALUE_COMMITMENT_PERSONALIZATION" to Be "Native_ASSET_BASE_PERSONALIZATION"?
        // TODO: Same for VALUE_COMMITMENT_V_BYTES?
        AssetId(pallas::Point::hash_to_curve(VALUE_COMMITMENT_PERSONALIZATION)(&VALUE_COMMITMENT_V_BYTES[..]))
    }

    /// The base point used in value commitments.
    pub fn cv_base(&self) -> pallas::Point {
        self.0
    }

    /// Whether this note represents a native or ZSA asset.
    pub fn is_native(&self) -> Choice {
        self.0.ct_eq(&Self::native().0)
    }
}

impl Hash for AssetId {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write(&self.to_bytes());
        h.finish();
    }
}

/// Check that `asset_desc` is of valid size.
pub fn is_asset_desc_of_valid_size(asset_desc: &str) -> bool {
    !asset_desc.is_empty() && asset_desc.bytes().len() <= MAX_ASSET_DESCRIPTION_SIZE
}

impl PartialEq for AssetId {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use super::AssetId;

    use proptest::prelude::*;

    use crate::keys::{testing::arb_spending_key, IssuanceAuthorizingKey, IssuanceValidatingKey};

    prop_compose! {
        /// Generate a uniformly distributed note type
        pub fn arb_asset_id()(
            is_native in prop::bool::ANY,
            sk in arb_spending_key(),
            str in "[A-Za-z]{255}",
        ) -> AssetId {
            if is_native {
                AssetId::native()
            } else {
                let isk = IssuanceAuthorizingKey::from(&sk);
                AssetId::derive(&IssuanceValidatingKey::from(&isk), &str)
            }
        }
    }

    prop_compose! {
        /// Generate the native note type
        pub fn native_asset_id()(_i in 0..10) -> AssetId {
            // TODO: remove _i
            AssetId::native()
        }
    }

    prop_compose! {
        /// Generate an asset ID
        pub fn arb_zsa_asset_id()(
            sk in arb_spending_key(),
            str in "[A-Za-z]{255}"
        ) -> AssetId {
            let isk = IssuanceAuthorizingKey::from(&sk);
            AssetId::derive(&IssuanceValidatingKey::from(&isk), &str)
        }
    }

    prop_compose! {
        /// Generate an asset ID using a specific description
        pub fn zsa_asset_id(asset_desc: String)(
            sk in arb_spending_key(),
        ) -> AssetId {
            assert!(super::is_asset_desc_of_valid_size(&asset_desc));
            let isk = IssuanceAuthorizingKey::from(&sk);
            AssetId::derive(&IssuanceValidatingKey::from(&isk), &asset_desc)
        }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::asset_id::test_vectors();

        for tv in test_vectors {
            let description = std::str::from_utf8(&tv.description).unwrap();

            let calculated_asset_id = AssetId::derive(
                &IssuanceValidatingKey::from_bytes(&tv.key).unwrap(),
                description,
            );
            let test_vector_asset_id = AssetId::from_bytes(&tv.asset_id).unwrap();

            assert_eq!(calculated_asset_id, test_vector_asset_id);
        }
    }
}
