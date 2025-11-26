//! Validating burn operations on asset bundles.
//!
//! The module provides a function `validate_bundle_burn` that can be used to validate the burn values for the bundle.
//!
use alloc::collections::BTreeMap;
use core::fmt;

use crate::{issuance::AssetRecord, note::AssetBase, value::NoteValue};

/// Possible errors that can occur during bundle burn validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurnError {
    /// Encountered a duplicate asset to burn.
    DuplicateAsset,
    /// Cannot burn a native asset.
    NativeAsset,
    /// Cannot burn an asset with a zero value.
    ZeroAmount,
    /// Asset not found in state
    AssetNotFoundInState,
    /// Insufficient supply for burn
    InsufficientSupply,
}

/// Validates burn operations for a bundle and computes the resulting asset states.
///
/// This function validates burn operations by:
/// - Ensuring each asset is unique, non-native, and has a non-zero burn value
/// - Verifying that each asset exists in the current state
/// - Checking that there is sufficient supply to burn
/// - Computing the new asset records after burning
///
/// Each burn element is represented as a tuple of `AssetBase` and `NoteValue` (value for the burn).
///
/// # Arguments
///
/// * `burn` - An iterable of assets to burn, where each asset is represented as a tuple of `AssetBase` and `NoteValue`
/// * `get_current_record` - A closure that retrieves the current `AssetRecord` for a given `AssetBase`
///
/// # Returns
///
/// Returns a `BTreeMap<AssetBase, AssetRecord>` containing the new asset records after burning.
///
/// # Errors
///
/// Returns a `BurnError` if:
/// * Any asset in the `burn` vector is native (`BurnError::NativeAsset`).
/// * Any asset in the `burn` vector has a zero value (`BurnError::ZeroAmount`).
/// * Any asset in the `burn` vector is not unique (`BurnError::DuplicateAsset`).
/// * Any asset is not found in the current state (`BurnError::AssetNotFoundInState`).
/// * Any asset has insufficient supply for the burn amount (`BurnError::InsufficientSupply`).
pub fn validate_bundle_burn(
    burn: impl IntoIterator<Item = (AssetBase, NoteValue)>,
    mut get_current_record: impl FnMut(&AssetBase) -> Option<AssetRecord>,
) -> Result<BTreeMap<AssetBase, AssetRecord>, BurnError> {
    let mut new_records = BTreeMap::new();

    for (asset, burn_amount) in burn {
        if asset.is_native().into() {
            return Err(BurnError::NativeAsset);
        }

        let burn_amount_raw = burn_amount.inner();
        if burn_amount_raw == 0 {
            return Err(BurnError::ZeroAmount);
        }

        let current_record = get_current_record(&asset).ok_or(BurnError::AssetNotFoundInState)?;

        let current_amount_raw = current_record.amount.inner();
        if current_amount_raw < burn_amount_raw {
            return Err(BurnError::InsufficientSupply);
        }

        let new_record = AssetRecord {
            amount: NoteValue::from_raw(current_amount_raw - burn_amount_raw),
            is_finalized: current_record.is_finalized,
            reference_note: current_record.reference_note,
        };

        if new_records.insert(asset, new_record).is_some() {
            return Err(BurnError::DuplicateAsset);
        }
    }

    Ok(new_records)
}

impl fmt::Display for BurnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BurnError::DuplicateAsset => write!(f, "Encountered a duplicate asset to burn."),
            BurnError::NativeAsset => write!(f, "Cannot burn a native asset."),
            BurnError::ZeroAmount => {
                write!(f, "Cannot burn an asset with a zero value.")
            }
            BurnError::AssetNotFoundInState => write!(f, "Asset not found in state."),
            BurnError::InsufficientSupply => write!(f, "Insufficient supply for burn"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{issuance::compute_asset_desc_hash, value::NoteValue, Note};
    use nonempty::NonEmpty;

    /// Creates an item of bundle burn list for a given asset description hash and value.
    ///
    /// This function is deterministic and guarantees that each call with the same parameters
    /// will return the same result. It achieves determinism by using a static `IssueAuthKey`.
    ///
    /// # Arguments
    ///
    /// * `asset_desc_hash` - The asset description hash.
    /// * `value` - The value for the burn.
    ///
    /// # Returns
    ///
    /// A tuple `(AssetBase, Amount)` representing the burn list item.
    ///
    fn get_burn_tuple(asset_desc_hash: &[u8; 32], value: u64) -> (AssetBase, NoteValue) {
        use crate::issuance_auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr};

        let isk = IssueAuthKey::<ZSASchnorr>::from_bytes(&[1u8; 32]).unwrap();

        (
            AssetBase::derive(&IssueValidatingKey::from(&isk), asset_desc_hash),
            NoteValue::from_raw(value),
        )
    }

    /// Builds a BTreeMap of asset states from an array of (asset_desc, supply) tuples.
    ///
    /// # Arguments
    ///
    /// * `data` - An array of tuples where each tuple contains:
    ///   - `asset_desc`: A byte slice representing the asset description
    ///   - `supply`: The supply amount for the asset
    ///
    /// # Returns
    ///
    /// A `BTreeMap<AssetBase, AssetRecord>` containing the asset records.
    fn build_state(data: &[(&[u8], u64)]) -> BTreeMap<AssetBase, AssetRecord> {
        use crate::keys::{FullViewingKey, Scope, SpendingKey};
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let fvk = FullViewingKey::from(&SpendingKey::random(&mut rng));
        let recipient = fvk.address_at(0u32, Scope::External);

        data.iter()
            .map(|(desc, supply)| {
                let (asset, _) = get_burn_tuple(
                    &compute_asset_desc_hash(&NonEmpty::from_slice(desc).unwrap()),
                    0,
                );

                // Create reference note with proper rho
                let reference_note = Note::new(
                    recipient,
                    NoteValue::from_raw(0),
                    asset,
                    crate::note::Rho::zero(),
                    &mut rng,
                );

                let record = AssetRecord {
                    amount: NoteValue::from_raw(*supply),
                    is_finalized: true,
                    reference_note,
                };
                (asset, record)
            })
            .collect()
    }

    /// Creates a mock state with predefined asset records
    fn create_mock_state() -> BTreeMap<AssetBase, AssetRecord> {
        let mock_data = [
            // (asset_desc, supply)
            (b"Asset 1".as_ref(), 100),
            (b"Asset 2".as_ref(), 50),
            (b"Asset 3".as_ref(), 200),
        ];

        build_state(&mock_data)
    }

    /// Helper function to validate bundle burn with the default mock state.
    fn validate_with_mock_state(
        burn: impl IntoIterator<Item = (AssetBase, NoteValue)>,
    ) -> Result<BTreeMap<AssetBase, AssetRecord>, BurnError> {
        let mock_state = create_mock_state();
        validate_bundle_burn(burn, |asset| mock_state.get(asset).cloned())
    }

    /// Strips reference notes, keeping only amounts (reference notes contain
    /// randomness and can't be compared directly).
    fn strip_reference_notes(
        records: &BTreeMap<AssetBase, AssetRecord>,
    ) -> BTreeMap<AssetBase, NoteValue> {
        records
            .iter()
            .map(|(asset, record)| (*asset, record.amount))
            .collect()
    }

    #[test]
    fn validate_bundle_burn_success() {
        let bundle_burn = vec![
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                10,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 2").unwrap()),
                20,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 3").unwrap()),
                10,
            ),
        ];

        let result = validate_with_mock_state(bundle_burn);

        assert!(result.is_ok());

        let expected_state = build_state(&[
            (&b"Asset 1".as_ref(), 90),
            (&b"Asset 2".as_ref(), 30),
            (&b"Asset 3".as_ref(), 190),
        ]);

        assert_eq!(
            strip_reference_notes(&result.unwrap()),
            strip_reference_notes(&expected_state)
        );
    }

    #[test]
    fn validate_bundle_burn_duplicate_asset() {
        let bundle_burn = vec![
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                10,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                20,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 3").unwrap()),
                10,
            ),
        ];

        let result = validate_with_mock_state(bundle_burn);

        assert_eq!(result, Err(BurnError::DuplicateAsset));
    }

    #[test]
    fn validate_bundle_burn_native_asset() {
        let bundle_burn = vec![
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                10,
            ),
            (AssetBase::native(), NoteValue::from_raw(20)),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 3").unwrap()),
                10,
            ),
        ];

        let result = validate_with_mock_state(bundle_burn);

        assert_eq!(result, Err(BurnError::NativeAsset));
    }

    #[test]
    fn validate_bundle_burn_zero_value() {
        let bundle_burn = vec![
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                10,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 2").unwrap()),
                0,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 3").unwrap()),
                10,
            ),
        ];

        let result = validate_with_mock_state(bundle_burn);

        assert_eq!(result, Err(BurnError::ZeroAmount));
    }

    #[test]
    fn validate_bundle_burn_asset_not_found() {
        let bundle_burn = vec![
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                10,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Unknown Asset").unwrap()),
                20,
            ),
        ];

        let result = validate_with_mock_state(bundle_burn);

        assert_eq!(result, Err(BurnError::AssetNotFoundInState));
    }

    #[test]
    fn validate_bundle_burn_insufficient_supply() {
        let bundle_burn = vec![
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 1").unwrap()),
                10,
            ),
            get_burn_tuple(
                &compute_asset_desc_hash(&NonEmpty::from_slice(b"Asset 2").unwrap()),
                100, // Asset 2 only has 50
            ),
        ];

        let result = validate_with_mock_state(bundle_burn);

        assert_eq!(result, Err(BurnError::InsufficientSupply));
    }
}
