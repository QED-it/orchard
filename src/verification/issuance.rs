//! Issuance verification functions

// FIXME: move all verification tests here
use std::collections::HashMap;

use crate::{
    issuance::{
        Error::{
            self, IssueActionPreviouslyFinalizedAssetBase, IssueBundleInvalidSignature,
            ValueOverflow, WrongAssetDescSize,
        },
        IssueBundle, Signed,
    },
    note::{asset_base::is_asset_desc_of_valid_size, AssetBase},
    supply_info::AssetSupply,
};

// FIXME: update the doc comment
/// Validation for Orchard IssueBundles
///
/// A set of previously finalized asset types must be provided in `finalized` argument.
///
/// The following checks are performed:
/// * For the `IssueBundle`:
///     * the Signature on top of the provided `sighash` verifies correctly.
/// * For each `IssueAction`:
///     * Asset description size is correct.
///     * `AssetBase` for the `IssueAction` has not been previously finalized.
/// * For each `Note` inside an `IssueAction`:
///     * All notes have the same, correct `AssetBase`.
///
/// # Returns
///
/// A Result containing a SupplyInfo struct, which stores supply information in a HashMap.
/// The HashMap `assets` uses AssetBase as the key, and an AssetSupply struct as the
/// value. The AssetSupply contains a NoteValue (representing the total value of all notes for
/// the asset), a bool indicating whether the asset is finalized and a Note (the reference note
/// for this asset).
///
/// # Errors
///
/// * `IssueBundleInvalidSignature`: This error occurs if the signature verification
///    for the provided `sighash` fails.
/// * `WrongAssetDescSize`: This error is raised if the asset description size for any
///    asset in the bundle is incorrect.
/// * `IssueActionPreviouslyFinalizedAssetBase`:  This error occurs if the asset has already been
///    finalized (inserted into the `finalized` collection).
/// * `ValueOverflow`: This error occurs if an overflow happens during the calculation of
///     the value sum for the notes in the asset.
/// * `IssueBundleIkMismatchAssetBase`: This error is raised if the `AssetBase` derived from
///    the `ik` (Issuance Validating Key) and the `asset_desc` (Asset Description) does not match
///    the expected `AssetBase`.

pub fn verify_issue_bundle(
    bundle: &IssueBundle<Signed>,
    sighash: [u8; 32],
    // FIXME: consider using AssetStateStore trait with get_asset method instead
    // FIXME: consider not using AssetStateUpdates (it's used for atomict batch updates), but
    // delegate this functionality to Zebra and simply add add_asset method to AssetStateStore
    // and use it instead
    get_asset_state: impl Fn(&AssetBase) -> Option<AssetSupply>,
) -> Result<HashMap<AssetBase, AssetSupply>, Error> {
    bundle
        .ik()
        .verify(&sighash, bundle.authorization().signature())
        .map_err(|_| IssueBundleInvalidSignature)?;

    let verified_asset_states =
        bundle
            .actions()
            .iter()
            .try_fold(HashMap::new(), |mut verified_asset_states, action| {
                if !is_asset_desc_of_valid_size(action.asset_desc()) {
                    return Err(WrongAssetDescSize);
                }

                let (asset, action_asset_state) = action.verify_supply(bundle.ik())?;

                let old_asset_state = verified_asset_states
                    .get(&asset)
                    .cloned()
                    .or_else(|| get_asset_state(&asset))
                    .unwrap_or_default();

                let amount =
                    (old_asset_state.amount + action_asset_state.amount).ok_or(ValueOverflow)?;

                let is_finalized = (!old_asset_state.is_finalized)
                    .then_some(action_asset_state.is_finalized)
                    .ok_or(IssueActionPreviouslyFinalizedAssetBase(asset))?;

                let reference_note = old_asset_state
                    .reference_note
                    .or(action_asset_state.reference_note);

                verified_asset_states.insert(
                    asset,
                    AssetSupply::new(amount, is_finalized, reference_note),
                );

                Ok(verified_asset_states)
            })?;

    Ok(verified_asset_states)
}
