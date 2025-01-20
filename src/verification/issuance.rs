//! Issuance verification functions

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

/// Validation for Orchard IssueBundles
///
/// The following checks are performed:
/// - **IssueBundle Verification**:
///     - The signature on the provided `sighash` is verified correctly.
/// - **IssueAction Verification**:
///     - The asset description size is correct.
///     - The `verify_supply` method checks pass,
///     - The new amount does not overflow the previous total supply value.
///     - The `AssetBase` for the `IssueAction` has not been previously finalized.
///
/// # Arguments
///
/// - `bundle` - A reference to the `IssueBundle` to be validated.
/// - `sighash` - A 32-byte array representing the sighash used to verify the bundle's signature.
/// - `get_asset_state` - A closure that takes a reference to an `AssetBase` and returns an
///   `Option<AssetSupply>`, representing the current state of the asset in the global store of
///   previously issued assets.
///
/// # Returns
///
/// A `Result` with a `HashMap` on success, which contains new values for updated or newly added
/// items in the global state. Each key is an `AssetBase`, and the corresponding value is a new
/// (updated) `AssetSupply`.
///
/// # Errors
///
/// - `IssueBundleInvalidSignature`: Occurs if the signature verification for the provided `sighash`
///    fails.
/// - `WrongAssetDescSize`: Raised if the asset description size for any asset in the bundle is
///    incorrect.
/// - `ValueOverflow`: Occurs if an overflow happens during the calculation of the total value for
///    the notes.
/// - `IssueActionPreviouslyFinalizedAssetBase`: Occurs if the asset has already been finalized.
/// - **Other Errors**: Any additional errors returned by the `verify_supply` method of `IssueAction`
///   will also be propagated.
pub fn verify_issue_bundle(
    bundle: &IssueBundle<Signed>,
    sighash: [u8; 32],
    // FIXME: consider using AssetStateStore trait with get_asset method instead
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

// FIXME: Add more tests for issued_assets (i.e. "global state") change after verify_issue_bundle
// is called: 1) check for expected output, 2) check for processing of existing assets etc.
#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::{
        issuance::{
            tests::{identity_point_test_params, setup_params},
            Error::{
                AssetBaseCannotBeIdentityPoint, IssueActionPreviouslyFinalizedAssetBase,
                IssueBundleIkMismatchAssetBase, IssueBundleInvalidSignature, WrongAssetDescSize,
            },
            IssueAction, IssueInfo, Signed,
        },
        keys::{IssuanceAuthorizingKey, IssuanceValidatingKey},
        note::{AssetBase, Nullifier, Rho},
        value::NoteValue,
        Note,
    };

    use super::{verify_issue_bundle, AssetSupply, IssueBundle};

    fn get_finalization_set(issued_assets: &HashMap<AssetBase, AssetSupply>) -> HashSet<AssetBase> {
        issued_assets
            .iter()
            .filter_map(|(asset, asset_supply)| asset_supply.is_finalized.then(|| asset.clone()))
            .collect::<HashSet<_>>()
    }

    #[test]
    fn issue_bundle_verify() {
        let (rng, isk, ik, recipient, sighash) = setup_params();

        let (bundle, _) = IssueBundle::new(
            ik,
            b"Verify".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let signed = bundle.prepare(sighash).sign(&isk).unwrap();

        let issued_assets = verify_issue_bundle(&signed, sighash, |_| None).unwrap();
        let prev_finalized = get_finalization_set(&issued_assets);

        assert!(prev_finalized.is_empty());
    }

    #[test]
    fn issue_bundle_verify_with_finalize() {
        let (rng, isk, ik, recipient, sighash) = setup_params();

        let (mut bundle, _) = IssueBundle::new(
            ik.clone(),
            b"Verify with finalize".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(7),
            }),
            true,
            rng,
        )
        .unwrap();

        bundle.finalize_action(b"Verify with finalize").unwrap();

        let signed = bundle.prepare(sighash).sign(&isk).unwrap();

        let issued_assets = verify_issue_bundle(&signed, sighash, |_| None).unwrap();
        let prev_finalized = get_finalization_set(&issued_assets);

        assert_eq!(prev_finalized.len(), 1);
        assert!(prev_finalized.contains(&AssetBase::derive(&ik, b"Verify with finalize")));
    }

    #[test]
    fn issue_bundle_verify_with_supply_info() {
        let (rng, isk, ik, recipient, sighash) = setup_params();

        let asset1_desc = b"Verify with supply info 1".to_vec();
        let asset2_desc = b"Verify with supply info 2".to_vec();
        let asset3_desc = b"Verify with supply info 3".to_vec();

        let asset1_base = AssetBase::derive(&ik, &asset1_desc);
        let asset2_base = AssetBase::derive(&ik, &asset2_desc);
        let asset3_base = AssetBase::derive(&ik, &asset3_desc);

        let (mut bundle, _) = IssueBundle::new(
            ik,
            asset1_desc.clone(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(7),
            }),
            true,
            rng,
        )
        .unwrap();

        bundle
            .add_recipient(&asset1_desc, recipient, NoteValue::from_raw(8), false, rng)
            .unwrap();

        bundle.finalize_action(&asset1_desc).unwrap();

        bundle
            .add_recipient(&asset2_desc, recipient, NoteValue::from_raw(10), true, rng)
            .unwrap();

        bundle.finalize_action(&asset2_desc).unwrap();

        bundle
            .add_recipient(&asset3_desc, recipient, NoteValue::from_raw(5), true, rng)
            .unwrap();

        let signed = bundle.prepare(sighash).sign(&isk).unwrap();

        let issued_assets = verify_issue_bundle(&signed, sighash, |_| None).unwrap();
        let prev_finalized = get_finalization_set(&issued_assets);

        assert_eq!(prev_finalized.len(), 2);

        assert!(prev_finalized.contains(&asset1_base));
        assert!(prev_finalized.contains(&asset2_base));
        assert!(!prev_finalized.contains(&asset3_base));

        assert_eq!(issued_assets.keys().len(), 3);

        let reference_note1 = signed.actions()[0].notes()[0];
        let reference_note2 = signed.actions()[1].notes()[0];
        let reference_note3 = signed.actions()[2].notes()[0];

        assert_eq!(
            issued_assets.get(&asset1_base),
            Some(&AssetSupply::new(
                NoteValue::from_raw(15),
                true,
                Some(reference_note1)
            ))
        );
        assert_eq!(
            issued_assets.get(&asset2_base),
            Some(&AssetSupply::new(
                NoteValue::from_raw(10),
                true,
                Some(reference_note2)
            ))
        );
        assert_eq!(
            issued_assets.get(&asset3_base),
            Some(&AssetSupply::new(
                NoteValue::from_raw(5),
                false,
                Some(reference_note3)
            ))
        );
    }

    #[test]
    fn issue_bundle_verify_fail_previously_finalized() {
        let (rng, isk, ik, recipient, sighash) = setup_params();

        let (bundle, _) = IssueBundle::new(
            ik.clone(),
            b"already final".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let signed = bundle.prepare(sighash).sign(&isk).unwrap();

        let final_type = AssetBase::derive(&ik, b"already final");

        let issued_assets = [(
            final_type,
            AssetSupply::new(NoteValue::from_raw(0), true, None),
        )]
        .into_iter()
        .collect::<HashMap<_, _>>();

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |asset| issued_assets.get(asset).copied())
                .unwrap_err(),
            IssueActionPreviouslyFinalizedAssetBase(final_type)
        );
    }

    #[test]
    fn issue_bundle_verify_fail_bad_signature() {
        // we want to inject "bad" signatures for test purposes.
        impl IssueBundle<Signed> {
            pub fn set_authorization(&mut self, authorization: Signed) {
                self.authorization = authorization;
            }
        }

        let (rng, isk, ik, recipient, sighash) = setup_params();

        let (bundle, _) = IssueBundle::new(
            ik,
            b"bad sig".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let wrong_isk: IssuanceAuthorizingKey = IssuanceAuthorizingKey::random();

        let mut signed = bundle.prepare(sighash).sign(&isk).unwrap();

        signed.set_authorization(Signed {
            signature: wrong_isk.try_sign(&sighash).unwrap(),
        });

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |_| None).unwrap_err(),
            IssueBundleInvalidSignature
        );
    }

    #[test]
    fn issue_bundle_verify_fail_wrong_sighash() {
        let (rng, isk, ik, recipient, random_sighash) = setup_params();
        let (bundle, _) = IssueBundle::new(
            ik,
            b"Asset description".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let sighash: [u8; 32] = bundle.commitment().into();
        let signed = bundle.prepare(sighash).sign(&isk).unwrap();

        assert_eq!(
            verify_issue_bundle(&signed, random_sighash, |_| None).unwrap_err(),
            IssueBundleInvalidSignature
        );
    }

    #[test]
    fn issue_bundle_verify_fail_incorrect_asset_description() {
        let (mut rng, isk, ik, recipient, sighash) = setup_params();

        let (bundle, _) = IssueBundle::new(
            ik,
            b"Asset description".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let mut signed = bundle.prepare(sighash).sign(&isk).unwrap();

        // Add "bad" note
        let note = Note::new(
            recipient,
            NoteValue::from_raw(5),
            AssetBase::derive(signed.ik(), b"zsa_asset"),
            Rho::from_nf_old(Nullifier::dummy(&mut rng)),
            &mut rng,
        );

        signed.actions.first_mut().notes.push(note);

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |_| None).unwrap_err(),
            IssueBundleIkMismatchAssetBase
        );
    }

    #[test]
    fn issue_bundle_verify_fail_incorrect_ik() {
        let asset_description = b"Asset".to_vec();

        let (mut rng, isk, ik, recipient, sighash) = setup_params();

        let (bundle, _) = IssueBundle::new(
            ik,
            asset_description.clone(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let mut signed = bundle.prepare(sighash).sign(&isk).unwrap();

        let incorrect_isk = IssuanceAuthorizingKey::random();
        let incorrect_ik: IssuanceValidatingKey = (&incorrect_isk).into();

        // Add "bad" note
        let note = Note::new(
            recipient,
            NoteValue::from_raw(55),
            AssetBase::derive(&incorrect_ik, &asset_description),
            Rho::from_nf_old(Nullifier::dummy(&mut rng)),
            &mut rng,
        );

        signed.actions.first_mut().notes = vec![note];

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |_| None).unwrap_err(),
            IssueBundleIkMismatchAssetBase
        );
    }

    #[test]
    fn issue_bundle_verify_fail_wrong_asset_descr_size() {
        // we want to inject a "malformed" description for test purposes.
        impl IssueAction {
            pub fn modify_descr(&mut self, new_descr: Vec<u8>) {
                self.asset_desc = new_descr;
            }
        }

        let (rng, isk, ik, recipient, sighash) = setup_params();

        let (bundle, _) = IssueBundle::new(
            ik,
            b"Asset description".to_vec(),
            Some(IssueInfo {
                recipient,
                value: NoteValue::from_raw(5),
            }),
            true,
            rng,
        )
        .unwrap();

        let mut signed = bundle.prepare(sighash).sign(&isk).unwrap();

        // 1. Try a description that is too long
        signed.actions.first_mut().modify_descr(vec![b'X'; 513]);

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |_| None).unwrap_err(),
            WrongAssetDescSize
        );

        // 2. Try a description that is empty
        signed.actions.first_mut().modify_descr(b"".to_vec());

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |_| None).unwrap_err(),
            WrongAssetDescSize
        );
    }

    #[test]
    fn issue_bundle_cannot_be_signed_with_asset_base_identity_point() {
        let (isk, bundle, sighash) = identity_point_test_params(10, 20);

        assert_eq!(
            bundle.prepare(sighash).sign(&isk).unwrap_err(),
            AssetBaseCannotBeIdentityPoint
        );
    }

    #[test]
    fn issue_bundle_verify_fail_asset_base_identity_point() {
        let (isk, bundle, sighash) = identity_point_test_params(10, 20);

        let signed = IssueBundle {
            ik: bundle.ik().clone(),
            actions: bundle.actions,
            authorization: Signed {
                signature: isk.try_sign(&sighash).unwrap(),
            },
        };

        assert_eq!(
            verify_issue_bundle(&signed, sighash, |_| None).unwrap_err(),
            AssetBaseCannotBeIdentityPoint
        );
    }
}
