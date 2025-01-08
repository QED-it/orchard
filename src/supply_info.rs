//! Structs and logic related to supply information management for assets.

use std::collections::{hash_map, HashMap, HashSet};

use crate::{issuance::Error, note::AssetBase, value::NoteValue, Note};

/// Represents the amount of an asset, its finalization status and reference note.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct AssetSupply {
    /// The amount of the asset.
    pub amount: NoteValue,

    /// Whether or not the asset is finalized.
    pub is_finalized: bool,

    /// The reference note, `None` if this `AssetSupply` instance is created from an issue bundle that does not include
    /// a reference note (a non-first issuance)
    pub reference_note: Option<Note>,
}

impl AssetSupply {
    /// Creates a new AssetSupply instance with the given amount, finalization status and reference
    /// note.
    pub fn new(amount: NoteValue, is_finalized: bool, reference_note: Option<Note>) -> Self {
        Self {
            amount,
            is_finalized,
            reference_note,
        }
    }
}

/// Contains information about the supply of assets.
#[derive(Debug, Clone)]
pub struct SupplyInfo {
    /// A map of asset bases to their respective supply information.
    pub assets: HashMap<AssetBase, AssetSupply>,
}

impl SupplyInfo {
    /// Creates a new, empty `SupplyInfo` instance.
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }

    /// Inserts or updates an asset's supply information in the supply info map.
    /// If the asset exists, adds the amounts (unconditionally) and updates the finalization status
    /// (only if the new supply is finalized). If the asset is not found, inserts the new supply.
    pub fn add_supply(&mut self, asset: AssetBase, new_supply: AssetSupply) -> Result<(), Error> {
        match self.assets.entry(asset) {
            hash_map::Entry::Occupied(entry) => {
                let supply = entry.into_mut();
                supply.amount = (supply.amount + new_supply.amount).ok_or(Error::ValueOverflow)?;
                supply.is_finalized |= new_supply.is_finalized;
                supply.reference_note = supply.reference_note.or(new_supply.reference_note);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(new_supply);
            }
        }

        Ok(())
    }

    /// Updates the set of finalized assets based on the supply information stored in
    /// the `SupplyInfo` instance.
    pub fn update_finalization_set(&self, finalization_set: &mut HashSet<AssetBase>) {
        finalization_set.extend(
            self.assets
                .iter()
                .filter_map(|(asset, supply)| supply.is_finalized.then_some(asset)),
        );
    }
}

impl Default for SupplyInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset(asset_desc: &[u8]) -> AssetBase {
        use crate::keys::{IssuanceAuthorizingKey, IssuanceValidatingKey};

        let isk = IssuanceAuthorizingKey::from_bytes([1u8; 32]).unwrap();

        AssetBase::derive(&IssuanceValidatingKey::from(&isk), asset_desc)
    }

    fn sum<T: IntoIterator<Item = &AssetSupply>>(supplies: T) -> Option<NoteValue> {
        supplies
            .into_iter()
            .map(|supply| supply.amount)
            .try_fold(NoteValue::from_raw(0), |sum, value| sum + value)
    }

    #[test]
    fn test_add_supply_valid() {
        let mut supply_info = SupplyInfo::new();

        let asset1 = create_test_asset(b"Asset 1");
        let asset2 = create_test_asset(b"Asset 2");

        let supply1 = AssetSupply::new(NoteValue::from_raw(20), false, None);
        let supply2 = AssetSupply::new(NoteValue::from_raw(30), true, None);
        let supply3 = AssetSupply::new(NoteValue::from_raw(10), false, None);
        let supply4 = AssetSupply::new(NoteValue::from_raw(10), true, None);
        let supply5 = AssetSupply::new(NoteValue::from_raw(50), false, None);

        assert_eq!(supply_info.assets.len(), 0);

        // Add supply1
        assert!(supply_info.add_supply(asset1, supply1).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(sum([&supply1]).unwrap(), false, None))
        );

        // Add supply2
        assert!(supply_info.add_supply(asset1, supply2).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(
                sum([&supply1, &supply2]).unwrap(),
                true,
                None
            ))
        );

        // Add supply3
        assert!(supply_info.add_supply(asset1, supply3).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(
                sum([&supply1, &supply2, &supply3]).unwrap(),
                true,
                None
            ))
        );

        // Add supply4
        assert!(supply_info.add_supply(asset1, supply4).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(
                sum([&supply1, &supply2, &supply3, &supply4]).unwrap(),
                true,
                None
            ))
        );

        // Add supply5
        assert!(supply_info.add_supply(asset2, supply5).is_ok());
        assert_eq!(supply_info.assets.len(), 2);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(
                sum([&supply1, &supply2, &supply3, &supply4]).unwrap(),
                true,
                None
            ))
        );
        assert_eq!(
            supply_info.assets.get(&asset2),
            Some(&AssetSupply::new(sum([&supply5]).unwrap(), false, None))
        );
    }

    #[test]
    fn test_update_finalization_set() {
        let mut supply_info = SupplyInfo::new();

        let asset1 = create_test_asset(b"Asset 1");
        let asset2 = create_test_asset(b"Asset 2");
        let asset3 = create_test_asset(b"Asset 3");

        let supply1 = AssetSupply::new(NoteValue::from_raw(10), false, None);
        let supply2 = AssetSupply::new(NoteValue::from_raw(20), true, None);
        let supply3 = AssetSupply::new(NoteValue::from_raw(40), false, None);
        let supply4 = AssetSupply::new(NoteValue::from_raw(50), true, None);

        assert!(supply_info.add_supply(asset1, supply1).is_ok());
        assert!(supply_info.add_supply(asset1, supply2).is_ok());
        assert!(supply_info.add_supply(asset2, supply3).is_ok());
        assert!(supply_info.add_supply(asset3, supply4).is_ok());

        let mut finalization_set = HashSet::new();

        supply_info.update_finalization_set(&mut finalization_set);

        assert_eq!(finalization_set.len(), 2);

        assert!(finalization_set.contains(&asset1));
        assert!(finalization_set.contains(&asset3));
    }
}
