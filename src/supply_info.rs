//! Structs and logic related to supply information management for assets.

use std::collections::{hash_map, HashMap, HashSet};

use crate::{issuance::Error, note::AssetBase, value::ValueSum};

/// Represents the amount of an asset and its finalization status.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AssetSupply {
    /// The amount of the asset.
    pub amount: ValueSum,
    /// Whether or not the asset is finalized.
    pub is_finalized: bool,
}

impl AssetSupply {
    /// Creates a new AssetSupply instance with the given amount and finalization status.
    pub fn new(amount: ValueSum, is_finalized: bool) -> Self {
        Self {
            amount,
            is_finalized,
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
    #[allow(clippy::new_without_default)]
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
                supply.amount =
                    (supply.amount + new_supply.amount).ok_or(Error::ValueSumOverflow)?;
                supply.is_finalized |= new_supply.is_finalized;
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(new_supply);
            }
        }

        Ok(())
    }

    /// Updates the set of finalized assets based on the supply information stored in
    /// the `SupplyInfo` instance.
    pub fn update_finalized_assets(&self, finalized_assets: &mut HashSet<AssetBase>) {
        finalized_assets.extend(
            self.assets
                .iter()
                .filter_map(|(asset, supply)| supply.is_finalized.then(|| asset)),
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

    fn create_random_asset(seed: u64) -> AssetBase {
        use {
            group::{Group, GroupEncoding},
            pasta_curves::pallas::Point,
            rand::{rngs::StdRng, SeedableRng},
        };

        AssetBase::from_bytes(&Point::random(StdRng::seed_from_u64(seed)).to_bytes()).unwrap()
    }

    #[test]
    fn test_add_supply_valid() {
        let mut supply_info = SupplyInfo::new();

        let asset1 = create_random_asset(1);
        let asset2 = create_random_asset(2);

        let supply1 = AssetSupply::new(ValueSum::from_raw(20), false);
        let supply2 = AssetSupply::new(ValueSum::from_raw(30), true);
        let supply3 = AssetSupply::new(ValueSum::from_raw(10), false);
        let supply4 = AssetSupply::new(ValueSum::from_raw(10), true);
        let supply5 = AssetSupply::new(ValueSum::from_raw(50), false);

        assert_eq!(supply_info.assets.len(), 0);

        // Add supply1
        assert!(supply_info.add_supply(asset1, supply1).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(ValueSum::from_raw(20), false))
        );

        // Add supply2
        assert!(supply_info.add_supply(asset1, supply2).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(ValueSum::from_raw(50), true))
        );

        // Add supply3
        assert!(supply_info.add_supply(asset1, supply3).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(ValueSum::from_raw(60), true))
        );

        // Add supply4
        assert!(supply_info.add_supply(asset1, supply4).is_ok());
        assert_eq!(supply_info.assets.len(), 1);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(ValueSum::from_raw(70), true))
        );

        // Add supply4
        assert!(supply_info.add_supply(asset2, supply5).is_ok());
        assert_eq!(supply_info.assets.len(), 2);
        assert_eq!(
            supply_info.assets.get(&asset1),
            Some(&AssetSupply::new(ValueSum::from_raw(70), true))
        );
        assert_eq!(
            supply_info.assets.get(&asset2),
            Some(&AssetSupply::new(ValueSum::from_raw(50), false))
        );
    }

    #[test]
    fn test_update_finalized_assets() {
        let mut supply_info = SupplyInfo::new();

        let asset1 = create_random_asset(1);
        let asset2 = create_random_asset(2);
        let asset3 = create_random_asset(3);

        assert!(supply_info
            .add_supply(asset1, AssetSupply::new(ValueSum::from_raw(10), false))
            .is_ok());
        assert!(supply_info
            .add_supply(asset1, AssetSupply::new(ValueSum::from_raw(20), true))
            .is_ok());

        assert!(supply_info
            .add_supply(asset2, AssetSupply::new(ValueSum::from_raw(40), false))
            .is_ok());

        assert!(supply_info
            .add_supply(asset3, AssetSupply::new(ValueSum::from_raw(50), true))
            .is_ok());

        let mut finalized_assets = HashSet::new();

        supply_info.update_finalized_assets(&mut finalized_assets);

        assert_eq!(finalized_assets.len(), 2);

        assert!(finalized_assets.contains(&asset1));
        assert!(finalized_assets.contains(&asset3));
    }
}
