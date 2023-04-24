//! Structs and logic related to supply information management for assets.

use std::collections::{hash_map, HashMap};

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
#[derive(Debug, Clone, Default)]
pub struct SupplyInfo {
    /// A map of asset bases to their respective supply information.
    pub assets: HashMap<AssetBase, AssetSupply>,
}

impl SupplyInfo {
    /// Inserts or updates an asset's supply information in the supply info map.
    /// If the asset exists, adds the amounts (unconditionally) and updates the finalization status
    /// (only if the new supply is finalized). If the asset is not found, inserts the new supply.
    pub fn add_supply(&mut self, asset: AssetBase, new_supply: AssetSupply) -> Result<(), Error> {
        match self.assets.entry(asset) {
            hash_map::Entry::Occupied(mut entry) => {
                let supply = entry.get_mut();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::ValueSum;

    #[test]
    fn test_add_supply_valid() {
        let mut supply_info = SupplyInfo::default();

        let asset = AssetBase::from_bytes(&[0u8; 32]).unwrap();

        let supply1 = AssetSupply::new(ValueSum::from_raw(20), false);
        let supply2 = AssetSupply::new(ValueSum::from_raw(30), true);
        let supply3 = AssetSupply::new(ValueSum::from_raw(10), false);
        let supply4 = AssetSupply::new(ValueSum::from_raw(10), true);

        assert!(supply_info.add_supply(asset, supply1).is_ok());

        assert_eq!(
            supply_info.assets.get(&asset),
            Some(&AssetSupply::new(ValueSum::from_raw(20), false))
        );

        assert!(supply_info.add_supply(asset, supply2).is_ok());

        assert_eq!(
            supply_info.assets.get(&asset),
            Some(&AssetSupply::new(ValueSum::from_raw(50), true))
        );

        assert!(supply_info.add_supply(asset, supply3).is_ok());

        assert_eq!(
            supply_info.assets.get(&asset),
            Some(&AssetSupply::new(ValueSum::from_raw(60), true))
        );

        assert!(supply_info.add_supply(asset, supply4).is_ok());

        assert_eq!(
            supply_info.assets.get(&asset),
            Some(&AssetSupply::new(ValueSum::from_raw(70), true))
        );
    }
}
