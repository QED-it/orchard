use super::{Action, Bundle, Zip32Derivation};
use crate::domain::OrchardDomainCommon;
use crate::orchard_flavor::OrchardFlavor;
use alloc::string::String;
use alloc::vec::Vec;

impl<FL: OrchardFlavor> Bundle<FL> {
    /// Updates the bundle with information provided in the given closure.
    pub fn update_with<F>(&mut self, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(Updater<'_, FL>) -> Result<(), UpdaterError>,
    {
        f(Updater(self))
    }
}

/// An updater for an Orchard PCZT bundle.
#[derive(Debug)]
pub struct Updater<'a, FL: OrchardFlavor>(&'a mut Bundle<FL>);

impl<FL: OrchardFlavor> Updater<'_, FL> {
    /// Provides read access to the bundle being updated.
    pub fn bundle(&self) -> &Bundle<FL> {
        self.0
    }

    /// Updates the action at the given index with information provided in the given
    /// closure.
    pub fn update_action_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(ActionUpdater<'_, FL>) -> Result<(), UpdaterError>,
    {
        f(ActionUpdater(
            self.0
                .actions
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }
}

/// An updater for an Orchard PCZT action.
#[derive(Debug)]
pub struct ActionUpdater<'a, D: OrchardDomainCommon>(&'a mut Action<D>);

impl<D: OrchardDomainCommon> ActionUpdater<'_, D> {
    /// Sets the ZIP 32 derivation path for the spent note's signing key.
    pub fn set_spend_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.spend.zip32_derivation = Some(derivation);
    }

    /// Stores the given spend-specific proprietary value at the given key.
    pub fn set_spend_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.spend.proprietary.insert(key, value);
    }

    /// Sets the ZIP 32 derivation path for the new note's signing key.
    pub fn set_output_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.output.zip32_derivation = Some(derivation);
    }

    /// Sets the user-facing address that the new note is being sent to.
    pub fn set_output_user_address(&mut self, user_address: String) {
        self.0.output.user_address = Some(user_address);
    }

    /// Stores the given output-specific proprietary value at the given key.
    pub fn set_output_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.output.proprietary.insert(key, value);
    }
}

/// Errors that can occur while updating an Orchard bundle in a PCZT.
#[derive(Debug)]
pub enum UpdaterError {
    /// An out-of-bounds index was provided when looking up an action.
    InvalidIndex,
}
