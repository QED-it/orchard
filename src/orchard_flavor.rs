//! Defines types and traits for the variations ("flavors") of the Orchard protocol (Vanilla and ZSA).
// FIXME: The circuit and note_encryption modules refer to this orchard_flavor module as well - are such circular references okay?
use crate::{circuit::OrchardCircuit, note_encryption::OrchardDomain};

/// Represents the standard ("Vanilla") variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardVanilla;

/// Represents a ZSA variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardZSA;

/// A trait binding the common functionality between different Orchard protocol variations
/// ("flavors").
pub trait OrchardFlavor: OrchardDomain + OrchardCircuit {}

impl OrchardFlavor for OrchardVanilla {}
impl OrchardFlavor for OrchardZSA {}
