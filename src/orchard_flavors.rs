//! Defines types and traits for the variations ("flavors") of the Orchard protocol (Vanilla and ZSA).

use crate::{bundle::OrchardHash, circuit::OrchardCircuit, note_encryption::OrchardDomainCommon};

/// Represents the standard ("Vanilla") variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardVanilla;

/// Represents a ZSA variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardZSA;

/// A trait binding the common functionality between different Orchard protocol variations
/// ("flavors").
pub trait OrchardFlavor: OrchardDomainCommon + OrchardCircuit + OrchardHash {}

impl OrchardFlavor for OrchardVanilla {}
impl OrchardFlavor for OrchardZSA {}
