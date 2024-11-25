//! Defines types and traits for the variations ("flavors") of the Orchard protocol (Vanilla and ZSA).

use crate::{bundle::OrchardHash, circuit::OrchardCircuit, note_encryption::OrchardDomainCommon};

/// Represents the "Vanilla" variation ("flavor") of the Orchard protocol.  
#[derive(Debug, Clone, Default)]
pub struct OrchardVanilla;

/// Represents the "ZSA" variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardZSA;

/// Represents the flavor of the Orchard protocol.
#[derive(Clone, Debug)]
pub enum Flavor {
    /// The "Vanilla" flavor of the Orchard protocol.
    OrchardVanillaFlavor,
    /// The "ZSA" flavor of the Orchard protocol.
    OrchardZSAFlavor,
}

/// A trait binding the common functionality between different Orchard protocol flavors.
pub trait OrchardFlavor: OrchardDomainCommon + OrchardCircuit + OrchardHash {
    /// Returns the flavor of the Orchard protocol.
    fn flavor() -> Flavor;
}

impl OrchardFlavor for OrchardVanilla {
    fn flavor() -> Flavor {
        Flavor::OrchardVanillaFlavor
    }
}
impl OrchardFlavor for OrchardZSA {
    fn flavor() -> Flavor {
        Flavor::OrchardZSAFlavor
    }
}
