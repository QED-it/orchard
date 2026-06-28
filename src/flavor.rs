//! Defines types and traits for the variations ("flavors") of the Orchard protocol (Vanilla and ZSA).

#[cfg(feature = "circuit")]
use crate::{circuit::OrchardCircuitVersion, primitives::OrchardPrimitives};

/// Represents the "Vanilla" variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrchardVanilla;

/// Represents the "ZSA" variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrchardZSA;

/// A trait binding the common functionality between different Orchard protocol flavors.
#[cfg(feature = "circuit")]
pub trait OrchardFlavor: OrchardPrimitives {
    /// Returns the [`OrchardCircuitVersion`] corresponding to this flavor.
    fn circuit_version() -> OrchardCircuitVersion;
}

#[cfg(feature = "circuit")]
impl OrchardFlavor for OrchardVanilla {
    fn circuit_version() -> OrchardCircuitVersion {
        OrchardCircuitVersion::FixedPostNu6_2
    }
}

#[cfg(feature = "circuit")]
impl OrchardFlavor for OrchardZSA {
    fn circuit_version() -> OrchardCircuitVersion {
        OrchardCircuitVersion::Zsa
    }
}
