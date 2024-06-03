//! Defines types and traits for the variations ("flavors") of the Orchard protocol (Vanilla and ZSA).

/// Represents the standard ("Vanilla") variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardVanilla;

/// Represents a ZSA variation ("flavor") of the Orchard protocol.
#[derive(Debug, Clone, Default)]
pub struct OrchardZSA;
