//! This module offers a set of utilities for adapting complex, generic
//! authorization-related types into a simplified, enumerable form. This adaptation facilitates
//! the external usage of these types, making it easier for consumers of the library to handle
//! various authorization states without delving into the underlying generic complexities.

use crate::{
    builder::{InProgress, Unauthorized, UnauthorizedBundle, Unproven},
    bundle::Bundle,
    circuit::OrchardCircuit,
    note_encryption::OrchardDomain,
    orchard_flavor::{OrchardVanilla, OrchardZSA},
};

/// `UnprovenEnum` serves as an adapter for converting between heavily generic
/// authorization-related types within the crate and a simplified, enumerable representation.
/// This enum is designed for use in external crates, where the complexity of the generic types
/// might not be necessary or desirable.
#[derive(Debug)]
pub enum UnprovenEnum {
    /// Wraps Unproven<OrchardVanilla>
    OrchardVanilla(Unproven<OrchardVanilla>),
    /// Wraps Unproven<OrchardZSA>
    OrchardZSA(Unproven<OrchardZSA>),
}

impl From<Unproven<OrchardVanilla>> for UnprovenEnum {
    fn from(unproven: Unproven<OrchardVanilla>) -> Self {
        UnprovenEnum::OrchardVanilla(unproven)
    }
}

impl From<Unproven<OrchardZSA>> for UnprovenEnum {
    fn from(unproven: Unproven<OrchardZSA>) -> Self {
        UnprovenEnum::OrchardZSA(unproven)
    }
}

/// Represents an unauthorized bundle that incorporates an enum to simplify the handling of
/// different authorization types. This structure is part of a system designed to abstract away
/// the complexity of handling various states of authorization in a generic and type-safe manner,
/// making it easier for external crates to work with the library's authorization mechanisms.
pub type UnauthorizedBundleWithEnum<V, D> = Bundle<InProgress<UnprovenEnum, Unauthorized>, V, D>;

impl<V, D: OrchardDomain + OrchardCircuit> From<UnauthorizedBundle<V, D>>
    for UnauthorizedBundleWithEnum<V, D>
where
    UnprovenEnum: From<Unproven<D>>,
{
    fn from(bundle: UnauthorizedBundle<V, D>) -> Self {
        Self {
            actions: bundle.actions,
            flags: bundle.flags,
            value_balance: bundle.value_balance,
            burn: bundle.burn,
            anchor: bundle.anchor,
            authorization: InProgress {
                proof: bundle.authorization.proof.into(),
                sigs: bundle.authorization.sigs,
            },
        }
    }
}
