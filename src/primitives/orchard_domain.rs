//! Orchard-specific note encryption domain.

use crate::{
    action::Action,
    flavor::OrchardVanilla,
    note::{NoteVersion, Rho},
    primitives::compact_action::CompactAction,
    primitives::orchard_primitives::OrchardPrimitives,
};

mod sealed {
    /// Marker trait that prevents external `DomainVersion` implementations.
    pub trait Sealed {}
}

/// A note plaintext version policy for a note encryption domain.
///
/// The policy selects which note plaintext version is expected during parsing
/// and decryption; the flavor (`Pr`) interprets it (see
/// [`OrchardPrimitives::parse_note_version`]). Encryption uses the version
/// recorded by the note.
pub(crate) trait DomainPolicy: core::fmt::Debug + Clone {
    /// The note plaintext version this domain expects.
    fn expected_note_version(&self) -> NoteVersion;
}

/// A sealed marker trait for note encryption domains with a fixed note plaintext version.
///
/// This trait is sealed so that only this crate can define supported note encryption
/// domains.
pub trait DomainVersion: sealed::Sealed + Clone + core::fmt::Debug + Default {
    /// The note plaintext version accepted by this domain during parsing and decryption.
    const NOTE_VERSION: NoteVersion;
}

impl<V: DomainVersion> DomainPolicy for V {
    fn expected_note_version(&self) -> NoteVersion {
        V::NOTE_VERSION
    }
}

/// Marker type for Orchard note encryption domains.
#[derive(Clone, Default, Debug)]
pub struct OrchardVersion;

impl sealed::Sealed for OrchardVersion {}

impl DomainVersion for OrchardVersion {
    const NOTE_VERSION: NoteVersion = NoteVersion::V2;
}

/// Marker type for Ironwood note encryption domains.
#[derive(Clone, Default, Debug)]
pub struct IronwoodVersion;

impl sealed::Sealed for IronwoodVersion {}

impl DomainVersion for IronwoodVersion {
    const NOTE_VERSION: NoteVersion = NoteVersion::V3;
}

/// Runtime note plaintext version policy, used by public bundle helpers that
/// are given the bundle's [`NoteVersion`].
#[derive(Clone, Debug)]
pub(crate) struct BundleDomainPolicy {
    note_version: NoteVersion,
}

impl DomainPolicy for BundleDomainPolicy {
    fn expected_note_version(&self) -> NoteVersion {
        self.note_version
    }
}

/// Orchard-specific note encryption logic.
///
/// The policy type `P` selects which note plaintext version is accepted during
/// parsing and decryption (see [`DomainVersion`]). Encryption uses the version
/// recorded by the note.
#[derive(Debug, Clone)]
pub struct OrchardDomain<Pr: OrchardPrimitives, P = OrchardVersion> {
    /// A parameter needed to generate the nullifier.
    pub rho: Rho,
    policy: P,
    phantom: core::marker::PhantomData<Pr>,
}

/// Ironwood-specific note encryption logic.
///
/// This domain is otherwise identical to `OrchardDomain<OrchardVanilla>`, but
/// accepts only [`NoteVersion::V3`] note plaintexts, which use lead byte `0x03`.
pub type IronwoodDomain = OrchardDomain<OrchardVanilla, IronwoodVersion>;

/// Note encryption logic restricted to a single note plaintext version.
///
/// This domain is used by public bundle helpers that are given the bundle's
/// [`NoteVersion`]. Trial decryption still happens once; after decryption
/// succeeds, the revealed note plaintext lead byte selects the note version, which is
/// enforced to match the expected one.
pub(crate) type BundleDomain<Pr> = OrchardDomain<Pr, BundleDomainPolicy>;

impl<Pr: OrchardPrimitives, P> memuse::DynamicUsage for OrchardDomain<Pr, P> {
    fn dynamic_usage(&self) -> usize {
        self.rho.dynamic_usage()
    }
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.rho.dynamic_usage_bounds()
    }
}

impl<Pr: OrchardPrimitives, P> OrchardDomain<Pr, P> {
    /// Returns the policy of this domain.
    pub(crate) fn policy(&self) -> &P {
        &self.policy
    }
}

impl<Pr: OrchardPrimitives, V: DomainVersion> OrchardDomain<Pr, V> {
    /// Constructs a domain from a rho.
    pub(crate) fn from_rho(rho: Rho) -> Self {
        Self {
            rho,
            policy: V::default(),
            phantom: Default::default(),
        }
    }

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<T>(act: &Action<T, Pr>) -> Self {
        Self::from_rho(act.rho())
    }

    /// Constructs a domain that can be used to trial-decrypt a PCZT action's output note.
    pub fn for_pczt_action(act: &crate::pczt::Action) -> Self {
        Self::from_rho(Rho::from_nf_old(act.spend().nullifier))
    }

    /// Constructs a domain that can be used to trial-decrypt this compact action's output note.
    pub fn for_compact_action(act: &CompactAction<Pr>) -> Self {
        Self::from_rho(act.rho())
    }

    /// Constructs a domain from a rho.
    #[cfg(test)]
    pub(crate) fn for_rho(rho: Rho) -> Self {
        Self::from_rho(rho)
    }
}

impl<Pr: OrchardPrimitives> BundleDomain<Pr> {
    /// Constructs a domain that can be used to trial-decrypt this action's
    /// output note as a note of `note_version`.
    pub(crate) fn for_action<T>(act: &Action<T, Pr>, note_version: NoteVersion) -> Self {
        Self {
            rho: act.rho(),
            policy: BundleDomainPolicy { note_version },
            phantom: Default::default(),
        }
    }
}
