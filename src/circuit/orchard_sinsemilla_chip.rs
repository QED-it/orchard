//! Defines the `OrchardSinsemillaChip` trait to abstract over `SinsemillaChip` and `SinsemillaChipOptimized` types.
//! Used to generalize the `commit_ivk` function.

use pasta_curves::pallas;

use halo2_proofs::circuit::Chip;

use halo2_gadgets::{
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaChipOptimized, SinsemillaConfig},
        primitives as sinsemilla, SinsemillaInstructions,
    },
    utilities::lookup_range_check::{
        // FIXME: rename PallasLookupConfigOptimized to PallasLookupRCConfigOptimized in halo2 (to
        // be consistent with PallasLookupRCConfig).
        PallasLookupConfigOptimized,
        PallasLookupRC,
        PallasLookupRCConfig,
    },
};

use crate::constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains};

type BaseSinsemillaChip =
    SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>;

pub(super) trait OrchardSinsemillaChip<Lookup: PallasLookupRC>:
    SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
        CellValue = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::CellValue,
        Message = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::Message,
        MessagePiece = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::MessagePiece,
        RunningSum = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::RunningSum,
        X = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::X,
        NonIdentityPoint = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::NonIdentityPoint,
        FixedPoints = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::FixedPoints,
        HashDomains = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::HashDomains,
        CommitDomains = <BaseSinsemillaChip as SinsemillaInstructions<
            pallas::Affine,
            { sinsemilla::K },
            { sinsemilla::C },
        >>::CommitDomains,
    > + Chip<
        pallas::Base,
        Config = SinsemillaConfig<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
            Lookup,
        >,
    > + Clone
    + std::fmt::Debug
    + Eq
{
}

impl OrchardSinsemillaChip<PallasLookupRCConfig> for BaseSinsemillaChip {}

impl OrchardSinsemillaChip<PallasLookupConfigOptimized>
    for SinsemillaChipOptimized<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>
{
}
