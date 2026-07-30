use criterion::{measurement::Measurement, BenchmarkGroup, Criterion};

use orchard::note_encryption::IronwoodVersion;
use orchard::{
    bundle::BundleVersion,
    note_encryption::{DomainVersion, OrchardVersion, ZSAVersion},
};

/// Marker type selecting the Vanilla flavor for the flavor-parameterized benchmarks.
pub(crate) struct Orchard;
/// Marker type selecting the Ironwood flavor for the flavor-parameterized benchmarks.
pub(crate) struct Ironwood;
/// Marker type selecting the ZSA flavor for the flavor-parameterized benchmarks.
pub(crate) struct Zsa;

pub(crate) trait OrchardFlavorBench {
    const DEFAULT_BUNDLE_VERSION: BundleVersion;
    type DomainVersion: DomainVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M>;
}

impl OrchardFlavorBench for Orchard {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::orchard_v3();
    type DomainVersion = OrchardVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardVanilla] {}", group_name))
    }
}

impl OrchardFlavorBench for Ironwood {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::ironwood_v3();
    type DomainVersion = IronwoodVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardVanilla] {}", group_name))
    }
}

impl OrchardFlavorBench for Zsa {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::zsa();
    type DomainVersion = ZSAVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardZSA] {}", group_name))
    }
}
