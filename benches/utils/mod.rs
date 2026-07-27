use criterion::{measurement::Measurement, BenchmarkGroup, Criterion};

use orchard::{
    bundle::BundleVersion,
    note_encryption::{DomainVersion, OrchardVersion, ZSAVersion},
};

/// Marker type selecting the Vanilla flavor for the flavor-parameterized benchmarks.
pub(crate) struct OrchardVanilla;
/// Marker type selecting the ZSA flavor for the flavor-parameterized benchmarks.
pub(crate) struct OrchardZSA;

pub(crate) trait OrchardFlavorBench {
    const DEFAULT_BUNDLE_VERSION: BundleVersion;
    type DomainVersion: DomainVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M>;
}

impl OrchardFlavorBench for OrchardVanilla {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::orchard_v2();
    type DomainVersion = OrchardVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardVanilla] {}", group_name))
    }
}

impl OrchardFlavorBench for OrchardZSA {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::zsa();
    type DomainVersion = ZSAVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardZSA] {}", group_name))
    }
}
