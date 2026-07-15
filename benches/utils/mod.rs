use criterion::{measurement::Measurement, BenchmarkGroup, Criterion};

use orchard::{
    bundle::BundleVersion,
    flavor::{OrchardFlavor, OrchardVanilla, OrchardZSA},
};

pub(crate) trait OrchardFlavorBench: OrchardFlavor {
    const DEFAULT_BUNDLE_VERSION: BundleVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M>;
}

impl OrchardFlavorBench for OrchardVanilla {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::orchard_v2();

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardVanilla] {}", group_name))
    }
}

impl OrchardFlavorBench for OrchardZSA {
    const DEFAULT_BUNDLE_VERSION: BundleVersion = BundleVersion::zsa_v3();

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardZSA] {}", group_name))
    }
}
