use criterion::{measurement::Measurement, BenchmarkGroup, Criterion};

use orchard::{
    builder::BundleType,
    circuit::OrchardCircuitVersion,
    flavor::{OrchardFlavor, OrchardVanilla, OrchardZSA},
};

pub(crate) trait OrchardFlavorBench: OrchardFlavor {
    const DEFAULT_BUNDLE_TYPE: BundleType;

    fn circuit_version() -> OrchardCircuitVersion;

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M>;
}

impl OrchardFlavorBench for OrchardVanilla {
    const DEFAULT_BUNDLE_TYPE: BundleType = BundleType::DEFAULT;

    fn circuit_version() -> OrchardCircuitVersion {
        OrchardCircuitVersion::FixedPostNu6_2
    }

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardVanilla] {}", group_name))
    }
}

impl OrchardFlavorBench for OrchardZSA {
    const DEFAULT_BUNDLE_TYPE: BundleType = BundleType::DEFAULT_ZSA;

    fn circuit_version() -> OrchardCircuitVersion {
        OrchardCircuitVersion::Zsa
    }

    fn benchmark_group<'a, M: Measurement>(
        c: &'a mut Criterion<M>,
        group_name: &str,
    ) -> BenchmarkGroup<'a, M> {
        c.benchmark_group(format!("[OrchardZSA] {}", group_name))
    }
}
