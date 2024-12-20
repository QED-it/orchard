use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use orchard::{
    builder::{Builder, BundleType},
    circuit::ProvingKey,
    domain::{CompactAction, OrchardDomain},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::AssetBase,
    orchard_flavor::{OrchardVanilla, OrchardZSA},
    value::NoteValue,
    Anchor, Bundle,
};
use rand::rngs::OsRng;
use zcash_note_encryption_zsa::{batch, try_compact_note_decryption, try_note_decryption};

#[cfg(unix)]
use pprof::criterion::{Output, PProfProfiler};

mod utils;

use utils::OrchardFlavorBench;

fn bench_note_decryption<FL: OrchardFlavorBench>(c: &mut Criterion) {
    let rng = OsRng;
    let pk = ProvingKey::build::<FL>();

    let fvk = FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap());
    let valid_ivk = fvk.to_ivk(Scope::External);
    let recipient = valid_ivk.address_at(0u32);
    let valid_ivk = PreparedIncomingViewingKey::new(&valid_ivk);

    // Compact actions don't have the full AEAD ciphertext, so ZIP 307 trial-decryption
    // relies on an invalid ivk resulting in random noise for which the note commitment
    // is invalid. However, in practice we still get early rejection:
    // - The version byte will be invalid in 255/256 instances.
    // - If the version byte is valid, one of either the note commitment check or the esk
    //   check will be invalid, saving us at least one scalar mul.
    //
    // Our fixed (action, invalid ivk) tuple will always fall into a specific rejection
    // case. In order to reflect the real behaviour in the benchmarks, we trial-decrypt
    // with 10240 invalid ivks (each of which will result in a different uniformly-random
    // plaintext); this is equivalent to trial-decrypting 10240 different actions with the
    // same ivk, but is faster to set up.
    let invalid_ivks: Vec<_> = (0u32..10240)
        .map(|i| {
            let mut sk = [0; 32];
            sk[..4].copy_from_slice(&i.to_le_bytes());
            let fvk = FullViewingKey::from(&SpendingKey::from_bytes(sk).unwrap());
            PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External))
        })
        .collect();

    let bundle = {
        let mut builder = Builder::new(
            BundleType::DEFAULT_VANILLA,
            Anchor::from_bytes([0; 32]).unwrap(),
        );
        // The builder pads to two actions, and shuffles their order. Add two recipients
        // so the first action is always decryptable.
        builder
            .add_output(
                None,
                recipient,
                NoteValue::from_raw(10),
                AssetBase::native(),
                None,
            )
            .unwrap();
        builder
            .add_output(
                None,
                recipient,
                NoteValue::from_raw(10),
                AssetBase::native(),
                None,
            )
            .unwrap();
        let bundle: Bundle<_, i64, FL> = builder.build(rng).unwrap().0;
        bundle
            .create_proof(&pk, rng)
            .unwrap()
            .apply_signatures(rng, [0; 32], &[])
            .unwrap()
    };
    let action = bundle.actions().first();

    let domain = OrchardDomain::for_action(action);

    let compact = {
        let mut group = FL::benchmark_group(c, "note-decryption");
        group.throughput(Throughput::Elements(1));

        group.bench_function("valid", |b| {
            b.iter(|| try_note_decryption(&domain, &valid_ivk, action).unwrap())
        });

        // Non-compact actions will always early-reject at the same point: AEAD decryption.
        group.bench_function("invalid", |b| {
            b.iter(|| try_note_decryption(&domain, &invalid_ivks[0], action))
        });

        let compact = CompactAction::from(action);

        group.bench_function("compact-valid", |b| {
            b.iter(|| try_compact_note_decryption(&domain, &valid_ivk, &compact).unwrap())
        });

        compact
    };

    {
        let mut group = FL::benchmark_group(c, "compact-note-decryption");
        group.throughput(Throughput::Elements(invalid_ivks.len() as u64));
        group.bench_function("invalid", |b| {
            b.iter(|| {
                for ivk in &invalid_ivks {
                    try_compact_note_decryption(&domain, ivk, &compact);
                }
            })
        });
    }

    {
        // Benchmark with 2 IVKs to emulate a wallet with two pools of funds.
        let ivks = 2;
        let valid_ivks = vec![valid_ivk; ivks];
        let actions: Vec<_> = (0..100)
            .map(|_| (OrchardDomain::for_action(action), action.clone()))
            .collect();
        let compact: Vec<_> = (0..100)
            .map(|_| {
                (
                    OrchardDomain::for_action(action),
                    CompactAction::from(action),
                )
            })
            .collect();

        let mut group = FL::benchmark_group(c, "batch-note-decryption");

        for size in [10, 50, 100] {
            group.throughput(Throughput::Elements((ivks * size) as u64));

            group.bench_function(BenchmarkId::new("valid", size), |b| {
                b.iter(|| batch::try_note_decryption(&valid_ivks, &actions[..size]))
            });

            group.bench_function(BenchmarkId::new("invalid", size), |b| {
                b.iter(|| batch::try_note_decryption(&invalid_ivks[..ivks], &actions[..size]))
            });

            group.bench_function(BenchmarkId::new("compact-valid", size), |b| {
                b.iter(|| batch::try_compact_note_decryption(&valid_ivks, &compact[..size]))
            });

            group.bench_function(BenchmarkId::new("compact-invalid", size), |b| {
                b.iter(|| {
                    batch::try_compact_note_decryption(&invalid_ivks[..ivks], &compact[..size])
                })
            });
        }
    }
}

#[cfg(unix)]
fn create_config() -> Criterion {
    Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
}

#[cfg(windows)]
fn create_config() -> Criterion {
    Criterion::default()
}

criterion_group! {
    name = benches_vanilla;
    config = create_config();
    targets = bench_note_decryption::<OrchardVanilla>
}

criterion_group! {
    name = benches_zsa;
    config = create_config();
    targets = bench_note_decryption::<OrchardZSA>
}

criterion_main!(benches_vanilla, benches_zsa);
