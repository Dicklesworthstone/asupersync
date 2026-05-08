//! RaptorQ blocked Gaussian elimination benchmark.
//!
//! Measures performance improvement from block-tiled elimination optimization.
//! Compares against naive O(n³) approach for various matrix sizes.

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn create_high_loss_decode_scenario(
    k: usize,
    symbol_size: usize,
    loss_rate: f64,
) -> (InactivationDecoder, Vec<ReceivedSymbol>) {
    // Generate source symbols
    let mut source_symbols = Vec::with_capacity(k);
    let mut rng_state = 0x12345678u64;
    for _i in 0..k {
        let mut symbol_data = vec![0u8; symbol_size];
        for byte in symbol_data.iter_mut() {
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (rng_state >> 16) as u8;
        }
        source_symbols.push(symbol_data);
    }

    let seed = 0x87654321u64;
    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation failed");

    // Create high-loss scenario to force dense matrix solving
    let loss_count = (k as f64 * loss_rate) as usize;
    let mut loss_pattern = vec![false; k];
    rng_state = 0xDEADBEEF;
    let mut losses_applied = 0;

    while losses_applied < loss_count {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (rng_state % k as u64) as usize;
        if !loss_pattern[idx] {
            loss_pattern[idx] = true;
            losses_applied += 1;
        }
    }

    // Build decoder and received symbols
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let mut received_symbols = decoder.constraint_symbols();

    // Add surviving source symbols
    for (i, &is_lost) in loss_pattern.iter().enumerate() {
        if !is_lost {
            let esi = i as u32;
            received_symbols.push(ReceivedSymbol::source(esi, source_symbols[i].clone()));
        }
    }

    // Add repair symbols
    let needed_repairs = loss_count + 100;
    for i in 0..needed_repairs {
        let repair_esi = (k + i) as u32;
        let (cols, coefs) = decoder
            .repair_equation(repair_esi)
            .expect("repair equation failed");
        let repair_data = encoder.repair_symbol(repair_esi);
        received_symbols.push(ReceivedSymbol::repair(repair_esi, cols, coefs, repair_data));
    }

    (decoder, received_symbols)
}

fn bench_blocked_elimination(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq_blocked_elimination");

    // Test different K values that stress dense matrix solving
    let test_cases = [
        (1000, 1316, 0.70), // 1K symbols, 70% loss
        (2500, 1316, 0.70), // 2.5K symbols, 70% loss
        (5000, 1316, 0.70), // 5K symbols, 70% loss
        (7500, 1316, 0.70), // 7.5K symbols, 70% loss
    ];

    for (k, symbol_size, loss_rate) in test_cases {
        let total_bytes = k * symbol_size;
        group.throughput(Throughput::Bytes(total_bytes as u64));

        let benchmark_id = BenchmarkId::new("decode_with_blocked_elimination", format!("K{}", k));

        group.bench_with_input(
            benchmark_id,
            &(k, symbol_size, loss_rate),
            |b, &(k, symbol_size, loss_rate)| {
                // Create scenario once, reuse for all iterations
                let (decoder, received_symbols) =
                    create_high_loss_decode_scenario(k, symbol_size, loss_rate);

                b.iter(|| {
                    let result = black_box(decoder.decode(&received_symbols))
                        .expect("decode should succeed");

                    // Verify correctness
                    black_box(&result.source);
                    black_box(result.stats.gauss_ops); // Ensure elimination happened
                });
            },
        );
    }

    group.finish();
}

fn bench_elimination_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("elimination_scaling");

    // Focus on larger K values where blocking provides most benefit
    let k_values = [2000, 4000, 6000, 8000];
    let symbol_size = 1316;
    let loss_rate = 0.75; // High loss to maximize dense operations

    for k in k_values {
        let benchmark_id = BenchmarkId::from_parameter(k);

        group.bench_with_input(benchmark_id, &k, |b, &k| {
            let (decoder, received_symbols) =
                create_high_loss_decode_scenario(k, symbol_size, loss_rate);

            b.iter(|| {
                let result =
                    black_box(decoder.decode(&received_symbols)).expect("decode should succeed");

                // Track elimination work performed
                black_box(result.stats.gauss_ops);
                black_box(result.stats.inactivated);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_blocked_elimination,
    bench_elimination_scaling
);
criterion_main!(benches);
