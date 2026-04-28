use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use asupersync::raptorq::systematic::SystematicEncoder;

/// Benchmark FEC-Payload-ID emission path in RaptorQ encoder.
///
/// Measures the hot loop in emit_repair() which calls repair_symbol_into_with_degree()
/// for each ESI (Encoding Symbol Identifier).
fn bench_fec_payload_id_emission(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_payload_id_emission");

    // Test parameters: varying source block sizes
    let source_sizes = [64, 256, 1024]; // K values
    let symbol_size = 1024; // 1KB symbols
    let repair_count = 10; // Number of repair symbols to generate

    for k in source_sizes {
        // Create source symbols: K symbols each of symbol_size bytes
        let source_symbols: Vec<Vec<u8>> = (0..k)
            .map(|i| vec![42u8 + (i as u8); symbol_size])
            .collect();

        // Create encoder once outside timing loop
        let mut encoder = SystematicEncoder::new(&source_symbols, symbol_size, 42).unwrap();

        group.bench_with_input(
            BenchmarkId::new("emit_repair_hot_path", k),
            &k,
            |b, _| {
                b.iter(|| {
                    // Reset state for clean measurement
                    let mut enc = SystematicEncoder::new(&source_symbols, symbol_size, 42).unwrap();

                    // This is the hot path: emit_repair() calls repair_symbol_into_with_degree()
                    // in a loop for each repair ESI
                    let symbols = enc.emit_repair(black_box(repair_count));
                    black_box(symbols);
                });
            }
        );

        // Also benchmark single repair symbol generation (the inner hot loop)
        group.bench_with_input(
            BenchmarkId::new("single_repair_symbol", k),
            &k,
            |b, _| {
                b.iter(|| {
                    let esi = k as u32; // First repair ESI
                    let symbol = encoder.repair_symbol(black_box(esi));
                    black_box(symbol);
                });
            }
        );
    }

    group.finish();
}

criterion_group!(benches, bench_fec_payload_id_emission);
criterion_main!(benches);