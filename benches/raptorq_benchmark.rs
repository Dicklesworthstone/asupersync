//! RaptorQ encode/decode performance benchmarks.
//!
//! This benchmark suite establishes baselines and profiles hot paths for:
//! - GF(256) bulk operations (addmul_slice, mul_slice, add_slice)
//! - Encoder/decoder roundtrip performance
//! - Gaussian elimination phases
//!
//! Follows the optimization loop: baseline → profile → single lever → golden outputs.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{gf256_add_slice, gf256_addmul_slice, gf256_mul_slice, Gf256};
use asupersync::raptorq::linalg::{row_scale_add, row_xor, DenseRow, GaussianSolver};
use asupersync::raptorq::systematic::SystematicEncoder;

// ============================================================================
// GF(256) primitive benchmarks
// ============================================================================

fn bench_gf256_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_primitives");

    // Test various symbol sizes (typical RaptorQ range)
    for &size in &[64, 256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        let src: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let c_val = Gf256::new(7);

        // Benchmark gf256_add_slice (pure XOR)
        group.bench_with_input(BenchmarkId::new("add_slice", size), &size, |b, _| {
            let mut dst = vec![0u8; size];
            b.iter(|| {
                gf256_add_slice(black_box(&mut dst), black_box(&src));
            });
        });

        // Benchmark gf256_mul_slice (scalar multiply)
        group.bench_with_input(BenchmarkId::new("mul_slice", size), &size, |b, _| {
            let mut dst: Vec<u8> = src.clone();
            b.iter(|| {
                gf256_mul_slice(black_box(&mut dst), black_box(c_val));
            });
        });

        // Benchmark gf256_addmul_slice (THE critical hot path)
        group.bench_with_input(BenchmarkId::new("addmul_slice", size), &size, |b, _| {
            let mut dst = vec![0u8; size];
            b.iter(|| {
                gf256_addmul_slice(black_box(&mut dst), black_box(&src), black_box(c_val));
            });
        });
    }

    group.finish();
}

// ============================================================================
// Linear algebra benchmarks
// ============================================================================

fn bench_linalg_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("linalg_operations");

    for &symbol_size in &[256, 1024, 4096] {
        group.throughput(Throughput::Bytes(symbol_size as u64));

        let src: Vec<u8> = (0..symbol_size).map(|i| (i % 256) as u8).collect();
        let c_val = Gf256::new(13);

        // Benchmark row_xor
        group.bench_with_input(
            BenchmarkId::new("row_xor", symbol_size),
            &symbol_size,
            |b, _| {
                let mut dst = vec![0u8; symbol_size];
                b.iter(|| {
                    row_xor(black_box(&mut dst), black_box(&src));
                });
            },
        );

        // Benchmark row_scale_add
        group.bench_with_input(
            BenchmarkId::new("row_scale_add", symbol_size),
            &symbol_size,
            |b, _| {
                let mut dst = vec![0u8; symbol_size];
                b.iter(|| {
                    row_scale_add(black_box(&mut dst), black_box(&src), black_box(c_val));
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Gaussian elimination benchmarks
// ============================================================================

fn bench_gaussian_elimination(c: &mut Criterion) {
    let mut group = c.benchmark_group("gaussian_elimination");

    // Test various matrix sizes
    for &n in &[8, 16, 32, 64] {
        // Build a solvable system with random-ish coefficients
        let rhs_size = 256usize;
        let seed = 42u64;

        group.bench_with_input(BenchmarkId::new("solve_basic", n), &n, |b, &n| {
            b.iter(|| {
                let mut solver = GaussianSolver::new(n, n);

                // Fill with deterministic pseudo-random data
                for row in 0..n {
                    let mut coeffs = vec![0u8; n];
                    for (col, coeff) in coeffs.iter_mut().enumerate() {
                        *coeff = ((row * 37 + col * 13 + seed as usize) % 256) as u8;
                    }
                    // Ensure diagonal dominance for solvability
                    coeffs[row] = coeffs[row].saturating_add(128);

                    let rhs_data: Vec<u8> = (0..rhs_size)
                        .map(|i| ((row * 7 + i * 11) % 256) as u8)
                        .collect();
                    solver.set_row(row, &coeffs, DenseRow::new(rhs_data));
                }

                let result = solver.solve();
                black_box(result)
            });
        });

        group.bench_with_input(BenchmarkId::new("solve_markowitz", n), &n, |b, &n| {
            b.iter(|| {
                let mut solver = GaussianSolver::new(n, n);

                // Fill with deterministic pseudo-random data
                for row in 0..n {
                    let mut coeffs = vec![0u8; n];
                    for (col, coeff) in coeffs.iter_mut().enumerate() {
                        *coeff = ((row * 37 + col * 13 + seed as usize) % 256) as u8;
                    }
                    coeffs[row] = coeffs[row].saturating_add(128);

                    let rhs_data: Vec<u8> = (0..rhs_size)
                        .map(|i| ((row * 7 + i * 11) % 256) as u8)
                        .collect();
                    solver.set_row(row, &coeffs, DenseRow::new(rhs_data));
                }

                let result = solver.solve_markowitz();
                black_box(result)
            });
        });
    }

    group.finish();
}

// ============================================================================
// End-to-end encode/decode benchmarks
// ============================================================================

fn bench_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq_e2e");

    // Test various configurations (k, symbol_size)
    let configs: Vec<(usize, usize)> = vec![
        (4, 256),   // Tiny
        (8, 256),   // Small
        (16, 1024), // Medium
        (32, 1024), // Larger
    ];

    for (k, symbol_size) in configs {
        let seed = 42u64;

        // Generate source data
        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let label = format!("k={k}_sym={symbol_size}");
        group.throughput(Throughput::Bytes((k * symbol_size) as u64));

        // Benchmark encoding
        group.bench_function(BenchmarkId::new("encode", &label), |b| {
            b.iter(|| {
                let encoder =
                    SystematicEncoder::new(black_box(&source), symbol_size, seed).unwrap();
                // Generate some repair symbols
                for esi in (k as u32)..((k + 4) as u32) {
                    let _ = black_box(encoder.repair_symbol(esi));
                }
            });
        });

        // Benchmark decoding (with all source symbols - best case)
        group.bench_function(BenchmarkId::new("decode_source_only", &label), |b| {
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let l = decoder.params().l;

            // Build received symbols (all source + enough repair to reach L)
            let received: Vec<ReceivedSymbol> = source
                .iter()
                .enumerate()
                .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
                .chain((k as u32..(l as u32)).map(|esi| {
                    let (cols, coefs) = decoder.repair_equation(esi);
                    let data = encoder.repair_symbol(esi);
                    ReceivedSymbol::repair(esi, cols, coefs, data)
                }))
                .collect();

            b.iter(|| {
                let result = decoder.decode(black_box(&received));
                black_box(result)
            });
        });

        // Benchmark decoding (repair only - worst case for Gaussian elimination)
        group.bench_function(BenchmarkId::new("decode_repair_only", &label), |b| {
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let l = decoder.params().l;

            // Build received symbols (only repair symbols)
            let received: Vec<ReceivedSymbol> = (k as u32..(k as u32 + l as u32))
                .map(|esi| {
                    let (cols, coefs) = decoder.repair_equation(esi);
                    let data = encoder.repair_symbol(esi);
                    ReceivedSymbol::repair(esi, cols, coefs, data)
                })
                .collect();

            b.iter(|| {
                let result = decoder.decode(black_box(&received));
                black_box(result)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Criterion setup
// ============================================================================

criterion_group!(
    benches,
    bench_gf256_primitives,
    bench_linalg_operations,
    bench_gaussian_elimination,
    bench_encode_decode,
);

criterion_main!(benches);
