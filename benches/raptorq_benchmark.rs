//! RaptorQ encode/decode performance benchmarks.
//!
//! This benchmark suite establishes baselines and profiles hot paths for:
//! - GF(256) bulk operations (addmul_slice, mul_slice, add_slice)
//! - Encoder/decoder roundtrip performance
//! - Gaussian elimination phases
//!
//! Follows the optimization loop: baseline → profile → single lever → golden outputs.

#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{
    gf256_add_slice, gf256_addmul_slice, gf256_addmul_slices2, gf256_mul_slice, gf256_mul_slices2,
    Gf256,
};
use asupersync::raptorq::linalg::{row_scale_add, row_xor, DenseRow, GaussianSolver};
use asupersync::raptorq::systematic::SystematicEncoder;

const TRACK_E_ARTIFACT_PATH: &str = "artifacts/raptorq_track_e_gf256_bench_v1.json";
const TRACK_E_REPRO_CMD: &str =
    "rch exec -- cargo bench --bench raptorq_benchmark -- gf256_primitives";

#[derive(Clone, Copy)]
struct Gf256BenchScenario {
    scenario_id: &'static str,
    seed: u64,
    k: usize,
    symbol_size: usize,
    loss_pattern: &'static str,
    len: usize,
    mul_const: u8,
}

fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_add(1);
    let mut out = vec![0u8; len];
    for byte in &mut out {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        *byte = (value & 0xFF) as u8;
    }
    out
}

fn gf256_bench_context(scenario: &Gf256BenchScenario, outcome: &str) -> String {
    format!(
        "scenario_id={} seed={} k={} symbol_size={} loss_pattern={} outcome={} artifact_path={} \
         repro_cmd='{}'",
        scenario.scenario_id,
        scenario.seed,
        scenario.k,
        scenario.symbol_size,
        scenario.loss_pattern,
        outcome,
        TRACK_E_ARTIFACT_PATH,
        TRACK_E_REPRO_CMD
    )
}

fn reference_mul_slice(dst: &mut [u8], c: Gf256) {
    for value in dst.iter_mut() {
        *value = (Gf256::new(*value) * c).raw();
    }
}

fn reference_addmul_slice(dst: &mut [u8], src: &[u8], c: Gf256) {
    assert_eq!(dst.len(), src.len());
    for (dst_value, src_value) in dst.iter_mut().zip(src.iter().copied()) {
        let product = (Gf256::new(src_value) * c).raw();
        *dst_value ^= product;
    }
}

fn validate_gf256_bit_exactness(scenario: &Gf256BenchScenario, src: &[u8], c_val: Gf256) {
    let base = deterministic_bytes(scenario.len, scenario.seed ^ 0xA5A5_5A5A_F0F0_0F0F);

    let mut add_actual = base.clone();
    gf256_add_slice(&mut add_actual, src);
    let mut add_expected = base.clone();
    for (dst_value, src_value) in add_expected.iter_mut().zip(src.iter().copied()) {
        *dst_value ^= src_value;
    }
    let add_ctx = gf256_bench_context(scenario, "add_slice_bit_exact");
    assert_eq!(add_actual, add_expected, "{add_ctx} mismatch");

    let mut mul_actual = src.to_vec();
    gf256_mul_slice(&mut mul_actual, c_val);
    let mut mul_expected = src.to_vec();
    reference_mul_slice(&mut mul_expected, c_val);
    let mul_ctx = gf256_bench_context(scenario, "mul_slice_bit_exact");
    assert_eq!(mul_actual, mul_expected, "{mul_ctx} mismatch");

    let mut addmul_actual = base.clone();
    gf256_addmul_slice(&mut addmul_actual, src, c_val);
    let mut addmul_expected = base;
    reference_addmul_slice(&mut addmul_expected, src, c_val);
    let addmul_ctx = gf256_bench_context(scenario, "addmul_slice_bit_exact");
    assert_eq!(addmul_actual, addmul_expected, "{addmul_ctx} mismatch");

    // Validate fused dual multiply path against sequential baseline.
    let mut mul_a_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0x0133_7001);
    let mut mul_b_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0x0133_7002);
    let mut mul_a_expected = mul_a_actual.clone();
    let mut mul_b_expected = mul_b_actual.clone();
    gf256_mul_slices2(&mut mul_a_actual, &mut mul_b_actual, c_val);
    gf256_mul_slice(&mut mul_a_expected, c_val);
    gf256_mul_slice(&mut mul_b_expected, c_val);
    let mul2_ctx = gf256_bench_context(scenario, "mul_slices2_bit_exact");
    assert_eq!(
        mul_a_actual, mul_a_expected,
        "{mul2_ctx} mismatch on lane_a"
    );
    assert_eq!(
        mul_b_actual, mul_b_expected,
        "{mul2_ctx} mismatch on lane_b"
    );

    // Validate fused dual addmul path against sequential baseline.
    let src2 = deterministic_bytes(scenario.len, scenario.seed ^ 0xABCD_0123);
    let mut addmul_a_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0xBEEF_1001);
    let mut addmul_b_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0xBEEF_1002);
    let mut addmul_a_expected = addmul_a_actual.clone();
    let mut addmul_b_expected = addmul_b_actual.clone();
    gf256_addmul_slices2(
        &mut addmul_a_actual,
        src,
        &mut addmul_b_actual,
        &src2,
        c_val,
    );
    gf256_addmul_slice(&mut addmul_a_expected, src, c_val);
    gf256_addmul_slice(&mut addmul_b_expected, &src2, c_val);
    let addmul2_ctx = gf256_bench_context(scenario, "addmul_slices2_bit_exact");
    assert_eq!(
        addmul_a_actual, addmul_a_expected,
        "{addmul2_ctx} mismatch on lane_a"
    );
    assert_eq!(
        addmul_b_actual, addmul_b_expected,
        "{addmul2_ctx} mismatch on lane_b"
    );
}

fn gf256_scenarios() -> [Gf256BenchScenario; 5] {
    [
        Gf256BenchScenario {
            scenario_id: "RQ-E-GF256-001",
            seed: 0x1001,
            k: 8,
            symbol_size: 64,
            loss_pattern: "none",
            len: 64,
            mul_const: 7,
        },
        Gf256BenchScenario {
            scenario_id: "RQ-E-GF256-002",
            seed: 0x1002,
            k: 16,
            symbol_size: 256,
            loss_pattern: "drop_10pct",
            len: 256,
            mul_const: 13,
        },
        Gf256BenchScenario {
            scenario_id: "RQ-E-GF256-003",
            seed: 0x1003,
            k: 32,
            symbol_size: 1024,
            loss_pattern: "drop_25pct_burst",
            len: 1024,
            mul_const: 29,
        },
        Gf256BenchScenario {
            scenario_id: "RQ-E-GF256-004",
            seed: 0x1004,
            k: 32,
            symbol_size: 4096,
            loss_pattern: "drop_35pct_burst",
            len: 4096,
            mul_const: 71,
        },
        Gf256BenchScenario {
            scenario_id: "RQ-E-GF256-005",
            seed: 0x1005,
            k: 64,
            symbol_size: 16384,
            loss_pattern: "drop_40pct_random",
            len: 16384,
            mul_const: 151,
        },
    ]
}

// ============================================================================
// GF(256) primitive benchmarks
// ============================================================================

fn bench_gf256_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_primitives");

    // Deterministic scenario matrix for reproducible profiling + parity checks.
    for scenario in gf256_scenarios() {
        group.throughput(Throughput::Bytes(scenario.len as u64));

        let src = deterministic_bytes(scenario.len, scenario.seed);
        let c_val = Gf256::new(scenario.mul_const);
        validate_gf256_bit_exactness(&scenario, &src, c_val);
        let label = format!(
            "{}_n{}_seed{}_k{}_sym{}",
            scenario.scenario_id, scenario.len, scenario.seed, scenario.k, scenario.symbol_size
        );

        // Benchmark gf256_add_slice (pure XOR)
        group.bench_with_input(BenchmarkId::new("add_slice", &label), &scenario, |b, _| {
            let mut dst = deterministic_bytes(scenario.len, scenario.seed ^ 0xAA55_AA55);
            b.iter(|| {
                gf256_add_slice(std::hint::black_box(&mut dst), std::hint::black_box(&src));
            });
        });

        // Benchmark gf256_mul_slice (scalar multiply)
        group.bench_with_input(BenchmarkId::new("mul_slice", &label), &scenario, |b, _| {
            let mut dst: Vec<u8> = src.clone();
            b.iter(|| {
                gf256_mul_slice(std::hint::black_box(&mut dst), std::hint::black_box(c_val));
            });
        });

        // Benchmark gf256_addmul_slice (THE critical hot path)
        group.bench_with_input(
            BenchmarkId::new("addmul_slice", &label),
            &scenario,
            |b, _| {
                let mut dst = deterministic_bytes(scenario.len, scenario.seed ^ 0x55AA_55AA);
                b.iter(|| {
                    gf256_addmul_slice(
                        std::hint::black_box(&mut dst),
                        std::hint::black_box(&src),
                        std::hint::black_box(c_val),
                    );
                });
            },
        );

        // Benchmark fused dual mul against sequential mul+mul.
        group.bench_with_input(
            BenchmarkId::new("mul_slices2_fused", &label),
            &scenario,
            |b, _| {
                let mut dst_a = deterministic_bytes(scenario.len, scenario.seed ^ 0x1111_2222);
                let mut dst_b = deterministic_bytes(scenario.len, scenario.seed ^ 0x3333_4444);
                b.iter(|| {
                    gf256_mul_slices2(
                        std::hint::black_box(&mut dst_a),
                        std::hint::black_box(&mut dst_b),
                        std::hint::black_box(c_val),
                    );
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("mul_slices2_sequential", &label),
            &scenario,
            |b, _| {
                let mut dst_a = deterministic_bytes(scenario.len, scenario.seed ^ 0x1111_2222);
                let mut dst_b = deterministic_bytes(scenario.len, scenario.seed ^ 0x3333_4444);
                b.iter(|| {
                    gf256_mul_slice(
                        std::hint::black_box(&mut dst_a),
                        std::hint::black_box(c_val),
                    );
                    gf256_mul_slice(
                        std::hint::black_box(&mut dst_b),
                        std::hint::black_box(c_val),
                    );
                });
            },
        );

        // Benchmark fused dual addmul against sequential addmul+addmul.
        group.bench_with_input(
            BenchmarkId::new("addmul_slices2_fused", &label),
            &scenario,
            |b, _| {
                let src_b = deterministic_bytes(scenario.len, scenario.seed ^ 0xCAFEBABE);
                let mut dst_a = deterministic_bytes(scenario.len, scenario.seed ^ 0xAAAA_0101);
                let mut dst_b = deterministic_bytes(scenario.len, scenario.seed ^ 0xBBBB_0202);
                b.iter(|| {
                    gf256_addmul_slices2(
                        std::hint::black_box(&mut dst_a),
                        std::hint::black_box(&src),
                        std::hint::black_box(&mut dst_b),
                        std::hint::black_box(&src_b),
                        std::hint::black_box(c_val),
                    );
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("addmul_slices2_sequential", &label),
            &scenario,
            |b, _| {
                let src_b = deterministic_bytes(scenario.len, scenario.seed ^ 0xCAFEBABE);
                let mut dst_a = deterministic_bytes(scenario.len, scenario.seed ^ 0xAAAA_0101);
                let mut dst_b = deterministic_bytes(scenario.len, scenario.seed ^ 0xBBBB_0202);
                b.iter(|| {
                    gf256_addmul_slice(
                        std::hint::black_box(&mut dst_a),
                        std::hint::black_box(&src),
                        std::hint::black_box(c_val),
                    );
                    gf256_addmul_slice(
                        std::hint::black_box(&mut dst_b),
                        std::hint::black_box(&src_b),
                        std::hint::black_box(c_val),
                    );
                });
            },
        );
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
                    row_xor(std::hint::black_box(&mut dst), std::hint::black_box(&src));
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
                    row_scale_add(
                        std::hint::black_box(&mut dst),
                        std::hint::black_box(&src),
                        std::hint::black_box(c_val),
                    );
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
                std::hint::black_box(result)
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
                std::hint::black_box(result)
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
                    SystematicEncoder::new(std::hint::black_box(&source), symbol_size, seed)
                        .unwrap();
                // Generate some repair symbols
                for esi in (k as u32)..((k + 4) as u32) {
                    let _ = std::hint::black_box(encoder.repair_symbol(esi));
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
                let result = decoder.decode(std::hint::black_box(&received));
                std::hint::black_box(result)
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
                let result = decoder.decode(std::hint::black_box(&received));
                std::hint::black_box(result)
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
