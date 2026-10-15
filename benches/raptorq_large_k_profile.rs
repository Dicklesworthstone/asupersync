//! RaptorQ large K performance profiling benchmark (K=1024+).
//!
//! **MISSION**: Find >5%-CPU bottlenecks in encoder/decoder hot paths under realistic workloads.
//! **TARGET AREAS**: gf256 multiply, matrix solve step, gap-handling
//! **METHODOLOGY**: Profile realistic scenarios with K=1024, 2048, 4096 to stress-test hot paths
//! **E-4 OUTPUT**: decode-vs-K rows carry JSONL-compatible envelope metadata for br-asupersync-atp-e4-decode-vs-k-result-u2xblb.
//!
//! Run with: rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_bench_docs cargo bench --bench raptorq_large_k_profile --features simd-intrinsics
//! Profile with: rch exec -- samply record --save-only -o raptorq_large_k.json -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_bench_docs cargo bench --bench raptorq_large_k_profile --features simd-intrinsics

#![allow(warnings)]
#![allow(dead_code)]
#![allow(missing_docs)]

use criterion::{
    BenchmarkId, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use std::{hint::black_box, time::Duration};

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice, gf256_mul_slice};
use asupersync::raptorq::linalg::{
    DenseRow, GaussianSolver, row_scale_add, row_scale_add_batch_multi, row_scale_add_batch2,
};
use asupersync::raptorq::systematic::SystematicEncoder;

/// Large K scenarios for stress testing encoder/decoder hot paths
#[derive(Debug, Clone)]
struct LargeKScenario {
    scenario_id: &'static str,
    k: usize,
    symbol_size: usize,
    loss_fraction: f64,
    extra_repair: usize,
    target_bottleneck: &'static str,
}

fn large_k_scenarios() -> [LargeKScenario; 6] {
    [
        // Stress GF256 multiply operations
        LargeKScenario {
            scenario_id: "LARGE-K-GF256-1024",
            k: 1024,
            symbol_size: 1316,  // ~1.3MB total
            loss_fraction: 0.5, // 50% loss
            extra_repair: 100,
            target_bottleneck: "gf256_multiply",
        },
        // Stress matrix solve (Gaussian elimination)
        LargeKScenario {
            scenario_id: "LARGE-K-GAUSS-1024",
            k: 1024,
            symbol_size: 1316,
            loss_fraction: 0.7, // High loss forces matrix solve
            extra_repair: 50,
            target_bottleneck: "matrix_solve",
        },
        // Stress gap-handling with scattered losses
        LargeKScenario {
            scenario_id: "LARGE-K-GAP-1024",
            k: 1024,
            symbol_size: 1316,
            loss_fraction: 0.6, // Moderate loss with gaps
            extra_repair: 200,  // Lots of repair symbols
            target_bottleneck: "gap_handling",
        },
        // Larger K=2048 scenarios
        LargeKScenario {
            scenario_id: "LARGE-K-GF256-2048",
            k: 2048,
            symbol_size: 658, // ~1.3MB total
            loss_fraction: 0.5,
            extra_repair: 100,
            target_bottleneck: "gf256_multiply",
        },
        LargeKScenario {
            scenario_id: "LARGE-K-GAUSS-2048",
            k: 2048,
            symbol_size: 658,
            loss_fraction: 0.65, // Force complex matrix operations
            extra_repair: 150,
            target_bottleneck: "matrix_solve",
        },
        // Extreme K=4096 scenario
        LargeKScenario {
            scenario_id: "LARGE-K-EXTREME-4096",
            k: 4096,
            symbol_size: 329, // ~1.3MB total
            loss_fraction: 0.55,
            extra_repair: 200,
            target_bottleneck: "combined",
        },
    ]
}

const E4_FIXED_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const E4_ATP_SYMBOL_SIZE: usize = 1400;
const E4_LOSS_FRACTION: f64 = 0.02;
const E4_MIN_EXTRA_REPAIR: usize = 32;
const E4_MAX_REPAIR_SYMBOLS: usize = 512;
const E4_DECODE_K_VALUES: [usize; 4] = [256, 1024, 4096, 8192];
const E4_ATP_DECODE_K_VALUES: [usize; 6] = [256, 512, 1024, 2048, 4096, 8192];
const E4_DECODE_BASELINE_K: usize = 256;
const E4_DECODE_BASELINE_SYMBOL_SIZE: usize = E4_FIXED_TOTAL_BYTES / E4_DECODE_BASELINE_K;
const E4_FIXED_TOTAL_MIB: usize = E4_FIXED_TOTAL_BYTES / (1024 * 1024);
const E4_TREE_ALPHA: f64 = 1.35;
const E4_TREE_MAX_DEPTH: usize = 6;
const E4_DECODE_VS_K_RESULT_SCHEMA: &str = "e4_decode_vs_k_result_v1";
const E4_DECODE_VS_K_COMPARISON_FAMILY: &str = "fixed_total_bytes_decode_vs_k";
const E4_DECODE_VS_K_DECISION_SIGNAL: &str =
    "compare_wall_time_per_byte_across_k_for_fixed_total_bytes";
const E4_ATP_FIXED_SYMBOL_COMPARISON_FAMILY: &str = "atp_fixed_symbol_size_decode_vs_k";
const E4_ATP_FIXED_SYMBOL_DECISION_SIGNAL: &str =
    "compare_wall_time_per_byte_across_k_for_atp_candidate_block_bytes";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodeVsKResult {
    k: usize,
    symbol_size: usize,
    total_bytes: usize,
    source_symbols: usize,
    required_symbols: usize,
    received_source_symbols: usize,
    missing_source_symbols: usize,
    repair_symbols: usize,
    total_received_symbols: usize,
    overhead_basis_points: u64,
    loss_basis_points: u64,
    repair_bytes: usize,
    decoder_input_bytes: usize,
    decoder_input_bytes_per_total_basis_points: u64,
    rank_slack_symbols: usize,
    baseline_k: usize,
    k_relative_to_baseline_basis_points: u64,
    symbol_size_relative_to_baseline_basis_points: u64,
    quadratic_k_work_units: u64,
    quadratic_work_units_per_mib: u64,
}

impl DecodeVsKResult {
    fn new(
        k: usize,
        symbol_size: usize,
        total_bytes: usize,
        received_source_symbols: usize,
        repair_symbols: usize,
        required_symbols: usize,
    ) -> Self {
        let missing_source_symbols = k.saturating_sub(received_source_symbols);
        let total_received_symbols = received_source_symbols.saturating_add(repair_symbols);
        let overhead_symbols = total_received_symbols.saturating_sub(k);
        let overhead_basis_points = if k == 0 {
            0
        } else {
            u64::try_from(overhead_symbols.saturating_mul(10_000) / k).unwrap_or(u64::MAX)
        };
        let loss_basis_points = if k == 0 {
            0
        } else {
            u64::try_from(missing_source_symbols.saturating_mul(10_000) / k).unwrap_or(u64::MAX)
        };
        let decoder_input_bytes = total_received_symbols.saturating_mul(symbol_size);
        let decoder_input_bytes_per_total_basis_points = if total_bytes == 0 {
            0
        } else {
            u64::try_from(decoder_input_bytes.saturating_mul(10_000) / total_bytes)
                .unwrap_or(u64::MAX)
        };
        let k_relative_to_baseline_basis_points =
            u64::try_from(k.saturating_mul(10_000) / E4_DECODE_BASELINE_K).unwrap_or(u64::MAX);
        let symbol_size_relative_to_baseline_basis_points = if E4_DECODE_BASELINE_SYMBOL_SIZE == 0 {
            0
        } else {
            u64::try_from(symbol_size.saturating_mul(10_000) / E4_DECODE_BASELINE_SYMBOL_SIZE)
                .unwrap_or(u64::MAX)
        };
        let quadratic_k_work_units = u64::try_from(k.saturating_mul(k)).unwrap_or(u64::MAX);
        let quadratic_work_units_per_mib = if E4_FIXED_TOTAL_MIB == 0 {
            quadratic_k_work_units
        } else {
            quadratic_k_work_units / u64::try_from(E4_FIXED_TOTAL_MIB).unwrap_or(1)
        };

        Self {
            k,
            symbol_size,
            total_bytes,
            source_symbols: k,
            required_symbols,
            received_source_symbols,
            missing_source_symbols,
            repair_symbols,
            total_received_symbols,
            overhead_basis_points,
            loss_basis_points,
            repair_bytes: repair_symbols.saturating_mul(symbol_size),
            decoder_input_bytes,
            decoder_input_bytes_per_total_basis_points,
            rank_slack_symbols: total_received_symbols.saturating_sub(required_symbols),
            baseline_k: E4_DECODE_BASELINE_K,
            k_relative_to_baseline_basis_points,
            symbol_size_relative_to_baseline_basis_points,
            quadratic_k_work_units,
            quadratic_work_units_per_mib,
        }
    }

    fn benchmark_id(self) -> String {
        format!(
            "{}_k{}_sym{}_total{}_required{}_source{}_missing{}_loss{}bp_repair{}_received{}_repairbytes{}_inputbytes{}_input{}bp_slack{}_overhead{}bp_krel{}bp_symrel{}bp_k2{}_k2pmib{}",
            E4_DECODE_VS_K_RESULT_SCHEMA,
            self.k,
            self.symbol_size,
            self.total_bytes,
            self.required_symbols,
            self.received_source_symbols,
            self.missing_source_symbols,
            self.loss_basis_points,
            self.repair_symbols,
            self.total_received_symbols,
            self.repair_bytes,
            self.decoder_input_bytes,
            self.decoder_input_bytes_per_total_basis_points,
            self.rank_slack_symbols,
            self.overhead_basis_points,
            self.k_relative_to_baseline_basis_points,
            self.symbol_size_relative_to_baseline_basis_points,
            self.quadratic_k_work_units,
            self.quadratic_work_units_per_mib
        )
    }

    fn artifact_json_for(
        self,
        comparison_family: &'static str,
        decision_signal: &'static str,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema_version": E4_DECODE_VS_K_RESULT_SCHEMA,
            "comparison_family": comparison_family,
            "decision_signal": decision_signal,
            "benchmark_id": self.benchmark_id(),
            "k": self.k,
            "symbol_size": self.symbol_size,
            "total_bytes": self.total_bytes,
            "source_symbols": self.source_symbols,
            "required_symbols": self.required_symbols,
            "received_source_symbols": self.received_source_symbols,
            "missing_source_symbols": self.missing_source_symbols,
            "repair_symbols": self.repair_symbols,
            "total_received_symbols": self.total_received_symbols,
            "overhead_basis_points": self.overhead_basis_points,
            "loss_basis_points": self.loss_basis_points,
            "repair_bytes": self.repair_bytes,
            "decoder_input_bytes": self.decoder_input_bytes,
            "decoder_input_bytes_per_total_basis_points": self.decoder_input_bytes_per_total_basis_points,
            "rank_slack_symbols": self.rank_slack_symbols,
            "baseline_k": self.baseline_k,
            "k_relative_to_baseline_basis_points": self.k_relative_to_baseline_basis_points,
            "symbol_size_relative_to_baseline_basis_points": self.symbol_size_relative_to_baseline_basis_points,
            "quadratic_k_work_units": self.quadratic_k_work_units,
            "quadratic_work_units_per_mib": self.quadratic_work_units_per_mib,
        })
    }

    fn artifact_json(self) -> serde_json::Value {
        self.artifact_json_for(
            E4_DECODE_VS_K_COMPARISON_FAMILY,
            E4_DECODE_VS_K_DECISION_SIGNAL,
        )
    }

    fn artifact_json_line(self) -> String {
        serde_json::to_string(&self.artifact_json())
            .expect("E-4 decode-vs-K result envelope must serialize")
    }

    fn artifact_json_line_for(
        self,
        comparison_family: &'static str,
        decision_signal: &'static str,
    ) -> String {
        serde_json::to_string(&self.artifact_json_for(comparison_family, decision_signal))
            .expect("E-4 decode-vs-K result envelope must serialize")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PowerLawTreeEntry {
    index: usize,
    depth: usize,
    size_bytes: usize,
}

fn next_lcg(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

fn next_unit_interval(state: &mut u64) -> f64 {
    let value = next_lcg(state) >> 11;
    (value as f64 + 1.0) / ((1u64 << 53) as f64 + 1.0)
}

fn generate_power_law_tree_entries(
    file_count: usize,
    min_size: usize,
    max_size: usize,
    seed: u64,
) -> Vec<PowerLawTreeEntry> {
    assert!(min_size > 0, "power-law tree min_size must be nonzero");
    assert!(
        min_size <= max_size,
        "power-law tree min_size must not exceed max_size"
    );

    let mut state = seed;
    (0..file_count)
        .map(|index| {
            let unit = next_unit_interval(&mut state);
            let pareto_size = (min_size as f64) / unit.powf(1.0 / E4_TREE_ALPHA);
            let size_bytes = pareto_size.clamp(min_size as f64, max_size as f64) as usize;
            let depth = 1 + (next_lcg(&mut state) as usize % E4_TREE_MAX_DEPTH);
            PowerLawTreeEntry {
                index,
                depth,
                size_bytes,
            }
        })
        .collect()
}

fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut rng_state = seed;
    for byte in data.iter_mut() {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (rng_state >> 16) as u8;
    }
    data
}

fn generate_source_symbols(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    generate_test_data(k * symbol_size, seed)
        .chunks_exact(symbol_size)
        .map(<[u8]>::to_vec)
        .collect()
}

fn create_scattered_loss_pattern(k: usize, loss_fraction: f64, seed: u64) -> Vec<bool> {
    let mut pattern = vec![false; k]; // true = symbol lost
    let loss_count = (k as f64 * loss_fraction) as usize;
    let mut rng_state = seed;

    // Create scattered losses (not clustered)
    let mut losses_placed = 0;
    while losses_placed < loss_count {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (rng_state % k as u64) as usize;
        if !pattern[idx] {
            pattern[idx] = true;
            losses_placed += 1;
        }
    }
    pattern
}

#[derive(Debug)]
struct FixedTotalDecodeScenario {
    k: usize,
    symbol_size: usize,
    total_bytes: usize,
    seed: u64,
    result: DecodeVsKResult,
    received_symbols: Vec<ReceivedSymbol>,
    expected_source_symbols: Vec<Vec<u8>>,
}

fn build_decode_scenario(k: usize, symbol_size: usize, seed: u64) -> FixedTotalDecodeScenario {
    let total_bytes = k.saturating_mul(symbol_size);
    let source_symbols = generate_source_symbols(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed)
        .expect("encoder creation failed");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let loss_pattern = create_scattered_loss_pattern(k, E4_LOSS_FRACTION, seed ^ 0x5EED);
    let mut received_symbols = Vec::with_capacity(k + E4_MIN_EXTRA_REPAIR);
    let mut received_source_symbols = 0usize;

    for (i, &lost) in loss_pattern.iter().enumerate() {
        if !lost {
            let esi = u32::try_from(i).expect("source ESI must fit in u32");
            received_symbols.push(ReceivedSymbol::source(esi, source_symbols[i].clone()));
            received_source_symbols += 1;
        }
    }

    let params = decoder.params();
    let required_symbols = params.l - params.k_prime.saturating_sub(params.k);
    let initial_repairs =
        required_symbols.saturating_sub(received_symbols.len()) + E4_MIN_EXTRA_REPAIR;
    let mut decoded_source = None;
    let mut repair_symbols = 0usize;

    for i in 0..E4_MAX_REPAIR_SYMBOLS {
        let repair_esi = u32::try_from(k + i).expect("repair ESI must fit in u32");
        let repair_data = encoder.repair_symbol(repair_esi);
        let (columns, coefficients) = decoder
            .repair_equation(repair_esi)
            .expect("repair equation creation failed");
        repair_symbols += 1;
        received_symbols.push(ReceivedSymbol::repair(
            repair_esi,
            columns,
            coefficients,
            repair_data,
        ));

        if i + 1 >= initial_repairs {
            match decoder.decode(&received_symbols) {
                Ok(decoded) => {
                    decoded_source = Some(decoded.source);
                    break;
                }
                Err(_) => continue,
            }
        }
    }

    let decoded_source = decoded_source.unwrap_or_else(|| {
        panic!(
            "fixed-total decode scenario did not become solvable for K={} after {} repair symbols",
            k, E4_MAX_REPAIR_SYMBOLS
        )
    });
    assert_eq!(
        decoded_source, source_symbols,
        "fixed-total decode scenario must round-trip"
    );

    let result = DecodeVsKResult::new(
        k,
        symbol_size,
        total_bytes,
        received_source_symbols,
        repair_symbols,
        required_symbols,
    );
    assert_eq!(
        result.total_received_symbols,
        received_symbols.len(),
        "E-4 result envelope must match the decoded input"
    );

    FixedTotalDecodeScenario {
        k,
        symbol_size,
        total_bytes,
        seed,
        result,
        received_symbols,
        expected_source_symbols: source_symbols,
    }
}

fn build_fixed_total_decode_scenario(k: usize) -> FixedTotalDecodeScenario {
    assert_eq!(
        E4_FIXED_TOTAL_BYTES % k,
        0,
        "fixed total bytes must divide K"
    );

    let symbol_size = E4_FIXED_TOTAL_BYTES / k;
    build_decode_scenario(k, symbol_size, 0xE400_0000_u64 ^ k as u64)
}

fn build_atp_fixed_symbol_decode_scenario(k: usize) -> FixedTotalDecodeScenario {
    build_decode_scenario(k, E4_ATP_SYMBOL_SIZE, 0xE4A7_0000_u64 ^ k as u64)
}

#[cfg(test)]
mod e4_decode_vs_k_tests {
    use super::*;

    #[test]
    fn decode_vs_k_result_reports_missing_repair_and_overhead() {
        let result = DecodeVsKResult::new(1024, 4096, E4_FIXED_TOTAL_BYTES, 1004, 52, 1024);

        assert_eq!(result.source_symbols, 1024);
        assert_eq!(result.required_symbols, 1024);
        assert_eq!(result.received_source_symbols, 1004);
        assert_eq!(result.missing_source_symbols, 20);
        assert_eq!(result.repair_symbols, 52);
        assert_eq!(result.total_received_symbols, 1056);
        assert_eq!(result.overhead_basis_points, 312);
        assert_eq!(result.loss_basis_points, 195);
        assert_eq!(result.repair_bytes, 212_992);
        assert_eq!(result.decoder_input_bytes, 4_325_376);
        assert_eq!(result.decoder_input_bytes_per_total_basis_points, 10_312);
        assert_eq!(result.rank_slack_symbols, 32);
        assert_eq!(result.baseline_k, 256);
        assert_eq!(result.k_relative_to_baseline_basis_points, 40_000);
        assert_eq!(result.symbol_size_relative_to_baseline_basis_points, 2_500);
        assert_eq!(result.quadratic_k_work_units, 1_048_576);
        assert_eq!(result.quadratic_work_units_per_mib, 262_144);
        assert_eq!(
            result.benchmark_id(),
            "e4_decode_vs_k_result_v1_k1024_sym4096_total4194304_required1024_source1004_missing20_loss195bp_repair52_received1056_repairbytes212992_inputbytes4325376_input10312bp_slack32_overhead312bp_krel40000bp_symrel2500bp_k21048576_k2pmib262144"
        );
    }

    #[test]
    fn decode_vs_k_result_artifact_json_line_round_trips_schema() {
        let result = DecodeVsKResult::new(1024, 4096, E4_FIXED_TOTAL_BYTES, 1004, 52, 1024);
        let benchmark_id = result.benchmark_id();
        let envelope = result.artifact_json();

        assert_eq!(
            envelope,
            serde_json::json!({
                "schema_version": E4_DECODE_VS_K_RESULT_SCHEMA,
                "comparison_family": E4_DECODE_VS_K_COMPARISON_FAMILY,
                "decision_signal": E4_DECODE_VS_K_DECISION_SIGNAL,
                "benchmark_id": benchmark_id,
                "k": 1024,
                "symbol_size": 4096,
                "total_bytes": E4_FIXED_TOTAL_BYTES,
                "source_symbols": 1024,
                "required_symbols": 1024,
                "received_source_symbols": 1004,
                "missing_source_symbols": 20,
                "repair_symbols": 52,
                "total_received_symbols": 1056,
                "overhead_basis_points": 312,
                "loss_basis_points": 195,
                "repair_bytes": 212_992,
                "decoder_input_bytes": 4_325_376,
                "decoder_input_bytes_per_total_basis_points": 10_312,
                "rank_slack_symbols": 32,
                "baseline_k": 256,
                "k_relative_to_baseline_basis_points": 40_000,
                "symbol_size_relative_to_baseline_basis_points": 2_500,
                "quadratic_k_work_units": 1_048_576,
                "quadratic_work_units_per_mib": 262_144,
            })
        );

        let line = result.artifact_json_line();
        assert!(
            !line.contains('\n'),
            "artifact envelope must be a JSONL-compatible single line"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("artifact envelope must be valid JSON");
        assert_eq!(parsed, envelope);
    }

    #[test]
    fn decode_vs_k_values_keep_fixed_total_divisible() {
        assert!(
            E4_DECODE_K_VALUES
                .iter()
                .all(|k| E4_FIXED_TOTAL_BYTES % k == 0)
        );
    }

    #[test]
    fn atp_fixed_symbol_values_map_k_to_candidate_block_bytes() {
        assert_eq!(E4_ATP_SYMBOL_SIZE, 1400);
        assert_eq!(E4_ATP_DECODE_K_VALUES, [256, 512, 1024, 2048, 4096, 8192]);

        let candidate_block_bytes: Vec<usize> = E4_ATP_DECODE_K_VALUES
            .iter()
            .map(|k| k.saturating_mul(E4_ATP_SYMBOL_SIZE))
            .collect();

        assert_eq!(
            candidate_block_bytes,
            vec![
                358_400, 716_800, 1_433_600, 2_867_200, 5_734_400, 11_468_800
            ]
        );
    }

    #[test]
    fn power_law_tree_entries_are_deterministic_and_bounded() {
        let first = generate_power_law_tree_entries(16, 1024, 1024 * 1024, 0xE4_700E);
        let second = generate_power_law_tree_entries(16, 1024, 1024 * 1024, 0xE4_700E);

        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
        assert!(first.iter().all(|entry| entry.depth >= 1));
        assert!(first.iter().all(|entry| entry.depth <= E4_TREE_MAX_DEPTH));
        assert!(first.iter().all(|entry| entry.size_bytes >= 1024));
        assert!(first.iter().all(|entry| entry.size_bytes <= 1024 * 1024));
        assert!(
            first
                .iter()
                .enumerate()
                .all(|(index, entry)| entry.index == index)
        );
    }
}

fn bench_e4_decode_vs_k_fixed_total_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("e4_decode_vs_k_fixed_total_bytes");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.warm_up_time(Duration::from_secs(2));

    for &k in &E4_DECODE_K_VALUES {
        let scenario = build_fixed_total_decode_scenario(k);
        group.throughput(Throughput::Bytes(scenario.total_bytes as u64));
        let bench_name = scenario.result.benchmark_id();
        let result_envelope = scenario.result.artifact_json_line();
        let bench_input = (scenario, result_envelope);

        group.bench_with_input(
            BenchmarkId::new("decode_block_path", &bench_name),
            &bench_input,
            |b, bench_input| {
                let scenario = &bench_input.0;
                let result_envelope = bench_input.1.as_str();
                b.iter(|| {
                    black_box(result_envelope);
                    let decoder =
                        InactivationDecoder::new(scenario.k, scenario.symbol_size, scenario.seed);
                    let decoded = decoder
                        .decode(black_box(&scenario.received_symbols))
                        .expect("decode failed");
                    assert_eq!(
                        decoded.source.len(),
                        scenario.expected_source_symbols.len(),
                        "decoded source symbol count mismatch"
                    );
                    assert_eq!(
                        decoded.source, scenario.expected_source_symbols,
                        "decoded source symbols must match exactly"
                    );
                    black_box(decoded);
                });
            },
        );
    }

    group.finish();
}

fn bench_e4_decode_vs_k_atp_fixed_symbol_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("e4_decode_vs_k_atp_fixed_symbol_size");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.warm_up_time(Duration::from_secs(2));

    for &k in &E4_ATP_DECODE_K_VALUES {
        let scenario = build_atp_fixed_symbol_decode_scenario(k);
        group.throughput(Throughput::Bytes(scenario.total_bytes as u64));
        let bench_name = format!(
            "atp_sym{}_blockbytes{}_{}",
            E4_ATP_SYMBOL_SIZE,
            scenario.total_bytes,
            scenario.result.benchmark_id()
        );
        let result_envelope = scenario.result.artifact_json_line_for(
            E4_ATP_FIXED_SYMBOL_COMPARISON_FAMILY,
            E4_ATP_FIXED_SYMBOL_DECISION_SIGNAL,
        );
        let bench_input = (scenario, result_envelope);

        group.bench_with_input(
            BenchmarkId::new("decode_block_path", &bench_name),
            &bench_input,
            |b, bench_input| {
                let scenario = &bench_input.0;
                let result_envelope = bench_input.1.as_str();
                b.iter(|| {
                    black_box(result_envelope);
                    let decoder =
                        InactivationDecoder::new(scenario.k, scenario.symbol_size, scenario.seed);
                    let decoded = decoder
                        .decode(black_box(&scenario.received_symbols))
                        .expect("decode failed");
                    assert_eq!(
                        decoded.source.len(),
                        scenario.expected_source_symbols.len(),
                        "decoded source symbol count mismatch"
                    );
                    assert_eq!(
                        decoded.source, scenario.expected_source_symbols,
                        "decoded source symbols must match exactly"
                    );
                    black_box(decoded);
                });
            },
        );
    }

    group.finish();
}

fn bench_large_k_encoder_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_k_encoder_roundtrip");
    group.sample_size(10); // Fewer samples for large workloads
    group.measurement_time(Duration::from_secs(30)); // Longer measurement time
    group.warm_up_time(Duration::from_secs(5));

    for scenario in &large_k_scenarios()[0..4] {
        // Skip extreme scenarios for basic profiling
        let total_bytes = scenario.k * scenario.symbol_size;
        group.throughput(Throughput::Bytes(total_bytes as u64));

        let bench_name = format!(
            "{}_k{}_sym{}_loss{:.1}",
            scenario.scenario_id,
            scenario.k,
            scenario.symbol_size,
            scenario.loss_fraction * 100.0
        );

        group.bench_with_input(
            BenchmarkId::new("encoder_roundtrip", &bench_name),
            scenario,
            |b, scenario| {
                // Generate test data once
                let source_symbols =
                    generate_source_symbols(scenario.k, scenario.symbol_size, 0x12345678);

                b.iter(|| {
                    // **HOT PATH 1: ENCODER** - Test systematic encoding performance
                    let encoder =
                        SystematicEncoder::new(&source_symbols, scenario.symbol_size, 0x12345678)
                            .expect("encoder creation failed");
                    let decoder =
                        InactivationDecoder::new(scenario.k, scenario.symbol_size, 0x12345678);

                    // Generate repair symbols - this stresses gf256 operations
                    let loss_pattern = create_scattered_loss_pattern(
                        scenario.k,
                        scenario.loss_fraction,
                        0xDEADBEEF,
                    );

                    let mut received_symbols = Vec::new();

                    // Add available source symbols
                    for (i, &lost) in loss_pattern.iter().enumerate() {
                        if !lost {
                            let esi = u32::try_from(i).expect("source ESI must fit in u32");
                            received_symbols
                                .push(ReceivedSymbol::source(esi, source_symbols[i].clone()));
                        }
                    }

                    // Add repair symbols to make decoding possible
                    let params = decoder.params();
                    let required_symbols = params.l - params.k_prime.saturating_sub(params.k);
                    let needed_repairs = required_symbols.saturating_sub(received_symbols.len())
                        + scenario.extra_repair;
                    for i in 0..needed_repairs {
                        let repair_esi =
                            u32::try_from(scenario.k + i).expect("repair ESI must fit in u32");
                        let repair_data = encoder.repair_symbol(repair_esi);
                        let (columns, coefficients) = decoder
                            .repair_equation(repair_esi)
                            .expect("repair equation creation failed");
                        received_symbols.push(ReceivedSymbol::repair(
                            repair_esi,
                            columns,
                            coefficients,
                            repair_data,
                        ));
                    }

                    // **HOT PATH 2: DECODER** - Test inactivation decoding performance
                    // **HOT PATH 3: DECODE** - This is where matrix solve and gap-handling happen
                    let decoded = decoder.decode(&received_symbols).expect("decode failed");

                    // Verify correctness
                    assert_eq!(
                        decoded.source.len(),
                        source_symbols.len(),
                        "decoded source symbol count mismatch"
                    );
                    assert_eq!(decoded.source, source_symbols, "decoded data mismatch");
                });
            },
        );
    }

    group.finish();
}

fn bench_gf256_bulk_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_bulk_operations");
    group.sample_size(20);

    // Test GF256 operations at various scales to find bottlenecks
    let sizes = [1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB
    let multipliers = [Gf256::new(7), Gf256::new(61), Gf256::new(137)];

    for &size in &sizes {
        for &mult in &multipliers {
            group.throughput(Throughput::Bytes(size as u64));

            let bench_name = format!("size_{}_mult_{}", size, mult.raw());

            // Test gf256_mul_slice performance
            group.bench_with_input(
                BenchmarkId::new("gf256_mul_slice", &bench_name),
                &(size, mult),
                |b, &(size, mult)| {
                    let mut data = generate_test_data(size, 0x87654321);
                    b.iter(|| {
                        gf256_mul_slice(&mut data, mult);
                    });
                },
            );

            // Test gf256_addmul_slice performance (more complex operation)
            group.bench_with_input(
                BenchmarkId::new("gf256_addmul_slice", &bench_name),
                &(size, mult),
                |b, &(size, mult)| {
                    let mut dst = generate_test_data(size, 0x11111111);
                    let src = generate_test_data(size, 0x22222222);
                    b.iter(|| {
                        gf256_addmul_slice(&mut dst, &src, mult);
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_matrix_operations_stress(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_operations_stress");
    group.sample_size(5); // Very few samples for heavy operations
    group.measurement_time(Duration::from_secs(60)); // Long measurement for stability

    // Test matrix operations that stress linear algebra hot paths
    let matrix_sizes = [128, 256, 512, 1024]; // Square matrix sizes

    for &size in &matrix_sizes {
        let bench_name = format!("gauss_solve_{}", size);

        group.bench_with_input(
            BenchmarkId::new("gaussian_elimination", &bench_name),
            &size,
            |b, &size| {
                b.iter(|| {
                    // Create a test matrix for Gaussian elimination
                    let mut solver = GaussianSolver::new(size, size);

                    // Add rows with random coefficients - simulate RaptorQ constraint matrix
                    for i in 0..size {
                        let mut rng_state = 0x98765432u64.wrapping_add(i as u64);

                        // Fill row with random coefficients
                        for j in 0..size {
                            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                            let coeff = Gf256::new((rng_state & 0xFF) as u8);
                            if !coeff.is_zero() {
                                solver.set_coefficient(i, j, coeff);
                            }
                        }

                        // Set RHS value
                        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                        let rhs = (rng_state & 0xFF) as u8;

                        solver.set_rhs(i, DenseRow::new(vec![rhs]));
                    }

                    // **HOT PATH: GAUSSIAN ELIMINATION**
                    // This is where the matrix solve bottlenecks would appear
                    let _solution = solver.solve();
                });
            },
        );
    }

    group.finish();
}

fn bench_row_scale_add_batching_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("row_scale_add_batching");
    group.sample_size(20);

    // Test scenarios mimicking Gaussian elimination workloads for K=1024
    let row_counts = [2, 4, 8, 16, 32]; // Batch sizes
    let symbol_sizes = [1316, 2632]; // Realistic RaptorQ symbol sizes
    let coefficients = [Gf256::new(7), Gf256::new(13), Gf256::new(61)];

    for &row_count in &row_counts {
        for &symbol_size in &symbol_sizes {
            for &coeff in &coefficients {
                let bench_name =
                    format!("rows_{}_size_{}_c_{}", row_count, symbol_size, coeff.raw());

                group.throughput(Throughput::Bytes((row_count * symbol_size) as u64));

                // Benchmark sequential row operations (current approach)
                group.bench_with_input(
                    BenchmarkId::new("sequential", &bench_name),
                    &(row_count, symbol_size, coeff),
                    |b, &(row_count, symbol_size, coeff)| {
                        // Pre-generate test data
                        let mut dst_rows = Vec::with_capacity(row_count);
                        let mut src_rows = Vec::with_capacity(row_count);

                        for i in 0..row_count {
                            dst_rows.push(vec![(i % 256) as u8; symbol_size]);
                            src_rows.push(vec![((i + 1) % 256) as u8; symbol_size]);
                        }

                        b.iter(|| {
                            // Sequential row operations (current bottleneck)
                            for (dst, src) in dst_rows.iter_mut().zip(src_rows.iter()) {
                                row_scale_add(dst, src, coeff);
                            }
                        });
                    },
                );

                // Benchmark batched row operations (optimization)
                if row_count >= 2 {
                    group.bench_with_input(
                        BenchmarkId::new("batched_dual", &bench_name),
                        &(row_count, symbol_size, coeff),
                        |b, &(row_count, symbol_size, coeff)| {
                            // Pre-generate test data
                            let mut dst_rows = Vec::with_capacity(row_count);
                            let mut src_rows = Vec::with_capacity(row_count);

                            for i in 0..row_count {
                                dst_rows.push(vec![(i % 256) as u8; symbol_size]);
                                src_rows.push(vec![((i + 1) % 256) as u8; symbol_size]);
                            }

                            b.iter(|| {
                                // Batched operations using dual-kernel optimization
                                let mut dst_refs: Vec<&mut [u8]> =
                                    dst_rows.iter_mut().map(|v| v.as_mut_slice()).collect();
                                let src_refs: Vec<&[u8]> =
                                    src_rows.iter().map(|v| v.as_slice()).collect();
                                row_scale_add_batch_multi(&mut dst_refs, &src_refs, coeff);
                            });
                        },
                    );
                }
            }
        }
    }

    group.finish();
}

fn bench_gf256_addmul_slice_pairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_addmul_slice_pairs");
    group.sample_size(30);

    // Test the fundamental dual-kernel optimization at different sizes
    let sizes = [1316, 2632, 5264]; // 1x, 2x, 4x typical RaptorQ symbol sizes
    let coefficients = [Gf256::new(7), Gf256::new(13)];

    for &size in &sizes {
        for &coeff in &coefficients {
            let bench_name = format!("size_{}_c_{}", size, coeff.raw());

            group.throughput(Throughput::Bytes((size * 2) as u64)); // Two operations

            // Benchmark two sequential gf256_addmul_slice calls
            group.bench_with_input(
                BenchmarkId::new("two_sequential", &bench_name),
                &(size, coeff),
                |b, &(size, coeff)| {
                    let mut dst_a = vec![0u8; size];
                    let src_a = vec![1u8; size];
                    let mut dst_b = vec![0u8; size];
                    let src_b = vec![2u8; size];

                    b.iter(|| {
                        gf256_addmul_slice(&mut dst_a, &src_a, coeff);
                        gf256_addmul_slice(&mut dst_b, &src_b, coeff);
                    });
                },
            );

            // Benchmark one batched dual-kernel call
            group.bench_with_input(
                BenchmarkId::new("one_batched", &bench_name),
                &(size, coeff),
                |b, &(size, coeff)| {
                    let mut dst_a = vec![0u8; size];
                    let src_a = vec![1u8; size];
                    let mut dst_b = vec![0u8; size];
                    let src_b = vec![2u8; size];

                    b.iter(|| {
                        row_scale_add_batch2(&mut dst_a, &src_a, &mut dst_b, &src_b, coeff);
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_output_color(true);
    targets =
        bench_large_k_encoder_roundtrip,
        bench_e4_decode_vs_k_fixed_total_bytes,
        bench_e4_decode_vs_k_atp_fixed_symbol_size,
        bench_gf256_bulk_operations,
        bench_matrix_operations_stress,
        bench_row_scale_add_batching_optimization,
        bench_gf256_addmul_slice_pairs
);
criterion_main!(benches);
