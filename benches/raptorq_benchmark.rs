//! RaptorQ encode/decode performance benchmarks.
//!
//! This benchmark suite establishes baselines and profiles hot paths for:
//! - GF(256) bulk operations (addmul_slice, mul_slice, add_slice)
//! - Encoder/decoder roundtrip performance
//! - Gaussian elimination phases
//!
//! Follows the optimization loop: baseline → profile → single lever → golden outputs.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use asupersync::raptorq::decoder::{DecodeStats, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{
    Gf256, Gf256ProfilePackId, Gf256ProfilePackManifestSnapshot, dual_addmul_kernel_decision,
    dual_mul_kernel_decision, gf256_add_slice, gf256_addmul_slice, gf256_addmul_slices2,
    gf256_mul_slice, gf256_mul_slices2, gf256_profile_pack_manifest_snapshot,
};
use asupersync::raptorq::linalg::{DenseRow, GaussianSolver, row_scale_add, row_xor};
use asupersync::raptorq::systematic::SystematicEncoder;

const TRACK_E_ARTIFACT_PATH: &str = "artifacts/raptorq_track_e_gf256_bench_v1.json";
const TRACK_E_REPRO_CMD: &str =
    "rch exec -- cargo bench --bench raptorq_benchmark -- gf256_primitives";
const TRACK_E_POLICY_SCHEMA_VERSION: &str = "raptorq-track-e-dual-policy-v1";
const TRACK_E_POLICY_PROBE_SCHEMA_VERSION: &str = "raptorq-track-e-dual-policy-probe-v1";
const TRACK_E_POLICY_PROBE_REPRO_CMD: &str =
    "rch exec -- cargo bench --bench raptorq_benchmark -- gf256_dual_policy";

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

#[derive(Clone, Copy)]
struct Gf256DualPolicyScenario {
    scenario_id: &'static str,
    seed: u64,
    lane_a_len: usize,
    lane_b_len: usize,
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

fn emit_track_e_policy_log(scenario: &Gf256BenchScenario) {
    let manifest = gf256_profile_pack_manifest_snapshot();
    let policy = manifest.active_policy;
    let env = manifest.environment_metadata;
    let (tile_bytes, unroll, prefetch_distance, fusion_shape) =
        selected_candidate_fields(&manifest);
    let mul_decision = dual_mul_kernel_decision(scenario.len, scenario.len);
    let addmul_decision = dual_addmul_kernel_decision(scenario.len, scenario.len);
    eprintln!(
        "{{\"schema_version\":\"{}\",\"manifest_schema_version\":\"{}\",\"profile_schema_version\":\"{}\",\"scenario_id\":\"{}\",\"seed\":{},\"kernel\":\"{:?}\",\"architecture_class\":\"{}\",\"profile_pack\":\"{}\",\"profile_fallback_reason\":\"{}\",\"rejected_profile_packs\":\"{}\",\"profile_catalog_count\":{},\"tuning_candidate_catalog_count\":{},\"active_profile_architecture_class\":\"{}\",\"target_arch\":\"{}\",\"target_os\":\"{}\",\"target_env\":\"{}\",\"target_endian\":\"{}\",\"target_pointer_width_bits\":{},\"tuning_corpus_id\":\"{}\",\"selected_tuning_candidate_id\":\"{}\",\"selected_tuning_tile_bytes\":{},\"selected_tuning_unroll\":{},\"selected_tuning_prefetch_distance\":{},\"selected_tuning_fusion_shape\":\"{}\",\"rejected_tuning_candidate_ids\":\"{}\",\"replay_pointer\":\"{}\",\"command_bundle\":\"{}\",\"mode\":\"{:?}\",\"mul_window_min\":{},\"mul_window_max\":{},\"addmul_window_min\":{},\"addmul_window_max\":{},\"max_lane_ratio\":{},\"lane_len_a\":{},\"lane_len_b\":{},\"total_len\":{},\"mul_decision\":\"{:?}\",\"addmul_decision\":\"{:?}\",\"artifact_path\":\"{}\",\"repro_command\":\"{}\"}}",
        TRACK_E_POLICY_SCHEMA_VERSION,
        manifest.schema_version,
        policy.profile_schema_version,
        scenario.scenario_id,
        scenario.seed,
        policy.kernel,
        policy.architecture_class.as_str(),
        policy.profile_pack.as_str(),
        policy
            .fallback_reason
            .map(|reason| reason.as_str())
            .unwrap_or("none"),
        csv_profile_pack_ids(policy.rejected_candidates),
        manifest.profile_pack_catalog.len(),
        manifest.tuning_candidate_catalog.len(),
        manifest.active_profile_metadata.architecture_class.as_str(),
        env.target_arch,
        env.target_os,
        env.target_env,
        env.target_endian,
        env.target_pointer_width_bits,
        policy.tuning_corpus_id,
        policy.selected_tuning_candidate_id,
        tile_bytes,
        unroll,
        prefetch_distance,
        fusion_shape,
        csv_str_ids(policy.rejected_tuning_candidate_ids),
        policy.replay_pointer,
        policy.command_bundle,
        policy.mode,
        policy.mul_min_total,
        policy.mul_max_total,
        policy.addmul_min_total,
        policy.addmul_max_total,
        policy.max_lane_ratio,
        scenario.len,
        scenario.len,
        scenario.len.saturating_mul(2),
        mul_decision,
        addmul_decision,
        TRACK_E_ARTIFACT_PATH,
        TRACK_E_REPRO_CMD,
    );
}

fn lane_ratio_string(len_a: usize, len_b: usize) -> String {
    let lo = len_a.min(len_b);
    let hi = len_a.max(len_b);
    if lo == 0 {
        return "inf".to_owned();
    }
    #[allow(clippy::cast_precision_loss)]
    let ratio = hi as f64 / lo as f64;
    format!("{ratio:.4}")
}

fn emit_track_e_policy_probe_log(
    scenario: &Gf256DualPolicyScenario,
    mul_decision: &str,
    addmul_decision: &str,
) {
    let manifest = gf256_profile_pack_manifest_snapshot();
    let policy = manifest.active_policy;
    let env = manifest.environment_metadata;
    let (tile_bytes, unroll, prefetch_distance, fusion_shape) =
        selected_candidate_fields(&manifest);
    let total = scenario.lane_a_len.saturating_add(scenario.lane_b_len);
    let lane_ratio = lane_ratio_string(scenario.lane_a_len, scenario.lane_b_len);
    eprintln!(
        "{{\"schema_version\":\"{}\",\"manifest_schema_version\":\"{}\",\"profile_schema_version\":\"{}\",\"scenario_id\":\"{}\",\"seed\":{},\"kernel\":\"{:?}\",\"architecture_class\":\"{}\",\"profile_pack\":\"{}\",\"profile_fallback_reason\":\"{}\",\"rejected_profile_packs\":\"{}\",\"profile_catalog_count\":{},\"tuning_candidate_catalog_count\":{},\"active_profile_architecture_class\":\"{}\",\"target_arch\":\"{}\",\"target_os\":\"{}\",\"target_env\":\"{}\",\"target_endian\":\"{}\",\"target_pointer_width_bits\":{},\"tuning_corpus_id\":\"{}\",\"selected_tuning_candidate_id\":\"{}\",\"selected_tuning_tile_bytes\":{},\"selected_tuning_unroll\":{},\"selected_tuning_prefetch_distance\":{},\"selected_tuning_fusion_shape\":\"{}\",\"rejected_tuning_candidate_ids\":\"{}\",\"replay_pointer\":\"{}\",\"command_bundle\":\"{}\",\"mode\":\"{:?}\",\"lane_len_a\":{},\"lane_len_b\":{},\"total_len\":{},\"lane_ratio\":\"{}\",\"mul_window_min\":{},\"mul_window_max\":{},\"addmul_window_min\":{},\"addmul_window_max\":{},\"max_lane_ratio\":{},\"mul_decision\":\"{}\",\"addmul_decision\":\"{}\",\"artifact_path\":\"{}\",\"repro_command\":\"{}\"}}",
        TRACK_E_POLICY_PROBE_SCHEMA_VERSION,
        manifest.schema_version,
        policy.profile_schema_version,
        scenario.scenario_id,
        scenario.seed,
        policy.kernel,
        policy.architecture_class.as_str(),
        policy.profile_pack.as_str(),
        policy
            .fallback_reason
            .map(|reason| reason.as_str())
            .unwrap_or("none"),
        csv_profile_pack_ids(policy.rejected_candidates),
        manifest.profile_pack_catalog.len(),
        manifest.tuning_candidate_catalog.len(),
        manifest.active_profile_metadata.architecture_class.as_str(),
        env.target_arch,
        env.target_os,
        env.target_env,
        env.target_endian,
        env.target_pointer_width_bits,
        policy.tuning_corpus_id,
        policy.selected_tuning_candidate_id,
        tile_bytes,
        unroll,
        prefetch_distance,
        fusion_shape,
        csv_str_ids(policy.rejected_tuning_candidate_ids),
        policy.replay_pointer,
        policy.command_bundle,
        policy.mode,
        scenario.lane_a_len,
        scenario.lane_b_len,
        total,
        lane_ratio,
        policy.mul_min_total,
        policy.mul_max_total,
        policy.addmul_min_total,
        policy.addmul_max_total,
        policy.max_lane_ratio,
        mul_decision,
        addmul_decision,
        TRACK_E_ARTIFACT_PATH,
        TRACK_E_POLICY_PROBE_REPRO_CMD,
    );
}

fn selected_candidate_fields(
    manifest: &Gf256ProfilePackManifestSnapshot,
) -> (usize, usize, usize, &'static str) {
    if let Some(candidate) = manifest.active_selected_tuning_candidate {
        (
            candidate.tile_bytes,
            candidate.unroll,
            candidate.prefetch_distance,
            candidate.fusion_shape,
        )
    } else {
        (0, 0, 0, "unknown")
    }
}

fn csv_profile_pack_ids(ids: &[Gf256ProfilePackId]) -> String {
    if ids.is_empty() {
        return "none".to_owned();
    }
    ids.iter()
        .map(|id| id.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_str_ids(ids: &[&str]) -> String {
    if ids.is_empty() {
        return "none".to_owned();
    }
    ids.join(",")
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
    let mut mul_left_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0x0133_7001);
    let mut mul_right_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0x0133_7002);
    let mut mul_left_expected = mul_left_actual.clone();
    let mut mul_right_expected = mul_right_actual.clone();
    gf256_mul_slices2(&mut mul_left_actual, &mut mul_right_actual, c_val);
    gf256_mul_slice(&mut mul_left_expected, c_val);
    gf256_mul_slice(&mut mul_right_expected, c_val);
    let mul2_ctx = gf256_bench_context(scenario, "mul_slices2_bit_exact");
    assert_eq!(
        mul_left_actual, mul_left_expected,
        "{mul2_ctx} mismatch on lane_a"
    );
    assert_eq!(
        mul_right_actual, mul_right_expected,
        "{mul2_ctx} mismatch on lane_b"
    );

    // Validate fused dual addmul path against sequential baseline.
    let src2 = deterministic_bytes(scenario.len, scenario.seed ^ 0xABCD_0123);
    let mut addmul_left_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0xBEEF_1001);
    let mut addmul_right_actual = deterministic_bytes(scenario.len, scenario.seed ^ 0xBEEF_1002);
    let mut addmul_left_expected = addmul_left_actual.clone();
    let mut addmul_right_expected = addmul_right_actual.clone();
    gf256_addmul_slices2(
        &mut addmul_left_actual,
        src,
        &mut addmul_right_actual,
        &src2,
        c_val,
    );
    gf256_addmul_slice(&mut addmul_left_expected, src, c_val);
    gf256_addmul_slice(&mut addmul_right_expected, &src2, c_val);
    let addmul2_ctx = gf256_bench_context(scenario, "addmul_slices2_bit_exact");
    assert_eq!(
        addmul_left_actual, addmul_left_expected,
        "{addmul2_ctx} mismatch on lane_a"
    );
    assert_eq!(
        addmul_right_actual, addmul_right_expected,
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

fn gf256_dual_policy_scenarios() -> [Gf256DualPolicyScenario; 6] {
    [
        Gf256DualPolicyScenario {
            scenario_id: "RQ-E-GF256-DUAL-001",
            seed: 0x2001,
            lane_a_len: 4096,
            lane_b_len: 4096,
            mul_const: 61,
        },
        Gf256DualPolicyScenario {
            scenario_id: "RQ-E-GF256-DUAL-002",
            seed: 0x2002,
            lane_a_len: 7168,
            lane_b_len: 1024,
            mul_const: 73,
        },
        Gf256DualPolicyScenario {
            scenario_id: "RQ-E-GF256-DUAL-003",
            seed: 0x2003,
            lane_a_len: 7424,
            lane_b_len: 768,
            mul_const: 99,
        },
        Gf256DualPolicyScenario {
            scenario_id: "RQ-E-GF256-DUAL-004",
            seed: 0x2004,
            lane_a_len: 12288,
            lane_b_len: 12288,
            mul_const: 131,
        },
        Gf256DualPolicyScenario {
            scenario_id: "RQ-E-GF256-DUAL-005",
            seed: 0x2005,
            lane_a_len: 15360,
            lane_b_len: 15360,
            mul_const: 149,
        },
        Gf256DualPolicyScenario {
            scenario_id: "RQ-E-GF256-DUAL-006",
            seed: 0x2006,
            lane_a_len: 16384,
            lane_b_len: 16384,
            mul_const: 187,
        },
    ]
}

#[allow(clippy::similar_names)]
fn validate_dual_policy_bit_exactness(scenario: &Gf256DualPolicyScenario, c_val: Gf256) {
    let src_a = deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0xAAAA_1111);
    let src_b = deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0xBBBB_2222);

    let mut mul_a_actual = deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0x1001_0001);
    let mut mul_b_actual = deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0x2002_0002);
    let mut mul_a_expected = mul_a_actual.clone();
    let mut mul_b_expected = mul_b_actual.clone();
    gf256_mul_slices2(&mut mul_a_actual, &mut mul_b_actual, c_val);
    gf256_mul_slice(&mut mul_a_expected, c_val);
    gf256_mul_slice(&mut mul_b_expected, c_val);
    let mul_ctx = format!(
        "dual_policy_mul scenario={} seed={} lane_a={} lane_b={} c={} artifact_path={} repro_cmd='{}'",
        scenario.scenario_id,
        scenario.seed,
        scenario.lane_a_len,
        scenario.lane_b_len,
        scenario.mul_const,
        TRACK_E_ARTIFACT_PATH,
        TRACK_E_POLICY_PROBE_REPRO_CMD
    );
    assert_eq!(mul_a_actual, mul_a_expected, "{mul_ctx} mismatch on lane_a");
    assert_eq!(mul_b_actual, mul_b_expected, "{mul_ctx} mismatch on lane_b");

    let mut addmul_a_actual = deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0x3003_0003);
    let mut addmul_b_actual = deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0x4004_0004);
    let mut addmul_a_expected = addmul_a_actual.clone();
    let mut addmul_b_expected = addmul_b_actual.clone();
    gf256_addmul_slices2(
        &mut addmul_a_actual,
        &src_a,
        &mut addmul_b_actual,
        &src_b,
        c_val,
    );
    gf256_addmul_slice(&mut addmul_a_expected, &src_a, c_val);
    gf256_addmul_slice(&mut addmul_b_expected, &src_b, c_val);
    let addmul_ctx = format!(
        "dual_policy_addmul scenario={} seed={} lane_a={} lane_b={} c={} artifact_path={} repro_cmd='{}'",
        scenario.scenario_id,
        scenario.seed,
        scenario.lane_a_len,
        scenario.lane_b_len,
        scenario.mul_const,
        TRACK_E_ARTIFACT_PATH,
        TRACK_E_POLICY_PROBE_REPRO_CMD
    );
    assert_eq!(
        addmul_a_actual, addmul_a_expected,
        "{addmul_ctx} mismatch on lane_a"
    );
    assert_eq!(
        addmul_b_actual, addmul_b_expected,
        "{addmul_ctx} mismatch on lane_b"
    );
}

// ============================================================================
// GF(256) primitive benchmarks
// ============================================================================

#[allow(clippy::too_many_lines)]
fn bench_gf256_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_primitives");

    // Deterministic scenario matrix for reproducible profiling + parity checks.
    for scenario in gf256_scenarios() {
        group.throughput(Throughput::Bytes(scenario.len as u64));

        let src = deterministic_bytes(scenario.len, scenario.seed);
        let c_val = Gf256::new(scenario.mul_const);
        validate_gf256_bit_exactness(&scenario, &src, c_val);
        emit_track_e_policy_log(&scenario);
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
                let src_b = deterministic_bytes(scenario.len, scenario.seed ^ 0xCAFE_BABE);
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
                let src_b = deterministic_bytes(scenario.len, scenario.seed ^ 0xCAFE_BABE);
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

#[allow(clippy::too_many_lines)]
fn bench_gf256_dual_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_dual_policy");
    for scenario in gf256_dual_policy_scenarios() {
        let c_val = Gf256::new(scenario.mul_const);
        validate_dual_policy_bit_exactness(&scenario, c_val);
        let mul_decision =
            if dual_mul_kernel_decision(scenario.lane_a_len, scenario.lane_b_len).is_fused() {
                "fused"
            } else {
                "sequential"
            };
        let addmul_decision =
            if dual_addmul_kernel_decision(scenario.lane_a_len, scenario.lane_b_len).is_fused() {
                "fused"
            } else {
                "sequential"
            };
        emit_track_e_policy_probe_log(&scenario, mul_decision, addmul_decision);

        let label = format!(
            "{}_a{}_b{}_seed{}",
            scenario.scenario_id, scenario.lane_a_len, scenario.lane_b_len, scenario.seed
        );
        group.throughput(Throughput::Bytes(
            scenario.lane_a_len.saturating_add(scenario.lane_b_len) as u64,
        ));

        let src_a = deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0xAAAA_1111);
        let src_b = deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0xBBBB_2222);

        group.bench_with_input(
            BenchmarkId::new("mul_slices2_auto", &label),
            &scenario,
            |b, _| {
                let mut dst_a =
                    deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0x1001_0001);
                let mut dst_b =
                    deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0x2002_0002);
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
            BenchmarkId::new("mul_slices2_sequential_baseline", &label),
            &scenario,
            |b, _| {
                let mut dst_a =
                    deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0x1001_0001);
                let mut dst_b =
                    deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0x2002_0002);
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

        group.bench_with_input(
            BenchmarkId::new("addmul_slices2_auto", &label),
            &scenario,
            |b, _| {
                let mut dst_a =
                    deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0x3003_0003);
                let mut dst_b =
                    deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0x4004_0004);
                b.iter(|| {
                    gf256_addmul_slices2(
                        std::hint::black_box(&mut dst_a),
                        std::hint::black_box(&src_a),
                        std::hint::black_box(&mut dst_b),
                        std::hint::black_box(&src_b),
                        std::hint::black_box(c_val),
                    );
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("addmul_slices2_sequential_baseline", &label),
            &scenario,
            |b, _| {
                let mut dst_a =
                    deterministic_bytes(scenario.lane_a_len, scenario.seed ^ 0x3003_0003);
                let mut dst_b =
                    deterministic_bytes(scenario.lane_b_len, scenario.seed ^ 0x4004_0004);
                b.iter(|| {
                    gf256_addmul_slice(
                        std::hint::black_box(&mut dst_a),
                        std::hint::black_box(&src_a),
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

fn build_decode_received(
    source: &[Vec<u8>],
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    drop_source_indices: &[usize],
    extra_repair: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let l = decoder.params().l;

    let mut dropped = vec![false; k];
    for &idx in drop_source_indices {
        if idx < k {
            dropped[idx] = true;
        }
    }

    let mut received = Vec::with_capacity(l.saturating_add(extra_repair));
    for (idx, data) in source.iter().enumerate() {
        if !dropped[idx] {
            received.push(ReceivedSymbol::source(idx as u32, data.clone()));
        }
    }

    let required_repairs = l.saturating_sub(received.len());
    let total_repairs = required_repairs.saturating_add(extra_repair);
    let repair_start = k as u32;
    let repair_end = repair_start.saturating_add(total_repairs as u32);
    for esi in repair_start..repair_end {
        let (cols, coefs) = decoder.repair_equation(esi);
        let data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, data));
    }

    received
}

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
            let received = build_decode_received(&source, &encoder, &decoder, &[], 0);

            b.iter(|| {
                let result = decoder.decode(std::hint::black_box(&received));
                std::hint::black_box(result)
            });
        });

        // Benchmark decoding (repair only - worst case for Gaussian elimination)
        group.bench_function(BenchmarkId::new("decode_repair_only", &label), |b| {
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let all_source_dropped: Vec<usize> = (0..k).collect();
            let received =
                build_decode_received(&source, &encoder, &decoder, &all_source_dropped, 0);

            b.iter(|| {
                let result = decoder.decode(std::hint::black_box(&received));
                std::hint::black_box(result)
            });
        });

        // Repair-heavy decode benchmark (drops 75% of source symbols, then adds repair margin).
        group.bench_function(BenchmarkId::new("decode_repair_heavy", &label), |b| {
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let heavy_drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
            let received = build_decode_received(&source, &encoder, &decoder, &heavy_drop, 3);

            b.iter(|| {
                let result = decoder.decode(std::hint::black_box(&received));
                std::hint::black_box(result)
            });
        });

        // Near-rank-deficient decode benchmark: clustered 50% source loss with minimal overhead.
        group.bench_function(
            BenchmarkId::new("decode_near_rank_deficient", &label),
            |b| {
                let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
                let decoder = InactivationDecoder::new(k, symbol_size, seed);
                let near_rank_drop: Vec<usize> = (0..(k / 2)).collect();
                let received =
                    build_decode_received(&source, &encoder, &decoder, &near_rank_drop, 1);

                b.iter(|| {
                    let result = decoder.decode(std::hint::black_box(&received));
                    std::hint::black_box(result)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// F4 Repair Campaign: multi-seed sweep with lever-aware structured logging
// ============================================================================

const F4_CAMPAIGN_SCHEMA_VERSION: &str = "raptorq-f4-repair-campaign-v1";
const F4_CAMPAIGN_REPRO_CMD: &str =
    "rch exec -- cargo bench --bench raptorq_benchmark -- repair_campaign";

/// Campaign scenario parameterising one repair-heavy decode configuration.
#[derive(Clone)]
struct RepairCampaignScenario {
    scenario_id: &'static str,
    k: usize,
    symbol_size: usize,
    seed: u64,
    /// Fraction of source symbols to drop (0.0–1.0).
    loss_fraction: f64,
    /// Extra repair symbols beyond exact rank.
    extra_repair: usize,
    /// Which loss pattern to use: "uniform", "clustered", "alternating".
    loss_pattern: &'static str,
}

fn repair_campaign_scenarios() -> Vec<RepairCampaignScenario> {
    vec![
        // Heavy uniform loss with moderate overhead
        RepairCampaignScenario {
            scenario_id: "RQ-F4-CAMP-001",
            k: 32,
            symbol_size: 1024,
            seed: 0xF4_0001,
            loss_fraction: 0.75,
            extra_repair: 3,
            loss_pattern: "uniform",
        },
        // All-repair worst case
        RepairCampaignScenario {
            scenario_id: "RQ-F4-CAMP-002",
            k: 16,
            symbol_size: 1024,
            seed: 0xF4_0002,
            loss_fraction: 1.0,
            extra_repair: 0,
            loss_pattern: "uniform",
        },
        // Near-rank-deficient with clustered loss
        RepairCampaignScenario {
            scenario_id: "RQ-F4-CAMP-003",
            k: 32,
            symbol_size: 1024,
            seed: 0xF4_0003,
            loss_fraction: 0.50,
            extra_repair: 1,
            loss_pattern: "clustered",
        },
        // Large k, alternating loss pattern
        RepairCampaignScenario {
            scenario_id: "RQ-F4-CAMP-004",
            k: 64,
            symbol_size: 256,
            seed: 0xF4_0004,
            loss_fraction: 0.50,
            extra_repair: 2,
            loss_pattern: "alternating",
        },
        // Small k high loss (Gaussian elimination dominant)
        RepairCampaignScenario {
            scenario_id: "RQ-F4-CAMP-005",
            k: 8,
            symbol_size: 256,
            seed: 0xF4_0005,
            loss_fraction: 0.875,
            extra_repair: 1,
            loss_pattern: "uniform",
        },
        // Medium k with extra overhead (should peel well)
        RepairCampaignScenario {
            scenario_id: "RQ-F4-CAMP-006",
            k: 32,
            symbol_size: 1024,
            seed: 0xF4_0006,
            loss_fraction: 0.25,
            extra_repair: 4,
            loss_pattern: "uniform",
        },
    ]
}

fn compute_drop_indices(k: usize, loss_fraction: f64, loss_pattern: &str, seed: u64) -> Vec<usize> {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let n_drop = ((k as f64) * loss_fraction).round() as usize;
    let n_drop = n_drop.min(k);
    match loss_pattern {
        "uniform" => (0..n_drop).collect(),
        "clustered" => (0..n_drop).collect(),
        "alternating" => {
            let mut indices: Vec<usize> = (0..k).filter(|i| i % 2 != 0).collect();
            // If we need more drops, add even indices deterministically.
            let mut extra_seed = seed;
            while indices.len() < n_drop && indices.len() < k {
                extra_seed = extra_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let candidate = (extra_seed as usize) % k;
                if !indices.contains(&candidate) {
                    indices.push(candidate);
                }
            }
            indices.truncate(n_drop);
            indices.sort_unstable();
            indices
        }
        _ => (0..n_drop).collect(),
    }
}

fn emit_campaign_decode_log(scenario: &RepairCampaignScenario, stats: &DecodeStats, outcome: &str) {
    eprintln!(
        "{{\"schema_version\":\"{}\",\"scenario_id\":\"{}\",\"seed\":{},\"k\":{},\"symbol_size\":{},\
         \"loss_fraction\":{:.3},\"loss_pattern\":\"{}\",\"extra_repair\":{},\"outcome\":\"{}\",\
         \"peeled\":{},\"inactivated\":{},\"gauss_ops\":{},\"pivots_selected\":{},\
         \"hard_regime_activated\":{},\"markowitz_pivots\":{},\"hard_regime_fallbacks\":{},\
         \"peel_queue_pushes\":{},\"peel_queue_pops\":{},\"peel_frontier_peak\":{},\
         \"dense_core_rows\":{},\"dense_core_cols\":{},\"dense_core_dropped_rows\":{},\
         \"policy_density_permille\":{},\"policy_rank_deficit_permille\":{},\
         \"policy_inactivation_pressure_permille\":{},\"policy_overhead_ratio_permille\":{},\
         \"policy_budget_exhausted\":{},\
         \"factor_cache_hits\":{},\"factor_cache_misses\":{},\"factor_cache_inserts\":{},\
         \"factor_cache_evictions\":{},\
         \"policy_mode\":\"{}\",\"policy_reason\":\"{}\",\"policy_replay_ref\":\"{}\",\
         \"hard_regime_branch\":\"{}\",\"hard_regime_conservative_fallback_reason\":\"{}\",\
         \"repro_command\":\"{}\"}}",
        F4_CAMPAIGN_SCHEMA_VERSION,
        scenario.scenario_id,
        scenario.seed,
        scenario.k,
        scenario.symbol_size,
        scenario.loss_fraction,
        scenario.loss_pattern,
        scenario.extra_repair,
        outcome,
        stats.peeled,
        stats.inactivated,
        stats.gauss_ops,
        stats.pivots_selected,
        stats.hard_regime_activated,
        stats.markowitz_pivots,
        stats.hard_regime_fallbacks,
        stats.peel_queue_pushes,
        stats.peel_queue_pops,
        stats.peel_frontier_peak,
        stats.dense_core_rows,
        stats.dense_core_cols,
        stats.dense_core_dropped_rows,
        stats.policy_density_permille,
        stats.policy_rank_deficit_permille,
        stats.policy_inactivation_pressure_permille,
        stats.policy_overhead_ratio_permille,
        stats.policy_budget_exhausted,
        stats.factor_cache_hits,
        stats.factor_cache_misses,
        stats.factor_cache_inserts,
        stats.factor_cache_evictions,
        stats.policy_mode.unwrap_or("unknown"),
        stats.policy_reason.unwrap_or("unknown"),
        stats.policy_replay_ref.unwrap_or("unknown"),
        stats.hard_regime_branch.unwrap_or("none"),
        stats
            .hard_regime_conservative_fallback_reason
            .unwrap_or("none"),
        F4_CAMPAIGN_REPRO_CMD,
    );
}

#[allow(clippy::too_many_lines)]
fn bench_repair_campaign(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_campaign");

    for scenario in repair_campaign_scenarios() {
        let source: Vec<Vec<u8>> = (0..scenario.k)
            .map(|i| deterministic_bytes(scenario.symbol_size, scenario.seed ^ (i as u64)))
            .collect();
        let encoder = SystematicEncoder::new(&source, scenario.symbol_size, scenario.seed).unwrap();
        let decoder = InactivationDecoder::new(scenario.k, scenario.symbol_size, scenario.seed);
        let drop_indices = compute_drop_indices(
            scenario.k,
            scenario.loss_fraction,
            scenario.loss_pattern,
            scenario.seed,
        );
        let received = build_decode_received(
            &source,
            &encoder,
            &decoder,
            &drop_indices,
            scenario.extra_repair,
        );

        // Correctness pre-check + structured log emission.
        match decoder.decode(&received) {
            Ok(result) => {
                // Verify source recovery correctness.
                for (i, sym) in result.source.iter().enumerate() {
                    assert_eq!(
                        sym, &source[i],
                        "{} seed={} source[{}] mismatch",
                        scenario.scenario_id, scenario.seed, i
                    );
                }
                emit_campaign_decode_log(&scenario, &result.stats, "ok");
            }
            Err(e) => {
                // Some near-rank-deficient scenarios may fail; log but don't panic.
                eprintln!(
                    "{{\"schema_version\":\"{}\",\"scenario_id\":\"{}\",\"seed\":{},\
                     \"outcome\":\"decode_error\",\"error\":\"{:?}\",\
                     \"repro_command\":\"{}\"}}",
                    F4_CAMPAIGN_SCHEMA_VERSION,
                    scenario.scenario_id,
                    scenario.seed,
                    e,
                    F4_CAMPAIGN_REPRO_CMD,
                );
            }
        }

        let label = format!(
            "{}_k{}_loss{:.0}pct_{}",
            scenario.scenario_id,
            scenario.k,
            scenario.loss_fraction * 100.0,
            scenario.loss_pattern
        );
        group.throughput(Throughput::Bytes(
            (scenario.k * scenario.symbol_size) as u64,
        ));

        // Benchmark decode under this repair regime.
        group.bench_with_input(BenchmarkId::new("decode", &label), &scenario, |b, _| {
            b.iter(|| {
                let result = decoder.decode(std::hint::black_box(&received));
                std::hint::black_box(result)
            });
        });

        // Multi-seed stability sweep: run 8 seeds and log stats for regression detection.
        let sweep_seeds: Vec<u64> = (0..8u64)
            .map(|i| {
                scenario
                    .seed
                    .wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            })
            .collect();
        for sweep_seed in &sweep_seeds {
            let sweep_source: Vec<Vec<u8>> = (0..scenario.k)
                .map(|i| deterministic_bytes(scenario.symbol_size, sweep_seed ^ (i as u64)))
                .collect();
            if let Some(sweep_encoder) =
                SystematicEncoder::new(&sweep_source, scenario.symbol_size, *sweep_seed)
            {
                let sweep_decoder =
                    InactivationDecoder::new(scenario.k, scenario.symbol_size, *sweep_seed);
                let sweep_drops = compute_drop_indices(
                    scenario.k,
                    scenario.loss_fraction,
                    scenario.loss_pattern,
                    *sweep_seed,
                );
                let sweep_received = build_decode_received(
                    &sweep_source,
                    &sweep_encoder,
                    &sweep_decoder,
                    &sweep_drops,
                    scenario.extra_repair,
                );
                if let Ok(sweep_result) = sweep_decoder.decode(&sweep_received) {
                    emit_campaign_decode_log(
                        &RepairCampaignScenario {
                            seed: *sweep_seed,
                            ..scenario.clone()
                        },
                        &sweep_result.stats,
                        "sweep_ok",
                    );
                }
            }
        }
    }

    group.finish();
}

// ============================================================================
// Criterion setup
// ============================================================================

criterion_group!(
    benches,
    bench_gf256_primitives,
    bench_gf256_dual_policy,
    bench_linalg_operations,
    bench_gaussian_elimination,
    bench_encode_decode,
    bench_repair_campaign,
);

criterion_main!(benches);
