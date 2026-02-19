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

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{
    Gf256, dual_addmul_kernel_decision, dual_kernel_policy_snapshot, dual_mul_kernel_decision,
    gf256_add_slice, gf256_addmul_slice, gf256_addmul_slices2, gf256_mul_slice, gf256_mul_slices2,
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
    let policy = dual_kernel_policy_snapshot();
    let mul_decision = dual_mul_kernel_decision(scenario.len, scenario.len);
    let addmul_decision = dual_addmul_kernel_decision(scenario.len, scenario.len);
    eprintln!(
        "{{\"schema_version\":\"{}\",\"scenario_id\":\"{}\",\"seed\":{},\"kernel\":\"{:?}\",\"mode\":\"{:?}\",\"mul_window_min\":{},\"mul_window_max\":{},\"addmul_window_min\":{},\"addmul_window_max\":{},\"max_lane_ratio\":{},\"lane_len_a\":{},\"lane_len_b\":{},\"total_len\":{},\"mul_decision\":\"{:?}\",\"addmul_decision\":\"{:?}\",\"artifact_path\":\"{}\",\"repro_command\":\"{}\"}}",
        TRACK_E_POLICY_SCHEMA_VERSION,
        scenario.scenario_id,
        scenario.seed,
        policy.kernel,
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
    let policy = dual_kernel_policy_snapshot();
    let total = scenario.lane_a_len.saturating_add(scenario.lane_b_len);
    let lane_ratio = lane_ratio_string(scenario.lane_a_len, scenario.lane_b_len);
    eprintln!(
        "{{\"schema_version\":\"{}\",\"scenario_id\":\"{}\",\"seed\":{},\"kernel\":\"{:?}\",\"mode\":\"{:?}\",\"lane_len_a\":{},\"lane_len_b\":{},\"total_len\":{},\"lane_ratio\":\"{}\",\"mul_window_min\":{},\"mul_window_max\":{},\"addmul_window_min\":{},\"addmul_window_max\":{},\"max_lane_ratio\":{},\"mul_decision\":\"{}\",\"addmul_decision\":\"{}\",\"artifact_path\":\"{}\",\"repro_command\":\"{}\"}}",
        TRACK_E_POLICY_PROBE_SCHEMA_VERSION,
        scenario.scenario_id,
        scenario.seed,
        policy.kernel,
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
// Criterion setup
// ============================================================================

criterion_group!(
    benches,
    bench_gf256_primitives,
    bench_gf256_dual_policy,
    bench_linalg_operations,
    bench_gaussian_elimination,
    bench_encode_decode,
);

criterion_main!(benches);
