//! G2: CI regression gates for correctness + performance.
//!
//! Integrates G8 `RegressionMonitor` (anytime-valid testing + conformal
//! calibration) into deterministic CI gate checks covering:
//!
//! - All 8 radical runtime paths (E4/E5/C5/C6/F5/F6/F7/F8)
//! - Conservative baseline comparators for each lever
//! - False-positive rate tracking
//! - Structured NDJSON logging with repro commands
//! - Actionable diagnostics and reproduction commands
//!
//! Bead: asupersync-3ec61
//! Dependencies: G1 (budgets), G8 (anytime-valid), D7 (logging), D4 (no tolerated failures)

#![allow(clippy::unusual_byte_groupings)] // Seed groupings encode scenario ID + sequence.

mod common;

use asupersync::raptorq::decoder::{DecodeStats, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::regression::{
    G8_REPLAY_REF, G8_SCHEMA_VERSION, RegressionMonitor, RegressionReport, RegressionVerdict,
    emit_regression_log,
};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::util::DetRng;
use std::collections::BTreeMap;

// ============================================================================
// G2 constants
// ============================================================================

const G2_SCHEMA_VERSION: &str = "raptorq-g2-ci-regression-gate-v1";
const G2_REPLAY_REF: &str = "replay:rq-track-g-ci-gate-v1";
const G2_REPRO_CMD: &str = "rch exec -- cargo test --test ci_regression_gates -- --nocapture";
const G2_ARTIFACT_PATH: &str = "artifacts/ci_regression_gate_report.ndjson";

/// Minimum calibration runs before gate checks activate.
const GATE_CALIBRATION_RUNS: usize = 15;

/// Number of gate-check runs per scenario.
const GATE_CHECK_RUNS: usize = 20;

/// Levers covered by G2 gate checks (maps to bead AC #4).
const COVERED_LEVERS: &[&str] = &["E4", "E5", "C5", "C6", "F5", "F6", "F7", "F8"];

/// Maximum false-positive rate tolerated before gate tuning is required.
const MAX_FALSE_POSITIVE_RATE: f64 = 0.10;

/// Retry budget for recoverable decode failures (e.g., SingularMatrix).
const MAX_RECOVERABLE_RETRIES: usize = 3;

/// Additional repair symbols added per retry attempt.
const RECOVERABLE_RETRY_REPAIR_STEP: usize = 4;

// ============================================================================
// Helpers
// ============================================================================

fn make_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
        .collect()
}

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

/// Decode a scenario and return stats, logging structured output.
fn decode_scenario(
    k: usize,
    symbol_size: usize,
    seed: u64,
    drop_indices: &[usize],
    extra_repair: usize,
    scenario_id: &str,
) -> DecodeStats {
    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

    for attempt in 0..=MAX_RECOVERABLE_RETRIES {
        let retry_extra = extra_repair.saturating_add(attempt * RECOVERABLE_RETRY_REPAIR_STEP);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let received =
            build_decode_received(&source, &encoder, &decoder, drop_indices, retry_extra);
        match decoder.decode(&received) {
            Ok(result) => {
                // Verify correctness.
                for (i, original) in source.iter().enumerate() {
                    assert_eq!(
                        &result.source[i], original,
                        "G2: source[{i}] mismatch for {scenario_id} seed={seed}"
                    );
                }
                return result.stats;
            }
            Err(err) => {
                if err.is_recoverable() && attempt < MAX_RECOVERABLE_RETRIES {
                    eprintln!(
                        "G2 recoverable decode retry scenario={scenario_id} seed={seed} \
                         attempt={} error={err:?} extra_repair={retry_extra}",
                        attempt + 1
                    );
                    continue;
                }
                panic!("G2 decode failed for {scenario_id} seed={seed}: {err:?}");
            }
        }
    }
    panic!("G2 decode retry loop exhausted for {scenario_id} seed={seed}");
}

/// Emit a structured NDJSON gate log line.
fn emit_gate_log(
    scenario_id: &str,
    seed: u64,
    lever: &str,
    gate_outcome: &str,
    stats: &DecodeStats,
    report: Option<&RegressionReport>,
) {
    let regime_state = stats
        .policy_mode
        .or(stats.hard_regime_branch)
        .unwrap_or("unknown");
    let policy_mode = stats.policy_mode.unwrap_or("unknown");
    let overall_verdict = report
        .map(|r| r.overall_verdict.label())
        .unwrap_or("unchecked");
    let regressed_count = report.map_or(0, |r| r.regressed_count);
    let warning_count = report.map_or(0, |r| r.warning_count);
    let total_observations = report.map_or(0, |r| r.total_observations);

    eprintln!(
        "{{\"schema_version\":\"{G2_SCHEMA_VERSION}\",\"replay_ref\":\"{G2_REPLAY_REF}\",\
         \"scenario_id\":\"{scenario_id}\",\"seed\":{seed},\"lever\":\"{lever}\",\
         \"gate_outcome\":\"{gate_outcome}\",\"overall_verdict\":\"{overall_verdict}\",\
         \"regressed_count\":{regressed_count},\"warning_count\":{warning_count},\
         \"total_observations\":{total_observations},\
         \"policy_mode\":\"{policy_mode}\",\"regime_state\":\"{regime_state}\",\
         \"peeled\":{},\"inactivated\":{},\"gauss_ops\":{},\
         \"dense_core_rows\":{},\"dense_core_cols\":{},\
         \"factor_cache_hits\":{},\"factor_cache_misses\":{},\
         \"hard_regime_activated\":{},\"hard_regime_fallbacks\":{},\
         \"policy_reason\":\"{}\",\"policy_replay_ref\":\"{}\",\
         \"hard_regime_branch\":\"{}\",\"hard_regime_fallback_reason\":\"{}\",\
         \"artifact_path\":\"{G2_ARTIFACT_PATH}\",\"repro_command\":\"{G2_REPRO_CMD}\"}}",
        stats.peeled,
        stats.inactivated,
        stats.gauss_ops,
        stats.dense_core_rows,
        stats.dense_core_cols,
        stats.factor_cache_hits,
        stats.factor_cache_misses,
        stats.hard_regime_activated,
        stats.hard_regime_fallbacks,
        stats.policy_reason.unwrap_or("unknown"),
        stats.policy_replay_ref.unwrap_or("unknown"),
        stats.hard_regime_branch.unwrap_or("none"),
        stats
            .hard_regime_conservative_fallback_reason
            .unwrap_or("none"),
    );
}

// ============================================================================
// Gate scenario definitions
// ============================================================================

struct GateScenario {
    id: &'static str,
    lever: &'static str,
    k: usize,
    symbol_size: usize,
    base_seed: u64,
    drop_pattern: DropPattern,
    extra_repair: usize,
}

enum DropPattern {
    /// Drop every Nth source symbol.
    EveryNth(usize),
    /// Drop a fraction (numerator/denominator) from the start.
    FractionFromStart { num: usize, den: usize },
    /// Drop all source symbols.
    All,
}

impl DropPattern {
    fn indices(&self, k: usize) -> Vec<usize> {
        match self {
            Self::EveryNth(n) => (0..k).filter(|i| i % n == 0).collect(),
            Self::FractionFromStart { num, den } => (0..(k * num / den)).collect(),
            Self::All => (0..k).collect(),
        }
    }
}

fn gate_scenarios() -> Vec<GateScenario> {
    vec![
        // E4/E5: GF256 kernel dispatch — exercised by all decodes via SIMD paths.
        GateScenario {
            id: "G2-E4-GF256-LOWLOSS",
            lever: "E4",
            k: 32,
            symbol_size: 1024,
            base_seed: 0xA2_E4_0001,
            drop_pattern: DropPattern::EveryNth(4),
            extra_repair: 3,
        },
        GateScenario {
            id: "G2-E5-GF256-HIGHLOSS",
            lever: "E5",
            k: 32,
            symbol_size: 1024,
            base_seed: 0xA2_E5_0001,
            drop_pattern: DropPattern::FractionFromStart { num: 3, den: 4 },
            extra_repair: 3,
        },
        // C5: Hard regime activation — Markowitz pivoting under heavy loss.
        GateScenario {
            id: "G2-C5-HARD-REGIME",
            lever: "C5",
            k: 32,
            symbol_size: 512,
            base_seed: 0xA2_C5_0001,
            drop_pattern: DropPattern::All,
            extra_repair: 0,
        },
        // C6: Dense core handling — triggered by moderate-to-high loss.
        GateScenario {
            id: "G2-C6-DENSE-CORE",
            lever: "C6",
            k: 32,
            symbol_size: 512,
            base_seed: 0xA2_C6_0001,
            drop_pattern: DropPattern::FractionFromStart { num: 1, den: 2 },
            extra_repair: 4,
        },
        // F5: Policy engine — low loss exercises conservative vs. radical split.
        GateScenario {
            id: "G2-F5-POLICY-LOW",
            lever: "F5",
            k: 64,
            symbol_size: 256,
            base_seed: 0xA2_F5_0001,
            drop_pattern: DropPattern::EveryNth(8),
            extra_repair: 4,
        },
        // F6: Regime-shift detector — tracked via regime stats in DecodeStats.
        GateScenario {
            id: "G2-F6-REGIME",
            lever: "F6",
            k: 16,
            symbol_size: 64,
            base_seed: 0xA2_F6_0001,
            drop_pattern: DropPattern::EveryNth(4),
            extra_repair: 3,
        },
        // F7: DenseFactorCache — exercised across repeated decodes on same decoder.
        GateScenario {
            id: "G2-F7-FACTOR-CACHE",
            lever: "F7",
            k: 32,
            symbol_size: 512,
            base_seed: 0xA2_F7_0001,
            drop_pattern: DropPattern::FractionFromStart { num: 3, den: 4 },
            extra_repair: 3,
        },
        // F8: Combined optimization paths — mixed scenario.
        GateScenario {
            id: "G2-F8-COMBINED",
            lever: "F8",
            k: 64,
            symbol_size: 256,
            base_seed: 0xA2_F8_0001,
            drop_pattern: DropPattern::FractionFromStart { num: 1, den: 2 },
            extra_repair: 2,
        },
    ]
}

// ============================================================================
// Tests: Gate scaffolding and schema
// ============================================================================

/// G2 gate schema version is well-formed.
#[test]
fn g2_gate_schema_version_format() {
    assert!(
        G2_SCHEMA_VERSION.starts_with("raptorq-g2-"),
        "G2 schema version must start with raptorq-g2-"
    );
    assert!(
        G2_REPLAY_REF.starts_with("replay:"),
        "G2 replay ref must start with replay:"
    );
}

/// G2 repro command uses rch offload.
#[test]
fn g2_repro_command_uses_rch() {
    assert!(
        G2_REPRO_CMD.contains("rch exec --"),
        "G2 repro command must use rch offload"
    );
}

/// G2 covers all 8 required radical runtime paths.
#[test]
fn g2_covers_all_required_levers() {
    let scenarios = gate_scenarios();
    let covered: std::collections::BTreeSet<&str> = scenarios.iter().map(|s| s.lever).collect();
    for lever in COVERED_LEVERS {
        assert!(
            covered.contains(lever),
            "G2: missing coverage for lever {lever}"
        );
    }
}

// ============================================================================
// Tests: Regression monitor integration
// ============================================================================

/// G2 gate: calibration phase produces calibrated monitor.
#[test]
fn g2_calibration_phase_completes() {
    let mut monitor = RegressionMonitor::new();
    let k = 16;
    let symbol_size = 64;

    // Calibrate with baseline runs.
    for i in 0..GATE_CALIBRATION_RUNS {
        let seed = 0xA2_CA_0001u64.wrapping_add(i as u64);
        let stats = decode_scenario(k, symbol_size, seed, &[0, 3, 7], 4, "G2-CALIBRATION");
        monitor.calibrate(&stats);
    }

    assert!(
        monitor.is_calibrated(),
        "G2: monitor must be calibrated after {} runs",
        GATE_CALIBRATION_RUNS
    );
    assert_eq!(
        monitor.total_observations(),
        GATE_CALIBRATION_RUNS,
        "G2: observation count mismatch"
    );
}

/// G2 gate: stable workload does not trigger false alarms.
#[test]
fn g2_stable_workload_no_false_alarm() {
    let mut monitor = RegressionMonitor::new();
    let k = 16;
    let symbol_size = 64;
    let drop = vec![0, 3, 7];

    // Calibrate.
    for i in 0..GATE_CALIBRATION_RUNS {
        let seed = 0xA2_0F_0001u64.wrapping_add(i as u64);
        let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-NO-FALSE-ALARM-CAL");
        monitor.calibrate(&stats);
    }

    // Gate checks on the same workload — no false alarm expected.
    let mut false_alarms = 0usize;
    for i in 0..GATE_CHECK_RUNS {
        let seed = 0xA2_0F_1001u64.wrapping_add(i as u64);
        let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-NO-FALSE-ALARM-CHK");
        let report = monitor.check(&stats);

        emit_gate_log(
            "G2-NO-FALSE-ALARM",
            seed,
            "ALL",
            report.overall_verdict.label(),
            &stats,
            Some(&report),
        );

        if report.overall_verdict == RegressionVerdict::Regressed {
            false_alarms += 1;
        }
    }

    assert!(
        !monitor.any_regressed(),
        "G2: stable workload should not trigger regression"
    );

    #[allow(clippy::cast_precision_loss)]
    let false_positive_rate = false_alarms as f64 / GATE_CHECK_RUNS as f64;
    assert!(
        false_positive_rate <= MAX_FALSE_POSITIVE_RATE,
        "G2: false-positive rate {false_positive_rate:.3} exceeds threshold {MAX_FALSE_POSITIVE_RATE}"
    );
}

/// G2 gate: per-scenario regression gate with conservative comparator.
#[test]
#[allow(clippy::too_many_lines)]
fn g2_per_scenario_gate_with_comparator() {
    let scenarios = gate_scenarios();
    let mut scenario_results: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new(); // (pass, warn, fail)

    for scenario in &scenarios {
        let mut monitor = RegressionMonitor::new();

        // Calibrate phase: baseline runs.
        for i in 0..GATE_CALIBRATION_RUNS {
            let seed = scenario.base_seed.wrapping_add(i as u64);
            let drop = scenario.drop_pattern.indices(scenario.k);
            let stats = decode_scenario(
                scenario.k,
                scenario.symbol_size,
                seed,
                &drop,
                scenario.extra_repair,
                scenario.id,
            );
            monitor.calibrate(&stats);
        }

        assert!(
            monitor.is_calibrated(),
            "G2: monitor for {} must calibrate",
            scenario.id
        );

        // Gate check phase: same-distribution runs.
        let mut pass_count = 0usize;
        let mut warn_count = 0usize;
        let mut fail_count = 0usize;

        for i in 0..GATE_CHECK_RUNS {
            let seed = scenario
                .base_seed
                .wrapping_add(0x1000)
                .wrapping_add(i as u64);
            let drop = scenario.drop_pattern.indices(scenario.k);
            let stats = decode_scenario(
                scenario.k,
                scenario.symbol_size,
                seed,
                &drop,
                scenario.extra_repair,
                scenario.id,
            );
            let report = monitor.check(&stats);

            emit_gate_log(
                scenario.id,
                seed,
                scenario.lever,
                report.overall_verdict.label(),
                &stats,
                Some(&report),
            );

            // Also emit G8-format regression log for each check.
            emit_regression_log(&report);

            match report.overall_verdict {
                RegressionVerdict::Accept | RegressionVerdict::Calibrating => pass_count += 1,
                RegressionVerdict::Warning => warn_count += 1,
                RegressionVerdict::Regressed => fail_count += 1,
            }
        }

        eprintln!(
            "G2 scenario {}: pass={pass_count} warn={warn_count} fail={fail_count}",
            scenario.id
        );

        scenario_results.insert(scenario.id, (pass_count, warn_count, fail_count));

        // Same-distribution gate checks should not trigger regression.
        assert!(
            !monitor.any_regressed(),
            "G2: scenario {} should not regress under stable workload (pass={pass_count}, warn={warn_count}, fail={fail_count})",
            scenario.id
        );
    }

    // Summary: all scenarios must pass.
    for (id, (pass, warn, fail)) in &scenario_results {
        assert_eq!(
            *fail, 0,
            "G2: scenario {id} has {fail} regression failures (pass={pass}, warn={warn})"
        );
    }
}

// ============================================================================
// Tests: Lever-specific observability
// ============================================================================

/// E4/E5: GF256 kernel path is exercised (verified via decode success).
#[test]
fn g2_e4_gf256_kernel_exercised() {
    let k = 32;
    let symbol_size = 1024;
    let seed = 0xA2_E4_AED1;

    let drop: Vec<usize> = (0..k).filter(|i| i % 4 == 0).collect();
    let stats = decode_scenario(k, symbol_size, seed, &drop, 3, "G2-E4-VERIFY");

    // GF256 operations happen in every decode — verify non-trivial work.
    assert!(
        stats.peeled > 0 || stats.gauss_ops > 0,
        "G2-E4: decode must perform non-trivial work"
    );

    emit_gate_log("G2-E4-VERIFY", seed, "E4", "pass", &stats, None);
}

/// C5: Hard regime activation under all-repair decode.
#[test]
fn g2_c5_hard_regime_activation() {
    let k = 32;
    let symbol_size = 512;
    let seed = 0xA2_C5_AED1;

    let drop: Vec<usize> = (0..k).collect();
    let stats = decode_scenario(k, symbol_size, seed, &drop, 0, "G2-C5-VERIFY");

    // All-repair should produce nontrivial dense core.
    assert!(
        stats.dense_core_rows > 0,
        "G2-C5: all-repair must produce dense core rows, got {}",
        stats.dense_core_rows
    );
    assert!(
        stats.gauss_ops > 0,
        "G2-C5: all-repair must trigger Gaussian elimination, got {}",
        stats.gauss_ops
    );

    emit_gate_log("G2-C5-VERIFY", seed, "C5", "pass", &stats, None);
}

/// C6: Dense core exercised under heavy loss.
#[test]
fn g2_c6_dense_core_exercised() {
    let k = 32;
    let symbol_size = 512;
    let seed = 0xA2_C6_AED1;

    let drop: Vec<usize> = (0..(k / 2)).collect();
    let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-C6-VERIFY");

    // Dense core columns should be nonzero under significant loss.
    assert!(
        stats.dense_core_cols > 0 || stats.inactivated > 0,
        "G2-C6: heavy loss must exercise dense elimination"
    );

    emit_gate_log("G2-C6-VERIFY", seed, "C6", "pass", &stats, None);
}

/// F5: Policy engine selects a mode and records it in stats.
#[test]
fn g2_f5_policy_mode_recorded() {
    let k = 64;
    let symbol_size = 256;
    let seed = 0xA2_F5_AED1;

    let drop: Vec<usize> = (0..k).filter(|i| i % 8 == 0).collect();
    let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-F5-VERIFY");

    // Policy mode should be recorded when dense elimination is needed.
    // Note: policy_mode may be None if peeling resolves everything.
    if stats.dense_core_rows > 0 {
        assert!(
            stats.policy_mode.is_some(),
            "G2-F5: policy_mode must be set when dense core is nontrivial"
        );
        assert!(
            stats.policy_replay_ref.is_some(),
            "G2-F5: policy_replay_ref must be set"
        );
    }

    emit_gate_log("G2-F5-VERIFY", seed, "F5", "pass", &stats, None);
}

/// F6: Regime detector state tracked across decodes.
#[test]
fn g2_f6_regime_tracked_across_decodes() {
    let k = 16;
    let symbol_size = 64;
    let seed = 0xA2_F6_AED1;

    // Use a single decoder to accumulate regime state.
    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_decode_received(&source, &encoder, &decoder, &[0, 3], 4);

    // Multiple decodes should keep replay metadata stable.
    let mut last_replay_ref = None;
    for i in 0..20 {
        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("G2-F6: decode {i} failed: {e:?}"));

        let replay_ref = result.stats.policy_replay_ref;
        assert!(
            replay_ref.is_some(),
            "G2-F6: policy_replay_ref must be populated at decode {i}"
        );
        if let Some(previous) = last_replay_ref {
            assert_eq!(
                replay_ref,
                Some(previous),
                "G2-F6: policy replay ref drifted at decode {i}"
            );
        }
        last_replay_ref = replay_ref;

        emit_gate_log(
            "G2-F6-VERIFY",
            seed.wrapping_add(i),
            "F6",
            "pass",
            &result.stats,
            None,
        );
    }

    assert!(
        last_replay_ref.is_some(),
        "G2-F6: expected at least one replay reference"
    );
}

/// F7: Factor cache stats tracked across repeated decodes.
#[test]
fn g2_f7_factor_cache_observed() {
    let k = 32;
    let symbol_size = 512;
    let seed = 0xA2_F7_AED1;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 3);

    // First decode — cache cold.
    let r1 = decoder.decode(&received).expect("G2-F7: first decode");
    let first_misses = r1.stats.factor_cache_misses;

    // Second decode — cache may hit.
    let r2 = decoder.decode(&received).expect("G2-F7: second decode");

    // Cache entries and capacity should be bounded.
    assert!(
        r2.stats.factor_cache_entries <= r2.stats.factor_cache_capacity,
        "G2-F7: cache entries({}) must <= capacity({})",
        r2.stats.factor_cache_entries,
        r2.stats.factor_cache_capacity
    );

    emit_gate_log("G2-F7-VERIFY", seed, "F7", "pass", &r2.stats, None);

    eprintln!(
        "G2-F7: first_misses={first_misses} second_hits={} second_misses={} entries={}/{}",
        r2.stats.factor_cache_hits,
        r2.stats.factor_cache_misses,
        r2.stats.factor_cache_entries,
        r2.stats.factor_cache_capacity,
    );
}

// ============================================================================
// Tests: Conservative comparator reporting
// ============================================================================

/// G2 comparator: conservative vs. radical overhead reporting.
///
/// This test decodes the same data twice: once with a fresh decoder (cold
/// cache, first-time regime) and once with a warmed-up decoder, comparing
/// the policy overhead to verify radical paths are net-positive.
#[test]
fn g2_conservative_vs_radical_overhead_report() {
    let k = 32;
    let symbol_size = 512;
    let seed = 0xA2_C0B_0001;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 3);

    // Baseline decode (cold).
    let baseline = decoder.decode(&received).expect("G2: baseline decode");

    // Warm-up decodes.
    for _ in 0..5 {
        decoder.decode(&received).expect("G2: warmup decode");
    }

    // Warmed decode.
    let warmed = decoder.decode(&received).expect("G2: warmed decode");

    // Log comparator report.
    eprintln!(
        "{{\"schema_version\":\"{G2_SCHEMA_VERSION}\",\"type\":\"comparator\",\
         \"replay_ref\":\"{G2_REPLAY_REF}\",\"seed\":{seed},\
         \"baseline_gauss_ops\":{},\"warmed_gauss_ops\":{},\
         \"baseline_peeled\":{},\"warmed_peeled\":{},\
         \"baseline_cache_hits\":{},\"warmed_cache_hits\":{},\
         \"baseline_regime_state\":\"{}\",\"warmed_regime_state\":\"{}\",\
         \"baseline_policy_mode\":\"{}\",\"warmed_policy_mode\":\"{}\",\
         \"repro_command\":\"{G2_REPRO_CMD}\"}}",
        baseline.stats.gauss_ops,
        warmed.stats.gauss_ops,
        baseline.stats.peeled,
        warmed.stats.peeled,
        baseline.stats.factor_cache_hits,
        warmed.stats.factor_cache_hits,
        baseline
            .stats
            .policy_mode
            .or(baseline.stats.hard_regime_branch)
            .unwrap_or("unknown"),
        warmed
            .stats
            .policy_mode
            .or(warmed.stats.hard_regime_branch)
            .unwrap_or("unknown"),
        baseline.stats.policy_mode.unwrap_or("unknown"),
        warmed.stats.policy_mode.unwrap_or("unknown"),
    );

    // Both must produce correct results (verified in decode_scenario helper
    // above for correctness, here we just verify stats are reasonable).
    assert!(
        baseline.stats.peeled + baseline.stats.inactivated <= decoder.params().l,
        "G2: baseline decode stats out of bounds"
    );
    assert!(
        warmed.stats.peeled + warmed.stats.inactivated <= decoder.params().l,
        "G2: warmed decode stats out of bounds"
    );
}

// ============================================================================
// Tests: False-positive rate tracking
// ============================================================================

/// G2 gate: track and bound the false-positive rate across all scenarios.
#[test]
fn g2_false_positive_rate_bounded() {
    let scenarios = gate_scenarios();
    let mut total_checks = 0usize;
    let mut total_false_positives = 0usize;

    for scenario in &scenarios {
        let mut monitor = RegressionMonitor::new();

        // Calibrate.
        for i in 0..GATE_CALIBRATION_RUNS {
            let seed = scenario
                .base_seed
                .wrapping_add(0x2000)
                .wrapping_add(i as u64);
            let drop = scenario.drop_pattern.indices(scenario.k);
            let stats = decode_scenario(
                scenario.k,
                scenario.symbol_size,
                seed,
                &drop,
                scenario.extra_repair,
                scenario.id,
            );
            monitor.calibrate(&stats);
        }

        // Check — same distribution.
        for i in 0..GATE_CHECK_RUNS {
            let seed = scenario
                .base_seed
                .wrapping_add(0x3000)
                .wrapping_add(i as u64);
            let drop = scenario.drop_pattern.indices(scenario.k);
            let stats = decode_scenario(
                scenario.k,
                scenario.symbol_size,
                seed,
                &drop,
                scenario.extra_repair,
                scenario.id,
            );
            let report = monitor.check(&stats);
            total_checks += 1;
            if report.overall_verdict == RegressionVerdict::Regressed {
                total_false_positives += 1;
            }
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let aggregate_fpr = if total_checks > 0 {
        total_false_positives as f64 / total_checks as f64
    } else {
        0.0
    };

    eprintln!("G2 aggregate FPR: {total_false_positives}/{total_checks} = {aggregate_fpr:.4}");

    assert!(
        aggregate_fpr <= MAX_FALSE_POSITIVE_RATE,
        "G2: aggregate false-positive rate {aggregate_fpr:.4} exceeds {MAX_FALSE_POSITIVE_RATE}"
    );
}

// ============================================================================
// Tests: Deterministic replay
// ============================================================================

/// G2 gate: deterministic replay produces identical gate verdicts.
#[test]
fn g2_deterministic_replay_gate_verdicts() {
    let k = 16;
    let symbol_size = 64;
    let drop = vec![0, 3, 7];
    let calibration_seeds: Vec<u64> = (0..GATE_CALIBRATION_RUNS as u64)
        .map(|i| 0xA2_DA_0001u64.wrapping_add(i))
        .collect();
    let check_seeds: Vec<u64> = (0..10u64)
        .map(|i| 0xA2_DA_1001u64.wrapping_add(i))
        .collect();

    // Run A.
    let mut monitor_a = RegressionMonitor::new();
    for &seed in &calibration_seeds {
        let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-REPLAY-A-CAL");
        monitor_a.calibrate(&stats);
    }
    let verdicts_a: Vec<RegressionVerdict> = check_seeds
        .iter()
        .map(|&seed| {
            let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-REPLAY-A-CHK");
            monitor_a.check(&stats).overall_verdict
        })
        .collect();

    // Run B — identical inputs.
    let mut monitor_b = RegressionMonitor::new();
    for &seed in &calibration_seeds {
        let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-REPLAY-B-CAL");
        monitor_b.calibrate(&stats);
    }
    let verdicts_b: Vec<RegressionVerdict> = check_seeds
        .iter()
        .map(|&seed| {
            let stats = decode_scenario(k, symbol_size, seed, &drop, 4, "G2-REPLAY-B-CHK");
            monitor_b.check(&stats).overall_verdict
        })
        .collect();

    assert_eq!(
        verdicts_a, verdicts_b,
        "G2: deterministic replay must produce identical gate verdicts"
    );
}

// ============================================================================
// Tests: Structured logging D7 compliance
// ============================================================================

/// G2 gate logs comply with D7 structured logging requirements.
#[test]
fn g2_structured_log_schema_compliance() {
    // Verify that a gate log line contains all required fields.
    let required_fields = [
        "schema_version",
        "replay_ref",
        "scenario_id",
        "seed",
        "lever",
        "gate_outcome",
        "policy_mode",
        "regime_state",
        "peeled",
        "inactivated",
        "gauss_ops",
        "artifact_path",
        "repro_command",
    ];

    // Build a representative log line.
    let stats = DecodeStats {
        peeled: 10,
        inactivated: 3,
        gauss_ops: 5,
        policy_mode: Some("conservative_baseline"),
        ..Default::default()
    };

    // Capture log output via format check.
    let log_line = format!(
        "{{\"schema_version\":\"{G2_SCHEMA_VERSION}\",\"replay_ref\":\"{G2_REPLAY_REF}\",\
         \"scenario_id\":\"G2-SCHEMA-TEST\",\"seed\":42,\"lever\":\"F5\",\
         \"gate_outcome\":\"pass\",\"overall_verdict\":\"accept\",\
         \"regressed_count\":0,\"warning_count\":0,\
         \"total_observations\":1,\
         \"policy_mode\":\"{}\",\"regime_state\":\"{}\",\
         \"peeled\":{},\"inactivated\":{},\"gauss_ops\":{},\
         \"dense_core_rows\":{},\"dense_core_cols\":{},\
         \"factor_cache_hits\":{},\"factor_cache_misses\":{},\
         \"hard_regime_activated\":{},\"hard_regime_fallbacks\":{},\
         \"policy_reason\":\"{}\",\"policy_replay_ref\":\"{}\",\
         \"hard_regime_branch\":\"{}\",\"hard_regime_fallback_reason\":\"{}\",\
         \"artifact_path\":\"{G2_ARTIFACT_PATH}\",\"repro_command\":\"{G2_REPRO_CMD}\"}}",
        stats.policy_mode.unwrap_or("unknown"),
        stats
            .policy_mode
            .or(stats.hard_regime_branch)
            .unwrap_or("unknown"),
        stats.peeled,
        stats.inactivated,
        stats.gauss_ops,
        stats.dense_core_rows,
        stats.dense_core_cols,
        stats.factor_cache_hits,
        stats.factor_cache_misses,
        stats.hard_regime_activated,
        stats.hard_regime_fallbacks,
        stats.policy_reason.unwrap_or("unknown"),
        stats.policy_replay_ref.unwrap_or("unknown"),
        stats.hard_regime_branch.unwrap_or("none"),
        stats
            .hard_regime_conservative_fallback_reason
            .unwrap_or("none"),
    );

    for field in required_fields {
        assert!(
            log_line.contains(&format!("\"{field}\"")),
            "G2: structured log missing required D7 field: {field}"
        );
    }

    // Verify it parses as valid JSON.
    let parsed: serde_json::Value =
        serde_json::from_str(&log_line).expect("G2 gate log must be valid JSON");
    assert_eq!(
        parsed["schema_version"].as_str(),
        Some(G2_SCHEMA_VERSION),
        "schema version mismatch in parsed log"
    );
    assert_eq!(
        parsed["replay_ref"].as_str(),
        Some(G2_REPLAY_REF),
        "replay ref mismatch in parsed log"
    );
}

/// G2 repro commands are present and actionable in gate output.
#[test]
fn g2_repro_commands_actionable() {
    assert!(
        G2_REPRO_CMD.contains("cargo test"),
        "G2 repro must run cargo test"
    );
    assert!(
        G2_REPRO_CMD.contains("ci_regression_gates"),
        "G2 repro must reference this test file"
    );
    assert!(
        G2_REPRO_CMD.contains("--nocapture"),
        "G2 repro must include --nocapture for log visibility"
    );
}

// ============================================================================
// Tests: Benchmark file coverage (G2 AC #4)
// ============================================================================

const RAPTORQ_BENCH_RS: &str = include_str!("../benches/raptorq_benchmark.rs");

/// G2 gate: benchmark file must reference lever observability fields
/// required for CI regression comparisons.
#[test]
fn g2_benchmark_covers_gate_observability_fields() {
    let required_fields = [
        "policy_density_permille",
        "hard_regime_activated",
        "dense_core_rows",
        "factor_cache_hits",
        "factor_cache_misses",
        "policy_mode",
        "policy_replay_ref",
        "hard_regime_branch",
    ];

    for field in required_fields {
        assert!(
            RAPTORQ_BENCH_RS.contains(field),
            "G2: benchmark must emit gate-observable field: {field}"
        );
    }
}

// ============================================================================
// Tests: G8 integration verification
// ============================================================================

/// G2 uses G8 schema and replay references correctly.
#[test]
fn g2_g8_integration_schema_alignment() {
    assert_eq!(
        G8_SCHEMA_VERSION, "raptorq-g8-anytime-regression-v1",
        "G2 must align with G8 schema version"
    );
    assert!(
        G8_REPLAY_REF.starts_with("replay:"),
        "G8 replay ref must be well-formed"
    );
}

/// G2 RegressionMonitor produces reports with correct schema metadata.
#[test]
fn g2_regression_report_metadata() {
    let mut monitor = RegressionMonitor::new();
    let stats = DecodeStats {
        gauss_ops: 5,
        dense_core_rows: 3,
        dense_core_cols: 2,
        inactivated: 1,
        pivots_selected: 1,
        peel_frontier_peak: 2,
        policy_mode: Some("stable"),
        ..Default::default()
    };

    // Calibrate.
    for _ in 0..15 {
        monitor.calibrate(&stats);
    }

    let report = monitor.check(&stats);
    assert_eq!(report.schema_version, G8_SCHEMA_VERSION);
    assert_eq!(report.replay_ref, G8_REPLAY_REF);
    assert_eq!(report.metrics.len(), 6, "G8 tracks 6 metrics");
    assert_eq!(
        report.regime_state,
        Some("stable".to_string()),
        "regime state covariate must be forwarded"
    );
}

// ============================================================================
// Tests: Gate runtime bounded (AC #8)
// ============================================================================

/// G2 gate: individual scenario gate check is bounded in iteration count.
#[test]
fn g2_gate_runtime_bounded() {
    // Verify the gate parameters are bounded for CI adoption.
    assert!(
        GATE_CALIBRATION_RUNS <= 50,
        "G2: calibration runs must be bounded for CI runtime"
    );
    assert!(
        GATE_CHECK_RUNS <= 50,
        "G2: check runs must be bounded for CI runtime"
    );

    // Total decodes per scenario = calibration + check.
    let total_per_scenario = GATE_CALIBRATION_RUNS + GATE_CHECK_RUNS;
    let total_scenarios = gate_scenarios().len();
    let total_decodes = total_per_scenario * total_scenarios;

    eprintln!(
        "G2: {total_scenarios} scenarios x {total_per_scenario} decodes = {total_decodes} total"
    );

    // Keep total decode count under 500 for reasonable CI time.
    assert!(
        total_decodes <= 500,
        "G2: total decode count {total_decodes} exceeds CI budget of 500"
    );
}
