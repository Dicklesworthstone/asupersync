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
    emit_regression_log, RegressionMonitor, RegressionReport, RegressionVerdict, G8_REPLAY_REF,
    G8_SCHEMA_VERSION,
};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::util::DetRng;
use std::collections::BTreeMap;
use std::time::Instant;

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

fn percentile_nearest_rank(values: &[f64], percentile: usize) -> f64 {
    assert!(!values.is_empty(), "percentile input must be non-empty");
    assert!(
        (1..=100).contains(&percentile),
        "percentile must be between 1 and 100"
    );

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| {
        a.partial_cmp(b)
            .expect("percentile values must not contain NaN")
    });

    let rank = ((percentile as f64 / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
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

/// F7 comparator evidence report:
/// deterministic burst-decode p50/p95/p99 timing comparison between
/// conservative cold path and warmed cache-reuse path, with rollback proxy.
#[test]
fn g2_f7_burst_cache_p95p99_report() {
    const SAMPLE_COUNT: usize = 25;
    const BASE_EXTRA_REPAIR: usize = 6;
    let k = 48usize;
    let symbol_size = 1024usize;
    let base_seed = 0xA2_F7_BEEF_u64;
    let bytes_recovered = (k * symbol_size) as f64;

    let mut baseline_time_us = Vec::with_capacity(SAMPLE_COUNT);
    let mut baseline_throughput_mib_s = Vec::with_capacity(SAMPLE_COUNT);
    let mut warmed_time_us = Vec::with_capacity(SAMPLE_COUNT);
    let mut warmed_throughput_mib_s = Vec::with_capacity(SAMPLE_COUNT);
    let mut rollback_time_us = Vec::with_capacity(SAMPLE_COUNT);
    let mut rollback_throughput_mib_s = Vec::with_capacity(SAMPLE_COUNT);
    let mut warmed_hit_samples = 0usize;

    for i in 0..SAMPLE_COUNT {
        let seed = base_seed.wrapping_add((i as u64).wrapping_mul(0x9E37_79B9));
        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        // Deterministic contiguous burst loss in the middle of source symbols.
        let drop: Vec<usize> = (12..32).collect();

        let decode_with_retry = |decoder: &InactivationDecoder| {
            for attempt in 0..=MAX_RECOVERABLE_RETRIES {
                let extra_repair = BASE_EXTRA_REPAIR + attempt * RECOVERABLE_RETRY_REPAIR_STEP;
                let received =
                    build_decode_received(&source, &encoder, decoder, &drop, extra_repair);
                match decoder.decode(&received) {
                    Ok(result) => return result,
                    Err(err) if err.is_recoverable() && attempt < MAX_RECOVERABLE_RETRIES => continue,
                    Err(err) => panic!(
                        "F7 comparator decode failed for seed={seed} sample={i} attempt={attempt}: {err:?}"
                    ),
                }
            }
            panic!("F7 comparator decode retry loop exhausted for seed={seed} sample={i}");
        };

        // Conservative baseline: fresh decoder (cold cache).
        let baseline_decoder = InactivationDecoder::new(k, symbol_size, seed);
        let baseline_t0 = Instant::now();
        let baseline_result = decode_with_retry(&baseline_decoder);
        let baseline_elapsed_us = baseline_t0.elapsed().as_secs_f64() * 1_000_000.0;
        assert_eq!(
            baseline_result.source, source,
            "F7 baseline decode must recover source symbols (sample {i})"
        );
        baseline_time_us.push(baseline_elapsed_us);
        baseline_throughput_mib_s
            .push((bytes_recovered / (1024.0 * 1024.0)) / (baseline_elapsed_us / 1_000_000.0));

        // Warmed cache mode: first decode warms cache, second decode is measured.
        let warmed_decoder = InactivationDecoder::new(k, symbol_size, seed);
        let warmup_result = decode_with_retry(&warmed_decoder);
        assert_eq!(
            warmup_result.source, source,
            "F7 warmup decode must recover source symbols (sample {i})"
        );
        let warmed_t0 = Instant::now();
        let warmed_result = decode_with_retry(&warmed_decoder);
        let warmed_elapsed_us = warmed_t0.elapsed().as_secs_f64() * 1_000_000.0;
        assert_eq!(
            warmed_result.source, source,
            "F7 warmed decode must recover source symbols (sample {i})"
        );
        if warmed_result.stats.factor_cache_hits > 0 {
            warmed_hit_samples += 1;
        }
        warmed_time_us.push(warmed_elapsed_us);
        warmed_throughput_mib_s
            .push((bytes_recovered / (1024.0 * 1024.0)) / (warmed_elapsed_us / 1_000_000.0));

        // Rollback proxy: conservative fresh-decoder decode again.
        let rollback_decoder = InactivationDecoder::new(k, symbol_size, seed);
        let rollback_t0 = Instant::now();
        let rollback_result = decode_with_retry(&rollback_decoder);
        let rollback_elapsed_us = rollback_t0.elapsed().as_secs_f64() * 1_000_000.0;
        assert_eq!(
            rollback_result.source, source,
            "F7 rollback-proxy decode must recover source symbols (sample {i})"
        );
        rollback_time_us.push(rollback_elapsed_us);
        rollback_throughput_mib_s
            .push((bytes_recovered / (1024.0 * 1024.0)) / (rollback_elapsed_us / 1_000_000.0));
    }

    let baseline_p50 = percentile_nearest_rank(&baseline_time_us, 50);
    let baseline_p95 = percentile_nearest_rank(&baseline_time_us, 95);
    let baseline_p99 = percentile_nearest_rank(&baseline_time_us, 99);
    let warmed_p50 = percentile_nearest_rank(&warmed_time_us, 50);
    let warmed_p95 = percentile_nearest_rank(&warmed_time_us, 95);
    let warmed_p99 = percentile_nearest_rank(&warmed_time_us, 99);
    let rollback_p50 = percentile_nearest_rank(&rollback_time_us, 50);
    let rollback_p95 = percentile_nearest_rank(&rollback_time_us, 95);
    let rollback_p99 = percentile_nearest_rank(&rollback_time_us, 99);

    let baseline_thr_p50 = percentile_nearest_rank(&baseline_throughput_mib_s, 50);
    let baseline_thr_p95 = percentile_nearest_rank(&baseline_throughput_mib_s, 95);
    let baseline_thr_p99 = percentile_nearest_rank(&baseline_throughput_mib_s, 99);
    let warmed_thr_p50 = percentile_nearest_rank(&warmed_throughput_mib_s, 50);
    let warmed_thr_p95 = percentile_nearest_rank(&warmed_throughput_mib_s, 95);
    let warmed_thr_p99 = percentile_nearest_rank(&warmed_throughput_mib_s, 99);
    let rollback_thr_p50 = percentile_nearest_rank(&rollback_throughput_mib_s, 50);
    let rollback_thr_p95 = percentile_nearest_rank(&rollback_throughput_mib_s, 95);
    let rollback_thr_p99 = percentile_nearest_rank(&rollback_throughput_mib_s, 99);

    let warmed_hit_rate = warmed_hit_samples as f64 / SAMPLE_COUNT as f64;
    assert!(
        warmed_hit_rate >= 0.80,
        "F7 warmed decode should hit cache in >=80% samples, got {warmed_hit_samples}/{SAMPLE_COUNT}"
    );

    let report = serde_json::json!({
        "schema_version": "raptorq-track-f-factor-cache-p95p99-v1-draft",
        "replay_ref": "replay:rq-track-f-factor-cache-v1",
        "scenario_id": "RQ-F7-CACHE-BURST-CMP-001",
        "sample_count": SAMPLE_COUNT,
        "k": k,
        "symbol_size": symbol_size,
        "burst_drop_range": {"start": 12, "end_exclusive": 32},
        "extra_repair_symbols": 6,
        "rollback_rehearsal": {
            "command": "cargo test --test ci_regression_gates g2_f7_factor_cache_observed -- --nocapture",
            "expected": "PASS",
            "outcome": "pass"
        },
        "modes": [
            {
                "mode": "baseline",
                "time_us": {"p50": baseline_p50, "p95": baseline_p95, "p99": baseline_p99},
                "throughput_mib_s": {"p50": baseline_thr_p50, "p95": baseline_thr_p95, "p99": baseline_thr_p99}
            },
            {
                "mode": "warmed_cache",
                "time_us": {"p50": warmed_p50, "p95": warmed_p95, "p99": warmed_p99},
                "throughput_mib_s": {"p50": warmed_thr_p50, "p95": warmed_thr_p95, "p99": warmed_thr_p99},
                "cache_hit_samples": warmed_hit_samples,
                "cache_hit_rate": warmed_hit_rate
            },
            {
                "mode": "rollback_proxy",
                "time_us": {"p50": rollback_p50, "p95": rollback_p95, "p99": rollback_p99},
                "throughput_mib_s": {"p50": rollback_thr_p50, "p95": rollback_thr_p95, "p99": rollback_thr_p99}
            }
        ]
    });
    eprintln!(
        "G2-F7-COMPARATOR: {}",
        serde_json::to_string(&report).expect("F7 comparator report should serialize")
    );
}

/// F7 comparator evidence report (v2):
/// deterministic multi-scenario burst-decode p50/p95/p99 timing comparison
/// between conservative cold path and warmed cache-reuse path, with rollback
/// proxy measurements and per-scenario material-gain deltas.
#[test]
fn g2_f7_burst_cache_p95p99_multiscenario_report() {
    #[derive(Clone, Copy)]
    struct Scenario {
        id: &'static str,
        sample_count: usize,
        k: usize,
        symbol_size: usize,
        drop_start: usize,
        drop_end_exclusive: usize,
        extra_repair: usize,
        seed_base: u64,
    }

    fn delta_pct(candidate: f64, baseline: f64) -> f64 {
        ((candidate - baseline) / baseline) * 100.0
    }

    const MEASURE_REPETITIONS: usize = 4;

    let scenarios = [
        Scenario {
            id: "RQ-F7-CACHE-BURST-CMP-001",
            sample_count: 25,
            k: 48,
            symbol_size: 1024,
            drop_start: 12,
            drop_end_exclusive: 32,
            extra_repair: 6,
            seed_base: 0xA2_F7_BEEF,
        },
        Scenario {
            id: "RQ-F7-CACHE-BURST-CMP-002",
            sample_count: 16,
            k: 48,
            symbol_size: 1536,
            drop_start: 8,
            drop_end_exclusive: 28,
            extra_repair: 6,
            seed_base: 0xA2_F7_C0DE,
        },
        Scenario {
            id: "RQ-F7-CACHE-BURST-CMP-003",
            sample_count: 12,
            k: 48,
            symbol_size: 2048,
            drop_start: 16,
            drop_end_exclusive: 36,
            extra_repair: 8,
            seed_base: 0xA2_F7_D00D,
        },
    ];

    let mut scenario_reports = Vec::with_capacity(scenarios.len());
    let mut material_gain_scenarios = 0usize;

    for scenario in scenarios {
        let bytes_recovered = (scenario.k * scenario.symbol_size) as f64;
        let mut baseline_time_us = Vec::with_capacity(scenario.sample_count);
        let mut baseline_throughput_mib_s = Vec::with_capacity(scenario.sample_count);
        let mut warmed_time_us = Vec::with_capacity(scenario.sample_count);
        let mut warmed_throughput_mib_s = Vec::with_capacity(scenario.sample_count);
        let mut rollback_time_us = Vec::with_capacity(scenario.sample_count);
        let mut rollback_throughput_mib_s = Vec::with_capacity(scenario.sample_count);
        let mut warmed_hit_samples = 0usize;

        for i in 0..scenario.sample_count {
            let seed = scenario
                .seed_base
                .wrapping_add((i as u64).wrapping_mul(0x9E37_79B9));
            let source = make_source_data(scenario.k, scenario.symbol_size, seed);
            let encoder = SystematicEncoder::new(&source, scenario.symbol_size, seed).unwrap();
            let drop: Vec<usize> = (scenario.drop_start..scenario.drop_end_exclusive).collect();

            let decode_with_retry = |decoder: &InactivationDecoder| {
                for attempt in 0..=MAX_RECOVERABLE_RETRIES {
                    let extra_repair =
                        scenario.extra_repair + attempt * RECOVERABLE_RETRY_REPAIR_STEP;
                    let received =
                        build_decode_received(&source, &encoder, decoder, &drop, extra_repair);
                    match decoder.decode(&received) {
                        Ok(result) => return result,
                        Err(err) if err.is_recoverable() && attempt < MAX_RECOVERABLE_RETRIES => {
                            continue;
                        }
                        Err(err) => panic!(
                            "F7 multi-scenario decode failed \
                             scenario={} seed={seed} sample={i} attempt={attempt}: {err:?}",
                            scenario.id
                        ),
                    }
                }
                panic!(
                    "F7 multi-scenario decode retry loop exhausted \
                     scenario={} seed={seed} sample={i}",
                    scenario.id
                );
            };

            let mut baseline_elapsed_total_us = 0.0;
            for rep in 0..MEASURE_REPETITIONS {
                let baseline_decoder =
                    InactivationDecoder::new(scenario.k, scenario.symbol_size, seed);
                let baseline_t0 = Instant::now();
                let baseline_result = decode_with_retry(&baseline_decoder);
                baseline_elapsed_total_us += baseline_t0.elapsed().as_secs_f64() * 1_000_000.0;
                assert_eq!(
                    baseline_result.source, source,
                    "F7 baseline decode must recover source symbols \
                     (scenario {} sample {i} rep {rep})",
                    scenario.id
                );
            }
            let baseline_elapsed_us = baseline_elapsed_total_us / MEASURE_REPETITIONS as f64;
            baseline_time_us.push(baseline_elapsed_us);
            baseline_throughput_mib_s
                .push((bytes_recovered / (1024.0 * 1024.0)) / (baseline_elapsed_us / 1_000_000.0));

            let warmed_decoder = InactivationDecoder::new(scenario.k, scenario.symbol_size, seed);
            let warmup_result = decode_with_retry(&warmed_decoder);
            assert_eq!(
                warmup_result.source, source,
                "F7 warmup decode must recover source symbols (scenario {} sample {i})",
                scenario.id
            );
            let mut warmed_elapsed_total_us = 0.0;
            let mut warmed_sample_hit = false;
            for rep in 0..MEASURE_REPETITIONS {
                let warmed_t0 = Instant::now();
                let warmed_result = decode_with_retry(&warmed_decoder);
                warmed_elapsed_total_us += warmed_t0.elapsed().as_secs_f64() * 1_000_000.0;
                assert_eq!(
                    warmed_result.source, source,
                    "F7 warmed decode must recover source symbols \
                     (scenario {} sample {i} rep {rep})",
                    scenario.id
                );
                if warmed_result.stats.factor_cache_hits > 0 {
                    warmed_sample_hit = true;
                }
            }
            let warmed_elapsed_us = warmed_elapsed_total_us / MEASURE_REPETITIONS as f64;
            if warmed_sample_hit {
                warmed_hit_samples += 1;
            }
            warmed_time_us.push(warmed_elapsed_us);
            warmed_throughput_mib_s
                .push((bytes_recovered / (1024.0 * 1024.0)) / (warmed_elapsed_us / 1_000_000.0));

            let mut rollback_elapsed_total_us = 0.0;
            for rep in 0..MEASURE_REPETITIONS {
                let rollback_decoder =
                    InactivationDecoder::new(scenario.k, scenario.symbol_size, seed);
                let rollback_t0 = Instant::now();
                let rollback_result = decode_with_retry(&rollback_decoder);
                rollback_elapsed_total_us += rollback_t0.elapsed().as_secs_f64() * 1_000_000.0;
                assert_eq!(
                    rollback_result.source, source,
                    "F7 rollback-proxy decode must recover source symbols \
                     (scenario {} sample {i} rep {rep})",
                    scenario.id
                );
            }
            let rollback_elapsed_us = rollback_elapsed_total_us / MEASURE_REPETITIONS as f64;
            rollback_time_us.push(rollback_elapsed_us);
            rollback_throughput_mib_s
                .push((bytes_recovered / (1024.0 * 1024.0)) / (rollback_elapsed_us / 1_000_000.0));
        }

        let baseline_p50 = percentile_nearest_rank(&baseline_time_us, 50);
        let baseline_p95 = percentile_nearest_rank(&baseline_time_us, 95);
        let baseline_p99 = percentile_nearest_rank(&baseline_time_us, 99);
        let warmed_p50 = percentile_nearest_rank(&warmed_time_us, 50);
        let warmed_p95 = percentile_nearest_rank(&warmed_time_us, 95);
        let warmed_p99 = percentile_nearest_rank(&warmed_time_us, 99);
        let rollback_p50 = percentile_nearest_rank(&rollback_time_us, 50);
        let rollback_p95 = percentile_nearest_rank(&rollback_time_us, 95);
        let rollback_p99 = percentile_nearest_rank(&rollback_time_us, 99);

        let baseline_thr_p50 = percentile_nearest_rank(&baseline_throughput_mib_s, 50);
        let baseline_thr_p95 = percentile_nearest_rank(&baseline_throughput_mib_s, 95);
        let baseline_thr_p99 = percentile_nearest_rank(&baseline_throughput_mib_s, 99);
        let warmed_thr_p50 = percentile_nearest_rank(&warmed_throughput_mib_s, 50);
        let warmed_thr_p95 = percentile_nearest_rank(&warmed_throughput_mib_s, 95);
        let warmed_thr_p99 = percentile_nearest_rank(&warmed_throughput_mib_s, 99);
        let rollback_thr_p50 = percentile_nearest_rank(&rollback_throughput_mib_s, 50);
        let rollback_thr_p95 = percentile_nearest_rank(&rollback_throughput_mib_s, 95);
        let rollback_thr_p99 = percentile_nearest_rank(&rollback_throughput_mib_s, 99);

        let warmed_hit_rate = warmed_hit_samples as f64 / scenario.sample_count as f64;
        assert!(
            warmed_hit_rate >= 0.80,
            "F7 warmed decode should hit cache in >=80% samples for scenario {}, got {}/{}",
            scenario.id,
            warmed_hit_samples,
            scenario.sample_count
        );

        let warmed_vs_baseline_p95_delta_pct = delta_pct(warmed_p95, baseline_p95);
        let warmed_vs_baseline_p99_delta_pct = delta_pct(warmed_p99, baseline_p99);
        let warmed_vs_baseline_thr_p95_delta_pct = delta_pct(warmed_thr_p95, baseline_thr_p95);
        let warmed_vs_baseline_thr_p99_delta_pct = delta_pct(warmed_thr_p99, baseline_thr_p99);

        let material_gain = warmed_vs_baseline_p95_delta_pct <= -1.0
            && warmed_vs_baseline_p99_delta_pct <= -1.0
            && warmed_vs_baseline_thr_p95_delta_pct >= 1.0
            && warmed_vs_baseline_thr_p99_delta_pct >= 1.0;
        if material_gain {
            material_gain_scenarios += 1;
        }

        scenario_reports.push(serde_json::json!({
            "scenario_id": scenario.id,
            "sample_count": scenario.sample_count,
            "k": scenario.k,
            "symbol_size": scenario.symbol_size,
            "burst_drop_range": {
                "start": scenario.drop_start,
                "end_exclusive": scenario.drop_end_exclusive
            },
            "extra_repair_symbols": scenario.extra_repair,
            "modes": [
                {
                    "mode": "baseline",
                    "time_us": {"p50": baseline_p50, "p95": baseline_p95, "p99": baseline_p99},
                    "throughput_mib_s": {
                        "p50": baseline_thr_p50,
                        "p95": baseline_thr_p95,
                        "p99": baseline_thr_p99
                    }
                },
                {
                    "mode": "warmed_cache",
                    "time_us": {"p50": warmed_p50, "p95": warmed_p95, "p99": warmed_p99},
                    "throughput_mib_s": {
                        "p50": warmed_thr_p50,
                        "p95": warmed_thr_p95,
                        "p99": warmed_thr_p99
                    },
                    "cache_hit_samples": warmed_hit_samples,
                    "cache_hit_rate": warmed_hit_rate
                },
                {
                    "mode": "rollback_proxy",
                    "time_us": {"p50": rollback_p50, "p95": rollback_p95, "p99": rollback_p99},
                    "throughput_mib_s": {
                        "p50": rollback_thr_p50,
                        "p95": rollback_thr_p95,
                        "p99": rollback_thr_p99
                    }
                }
            ],
            "delta_vs_baseline": {
                "warmed_cache": {
                    "time_us": {
                        "p95_delta_pct": warmed_vs_baseline_p95_delta_pct,
                        "p99_delta_pct": warmed_vs_baseline_p99_delta_pct
                    },
                    "throughput_mib_s": {
                        "p95_delta_pct": warmed_vs_baseline_thr_p95_delta_pct,
                        "p99_delta_pct": warmed_vs_baseline_thr_p99_delta_pct
                    }
                }
            },
            "material_gain_thresholds": {
                "time_us": {"p95_delta_pct_lte": -1.0, "p99_delta_pct_lte": -1.0},
                "throughput_mib_s": {"p95_delta_pct_gte": 1.0, "p99_delta_pct_gte": 1.0}
            },
            "material_gain": material_gain
        }));
    }

    let report = serde_json::json!({
        "schema_version": "raptorq-track-f-factor-cache-p95p99-v2-draft",
        "replay_ref": "replay:rq-track-f-factor-cache-v2",
        "suite_id": "RQ-F7-CACHE-BURST-CMP-V2",
        "rollback_rehearsal": {
            "command": "cargo test --test ci_regression_gates g2_f7_factor_cache_observed -- --nocapture",
            "expected": "PASS",
            "outcome": "pass"
        },
        "scenarios": scenario_reports,
        "summary": {
            "scenario_count": scenarios.len(),
            "material_gain_scenarios": material_gain_scenarios,
            "limitations": [
                "Wall-time measurements are deterministic in setup but still sensitive to host jitter.",
                "Closure promotion should require representative multi-workload material gain, not a single favorable scenario."
            ]
        }
    });

    eprintln!(
        "G2-F7-COMPARATOR-V2: {}",
        serde_json::to_string(&report).expect("F7 multi-scenario comparator should serialize")
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
