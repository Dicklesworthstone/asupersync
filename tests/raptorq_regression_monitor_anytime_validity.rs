//! G8 anytime-valid regression-monitor statistical contract.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). The existing `regression.rs` integration
//! tests cover the structured-log golden output (`raptorq_regression_log_golden`)
//! and the CI gate scenarios (`ci_regression_gates`). Neither pins the
//! `RegressionMonitor` *statistical contract* itself — the conformal +
//! e-process engine that backs the "deterministic, replayable, anytime-valid"
//! guarantee. This crate fills that gap with oracle-free invariants:
//!
//!   * a fresh monitor is uncalibrated, has unit (1.0) martingale evidence for
//!     every tracked metric, no active conformal thresholds, and reports
//!     `None` for unknown metrics;
//!   * every `RegressionReport` is well-formed: schema/replay pins, one result
//!     per tracked metric, overall verdict == worst-case (max severity), and
//!     the regressed/warning counts agree with the per-metric verdicts;
//!   * calibration completes after enough baseline observations and activates a
//!     conformal threshold for every metric;
//!   * the engine is DETERMINISTIC — two independent monitors fed the identical
//!     calibrate/check sequence reach byte-identical state and emit identical
//!     reports (the replay guarantee);
//!   * a sustained in-distribution stream NEVER rejects H0 (anytime-valid
//!     false-positive control — the breach rate stays below the e-process null
//!     rate, so no metric regresses);
//!   * a sustained, escalating breach on a single metric eventually rejects H0
//!     for THAT metric only (detection power + per-metric isolation), driving
//!     its e-value past the `1/alpha` rejection threshold.
//!
//! Repro: `cargo test -p asupersync --test raptorq_regression_monitor_anytime_validity`

use asupersync::raptorq::decoder::DecodeStats;
use asupersync::raptorq::regression::{
    G8_REPLAY_REF, G8_SCHEMA_VERSION, RegressionMonitor, RegressionVerdict,
};
use std::collections::BTreeSet;

/// The six decode metrics the monitor tracks (a stable public contract,
/// observable on every `RegressionReport`). Kept local because the source
/// `TRACKED_METRICS` const is private; cross-checked against a live report in
/// `report_is_well_formed_and_overall_is_worst_case`.
const TRACKED: [&str; 6] = [
    "gauss_ops",
    "dense_core_rows",
    "dense_core_cols",
    "inactivated",
    "pivots_selected",
    "peel_frontier_peak",
];

/// A deterministic in-distribution observation. The jitter band is fixed and
/// bounded so calibration and check streams are exchangeable draws from the
/// same distribution — the textbook conformal setting.
fn baseline_stats(tick: usize) -> DecodeStats {
    let j = tick % 10;
    DecodeStats {
        gauss_ops: 1000 + j,
        dense_core_rows: 200 + j,
        dense_core_cols: 200 + j,
        inactivated: 50 + j,
        pivots_selected: 150 + j,
        peel_frontier_peak: 80 + j,
        ..Default::default()
    }
}

/// A breach observation: `gauss_ops` escalates strictly (so it exceeds any
/// adapting conformal threshold every step), while the other five metrics stay
/// in-distribution. Drives detection power on `gauss_ops` in isolation.
fn gauss_breach_stats(step: usize) -> DecodeStats {
    DecodeStats {
        gauss_ops: 100_000 * (step + 1),
        ..baseline_stats(step)
    }
}

#[test]
fn fresh_monitor_starts_uncalibrated_with_unit_evidence() {
    let monitor = RegressionMonitor::new();

    assert!(
        !monitor.is_calibrated(),
        "a fresh monitor is not yet calibrated"
    );
    assert_eq!(monitor.total_observations(), 0);
    assert!(!monitor.any_regressed());
    assert!(monitor.regressed_metrics().is_empty());

    for metric in TRACKED {
        assert_eq!(
            monitor.e_value(metric),
            Some(1.0),
            "{metric}: e-value must start at the martingale unit 1.0"
        );
        assert_eq!(
            monitor.threshold(metric),
            None,
            "{metric}: no conformal threshold exists before calibration"
        );
    }

    // Unknown metrics are reported as absent, not fabricated.
    assert_eq!(monitor.e_value("not_a_tracked_metric"), None);
    assert_eq!(monitor.threshold("not_a_tracked_metric"), None);
}

#[test]
fn report_is_well_formed_and_overall_is_worst_case() {
    let mut monitor = RegressionMonitor::new();
    let report = monitor.check(&baseline_stats(0));

    // Canonical schema / replay pins.
    assert_eq!(report.schema_version, G8_SCHEMA_VERSION);
    assert_eq!(report.replay_ref, G8_REPLAY_REF);

    // Exactly one result per tracked metric; the live metric set matches the
    // contract set (order-independent).
    assert_eq!(report.metrics.len(), TRACKED.len());
    let live: BTreeSet<&str> = report.metrics.iter().map(|r| r.metric.as_str()).collect();
    let expected: BTreeSet<&str> = TRACKED.iter().copied().collect();
    assert_eq!(
        live, expected,
        "report metric set must equal the tracked set"
    );

    // First-ever check has no calibrated thresholds yet -> every metric is
    // Calibrating, so the overall verdict is Calibrating.
    for r in &report.metrics {
        assert_eq!(
            r.verdict,
            RegressionVerdict::Calibrating,
            "{}: uncalibrated metric must report Calibrating",
            r.metric
        );
        assert!(
            r.threshold.is_none(),
            "{}: no threshold before calibration",
            r.metric
        );
    }
    assert_eq!(report.overall_verdict, RegressionVerdict::Calibrating);

    // Overall verdict == worst-case (maximum severity) across metrics, and the
    // aggregate counts agree with the per-metric verdicts.
    let worst = report
        .metrics
        .iter()
        .map(|r| r.verdict as u8)
        .max()
        .unwrap();
    assert_eq!(
        report.overall_verdict as u8, worst,
        "overall verdict must be the worst case"
    );
    let regressed = report
        .metrics
        .iter()
        .filter(|r| r.verdict == RegressionVerdict::Regressed)
        .count();
    let warning = report
        .metrics
        .iter()
        .filter(|r| r.verdict == RegressionVerdict::Warning)
        .count();
    assert_eq!(report.regressed_count, regressed);
    assert_eq!(report.warning_count, warning);

    // total_observations is mirrored on the monitor and advances per check.
    assert_eq!(report.total_observations, monitor.total_observations());
    let next = monitor.check(&baseline_stats(1));
    assert_eq!(next.total_observations, report.total_observations + 1);
}

#[test]
fn calibration_completes_and_activates_thresholds() {
    let mut monitor = RegressionMonitor::new();
    assert!(!monitor.is_calibrated());

    // Feed comfortably more than MIN_CALIBRATION_SAMPLES (20) baseline draws.
    for tick in 0..25 {
        monitor.calibrate(&baseline_stats(tick));
    }

    assert!(
        monitor.is_calibrated(),
        "monitor must calibrate after >= MIN_CALIBRATION_SAMPLES baseline observations"
    );
    assert_eq!(monitor.total_observations(), 25);
    for metric in TRACKED {
        assert!(
            monitor.threshold(metric).is_some(),
            "{metric}: a conformal threshold must be active once calibrated"
        );
    }
}

#[test]
fn engine_is_deterministic_across_independent_monitors() {
    // Identical calibrate-then-check program on two fresh monitors.
    fn drive() -> RegressionMonitor {
        let mut monitor = RegressionMonitor::new();
        for tick in 0..25 {
            monitor.calibrate(&baseline_stats(tick));
        }
        for tick in 15..40 {
            let _ = monitor.check(&baseline_stats(tick));
        }
        monitor
    }

    let a = drive();
    let b = drive();

    // Final-state determinism.
    assert_eq!(a.is_calibrated(), b.is_calibrated());
    assert_eq!(a.total_observations(), b.total_observations());
    assert_eq!(a.any_regressed(), b.any_regressed());
    assert_eq!(a.regressed_metrics(), b.regressed_metrics());
    for metric in TRACKED {
        assert_eq!(
            a.e_value(metric),
            b.e_value(metric),
            "{metric}: e-value must be replay-identical"
        );
        assert_eq!(
            a.threshold(metric),
            b.threshold(metric),
            "{metric}: threshold must be replay-identical"
        );
    }

    // Report-level determinism: feeding the identical next observation to both
    // yields byte-identical reports (verdicts, thresholds, e-values).
    let mut a2 = drive();
    let mut b2 = drive();
    let ra = a2.check(&baseline_stats(99));
    let rb = b2.check(&baseline_stats(99));
    assert_eq!(ra.overall_verdict, rb.overall_verdict);
    assert_eq!(ra.regressed_count, rb.regressed_count);
    assert_eq!(ra.warning_count, rb.warning_count);
    assert_eq!(ra.metrics.len(), rb.metrics.len());
    for (xa, xb) in ra.metrics.iter().zip(rb.metrics.iter()) {
        assert_eq!(xa.metric, xb.metric);
        assert_eq!(xa.value, xb.value);
        assert_eq!(
            xa.threshold, xb.threshold,
            "{}: threshold replay mismatch",
            xa.metric
        );
        assert_eq!(
            xa.e_value, xb.e_value,
            "{}: e-value replay mismatch",
            xa.metric
        );
        assert_eq!(xa.exceeds_threshold, xb.exceeds_threshold);
        assert_eq!(
            xa.verdict, xb.verdict,
            "{}: verdict replay mismatch",
            xa.metric
        );
    }
}

#[test]
fn sustained_in_distribution_stream_never_regresses() {
    let mut monitor = RegressionMonitor::new();
    for tick in 0..30 {
        monitor.calibrate(&baseline_stats(tick));
    }
    assert!(monitor.is_calibrated());

    // A long exchangeable in-distribution stream: the conformal breach rate
    // stays below the e-process null rate, so the e-process must never reject.
    for tick in 30..230 {
        let report = monitor.check(&baseline_stats(tick));
        assert_ne!(
            report.overall_verdict,
            RegressionVerdict::Regressed,
            "in-distribution observation falsely flagged Regressed at tick {tick}"
        );
        assert_eq!(
            report.regressed_count, 0,
            "no metric may regress under baseline at tick {tick}"
        );
        for r in &report.metrics {
            assert_ne!(
                r.verdict,
                RegressionVerdict::Regressed,
                "{}: false regression at tick {tick}",
                r.metric
            );
        }
    }

    assert!(
        !monitor.any_regressed(),
        "no metric may reject H0 under a sustained baseline stream"
    );
    assert!(monitor.regressed_metrics().is_empty());
}

#[test]
fn sustained_escalating_breach_rejects_only_the_breached_metric() {
    let mut monitor = RegressionMonitor::new();
    for tick in 0..30 {
        monitor.calibrate(&baseline_stats(tick));
    }
    assert!(monitor.is_calibrated());
    assert!(!monitor.any_regressed());

    // Drive a sustained, strictly-escalating breach on gauss_ops while every
    // other metric stays in-distribution. Detection must fire within budget.
    let mut detected_at = None;
    for step in 0..120 {
        let report = monitor.check(&gauss_breach_stats(step));
        if report.overall_verdict == RegressionVerdict::Regressed {
            detected_at = Some(step);
            break;
        }
    }

    let step =
        detected_at.expect("a sustained escalating gauss_ops breach must eventually reject H0");
    assert!(
        monitor.any_regressed(),
        "detection at step {step} must set the regressed flag"
    );

    // Per-metric isolation: ONLY gauss_ops regressed; the in-distribution
    // metrics did not.
    assert_eq!(
        monitor.regressed_metrics(),
        vec!["gauss_ops".to_string()],
        "only the breached metric (gauss_ops) may regress"
    );

    // The rejecting metric's e-value crossed the 1/alpha = 20 rejection bar.
    let e = monitor.e_value("gauss_ops").expect("gauss_ops is tracked");
    assert!(
        e >= 20.0,
        "a rejecting e-value must reach the 1/alpha = 20 threshold (got {e})"
    );
}
