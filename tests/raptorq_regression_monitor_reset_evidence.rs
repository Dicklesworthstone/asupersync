//! G8 regression monitor — `reset_evidence()` lifecycle conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330) AC3/AC8. `RegressionMonitor::reset_evidence`
//! is the operator's "I've addressed the regression, resume monitoring" lever:
//! it clears every per-metric e-process (sequential evidence) while KEEPING the
//! conformal calibration so the monitor stays armed. It had ZERO integration
//! coverage — the companion `raptorq_regression_monitor_anytime_validity` crate
//! exercises calibration, determinism, false-positive control, and detection
//! power, but never resets, so nothing pinned that a reset:
//!   * actually clears accumulated evidence (e-values return to the unit
//!     martingale 1.0; `any_regressed()` clears; `regressed_metrics()` empties);
//!   * PRESERVES calibration (every tracked metric keeps an active conformal
//!     threshold and `is_calibrated()` stays true);
//!   * does NOT rewind `total_observations()` (it touches only the e-processes);
//!   * leaves a fresh/quiet monitor untouched (harmless no-op);
//!   * yields a REUSABLE monitor — detection power survives, so a fresh breach
//!     after reset re-rejects the same metric (proves reset restored a working
//!     clean state, not a degenerate one);
//!   * is idempotent (resetting twice equals resetting once).
//!
//! All invariants are oracle-free: recomputed from the public monitor accessors
//! and the documented `EProcess::reset` contract (current e-value -> 1.0).
//!
//! Repro: `cargo test -p asupersync --test raptorq_regression_monitor_reset_evidence`

use asupersync::raptorq::decoder::DecodeStats;
use asupersync::raptorq::regression::{RegressionMonitor, RegressionVerdict};

/// The six decode metrics the monitor tracks (mirrors the private
/// `TRACKED_METRICS`; cross-checked against live reports by the companion
/// anytime-validity crate).
const TRACKED: [&str; 6] = [
    "gauss_ops",
    "dense_core_rows",
    "dense_core_cols",
    "inactivated",
    "pivots_selected",
    "peel_frontier_peak",
];

/// A deterministic in-distribution observation (fixed, bounded jitter band so
/// calibration and check streams are exchangeable draws — the conformal
/// setting). Matches the companion crate's baseline for cross-crate parity.
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

/// A strictly-escalating breach on `gauss_ops` only; the other five metrics stay
/// in-distribution. Drives detection power on `gauss_ops` in isolation.
fn gauss_breach_stats(step: usize) -> DecodeStats {
    DecodeStats {
        gauss_ops: 100_000 * (step + 1),
        ..baseline_stats(step)
    }
}

/// Build a calibrated monitor (30 baseline ticks is past `MIN_CALIBRATION_SAMPLES`).
fn calibrated_monitor() -> RegressionMonitor {
    let mut monitor = RegressionMonitor::new();
    for tick in 0..30 {
        monitor.calibrate(&baseline_stats(tick));
    }
    assert!(monitor.is_calibrated(), "30 baseline ticks must calibrate");
    monitor
}

/// Drive a sustained escalating gauss_ops breach until H0 is rejected; returns
/// the step at which detection fired. Panics if detection never fires.
fn drive_until_regressed(monitor: &mut RegressionMonitor) -> usize {
    for step in 0..120 {
        let report = monitor.check(&gauss_breach_stats(step));
        if report.overall_verdict == RegressionVerdict::Regressed {
            return step;
        }
    }
    panic!("a sustained escalating gauss_ops breach must eventually reject H0");
}

#[test]
fn reset_evidence_clears_evidence_but_preserves_calibration() {
    let mut monitor = calibrated_monitor();
    drive_until_regressed(&mut monitor);

    // Pre-reset: regression is live and accounted for.
    assert!(monitor.any_regressed());
    assert_eq!(monitor.regressed_metrics(), vec!["gauss_ops".to_string()]);
    assert!(
        monitor.e_value("gauss_ops").expect("tracked") >= 20.0,
        "the rejecting metric crossed the 1/alpha bar before reset"
    );
    // Calibration and the observation counter are established.
    let obs_before = monitor.total_observations();
    assert!(obs_before > 0);
    for m in TRACKED {
        assert!(
            monitor.threshold(m).is_some(),
            "{m} threshold active pre-reset"
        );
    }

    monitor.reset_evidence();

    // Evidence is gone: every e-process is back to the unit martingale and no
    // metric is regressed.
    assert!(
        !monitor.any_regressed(),
        "reset must clear the regressed flag"
    );
    assert!(
        monitor.regressed_metrics().is_empty(),
        "reset must empty the regressed-metric set"
    );
    for m in TRACKED {
        assert_eq!(
            monitor.e_value(m),
            Some(1.0),
            "{m} e-value must reset to the unit martingale"
        );
        // Calibration is preserved: the conformal threshold survives the reset.
        assert!(
            monitor.threshold(m).is_some(),
            "{m} threshold must survive reset (calibration preserved)"
        );
    }
    assert!(
        monitor.is_calibrated(),
        "reset clears evidence only, never calibration"
    );
    // reset_evidence touches only the e-processes, not the observation counter.
    assert_eq!(
        monitor.total_observations(),
        obs_before,
        "reset_evidence must not rewind total_observations"
    );
}

#[test]
fn reset_evidence_is_a_noop_on_a_fresh_monitor() {
    let mut monitor = RegressionMonitor::new();
    // Pre: fresh state.
    assert!(!monitor.is_calibrated());
    assert_eq!(monitor.total_observations(), 0);
    for m in TRACKED {
        assert_eq!(monitor.e_value(m), Some(1.0));
        assert!(monitor.threshold(m).is_none());
    }

    monitor.reset_evidence();

    // Post: identical fresh state — harmless no-op.
    assert!(!monitor.is_calibrated());
    assert!(!monitor.any_regressed());
    assert!(monitor.regressed_metrics().is_empty());
    assert_eq!(monitor.total_observations(), 0);
    for m in TRACKED {
        assert_eq!(monitor.e_value(m), Some(1.0));
        assert!(monitor.threshold(m).is_none());
    }
    // Unknown metric stays unknown.
    assert_eq!(monitor.e_value("not-a-metric"), None);
}

#[test]
fn reset_evidence_preserves_a_calibrated_quiet_monitor() {
    let mut monitor = calibrated_monitor();
    // A quiet (in-distribution) stream never regresses.
    for tick in 30..60 {
        let _ = monitor.check(&baseline_stats(tick));
    }
    assert!(!monitor.any_regressed());
    let obs_before = monitor.total_observations();
    let thresholds_before: Vec<Option<f64>> =
        TRACKED.iter().map(|m| monitor.threshold(m)).collect();

    monitor.reset_evidence();

    assert!(monitor.is_calibrated(), "calibration preserved");
    assert!(!monitor.any_regressed());
    assert_eq!(
        monitor.total_observations(),
        obs_before,
        "no-op on the observation counter"
    );
    let thresholds_after: Vec<Option<f64>> = TRACKED.iter().map(|m| monitor.threshold(m)).collect();
    assert_eq!(
        thresholds_before, thresholds_after,
        "conformal thresholds are unchanged by an evidence reset"
    );
}

#[test]
fn monitor_re_detects_a_regression_after_reset() {
    let mut monitor = calibrated_monitor();
    drive_until_regressed(&mut monitor);
    assert!(monitor.any_regressed());

    monitor.reset_evidence();
    assert!(!monitor.any_regressed(), "clean slate after reset");

    // Detection power must survive the reset: a fresh escalating breach
    // re-rejects, and still only the breached metric regresses.
    let step = drive_until_regressed(&mut monitor);
    assert!(
        monitor.any_regressed(),
        "post-reset re-detection must fire (detected at step {step})"
    );
    assert_eq!(
        monitor.regressed_metrics(),
        vec!["gauss_ops".to_string()],
        "per-metric isolation holds after reset too"
    );
}

#[test]
fn reset_evidence_is_idempotent() {
    let mut monitor = calibrated_monitor();
    drive_until_regressed(&mut monitor);

    monitor.reset_evidence();
    let after_one: Vec<Option<f64>> = TRACKED.iter().map(|m| monitor.e_value(m)).collect();
    let regressed_after_one = monitor.any_regressed();
    let obs_after_one = monitor.total_observations();

    monitor.reset_evidence();
    let after_two: Vec<Option<f64>> = TRACKED.iter().map(|m| monitor.e_value(m)).collect();

    assert_eq!(
        after_one, after_two,
        "resetting twice equals resetting once"
    );
    assert!(after_two.iter().all(|e| *e == Some(1.0)));
    assert!(!regressed_after_one);
    assert!(!monitor.any_regressed());
    assert_eq!(
        monitor.total_observations(),
        obs_after_one,
        "the second reset is also a no-op on the counter"
    );
}
