//! E2E regression tests for conformal calibration of lab metrics.
//!
//! Tests the conformal prediction pipeline end-to-end: calibration from
//! oracle reports, prediction set generation, coverage tracking, and
//! integration with evidence ledger.

mod common;
use common::*;

use asupersync::lab::conformal::{CalibrationReport, ConformalCalibrator, ConformalConfig};
use asupersync::lab::oracle::OracleSuite;
use asupersync::lab::{LabConfig, LabRuntime, OracleReport, ALL_ORACLE_INVARIANTS};
use asupersync::types::{Budget, Time};

const SEED_BASE: u64 = 0xCAFE_1234;

fn count_to_f64(count: usize) -> f64 {
    let clamped = count.min(u32::MAX as usize);
    f64::from(u32::try_from(clamped).expect("clamped to u32 max"))
}

/// Run a lab runtime with a single task and return the oracle report.
fn single_task_report(seed: u64) -> OracleReport {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (t, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async { 42 })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(t, 0);
    runtime.run_until_quiescent();
    runtime.oracles.report(runtime.now())
}

/// Generate a clean oracle report from a fresh OracleSuite.
fn clean_oracle_report(nanos: u64) -> OracleReport {
    let suite = OracleSuite::new();
    suite.report(Time::from_nanos(nanos))
}

/// Generate a violated oracle report (task leak).
fn violated_oracle_report(nanos: u64) -> OracleReport {
    let mut suite = OracleSuite::new();
    let region = asupersync::types::RegionId::new_for_test(1, 0);
    let task = asupersync::types::TaskId::new_for_test(1, 0);
    let time = Time::from_nanos(nanos);
    suite.task_leak.on_spawn(task, region, time);
    suite.task_leak.on_region_close(region, time);
    suite.report(Time::from_nanos(nanos))
}

// ==================== Calibration Basics ====================

#[test]
fn e2e_conformal_calibration_from_clean_reports() {
    init_test_logging();
    test_phase!("e2e_conformal_calibration_from_clean_reports");

    let config = ConformalConfig::new(0.10).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    // Calibrate with 10 clean reports.
    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }

    assert!(cal.is_calibrated());
    assert_eq!(cal.calibration_samples(), 10);

    // Predict on a new clean report.
    let report = cal
        .predict(&clean_oracle_report(99_000))
        .expect("should be calibrated");

    assert!(!report.prediction_sets.is_empty());
    // All prediction sets from clean data should be conforming.
    for ps in &report.prediction_sets {
        assert!(
            ps.conforming,
            "invariant {} should be conforming, score={:.4} threshold={:.4}",
            ps.invariant, ps.score, ps.threshold
        );
    }

    test_complete!("e2e_conformal_calibration_from_clean_reports");
}

#[test]
fn e2e_conformal_violation_detection() {
    init_test_logging();
    test_phase!("e2e_conformal_violation_detection");

    let config = ConformalConfig::new(0.10).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    // Calibrate with clean reports.
    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }

    // Predict on a violated report.
    let report = cal
        .predict(&violated_oracle_report(99_000))
        .expect("should be calibrated");

    // The task_leak invariant should be flagged as anomalous.
    let task_leak_ps = report
        .prediction_sets
        .iter()
        .find(|ps| ps.invariant == "task_leak");

    if let Some(ps) = task_leak_ps {
        assert!(!ps.conforming, "violated invariant should be anomalous");
        assert!(ps.score >= 1.0, "violation score should be >= 1.0");
    }

    test_complete!("e2e_conformal_violation_detection");
}

// ==================== Coverage Guarantee ====================

#[test]
fn e2e_conformal_coverage_guarantee() {
    init_test_logging();
    test_phase!("e2e_conformal_coverage_guarantee");

    let alpha = 0.10;
    let config = ConformalConfig::new(alpha).min_samples(10);
    let mut cal = ConformalCalibrator::new(config);

    // Calibrate with 20 clean reports.
    for i in 0..20 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }

    // Make 100 predictions on clean data.
    let mut covered: u32 = 0;
    let n_predict: u32 = 100;
    for i in 0..n_predict {
        let report = cal
            .predict(&clean_oracle_report((20_u64 + u64::from(i)) * 1000))
            .expect("calibrated");
        // Count how many prediction sets are fully conforming.
        let all_conforming = report.prediction_sets.iter().all(|ps| ps.conforming);
        if all_conforming {
            covered += 1;
        }
    }

    // Coverage should be >= 1 - alpha (with some slack for finite samples).
    let coverage = f64::from(covered) / f64::from(n_predict);
    let target = 1.0 - alpha;
    assert!(
        coverage >= target - 0.10, // Allow 10% slack for finite-sample effects
        "empirical coverage {coverage:.2} should be near target {target:.2}"
    );

    test_complete!(
        "e2e_conformal_coverage_guarantee",
        coverage = coverage,
        target = target
    );
}

// ==================== Report Output ====================

#[test]
fn e2e_conformal_report_text() {
    init_test_logging();
    test_phase!("e2e_conformal_report_text");

    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }
    let report = cal
        .predict(&clean_oracle_report(99_000))
        .expect("calibrated");
    let text = report.to_text();

    assert!(text.contains("CONFORMAL CALIBRATION REPORT"));
    assert!(text.contains("95.0%"));
    assert!(text.contains("alpha=0.050"));
    // Should contain at least one invariant name.
    assert!(text.contains("task_leak") || text.contains("quiescence"));

    test_complete!("e2e_conformal_report_text");
}

#[test]
fn e2e_conformal_report_json() {
    init_test_logging();
    test_phase!("e2e_conformal_report_json");

    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }
    let report = cal
        .predict(&clean_oracle_report(99_000))
        .expect("calibrated");
    let json = report.to_json();

    assert!(json.is_object());
    assert_eq!(json["alpha"], 0.05);
    assert_eq!(json["coverage_target"], 0.95);
    assert!(json["well_calibrated"].as_bool().unwrap());
    assert!(json["prediction_sets"].is_array());
    assert!(!json["prediction_sets"].as_array().unwrap().is_empty());
    assert!(json["per_invariant_coverage"].is_array());

    test_complete!("e2e_conformal_report_json");
}

#[test]
fn e2e_conformal_report_json_roundtrip() {
    init_test_logging();
    test_phase!("e2e_conformal_report_json_roundtrip");

    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }
    let report = cal
        .predict(&clean_oracle_report(99_000))
        .expect("calibrated");

    // Serialize to JSON string and back.
    let json_str = serde_json::to_string(&report).expect("serialize");
    let deserialized: CalibrationReport = serde_json::from_str(&json_str).expect("deserialize");

    assert!(
        (report.alpha - deserialized.alpha).abs() < f64::EPSILON,
        "alpha mismatch after JSON roundtrip: {} vs {}",
        report.alpha,
        deserialized.alpha
    );
    assert_eq!(
        report.prediction_sets.len(),
        deserialized.prediction_sets.len()
    );
    assert_eq!(report.calibration_samples, deserialized.calibration_samples);

    test_complete!("e2e_conformal_report_json_roundtrip");
}

// ==================== Determinism ====================

#[test]
fn e2e_conformal_deterministic() {
    init_test_logging();
    test_phase!("e2e_conformal_deterministic");

    let run = || {
        let config = ConformalConfig::new(0.05).min_samples(5);
        let mut cal = ConformalCalibrator::new(config);
        for i in 0..10 {
            cal.calibrate(&clean_oracle_report(i * 1000));
        }
        cal.predict(&clean_oracle_report(99_000))
            .expect("calibrated")
    };

    let r1 = run();
    let r2 = run();

    assert_eq!(r1.prediction_sets.len(), r2.prediction_sets.len());
    for (a, b) in r1.prediction_sets.iter().zip(r2.prediction_sets.iter()) {
        assert_eq!(a.invariant, b.invariant);
        assert!((a.score - b.score).abs() < f64::EPSILON);
        assert!((a.threshold - b.threshold).abs() < f64::EPSILON);
        assert_eq!(a.conforming, b.conforming);
    }

    test_complete!("e2e_conformal_deterministic");
}

// ==================== Well-Calibrated Diagnostics ====================

#[test]
fn e2e_conformal_well_calibrated_clean_data() {
    init_test_logging();
    test_phase!("e2e_conformal_well_calibrated_clean_data");

    let config = ConformalConfig::new(0.10).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    // Calibrate.
    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }

    // Predict many times.
    let mut last_report = None;
    for i in 0..50 {
        last_report = cal.predict(&clean_oracle_report((10 + i) * 1000));
    }

    let report = last_report.expect("should have predictions");
    assert!(report.is_well_calibrated());
    assert!(report.miscalibrated_invariants().is_empty());

    test_complete!("e2e_conformal_well_calibrated_clean_data");
}

#[test]
fn e2e_conformal_violation_rates() {
    init_test_logging();
    test_phase!("e2e_conformal_violation_rates");

    let config = ConformalConfig::new(0.10).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    // Mix of clean and violated reports.
    for i in 0..8 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }
    for i in 0..2 {
        cal.calibrate(&violated_oracle_report((8 + i) * 1000));
    }

    let rates = cal.violation_rates();
    // task_leak should have some violations.
    let task_leak_rate = rates.get("task_leak").copied().unwrap_or(0.0);
    assert!(
        task_leak_rate > 0.0,
        "task_leak should have violations, rate={task_leak_rate:.2}"
    );

    // Most other invariants should have 0 violations.
    let clean_rate = rates.get("quiescence").copied().unwrap_or(0.0);
    assert!(
        (clean_rate - 0.0).abs() < f64::EPSILON,
        "clean invariant should have 0 violations"
    );

    test_complete!("e2e_conformal_violation_rates");
}

// ==================== Integration with Lab Runtime ====================

#[test]
fn e2e_conformal_with_lab_runtime() {
    init_test_logging();
    test_phase!("e2e_conformal_with_lab_runtime");

    let config = ConformalConfig::new(0.10).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    // Calibrate using actual lab runtime oracle reports.
    for i in 0..10 {
        let report = single_task_report(SEED_BASE + i);
        cal.calibrate(&report);
    }

    assert!(cal.is_calibrated());

    // Predict on a new run.
    let new_report = single_task_report(SEED_BASE + 999);
    let cal_report = cal.predict(&new_report).expect("should be calibrated");

    assert!(!cal_report.prediction_sets.is_empty());
    // A well-behaved single-task program should produce conforming predictions.
    let n_conforming = cal_report
        .prediction_sets
        .iter()
        .filter(|ps| ps.conforming)
        .count();
    let n_total = cal_report.prediction_sets.len();

    // Most predictions should be conforming.
    let conforming_ratio = count_to_f64(n_conforming) / count_to_f64(n_total);
    assert!(
        conforming_ratio >= 0.5,
        "at least half should be conforming: {n_conforming}/{n_total}"
    );

    tracing::info!(
        conforming = n_conforming,
        total = n_total,
        well_calibrated = cal_report.is_well_calibrated(),
        "lab runtime conformal calibration"
    );

    test_complete!("e2e_conformal_with_lab_runtime");
}

// ==================== Prediction Set Properties ====================

#[test]
fn e2e_conformal_prediction_set_properties() {
    init_test_logging();
    test_phase!("e2e_conformal_prediction_set_properties");

    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }

    let report = cal
        .predict(&clean_oracle_report(99_000))
        .expect("calibrated");

    for ps in &report.prediction_sets {
        // Structural properties.
        assert!(
            !ps.invariant.is_empty(),
            "invariant name should be non-empty"
        );
        assert!(ps.threshold >= 0.0, "threshold should be non-negative");
        assert!(ps.score >= 0.0, "score should be non-negative");
        assert!(
            ps.calibration_n >= 10,
            "should have ≥10 calibration samples"
        );
        assert!(
            (ps.coverage_target - 0.95).abs() < f64::EPSILON,
            "coverage target should be 0.95"
        );

        // Conformity: score ≤ threshold ↔ conforming.
        if ps.conforming {
            assert!(
                ps.score <= ps.threshold,
                "conforming implies score ≤ threshold"
            );
        } else {
            assert!(
                ps.score > ps.threshold,
                "non-conforming implies score > threshold"
            );
        }
    }

    test_complete!("e2e_conformal_prediction_set_properties");
}

#[test]
fn e2e_conformal_13_invariants_covered() {
    init_test_logging();
    test_phase!("e2e_conformal_13_invariants_covered");

    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut cal = ConformalCalibrator::new(config);

    // Oracle reports from OracleSuite include all registered invariants.
    for i in 0..10 {
        cal.calibrate(&clean_oracle_report(i * 1000));
    }

    let report = cal
        .predict(&clean_oracle_report(99_000))
        .expect("calibrated");

    // Should have prediction sets for all oracle invariants.
    assert_eq!(
        report.prediction_sets.len(),
        ALL_ORACLE_INVARIANTS.len(),
        "should cover all oracle invariants"
    );

    let invariant_names: Vec<&str> = report
        .prediction_sets
        .iter()
        .map(|ps| ps.invariant.as_str())
        .collect();

    // Verify key invariants are present.
    assert!(invariant_names.contains(&"task_leak"));
    assert!(invariant_names.contains(&"obligation_leak"));
    assert!(invariant_names.contains(&"quiescence"));
    assert!(invariant_names.contains(&"cancellation_protocol"));

    test_complete!("e2e_conformal_13_invariants_covered");
}
