#![allow(warnings)]
#![allow(clippy::all)]

use asupersync::raptorq::decoder::DecodeStats;
use asupersync::raptorq::regression::{
    RegressionMonitor, RegressionReport, RegressionVerdict, regression_log_lines,
};
use insta::assert_json_snapshot;
use serde_json::{Value, json};

const CALIBRATION_WARMUP: usize = 15;

fn make_baseline_stats(gauss_ops: usize, inactivated: usize) -> DecodeStats {
    DecodeStats {
        gauss_ops,
        inactivated,
        dense_core_rows: gauss_ops / 2,
        dense_core_cols: gauss_ops / 3,
        pivots_selected: inactivated,
        peel_frontier_peak: 4,
        policy_mode: Some("stable"),
        ..Default::default()
    }
}

fn calibrate_monitor_for_k(k: usize) -> RegressionMonitor {
    let mut monitor = RegressionMonitor::new();
    let base_gauss = (k / 2).max(10);
    let base_inactivated = (k / 8).max(1);

    for i in 0..CALIBRATION_WARMUP {
        let stats = make_baseline_stats(base_gauss + i % 3, base_inactivated + i % 2);
        monitor.calibrate(&stats);
    }

    monitor
}

fn drive_decode_failure_report(
    k: usize,
    erasure_pattern: &'static str,
    gauss_multiplier: usize,
    inactivated_multiplier: usize,
) -> RegressionReport {
    let base_gauss = (k / 2).max(10);
    let base_inactivated = (k / 8).max(1);
    let mut monitor = calibrate_monitor_for_k(k);

    for attempt in 0..256 {
        let mut stats = make_baseline_stats(
            base_gauss.saturating_mul(gauss_multiplier) + attempt % 3,
            base_inactivated
                .saturating_mul(inactivated_multiplier)
                .saturating_add(attempt % 2),
        );
        stats.policy_mode = Some(erasure_pattern);
        let report = monitor.check(&stats);
        if report.overall_verdict == RegressionVerdict::Regressed {
            return report;
        }
    }

    panic!("expected {erasure_pattern} scenario for k={k} to reach regression");
}

fn parse_log_lines(report: &RegressionReport) -> Vec<Value> {
    regression_log_lines(report)
        .into_iter()
        .map(|line| serde_json::from_str(&line).expect("log line must stay valid JSON"))
        .collect()
}

#[test]
fn decode_failure_log_scenarios_scrubbed() {
    let scenarios = [
        (10usize, "burst-loss-40pct", 8usize, 5usize),
        (100usize, "checkerboard-loss-35pct", 6usize, 4usize),
        (1000usize, "tail-drop-loss-25pct", 5usize, 3usize),
    ];

    let snapshot = scenarios
        .into_iter()
        .map(
            |(k, erasure_pattern, gauss_multiplier, inactivated_multiplier)| {
                let report = drive_decode_failure_report(
                    k,
                    erasure_pattern,
                    gauss_multiplier,
                    inactivated_multiplier,
                );
                (
                    format!("k_{k}"),
                    json!({
                        "k": k,
                        "erasure_pattern": erasure_pattern,
                        "overall_verdict": report.overall_verdict.label(),
                        "regressed_count": report.regressed_count,
                        "warning_count": report.warning_count,
                        "log_lines": parse_log_lines(&report),
                    }),
                )
            },
        )
        .collect::<serde_json::Map<String, Value>>();

    assert_json_snapshot!("decode_failure_log_scenarios_scrubbed", snapshot);
}
