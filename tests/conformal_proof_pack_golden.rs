//! Golden snapshots for conformal proof-pack rendering.

use asupersync::lab::conformal::{ConformalCalibrator, ConformalConfig};
use asupersync::lab::oracle::{OracleEntryReport, OracleReport, OracleStats};
use insta::assert_json_snapshot;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Serialize)]
struct ScenarioProofPack {
    scenario: &'static str,
    config: ScenarioConfig,
    source_report: ScrubbedOracleReport,
    calibration_samples_before_attempt: usize,
    proof: Option<RenderedProofPack>,
    boundary: Option<BoundaryState>,
}

#[derive(Debug, Serialize)]
struct ScenarioConfig {
    alpha: f64,
    min_calibration_samples: usize,
}

#[derive(Debug, Serialize)]
struct ScrubbedOracleReport {
    total: usize,
    passed: usize,
    failed: usize,
    check_time_nanos: &'static str,
    entries: Vec<ScrubbedOracleEntry>,
}

#[derive(Debug, Serialize)]
struct ScrubbedOracleEntry {
    invariant: String,
    passed: bool,
    violation: Option<String>,
    entities_tracked: usize,
    events_recorded: usize,
}

#[derive(Debug, Serialize)]
struct RenderedProofPack {
    text: String,
    json: Value,
    well_calibrated: bool,
    miscalibrated_invariants: Vec<String>,
    anomalous_invariants: Vec<String>,
    conforming_invariants: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BoundaryState {
    prediction_available: bool,
    calibration_samples_after_attempt: usize,
    calibrated_after_attempt: bool,
    reason: &'static str,
}

fn entry(
    invariant: &str,
    passed: bool,
    violation: Option<&str>,
    entities_tracked: usize,
    events_recorded: usize,
) -> OracleEntryReport {
    OracleEntryReport {
        invariant: invariant.to_owned(),
        passed,
        violation: violation.map(str::to_owned),
        stats: OracleStats {
            entities_tracked,
            events_recorded,
        },
    }
}

fn report(check_time_nanos: u64, entries: Vec<OracleEntryReport>) -> OracleReport {
    let total = entries.len();
    let passed = entries.iter().filter(|entry| entry.passed).count();
    OracleReport {
        entries,
        total,
        passed,
        failed: total.saturating_sub(passed),
        check_time_nanos,
    }
}

fn clean_report(check_time_nanos: u64, task_entities: usize, task_events: usize) -> OracleReport {
    report(
        check_time_nanos,
        vec![
            entry("task_leak", true, None, task_entities, task_events),
            entry(
                "quiescence",
                true,
                None,
                task_entities.saturating_sub(1).max(1),
                task_events.saturating_add(2),
            ),
        ],
    )
}

fn violated_report(check_time_nanos: u64) -> OracleReport {
    report(
        check_time_nanos,
        vec![
            entry(
                "task_leak",
                false,
                Some("task leaked past region close"),
                24,
                180,
            ),
            entry(
                "quiescence",
                false,
                Some("region failed to quiesce before deadline"),
                19,
                144,
            ),
        ],
    )
}

fn scrub_source_report(report: &OracleReport) -> ScrubbedOracleReport {
    ScrubbedOracleReport {
        total: report.total,
        passed: report.passed,
        failed: report.failed,
        check_time_nanos: "[check_time_nanos]",
        entries: report
            .entries
            .iter()
            .map(|entry| ScrubbedOracleEntry {
                invariant: entry.invariant.clone(),
                passed: entry.passed,
                violation: entry.violation.clone(),
                entities_tracked: entry.stats.entities_tracked,
                events_recorded: entry.stats.events_recorded,
            })
            .collect(),
    }
}

fn round_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(round_json).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, round_json(value)))
                .collect(),
        ),
        Value::Number(number) => number.as_f64().map_or(Value::Number(number), |value| {
            json!(((value * 1_000_000.0).round()) / 1_000_000.0)
        }),
        other => other,
    }
}

fn render_proof_pack(
    calibrator: &mut ConformalCalibrator,
    source_report: &OracleReport,
) -> Option<RenderedProofPack> {
    let report = calibrator.predict(source_report)?;
    let json = round_json(report.to_json());
    let anomalous_invariants = report
        .prediction_sets
        .iter()
        .filter(|prediction| !prediction.conforming)
        .map(|prediction| prediction.invariant.clone())
        .collect();
    let conforming_invariants = report
        .prediction_sets
        .iter()
        .filter(|prediction| prediction.conforming)
        .map(|prediction| prediction.invariant.clone())
        .collect();

    Some(RenderedProofPack {
        text: report.to_text(),
        json,
        well_calibrated: report.is_well_calibrated(),
        miscalibrated_invariants: report.miscalibrated_invariants(),
        anomalous_invariants,
        conforming_invariants,
    })
}

fn passing_proof_pack() -> ScenarioProofPack {
    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut calibrator = ConformalCalibrator::new(config.clone());

    for offset in 0..8 {
        calibrator.calibrate(&clean_report(
            1_000 + offset,
            8 + (offset as usize % 2),
            48 + offset as usize,
        ));
    }

    let source_report = clean_report(99_000, 8, 49);
    let calibration_samples_before_attempt = calibrator.calibration_samples();
    let proof = render_proof_pack(&mut calibrator, &source_report);

    ScenarioProofPack {
        scenario: "passing_clean_observation",
        config: ScenarioConfig {
            alpha: config.alpha,
            min_calibration_samples: config.min_calibration_samples,
        },
        source_report: scrub_source_report(&source_report),
        calibration_samples_before_attempt,
        proof,
        boundary: None,
    }
}

fn failing_proof_pack() -> ScenarioProofPack {
    let config = ConformalConfig::new(0.05).min_samples(5);
    let mut calibrator = ConformalCalibrator::new(config.clone());

    for offset in 0..8 {
        calibrator.calibrate(&clean_report(
            2_000 + offset,
            7 + (offset as usize % 3),
            44 + offset as usize,
        ));
    }

    let calibration_samples_before_attempt = calibrator.calibration_samples();
    let mut last_source_report = violated_report(199_000);
    let mut proof = None;
    for index in 0..3 {
        last_source_report = violated_report(199_000 + index);
        proof = render_proof_pack(&mut calibrator, &last_source_report);
    }

    ScenarioProofPack {
        scenario: "failing_repeated_violation",
        config: ScenarioConfig {
            alpha: config.alpha,
            min_calibration_samples: config.min_calibration_samples,
        },
        source_report: scrub_source_report(&last_source_report),
        calibration_samples_before_attempt,
        proof,
        boundary: None,
    }
}

fn edge_proof_pack() -> ScenarioProofPack {
    let config = ConformalConfig::new(0.10).min_samples(5);
    let mut calibrator = ConformalCalibrator::new(config.clone());

    for offset in 0..4 {
        calibrator.calibrate(&clean_report(
            3_000 + offset,
            9 + (offset as usize % 2),
            46 + offset as usize,
        ));
    }

    let source_report = clean_report(299_000, 9, 47);
    let calibration_samples_before_attempt = calibrator.calibration_samples();
    let proof = render_proof_pack(&mut calibrator, &source_report);

    ScenarioProofPack {
        scenario: "edge_calibration_boundary_skip",
        config: ScenarioConfig {
            alpha: config.alpha,
            min_calibration_samples: config.min_calibration_samples,
        },
        source_report: scrub_source_report(&source_report),
        calibration_samples_before_attempt,
        proof,
        boundary: Some(BoundaryState {
            prediction_available: false,
            calibration_samples_after_attempt: calibrator.calibration_samples(),
            calibrated_after_attempt: calibrator.is_calibrated(),
            reason: "observation consumed by calibration boundary transition",
        }),
    }
}

#[test]
fn proof_pack_output_scrubbed() {
    let snapshot = vec![
        passing_proof_pack(),
        failing_proof_pack(),
        edge_proof_pack(),
    ];
    assert_json_snapshot!("proof_pack_output_scrubbed", snapshot);
}
