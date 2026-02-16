//! Track-6 closed-loop impact report contract checks (asupersync-3gf4i).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const REPORT_JSON: &str =
    include_str!("../formal/lean/coverage/proof_impact_closed_loop_report_v1.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

fn bead_ids() -> BTreeSet<String> {
    BEADS_JSONL
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .fold(BTreeSet::new(), |mut ids, entry| {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                ids.insert(id.to_string());
            }
            if let Some(external_ref) = entry.get("external_ref").and_then(Value::as_str) {
                ids.insert(external_ref.to_string());
            }
            ids
        })
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> &'a [Value] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{ctx} must be an array"))
}

fn as_object<'a>(value: &'a Value, ctx: &str) -> &'a serde_json::Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{ctx} must be an object"))
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{ctx} must be a string"))
}

fn as_f64(value: &Value, ctx: &str) -> f64 {
    value
        .as_f64()
        .unwrap_or_else(|| panic!("{ctx} must be numeric"))
}

fn approx_eq(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-9
}

#[test]
fn closed_loop_report_has_required_top_level_contract() {
    let report: Value = serde_json::from_str(REPORT_JSON).expect("report JSON must parse");
    let report_obj = as_object(&report, "report");

    assert_eq!(
        as_str(
            report_obj
                .get("schema_version")
                .expect("schema_version is required"),
            "schema_version",
        ),
        "1.0.0"
    );
    assert_eq!(
        as_str(
            report_obj.get("report_id").expect("report_id is required"),
            "report_id",
        ),
        "lean.track6.closed_loop_impact_report.v1"
    );
    assert_eq!(
        as_str(
            report_obj
                .get("generated_by")
                .expect("generated_by is required"),
            "generated_by",
        ),
        "asupersync-3gf4i"
    );

    for required in [
        "generated_at",
        "source_artifacts",
        "periodicity_contract",
        "measurement_framework",
        "report_snapshot",
    ] {
        assert!(
            report_obj.contains_key(required),
            "missing field {required}"
        );
    }

    let source_artifacts = as_array(
        report_obj
            .get("source_artifacts")
            .expect("source_artifacts is required"),
        "source_artifacts",
    );
    assert!(
        source_artifacts.len() >= 5,
        "source_artifacts must include all upstream coverage contracts"
    );
    for artifact in source_artifacts {
        let path = as_str(artifact, "source_artifacts[]");
        assert!(
            Path::new(path).exists(),
            "missing source artifact path: {path}"
        );
    }
}

#[test]
fn periodicity_contract_is_deterministic() {
    let report: Value = serde_json::from_str(REPORT_JSON).expect("report JSON must parse");
    let periodicity = as_object(
        report
            .get("periodicity_contract")
            .expect("periodicity_contract is required"),
        "periodicity_contract",
    );

    assert_eq!(
        as_str(
            periodicity
                .get("cadence_id")
                .expect("cadence_id is required"),
            "cadence_id",
        ),
        "weekly"
    );
    assert_eq!(
        periodicity
            .get("max_interval_days")
            .and_then(Value::as_u64)
            .expect("max_interval_days must be numeric"),
        7
    );

    let windows = as_array(
        periodicity.get("windows").expect("windows is required"),
        "periodicity_contract.windows",
    );
    assert_eq!(windows.len(), 2, "expected baseline + current windows");
    let baseline = as_object(&windows[0], "windows[0]");
    let current = as_object(&windows[1], "windows[1]");
    assert_eq!(
        as_str(
            baseline.get("window_id").expect("window_id is required"),
            "windows[0].window_id",
        ),
        "baseline"
    );
    assert_eq!(
        as_str(
            current.get("window_id").expect("window_id is required"),
            "windows[1].window_id",
        ),
        "current"
    );
    let baseline_from = as_str(
        baseline.get("from_utc").expect("from_utc is required"),
        "windows[0].from_utc",
    );
    let baseline_to = as_str(
        baseline.get("to_utc").expect("to_utc is required"),
        "windows[0].to_utc",
    );
    let current_from = as_str(
        current.get("from_utc").expect("from_utc is required"),
        "windows[1].from_utc",
    );
    let current_to = as_str(
        current.get("to_utc").expect("to_utc is required"),
        "windows[1].to_utc",
    );
    assert!(
        baseline_from < baseline_to,
        "baseline window must be ordered"
    );
    assert!(current_from < current_to, "current window must be ordered");
    assert!(
        baseline_to < current_from,
        "baseline and current windows must not overlap"
    );

    let reproducibility_rules = as_array(
        periodicity
            .get("reproducibility_rules")
            .expect("reproducibility_rules is required"),
        "periodicity_contract.reproducibility_rules",
    );
    assert!(!reproducibility_rules.is_empty());
}

#[test]
fn dimension_contracts_cover_performance_reliability_and_correctness() {
    let report: Value = serde_json::from_str(REPORT_JSON).expect("report JSON must parse");
    let bead_ids = bead_ids();

    let framework = as_object(
        report
            .get("measurement_framework")
            .expect("measurement_framework is required"),
        "measurement_framework",
    );

    let policy = as_object(
        framework
            .get("attribution_policy")
            .expect("attribution_policy is required"),
        "measurement_framework.attribution_policy",
    );
    for flag in [
        "coverage_change_beads_required",
        "source_field_path_required",
        "confidence_note_required",
        "before_after_delta_required",
    ] {
        assert!(
            policy
                .get(flag)
                .and_then(Value::as_bool)
                .expect("policy flags must be bool"),
            "policy flag must be true: {flag}"
        );
    }

    assert_dimension_contracts(framework, &bead_ids);
    assert_performance_workloads(framework);
}

fn assert_dimension_contracts(
    framework: &serde_json::Map<String, Value>,
    bead_ids: &BTreeSet<String>,
) {
    let contracts = as_array(
        framework
            .get("dimension_contracts")
            .expect("dimension_contracts is required"),
        "measurement_framework.dimension_contracts",
    );
    assert_eq!(contracts.len(), 3, "must define three dimension contracts");

    let mut dimensions = BTreeSet::new();
    for contract in contracts {
        let obj = as_object(contract, "dimension_contracts[]");
        let dimension_id = as_str(
            obj.get("dimension_id").expect("dimension_id is required"),
            "dimension_id",
        );
        dimensions.insert(dimension_id.to_string());

        let owner_bead = as_str(
            obj.get("owner_bead").expect("owner_bead is required"),
            "owner_bead",
        );
        assert!(
            bead_ids.contains(owner_bead),
            "unknown owner_bead {owner_bead}"
        );

        let coverage_inputs = as_array(
            obj.get("coverage_inputs")
                .expect("coverage_inputs is required"),
            "coverage_inputs",
        );
        assert!(
            !coverage_inputs.is_empty(),
            "coverage_inputs must not be empty"
        );
        for input in coverage_inputs {
            let path = as_str(input, "coverage_inputs[]");
            assert!(
                Path::new(path).exists(),
                "missing coverage input path: {path}"
            );
        }

        let required_fields = as_array(
            obj.get("required_report_fields")
                .expect("required_report_fields is required"),
            "required_report_fields",
        )
        .iter()
        .map(|field| as_str(field, "required_report_fields[]"))
        .collect::<BTreeSet<_>>();
        for field in [
            "metric_id",
            "baseline",
            "current",
            "delta",
            "unit",
            "confidence",
            "attribution",
        ] {
            assert!(
                required_fields.contains(field),
                "missing required_report_field {field} in {dimension_id}"
            );
        }

        let commands = as_array(
            obj.get("mandatory_commands")
                .expect("mandatory_commands is required"),
            "mandatory_commands",
        );
        assert!(!commands.is_empty(), "mandatory_commands must not be empty");
        for command in commands {
            let command = as_str(command, "mandatory_commands[]");
            assert!(
                command.starts_with("rch exec -- "),
                "command must be offloaded via rch: {command}"
            );
        }
    }

    assert_eq!(
        dimensions,
        BTreeSet::from([
            "performance".to_string(),
            "reliability".to_string(),
            "correctness".to_string(),
        ])
    );
}

fn assert_performance_workloads(framework: &serde_json::Map<String, Value>) {
    let workloads = as_array(
        framework
            .get("performance_workloads")
            .expect("performance_workloads is required"),
        "measurement_framework.performance_workloads",
    );
    assert!(
        !workloads.is_empty(),
        "performance_workloads must not be empty"
    );

    let mut workload_ids = BTreeSet::new();
    for workload in workloads {
        let obj = as_object(workload, "performance_workloads[]");
        let workload_id = as_str(
            obj.get("workload_id").expect("workload_id is required"),
            "performance_workloads[].workload_id",
        );
        assert!(
            workload_ids.insert(workload_id.to_string()),
            "duplicate workload_id: {workload_id}"
        );

        let target_surface = as_array(
            obj.get("target_surface")
                .expect("target_surface is required"),
            "performance_workloads[].target_surface",
        );
        assert!(
            !target_surface.is_empty(),
            "target_surface must not be empty for {workload_id}"
        );

        let constraint_ids = as_array(
            obj.get("constraint_ids")
                .expect("constraint_ids is required"),
            "performance_workloads[].constraint_ids",
        );
        assert!(
            !constraint_ids.is_empty(),
            "constraint_ids must not be empty for {workload_id}"
        );

        let repro_command = as_str(
            obj.get("repro_command").expect("repro_command is required"),
            "performance_workloads[].repro_command",
        );
        assert!(
            repro_command.starts_with("rch exec -- "),
            "repro_command must use rch: {repro_command}"
        );

        for artifact_field in ["baseline_artifact", "current_artifact"] {
            assert!(
                obj.get(artifact_field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "{artifact_field} must be non-empty for {workload_id}"
            );
        }
    }
}

fn assert_snapshot_metrics(
    metrics: &[Value],
    bead_ids: &BTreeSet<String>,
) -> ((f64, f64, f64), (f64, f64, f64)) {
    assert_eq!(metrics.len(), 3, "must report one metric per dimension");
    let mut dimensions = BTreeSet::new();
    let mut reliability_metric = None;
    let mut correctness_metric = None;
    for metric in metrics {
        let obj = as_object(metric, "metrics[]");
        let dimension_id = as_str(
            obj.get("dimension_id").expect("dimension_id is required"),
            "metrics[].dimension_id",
        );
        dimensions.insert(dimension_id.to_string());

        let baseline = as_f64(
            obj.get("baseline").expect("baseline is required"),
            "metrics[].baseline",
        );
        let current = as_f64(
            obj.get("current").expect("current is required"),
            "metrics[].current",
        );
        let delta = as_f64(
            obj.get("delta").expect("delta is required"),
            "metrics[].delta",
        );
        assert!(
            approx_eq(delta, current - baseline),
            "delta must equal current - baseline for {dimension_id}"
        );
        if dimension_id == "reliability" {
            reliability_metric = Some((baseline, current, delta));
        } else if dimension_id == "correctness" {
            correctness_metric = Some((baseline, current, delta));
        }

        let confidence_note = as_str(
            obj.get("confidence_note")
                .expect("confidence_note is required"),
            "metrics[].confidence_note",
        );
        assert!(
            !confidence_note.trim().is_empty(),
            "confidence_note must be non-empty"
        );

        let attribution = as_object(
            obj.get("attribution").expect("attribution is required"),
            "metrics[].attribution",
        );
        let coverage_change_beads = as_array(
            attribution
                .get("coverage_change_beads")
                .expect("coverage_change_beads is required"),
            "metrics[].attribution.coverage_change_beads",
        );
        assert!(
            !coverage_change_beads.is_empty(),
            "coverage_change_beads must not be empty"
        );
        for bead in coverage_change_beads {
            let bead = as_str(bead, "coverage_change_beads[]");
            assert!(
                bead_ids.contains(bead),
                "unknown coverage-change bead {bead}"
            );
        }
        assert!(
            attribution
                .get("source_field_path")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.trim().is_empty()),
            "source_field_path must be non-empty"
        );

        let supporting_commands = as_array(
            obj.get("supporting_commands")
                .expect("supporting_commands is required"),
            "metrics[].supporting_commands",
        );
        assert!(
            !supporting_commands.is_empty(),
            "supporting_commands must not be empty"
        );
        for command in supporting_commands {
            let command = as_str(command, "supporting_commands[]");
            assert!(
                command.starts_with("rch exec -- "),
                "supporting command must use rch: {command}"
            );
        }
    }
    assert_eq!(
        dimensions,
        BTreeSet::from([
            "performance".to_string(),
            "reliability".to_string(),
            "correctness".to_string(),
        ])
    );
    (
        reliability_metric.expect("reliability metric must be present"),
        correctness_metric.expect("correctness metric must be present"),
    )
}

fn assert_performance_delta_evidence(
    snapshot: &serde_json::Map<String, Value>,
    defined_workloads: &BTreeSet<String>,
) {
    let performance_delta_evidence = as_object(
        snapshot
            .get("performance_delta_evidence")
            .expect("performance_delta_evidence is required"),
        "report_snapshot.performance_delta_evidence",
    );
    let workload_results = as_array(
        performance_delta_evidence
            .get("workload_results")
            .expect("workload_results is required"),
        "report_snapshot.performance_delta_evidence.workload_results",
    );
    assert!(
        !workload_results.is_empty(),
        "workload_results must not be empty"
    );
    for result in workload_results {
        let obj = as_object(result, "workload_results[]");
        let workload_id = as_str(
            obj.get("workload_id").expect("workload_id is required"),
            "workload_results[].workload_id",
        );
        assert!(
            defined_workloads.contains(workload_id),
            "workload_result references undefined workload_id: {workload_id}"
        );

        let before = as_f64(obj.get("before").expect("before is required"), "before");
        let after = as_f64(obj.get("after").expect("after is required"), "after");
        let delta = as_f64(obj.get("delta").expect("delta is required"), "delta");
        assert!(
            approx_eq(delta, after - before),
            "workload_result delta must equal after - before for {workload_id}"
        );
        for text_field in ["confidence_note", "workload_definition"] {
            assert!(
                obj.get(text_field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "{text_field} must be non-empty for {workload_id}"
            );
        }
    }
    let attribution_notes = as_array(
        performance_delta_evidence
            .get("attribution_notes")
            .expect("attribution_notes is required"),
        "report_snapshot.performance_delta_evidence.attribution_notes",
    );
    assert!(
        !attribution_notes.is_empty(),
        "attribution_notes must not be empty"
    );
}

fn assert_reliability_delta_evidence(
    snapshot: &serde_json::Map<String, Value>,
    reliability_metric: (f64, f64, f64),
    bead_ids: &BTreeSet<String>,
) {
    let reliability_delta_evidence = as_object(
        snapshot
            .get("reliability_delta_evidence")
            .expect("reliability_delta_evidence is required"),
        "report_snapshot.reliability_delta_evidence",
    );
    let milestones = as_array(
        reliability_delta_evidence
            .get("milestone_series")
            .expect("milestone_series is required"),
        "report_snapshot.reliability_delta_evidence.milestone_series",
    );
    assert!(
        milestones.len() >= 2,
        "milestone_series must include baseline/current reliability snapshots"
    );
    let mut milestone_by_window = BTreeMap::new();
    for milestone in milestones {
        let obj = as_object(milestone, "milestone_series[]");
        let milestone_id = as_str(
            obj.get("milestone_id").expect("milestone_id is required"),
            "milestone_series[].milestone_id",
        );
        assert!(
            !milestone_id.trim().is_empty(),
            "milestone_id must be non-empty"
        );
        let window_id = as_str(
            obj.get("window_id").expect("window_id is required"),
            "milestone_series[].window_id",
        );
        assert!(
            obj.get("coverage_artifact")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "coverage_artifact must be non-empty for {milestone_id}"
        );
        let coverage_ratio = as_f64(
            obj.get("coverage_ratio")
                .expect("coverage_ratio is required"),
            "milestone_series[].coverage_ratio",
        );
        assert!(
            (0.0..=1.0).contains(&coverage_ratio),
            "coverage_ratio must be in [0,1] for {milestone_id}"
        );
        let triage = as_f64(
            obj.get("diagnostic_time_to_triage_minutes")
                .expect("diagnostic_time_to_triage_minutes is required"),
            "milestone_series[].diagnostic_time_to_triage_minutes",
        );
        let frequency = as_f64(
            obj.get("incident_frequency_per_1000_runs")
                .expect("incident_frequency_per_1000_runs is required"),
            "milestone_series[].incident_frequency_per_1000_runs",
        );
        let severity = as_f64(
            obj.get("severity_weighted_incident_index")
                .expect("severity_weighted_incident_index is required"),
            "milestone_series[].severity_weighted_incident_index",
        );
        assert!(triage >= 0.0, "triage metric must be non-negative");
        assert!(frequency >= 0.0, "frequency metric must be non-negative");
        assert!(severity >= 0.0, "severity metric must be non-negative");
        milestone_by_window.insert(
            window_id.to_string(),
            (coverage_ratio, triage, frequency, severity),
        );
    }
    let (baseline_coverage, baseline_triage, baseline_frequency, baseline_severity) =
        milestone_by_window
            .get("baseline")
            .copied()
            .expect("baseline reliability milestone is required");
    let (current_coverage, current_triage, current_frequency, current_severity) =
        milestone_by_window
            .get("current")
            .copied()
            .expect("current reliability milestone is required");

    assert_reliability_deltas(
        reliability_delta_evidence,
        (baseline_triage, baseline_frequency, baseline_severity),
        (current_triage, current_frequency, current_severity),
        (baseline_coverage, current_coverage),
        reliability_metric,
        bead_ids,
    );
}

fn assert_reliability_deltas(
    evidence: &serde_json::Map<String, Value>,
    baseline: (f64, f64, f64),
    current: (f64, f64, f64),
    coverage: (f64, f64),
    reliability_metric: (f64, f64, f64),
    bead_ids: &BTreeSet<String>,
) {
    let delta_summary = as_object(
        evidence
            .get("delta_summary")
            .expect("delta_summary is required"),
        "report_snapshot.reliability_delta_evidence.delta_summary",
    );
    let triage_delta = as_f64(
        delta_summary
            .get("diagnostic_time_to_triage_minutes_delta")
            .expect("diagnostic_time_to_triage_minutes_delta is required"),
        "delta_summary.diagnostic_time_to_triage_minutes_delta",
    );
    let frequency_delta = as_f64(
        delta_summary
            .get("incident_frequency_per_1000_runs_delta")
            .expect("incident_frequency_per_1000_runs_delta is required"),
        "delta_summary.incident_frequency_per_1000_runs_delta",
    );
    let severity_delta = as_f64(
        delta_summary
            .get("severity_weighted_incident_index_delta")
            .expect("severity_weighted_incident_index_delta is required"),
        "delta_summary.severity_weighted_incident_index_delta",
    );
    assert!(approx_eq(triage_delta, current.0 - baseline.0));
    assert!(approx_eq(frequency_delta, current.1 - baseline.1));
    assert!(approx_eq(severity_delta, current.2 - baseline.2));
    assert!(triage_delta <= 0.0, "triage delta should trend down");
    assert!(
        frequency_delta <= 0.0,
        "incident frequency delta should trend down"
    );
    assert!(
        severity_delta <= 0.0,
        "incident severity delta should trend down"
    );
    assert!(
        approx_eq(reliability_metric.0, coverage.0)
            && approx_eq(reliability_metric.1, coverage.1)
            && approx_eq(reliability_metric.2, coverage.1 - coverage.0),
        "reliability metric row must align with reliability milestone coverage ratios"
    );

    let linked_beads = as_array(
        delta_summary
            .get("linked_beads")
            .expect("linked_beads is required"),
        "delta_summary.linked_beads",
    );
    assert!(!linked_beads.is_empty(), "linked_beads must not be empty");
    for bead in linked_beads {
        let bead = as_str(bead, "linked_beads[]");
        assert!(bead_ids.contains(bead), "unknown linked bead {bead}");
    }
    assert!(
        linked_beads
            .iter()
            .filter_map(Value::as_str)
            .any(|bead| bead == "asupersync-2ue65"),
        "linked_beads must include asupersync-2ue65"
    );

    assert_reliability_attribution_and_caveats(evidence);
}

fn assert_reliability_attribution_and_caveats(
    evidence: &serde_json::Map<String, Value>,
) {
    let attribution_method = as_object(
        evidence
            .get("attribution_method")
            .expect("attribution_method is required"),
        "report_snapshot.reliability_delta_evidence.attribution_method",
    );
    for field in ["method_id", "description"] {
        assert!(
            attribution_method
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "attribution_method field must be non-empty: {field}"
        );
    }
    let required_commands = as_array(
        attribution_method
            .get("required_commands")
            .expect("required_commands is required"),
        "attribution_method.required_commands",
    );
    assert!(
        !required_commands.is_empty(),
        "attribution_method.required_commands must not be empty"
    );
    for command in required_commands {
        let command = as_str(command, "required_commands[]");
        assert!(
            command.starts_with("rch exec -- "),
            "required command must use rch: {command}"
        );
    }
    let assumptions = as_array(
        attribution_method
            .get("assumptions")
            .expect("assumptions is required"),
        "attribution_method.assumptions",
    );
    assert!(!assumptions.is_empty(), "assumptions must not be empty");

    let reliability_caveats = as_array(
        evidence
            .get("caveats")
            .expect("caveats is required"),
        "report_snapshot.reliability_delta_evidence.caveats",
    );
    assert!(
        !reliability_caveats.is_empty(),
        "reliability caveats must not be empty"
    );
}

fn assert_correctness_delta_evidence(
    snapshot: &serde_json::Map<String, Value>,
    correctness_metric: (f64, f64, f64),
    bead_ids: &BTreeSet<String>,
) {
    let correctness_delta_evidence = as_object(
        snapshot
            .get("correctness_delta_evidence")
            .expect("correctness_delta_evidence is required"),
        "report_snapshot.correctness_delta_evidence",
    );
    let correctness_milestones = as_array(
        correctness_delta_evidence
            .get("maturity_milestones")
            .expect("maturity_milestones is required"),
        "report_snapshot.correctness_delta_evidence.maturity_milestones",
    );
    assert!(
        correctness_milestones.len() >= 2,
        "maturity_milestones must include baseline/current correctness snapshots"
    );
    let mut correctness_by_window = BTreeMap::new();
    for milestone in correctness_milestones {
        let obj = as_object(milestone, "maturity_milestones[]");
        let milestone_id = as_str(
            obj.get("milestone_id").expect("milestone_id is required"),
            "maturity_milestones[].milestone_id",
        );
        assert!(
            !milestone_id.trim().is_empty(),
            "milestone_id must be non-empty"
        );
        let window_id = as_str(
            obj.get("window_id").expect("window_id is required"),
            "maturity_milestones[].window_id",
        );
        assert!(
            obj.get("conformance_gate_mode")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "conformance_gate_mode must be non-empty for {milestone_id}"
        );
        let gate_ratio = as_f64(
            obj.get("proof_gate_coverage_ratio")
                .expect("proof_gate_coverage_ratio is required"),
            "maturity_milestones[].proof_gate_coverage_ratio",
        );
        assert!(
            (0.0..=1.0).contains(&gate_ratio),
            "proof_gate_coverage_ratio must be in [0,1] for {milestone_id}"
        );
        let regressions = as_f64(
            obj.get("regressions_per_100_changes")
                .expect("regressions_per_100_changes is required"),
            "maturity_milestones[].regressions_per_100_changes",
        );
        let rework = as_f64(
            obj.get("rework_hours_per_regression")
                .expect("rework_hours_per_regression is required"),
            "maturity_milestones[].rework_hours_per_regression",
        );
        let diagnosis = as_f64(
            obj.get("time_to_diagnosis_hours")
                .expect("time_to_diagnosis_hours is required"),
            "maturity_milestones[].time_to_diagnosis_hours",
        );
        assert!(
            regressions >= 0.0,
            "regressions metric must be non-negative"
        );
        assert!(rework >= 0.0, "rework metric must be non-negative");
        assert!(
            diagnosis >= 0.0,
            "time_to_diagnosis metric must be non-negative"
        );
        correctness_by_window.insert(
            window_id.to_string(),
            (gate_ratio, regressions, rework, diagnosis),
        );
    }

    let (baseline_gate_ratio, baseline_regressions, baseline_rework, baseline_diagnosis) =
        correctness_by_window
            .get("baseline")
            .copied()
            .expect("baseline correctness milestone is required");
    let (current_gate_ratio, current_regressions, current_rework, current_diagnosis) =
        correctness_by_window
            .get("current")
            .copied()
            .expect("current correctness milestone is required");
    assert!(
        approx_eq(correctness_metric.0, baseline_gate_ratio)
            && approx_eq(correctness_metric.1, current_gate_ratio)
            && approx_eq(
                correctness_metric.2,
                current_gate_ratio - baseline_gate_ratio
            ),
        "correctness metric row must align with correctness maturity gate ratios"
    );

    assert_correctness_deltas(
        correctness_delta_evidence,
        (baseline_regressions, baseline_rework, baseline_diagnosis),
        (current_regressions, current_rework, current_diagnosis),
        bead_ids,
    );
}

fn assert_correctness_deltas(
    evidence: &serde_json::Map<String, Value>,
    baseline: (f64, f64, f64),
    current: (f64, f64, f64),
    bead_ids: &BTreeSet<String>,
) {
    let correctness_delta_summary = as_object(
        evidence
            .get("delta_summary")
            .expect("delta_summary is required"),
        "report_snapshot.correctness_delta_evidence.delta_summary",
    );
    let regressions_delta = as_f64(
        correctness_delta_summary
            .get("regressions_per_100_changes_delta")
            .expect("regressions_per_100_changes_delta is required"),
        "delta_summary.regressions_per_100_changes_delta",
    );
    let rework_delta = as_f64(
        correctness_delta_summary
            .get("rework_hours_per_regression_delta")
            .expect("rework_hours_per_regression_delta is required"),
        "delta_summary.rework_hours_per_regression_delta",
    );
    let diagnosis_delta = as_f64(
        correctness_delta_summary
            .get("time_to_diagnosis_hours_delta")
            .expect("time_to_diagnosis_hours_delta is required"),
        "delta_summary.time_to_diagnosis_hours_delta",
    );
    assert!(approx_eq(regressions_delta, current.0 - baseline.0));
    assert!(approx_eq(rework_delta, current.1 - baseline.1));
    assert!(approx_eq(diagnosis_delta, current.2 - baseline.2));
    assert!(
        regressions_delta <= 0.0,
        "regressions trend should not increase"
    );
    assert!(rework_delta <= 0.0, "rework trend should not increase");
    assert!(
        diagnosis_delta <= 0.0,
        "time-to-diagnosis trend should not increase"
    );
    assert!(
        correctness_delta_summary
            .get("confidence_note")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "correctness delta summary must include confidence_note"
    );

    let repro_queries = as_array(
        evidence
            .get("repro_queries")
            .expect("repro_queries is required"),
        "report_snapshot.correctness_delta_evidence.repro_queries",
    );
    assert!(!repro_queries.is_empty(), "repro_queries must not be empty");
    for query in repro_queries {
        let query = as_str(query, "repro_queries[]");
        assert!(
            query.starts_with("rch exec -- "),
            "repro query must use rch: {query}"
        );
    }

    let governance_adjustments = as_array(
        evidence
            .get("governance_adjustments")
            .expect("governance_adjustments is required"),
        "report_snapshot.correctness_delta_evidence.governance_adjustments",
    );
    assert!(
        !governance_adjustments.is_empty(),
        "governance_adjustments must not be empty"
    );
    for adjustment in governance_adjustments {
        let obj = as_object(adjustment, "governance_adjustments[]");
        for field in ["adjustment_id", "trigger", "owner_bead", "status"] {
            assert!(
                obj.get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "governance_adjustment field must be non-empty: {field}"
            );
        }
        let owner_bead = as_str(
            obj.get("owner_bead").expect("owner_bead is required"),
            "governance_adjustments[].owner_bead",
        );
        assert!(
            bead_ids.contains(owner_bead),
            "unknown governance owner bead {owner_bead}"
        );
    }

    let correctness_caveats = as_array(
        evidence
            .get("caveats")
            .expect("caveats is required"),
        "report_snapshot.correctness_delta_evidence.caveats",
    );
    assert!(
        !correctness_caveats.is_empty(),
        "correctness caveats must not be empty"
    );
}

fn assert_playbook_handoff(
    snapshot: &serde_json::Map<String, Value>,
    bead_ids: &BTreeSet<String>,
) {
    let handoff = as_object(
        snapshot
            .get("playbook_handoff_contract")
            .expect("playbook_handoff_contract is required"),
        "report_snapshot.playbook_handoff_contract",
    );
    assert_eq!(
        as_str(
            handoff.get("target_bead").expect("target_bead is required"),
            "playbook_handoff_contract.target_bead",
        ),
        "asupersync-3gfir"
    );
    let required_fields = as_array(
        handoff
            .get("required_case_study_fields")
            .expect("required_case_study_fields is required"),
        "playbook_handoff_contract.required_case_study_fields",
    );
    let required_fields = required_fields
        .iter()
        .map(|field| as_str(field, "required_case_study_fields[]"))
        .collect::<BTreeSet<_>>();
    for field in [
        "intervention_id",
        "proof_anchor_ids",
        "before_after_metrics",
        "confidence_notes",
        "repro_commands",
        "residual_risks",
    ] {
        assert!(
            required_fields.contains(field),
            "required_case_study_fields missing {field}"
        );
    }

    let workflow_template = as_object(
        handoff
            .get("workflow_template")
            .expect("workflow_template is required"),
        "playbook_handoff_contract.workflow_template",
    );
    for field in ["steps", "checklists", "failure_modes", "templates"] {
        let items = as_array(
            workflow_template
                .get(field)
                .expect("workflow field is required"),
            "playbook_handoff_contract.workflow_template.*",
        );
        assert!(
            !items.is_empty(),
            "workflow_template.{field} must not be empty"
        );
        for item in items {
            let item = as_str(item, "workflow item");
            assert!(!item.trim().is_empty(), "workflow item must be non-empty");
        }
    }

    assert_case_studies(handoff, bead_ids);
}

fn assert_case_studies(
    handoff: &serde_json::Map<String, Value>,
    bead_ids: &BTreeSet<String>,
) {
    let case_studies = as_array(
        handoff
            .get("case_studies")
            .expect("case_studies is required"),
        "playbook_handoff_contract.case_studies",
    );
    assert!(
        case_studies.len() >= 3,
        "playbook must include at least three case studies"
    );
    let mut dimensions = BTreeSet::new();
    for case in case_studies {
        let case = as_object(case, "case_studies[]");
        for field in [
            "case_id",
            "dimension",
            "baseline",
            "intervention",
            "measured_outcome",
        ] {
            assert!(
                case.get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "case study field must be non-empty: {field}"
            );
        }
        let dimension = as_str(
            case.get("dimension").expect("dimension is required"),
            "case_studies[].dimension",
        );
        dimensions.insert(dimension.to_string());

        for link_field in ["proof_anchor_ids", "mapping_links", "conformance_links"] {
            let links = as_array(
                case.get(link_field).expect("link field is required"),
                "case study links",
            );
            assert!(!links.is_empty(), "{link_field} must not be empty");
            for link in links {
                let link = as_str(link, "case study link");
                let path = link
                    .split('#')
                    .next()
                    .expect("split always yields one element")
                    .trim();
                assert!(!path.is_empty(), "case study link path must be non-empty");
                assert!(
                    Path::new(path).exists(),
                    "case study link path must exist: {path}"
                );
            }
        }

        let lineage = as_array(
            case.get("bead_lineage").expect("bead_lineage is required"),
            "case_studies[].bead_lineage",
        );
        assert!(!lineage.is_empty(), "bead_lineage must not be empty");
        for bead in lineage {
            let bead = as_str(bead, "bead_lineage[]");
            assert!(bead_ids.contains(bead), "unknown bead in lineage: {bead}");
        }

        let repro_commands = as_array(
            case.get("repro_commands")
                .expect("repro_commands is required"),
            "case_studies[].repro_commands",
        );
        assert!(
            !repro_commands.is_empty(),
            "repro_commands must not be empty"
        );
        for command in repro_commands {
            let command = as_str(command, "repro_commands[]");
            assert!(
                command.starts_with("rch exec -- "),
                "repro command must use rch: {command}"
            );
        }

        let residual_risks = as_array(
            case.get("residual_risks")
                .expect("residual_risks is required"),
            "case_studies[].residual_risks",
        );
        assert!(
            !residual_risks.is_empty(),
            "residual_risks must not be empty"
        );
    }
    assert_eq!(
        dimensions,
        BTreeSet::from([
            "performance".to_string(),
            "reliability".to_string(),
            "correctness".to_string(),
        ]),
        "case studies must cover performance/reliability/correctness"
    );
}

#[test]
fn snapshot_metrics_include_deltas_confidence_and_attribution() {
    let report: Value = serde_json::from_str(REPORT_JSON).expect("report JSON must parse");
    let bead_ids = bead_ids();

    let snapshot = as_object(
        report
            .get("report_snapshot")
            .expect("report_snapshot is required"),
        "report_snapshot",
    );
    assert_eq!(
        as_str(
            snapshot
                .get("parent_bead")
                .expect("parent_bead is required"),
            "report_snapshot.parent_bead",
        ),
        "asupersync-3gf4i"
    );
    assert_eq!(
        as_str(
            snapshot.get("cadence_id").expect("cadence_id is required"),
            "report_snapshot.cadence_id",
        ),
        "weekly"
    );

    let metrics = as_array(
        snapshot.get("metrics").expect("metrics is required"),
        "metrics",
    );
    let (reliability_metric, correctness_metric) = assert_snapshot_metrics(metrics, &bead_ids);

    let evidence_commands = as_array(
        snapshot
            .get("evidence_commands")
            .expect("evidence_commands is required"),
        "report_snapshot.evidence_commands",
    );
    assert!(!evidence_commands.is_empty());
    for command in evidence_commands {
        let command = as_str(command, "evidence_commands[]");
        assert!(
            command.starts_with("rch exec -- "),
            "evidence command must use rch: {command}"
        );
    }

    let defined_workloads = as_array(
        report
            .get("measurement_framework")
            .expect("measurement_framework is required")
            .get("performance_workloads")
            .expect("performance_workloads is required"),
        "measurement_framework.performance_workloads",
    )
    .iter()
    .map(|workload| {
        as_str(
            workload
                .get("workload_id")
                .expect("workload_id is required"),
            "performance_workloads[].workload_id",
        )
        .to_string()
    })
    .collect::<BTreeSet<_>>();

    assert_performance_delta_evidence(snapshot, &defined_workloads);
    assert_reliability_delta_evidence(snapshot, reliability_metric, &bead_ids);
    assert_correctness_delta_evidence(snapshot, correctness_metric, &bead_ids);

    let downstream = as_array(
        snapshot
            .get("downstream_consumers")
            .expect("downstream_consumers is required"),
        "report_snapshot.downstream_consumers",
    );
    assert!(!downstream.is_empty());
    for bead in downstream {
        let bead = as_str(bead, "downstream_consumers[]");
        assert!(
            bead_ids.contains(bead),
            "unknown downstream consumer bead {bead}"
        );
    }

    assert_playbook_handoff(snapshot, &bead_ids);
}
