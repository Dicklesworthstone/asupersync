//! Baseline report consistency checks (bd-5w2lq).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const BASELINE_JSON: &str = include_str!("../formal/lean/coverage/baseline_report_v1.json");
const THEOREM_JSON: &str = include_str!("../formal/lean/coverage/theorem_surface_inventory.json");
const STEP_JSON: &str = include_str!("../formal/lean/coverage/step_constructor_coverage.json");
const INVARIANT_JSON: &str =
    include_str!("../formal/lean/coverage/invariant_status_inventory.json");
const GAP_JSON: &str = include_str!("../formal/lean/coverage/gap_risk_sequencing_plan.json");
const FRONTIER_JSON: &str = include_str!("../formal/lean/coverage/lean_frontier_buckets_v1.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

#[test]
fn baseline_report_core_counts_match_sources() {
    let baseline: Value = serde_json::from_str(BASELINE_JSON).expect("baseline report must parse");
    let theorem: Value = serde_json::from_str(THEOREM_JSON).expect("theorem inventory must parse");
    let step: Value = serde_json::from_str(STEP_JSON).expect("step coverage must parse");
    let invariant: Value =
        serde_json::from_str(INVARIANT_JSON).expect("invariant inventory must parse");

    assert_eq!(
        baseline
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be string"),
        "1.0.0"
    );

    let baseline_theorem_count = baseline
        .pointer("/snapshot/theorem_surface/theorem_count")
        .and_then(Value::as_u64)
        .expect("baseline theorem_count must be numeric");
    let theorem_count = theorem
        .get("theorem_count")
        .and_then(Value::as_u64)
        .expect("theorem_count must be numeric");
    assert_eq!(baseline_theorem_count, theorem_count);

    let covered = baseline
        .pointer("/snapshot/step_constructor_coverage/covered")
        .and_then(Value::as_u64)
        .expect("covered count must be numeric");
    let partial = baseline
        .pointer("/snapshot/step_constructor_coverage/partial")
        .and_then(Value::as_u64)
        .expect("partial count must be numeric");
    let missing = baseline
        .pointer("/snapshot/step_constructor_coverage/missing")
        .and_then(Value::as_u64)
        .expect("missing count must be numeric");

    assert_eq!(
        covered,
        step.pointer("/summary/covered")
            .and_then(Value::as_u64)
            .expect("step summary covered must be numeric")
    );
    assert_eq!(
        partial,
        step.pointer("/summary/partial")
            .and_then(Value::as_u64)
            .expect("step summary partial must be numeric")
    );
    assert_eq!(
        missing,
        step.pointer("/summary/missing")
            .and_then(Value::as_u64)
            .expect("step summary missing must be numeric")
    );

    assert_eq!(
        baseline
            .pointer("/snapshot/invariant_status/fully_proven")
            .and_then(Value::as_u64)
            .expect("baseline invariant fully_proven must be numeric"),
        invariant
            .pointer("/summary/fully_proven")
            .and_then(Value::as_u64)
            .expect("invariant fully_proven must be numeric")
    );
    assert_eq!(
        baseline
            .pointer("/snapshot/invariant_status/partially_proven")
            .and_then(Value::as_u64)
            .expect("baseline invariant partially_proven must be numeric"),
        invariant
            .pointer("/summary/partially_proven")
            .and_then(Value::as_u64)
            .expect("invariant partially_proven must be numeric")
    );
    assert_eq!(
        baseline
            .pointer("/snapshot/invariant_status/unproven")
            .and_then(Value::as_u64)
            .expect("baseline invariant unproven must be numeric"),
        invariant
            .pointer("/summary/unproven")
            .and_then(Value::as_u64)
            .expect("invariant unproven must be numeric")
    );
}

#[test]
fn baseline_report_frontier_counts_match_frontier_report() {
    let baseline: Value = serde_json::from_str(BASELINE_JSON).expect("baseline report must parse");
    let frontier: Value = serde_json::from_str(FRONTIER_JSON).expect("frontier report must parse");

    assert_eq!(
        baseline
            .pointer("/snapshot/frontier_buckets/diagnostics_total")
            .and_then(Value::as_u64)
            .expect("baseline frontier diagnostics_total must be numeric"),
        frontier
            .get("diagnostics_total")
            .and_then(Value::as_u64)
            .expect("frontier diagnostics_total must be numeric")
    );
    assert_eq!(
        baseline
            .pointer("/snapshot/frontier_buckets/errors_total")
            .and_then(Value::as_u64)
            .expect("baseline frontier errors_total must be numeric"),
        frontier
            .get("errors_total")
            .and_then(Value::as_u64)
            .expect("frontier errors_total must be numeric")
    );
    assert_eq!(
        baseline
            .pointer("/snapshot/frontier_buckets/warnings_total")
            .and_then(Value::as_u64)
            .expect("baseline frontier warnings_total must be numeric"),
        frontier
            .get("warnings_total")
            .and_then(Value::as_u64)
            .expect("frontier warnings_total must be numeric")
    );
    assert_eq!(
        baseline
            .pointer("/snapshot/frontier_buckets/bucket_count")
            .and_then(Value::as_u64)
            .expect("baseline frontier bucket_count must be numeric"),
        frontier
            .get("buckets")
            .and_then(Value::as_array)
            .expect("frontier buckets must be an array")
            .len() as u64
    );
}

#[test]
fn baseline_report_gap_priority_matches_gap_plan() {
    let baseline: Value = serde_json::from_str(BASELINE_JSON).expect("baseline report must parse");
    let gap: Value = serde_json::from_str(GAP_JSON).expect("gap plan must parse");

    let baseline_first_class = baseline
        .pointer("/snapshot/gap_priority/first_class_blockers")
        .and_then(Value::as_array)
        .expect("baseline first_class_blockers must be an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("baseline first_class_blocker values must be strings")
        })
        .collect::<Vec<_>>();
    let gap_first_class = gap
        .get("first_class_blockers")
        .and_then(Value::as_array)
        .expect("gap plan first_class_blockers must be an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("gap plan first_class_blocker values must be strings")
        })
        .collect::<Vec<_>>();
    assert_eq!(baseline_first_class, gap_first_class);
}

#[test]
fn baseline_report_references_existing_beads_and_has_cadence() {
    let baseline: Value = serde_json::from_str(BASELINE_JSON).expect("baseline report must parse");
    let bead_ids = BEADS_JSONL
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
        });

    let ownership_rows = baseline
        .get("ownership_map")
        .and_then(Value::as_array)
        .expect("ownership_map must be an array");
    assert!(
        !ownership_rows.is_empty(),
        "ownership_map must not be empty"
    );
    for row in ownership_rows {
        let bead_id = row
            .get("bead_id")
            .and_then(Value::as_str)
            .expect("ownership bead_id must be string");
        assert!(
            bead_ids.contains(bead_id),
            "ownership_map references unknown bead {bead_id}"
        );
    }

    let refresh_triggers = baseline
        .pointer("/maintenance_cadence/refresh_triggers")
        .and_then(Value::as_array)
        .expect("refresh_triggers must be an array");
    assert!(
        refresh_triggers.len() >= 3,
        "baseline cadence must define at least 3 refresh triggers"
    );

    let gates = baseline
        .pointer("/maintenance_cadence/verification_gates")
        .and_then(Value::as_array)
        .expect("verification_gates must be an array")
        .iter()
        .map(|v| v.as_str().expect("verification gates must be strings"))
        .collect::<BTreeSet<_>>();
    assert!(gates.contains("cargo fmt --check"));
    assert!(gates.contains("cargo check --all-targets"));
    assert!(gates.contains("cargo clippy --all-targets -- -D warnings"));
    assert!(gates.contains("cargo test"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn baseline_report_track2_burndown_and_closure_gate_are_well_formed() {
    let baseline: Value = serde_json::from_str(BASELINE_JSON).expect("baseline report must parse");
    let frontier: Value = serde_json::from_str(FRONTIER_JSON).expect("frontier report must parse");

    let dashboard = baseline
        .get("track2_frontier_burndown_dashboard")
        .and_then(Value::as_object)
        .expect("track2_frontier_burndown_dashboard must be object");
    assert_eq!(
        dashboard
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("dashboard schema_version must be string"),
        "1.0.0"
    );

    let runs = dashboard
        .get("runs")
        .and_then(Value::as_array)
        .expect("dashboard runs must be array");
    assert!(!runs.is_empty(), "dashboard runs must not be empty");

    let mut previous_run_index = 0_u64;
    for run in runs {
        let run_index = run
            .get("run_index")
            .and_then(Value::as_u64)
            .expect("run_index must be numeric");
        assert!(
            run_index > previous_run_index,
            "run_index values must be strictly increasing"
        );
        previous_run_index = run_index;
    }

    let latest = runs.last().expect("runs is non-empty");
    let latest_errors = latest
        .get("errors_total")
        .and_then(Value::as_u64)
        .expect("latest errors_total must be numeric");
    let latest_warnings = latest
        .get("warnings_total")
        .and_then(Value::as_u64)
        .expect("latest warnings_total must be numeric");
    let latest_diagnostics = latest
        .get("diagnostics_total")
        .and_then(Value::as_u64)
        .expect("latest diagnostics_total must be numeric");
    let latest_bucket_count = latest
        .get("bucket_count")
        .and_then(Value::as_u64)
        .expect("latest bucket_count must be numeric");

    assert_eq!(
        latest_diagnostics,
        baseline
            .pointer("/snapshot/frontier_buckets/diagnostics_total")
            .and_then(Value::as_u64)
            .expect("snapshot diagnostics_total must be numeric")
    );
    assert_eq!(
        latest_errors,
        baseline
            .pointer("/snapshot/frontier_buckets/errors_total")
            .and_then(Value::as_u64)
            .expect("snapshot errors_total must be numeric")
    );
    assert_eq!(
        latest_warnings,
        baseline
            .pointer("/snapshot/frontier_buckets/warnings_total")
            .and_then(Value::as_u64)
            .expect("snapshot warnings_total must be numeric")
    );
    assert_eq!(
        latest_bucket_count,
        baseline
            .pointer("/snapshot/frontier_buckets/bucket_count")
            .and_then(Value::as_u64)
            .expect("snapshot bucket_count must be numeric")
    );

    let frontier_buckets = frontier
        .get("buckets")
        .and_then(Value::as_array)
        .expect("frontier buckets must be array");
    let frontier_map = frontier_buckets
        .iter()
        .map(|bucket| {
            let bucket_id = bucket
                .get("bucket_id")
                .and_then(Value::as_str)
                .expect("frontier bucket_id must be string");
            let count = bucket
                .get("count")
                .and_then(Value::as_u64)
                .expect("frontier count must be numeric");
            (bucket_id.to_string(), count)
        })
        .collect::<BTreeMap<_, _>>();

    let bucket_trends = dashboard
        .get("bucket_trends")
        .and_then(Value::as_array)
        .expect("dashboard bucket_trends must be array");
    assert_eq!(
        bucket_trends.len(),
        frontier_buckets.len(),
        "bucket_trends size must match frontier bucket count"
    );

    let mut trend_ids = BTreeSet::new();
    for trend in bucket_trends {
        let bucket_id = trend
            .get("bucket_id")
            .and_then(Value::as_str)
            .expect("bucket trend bucket_id must be string");
        let current_count = trend
            .get("current_count")
            .and_then(Value::as_u64)
            .expect("bucket trend current_count must be numeric");
        let delta = trend
            .get("delta_from_previous")
            .and_then(Value::as_i64)
            .expect("bucket trend delta_from_previous must be numeric");
        let trend_label = trend
            .get("trend")
            .and_then(Value::as_str)
            .expect("bucket trend label must be string");

        let expected_count = frontier_map
            .get(bucket_id)
            .copied()
            .expect("bucket trend bucket_id must exist in frontier");
        assert_eq!(current_count, expected_count);
        assert_eq!(delta, 0, "baseline run must use zero deltas");
        assert_eq!(trend_label, "baseline");
        trend_ids.insert(bucket_id.to_string());
    }

    let frontier_ids = frontier_map.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        trend_ids, frontier_ids,
        "bucket trend IDs must match frontier"
    );

    let closure_gate = baseline
        .get("track2_closure_gate")
        .and_then(Value::as_object)
        .expect("track2_closure_gate must be object");
    assert_eq!(
        closure_gate
            .get("policy_version")
            .and_then(Value::as_str)
            .expect("closure gate policy_version must be string"),
        "1.0.0"
    );

    let status = closure_gate
        .get("status")
        .and_then(Value::as_str)
        .expect("closure gate status must be string");
    assert!(
        matches!(status, "not-satisfied" | "satisfied"),
        "closure gate status must be not-satisfied|satisfied"
    );

    let blocking_classes = closure_gate
        .get("blocking_classes_must_be_zero")
        .and_then(Value::as_array)
        .expect("blocking_classes_must_be_zero must be array");
    assert!(
        blocking_classes.len() >= 3,
        "closure gate must include at least 3 zero-class constraints"
    );

    let stability_requirement = closure_gate
        .get("stability_requirement")
        .and_then(Value::as_object)
        .expect("stability_requirement must be object");
    assert!(
        stability_requirement
            .get("consecutive_runs_required")
            .and_then(Value::as_u64)
            .expect("consecutive_runs_required must be numeric")
            >= 2,
        "stability requirement must require at least two runs"
    );
    assert!(
        stability_requirement
            .get("no_regression_required")
            .and_then(Value::as_bool)
            .expect("no_regression_required must be boolean"),
        "stability requirement must require no regression"
    );

    let bead_ids = BEADS_JSONL
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
        });

    let references = closure_gate
        .get("references")
        .and_then(Value::as_object)
        .expect("closure gate references must be object");
    for field in [
        "track_close_decision_bead",
        "track3_dependency_bead",
        "track5_ci_policy_bead",
        "track5_threshold_policy_bead",
    ] {
        let bead_id = references
            .get(field)
            .and_then(Value::as_str)
            .expect("closure gate reference must be string");
        assert!(
            bead_ids.contains(bead_id),
            "closure gate reference {field} points to unknown bead {bead_id}"
        );
    }
}
