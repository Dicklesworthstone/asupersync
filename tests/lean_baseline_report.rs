//! Baseline report consistency checks (bd-5w2lq).

use serde_json::Value;
use std::collections::BTreeSet;

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
        .filter_map(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .collect::<BTreeSet<_>>();

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
