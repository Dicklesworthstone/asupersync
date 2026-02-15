//! Frontier bucket artifact integrity checks (bd-1dorb).

use serde_json::Value;
use std::collections::BTreeSet;

const FRONTIER_JSON: &str = include_str!("../formal/lean/coverage/lean_frontier_buckets_v1.json");
const GAP_PLAN_JSON: &str = include_str!("../formal/lean/coverage/gap_risk_sequencing_plan.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

#[test]
fn frontier_report_has_valid_schema_and_sorted_buckets() {
    let report: Value = serde_json::from_str(FRONTIER_JSON).expect("frontier report must parse");
    assert_eq!(
        report
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be string"),
        "1.0.0"
    );
    assert_eq!(
        report
            .get("report_id")
            .and_then(Value::as_str)
            .expect("report_id must be string"),
        "lean.frontier.buckets.v1"
    );
    assert_eq!(
        report
            .get("generated_by")
            .and_then(Value::as_str)
            .expect("generated_by must be string"),
        "bd-1dorb"
    );

    let diagnostics_total = report
        .get("diagnostics_total")
        .and_then(Value::as_u64)
        .expect("diagnostics_total must be numeric");
    let errors_total = report
        .get("errors_total")
        .and_then(Value::as_u64)
        .expect("errors_total must be numeric");
    let warnings_total = report
        .get("warnings_total")
        .and_then(Value::as_u64)
        .expect("warnings_total must be numeric");
    assert_eq!(
        diagnostics_total,
        errors_total + warnings_total,
        "diagnostics_total must equal errors_total + warnings_total"
    );

    let buckets = report
        .get("buckets")
        .and_then(Value::as_array)
        .expect("buckets must be an array");
    assert!(!buckets.is_empty(), "buckets must not be empty");

    let bucket_ids = buckets
        .iter()
        .map(|bucket| {
            bucket
                .get("bucket_id")
                .and_then(Value::as_str)
                .expect("bucket_id must be string")
        })
        .collect::<Vec<_>>();
    let mut sorted_bucket_ids = bucket_ids.clone();
    sorted_bucket_ids.sort_unstable();
    assert_eq!(
        bucket_ids, sorted_bucket_ids,
        "bucket ordering must be deterministic"
    );
    assert!(
        !bucket_ids.contains(&"declaration-order.unknown-identifier"),
        "declaration-order bucket should be eliminated after bd-cspxm helper-ordering pass"
    );
    assert!(
        !bucket_ids.contains(&"declaration-order.helper-availability"),
        "declaration-order helper-availability bucket should remain eliminated after bd-53a0d ordering stabilization"
    );
    assert!(
        !bucket_ids.contains(&"tactic-instability.tactic-simp-nested-error"),
        "tactic-instability bucket should be eliminated after bd-kf0mv stabilization pass"
    );
}

#[test]
fn frontier_buckets_link_to_known_failure_modes_and_beads() {
    let report: Value = serde_json::from_str(FRONTIER_JSON).expect("frontier report must parse");
    let gap_plan: Value = serde_json::from_str(GAP_PLAN_JSON).expect("gap plan must parse");

    let allowed_failure_modes = gap_plan
        .get("failure_mode_catalog")
        .and_then(Value::as_array)
        .expect("failure_mode_catalog must be an array")
        .iter()
        .map(|entry| {
            entry
                .get("code")
                .and_then(Value::as_str)
                .expect("failure_mode code must be string")
        })
        .collect::<BTreeSet<_>>();

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

    let buckets = report
        .get("buckets")
        .and_then(Value::as_array)
        .expect("buckets must be an array");
    for bucket in buckets {
        let failure_mode = bucket
            .get("failure_mode")
            .and_then(Value::as_str)
            .expect("failure_mode must be string");
        assert!(
            allowed_failure_modes.contains(failure_mode),
            "unknown failure_mode '{failure_mode}'"
        );

        let linked_beads = bucket
            .get("linked_bead_ids")
            .and_then(Value::as_array)
            .expect("linked_bead_ids must be an array");
        for bead in linked_beads {
            let bead_id = bead
                .as_str()
                .expect("linked bead identifiers must be strings");
            assert!(
                bead_ids.contains(bead_id),
                "linked bead {bead_id} does not exist in .beads/issues.jsonl"
            );
        }
    }
}

#[test]
fn frontier_errors_have_single_primary_taxonomy_code() {
    let report: Value = serde_json::from_str(FRONTIER_JSON).expect("frontier report must parse");
    let gap_plan: Value = serde_json::from_str(GAP_PLAN_JSON).expect("gap plan must parse");

    let allowed_error_pairs = gap_plan
        .get("error_code_catalog")
        .and_then(Value::as_array)
        .expect("error_code_catalog must be an array")
        .iter()
        .map(|entry| {
            let failure_mode = entry
                .get("failure_mode")
                .and_then(Value::as_str)
                .expect("error_code_catalog failure_mode must be string");
            let error_code = entry
                .get("error_code")
                .and_then(Value::as_str)
                .expect("error_code_catalog error_code must be string");
            (failure_mode.to_string(), error_code.to_string())
        })
        .collect::<BTreeSet<_>>();

    let buckets = report
        .get("buckets")
        .and_then(Value::as_array)
        .expect("buckets must be an array");
    let errors_total = report
        .get("errors_total")
        .and_then(Value::as_u64)
        .expect("errors_total must be numeric");

    let mut total_bucketed_errors = 0u64;
    let mut seen_bucket_ids = BTreeSet::<String>::new();

    for bucket in buckets {
        let bucket_id = bucket
            .get("bucket_id")
            .and_then(Value::as_str)
            .expect("bucket_id must be string");
        let failure_mode = bucket
            .get("failure_mode")
            .and_then(Value::as_str)
            .expect("failure_mode must be string");
        let error_code = bucket
            .get("error_code")
            .and_then(Value::as_str)
            .expect("error_code must be string");
        let count = bucket
            .get("count")
            .and_then(Value::as_u64)
            .expect("count must be numeric");

        assert!(
            seen_bucket_ids.insert(bucket_id.to_string()),
            "bucket_id '{bucket_id}' must be unique"
        );
        assert_eq!(
            bucket_id,
            format!("{failure_mode}.{error_code}"),
            "bucket_id must be canonical failure_mode.error_code"
        );
        assert!(
            allowed_error_pairs.contains(&(failure_mode.to_string(), error_code.to_string())),
            "bucket ({failure_mode}, {error_code}) is not in error_code_catalog"
        );
        total_bucketed_errors += count;
    }

    assert_eq!(
        total_bucketed_errors, errors_total,
        "sum(bucket.count) must match errors_total so every error has exactly one primary taxonomy code"
    );
}
