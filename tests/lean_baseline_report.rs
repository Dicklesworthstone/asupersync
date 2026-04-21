#![allow(warnings)]
#![allow(clippy::all)]
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
const TESTING_MATRIX_DIFF_JSON: &str =
    include_str!("../formal/lean/coverage/testing_matrix_diff_v1.json");
const NO_MOCK_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/no_mock_inventory_v1.json");
const NO_MOCK_POLICY_JSON: &str = include_str!("../.github/no_mock_policy.json");

fn beads_issues_jsonl() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(".beads/issues.jsonl");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

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
    let bead_ids = beads_issues_jsonl()
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
    assert!(
        runs.len() >= 2,
        "dashboard runs must include at least two entries for stability checks"
    );

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
    if latest_errors == 0 {
        assert!(
            frontier_buckets.is_empty(),
            "frontier buckets must be empty when latest_errors is zero"
        );
    }
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
    if latest_errors == 0 {
        assert_eq!(
            status, "satisfied",
            "closure gate should be satisfied when frontier errors are zero"
        );
    }

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

    let bead_ids = beads_issues_jsonl()
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

#[test]
#[allow(clippy::too_many_lines)]
fn baseline_report_testing_matrix_diff_is_present_and_tracks_unresolved_deltas() {
    let diff: Value =
        serde_json::from_str(TESTING_MATRIX_DIFF_JSON).expect("testing matrix diff must parse");
    assert_eq!(
        diff.get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be string"),
        "1.0.0"
    );
    assert_eq!(
        diff.pointer("/source_matrix/testing_md_path")
            .and_then(Value::as_str)
            .expect("source_matrix.testing_md_path must be string"),
        "TESTING.md"
    );

    let expected_subsystems = [
        "Runtime + scheduler",
        "Cancellation + obligations",
        "Channels + sync primitives",
        "IO + reactor + time",
        "Net + HTTP + H2 + WebSocket + gRPC",
        "RaptorQ codec + pipelines",
        "Distributed + remote",
        "Trace + record + replay + DPOR",
        "Security + capabilities",
        "Lab runtime + testing infra",
        "Config + CLI + observability",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();

    let row_mappings = diff
        .get("row_mappings")
        .and_then(Value::as_array)
        .expect("row_mappings must be an array");
    assert_eq!(
        row_mappings.len(),
        expected_subsystems.len(),
        "row_mappings must cover every TESTING.md subsystem row"
    );

    let mut seen_subsystems = BTreeSet::new();
    for row in row_mappings {
        let subsystem = row
            .get("subsystem")
            .and_then(Value::as_str)
            .expect("row subsystem must be string");
        seen_subsystems.insert(subsystem.to_string());
        let status = row
            .pointer("/lean_alignment/status")
            .and_then(Value::as_str)
            .expect("lean_alignment.status must be string");
        assert!(
            matches!(status, "aligned" | "partial" | "missing"),
            "lean_alignment.status must be aligned|partial|missing"
        );
        let delta_summary = row
            .get("delta_summary")
            .and_then(Value::as_str)
            .expect("delta_summary must be string");
        assert!(
            !delta_summary.trim().is_empty(),
            "delta_summary must not be empty"
        );

        for bucket in ["unit", "integration", "e2e"] {
            let refs = row
                .pointer(&format!("/testing_refs/{bucket}"))
                .and_then(Value::as_array)
                .expect("testing_refs lists must be arrays");
            assert!(
                !refs.is_empty(),
                "testing_refs.{bucket} must include at least one file:test reference"
            );
        }
    }
    assert_eq!(
        seen_subsystems, expected_subsystems,
        "row_mappings subsystem set must match TESTING.md matrix subsystems"
    );

    let unresolved = diff
        .get("unresolved_deltas")
        .and_then(Value::as_array)
        .expect("unresolved_deltas must be an array");
    assert!(
        !unresolved.is_empty(),
        "unresolved_deltas must list open matrix-alignment gaps"
    );
    for delta in unresolved {
        let severity = delta
            .get("severity")
            .and_then(Value::as_str)
            .expect("delta severity must be string");
        assert!(
            matches!(severity, "low" | "medium" | "high" | "critical"),
            "delta severity must be low|medium|high|critical"
        );
        for field in ["id", "detail", "recommended_action", "owner_bead"] {
            let value = delta
                .get(field)
                .and_then(Value::as_str)
                .expect("delta string field must exist");
            assert!(
                !value.trim().is_empty(),
                "delta field {field} must be non-empty"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn baseline_report_no_mock_inventory_classifies_all_policy_paths() {
    let inventory: Value =
        serde_json::from_str(NO_MOCK_INVENTORY_JSON).expect("test-double inventory must parse");
    let policy: Value = serde_json::from_str(NO_MOCK_POLICY_JSON).expect("policy json must parse");

    assert_eq!(
        inventory
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("inventory schema_version must be string"),
        "1.0.0"
    );
    assert_eq!(
        inventory
            .get("source_policy")
            .and_then(Value::as_str)
            .expect("source_policy must be string"),
        ".github/no_mock_policy.json"
    );

    let allowlisted_paths = inventory
        .get("allowlisted_paths")
        .and_then(Value::as_array)
        .expect("allowlisted_paths must be an array");
    let waiver_paths = inventory
        .get("waiver_paths")
        .and_then(Value::as_array)
        .expect("waiver_paths must be an array");
    let remediation = inventory
        .get("remediation_required_paths")
        .and_then(Value::as_array)
        .expect("remediation_required_paths must be an array");
    assert!(
        remediation.is_empty(),
        "policy-gated inventory should have no unresolved remediation paths"
    );

    let allowlisted_set = allowlisted_paths
        .iter()
        .map(|row| {
            let classification = row
                .get("classification")
                .and_then(Value::as_str)
                .expect("allowlist classification must be string");
            assert_eq!(classification, "allowlisted_deterministic_double");
            let hit_count = row
                .get("hit_count")
                .and_then(Value::as_u64)
                .expect("allowlist hit_count must be numeric");
            assert!(hit_count >= 1, "allowlist hit_count must be >= 1");
            let policy_rationale = row
                .get("policy_rationale")
                .and_then(Value::as_str)
                .expect("allowlist policy_rationale must be string");
            assert!(
                !policy_rationale.trim().is_empty(),
                "allowlist policy_rationale must be non-empty"
            );
            row.get("path")
                .and_then(Value::as_str)
                .expect("allowlist path must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let waiver_set = waiver_paths
        .iter()
        .map(|row| {
            let classification = row
                .get("classification")
                .and_then(Value::as_str)
                .expect("waiver classification must be string");
            assert_eq!(classification, "temporary_waiver");
            assert_eq!(
                row.get("status")
                    .and_then(Value::as_str)
                    .expect("waiver status must be string"),
                "active"
            );
            for field in ["waiver_id", "owner", "expires_at_utc", "replacement_issue"] {
                let value = row
                    .get(field)
                    .and_then(Value::as_str)
                    .expect("waiver field must be string");
                assert!(
                    !value.trim().is_empty(),
                    "waiver field {field} must be non-empty"
                );
            }
            let hit_count = row
                .get("hit_count")
                .and_then(Value::as_u64)
                .expect("waiver hit_count must be numeric");
            assert!(hit_count >= 1, "waiver hit_count must be >= 1");
            row.get("path")
                .and_then(Value::as_str)
                .expect("waiver path must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let policy_allowlisted = policy
        .get("allowlist_paths")
        .and_then(Value::as_array)
        .expect("policy allowlist_paths must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("policy allowlist path must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        allowlisted_set, policy_allowlisted,
        "inventory allowlisted paths must match policy allowlist_paths"
    );

    let policy_active_waivers = policy
        .get("waivers")
        .and_then(Value::as_array)
        .expect("policy waivers must be an array")
        .iter()
        .filter(|waiver| waiver.get("status").and_then(Value::as_str) == Some("active"))
        .map(|waiver| {
            waiver
                .get("path")
                .and_then(Value::as_str)
                .expect("active waiver path must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        waiver_set, policy_active_waivers,
        "inventory waiver paths must match active waiver policy paths"
    );

    let summary = inventory
        .get("summary")
        .and_then(Value::as_object)
        .expect("summary must be object");
    let total = summary
        .get("matching_paths_total")
        .and_then(Value::as_u64)
        .expect("summary matching_paths_total must be numeric");
    let allowlisted_count = summary
        .get("allowlisted_count")
        .and_then(Value::as_u64)
        .expect("summary allowlisted_count must be numeric");
    let waiver_count = summary
        .get("waiver_count")
        .and_then(Value::as_u64)
        .expect("summary waiver_count must be numeric");
    let remediation_count = summary
        .get("remediation_required_count")
        .and_then(Value::as_u64)
        .expect("summary remediation_required_count must be numeric");
    assert_eq!(allowlisted_count, allowlisted_paths.len() as u64);
    assert_eq!(waiver_count, waiver_paths.len() as u64);
    assert_eq!(remediation_count, remediation.len() as u64);
    assert_eq!(
        total,
        allowlisted_count + waiver_count + remediation_count,
        "summary counts must add up to matching_paths_total"
    );
}
