//! Deterministic Lean frontier extractor checks (bd-1dorb).

use conformance::extract_frontier_report;
use std::collections::BTreeSet;

const GAP_PLAN_JSON: &str = include_str!("../formal/lean/coverage/gap_risk_sequencing_plan.json");

const SAMPLE_LOG: &str = "\
error: Asupersync.lean:2335:42: Unknown identifier `r`\n\
error: Asupersync.lean:2874:2: Alternative `cancelChild` has not been provided\n\
error: Asupersync.lean:2506:28: Type mismatch\n\
error: Asupersync.lean:2699:14: unsolved goals\n\
error: Asupersync.lean:3618:2: Tactic `simp` failed with a nested error:\n\
warning: Asupersync.lean:2600:5: unused variable `h`\n\
";

#[test]
fn extractor_output_is_byte_stable_for_identical_input() {
    let report_a = extract_frontier_report(SAMPLE_LOG, "sample.log", Some(GAP_PLAN_JSON));
    let report_b = extract_frontier_report(SAMPLE_LOG, "sample.log", Some(GAP_PLAN_JSON));
    let json_a = serde_json::to_string_pretty(&report_a).expect("serialization must succeed");
    let json_b = serde_json::to_string_pretty(&report_b).expect("serialization must succeed");
    assert_eq!(json_a, json_b, "frontier extraction must be deterministic");
}

#[test]
fn extractor_assigns_expected_buckets_and_gap_links() {
    let report = extract_frontier_report(SAMPLE_LOG, "sample.log", Some(GAP_PLAN_JSON));
    assert_eq!(report.schema_version, "1.0.0");
    assert_eq!(report.report_id, "lean.frontier.buckets.v1");
    assert_eq!(report.generated_by, "bd-1dorb");
    assert_eq!(report.diagnostics_total, 6);
    assert_eq!(report.errors_total, 5);
    assert_eq!(report.warnings_total, 1);

    let bucket_ids = report
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        bucket_ids,
        BTreeSet::from([
            "declaration-order.unknown-identifier",
            "missing-lemma.constructor-alternative-missing",
            "proof-shape.type-mismatch",
            "proof-shape.unsolved-goals",
            "tactic-instability.tactic-simp-nested-error",
        ])
    );

    let declaration_order = report
        .buckets
        .iter()
        .find(|bucket| bucket.bucket_id == "declaration-order.unknown-identifier")
        .expect("declaration-order bucket must exist");
    assert!(
        declaration_order
            .linked_bead_ids
            .iter()
            .any(|bead| bead == "bd-1dorb"),
        "declaration-order bucket should link to bd-1dorb"
    );
}
