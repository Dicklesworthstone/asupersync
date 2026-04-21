#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for the migration strategy and decision framework (2oh2u.11.1).
//!
//! Validates scenario coverage, structured logging schema requirements,
//! hard-fail quality gates, and failure-triage guidance.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_migration_strategy_decision_framework.md");
    std::fs::read_to_string(path).expect("migration strategy document must exist")
}

fn extract_scenario_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        if !line.contains("MS-") {
            continue;
        }
        for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
            if token.starts_with("MS-") && token.len() == 6 {
                ids.insert(token.to_string());
            }
        }
    }
    ids
}

fn extract_gate_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        if !line.contains("LG-") {
            continue;
        }
        for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
            if token.starts_with("LG-") && token.len() >= 9 {
                ids.insert(token.to_string());
            }
        }
    }
    ids
}

#[test]
fn document_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 5000,
        "migration strategy doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn document_references_correct_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.11.1"),
        "document must reference bead 2oh2u.11.1"
    );
    assert!(doc.contains("[T9.1]"), "document must reference T9.1");
}

#[test]
fn document_preserves_runtime_invariants() {
    let doc = load_doc();
    for token in [
        "Structured concurrency",
        "Cancellation protocol correctness",
        "No obligation leaks",
        "Region close implies quiescence",
        "No ambient authority",
    ] {
        assert!(doc.contains(token), "missing invariant token: {token}");
    }
}

#[test]
fn document_defines_wave_based_migration_strategy() {
    let doc = load_doc();
    for token in ["W0 Baseline", "W1 Shadow", "W2 Canary", "W3 Full Rollout"] {
        assert!(doc.contains(token), "missing migration wave token: {token}");
    }
    assert!(
        doc.contains("Entry Conditions") && doc.contains("Exit Conditions"),
        "wave table must define entry and exit conditions"
    );
}

#[test]
fn scenario_manifest_contract_includes_required_fields() {
    let doc = load_doc();
    assert!(
        doc.contains("Scenario Manifest Contract"),
        "must include scenario manifest contract section"
    );
    for field in [
        "scenario_id",
        "track",
        "capability_domain",
        "environment",
        "preconditions",
        "steps",
        "failure_injection",
        "expected_outcome",
        "expected_log_signals",
        "replay_seed",
        "artifact_bundle",
        "rollback_plan",
        "owner",
    ] {
        assert!(
            doc.contains(&format!("`{field}`")),
            "manifest contract missing required field: {field}"
        );
    }
}

#[test]
fn representative_scenarios_cover_success_and_failure() {
    let doc = load_doc();
    let scenario_ids = extract_scenario_ids(&doc);
    assert!(
        scenario_ids.len() >= 8,
        "must define >= 8 scenario IDs, found {}",
        scenario_ids.len()
    );
    assert!(
        doc.contains("| success |") && doc.contains("| failure |"),
        "scenario pack must include both success and failure scenarios"
    );
}

#[test]
fn structured_logging_schema_fields_are_declared() {
    let doc = load_doc();
    for field in [
        "correlation_id",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "schema_version",
        "seed",
        "replay_trace_uri",
        "outcome_class",
        "redaction_profile",
        "gate_status",
        "owner",
        "timestamp_utc",
    ] {
        assert!(
            doc.contains(&format!("`{field}`")),
            "structured logging contract missing field: {field}"
        );
    }
}

#[test]
fn replay_linkage_rules_are_defined() {
    let doc = load_doc();
    assert!(
        doc.contains("Replay linkage rule"),
        "must define replay linkage rule"
    );
    for token in ["scenario_id + seed + schema_version", "Replay verification"] {
        assert!(doc.contains(token), "missing replay token: {token}");
    }
}

#[test]
fn hard_fail_redaction_and_quality_gates_are_enforced() {
    let doc = load_doc();
    let gate_ids = extract_gate_ids(&doc);
    assert!(
        gate_ids.len() >= 6,
        "must define >= 6 LG-* hard-fail gates, found {}",
        gate_ids.len()
    );
    for required in [
        "LG-RED-01",
        "LG-SCHEMA-01",
        "LG-REPLAY-01",
        "LG-CORR-01",
        "LG-OUTCOME-01",
        "LG-QUALITY-01",
    ] {
        assert!(gate_ids.contains(required), "missing gate {required}");
    }
    assert!(
        doc.contains("Hard-fail"),
        "gate policy must explicitly require hard-fail behavior"
    );
}

#[test]
fn expected_outcomes_define_invariant_bits_and_threshold_behavior() {
    let doc = load_doc();
    for token in [
        "expected_outcome.status",
        "latency_p95_delta_ms",
        "error_rate_delta",
        "resource_delta",
        "no_task_leak",
        "no_obligation_leak",
        "quiescence_verified",
        "rollback_ready",
    ] {
        assert!(
            doc.contains(token),
            "expected outcomes section missing token: {token}"
        );
    }
}

#[test]
fn failure_triage_guidance_is_actionable() {
    let doc = load_doc();
    assert!(
        doc.contains("Failure Triage Guidance"),
        "must include failure triage guidance section"
    );
    for class in [
        "SchemaViolation",
        "RedactionViolation",
        "ReplayMismatch",
        "InvariantBreak",
        "KPIRegression",
        "DependencyOutage",
    ] {
        assert!(
            doc.contains(class),
            "triage table missing failure class: {class}"
        );
    }
    for token in [
        "scenario manifest",
        "structured log bundle",
        "replay trace URI",
        "retry/rollback recommendation",
    ] {
        assert!(doc.contains(token), "triage packet missing token: {token}");
    }
}

#[test]
fn document_declares_ci_artifacts_and_rch_offload_commands() {
    let doc = load_doc();
    for token in [
        "Scenario manifest bundle",
        "Structured execution logs",
        "Replay traces",
        "Gate report",
        "Failure triage markdown",
        "rch exec -- cargo test --test tokio_migration_strategy_decision_framework",
    ] {
        assert!(
            doc.contains(token),
            "CI/artifact section missing token: {token}"
        );
    }
}

#[test]
fn document_maps_downstream_dependency_targets() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.11.2",
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.11.11",
        "asupersync-2oh2u.10.9",
    ] {
        assert!(
            doc.contains(token),
            "missing downstream mapping token: {token}"
        );
    }
}
