#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for replay artifact schema + trace policy spec (2oh2u.10.6).
//!
//! Enforces normative schema/rules, promotion+rollback criteria, ownership
//! controls, and CI gate integration tokens.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_replay_artifact_schema_policy.md");
    std::fs::read_to_string(path).expect("replay artifact schema policy document must exist")
}

fn extract_policy_ids(doc: &str, prefix: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(first_cell) = trimmed.split('|').next() {
            let candidate = first_cell.trim().trim_matches('`');
            if candidate.starts_with(prefix) {
                ids.insert(candidate.to_string());
            }
        }
    }
    ids
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 3500,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_correct_bead_and_track() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.10.6"),
        "document must reference bead 2oh2u.10.6"
    );
    assert!(doc.contains("[T8.6]"), "document must reference T8.6");
}

#[test]
fn doc_references_required_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.2",
        "tokio_executable_conformance_contracts.md",
        "tokio_ci_quality_gate_enforcement.md",
        "replay-debugging.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_schema_policy_block() {
    let doc = load_doc();
    for token in [
        "schema_id",
        "schema_version",
        "contract_ids",
        "gate_ids",
        "commit_sha",
        "run_id",
        "generated_at",
        "artifact_digest",
    ] {
        assert!(doc.contains(token), "missing schema field token: {token}");
    }
}

#[test]
fn doc_has_required_artifact_bundle_tokens() {
    let doc = load_doc();
    for token in [
        "summary.json",
        "event_log.txt",
        "failed_assertions.json",
        "repro_manifest.json",
        "golden_trace_replay_delta_report.json",
        "golden_trace_replay_delta_triage_bundle.json",
    ] {
        assert!(
            doc.contains(token),
            "missing required artifact bundle token: {token}"
        );
    }
}

#[test]
fn doc_defines_ra_rules() {
    let doc = load_doc();
    let ids = extract_policy_ids(&doc, "RA-");
    for id in [
        "RA-01", "RA-02", "RA-03", "RA-04", "RA-05", "RA-06", "RA-07", "RA-08", "RA-09", "RA-10",
        "RA-11", "RA-12", "RA-13",
    ] {
        assert!(ids.contains(id), "missing schema policy id: {id}");
    }
}

#[test]
fn doc_defines_retention_freshness_and_privacy_rules() {
    let doc = load_doc();
    let ids = extract_policy_ids(&doc, "RP-");
    for id in [
        "RP-01", "RP-02", "RP-03", "RP-04", "RP-05", "RP-06", "RP-07", "RP-08", "RP-09", "RP-10",
        "RP-11", "RP-12",
    ] {
        assert!(
            ids.contains(id),
            "missing retention/privacy policy id: {id}"
        );
    }

    assert!(
        doc.contains("stale_evidence"),
        "freshness policy must include stale_evidence token"
    );
}

#[test]
fn doc_defines_promotion_and_rollback_criteria() {
    let doc = load_doc();
    let pr_ids = extract_policy_ids(&doc, "PR-");
    let rb_ids = extract_policy_ids(&doc, "RB-");

    for id in ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06"] {
        assert!(pr_ids.contains(id), "missing promotion criterion id: {id}");
    }

    for id in ["RB-01", "RB-02", "RB-03", "RB-04", "RB-05"] {
        assert!(rb_ids.contains(id), "missing rollback trigger id: {id}");
    }
}

#[test]
fn doc_defines_ownership_escalation_and_exceptions() {
    let doc = load_doc();
    let ids = extract_policy_ids(&doc, "OG-");
    for id in [
        "OG-01", "OG-02", "OG-03", "OG-04", "OG-05", "OG-06", "OG-07", "OG-08", "OG-09", "OG-10",
    ] {
        assert!(ids.contains(id), "missing governance policy id: {id}");
    }
}

#[test]
fn doc_requires_ci_integration_and_rch_exec() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch exec for heavy commands"
    );

    for token in [
        "rch exec -- cargo test --test tokio_executable_conformance_contracts -- --nocapture",
        "rch exec -- cargo test --test tokio_ci_quality_gate_enforcement -- --nocapture",
        "rch exec -- cargo test --test tokio_replay_artifact_schema_policy -- --nocapture",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo fmt --check",
        "QG-04",
        "QG-06",
    ] {
        assert!(doc.contains(token), "missing CI integration token: {token}");
    }
}

#[test]
fn doc_defines_policy_output_bundle() {
    let doc = load_doc();
    for token in [
        "replay_artifact_policy_report.json",
        "replay_artifact_policy_failures.json",
        "replay_artifact_policy_summary.md",
        "replay_artifact_policy_repro_commands.txt",
    ] {
        assert!(
            doc.contains(token),
            "missing policy output artifact token: {token}"
        );
    }
}

#[test]
fn doc_binds_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.8",
        "asupersync-2oh2u.11.7",
        "asupersync-2oh2u.11.9",
    ] {
        assert!(
            doc.contains(token),
            "missing downstream binding token: {token}"
        );
    }
}
