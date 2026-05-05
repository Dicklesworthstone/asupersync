//! Contract tests for deterministic CI quality-gate enforcement spec (2oh2u.10.5).
//!
//! Enforces gate IDs, deterministic status semantics, evidence/freshness policy,
//! output schema expectations, and downstream bindings.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_ci_quality_gate_enforcement.md");
    std::fs::read_to_string(path).expect("CI quality-gate enforcement document must exist")
}

fn extract_gate_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("QG-") {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

fn extract_freshness_rule_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("FS-") {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 3000,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_correct_bead_and_track() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.10.5"),
        "document must reference bead 2oh2u.10.5"
    );
    assert!(doc.contains("[T8.5]"), "document must reference T8.5");
    assert!(
        doc.contains("asupersync-2oh2u.10.7"),
        "document must reference bead 2oh2u.10.7"
    );
    assert!(doc.contains("[T8.7]"), "document must reference T8.7");
}

#[test]
fn doc_references_required_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.2",
        "tokio_executable_conformance_contracts.md",
        "tokio_cancellation_drain_fuzz_race_campaigns.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing required dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_canonical_evidence_fields() {
    let doc = load_doc();
    for token in [
        "run_id",
        "commit_sha",
        "gate_profile",
        "artifacts",
        "contract_results",
        "campaign_results",
        "tool_results",
        "generated_at",
        "repro_commands",
    ] {
        assert!(
            doc.contains(token),
            "document missing required evidence field token: {token}"
        );
    }
}

#[test]
fn doc_has_required_gate_set() {
    let doc = load_doc();
    let gate_ids = extract_gate_ids(&doc);
    for id in ["QG-01", "QG-02", "QG-03", "QG-04", "QG-05", "QG-06"] {
        assert!(gate_ids.contains(id), "missing gate id token: {id}");
    }
}

#[test]
fn doc_defines_status_and_blocked_semantics() {
    let doc = load_doc();
    for status in ["PASS", "FAIL", "BLOCKED"] {
        assert!(doc.contains(status), "missing status token: {status}");
    }
    assert!(
        doc.contains("`BLOCKED` is never equivalent to `PASS`"),
        "document must define BLOCKED != PASS semantics"
    );
}

#[test]
fn doc_defines_freshness_rules() {
    let doc = load_doc();
    let fs_ids = extract_freshness_rule_ids(&doc);
    for id in ["FS-01", "FS-02", "FS-03", "FS-04", "FS-05"] {
        assert!(
            fs_ids.contains(id),
            "missing freshness/staleness rule token: {id}"
        );
    }
    assert!(
        doc.contains("stale_evidence"),
        "document must define stale evidence failure token"
    );
}

#[test]
fn doc_defines_required_output_bundle() {
    let doc = load_doc();
    for token in [
        "quality_gate_report.json",
        "quality_gate_summary.md",
        "quality_gate_failures.json",
        "quality_gate_repro_commands.txt",
    ] {
        assert!(
            doc.contains(token),
            "missing output artifact token: {token}"
        );
    }
}

#[test]
fn doc_requires_rch_exec_for_heavy_checks() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch exec for heavy validation"
    );
    for token in [
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo test --test tokio_executable_conformance_contracts -- --nocapture",
        "rch exec -- cargo test --test tokio_cancellation_drain_fuzz_race_campaigns -- --nocapture",
        "rch exec -- cargo test --test tokio_ci_quality_gate_enforcement -- --nocapture",
    ] {
        assert!(doc.contains(token), "missing runner command token: {token}");
    }
}

#[test]
fn doc_defines_release_promotion_denial_conditions() {
    let doc = load_doc();
    for token in [
        "Release promotion",
        "promotion is denied",
        "unresolved `FAIL`",
        "unresolved `BLOCKED`",
        "schema-valid",
    ] {
        assert!(
            doc.contains(token),
            "missing release-promotion policy token: {token}"
        );
    }
}

#[test]
fn doc_binds_to_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.8",
        "asupersync-2oh2u.10.6",
        "asupersync-2oh2u.10.7",
        "asupersync-2oh2u.10.9",
    ] {
        assert!(
            doc.contains(token),
            "missing downstream binding token: {token}"
        );
    }
}

#[test]
fn doc_defines_t87_perf_budget_gate_set() {
    let doc = load_doc();
    for token in [
        "PB-01",
        "PB-02",
        "PB-03",
        "PB-04",
        "PB-05",
        "PB-06",
        "p95 latency regression",
        "throughput regression",
        "handshake/stream setup latency",
        "request path latency",
        "end-to-end operation latency",
        "bridge overhead and scheduling cost",
    ] {
        assert!(
            doc.contains(token),
            "missing T8.7 performance budget token: {token}"
        );
    }
}

#[test]
fn doc_defines_t87_perf_alarm_artifacts_and_commands() {
    let doc = load_doc();
    for token in [
        "tokio_track_perf_budgets.json",
        "tokio_track_perf_alarms.json",
        "tokio_track_perf_regression_report.md",
        "tokio_track_perf_repro_commands.txt",
        "alert_id",
        "budget_id",
        "thread_id",
        "first_failing_commit",
        "rch exec -- cargo bench --bench scheduler_benchmark",
        "rch exec -- cargo bench --bench reactor_benchmark",
        "rch exec -- cargo bench --bench protocol_benchmark",
        "rch exec -- cargo test --test perf_regression_gates -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "missing T8.7 alarm/runner token: {token}"
        );
    }
}
