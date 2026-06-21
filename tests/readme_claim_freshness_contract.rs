//! Contract tests for the README/AGENTS proof-claim freshness receipt helper.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/readme_claim_freshness.py";
const FIXTURE_ROOT: &str = "tests/fixtures/readme_claim_freshness";
const GENERATED_AT: &str = "2026-05-08T05:20:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(snapshot: &Path, readme: &Path, agents: &Path) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--snapshot")
        .arg(snapshot)
        .arg("--readme")
        .arg(readme)
        .arg("--agents")
        .arg(agents)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run readme claim freshness helper")
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join(FIXTURE_ROOT).join(name)
}

fn receipt_json(snapshot: &Path, readme: &Path, agents: &Path) -> Value {
    let output = run_receipt(snapshot, readme, agents);
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
}

fn receipt_stdout(snapshot: &Path, readme: &Path, agents: &Path) -> String {
    let output = run_receipt(snapshot, readme, agents);
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("receipt output must be UTF-8")
}

fn fixture_text(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).expect("fixture golden must be readable")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "freshness helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn live_docs_cover_every_snapshot_marker() {
    let root = repo_root();
    let receipt = receipt_json(
        &root.join("artifacts/proof_status_snapshot_v1.json"),
        &root.join("README.md"),
        &root.join("AGENTS.md"),
    );

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("readme-claim-freshness-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["verdict"].as_str(), Some("fresh"));
    assert_eq!(receipt["decision"].as_str(), Some("passed"));
    assert_eq!(receipt["missing_marker_count"].as_u64(), Some(0));
    assert_eq!(receipt["proof_evidence_issue_count"].as_u64(), Some(0));
    assert_eq!(
        receipt["documents"]["README.md"]["missing_marker_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        receipt["documents"]["AGENTS.md"]["missing_marker_count"].as_u64(),
        Some(0)
    );

    let claims = receipt["claims"].as_array().expect("claims array");
    assert_eq!(
        claims.len(),
        33,
        "live snapshot should still cover 33 claim rows"
    );
    for claim in claims {
        assert_eq!(claim["fresh"].as_bool(), Some(true));
        assert_eq!(claim["missing_marker_count"].as_u64(), Some(0));
        assert_eq!(claim["proof_evidence_issue_count"].as_u64(), Some(0));
        assert!(
            claim["proof_evidence_status"]
                .as_str()
                .is_some_and(|status| !status.is_empty()),
            "claim should carry a reportable proof evidence status: {claim:?}"
        );
    }
}

#[test]
fn stale_fixture_reports_exact_missing_doc_marker() {
    let fixture_root = std::env::temp_dir().join(format!(
        "asupersync-readme-claim-freshness-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&fixture_root).expect("create fixture root");
    let snapshot_path = fixture_root.join("snapshot.json");
    let readme_path = fixture_root.join("README.md");
    let agents_path = fixture_root.join("AGENTS.md");

    std::fs::write(&readme_path, "README contains present readme marker\n").expect("write readme");
    std::fs::write(&agents_path, "AGENTS contains present agents marker\n").expect("write agents");
    std::fs::write(
        &snapshot_path,
        serde_json::to_vec_pretty(&json!({
            "claim_categories": [
                {
                    "claim_id": "fresh-doc-claim",
                    "category": "fresh docs",
                    "status": "green",
                    "proof_evidence_status": "rerun-required",
                    "notes": "Green here is mapped but not a fresh proof; rerun before citing it.",
                    "doc_claim_markers": {
                        "README.md": ["present readme marker"],
                        "AGENTS.md": ["present agents marker"]
                    }
                },
                {
                    "claim_id": "stale-doc-claim",
                    "category": "stale docs",
                    "status": "yellow_frontier",
                    "proof_evidence_status": "rerun-required",
                    "notes": "Yellow frontier row: rerun required and not a broad proof claim.",
                    "doc_claim_markers": {
                        "README.md": ["missing readme marker"]
                    }
                }
            ]
        }))
        .expect("serialize snapshot"),
    )
    .expect("write snapshot");

    let receipt = receipt_json(&snapshot_path, &readme_path, &agents_path);

    assert_eq!(receipt["verdict"].as_str(), Some("stale"));
    assert_eq!(receipt["decision"].as_str(), Some("blocked-doc-stale"));
    assert_eq!(receipt["missing_marker_count"].as_u64(), Some(1));
    assert_eq!(receipt["proof_evidence_issue_count"].as_u64(), Some(0));
    assert_eq!(
        receipt["documents"]["README.md"]["missing_marker_count"].as_u64(),
        Some(1)
    );

    let stale_claim = receipt["claims"]
        .as_array()
        .expect("claims array")
        .iter()
        .find(|claim| claim["claim_id"].as_str() == Some("stale-doc-claim"))
        .expect("stale claim row");
    assert_eq!(stale_claim["fresh"].as_bool(), Some(false));
    assert_eq!(
        stale_claim["missing_doc_markers"][0]["document"].as_str(),
        Some("README.md")
    );
    assert_eq!(
        stale_claim["missing_doc_markers"][0]["marker"].as_str(),
        Some("missing readme marker")
    );
    assert_eq!(stale_claim["proof_evidence_issue_count"].as_u64(), Some(0));
}

#[test]
fn stale_fixture_matches_full_output_golden() {
    let expected_fixture = "stale_doc_marker_expected.json";
    let actual_text = receipt_stdout(
        &fixture_path("stale_doc_marker_snapshot.json"),
        &fixture_path("stale_README.md"),
        &fixture_path("stale_AGENTS.md"),
    );
    let expected_text = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual_text).unwrap_or_else(|err| {
        panic!("actual README claim freshness receipt JSON for {expected_fixture}: {err}")
    });
    let expected_json: Value = serde_json::from_str(&expected_text).unwrap_or_else(|err| {
        panic!("expected README claim freshness fixture {expected_fixture} must be JSON: {err}")
    });

    assert_eq!(
        actual_json, expected_json,
        "parsed README claim freshness receipt JSON drifted from {expected_fixture}; update the golden only after reviewing missing-marker semantics"
    );
    assert_eq!(
        actual_text, expected_text,
        "README claim freshness stale-doc-marker receipt changed; update the golden only after reviewing missing-marker semantics"
    );
}

#[test]
fn stale_proof_evidence_fails_even_when_doc_markers_are_present() {
    let receipt = receipt_json(
        &fixture_path("stale_proof_evidence_snapshot.json"),
        &fixture_path("stale_proof_README.md"),
        &fixture_path("stale_proof_AGENTS.md"),
    );

    assert_eq!(receipt["verdict"].as_str(), Some("stale"));
    assert_eq!(
        receipt["decision"].as_str(),
        Some("blocked-proof-evidence-stale")
    );
    assert_eq!(receipt["missing_marker_count"].as_u64(), Some(0));
    assert_eq!(receipt["proof_evidence_issue_count"].as_u64(), Some(1));

    let stale_claim = receipt["claims"]
        .as_array()
        .expect("claims array")
        .iter()
        .find(|claim| claim["claim_id"].as_str() == Some("stale-proof-claim"))
        .expect("stale proof row");
    assert_eq!(stale_claim["fresh"].as_bool(), Some(false));
    assert_eq!(
        stale_claim["proof_evidence_status"].as_str(),
        Some("stale-evidence")
    );
    assert_eq!(
        stale_claim["proof_evidence_issues"][0]["kind"].as_str(),
        Some("unciteable-proof-evidence-status")
    );
}

#[test]
fn blocked_proof_evidence_requires_frontier_and_no_claim_boundary() {
    let fixture_root = std::env::temp_dir().join(format!(
        "asupersync-readme-claim-freshness-proof-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&fixture_root).expect("create fixture root");
    let snapshot_path = fixture_root.join("snapshot.json");
    let readme_path = fixture_root.join("README.md");
    let agents_path = fixture_root.join("AGENTS.md");

    std::fs::write(&readme_path, "README contains present readme marker\n").expect("write readme");
    std::fs::write(&agents_path, "AGENTS contains present agents marker\n").expect("write agents");
    std::fs::write(
        &snapshot_path,
        serde_json::to_vec_pretty(&json!({
            "claim_categories": [
                {
                    "claim_id": "blocked-no-frontier",
                    "category": "blocked proof without metadata",
                    "status": "green",
                    "proof_evidence_status": "blocked",
                    "notes": "Blocked proof row; rerun before citing it.",
                    "doc_claim_markers": {
                        "README.md": ["present readme marker"]
                    }
                },
                {
                    "claim_id": "blocked-no-boundary",
                    "category": "blocked proof without boundary",
                    "status": "green",
                    "proof_evidence_status": "blocked",
                    "blocked_frontier": {
                        "blocker_id": "RCH-123",
                        "reason": "remote worker stopped before completion",
                        "required_followup": "rerun the proof lane remotely"
                    },
                    "notes": "Validation evidence summary.",
                    "doc_claim_markers": {
                        "AGENTS.md": ["present agents marker"]
                    }
                }
            ]
        }))
        .expect("serialize snapshot"),
    )
    .expect("write snapshot");

    let receipt = receipt_json(&snapshot_path, &readme_path, &agents_path);

    assert_eq!(receipt["verdict"].as_str(), Some("stale"));
    assert_eq!(
        receipt["decision"].as_str(),
        Some("blocked-proof-evidence-stale")
    );
    assert_eq!(receipt["missing_marker_count"].as_u64(), Some(0));
    assert_eq!(receipt["proof_evidence_issue_count"].as_u64(), Some(2));

    let issue_kinds: Vec<&str> = receipt["claims"]
        .as_array()
        .expect("claims array")
        .iter()
        .flat_map(|claim| {
            claim["proof_evidence_issues"]
                .as_array()
                .expect("proof issues array")
                .iter()
                .map(|issue| issue["kind"].as_str().expect("issue kind"))
        })
        .collect();
    assert!(
        issue_kinds.contains(&"blocked-without-frontier-evidence"),
        "blocked proof rows must identify the blocker frontier"
    );
    assert!(
        issue_kinds.contains(&"missing-no-claim-boundary"),
        "blocked proof rows must state a no-claim boundary"
    );
}

#[test]
fn stale_proof_fixture_matches_full_output_golden() {
    let expected_fixture = "stale_proof_evidence_expected.json";
    let actual_text = receipt_stdout(
        &fixture_path("stale_proof_evidence_snapshot.json"),
        &fixture_path("stale_proof_README.md"),
        &fixture_path("stale_proof_AGENTS.md"),
    );
    let expected_text = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual_text).unwrap_or_else(|err| {
        panic!("actual README proof evidence receipt JSON for {expected_fixture}: {err}")
    });
    let expected_json: Value = serde_json::from_str(&expected_text).unwrap_or_else(|err| {
        panic!("expected README proof evidence fixture {expected_fixture} must be JSON: {err}")
    });

    assert_eq!(
        actual_json, expected_json,
        "parsed README proof evidence receipt JSON drifted from {expected_fixture}; update the golden only after reviewing proof-evidence semantics"
    );
    assert_eq!(
        actual_text, expected_text,
        "README proof evidence receipt changed; update the golden only after reviewing proof-evidence semantics"
    );
}

#[test]
fn helper_declares_it_does_not_mutate_repo_state() {
    let root = repo_root();
    let receipt = receipt_json(
        &root.join("artifacts/proof_status_snapshot_v1.json"),
        &root.join("README.md"),
        &root.join("AGENTS.md"),
    );

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
