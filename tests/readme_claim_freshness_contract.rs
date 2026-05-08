//! Contract tests for the README/AGENTS proof-claim freshness receipt helper.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/readme_claim_freshness.py";
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
        8,
        "live snapshot should still cover 8 claim rows"
    );
    for claim in claims {
        assert_eq!(claim["fresh"].as_bool(), Some(true));
        assert_eq!(claim["missing_marker_count"].as_u64(), Some(0));
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
                    "doc_claim_markers": {
                        "README.md": ["present readme marker"],
                        "AGENTS.md": ["present agents marker"]
                    }
                },
                {
                    "claim_id": "stale-doc-claim",
                    "category": "stale docs",
                    "status": "yellow_frontier",
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
