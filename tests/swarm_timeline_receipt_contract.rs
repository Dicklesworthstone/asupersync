//! Contract tests for the redacted swarm timeline receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/swarm_timeline_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/swarm_timeline_receipt";
const GENERATED_AT: &str = "2026-05-08T05:30:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run swarm timeline receipt")
}

fn fixture_path(fixture: &str) -> PathBuf {
    repo_root().join(FIXTURE_ROOT).join(fixture)
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(fixture_path(fixture)).expect("read fixture text")
}

fn receipt_json(fixture: &str) -> Value {
    let output = run_receipt(fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
}

fn receipt_json_from_value(fixture: &Value) -> Value {
    let fixture_dir = repo_root().join("target/swarm_timeline_receipt_contract");
    fs::create_dir_all(&fixture_dir).expect("create generated fixture directory");
    let fixture_path = fixture_dir.join("later_ship_ordering.json");
    let fixture_body = serde_json::to_vec_pretty(fixture).expect("serialize generated fixture");
    fs::write(&fixture_path, fixture_body).expect("write generated fixture");

    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run swarm timeline receipt with generated fixture");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
}

fn receipt_text(fixture: &str) -> String {
    let output = run_receipt(fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("receipt output must be UTF-8")
}

fn assert_output_matches_golden(fixture: &str, expected_fixture: &str, drift_message: &str) {
    let actual = receipt_text(fixture);
    let expected = fixture_text(expected_fixture);

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(
        actual_json, expected_json,
        "parsed swarm timeline receipt JSON drifted for {fixture} -> {expected_fixture}"
    );
    assert_eq!(actual, expected, "{drift_message}");
}

fn timeline(receipt: &Value) -> &Vec<Value> {
    receipt["timeline"]
        .as_array()
        .expect("timeline must be an array")
}

fn event<'a>(receipt: &'a Value, kind: &str) -> &'a Value {
    timeline(receipt)
        .iter()
        .find(|event| event["kind"].as_str() == Some(kind))
        .expect("event kind should exist")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "receipt helper must exist at {SCRIPT_PATH}"
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
fn mixed_messages_and_commits_become_ordered_timeline() {
    let receipt = receipt_json("mixed_claim_ship_block.json");
    let rows = timeline(&receipt);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("swarm-timeline-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(
        receipt["source_counts"]["agent_mail_messages"].as_u64(),
        Some(4)
    );
    assert_eq!(receipt["source_counts"]["git_commits"].as_u64(), Some(1));
    assert_eq!(rows.len(), 5);

    let kinds: Vec<&str> = rows
        .iter()
        .map(|row| row["kind"].as_str().expect("kind"))
        .collect();
    assert!(kinds.contains(&"claim"));
    assert!(kinds.contains(&"ship"));
    assert!(kinds.contains(&"block"));
    assert!(kinds.contains(&"reservation"));

    let ship = event(&receipt, "ship");
    assert_eq!(ship["commit"].as_str(), Some("230604c1b8d0"));
    assert!(
        ship["bead_ids"]
            .as_array()
            .expect("ship bead ids")
            .iter()
            .any(|id| id.as_str() == Some("asupersync-aj7lx3.11"))
    );
    assert!(
        !ship["validation"]
            .as_array()
            .expect("ship validation")
            .is_empty(),
        "ship event should keep validation evidence"
    );
}

#[test]
fn mixed_timeline_matches_exact_reviewed_golden() {
    assert_output_matches_golden(
        "mixed_claim_ship_block.json",
        "mixed_claim_ship_block_expected.json",
        "mixed timeline receipt changed; update the golden only after reviewing claim, ship, block, and reservation ordering semantics",
    );
}

#[test]
fn unresolved_blocker_and_active_claim_cues_are_emitted() {
    let receipt = receipt_json("mixed_claim_ship_block.json");
    let cues = receipt["unresolved_cues"].as_array().expect("cues");

    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("active-claim-without-ship")
            && cue["bead_id"].as_str() == Some("asupersync-aj7lx3.12")
    }));
    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("unresolved-blocker")
            && cue["bead_id"].as_str() == Some("asupersync-vddieh")
    }));
}

#[test]
fn unresolved_cues_require_ship_after_claim_or_blocker() {
    let fixture = serde_json::json!({
        "agent_mail": {
            "messages": [
                {
                    "id": 20,
                    "from": "CopperSpring",
                    "thread_id": "asupersync-order1",
                    "subject": "[asupersync-order1] Starting ordered receipt",
                    "created_ts": "2026-05-08T05:20:00Z",
                    "body_md": "Claimed asupersync-order1."
                },
                {
                    "id": 21,
                    "from": "CopperSpring",
                    "thread_id": "asupersync-order1",
                    "subject": "[asupersync-order1] Claiming follow-up after prior commit",
                    "created_ts": "2026-05-08T05:40:00Z",
                    "body_md": "Claimed asupersync-order1 after the earlier commit event."
                },
                {
                    "id": 22,
                    "from": "MossyJaguar",
                    "thread_id": "asupersync-order2",
                    "subject": "Blocker: pre-ship validation frontier",
                    "created_ts": "2026-05-08T05:21:00Z",
                    "body_md": "asupersync-order2 is blocked before its later ship event."
                },
                {
                    "id": 23,
                    "from": "MossyJaguar",
                    "thread_id": "asupersync-order3",
                    "subject": "Blocker: post-ship validation frontier",
                    "created_ts": "2026-05-08T05:41:00Z",
                    "body_md": "asupersync-order3 is blocked after an earlier ship event."
                }
            ]
        },
        "git": {
            "commits": [
                {
                    "hash": "aaaaaaaaaaaa1111",
                    "author": "CopperSpring",
                    "created_ts": "2026-05-08T05:30:00Z",
                    "subject": "[br-asupersync-order1] ship ordered receipt",
                    "body": "Validation: rch exec -- cargo test -p asupersync --test swarm_timeline_receipt_contract passed."
                },
                {
                    "hash": "bbbbbbbbbbbb2222",
                    "author": "MossyJaguar",
                    "created_ts": "2026-05-08T05:31:00Z",
                    "subject": "[br-asupersync-order2] ship validation resolution",
                    "body": "Validation: rch exec -- cargo test -p asupersync --test swarm_timeline_receipt_contract passed."
                },
                {
                    "hash": "cccccccccccc3333",
                    "author": "MossyJaguar",
                    "created_ts": "2026-05-08T05:32:00Z",
                    "subject": "[br-asupersync-order3] ship earlier work",
                    "body": "Validation: rch exec -- cargo test -p asupersync --test swarm_timeline_receipt_contract passed."
                }
            ]
        }
    });

    let receipt = receipt_json_from_value(&fixture);
    let cues = receipt["unresolved_cues"].as_array().expect("cues");

    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("active-claim-without-ship")
            && cue["bead_id"].as_str() == Some("asupersync-order1")
            && cue["reason"].as_str() == Some("claim has no later ship event in this receipt")
    }));
    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("unresolved-blocker")
            && cue["bead_id"].as_str() == Some("asupersync-order3")
            && cue["reason"].as_str() == Some("blocker has no later ship event in this receipt")
    }));
    assert!(
        !cues.iter().any(|cue| {
            cue["bead_id"].as_str() == Some("asupersync-order2")
                && cue["kind"].as_str() == Some("unresolved-blocker")
        }),
        "a blocker before a later ship should be resolved"
    );
}

#[test]
fn secrets_urls_and_oversized_bodies_are_redacted() {
    let receipt = receipt_json("redaction_and_urls.json");
    let serialized = serde_json::to_string(&receipt).expect("serialize receipt");

    assert!(!serialized.contains("sk-live-this-should-not-leak"));
    assert!(!serialized.contains("token=abc123"));
    assert!(!serialized.contains("sig=secret-signature"));
    assert!(serialized.contains("[REDACTED_SECRET]"));
    assert!(serialized.contains("[REDACTED_QUERY]"));
    assert!(
        receipt["redaction_counts"]["secret"].as_u64().unwrap_or(0) >= 1,
        "at least one secret should be redacted"
    );
    assert!(
        receipt["redaction_counts"]["url_query"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "at least one URL query should be redacted"
    );
    assert!(
        receipt["redaction_counts"]["truncated"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "oversized emitted text should be truncated"
    );
}

#[test]
fn redaction_and_urls_matches_exact_reviewed_golden() {
    assert_output_matches_golden(
        "redaction_and_urls.json",
        "redaction_and_urls_expected.json",
        "swarm timeline redaction receipt changed; update the golden only after reviewing secret/query redaction and truncation semantics",
    );
}

#[test]
fn duplicate_events_are_coalesced_with_source_refs() {
    let receipt = receipt_json("duplicate_events.json");
    let rows = timeline(&receipt);

    assert_eq!(
        receipt["source_counts"]["events_before_coalescing"].as_u64(),
        Some(3)
    );
    assert_eq!(
        receipt["source_counts"]["duplicates_coalesced"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["source_counts"]["timeline_events"].as_u64(),
        Some(2)
    );

    let duplicate = rows
        .iter()
        .find(|row| row["duplicates"].as_u64() == Some(1))
        .expect("coalesced duplicate row");
    assert_eq!(
        duplicate["source_refs"]
            .as_array()
            .expect("source refs")
            .len(),
        2
    );
}

#[test]
fn duplicate_events_match_exact_reviewed_golden() {
    assert_output_matches_golden(
        "duplicate_events.json",
        "duplicate_events_expected.json",
        "swarm timeline duplicate-events receipt changed; update the golden only after reviewing duplicate coalescing and source-ref semantics",
    );
}

#[test]
fn receipt_declares_non_mutating_safety_contract() {
    let receipt = receipt_json("mixed_claim_ship_block.json");

    for key in [
        "non_mutating",
        "agent_mail_mutated",
        "beads_mutated",
        "git_mutated",
        "cargo_executed",
        "branch_or_worktree_operations",
        "files_deleted",
    ] {
        let expected = key == "non_mutating";
        assert_eq!(
            receipt["safety"][key].as_bool(),
            Some(expected),
            "{key} safety flag mismatch"
        );
    }
    assert!(
        receipt["safety_notes"]
            .as_array()
            .expect("safety notes")
            .iter()
            .any(|note| note
                .as_str()
                .unwrap_or("")
                .contains("no Agent Mail acknowledgements"))
    );
}
