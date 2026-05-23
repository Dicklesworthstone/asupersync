//! Contract tests for the dirty-tree ownership receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRIPT_PATH: &str = "scripts/dirty_tree_ownership_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/dirty_tree_ownership_receipt";
const GENERATED_AT: &str = "2026-05-08T05:10:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    run_receipt_with_args(fixture, &[])
}

fn run_receipt_with_args(fixture: &str, extra_args: &[&str]) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .args(extra_args)
        .current_dir(repo_root())
        .output()
        .expect("run dirty tree ownership receipt")
}

fn json_from_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
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
    json_from_output(&output)
}

fn receipt_stdout(fixture: &str) -> String {
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

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .expect("fixture golden must be readable")
}

fn unique_temp_dir(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "asupersync-dirty-tree-{test_name}-{}-{nanos}",
        std::process::id()
    ))
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_git(repo_path: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .unwrap_or_else(|err| panic!("run git {args:?}: {err}"))
}

fn git_success(repo_path: &Path, args: &[&str]) {
    let output = run_git(repo_path, args);
    assert_success(&output, &format!("git {args:?}"));
}

fn git_stdout(repo_path: &Path, args: &[&str]) -> String {
    let output = run_git(repo_path, args);
    assert_success(&output, &format!("git {args:?}"));
    String::from_utf8(output.stdout).expect("git stdout must be UTF-8")
}

fn git_commit(repo_path: &Path, message: &str, args: &[&str]) {
    let mut command = Command::new("git");
    let output = command
        .arg("-c")
        .arg("user.name=Asupersync Test")
        .arg("-c")
        .arg("user.email=asupersync-test@example.invalid")
        .arg("commit")
        .arg("-m")
        .arg(message)
        .args(args)
        .current_dir(repo_path)
        .output()
        .expect("run git commit");
    assert_success(&output, "git commit");
}

fn write_repo_file(repo_path: &Path, relative_path: &str, contents: &str) {
    let path = repo_path.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, contents).expect("write repo file");
}

fn write_reservation_artifact(
    artifact_dir: &Path,
    id: u64,
    agent: &str,
    path_pattern: &str,
    expires_ts: &str,
) {
    fs::create_dir_all(artifact_dir).expect("create reservation artifact dir");
    fs::write(
        artifact_dir.join(format!("reservation-{id}.json")),
        format!(
            r#"{{
  "id": {id},
  "project": "/tmp/asupersync-dirty-tree-test",
  "agent": "{agent}",
  "path_pattern": "{path_pattern}",
  "exclusive": true,
  "reason": "no-mock-shared-main-test",
  "created_ts": "2026-05-08T05:00:00Z",
  "expires_ts": "{expires_ts}"
}}"#
        ),
    )
    .expect("write reservation artifact");
}

fn init_temp_git_repo(test_name: &str) -> PathBuf {
    let repo_path = unique_temp_dir(test_name);
    assert!(
        repo_path.starts_with(std::env::temp_dir()),
        "no-mock guard tests must stay under the system temp dir"
    );
    assert!(
        !repo_path.starts_with(repo_root()),
        "no-mock guard tests must not create repos inside the project checkout"
    );

    fs::create_dir_all(&repo_path).expect("create temp repo");
    git_success(&repo_path, &["init", "-b", "main"]);
    write_repo_file(
        &repo_path,
        "src/self.rs",
        "pub fn self_value() -> u8 { 1 }\n",
    );
    write_repo_file(
        &repo_path,
        "src/peer.rs",
        "pub fn peer_value() -> u8 { 1 }\n",
    );
    write_repo_file(&repo_path, "docs/operator.md", "initial operator notes\n");
    git_success(
        &repo_path,
        &[
            "add",
            "--",
            "src/self.rs",
            "src/peer.rs",
            "docs/operator.md",
        ],
    );
    git_commit(&repo_path, "initial", &[]);
    repo_path
}

fn run_live_declared_preflight(
    repo_path: &Path,
    artifact_dir: &Path,
    commit_paths: &[&str],
) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-path")
        .arg(repo_path)
        .arg("--agent")
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--timeout")
        .arg("5")
        .arg("--reservation-artifact-dir")
        .arg(artifact_dir)
        .arg("--declared-commit-preflight")
        .arg("--output")
        .arg("json");
    for path in commit_paths {
        command.arg("--commit-path").arg(path);
    }
    command
        .current_dir(repo_root())
        .output()
        .expect("run live declared preflight")
}

fn json_string_array<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
        })
        .collect()
}

fn assert_receipt_output_matches_golden(fixture: &str, expected_fixture: &str) {
    let actual_text = receipt_stdout(fixture);
    let expected_text = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual_text).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected_text).expect("expected receipt JSON");

    assert_eq!(
        actual_json, expected_json,
        "parsed dirty-tree ownership receipt JSON drifted for {fixture} -> {expected_fixture}"
    );
    assert_eq!(
        actual_text, expected_text,
        "dirty-tree ownership receipt {expected_fixture} changed; update the golden only after reviewing dirty ownership semantics"
    );
}

fn row<'a>(receipt: &'a Value, path: &str) -> &'a Value {
    receipt["rows"]
        .as_array()
        .expect("rows must be array")
        .iter()
        .find(|row| row["path"].as_str() == Some(path))
        .expect("fixture row should exist")
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
fn live_probe_preserves_porcelain_status_columns_for_unstaged_paths() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("dirty_tree_ownership_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Completed:
    stdout = " M tests/fixtures/dirty-tree/unstaged-path.log \n"

module.subprocess.run = lambda *args, **kwargs: Completed()
status, raw = module.run_text(pathlib.Path("."), ["git", "status", "--porcelain=v1"], 1.0)
entries = module.parse_status_lines(raw if status == "ok" else "")
print(json.dumps({"status": status, "raw": raw, "entries": entries}))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .output()
        .expect("run dirty-tree live probe parser smoke");
    assert!(
        output.status.success(),
        "parser smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parser smoke JSON");
    assert_eq!(parsed["status"].as_str(), Some("ok"));
    assert_eq!(
        parsed["raw"].as_str(),
        Some(" M tests/fixtures/dirty-tree/unstaged-path.log ")
    );
    assert_eq!(parsed["entries"][0]["status"].as_str(), Some(" M"));
    assert_eq!(
        parsed["entries"][0]["path"].as_str(),
        Some("tests/fixtures/dirty-tree/unstaged-path.log ")
    );
}

#[test]
fn peer_reservation_blocks_staging() {
    let receipt = receipt_json("peer_reservation.json");
    let row = row(&receipt, "src/security/secret.rs");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("dirty-tree-ownership-receipt-v1")
    );
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["classification"].as_str(), Some("peer-owned"));
    assert_eq!(row["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
    assert_eq!(
        row["evidence"]["reservation_expires_ts"].as_str(),
        Some("2026-05-08T05:56:00Z")
    );
}

#[test]
fn peer_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden("peer_reservation.json", "peer_reservation_expected.json");
}

#[test]
fn directory_reservation_blocks_child_path_staging() {
    let receipt = receipt_json("directory_reservation.json");
    let row = row(&receipt, "src/security/secret.rs");

    assert_eq!(row["classification"].as_str(), Some("peer-owned"));
    assert_eq!(row["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(
        row["evidence"]["reservation_path_pattern"].as_str(),
        Some("src/security")
    );
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
}

#[test]
fn directory_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden(
        "directory_reservation.json",
        "directory_reservation_expected.json",
    );
}

#[test]
fn rename_target_reservation_blocks_destination_after_porcelain_expansion() {
    let receipt = receipt_json("rename_target_reservation.json");
    let source = row(&receipt, "docs/old-secret.rs");
    let target = row(&receipt, "src/security/secret.rs");

    assert_eq!(source["classification"].as_str(), Some("unattributed"));
    assert_eq!(target["classification"].as_str(), Some("peer-owned"));
    assert_eq!(target["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(
        target["evidence"]["reservation_path_pattern"].as_str(),
        Some("src/security")
    );
    assert_eq!(
        target["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
    assert_eq!(receipt["summary"]["total_paths"].as_u64(), Some(2));
    assert_eq!(receipt["summary"]["peer_owned"].as_u64(), Some(1));
    assert_eq!(receipt["summary"]["unattributed"].as_u64(), Some(1));
}

#[test]
fn rename_target_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden(
        "rename_target_reservation.json",
        "rename_target_reservation_expected.json",
    );
}

#[test]
fn self_reservation_allows_pathspec_staging() {
    let receipt = receipt_json("self_reservation.json");
    let row = row(&receipt, "scripts/dirty_tree_ownership_receipt.py");

    assert_eq!(row["classification"].as_str(), Some("self-owned"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("safe-to-stage-with-pathspec")
    );
    assert_eq!(
        row["proposed_action"]["command"].as_str(),
        Some("git add -- scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(row["proposed_action"]["allowed_now"].as_bool(), Some(true));
}

#[test]
fn self_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden("self_reservation.json", "self_reservation_expected.json");
}

#[test]
fn mixed_staged_index_requires_path_limited_commit_boundary() {
    let receipt = receipt_json("mixed_staged_index.json");
    let boundary = &receipt["commit_boundary"];

    assert_eq!(
        boundary["decision"].as_str(),
        Some("path-limited-commit-required")
    );
    assert_eq!(
        boundary["ordinary_index_commit_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        boundary["peer_index_preservation_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        boundary["self_owned_staged_paths"][0].as_str(),
        Some("scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(
        boundary["non_self_staged_paths"]
            .as_array()
            .expect("non-self staged paths")
            .len(),
        2
    );
    assert_eq!(
        boundary["path_limited_commit_command"].as_str(),
        Some("git commit --only -- scripts/dirty_tree_ownership_receipt.py")
    );
    assert!(
        !boundary["path_limited_commit_command"]
            .as_str()
            .expect("path-limited commit command")
            .contains("fuzz/Cargo.toml"),
        "path-limited commit command must not include peer staged paths"
    );

    let fuzz = row(&receipt, "fuzz/Cargo.toml");
    assert_eq!(fuzz["classification"].as_str(), Some("peer-owned"));
    assert_eq!(
        fuzz["staging_guidance"]["decision"].as_str(),
        Some("unstage-before-commit")
    );
}

#[test]
fn declared_commit_preflight_refuses_peer_staged_paths_outside_declared_scope() {
    let output = run_receipt_with_args(
        "mixed_staged_index.json",
        &[
            "--declared-commit-preflight",
            "--commit-path",
            "scripts/dirty_tree_ownership_receipt.py",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "peer staged paths outside declaration should fail closed"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(preflight["allowed"].as_bool(), Some(false));
    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-staged-paths-outside-declared-scope")
    );
    assert_eq!(
        preflight["declared_paths"][0].as_str(),
        Some("scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(
        preflight["currently_staged_paths"]
            .as_array()
            .expect("staged paths")
            .len(),
        3
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["path"].as_str(),
        Some("fuzz/Cargo.toml")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["scope"].as_str(),
        Some("peer-reserved")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["reservation_holder"].as_str(),
        Some("MaroonBear")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["reservation_path_pattern"].as_str(),
        Some("fuzz/Cargo.toml")
    );
    assert_eq!(preflight["path_limited_commit_command"].as_str(), Some(""));
}

#[test]
fn declared_commit_preflight_reads_offline_reservation_artifacts_for_blockers() {
    let artifact_dir = unique_temp_dir("offline-reservations");
    fs::create_dir_all(&artifact_dir).expect("create reservation artifact dir");
    fs::write(
        artifact_dir.join("id-9001.json"),
        r#"{
  "id": 9001,
  "project": "/data/projects/asupersync",
  "agent": "TopazGoose",
  "path_pattern": "scripts/dirty_tree_ownership_receipt.py",
  "exclusive": true,
  "reason": "declared-path-test",
  "created_ts": "2026-05-08T05:00:00Z",
  "expires_ts": "2026-05-08T06:08:00Z"
}"#,
    )
    .expect("write self reservation artifact");
    fs::write(
        artifact_dir.join("id-9002.json"),
        r#"{
  "id": 9002,
  "project": "/data/projects/asupersync",
  "agent": "MaroonBear",
  "path_pattern": "fuzz/Cargo.toml",
  "exclusive": true,
  "reason": "declared-path-test-peer",
  "created_ts": "2026-05-08T05:00:00Z",
  "expires_ts": "2026-05-08T06:30:00Z"
}"#,
    )
    .expect("write peer reservation artifact");
    fs::write(
        artifact_dir.join("id-9003.json"),
        r#"{
  "id": 9003,
  "project": "/data/projects/asupersync",
  "agent": "MaroonBear",
  "path_pattern": "fuzz/fuzz_targets/*.rs",
  "exclusive": true,
  "reason": "declared-path-test-peer-glob",
  "created_ts": "2026-05-08T05:00:00Z",
  "expires_ts": "2026-05-08T06:30:00Z"
}"#,
    )
    .expect("write peer glob reservation artifact");

    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(
            repo_root()
                .join(FIXTURE_ROOT)
                .join("mixed_staged_index.json"),
        )
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .arg("--reservation-artifact-dir")
        .arg(&artifact_dir)
        .arg("--declared-commit-preflight")
        .arg("--commit-path")
        .arg("scripts/dirty_tree_ownership_receipt.py")
        .current_dir(repo_root())
        .output()
        .expect("run dirty tree ownership receipt with offline artifacts");
    assert_eq!(
        output.status.code(),
        Some(2),
        "offline peer reservation blocker should fail closed"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        receipt["subsystems"]["agent_mail"].as_str(),
        Some("offline-reservation-artifacts-ok")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["path"].as_str(),
        Some("fuzz/Cargo.toml")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["reservation_id"].as_str(),
        Some("9002")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["reservation_artifact_path"]
            .as_str()
            .expect("artifact path")
            .ends_with("id-9002.json"),
        true
    );
}

#[test]
fn declared_commit_preflight_treats_expired_offline_reservation_as_unreserved_blocker() {
    let artifact_dir = unique_temp_dir("expired-offline-reservations");
    fs::create_dir_all(&artifact_dir).expect("create reservation artifact dir");
    fs::write(
        artifact_dir.join("id-9011.json"),
        r#"{
  "id": 9011,
  "project": "/data/projects/asupersync",
  "agent": "TopazGoose",
  "path_pattern": "scripts/dirty_tree_ownership_receipt.py",
  "exclusive": true,
  "reason": "declared-path-test",
  "created_ts": "2026-05-08T05:00:00Z",
  "expires_ts": "2026-05-08T06:08:00Z"
}"#,
    )
    .expect("write self reservation artifact");
    fs::write(
        artifact_dir.join("id-9012.json"),
        r#"{
  "id": 9012,
  "project": "/data/projects/asupersync",
  "agent": "MaroonBear",
  "path_pattern": "fuzz/Cargo.toml",
  "exclusive": true,
  "reason": "expired-peer",
  "created_ts": "2026-05-08T04:00:00Z",
  "expires_ts": "2026-05-08T04:30:00Z"
}"#,
    )
    .expect("write expired peer reservation artifact");

    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(
            repo_root()
                .join(FIXTURE_ROOT)
                .join("mixed_staged_index.json"),
        )
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .arg("--reservation-artifact-dir")
        .arg(&artifact_dir)
        .arg("--declared-commit-preflight")
        .arg("--commit-path")
        .arg("scripts/dirty_tree_ownership_receipt.py")
        .current_dir(repo_root())
        .output()
        .expect("run dirty tree ownership receipt with expired offline artifact");
    assert_eq!(
        output.status.code(),
        Some(2),
        "expired peer artifact should leave staged path unreserved and blocked"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        preflight["commit_race_blockers"][0]["path"].as_str(),
        Some("fuzz/Cargo.toml")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["scope"].as_str(),
        Some("unreserved")
    );
    assert!(
        preflight["commit_race_blockers"][0]["reservation_id"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "expired reservation id must not be cited as active ownership"
    );
}

#[test]
fn no_mock_shared_index_preflight_refuses_peer_staged_race_without_mutating_index() {
    let repo_path = init_temp_git_repo("peer-staged-race");
    let artifact_dir = unique_temp_dir("peer-staged-race-reservations");
    write_reservation_artifact(
        &artifact_dir,
        9101,
        "TopazGoose",
        "src/self.rs",
        "2026-05-08T06:08:00Z",
    );
    write_reservation_artifact(
        &artifact_dir,
        9102,
        "MaroonBear",
        "src/peer.rs",
        "2026-05-08T06:08:00Z",
    );

    write_repo_file(
        &repo_path,
        "src/self.rs",
        "pub fn self_value() -> u8 { 2 }\n",
    );
    write_repo_file(
        &repo_path,
        "src/peer.rs",
        "pub fn peer_value() -> u8 { 2 }\n",
    );
    git_success(&repo_path, &["add", "--", "src/self.rs", "src/peer.rs"]);

    let before_status = git_stdout(&repo_path, &["status", "--porcelain=v1"]);
    assert!(before_status.contains("M  src/self.rs"));
    assert!(before_status.contains("M  src/peer.rs"));

    let output = run_live_declared_preflight(&repo_path, &artifact_dir, &["src/self.rs"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "live shared-index peer race should fail closed"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(receipt["subsystems"]["git"].as_str(), Some("ok"));
    assert_eq!(
        receipt["subsystems"]["agent_mail"].as_str(),
        Some("offline-reservation-artifacts-ok")
    );
    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-staged-paths-outside-declared-scope")
    );
    assert_eq!(
        json_string_array(preflight, "currently_staged_paths"),
        vec!["src/peer.rs", "src/self.rs"]
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["path"].as_str(),
        Some("src/peer.rs")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["scope"].as_str(),
        Some("peer-reserved")
    );
    assert_eq!(
        preflight["commit_race_blockers"][0]["reservation_holder"].as_str(),
        Some("MaroonBear")
    );

    let after_status = git_stdout(&repo_path, &["status", "--porcelain=v1"]);
    assert_eq!(
        after_status, before_status,
        "preflight must not mutate staged self or peer paths"
    );
}

#[test]
fn no_mock_declared_only_commit_preserves_unstaged_peer_work() {
    let repo_path = init_temp_git_repo("declared-only-preserves-peer-work");
    let artifact_dir = unique_temp_dir("declared-only-preserves-peer-work-reservations");
    write_reservation_artifact(
        &artifact_dir,
        9111,
        "TopazGoose",
        "src/self.rs",
        "2026-05-08T06:08:00Z",
    );
    write_reservation_artifact(
        &artifact_dir,
        9112,
        "MaroonBear",
        "src/peer.rs",
        "2026-05-08T06:08:00Z",
    );

    write_repo_file(
        &repo_path,
        "src/self.rs",
        "pub fn self_value() -> u8 { 3 }\n",
    );
    write_repo_file(
        &repo_path,
        "src/peer.rs",
        "pub fn peer_value() -> u8 { 3 }\n",
    );
    git_success(&repo_path, &["add", "--", "src/self.rs"]);

    let output = run_live_declared_preflight(&repo_path, &artifact_dir, &["src/self.rs"]);
    assert_success(&output, "live declared-only preflight");
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        preflight["decision"].as_str(),
        Some("ready-path-limited-commit")
    );
    assert_eq!(
        preflight["path_limited_commit_command"].as_str(),
        Some("git commit --only -- src/self.rs")
    );
    assert_eq!(
        json_string_array(preflight, "dirty_peer_paths_outside_scope"),
        vec!["src/peer.rs"]
    );
    assert_eq!(
        json_string_array(preflight, "dirty_unstaged_paths_outside_scope"),
        vec!["src/peer.rs"]
    );

    git_commit(
        &repo_path,
        "commit self slice only",
        &["--only", "--", "src/self.rs"],
    );
    let committed_paths = git_stdout(
        &repo_path,
        &["show", "--name-only", "--pretty=format:", "HEAD"],
    );
    assert!(committed_paths.contains("src/self.rs"));
    assert!(
        !committed_paths.contains("src/peer.rs"),
        "path-limited commit must exclude peer work"
    );

    let status = git_stdout(&repo_path, &["status", "--porcelain=v1"]);
    assert!(
        status.contains(" M src/peer.rs"),
        "unstaged peer work should remain after declared-only commit: {status:?}"
    );
    assert!(
        !status.contains("src/self.rs"),
        "declared self path should be clean after commit: {status:?}"
    );
}

#[test]
fn no_mock_path_limited_commit_preserves_other_staged_work_when_guard_allows() {
    let repo_path = init_temp_git_repo("path-limited-preserves-other-staged-work");
    let artifact_dir = unique_temp_dir("path-limited-preserves-other-staged-work-reservations");
    write_reservation_artifact(
        &artifact_dir,
        9121,
        "TopazGoose",
        "src/self.rs",
        "2026-05-08T06:08:00Z",
    );
    write_reservation_artifact(
        &artifact_dir,
        9122,
        "TopazGoose",
        "docs/operator.md",
        "2026-05-08T06:08:00Z",
    );

    write_repo_file(
        &repo_path,
        "src/self.rs",
        "pub fn self_value() -> u8 { 4 }\n",
    );
    write_repo_file(&repo_path, "docs/operator.md", "follow-up operator notes\n");
    git_success(
        &repo_path,
        &["add", "--", "src/self.rs", "docs/operator.md"],
    );

    let output = run_live_declared_preflight(&repo_path, &artifact_dir, &["src/self.rs"]);
    assert_success(&output, "live path-limited preflight");
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        preflight["decision"].as_str(),
        Some("ready-path-limited-commit")
    );
    assert_eq!(
        preflight["own_reserved_staged_paths_outside_scope"][0]["path"].as_str(),
        Some("docs/operator.md")
    );
    assert_eq!(
        preflight["path_limited_commit_command"].as_str(),
        Some("git commit --only -- src/self.rs")
    );

    git_commit(
        &repo_path,
        "commit one reserved path only",
        &["--only", "--", "src/self.rs"],
    );
    let status = git_stdout(&repo_path, &["status", "--porcelain=v1"]);
    assert!(
        status.contains("M  docs/operator.md"),
        "other staged work should remain staged after git commit --only: {status:?}"
    );
    assert!(
        !status.contains("src/self.rs"),
        "declared path should be clean after path-limited commit: {status:?}"
    );
}

#[test]
fn declared_commit_preflight_refuses_empty_declared_path_set() {
    let output = run_receipt_with_args("mixed_staged_index.json", &["--declared-commit-preflight"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "empty declaration should fail closed"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(preflight["allowed"].as_bool(), Some(false));
    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-empty-declared-paths")
    );
    assert_eq!(
        preflight["final_commit_path_set"]
            .as_array()
            .expect("final commit paths")
            .len(),
        0
    );
}

#[test]
fn declared_commit_preflight_refuses_paths_outside_repository() {
    let output = run_receipt_with_args(
        "mixed_staged_index.json",
        &[
            "--declared-commit-preflight",
            "--commit-path",
            "../outside.rs",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "outside declaration should fail closed"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-invalid-declared-paths")
    );
    assert_eq!(
        preflight["declared_path_errors"][0]["reason"].as_str(),
        Some("declared commit path resolves outside repository")
    );
}

#[test]
fn declared_commit_preflight_refuses_peer_declared_path() {
    let output = run_receipt_with_args(
        "mixed_staged_index.json",
        &[
            "--declared-commit-preflight",
            "--commit-path",
            "fuzz/Cargo.toml",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "peer-owned declaration should fail closed"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-unowned-declared-paths")
    );
    assert_eq!(
        preflight["unsafe_declared_paths"][0].as_str(),
        Some("fuzz/Cargo.toml")
    );
    assert_eq!(preflight["path_limited_commit_command"].as_str(), Some(""));
}

#[test]
fn declared_commit_preflight_allows_unattributed_declared_tracked_path_with_warning() {
    let output = run_receipt_with_args(
        "no_agent_mail.json",
        &[
            "--declared-commit-preflight",
            "--commit-path",
            "src/unknown.rs",
        ],
    );
    assert!(
        output.status.success(),
        "tracked unattributed declaration should pass with warning: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(preflight["allowed"].as_bool(), Some(true));
    assert_eq!(
        preflight["decision"].as_str(),
        Some("ready-path-limited-commit")
    );
    assert_eq!(
        preflight["unattributed_declared_paths"][0].as_str(),
        Some("src/unknown.rs")
    );
    assert_eq!(
        preflight["final_commit_path_set"][0].as_str(),
        Some("src/unknown.rs")
    );
    assert_eq!(
        preflight["path_limited_commit_command"].as_str(),
        Some("git commit --only -- src/unknown.rs")
    );
}

#[test]
fn declared_commit_preflight_refuses_untracked_declared_path_until_staged() {
    let output = run_receipt_with_args(
        "self_reservation.json",
        &[
            "--declared-commit-preflight",
            "--commit-path",
            "scripts/dirty_tree_ownership_receipt.py",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "untracked declaration should fail until staged"
    );
    let receipt = json_from_output(&output);
    let preflight = &receipt["declared_commit"];

    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-untracked-declared-paths")
    );
    assert_eq!(
        preflight["untracked_declared_paths"][0].as_str(),
        Some("scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(
        preflight["final_commit_path_set"]
            .as_array()
            .expect("final commit paths")
            .len(),
        0
    );
}

#[test]
fn declared_commit_preflight_refuses_clean_tree_noop() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
repo_path = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("dirty_tree_ownership_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

preflight = module.build_declared_commit_preflight([], ["src/lib.rs"], repo_path)
print(json.dumps(preflight))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(repo_root().join(SCRIPT_PATH))
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run clean-tree declared preflight smoke");
    assert!(
        output.status.success(),
        "clean-tree preflight smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let preflight: Value = serde_json::from_slice(&output.stdout).expect("preflight JSON");
    assert_eq!(
        preflight["decision"].as_str(),
        Some("refuse-no-dirty-declared-paths")
    );
    assert_eq!(
        preflight["declared_clean_or_missing_paths"][0].as_str(),
        Some("src/lib.rs")
    );
    assert_eq!(
        preflight["final_commit_path_set"]
            .as_array()
            .expect("final commit paths")
            .len(),
        0
    );
}

#[test]
fn declared_commit_preflight_quotes_pathspec_edges() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
repo_path = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("dirty_tree_ownership_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

rows = [
    {
        "path": "docs/path with space.md",
        "classification": "self-owned",
        "evidence": {"index_status": "A"},
    },
]
preflight = module.build_declared_commit_preflight(
    rows, ["docs/path with space.md"], repo_path
)
print(json.dumps(preflight))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(repo_root().join(SCRIPT_PATH))
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run pathspec declared preflight smoke");
    assert!(
        output.status.success(),
        "pathspec preflight smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let preflight: Value = serde_json::from_slice(&output.stdout).expect("preflight JSON");
    assert_eq!(
        preflight["path_limited_commit_command"].as_str(),
        Some("git commit --only -- 'docs/path with space.md'")
    );
}

#[test]
fn mixed_staged_index_matches_full_output_golden() {
    assert_receipt_output_matches_golden(
        "mixed_staged_index.json",
        "mixed_staged_index_expected.json",
    );
}

#[test]
fn upstream_drift_requires_refresh_before_commit() {
    let receipt = receipt_json("upstream_drift.json");
    let boundary = &receipt["shared_main_boundary"];

    assert_eq!(boundary["decision"].as_str(), Some("refresh-before-commit"));
    assert_eq!(boundary["upstream_drift"]["behind"].as_u64(), Some(2));
    assert_eq!(
        boundary["upstream_drift"]["requires_refresh"].as_bool(),
        Some(true)
    );
    assert_eq!(
        boundary["safe_to_stage_paths"][0].as_str(),
        Some("scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(
        boundary["unsafe_to_stage_paths"][0].as_str(),
        Some("tests/proof_status_snapshot_contract.rs")
    );
    assert_eq!(
        boundary["staged_without_ownership_paths"][0].as_str(),
        Some("tests/proof_status_snapshot_contract.rs")
    );
    assert_eq!(
        boundary["recommended_git_add_command"].as_str(),
        Some("git add -- scripts/dirty_tree_ownership_receipt.py")
    );
}

#[test]
fn tracker_dirty_state_is_never_mixed() {
    let receipt = receipt_json("tracker_dirty.json");
    let row = row(&receipt, ".beads/issues.jsonl");

    assert_eq!(row["classification"].as_str(), Some("tracker-state"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
    assert_eq!(receipt["summary"]["tracker_state"].as_u64(), Some(1));
}

#[test]
fn tracker_dirty_matches_full_output_golden() {
    assert_receipt_output_matches_golden("tracker_dirty.json", "tracker_dirty_expected.json");
}

#[test]
fn recent_message_can_assign_peer_owner_without_reservation() {
    let receipt = receipt_json("message_owner.json");
    let row = row(&receipt, "tests/proof_status_snapshot_contract.rs");

    assert_eq!(row["classification"].as_str(), Some("peer-owned"));
    assert_eq!(row["owner"].as_str(), Some("CoralGorge"));
    assert_eq!(
        row["evidence"]["message_created_ts"].as_str(),
        Some("2026-05-08T05:04:37Z")
    );
}

#[test]
fn message_owner_matches_full_output_golden() {
    assert_receipt_output_matches_golden("message_owner.json", "message_owner_expected.json");
}

#[test]
fn unavailable_agent_mail_leaves_path_unattributed() {
    let receipt = receipt_json("no_agent_mail.json");
    let row = row(&receipt, "src/unknown.rs");

    assert_eq!(
        receipt["subsystems"]["agent_mail"].as_str(),
        Some("unavailable")
    );
    assert_eq!(row["classification"].as_str(), Some("unattributed"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("needs-owner")
    );
}

#[test]
fn no_agent_mail_matches_full_output_golden() {
    assert_receipt_output_matches_golden("no_agent_mail.json", "no_agent_mail_expected.json");
}

#[test]
fn conflicting_owner_signals_are_explicit() {
    let receipt = receipt_json("owner_conflict.json");
    let row = row(&receipt, "src/sync/rwlock.rs");

    assert_eq!(row["classification"].as_str(), Some("owner-conflict"));
    assert_eq!(receipt["summary"]["owner_conflict"].as_u64(), Some(1));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
}

#[test]
fn owner_conflict_matches_full_output_golden() {
    assert_receipt_output_matches_golden("owner_conflict.json", "owner_conflict_expected.json");
}

#[test]
fn receipt_safety_contract_forbids_execution_and_destructive_commands() {
    let receipt = receipt_json("self_reservation.json");

    assert_eq!(
        receipt["safety"]["mutating_commands_executed"].as_bool(),
        Some(false)
    );
    assert_eq!(receipt["safety"]["beads_mutated"].as_bool(), Some(false));
    assert_eq!(receipt["safety"]["cargo_executed"].as_bool(), Some(false));
    assert_eq!(
        receipt["safety"]["branch_or_worktree_operations"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["safety"]["forbidden_command_tokens"]
            .as_array()
            .expect("forbidden tokens array")
            .len(),
        0
    );
}

#[test]
fn receipt_has_required_top_level_shape() {
    let receipt = receipt_json("peer_reservation.json");
    for field in [
        "schema_version",
        "generated_at",
        "current_date",
        "agent",
        "repo_path",
        "subsystems",
        "rows",
        "summary",
        "safety",
    ] {
        assert!(receipt.get(field).is_some(), "receipt missing {field}");
    }
}
