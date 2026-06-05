//! Contract tests for the proof artifact freshness receipt helper.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SCRIPT_PATH: &str = "scripts/proof_artifact_freshness_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/proof_artifact_freshness_receipt";
const LARGE_CORPUS_CONTRACT_PATH: &str = "artifacts/proof_reuse_large_corpus_contract_v1.json";
const GENERATED_AT: &str = "2026-05-08T05:20:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    run_receipt_with_repo_path(fixture, repo_root().to_string_lossy().as_ref())
}

fn run_receipt_with_repo_path(fixture: &str, repo_path: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_path)
        .arg("--agent")
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run proof artifact freshness receipt")
}

fn run_reuse_index(output_format: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-path")
        .arg("/repo")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--reuse-index-root")
        .arg(repo_root().join(FIXTURE_ROOT).join("reuse_index_receipts"))
        .arg("--output")
        .arg(output_format)
        .current_dir(repo_root())
        .output()
        .expect("run proof reuse index")
}

fn run_reuse_query(output_format: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-path")
        .arg("/repo")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--reuse-index-root")
        .arg(repo_root().join(FIXTURE_ROOT).join("reuse_index_receipts"))
        .arg("--request")
        .arg(
            repo_root()
                .join(FIXTURE_ROOT)
                .join("reuse_index_request.json"),
        )
        .arg("--output")
        .arg(output_format)
        .current_dir(repo_root())
        .output()
        .expect("run proof reuse query")
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

fn reuse_query_json() -> Value {
    let output = run_reuse_query("json");
    assert!(
        output.status.success(),
        "proof reuse query failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("proof reuse query output must be JSON")
}

fn large_corpus_contract_json() -> Value {
    let text = fs::read_to_string(repo_root().join(LARGE_CORPUS_CONTRACT_PATH))
        .expect("read large-corpus proof reuse contract");
    serde_json::from_str(&text).expect("large-corpus proof reuse contract JSON")
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture)).expect("read fixture text")
}

fn first_row(receipt: &Value) -> &Value {
    receipt
        .get("rows")
        .and_then(Value::as_array)
        .expect("rows must be array")
        .first()
        .expect("fixture should have at least one row")
}

fn assert_output_matches_full_golden(input_fixture: &str, expected_fixture: &str) {
    let output = run_receipt_with_repo_path(input_fixture, "/repo");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("receipt stdout is utf-8");
    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt output JSON");
    let expected = fixture_text(expected_fixture);
    let expected_json: Value =
        serde_json::from_str(&expected).expect("expected receipt output JSON");

    assert_eq!(
        actual_json, expected_json,
        "parsed proof artifact freshness receipt JSON drifted for {input_fixture} -> {expected_fixture}"
    );
    assert_eq!(
        actual, expected,
        "proof artifact freshness receipt text drifted for {input_fixture} -> {expected_fixture}"
    );
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
spec = importlib.util.spec_from_file_location("proof_artifact_freshness_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Completed:
    stdout = " M tests/fixtures/proof-artifact/unstaged-path.log \n"

module.subprocess.run = lambda *args, **kwargs: Completed()
status, raw = module.run_text(pathlib.Path("."), ["git", "status", "--porcelain=v1"], 1.0)
entries = module.parse_status_lines(raw if status == "ok" else "")
print(json.dumps({"status": status, "raw": raw, "entries": entries}))
"#;
    let mut child = Command::new("python3")
        .arg("-")
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proof-artifact live probe parser smoke");
    child
        .stdin
        .as_mut()
        .expect("parser smoke stdin")
        .write_all(script.as_bytes())
        .expect("write parser smoke script");
    let output = child
        .wait_with_output()
        .expect("run proof-artifact live probe parser smoke");
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
        Some(" M tests/fixtures/proof-artifact/unstaged-path.log ")
    );
    assert_eq!(parsed["entries"][0]["status"].as_str(), Some(" M"));
    assert_eq!(
        parsed["entries"][0]["path"].as_str(),
        Some("tests/fixtures/proof-artifact/unstaged-path.log ")
    );
}

#[test]
fn live_probe_expands_porcelain_rename_source_and_target_paths() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("proof_artifact_freshness_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

entries = module.parse_status_lines(
    "R  tests/fixtures/proof-artifact/old.log -> tests/fixtures/proof-artifact/new.log\n"
)
print(json.dumps({"entries": entries}))
"#;
    let mut child = Command::new("python3")
        .arg("-")
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proof-artifact rename parser smoke");
    child
        .stdin
        .as_mut()
        .expect("parser smoke stdin")
        .write_all(script.as_bytes())
        .expect("write parser smoke script");
    let output = child
        .wait_with_output()
        .expect("run proof-artifact rename parser smoke");
    assert!(
        output.status.success(),
        "rename parser smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parser smoke JSON");
    let entries = parsed["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["status"].as_str(), Some("R "));
    assert_eq!(
        entries[0]["path"].as_str(),
        Some("tests/fixtures/proof-artifact/old.log")
    );
    assert_eq!(
        entries[1]["path"].as_str(),
        Some("tests/fixtures/proof-artifact/new.log")
    );
}

#[test]
fn current_clean_artifact_is_citeable() {
    let receipt = receipt_json("current_clean.json");
    let row = first_row(&receipt);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("proof-artifact-freshness-receipt-v1")
    );
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["classification"].as_str(), Some("current-clean"));
    assert_eq!(row["decision"].as_str(), Some("cite-as-current"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(true));
    assert_eq!(
        row["evidence"]["rch_remote_route_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        row["evidence"]["rch_remote_route_segments"][0].as_str(),
        Some("[RCH] remote rch-worker-proof-01 (12.3s)")
    );
    assert_eq!(
        row["evidence"]["proof_output_digest"].as_str(),
        Some("sha256:424dd7b9454acabbeeabcd07f2023c8b268aed605036a5e13c8b727b0a96f180")
    );
    assert_eq!(
        row["evidence"]["proof_output_byte_count"].as_u64(),
        Some(40)
    );
    assert_eq!(
        row["evidence"]["proof_output_segment_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        row["evidence"]["artifact_source_fingerprint"].as_str(),
        Some("sha256:source-current-clean")
    );
    assert_eq!(
        row["evidence"]["artifact_tree_fingerprint"].as_str(),
        Some("git-tree:current-clean")
    );
    assert_eq!(receipt["summary"]["safe_to_cite"].as_u64(), Some(1));
}

#[test]
fn current_clean_matches_full_output_golden() {
    assert_output_matches_full_golden("current_clean.json", "current_clean_expected.json");
}

#[test]
fn bare_cargo_command_requires_rerun_even_at_current_head() {
    let receipt = receipt_json("bare_cargo_command.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unsafe-proof-command"));
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    assert_eq!(row["evidence"]["bare_cargo_command"].as_bool(), Some(true));
    assert!(
        row["remediation"]["rerun_command"]
            .as_str()
            .expect("rerun command")
            .starts_with(
                "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test"
            )
    );
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
}

#[test]
fn rch_cargo_without_remote_required_or_target_dir_requires_rerun() {
    let receipt = receipt_json("missing_remote_required_command.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unsafe-proof-command"));
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    let reasons = row["evidence"]["unsafe_cargo_command_reasons"]
        .as_array()
        .expect("unsafe reasons must be present");
    assert!(
        reasons
            .iter()
            .any(|reason| reason.as_str() == Some("missing-rch-require-remote"))
    );
    assert!(
        row["remediation"]["rerun_command"]
            .as_str()
            .expect("rerun command")
            .starts_with(
                "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test"
            )
    );
}

#[test]
fn missing_remote_required_command_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "missing_remote_required_command.json",
        "missing_remote_required_command_expected.json",
    );
}

#[test]
fn rch_exec_cargo_without_env_target_dir_requires_rerun() {
    let receipt = receipt_json("missing_target_dir_command.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unsafe-proof-command"));
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    let reasons = row["evidence"]["unsafe_cargo_command_reasons"]
        .as_array()
        .expect("unsafe reasons must be present");
    assert!(
        reasons
            .iter()
            .any(|reason| reason.as_str() == Some("missing-cargo-target-dir"))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.as_str() == Some("missing-rch-env-wrapper"))
    );
}

#[test]
fn rch_cargo_without_remote_worker_route_evidence_requires_rerun() {
    let receipt = receipt_json("missing_remote_route_evidence.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("unverifiable-rch-remote-proof")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    assert_eq!(
        row["reason"].as_str(),
        Some("artifact proof evidence lacks positive rch remote worker route marker")
    );
    assert_eq!(
        row["evidence"]["rch_remote_route_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        row["evidence"]["rch_remote_route_segments"]
            .as_array()
            .expect("remote route segments")
            .len(),
        0
    );
    assert_eq!(
        row["evidence"]["proof_output_digest"].as_str(),
        Some("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(row["evidence"]["proof_output_byte_count"].as_u64(), Some(0));
    assert_eq!(
        row["evidence"]["proof_output_segment_count"].as_u64(),
        Some(0)
    );
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
    assert_eq!(receipt["summary"]["unverifiable"].as_u64(), Some(1));
    assert_eq!(
        row["remediation"]["operator_note"].as_str(),
        Some("Do not cite an RCH Cargo proof without positive remote-worker route evidence.")
    );
}

#[test]
fn fuzz_extent_warm_cache_only_requires_source_fresh_target_coverage() {
    let receipt = receipt_json("fuzz_extent_warm_cache_only.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("unverifiable-fuzz-extent-proof")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    let reasons = row["evidence"]["fuzz_extent_proof_reasons"]
        .as_array()
        .expect("fuzz extent reasons must be present");
    for expected in [
        "cache-warmth-used-as-correctness-evidence",
        "missing-command-fingerprint",
        "missing-registered-targets",
        "missing-source-fresh-target-coverage",
        "missing-target-dir-identity",
        "missing-toolchain-fingerprint",
        "success-output-without-target-coverage",
        "target-dir-not-source-fresh",
    ] {
        assert!(
            reasons
                .iter()
                .any(|reason| reason.as_str() == Some(expected)),
            "missing fuzz extent proof reason: {expected}"
        );
    }
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
}

#[test]
fn fuzz_extent_missing_registered_target_requires_rerun() {
    let receipt = receipt_json("fuzz_extent_missing_target.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("unverifiable-fuzz-extent-proof")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    let reasons = row["evidence"]["fuzz_extent_proof_reasons"]
        .as_array()
        .expect("fuzz extent reasons must be present");
    assert!(
        reasons
            .iter()
            .any(|reason| reason.as_str() == Some("source-fresh-target-coverage-incomplete"))
    );
    assert_eq!(
        row["evidence"]["fuzz_extent_missing_targets"][0].as_str(),
        Some("dns_message_decoder")
    );
}

#[test]
fn fuzz_extent_source_fresh_receipt_is_citeable() {
    let receipt = receipt_json("fuzz_extent_source_fresh.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("current-clean"));
    assert_eq!(row["decision"].as_str(), Some("cite-as-current"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(true));
    assert_eq!(
        row["evidence"]["fuzz_extent"]["target_dir_freshness"].as_str(),
        Some("unique")
    );
    assert_eq!(
        row["evidence"]["fuzz_extent"]["registered_targets"]
            .as_array()
            .expect("registered targets")
            .len(),
        2
    );
}

#[test]
fn missing_target_dir_command_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "missing_target_dir_command.json",
        "missing_target_dir_command_expected.json",
    );
}

#[test]
fn rch_local_fallback_output_requires_rerun_even_at_current_head() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("proof_artifact_freshness_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

artifact = module.normalize_artifact({
    "artifact_path": "artifacts/proof/local-fallback.json",
    "git_sha": "2222222222222222222222222222222222222222",
    "git_branch": "main",
    "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_agent cargo test -p asupersync --test proof_artifact_freshness_receipt_contract",
    "stderr": "\n".join([
        "[RCH] local (daemon unavailable)",
        "falling back to local execution",
        "local fallback forced by wrapper",
        "fallback to local after remote queue timeout",
        "executing locally after remote failure",
    ]),
    "touched_files": [
        "scripts/proof_artifact_freshness_receipt.py",
        "tests/proof_artifact_freshness_receipt_contract.rs"
    ],
    "status": "pass",
    "generated_at": "2026-05-08T05:15:00Z",
})
row = module.classify_artifact(
    artifact,
    "2222222222222222222222222222222222222222",
    "main",
    [],
)
print(json.dumps(row, sort_keys=True))
"#;
    let mut child = Command::new("python3")
        .arg("-")
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proof-artifact rch local fallback classifier smoke");
    child
        .stdin
        .as_mut()
        .expect("classifier smoke stdin")
        .write_all(script.as_bytes())
        .expect("write classifier smoke script");
    let output = child
        .wait_with_output()
        .expect("run proof-artifact rch local fallback classifier smoke");
    assert!(
        output.status.success(),
        "rch local fallback classifier smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("classifier smoke JSON");
    assert_eq!(
        parsed["classification"].as_str(),
        Some("rch-local-fallback-proof")
    );
    assert_eq!(parsed["decision"].as_str(), Some("rerun-required"));
    assert_eq!(parsed["safe_to_cite"].as_bool(), Some(false));
    assert_eq!(
        parsed["evidence"]["rch_local_fallback"].as_bool(),
        Some(true)
    );
    assert_eq!(
        parsed["evidence"]["rch_local_fallback_segments"][0].as_str(),
        Some("[RCH] local (daemon unavailable)")
    );
    let segments = parsed["evidence"]["rch_local_fallback_segments"]
        .as_array()
        .expect("fallback segments must be array");
    for expected in [
        "[RCH] local (daemon unavailable)",
        "falling back to local execution",
        "local fallback forced by wrapper",
        "fallback to local after remote queue timeout",
        "executing locally after remote failure",
    ] {
        assert!(
            segments
                .iter()
                .any(|segment| segment.as_str() == Some(expected)),
            "missing fallback segment: {expected}"
        );
    }
}

#[test]
fn rch_remote_worker_route_evidence_normalizes_from_common_output_fields() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("proof_artifact_freshness_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

head = "2222222222222222222222222222222222222222"
rows = []
for field in ["stdout", "stderr", "proof_output", "command_output"]:
    raw = {
        "artifact_path": "artifacts/proof/" + field + ".json",
        "git_sha": head,
        "git_branch": "main",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_remote_route cargo test -p asupersync --test proof_artifact_freshness_receipt_contract",
        field: "[RCH] remote rch-worker-" + field + " (1.0s)",
        "touched_files": [
            "scripts/proof_artifact_freshness_receipt.py",
            "tests/proof_artifact_freshness_receipt_contract.rs"
        ],
        "status": "pass",
        "generated_at": "2026-05-08T05:15:00Z",
    }
    artifact = module.normalize_artifact(raw)
    row = module.classify_artifact(artifact, head, "main", [])
    rows.append({
        "field": field,
        "classification": row["classification"],
        "safe_to_cite": row["safe_to_cite"],
        "segments": row["evidence"].get("rch_remote_route_segments", []),
    })
print(json.dumps(rows, sort_keys=True))
"#;
    let mut child = Command::new("python3")
        .arg("-")
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proof-artifact remote route classifier smoke");
    child
        .stdin
        .as_mut()
        .expect("classifier smoke stdin")
        .write_all(script.as_bytes())
        .expect("write classifier smoke script");
    let output = child
        .wait_with_output()
        .expect("run proof-artifact remote route classifier smoke");
    assert!(
        output.status.success(),
        "remote route classifier smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("classifier smoke JSON");
    let rows = parsed.as_array().expect("classifier smoke rows");
    assert_eq!(rows.len(), 4);
    for field in ["stdout", "stderr", "proof_output", "command_output"] {
        let row = rows
            .iter()
            .find(|row| row["field"].as_str() == Some(field))
            .expect("field row");
        assert_eq!(row["classification"].as_str(), Some("current-clean"));
        assert_eq!(row["safe_to_cite"].as_bool(), Some(true));
        let expected_segment = format!("[RCH] remote rch-worker-{field} (1.0s)");
        assert_eq!(row["segments"][0].as_str(), Some(expected_segment.as_str()));
    }
}

#[test]
fn proof_output_digest_normalizes_line_endings_and_accepts_fingerprints() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("proof_artifact_freshness_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

head = "2222222222222222222222222222222222222222"
base = {
    "artifact_path": "artifacts/proof/digest.json",
    "git_sha": head,
    "git_branch": "main",
    "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_digest cargo test -p asupersync --test proof_artifact_freshness_receipt_contract",
    "touched_files": [
        "scripts/proof_artifact_freshness_receipt.py",
        "tests/proof_artifact_freshness_receipt_contract.rs"
    ],
    "status": "pass",
    "generated_at": "2026-05-08T05:15:00Z",
}
with_crlf = dict(base)
with_crlf.update({
    "stderr": "[RCH] remote rch-worker-digest (1.0s)",
    "stdout": "line one\r\nline two\n",
    "source": {"fingerprint": "sha256:source-digest"},
    "metadata": {"source_tree_fingerprint": "git-tree:digest"},
})
split_fields = dict(base)
split_fields.update({
    "stderr": "line two",
    "stdout": "line one",
    "proof_output": "[RCH] remote rch-worker-digest (1.0s)",
    "metadata": {
        "source_fingerprint": "sha256:source-digest",
        "git_tree_sha": "git-tree:digest",
    },
})
rows = []
for name, raw in [("with_crlf", with_crlf), ("split_fields", split_fields)]:
    artifact = module.normalize_artifact(raw)
    row = module.classify_artifact(artifact, head, "main", [])
    rows.append({"name": name, "evidence": row["evidence"]})
print(json.dumps(rows, sort_keys=True))
"#;
    let mut child = Command::new("python3")
        .arg("-")
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proof-output digest classifier smoke");
    child
        .stdin
        .as_mut()
        .expect("classifier smoke stdin")
        .write_all(script.as_bytes())
        .expect("write classifier smoke script");
    let output = child
        .wait_with_output()
        .expect("run proof-output digest classifier smoke");
    assert!(
        output.status.success(),
        "proof-output digest classifier smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("classifier smoke JSON");
    let rows = parsed.as_array().expect("classifier smoke rows");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let evidence = &row["evidence"];
        assert_eq!(
            evidence["proof_output_digest"].as_str(),
            Some("sha256:db286a313e464f83b82a2f2726df39ad11dd82f58ab3431084939d3551e31583")
        );
        assert_eq!(evidence["proof_output_byte_count"].as_u64(), Some(55));
        assert_eq!(
            evidence["artifact_source_fingerprint"].as_str(),
            Some("sha256:source-digest")
        );
        assert_eq!(
            evidence["artifact_tree_fingerprint"].as_str(),
            Some("git-tree:digest")
        );
    }
}

#[test]
fn bare_cargo_command_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "bare_cargo_command.json",
        "bare_cargo_command_expected.json",
    );
}

#[test]
fn superseded_head_is_suppressed_even_when_status_passed() {
    let receipt = receipt_json("superseded_head.json");
    let row = first_row(&receipt);

    assert_eq!(row["status"].as_str(), Some("pass"));
    assert_eq!(row["classification"].as_str(), Some("superseded-head"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-stale"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    assert_eq!(
        row["evidence"]["artifact_git_sha"].as_str(),
        Some("1111111111111111111111111111111111111111")
    );
    assert_eq!(
        row["evidence"]["current_head_sha"].as_str(),
        Some("2222222222222222222222222222222222222222")
    );
}

#[test]
fn superseded_head_matches_full_output_golden() {
    assert_output_matches_full_golden("superseded_head.json", "superseded_head_expected.json");
}

#[test]
fn non_main_artifact_branch_is_wrong_branch() {
    let receipt = receipt_json("wrong_branch.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("wrong-branch"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-stale"));
    assert_eq!(
        row["reason"].as_str(),
        Some("artifact was produced on a non-main branch")
    );
}

#[test]
fn wrong_branch_matches_full_output_golden() {
    assert_output_matches_full_golden("wrong_branch.json", "wrong_branch_expected.json");
}

#[test]
fn dirty_peer_surface_overlap_requires_rerun() {
    let receipt = receipt_json("dirty_surface_overlap.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("dirty-surface-overlap")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(
        row["evidence"]["dirty_overlaps"][0]["owner"].as_str(),
        Some("CoralGorge")
    );
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
}

#[test]
fn dirty_surface_overlap_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "dirty_surface_overlap.json",
        "dirty_surface_overlap_expected.json",
    );
}

#[test]
fn dirty_rename_target_overlap_requires_rerun() {
    let receipt = receipt_json("dirty_rename_target.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("dirty-surface-overlap")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(
        row["evidence"]["dirty_overlaps"][0]["path"].as_str(),
        Some("tests/fixtures/proof_artifact_freshness_receipt/renamed_target.json")
    );
    assert_eq!(
        row["evidence"]["dirty_overlaps"][0]["owner"].as_str(),
        Some("CoralGorge")
    );
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
}

#[test]
fn dirty_rename_target_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "dirty_rename_target.json",
        "dirty_rename_target_expected.json",
    );
}

#[test]
fn directory_touched_surface_overlap_requires_rerun_for_dirty_child() {
    let receipt = receipt_json("directory_surface_overlap.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("dirty-surface-overlap")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(row["touched_files"][0].as_str(), Some("tests/proof_status"));
    assert_eq!(
        row["evidence"]["dirty_overlaps"][0]["path"].as_str(),
        Some("tests/proof_status/snapshot.json")
    );
    assert_eq!(
        row["evidence"]["dirty_overlaps"][0]["owner"].as_str(),
        Some("CoralGorge")
    );
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
}

#[test]
fn directory_surface_overlap_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "directory_surface_overlap.json",
        "directory_surface_overlap_expected.json",
    );
}

#[test]
fn missing_git_sha_is_unverifiable() {
    let receipt = receipt_json("missing_head.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unverifiable-head"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-unverifiable"));
    assert_eq!(receipt["summary"]["unverifiable"].as_u64(), Some(1));
}

#[test]
fn missing_head_matches_full_output_golden() {
    assert_output_matches_full_golden("missing_head.json", "missing_head_expected.json");
}

#[test]
fn missing_touched_files_is_unverifiable_surface() {
    let receipt = receipt_json("missing_touched_files.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unverifiable-surface"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-unverifiable"));
}

#[test]
fn missing_touched_files_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "missing_touched_files.json",
        "missing_touched_files_expected.json",
    );
}

#[test]
fn missing_command_is_unverifiable() {
    let receipt = receipt_json("missing_command.json");
    let row = first_row(&receipt);

    assert_eq!(row["status"].as_str(), Some("pass"));
    assert_eq!(row["classification"].as_str(), Some("unverifiable-command"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-unverifiable"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    assert_eq!(
        row["reason"].as_str(),
        Some("artifact does not declare a reproducible proof command")
    );
    assert_eq!(receipt["summary"]["unverifiable"].as_u64(), Some(1));
}

#[test]
fn failed_status_requires_rerun_even_at_current_head() {
    let receipt = receipt_json("failed_status.json");
    let rows = receipt["rows"].as_array().expect("rows must be array");

    assert_eq!(rows.len(), 3);
    for (row, status) in rows
        .iter()
        .zip(["failed", "non-zero-exit", "exit-code-101"])
    {
        assert_eq!(row["status"].as_str(), Some(status));
        assert_eq!(
            row["classification"].as_str(),
            Some("failed-proof-artifact")
        );
        assert_eq!(row["decision"].as_str(), Some("rerun-required"));
        assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
        assert_eq!(
            row["reason"].as_str(),
            Some("artifact status reports a failed proof")
        );
        assert_eq!(
            row["remediation"]["operator_note"].as_str(),
            Some("Do not cite a proof artifact whose own status is failed.")
        );
    }
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(3));
}

#[test]
fn proof_reuse_classifier_accepts_exact_fail_closed_cache_hit() {
    let receipt = receipt_json("reuse_classifier_exact_hit.json");
    let reuse = receipt
        .get("proof_reuse")
        .expect("reuse classifier output must be present");
    assert_eq!(
        reuse["schema_version"].as_str(),
        Some("proof-reuse-classifier-v1")
    );
    assert_eq!(
        reuse["request"]["request_id"].as_str(),
        Some("proof-reuse-exact-hit")
    );
    assert_eq!(reuse["summary"]["total"].as_u64(), Some(1));
    assert_eq!(reuse["summary"]["reusable"].as_u64(), Some(1));
    assert_eq!(reuse["summary"]["refused"].as_u64(), Some(0));
    assert_eq!(
        reuse["safety"]["cache_hit_is_never_fresh_rch_pass"].as_bool(),
        Some(true)
    );

    let row = reuse["rows"].as_array().expect("reuse rows")[0].clone();
    assert_eq!(row["decision"].as_str(), Some("reusable"));
    assert_eq!(row["safe_to_reuse"].as_bool(), Some(true));
    assert_eq!(row["cache_hit_is_fresh_rch_pass"].as_bool(), Some(false));
    assert_eq!(
        row["candidate_id"].as_str(),
        Some("artifacts/proof/reusable-proof-lane-manifest.json")
    );
    assert_eq!(
        row["evidence"]["request_command_fingerprint"].as_str(),
        Some("sha256:proof-lane-manifest-command")
    );
    assert_eq!(
        row["evidence"]["candidate_command_fingerprint"].as_str(),
        Some("sha256:proof-lane-manifest-command")
    );
    assert_eq!(
        row["evidence"]["rch_remote_route_segments"][0].as_str(),
        Some("[RCH] remote rch-worker-reuse-01 (11.0s)")
    );
    assert_eq!(
        row["remediation"]["operator_note"].as_str(),
        Some("Candidate may be cited only as an approved cache hit for the requested scope.")
    );
}

#[test]
fn proof_reuse_classifier_reports_specific_miss_and_refusal_reasons() {
    let receipt = receipt_json("reuse_classifier_refusals.json");
    let reuse = receipt
        .get("proof_reuse")
        .expect("reuse classifier output must be present");
    assert_eq!(reuse["summary"]["total"].as_u64(), Some(12));
    assert_eq!(reuse["summary"]["reusable"].as_u64(), Some(0));
    assert_eq!(reuse["summary"]["miss"].as_u64(), Some(1));
    assert_eq!(reuse["summary"]["refused"].as_u64(), Some(11));

    let rows = reuse["rows"].as_array().expect("reuse rows");
    let by_candidate = |candidate: &str| -> &Value {
        rows.iter()
            .find(|row| row["candidate_id"].as_str() == Some(candidate))
            .unwrap_or_else(|| panic!("missing candidate {candidate}"))
    };
    for (candidate, decision, reason) in [
        (
            "artifacts/proof/local-fallback.json",
            "refused",
            "local-fallback-marker",
        ),
        (
            "artifacts/proof/failed-status.json",
            "refused",
            "failed-proof-status",
        ),
        ("artifacts/proof/stale-head.json", "refused", "stale-head"),
        (
            "artifacts/proof/dirty-overlap.json",
            "refused",
            "dirty-frontier-overlap",
        ),
        (
            "artifacts/proof/command-mismatch.json",
            "refused",
            "command-mismatch",
        ),
        (
            "artifacts/proof/source-mismatch.json",
            "refused",
            "source-hash-mismatch",
        ),
        (
            "artifacts/proof/toolchain-mismatch.json",
            "refused",
            "toolchain-mismatch",
        ),
        (
            "artifacts/proof/broad-claim.json",
            "refused",
            "broad-claim-unsupported",
        ),
        (
            "artifacts/proof/missing-allowed-claims.json",
            "refused",
            "unknown-cache-policy",
        ),
        (
            "artifacts/proof/non-rch-command.json",
            "refused",
            "missing-command-fingerprint",
        ),
        (
            "artifacts/proof/explicit-local-fallback-marker.json",
            "refused",
            "local-fallback-marker",
        ),
        (
            "artifacts/proof/lane-mismatch.json",
            "miss",
            "lane-mismatch",
        ),
    ] {
        let row = by_candidate(candidate);
        assert_eq!(
            row["decision"].as_str(),
            Some(decision),
            "{candidate} decision drifted"
        );
        assert_eq!(row["safe_to_reuse"].as_bool(), Some(false));
        let reasons = row["reason_codes"].as_array().expect("reason codes");
        assert!(
            reasons.iter().any(|item| item.as_str() == Some(reason)),
            "{candidate} missing reason {reason}: {reasons:?}"
        );
        assert_eq!(row["cache_hit_is_fresh_rch_pass"].as_bool(), Some(false));
    }

    assert_eq!(
        reuse["summary"]["by_reason_code"]["local-fallback-marker"].as_u64(),
        Some(2)
    );
    assert_eq!(
        reuse["summary"]["by_reason_code"]["lane-mismatch"].as_u64(),
        Some(1)
    );
    assert_eq!(
        reuse["summary"]["by_reason_code"]["missing-command-fingerprint"].as_u64(),
        Some(1)
    );
    assert_eq!(
        reuse["summary"]["by_reason_code"]["unknown-cache-policy"].as_u64(),
        Some(1)
    );
}

#[test]
fn proof_reuse_index_emits_normalized_entries_from_approved_fixture_root() {
    let output = run_reuse_index("json");
    assert!(
        output.status.success(),
        "proof reuse index failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let index: Value = serde_json::from_slice(&output.stdout).expect("proof reuse index JSON");

    assert_eq!(
        index["schema_version"].as_str(),
        Some("proof-reuse-index-v1")
    );
    assert_eq!(index["repo_path"].as_str(), Some("/repo"));
    assert_eq!(index["summary"]["candidate_count"].as_u64(), Some(6));
    assert_eq!(index["summary"]["safe_to_cite"].as_u64(), Some(2));
    assert_eq!(index["summary"]["freshness_refused"].as_u64(), Some(4));
    assert_eq!(
        index["summary"]["by_lane"]["proof-reuse-cache-contract"].as_u64(),
        Some(5)
    );
    assert_eq!(
        index["safety"]["raw_proof_logs_embedded"].as_bool(),
        Some(false)
    );
    assert_eq!(
        index["safety"]["tracker_mutation_allowed"].as_bool(),
        Some(false)
    );

    let entries = index["entries"].as_array().expect("index entries");
    assert_eq!(entries.len(), 6);
    let reusable = entries
        .iter()
        .find(|entry| entry["proof_id"].as_str() == Some("proof:reuse-index-reusable"))
        .expect("reusable proof entry");
    assert_eq!(
        reusable["manifest_lane_id"].as_str(),
        Some("proof-reuse-cache-contract")
    );
    assert_eq!(
        reusable["command_fingerprint"].as_str(),
        Some("sha256:proof-reuse-cache-command")
    );
    assert_eq!(
        reusable["source_fingerprint"].as_str(),
        Some("sha256:source-index-current")
    );
    assert_eq!(
        reusable["toolchain_fingerprint"].as_str(),
        Some("sha256:toolchain-index-current")
    );
    assert_eq!(
        reusable["env_fingerprint"].as_str(),
        Some("sha256:env-index-current")
    );
    assert_eq!(
        reusable["citeable_claims"][0].as_str(),
        Some("proof-reuse-cache-schema")
    );
    assert_eq!(
        reusable["refusal_metadata"]["safe_to_cite"].as_bool(),
        Some(true)
    );

    let local_fallback = entries
        .iter()
        .find(|entry| entry["proof_id"].as_str() == Some("proof:reuse-index-local-fallback"))
        .expect("local fallback proof entry");
    assert_eq!(
        local_fallback["refusal_metadata"]["freshness_refusal_reason_code"].as_str(),
        Some("local-fallback-marker")
    );
    assert_eq!(
        local_fallback["refusal_metadata"]["local_fallback_marker_count"].as_u64(),
        Some(2)
    );
}

#[test]
fn proof_reuse_query_selects_only_classifier_approved_candidate() {
    let query = reuse_query_json();
    assert_eq!(
        query["schema_version"].as_str(),
        Some("proof-reuse-query-result-v1")
    );
    assert_eq!(query["summary"]["candidate_count"].as_u64(), Some(6));
    assert_eq!(query["summary"]["accepted_count"].as_u64(), Some(1));
    assert_eq!(query["summary"]["refused_count"].as_u64(), Some(4));
    assert_eq!(query["summary"]["miss_count"].as_u64(), Some(1));
    assert_eq!(query["summary"]["candidate_pruned_count"].as_u64(), Some(5));
    assert_eq!(query["summary"]["row_limit"].as_u64(), Some(100));
    assert_eq!(query["summary"]["rows_emitted_count"].as_u64(), Some(6));
    assert_eq!(query["summary"]["rows_omitted_count"].as_u64(), Some(0));
    assert_eq!(query["summary"]["rows_omission_reason"].as_str(), Some(""));
    assert_eq!(
        query["summary"]["chosen_proof_id"].as_str(),
        Some("proof:reuse-index-reusable")
    );
    assert_eq!(
        query["safety"]["cache_hit_is_never_fresh_rch_pass"].as_bool(),
        Some(true)
    );
    assert_eq!(
        query["safety"]["query_never_overrides_classifier"].as_bool(),
        Some(true)
    );

    let best = &query["best_candidate"];
    assert_eq!(best["decision"].as_str(), Some("reusable"));
    assert_eq!(best["classifier_decision"].as_str(), Some("reusable"));
    assert_eq!(best["safe_to_reuse"].as_bool(), Some(true));
    assert_eq!(best["cache_hit_is_fresh_rch_pass"].as_bool(), Some(false));
    assert_eq!(
        best["proof_id"].as_str(),
        Some("proof:reuse-index-reusable")
    );

    let rows = query["rows"].as_array().expect("query rows");
    assert_eq!(rows.len(), 6);
    assert!(rows.iter().all(|row| {
        row["decision"].as_str() != Some("reusable")
            || (row["classifier_decision"].as_str() == Some("reusable")
                && row["safe_to_reuse"].as_bool() == Some(true))
    }));

    let reason_counts = &query["summary"]["by_reason_code"];
    for reason in [
        "stale-head",
        "failed-proof-status",
        "local-fallback-marker",
        "dirty-frontier-overlap",
        "lane-mismatch",
    ] {
        assert_eq!(
            reason_counts[reason].as_u64(),
            Some(1),
            "missing reason count for {reason}"
        );
    }
    assert_eq!(query["logs"][0]["stage"].as_str(), Some("scan"));
    assert_eq!(query["logs"][1]["stage"].as_str(), Some("classify"));
    assert_eq!(query["logs"][1]["accepted_count"].as_u64(), Some(1));
    assert_eq!(query["logs"][1]["candidate_pruned_count"].as_u64(), Some(5));
    assert_eq!(
        query["logs"][1]["pruning_reason_counts"]["lane-mismatch"].as_u64(),
        Some(1)
    );
    assert_eq!(query["logs"][2]["stage"].as_str(), Some("project"));
    assert_eq!(query["logs"][2]["row_limit"].as_u64(), Some(100));
    assert_eq!(query["logs"][2]["rows_emitted_count"].as_u64(), Some(6));
    assert_eq!(query["logs"][2]["rows_omitted_count"].as_u64(), Some(0));
    assert_eq!(query["logs"][3]["stage"].as_str(), Some("choose"));
    assert_eq!(
        query["logs"][3]["chosen_proof_id"].as_str(),
        Some("proof:reuse-index-reusable")
    );
    assert!(
        query["logs"][3]["top_rerun_command"]
            .as_str()
            .expect("top rerun command")
            .starts_with("RCH_REQUIRE_REMOTE=1 rch exec --")
    );
}

fn proof_reuse_large_corpus_artifact(
    index: usize,
    manifest_lane_id: &str,
    source_fingerprint: &str,
    toolchain_fingerprint: &str,
    local_fallback: bool,
) -> Value {
    let mut artifact = json!({
        "proof_id": format!("proof:large-corpus-{index:05}"),
        "artifact_path": format!("artifacts/proof/large-corpus-{index:05}.json"),
        "git_sha": "3333333333333333333333333333333333333333",
        "git_branch": "main",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_large_corpus cargo test -p asupersync --test proof_artifact_freshness_receipt_contract proof_reuse_large_corpus",
        "command_fingerprint": "sha256:large-corpus-command",
        "manifest_lane_id": manifest_lane_id,
        "manifest_guarantee_ids": ["proof-reuse-large-corpus"],
        "allowed_cache_hit_claims": ["proof-reuse-large-corpus"],
        "source_fingerprint": source_fingerprint,
        "tree_fingerprint": "git-tree:large-corpus-current",
        "toolchain_fingerprint": toolchain_fingerprint,
        "env_fingerprint": "sha256:large-corpus-env",
        "feature_flags": ["test-internals"],
        "touched_files": [
            "scripts/proof_artifact_freshness_receipt.py",
            "tests/proof_artifact_freshness_receipt_contract.rs",
            "artifacts/proof_reuse_large_corpus_contract_v1.json"
        ],
        "status": "pass",
        "generated_at": format!("2026-05-08T05:{:02}:00Z", index % 60),
        "stdout": "[RCH] remote rch-worker-large-corpus (1.0s)"
    });
    if local_fallback {
        artifact["local_fallback_markers"] = json!(["falling back to local execution"]);
    }
    artifact
}

fn write_large_corpus_fixture(contract: &Value) -> (PathBuf, PathBuf, PathBuf) {
    let corpus = &contract["synthetic_corpus"];
    let candidate_count =
        usize::try_from(corpus["candidate_count"].as_u64().expect("candidate_count"))
            .expect("candidate_count fits usize");
    let accepted_count =
        usize::try_from(corpus["accepted_count"].as_u64().expect("accepted_count"))
            .expect("accepted_count fits usize");
    let source_mismatch_count = usize::try_from(
        corpus["source_mismatch_count"]
            .as_u64()
            .expect("source_mismatch_count"),
    )
    .expect("source_mismatch_count fits usize");
    let toolchain_mismatch_count = usize::try_from(
        corpus["toolchain_mismatch_count"]
            .as_u64()
            .expect("toolchain_mismatch_count"),
    )
    .expect("toolchain_mismatch_count fits usize");
    let local_fallback_count = usize::try_from(
        corpus["local_fallback_count"]
            .as_u64()
            .expect("local_fallback_count"),
    )
    .expect("local_fallback_count fits usize");

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let temp_repo = std::env::temp_dir().join(format!(
        "asupersync-proof-reuse-large-corpus-{}-{nonce}",
        std::process::id()
    ));
    let reuse_root = temp_repo
        .join(FIXTURE_ROOT)
        .join("large_reuse_index_receipts");
    fs::create_dir_all(&reuse_root).expect("create large-corpus approved root");

    let mut artifacts = Vec::with_capacity(candidate_count);
    for index in 0..candidate_count {
        let source_mismatch_end = accepted_count + source_mismatch_count;
        let toolchain_mismatch_end = source_mismatch_end + toolchain_mismatch_count;
        let local_fallback_end = toolchain_mismatch_end + local_fallback_count;
        let (manifest_lane_id, source_fingerprint, toolchain_fingerprint, local_fallback) =
            if index < accepted_count {
                (
                    "proof-reuse-large-corpus",
                    "sha256:large-corpus-source",
                    "sha256:large-corpus-toolchain",
                    false,
                )
            } else if index < source_mismatch_end {
                (
                    "proof-reuse-large-corpus",
                    "sha256:large-corpus-source-mismatch",
                    "sha256:large-corpus-toolchain",
                    false,
                )
            } else if index < toolchain_mismatch_end {
                (
                    "proof-reuse-large-corpus",
                    "sha256:large-corpus-source",
                    "sha256:large-corpus-toolchain-mismatch",
                    false,
                )
            } else if index < local_fallback_end {
                (
                    "proof-reuse-large-corpus",
                    "sha256:large-corpus-source",
                    "sha256:large-corpus-toolchain",
                    true,
                )
            } else {
                (
                    "proof-reuse-unrelated-lane",
                    "sha256:large-corpus-source",
                    "sha256:large-corpus-toolchain",
                    false,
                )
            };
        artifacts.push(proof_reuse_large_corpus_artifact(
            index,
            manifest_lane_id,
            source_fingerprint,
            toolchain_fingerprint,
            local_fallback,
        ));
    }

    let corpus_path = reuse_root.join("corpus.json");
    let corpus_json = json!({
        "repo": {
            "head_sha": "3333333333333333333333333333333333333333",
            "branch": "main"
        },
        "artifacts": artifacts
    });
    let corpus_file = fs::File::create(&corpus_path).expect("create large-corpus JSON");
    serde_json::to_writer(corpus_file, &corpus_json).expect("write large-corpus JSON");

    let request_path = temp_repo
        .join(FIXTURE_ROOT)
        .join("large_reuse_request.json");
    let request_json = json!({
        "request_id": "proof-reuse-large-corpus-query",
        "manifest_lane_id": "proof-reuse-large-corpus",
        "claim_scope": "proof-reuse-large-corpus",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_large_corpus cargo test -p asupersync --test proof_artifact_freshness_receipt_contract proof_reuse_large_corpus",
        "command_fingerprint": "sha256:large-corpus-command",
        "source_fingerprint": "sha256:large-corpus-source",
        "tree_fingerprint": "git-tree:large-corpus-current",
        "toolchain_fingerprint": "sha256:large-corpus-toolchain",
        "env_fingerprint": "sha256:large-corpus-env",
        "feature_flags": ["test-internals"],
        "touched_files": [
            "scripts/proof_artifact_freshness_receipt.py",
            "tests/proof_artifact_freshness_receipt_contract.rs",
            "artifacts/proof_reuse_large_corpus_contract_v1.json"
        ],
        "dirty_frontier_status": "clean"
    });
    let request_file = fs::File::create(&request_path).expect("create large-corpus request JSON");
    serde_json::to_writer(request_file, &request_json).expect("write large-corpus request JSON");

    (temp_repo, reuse_root, request_path)
}

#[test]
fn proof_reuse_large_corpus_query_is_bounded_and_logged() {
    let contract = large_corpus_contract_json();
    let (temp_repo, reuse_root, request_path) = write_large_corpus_fixture(&contract);
    let row_limit = contract["query"]["row_limit"]
        .as_u64()
        .expect("row_limit")
        .to_string();

    let started_at = Instant::now();
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-path")
        .arg(&temp_repo)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--reuse-index-root")
        .arg(&reuse_root)
        .arg("--request")
        .arg(&request_path)
        .arg("--max-query-rows")
        .arg(&row_limit)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run large-corpus proof reuse query");
    let elapsed = started_at.elapsed();

    assert!(
        output.status.success(),
        "large-corpus proof reuse query failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let query: Value =
        serde_json::from_slice(&output.stdout).expect("large-corpus query output JSON");
    let summary = &query["summary"];
    eprintln!(
        "[proof-reuse-large-corpus] corpus_size={} indexed_receipt_count={} \
         candidate_pruned_count={} accepted_count={} refused_count={} miss_count={} \
         rows_emitted_count={} rows_omitted_count={} chosen_proof_id={} elapsed_ms={}",
        contract["synthetic_corpus"]["candidate_count"],
        query["index_summary"]["candidate_count"],
        summary["candidate_pruned_count"],
        summary["accepted_count"],
        summary["refused_count"],
        summary["miss_count"],
        summary["rows_emitted_count"],
        summary["rows_omitted_count"],
        summary["chosen_proof_id"],
        elapsed.as_millis()
    );
    eprintln!(
        "[proof-reuse-large-corpus] pruning_reason_counts={}",
        summary["by_reason_code"]
    );

    assert_eq!(
        query["index_summary"]["candidate_count"].as_u64(),
        contract["synthetic_corpus"]["candidate_count"].as_u64()
    );
    assert_eq!(
        summary["candidate_count"].as_u64(),
        contract["synthetic_corpus"]["candidate_count"].as_u64()
    );
    assert_eq!(
        summary["accepted_count"].as_u64(),
        contract["synthetic_corpus"]["accepted_count"].as_u64()
    );
    assert_eq!(
        summary["refused_count"].as_u64(),
        contract["synthetic_corpus"]["refused_count"].as_u64()
    );
    assert_eq!(
        summary["miss_count"].as_u64(),
        contract["synthetic_corpus"]["miss_count"].as_u64()
    );
    assert_eq!(
        summary["candidate_pruned_count"].as_u64(),
        contract["query"]["expected_candidate_pruned_count"].as_u64()
    );
    assert_eq!(
        summary["rows_emitted_count"].as_u64(),
        contract["query"]["expected_rows_emitted_count"].as_u64()
    );
    assert_eq!(
        summary["rows_omitted_count"].as_u64(),
        contract["query"]["expected_rows_omitted_count"].as_u64()
    );
    assert_eq!(
        summary["chosen_proof_id"].as_str(),
        contract["query"]["chosen_proof_id"].as_str()
    );
    assert_eq!(
        summary["by_reason_code"]["source-hash-mismatch"].as_u64(),
        contract["synthetic_corpus"]["source_mismatch_count"].as_u64()
    );
    assert_eq!(
        summary["by_reason_code"]["toolchain-mismatch"].as_u64(),
        contract["synthetic_corpus"]["toolchain_mismatch_count"].as_u64()
    );
    assert_eq!(
        summary["by_reason_code"]["local-fallback-marker"].as_u64(),
        contract["synthetic_corpus"]["local_fallback_count"].as_u64()
    );
    assert_eq!(
        summary["by_reason_code"]["lane-mismatch"].as_u64(),
        contract["synthetic_corpus"]["lane_mismatch_count"].as_u64()
    );
    assert_eq!(query["logs"][2]["stage"].as_str(), Some("project"));
    assert_eq!(
        query["logs"][2]["rows_omission_reason"].as_str(),
        Some("bounded-query-output")
    );
    assert_eq!(
        query["safety"]["raw_proof_logs_embedded"].as_bool(),
        Some(false)
    );
    assert_eq!(
        query["summary"]["elapsed_time"]["measured"].as_bool(),
        Some(false)
    );

    let rows = query["rows"].as_array().expect("large-corpus rows array");
    assert_eq!(
        u64::try_from(rows.len()).expect("row count fits u64"),
        contract["query"]["row_limit"].as_u64().expect("row_limit")
    );
    assert!(
        rows.iter().all(|row| row.get("proof_text").is_none()
            && row.get("stdout").is_none()
            && row.get("stderr").is_none()),
        "large-corpus query rows must not embed raw proof logs"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("rch-worker-large-corpus"),
        "large-corpus query output must not dump raw RCH route log text"
    );
    assert!(
        elapsed.as_millis()
            <= u128::from(
                contract["resource_envelope"]["max_query_elapsed_ms"]
                    .as_u64()
                    .expect("max_query_elapsed_ms")
            ),
        "large-corpus proof reuse query exceeded coarse elapsed-time envelope: {:?}",
        elapsed
    );
}

#[test]
fn proof_reuse_query_json_matches_full_output_golden() {
    let output = run_reuse_query("json");
    assert!(
        output.status.success(),
        "proof reuse query failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("query stdout is utf-8");
    let actual_json: Value = serde_json::from_str(&actual).expect("query output JSON");
    let expected = fixture_text("reuse_index_query_expected.json");
    let expected_json: Value = serde_json::from_str(&expected).expect("expected query JSON");

    assert_eq!(actual_json, expected_json, "proof reuse query JSON drifted");
    assert_eq!(actual, expected, "proof reuse query text drifted");
}

#[test]
fn proof_reuse_query_markdown_matches_summary_golden() {
    let output = run_reuse_query("markdown");
    assert!(
        output.status.success(),
        "proof reuse query markdown failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("markdown stdout is utf-8");
    let expected = fixture_text("reuse_index_query_expected.md");
    assert_eq!(actual, expected, "proof reuse query markdown drifted");
}

#[test]
fn proof_reuse_index_rejects_unapproved_roots() {
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-path")
        .arg("/repo")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--reuse-index-root")
        .arg("/tmp")
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run proof reuse index with unapproved root");
    assert!(!output.status.success(), "unapproved root should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("proof reuse index root must be inside repo")
            || stderr.contains("is not approved"),
        "unexpected stderr for unapproved root: {stderr}"
    );
}

#[test]
fn agent_mail_summary_covers_mixed_closeout_rows() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("proof_artifact_freshness_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

head = "2222222222222222222222222222222222222222"
artifacts = [
    {
        "artifact_path": "artifacts/proof/current.json",
        "git_sha": head,
        "git_branch": "main",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_current cargo test -p asupersync --lib current",
        "stdout": "[RCH] remote rch-worker-current (1.0s)",
        "touched_files": ["src/current.rs"],
        "status": "pass",
        "generated_at": "2026-05-08T05:15:00Z",
    },
    {
        "artifact_path": "artifacts/proof/dirty.json",
        "git_sha": head,
        "git_branch": "main",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_dirty cargo test -p asupersync --lib dirty",
        "stdout": "[RCH] remote rch-worker-dirty (1.0s)",
        "touched_files": ["src/dirty.rs"],
        "status": "pass",
        "generated_at": "2026-05-08T05:16:00Z",
    },
    {
        "artifact_path": "artifacts/proof/stale.json",
        "git_sha": head,
        "git_branch": "feature/proof",
        "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_stale cargo test -p asupersync --lib stale",
        "stdout": "[RCH] remote rch-worker-stale (1.0s)",
        "touched_files": ["src/stale.rs"],
        "status": "pass",
        "generated_at": "2026-05-08T05:17:00Z",
    },
]
dirty = [{"status": " M", "path": "src/dirty.rs", "classification": "peer-owned", "owner": "TopazGoose"}]
rows = [
    module.classify_artifact(module.normalize_artifact(artifact), head, "main", dirty)
    for artifact in artifacts
]
summary = module.summarize(rows)
print(json.dumps({
    "summary": summary,
    "agent_mail_summary": module.agent_mail_summary(rows, summary),
    "collapsed_scalar": module.summary_scalar("line one\nline two"),
}, sort_keys=True))
"#;
    let mut child = Command::new("python3")
        .arg("-")
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proof-artifact agent mail summary smoke");
    child
        .stdin
        .as_mut()
        .expect("summary smoke stdin")
        .write_all(script.as_bytes())
        .expect("write summary smoke script");
    let output = child
        .wait_with_output()
        .expect("run proof-artifact agent mail summary smoke");
    assert!(
        output.status.success(),
        "agent mail summary smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("summary smoke JSON");
    assert_eq!(parsed["summary"]["total"].as_u64(), Some(3));
    assert_eq!(parsed["summary"]["safe_to_cite"].as_u64(), Some(1));
    assert_eq!(parsed["summary"]["rerun_required"].as_u64(), Some(1));
    assert_eq!(parsed["summary"]["suppressed"].as_u64(), Some(1));
    assert_eq!(
        parsed["collapsed_scalar"].as_str(),
        Some("line one line two")
    );

    let summary = parsed["agent_mail_summary"]
        .as_str()
        .expect("agent mail summary string");
    for expected in [
        "Proof receipt closeout summary: 3 total; 1 citeable; 1 rerun-required; 1 suppressed.",
        "artifacts/proof/current.json | classification=current-clean | decision=cite-as-current | safe_to_cite=true",
        "artifacts/proof/dirty.json | classification=dirty-surface-overlap | decision=rerun-required | safe_to_cite=false",
        "artifacts/proof/stale.json | classification=wrong-branch | decision=suppress-as-stale | safe_to_cite=false",
        "command: RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_dirty cargo test -p asupersync --lib dirty",
        "top_remediation: Do not cite stale green output across dirty shared-main work.",
        "top_remediation: Suppress this artifact as stale before reporting a green lane.",
    ] {
        assert!(
            summary.contains(expected),
            "agent mail summary missing {expected:?}: {summary}"
        );
    }
}

#[test]
fn receipt_safety_contract_declares_read_only_behavior() {
    let receipt = receipt_json("current_clean.json");

    assert_eq!(receipt["safety"]["non_mutating"].as_bool(), Some(true));
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
        receipt["safety"]["destructive_commands_executed"].as_bool(),
        Some(false)
    );
}

#[test]
fn receipt_has_required_top_level_shape() {
    let receipt = receipt_json("dirty_surface_overlap.json");
    for field in [
        "schema_version",
        "generated_at",
        "current_date",
        "agent",
        "agent_mail_summary",
        "repo_path",
        "current_head_sha",
        "current_branch",
        "rows",
        "summary",
        "safety",
    ] {
        assert!(receipt.get(field).is_some(), "receipt missing {field}");
    }
}
