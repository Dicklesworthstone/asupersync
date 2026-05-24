use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRIPT_PATH: &str = "scripts/atp_no_mock_gate/scan.py";
const GENERATED_AT: &str = "2026-05-24T22:30:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_fixture_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "asupersync_atp_no_mock_gate_{name}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&root).expect("create no-mock fixture root");
    root
}

fn write_text(path: &Path, value: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture parent");
    }
    fs::write(path, value).expect("write fixture");
}

fn write_json(path: &Path, value: &Value) {
    write_text(
        path,
        &serde_json::to_string_pretty(value).expect("serialize fixture JSON"),
    );
}

fn policy() -> Value {
    json!({
        "schema_version": "atp-no-mock-policy-v1",
        "scan": {
            "roots": ["src/atp", "tests/atp"],
            "terms": ["mock", "fake", "stub", "placeholder", "todo", "unimplemented"]
        },
        "default_owner": "atp-dml",
        "allowlist_entries": [
            {
                "id": "allowed-test-fixture",
                "pattern": "tests/atp/no_mock/**",
                "category": "scanner_fixture",
                "owner": "atp-dml",
                "reason": "The scanner harness embeds synthetic fake/mock strings.",
                "proof_lane": "atp_no_mock_gate",
                "expires_at_utc": "2026-07-01T00:00:00Z"
            }
        ]
    })
}

fn write_policy(root: &Path) -> PathBuf {
    let policy_path = root.join("policy.json");
    write_json(&policy_path, &policy());
    policy_path
}

fn run_gate(root: &Path, policy: &Path) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-root")
        .arg(root)
        .arg("--policy")
        .arg(policy)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run ATP no-mock gate")
}

fn parse_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "stdout must be JSON: {err}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn gate_allows_explicit_scanner_fixture() {
    let root = unique_fixture_root("allowed_fixture");
    let policy = write_policy(&root);
    write_text(
        &root.join("tests/atp/no_mock/fixture.rs"),
        "struct MockPeer; fn payload() -> &'static str { \"fake scanner fixture\" }\n",
    );

    let output = run_gate(&root, &policy);
    assert!(
        output.status.success(),
        "allowed fixture should pass: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout(&output);
    assert_eq!(report["summary"]["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["violation_hits"].as_u64(), Some(0));
    assert!(
        report["covered"]
            .as_array()
            .expect("covered rows")
            .iter()
            .any(|row| row["allowlist_id"].as_str() == Some("allowed-test-fixture"))
    );
}

#[test]
fn gate_rejects_unlisted_production_placeholder() {
    let root = unique_fixture_root("production_reject");
    let policy = write_policy(&root);
    write_text(
        &root.join("tests/atp/no_mock/fixture.rs"),
        "struct MockPeer; fn payload() -> &'static str { \"fake scanner fixture\" }\n",
    );
    write_text(
        &root.join("src/atp/transport.rs"),
        "pub fn transfer() { todo!(\"placeholder mock transport\"); }\n",
    );

    let output = run_gate(&root, &policy);
    assert!(
        !output.status.success(),
        "unlisted production placeholder must fail closed"
    );
    let report = parse_stdout(&output);
    assert_eq!(report["summary"]["status"].as_str(), Some("fail"));
    assert!(
        report["violations"]
            .as_array()
            .expect("violation rows")
            .iter()
            .any(|row| row["path"].as_str() == Some("src/atp/transport.rs"))
    );
}

#[test]
fn repository_policy_covers_current_atp_debt_without_hiding_new_hits() {
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run repository ATP no-mock gate");
    assert!(
        output.status.success(),
        "current ATP surface should be covered by scoped policy:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout(&output);
    assert_eq!(report["summary"]["status"].as_str(), Some("pass"));
    assert!(
        report["covered"]
            .as_array()
            .expect("covered rows")
            .iter()
            .any(|row| row["category"].as_str() == Some("known_production_debt")),
        "repository policy should keep known ATP debt visible"
    );
}
