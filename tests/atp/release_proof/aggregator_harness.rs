use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRIPT_PATH: &str = "scripts/atp_release_proof/enumerator.py";
const GENERATED_AT: &str = "2026-05-24T22:20:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_fixture_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "asupersync_atp_release_proof_{name}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&root).expect("create release proof fixture root");
    root
}

fn write_json(path: &Path, value: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create JSON parent");
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize JSON"),
    )
    .expect("write JSON fixture");
}

fn write_text(path: &Path, value: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create text parent");
    }
    fs::write(path, value).expect("write text fixture");
}

fn dashboard_contract(required_artifact: &str) -> Value {
    json!({
        "contract_version": "atp-completion-dashboard-contract-v1",
        "schema_version": "atp-completion-dashboard-v1",
        "required_release_gates": [
            {
                "gate_id": "ATP-NR1",
                "bead_id": "asupersync-vk4kcf.2",
                "title": "No-mock/no-placeholder ATP production and test gate",
                "required_artifacts": [required_artifact],
                "proof_command": "python3 scripts/check_no_mock_policy.py --report-json target/atp-no-mock-policy/report.json"
            },
            {
                "gate_id": "ATP-NR13",
                "bead_id": "asupersync-vk4kcf.11",
                "title": "ATP release proof aggregator",
                "required_artifacts": [],
                "proof_command": "python3 scripts/atp_release_proof/enumerator.py --output json"
            }
        ]
    })
}

fn proof_lane_manifest() -> Value {
    json!({
        "contract_version": "proof-lane-manifest-v1",
        "lanes": [
            {
                "lane_id": "lib-tests",
                "command": "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lib_tests cargo test -p asupersync --lib",
                "guarantee_ids": ["lib-test-frontier"]
            }
        ]
    })
}

fn autotune_corpus(sample_count: u64) -> Value {
    json!({
        "schema_version": "atp-autotune-noisy-pressure-replay-corpus-v1",
        "update_command": "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p7 cargo test -p asupersync --test atp_autotune_replay_corpus -- --nocapture",
        "fixtures": [
            {
                "kind": "decision",
                "fixture_id": "clean_path_growth",
                "expected_receipt": {
                    "schema_version": "atp-autotune-decision-receipt-v1",
                    "trace_id": "trace-atp-clean-001",
                    "workload_id": "workload-clean-bulk",
                    "sample_count": sample_count,
                    "consumer_status": "pass",
                    "proof_pointer": {
                        "receipt_schema_version": "atp-autotune-decision-receipt-v1",
                        "trace_id": "trace-atp-clean-001",
                        "workload_id": "workload-clean-bulk",
                        "sample_count": sample_count
                    }
                }
            },
            {
                "kind": "decision",
                "fixture_id": "lossy_high_repair_roi",
                "expected_receipt": {
                    "schema_version": "atp-autotune-decision-receipt-v1",
                    "trace_id": "trace-atp-loss-001",
                    "workload_id": "workload-lossy",
                    "sample_count": 16,
                    "consumer_status": "degraded",
                    "proof_pointer": {
                        "receipt_schema_version": "atp-autotune-decision-receipt-v1",
                        "trace_id": "trace-atp-loss-001",
                        "workload_id": "workload-lossy",
                        "sample_count": 16
                    }
                }
            }
        ]
    })
}

fn write_common_inputs(
    root: &Path,
    required_artifact: &str,
    create_required_artifact: bool,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let dashboard = root.join("dashboard.json");
    let manifest = root.join("proof_lane_manifest.json");
    let corpus = root.join("corpus.json");
    let issues = root.join("issues.jsonl");
    write_json(&dashboard, &dashboard_contract(required_artifact));
    write_json(&manifest, &proof_lane_manifest());
    write_json(&corpus, &autotune_corpus(16));
    write_text(
        &issues,
        concat!(
            "{\"id\":\"asupersync-vk4kcf.2\",\"status\":\"closed\"}\n",
            "{\"id\":\"asupersync-vk4kcf.11\",\"status\":\"closed\"}\n",
        ),
    );

    write_text(
        &root.join("scripts/atp_release_proof/enumerator.py"),
        "enumerator fixture marker\n",
    );
    write_text(
        &root.join("tests/atp/release_proof/aggregator_harness.rs"),
        "aggregator harness fixture marker\n",
    );
    write_text(
        &root.join("src/atp/autotune.rs"),
        "atp-autotune-decision-receipt-v1\natp-autotune-application-receipt-v1\n",
    );
    write_text(
        &root.join("tests/atp/security/byzantine_e2e.rs"),
        "security fixture marker\n",
    );
    write_text(
        &root.join("scripts/atp_perf/workflow_acceptance_smoke.py"),
        "benchmark fixture marker\n",
    );
    if create_required_artifact {
        write_text(&root.join(required_artifact), "no mock report fixture\n");
    }

    (dashboard, manifest, corpus, issues)
}

fn run_aggregator(
    root: &Path,
    dashboard: &Path,
    manifest: &Path,
    corpus: &Path,
    issues: &Path,
    allow_red: bool,
) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-root")
        .arg(root)
        .arg("--dashboard-contract")
        .arg(dashboard)
        .arg("--proof-lane-manifest")
        .arg(manifest)
        .arg("--autotune-corpus")
        .arg(corpus)
        .arg("--issues")
        .arg(issues)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root());
    if allow_red {
        command.arg("--allow-red");
    }
    command.output().expect("run ATP release proof aggregator")
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
fn aggregator_enumerates_release_gates_and_autotune_receipts() {
    let root = unique_fixture_root("green");
    let (dashboard, manifest, corpus, issues) =
        write_common_inputs(&root, "artifacts/no_mock_policy_contract_v1.json", true);

    let output = run_aggregator(&root, &dashboard, &manifest, &corpus, &issues, false);
    assert!(
        output.status.success(),
        "aggregator should be green for complete fixture: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout(&output);

    assert_eq!(
        report["schema_version"].as_str(),
        Some("atp-release-proof-aggregator-v1")
    );
    assert_eq!(report["release_decision"]["ready"].as_bool(), Some(true));
    assert_eq!(report["summary"]["gate_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["receipt_input_count"].as_u64(), Some(4));
    assert!(
        report["summary"]["coverage_families"]
            .as_array()
            .expect("coverage families")
            .iter()
            .any(|family| family.as_str() == Some("benchmark"))
    );
    assert!(
        report["receipt_inputs"]
            .as_array()
            .expect("receipt inputs")
            .iter()
            .any(|row| row["source_bead"].as_str() == Some("asupersync-l9uzgt"))
    );
    assert!(
        report["receipt_inputs"]
            .as_array()
            .expect("receipt inputs")
            .iter()
            .any(|row| row["source_bead"].as_str() == Some("asupersync-nm2us1"))
    );
}

#[test]
fn fail_on_red_refuses_missing_gate_artifact() {
    let root = unique_fixture_root("missing_artifact");
    let (dashboard, manifest, corpus, issues) =
        write_common_inputs(&root, "artifacts/no_mock_policy_contract_v1.json", false);

    let output = run_aggregator(&root, &dashboard, &manifest, &corpus, &issues, false);
    assert!(
        !output.status.success(),
        "missing expected artifact must fail closed"
    );
    let report = parse_stdout(&output);
    assert_eq!(report["release_decision"]["ready"].as_bool(), Some(false));
    assert!(
        report["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .any(|issue| issue["kind"].as_str() == Some("missing_expected_artifact"))
    );
}

#[test]
fn allow_red_keeps_dashboard_machine_readable_for_blockers() {
    let root = unique_fixture_root("allow_red");
    let (dashboard, manifest, corpus, issues) =
        write_common_inputs(&root, "artifacts/no_mock_policy_contract_v1.json", false);

    let output = run_aggregator(&root, &dashboard, &manifest, &corpus, &issues, true);
    assert!(
        output.status.success(),
        "--allow-red should preserve JSON output for blocker dashboards"
    );
    let report = parse_stdout(&output);
    assert_eq!(report["release_decision"]["verdict"].as_str(), Some("red"));
    assert_eq!(
        report["summary"]["release_blocking_count"].as_u64(),
        Some(1)
    );
}
