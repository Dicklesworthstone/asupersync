use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SCRIPT_PATH: &str = "scripts/atp_perf/workflow_acceptance_smoke.py";
const CONTRACT_VERSION: &str = "atp-n9-workflow-acceptance-v1";
const REPORT_SCHEMA_VERSION: &str = "atp-n9-workflow-report-v1";
const EVENT_SCHEMA_VERSION: &str = "atp-n9-workflow-event-v1";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn read_script() -> String {
    std::fs::read_to_string(repo_path(SCRIPT_PATH)).expect("ATP-N9 runner script must exist")
}

fn run_contract_smoke() -> Value {
    let output_root = repo_path("target/atp_perf_acceptance_contract");
    let output = Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .args([
            "--contract-only",
            "--run-id",
            "atp-n9-contract",
            "--output-root",
            output_root
                .to_str()
                .expect("output root path must be valid UTF-8"),
        ])
        .current_dir(repo_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ATP-N9 workflow acceptance smoke contract");

    if !output.status.success() {
        panic!(
            "ATP-N9 runner failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).expect("runner stdout must be JSON")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| item.as_str().expect("entry must be string").to_string())
        .collect()
}

fn artifact_path(report: &Value, key: &str) -> PathBuf {
    let raw = report["artifacts"][key]
        .as_str()
        .unwrap_or_else(|| panic!("artifact path {key} must be string"));
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_path(raw)
    }
}

#[test]
fn runner_declares_fast_regression_and_manual_modes() {
    let script = read_script();
    for required in [
        "--list",
        "--mode",
        "--workflow",
        "--output-root",
        "--run-id",
        "--contract-only",
        "--require-external-tools",
        "smoke",
        "regression",
        "manual",
    ] {
        assert!(script.contains(required), "runner must declare {required}");
    }
}

#[test]
fn workflow_catalog_covers_real_user_acceptance_surfaces() {
    let report = run_contract_smoke();
    assert_eq!(report["contract_version"].as_str(), Some(CONTRACT_VERSION));
    assert_eq!(
        report["schema_version"].as_str(),
        Some(REPORT_SCHEMA_VERSION)
    );
    assert_eq!(report["bead_id"].as_str(), Some("asupersync-m7hmrq"));

    let workflow_classes = array(&report, "workflow_catalog")
        .iter()
        .map(|workflow| {
            workflow["workflow_class"]
                .as_str()
                .expect("workflow_class must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_class in [
        "huge_file",
        "many_small_files",
        "sync_tree_small_edits",
        "sparse_image",
        "model_bundle",
        "dataset",
        "relay_only",
        "mailbox",
        "first_pairing",
        "interrupted_resume",
        "cache_swarm",
    ] {
        assert!(
            workflow_classes.contains(required_class),
            "workflow catalog must cover {required_class}"
        );
    }

    let selected = string_set(&report, "selected_workflow_ids");
    for required_smoke in [
        "one_huge_file",
        "relay_only_transfer",
        "mailbox_transfer",
        "first_pairing_transfer",
        "interrupted_resume_transfer",
        "cache_swarm_get",
    ] {
        assert!(
            selected.contains(required_smoke),
            "smoke mode must include {required_smoke}"
        );
    }
}

#[test]
fn metric_budgets_and_bottleneck_classes_are_stable() {
    let report = run_contract_smoke();
    let metrics = array(&report, "metric_budgets")
        .iter()
        .map(|metric| {
            metric["metric"]
                .as_str()
                .expect("metric name must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_metric in [
        "time_to_first_verified_file_ms",
        "time_to_usable_prefix_ms",
        "whole_object_commit_ms",
        "resume_after_interruption_ms",
        "bytes_wasted",
        "cpu_ms_per_gib",
        "memory_peak_bytes",
        "operator_action_count",
        "failure_explanation_clarity_score",
    ] {
        assert!(
            metrics.contains(required_metric),
            "metric budget must include {required_metric}"
        );
    }

    let classes = string_set(&report, "failure_bottleneck_classes");
    for required_class in [
        "path",
        "disk",
        "cpu",
        "repair",
        "relay",
        "permission",
        "protocol",
        "user_policy",
    ] {
        assert!(
            classes.contains(required_class),
            "failure bottleneck catalog must include {required_class}"
        );
    }
}

#[test]
fn emitted_artifacts_have_required_schema_and_replay_fields() {
    let report = run_contract_smoke();
    assert_eq!(report["status"].as_str(), Some("pass"));

    for key in [
        "summary",
        "run_report",
        "structured_events",
        "fixture_manifest",
        "replay_pointer",
    ] {
        let path = artifact_path(&report, key);
        assert!(path.exists(), "artifact {key} must exist at {path:?}");
    }

    let summary = std::fs::read_to_string(artifact_path(&report, "summary"))
        .expect("summary artifact must be readable");
    assert!(
        summary.lines().count() <= 12,
        "human summary must stay concise"
    );
    assert!(summary.contains("ATP-N9 workflow acceptance summary"));

    let events_raw = std::fs::read_to_string(artifact_path(&report, "structured_events"))
        .expect("events artifact must be readable");
    let events = events_raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event line must be JSON"))
        .collect::<Vec<_>>();
    assert!(!events.is_empty(), "runner must emit at least one event");

    for event in events {
        assert_eq!(event["schema_version"].as_str(), Some(EVENT_SCHEMA_VERSION));
        for required in [
            "command_line",
            "profile",
            "transfer_id",
            "path_summary",
            "manifest_root",
            "proof_root",
            "metrics",
            "thresholds",
            "regression_thresholds",
            "bottleneck_classification",
            "failure_explanation",
            "replay_pointer",
        ] {
            assert!(
                !event[required].is_null(),
                "{} must include required event field {required}",
                event["workflow_id"].as_str().unwrap_or("<unknown>")
            );
        }
        assert!(
            event["replay_pointer"]["command"]
                .as_str()
                .expect("replay command must be string")
                .contains(SCRIPT_PATH),
            "replay pointer must name the ATP-N9 runner"
        );
        assert!(
            event["path_summary"]["path_modes"]
                .as_array()
                .expect("path_modes must be array")
                .iter()
                .all(Value::is_string),
            "path summary must expose path mode strings"
        );
    }
}
