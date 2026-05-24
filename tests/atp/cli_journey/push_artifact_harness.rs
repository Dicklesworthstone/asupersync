use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SCRIPT_PATH: &str = "scripts/atp_user_journey/push_artifact_cli_daemon.sh";
const REPORT_SCHEMA: &str = "asupersync.atp.user_journey.cli_daemon_report.v1";
const EVENT_SCHEMA: &str = "asupersync.atp.user_journey.cli_daemon_event.v1";
const SCENARIO_ID: &str = "cli_push_artifact_daemon_log";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn run_journey(run_id: &str) -> Value {
    let output_root = repo_path("target/atp_user_journey_cli_daemon_contract");
    let output = Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args([
            "--output-root",
            output_root.to_str().expect("UTF-8 output root"),
        ])
        .args(["--run-id", run_id])
        .current_dir(repo_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ATP user journey script");

    assert!(
        output.status.success(),
        "ATP user journey failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("runner stdout must be JSON")
}

fn artifact_path(report: &Value, key: &str) -> PathBuf {
    let raw = report["artifacts"][key]
        .as_str()
        .expect("artifact path must be a string");
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root().join(path)
    }
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    let raw = fs::read_to_string(path).expect("JSONL artifact must be readable");
    raw.lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event row must be JSON"))
        .collect()
}

fn event_types(events: &[Value]) -> BTreeSet<String> {
    events
        .iter()
        .map(|event| {
            event["event_type"]
                .as_str()
                .expect("event_type must be present")
                .to_string()
        })
        .collect()
}

#[test]
fn cli_push_artifact_journey_copies_and_verifies_payload() {
    let report = run_journey("nr10-cli-daemon-copy");
    assert_eq!(report["schema_version"].as_str(), Some(REPORT_SCHEMA));
    assert_eq!(report["event_schema_version"].as_str(), Some(EVENT_SCHEMA));
    assert_eq!(report["scenario_id"].as_str(), Some(SCENARIO_ID));
    assert_eq!(report["status"].as_str(), Some("success"));
    assert_eq!(report["real_io_required"].as_bool(), Some(true));
    assert_eq!(report["process_model"].as_str(), Some("local_child_daemon"));
    assert_eq!(
        report["transport"].as_str(),
        Some("filesystem_spool_atomic_publish")
    );

    let source_path = PathBuf::from(report["transfer"]["source_path"].as_str().unwrap());
    let destination_path = PathBuf::from(report["transfer"]["destination_path"].as_str().unwrap());
    assert!(source_path.exists(), "source payload must exist");
    assert!(destination_path.exists(), "destination payload must exist");
    assert_eq!(
        fs::read(&source_path).expect("source readable"),
        fs::read(&destination_path).expect("destination readable")
    );
    assert_eq!(
        report["transfer"]["source_sha256"],
        report["transfer"]["received_sha256"]
    );
    assert_eq!(
        report["transfer"]["verification"].as_str(),
        Some("byte_for_byte_cmp_and_sha256")
    );
    assert!(
        report["transfer"]["bytes_transferred"]
            .as_u64()
            .expect("bytes_transferred must be numeric")
            > 0
    );
}

#[test]
fn structured_logs_include_cli_daemon_and_replay_fields() {
    let report = run_journey("nr10-cli-daemon-logs");
    let events = read_jsonl(&artifact_path(&report, "events_path"));
    let daemon_events = read_jsonl(&artifact_path(&report, "daemon_log_path"));
    assert!(!events.is_empty(), "structured event log must not be empty");
    assert!(
        !daemon_events.is_empty(),
        "daemon structured log must not be empty"
    );

    for event in events.iter().chain(daemon_events.iter()) {
        assert_eq!(event["schema_version"].as_str(), Some(EVENT_SCHEMA));
        for required in [
            "bead_id",
            "run_id",
            "scenario_id",
            "command_line",
            "environment",
            "peer_ids",
            "transfer_id",
            "path_summary",
            "grant_decision",
            "capability_decision",
            "manifest_root",
            "proof_root",
            "journal_path",
            "replay_pointer",
        ] {
            assert!(
                !event[required].is_null(),
                "{} must include required field {required}",
                event["event_type"].as_str().unwrap_or("<unknown>")
            );
        }
        assert_eq!(event["scenario_id"].as_str(), Some(SCENARIO_ID));
        assert!(
            event["command_line"]
                .as_str()
                .expect("command line must be a string")
                .contains("asupersync atp send")
        );
    }

    let daemon_types = event_types(&daemon_events);
    for required in [
        "daemon_started",
        "daemon_manifest_received",
        "daemon_artifact_verified",
        "daemon_proof_written",
        "daemon_stopped",
    ] {
        assert!(
            daemon_types.contains(required),
            "daemon log must include {required}; saw {daemon_types:?}"
        );
    }

    let proof_path = artifact_path(&report, "proof_path");
    let proof: Value =
        serde_json::from_str(&fs::read_to_string(proof_path).expect("proof readable"))
            .expect("proof must be JSON");
    assert_eq!(proof["transfer_id"], report["transfer"]["transfer_id"]);
    assert_eq!(proof["manifest_root"], report["transfer"]["manifest_root"]);
    assert_eq!(proof["proof_root"], report["transfer"]["proof_root"]);
}

#[test]
fn failure_bundle_and_human_summary_are_stable() {
    let report = run_journey("nr10-cli-daemon-bundle");
    let failure_bundle_path = artifact_path(&report, "failure_bundle_path");
    let summary_path = artifact_path(&report, "summary_path");
    assert!(failure_bundle_path.exists(), "failure bundle must exist");
    assert!(summary_path.exists(), "human summary must exist");

    let bundle: Value = serde_json::from_str(
        &fs::read_to_string(failure_bundle_path).expect("failure bundle readable"),
    )
    .expect("failure bundle must be JSON");
    assert_eq!(
        bundle["redaction_policy"].as_str(),
        Some("paths_and_hashes_only_no_payload_bytes")
    );
    assert!(
        bundle["replay_command"]
            .as_str()
            .expect("replay command must be a string")
            .contains(SCRIPT_PATH)
    );

    let summary = fs::read_to_string(summary_path).expect("summary readable");
    assert!(
        summary.lines().count() <= 4,
        "human summary must stay concise"
    );

    let combined = format!("{report}\n{bundle}\n{summary}");
    for marker in [
        "fabricated",
        "synthetic progress",
        "skipped verification",
        "disabled assertion",
    ] {
        assert!(
            !combined.contains(marker),
            "journey success must not depend on {marker}"
        );
    }
}
