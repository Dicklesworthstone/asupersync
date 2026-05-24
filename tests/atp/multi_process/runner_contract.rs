use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const RUN_ID: &str = "nr5-two-peer-transfer";
const REPORT_SCHEMA: &str = "asupersync.atp.multiproc.runner.v1";
const EVENT_SCHEMA: &str = "asupersync.atp.multiproc.event.v1";

#[derive(Debug, Deserialize)]
struct RunReport {
    schema_version: String,
    run_id: String,
    status: String,
    peer_count: usize,
    process_model: String,
    transport: String,
    real_io_required: bool,
    transfer: TransferReport,
    child_processes: Vec<ChildProcessReport>,
    artifacts: ArtifactReport,
}

#[derive(Debug, Deserialize)]
struct TransferReport {
    transfer_id: String,
    source_peer_id: String,
    destination_peer_id: String,
    source_path: PathBuf,
    destination_path: PathBuf,
    bytes_transferred: u64,
    source_sha256: String,
    received_sha256: String,
    verification: String,
}

#[derive(Debug, Deserialize)]
struct ChildProcessReport {
    role: String,
    peer_id: String,
    pid: u32,
    exit_status: i32,
    home: PathBuf,
    command: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactReport {
    run_dir: PathBuf,
    events_path: PathBuf,
    run_log_path: PathBuf,
    failure_bundle_path: PathBuf,
    replay_command: String,
}

#[test]
fn two_peer_runner_spawns_processes_and_verifies_transfer() {
    let temp_dir = TempDir::new().expect("temp output root");
    let script = repo_path("scripts/atp_multiproc_e2e/run_two_peer_transfer.sh");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--output-root")
        .arg(temp_dir.path())
        .arg("--run-id")
        .arg(RUN_ID)
        .output()
        .expect("spawn ATP multi-process runner");

    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = temp_dir
        .path()
        .join(format!("run_{RUN_ID}/run_report.json"));
    let report_raw = fs::read_to_string(&report_path).expect("run report exists");
    let report: RunReport = serde_json::from_str(&report_raw).expect("run report schema");

    assert_eq!(report.schema_version, REPORT_SCHEMA);
    assert_eq!(report.run_id, RUN_ID);
    assert_eq!(report.status, "success");
    assert_eq!(report.peer_count, 2);
    assert_eq!(report.process_model, "local_child_processes");
    assert_eq!(report.transport, "filesystem_spool_with_atomic_publish");
    assert!(report.real_io_required);

    assert_eq!(report.transfer.source_peer_id, "peer-sender");
    assert_eq!(report.transfer.destination_peer_id, "peer-receiver");
    assert!(report.transfer.transfer_id.contains(RUN_ID));
    assert!(report.transfer.bytes_transferred > 0);
    assert_eq!(
        report.transfer.source_sha256,
        report.transfer.received_sha256
    );
    assert_eq!(report.transfer.verification, "byte_for_byte_cmp_and_sha256");
    assert_same_file_bytes(
        &report.transfer.source_path,
        &report.transfer.destination_path,
    );

    assert_eq!(report.child_processes.len(), 2);
    let sender = child(&report, "sender");
    let receiver = child(&report, "receiver");
    assert_eq!(sender.peer_id, "peer-sender");
    assert_eq!(receiver.peer_id, "peer-receiver");
    assert_ne!(sender.pid, 0);
    assert_ne!(receiver.pid, 0);
    assert_ne!(sender.pid, receiver.pid);
    assert_eq!(sender.exit_status, 0);
    assert_eq!(receiver.exit_status, 0);
    assert!(sender.home.ends_with("homes/sender"));
    assert!(receiver.home.ends_with("homes/receiver"));
    assert!(sender.command.contains("--role sender"));
    assert!(receiver.command.contains("--role receiver"));

    assert!(report.artifacts.run_dir.exists());
    assert!(report.artifacts.run_log_path.exists());
    assert!(report.artifacts.failure_bundle_path.exists());
    assert!(report.artifacts.replay_command.contains(RUN_ID));

    let events_raw = fs::read_to_string(&report.artifacts.events_path).expect("events log exists");
    assert_event_contract(&events_raw);
    assert_forbidden_success_markers_absent(&report_raw);
    assert_forbidden_success_markers_absent(&events_raw);
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn assert_same_file_bytes(left: &Path, right: &Path) {
    let left_bytes = fs::read(left).expect("source payload readable");
    let right_bytes = fs::read(right).expect("destination payload readable");
    assert_eq!(left_bytes, right_bytes);
}

fn child<'a>(report: &'a RunReport, role: &str) -> &'a ChildProcessReport {
    report
        .child_processes
        .iter()
        .find(|child| child.role == role)
        .unwrap_or_else(|| panic!("missing child process role {role}"))
}

fn assert_event_contract(events_raw: &str) {
    let mut event_types = Vec::new();
    for line in events_raw.lines() {
        let event: Value = serde_json::from_str(line).expect("event log row is JSON");
        assert_eq!(event["schema_version"], EVENT_SCHEMA);
        assert_eq!(event["run_id"], RUN_ID);
        event_types.push(
            event["event_type"]
                .as_str()
                .expect("event_type is present")
                .to_string(),
        );
    }

    for required in [
        "harness_started",
        "fixture_generated",
        "process_started",
        "peer_ready",
        "transfer_sent",
        "transfer_received",
        "transfer_verified",
    ] {
        assert!(
            event_types.iter().any(|event_type| event_type == required),
            "missing structured event {required}; saw {event_types:?}"
        );
    }
}

fn assert_forbidden_success_markers_absent(text: &str) {
    for marker in [
        "fabricated",
        "synthetic progress",
        "skipped verification",
        "disabled assertion",
        "mock transfer",
        "fake object",
    ] {
        assert!(
            !text.contains(marker),
            "multi-process harness must not report success through {marker}"
        );
    }
}
