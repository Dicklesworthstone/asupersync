use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SCRIPT_PATH: &str = "scripts/atp_user_journey/push_artifact_cli_daemon.sh";
const REPORT_SCHEMA: &str = "asupersync.atp.user_journey.cli_daemon_report.v1";
const EVENT_SCHEMA: &str = "asupersync.atp.user_journey.cli_daemon_event.v1";
const SCENARIO_ID: &str = "cli_push_artifact_daemon_log";
const OUTPUT_ROOT: &str = "target/atp_user_journey_cli_daemon_contract";
/// The `asupersync` binary cargo built for this target. The journey runs it as
/// both the daemon and the CLI; the script has no other way to move bytes.
const ASUPERSYNC_BIN: &str = env!("CARGO_BIN_EXE_asupersync");
/// The ATP-over-TCP bulk chunk size (`DEFAULT_CHUNK_SIZE`).
const ATP_TCP_CHUNK_BYTES: usize = 256 * 1024;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn journey_command(run_id: &str) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(repo_path(SCRIPT_PATH))
        .arg("--output-root")
        .arg(repo_path(OUTPUT_ROOT))
        .args(["--run-id", run_id])
        .current_dir(repo_root())
        .env_remove("ASUPERSYNC_BIN")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn describe(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_journey(run_id: &str) -> Value {
    let output = journey_command(run_id)
        .args(["--asupersync-bin", ASUPERSYNC_BIN])
        .output()
        .expect("run ATP user journey script");

    assert!(
        output.status.success(),
        "ATP user journey failed\n{}",
        describe(&output)
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

fn events_of_type<'a>(events: &'a [Value], event_type: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| event["event_type"].as_str() == Some(event_type))
        .collect()
}

fn is_lower_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// The address `atp serve` reported: loopback, with the port the OS chose.
fn assert_bound_loopback_address(address: &str) {
    let (host, port) = address
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("listen address {address} must be host:port"));
    assert_eq!(
        host, "127.0.0.1",
        "daemon must listen on loopback: {address}"
    );
    let port: u16 = port
        .parse()
        .unwrap_or_else(|err| panic!("listen address {address} has a bad port: {err}"));
    assert_ne!(
        port, 0,
        "daemon must report the port it bound, got {address}"
    );
}

#[test]
fn cli_push_artifact_journey_copies_and_verifies_payload() {
    let report = run_journey("nr10-cli-daemon-copy");
    assert_eq!(report["schema_version"].as_str(), Some(REPORT_SCHEMA));
    assert_eq!(report["event_schema_version"].as_str(), Some(EVENT_SCHEMA));
    assert_eq!(report["scenario_id"].as_str(), Some(SCENARIO_ID));
    assert_eq!(report["status"].as_str(), Some("success"), "{report:#}");
    assert_eq!(report["real_io_required"].as_bool(), Some(true));
    assert_eq!(report["process_model"].as_str(), Some("local_child_daemon"));
    assert_eq!(report["transport"].as_str(), Some("atp_tcp_loopback"));
    assert_eq!(report["failure_reasons"].as_array().map(Vec::len), Some(0));

    // The binary that ran is the one cargo built for this test.
    let ran = report["environment"]["asupersync_bin"]
        .as_str()
        .expect("report names the binary it ran");
    assert_eq!(
        fs::canonicalize(ran).expect("reported binary exists"),
        fs::canonicalize(ASUPERSYNC_BIN).expect("cargo-built binary exists"),
        "the journey must run the cargo-built asupersync binary"
    );

    // Daemon side: `atp serve` reported a real bound port and kept serving
    // until the harness stopped it.
    let daemon = &report["daemon"];
    let listen = daemon["listen_address"]
        .as_str()
        .expect("daemon listen address must be reported");
    assert_bound_loopback_address(listen);
    assert_eq!(daemon["requested_listen"].as_str(), Some("127.0.0.1:0"));
    assert_eq!(
        daemon["alive_until_stop"].as_bool(),
        Some(true),
        "{daemon:#}"
    );
    assert!(
        daemon["command_line"]
            .as_str()
            .expect("daemon command line must be a string")
            .contains(" atp serve --listen 127.0.0.1:0 --data-dir "),
        "{daemon:#}"
    );

    // CLI side: `atp send` exited 0 and printed the receiver's receipt.
    let cli = &report["cli"];
    assert_eq!(cli["exit_status"].as_i64(), Some(0), "{cli:#}");
    assert_eq!(cli["timed_out"].as_bool(), Some(false), "{cli:#}");
    let result = &cli["result"];
    assert_eq!(result["status"].as_str(), Some("committed"), "{result}");
    assert_eq!(result["committed"].as_bool(), Some(true), "{result}");
    assert_eq!(result["sha_ok"].as_bool(), Some(true), "{result}");
    assert_eq!(result["merkle_ok"].as_bool(), Some(true), "{result}");
    assert_eq!(result["files"].as_u64(), Some(1), "{result}");
    assert_eq!(result["target"].as_str(), Some(listen), "{result}");

    // The committed copy lives in the daemon's own inbox, and nothing else does.
    let source_path = PathBuf::from(report["transfer"]["source_path"].as_str().unwrap());
    let destination_path = PathBuf::from(report["transfer"]["destination_path"].as_str().unwrap());
    let data_dir = artifact_path(&report, "receiver_data_dir");
    assert_eq!(
        destination_path,
        data_dir.join("inbox").join("artifact.txt"),
        "the artifact must be committed under the daemon's --data-dir inbox"
    );
    assert_eq!(
        daemon["inbox_entries"],
        serde_json::json!(["artifact.txt"]),
        "{daemon:#}"
    );
    assert!(source_path.exists(), "source payload must exist");
    assert!(destination_path.exists(), "destination payload must exist");
    let source_bytes = fs::read(&source_path).expect("source readable");
    let received_bytes = fs::read(&destination_path).expect("destination readable");
    assert!(
        source_bytes == received_bytes,
        "{} holds {} bytes that differ from the {}-byte source",
        destination_path.display(),
        received_bytes.len(),
        source_bytes.len()
    );
    assert!(
        source_bytes.len() > ATP_TCP_CHUNK_BYTES,
        "the payload must span more than one ATP-over-TCP chunk, got {} bytes",
        source_bytes.len()
    );
    assert_eq!(
        report["transfer"]["source_sha256"],
        report["transfer"]["received_sha256"]
    );
    assert_eq!(
        report["transfer"]["verification"].as_str(),
        Some("byte_for_byte_cmp_and_sha256")
    );
    let source_len = u64::try_from(source_bytes.len()).expect("payload length fits u64");
    assert_eq!(
        report["transfer"]["bytes_transferred"].as_u64(),
        Some(source_len),
        "the sender must report every byte as sent (a receiver already in sync sends 0)"
    );
    assert_eq!(result["bytes_sent"].as_u64(), Some(source_len), "{result}");

    // Identifiers come from the binary, not from the harness.
    let transfer_id = report["transfer"]["transfer_id"]
        .as_str()
        .expect("transfer id must be a string");
    assert!(is_lower_hex(transfer_id), "transfer id {transfer_id}");
    assert_eq!(result["transfer_id"].as_str(), Some(transfer_id));
    let manifest_root = report["transfer"]["manifest_root"]
        .as_str()
        .expect("manifest root must be a string");
    assert!(
        manifest_root.len() == 64 && is_lower_hex(manifest_root),
        "manifest root {manifest_root}"
    );
    assert_eq!(result["merkle_root"].as_str(), Some(manifest_root));
}

#[test]
fn structured_logs_include_cli_daemon_and_replay_fields() {
    let report = run_journey("nr10-cli-daemon-logs");
    let events = read_jsonl(&artifact_path(&report, "events_path"));
    let daemon_events = read_jsonl(&artifact_path(&report, "daemon_log_path"));
    let cli_events = read_jsonl(&artifact_path(&report, "cli_log_path"));
    assert!(!events.is_empty(), "structured event log must not be empty");
    assert!(
        !daemon_events.is_empty(),
        "daemon structured log must not be empty"
    );
    assert!(
        !cli_events.is_empty(),
        "CLI structured log must not be empty"
    );

    for event in events
        .iter()
        .chain(daemon_events.iter())
        .chain(cli_events.iter())
    {
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

        // Each row names the command line of the process it describes.
        let command_line = event["command_line"]
            .as_str()
            .expect("command line must be a string");
        let expected = match event["actor"].as_str() {
            Some("atp_serve") => " atp serve ",
            Some("atp_send") => " atp send ",
            Some("harness") => SCRIPT_PATH,
            other => panic!("unexpected actor {other:?} in {event}"),
        };
        assert!(
            command_line.contains(expected),
            "{} command line must contain {expected:?}: {command_line}",
            event["event_type"].as_str().unwrap_or("<unknown>")
        );
    }
    for event in &daemon_events {
        assert_eq!(event["actor"].as_str(), Some("atp_serve"), "{event}");
    }
    for event in &cli_events {
        assert_eq!(event["actor"].as_str(), Some("atp_send"), "{event}");
    }

    let daemon_types = event_types(&daemon_events);
    for required in [
        "daemon_started",
        "daemon_artifact_verified",
        "daemon_stopped",
    ] {
        assert!(
            daemon_types.contains(required),
            "daemon log must include {required}; saw {daemon_types:?}"
        );
    }

    // What `atp serve` cannot show is reported as not run, never written into
    // the daemon log by the harness.
    let not_run: BTreeSet<&str> = report["not_run"]
        .as_array()
        .expect("not_run must be an array")
        .iter()
        .map(|row| {
            assert!(
                row["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty()),
                "every not_run row needs a reason: {row}"
            );
            row["assertion"].as_str().expect("not_run assertion name")
        })
        .collect();
    for absent in ["daemon_manifest_received", "daemon_proof_written"] {
        assert!(
            !daemon_types.contains(absent),
            "{absent} is not observable from atp serve and must not be logged"
        );
        assert!(
            not_run.contains(absent),
            "{absent} must be reported as not run"
        );
    }

    let listen = report["daemon"]["listen_address"]
        .as_str()
        .expect("daemon listen address must be reported");
    for started in events_of_type(&daemon_events, "daemon_started") {
        assert_eq!(started["detail"]["listen_address"].as_str(), Some(listen));
    }
    for stopped in events_of_type(&daemon_events, "daemon_stopped") {
        assert_eq!(
            stopped["detail"]["alive_until_stop"].as_bool(),
            Some(true),
            "{stopped}"
        );
    }

    let cli_types = event_types(&cli_events);
    for required in ["cli_command_started", "cli_send_completed"] {
        assert!(
            cli_types.contains(required),
            "CLI log must include {required}; saw {cli_types:?}"
        );
    }

    // Rows written after `atp send` finished carry the binary's transfer id
    // and merkle root.
    let transfer_id = &report["transfer"]["transfer_id"];
    let manifest_root = &report["transfer"]["manifest_root"];
    for row in events_of_type(&cli_events, "cli_send_completed")
        .into_iter()
        .chain(events_of_type(&daemon_events, "daemon_artifact_verified"))
    {
        assert_eq!(&row["transfer_id"], transfer_id, "{row}");
        assert_eq!(&row["manifest_root"], manifest_root, "{row}");
    }

    let proof_path = artifact_path(&report, "proof_path");
    let proof: Value =
        serde_json::from_str(&fs::read_to_string(proof_path).expect("proof readable"))
            .expect("proof must be JSON");
    assert_eq!(proof["status"].as_str(), Some("verified"), "{proof:#}");
    assert_eq!(proof["transfer_id"], report["transfer"]["transfer_id"]);
    assert_eq!(proof["manifest_root"], report["transfer"]["manifest_root"]);
    assert_eq!(proof["proof_root"], report["transfer"]["proof_root"]);
    assert_eq!(
        proof["receiver_receipt"]["committed"].as_bool(),
        Some(true),
        "{proof:#}"
    );
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
    let replay = bundle["replay_command"]
        .as_str()
        .expect("replay command must be a string");
    assert!(replay.contains(SCRIPT_PATH), "{replay}");
    assert!(
        replay.contains("--asupersync-bin "),
        "the replay command must name the binary it ran: {replay}"
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

/// Without a runnable binary the script refuses to run (exit 2) instead of
/// moving the artifact some other way.
#[test]
fn journey_refuses_to_run_without_the_real_binary() {
    let missing = repo_path(OUTPUT_ROOT).join("no-such-asupersync");
    let cases: [(&str, Option<&Path>, &str); 2] = [
        ("nr10-cli-daemon-no-binary", None, "--asupersync-bin"),
        (
            "nr10-cli-daemon-missing-binary",
            Some(missing.as_path()),
            "is not an executable file",
        ),
    ];
    for (run_id, binary, expected) in cases {
        let mut command = journey_command(run_id);
        if let Some(binary) = binary {
            command.arg("--asupersync-bin").arg(binary);
        }
        let output = command.output().expect("run ATP user journey script");
        assert_eq!(output.status.code(), Some(2), "{}", describe(&output));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "stderr must explain the refusal ({expected:?})\n{}",
            describe(&output)
        );
        assert!(
            output.stdout.is_empty(),
            "a refused run prints no report\n{}",
            describe(&output)
        );
    }
}
