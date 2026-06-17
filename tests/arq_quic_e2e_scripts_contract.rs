//! Contract tests for the ARQ/QUIC H5 E2E script surfaces.
//!
//! These tests intentionally exercise offline validation and structure paths.
//! The full loopback transfer is run through `scripts/run_arq_quic_loopback_e2e.sh`
//! via RCH for H5 closeout evidence.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "arq_quic_scripts_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn unique_artifact_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    repo_root().join("artifacts/arq_quic_e2e").join(format!(
        "{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write file");
}

fn write_fixture(dir: &Path, sha_match: bool) {
    let event_lines = [
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:00Z","stage":"setup","status":"started","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:01Z","stage":"receiver_ready","status":"passed","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:02Z","stage":"sender_transfer","status":"passed","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:03Z","stage":"sha256_verify","status":"passed","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:04Z","stage":"summary","status":"passed","message":"fixture","details":{"transport_counters":{"no_claim":"fixture no-claim"}}}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:04Z","stage":"offline_validation","status":"passed","message":"fixture"}"#,
    ];
    write_file(
        &dir.join("events.ndjson"),
        &format!("{}\n", event_lines.join("\n")),
    );

    let summary = format!(
        r#"{{
  "schema_version": "arq-quic-loopback-e2e-summary-v1",
  "status": "passed",
  "transport": "quic",
  "bytes_sent": 8192,
  "bytes_received": 8192,
  "sender": {{"event":"atp_send","transport":"quic","committed":true,"bytes_sent":8192}},
  "receiver": {{"event":"atp_receive","transport":"quic","committed":true,"bytes_received":8192}},
  "sha256_match": {sha_match},
  "metrics": {{"sender_max_rss_kb": 12345, "sender_elapsed_raw":"0:00.01"}},
  "transport_counters": {{
    "source":"atp-cli-json",
    "symbols_sent": 64,
    "symbols_accepted": 64,
    "feedback_rounds_sender": 0,
    "feedback_rounds_receiver": 0,
    "decode_count": null,
    "symbols_sent_available": true,
    "symbols_accepted_available": true,
    "feedback_rounds_available": true,
    "decode_count_available": false,
    "no_claim": "fixture decode-count no-claim"
  }},
  "artifacts": {{"events_ndjson":"events.ndjson"}}
}}"#
    );
    write_file(&dir.join("summary.json"), &summary);
}

fn read_lossy(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| format!("<unavailable: {err}>"))
}

fn real_loopback_debug_dump(root: &Path) -> String {
    [
        ("events.ndjson", root.join("events.ndjson")),
        ("summary.json", root.join("summary.json")),
        ("sender.json", root.join("sender.json")),
        ("receiver.json", root.join("receiver.json")),
        ("sender.stderr", root.join("sender.stderr")),
        ("receiver.stderr", root.join("receiver.stderr")),
        ("sender.time.txt", root.join("sender.time.txt")),
        ("certs.log", root.join("certs.log")),
    ]
    .into_iter()
    .map(|(label, path)| format!("--- {label} ---\n{}", read_lossy(&path)))
    .collect::<Vec<_>>()
    .join("\n")
}

#[test]
fn loopback_from_output_accepts_valid_retained_artifacts() {
    let root = unique_tmp("valid");
    write_fixture(&root, true);

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        output.status.success(),
        "validator rejected valid fixture; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_corrupted_summary() {
    let root = unique_tmp("corrupt");
    write_fixture(&root, false);

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted corrupted fixture; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_missing_counter_values_even_when_flags_claim_available() {
    let root = unique_tmp("missing_counter");
    write_fixture(&root, true);

    let summary_path = root.join("summary.json");
    let summary = std::fs::read_to_string(&summary_path).expect("read summary fixture");
    write_file(
        &summary_path,
        &summary.replace(
            r#""feedback_rounds_receiver": 0"#,
            r#""feedback_rounds_receiver": null"#,
        ),
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted unavailable feedback counter hidden by availability flag; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fleet_script_structure_validation_is_no_claim_and_deterministic() {
    let script_path = repo_root().join("scripts/run_arq_quic_fleet_e2e.sh");
    let script = std::fs::read_to_string(&script_path).expect("read fleet script");
    assert!(
        script.contains(r#"export METHODS="atpquic""#),
        "fleet wrapper must force the H5-owned atpquic method instead of inheriting METHODS"
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_fleet_e2e.sh"))
        .arg("--validate-structure")
        .output()
        .expect("run fleet structure validator");

    assert!(
        output.status.success(),
        "fleet structure validation failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""schema_version": "arq-quic-fleet-e2e-structure-v1""#));
    assert!(stdout.contains(r#""forced_methods": "atpquic""#));
    assert!(stdout.contains("G1/G2 own two-machine evidence"));
}

#[test]
#[ignore = "runs the real atp QUIC loopback; invoke explicitly through RCH"]
fn loopback_script_runs_real_atp_binary() {
    let atp_bin = std::env::var_os("CARGO_BIN_EXE_atp")
        .map(PathBuf::from)
        .expect("CARGO_BIN_EXE_atp must be available; run with --features atp-cli,tls");
    let root = unique_artifact_dir("h5_loopback");

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .env("ATP_BIN", &atp_bin)
        .env("ARQ_QUIC_OUTPUT_DIR", &root)
        .env("ARQ_QUIC_PAYLOAD_BYTES", "8192")
        .output()
        .expect("run real loopback script");

    assert!(
        output.status.success(),
        "real loopback script failed at {}; stdout: {}; stderr: {}\n{}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        real_loopback_debug_dump(&root)
    );

    let validate = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("validate retained real loopback artifacts");

    assert!(
        validate.status.success(),
        "retained real loopback artifacts failed validation; stdout: {}; stderr: {}\n{}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr),
        real_loopback_debug_dump(&root)
    );

    let summary = std::fs::read_to_string(root.join("summary.json")).expect("read summary");
    let events = std::fs::read_to_string(root.join("events.ndjson")).expect("read events");

    assert!(summary.contains(r#""schema_version": "arq-quic-loopback-e2e-summary-v1""#));
    assert!(summary.contains(r#""transport": "quic""#));
    assert!(summary.contains(r#""sha256_match": true"#));
    assert!(summary.contains(r#""sender_max_rss_kb":"#));
    assert!(summary.contains(r#""symbols_sent_available": true"#));
    assert!(summary.contains(r#""symbols_accepted_available": true"#));
    assert!(summary.contains(r#""feedback_rounds_available": true"#));
    assert!(summary.contains(r#""decode_count_available": false"#));
    assert!(events.contains(r#""stage":"receiver_ready","status":"passed""#));
    assert!(events.contains(r#""stage":"sender_transfer","status":"passed""#));
    assert!(events.contains(r#""stage":"sha256_verify","status":"passed""#));
}
