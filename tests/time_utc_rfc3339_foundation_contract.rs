//! Finite contract for the owned UTC formatter and current trace-info CLI.
//!
//! Bead: asupersync-d24mms.4
//! Governing ADR: DEP-ADR-011

#![cfg(feature = "cli")]
#![allow(missing_docs)]

use asupersync::time::format_unix_nanos_rfc3339;
use asupersync::trace::{REPLAY_SCHEMA_VERSION, TRACE_FILE_VERSION, TraceMetadata, write_trace};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use time::format_description::well_known::Rfc3339;

const ARTIFACT: &str = include_str!("../artifacts/time_utc_rfc3339_foundation_v1.json");
const ARTIFACT_PATH: &str = "artifacts/time_utc_rfc3339_foundation_v1.json";
const DOC_PATH: &str = "docs/time_utc_rfc3339_foundation.md";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const SCENARIO_ID: &str = "dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8";
const TEST_NAME: &str = "dep_sovereignty_asupersync_d24mms_4_b6e90e93b1e8";
const EXPECTED_TIMESTAMP: &str = "2020-02-29T12:34:56.123456789Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn run_trace_info(path: &Path, format: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args(["--format", format, "--color", "never", "trace", "info"])
        .arg(path)
        .output()
        .expect("run trace info")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{label} wrote unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_empty_trace(path: &Path, recorded_at: u64, description: &str) -> u64 {
    let metadata = TraceMetadata {
        version: REPLAY_SCHEMA_VERSION,
        seed: 42,
        recorded_at,
        config_hash: 99,
        description: Some(description.to_string()),
    };
    write_trace(path, &metadata, &[]).expect("write deterministic empty trace");
    std::fs::metadata(path).expect("read trace metadata").len()
}

fn expected_json(
    path: &Path,
    size_bytes: u64,
    created_at: Option<&str>,
    description: &str,
) -> Vec<u8> {
    let value = json!({
        "file": path.display().to_string(),
        "file_version": TRACE_FILE_VERSION,
        "schema_version": REPLAY_SCHEMA_VERSION,
        "compressed": false,
        "compression": "none",
        "size_bytes": size_bytes,
        "event_count": 0,
        "duration_nanos": null,
        "created_at": created_at,
        "seed": 42,
        "config_hash": 99,
        "description": description,
    });
    let mut bytes = serde_json::to_vec(&value).expect("serialize expected JSON");
    bytes.push(b'\n');
    bytes
}

fn expected_human(
    path: &Path,
    size_bytes: u64,
    created_at: Option<&str>,
    description: &str,
) -> String {
    assert!(size_bytes < 1024, "fixture should remain byte-sized");
    let created_line = created_at.map_or_else(String::new, |value| format!("Created: {value}\n"));
    format!(
        "File: {}\n\
         Version: {}\n\
         Schema: {}\n\
         Compressed: no\n\
         Size: {} B\n\
         Events: 0\n\
         {}Seed: 42\n\
         Config hash: 99\n\
         Description: {}\n",
        path.display(),
        TRACE_FILE_VERSION,
        REPLAY_SCHEMA_VERSION,
        size_bytes,
        created_line,
        description,
    )
}

fn assert_packet_and_registration(packet: &Value) {
    assert_eq!(
        text(packet, "artifact_id"),
        "time-utc-rfc3339-foundation-v1"
    );
    assert_eq!(packet["schema_version"], 1);
    assert_eq!(text(packet, "bead_id"), "asupersync-d24mms.4");
    assert_eq!(text(packet, "governing_adr"), "DEP-ADR-011");

    let decision = &packet["decision"];
    assert_eq!(
        text(decision, "state"),
        "KEEP_PENDING_SPARSE_GRAPH_AND_LEDGER_PROOF"
    );
    assert_eq!(decision["checkpoint_allowed"], true);
    assert_eq!(decision["close_bead_allowed"], false);
    assert_eq!(text(decision, "dependency_action"), "RETAIN_TIME_EDGE");

    let formatter = &packet["formatter_contract"];
    assert_eq!(text(formatter, "input"), "u64 nonnegative Unix nanoseconds");
    assert_eq!(text(formatter, "supported_years"), "1970..=2554");
    assert_eq!(formatter["clock_reads"], 0);

    let evidence = &packet["evidence"];
    assert_eq!(text(evidence, "scenario_id"), SCENARIO_ID);
    assert_eq!(text(evidence, "stable_test_name"), TEST_NAME);
    assert_eq!(
        text(evidence, "profile"),
        "current-cli-owned-formatter-keep"
    );
    assert_eq!(evidence["features"], json!(["cli"]));

    let runner = repo_file(RUNNER_PATH);
    assert!(runner.contains(SCENARIO_ID));
    assert!(runner.contains(TEST_NAME));
    assert!(runner.contains("--features cli"));
    assert!(runner.contains(ARTIFACT_PATH));

    let docs = repo_file(DOC_PATH);
    for marker in [
        SCENARIO_ID,
        "KEEP_PENDING_SPARSE_GRAPH_AND_LEDGER_PROOF",
        TEST_NAME,
    ] {
        assert!(docs.contains(marker), "documentation must contain {marker}");
    }

    let cli = repo_file("src/bin/asupersync.rs");
    assert!(cli.contains("format_unix_nanos_rfc3339(recorded_at_nanos)"));
    assert!(!cli.contains("time::OffsetDateTime"));
    assert!(repo_file("Cargo.toml").contains("time = { version = \">=0.3\""));
}

fn assert_fixed_formatter_vectors(packet: &Value) {
    let vectors = packet["vectors"]
        .as_array()
        .expect("vectors must be an array");
    assert_eq!(vectors.len(), 8);
    for vector in vectors {
        let unix_nanos = vector["unix_nanos"].as_u64().expect("u64 Unix nanoseconds");
        let expected = text(vector, "rfc3339");
        assert_eq!(format_unix_nanos_rfc3339(unix_nanos), expected);

        let incumbent = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_nanos))
            .expect("the finite u64 corpus is in the retained formatter range")
            .format(&Rfc3339)
            .expect("the retained formatter accepts the finite corpus");
        assert_eq!(incumbent, expected);
    }
}

fn assert_exact_cli_journeys() {
    let workspace = tempfile::tempdir().expect("temporary CLI workspace");

    let timestamp_path = workspace.path().join("time-utc-rfc3339.trace");
    let timestamp_description = "UTC formatter CLI contract";
    let timestamp_size = write_empty_trace(
        &timestamp_path,
        1_582_979_696_123_456_789,
        timestamp_description,
    );

    let json_output = run_trace_info(&timestamp_path, "json");
    assert_success(&json_output, "timestamp JSON journey");
    assert_eq!(
        json_output.stdout,
        expected_json(
            &timestamp_path,
            timestamp_size,
            Some(EXPECTED_TIMESTAMP),
            timestamp_description,
        )
    );
    let repeated_json = run_trace_info(&timestamp_path, "json");
    assert_success(&repeated_json, "repeated timestamp JSON journey");
    assert_eq!(repeated_json.stdout, json_output.stdout);

    let human_output = run_trace_info(&timestamp_path, "human");
    assert_success(&human_output, "timestamp human journey");
    assert_eq!(
        human_output.stdout,
        expected_human(
            &timestamp_path,
            timestamp_size,
            Some(EXPECTED_TIMESTAMP),
            timestamp_description,
        )
        .as_bytes()
    );

    let zero_path = workspace.path().join("time-utc-zero-sentinel.trace");
    let zero_description = "UTC formatter zero sentinel";
    let zero_size = write_empty_trace(&zero_path, 0, zero_description);

    let zero_json = run_trace_info(&zero_path, "json");
    assert_success(&zero_json, "zero-sentinel JSON journey");
    assert_eq!(
        zero_json.stdout,
        expected_json(&zero_path, zero_size, None, zero_description)
    );

    let zero_human = run_trace_info(&zero_path, "human");
    assert_success(&zero_human, "zero-sentinel human journey");
    assert_eq!(
        zero_human.stdout,
        expected_human(&zero_path, zero_size, None, zero_description).as_bytes()
    );
}

#[test]
fn dep_sovereignty_asupersync_d24mms_4_b6e90e93b1e8() {
    let packet: Value =
        serde_json::from_str(ARTIFACT).expect("foundation packet must be valid JSON");
    assert_packet_and_registration(&packet);
    assert_fixed_formatter_vectors(&packet);
    assert_exact_cli_journeys();
}
