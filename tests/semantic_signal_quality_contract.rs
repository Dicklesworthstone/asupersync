#![allow(clippy::all)]
//! SEM-10.5 signal-quality gate contract tests.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FIXTURE_DIR: &str = "tests/fixtures/semantic_signal_quality";
const SCRIPT_PATH: &str = "scripts/check_semantic_signal_quality.sh";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIR)
        .join(name)
}

fn unique_output_path(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("semantic_signal_quality_{suffix}_{nanos}.json"))
}

fn run_signal_quality(dashboard_fixture: &str) -> (std::process::ExitStatus, Value) {
    let output_path = unique_output_path("report");
    let command_output = Command::new("bash")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg(SCRIPT_PATH)
        .arg("--report")
        .arg(fixture_path("verification_report_sample.json"))
        .arg("--dashboard")
        .arg(fixture_path(dashboard_fixture))
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("failed to execute signal quality script");

    let raw = std::fs::read_to_string(&output_path).expect("expected output JSON report");
    let parsed: Value =
        serde_json::from_str(&raw).expect("signal quality output must be valid JSON");
    let _ = std::fs::remove_file(output_path);
    (command_output.status, parsed)
}

#[test]
fn signal_quality_pass_fixture_meets_thresholds() {
    let (status, report) = run_signal_quality("variance_dashboard_pass.json");

    assert!(
        status.success(),
        "pass fixture should satisfy thresholds and return success"
    );
    assert_eq!(
        report["schema_version"].as_str(),
        Some("semantic-signal-quality-v1"),
        "schema version must be pinned"
    );
    assert_eq!(
        report["status"].as_str(),
        Some("pass"),
        "pass fixture should produce pass status"
    );
    assert_eq!(
        report["metrics"]["flake_rate_pct"].as_f64(),
        Some(0.0),
        "pass fixture should have zero flake rate"
    );
    assert!(
        report["diagnostics_links"]["existing_required_artifacts"]
            .as_array()
            .is_some_and(|arr| arr.len() >= 2),
        "required artifacts should be linked for deep diagnostics"
    );
}

#[test]
fn signal_quality_fail_fixture_flags_flake_and_false_positive_proxy() {
    let (status, report) = run_signal_quality("variance_dashboard_fail.json");

    assert!(
        !status.success(),
        "fail fixture should return non-zero status"
    );
    assert_eq!(
        report["status"].as_str(),
        Some("fail"),
        "fail fixture should produce fail status"
    );
    assert_eq!(
        report["metrics"]["flake_rate_pct"].as_f64(),
        Some(50.0),
        "one unstable suite out of two should be 50 percent"
    );
    assert_eq!(
        report["metrics"]["false_positive_proxy_rate_pct"].as_f64(),
        Some(50.0),
        "unstable suite with zero failures should contribute to proxy rate"
    );

    let failures = report["failures"]
        .as_array()
        .expect("failures must be an array");
    assert!(
        failures
            .iter()
            .filter_map(Value::as_str)
            .any(|msg| msg.contains("flake_rate_pct")),
        "failure report should include flake-rate threshold breach"
    );
    assert!(
        failures
            .iter()
            .filter_map(Value::as_str)
            .any(|msg| msg.contains("false_positive_proxy_rate_pct")),
        "failure report should include false-positive proxy threshold breach"
    );
}
