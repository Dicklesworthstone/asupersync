//! SEM-10.5 signal-quality gate contract tests.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
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

fn run_signal_quality_output(dashboard_fixture: &str) -> (ExitStatus, String) {
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
    let _ = std::fs::remove_file(output_path);
    (command_output.status, raw)
}

fn run_signal_quality(dashboard_fixture: &str) -> (ExitStatus, Value) {
    let (status, raw) = run_signal_quality_output(dashboard_fixture);
    let parsed: Value =
        serde_json::from_str(&raw).expect("signal quality output must be valid JSON");
    (status, parsed)
}

fn fixture_json(name: &str) -> Value {
    let raw = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|error| panic!("read fixture {name}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse fixture {name}: {error}"))
}

fn fixture_text(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|error| panic!("read fixture {name}: {error}"))
}

fn scrub_report_text(raw: &str) -> String {
    scrub_generated_at_lines(&scrub_string(raw))
}

fn scrub_generated_at_lines(text: &str) -> String {
    let mut scrubbed = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("\"generated_at\":") {
            let indent_len = line.len() - trimmed.len();
            scrubbed.push_str(&line[..indent_len]);
            scrubbed.push_str("\"generated_at\": \"[generated_at]\"");
            if trimmed.ends_with(',') {
                scrubbed.push(',');
            }
        } else {
            scrubbed.push_str(line);
        }
        scrubbed.push('\n');
    }
    if !text.ends_with('\n') {
        scrubbed.pop();
    }
    scrubbed
}

fn assert_signal_quality_output_matches_golden(
    dashboard_fixture: &str,
    expected_fixture: &str,
    should_succeed: bool,
) {
    let (status, raw) = run_signal_quality_output(dashboard_fixture);
    assert_eq!(
        status.success(),
        should_succeed,
        "{dashboard_fixture} exit status did not match expected success"
    );

    let actual = scrub_report_text(&raw);
    let expected = fixture_text(expected_fixture);
    let actual_json: Value =
        serde_json::from_str(&actual).expect("scrubbed signal quality output must be JSON");
    let expected_json = fixture_json(expected_fixture);
    assert_eq!(
        actual_json, expected_json,
        "semantic signal-quality parsed golden drifted"
    );
    assert_eq!(
        actual, expected,
        "semantic signal-quality reviewed text golden drifted"
    );
}

fn scrub_string(text: &str) -> String {
    let repo = env!("CARGO_MANIFEST_DIR");
    let tmp = std::env::temp_dir();
    let tmp = tmp.to_string_lossy();
    let scrubbed = text.replace(repo, "$REPO").replace(tmp.as_ref(), "$TMP");
    collapse_signal_quality_temp_names(scrubbed)
}

fn collapse_signal_quality_temp_names(mut text: String) -> String {
    const MARKER: &str = "semantic_signal_quality_report_";
    const REPLACEMENT: &str = "semantic_signal_quality_report_[n].json";
    let mut search_start = 0;
    while let Some(relative_start) = text[search_start..].find(MARKER) {
        let start = search_start + relative_start;
        let mut digit_end = start + MARKER.len();
        while digit_end < text.len() && text.as_bytes()[digit_end].is_ascii_digit() {
            digit_end += 1;
        }
        if digit_end == start + MARKER.len() || !text[digit_end..].starts_with(".json") {
            search_start = digit_end;
            continue;
        }
        text.replace_range(start..digit_end + ".json".len(), REPLACEMENT);
        search_start = start + REPLACEMENT.len();
    }
    text
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
fn signal_quality_pass_fixture_matches_scrubbed_golden() {
    assert_signal_quality_output_matches_golden(
        "variance_dashboard_pass.json",
        "variance_dashboard_pass_expected.json",
        true,
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

#[test]
fn signal_quality_fail_fixture_matches_scrubbed_golden() {
    assert_signal_quality_output_matches_golden(
        "variance_dashboard_fail.json",
        "variance_dashboard_fail_expected.json",
        false,
    );
}
