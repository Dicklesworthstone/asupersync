//! Contract tests for the onboarding receipt cache helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/onboarding_receipt_cache.py";
const FIXTURE_ROOT: &str = "tests/fixtures/onboarding_receipt_cache";
const GENERATED_AT: &str = "2026-05-08T05:20:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_cache(receipt: &Path, cache: Option<&Path>, ttl_seconds: u64) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--receipt")
        .arg(receipt)
        .arg("--ttl-seconds")
        .arg(ttl_seconds.to_string())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root());
    if let Some(cache) = cache {
        command.arg("--cache").arg(cache);
    }
    command.output().expect("run onboarding cache helper")
}

fn cache_json(receipt: &Path, cache: Option<&Path>, ttl_seconds: u64) -> Value {
    let output = run_cache(receipt, cache, ttl_seconds);
    assert!(
        output.status.success(),
        "cache helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cache output must be JSON")
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join(FIXTURE_ROOT).join(name)
}

fn fixture_text(name: &str) -> String {
    fs::read_to_string(fixture(name))
        .unwrap_or_else(|error| panic!("read golden fixture {name}: {error}"))
}

fn assert_cache_output_matches_golden(output: Output, fixture_name: &str, label: &str) {
    assert!(
        output.status.success(),
        "cache helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("cache stdout is utf-8");
    let expected = fixture_text(fixture_name);
    let actual_json: Value = serde_json::from_str(&actual).expect("actual cache JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden cache JSON");
    assert_eq!(
        actual_json, expected_json,
        "parsed {label} onboarding receipt cache JSON drifted from the reviewed golden"
    );
    assert_eq!(
        actual, expected,
        "{label} onboarding receipt cache output drifted from the reviewed golden"
    );
}

fn patched_cache(fixture_name: &str, receipt: &Value) -> tempfile::NamedTempFile {
    let current_key = receipt["receipt_key"]
        .as_str()
        .expect("receipt key")
        .to_string();
    let current_digest = receipt["current_receipt_summary"]["receipt_digest_sha256"]
        .as_str()
        .expect("receipt digest")
        .to_string();
    let raw = fs::read_to_string(fixture(fixture_name)).expect("read cache fixture");
    let mut patched: Value = serde_json::from_str(&raw).expect("parse cache fixture");
    for entry in patched["entries"]
        .as_array_mut()
        .expect("cache fixture entries")
    {
        if entry["receipt_key"].as_str() == Some("PLACEHOLDER_FILLED_BY_TEST") {
            entry["receipt_key"] = Value::String(current_key.clone());
        }
        if entry["receipt_digest_sha256"].as_str() == Some("PLACEHOLDER_FILLED_BY_TEST") {
            entry["receipt_digest_sha256"] = Value::String(current_digest.clone());
        }
    }
    let mut file = tempfile::NamedTempFile::new().expect("create patched cache");
    file.write_all(
        serde_json::to_string_pretty(&patched)
            .expect("serialize patched cache")
            .as_bytes(),
    )
    .expect("write patched cache");
    file
}

#[test]
fn no_cache_output_matches_full_reviewed_golden() {
    let output = run_cache(&fixture("current_receipt.json"), None, 1800);
    assert_cache_output_matches_golden(output, "no_cache_expected.json", "no-cache");
}

#[test]
fn fresh_cache_output_matches_full_reviewed_golden() {
    let first = cache_json(&fixture("current_receipt.json"), None, 1800);
    let cache = patched_cache("fresh_cache.json", &first);
    let output = run_cache(&fixture("current_receipt.json"), Some(cache.path()), 1800);
    assert_cache_output_matches_golden(output, "fresh_cache_expected.json", "fresh");
}

#[test]
fn stale_cache_output_matches_full_reviewed_golden() {
    let first = cache_json(&fixture("current_receipt.json"), None, 1800);
    let cache = patched_cache("stale_cache.json", &first);
    let output = run_cache(&fixture("current_receipt.json"), Some(cache.path()), 1800);
    assert_cache_output_matches_golden(output, "stale_cache_expected.json", "stale");
}

#[test]
fn changed_cache_output_matches_full_reviewed_golden() {
    let first = cache_json(&fixture("current_receipt.json"), None, 1800);
    let cache = patched_cache("changed_cache.json", &first);
    let output = run_cache(&fixture("current_receipt.json"), Some(cache.path()), 1800);
    assert_cache_output_matches_golden(output, "changed_cache_expected.json", "changed-digest");
}

#[test]
fn no_matching_cache_output_matches_full_reviewed_golden() {
    let output = run_cache(
        &fixture("current_receipt.json"),
        Some(&fixture("no_matching_cache.json")),
        1800,
    );
    assert_cache_output_matches_golden(output, "no_matching_cache_expected.json", "no-matching");
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn no_cache_entry_requests_refresh_with_proposed_record() {
    let receipt = cache_json(&fixture("current_receipt.json"), None, 1800);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("onboarding-receipt-cache-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["decision"].as_str(), Some("refresh-cache"));
    assert_eq!(receipt["reason"].as_str(), Some("no matching cache entry"));
    assert_eq!(receipt["cache_entry_found"].as_bool(), Some(false));
    assert_eq!(
        receipt["proposed_cache_record"]["cached_at"].as_str(),
        Some(GENERATED_AT)
    );
}

#[test]
fn matching_fresh_entry_reuses_cache() {
    let first = cache_json(&fixture("current_receipt.json"), None, 1800);
    let cache = patched_cache("fresh_cache.json", &first);
    let receipt = cache_json(&fixture("current_receipt.json"), Some(cache.path()), 1800);

    assert_eq!(receipt["decision"].as_str(), Some("reuse-cache"));
    assert_eq!(
        receipt["reason"].as_str(),
        Some("matching entry is fresh and digest-stable")
    );
    assert_eq!(receipt["cache_entry_found"].as_bool(), Some(true));
    assert_eq!(receipt["cache_age_seconds"].as_u64(), Some(600));
}

#[test]
fn stale_matching_entry_forces_refresh() {
    let first = cache_json(&fixture("current_receipt.json"), None, 1800);
    let cache = patched_cache("stale_cache.json", &first);
    let receipt = cache_json(&fixture("current_receipt.json"), Some(cache.path()), 1800);

    assert_eq!(receipt["decision"].as_str(), Some("refresh-cache"));
    assert_eq!(
        receipt["reason"].as_str(),
        Some("matching entry exceeded TTL")
    );
    assert_eq!(receipt["cache_age_seconds"].as_u64(), Some(4800));
}

#[test]
fn digest_changed_matching_entry_forces_refresh() {
    let first = cache_json(&fixture("current_receipt.json"), None, 1800);
    let cache = patched_cache("changed_cache.json", &first);
    let receipt = cache_json(&fixture("current_receipt.json"), Some(cache.path()), 1800);

    assert_eq!(receipt["decision"].as_str(), Some("refresh-cache"));
    assert_eq!(
        receipt["reason"].as_str(),
        Some("matching entry digest differs from current receipt")
    );
}

#[test]
fn different_key_cache_does_not_count_as_match() {
    let receipt = cache_json(
        &fixture("current_receipt.json"),
        Some(&fixture("no_matching_cache.json")),
        1800,
    );

    assert_eq!(receipt["decision"].as_str(), Some("refresh-cache"));
    assert_eq!(receipt["cache_entry_found"].as_bool(), Some(false));
}

#[test]
fn output_is_redacted_and_non_mutating() {
    let receipt = cache_json(&fixture("current_receipt.json"), None, 1800);
    let rendered = serde_json::to_string(&receipt).expect("serialize receipt");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    assert_eq!(
        receipt["redaction_policy"]["raw_receipt_embedded"].as_bool(),
        Some(false)
    );
    assert!(!rendered.contains("PeerAgent"));
    assert!(!rendered.contains("src/runtime/scheduler/mod.rs"));
    for key in [
        "writes_cache",
        "runs_cargo",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
