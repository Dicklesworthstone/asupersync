//! Contract tests for the proof-traffic installed-RCH capability drift gate.
//!
//! This pins the A1 artifact for `asupersync-proof-traffic-control-kuyx64.1`.
//! The gate is deliberately narrow: it records installed command-shape
//! capability and fail-closed operator behavior. It does not prove live fleet
//! health, release readiness, broad workspace correctness, or permission to use
//! local Cargo fallback.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const ARTIFACT_PATH: &str = "artifacts/proof_traffic_rch_capabilities_v1.json";
const CLEAN_OVERLAY_RUNBOOK_PATH: &str = "docs/clean_overlay_proof_orchestration_runbook.md";
const DOCS_PATH: &str = "docs/proof_traffic_control.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FeatureSupport {
    Supported,
    Unsupported,
    Unknown,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn assert_contains_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(haystack.contains(needle), "missing {needle}");
    }
}

fn detect_flag_support(help_text: Option<&str>, flag: &str) -> FeatureSupport {
    match help_text {
        Some(text) if !text.trim().is_empty() && text.contains(flag) => FeatureSupport::Supported,
        Some(text) if !text.trim().is_empty() => FeatureSupport::Unsupported,
        _ => FeatureSupport::Unknown,
    }
}

#[test]
fn artifact_records_installed_rch_capabilities_and_drift() {
    let artifact = json(ARTIFACT_PATH);
    assert_eq!(
        string_field(&artifact, "schema_version"),
        "proof-traffic-rch-capabilities-v1"
    );
    assert_eq!(
        string_field(&artifact, "bead_id"),
        "asupersync-proof-traffic-control-kuyx64.1"
    );
    assert_eq!(string_field(&artifact, "status"), "contract_guarded");

    for path in [
        string_field(&artifact["source_of_truth"], "artifact"),
        string_field(&artifact["source_of_truth"], "operator_doc"),
        string_field(&artifact["source_of_truth"], "contract_test"),
        string_field(&artifact["source_of_truth"], "agent_instructions"),
        string_field(&artifact["source_of_truth"], "readme"),
        string_field(&artifact["source_of_truth"], "clean_overlay_runbook"),
        string_field(&artifact["source_of_truth"], "proof_lane_manifest"),
        string_field(&artifact["source_of_truth"], "proof_status_snapshot"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    assert_eq!(
        string_field(&artifact["probe"], "installed_rch_version"),
        "1.0.49"
    );
    assert!(array(&artifact["probe"], "commands").iter().any(|command| {
        command["command"].as_str() == Some("rch --version")
            && command["observed_at"].as_str() == Some("2026-07-16T06:57:00Z")
            && command["observed_signal"].as_str() == Some("rch 1.0.49 (commit 40beb520c1f3)")
    }));
    assert!(
        string_field(&artifact["probe"], "freshness_note")
            .contains("remote-required refusal fixture remains the separately dated 2026-06-15")
    );

    let clean_overlay = &artifact["capabilities"]["clean_overlay_flags"];
    assert_eq!(clean_overlay["supported"].as_bool(), Some(false));
    let missing = string_set(clean_overlay, "missing_flags");
    for flag in [
        "--base",
        "--clean-overlay",
        "--overlay-path",
        "--no-overlay",
    ] {
        assert!(missing.contains(flag), "missing unsupported flag {flag}");
    }

    assert_eq!(
        artifact["capabilities"]["remote_required_env"]["supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["capabilities"]["json_output"]["supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["command_policy"]["local_cargo_fallback_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        artifact["command_policy"]["never_cancel_peer_owned_builds"].as_bool(),
        Some(true)
    );
}

#[test]
fn flag_support_parser_covers_supported_unsupported_and_unknown_states() {
    let help_text = "\
Execute a compilation command on a remote worker

Usage: rch exec [OPTIONS] <COMMAND>...

Options:
  -j, --json
  -F, --format <format>
      --robot-triage
";

    assert_eq!(
        detect_flag_support(Some(help_text), "--json"),
        FeatureSupport::Supported
    );
    assert_eq!(
        detect_flag_support(Some(help_text), "--clean-overlay"),
        FeatureSupport::Unsupported
    );
    assert_eq!(detect_flag_support(None, "--json"), FeatureSupport::Unknown);
    assert_eq!(
        detect_flag_support(Some(""), "--json"),
        FeatureSupport::Unknown
    );
}

#[test]
fn artifact_and_docs_fail_closed_on_unsupported_clean_overlay_flags() {
    let artifact = json(ARTIFACT_PATH);
    let docs = read_repo_file(DOCS_PATH);
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    let clean_overlay_runbook = read_repo_file(CLEAN_OVERLAY_RUNBOOK_PATH);

    assert_contains_all(
        &docs,
        &[
            "blocked-by-capability-drift",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=...",
            "No local Cargo fallback",
            "Do not cancel peer-owned builds",
            "--base",
            "--clean-overlay",
            "--overlay-path",
            "--no-overlay",
            "version `1.0.49`",
        ],
    );
    let handoff_fields = docs
        .split_once("## Required Handoff Fields")
        .expect("required handoff section")
        .1
        .split_once("## Proof-Traffic A2")
        .expect("next section after required handoff fields")
        .0;
    for field in ["`clean_overlay_supported`", "`missing_flags`"] {
        assert!(
            handoff_fields.contains(field),
            "global handoff section missing {field}"
        );
    }

    let clean_overlay_documented = readme.contains(CLEAN_OVERLAY_RUNBOOK_PATH)
        && agents.contains(CLEAN_OVERLAY_RUNBOOK_PATH)
        && clean_overlay_runbook.contains("--clean-overlay");
    assert!(
        clean_overlay_documented,
        "README/AGENTS should point at the clean-overlay runbook and the runbook should expose command-shape context"
    );
    assert_eq!(
        artifact["capabilities"]["clean_overlay_flags"]["supported"].as_bool(),
        Some(false),
        "installed capability must fail closed while docs mention clean-overlay flags"
    );

    let findings = array(&artifact, "drift_findings");
    assert!(
        findings.iter().any(|finding| {
            finding["finding_id"].as_str()
                == Some("clean-overlay-docs-advertise-unavailable-exec-flags")
                && finding["operator_action"]
                    .as_str()
                    .is_some_and(|text| text.contains("Fail closed"))
        }),
        "artifact must carry a fail-closed clean-overlay drift finding"
    );
}

#[test]
fn artifact_help_excerpt_classifies_installed_rch_exec_flags() {
    let artifact = json(ARTIFACT_PATH);
    let help_text = array(&artifact["probe"], "help_excerpt")
        .iter()
        .map(|entry| entry.as_str().expect("help excerpt string"))
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(
        detect_flag_support(Some(&help_text), "--json"),
        FeatureSupport::Supported
    );
    for flag in [
        "--base",
        "--clean-overlay",
        "--overlay-path",
        "--no-overlay",
    ] {
        assert_eq!(
            detect_flag_support(Some(&help_text), flag),
            FeatureSupport::Unsupported,
            "{flag} should remain unsupported for installed rch exec"
        );
    }
}

#[test]
fn command_policy_and_no_claim_boundaries_are_explicit() {
    let artifact = json(ARTIFACT_PATH);
    let no_claims = string_set(&artifact, "no_claim_boundaries");
    for boundary in [
        "No release-readiness claim.",
        "No broad workspace-health claim.",
        "No runtime-correctness claim.",
        "No performance-improvement claim.",
        "No live RCH fleet-availability claim.",
        "No local Cargo fallback approval.",
        "No permission to delete files, clean worktrees, create branches, or create worktrees.",
        "No claim that documented clean-overlay flags are available unless installed capability evidence says they are supported.",
    ] {
        assert!(no_claims.contains(boundary), "missing boundary {boundary}");
    }

    let required = string_set(&artifact, "operator_report_required_fields");
    for field in [
        "gate_id",
        "status",
        "head_commit",
        "command_intent",
        "target_dir",
        "selected_paths",
        "capability_probe_version",
        "clean_overlay_supported",
        "missing_flags",
        "capability_findings",
        "rch_worker_or_refusal",
        "retry_condition",
        "no_claim_boundaries",
    ] {
        assert!(required.contains(field), "missing report field {field}");
    }
}

#[test]
fn manifest_and_status_sources_remain_parseable_for_later_signoff() {
    let manifest = json(MANIFEST_PATH);
    let status = json(STATUS_PATH);
    assert!(
        array(&manifest, "lanes").iter().any(|lane| {
            lane["command"]
                .as_str()
                .is_some_and(|command| command.contains("rch exec -- env CARGO_TARGET_DIR"))
        }),
        "manifest should retain RCH-routed proof lanes"
    );
    assert!(
        !array(&status, "claim_categories").is_empty(),
        "proof status snapshot should contain claim category rows"
    );
}
