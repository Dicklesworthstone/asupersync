#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/agent_swarm_coordination_redaction_contract.md";
const ARTIFACT_PATH: &str = "artifacts/agent_swarm_coordination_redaction_contract_v1.json";
const WORKLOAD_ARTIFACT_PATH: &str = "artifacts/agent_swarm_coordination_workload_contract_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_path(DOC_PATH)).expect("read redaction contract doc")
}

fn load_json(relative: &str) -> Value {
    let raw = std::fs::read_to_string(repo_path(relative)).expect("read json artifact");
    serde_json::from_str(&raw).expect("parse json artifact")
}

fn contract() -> Value {
    load_json(ARTIFACT_PATH)
}

fn string_array<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
        })
        .collect()
}

#[test]
fn doc_references_artifact_test_and_source_workload_contract() {
    let doc = load_doc();
    for expected in [
        "asupersync-qn8i0p.6",
        ARTIFACT_PATH,
        "tests/agent_swarm_coordination_redaction_contract.rs",
        "docs/agent_swarm_coordination_workload_contract.md",
        WORKLOAD_ARTIFACT_PATH,
    ] {
        assert!(doc.contains(expected), "doc must reference {expected}");
    }

    for section in [
        "Purpose",
        "Contract Artifact",
        "Redaction Classes",
        "Trust Levels",
        "Pseudonymization",
        "Privacy Report",
        "Validation",
        "Cross-References",
    ] {
        assert!(doc.contains(section), "doc missing section {section}");
    }

    assert!(
        doc.contains(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_redaction cargo test -p asupersync --test agent_swarm_coordination_redaction_contract -- --nocapture"
        ),
        "doc must publish the focused remote-required rch validation command"
    );
    assert!(
        doc.contains("RCH_REQUIRE_REMOTE=1 rch exec -- env"),
        "doc must require remote rch and preserve env routing"
    );
    assert!(
        doc.contains(
            "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_redaction"
        ),
        "doc must isolate Cargo target dir for the focused proof"
    );
    assert!(
        !doc.contains("rch exec -- cargo"),
        "doc must not publish bare rch Cargo routing"
    );
}

#[test]
fn artifact_links_to_source_workload_contract_and_versions() {
    let redaction = contract();
    let workload = load_json(WORKLOAD_ARTIFACT_PATH);

    assert_eq!(
        redaction.get("contract_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-redaction-contract-v1")
    );
    assert_eq!(
        redaction.get("schema_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-redaction-report-v1")
    );
    assert_eq!(
        redaction.get("bead_id").and_then(Value::as_str),
        Some("asupersync-qn8i0p.6")
    );
    assert_eq!(
        redaction
            .get("source_workload_contract")
            .and_then(Value::as_str),
        workload.get("contract_version").and_then(Value::as_str)
    );
    assert_eq!(
        redaction
            .get("source_workload_artifact")
            .and_then(Value::as_str),
        Some(WORKLOAD_ARTIFACT_PATH)
    );
}

#[test]
fn redaction_classes_cover_required_privacy_surfaces() {
    let contract = contract();
    let classes = contract["redaction_classes"]
        .as_array()
        .expect("redaction_classes array");
    let class_names: BTreeSet<_> = classes
        .iter()
        .map(|class| class["class"].as_str().expect("class string"))
        .collect();

    let expected = BTreeSet::from([
        "absolute_local_path",
        "agent_identity",
        "api_key",
        "attachment_reference",
        "bearer_token",
        "command_env_var",
        "email_identifier",
        "git_remote_url",
        "github_token",
        "hostname",
        "malformed_redaction_metadata",
        "message_body",
        "secret_like",
        "ssh_path",
        "worker_metadata",
    ]);
    assert_eq!(class_names, expected);

    for class in classes {
        assert!(
            class["default_action"]
                .as_str()
                .is_some_and(|action| !action.is_empty()),
            "each class must declare an action"
        );
        assert!(
            class["refusal_reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "each class must declare a refusal reason"
        );
    }
}

#[test]
fn trust_levels_fail_closed_for_unknown_inputs() {
    let contract = contract();
    let trust_levels = contract["trust_levels"]
        .as_array()
        .expect("trust_levels array");
    let mut seen = BTreeSet::new();
    for level in trust_levels {
        let name = level["trust_level"].as_str().expect("trust level string");
        seen.insert(name);
        assert_eq!(
            level["requires_redaction_report"].as_bool(),
            Some(true),
            "trust level {name} must require a report"
        );
        if name == "unknown" {
            assert_eq!(
                level["accepted_for_replay"].as_bool(),
                Some(false),
                "unknown inputs can only fail closed"
            );
        }
    }

    assert_eq!(
        seen,
        BTreeSet::from([
            "explicit_export",
            "fixture_checked",
            "live_command_output",
            "metadata_only",
            "unknown",
        ])
    );
}

#[test]
fn detector_fixtures_cover_acceptance_surface_and_expected_actions() {
    let contract = contract();
    let class_actions: BTreeMap<_, _> = contract["redaction_classes"]
        .as_array()
        .expect("redaction classes")
        .iter()
        .map(|class| {
            (
                class["class"].as_str().expect("class"),
                class["default_action"].as_str().expect("action"),
            )
        })
        .collect();

    let fixtures = contract["detector_fixtures"]
        .as_array()
        .expect("detector fixtures array");
    let fixture_classes: BTreeSet<_> = fixtures
        .iter()
        .map(|fixture| fixture["class"].as_str().expect("fixture class"))
        .collect();
    let class_names: BTreeSet<_> = class_actions.keys().copied().collect();
    assert_eq!(
        fixture_classes, class_names,
        "every redaction class must have a fixture"
    );

    for fixture in fixtures {
        let class = fixture["class"].as_str().expect("fixture class");
        let action = fixture["expected_action"]
            .as_str()
            .expect("expected action");
        let expected_action = class_actions
            .get(class)
            .unwrap_or_else(|| panic!("fixture class {class} must be declared"));
        assert_eq!(
            action, *expected_action,
            "fixture {class} should use class default action"
        );
        let input = fixture["synthetic_input"]
            .as_str()
            .expect("synthetic input string");
        assert!(
            !input.contains("sk-")
                && !input.contains("xoxb-")
                && !input.contains("BEGIN OPENSSH PRIVATE KEY"),
            "fixtures must use synthetic sentinels, not live-looking credentials"
        );
        let refusal = fixture["refusal_reason"].as_str().expect("refusal reason");
        if action == "refuse" {
            assert!(!refusal.is_empty(), "refused fixtures need a reason");
            assert!(
                fixture["expected_output"]
                    .as_str()
                    .unwrap_or_default()
                    .is_empty(),
                "refused fixtures must not retain raw output"
            );
        }
    }
}

#[test]
fn pseudonymization_fixtures_are_stable_and_namespaced() {
    let contract = contract();
    let fixtures = contract["detector_fixtures"]
        .as_array()
        .expect("detector fixtures array");
    let mut by_input_and_class = BTreeMap::new();
    let mut outputs = BTreeMap::new();

    for fixture in fixtures {
        let action = fixture["expected_action"].as_str().expect("action");
        if action != "pseudonymize" {
            continue;
        }
        let class = fixture["class"].as_str().expect("class");
        let input = fixture["synthetic_input"].as_str().expect("input");
        let output = fixture["expected_output"].as_str().expect("output");
        let key = (class, input);
        if let Some(previous) = by_input_and_class.insert(key, output) {
            assert_eq!(
                previous, output,
                "same class and normalized input must produce the same pseudonym"
            );
        }
        outputs.insert(output, class);
        let prefixes = &contract["pseudonymization"]["output_prefixes"];
        let expected_prefix = prefixes
            .get(class)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing prefix for {class}"));
        assert!(
            output.starts_with(expected_prefix),
            "pseudonym {output} should use class prefix {expected_prefix}"
        );
    }

    assert!(
        outputs.len() >= 5,
        "fixtures should cover multiple pseudonym namespaces"
    );
}

#[test]
fn privacy_reports_include_counts_hashes_refusals_and_verdicts() {
    let contract = contract();
    let required = string_array(&contract, "privacy_report_required_fields");
    let reports = contract["sample_privacy_reports"]
        .as_array()
        .expect("sample privacy reports");
    let mut verdicts = BTreeSet::new();

    for report in reports {
        for field in &required {
            assert!(
                report.get(*field).is_some(),
                "privacy report missing {field}"
            );
        }

        let verdict = report["privacy_verdict"]
            .as_str()
            .expect("privacy verdict string");
        verdicts.insert(verdict);
        let source_hashes = report["source_hashes"]
            .as_array()
            .expect("source hashes array");
        assert!(
            !source_hashes.is_empty(),
            "reports must preserve source hashes"
        );
        let retained = report["retained_field_summary"]
            .as_array()
            .expect("retained summary array");
        assert!(
            !retained.is_empty(),
            "reports must explain retained field shapes"
        );

        if verdict == "pass" {
            assert_eq!(report["refused_event_count"].as_u64(), Some(0));
            assert!(
                report["refusal_reasons"]
                    .as_array()
                    .expect("refusal reasons")
                    .is_empty(),
                "passing reports must not carry refusal reasons"
            );
        } else {
            assert!(
                report["refused_event_count"].as_u64().unwrap_or_default() > 0,
                "non-pass reports need refused events"
            );
            assert!(
                !report["refusal_reasons"]
                    .as_array()
                    .expect("refusal reasons")
                    .is_empty(),
                "non-pass reports need refusal reasons"
            );
        }
    }

    assert_eq!(verdicts, BTreeSet::from(["fail_closed", "pass"]));
}

#[test]
fn escape_hatches_are_disabled_by_default_and_test_bound() {
    let contract = contract();
    let escape_hatches = contract["escape_hatches"]
        .as_object()
        .expect("escape hatches object");
    for (name, hatch) in escape_hatches {
        assert_eq!(
            hatch["enabled_by_default"].as_bool(),
            Some(false),
            "{name} must be disabled by default"
        );
        assert_eq!(
            hatch["requires_explicit_operator_flag"].as_bool(),
            Some(true),
            "{name} must require explicit operator intent"
        );
        assert_eq!(
            hatch["requires_test_fixture"].as_bool(),
            Some(true),
            "{name} must be test-covered"
        );
        assert!(
            hatch["refusal_when_absent"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{name} must fail closed when not enabled"
        );
    }
}
