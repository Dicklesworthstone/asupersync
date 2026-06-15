//! Contract tests for PROOF-TRAFFIC A5 blocked proof-loop e2e.
//!
//! The e2e is deterministic fixture composition. Live RCH state may be attached
//! as operator evidence, but correctness comes from the checked fixture packet.

#![allow(missing_docs)]

use asupersync::audit::proof_traffic_blocked_loop_e2e::{
    PROOF_TRAFFIC_BLOCKED_LOOP_E2E_ID, PROOF_TRAFFIC_BLOCKED_LOOP_E2E_SCHEMA_VERSION,
    PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY, PROOF_TRAFFIC_BLOCKED_LOOP_PEER_POISON,
    proof_traffic_blocked_loop_fixture,
};
use asupersync::audit::proof_traffic_receipt::ProofTrafficDecision;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/proof_traffic_blocked_loop_e2e_v1.json";
const DOCS_PATH: &str = "docs/proof_traffic_control.md";

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

#[test]
fn fixtures_cover_blocked_loop_decisions() {
    let scenario = proof_traffic_blocked_loop_fixture();
    assert_eq!(
        scenario.schema_version,
        PROOF_TRAFFIC_BLOCKED_LOOP_E2E_SCHEMA_VERSION
    );
    assert_eq!(scenario.scenario_id, PROOF_TRAFFIC_BLOCKED_LOOP_E2E_ID);

    let decisions = scenario
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step.decision))
        .collect::<Vec<_>>();
    assert_eq!(
        decisions,
        vec![
            ("owned-dirty-admitted-control", ProofTrafficDecision::RunNow),
            ("peer-poison-excluded", ProofTrafficDecision::BlockedByPeer),
            (
                "missing-overlay-capability",
                ProofTrafficDecision::BlockedByCapabilityDrift,
            ),
            (
                "active-project-refusal",
                ProofTrafficDecision::ParkRerunRequired,
            ),
            (
                "progress-stale-peer-build",
                ProofTrafficDecision::BlockedByPeer,
            ),
        ]
    );

    let admitted = scenario.admitted_commands();
    assert_eq!(admitted.len(), 1);
    assert!(admitted[0].contains("RCH_REQUIRE_REMOTE=1"));
    assert!(admitted[0].contains("--clean-overlay"));
    assert!(admitted[0].contains(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY));
}

#[test]
fn structured_logs_include_required_fields() {
    let scenario = proof_traffic_blocked_loop_fixture();
    for step in &scenario.steps {
        assert!(!step.input_command.trim().is_empty(), "input command");
        assert!(!step.selected_paths.is_empty(), "selected paths");
        assert!(!step.reservation_state.trim().is_empty(), "reservation");
        assert!(!step.queue_snapshot.trim().is_empty(), "queue snapshot");
        assert!(!step.rendered_handoff.trim().is_empty(), "handoff");
        assert!(
            step.rendered_handoff
                .contains("local_cargo_fallback_allowed: `false`"),
            "handoff should carry local fallback denial"
        );
        assert!(
            step.no_claim_boundary
                .contains("No local Cargo fallback approval"),
            "no-claim boundary"
        );
        assert!(
            !step.replay_or_resume_command.trim().is_empty(),
            "resume command"
        );
    }

    assert!(scenario.steps.iter().any(|step| {
        step.queue_snapshot
            .contains("active_project_exclusion=true")
    }));
    assert!(
        scenario
            .steps
            .iter()
            .any(|step| step.queue_snapshot.contains("progress_stale=true"))
    );
}

#[test]
fn admitted_commands_exclude_peer_poison_and_forbidden_fallbacks() {
    let scenario = proof_traffic_blocked_loop_fixture();
    assert!(
        scenario.forbidden_admitted_command_tokens().is_empty(),
        "forbidden tokens leaked: {:?}",
        scenario.forbidden_admitted_command_tokens()
    );
    assert!(!scenario.uses_local_cargo_fallback());
    assert!(
        scenario.peer_poison_paths_in_admitted_commands().is_empty(),
        "peer poison leaked into admitted commands"
    );

    let report = scenario.render_markdown();
    assert!(report.contains(PROOF_TRAFFIC_BLOCKED_LOOP_PEER_POISON));
    for command in scenario.admitted_commands() {
        assert!(!command.contains(PROOF_TRAFFIC_BLOCKED_LOOP_PEER_POISON));
        assert!(!command.contains("git branch"));
        assert!(!command.contains("git worktree"));
        assert!(!command.contains("git clone"));
        assert!(!command.contains("git clean"));
        assert!(!command.contains("git reset"));
        assert!(!command.contains("rm -"));
    }
}

#[test]
fn artifact_bundle_contains_json_markdown_agent_mail_br_and_resume() {
    let scenario = proof_traffic_blocked_loop_fixture();
    let bundle = &scenario.artifact_bundle;

    let json_receipt = serde_json::to_value(&bundle.json_receipt).expect("json receipt");
    assert_eq!(
        json_receipt["schema_version"].as_str(),
        Some("proof-traffic-parking-lot-v1")
    );
    assert_eq!(
        json_receipt["attempts"].as_array().expect("attempts").len(),
        4
    );

    for body in [
        &bundle.markdown_report,
        &bundle.agent_mail_body,
        &bundle.br_comment_body,
        &bundle.replay_resume_command,
    ] {
        assert!(!body.trim().is_empty(), "bundle body");
    }
    assert!(
        bundle
            .markdown_report
            .contains("Proof-traffic blocked-loop e2e")
    );
    assert!(
        bundle
            .agent_mail_body
            .contains("proof_traffic_blocked_loop_e2e")
    );
    assert!(
        bundle
            .br_comment_body
            .contains("Proof-traffic blocked-loop e2e")
    );
    assert!(bundle.replay_resume_command.starts_with("# PARKED"));
}

#[test]
fn serde_roundtrip_preserves_scenario_and_reports() {
    let scenario = proof_traffic_blocked_loop_fixture();
    let encoded = serde_json::to_string(&scenario).expect("serialize scenario");
    let decoded = serde_json::from_str(&encoded).expect("deserialize scenario");
    assert_eq!(scenario, decoded);
    assert_eq!(scenario.render_markdown(), decoded.render_markdown());
    assert_eq!(scenario.agent_mail_body(), decoded.agent_mail_body());
    assert_eq!(scenario.br_comment_body(), decoded.br_comment_body());
}

#[test]
fn artifact_and_docs_pin_a5_contract_scope() {
    let artifact = json(ARTIFACT_PATH);
    assert_eq!(
        string_field(&artifact, "schema_version"),
        "proof-traffic-blocked-loop-e2e-v1"
    );
    assert_eq!(
        string_field(&artifact, "bead_id"),
        PROOF_TRAFFIC_BLOCKED_LOOP_E2E_ID
    );
    assert_eq!(string_field(&artifact, "status"), "contract_guarded");

    for path in [
        string_field(&artifact["source_of_truth"], "artifact"),
        string_field(&artifact["source_of_truth"], "operator_doc"),
        string_field(&artifact["source_of_truth"], "contract_test"),
        string_field(&artifact["source_of_truth"], "rust_module"),
        string_field(&artifact["source_of_truth"], "admission_module"),
        string_field(&artifact["source_of_truth"], "overlay_handshake_module"),
        string_field(&artifact["source_of_truth"], "parking_lot_module"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    let fixtures = string_set(&artifact, "required_fixture_coverage");
    for fixture in [
        "owned-dirty-path",
        "peer-poison-path",
        "missing-overlay-capability",
        "active-project-refusal",
        "progress-stale-peer-build",
        "admitted-command-positive-control",
    ] {
        assert!(fixtures.contains(fixture), "missing fixture {fixture}");
    }

    let fields = string_set(&artifact, "required_structured_log_fields");
    for field in [
        "input_command",
        "selected_paths",
        "reservation_state",
        "queue_snapshot",
        "decision",
        "rendered_handoff",
        "no_claim_boundary",
        "replay_or_resume_command",
    ] {
        assert!(fields.contains(field), "missing field {field}");
    }

    let docs = read_repo_file(DOCS_PATH);
    for needle in [
        "Proof-Traffic A5 Blocked-Loop E2E",
        "artifacts/proof_traffic_blocked_loop_e2e_v1.json",
        "tests/proof_traffic_blocked_loop_e2e_contract.rs",
        "owned dirty path",
        "peer poison path",
        "missing overlay capability",
        "active-project refusal",
        "progress-stale peer build",
        "deterministic fixtures are the correctness source",
    ] {
        assert!(docs.contains(needle), "docs missing {needle}");
    }
}
