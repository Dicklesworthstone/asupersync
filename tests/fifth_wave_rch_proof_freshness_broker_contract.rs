#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const ATLAS_PATH: &str = "artifacts/fifth_wave_swarm_control_plane_atlas_v1.json";
const BROKER_PATH: &str = "artifacts/fifth_wave_rch_proof_freshness_broker_v1.json";
const DURABLE_SIGNOFF_PATH: &str = "artifacts/durable_rch_proof_final_signoff_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const RECEIPT_CONTRACT_PATH: &str = "artifacts/durable_rch_proof_receipt_contract_v1.json";
const RUNBOOK_PATH: &str = "docs/proof_runner_usage.md";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const TEST_PATH: &str = "tests/fifth_wave_rch_proof_freshness_broker_contract.rs";

const REQUIRED_STATUSES: &[&str] = &[
    "fresh-rch-pass",
    "failed-rch-test",
    "stale-progress",
    "heartbeat-stale",
    "active-project-exclusion",
    "canceled-owned",
    "canceled-peer-with-handoff",
    "canceled-peer-rch-recommended",
    "local-fallback-refused",
    "zero-test-filter",
    "stale-head",
    "broad-claim-refused",
    "malformed",
];

const PROOF_REFUSAL_RULES: &[&str] = &[
    "stale-progress-not-proof",
    "local-fallback-refused",
    "zero-test-filter-not-proof",
    "narrow-command-refuses-broad-claim",
];

const REQUIRED_DECISIONS: &[&str] = &[
    "cite_green_receipt",
    "wait_for_active_peer",
    "cancel_owned_stale_build",
    "request_peer_handoff",
    "cancel_peer_after_rch_recommendation",
    "record_blocked_without_proof",
];

const REQUIRED_TEMPLATES: &[&str] = &[
    "green-receipt-closeout",
    "wait-for-peer-build",
    "owned-stale-cancel",
    "peer-handoff-request",
    "peer-stale-cancel-notice",
    "blocked-no-local-fallback",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn broker() -> Value {
    serde_json::from_str(&read_repo_file(BROKER_PATH))
        .unwrap_or_else(|error| panic!("parse {BROKER_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, key)
        .iter()
        .map(|row| (string(row, id_key).to_string(), row))
        .collect()
}

fn assert_remote_required_cargo_command(command: &str, target_dir: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "command must be remote-required RCH: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "command must route a focused Cargo test through RCH: {command}"
    );
    assert!(
        command.contains("CARGO_INCREMENTAL=0"),
        "command must disable incremental compilation: {command}"
    );
    assert!(
        command.contains("CARGO_PROFILE_TEST_DEBUG=0"),
        "command must keep test debug output light: {command}"
    );
    assert!(
        command.contains("RUSTFLAGS='-D warnings -C debuginfo=0'"),
        "command must fail warnings and trim debuginfo: {command}"
    );
    assert!(
        command.contains(target_dir),
        "command must contain target dir {target_dir}: {command}"
    );
    assert!(
        target_dir.starts_with("${TMPDIR:-/tmp}/rch_target_fifth_wave_"),
        "target dir must be fifth-wave scoped: {target_dir}"
    );
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "rch exec -- cargo",
        "[RCH] local",
        "local fallback accepted",
    ] {
        assert!(
            !command.contains(forbidden),
            "command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

#[test]
fn broker_declares_sources_remote_contract_lane_and_receipt_schema() {
    let broker = broker();
    assert_eq!(
        string(&broker, "schema_version"),
        "fifth-wave-rch-proof-freshness-broker-v1"
    );
    assert_eq!(
        string(&broker, "bead_id"),
        "asupersync-rch-proof-freshness-broker-u9iy0g"
    );

    let source = object(&broker, "source_of_truth");
    for (key, expected) in [
        ("broker_artifact", BROKER_PATH),
        ("contract_test", TEST_PATH),
        ("swarm_atlas", ATLAS_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("proof_status_snapshot", SNAPSHOT_PATH),
        ("durable_rch_final_signoff", DURABLE_SIGNOFF_PATH),
        ("durable_rch_receipt_contract", RECEIPT_CONTRACT_PATH),
        ("proof_runner_runbook", RUNBOOK_PATH),
        ("agent_instructions", AGENTS_PATH),
        ("readme", README_PATH),
    ] {
        assert_eq!(
            source
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("source_of_truth.{key}")),
            expected
        );
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path must exist: {expected}"
        );
    }

    let lane = &broker["broker_contract_lane"];
    assert_eq!(
        string(lane, "owner_bead"),
        "asupersync-rch-proof-freshness-broker-u9iy0g"
    );
    let envelope = lane
        .get("resource_envelope")
        .unwrap_or_else(|| panic!("broker_contract_lane missing resource_envelope"));
    assert!(bool_field(envelope, "remote_required"));
    assert!(!bool_field(envelope, "local_fallback_allowed"));
    assert!(u64_field(envelope, "timeout_seconds") >= 900);
    assert_remote_required_cargo_command(
        string(lane, "proof_command"),
        string(envelope, "target_dir"),
    );

    let schema = &broker["receipt_schema"];
    for status in REQUIRED_STATUSES {
        assert!(
            string_set(schema, "status_values").contains(*status),
            "missing receipt status {status}"
        );
    }
    for required_field in [
        "rch_build_id",
        "tree_fingerprint",
        "dirty_tree_caveat",
        "progress_age_secs",
        "local_fallback_observed",
        "test_evidence",
        "agent_mail_thread",
    ] {
        assert!(
            string_set(schema, "required_fields").contains(required_field),
            "missing receipt field {required_field}"
        );
    }
    assert_eq!(
        string(schema, "required_remote_prefix"),
        "RCH_REQUIRE_REMOTE=1 rch exec -- env "
    );
}

#[test]
fn classification_rules_refuse_stale_local_zero_test_and_broad_claims() {
    let broker = broker();
    let rules = rows_by_id(&broker, "classification_rules", "rule_id");
    for rule_id in PROOF_REFUSAL_RULES {
        let rule = rules
            .get(*rule_id)
            .unwrap_or_else(|| panic!("missing rule {rule_id}"));
        assert!(
            !bool_field(rule, "proof_allowed"),
            "{rule_id} must not allow proof"
        );
        assert_ne!(
            string(rule, "claim_scope"),
            "exact manifest lane only",
            "{rule_id} cannot cite exact-lane green proof"
        );
        assert!(
            string_set(rule, "required_conditions").len() >= 2,
            "{rule_id} must document refusal conditions"
        );
    }

    let fresh = rules
        .get("fresh-remote-pass")
        .expect("fresh-remote-pass rule");
    assert!(bool_field(fresh, "proof_allowed"));
    assert_eq!(string(fresh, "claim_scope"), "exact manifest lane only");
    let fresh_conditions = string_set(fresh, "required_conditions");
    for condition in [
        "remote_observed=true",
        "local_fallback_observed=false",
        "exit_code=0",
        "test_evidence is nonzero",
        "command maps exactly to manifest_lane_id",
    ] {
        assert!(
            fresh_conditions.contains(condition),
            "fresh rule missing {condition}"
        );
    }
}

#[test]
fn operator_decisions_and_mail_templates_encode_peer_cancel_discipline() {
    let broker = broker();
    let decisions = rows_by_id(&broker, "operator_decision_table", "decision");
    for decision_id in REQUIRED_DECISIONS {
        let row = decisions
            .get(*decision_id)
            .unwrap_or_else(|| panic!("missing decision {decision_id}"));
        assert!(!string(row, "when").trim().is_empty());
        assert!(
            REQUIRED_TEMPLATES.contains(&string(row, "mail_template_id")),
            "{decision_id} must map to a known mail template"
        );
    }

    let wait = decisions
        .get("wait_for_active_peer")
        .expect("wait_for_active_peer");
    assert!(bool_field(wait, "allowed_for_peer_builds"));
    assert!(bool_field(wait, "requires_agent_mail"));
    assert!(string(wait, "when").contains("fresh progress"));

    let peer_cancel = decisions
        .get("cancel_peer_after_rch_recommendation")
        .expect("cancel_peer_after_rch_recommendation");
    assert!(bool_field(peer_cancel, "allowed_for_peer_builds"));
    assert!(bool_field(peer_cancel, "requires_agent_mail"));
    assert!(string(peer_cancel, "when").contains("RCH status recommends"));
    assert!(string(peer_cancel, "when").contains("build id"));

    let templates = rows_by_id(&broker, "agent_mail_templates", "template_id");
    for template_id in REQUIRED_TEMPLATES {
        let template = templates
            .get(*template_id)
            .unwrap_or_else(|| panic!("missing mail template {template_id}"));
        assert!(
            string(template, "subject").contains("[{bead_id}]")
                || string(template, "subject").contains("RCH")
        );
        assert!(
            string_set(template, "required_body_tokens").len() >= 4,
            "{template_id} must specify concrete body tokens"
        );
    }

    let cancel_notice = templates
        .get("peer-stale-cancel-notice")
        .expect("peer-stale-cancel-notice");
    let cancel_tokens = string_set(cancel_notice, "required_body_tokens");
    for token in [
        "active_build_id",
        "RCH recommended cancel",
        "will not touch source files",
        "next proof command",
    ] {
        assert!(
            cancel_tokens.contains(token),
            "cancel template missing {token}"
        );
    }
}

#[test]
fn failure_fixtures_and_non_claims_fail_closed() {
    let broker = broker();
    let fixtures = rows_by_id(&broker, "failure_fixtures", "fixture_id");
    for fixture_id in [
        "stale-progress-claimed-green",
        "local-fallback-accepted",
        "zero-test-green",
        "narrow-proof-release-claim",
        "peer-cancel-without-notice",
    ] {
        let fixture = fixtures
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing fixture {fixture_id}"));
        assert_eq!(string(fixture, "expected_verdict"), "fail_closed");
        assert!(!string(fixture, "expected_reason").trim().is_empty());
    }

    let non_claims = string_set(&broker, "non_claims");
    for required in [
        "does not prove release readiness",
        "does not prove broad workspace health",
        "does not prove live RCH fleet availability",
        "does not implement RCH daemon scheduling",
        "does not prove performance improvement",
        "does not prove no regression",
        "does not authorize local Cargo fallback",
        "does not implement fourth-wave runtime admission control",
    ] {
        assert!(
            non_claims.contains(required),
            "missing non-claim {required}"
        );
    }

    for requirement in array(&broker, "closeout_requirements") {
        let text = requirement
            .as_str()
            .expect("closeout_requirements entries must be strings");
        assert!(!text.trim().is_empty(), "closeout requirement is empty");
    }
}
