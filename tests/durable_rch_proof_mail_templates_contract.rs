#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/durable_rch_proof_mail_templates_v1.json";
const CONTRACT_TEST_PATH: &str = "tests/durable_rch_proof_mail_templates_contract.rs";
const RUNBOOK_PATH: &str = "docs/proof_runner_usage.md";

const EXPECTED_TEMPLATE_IDS: &[&str] = &[
    "canceled-yielded-proof-lane",
    "handoff-to-next-agent",
    "running-proof-lane",
    "stale-proof-lane",
    "submitted-proof-lane",
    "terminal-fail-proof-lane",
    "terminal-pass-proof-lane",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contract() -> Value {
    json(CONTRACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
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
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            let text = item
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"));
            assert!(!text.trim().is_empty(), "{key} entries must be nonempty");
            text.to_string()
        })
        .collect()
}

fn expected_template_ids() -> BTreeSet<String> {
    EXPECTED_TEMPLATE_IDS
        .iter()
        .map(|template_id| (*template_id).to_string())
        .collect()
}

fn render_template_projection(contract: &Value) -> String {
    let mut rows: Vec<(String, String, String, String, String)> = array(contract, "templates")
        .iter()
        .map(|template| {
            (
                string(template, "template_id").to_string(),
                string(template, "lifecycle_state").to_string(),
                string(template, "proof_evidence_status").to_string(),
                bool_field(template, "may_claim_green_proof").to_string(),
                string(template, "operator_action").to_string(),
            )
        })
        .collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));

    let mut markdown = String::from(
        "| template_id | lifecycle_state | proof_evidence_status | may_claim_green_proof | operator_action |\n| --- | --- | --- | --- | --- |\n",
    );
    for (template_id, lifecycle, proof_status, may_claim, operator_action) in rows {
        writeln!(
            &mut markdown,
            "| {template_id} | {lifecycle} | {proof_status} | {may_claim} | {operator_action} |"
        )
        .expect("write template markdown row");
    }
    markdown
}

#[test]
fn contract_declares_offline_targeted_agent_mail_policy() {
    let contract = contract();
    assert_eq!(
        string(&contract, "contract_version"),
        "durable-rch-proof-mail-templates-v1"
    );
    assert_eq!(
        string(&contract, "bead_id"),
        "asupersync-durable-rch-proof-submission-zxnnhe.6"
    );

    let sources = contract.get("source_of_truth").expect("source_of_truth");
    for source_key in [
        "contract",
        "contract_test",
        "runbook",
        "submission_cli",
        "receipt_contract",
        "proof_lane_manifest",
        "proof_status_snapshot",
    ] {
        let source_path = string(sources, source_key);
        assert!(
            repo_path(source_path).is_file(),
            "{source_key} source path must exist: {source_path}"
        );
    }
    assert_eq!(string(sources, "contract"), CONTRACT_PATH);
    assert_eq!(string(sources, "contract_test"), CONTRACT_TEST_PATH);
    assert_eq!(string(sources, "runbook"), RUNBOOK_PATH);

    let policy = contract.get("policy").expect("policy");
    for false_field in [
        "network_access_required_for_tests",
        "live_agent_mail_required_for_tests",
        "tracker_mutation_allowed",
        "broadcast_allowed",
        "raw_agent_mail_bodies_allowed",
    ] {
        assert!(
            !bool_field(policy, false_field),
            "{false_field} must stay disabled for deterministic template tests"
        );
    }
    assert!(
        string(policy, "required_query_command_prefix")
            .starts_with("python3 scripts/durable_rch_proof_submission.py query"),
        "query command prefix must route operators to the durable proof CLI"
    );
    assert!(
        string(policy, "targeting_rule").contains("Do not broadcast."),
        "targeting rule must reject broadcast handoffs"
    );

    let boundaries = string_set(policy, "non_claim_boundaries");
    assert_eq!(
        boundaries,
        BTreeSet::from([
            "live-rch-fleet-availability".to_string(),
            "release-readiness".to_string(),
            "unrelated-proof-lanes".to_string(),
            "workspace-health".to_string(),
        ])
    );
}

#[test]
fn every_template_has_required_fields_placeholders_and_claim_boundaries() {
    let contract = contract();
    let templates = array(&contract, "templates");
    let required_fields = string_set(&contract, "required_template_fields");
    let required_placeholders = string_set(&contract, "required_placeholders");
    let non_claim_boundaries = string_set(
        contract.get("policy").expect("policy"),
        "non_claim_boundaries",
    );
    let template_ids: BTreeSet<String> = templates
        .iter()
        .map(|template| string(template, "template_id").to_string())
        .collect();
    assert_eq!(template_ids, expected_template_ids());

    for template in templates {
        let template_id = string(template, "template_id");
        for field in &required_fields {
            assert!(
                template.get(field).is_some(),
                "{template_id}: missing required template field {field}"
            );
        }

        assert_eq!(
            string_set(template, "required_placeholders"),
            required_placeholders,
            "{template_id}: template placeholders must match the contract-level set exactly"
        );
        assert!(
            !bool_field(template, "broadcast_allowed"),
            "{template_id}: templates must not permit broadcast sends"
        );
        assert_eq!(
            string_set(template, "claims_forbidden"),
            non_claim_boundaries,
            "{template_id}: forbidden claims must match policy boundaries"
        );
        assert!(
            !array(template, "claims_allowed").is_empty(),
            "{template_id}: each template should name its narrow allowed claim"
        );

        let subject = string(template, "subject_template");
        assert!(
            subject.contains("{manifest_lane_id}") && subject.contains("{durable_submission_id}"),
            "{template_id}: subject must identify the manifest lane and durable submission"
        );

        let body = string(template, "body_template");
        for placeholder in &required_placeholders {
            assert!(
                body.contains(placeholder),
                "{template_id}: body must include placeholder {placeholder}"
            );
        }
    }
}

#[test]
fn only_terminal_pass_template_can_claim_exact_fresh_rch_pass() {
    let contract = contract();
    let green_phrases = string_set(
        contract.get("policy").expect("policy"),
        "green_proof_phrases",
    );

    for template in array(&contract, "templates") {
        let template_id = string(template, "template_id");
        let lifecycle = string(template, "lifecycle_state");
        let terminal_classification = string(template, "terminal_classification");
        let proof_status = string(template, "proof_evidence_status");
        let may_claim_green = bool_field(template, "may_claim_green_proof");
        let body = string(template, "body_template").to_ascii_lowercase();

        if template_id == "terminal-pass-proof-lane" {
            assert!(may_claim_green, "terminal pass must be citeable");
            assert_eq!(lifecycle, "terminal_pass");
            assert_eq!(terminal_classification, "pass");
            assert_eq!(proof_status, "fresh-rch-pass");
            assert!(
                body.contains("cite only the exact manifest lane"),
                "terminal pass body must keep proof scope narrow"
            );
        } else {
            assert!(
                !may_claim_green,
                "{template_id}: non-pass templates cannot claim green proof"
            );
            assert_ne!(
                proof_status, "fresh-rch-pass",
                "{template_id}: non-pass templates cannot use fresh-rch-pass status"
            );
            for phrase in &green_phrases {
                assert!(
                    !body.contains(phrase),
                    "{template_id}: non-pass body contains green proof phrase {phrase}"
                );
            }
        }
    }
}

#[test]
fn templates_do_not_use_broadcast_spam_or_raw_mail_body_language() {
    let contract = contract();
    let forbidden_broadcast_phrases = string_set(
        contract.get("policy").expect("policy"),
        "forbidden_broadcast_phrases",
    );
    let raw_body_markers = BTreeSet::from([
        "raw_body".to_string(),
        "raw_agent_mail_body".to_string(),
        "body_md_raw".to_string(),
    ]);

    for template in array(&contract, "templates") {
        let template_id = string(template, "template_id");
        for marker in &raw_body_markers {
            assert!(
                template.get(marker).is_none(),
                "{template_id}: raw mail body field {marker} must not be present"
            );
        }
        for field in [
            "subject_template",
            "body_template",
            "operator_action",
            "lane_ownership_rule",
        ] {
            let text = string(template, field).to_ascii_lowercase();
            for phrase in &forbidden_broadcast_phrases {
                assert!(
                    !text.contains(phrase),
                    "{template_id}: {field} contains forbidden broadcast phrase {phrase}"
                );
            }
        }
    }
}

#[test]
fn golden_markdown_projection_matches_contract() {
    let contract = contract();
    assert_eq!(
        render_template_projection(&contract),
        string(&contract, "golden_markdown")
    );
}

#[test]
fn runbook_references_template_contract_and_no_claim_boundaries() {
    let runbook = read_repo_file(RUNBOOK_PATH);
    for needle in [
        CONTRACT_PATH,
        CONTRACT_TEST_PATH,
        "durable-rch-proof-mail-templates-v1",
        "Do not broadcast",
        "release-readiness",
        "workspace-health",
        "live-rch-fleet-availability",
    ] {
        assert!(runbook.contains(needle), "runbook missing {needle}");
    }

    for template_id in EXPECTED_TEMPLATE_IDS {
        assert!(
            runbook.contains(template_id),
            "runbook must list template {template_id}"
        );
    }
}
