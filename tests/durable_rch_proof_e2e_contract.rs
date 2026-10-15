//! Deterministic end-to-end contract tests for durable RCH proof submissions.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/durable_rch_proof_e2e_scenarios_v1.json";
const SUBMISSION_SCRIPT: &str = "scripts/durable_rch_proof_submission.py";
const RECEIPT_SCRIPT: &str = "scripts/durable_rch_proof_receipt.py";
const MAIL_TEMPLATE_PATH: &str = "artifacts/durable_rch_proof_mail_templates_v1.json";
const PROOF_STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const RUNBOOK_PATH: &str = "docs/proof_runner_usage.md";

const GENERATED_AT: &str = "2026-06-09T11:30:00Z";
const HEAD: &str = "01a40c0e9a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const LANE_ID: &str = "proof-lane-manifest-contract";
const SOURCE_TREE: &str = "git-tree:01a40c0e9";
const FIXTURE_ROOT: &str = "tests/fixtures/durable_rch_proof_receipt_capture";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contract() -> Value {
    json_file(CONTRACT_PATH)
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

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            let text = entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"));
            assert!(!text.trim().is_empty(), "{key} entries must be nonempty");
            text.to_string()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    string_vec(value, key).into_iter().collect()
}

fn scenario_map(contract: &Value) -> BTreeMap<String, Value> {
    array(contract, "scenarios")
        .iter()
        .map(|scenario| {
            (
                string(scenario, "scenario_id").to_string(),
                scenario.clone(),
            )
        })
        .collect()
}

fn expected(scenario: &Value) -> &Value {
    scenario.get("expected").expect("scenario expected block")
}

fn output_json(output: Output, context: &str) -> Value {
    assert!(
        output.status.success(),
        "{context} failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("{context} emitted invalid JSON: {err}"))
}

fn python_json(script: &str, args: &[String], context: &str) -> Value {
    let output = Command::new("python3")
        .arg(repo_path(script))
        .args(args)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|err| panic!("run {context}: {err}"));
    output_json(output, context)
}

fn write_json_temp(value: &Value) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create JSON temp file");
    serde_json::to_writer_pretty(&mut file, value).expect("write JSON temp file");
    writeln!(file).expect("terminate JSON temp file");
    file
}

fn submission_json(extra_args: &[String]) -> Value {
    let repo = repo_root().display().to_string();
    let mut args = vec![
        "submit".to_string(),
        "--repo-root".to_string(),
        repo,
        "--lane-id".to_string(),
        LANE_ID.to_string(),
        "--agent".to_string(),
        "MistyMill".to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
        "--branch".to_string(),
        "main".to_string(),
        "--head-commit".to_string(),
        HEAD.to_string(),
        "--expected-head".to_string(),
        HEAD.to_string(),
        "--source-tree-fingerprint".to_string(),
        SOURCE_TREE.to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    args.extend(extra_args.iter().cloned());
    python_json(SUBMISSION_SCRIPT, &args, "durable submission helper")
}

fn accepted_submission() -> Value {
    submission_json(&[])["submission"].clone()
}

fn capture_receipt(fixture_name: &str, submission: &Value) -> Value {
    let mut fixture = json_file(&format!("{FIXTURE_ROOT}/{fixture_name}"));
    fixture["submission"] = submission.clone();
    let fixture_file = write_json_temp(&fixture);
    let args = vec![
        "--repo-root".to_string(),
        repo_root().display().to_string(),
        "--fixture".to_string(),
        fixture_file.path().display().to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    python_json(RECEIPT_SCRIPT, &args, "durable receipt helper")
}

fn job_store(
    submissions: Vec<Value>,
    receipts: Vec<Value>,
    cancellations: Vec<Value>,
) -> tempfile::NamedTempFile {
    write_json_temp(&json!({
        "submissions": submissions,
        "receipts": receipts,
        "cancellations": cancellations,
    }))
}

fn cli_json(operation: &str, store: &Path, submission_id: &str, extra_args: &[String]) -> Value {
    let mut args = vec![
        operation.to_string(),
        "--job-store".to_string(),
        store.display().to_string(),
        "--submission-id".to_string(),
        submission_id.to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    args.extend(extra_args.iter().cloned());
    python_json(SUBMISSION_SCRIPT, &args, "durable proof CLI")
}

fn reason_codes(value: &Value) -> BTreeSet<String> {
    string_set(value, "reason_codes")
}

fn status_rows_by_id() -> BTreeMap<String, Value> {
    array(&json_file(PROOF_STATUS_PATH), "durable_receipt_status_rows")
        .iter()
        .map(|row| (string(row, "row_id").to_string(), row.clone()))
        .collect()
}

fn mail_templates_by_id() -> BTreeMap<String, Value> {
    array(&json_file(MAIL_TEMPLATE_PATH), "templates")
        .iter()
        .map(|template| {
            (
                string(template, "template_id").to_string(),
                template.clone(),
            )
        })
        .collect()
}

fn render_matrix(contract: &Value) -> String {
    let mut rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = array(contract, "scenarios")
        .iter()
        .map(|scenario| {
            let expected = expected(scenario);
            (
                string(scenario, "scenario_id").to_string(),
                string(scenario, "kind").to_string(),
                string(expected, "lifecycle_state").to_string(),
                string(expected, "terminal_classification").to_string(),
                string(expected, "proof_evidence_status").to_string(),
                bool_field(expected, "requested_claim_citable").to_string(),
                string(expected, "primary_decision").to_string(),
                string(scenario, "mail_template_id").to_string(),
            )
        })
        .collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));

    let mut table = String::from(
        "| scenario_id | kind | lifecycle_state | terminal_classification | proof_evidence_status | requested_claim_citable | primary_decision | mail_template_id |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for (
        scenario_id,
        kind,
        lifecycle,
        terminal_classification,
        proof_status,
        requested_claim_citable,
        primary_decision,
        mail_template_id,
    ) in rows
    {
        writeln!(
            &mut table,
            "| {scenario_id} | {kind} | {lifecycle} | {terminal_classification} | {proof_status} | {requested_claim_citable} | {primary_decision} | {mail_template_id} |"
        )
        .expect("write matrix row");
    }
    table
}

#[test]
fn corpus_declares_offline_sources_and_required_scenarios() {
    let contract = contract();
    assert_eq!(
        string(&contract, "contract_version"),
        "durable-rch-proof-e2e-scenarios-v1"
    );
    assert_eq!(
        string(&contract, "bead_id"),
        "asupersync-durable-rch-proof-submission-zxnnhe.7"
    );

    let sources = contract.get("source_of_truth").expect("source_of_truth");
    for source_key in [
        "contract",
        "contract_test",
        "submission_cli",
        "receipt_capture_cli",
        "receipt_contract",
        "mail_templates",
        "proof_lane_manifest",
        "proof_status_snapshot",
        "runbook",
    ] {
        let source_path = string(sources, source_key);
        assert!(
            repo_path(source_path).exists(),
            "{source_key} must point at an existing repo path: {source_path}"
        );
    }

    let policy = contract.get("policy").expect("policy");
    for false_field in [
        "network_access_required_for_tests",
        "live_rch_required_for_tests",
        "live_agent_mail_required_for_tests",
        "tracker_mutation_allowed",
        "raw_agent_mail_bodies_allowed",
        "local_fallback_allowed",
    ] {
        assert!(
            !bool_field(policy, false_field),
            "{false_field} must stay disabled for deterministic e2e replay"
        );
    }
    assert!(bool_field(policy, "deterministic_fixture_replay_only"));
    assert_eq!(string(policy, "required_branch"), "main");
    assert_eq!(
        string(policy, "duplicate_policy"),
        "coalesce-identical-lane-head-command"
    );

    let required = string_set(&contract, "required_scenario_ids");
    let actual: BTreeSet<String> = scenario_map(&contract).into_keys().collect();
    assert_eq!(
        actual, required,
        "scenario corpus must exactly match required_scenario_ids"
    );
    assert_eq!(
        string_set(&contract, "required_status_row_ids"),
        BTreeSet::from([
            "durable-receipt-unsupported-broad-claim".to_string(),
            "durable-receipt-wrong-command-envelope".to_string(),
            "durable-receipt-wrong-feature-set".to_string(),
        ])
    );
}

#[test]
fn replayable_receipt_scenarios_match_capture_helpers_and_cli() {
    let contract = contract();
    for scenario in array(&contract, "scenarios") {
        let kind = string(scenario, "kind");
        if kind != "receipt-capture" && kind != "cli-query-policy" {
            continue;
        }

        let expected = expected(scenario);
        let submission = accepted_submission();
        let receipt = capture_receipt(string(scenario, "capture_fixture"), &submission);
        let receipt_citable = receipt["claim_boundaries"]["citable"]
            .as_bool()
            .expect("receipt citable boolean");

        assert_eq!(
            receipt["lifecycle_state"].as_str(),
            Some(string(expected, "lifecycle_state")),
            "{} lifecycle",
            string(scenario, "scenario_id")
        );
        assert_eq!(
            receipt["terminal_classification"].as_str(),
            Some(string(expected, "terminal_classification")),
            "{} terminal classification",
            string(scenario, "scenario_id")
        );
        if kind == "receipt-capture" {
            assert_eq!(
                receipt["proof_evidence_status"].as_str(),
                Some(string(expected, "proof_evidence_status")),
                "{} proof evidence status",
                string(scenario, "scenario_id")
            );
        }
        assert_eq!(
            receipt["outcome"]["status"].as_str(),
            Some(string(expected, "outcome_status")),
            "{} outcome status",
            string(scenario, "scenario_id")
        );
        assert_eq!(
            receipt_citable,
            bool_field(expected, "exact_lane_citable"),
            "{} exact-lane citable flag",
            string(scenario, "scenario_id")
        );
        assert_eq!(
            receipt["manifest_lane_id"].as_str(),
            Some(string(scenario, "manifest_lane_id"))
        );
        assert_eq!(
            receipt["source"]["branch"].as_str(),
            Some("main"),
            "{} must keep source branch on main",
            string(scenario, "scenario_id")
        );
        assert_eq!(
            receipt["command"]["local_fallback_allowed"].as_bool(),
            Some(false),
            "{} must not allow local fallback",
            string(scenario, "scenario_id")
        );

        let blockers = string_vec(&receipt["outcome"], "first_blocker_lines").join("\n");
        for needle in string_vec(expected, "first_blocker_contains") {
            assert!(
                blockers.contains(&needle),
                "{} first blocker must contain {needle:?}; got {blockers:?}",
                string(scenario, "scenario_id")
            );
        }
        if bool_field(expected, "not_cargo_failure") {
            assert_ne!(
                string(expected, "terminal_classification"),
                "cargo_failure",
                "{} should be classified apart from Cargo failure",
                string(scenario, "scenario_id")
            );
        }

        let store = job_store(vec![submission.clone()], vec![receipt], Vec::new());
        let submission_id = string(&submission, "submission_id");
        for assertion in array(scenario, "cli_assertions") {
            let operation = string(assertion, "operation");
            let mut extra = Vec::new();
            if operation == "query" {
                extra.push("--claim".to_string());
                extra.push(string(assertion, "claim").to_string());
            }
            let record = cli_json(operation, store.path(), submission_id, &extra);
            assert_eq!(
                record["decision"].as_str(),
                Some(string(assertion, "expected_decision")),
                "{} {operation} decision",
                string(scenario, "scenario_id")
            );
            assert_eq!(
                record["terminal"].as_bool(),
                Some(bool_field(assertion, "expected_terminal")),
                "{} {operation} terminal flag",
                string(scenario, "scenario_id")
            );
            if let Some(expected_receipt_available) = assertion
                .get("expected_receipt_available")
                .and_then(Value::as_bool)
            {
                assert_eq!(
                    record["receipt_available"].as_bool(),
                    Some(expected_receipt_available),
                    "{} {operation} receipt availability",
                    string(scenario, "scenario_id")
                );
            }
            assert_eq!(
                reason_codes(&record),
                string_set(assertion, "expected_reason_codes"),
                "{} {operation} reason codes",
                string(scenario, "scenario_id")
            );
            if operation == "query" {
                assert_eq!(
                    record["claim_boundaries"]["citable"].as_bool(),
                    Some(bool_field(expected, "requested_claim_citable")),
                    "{} query citable flag",
                    string(scenario, "scenario_id")
                );
            }
        }
    }
}

#[test]
fn submission_refusal_and_duplicate_scenarios_fail_closed_without_rch() {
    let scenarios = scenario_map(&contract());

    for scenario_id in [
        "stale_head_refused_before_execution",
        "dirty_overlap_refused_before_execution",
    ] {
        let scenario = scenarios.get(scenario_id).expect("scenario exists");
        let expected = expected(scenario);
        let record = submission_json(&string_vec(scenario, "submission_args"));
        let submission = record.get("submission").expect("submission");

        assert_eq!(record["decision"].as_str(), Some("refused"));
        assert_eq!(
            submission["lifecycle_state"].as_str(),
            Some(string(expected, "lifecycle_state"))
        );
        assert_eq!(
            submission["terminal_classification"].as_str(),
            Some(string(expected, "terminal_classification"))
        );
        assert_eq!(
            submission["proof_evidence_status"].as_str(),
            Some(string(expected, "proof_evidence_status"))
        );
        assert_eq!(reason_codes(&record), string_set(expected, "reason_codes"));
        assert_eq!(
            submission["execution"]["live_rch_invoked"].as_bool(),
            Some(false),
            "{scenario_id} must fail before invoking RCH"
        );
        assert_eq!(
            submission["execution"]["tracker_mutation_allowed"].as_bool(),
            Some(false),
            "{scenario_id} must not mutate tracker state"
        );
    }

    let duplicate = scenarios
        .get("duplicate_lane_head_coalesced")
        .expect("duplicate scenario");
    let first_record = submission_json(&[]);
    let first_submission = first_record["submission"].clone();
    let existing = write_json_temp(&json!({
        "submissions": [{
            "submission_id": "drps-existing-running",
            "manifest_lane_id": LANE_ID,
            "lifecycle_state": "running",
            "command": {
                "command_fingerprint": first_submission["command"]["command_fingerprint"]
            },
            "source": {
                "expected_head": HEAD
            },
            "lease": {
                "match_key": first_submission["lease"]["match_key"]
            }
        }]
    }));
    let args = vec![
        "--existing-submissions".to_string(),
        existing.path().display().to_string(),
    ];
    let coalesced = submission_json(&args);
    let expected = expected(duplicate);
    assert_eq!(
        coalesced["decision"].as_str(),
        Some(string(expected, "primary_decision"))
    );
    assert_eq!(
        coalesced["submission"]["lifecycle_state"].as_str(),
        Some(string(expected, "lifecycle_state"))
    );
    assert_eq!(
        coalesced["submission"]["lease"]["duplicate_action"].as_str(),
        Some("coalesced-existing-submission")
    );
    assert_eq!(
        coalesced["submission"]["lease"]["existing_submission_id"].as_str(),
        Some("drps-existing-running")
    );
}

#[test]
fn policy_status_rows_are_represented_for_non_replayable_refusals() {
    let contract = contract();
    let rows = status_rows_by_id();
    for scenario in array(&contract, "scenarios") {
        let Some(row_id) = scenario.get("policy_status_row_id").and_then(Value::as_str) else {
            continue;
        };
        let row = rows
            .get(row_id)
            .unwrap_or_else(|| panic!("missing durable status row {row_id}"));
        let expected = expected(scenario);

        assert_eq!(
            row["manifest_lane_id"].as_str(),
            Some(string(scenario, "manifest_lane_id")),
            "{row_id}: manifest lane"
        );
        assert_eq!(
            row["expected_decision"].as_str(),
            Some(string(expected, "primary_decision")),
            "{row_id}: decision"
        );
        assert_eq!(
            row["proof_evidence_status"].as_str(),
            Some(string(expected, "proof_evidence_status")),
            "{row_id}: proof status"
        );
        assert_eq!(
            string_set(row, "reason_codes"),
            string_set(expected, "reason_codes"),
            "{row_id}: refusal reasons"
        );
        assert!(
            string(row, "rerun_command").starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env"),
            "{row_id}: rerun command must remain remote-required"
        );
    }
}

#[test]
fn mail_template_handoff_mapping_never_broadens_scenario_claims() {
    let contract = contract();
    let templates = mail_templates_by_id();
    let policy_non_claims = string_set(
        contract.get("policy").expect("policy"),
        "non_claim_boundaries",
    );

    for scenario in array(&contract, "scenarios") {
        let template_id = string(scenario, "mail_template_id");
        let template = templates
            .get(template_id)
            .unwrap_or_else(|| panic!("missing mail template {template_id}"));
        let expected = expected(scenario);

        assert!(
            !bool_field(template, "broadcast_allowed"),
            "{template_id} must never permit broadcast"
        );
        assert_eq!(
            string_set(template, "claims_forbidden"),
            policy_non_claims,
            "{template_id} forbidden claims must match e2e policy"
        );
        assert!(
            string(template, "body_template").contains("{query_command}"),
            "{template_id} must tell the recipient how to query the durable receipt"
        );

        let template_green = bool_field(template, "may_claim_green_proof");
        if bool_field(expected, "requested_claim_citable") {
            assert!(
                template_green,
                "{} needs the terminal pass closeout template",
                string(scenario, "scenario_id")
            );
            assert_eq!(template_id, "terminal-pass-proof-lane");
        } else {
            assert!(
                !template_green,
                "{} must not use a green-proof mail template",
                string(scenario, "scenario_id")
            );
        }
    }
}

#[test]
fn golden_scenario_matrix_matches_contract_projection() {
    let contract = contract();
    assert_eq!(
        render_matrix(&contract),
        string(&contract, "golden_scenario_matrix_markdown")
    );
}

#[test]
fn runbook_names_e2e_contract_and_no_claim_boundaries() {
    let runbook = read_repo_file(RUNBOOK_PATH);
    for required in [
        CONTRACT_PATH,
        "durable-rch-proof-e2e-scenarios-v1",
        "tests/durable_rch_proof_e2e_contract.rs",
        "Synthetic fixtures do not prove live RCH fleet availability",
        "do not prove release readiness",
        "wrong-feature-set",
        "stale_progress_canceled",
    ] {
        assert!(
            runbook.contains(required),
            "runbook must mention deterministic e2e marker {required:?}"
        );
    }
}
