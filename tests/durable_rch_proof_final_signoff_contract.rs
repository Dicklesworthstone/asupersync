#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const E2E_PATH: &str = "artifacts/durable_rch_proof_e2e_scenarios_v1.json";
const MAIL_TEMPLATE_PATH: &str = "artifacts/durable_rch_proof_mail_templates_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const RECEIPT_CONTRACT_PATH: &str = "artifacts/durable_rch_proof_receipt_contract_v1.json";
const RUNBOOK_PATH: &str = "docs/proof_runner_usage.md";
const SIGNOFF_PATH: &str = "artifacts/durable_rch_proof_final_signoff_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const TEST_PATH: &str = "tests/durable_rch_proof_final_signoff_contract.rs";

const CHILD_BEADS: &[&str] = &[
    "asupersync-durable-rch-proof-submission-zxnnhe.1",
    "asupersync-durable-rch-proof-submission-zxnnhe.2",
    "asupersync-durable-rch-proof-submission-zxnnhe.3",
    "asupersync-durable-rch-proof-submission-zxnnhe.4",
    "asupersync-durable-rch-proof-submission-zxnnhe.5",
    "asupersync-durable-rch-proof-submission-zxnnhe.6",
    "asupersync-durable-rch-proof-submission-zxnnhe.7",
];

#[derive(Debug, Clone, Eq, PartialEq)]
struct ReportRow {
    row_id: String,
    owner_bead: String,
    proof_command_id: String,
    rch_build_id: String,
    evidence_status: String,
    artifact_hashes: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct OperatorReport {
    final_verdict: String,
    first_failing_row: Option<String>,
    rows: Vec<ReportRow>,
    markdown: String,
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

fn signoff() -> Value {
    json(SIGNOFF_PATH)
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

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn manifest_guarantees(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_string(),
                guarantee.clone(),
            )
        })
        .collect()
}

fn snapshot_claims(snapshot: &Value) -> BTreeMap<String, Value> {
    array(snapshot, "claim_categories")
        .iter()
        .map(|claim| (string(claim, "claim_id").to_string(), claim.clone()))
        .collect()
}

fn e2e_scenarios(e2e: &Value) -> BTreeMap<String, Value> {
    array(e2e, "scenarios")
        .iter()
        .map(|scenario| {
            (
                string(scenario, "scenario_id").to_string(),
                scenario.clone(),
            )
        })
        .collect()
}

fn mail_templates(templates: &Value) -> BTreeMap<String, Value> {
    array(templates, "templates")
        .iter()
        .map(|template| {
            (
                string(template, "template_id").to_string(),
                template.clone(),
            )
        })
        .collect()
}

fn assert_contains_all(label: &str, text: &str, markers: &[&str]) {
    for marker in markers {
        assert!(text.contains(marker), "{label} missing {marker}");
    }
}

fn assert_remote_required_cargo(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "command must be remote-required RCH: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_durable_rch"),
        "command must isolate a durable RCH target dir: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "command must route a focused Cargo test through RCH: {command}"
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
            "command contains forbidden local/fallback marker {forbidden}: {command}"
        );
    }
}

fn sha256_file(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("hash input {relative}: {error}"));
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn render_report(signoff: &Value) -> OperatorReport {
    let required_status = string(
        &signoff["freshness_policy"],
        "required_child_evidence_status",
    );
    let rows = array(signoff, "required_child_rows")
        .iter()
        .map(|row| {
            let mut artifact_paths = string_set(row, "artifact_paths")
                .into_iter()
                .collect::<Vec<_>>();
            artifact_paths.sort();
            let artifact_hashes = artifact_paths
                .iter()
                .map(|path| format!("{path}:sha256={}", sha256_file(path)))
                .collect::<Vec<_>>();
            ReportRow {
                row_id: string(row, "row_id").to_string(),
                owner_bead: string(row, "owner_bead").to_string(),
                proof_command_id: string(row, "proof_command_id").to_string(),
                rch_build_id: string(row, "rch_build_id").to_string(),
                evidence_status: string(row, "current_evidence_status").to_string(),
                artifact_hashes,
            }
        })
        .collect::<Vec<_>>();

    let first_failing_row = rows
        .iter()
        .find(|row| row.evidence_status != required_status)
        .map(|row| row.row_id.clone());
    let final_verdict = if first_failing_row.is_none() {
        "pass"
    } else {
        "fail_closed"
    }
    .to_string();
    let mut markdown = format!(
        "# Durable RCH final signoff\n\nfinal_verdict={final_verdict}\nfirst_failing_row={}\nfreshness_window_seconds={}\n",
        first_failing_row.as_deref().unwrap_or("none"),
        signoff["freshness_policy"]["freshness_window_seconds"]
            .as_u64()
            .expect("freshness_window_seconds")
    );
    for row in &rows {
        markdown.push_str(&format!(
            "\n- child_bead_id={} proof_command_id={} rch_build_id={} evidence_status={}",
            row.owner_bead, row.proof_command_id, row.rch_build_id, row.evidence_status
        ));
        for hash in &row.artifact_hashes {
            markdown.push_str(&format!(" artifact_sha256={hash}"));
        }
    }

    OperatorReport {
        final_verdict,
        first_failing_row,
        rows,
        markdown,
    }
}

#[test]
fn signoff_artifact_declares_sources_policy_and_child_evidence() {
    let artifact = signoff();
    assert_eq!(
        string(&artifact, "schema_version"),
        "durable-rch-proof-final-signoff-v1"
    );
    assert_eq!(
        string(&artifact, "bead_id"),
        "asupersync-durable-rch-proof-submission-zxnnhe.8"
    );
    assert_eq!(
        string(&artifact, "parent_bead"),
        "asupersync-durable-rch-proof-submission-zxnnhe"
    );

    let source = &artifact["source_of_truth"];
    for (key, expected) in [
        ("signoff_artifact", SIGNOFF_PATH),
        ("contract_test", TEST_PATH),
        ("operator_runbook", RUNBOOK_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("proof_status_snapshot", SNAPSHOT_PATH),
        ("receipt_contract", RECEIPT_CONTRACT_PATH),
        ("mail_templates", MAIL_TEMPLATE_PATH),
        ("e2e_scenarios", E2E_PATH),
        ("readme", README_PATH),
        ("agent_instructions", AGENTS_PATH),
    ] {
        assert_eq!(string(source, key), expected);
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path {expected} must exist"
        );
    }

    let policy = &artifact["freshness_policy"];
    assert_eq!(
        string(policy, "required_child_evidence_status"),
        "fresh-rch-pass"
    );
    assert_eq!(string(policy, "required_branch"), "main");
    assert_eq!(
        string(policy, "legacy_master_sync_command"),
        "git push origin main:master"
    );
    assert!(bool_field(policy, "ignored_artifact_force_add_required"));
    assert!(string_set(policy, "reject_evidence_statuses").contains("blocked"));
    assert!(string_set(policy, "reject_transcript_markers").contains("[RCH] local"));

    let rows = array(&artifact, "required_child_rows");
    assert_eq!(rows.len(), CHILD_BEADS.len());
    let owner_beads = rows
        .iter()
        .map(|row| string(row, "owner_bead").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        owner_beads,
        CHILD_BEADS
            .iter()
            .map(|bead| (*bead).to_string())
            .collect::<BTreeSet<_>>()
    );

    for row in rows {
        let row_id = string(row, "row_id");
        assert_eq!(
            string(row, "current_evidence_status"),
            "fresh-rch-pass",
            "{row_id}: child evidence must be fresh"
        );
        assert!(
            string(row, "rch_build_id")
                .chars()
                .all(|ch| ch.is_ascii_digit()),
            "{row_id}: RCH build id must be numeric"
        );
        assert!(
            string(row, "test_evidence").contains("passed"),
            "{row_id}: test evidence must record a passing count"
        );
        assert_remote_required_cargo(string(row, "proof_command"));
        assert!(
            string(row, "claim_boundary").contains("only")
                || string(row, "claim_boundary").contains("no live fleet"),
            "{row_id}: claim boundary must stay narrow"
        );
        for artifact_path in string_set(row, "artifact_paths") {
            assert!(
                repo_path(&artifact_path).exists(),
                "{row_id}: artifact path missing: {artifact_path}"
            );
        }
    }
}

#[test]
fn manifest_and_status_snapshot_wire_the_final_signoff_lane() {
    let artifact = signoff();
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let claims = snapshot_claims(&snapshot);
    let signoff_lane = &artifact["signoff_lane"];
    let lane_id = string(signoff_lane, "lane_id");
    let guarantee_id = string(signoff_lane, "guarantee_id");
    let claim_id = string(signoff_lane, "proof_status_claim_id");
    let proof_command = string(signoff_lane, "proof_command");

    let lane = lanes
        .get(lane_id)
        .unwrap_or_else(|| panic!("manifest missing lane {lane_id}"));
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(string(lane, "command"), proof_command);
    assert_remote_required_cargo(string(lane, "command"));
    assert!(string_set(lane, "guarantee_ids").contains(guarantee_id));
    for required_path in [
        SIGNOFF_PATH,
        TEST_PATH,
        RUNBOOK_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        E2E_PATH,
        MAIL_TEMPLATE_PATH,
        RECEIPT_CONTRACT_PATH,
    ] {
        assert!(
            string_set(lane, "source_paths").contains(required_path),
            "final signoff lane missing source path {required_path}"
        );
    }
    assert_contains_all(
        "final signoff explicit_not_covered",
        string(lane, "explicit_not_covered"),
        &[
            "release readiness",
            "broad workspace health",
            "live RCH fleet availability",
            "unrelated proof lanes",
        ],
    );

    let guarantee = guarantees
        .get(guarantee_id)
        .unwrap_or_else(|| panic!("missing guarantee {guarantee_id}"));
    assert!(string_set(guarantee, "lane_ids").contains(lane_id));

    let claim = claims
        .get(claim_id)
        .unwrap_or_else(|| panic!("snapshot missing claim {claim_id}"));
    assert_eq!(string(claim, "status"), "green");
    assert_eq!(string(claim, "proof_evidence_status"), "rerun-required");
    assert!(string_set(claim, "manifest_lane_ids").contains(lane_id));
    assert!(string_set(claim, "manifest_guarantee_ids").contains(guarantee_id));
    assert!(string_set(claim, "proof_commands").contains(proof_command));
    assert_contains_all(
        "final signoff status notes",
        string(claim, "notes"),
        &[
            "does not prove release readiness",
            "broad workspace health",
            "live RCH fleet availability",
        ],
    );
}

#[test]
fn child_rows_have_stable_report_hashes_and_no_external_claims() {
    let artifact = signoff();
    let left = render_report(&artifact);
    let right = render_report(&artifact);
    assert_eq!(left, right, "operator report rendering must be stable");
    assert_eq!(left.final_verdict, "pass");
    assert_eq!(left.first_failing_row, None);
    assert_contains_all(
        "operator report",
        &left.markdown,
        &[
            "child_bead_id=",
            "proof_command_id=",
            "rch_build_id=",
            "artifact_sha256=",
            "freshness_window_seconds=86400",
            "final_verdict=pass",
        ],
    );

    for row in &left.rows {
        assert!(!row.artifact_hashes.is_empty(), "{} hashes", row.row_id);
        for hash in &row.artifact_hashes {
            let digest = hash
                .rsplit_once("sha256=")
                .map(|(_, digest)| digest)
                .expect("sha256 marker");
            assert_eq!(digest.len(), 64, "sha256 digest length for {hash}");
            assert!(
                digest.chars().all(|ch| ch.is_ascii_hexdigit()),
                "sha256 digest must be hex for {hash}"
            );
        }
    }

    let non_claims = string_set(&artifact, "non_claims")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    assert_contains_all(
        "non_claims",
        &non_claims,
        &[
            "does not prove live RCH fleet availability",
            "does not prove release readiness",
            "does not prove broad workspace health",
            "does not prove correctness of unrelated proof lanes",
            "does not prove broad clippy or full test release gates",
            "does not allow local Cargo fallback as proof",
        ],
    );
    for forbidden in [
        "proves release readiness",
        "proves broad workspace health",
        "proves live RCH fleet availability",
    ] {
        assert!(
            !left.markdown.contains(forbidden),
            "operator report overclaims: {forbidden}"
        );
    }
}

#[test]
fn refusal_matrix_matches_e2e_scenarios_and_canceled_template() {
    let artifact = signoff();
    let e2e = json(E2E_PATH);
    let mail = json(MAIL_TEMPLATE_PATH);
    let receipt_contract = json(RECEIPT_CONTRACT_PATH);
    let scenarios = e2e_scenarios(&e2e);
    let templates = mail_templates(&mail);
    let rows = array(&artifact, "refusal_matrix")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row.clone()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        rows.len(),
        scenarios.len() + 1,
        "matrix should cover every e2e scenario plus operator cancellation"
    );
    for (scenario_id, scenario) in scenarios {
        let row = rows
            .get(&scenario_id)
            .unwrap_or_else(|| panic!("missing refusal matrix row {scenario_id}"));
        let expected = scenario.get("expected").expect("scenario expected block");
        assert_eq!(
            string(row, "terminal_classification"),
            string(expected, "terminal_classification"),
            "{scenario_id}: terminal classification drift"
        );
        assert_eq!(
            string(row, "proof_evidence_status"),
            string(expected, "proof_evidence_status"),
            "{scenario_id}: proof evidence status drift"
        );
        assert_eq!(
            bool_field(row, "green_proof_allowed"),
            bool_field(expected, "requested_claim_citable"),
            "{scenario_id}: citable decision drift"
        );
        if scenario_id == "terminal_pass_citable_exact_lane" {
            assert!(bool_field(row, "green_proof_allowed"));
            assert_eq!(string(row, "claim_scope"), "exact manifest lane only");
        } else {
            assert!(
                !bool_field(row, "green_proof_allowed"),
                "{scenario_id}: non-pass scenario must not become green proof"
            );
        }
    }

    let canceled = rows
        .get("operator_canceled_not_green")
        .expect("operator canceled matrix row");
    assert_eq!(string(canceled, "source"), "mail_template");
    assert_eq!(
        string(canceled, "terminal_classification"),
        "operator_canceled"
    );
    assert!(
        string_set(&receipt_contract, "terminal_classifications").contains("operator_canceled")
    );
    let template = templates
        .get(string(canceled, "mail_template_id"))
        .expect("canceled template");
    assert!(
        !bool_field(template, "may_claim_green_proof"),
        "canceled mail template must not claim green proof"
    );
}

#[test]
fn operator_recipes_cover_common_paths_without_live_services() {
    let artifact = signoff();
    let recipe_ids = array(&artifact, "operator_recipes")
        .iter()
        .map(|recipe| string(recipe, "recipe_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        recipe_ids,
        BTreeSet::from([
            "cancel".to_string(),
            "cite".to_string(),
            "detach".to_string(),
            "handoff".to_string(),
            "query".to_string(),
            "refuse".to_string(),
            "submit".to_string(),
        ])
    );

    for recipe in array(&artifact, "operator_recipes") {
        let recipe_id = string(recipe, "recipe_id");
        let command = string(recipe, "command");
        assert!(
            !command.contains("git branch")
                && !command.contains("git worktree")
                && !command.contains("rm -rf")
                && !command.contains("RCH_ALLOW_LOCAL=1"),
            "{recipe_id}: recipe must not require unsafe workflow or local fallback"
        );
        if recipe_id == "cite" {
            assert!(bool_field(recipe, "may_claim_green_proof"));
            assert_contains_all(
                "cite recipe",
                command,
                &[
                    "terminal_pass",
                    "fresh-rch-pass",
                    "exact manifest lane",
                    "no local fallback markers",
                ],
            );
        } else {
            assert!(
                !bool_field(recipe, "may_claim_green_proof"),
                "{recipe_id}: only cite may claim green proof"
            );
        }
    }

    let invariants = string_set(&artifact, "workflow_invariants")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    assert_contains_all(
        "workflow invariants",
        &invariants,
        &[
            "main",
            "git push origin main:master",
            "do not create branches",
            "do not delete files",
            "git add -f",
            "do not require live RCH",
        ],
    );
}

#[test]
fn runbook_and_agent_instructions_preserve_final_closeout_boundaries() {
    let runbook = read_repo_file(RUNBOOK_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    assert_contains_all(
        "runbook final signoff section",
        &runbook,
        &[
            "Durable RCH Final Signoff",
            "artifacts/durable_rch_proof_final_signoff_v1.json",
            "tests/durable_rch_proof_final_signoff_contract.rs",
            "git add -f artifacts/durable_rch_proof_final_signoff_v1.json",
            "does not prove live RCH fleet availability",
            "does not prove release readiness",
            "does not prove broad workspace health",
            "does not prove correctness of unrelated proof lanes",
        ],
    );
    assert_contains_all(
        "AGENTS main/master workflow",
        &agents,
        &[
            "All work happens on `main`",
            "git push origin main:master",
            "NO GIT BRANCHES",
            "NO FILE DELETION",
            "artifacts/proof_lane_manifest_v1.json",
            "artifacts/proof_status_snapshot_v1.json",
        ],
    );
}
