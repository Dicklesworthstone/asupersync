#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const DOWNSTREAM_PROOF_PATH: &str = "artifacts/downstream_consumer_proof_v1.json";
const GRAPH_BUDGETS_PATH: &str = "artifacts/validation_frontier_graph_budgets_v1.json";
const INVENTORY_PATH: &str = "artifacts/validation_frontier_inventory_v1.json";
const LANE_ID: &str = "validation-frontier-final-signoff";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const RUNBOOK_PATH: &str = "docs/proof/validation_frontier_runbook.md";
const SCRIPT_PATH: &str = "scripts/run_validation_frontier_signoff_e2e.sh";
const SIGNOFF_PATH: &str = "artifacts/validation_frontier_signoff_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const STALE_RECEIPT_PATH: &str = "artifacts/rch_stale_progress_receipt_contract_v1.json";
const TEST_PATH: &str = "tests/validation_frontier_signoff_contract.rs";

const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test validation_frontier_signoff_contract -- --nocapture";

#[derive(Debug, Clone, Eq, PartialEq)]
struct OperatorReport {
    final_verdict: String,
    parent_close_allowed: bool,
    first_failing_row: String,
    markdown: String,
    artifact_hashes: Vec<String>,
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
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_owned(), lane.clone()))
        .collect()
}

fn manifest_guarantees(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_owned(),
                guarantee.clone(),
            )
        })
        .collect()
}

fn snapshot_claims(snapshot: &Value) -> BTreeMap<String, Value> {
    array(snapshot, "claim_categories")
        .iter()
        .map(|claim| (string(claim, "claim_id").to_owned(), claim.clone()))
        .collect()
}

fn inventory_rows(inventory: &Value) -> BTreeMap<String, Value> {
    array(inventory, "lanes")
        .iter()
        .map(|row| (string(row, "lane_id").to_owned(), row.clone()))
        .collect()
}

fn assert_remote_required_cargo(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_"),
        "Cargo proof command must isolate target output: {command}"
    );
    assert!(
        command.contains(" cargo "),
        "proof command must route Cargo through RCH: {command}"
    );
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "rch exec -- cargo",
        "[RCH] local",
        "local fallback accepted",
        "falling back to local execution",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden local/fallback marker {forbidden}: {command}"
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
    let report = &signoff["current_operator_report"];
    let policy = &signoff["freshness_policy"];
    let mut markdown = format!(
        "# Validation Frontier final signoff\n\nfinal_verdict={}\nparent_close_allowed={}\nfirst_failing_row={}\nfreshness_window_seconds={}\n",
        string(report, "final_verdict"),
        bool_field(report, "parent_close_allowed"),
        string(report, "first_failing_row"),
        policy["freshness_window_seconds"]
            .as_u64()
            .expect("freshness_window_seconds")
    );
    let mut artifact_hashes = Vec::new();
    for row in array(signoff, "source_deliverable_rows") {
        markdown.push_str(&format!(
            "\n- owner_bead={} proof_command_id={} evidence_status={}",
            string(row, "owner_bead"),
            string(row, "proof_command_id"),
            string(row, "current_evidence_status")
        ));
        for path in array(row, "artifact_paths") {
            let path = path.as_str().expect("artifact_paths entries are strings");
            artifact_hashes.push(format!("{path}:sha256={}", sha256_file(path)));
        }
    }
    markdown.push('\n');

    OperatorReport {
        final_verdict: string(report, "final_verdict").to_owned(),
        parent_close_allowed: bool_field(report, "parent_close_allowed"),
        first_failing_row: string(report, "first_failing_row").to_owned(),
        markdown,
        artifact_hashes,
    }
}

#[test]
fn signoff_artifact_declares_sources_decision_and_remote_required_lane() {
    let artifact = json(SIGNOFF_PATH);
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("validation-frontier-signoff-v1")
    );
    assert_eq!(
        string(&artifact, "bead_id"),
        "asupersync-validation-frontier-v2-b5cjsv.7"
    );
    assert_eq!(
        string(&artifact, "parent_bead"),
        "asupersync-validation-frontier-v2-b5cjsv"
    );

    let source = &artifact["source_of_truth"];
    for (key, expected) in [
        ("signoff_artifact", SIGNOFF_PATH),
        ("operator_runbook", RUNBOOK_PATH),
        ("e2e_runner", SCRIPT_PATH),
        ("contract_test", TEST_PATH),
        ("validation_frontier_inventory", INVENTORY_PATH),
        ("validation_frontier_graph_budgets", GRAPH_BUDGETS_PATH),
        ("rch_stale_progress_receipt", STALE_RECEIPT_PATH),
        ("downstream_consumer_proof", DOWNSTREAM_PROOF_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("proof_status_snapshot", SNAPSHOT_PATH),
        ("readme", README_PATH),
        ("agent_instructions", AGENTS_PATH),
    ] {
        assert_eq!(string(source, key), expected);
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path {expected} must exist"
        );
    }

    let lane = &artifact["signoff_lane"];
    assert_eq!(string(lane, "lane_id"), LANE_ID);
    assert_eq!(string(lane, "guarantee_id"), LANE_ID);
    assert_eq!(string(lane, "proof_status_claim_id"), LANE_ID);
    assert_eq!(string(lane, "proof_command"), PROOF_COMMAND);
    assert_remote_required_cargo(string(lane, "proof_command"));

    let policy = &artifact["freshness_policy"];
    assert_eq!(
        string(policy, "required_before_parent_close"),
        "fresh-rch-pass"
    );
    assert_eq!(string(policy, "current_required_status"), "rerun-required");
    assert_eq!(
        string(policy, "required_remote_prefix"),
        "RCH_REQUIRE_REMOTE=1 rch exec -- env "
    );
    assert!(bool_field(policy, "reject_zero_tests"));
}

#[test]
fn source_rows_bind_child_deliverables_and_channel_regression_without_overclaiming() {
    let artifact = json(SIGNOFF_PATH);
    let rows = array(&artifact, "source_deliverable_rows");
    let row_ids = rows
        .iter()
        .map(|row| string(row, "row_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        row_ids,
        BTreeSet::from([
            "validation-frontier-inventory".to_string(),
            "rch-stale-progress-receipts".to_string(),
            "downstream-consumer-proof".to_string(),
            "validation-frontier-graph-budgets".to_string(),
        ])
    );

    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lanes = manifest_lanes(&manifest);
    let claims = snapshot_claims(&snapshot);

    for row in rows {
        assert_eq!(string(row, "current_evidence_status"), "rerun-required");
        assert_remote_required_cargo(string(row, "proof_command"));
        if let Some(lane_id) = row.get("manifest_lane_id").and_then(Value::as_str) {
            let lane = lanes
                .get(lane_id)
                .unwrap_or_else(|| panic!("{} missing lane {lane_id}", string(row, "row_id")));
            assert_eq!(string(row, "proof_command"), string(lane, "command"));
        }
        if let Some(claim_id) = row.get("proof_status_claim_id").and_then(Value::as_str) {
            let claim = claims
                .get(claim_id)
                .unwrap_or_else(|| panic!("{} missing claim {claim_id}", string(row, "row_id")));
            assert!(
                string_set(claim, "proof_commands").contains(string(row, "proof_command")),
                "{} claim must include row proof command",
                string(row, "row_id")
            );
        }
        for path in array(row, "artifact_paths") {
            let path = path.as_str().expect("artifact_paths entries are strings");
            assert!(repo_path(path).exists(), "missing artifact path {path}");
        }
        assert!(
            string(row, "claim_boundary").contains("only")
                || string(row, "claim_boundary").contains("does not"),
            "{} must preserve a scoped claim boundary",
            string(row, "row_id")
        );
    }

    let inventory = json(INVENTORY_PATH);
    let inventory_rows = inventory_rows(&inventory);
    let fixture = &artifact["channel_mpsc_select_regression_fixture"];
    let public_lane = string(fixture, "public_execution_lane");
    let compile_lane = string(fixture, "compile_only_lane");
    assert_eq!(
        string(&inventory_rows[public_lane], "current_rch_behavior"),
        "green_observed"
    );
    assert_eq!(
        string(&inventory_rows[compile_lane], "current_rch_behavior"),
        "green_observed"
    );
    for lane_id in array(fixture, "stale_or_blocked_lanes") {
        let lane_id = lane_id.as_str().expect("stale lane ids are strings");
        let row = inventory_rows
            .get(lane_id)
            .unwrap_or_else(|| panic!("missing inventory row {lane_id}"));
        assert!(
            string(row, "current_rch_behavior") == "stale_progress_observed"
                || string(row, "current_rch_behavior") == "preflight_failed_observed",
            "{lane_id} must stay a frontier row"
        );
    }
    assert!(
        string(fixture, "claim_boundary").contains("stale cfg(test)")
            && string(fixture, "claim_boundary").contains("validation-frontier evidence")
    );
}

#[test]
fn manifest_status_snapshot_docs_and_script_wire_final_signoff_lane() {
    let artifact = json(SIGNOFF_PATH);
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let claims = snapshot_claims(&snapshot);

    let lane = lanes.get(LANE_ID).expect("manifest lane missing");
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(string(lane, "command"), PROOF_COMMAND);
    assert_eq!(
        string_set(lane, "guarantee_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_remote_required_cargo(string(lane, "command"));
    for path in string_set(lane, "source_paths") {
        assert!(
            repo_path(&path).exists(),
            "manifest source path missing: {path}"
        );
    }
    assert!(
        string(lane, "explicit_not_covered").contains("release readiness")
            && string(lane, "explicit_not_covered").contains("broad workspace health")
            && string(lane, "explicit_not_covered").contains("live RCH fleet availability")
    );

    let guarantee = guarantees.get(LANE_ID).expect("manifest guarantee missing");
    assert_eq!(
        string_set(guarantee, "lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );

    let claim = claims.get(LANE_ID).expect("proof-status claim missing");
    assert_eq!(string(claim, "status"), "yellow_scoped");
    assert_eq!(string(claim, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(claim, "manifest_lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(claim, "manifest_guarantee_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(claim, "proof_commands"),
        BTreeSet::from([PROOF_COMMAND.to_owned()])
    );
    assert!(claim["blocked_frontier"].is_null());

    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    let runbook = read_repo_file(RUNBOOK_PATH);
    for marker in [
        "artifacts/validation_frontier_signoff_v1.json",
        "docs/proof/validation_frontier_runbook.md",
        "validation-frontier-final-signoff",
    ] {
        assert!(readme.contains(marker), "README missing marker {marker}");
        assert!(agents.contains(marker), "AGENTS missing marker {marker}");
    }
    for marker in [
        "<!-- validation-frontier-signoff-v1 -->",
        "compile_only",
        "RCH stale-progress",
        "channel-mpsc-select-e2e-public-run",
        "validation-frontier-final-signoff",
    ] {
        assert!(runbook.contains(marker), "runbook missing marker {marker}");
    }

    let script = read_repo_file(SCRIPT_PATH);
    for command in array(&artifact["e2e_runner"], "required_commands") {
        let command = command.as_str().expect("required commands are strings");
        assert_remote_required_cargo(command);
        assert!(script.contains(command), "script missing command {command}");
    }
    for forbidden in ["\ncargo test ", "RCH_REQUIRE_REMOTE=0"] {
        assert!(
            !script.contains(forbidden),
            "script contains forbidden local/fallback marker {forbidden}"
        );
    }
}

#[test]
fn deterministic_operator_report_matches_golden_and_preserves_non_claims() {
    let artifact = json(SIGNOFF_PATH);
    let left = render_report(&artifact);
    let right = render_report(&artifact);
    assert_eq!(left, right, "operator report rendering must be stable");
    assert_eq!(left.final_verdict, "rerun_required_before_parent_close");
    assert!(!left.parent_close_allowed);
    assert_eq!(left.first_failing_row, "validation-frontier-inventory");
    assert_eq!(left.markdown, string(&artifact, "markdown_summary_golden"));

    assert!(
        !left.artifact_hashes.is_empty(),
        "operator report must hash source artifacts"
    );
    for hash in &left.artifact_hashes {
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

    let non_claims = string_set(&artifact, "non_claims")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "does not prove broad workspace health",
        "does not prove release readiness",
        "does not prove source correctness outside cited surfaces",
        "does not prove performance improvement",
        "does not prove no regression",
        "does not prove live RCH fleet availability",
        "does not authorize local Cargo fallback",
        "does not authorize deleting files",
        "does not close the parent validation-frontier epic",
    ] {
        assert!(
            non_claims.contains(required),
            "missing non-claim {required}"
        );
    }
}

#[test]
fn failure_fixtures_fail_closed_for_missing_rows_local_fallback_compile_overclaim_and_release_overclaim()
 {
    let artifact = json(SIGNOFF_PATH);
    let fixtures = array(&artifact, "failure_fixtures")
        .iter()
        .map(|fixture| (string(fixture, "fixture_id").to_owned(), fixture.clone()))
        .collect::<BTreeMap<_, _>>();

    for (fixture_id, row_id, reason) in [
        (
            "missing-inventory-row",
            "validation-frontier-inventory",
            "inventory deliverable required",
        ),
        (
            "local-fallback-evidence",
            "rch-stale-progress-receipts",
            "local fallback evidence rejected",
        ),
        (
            "compile-only-overclaim",
            "channel-mpsc-select-e2e-lib-check",
            "compile-only evidence cannot prove test execution",
        ),
        (
            "broad-release-overclaim",
            "validation-frontier-final-signoff",
            "focused signoff cannot prove release readiness",
        ),
    ] {
        let fixture = fixtures
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing fixture {fixture_id}"));
        assert_eq!(string(fixture, "expected_verdict"), "fail_closed");
        assert_eq!(string(fixture, "expected_first_failing_row"), row_id);
        assert_eq!(string(fixture, "expected_reason"), reason);
    }
}
