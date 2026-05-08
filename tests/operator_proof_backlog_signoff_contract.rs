#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/operator_proof_backlog_signoff_contract_v1.json";
const PROOF_RECEIPT_SCRIPT: &str = "scripts/proof_receipt_inventory.py";
const PROOF_RUNNER_SCRIPT: &str = "scripts/proof_runner.py";
const RECEIPT_FIXTURE_ROOT: &str = "tests/fixtures/proof_receipt_inventory";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> JsonValue {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contract() -> JsonValue {
    json_file(CONTRACT_PATH)
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn child<'a>(contract: &'a JsonValue, bead_id: &str) -> &'a JsonValue {
    array(contract, "child_receipts")
        .iter()
        .find(|row| row.get("bead_id").and_then(JsonValue::as_str) == Some(bead_id))
        .unwrap_or_else(|| panic!("missing child receipt {bead_id}"))
}

fn run_python_script(script: &str, args: &[&str]) -> Output {
    Command::new("python3")
        .arg(repo_path(script))
        .args(args)
        .current_dir(repo_path(""))
        .output()
        .unwrap_or_else(|err| panic!("run {script}: {err}"))
}

fn output_json(output: &Output, label: &str) -> JsonValue {
    assert!(
        output.status.success(),
        "{label} failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "{label} stdout must be JSON: {err}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn sha256_file(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|err| panic!("read bytes for {relative}: {err}"));
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[test]
fn signoff_contract_declares_hold_verdict_and_required_surfaces() {
    let contract = contract();
    assert_eq!(
        contract.get("schema_version").and_then(JsonValue::as_str),
        Some("operator-proof-backlog-signoff-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-xeh8m0.8")
    );
    assert_eq!(
        contract.get("scenario_id").and_then(JsonValue::as_str),
        Some("xeh8m0.operator-proof-backlog.final-signoff")
    );
    assert_eq!(
        contract
            .get("final_operator_verdict")
            .and_then(JsonValue::as_str),
        Some("no-win-hold"),
        "signoff must hold broad readiness while .3 has a no-win runtime blocker"
    );
    assert_eq!(
        contract
            .get("broad_readiness_claim")
            .and_then(JsonValue::as_str),
        Some("not_claimed")
    );
    assert_eq!(
        array(&contract, "child_receipts").len(),
        7,
        "signoff must cover xeh8m0.1 through xeh8m0.7"
    );

    for bead_id in [
        "asupersync-xeh8m0.1",
        "asupersync-xeh8m0.2",
        "asupersync-xeh8m0.3",
        "asupersync-xeh8m0.4",
        "asupersync-xeh8m0.5",
        "asupersync-xeh8m0.6",
        "asupersync-xeh8m0.7",
    ] {
        let row = child(&contract, bead_id);
        assert!(
            !array(row, "artifact_paths").is_empty(),
            "{bead_id} must name artifact paths"
        );
        assert!(
            string(row, "proof_command").starts_with("rch exec -- "),
            "{bead_id} proof command must be rch-routed"
        );
    }
}

#[test]
fn source_artifact_hashes_match_current_files() {
    let contract = contract();
    for row in array(&contract, "source_artifact_hashes") {
        let path = string(row, "path");
        let expected = string(row, "sha256");
        assert!(
            repo_path(path).exists(),
            "source artifact path must exist: {path}"
        );
        assert_eq!(
            sha256_file(path),
            expected,
            "source artifact hash drifted for {path}"
        );
    }
}

#[test]
fn gate_commands_cover_required_proofs_and_block_local_cargo_fallbacks() {
    let contract = contract();
    let gate_ids = array(&contract, "gate_commands")
        .iter()
        .map(|gate| string(gate, "gate_id").to_string())
        .collect::<BTreeSet<_>>();

    for required in [
        "proof_receipt_inventory_contract",
        "proof_lane_manifest_contract",
        "proof_status_snapshot_contract",
        "operator_recipe_list",
        "operator_recipe_dry_run",
        "operator_recipe_safe_execute",
        "bv_robot_alerts",
    ] {
        assert!(gate_ids.contains(required), "missing gate {required}");
    }

    for gate in array(&contract, "gate_commands") {
        let gate_id = string(gate, "gate_id");
        let kind = string(gate, "kind");
        let command = string(gate, "command");
        match kind {
            "rch_cargo_test" => {
                assert!(
                    command.starts_with("rch exec -- "),
                    "{gate_id} cargo proof must be rch-routed"
                );
                assert!(
                    command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/"),
                    "{gate_id} must keep target dir worker-scoped"
                );
                assert!(
                    !command.starts_with("cargo ") && !command.contains(" cargo +"),
                    "{gate_id} must not permit local cargo fallback"
                );
            }
            "local_deterministic_helper" => {
                assert!(
                    command.starts_with("python3 scripts/proof_runner.py "),
                    "{gate_id} helper command must use proof_runner.py"
                );
            }
            "tracker_diagnostic" => {
                assert_eq!(command, "bv --robot-alerts");
            }
            other => panic!("unknown gate kind {other} for {gate_id}"),
        }
    }
}

#[test]
fn proof_receipt_inventory_and_operator_recipe_smokes_execute() {
    let current = output_json(
        &run_python_script(
            PROOF_RECEIPT_SCRIPT,
            &[
                "--fixture",
                &repo_path(RECEIPT_FIXTURE_ROOT)
                    .join("current_inventory.json")
                    .to_string_lossy(),
                "--repo-path",
                "/repo",
                "--agent",
                "CopperSpring",
                "--generated-at",
                "2026-05-08T12:56:00Z",
                "--output",
                "json",
            ],
        ),
        "proof receipt current inventory",
    );
    assert_eq!(
        current.get("schema_version").and_then(JsonValue::as_str),
        Some("proof-receipt-inventory-v1")
    );

    let duplicate = output_json(
        &run_python_script(
            PROOF_RECEIPT_SCRIPT,
            &[
                "--fixture",
                &repo_path(RECEIPT_FIXTURE_ROOT)
                    .join("duplicate_current.json")
                    .to_string_lossy(),
                "--repo-path",
                "/repo",
                "--agent",
                "CopperSpring",
                "--generated-at",
                "2026-05-08T12:56:00Z",
                "--output",
                "json",
            ],
        ),
        "proof receipt duplicate inventory",
    );
    assert_eq!(
        duplicate["classification_counts"]["duplicate-capability"].as_u64(),
        Some(1),
        "duplicate helper capability must fail closed with an inventory cue"
    );

    let listed = output_json(
        &run_python_script(
            PROOF_RUNNER_SCRIPT,
            &["--list-operator-recipes", "--output", "json"],
        ),
        "operator recipe list",
    );
    assert_eq!(
        listed.get("schema_version").and_then(JsonValue::as_str),
        Some("operator-action-recipe-v1")
    );

    let dry_run = output_json(
        &run_python_script(
            PROOF_RUNNER_SCRIPT,
            &[
                "--operator-recipe",
                "rerun-proof-lane",
                "--operator-mode",
                "dry-run",
                "--output",
                "json",
            ],
        ),
        "operator recipe dry run",
    );
    assert_eq!(dry_run["mode"].as_str(), Some("dry-run"));
    assert_eq!(dry_run["executed"].as_bool(), Some(false));
    assert_eq!(dry_run["mutates_tracker"].as_bool(), Some(false));

    let safe_execute = output_json(
        &run_python_script(
            PROOF_RUNNER_SCRIPT,
            &[
                "--operator-recipe",
                "dirty-frontier-refusal",
                "--operator-mode",
                "execute",
                "--output",
                "json",
            ],
        ),
        "operator recipe safe execute",
    );
    assert_eq!(safe_execute["mode"].as_str(), Some("execute"));
    assert_eq!(safe_execute["executed"].as_bool(), Some(true));
    assert_eq!(safe_execute["side_effects"].as_array().unwrap().len(), 0);
    assert_eq!(safe_execute["operator_verdict"].as_str(), Some("refuse"));
}

#[test]
fn fail_closed_checks_cover_required_negative_conditions() {
    let contract = contract();
    let actual = array(&contract, "fail_closed_checks")
        .iter()
        .map(|check| string(check, "check_id").to_string())
        .collect::<BTreeSet<_>>();
    let expected = [
        "duplicate-helper-capability",
        "missing-fixture-root",
        "stale-schema-version",
        "local-rch-fallback-marker",
        "raw-coordination-data",
        "unsupported-broad-docs-claim",
        "missing-first-blocker-line",
        "missing-no-win-fallback-verdict",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    for check in array(&contract, "fail_closed_checks") {
        assert!(repo_path_exists_or_named_evidence(string(
            check, "evidence"
        )));
        assert!(
            !string(check, "expected_signal").contains("maybe"),
            "fail-closed expected signal must be deterministic"
        );
    }
}

#[test]
fn scheduler_no_win_receipt_blocks_broad_signoff_until_first_blocker_is_fixed() {
    let contract = contract();
    let scheduler = child(&contract, "asupersync-xeh8m0.3");
    assert_eq!(string(scheduler, "operator_verdict"), "no-win");
    assert_eq!(
        scheduler
            .get("remote_exit_status")
            .and_then(JsonValue::as_i64),
        Some(101)
    );

    let blocker = scheduler
        .get("first_blocker")
        .expect("scheduler first_blocker object");
    assert_eq!(string(blocker, "file"), "os-thread-local-0.1.3/src/lib.rs");
    assert!(
        blocker.get("line").and_then(JsonValue::as_u64).unwrap_or(0) > 0,
        "first blocker line must be nonzero"
    );
    assert!(
        string(scheduler, "fallback_no_win_reason").contains("p50/p95/p999"),
        "no-win fallback must explain missing required quantiles"
    );
    assert_eq!(
        contract
            .get("final_operator_verdict")
            .and_then(JsonValue::as_str),
        Some("no-win-hold")
    );
}

#[test]
fn public_signoff_artifact_rejects_raw_coordination_and_broad_claims() {
    let contract_text = read_repo_file(CONTRACT_PATH);
    for forbidden in [
        "body_md",
        "ack_required",
        "sender_token",
        "/home/ubuntu/",
        "production_ready",
        "full_support",
        "all green",
        "broad readiness is proven",
    ] {
        assert!(
            !contract_text.contains(forbidden),
            "public signoff artifact must not contain forbidden marker {forbidden}"
        );
    }

    let contract = contract();
    assert_eq!(
        contract
            .get("broad_readiness_claim")
            .and_then(JsonValue::as_str),
        Some("not_claimed")
    );
    assert!(
        array(&contract, "generated_artifact_paths")
            .iter()
            .all(|path| path
                .as_str()
                .is_some_and(|path| path.starts_with("artifacts/"))),
        "generated artifact paths must stay under artifacts/"
    );
}

fn repo_path_exists_or_named_evidence(evidence: &str) -> bool {
    repo_path(evidence).exists()
        || matches!(
            evidence,
            "operator-proof-backlog-signoff-contract-v1"
                | "gate_commands"
                | "public artifact scan"
                | "broad_readiness_claim"
                | "asupersync-xeh8m0.3 first_blocker"
                | "asupersync-xeh8m0.3 fallback_no_win_reason"
        )
}
