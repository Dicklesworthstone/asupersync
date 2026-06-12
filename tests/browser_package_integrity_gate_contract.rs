#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const GATE_PATH: &str = "artifacts/browser_package_integrity_gate_v1.json";
const FIXTURE_PATH: &str = "tests/fixtures/browser_package_integrity_gate/failure_rehearsals.json";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.4.2";

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

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a [JsonValue] {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a serde_json::Map<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn gate() -> JsonValue {
    json_file(GATE_PATH)
}

fn fixture() -> JsonValue {
    json_file(FIXTURE_PATH)
}

fn assert_repo_path_exists(relative: &str) {
    assert!(
        repo_path(relative).exists(),
        "referenced path must exist: {relative}"
    );
}

fn package_version(manifest_path: &str) -> String {
    let manifest = json_file(manifest_path);
    string(&manifest, "version").to_owned()
}

#[test]
fn gate_declares_required_schema_scope_and_no_claim_boundaries() {
    let gate = gate();
    assert_eq!(
        gate.get("schema_version").and_then(JsonValue::as_str),
        Some("browser-package-integrity-gate-v1")
    );
    assert_eq!(
        gate.get("bead_id").and_then(JsonValue::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        gate.get("gate_id").and_then(JsonValue::as_str),
        Some("browser_package_integrity_gate")
    );

    let decision_window = object(&gate, "decision_window");
    assert_eq!(
        decision_window
            .get("candidate_window_required")
            .and_then(JsonValue::as_bool),
        Some(true),
        "package GA must require a single candidate evidence window"
    );
    assert_eq!(
        decision_window
            .get("promotion_effect")
            .and_then(JsonValue::as_str),
        Some("block_package_ga_on_any_required_gate_failure")
    );

    let no_claims = string_set(&gate, "no_claim_boundaries");
    for required in [
        "does_not_execute_npm_publish",
        "does_not_prove_full_workspace_health",
        "does_not_replace_cross_framework_e2e_or_browser_smoke_artifacts",
        "does_not_prove_runtime_performance_or_scheduler_correctness",
        "does_not_override_surface_ceiling_readiness_matrix",
    ] {
        assert!(
            no_claims.contains(required),
            "missing no-claim boundary {required}"
        );
    }
}

#[test]
fn package_set_matches_live_package_manifests_and_committed_files() {
    let gate = gate();
    let packages = array(&gate, "package_set");
    let expected_names = BTreeSet::from([
        "@asupersync/browser-core".to_owned(),
        "@asupersync/browser".to_owned(),
        "@asupersync/react".to_owned(),
        "@asupersync/next".to_owned(),
    ]);
    let actual_names = packages
        .iter()
        .map(|package| string(package, "name").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_names, expected_names,
        "B2 package integrity gate must cover exactly the four Browser Edition packages"
    );

    for package in packages {
        let name = string(package, "name");
        let manifest_path = string(package, "manifest");
        assert_repo_path_exists(manifest_path);
        assert_eq!(
            string(package, "manifest_version"),
            package_version(manifest_path),
            "{name} version in gate artifact must match live package manifest"
        );

        assert!(
            !string(package, "kind").is_empty(),
            "{name} must declare package kind"
        );
        for path in array(package, "required_committed_files") {
            let path = path
                .as_str()
                .expect("required_committed_files entries must be strings");
            assert_repo_path_exists(path);
        }
    }
}

#[test]
fn artifact_inputs_and_linked_contracts_resolve_to_existing_paths() {
    let gate = gate();
    let artifact_inputs = object(&gate, "artifact_inputs");
    for required in [
        "integrity_manifest",
        "sbom",
        "provenance",
        "bundle_budget",
        "readiness_matrix",
        "release_channel_strategy",
        "rollback_playbook",
    ] {
        let path = artifact_inputs
            .get(required)
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("artifact_inputs.{required} must be a path string"));
        assert_repo_path_exists(path);
    }

    let contracts = array(&gate, "linked_contracts");
    let expected_contracts = BTreeSet::from([
        "package_metadata_exports".to_owned(),
        "package_build_topology".to_owned(),
        "artifact_integrity_sbom_provenance".to_owned(),
        "abi_metadata_and_downgrade_matrix".to_owned(),
        "bundle_budget".to_owned(),
        "rollback_and_release_channel_policy".to_owned(),
        "browser_surface_readiness_alignment".to_owned(),
    ]);
    let actual_contracts = contracts
        .iter()
        .map(|contract| string(contract, "id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_contracts, expected_contracts);

    for contract in contracts {
        let id = string(contract, "id");
        assert_eq!(
            contract
                .get("blocks_on_failure")
                .and_then(JsonValue::as_bool),
            Some(true),
            "{id} must block package GA on failure"
        );
        assert_repo_path_exists(string(contract, "contract_test"));
        assert!(
            !string(contract, "claim").is_empty(),
            "{id} must document the exact claim it contributes"
        );
        for path in array(contract, "source_paths") {
            let path = path.as_str().expect("source_paths entries must be strings");
            assert_repo_path_exists(path);
        }
    }
}

#[test]
fn failure_rehearsals_cover_required_fail_closed_package_integrity_mutations() {
    let gate = gate();
    assert_eq!(
        gate.get("failure_rehearsal_fixture")
            .and_then(JsonValue::as_str),
        Some(FIXTURE_PATH)
    );
    assert_repo_path_exists(FIXTURE_PATH);

    let fixture = fixture();
    assert_eq!(
        fixture.get("schema_version").and_then(JsonValue::as_str),
        Some("browser-package-integrity-failure-rehearsals-v1")
    );
    assert_eq!(
        fixture.get("bead_id").and_then(JsonValue::as_str),
        Some(BEAD_ID)
    );

    let rehearsals = array(&fixture, "rehearsals");
    let expected_ids = BTreeSet::from([
        "tampered_wasm_digest".to_owned(),
        "abi_metadata_mismatch".to_owned(),
        "oversized_bundle_ceiling".to_owned(),
        "missing_types_declaration".to_owned(),
        "missing_rollback_evidence".to_owned(),
    ]);
    let actual_ids = rehearsals
        .iter()
        .map(|rehearsal| string(rehearsal, "id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);

    let automatic_blockers = array(&gate, "automatic_blockers")
        .iter()
        .map(|blocker| string(blocker, "id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        automatic_blockers, expected_ids,
        "automatic blockers must exactly mirror rehearsed failure IDs"
    );

    for rehearsal in rehearsals {
        let id = string(rehearsal, "id");
        assert_eq!(
            rehearsal.get("fail_closed").and_then(JsonValue::as_bool),
            Some(true),
            "{id} must be fail-closed"
        );
        assert_eq!(string(rehearsal, "expected_action"), "block_package_ga");
        assert_eq!(string(rehearsal, "release_channel_effect"), "no_promotion");
        assert_repo_path_exists(string(rehearsal, "mutated_path"));
        assert!(
            !array(rehearsal, "operator_recovery").is_empty(),
            "{id} must include operator recovery steps"
        );
        for path in array(rehearsal, "detected_by") {
            let path = path.as_str().expect("detected_by entries must be strings");
            assert_repo_path_exists(path);
        }
    }
}

#[test]
fn validation_commands_and_deterministic_report_are_release_usable() {
    let gate = gate();
    let commands = array(&gate, "validation_commands");
    let command_ids = commands
        .iter()
        .map(|command| string(command, "id").to_owned())
        .collect::<BTreeSet<_>>();
    for required in [
        "browser-package-integrity-gate-contract",
        "browser-package-workspace-validate",
        "browser-package-supply-chain-contracts",
    ] {
        assert!(
            command_ids.contains(required),
            "missing validation command {required}"
        );
    }

    let focused = commands
        .iter()
        .find(|command| string(command, "id") == "browser-package-integrity-gate-contract")
        .expect("focused contract command required");
    let focused_command = string(focused, "command");
    assert!(
        focused_command.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "focused contract must be documented as an RCH remote-required lane"
    );
    assert!(
        focused_command.contains("browser_package_integrity_gate_contract"),
        "focused command must run this contract"
    );

    let package_validate = commands
        .iter()
        .find(|command| string(command, "id") == "browser-package-workspace-validate")
        .expect("package validate command required");
    assert!(
        string(package_validate, "command").contains("corepack pnpm run validate"),
        "package validate command must use the root package validate entrypoint"
    );
    assert!(
        string(package_validate, "proves").contains("scripts/validate_package_build.sh")
            && string(package_validate, "proves").contains("scripts/validate_npm_pack_smoke.sh"),
        "package validate command must name both underlying package validators"
    );

    let report = gate
        .get("deterministic_report")
        .expect("deterministic_report must exist");
    let report_object = report
        .as_object()
        .expect("deterministic_report must be an object");
    assert_eq!(
        report_object.get("path").and_then(JsonValue::as_str),
        Some(GATE_PATH)
    );
    assert_eq!(
        report_object
            .get("report_status_field")
            .and_then(JsonValue::as_str),
        Some("promotion_effect")
    );
    let stable_order = string_set(report, "stable_order");
    for required in [
        "schema_version",
        "gate_id",
        "package_set",
        "linked_contracts",
        "failure_rehearsal_fixture",
        "automatic_blockers",
        "no_claim_boundaries",
    ] {
        assert!(
            stable_order.contains(required),
            "deterministic report must include stable field {required}"
        );
    }
}

#[test]
fn release_channel_strategy_names_b2_gate_as_package_ga_blocker() {
    let doc = read_repo_file("docs/wasm_release_channel_strategy.md");
    for marker in [
        BEAD_ID,
        GATE_PATH,
        FIXTURE_PATH,
        "tests/browser_package_integrity_gate_contract.rs",
        "block_package_ga",
        "tampered_wasm_digest",
        "abi_metadata_mismatch",
        "oversized_bundle_ceiling",
    ] {
        assert!(
            doc.contains(marker),
            "release channel strategy must mention B2 marker {marker}"
        );
    }
}
