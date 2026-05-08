//! Contract tests for browser operator console snapshot payloads.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/browser_operator_console_snapshot_contract_v1.json";
const MODEL_PATH: &str = "asupersync-browser-core/src/types.rs";
const EXPORT_PATH: &str = "asupersync-browser-core/src/exports.rs";
const ABI_EXPORT_TEST_PATH: &str = "asupersync-browser-core/tests/abi_exports.rs";
const TEST_PATH: &str = "tests/browser_operator_console_snapshot_contract.rs";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn contract() -> Value {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH))
        .unwrap_or_else(|err| panic!("parse {CONTRACT_PATH}: {err}"))
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

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn render_markdown(contract: &Value) -> Vec<String> {
    let mut lines = vec![
        "| snapshot | runtime_state | pressure | admission | proof | omitted_native_fields |"
            .to_string(),
        "|---|---|---|---|---|---|".to_string(),
    ];

    for scenario in array(contract, "scenario_matrix") {
        let admission = if bool_field(scenario, "admission_open") {
            "open"
        } else {
            "closed"
        };
        let proof = if bool_field(scenario, "proof_fresh") {
            "fresh"
        } else {
            "blocked"
        };
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            string(scenario, "kind"),
            string(scenario, "runtime_state"),
            string(scenario, "pressure_level"),
            admission,
            proof,
            array(scenario, "required_unsupported_field_ids").len()
        ));
    }

    lines
}

#[test]
fn contract_names_source_model_and_required_snapshot_schema() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("browser-operator-console-snapshot-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-eubg99")
    );
    assert_eq!(
        contract["source_of_truth"]["model"].as_str(),
        Some(MODEL_PATH)
    );
    assert_eq!(
        contract["source_of_truth"]["export"].as_str(),
        Some(EXPORT_PATH)
    );
    assert_eq!(
        contract["source_of_truth"]["contract"].as_str(),
        Some(CONTRACT_PATH)
    );
    assert_eq!(
        contract["source_of_truth"]["verifier"].as_str(),
        Some(TEST_PATH)
    );
    assert_eq!(
        contract["schema"]["runtime_payload_schema"].as_str(),
        Some("browser-operator-snapshot-v1")
    );

    let required_fields = string_set(&contract["schema"], "required_top_level_fields");
    for field in [
        "schema_version",
        "kind",
        "runtime",
        "regions",
        "tasks",
        "channels",
        "budgets",
        "pressure",
        "proof_status",
        "unsupported_native_fields",
    ] {
        assert!(required_fields.contains(field), "missing field {field}");
    }
}

#[test]
fn snapshot_model_is_source_owned_and_names_required_markers() {
    let contract = contract();

    for entry in array(&contract, "source_markers") {
        let path = string(entry, "path");
        assert!(
            repo_path(path).exists(),
            "source marker path must exist: {path}"
        );
        let source = read_repo_file(path);

        for marker in array(entry, "markers") {
            let marker = marker.as_str().expect("marker string");
            assert!(
                source.contains(marker),
                "{path} must contain source marker {marker:?}"
            );
        }
    }

    let model = read_repo_file(MODEL_PATH);
    for field in string_set(&contract["schema"], "required_top_level_fields") {
        assert!(
            model.contains(&field),
            "browser snapshot model must name required field {field:?}"
        );
    }
}

#[test]
fn live_export_is_wired_to_dispatcher_diagnostics() {
    let lib = read_repo_file("asupersync-browser-core/src/lib.rs");
    let exports = read_repo_file(EXPORT_PATH);
    let abi_export_tests = read_repo_file(ABI_EXPORT_TEST_PATH);
    let model = read_repo_file(MODEL_PATH);

    assert!(
        model.contains("from_dispatcher_diagnostics"),
        "model must expose dispatcher-diagnostics conversion"
    );
    assert!(
        lib.contains("browser_operator_snapshot_impl"),
        "lib must define live snapshot implementation"
    );
    assert!(
        lib.contains("BrowserOperatorConsoleSnapshot::from_dispatcher_diagnostics"),
        "live export must derive from dispatcher diagnostics"
    );
    assert!(
        exports.contains("wasm_bindgen(js_name = browser_operator_snapshot)"),
        "exports must expose wasm browser_operator_snapshot symbol"
    );
    assert!(
        abi_export_tests
            .contains("browser_operator_snapshot_export_projects_live_dispatcher_diagnostics"),
        "host export tests must exercise live snapshot export"
    );
}

#[test]
fn live_dispatcher_leaks_fail_closed_to_cancelled_snapshot() {
    let contract = contract();
    let policy = &contract["live_dispatcher_fail_closed_policy"];
    assert_eq!(string(policy, "leak_snapshot_kind"), "cancelled_runtime");
    assert_eq!(string(policy, "runtime_state"), "cancelling");
    assert!(!bool_field(policy, "admission_open"));
    assert!(!bool_field(policy, "proof_fresh"));
    assert!(bool_field(policy, "proof_lane_must_be_absent"));

    let model = read_repo_file(MODEL_PATH);
    let source_test = string(policy, "source_test");
    let blocked_reason = string(policy, "blocked_reason_contains");
    assert!(
        model.contains(source_test),
        "model tests must include live dispatcher leak policy test {source_test}"
    );
    assert!(
        model.contains("BrowserOperatorSnapshotKind::CancelledRuntime"),
        "leaked dispatcher diagnostics must project cancelled runtime kind"
    );
    assert!(
        model.contains("BrowserOperatorRuntimeState::Cancelling"),
        "leaked dispatcher diagnostics must project cancelling runtime state"
    );
    assert!(
        model.contains("admission_open: !has_leaks"),
        "leaked dispatcher diagnostics must close admission"
    );
    assert!(
        model.contains("let proof_lane = (!has_leaks).then"),
        "leaked dispatcher diagnostics must omit proof lane"
    );
    assert!(
        model.contains("proof_fresh: !has_leaks"),
        "leaked dispatcher diagnostics must clear proof freshness"
    );
    assert!(
        model.contains(blocked_reason),
        "leaked dispatcher diagnostics must expose blocked cleanup reason"
    );

    let commands = array(&contract, "validation_commands");
    assert!(
        commands.iter().any(|command| command
            .as_str()
            .is_some_and(|command| command.contains(source_test))),
        "validation commands must include the live dispatcher leak policy test"
    );
}

#[test]
fn scenario_matrix_covers_core_browser_console_states() {
    let contract = contract();
    let expected_kinds = string_set(&contract["schema"], "required_snapshot_kinds");
    let actual_kinds = array(&contract, "scenario_matrix")
        .iter()
        .map(|scenario| string(scenario, "kind").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_kinds, expected_kinds);

    let runtime_states = string_set(&contract["schema"], "required_runtime_states");
    let pressure_levels = string_set(&contract["schema"], "required_pressure_levels");
    let mut seen_states = BTreeSet::new();
    let mut seen_pressure = BTreeSet::new();

    for scenario in array(&contract, "scenario_matrix") {
        let kind = string(scenario, "kind");
        let state = string(scenario, "runtime_state");
        let pressure = string(scenario, "pressure_level");
        assert!(
            runtime_states.contains(state),
            "{kind} uses unknown runtime state {state}"
        );
        assert!(
            pressure_levels.contains(pressure),
            "{kind} uses unknown pressure level {pressure}"
        );
        seen_states.insert(state.to_string());
        seen_pressure.insert(pressure.to_string());

        assert!(
            u64_field(scenario, "minimum_regions") >= 1,
            "{kind} must expose at least the root region"
        );
        if kind != "empty_runtime" {
            assert!(
                u64_field(scenario, "minimum_tasks") >= 1,
                "{kind} must represent non-empty task pressure"
            );
        }
        if kind == "pressure_governed_runtime" {
            assert!(
                !bool_field(scenario, "proof_fresh"),
                "pressure-governed browser snapshot must fail closed until live proof is wired"
            );
            assert!(
                bool_field(scenario, "blocked_reason_required"),
                "pressure-governed snapshot must require blocked reason"
            );
        }
    }

    assert_eq!(seen_states, runtime_states);
    assert_eq!(seen_pressure, pressure_levels);
}

#[test]
fn unsupported_native_fields_are_explicitly_fail_closed() {
    let contract = contract();
    let model = read_repo_file(MODEL_PATH);
    let required_unsupported =
        string_set(&contract["fail_closed_policy"], "unsupported_native_fields");

    assert!(
        model.contains("BrowserOperatorFieldStatus::UnsupportedNativeOnly"),
        "browser model must use explicit unsupported-native field status"
    );
    for field_id in &required_unsupported {
        assert!(
            model.contains(field_id),
            "browser model must name unsupported native field {field_id}"
        );
    }

    for scenario in array(&contract, "scenario_matrix") {
        let ids = string_set(scenario, "required_unsupported_field_ids");
        assert_eq!(
            ids,
            required_unsupported,
            "{} must carry every required unsupported native field",
            string(scenario, "kind")
        );
    }
}

#[test]
fn projection_is_stable_and_rejects_native_parity_claims() {
    let contract = contract();
    let rendered = render_markdown(&contract);
    let golden = array(&contract, "markdown_golden")
        .iter()
        .map(|line| line.as_str().expect("markdown line string").to_string())
        .collect::<Vec<_>>();
    assert_eq!(rendered, golden);

    let scenario_text =
        serde_json::to_string(array(&contract, "scenario_matrix")).expect("scenario json");
    let model_text = read_repo_file(MODEL_PATH);
    let rendered_text = rendered.join("\n");
    for forbidden in array(&contract["fail_closed_policy"], "forbidden_claims") {
        let forbidden = forbidden.as_str().expect("forbidden claim string");
        assert!(
            !scenario_text.contains(forbidden)
                && !model_text.contains(forbidden)
                && !rendered_text.contains(forbidden),
            "browser snapshot contract must not contain unsupported native claim {forbidden:?}"
        );
    }
}

#[test]
fn validation_commands_are_rch_routed_and_target_isolated() {
    let contract = contract();
    for command in array(&contract, "validation_commands") {
        let command = command.as_str().expect("validation command string");
        assert!(
            command.starts_with("rch exec -- "),
            "validation command must be rch routed: {command}"
        );
        if command.contains(" cargo test ") {
            assert!(
                command.contains(
                    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_browser_operator_console_snapshot_"
                ),
                "cargo validation must use a browser-snapshot-specific target dir: {command}"
            );
        }
    }
}
