#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MATRIX_PATH: &str = "artifacts/browser_consumer_compatibility_matrix_v1.json";
const READINESS_PATH: &str = "artifacts/browser_edition_readiness_matrix_v1.json";
const FAILURE_FIXTURE_PATH: &str =
    "tests/fixtures/browser_consumer_compatibility_matrix/failure_bundles.json";
const DOC_PATH: &str = "docs/browser_consumer_compatibility_matrix.md";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.4.3";

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
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
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

fn strings(value: &JsonValue, key: &str) -> Vec<String> {
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

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn path_exists(relative: &str) -> bool {
    repo_path(relative.trim_end_matches('/')).exists()
}

fn matrix() -> JsonValue {
    json_file(MATRIX_PATH)
}

fn readiness_rows_by_id() -> BTreeMap<String, JsonValue> {
    array(&json_file(READINESS_PATH), "rows")
        .iter()
        .map(|row| (string(row, "surface_id").to_owned(), row.clone()))
        .collect()
}

fn consumer_ids(matrix: &JsonValue) -> BTreeSet<String> {
    array(matrix, "consumer_matrix")
        .iter()
        .map(|row| string(row, "consumer_id").to_owned())
        .collect()
}

#[test]
fn matrix_declares_schema_scope_and_required_consumers() {
    let matrix = matrix();
    assert_eq!(
        matrix.get("schema_version").and_then(JsonValue::as_str),
        Some("browser-consumer-compatibility-matrix-v1")
    );
    assert_eq!(
        matrix.get("bead_id").and_then(JsonValue::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        matrix.get("matrix_id").and_then(JsonValue::as_str),
        Some("browser_consumer_compatibility_matrix")
    );

    let required = string_set(&matrix, "required_consumer_ids");
    assert_eq!(
        consumer_ids(&matrix),
        required,
        "consumer_matrix must exactly cover required_consumer_ids"
    );

    let rules = object(&matrix, "decision_rules");
    for key in [
        "candidate_window_required",
        "unsupported_skip_is_never_green",
        "bridge_broker_and_preview_rows_do_not_promote_direct_runtime",
        "required_failure_bundle_on_non_pass",
    ] {
        assert_eq!(
            rules.get(key).and_then(JsonValue::as_bool),
            Some(true),
            "decision_rules.{key} must be true"
        );
    }

    let source_artifacts = object(&matrix, "source_artifacts");
    for key in [
        "readiness_matrix",
        "package_integrity_gate",
        "e2e_log_schema",
        "human_report",
    ] {
        let path = source_artifacts
            .get(key)
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("source_artifacts.{key} must be a path"));
        assert!(path_exists(path), "source artifact missing: {path}");
    }
}

#[test]
fn consumer_rows_align_with_readiness_matrix_and_existing_fixtures() {
    let matrix = matrix();
    let readiness = readiness_rows_by_id();

    for row in array(&matrix, "consumer_matrix") {
        let consumer_id = string(row, "consumer_id");
        let surface_id = string(row, "readiness_surface_id");
        let readiness_row = readiness
            .get(surface_id)
            .unwrap_or_else(|| panic!("{consumer_id} references missing surface {surface_id}"));

        assert_eq!(
            string(row, "support_class"),
            string(readiness_row, "support_class"),
            "{consumer_id} support_class must match readiness matrix"
        );
        assert_eq!(
            row.get("direct_runtime_allowed")
                .and_then(JsonValue::as_bool),
            readiness_row
                .get("direct_runtime_allowed")
                .and_then(JsonValue::as_bool),
            "{consumer_id} direct_runtime_allowed must match readiness matrix"
        );

        let fixture_path = string(row.get("fixture").expect("fixture"), "path");
        assert!(
            path_exists(fixture_path),
            "{consumer_id} fixture missing: {fixture_path}"
        );

        let runner_value = row.get("runner").expect("runner");
        let script = string(runner_value, "script");
        let script_stem = Path::new(script)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(script);
        assert!(
            path_exists(script),
            "{consumer_id} runner script missing: {script}"
        );
        assert!(
            !string(runner_value, "command").is_empty(),
            "{consumer_id} runner command must be non-empty"
        );
        assert!(
            !string(runner_value, "summary_pattern").is_empty(),
            "{consumer_id} must declare summary artifact pattern"
        );

        let repro_commands = array(row, "repro_commands");
        assert!(
            !repro_commands.is_empty(),
            "{consumer_id} must declare fixture-specific repro commands"
        );
        assert!(
            repro_commands.iter().all(|command| {
                let command = command.as_str().unwrap_or_default();
                command.contains(script) || command.contains(script_stem)
            }),
            "{consumer_id} repro commands should reference its runner script"
        );
    }
}

#[test]
fn skip_preview_bridge_and_broker_rows_never_count_as_green_ga_rows() {
    let matrix = matrix();
    for row in array(&matrix, "consumer_matrix") {
        let consumer_id = string(row, "consumer_id");
        let support_class = string(row, "support_class");
        let outcome_value = row.get("expected_outcome").expect("expected_outcome");
        let outcome = object(row, "expected_outcome");
        let verdict = string(outcome_value, "verdict");
        let green_for_ga = outcome
            .get("green_for_ga")
            .and_then(JsonValue::as_bool)
            .unwrap_or_else(|| panic!("{consumer_id} missing expected_outcome.green_for_ga"));
        let promotion_effect = string(outcome_value, "promotion_effect");

        let restricted = matches!(
            support_class,
            "bridge_only"
                | "broker_coordinator_only"
                | "preview_public_lane"
                | "impossible_unsupported"
        );
        if restricted || verdict.contains("skip") {
            assert!(
                !green_for_ga,
                "{consumer_id} has support_class={support_class} verdict={verdict} but is green"
            );
            assert!(
                !promotion_effect.contains("eligible_for_browser_ga"),
                "{consumer_id} cannot be a direct GA promotion row"
            );
        }

        if let Some(skip_policy) = row.get("skip_policy") {
            assert_eq!(
                skip_policy.get("skip_allowed").and_then(JsonValue::as_bool),
                Some(true),
                "{consumer_id} skip_policy must explicitly allow skip"
            );
            assert_eq!(
                skip_policy
                    .get("skip_is_green")
                    .and_then(JsonValue::as_bool),
                Some(false),
                "{consumer_id} skip_policy.skip_is_green must be false"
            );
        }
    }
}

#[test]
fn structured_outputs_and_no_claim_boundaries_are_complete() {
    let matrix = matrix();
    let global_no_claims = string_set(&matrix, "no_claim_boundaries");
    for required in [
        "does_not_execute_npm_publish",
        "does_not_prove_broad_workspace_health",
        "does_not_promote_preview_rust_browser_runtime_to_stable",
        "does_not_promote_service_worker_or_shared_worker_direct_runtime",
        "does_not_claim_native_only_browser_capability_parity",
        "does_not_replace_b1_readiness_or_b2_package_integrity_gates",
    ] {
        assert!(
            global_no_claims.contains(required),
            "missing global no-claim boundary {required}"
        );
    }

    for row in array(&matrix, "consumer_matrix") {
        let consumer_id = string(row, "consumer_id");
        let outputs_value = row.get("structured_outputs").expect("structured_outputs");
        let outputs = object(row, "structured_outputs");
        assert_eq!(
            outputs
                .get("summary_json_required")
                .and_then(JsonValue::as_bool),
            Some(true),
            "{consumer_id} must require summary JSON"
        );
        assert_eq!(
            outputs.get("event_log_schema").and_then(JsonValue::as_str),
            Some("wasm-e2e-log-schema-v1"),
            "{consumer_id} must tie logs to the canonical WASM E2E schema"
        );
        assert_eq!(
            outputs
                .get("failure_bundle_required_on_non_pass")
                .and_then(JsonValue::as_bool),
            Some(true),
            "{consumer_id} must require failure bundles on non-pass"
        );
        assert!(
            !array(outputs_value, "required_summary_fields").is_empty(),
            "{consumer_id} must declare required summary fields"
        );
        assert!(
            !array(row, "no_claims").is_empty(),
            "{consumer_id} must declare row-level no-claims"
        );
    }
}

#[test]
fn failure_bundle_fixture_covers_required_fail_closed_cases() {
    let matrix = matrix();
    assert_eq!(
        matrix
            .get("failure_bundle_fixture")
            .and_then(JsonValue::as_str),
        Some(FAILURE_FIXTURE_PATH)
    );
    assert!(path_exists(FAILURE_FIXTURE_PATH));

    let fixture = json_file(FAILURE_FIXTURE_PATH);
    assert_eq!(
        fixture.get("schema_version").and_then(JsonValue::as_str),
        Some("browser-consumer-compatibility-failure-bundles-v1")
    );
    assert_eq!(
        fixture.get("bead_id").and_then(JsonValue::as_str),
        Some(BEAD_ID)
    );

    let required_fields = string_set(&fixture, "required_failure_fields");
    for required in [
        "consumer_id",
        "readiness_surface_id",
        "support_class",
        "verdict",
        "reason_code",
        "repro_command",
        "expected_action",
        "green_for_ga",
    ] {
        assert!(
            required_fields.contains(required),
            "missing failure field {required}"
        );
    }

    let consumers = consumer_ids(&matrix);
    let expected_rehearsals = BTreeSet::from([
        "missing_packaged_browser_artifact".to_owned(),
        "browser_capability_skip".to_owned(),
        "unsupported_direct_runtime_attempt".to_owned(),
        "next_edge_direct_runtime_attempt".to_owned(),
        "bundle_budget_regression".to_owned(),
        "rust_preview_rch_local_fallback".to_owned(),
        "native_only_surface_skip".to_owned(),
    ]);
    let actual_rehearsals = array(&fixture, "failure_rehearsals")
        .iter()
        .map(|rehearsal| string(rehearsal, "id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_rehearsals, expected_rehearsals);

    for rehearsal in array(&fixture, "failure_rehearsals") {
        let id = string(rehearsal, "id");
        let consumer_id = string(rehearsal, "consumer_id");
        assert!(
            consumers.contains(consumer_id),
            "{id} references unknown consumer {consumer_id}"
        );
        assert_eq!(
            rehearsal.get("green_for_ga").and_then(JsonValue::as_bool),
            Some(false),
            "{id} failure rehearsal must never be green"
        );
        assert!(
            !string(rehearsal, "expected_action").is_empty(),
            "{id} must name expected action"
        );
        assert!(
            !string(rehearsal, "repro_command").is_empty(),
            "{id} must name repro command"
        );
    }
}

#[test]
fn docs_and_validation_commands_reference_the_matrix() {
    let matrix = matrix();
    let docs = read_repo_file(DOC_PATH);
    assert!(docs.contains("browser-consumer-compatibility-matrix-v1"));
    assert!(docs.contains(BEAD_ID));
    assert!(docs.contains(MATRIX_PATH));
    assert!(docs.contains(FAILURE_FIXTURE_PATH));
    assert!(docs.contains("skip is not green evidence"));

    for consumer_id in consumer_ids(&matrix) {
        assert!(docs.contains(&consumer_id), "docs missing {consumer_id}");
    }

    let commands = array(&matrix, "validation_commands");
    assert!(
        commands.iter().any(|command| {
            string(command, "id") == "browser-consumer-compatibility-matrix-contract"
                && string(command, "command").contains("RCH_REQUIRE_REMOTE=1 rch exec")
                && string(command, "command")
                    .contains("browser_consumer_compatibility_matrix_contract")
        }),
        "focused remote-required contract command missing"
    );
}
