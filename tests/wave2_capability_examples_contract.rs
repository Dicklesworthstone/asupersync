#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const ARTIFACT_PATH: &str = "artifacts/wave2/capability_examples_smoke_recipes_evidence.json";
const REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_json(relative: &str) -> JsonValue {
    let path = repo_path(relative);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn artifact() -> JsonValue {
    read_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn optional_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
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
                .to_string()
        })
        .collect()
}

fn row_string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    string_set(value, key)
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-osh9jv".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

fn validate_example_rows(artifact: &JsonValue) -> Result<(), String> {
    let required_fields = string_set(artifact, "required_log_fields");
    let required_cases = string_set(artifact, "required_support_cases");
    let forbidden_markers = string_set(artifact, "forbidden_runtime_markers");
    let mut seen_cases = BTreeSet::new();

    for row in array(artifact, "example_rows") {
        let scenario_id = string(row, "scenario_id");
        for field in &required_fields {
            if row.get(field).is_none() {
                return Err(format!("{scenario_id}:missing_field:{field}"));
            }
        }

        let command = string(row, "command");
        if command.contains("cargo ") && !command.contains("rch exec --") {
            return Err(format!("{scenario_id}:cargo_command_without_rch"));
        }
        for marker in ["password=", "token=", "secret=", "bearer "] {
            assert!(
                !serde_json::to_string(row)
                    .expect("row serialization")
                    .to_lowercase()
                    .contains(marker),
                "{scenario_id}: sensitive marker {marker}"
            );
        }

        seen_cases.extend(row_string_set(row, "case_tags"));
        let example_path = optional_string(row, "example_path");
        let unsupported_reason = optional_string(row, "unsupported_reason");
        if unsupported_reason.trim().is_empty() {
            if example_path.trim().is_empty() || !repo_path(example_path).exists() {
                return Err(format!("{scenario_id}:example_path_not_found"));
            }
            assert_eq!(
                optional_string(row, "expected_output_digest"),
                optional_string(row, "actual_output_digest"),
                "{scenario_id}: digest mismatch"
            );
        } else {
            let fallback_target = string(row, "fallback_target");
            if !repo_path(fallback_target).exists() {
                return Err(format!("{scenario_id}:fallback_target_not_found"));
            }
            assert!(
                !string(row, "live_owner_bead_id").trim().is_empty(),
                "{scenario_id}: unsupported rows need a live owner bead"
            );
        }

        if example_path.starts_with("examples/") {
            let body = std::fs::read_to_string(repo_path(example_path))
                .unwrap_or_else(|err| panic!("read {example_path}: {err}"));
            for marker in &forbidden_markers {
                assert!(
                    !body.contains(marker),
                    "{scenario_id}: forbidden runtime marker {marker}"
                );
            }
        }
    }

    if !required_cases.is_subset(&seen_cases) {
        return Err(format!(
            "required_support_cases_missing:{:?}",
            required_cases
                .difference(&seen_cases)
                .cloned()
                .collect::<Vec<_>>()
        ));
    }

    Ok(())
}

fn promoted_registry_capability_ids(registry: &JsonValue) -> BTreeSet<String> {
    array(registry, "capability_rows")
        .iter()
        .filter(|row| row.get("promotion_state").and_then(JsonValue::as_str) == Some("promoted"))
        .map(|row| string(row, "capability_id").to_string())
        .collect()
}

fn example_capability_ids(artifact: &JsonValue) -> BTreeSet<String> {
    array(artifact, "example_rows")
        .iter()
        .map(|row| string(row, "capability_id").to_string())
        .collect()
}

fn validate_promoted_registry_coverage(
    artifact: &JsonValue,
    registry: &JsonValue,
) -> Result<(), String> {
    let promoted = promoted_registry_capability_ids(registry);
    let covered = example_capability_ids(artifact);
    let missing = promoted
        .difference(&covered)
        .cloned()
        .collect::<Vec<String>>();
    if !missing.is_empty() {
        return Err(format!("promoted_capability_examples_missing:{missing:?}"));
    }
    for row in array(artifact, "example_rows") {
        let capability_id = string(row, "capability_id");
        if promoted.contains(capability_id)
            && optional_string(row, "unsupported_reason").trim().is_empty()
        {
            let example_path = string(row, "example_path");
            if example_path.starts_with("artifacts/") {
                return Err(format!(
                    "{capability_id}:promoted_example_path_not_public:{example_path}"
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn artifact_declares_examples_schema_sources_and_required_logs() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("capability-examples-smoke-recipes-evidence-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-osh9jv")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("capability_examples_smoke_recipes")
    );

    for path_key in ["runner_script", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).is_file(),
            "{path_key} path must exist: {path}"
        );
    }
    for source_path in array(&artifact, "source_evidence_paths") {
        let source_path = source_path.as_str().expect("source path string");
        assert!(
            repo_path(source_path).exists(),
            "source evidence path must exist: {source_path}"
        );
    }

    let expected_log_fields = [
        "bead_id",
        "scenario_id",
        "capability_id",
        "example_path",
        "feature_flags",
        "host_context",
        "broker_kind",
        "platform_requirement",
        "command",
        "expected_output_digest",
        "actual_output_digest",
        "unsupported_reason",
        "fallback_target",
        "artifact_path",
        "verdict",
        "first_failure",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        string_set(&artifact, "required_log_fields"),
        expected_log_fields
    );

    log_contract_event(
        "examples-schema",
        &[
            (
                "source_evidence_paths",
                array(&artifact, "source_evidence_paths").len().to_string(),
            ),
            (
                "required_log_fields",
                array(&artifact, "required_log_fields").len().to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn example_rows_have_public_recipe_or_stable_unsupported_reason() {
    let artifact = artifact();
    validate_example_rows(&artifact).expect("example row contract");

    let rows = array(&artifact, "example_rows");
    let unsupported_rows = rows
        .iter()
        .filter(|row| !optional_string(row, "unsupported_reason").trim().is_empty())
        .count();
    assert!(
        unsupported_rows > 0,
        "pending proof must preserve unsupported reasons for unpromoted recipes"
    );

    log_contract_event(
        "example-row-coverage",
        &[
            ("example_rows", rows.len().to_string()),
            ("unsupported_rows", unsupported_rows.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn example_rows_cover_every_promoted_wave2_registry_capability() {
    let artifact = artifact();
    let registry = read_repo_json(REGISTRY_PATH);
    validate_promoted_registry_coverage(&artifact, &registry)
        .expect("promoted registry capability coverage");

    let promoted = promoted_registry_capability_ids(&registry);
    let covered = example_capability_ids(&artifact);
    log_contract_event(
        "promoted-registry-coverage",
        &[
            ("promoted_count", promoted.len().to_string()),
            ("covered_count", covered.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn missing_promoted_registry_capability_is_rejected() {
    let mut artifact = artifact();
    let registry = read_repo_json(REGISTRY_PATH);
    let target = promoted_registry_capability_ids(&registry)
        .into_iter()
        .next()
        .expect("at least one promoted capability");
    let rows = artifact
        .get_mut("example_rows")
        .and_then(JsonValue::as_array_mut)
        .expect("example rows");
    rows.retain(|row| {
        row.get("capability_id").and_then(JsonValue::as_str) != Some(target.as_str())
    });

    let err = validate_promoted_registry_coverage(&artifact, &registry)
        .expect_err("missing promoted capability must fail");
    assert!(
        err.contains("promoted_capability_examples_missing"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-missing-promoted-registry-row",
        &[
            ("removed_capability", target),
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn artifact_only_promoted_recipe_is_rejected() {
    let mut artifact = artifact();
    let registry = read_repo_json(REGISTRY_PATH);
    let target = promoted_registry_capability_ids(&registry)
        .into_iter()
        .next()
        .expect("at least one promoted capability");
    let rows = artifact
        .get_mut("example_rows")
        .and_then(JsonValue::as_array_mut)
        .expect("example rows");
    let row = rows
        .iter_mut()
        .find(|row| row.get("capability_id").and_then(JsonValue::as_str) == Some(target.as_str()))
        .expect("promoted example row");
    row["example_path"] =
        JsonValue::String("artifacts/wave2/capability_examples_smoke_recipes_evidence.json".into());
    row["unsupported_reason"] = JsonValue::String(String::new());

    let err = validate_promoted_registry_coverage(&artifact, &registry)
        .expect_err("artifact-only promoted capability must fail");
    assert!(
        err.contains("promoted_example_path_not_public"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-artifact-only-promoted-row",
        &[
            ("capability_id", target),
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn missing_example_and_unsupported_reason_is_rejected() {
    let mut artifact = artifact();
    let rows = artifact
        .get_mut("example_rows")
        .and_then(JsonValue::as_array_mut)
        .expect("example rows");
    let row = rows.first_mut().expect("first row");
    row["example_path"] = JsonValue::String(String::new());
    row["unsupported_reason"] = JsonValue::String(String::new());

    let err = validate_example_rows(&artifact).expect_err("invalid row must fail");
    assert!(
        err.contains("example_path_not_found"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-missing-example",
        &[
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn cargo_recipe_without_rch_is_rejected() {
    let mut artifact = artifact();
    let rows = artifact
        .get_mut("example_rows")
        .and_then(JsonValue::as_array_mut)
        .expect("example rows");
    let row = rows.first_mut().expect("first row");
    row["command"] = JsonValue::String("cargo check -p asupersync".to_string());

    let err = validate_example_rows(&artifact).expect_err("invalid row must fail");
    assert!(
        err.contains("cargo_command_without_rch"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-missing-rch",
        &[
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn smoke_runner_emits_required_log_fields_and_report() {
    let output_root = repo_path("target/wave2-capability-examples-contract");
    let output = Command::new("bash")
        .arg(repo_path("scripts/run_wave2_capability_examples_smoke.sh"))
        .arg("--artifact")
        .arg(repo_path(ARTIFACT_PATH))
        .arg("--output-root")
        .arg(&output_root)
        .arg("--run-id")
        .arg("contract")
        .output()
        .expect("run capability examples smoke script");

    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("runner stdout utf8");
    let required_fields = string_set(&artifact(), "required_log_fields");
    let row_lines = stdout
        .lines()
        .filter(|line| line.contains("bead_id=asupersync-osh9jv"))
        .collect::<Vec<_>>();
    assert!(!row_lines.is_empty(), "runner must emit row logs");
    for line in row_lines {
        for field in &required_fields {
            assert!(
                line.contains(&format!("{field}=")),
                "missing {field}: {line}"
            );
        }
    }

    let report_path = output_root
        .join("asupersync-osh9jv")
        .join("contract")
        .join("capability-examples-smoke-report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", report_path.display()));
    let report: JsonValue = serde_json::from_str(&report).expect("parse runner report");
    assert_eq!(
        report.get("validation_passed").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        report.get("row_count").and_then(JsonValue::as_u64),
        Some(array(&artifact(), "example_rows").len() as u64)
    );

    log_contract_event(
        "runner-report",
        &[
            (
                "row_count",
                report
                    .get("row_count")
                    .and_then(JsonValue::as_u64)
                    .unwrap_or(0)
                    .to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn registry_row_records_promoted_examples_artifact_contract() {
    let registry = read_repo_json(REGISTRY_PATH);
    let rows = array(&registry, "capability_rows");
    let row = rows
        .iter()
        .find(|row| {
            row.get("capability_id").and_then(JsonValue::as_str)
                == Some("capability_examples_smoke_recipes")
        })
        .expect("capability examples registry row");

    assert_eq!(
        row.get("owner_bead_id").and_then(JsonValue::as_str),
        Some("asupersync-osh9jv")
    );
    assert_eq!(
        row.get("promotion_state").and_then(JsonValue::as_str),
        Some("promoted")
    );
    assert_eq!(
        row.get("support_class_after").and_then(JsonValue::as_str),
        Some("artifact-contract-backed")
    );
    assert!(
        string_set(row, "artifact_paths").contains(ARTIFACT_PATH),
        "registry row must record the examples artifact as shipped proof"
    );
    assert!(
        string_set(row, "planned_artifact_paths").is_empty(),
        "promoted examples registry row cannot keep planned artifact paths"
    );
    assert!(
        row.get("unsupported_reason")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .trim()
            .is_empty(),
        "promoted examples registry row cannot carry unsupported_reason"
    );
    assert!(
        string_set(row, "unit_proof_commands")
            .iter()
            .any(|command| command.contains("wave2_capability_examples_contract")),
        "registry row must name this contract test"
    );
    assert!(
        string_set(row, "e2e_proof_commands")
            .contains("bash scripts/run_wave2_capability_examples_smoke.sh"),
        "registry row must name the smoke runner"
    );

    log_contract_event(
        "registry-promoted-link",
        &[
            ("promotion_state", "promoted".to_string()),
            ("artifact", ARTIFACT_PATH.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
