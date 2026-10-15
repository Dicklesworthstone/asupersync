#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const ARTIFACT_PATH: &str = "artifacts/wave2/docs_support_matrix_reconciliation_evidence.json";
const REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn read_repo_json(relative: &str) -> JsonValue {
    serde_json::from_str(&read_repo_text(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn artifact() -> JsonValue {
    read_repo_json(ARTIFACT_PATH)
}

fn registry() -> JsonValue {
    read_repo_json(REGISTRY_PATH)
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

fn registry_rows_by_capability(registry: &JsonValue) -> BTreeMap<String, &JsonValue> {
    array(registry, "capability_rows")
        .iter()
        .map(|row| (string(row, "capability_id").to_string(), row))
        .collect()
}

fn promoted_states(registry: &JsonValue) -> BTreeSet<String> {
    string_set(
        registry
            .get("registry_contract")
            .expect("registry_contract"),
        "promoted_states_require_full_evidence",
    )
}

fn promoted_registry_capability_ids(registry: &JsonValue) -> BTreeSet<String> {
    let promoted_states = promoted_states(registry);
    array(registry, "capability_rows")
        .iter()
        .filter(|row| promoted_states.contains(optional_string(row, "promotion_state")))
        .map(|row| string(row, "capability_id").to_string())
        .collect()
}

fn declared_promoted_capability_ids(artifact: &JsonValue) -> BTreeSet<String> {
    array(artifact, "promoted_capability_markers")
        .iter()
        .map(|row| string(row, "capability_id").to_string())
        .collect()
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-xl06qj".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

fn validate_doc_markers(artifact: &JsonValue) -> Result<(), String> {
    for row in array(artifact, "doc_marker_contract") {
        let path = string(row, "path");
        let text = read_repo_text(path);
        for marker in array(row, "required") {
            let marker = marker.as_str().expect("required marker string");
            if !text.contains(marker) {
                return Err(format!("doc_marker_missing:{path}:{marker}"));
            }
        }
        for marker in array(row, "forbidden") {
            let marker = marker.as_str().expect("forbidden marker string");
            if text.contains(marker) {
                return Err(format!("doc_forbidden_marker_present:{path}:{marker}"));
            }
        }
    }

    for support_row in array(artifact, "support_class_doc_markers") {
        let support_class = string(support_row, "support_class");
        for requirement in array(support_row, "docs_required") {
            let path = string(requirement, "path");
            let text = read_repo_text(path);
            for marker in array(requirement, "markers") {
                let marker = marker.as_str().expect("support marker string");
                if !text.contains(marker) {
                    return Err(format!(
                        "support_class_marker_missing:{support_class}:{path}:{marker}"
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_promoted_registry_reconciliation(
    artifact: &JsonValue,
    registry: &JsonValue,
) -> Result<(), String> {
    let promoted = promoted_registry_capability_ids(registry);
    let declared = declared_promoted_capability_ids(artifact);
    let missing = promoted
        .difference(&declared)
        .cloned()
        .collect::<Vec<String>>();
    if !missing.is_empty() {
        return Err(format!("promoted_capability_missing:{missing:?}"));
    }

    let rows_by_capability = registry_rows_by_capability(registry);
    let promoted_states = promoted_states(registry);
    for row in array(artifact, "promoted_capability_markers") {
        let capability_id = string(row, "capability_id");
        let registry_row = rows_by_capability
            .get(capability_id)
            .ok_or_else(|| format!("registry_row_missing:{capability_id}"))?;
        let expected = string(row, "expected_support_class_after");
        let actual = string(registry_row, "support_class_after");
        if actual != expected {
            return Err(format!(
                "support_class_after_mismatch:{capability_id}:{actual}:{expected}"
            ));
        }

        if promoted_states.contains(optional_string(registry_row, "promotion_state")) {
            if !optional_string(registry_row, "unsupported_reason")
                .trim()
                .is_empty()
            {
                return Err(format!(
                    "promoted_unsupported_reason_present:{capability_id}"
                ));
            }
            if array(registry_row, "artifact_paths").is_empty() {
                return Err(format!("promoted_artifact_paths_empty:{capability_id}"));
            }
        }

        for source in array(row, "source_artifacts") {
            let source = source.as_str().expect("source artifact string");
            if !repo_path(source).exists() {
                return Err(format!("promoted_source_missing:{capability_id}:{source}"));
            }
        }

        for marker in array(row, "doc_markers") {
            let path = string(marker, "path");
            let marker_text = string(marker, "marker");
            let text = read_repo_text(path);
            if !text.contains(marker_text) {
                return Err(format!(
                    "promoted_doc_marker_missing:{capability_id}:{path}:{marker_text}"
                ));
            }
        }
    }

    Ok(())
}

fn validate_deferred_registry_policy(registry: &JsonValue) -> Result<(), String> {
    let promoted_states = promoted_states(registry);
    for row in array(registry, "capability_rows") {
        let capability_id = string(row, "capability_id");
        if promoted_states.contains(optional_string(row, "promotion_state")) {
            continue;
        }
        let has_reason = !optional_string(row, "unsupported_reason").trim().is_empty();
        let has_residual = !array(row, "residual_risks").is_empty();
        let has_fallback_or_artifact = !optional_string(row, "fallback_target").trim().is_empty()
            || !array(row, "planned_artifact_paths").is_empty()
            || !array(row, "artifact_paths").is_empty();
        if !(has_reason || has_residual) || !has_fallback_or_artifact {
            return Err(format!("deferred_rationale_missing:{capability_id}"));
        }
    }
    Ok(())
}

fn validate_command_policy(artifact: &JsonValue, registry: &JsonValue) -> Result<(), String> {
    let mut commands = array(artifact, "command_examples_checked")
        .iter()
        .map(|entry| string(entry, "command").to_string())
        .collect::<Vec<_>>();
    for row in array(registry, "capability_rows") {
        commands.extend(
            array(row, "unit_proof_commands")
                .iter()
                .map(|command| command.as_str().expect("unit command string").to_string()),
        );
        commands.extend(
            array(row, "e2e_proof_commands")
                .iter()
                .map(|command| command.as_str().expect("e2e command string").to_string()),
        );
    }

    for command in commands {
        if (command.contains("cargo ") || command.contains("lake build"))
            && !command.contains("rch exec --")
        {
            return Err(format!("command_missing_rch:{command}"));
        }
        for forbidden in ["password=", "token=", "secret=", "bearer "] {
            if command.to_ascii_lowercase().contains(forbidden) {
                return Err(format!("command_sensitive_marker:{forbidden}:{command}"));
            }
        }
    }
    Ok(())
}

#[test]
fn artifact_declares_schema_sources_support_classes_and_required_logs() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("wave2-docs-support-matrix-reconciliation-evidence-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-xl06qj")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("docs_support_matrix_reconciliation")
    );

    for path_key in ["artifact_path", "runner_script", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).exists(),
            "{path_key} path must exist: {path}"
        );
    }

    for doc in array(&artifact, "docs_checked") {
        let doc = doc.as_str().expect("doc path string");
        assert!(repo_path(doc).is_file(), "doc path must exist: {doc}");
    }

    for source in array(&artifact, "source_artifacts_checked") {
        let source = source.as_str().expect("source path string");
        assert!(
            repo_path(source).exists(),
            "source artifact path must exist: {source}"
        );
    }

    let expected_log_fields = [
        "bead_id",
        "scenario_id",
        "docs_checked",
        "source_artifacts_checked",
        "support_classes_seen",
        "promoted_capabilities",
        "deferred_capabilities",
        "deferred_links_checked",
        "command_examples_checked",
        "drift_count",
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

    let support_classes = string_set(&artifact, "public_support_classes");
    for required in [
        "shipped",
        "feature-gated",
        "preview",
        "lab/virtual-backed",
        "substrate-only",
        "broker/coordinator-only",
        "deferred",
        "unsupported",
        "platform-scoped",
    ] {
        assert!(
            support_classes.contains(required),
            "missing support class {required}"
        );
    }

    log_contract_event(
        "artifact-schema",
        &[
            (
                "docs_checked",
                array(&artifact, "docs_checked").len().to_string(),
            ),
            (
                "source_artifacts_checked",
                array(&artifact, "source_artifacts_checked")
                    .len()
                    .to_string(),
            ),
            ("support_classes_seen", support_classes.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn public_docs_have_wave2_support_markers_and_no_stale_overclaims() {
    let artifact = artifact();
    validate_doc_markers(&artifact).expect("public docs marker contract");

    log_contract_event(
        "doc-marker-contract",
        &[
            (
                "doc_rows",
                array(&artifact, "doc_marker_contract").len().to_string(),
            ),
            (
                "support_class_rows",
                array(&artifact, "support_class_doc_markers")
                    .len()
                    .to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn promoted_registry_rows_have_public_docs_markers_and_source_artifacts() {
    let artifact = artifact();
    let registry = registry();
    validate_promoted_registry_reconciliation(&artifact, &registry)
        .expect("promoted registry docs reconciliation");

    let promoted = promoted_registry_capability_ids(&registry);
    log_contract_event(
        "promoted-registry-reconciliation",
        &[
            ("promoted_capabilities", promoted.len().to_string()),
            (
                "declared_promoted",
                declared_promoted_capability_ids(&artifact)
                    .len()
                    .to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn non_promoted_registry_rows_keep_deferred_rationale() {
    let registry = registry();
    validate_deferred_registry_policy(&registry).expect("deferred registry policy");

    let promoted = promoted_registry_capability_ids(&registry);
    let deferred_count = array(&registry, "capability_rows")
        .len()
        .checked_sub(promoted.len())
        .expect("promoted subset");
    log_contract_event(
        "deferred-registry-policy",
        &[
            ("deferred_capabilities", deferred_count.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn proof_commands_preserve_rch_boundary_and_redaction() {
    let artifact = artifact();
    let registry = registry();
    validate_command_policy(&artifact, &registry).expect("proof command policy");

    log_contract_event(
        "command-policy",
        &[
            (
                "command_examples_checked",
                array(&artifact, "command_examples_checked")
                    .len()
                    .to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn missing_promoted_registry_capability_is_rejected() {
    let mut artifact = artifact();
    let registry = registry();
    let target = promoted_registry_capability_ids(&registry)
        .into_iter()
        .next()
        .expect("at least one promoted capability");
    let rows = artifact
        .get_mut("promoted_capability_markers")
        .and_then(JsonValue::as_array_mut)
        .expect("promoted capability markers");
    rows.retain(|row| {
        row.get("capability_id").and_then(JsonValue::as_str) != Some(target.as_str())
    });

    let err = validate_promoted_registry_reconciliation(&artifact, &registry)
        .expect_err("missing promoted row must fail");
    assert!(
        err.contains("promoted_capability_missing"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-missing-promoted",
        &[
            ("removed_capability", target),
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn missing_public_marker_for_promoted_capability_is_rejected() {
    let mut artifact = artifact();
    let registry = registry();
    let rows = artifact
        .get_mut("promoted_capability_markers")
        .and_then(JsonValue::as_array_mut)
        .expect("promoted capability markers");
    let row = rows.first_mut().expect("first promoted marker row");
    let markers = row
        .get_mut("doc_markers")
        .and_then(JsonValue::as_array_mut)
        .expect("doc markers");
    markers[0]["marker"] = JsonValue::String("definitely-not-a-real-wave2-marker".into());
    let capability = row
        .get("capability_id")
        .and_then(JsonValue::as_str)
        .unwrap_or("<missing>")
        .to_string();

    let err = validate_promoted_registry_reconciliation(&artifact, &registry)
        .expect_err("missing public marker must fail");
    assert!(
        err.contains("promoted_doc_marker_missing"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-missing-promoted-marker",
        &[
            ("capability_id", capability),
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn cargo_or_lake_command_without_rch_is_rejected() {
    let mut artifact = artifact();
    let registry = registry();
    let rows = artifact
        .get_mut("command_examples_checked")
        .and_then(JsonValue::as_array_mut)
        .expect("command examples");
    rows[0]["command"] = JsonValue::String("cargo test -p asupersync".to_string());

    let err =
        validate_command_policy(&artifact, &registry).expect_err("cargo without rch must fail");
    assert!(
        err.contains("command_missing_rch"),
        "unexpected error: {err}"
    );

    log_contract_event(
        "negative-command-without-rch",
        &[
            ("rejected", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn smoke_runner_emits_required_log_fields_and_report() {
    let output_root = repo_path("target/wave2-docs-support-matrix-contract");
    let output = Command::new("bash")
        .arg(repo_path(
            "scripts/run_wave2_docs_support_matrix_reconciliation.sh",
        ))
        .arg("--artifact")
        .arg(repo_path(ARTIFACT_PATH))
        .arg("--output-root")
        .arg(&output_root)
        .arg("--run-id")
        .arg("contract")
        .output()
        .expect("run docs support reconciliation script");

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
        .filter(|line| line.contains("bead_id=asupersync-xl06qj"))
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
        .join("asupersync-xl06qj")
        .join("contract")
        .join("docs-support-matrix-report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", report_path.display()));
    let report: JsonValue = serde_json::from_str(&report).expect("parse runner report");
    assert_eq!(
        report.get("schema_version").and_then(JsonValue::as_str),
        Some("wave2-docs-support-matrix-reconciliation-report-v1")
    );
    assert_eq!(
        report.get("verdict").and_then(JsonValue::as_str),
        Some("passed")
    );
    assert_eq!(
        report.get("drift_count").and_then(JsonValue::as_u64),
        Some(0)
    );

    log_contract_event(
        "runner-report",
        &[
            (
                "promoted_capabilities",
                array(&report, "promoted_capabilities").len().to_string(),
            ),
            (
                "deferred_capabilities",
                array(&report, "deferred_capabilities").len().to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
