#![allow(missing_docs)]

use serde_json::{Value as JsonValue, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const SIGNOFF_PATH: &str = "artifacts/wave2/wave2_signoff_proof_pack_evidence.json";
const REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";

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

fn signoff() -> JsonValue {
    json_file(SIGNOFF_PATH)
}

fn registry() -> JsonValue {
    json_file(REGISTRY_PATH)
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn nonempty_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
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

fn promoted_states(registry: &JsonValue) -> BTreeSet<String> {
    string_set(
        registry
            .get("registry_contract")
            .expect("registry_contract object"),
        "promoted_states_require_full_evidence",
    )
}

fn registry_rows_by_capability(registry: &JsonValue) -> BTreeMap<String, &JsonValue> {
    array(registry, "capability_rows")
        .iter()
        .map(|row| (nonempty_string(row, "capability_id").to_string(), row))
        .collect()
}

fn signoff_rows_by_capability(signoff: &JsonValue) -> BTreeMap<String, &JsonValue> {
    array(signoff, "signoff_rows")
        .iter()
        .map(|row| (nonempty_string(row, "capability_id").to_string(), row))
        .collect()
}

fn validate_signoff_artifact(
    signoff: &JsonValue,
    registry: &JsonValue,
    check_paths: bool,
) -> Vec<String> {
    let mut failures = Vec::new();
    let promoted_states = promoted_states(registry);
    let registry_rows = registry_rows_by_capability(registry);
    let signoff_rows = signoff_rows_by_capability(signoff);

    if registry_rows.keys().collect::<BTreeSet<_>>() != signoff_rows.keys().collect::<BTreeSet<_>>()
    {
        failures.push("capability_inventory_mismatch".to_string());
    }

    let required_owners = string_set(registry, "required_wave2_child_beads");
    let signoff_owners = array(signoff, "signoff_rows")
        .iter()
        .map(|row| nonempty_string(row, "owner_bead_id").to_string())
        .collect::<Vec<_>>();
    let unique_owners = signoff_owners.iter().cloned().collect::<BTreeSet<_>>();
    if unique_owners != required_owners {
        failures.push("owner_inventory_mismatch".to_string());
    }
    if unique_owners.len() != signoff_owners.len() {
        failures.push("duplicate_owner_bead_id".to_string());
    }

    for (capability_id, row) in signoff_rows {
        let Some(registry_row) = registry_rows.get(&capability_id) else {
            continue;
        };
        for key in [
            "owner_bead_id",
            "promotion_state",
            "support_class_before",
            "support_class_after",
            "unsupported_reason",
            "fallback_target",
            "redaction_verdict",
        ] {
            if row.get(key) != registry_row.get(key) {
                failures.push(format!("{capability_id}:{key}_registry_drift"));
            }
        }

        let source_files = array(row, "source_files");
        let test_files = array(row, "test_files");
        let unit_proofs = array(row, "unit_proofs");
        let e2e_proofs = array(row, "e2e_proofs");
        let e2e_artifacts = array(row, "e2e_artifacts");
        let residual_risks = array(row, "residual_risks");
        let promotion_state = nonempty_string(row, "promotion_state");
        let is_promoted = promoted_states.contains(promotion_state);

        if test_files.is_empty() {
            failures.push(format!("{capability_id}:missing_test_file"));
        }
        if check_paths {
            for source_file in source_files {
                let path = source_file.as_str().expect("source file string");
                if !repo_path(path).exists() {
                    failures.push(format!("{capability_id}:missing_source:{path}"));
                }
            }
            for artifact in e2e_artifacts {
                let path = nonempty_string(artifact, "path");
                let state = nonempty_string(artifact, "state");
                if state == "shipped" && !repo_path(path).exists() {
                    failures.push(format!("{capability_id}:missing_artifact:{path}"));
                }
            }
        }

        if is_promoted {
            if source_files.is_empty() {
                failures.push(format!("{capability_id}:promoted_missing_source"));
            }
            if unit_proofs.is_empty() {
                failures.push(format!("{capability_id}:promoted_missing_unit_proof"));
            }
            if e2e_proofs.is_empty() {
                failures.push(format!("{capability_id}:promoted_missing_e2e_proof"));
            }
            let shipped_artifact_count = e2e_artifacts
                .iter()
                .filter(|artifact| {
                    artifact.get("state").and_then(JsonValue::as_str) == Some("shipped")
                })
                .count();
            if shipped_artifact_count == 0 {
                failures.push(format!("{capability_id}:promoted_missing_shipped_artifact"));
            }
            if row
                .get("unsupported_reason")
                .and_then(JsonValue::as_str)
                .is_some_and(|reason| !reason.trim().is_empty())
            {
                failures.push(format!("{capability_id}:promoted_has_unsupported_reason"));
            }
            if matches!(
                row.get("support_class_after").and_then(JsonValue::as_str),
                Some("pending-proof" | "unsupported" | "deferred")
            ) {
                failures.push(format!(
                    "{capability_id}:promoted_has_pending_support_class"
                ));
            }
        } else {
            let has_rationale = row
                .get("unsupported_reason")
                .and_then(JsonValue::as_str)
                .is_some_and(|reason| !reason.trim().is_empty())
                || row
                    .get("fallback_target")
                    .and_then(JsonValue::as_str)
                    .is_some_and(|target| !target.trim().is_empty())
                || !residual_risks.is_empty();
            if !has_rationale {
                failures.push(format!("{capability_id}:deferred_missing_rationale"));
            }
            if e2e_artifacts.is_empty() {
                failures.push(format!("{capability_id}:deferred_missing_artifact_or_plan"));
            }
        }

        for command_row in unit_proofs.iter().chain(e2e_proofs.iter()) {
            let command = nonempty_string(command_row, "command");
            if (command.contains("cargo ") || command.contains("lake build"))
                && !command.contains("rch exec --")
            {
                failures.push(format!("{capability_id}:heavy_command_without_rch"));
            }
            let lowered = command.to_ascii_lowercase();
            for marker in ["password=", "token=", "secret=", "bearer "] {
                if lowered.contains(marker) {
                    failures.push(format!("{capability_id}:sensitive_command_marker:{marker}"));
                }
            }
        }
    }

    failures
}

fn first_row_mut<'a>(
    value: &'a mut JsonValue,
    predicate: impl Fn(&JsonValue) -> bool,
) -> &'a mut JsonValue {
    value
        .get_mut("signoff_rows")
        .and_then(JsonValue::as_array_mut)
        .expect("signoff_rows array")
        .iter_mut()
        .find(|row| predicate(row))
        .expect("matching row")
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-1e5xeh".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

#[test]
fn signoff_artifact_has_stable_schema_paths_and_required_log_fields() {
    let signoff = signoff();
    assert_eq!(
        signoff.get("schema_version").and_then(JsonValue::as_str),
        Some("wave2-signoff-proof-pack-evidence-v1")
    );
    assert_eq!(
        signoff.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-1e5xeh")
    );
    assert_eq!(
        signoff.get("wave_id").and_then(JsonValue::as_str),
        Some("reality-check-wave2")
    );
    for key in [
        "artifact_path",
        "runner_script",
        "contract_test",
        "registry_path",
        "issues_path",
    ] {
        let path = nonempty_string(&signoff, key);
        assert!(repo_path(path).exists(), "{key} path must exist: {path}");
    }

    let required_fields = string_set(&signoff, "required_log_fields");
    let expected = [
        "bead_id",
        "wave_id",
        "child_bead_count",
        "closed_child_count",
        "promoted_count",
        "deferred_count",
        "proof_command_count",
        "e2e_artifact_count",
        "docs_drift_count",
        "bv_cycle_count",
        "br_ready_count",
        "residual_risk_count",
        "artifact_path",
        "verdict",
        "first_failure",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    assert_eq!(required_fields, expected);

    log_contract_event(
        "schema",
        &[
            ("required_fields", required_fields.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn every_wave2_child_and_registry_capability_appears_exactly_once() {
    let signoff = signoff();
    let registry = registry();
    let failures = validate_signoff_artifact(&signoff, &registry, false);
    assert!(
        !failures
            .iter()
            .any(|failure| failure.contains("inventory") || failure.contains("duplicate")),
        "inventory failures: {failures:?}"
    );
    assert_eq!(
        array(&signoff, "signoff_rows").len(),
        string_set(&registry, "required_wave2_child_beads").len()
    );

    log_contract_event(
        "inventory",
        &[
            (
                "signoff_rows",
                array(&signoff, "signoff_rows").len().to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn promoted_rows_have_source_unit_e2e_command_artifact_and_support_transition() {
    let signoff = signoff();
    let registry = registry();
    let failures = validate_signoff_artifact(&signoff, &registry, true);
    let promoted_failures = failures
        .iter()
        .filter(|failure| {
            failure.contains("promoted_")
                || failure.contains("missing_source")
                || failure.contains("missing_artifact")
                || failure.contains("_registry_drift")
        })
        .collect::<Vec<_>>();
    assert!(promoted_failures.is_empty(), "{promoted_failures:?}");

    let promoted_states = promoted_states(&registry);
    let promoted_count = array(&signoff, "signoff_rows")
        .iter()
        .filter(|row| promoted_states.contains(nonempty_string(row, "promotion_state")))
        .count();
    assert!(promoted_count >= 10, "signoff row should be promoted");

    log_contract_event(
        "promoted-gates",
        &[
            ("promoted_count", promoted_count.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn deferred_rows_keep_rationale_fallback_planned_artifacts_and_residual_risk() {
    let signoff = signoff();
    let registry = registry();
    let failures = validate_signoff_artifact(&signoff, &registry, false);
    let deferred_failures = failures
        .iter()
        .filter(|failure| failure.contains("deferred_"))
        .collect::<Vec<_>>();
    assert!(deferred_failures.is_empty(), "{deferred_failures:?}");

    let promoted_states = promoted_states(&registry);
    let deferred_count = array(&signoff, "signoff_rows")
        .iter()
        .filter(|row| !promoted_states.contains(nonempty_string(row, "promotion_state")))
        .count();
    assert!(
        deferred_count > 0,
        "signoff must keep unresolved rows visible"
    );

    log_contract_event(
        "deferred-gates",
        &[
            ("deferred_count", deferred_count.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn control_plane_checks_record_graph_health_and_degraded_cycle_fallback() {
    let signoff = signoff();
    let checks = array(&signoff, "control_plane_checks")
        .iter()
        .map(|check| (nonempty_string(check, "command_id").to_string(), check))
        .collect::<BTreeMap<_, _>>();
    for required in [
        "br_lint",
        "br_ready_json",
        "br_dep_cycles_json",
        "bv_robot_plan",
        "bv_robot_alerts",
        "bv_robot_suggest",
    ] {
        assert!(checks.contains_key(required), "missing {required}");
    }
    assert_eq!(
        checks["br_lint"].get("status").and_then(JsonValue::as_str),
        Some("passed")
    );
    assert_eq!(
        checks["br_dep_cycles_json"]
            .get("status")
            .and_then(JsonValue::as_str),
        Some("timed_out")
    );
    nonempty_string(checks["br_dep_cycles_json"], "degraded_fallback");

    log_contract_event(
        "control-plane",
        &[
            ("checks", checks.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn cargo_and_lake_proof_commands_are_rch_offloaded_and_redacted() {
    let signoff = signoff();
    let registry = registry();
    let failures = validate_signoff_artifact(&signoff, &registry, false);
    let command_failures = failures
        .iter()
        .filter(|failure| {
            failure.contains("heavy_command_without_rch")
                || failure.contains("sensitive_command_marker")
        })
        .collect::<Vec<_>>();
    assert!(command_failures.is_empty(), "{command_failures:?}");
}

#[test]
fn runner_emits_required_summary_fields_and_report() {
    let signoff = signoff();
    let runner = nonempty_string(&signoff, "runner_script");
    let output_root = repo_path("target/wave2-signoff-proof-pack-contract-test");
    let output = Command::new("bash")
        .arg(repo_path(runner))
        .arg("--output-root")
        .arg(&output_root)
        .arg("--run-id")
        .arg("contract")
        .output()
        .unwrap_or_else(|err| panic!("run {runner}: {err}"));
    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = output_root
        .join("asupersync-1e5xeh")
        .join("contract")
        .join("wave2-signoff-report.json");
    assert!(
        report_path.is_file(),
        "report missing: {}",
        report_path.display()
    );
    let report: JsonValue = serde_json::from_str(
        &std::fs::read_to_string(&report_path)
            .unwrap_or_else(|err| panic!("read runner report: {err}")),
    )
    .unwrap_or_else(|err| panic!("parse runner report: {err}"));
    assert_eq!(
        report.get("schema_version").and_then(JsonValue::as_str),
        Some("wave2-signoff-proof-pack-report-v1")
    );
    assert_eq!(
        report.get("verdict").and_then(JsonValue::as_str),
        Some("passed")
    );

    let summary = array(&report, "events")
        .iter()
        .find(|event| event.get("scenario_id").and_then(JsonValue::as_str) == Some("summary"))
        .expect("summary event");
    for field in array(&signoff, "required_log_fields") {
        let field = field.as_str().expect("field string");
        assert!(summary.get(field).is_some(), "summary missing {field}");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bead_id=asupersync-1e5xeh"));
    assert!(stdout.contains("scenario_id=summary"));

    log_contract_event(
        "runner",
        &[
            ("events", array(&report, "events").len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn negative_promoted_row_without_source_proof_is_rejected() {
    let mut signoff = signoff();
    let registry = registry();
    let promoted = promoted_states(&registry);
    let row = first_row_mut(&mut signoff, |row| {
        promoted.contains(nonempty_string(row, "promotion_state"))
    });
    row["source_files"] = json!([]);
    let failures = validate_signoff_artifact(&signoff, &registry, false);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("promoted_missing_source")),
        "{failures:?}"
    );
}

#[test]
fn negative_deferred_row_without_rationale_is_rejected() {
    let mut signoff = signoff();
    let registry = registry();
    let promoted = promoted_states(&registry);
    let row = first_row_mut(&mut signoff, |row| {
        !promoted.contains(nonempty_string(row, "promotion_state"))
    });
    row["unsupported_reason"] = json!("");
    row["fallback_target"] = json!("");
    row["residual_risks"] = json!([]);
    let failures = validate_signoff_artifact(&signoff, &registry, false);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("deferred_missing_rationale")),
        "{failures:?}"
    );
}

#[test]
fn negative_cargo_command_without_rch_is_rejected() {
    let mut signoff = signoff();
    let registry = registry();
    let row = first_row_mut(&mut signoff, |_| true);
    row["unit_proofs"][0]["command"] = json!("cargo test -p asupersync --test bad");
    let failures = validate_signoff_artifact(&signoff, &registry, false);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("heavy_command_without_rch")),
        "{failures:?}"
    );
}
