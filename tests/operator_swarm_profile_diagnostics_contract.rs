#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const ARTIFACT_PATH: &str = "artifacts/wave2/operator_swarm_profile_diagnostics_evidence.json";

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

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a serde_json::Map<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
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

fn u64_value(value: &JsonValue, key: &str) -> u64 {
    value
        .get(key)
        .and_then(JsonValue::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
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
        "bead_id=asupersync-5dudcn".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

#[test]
fn artifact_declares_operator_schema_sources_and_required_log_fields() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("operator-swarm-profile-diagnostics-evidence-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-5dudcn")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("operator_swarm_profile_diagnostics")
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
        "host_profile",
        "selected_profile",
        "confidence_score",
        "saturation_class",
        "primary_bottleneck",
        "recommended_action",
        "rollback_trigger",
        "no_win_reason",
        "redaction_verdict",
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

    let decision_contract = object(&artifact, "decision_contract");
    assert!(
        decision_contract
            .get("aggressive_profile_gate")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .contains("confidence_score >= 90"),
        "aggressive recommendations must be confidence gated"
    );
    assert!(
        decision_contract
            .get("fallback_policy")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .contains("conservative baseline"),
        "fallback policy must keep conservative baseline"
    );

    log_contract_event(
        "operator-schema",
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
fn diagnostics_cover_all_saturation_classes_and_recommendation_cases() {
    let artifact = artifact();
    let required_saturation_classes = string_set(&artifact, "required_saturation_classes");
    let required_cases = string_set(&artifact, "recommendation_case_requirements");
    let rows = array(&artifact, "diagnostic_rows");
    let seen_saturation_classes = rows
        .iter()
        .map(|row| string(row, "saturation_class").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        seen_saturation_classes, required_saturation_classes,
        "diagnostic rows must cover every required saturation class"
    );

    let seen_cases = rows
        .iter()
        .flat_map(|row| row_string_set(row, "case_tags"))
        .collect::<BTreeSet<_>>();
    assert!(
        required_cases.is_subset(&seen_cases),
        "missing recommendation cases: required={required_cases:?} seen={seen_cases:?}"
    );

    for row in rows {
        let scenario_id = string(row, "scenario_id");
        let selected_profile = string(row, "selected_profile");
        let confidence_score = u64_value(row, "confidence_score");
        assert!(confidence_score <= 100, "{scenario_id}: confidence cap");
        assert!(
            !string(row, "primary_bottleneck").trim().is_empty(),
            "{scenario_id}: primary bottleneck"
        );
        assert!(
            !string(row, "recommended_action").trim().is_empty(),
            "{scenario_id}: recommended action"
        );
        assert!(
            !array(row, "source_refs").is_empty(),
            "{scenario_id}: source refs"
        );
        if selected_profile != "conservative_baseline" {
            assert!(
                confidence_score >= 90,
                "{scenario_id}: aggressive profile requires high confidence"
            );
            assert!(
                !string(row, "rollback_trigger").trim().is_empty(),
                "{scenario_id}: aggressive profile requires rollback trigger"
            );
            assert_eq!(optional_string(row, "no_win_reason"), "");
            assert_eq!(string(row, "verdict"), "pass");
        } else {
            assert!(
                !optional_string(row, "no_win_reason").trim().is_empty(),
                "{scenario_id}: conservative fallback needs no-win reason"
            );
            assert_eq!(string(row, "verdict"), "no_win");
        }
    }

    log_contract_event(
        "saturation-and-cases",
        &[
            (
                "saturation_classes",
                seen_saturation_classes.len().to_string(),
            ),
            ("recommendation_cases", seen_cases.len().to_string()),
            ("diagnostic_rows", rows.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn source_refs_link_to_capacity_and_host_profile_evidence() {
    let artifact = artifact();
    let host_profile_contract =
        read_repo_json("artifacts/host_profile_planner_smoke_contract_v1.json");
    let host_profile_ids = array(&host_profile_contract, "smoke_scenarios")
        .iter()
        .map(|row| string(row, "scenario_id").to_string())
        .collect::<BTreeSet<_>>();
    let capacity_contract =
        read_repo_json("artifacts/wave2/massive_swarm_capacity_envelope_evidence.json");
    let capacity_ids = array(&capacity_contract, "profile_matrix")
        .iter()
        .map(|row| string(row, "scenario_id").to_string())
        .collect::<BTreeSet<_>>();

    let mut host_profile_refs = 0usize;
    let mut capacity_refs = 0usize;
    for row in array(&artifact, "diagnostic_rows") {
        for source_ref in row_string_set(row, "source_refs") {
            if host_profile_ids.contains(&source_ref) {
                host_profile_refs += 1;
            }
            if capacity_ids.contains(&source_ref) {
                capacity_refs += 1;
            }
        }
    }
    assert!(
        host_profile_refs >= 3,
        "operator diagnostics should consume host profile scenarios"
    );
    assert!(
        capacity_refs >= 2,
        "operator diagnostics should consume capacity-envelope profile scenarios"
    );

    for source_ref in array(&artifact, "host_profile_source_refs") {
        let scenario_id = string(source_ref, "scenario_id");
        assert!(
            host_profile_ids.contains(scenario_id),
            "host profile source ref missing from host profile contract: {scenario_id}"
        );
    }
    for source_ref in array(&artifact, "capacity_envelope_source_refs") {
        let scenario_id = source_ref.as_str().expect("capacity source ref string");
        assert!(
            capacity_ids.contains(scenario_id),
            "capacity source ref missing from capacity envelope artifact: {scenario_id}"
        );
    }

    log_contract_event(
        "source-linkage",
        &[
            ("host_profile_refs", host_profile_refs.to_string()),
            ("capacity_refs", capacity_refs.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn redaction_and_no_win_rows_are_operator_safe() {
    let artifact = artifact();
    let serialized = serde_json::to_string(&artifact).expect("artifact serializes");
    for forbidden in [
        "api_token=super-secret",
        "bearer raw",
        "password=",
        "secret=",
        "token=super-secret",
    ] {
        assert!(
            !serialized.to_ascii_lowercase().contains(forbidden),
            "artifact must not contain sensitive marker {forbidden}"
        );
    }

    let rows = array(&artifact, "diagnostic_rows");
    let redacted_rows = rows
        .iter()
        .filter(|row| string(row, "redaction_verdict") == "redacted")
        .count();
    let no_win_rows = rows
        .iter()
        .filter(|row| string(row, "verdict") == "no_win")
        .count();
    assert!(redacted_rows >= 2, "must prove redacted operator rows");
    assert!(no_win_rows >= 4, "must include no-win fallback rows");

    for row in rows {
        let redaction_verdict = string(row, "redaction_verdict");
        assert!(
            matches!(redaction_verdict, "not_applicable" | "redacted"),
            "unsupported redaction verdict {redaction_verdict}"
        );
        if string(row, "verdict") == "no_win" {
            assert!(
                !optional_string(row, "no_win_reason").is_empty(),
                "no-win row needs reason"
            );
        }
    }

    log_contract_event(
        "operator-safety",
        &[
            ("redacted_rows", redacted_rows.to_string()),
            ("no_win_rows", no_win_rows.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn runner_emits_required_operator_logs_and_report() {
    let output_root = repo_path("target/operator-swarm-profile-diagnostics-contract");
    let output = Command::new("bash")
        .arg(repo_path(
            "scripts/run_operator_swarm_profile_diagnostics.sh",
        ))
        .arg("--output-root")
        .arg(&output_root)
        .arg("--profile")
        .arg("all")
        .arg("--run-id")
        .arg("contract")
        .output()
        .expect("run operator swarm profile diagnostics script");
    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = output_root.join("run_contract/run_report.json");
    let log_path = output_root.join("run_contract/run.log");
    let report = serde_json::from_str::<JsonValue>(
        &std::fs::read_to_string(&report_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", report_path.display())),
    )
    .unwrap_or_else(|err| panic!("parse {}: {err}", report_path.display()));
    assert_eq!(
        report.get("schema_version").and_then(JsonValue::as_str),
        Some("operator-swarm-profile-diagnostics-run-report-v1")
    );
    assert_eq!(
        report.get("validation_passed").and_then(JsonValue::as_bool),
        Some(true)
    );

    let rows = array(&report, "diagnostic_rows");
    assert_eq!(rows.len(), 8, "runner should emit all diagnostic rows");
    let required_fields = string_set(&report, "required_log_fields");
    let log_body = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", log_path.display()));
    assert_eq!(log_body.lines().count(), rows.len(), "run.log row count");

    for row in rows {
        let scenario_id = string(row, "scenario_id");
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "{scenario_id}: missing required log field {field}"
            );
            assert!(
                log_body.contains(&format!("{field}=")),
                "run.log should include key {field}"
            );
        }
        assert_eq!(
            optional_string(row, "artifact_path"),
            "target/operator-swarm-profile-diagnostics-contract/run_contract/run_report.json"
        );
        assert_eq!(optional_string(row, "first_failure"), "");
    }

    log_contract_event(
        "runner-output",
        &[
            ("rows", rows.len().to_string()),
            ("required_fields", required_fields.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
