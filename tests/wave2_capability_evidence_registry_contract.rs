#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";
const TRACKER_ISSUES_PATH: &str = ".beads/issues.jsonl";
const DIRECT_LEAN_BUILD_COMMAND: &str = "rch exec -- lake --dir formal/lean build";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn registry() -> JsonValue {
    serde_json::from_str(&read_repo_file(REGISTRY_PATH))
        .unwrap_or_else(|err| panic!("parse {REGISTRY_PATH}: {err}"))
}

fn closed_owner_beads_from_tracker() -> BTreeSet<String> {
    read_repo_file(TRACKER_ISSUES_PATH)
        .lines()
        .filter_map(|line| serde_json::from_str::<JsonValue>(line).ok())
        .filter(|row| row.get("status").and_then(JsonValue::as_str) == Some("closed"))
        .filter_map(|row| row.get("id").and_then(JsonValue::as_str).map(str::to_owned))
        .collect()
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

fn row_string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-6qju7t".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

#[test]
fn registry_has_stable_schema_runner_and_support_class_vocabulary() {
    let registry = registry();
    assert_eq!(
        registry.get("schema_version").and_then(JsonValue::as_str),
        Some("wave2-capability-evidence-registry-v1")
    );
    assert_eq!(
        registry.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-6qju7t")
    );
    assert_eq!(
        registry.get("wave_id").and_then(JsonValue::as_str),
        Some("reality-check-wave2")
    );

    let runner = nonempty_string(&registry, "runner_script");
    assert!(
        repo_path(runner).is_file(),
        "runner script must exist at {runner}"
    );

    let support_classes = string_set(&registry, "support_class_vocabulary");
    for required in [
        "shipped",
        "feature-gated",
        "preview",
        "lab/virtual-backed",
        "broker/coordinator-only",
        "substrate-only",
        "deferred",
        "unsupported",
        "platform-scoped",
        "assumption-bound",
        "pending-proof",
        "artifact-contract-backed",
    ] {
        assert!(
            support_classes.contains(required),
            "missing support class {required}"
        );
    }

    log_contract_event(
        "schema-vocabulary",
        &[
            ("support_classes", support_classes.len().to_string()),
            ("runner_exists", "true".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn every_required_wave2_child_has_exactly_one_capability_row() {
    let registry = registry();
    let required = string_set(&registry, "required_wave2_child_beads");
    let rows = array(&registry, "capability_rows");
    let owners = rows
        .iter()
        .map(|row| nonempty_string(row, "owner_bead_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        owners, required,
        "capability rows must cover required wave2 beads exactly once"
    );

    let capability_ids = rows
        .iter()
        .map(|row| nonempty_string(row, "capability_id").to_string())
        .collect::<Vec<_>>();
    let deduped = capability_ids.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        capability_ids.len(),
        deduped.len(),
        "capability_id values must be unique"
    );

    log_contract_event(
        "row-coverage",
        &[
            ("required_child_beads", required.len().to_string()),
            ("capability_rows", rows.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn rows_have_required_fields_and_existing_source_or_artifact_paths() {
    let registry = registry();
    let contract = registry
        .get("registry_contract")
        .expect("registry_contract object");
    let required_fields = string_set(contract, "required_row_fields");
    let support_classes = string_set(&registry, "support_class_vocabulary");

    for row in array(&registry, "capability_rows") {
        let capability_id = nonempty_string(row, "capability_id");
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "{capability_id}: missing required row field {field}"
            );
        }

        let before = nonempty_string(row, "support_class_before");
        let after = nonempty_string(row, "support_class_after");
        assert!(
            support_classes.contains(before) || before.contains('-'),
            "{capability_id}: before support class {before} is not recognized"
        );
        assert!(
            support_classes.contains(after) || after.contains('-'),
            "{capability_id}: after support class {after} is not recognized"
        );

        let source_paths = row
            .get("source_paths")
            .and_then(JsonValue::as_array)
            .unwrap_or_else(|| panic!("{capability_id}: source_paths array"));
        assert!(
            !source_paths.is_empty(),
            "{capability_id}: source_paths must not be empty"
        );
        for source_path in source_paths {
            let source_path = source_path.as_str().expect("source path string");
            assert!(
                repo_path(source_path).exists(),
                "{capability_id}: source path missing: {source_path}"
            );
        }

        for artifact_path in array(row, "artifact_paths") {
            let artifact_path = artifact_path.as_str().expect("artifact path string");
            assert!(
                repo_path(artifact_path).exists(),
                "{capability_id}: artifact path missing: {artifact_path}"
            );
        }

        log_contract_event(
            "row-shape",
            &[
                ("capability_id", capability_id.to_string()),
                ("source_path_count", source_paths.len().to_string()),
                (
                    "artifact_count",
                    array(row, "artifact_paths").len().to_string(),
                ),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}

#[test]
fn promoted_rows_require_source_unit_e2e_artifact_and_no_unsupported_reason() {
    let registry = registry();
    let contract = registry
        .get("registry_contract")
        .expect("registry_contract object");
    let promoted_states = string_set(contract, "promoted_states_require_full_evidence");

    for row in array(&registry, "capability_rows") {
        let capability_id = nonempty_string(row, "capability_id");
        let promotion_state = nonempty_string(row, "promotion_state");
        let is_promoted = promoted_states.contains(promotion_state);
        let source_count = array(row, "source_paths").len();
        let unit_count = array(row, "unit_proof_commands").len();
        let e2e_count = array(row, "e2e_proof_commands").len();
        let artifact_count = array(row, "artifact_paths").len();

        if is_promoted {
            assert!(
                source_count > 0,
                "{capability_id}: promoted row needs source"
            );
            assert!(
                unit_count > 0,
                "{capability_id}: promoted row needs unit commands"
            );
            assert!(
                e2e_count > 0,
                "{capability_id}: promoted row needs E2E commands"
            );
            assert!(
                artifact_count > 0,
                "{capability_id}: promoted row needs artifact paths"
            );
            let unsupported_reason = row
                .get("unsupported_reason")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            assert!(
                unsupported_reason.trim().is_empty(),
                "{capability_id}: promoted rows cannot carry unsupported_reason"
            );
        } else {
            let has_reason = row
                .get("unsupported_reason")
                .and_then(JsonValue::as_str)
                .is_some_and(|reason| !reason.trim().is_empty());
            let has_residual = !array(row, "residual_risks").is_empty();
            assert!(
                has_reason || has_residual,
                "{capability_id}: pending rows need unsupported_reason or residual risk"
            );
        }

        log_contract_event(
            "promotion-gate",
            &[
                ("capability_id", capability_id.to_string()),
                ("promotion_state", promotion_state.to_string()),
                ("is_promoted", is_promoted.to_string()),
                ("unit_command_count", unit_count.to_string()),
                ("e2e_command_count", e2e_count.to_string()),
                ("artifact_count", artifact_count.to_string()),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}

#[test]
fn cargo_backed_commands_are_rch_offloaded_and_sensitive_fields_are_redacted() {
    let registry = registry();
    for row in array(&registry, "capability_rows") {
        let capability_id = nonempty_string(row, "capability_id");
        let commands = array(row, "unit_proof_commands")
            .iter()
            .chain(array(row, "e2e_proof_commands").iter())
            .map(|command| command.as_str().expect("command string"))
            .collect::<Vec<_>>();
        assert!(
            !commands.is_empty(),
            "{capability_id}: proof commands must not be empty"
        );
        for command in commands {
            if command.contains("cargo ") || command.contains("lake build") {
                assert!(
                    command.contains("rch exec --"),
                    "{capability_id}: cargo/proof-heavy command must use rch: {command}"
                );
            }
            if command.contains("lake build") {
                assert_eq!(
                    command, DIRECT_LEAN_BUILD_COMMAND,
                    "{capability_id}: Lean proof command must use direct lake argv"
                );
                assert!(
                    !command.contains("bash -lc") && !command.contains("cd formal/lean"),
                    "{capability_id}: Lean proof command must not shell-wrap lake build"
                );
            }
            for forbidden in ["password=", "token=", "secret=", "bearer "] {
                assert!(
                    !command.to_ascii_lowercase().contains(forbidden),
                    "{capability_id}: command appears to leak sensitive field {forbidden}"
                );
            }
        }

        let redaction_verdict = nonempty_string(row, "redaction_verdict");
        assert!(
            matches!(
                redaction_verdict,
                "not_applicable"
                    | "required_for_endpoint_logs"
                    | "required_for_origin_scope"
                    | "required_for_client_identity_logs"
                    | "required_for_cookie_values"
                    | "required_for_temp_paths"
                    | "required_for_trace_payloads"
                    | "required_for_request_headers"
                    | "required_for_connection_uri"
                    | "required_for_endpoint_and_host_facts"
                    | "required_for_example_endpoints"
            ),
            "{capability_id}: unknown redaction verdict {redaction_verdict}"
        );
    }
}

#[test]
fn runner_emits_required_structured_fields_and_summary_artifact() {
    let registry = registry();
    let runner = nonempty_string(&registry, "runner_script");
    let output_root = repo_path("target/wave2-capability-evidence-registry-contract-test");
    let output = Command::new("bash")
        .arg(repo_path(runner))
        .arg("--output-root")
        .arg(&output_root)
        .output()
        .unwrap_or_else(|err| panic!("run {runner}: {err}"));
    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = output_root
        .join("asupersync-6qju7t")
        .join("registry-report.json");
    assert!(
        report_path.is_file(),
        "runner must write report at {}",
        report_path.display()
    );
    let report: JsonValue = serde_json::from_str(
        &std::fs::read_to_string(&report_path)
            .unwrap_or_else(|err| panic!("read runner report: {err}")),
    )
    .unwrap_or_else(|err| panic!("parse runner report: {err}"));
    assert_eq!(
        report.get("verdict").and_then(JsonValue::as_str),
        Some("passed")
    );
    assert_eq!(
        report.get("schema_version").and_then(JsonValue::as_str),
        Some("wave2-capability-evidence-registry-report-v1")
    );

    let required_fields = string_set(&registry, "required_log_fields");
    let first_row = array(&report, "rows")
        .first()
        .expect("runner report must include row logs");
    let actual_fields = first_row
        .as_object()
        .expect("row log object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for field in required_fields {
        assert!(
            actual_fields.contains(&field),
            "runner row log must contain required field {field}"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bead_id=asupersync-6qju7t"),
        "runner stdout must include bead id logs"
    );
    assert!(
        stdout.contains("scenario_id=summary"),
        "runner stdout must include summary line"
    );

    log_contract_event(
        "runner-report",
        &[
            ("rows", array(&report, "rows").len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn registry_rows_do_not_depend_on_tracker_status_as_proof() {
    let registry = registry();
    for row in array(&registry, "capability_rows") {
        let capability_id = nonempty_string(row, "capability_id");
        let residual = row_string_set(row, "residual_risks");
        let artifact_paths = array(row, "artifact_paths");
        let promotion_state = nonempty_string(row, "promotion_state");
        if promotion_state == "pending" {
            assert!(
                !residual.is_empty() || artifact_paths.is_empty(),
                "{capability_id}: pending rows must keep residual risk visible"
            );
        }
    }
}

#[test]
fn closed_owner_rows_do_not_keep_stale_pending_states() {
    let registry = registry();
    let closed_owner_beads = closed_owner_beads_from_tracker();
    assert!(
        !closed_owner_beads.is_empty(),
        "closed tracker owner set must be available from {TRACKER_ISSUES_PATH}"
    );

    for row in array(&registry, "capability_rows") {
        let capability_id = nonempty_string(row, "capability_id");
        let owner_bead_id = nonempty_string(row, "owner_bead_id");
        if !closed_owner_beads.contains(owner_bead_id) {
            continue;
        }

        let promotion_state = nonempty_string(row, "promotion_state");
        assert_ne!(
            promotion_state, "pending",
            "{capability_id}: closed owner bead {owner_bead_id} must not remain promotion_state=pending"
        );

        let support_class_after = nonempty_string(row, "support_class_after");
        assert!(
            !support_class_after.contains("pending"),
            "{capability_id}: closed owner bead {owner_bead_id} must not keep pending support class {support_class_after}"
        );

        log_contract_event(
            "closed-owner-terminal-state",
            &[
                ("capability_id", capability_id.to_string()),
                ("owner_bead_id", owner_bead_id.to_string()),
                ("promotion_state", promotion_state.to_string()),
                ("support_class_after", support_class_after.to_string()),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}
