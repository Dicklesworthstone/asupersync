#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const SIGNOFF_PATH: &str = "artifacts/reality_check_gap_closure_signoff_v1.json";
const DIRECT_FORMAL_LEAN_BUILD_COMMAND: &str = "rch exec -- lake --dir formal/lean build";

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

fn is_full_hex_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn commit_exists(commit: &str) -> bool {
    if !repo_path(".git").exists() {
        return true;
    }
    Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("cat-file")
        .arg("-e")
        .arg(format!("{commit}^{{commit}}"))
        .status()
        .is_ok_and(|status| status.success())
}

fn require_commit_objects() -> bool {
    std::env::var_os("ASUPERSYNC_REQUIRE_SIGNOFF_COMMITS_IN_GIT").is_some()
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-rcksgn".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

#[test]
fn signoff_artifact_has_stable_schema_and_required_gap_rows() {
    let signoff = signoff();
    assert_eq!(
        signoff.get("schema_version").and_then(JsonValue::as_str),
        Some("reality-check-gap-closure-signoff-v1")
    );
    assert_eq!(
        signoff.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rcksgn")
    );

    let required = string_set(&signoff, "required_gap_ids");
    let rows = array(&signoff, "gap_rows");
    let actual = rows
        .iter()
        .map(|row| nonempty_string(row, "gap_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, required, "gap rows must match required_gap_ids");
    assert_eq!(rows.len(), 10, "reality-check signoff should have 10 rows");

    let support_classes = string_set(&signoff, "support_classes");
    assert_eq!(support_classes.len(), 10, "one support class per gap row");

    log_contract_event(
        "schema-and-gap-rows",
        &[
            ("gap_rows", rows.len().to_string()),
            ("support_classes", support_classes.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn dependency_and_graph_diagnostics_record_br_degradation_and_jsonl_fallback() {
    let signoff = signoff();
    let dependency_status = signoff
        .get("dependency_status")
        .expect("dependency_status object");
    assert_eq!(
        dependency_status
            .get("dependencies_closed_before_signoff")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    let jsonl = dependency_status
        .get("jsonl_reality_check_state")
        .expect("jsonl_reality_check_state object");
    assert_eq!(
        jsonl
            .get("total_reality_check_items")
            .and_then(JsonValue::as_u64),
        Some(16)
    );
    assert_eq!(
        jsonl.get("closed_count").and_then(JsonValue::as_u64),
        Some(16)
    );
    let open_items = array(jsonl, "open_items");
    let open_ids = open_items
        .iter()
        .map(|item| nonempty_string(item, "bead_id").to_string())
        .collect::<BTreeSet<_>>();
    assert!(
        open_ids.is_empty(),
        "final signoff must leave no open reality-check items"
    );

    let diagnostics = signoff
        .get("control_plane_diagnostics")
        .expect("control_plane_diagnostics object");
    assert_eq!(
        diagnostics["br_dep_cycles_json"]["status"].as_str(),
        Some("timed_out")
    );
    assert_eq!(
        diagnostics["br_dep_cycles_json"]["exit_code"].as_u64(),
        Some(124)
    );
    assert_eq!(
        diagnostics["br_list_json"]["status"].as_str(),
        Some("failed_external_lock")
    );
    assert!(
        diagnostics["br_list_json"]["error"]
            .as_str()
            .is_some_and(|error| error.contains(".beads/.write.lock")),
        "br list degradation must include the lock path"
    );
    assert_eq!(
        diagnostics["bv_robot_plan_reality_check"]["single_actionable"].as_str(),
        Some("asupersync-rcksgn")
    );
    assert_eq!(
        diagnostics["bv_robot_plan_reality_check_after_close"]["open_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        diagnostics["bv_robot_plan_reality_check_after_close"]["closed_count"].as_u64(),
        Some(16)
    );
    assert_eq!(
        diagnostics["bv_robot_plan_reality_check_after_close"]["total_actionable"].as_u64(),
        Some(0)
    );

    log_contract_event(
        "graph-diagnostics",
        &[
            ("open_reality_check_items", open_items.len().to_string()),
            (
                "br_dep_cycles_status",
                diagnostics["br_dep_cycles_json"]["status"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            ),
            (
                "br_list_status",
                diagnostics["br_list_json"]["status"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn every_fully_closed_gap_has_commit_artifacts_passing_proof_and_residual_risk_field() {
    let signoff = signoff();
    let mut proof_command_count = 0usize;
    let mut stale_closed_count = 0usize;
    let mut rows_by_id = BTreeSet::new();

    for row in array(&signoff, "gap_rows") {
        let gap_id = nonempty_string(row, "gap_id");
        assert!(
            rows_by_id.insert(gap_id.to_string()),
            "duplicate gap row {gap_id}"
        );
        let commit = nonempty_string(row, "commit");
        assert!(is_full_hex_sha(commit), "{gap_id}: commit must be full hex");
        if require_commit_objects() {
            assert!(commit_exists(commit), "{gap_id}: commit missing: {commit}");
        }
        if let Some(tracker_commit) = row.get("tracker_commit").and_then(JsonValue::as_str) {
            assert!(
                is_full_hex_sha(tracker_commit),
                "{gap_id}: tracker_commit must be full hex"
            );
            if require_commit_objects() {
                assert!(
                    commit_exists(tracker_commit),
                    "{gap_id}: tracker commit missing: {tracker_commit}"
                );
            }
        }

        nonempty_string(row, "closing_bead");
        nonempty_string(row, "support_class_after");
        nonempty_string(row, "evidence_quality");
        nonempty_string(row, "tracker_close_mode");
        assert_eq!(
            row.get("closure_status").and_then(JsonValue::as_str),
            Some("fully_closed"),
            "{gap_id}: signoff rows must be fully closed or signoff must stay open"
        );

        let artifact_paths = array(row, "artifact_paths");
        assert!(
            !artifact_paths.is_empty(),
            "{gap_id}: durable artifact paths required"
        );
        for path in artifact_paths {
            let path = path.as_str().expect("artifact path string");
            assert!(
                repo_path(path).exists(),
                "{gap_id}: artifact path missing: {path}"
            );
        }

        let proof_commands = array(row, "proof_commands");
        assert!(
            proof_commands
                .iter()
                .any(|command| command["status"].as_str() == Some("passed")),
            "{gap_id}: fully closed row needs a passing proof command"
        );
        proof_command_count += proof_commands.len();
        for command in proof_commands {
            let proof_command = nonempty_string(command, "command");
            assert!(
                proof_command.starts_with("rch exec -- ")
                    || proof_command == "bash scripts/scan_stubs.sh"
                    || proof_command.contains(" bash scripts/run_reality_check_docs_evidence.sh"),
                "{gap_id}: proof command should be rch-backed or the dedicated docs/stub e2e script: {proof_command}"
            );
            assert!(
                !proof_command.contains("bash -lc"),
                "{gap_id}: proof command must not shell-wrap proof execution: {proof_command}"
            );
            nonempty_string(command, "observed_signal");
            assert_eq!(
                command.get("status").and_then(JsonValue::as_str),
                Some("passed"),
                "{gap_id}: proof command must pass"
            );
        }
        if gap_id == "formal-proof-posture" {
            assert!(
                proof_commands
                    .iter()
                    .any(|command| command["command"].as_str()
                        == Some(DIRECT_FORMAL_LEAN_BUILD_COMMAND)),
                "{gap_id}: formal Lean proof command must use direct lake argv"
            );
        }

        assert!(
            row.get("residual_risks")
                .and_then(JsonValue::as_array)
                .is_some_and(|risks| !risks.is_empty() && risks.iter().all(JsonValue::is_string)),
            "{gap_id}: residual_risks must be a nonempty string array"
        );

        if row
            .get("stale_closed_tracker_repair")
            .and_then(JsonValue::as_bool)
            == Some(true)
        {
            stale_closed_count += 1;
        }
    }

    let invariants = signoff
        .get("signoff_invariants")
        .expect("signoff_invariants object");
    assert_eq!(
        invariants["stale_closed_bead_count"].as_u64(),
        Some(stale_closed_count as u64)
    );
    assert!(
        proof_command_count >= 12,
        "expected at least 12 proof commands, got {proof_command_count}"
    );

    log_contract_event(
        "gap-row-proof-contract",
        &[
            ("gap_rows", rows_by_id.len().to_string()),
            ("proof_command_count", proof_command_count.to_string()),
            ("stale_closed_bead_count", stale_closed_count.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn no_tokio_rerun_and_signoff_invariants_are_recorded() {
    let signoff = signoff();
    let fresh = array(&signoff, "fresh_signoff_commands");
    let no_tokio = fresh
        .iter()
        .find(|row| row["command_id"].as_str() == Some("no-tokio-default-normal-graph-rerun"))
        .expect("missing no-tokio rerun command");
    assert_eq!(no_tokio["status"].as_str(), Some("passed"));
    assert_eq!(
        no_tokio["observed_signal"].as_str(),
        Some("warning: nothing to print.")
    );

    let invariants = signoff
        .get("signoff_invariants")
        .expect("signoff_invariants object");
    for key in [
        "every_required_gap_has_row",
        "every_dependency_closed",
        "no_row_marked_fully_closed_without_passing_proof",
        "no_row_marked_fully_closed_without_durable_artifact",
        "no_unresolved_gap_hidden_in_prose",
    ] {
        assert_eq!(
            invariants.get(key).and_then(JsonValue::as_bool),
            Some(true),
            "invariant {key} must be true"
        );
    }
    assert!(
        array(invariants, "failed_or_blocked_required_proof_commands").is_empty(),
        "required proof commands must not be failed or blocked"
    );
    assert_eq!(
        array(invariants, "control_plane_degraded_commands").len(),
        2,
        "br cycle/list degradations should be recorded"
    );

    log_contract_event(
        "fresh-signoff-commands",
        &[
            ("fresh_commands", fresh.len().to_string()),
            ("no_tokio_status", "passed".to_string()),
            (
                "control_plane_degraded_commands",
                array(invariants, "control_plane_degraded_commands")
                    .len()
                    .to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn e2e_signoff_script_contract_logs_required_fields() {
    let signoff = signoff();
    let e2e = signoff
        .get("e2e_logging_contract")
        .expect("e2e_logging_contract object");
    let script = nonempty_string(e2e, "script");
    let script_text = read_repo_file(script);
    assert!(repo_path(script).is_file(), "script must exist: {script}");
    assert!(
        script_text.contains("asupersync-rcksgn"),
        "script must name bead id"
    );
    for field in array(e2e, "required_top_level_fields") {
        let field = field.as_str().expect("required field string");
        assert!(
            script_text.contains(field),
            "script must mention required field {field}"
        );
    }
    assert!(
        nonempty_string(e2e, "default_artifact_path").ends_with("signoff-report.json"),
        "default report path must be deterministic JSON"
    );

    log_contract_event(
        "e2e-script-contract",
        &[
            ("script", script.to_string()),
            (
                "required_fields",
                array(e2e, "required_top_level_fields").len().to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
