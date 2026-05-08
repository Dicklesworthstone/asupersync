#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/channel_telemetry_contract_v1.json";

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(CONTRACT_PATH))
        .unwrap_or_else(|error| panic!("read {CONTRACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {CONTRACT_PATH}: {error}"))
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_kind(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "channel_rows")
        .iter()
        .map(|row| (string(row, "channel_kind").to_string(), row))
        .collect()
}

fn pressure_fields(row: &Value) -> Vec<String> {
    let fields = string_set(row, "metric_fields");
    [
        "queued_messages",
        "reserved_uncommitted_obligations",
        "send_waiter_count",
        "recv_waiter_count",
        "receiver_health",
        "lagged_receiver_count",
        "cancellation_count",
    ]
    .iter()
    .filter(|field| fields.contains(**field))
    .map(|field| (*field).to_string())
    .collect()
}

fn markdown_projection(contract: &Value) -> String {
    let mut lines = vec![
        "| channel_kind | status | required_pressure_fields |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];
    for (kind, row) in rows_by_kind(contract) {
        lines.push(format!(
            "| {kind} | {} | {} |",
            string(row, "report_status"),
            pressure_fields(row).join(", ")
        ));
    }
    lines.join("\n") + "\n"
}

#[test]
fn contract_declares_channel_telemetry_policy_and_sources() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("channel-telemetry-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-97wkp1"));

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in [
        "contract",
        "contract_test",
        "channel_module",
        "flow_control_monitor",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }

    let policy = contract
        .get("telemetry_policy")
        .expect("telemetry_policy object");
    assert_eq!(policy["default_mode"].as_str(), Some("disabled"));
    assert_eq!(policy["enabled_mode"].as_str(), Some("opt_in"));
    assert_eq!(policy["lab_runtime_deterministic"].as_bool(), Some(true));
    assert_eq!(policy["no_ambient_globals"].as_bool(), Some(true));
    assert_eq!(
        policy["reserved_uncommitted_obligations_must_be_separate_from_queued_data"].as_bool(),
        Some(true)
    );
}

#[test]
fn contract_covers_all_required_channel_kinds_with_live_source_paths() {
    let contract = contract();
    let required = string_set(&contract, "required_channel_kinds");
    let rows = rows_by_kind(&contract);
    let actual = rows.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual, required);

    for (kind, row) in rows {
        let path = string(row, "implementation_path");
        assert!(
            repo_path(path).exists(),
            "{kind} implementation path must exist: {path}"
        );
        assert!(
            !array(row, "core_invariants").is_empty(),
            "{kind} must name core invariants"
        );
    }
}

#[test]
fn metric_fields_keep_reservation_pressure_separate_from_backlog() {
    let contract = contract();
    let required_fields = string_set(&contract, "required_metric_fields");
    for required in [
        "channel_id",
        "channel_kind",
        "queued_messages",
        "reserved_uncommitted_obligations",
        "receiver_health",
        "cancellation_count",
        "closed",
    ] {
        assert!(
            required_fields.contains(required),
            "required_metric_fields must include {required}"
        );
    }

    for (kind, row) in rows_by_kind(&contract) {
        let fields = string_set(row, "metric_fields");
        let raw_fields = array(row, "metric_fields");
        for required in [
            "channel_id",
            "channel_kind",
            "queued_messages",
            "reserved_uncommitted_obligations",
            "receiver_health",
            "cancellation_count",
            "closed",
        ] {
            assert!(fields.contains(required), "{kind} must include {required}");
        }
        assert!(
            fields.contains("queued_messages"),
            "{kind} must expose queued data separately"
        );
        assert!(
            fields.contains("reserved_uncommitted_obligations"),
            "{kind} must expose uncommitted reserves separately"
        );
        let queued_entries = raw_fields
            .iter()
            .filter(|field| field.as_str() == Some("queued_messages"))
            .count();
        let reserve_entries = raw_fields
            .iter()
            .filter(|field| field.as_str() == Some("reserved_uncommitted_obligations"))
            .count();
        assert_eq!(
            queued_entries, 1,
            "{kind} must list queued data exactly once"
        );
        assert_eq!(
            reserve_entries, 1,
            "{kind} must list uncommitted reserves exactly once"
        );
    }
}

#[test]
fn unwired_channel_rows_fail_closed_until_live_metrics_exist() {
    let contract = contract();
    let allowed_statuses = string_set(&contract, "allowed_report_statuses");
    assert!(allowed_statuses.contains("XFAIL"));
    assert!(!allowed_statuses.contains("PASS"));

    for (kind, row) in rows_by_kind(&contract) {
        let status = string(row, "report_status");
        assert!(
            allowed_statuses.contains(status),
            "{kind} status must be recognized"
        );
        if row["live_telemetry_wired"].as_bool() == Some(false) {
            assert_eq!(status, "XFAIL", "{kind} must fail closed while unwired");
            assert!(
                string(row, "status_reason").contains("not wired yet"),
                "{kind} must explain why it is XFAIL"
            );
        }
    }
}

#[test]
fn receiver_health_and_lag_are_explicit_for_multireceiver_channels() {
    let contract = contract();
    let rows = rows_by_kind(&contract);
    for kind in ["broadcast", "watch", "session"] {
        let row = rows.get(kind).expect("row for multireceiver channel");
        let fields = string_set(row, "metric_fields");
        assert!(
            fields.contains("receiver_health"),
            "{kind} must expose receiver_health"
        );
        assert!(
            fields.contains("lagged_receiver_count"),
            "{kind} must expose lagged_receiver_count"
        );
    }
}

#[test]
fn golden_markdown_projection_is_stable_and_redacted() {
    let contract = contract();
    let expected = string(&contract, "golden_markdown");
    let actual = markdown_projection(&contract);
    assert_eq!(actual, expected);

    for forbidden in [
        "/home/ubuntu/",
        "body_md",
        "ack_required",
        "Authorization: Bearer ",
    ] {
        assert!(
            !actual.contains(forbidden),
            "markdown projection must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn proof_commands_are_rch_routed_and_target_this_contract() {
    let contract = contract();
    let commands = string_set(&contract, "proof_commands");
    assert!(
        commands
            .iter()
            .any(|command| command.contains("--test channel_telemetry_contract")),
        "contract must name its own proof command"
    );
    for command in commands {
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
    }
}
