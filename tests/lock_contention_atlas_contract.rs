#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/lock_contention_atlas_contract_v1.json";

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

fn string_list(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_surface(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "atlas_rows")
        .iter()
        .map(|row| (string(row, "surface").to_string(), row))
        .collect()
}

fn markdown_projection(contract: &Value) -> String {
    let mut lines = vec![
        "| surface | status | required_fields |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];
    for (surface, row) in rows_by_surface(contract) {
        lines.push(format!(
            "| {surface} | {} | {} |",
            string(row, "report_status"),
            string_list(row, "required_fields").join(", ")
        ));
    }
    lines.join("\n") + "\n"
}

#[test]
fn contract_declares_sources_and_atlas_policy() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("lock-contention-atlas-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-xpjyl7"));

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in [
        "contract",
        "contract_test",
        "contended_mutex",
        "lock_ordering",
        "sharded_state",
        "contention_inventory",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }

    let policy = contract.get("atlas_policy").expect("atlas_policy object");
    assert_eq!(policy["default_mode"].as_str(), Some("disabled"));
    assert_eq!(policy["enabled_mode"].as_str(), Some("opt_in_lock_metrics"));
    assert_eq!(
        policy["instrumentation_off_overhead_must_be_measured"].as_bool(),
        Some(true)
    );
    assert_eq!(policy["lab_runtime_deterministic"].as_bool(), Some(true));
    assert_eq!(
        policy["fail_closed_when_live_samples_missing"].as_bool(),
        Some(true)
    );
}

#[test]
fn canonical_lock_order_matches_project_policy() {
    let contract = contract();
    let order = array(&contract, "canonical_lock_order");
    let ranks = order
        .iter()
        .map(|entry| string(entry, "rank"))
        .collect::<Vec<_>>();
    assert_eq!(ranks, vec!["E", "D", "B", "A", "C"]);

    let names = order
        .iter()
        .map(|entry| string(entry, "name"))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "Config",
            "Instrumentation",
            "Regions",
            "Tasks",
            "Obligations"
        ]
    );

    let numeric = order
        .iter()
        .map(|entry| {
            entry
                .get("numeric_rank")
                .and_then(Value::as_u64)
                .expect("numeric_rank")
        })
        .collect::<Vec<_>>();
    assert_eq!(numeric, vec![10, 20, 30, 40, 50]);

    for window in numeric.windows(2) {
        assert!(window[0] < window[1], "lock ranks must be ascending");
    }

    let final_rank = order.last().expect("final rank");
    assert!(
        array(final_rank, "must_precede").is_empty(),
        "obligations is the terminal lock rank"
    );
}

#[test]
fn atlas_fields_extend_current_snapshot_without_losing_existing_counters() {
    let contract = contract();
    let current = string_set(&contract, "current_snapshot_fields");
    for field in [
        "name",
        "acquisitions",
        "contentions",
        "wait_ns",
        "hold_ns",
        "max_wait_ns",
        "max_hold_ns",
    ] {
        assert!(
            current.contains(field),
            "current snapshot must include {field}"
        );
    }

    let required = string_set(&contract, "required_atlas_fields");
    for field in [
        "lock_name",
        "lock_rank",
        "lock_module",
        "p95_wait_ns",
        "p999_wait_ns",
        "p95_hold_ns",
        "p999_hold_ns",
        "order_edges_exercised",
        "order_violations",
        "instrumentation_mode",
    ] {
        assert!(required.contains(field), "atlas must require {field}");
    }

    assert!(
        required.contains("wait_ns") && required.contains("p999_wait_ns"),
        "atlas must keep cumulative wait time separate from tail latency"
    );
    assert!(
        required.contains("hold_ns") && required.contains("p999_hold_ns"),
        "atlas must keep cumulative hold time separate from tail latency"
    );
}

#[test]
fn rows_fail_closed_until_live_atlas_reporting_exists() {
    let contract = contract();
    let allowed_statuses = string_set(&contract, "allowed_report_statuses");
    assert!(allowed_statuses.contains("XFAIL"));
    assert!(!allowed_statuses.contains("PASS"));

    for (surface, row) in rows_by_surface(&contract) {
        let implementation_path = string(row, "implementation_path");
        assert!(
            repo_path(implementation_path).exists(),
            "{surface} implementation path must exist: {implementation_path}"
        );

        let status = string(row, "report_status");
        assert!(
            allowed_statuses.contains(status),
            "{surface} status must be recognized"
        );
        if row["live_atlas_wired"].as_bool() == Some(false) {
            assert_eq!(
                status, "XFAIL",
                "{surface} must fail closed while atlas rows are unwired"
            );
            assert!(
                string(row, "status_reason").contains("not wired yet")
                    || string(row, "status_reason").contains("required before"),
                "{surface} must explain why it is XFAIL"
            );
        }
    }
}

#[test]
fn proofs_cover_inversion_overhead_and_stable_report() {
    let contract = contract();
    let proofs = array(&contract, "required_proofs")
        .iter()
        .map(|proof| (string(proof, "proof_id").to_string(), proof))
        .collect::<BTreeMap<_, _>>();

    for proof_id in [
        "synthetic-inversion",
        "instrumentation-off-overhead",
        "stable-redacted-report",
    ] {
        let proof = proofs
            .get(proof_id)
            .unwrap_or_else(|| panic!("missing proof {proof_id}"));
        assert_eq!(
            proof["status"].as_str(),
            Some("XFAIL"),
            "{proof_id} must not claim live proof before implementation exists"
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
            "atlas projection must not expose raw coordination marker {forbidden}"
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
            .any(|command| command.contains("--test lock_contention_atlas_contract")),
        "contract must name its own proof command"
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("lock-metrics")),
        "proof command must exercise the lock-metrics feature gate"
    );
    for command in commands {
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
    }
}
