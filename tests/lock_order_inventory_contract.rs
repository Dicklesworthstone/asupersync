#![allow(missing_docs)]

use asupersync::sync::lock_ordering::{LockModule, LockRank};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const INVENTORY_PATH: &str = "artifacts/lock_order_inventory_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn inventory() -> Value {
    serde_json::from_str(&read_repo_file(INVENTORY_PATH))
        .unwrap_or_else(|error| panic!("parse {INVENTORY_PATH}: {error}"))
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

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(Value::String(text)) => {
            assert!(
                !text.trim().is_empty(),
                "{key} must be nonempty when present"
            );
            Some(text)
        }
        _ => panic!("{key} must be a string or null"),
    }
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
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

fn rows_by_key<'a>(rows: &'a [Value], key: &str) -> BTreeMap<String, &'a Value> {
    rows.iter()
        .map(|row| (string(row, key).to_string(), row))
        .collect()
}

fn rank_name(rank: LockRank) -> &'static str {
    match rank {
        LockRank::Config => "Config",
        LockRank::Instrumentation => "Instrumentation",
        LockRank::Regions => "Regions",
        LockRank::Tasks => "Tasks",
        LockRank::Obligations => "Obligations",
    }
}

fn module_name(module: LockModule) -> &'static str {
    match module {
        LockModule::Runtime => "Runtime",
        LockModule::Sync => "Sync",
        LockModule::Cx => "Cx",
        LockModule::Cancel => "Cancel",
        LockModule::Obligation => "Obligation",
        LockModule::Channel => "Channel",
        LockModule::Io => "Io",
        LockModule::Other => "Other",
    }
}

#[test]
fn inventory_declares_live_source_files_and_no_claim_boundaries() {
    let inventory = inventory();
    assert_eq!(
        inventory["contract_version"].as_str(),
        Some("lock-order-inventory-v1")
    );
    assert_eq!(
        inventory["bead_id"].as_str(),
        Some("asupersync-lock-order-deadlock-proof-dw03gl.1")
    );

    let source = inventory
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in [
        "artifact",
        "contract_test",
        "contended_mutex",
        "lock_ordering",
        "sharded_state",
        "trace_buffer",
        "evidence_sink",
        "contention_inventory",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point at a live file: {path}"
        );
    }

    let boundaries = array(&inventory, "no_claim_boundaries")
        .iter()
        .map(|row| string(row, "boundary_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        boundaries,
        BTreeSet::from([
            "not_broad_scheduler_performance_proof".to_string(),
            "not_global_third_party_deadlock_proof".to_string(),
            "not_replacement_for_sharded_state_conformance".to_string(),
        ])
    );
}

#[test]
fn documented_rank_names_are_represented_exactly_once() {
    let inventory = inventory();
    let rows = array(&inventory, "rank_map");
    let by_name = rows_by_key(rows, "rank_name");
    let expected = [
        ("Config", "E", 10_u64),
        ("Instrumentation", "D", 20_u64),
        ("Regions", "B", 30_u64),
        ("Tasks", "A", 40_u64),
        ("Obligations", "C", 50_u64),
    ];
    assert_eq!(
        by_name.len(),
        expected.len(),
        "rank_map must not duplicate ranks"
    );

    let lock_ordering_source = read_repo_file("src/sync/lock_ordering.rs");
    for (name, symbol, numeric) in expected {
        let row = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing rank_map row for {name}"));
        assert_eq!(string(row, "order_symbol"), symbol);
        assert_eq!(
            row.get("numeric_rank").and_then(Value::as_u64),
            Some(numeric)
        );
        assert!(
            lock_ordering_source.contains(&format!("LockRank::{name} => \"{name}\"")),
            "LockRank::name source must keep documented name {name}"
        );

        for sample in string_list(row, "from_name_samples") {
            let rank = LockRank::from_name(&sample)
                .unwrap_or_else(|| panic!("sample {sample} must map to {name}"));
            assert_eq!(rank_name(rank), name, "sample {sample} rank drifted");
        }
    }
}

#[test]
fn module_classifier_samples_match_current_api() {
    let inventory = inventory();
    for row in array(&inventory, "module_classifier_samples") {
        let sample = string(row, "sample");
        let expected = string(row, "module");
        assert_eq!(
            module_name(LockModule::from_name(sample)),
            expected,
            "module classifier sample drifted for {sample}"
        );
    }
}

#[test]
fn sharded_state_shard_locks_are_represented_exactly_once_and_source_backed() {
    let inventory = inventory();
    let shard_rows = array(&inventory, "lock_sites")
        .iter()
        .filter(|row| string(row, "category") == "sharded_state_shard")
        .collect::<Vec<_>>();
    let by_lock = shard_rows
        .iter()
        .map(|row| (string(row, "lock_name").to_string(), *row))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        by_lock.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "regions".to_string(),
            "tasks".to_string(),
            "obligations".to_string(),
        ]),
        "all ShardedState shard locks must be represented exactly once"
    );

    let sharded_state = read_repo_file("src/runtime/sharded_state.rs");
    for (lock_name, expected_rank, expected_symbol) in [
        ("regions", "Regions", "B"),
        ("tasks", "Tasks", "A"),
        ("obligations", "Obligations", "C"),
    ] {
        let row = by_lock
            .get(lock_name)
            .unwrap_or_else(|| panic!("missing shard lock row for {lock_name}"));
        assert_eq!(string(row, "rank_name"), expected_rank);
        assert_eq!(string(row, "order_symbol"), expected_symbol);
        assert!(bool_field(row, "automatic_enforcement"));
        assert!(
            sharded_state.contains(string(row, "source_marker")),
            "sharded state source must contain marker for {lock_name}"
        );
        let rank = LockRank::from_name(lock_name)
            .unwrap_or_else(|| panic!("{lock_name} must still map to a LockRank"));
        assert_eq!(rank_name(rank), expected_rank);
        assert_eq!(
            module_name(LockModule::from_name(lock_name)),
            string(row, "module_classifier_result")
        );
    }
}

#[test]
fn shard_guard_constructor_inventory_matches_current_api() {
    let inventory = inventory();
    let rows = array(&inventory, "shard_guard_constructors");
    let by_constructor = rows_by_key(rows, "constructor");
    let expected_orders = BTreeMap::from([
        ("tasks_only", vec!["A"]),
        ("regions_only", vec!["B"]),
        ("obligations_only", vec!["C"]),
        ("for_spawn", vec!["B", "A"]),
        ("for_obligation", vec!["B", "C"]),
        ("for_task_completed", vec!["B", "A", "C"]),
        ("for_cancel", vec!["B", "A", "C"]),
        ("for_obligation_resolve", vec!["B", "A", "C"]),
        ("all", vec!["B", "A", "C"]),
    ]);
    assert_eq!(
        by_constructor.keys().cloned().collect::<BTreeSet<_>>(),
        expected_orders
            .keys()
            .map(|key| (*key).to_string())
            .collect::<BTreeSet<_>>(),
        "ShardGuard constructor inventory must match the current API"
    );

    let sharded_state = read_repo_file("src/runtime/sharded_state.rs");
    for (constructor, expected_order) in expected_orders {
        let row = by_constructor
            .get(constructor)
            .unwrap_or_else(|| panic!("missing ShardGuard row for {constructor}"));
        assert!(
            sharded_state.contains(&format!("pub fn {constructor}(")),
            "source must keep ShardGuard::{constructor}"
        );
        assert_eq!(string_list(row, "rank_order"), expected_order);
        assert!(bool_field(row, "automatic_enforcement"));
    }
}

#[test]
fn unknown_rank_locks_are_justified_or_queued() {
    let inventory = inventory();
    let unknown_rows = array(&inventory, "lock_sites")
        .iter()
        .filter(|row| optional_string(row, "rank_name").is_none())
        .collect::<Vec<_>>();
    assert!(
        !unknown_rows.is_empty(),
        "inventory should explicitly document unknown-rank gaps"
    );

    for row in unknown_rows {
        let lock_name = string(row, "lock_name");
        assert!(
            !bool_field(row, "automatic_enforcement"),
            "unknown-rank lock {lock_name} must not claim automatic enforcement"
        );
        assert!(
            !string(row, "unknown_rank_justification").is_empty(),
            "unknown-rank lock {lock_name} needs a justification"
        );
        assert!(
            !string(row, "queued_followup").is_empty(),
            "unknown-rank lock {lock_name} needs a queued follow-up"
        );
    }
}

#[test]
fn hidden_instrumentation_mutexes_are_declared_and_source_backed() {
    let inventory = inventory();
    let rows = array(&inventory, "hidden_mutex_surfaces");
    let by_surface = rows_by_key(rows, "surface_id");
    assert_eq!(
        by_surface.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "trace_buffer_handle".to_string(),
            "jsonl_evidence_sink".to_string(),
            "collector_evidence_sink".to_string(),
        ])
    );

    for row in rows {
        assert_eq!(string(row, "rank_name"), "Instrumentation");
        assert!(!bool_field(row, "automatic_enforcement"));
        let source = read_repo_file(string(row, "source_file"));
        assert!(
            source.contains(string(row, "source_marker")),
            "hidden mutex source marker missing for {}",
            string(row, "surface_id")
        );
        assert!(
            !string(row, "gap").is_empty(),
            "hidden mutex rows must describe the enforcement gap"
        );
    }

    assert_eq!(
        by_surface
            .get("trace_buffer_handle")
            .map(|row| bool_field(row, "held_across_callbacks_or_trace_emission")),
        Some(true),
        "trace record_event must be called out as callback-sensitive"
    );
}

#[test]
fn proof_lane_is_remote_required_and_focused() {
    let inventory = inventory();
    let commands = string_list(&inventory, "proof_commands");
    assert_eq!(commands.len(), 1);
    let command = &commands[0];
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
        "proof command must be remote-required"
    );
    assert!(
        command.contains("cargo test -p asupersync --test lock_order_inventory_contract"),
        "proof command must target this focused contract"
    );
}
