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

fn source_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read source file {relative}: {error}"))
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
        "manifest",
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
        "p95_wait_ns",
        "p999_wait_ns",
        "p95_hold_ns",
        "p999_hold_ns",
        "instrumentation_mode",
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

#[cfg(feature = "lock-metrics")]
#[test]
fn live_contended_mutex_snapshot_projects_tail_latency_fields() {
    use asupersync::sync::ContendedMutex;

    let contract = contract();
    let rows = rows_by_surface(&contract);
    let row = rows
        .get("contended_mutex_snapshot")
        .expect("contended mutex row");
    assert_eq!(row["report_status"].as_str(), Some("LIVE"));
    assert_eq!(row["live_atlas_wired"].as_bool(), Some(true));

    let lock = ContendedMutex::new("tasks", 0u32);
    for _ in 0..4 {
        let mut guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard += 1;
    }

    let snapshot = lock.snapshot();
    assert_eq!(snapshot.name, "tasks");
    assert_eq!(snapshot.instrumentation_mode, "opt_in_lock_metrics");
    assert_eq!(snapshot.acquisitions, 4);
    assert!(snapshot.p95_wait_ns <= snapshot.max_wait_ns);
    assert!(snapshot.p999_wait_ns <= snapshot.max_wait_ns);
    assert!(snapshot.p95_hold_ns <= snapshot.max_hold_ns);
    assert!(snapshot.p999_hold_ns <= snapshot.max_hold_ns);
}

#[cfg(not(feature = "lock-metrics"))]
#[test]
fn instrumentation_disabled_path_does_not_record_or_sample_metrics() {
    use asupersync::sync::ContendedMutex;

    let contract = contract();
    let rows = rows_by_surface(&contract);
    let row = rows
        .get("instrumentation_off_overhead")
        .expect("instrumentation-off row");
    assert_eq!(row["report_status"].as_str(), Some("LIVE"));
    assert_eq!(row["live_atlas_wired"].as_bool(), Some(true));

    let lock = ContendedMutex::new("tasks", 0u32);
    for _ in 0..128 {
        let mut guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard += 1;
    }
    assert_eq!(
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        128
    );

    let snapshot = lock.snapshot();
    assert_eq!(snapshot.name, "tasks");
    assert_eq!(snapshot.instrumentation_mode, "disabled");
    assert_eq!(snapshot.acquisitions, 0);
    assert_eq!(snapshot.contentions, 0);
    assert_eq!(snapshot.wait_ns, 0);
    assert_eq!(snapshot.hold_ns, 0);
    assert_eq!(snapshot.max_wait_ns, 0);
    assert_eq!(snapshot.max_hold_ns, 0);
    assert_eq!(snapshot.p95_wait_ns, 0);
    assert_eq!(snapshot.p999_wait_ns, 0);
    assert_eq!(snapshot.p95_hold_ns, 0);
    assert_eq!(snapshot.p999_hold_ns, 0);

    lock.reset_metrics();
    let after_reset = lock.snapshot();
    assert_eq!(after_reset.instrumentation_mode, "disabled");
    assert_eq!(after_reset.acquisitions, 0);
    assert_eq!(after_reset.contentions, 0);
}

#[cfg(debug_assertions)]
#[test]
fn live_lock_order_edges_report_exercised_edges_and_synthetic_inversion() {
    use asupersync::sync::lock_ordering::{self, LockModule, LockRank};

    let contract = contract();
    let rows = rows_by_surface(&contract);
    let row = rows.get("lock_order_edges").expect("lock-order row");
    assert_eq!(row["report_status"].as_str(), Some("LIVE"));
    assert_eq!(row["live_atlas_wired"].as_bool(), Some(true));

    lock_ordering::clear_held_locks();
    lock_ordering::clear_lock_order_atlas();

    lock_ordering::check_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
    lock_ordering::record_acquire_with_module(
        "config_cache",
        LockRank::Config,
        LockModule::Runtime,
    );
    lock_ordering::check_acquire_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);
    lock_ordering::record_acquire_with_module(
        "runtime_tasks",
        LockRank::Tasks,
        LockModule::Runtime,
    );

    let snapshot = lock_ordering::lock_order_atlas_snapshot();
    assert_eq!(snapshot.instrumentation_mode, "debug_lock_ordering");
    assert!(snapshot.order_violations.is_empty());
    assert!(snapshot.order_edges_exercised.iter().any(|edge| {
        edge.held_lock_name == "config_cache"
            && edge.held_rank == LockRank::Config
            && edge.held_module == LockModule::Runtime
            && edge.acquired_lock_name == "runtime_tasks"
            && edge.acquired_rank == LockRank::Tasks
            && edge.acquired_module == LockModule::Runtime
    }));

    lock_ordering::clear_held_locks();
    lock_ordering::record_acquire_with_module("tasks_queue", LockRank::Tasks, LockModule::Runtime);

    let inversion = std::panic::catch_unwind(|| {
        lock_ordering::check_acquire_with_module(
            "config_cache",
            LockRank::Config,
            LockModule::Runtime,
        );
    });
    assert!(inversion.is_err());

    let snapshot = lock_ordering::lock_order_atlas_snapshot();
    assert!(snapshot.order_violations.iter().any(|violation| {
        violation.lock_name == "config_cache"
            && violation.lock_rank == LockRank::Config
            && violation.lock_module == LockModule::Runtime
            && violation.held_rank == LockRank::Tasks
            && violation.reason == "rank-order"
    }));

    lock_ordering::clear_held_locks();
}

#[test]
fn sharded_state_order_row_is_backed_by_guard_metamorphic_source() {
    let contract = contract();
    let rows = rows_by_surface(&contract);
    let row = rows.get("sharded_state_order").expect("sharded-state row");
    assert_eq!(row["report_status"].as_str(), Some("LIVE"));
    assert_eq!(row["live_atlas_wired"].as_bool(), Some(true));

    let required = string_set(row, "required_fields");
    for field in [
        "lock_rank",
        "order_edges_exercised",
        "order_violations",
        "instrumentation_mode",
    ] {
        assert!(
            required.contains(field),
            "sharded-state row must require {field}"
        );
    }

    let source_path = string(row, "implementation_path");
    let source = source_text(source_path);
    for marker in [
        "fn metamorphic_lock_order_accepts_only_canonical_permutations()",
        "fn metamorphic_guard_unions_match_canonical_supersets()",
        "fn capture_labels(guard: ShardGuard<'_>)",
        "lock_order::held_labels()",
        "assert_eq!(lock_order::held_count(), 0)",
        "ShardGuard::for_spawn(&state)",
        "ShardGuard::for_obligation(&state)",
        "ShardGuard::for_cancel(&state)",
        "ShardGuard::for_task_completed(&state)",
        "ShardGuard::for_obligation_resolve(&state)",
        "ShardGuard::all(&state)",
    ] {
        assert!(
            source.contains(marker),
            "sharded-state source must keep guard-order proof marker: {marker}"
        );
    }

    for marker in [
        "lock_order::before_lock(LockShard::Regions)",
        "lock_order::before_lock(LockShard::Tasks)",
        "lock_order::before_lock(LockShard::Obligations)",
        "canonicalize_labels",
    ] {
        assert!(
            source.contains(marker),
            "sharded-state source must keep canonical order marker: {marker}"
        );
    }
}

#[test]
fn proofs_cover_inversion_overhead_and_stable_report() {
    let contract = contract();
    let proofs = array(&contract, "required_proofs")
        .iter()
        .map(|proof| (string(proof, "proof_id").to_string(), proof))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        proofs
            .get("synthetic-inversion")
            .and_then(|proof| proof["status"].as_str()),
        Some("LIVE"),
        "synthetic inversion is now a live lock-order atlas proof"
    );
    assert_eq!(
        proofs
            .get("stable-redacted-report")
            .and_then(|proof| proof["status"].as_str()),
        Some("LIVE"),
        "stable redacted report is covered by the golden markdown projection proof"
    );
    assert_eq!(
        proofs
            .get("instrumentation-off-overhead")
            .and_then(|proof| proof["status"].as_str()),
        Some("LIVE"),
        "default-build instrumentation-off proof keeps the metrics path disabled"
    );
    assert_eq!(
        proofs
            .get("sharded-state-order")
            .and_then(|proof| proof["status"].as_str()),
        Some("LIVE"),
        "sharded-state guard-order proof is source-backed by metamorphic tests"
    );
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
    assert!(
        commands.iter().any(|command| command
            .contains("instrumentation_disabled_path_does_not_record_or_sample_metrics")),
        "proof commands must include the default feature-off overhead proof"
    );
    assert!(
        commands.iter().any(|command| command
            .contains("sharded_state_order_row_is_backed_by_guard_metamorphic_source")),
        "proof commands must include the sharded-state guard-order proof"
    );
    for command in commands {
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
    }
}
