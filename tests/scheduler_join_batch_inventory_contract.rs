#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/scheduler_join_batch_inventory_v1.json";
const BASELINE_PATH: &str = "artifacts/baseline.json";
const BENCH_PATH: &str = "benches/spawn_throughput.rs";
const DOC_PATH: &str = "docs/scheduler_join_batch_inventory.md";
const PERF_RUNBOOK_PATH: &str = "docs/perf_runbook.md";
const BEAD_ID: &str = "asupersync-sched-hot-path-perf-bt4y5f.3.1";
const ARTIFACT_ID: &str = "scheduler-join-batch-inventory-v1";
const REFRESH_ID: &str = "SCHED-JOIN-BATCH-PROVENANCE-REFRESH-2026-08-06";
const ORIGINAL_BASE_COMMIT: &str = "e9a2d6229fd42d982f9bc296129852b7821c0905";
const REFRESH_BASE_COMMIT: &str = "fbbd4d065ae4768b84e4161a00d10e5acba04b39";
const BEGIN_MARKER: &str = "<!-- BEGIN SCHEDULER JOIN BATCH INVENTORY -->";
const END_MARKER: &str = "<!-- END SCHEDULER JOIN BATCH INVENTORY -->";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(repo_path(relative)).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_repo_file(relative: &str) -> String {
    String::from_utf8(read_repo_bytes(relative))
        .unwrap_or_else(|error| panic!("{relative} must be UTF-8: {error}"))
}

fn repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn unsigned(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn number(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or_else(|| panic!("{key} must be numeric"))
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be nonempty strings"))
                .to_owned()
        })
        .collect()
}

fn row_id_set(value: &Value, rows_key: &str, id_key: &str) -> BTreeSet<String> {
    let rows = array(value, rows_key);
    let ids = rows
        .iter()
        .map(|row| text(row, id_key).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), rows.len(), "duplicate {rows_key}.{id_key}");
    ids
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn check_anchor_objects(value: &Value) -> usize {
    match value {
        Value::Array(values) => values.iter().map(check_anchor_objects).sum(),
        Value::Object(fields) => {
            let mut checked = 0;
            if let (Some(path), Some(line), Some(fragment)) = (
                fields.get("path").and_then(Value::as_str),
                fields.get("line").and_then(Value::as_u64),
                fields.get("fragment").and_then(Value::as_str),
            ) {
                assert!(line > 0, "anchor line must be one-based for {path}");
                let line_index = usize::try_from(line).expect("anchor line fits usize");
                let source = read_repo_file(path);
                let actual = source
                    .lines()
                    .nth(line_index - 1)
                    .unwrap_or_else(|| panic!("missing {path}:{line}"));
                assert!(
                    actual.contains(fragment),
                    "anchor drift at {path}:{line}: expected {fragment:?}, got {actual:?}"
                );
                checked += 1;
            }
            checked + fields.values().map(check_anchor_objects).sum::<usize>()
        }
        _ => 0,
    }
}

#[test]
fn source_pins_and_exact_anchors_match_the_captured_tree() {
    let artifact = repo_json(ARTIFACT_PATH);
    assert_eq!(text(&artifact, "artifact_id"), ARTIFACT_ID);
    assert_eq!(text(&artifact, "bead_id"), BEAD_ID);
    assert_eq!(unsigned(&artifact, "schema_version"), 1);
    assert_eq!(
        text(&artifact, "disposition"),
        "STATIC_SURFACE_COMPLETE_MEASUREMENT_BLOCKED"
    );
    assert_eq!(text(&artifact, "base_commit"), ORIGINAL_BASE_COMMIT);

    let pins = array(&artifact, "source_pins");
    assert_eq!(pins.len(), 15);
    let mut paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(paths.insert(path.to_owned()), "duplicate source pin {path}");
        assert!(!text(pin, "role").is_empty());
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "source hash drift for {path}"
        );
        let source = std::str::from_utf8(&bytes).expect("pinned source must be UTF-8");
        assert_eq!(
            u64::try_from(source.lines().count()).expect("line count fits u64"),
            unsigned(pin, "line_count"),
            "line count drift for {path}"
        );
    }
    assert!(paths.contains(BENCH_PATH));
    assert!(paths.contains(BASELINE_PATH));
    assert!(paths.contains("src/runtime/builder.rs"));
    assert!(paths.contains("src/runtime/task_handle.rs"));
    assert!(paths.contains("src/runtime/spawn_mailbox.rs"));
    assert!(paths.contains("src/runtime/scheduler/three_lane.rs"));

    assert_eq!(check_anchor_objects(&artifact), 76);
}

#[test]
fn post_capture_provenance_refresh_is_exact_and_non_semantic() {
    let artifact = repo_json(ARTIFACT_PATH);
    let refresh = object(&artifact, "post_capture_provenance_refresh");
    let refresh_value = Value::Object(refresh.clone());

    for (key, expected) in [
        ("refresh_id", REFRESH_ID),
        ("captured_date_utc", "2026-08-06"),
        ("base_commit", REFRESH_BASE_COMMIT),
        ("original_base_commit", ORIGINAL_BASE_COMMIT),
        ("refresh_state", "STATIC_SOURCE_PIN_MAINTENANCE"),
        ("disposition", "STATIC_SURFACE_COMPLETE_MEASUREMENT_BLOCKED"),
    ] {
        assert_eq!(text(&refresh_value, key), expected, "refresh {key} drifted");
    }
    assert_eq!(unsigned(&refresh_value, "source_pin_path_count"), 15);
    assert_eq!(unsigned(&refresh_value, "stale_path_count"), 2);
    assert_eq!(unsigned(&refresh_value, "exact_anchor_count"), 76);
    assert!(boolean(&refresh_value, "all_exact_anchors_match"));
    for key in [
        "source_pin_path_set_changed",
        "semantic_contract_changed",
        "measurement_state_changed",
        "production_source_changed_by_refresh",
        "benchmark_source_changed_by_refresh",
        "baseline_registry_changed_by_refresh",
        "rust_contract_executed",
    ] {
        assert!(!boolean(&refresh_value, key), "refresh {key} must be false");
    }

    assert_eq!(
        row_id_set(&refresh_value, "refreshed_paths", "path"),
        expected_set(&[
            "src/runtime/scheduler/three_lane.rs",
            "src/runtime/state.rs",
        ])
    );
    let refreshed_paths = array(&refresh_value, "refreshed_paths");
    let scheduler = refreshed_paths
        .iter()
        .find(|row| text(row, "path") == "src/runtime/scheduler/three_lane.rs")
        .expect("scheduler refresh row");
    assert_eq!(
        text(scheduler, "change_commit"),
        "b213fc7ba7966e3a8522d9d23fc0e57037613e2a"
    );
    assert_eq!(unsigned(scheduler, "previous_line_count"), 8190);
    assert_eq!(unsigned(scheduler, "current_line_count"), 8190);
    assert_eq!(unsigned(scheduler, "exact_anchor_count"), 4);
    assert!(boolean(scheduler, "all_exact_anchors_match"));
    assert!(text(scheduler, "classification").contains("WAKE_INJECTION"));
    assert!(text(scheduler, "semantic_scope_effect").contains("batch-one"));

    let state = refreshed_paths
        .iter()
        .find(|row| text(row, "path") == "src/runtime/state.rs")
        .expect("runtime state refresh row");
    assert_eq!(
        text(state, "change_commit"),
        "6688f15be0acb724b264dd6ca6051201fe0e7f06"
    );
    assert_eq!(unsigned(state, "previous_line_count"), 10160);
    assert_eq!(unsigned(state, "current_line_count"), 10177);
    assert_eq!(unsigned(state, "exact_anchor_count"), 3);
    assert!(boolean(state, "all_exact_anchors_match"));
    assert!(text(state, "classification").contains("OBLIGATION_LEAK"));
    assert!(text(state, "semantic_scope_effect").contains("three pinned"));

    for row in refreshed_paths {
        assert_ne!(text(row, "previous_sha256"), text(row, "current_sha256"));
        let pin = array(&artifact, "source_pins")
            .iter()
            .find(|pin| text(pin, "path") == text(row, "path"))
            .expect("refreshed source pin");
        assert_eq!(text(pin, "sha256"), text(row, "current_sha256"));
        assert_eq!(
            unsigned(pin, "line_count"),
            unsigned(row, "current_line_count")
        );
    }

    assert!(
        text(&refresh_value, "no_claim_boundary")
            .contains("executes no Rust contract or benchmark")
    );
    let authority = Value::Object(object(&artifact, "authority").clone());
    assert!(
        text(&authority, "source_revision_authority").contains("post_capture_provenance_refresh")
    );
}

#[test]
fn both_handle_families_and_every_terminal_semantic_are_distinct() {
    let artifact = repo_json(ARTIFACT_PATH);
    let families = array(&artifact, "handle_families");
    assert_eq!(families.len(), 2);
    let family_ids = families
        .iter()
        .map(|family| text(family, "family_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        family_ids,
        expected_set(&["CANONICAL-CX-TASK", "LEGACY-RUNTIME-JOIN"])
    );

    let legacy = families
        .iter()
        .find(|family| text(family, "family_id") == "LEGACY-RUNTIME-JOIN")
        .expect("legacy family");
    assert!(boolean(legacy, "selected_for_safe_experiment"));
    assert!(text(legacy, "completion_transport").contains("Mutex<JoinState"));
    assert_eq!(text(legacy, "terminal_api"), "Future<Output = T>");
    assert!(text(legacy, "cancellation_shape").contains("panic"));

    let canonical = families
        .iter()
        .find(|family| text(family, "family_id") == "CANONICAL-CX-TASK")
        .expect("canonical family");
    assert!(!boolean(canonical, "selected_for_safe_experiment"));
    assert!(text(canonical, "completion_transport").contains("Mutex<OneShotInner"));
    assert!(text(canonical, "producer_take_once").contains("Mutex<Option<Sender>>"));
    assert!(text(canonical, "terminal_api").contains("JoinError"));

    assert_eq!(
        row_id_set(&artifact, "semantic_contract", "semantic_id"),
        expected_set(&[
            "LEGACY-CANCEL-BEFORE-ADMISSION",
            "LEGACY-FINISHED-AND-REPOLL",
            "LEGACY-HANDLE-DROP",
            "LEGACY-PENDING-WAKE",
            "LEGACY-SHUTDOWN-OR-EXECUTOR-DROP",
            "LEGACY-SUCCESS-SINGLE-TAKE",
            "LEGACY-SYNC-SPAWN-FAILURE",
            "LEGACY-TASK-PANIC",
            "STRUCTURED-COLLECTION-ORDER",
            "TASK-CANCEL-OR-ADMISSION-DENIAL",
            "TASK-EXPLICIT-ABORT",
            "TASK-FINISHED-AND-REPOLL",
            "TASK-HANDLE-DROP",
            "TASK-JOIN-FUTURE-DROP",
            "TASK-PANIC",
            "TASK-PENDING-WAKE",
            "TASK-SUCCESS-SINGLE-TAKE",
            "TASK-SYNC-SPAWN-FAILURE",
        ])
    );
    for row in array(&artifact, "semantic_contract") {
        assert!(!text(row, "surface").is_empty());
        assert!(!text(row, "event").is_empty());
        assert!(!text(row, "incumbent_contract").is_empty());
        assert!(!text(row, "must_preserve").is_empty());
        assert!(!array(row, "anchors").is_empty());
    }
}

#[test]
fn producer_amortization_does_not_rewrite_consumer_fairness() {
    let artifact = repo_json(ARTIFACT_PATH);
    let batch = object(&artifact, "batch_path");
    let batch_value = Value::Object(batch.clone());
    assert_eq!(text(&batch_value, "current_public_batch_api"), "ABSENT");
    assert_eq!(
        string_set(&batch_value, "absent_symbols_checked"),
        expected_set(&[
            "Cx::spawn_batch",
            "Cx::spawn_batch_in",
            "JoinSet::spawn_all",
            "Scope::spawn_batch",
        ])
    );

    let cx_source = read_repo_file("src/cx/cx.rs");
    let scope_source = read_repo_file("src/cx/scope.rs");
    let join_set_source = read_repo_file("src/combinator/join_set.rs");
    assert!(!cx_source.contains("pub fn spawn_batch"));
    assert!(!scope_source.contains("pub fn spawn_batch"));
    assert!(!join_set_source.contains("pub fn spawn_all"));

    let producer = object(&batch_value, "producer_now");
    let producer_value = Value::Object(producer.clone());
    assert!(text(&producer_value, "publication").contains("one scheduler notification"));
    assert!(text(&producer_value, "trace").contains("before"));

    let consumer = object(&batch_value, "consumer_now");
    let consumer_value = Value::Object(consumer.clone());
    assert!(text(&consumer_value, "global_send_lane").contains("one request"));
    assert!(text(&consumer_value, "owner_local_lane").contains("sixteen"));
    assert!(text(&consumer_value, "fairness_boundary").contains("does not authorize"));

    let future_contract = array(&batch_value, "required_future_contract");
    assert_eq!(future_contract.len(), 10);
    let contract_text = future_contract
        .iter()
        .map(|entry| entry.as_str().expect("future contract text"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(contract_text.contains("one queue operation"));
    assert!(contract_text.contains("batch one"));
    assert!(contract_text.contains("single-spawn"));
    assert!(contract_text.contains("no unsafe code"));
}

#[test]
fn existing_baselines_are_machine_checked_as_non_equivalent() {
    let artifact = repo_json(ARTIFACT_PATH);
    let reconciliation = object(&artifact, "baseline_reconciliation");
    let reconciliation_value = Value::Object(reconciliation.clone());
    assert_eq!(unsigned(&reconciliation_value, "registry_row_count"), 105);
    assert_eq!(
        unsigned(&reconciliation_value, "required_join_batch_row_count"),
        0
    );
    assert_eq!(
        unsigned(&reconciliation_value, "methodology_task_spawn_row_count"),
        12
    );
    assert_eq!(
        unsigned(
            &reconciliation_value,
            "methodology_task_spawn_operation_count"
        ),
        6
    );
    assert_eq!(
        string_set(&reconciliation_value, "methodology_task_spawn_environments"),
        expected_set(&["host:fixmydocuments", "host:hetzner2"])
    );
    assert_eq!(
        text(&reconciliation_value, "required_measurement_state"),
        "MISSING"
    );

    let baseline = repo_json(BASELINE_PATH);
    let rows = array(&baseline, "baselines");
    assert_eq!(rows.len(), 105);
    let required_rows = rows
        .iter()
        .filter(|row| {
            let operation = text(row, "operation");
            operation.contains("join_handle_completion")
                || operation.contains("join_set_fanout")
                || operation.contains("spawn_throughput")
                || operation.starts_with("sched/join_batch/v1/")
        })
        .count();
    assert_eq!(required_rows, 0);

    let task_spawn_rows = rows
        .iter()
        .filter(|row| text(row, "operation").starts_with("methodology/task_spawn/"))
        .collect::<Vec<_>>();
    assert_eq!(task_spawn_rows.len(), 12);
    assert_eq!(
        task_spawn_rows
            .iter()
            .map(|row| text(row, "operation").to_owned())
            .collect::<BTreeSet<_>>()
            .len(),
        6
    );

    let queue_rows = task_spawn_rows
        .iter()
        .copied()
        .filter(|row| {
            text(row, "operation") == "methodology/task_spawn/local_queue_spawn_batch/1000"
        })
        .collect::<Vec<_>>();
    assert_eq!(queue_rows.len(), 2);
    let fixmydocuments = queue_rows
        .iter()
        .copied()
        .find(|row| text(row, "environment") == "host:fixmydocuments")
        .expect("fixmydocuments queue row");
    let hetzner2 = queue_rows
        .iter()
        .copied()
        .find(|row| text(row, "environment") == "host:hetzner2")
        .expect("hetzner2 queue row");
    assert_eq!(number(fixmydocuments, "p50_ns"), 50_072.0);
    assert_eq!(number(hetzner2, "p50_ns"), 53_604.0);
    assert!(fixmydocuments["p95_ns"].is_null());
    assert!(hetzner2["p95_ns"].is_null());
    assert!(fixmydocuments.get("allocation_count").is_none());
    assert!(hetzner2.get("allocation_count").is_none());

    let surfaces = array(&reconciliation_value, "incumbent_surfaces");
    assert_eq!(surfaces.len(), 4);
    for surface in surfaces {
        assert!(text(surface, "evidence_class").contains("NON_EQUIVALENT"));
        assert!(!text(surface, "reason").is_empty());
    }
    assert_eq!(
        array(&reconciliation_value, "missing_required_evidence").len(),
        6
    );

    let authority = object(&artifact, "authority");
    assert!(!boolean(
        &Value::Object(authority.clone()),
        "baseline_registry_changed"
    ));
}

#[test]
fn required_measurement_matrix_fails_closed_until_complete() {
    let artifact = repo_json(ARTIFACT_PATH);
    let measurements = object(&artifact, "required_measurements");
    let measurements_value = Value::Object(measurements.clone());
    assert_eq!(text(&measurements_value, "harness_path"), BENCH_PATH);
    assert_eq!(
        text(&measurements_value, "operation_namespace"),
        "sched/join_batch/v1/"
    );
    assert_eq!(unsigned(&measurements_value, "minimum_host_families"), 2);
    assert_eq!(
        unsigned(&measurements_value, "minimum_repetitions_per_host"),
        3
    );
    assert_eq!(text(&measurements_value, "state"), "NOT_RECORDED");
    assert_eq!(
        string_set(&measurements_value, "required_quantiles"),
        expected_set(&["p50_ns", "p95_ns"])
    );
    assert_eq!(
        string_set(&measurements_value, "required_allocation_fields"),
        expected_set(&["allocated_bytes", "allocation_count", "allocation_method"])
    );

    assert_eq!(
        row_id_set(&measurements_value, "operation_cells", "operation_id"),
        expected_set(&[
            "sched/join_batch/v1/legacy_completion_handoff/drop_observer",
            "sched/join_batch/v1/legacy_completion_handoff/pending_wake",
            "sched/join_batch/v1/legacy_completion_handoff/ready",
            "sched/join_batch/v1/public_cx_spawn_batch/1000",
            "sched/join_batch/v1/public_cx_spawn_loop/1000",
            "sched/join_batch/v1/public_join_set_spawn_loop/1000",
            "sched/join_batch/v1/task_handle_completion/drop_join_future",
            "sched/join_batch/v1/task_handle_completion/pending_wake",
            "sched/join_batch/v1/task_handle_completion/ready",
        ])
    );
    let cells = array(&measurements_value, "operation_cells");
    let public_cx_loop = cells
        .iter()
        .find(|cell| text(cell, "operation_id") == "sched/join_batch/v1/public_cx_spawn_loop/1000")
        .expect("public Cx loop cell must exist");
    assert!(text(public_cx_loop, "measurement_scope").contains("request_cx_with_budget"));
    assert_eq!(
        cells
            .iter()
            .filter(|cell| boolean(cell, "baseline_required"))
            .count(),
        8
    );
    assert_eq!(
        cells
            .iter()
            .filter(|cell| !boolean(cell, "baseline_required"))
            .count(),
        1
    );
    for cell in cells {
        assert!(text(cell, "operation_id").starts_with("sched/join_batch/v1/"));
        assert!(!text(cell, "measurement_scope").is_empty());
        assert!(!array(cell, "profile_ids").is_empty());
    }

    let required_fields = string_set(&measurements_value, "required_observation_fields");
    assert_eq!(required_fields.len(), 38);
    for field in [
        "operation_id",
        "profile_id",
        "p50_ns",
        "p95_ns",
        "allocation_count",
        "allocated_bytes",
        "repetition_count",
        "source_revision",
        "harness_sha256",
        "environment",
        "worker_label",
        "cpu_model",
        "numa_nodes",
        "allocator",
        "timer_source",
    ] {
        assert!(
            required_fields.contains(field),
            "missing required field {field}"
        );
    }
    assert_eq!(array(&measurements_value, "timing_rules").len(), 6);
}

#[test]
fn candidate_thresholds_and_no_claim_boundary_are_explicit() {
    let artifact = repo_json(ARTIFACT_PATH);
    let authority = object(&artifact, "authority");
    let authority_value = Value::Object(authority.clone());
    assert!(!boolean(&authority_value, "production_behavior_changed"));
    assert!(!boolean(&authority_value, "benchmark_behavior_changed"));
    assert!(!boolean(&authority_value, "baseline_registry_changed"));
    assert!(!boolean(&authority_value, "implementation_authorized"));
    assert!(!boolean(&authority_value, "performance_claim_made"));
    assert!(text(&authority_value, "completion_candidate_selected").contains("legacy"));
    assert!(text(&authority_value, "structured_task_handle_role").contains("comparator"));

    let policy = object(&artifact, "candidate_and_decision_policy");
    let policy_value = Value::Object(policy.clone());
    let join_candidate = object(&policy_value, "join_candidate");
    let join_candidate_value = Value::Object(join_candidate.clone());
    assert!(text(&join_candidate_value, "target").contains("legacy"));
    assert!(text(&join_candidate_value, "first_candidate").contains("oneshot"));
    assert!(text(&join_candidate_value, "explicit_non_claim").contains("mutex-backed"));

    let batch_candidate = object(&policy_value, "batch_candidate");
    let batch_candidate_value = Value::Object(batch_candidate.clone());
    assert!(
        text(&batch_candidate_value, "first_candidate")
            .contains("one final scheduler notification")
    );
    assert!(text(&batch_candidate_value, "explicit_non_claim").contains("not one queue operation"));

    let ship = array(&policy_value, "ship_thresholds")
        .iter()
        .map(|entry| entry.as_str().expect("ship threshold text"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(ship.contains("at least 5 percent"));
    assert!(ship.contains("p95"));
    assert!(ship.contains("allocation"));
    assert!(ship.contains("two admitted host families"));
    assert_eq!(array(&policy_value, "keep_or_no_win_triggers").len(), 7);
    assert_eq!(array(&policy_value, "rollback").len(), 5);

    let validation = object(&artifact, "validation_state");
    let validation_value = Value::Object(validation.clone());
    for key in [
        "rust_contract_executed",
        "compiler_or_toolchain_invoked",
        "tests_executed",
        "benchmarks_executed",
        "remote_jobs_executed",
    ] {
        assert!(!boolean(&validation_value, key), "{key} must remain false");
    }
    assert!(boolean(&validation_value, "rust_contract_authored"));

    let no_claims = array(&artifact, "no_claims")
        .iter()
        .map(|entry| entry.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "no implementation",
        "no compilation",
        "no test",
        "no benchmark",
        "no completion improvement",
        "no producer-batch improvement",
        "no scheduler consumer fairness change",
        "no unsafe-code authorization",
        "no release readiness",
        "no bead closure",
    ] {
        assert!(no_claims.contains(required), "missing no-claim {required}");
    }
}

#[test]
fn docs_and_existing_harness_use_the_frozen_vocabulary() {
    let doc = read_repo_file(DOC_PATH);
    assert_eq!(doc.matches(BEGIN_MARKER).count(), 1);
    assert_eq!(doc.matches(END_MARKER).count(), 1);
    assert!(doc.contains(BEAD_ID));
    assert!(doc.contains(ARTIFACT_PATH));
    assert!(doc.contains(REFRESH_ID));
    assert!(doc.contains("Exactly two of the 15 source"));
    assert!(doc.contains("all 76 exact anchors still matched"));
    assert!(doc.contains("STATIC_SURFACE_COMPLETE_MEASUREMENT_BLOCKED"));
    assert!(doc.contains("zero baseline-registry rows"));
    assert!(doc.contains("mutex-backed"));
    assert!(doc.contains("request_cx_with_budget"));
    assert!(doc.contains("global scheduler consumer deliberately dequeues at most one"));
    for operation in [
        "sched/join_batch/v1/legacy_completion_handoff/ready",
        "sched/join_batch/v1/task_handle_completion/ready",
        "sched/join_batch/v1/public_cx_spawn_loop/1000",
        "sched/join_batch/v1/public_cx_spawn_batch/1000",
    ] {
        assert!(doc.contains(operation), "doc missing operation {operation}");
    }

    let runbook = read_repo_file(PERF_RUNBOOK_PATH);
    assert!(runbook.contains(DOC_PATH));
    assert!(runbook.contains(ARTIFACT_PATH));
    assert!(runbook.contains("sched/join_batch/v1/"));
    assert!(runbook.contains("measurement-blocked"));
    assert!(runbook.contains("p50"));
    assert!(runbook.contains("p95"));

    let bench = read_repo_file(BENCH_PATH);
    assert!(bench.contains("fn join_handle_completion_batch(runtime: &Runtime)"));
    assert!(bench.contains("Runtime::current_handle()"));
    assert!(bench.contains("joins.push(handle.spawn(async move { value }))"));
    assert!(bench.contains("fn join_set_join_all_fanout"));
    assert!(bench.contains("const SPAWNS_PER_ITER: usize = 1_000"));
}
