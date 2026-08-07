#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/scheduler_hot_read_inventory_v1.json";
const BASELINE_PATH: &str = "artifacts/baseline.json";
const BENCH_PATH: &str = "benches/task_state_hot_reads.rs";
const DOC_PATH: &str = "docs/scheduler_hot_read_inventory.md";
const PERF_RUNBOOK_PATH: &str = "docs/perf_runbook.md";
const BEAD_ID: &str = "asupersync-sched-hot-path-perf-bt4y5f.4.1";
const ARTIFACT_ID: &str = "scheduler-hot-read-inventory-v1";
const BEGIN_MARKER: &str = "<!-- BEGIN SCHEDULER HOT READ INVENTORY -->";
const END_MARKER: &str = "<!-- END SCHEDULER HOT READ INVENTORY -->";

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
    hex::encode(Sha256::digest(bytes))
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
        "STATIC_INVENTORY_COMPLETE_PRODUCTION_UNCHANGED"
    );

    let pins = array(&artifact, "source_pins");
    assert_eq!(pins.len(), 26);
    let mut paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(paths.insert(path.to_owned()), "duplicate source pin {path}");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "hash drift: {path}"
        );
        let source = String::from_utf8(bytes).expect("pinned source must be UTF-8");
        assert_eq!(
            source.lines().count() as u64,
            unsigned(pin, "line_count"),
            "line-count drift: {path}"
        );
        text(pin, "role");
    }

    assert_eq!(check_anchor_objects(&artifact), 133);
}

#[test]
fn ownership_read_writer_wake_and_lifetime_sets_are_explicit() {
    let artifact = repo_json(ARTIFACT_PATH);
    assert_eq!(
        row_id_set(&artifact, "ownership_model", "ownership_id"),
        expected_set(&[
            "HOTREAD-OWN-RICH-TASK",
            "HOTREAD-OWN-PHASE",
            "HOTREAD-OWN-WAKE",
            "HOTREAD-OWN-CANCEL",
            "HOTREAD-OWN-TABLE",
        ])
    );
    assert_eq!(
        row_id_set(&artifact, "production_read_surfaces", "surface_id"),
        expected_set(&[
            "HOTREAD-READ-PHASE-CORE",
            "HOTREAD-READ-PHASE-AGGREGATE",
            "HOTREAD-READ-RICH-TASK",
            "HOTREAD-READ-CX-QUERY",
            "HOTREAD-READ-FAST-CANCEL",
            "HOTREAD-READ-REASON-WAKERS",
            "HOTREAD-READ-OBSERVABILITY",
            "HOTREAD-READ-LEGACY-WORKER",
        ])
    );
    assert_eq!(
        row_id_set(&artifact, "fast_cancel_writer_sites", "writer_id"),
        expected_set(&[
            "HOTREAD-CANCEL-WRITER-TASK-RECORD",
            "HOTREAD-CANCEL-WRITER-TASK-HANDLE",
            "HOTREAD-CANCEL-WRITER-CHECKPOINT",
            "HOTREAD-CANCEL-WRITER-CX-APIS",
            "HOTREAD-CANCEL-WRITER-ACTOR",
            "HOTREAD-CANCEL-WRITER-GEN-SERVER",
            "HOTREAD-CANCEL-WRITER-LAB",
        ])
    );
    assert_eq!(
        row_id_set(&artifact, "wake_publication_surfaces", "surface_id"),
        expected_set(&[
            "HOTREAD-WAKE-PRIMITIVE",
            "HOTREAD-WAKE-GLOBAL-INJECTION",
            "HOTREAD-WAKE-CANCEL-ADMISSION",
            "HOTREAD-WAKE-INITIAL-PUBLICATION",
            "HOTREAD-WAKE-LOCAL-AND-WAITER",
            "HOTREAD-WAKE-POLL-CYCLE",
            "HOTREAD-WAKE-WAKER-ROUTES",
            "HOTREAD-WAKE-CANCEL-AUXILIARY",
        ])
    );
    assert_eq!(
        row_id_set(&artifact, "record_lifetime_boundaries", "boundary_id"),
        expected_set(&[
            "HOTREAD-LIFE-ARENA-LOOKUP",
            "HOTREAD-LIFE-ARENA-REMOVE",
            "HOTREAD-LIFE-RECORD-RESET",
            "HOTREAD-LIFE-SHARDED-COMPLETION",
        ])
    );
    assert_eq!(
        row_id_set(&artifact, "source_accuracy_findings", "finding_id"),
        expected_set(&[
            "HOTREAD-ACCURACY-BENCH-SHAPE",
            "HOTREAD-ACCURACY-LYAPUNOV-O1",
            "HOTREAD-ACCURACY-FAST-CANCEL-REASON",
            "HOTREAD-ACCURACY-SHARDED-POOL",
            "HOTREAD-ACCURACY-OBSERVABILITY-BACKING",
        ])
    );

    for owner in array(&artifact, "ownership_model") {
        for field in [
            "owner",
            "payload",
            "synchronization",
            "lifetime",
            "generation",
            "publication",
        ] {
            text(owner, field);
        }
    }
    for surface in array(&artifact, "production_read_surfaces") {
        for field in [
            "owner",
            "synchronization",
            "lifetime_and_generation",
            "expected_frequency",
            "semantic_payload",
            "disposition",
        ] {
            text(surface, field);
        }
    }
    for writer in array(&artifact, "fast_cancel_writer_sites") {
        text(writer, "owner");
        assert!(text(writer, "ordering").contains("write guard"));
    }
}

#[test]
fn incumbent_rows_remain_exact_and_are_not_reinterpreted() {
    let artifact = repo_json(ARTIFACT_PATH);
    let reconciliation = object(&artifact, "benchmark_reconciliation");
    let reconciliation = Value::Object(reconciliation.clone());
    assert_eq!(
        text(&reconciliation, "incumbent_classification"),
        "HISTORICAL_NON_EQUIVALENT"
    );
    assert!(boolean(&reconciliation, "incumbent_rows_preserved"));
    assert!(!boolean(&reconciliation, "baseline_modified_by_hotread_1"));
    assert_eq!(unsigned(&reconciliation, "row_count"), 6);
    assert_eq!(
        string_set(&reconciliation, "operation_ids"),
        expected_set(&[
            "sched/task_state/locked_read_contended/4",
            "sched/task_state/locked_read_contended/8",
            "sched/task_state/locked_read_cycle",
        ])
    );
    assert_eq!(
        string_set(&reconciliation, "host_environments"),
        expected_set(&["host:fixmydocuments", "host:hetzner2"])
    );

    let baseline = repo_json(BASELINE_PATH);
    let live_rows = array(&baseline, "baselines")
        .iter()
        .filter(|row| text(row, "operation").starts_with("sched/task_state/"))
        .map(|row| {
            (
                (
                    text(row, "operation").to_owned(),
                    text(row, "environment").to_owned(),
                ),
                row,
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(live_rows.len(), 6);

    for expected in array(&reconciliation, "rows") {
        let key = (
            text(expected, "operation").to_owned(),
            text(expected, "environment").to_owned(),
        );
        let actual = live_rows
            .get(&key)
            .unwrap_or_else(|| panic!("missing incumbent row {key:?}"));
        assert_eq!(
            actual.get("p50_ns"),
            expected.get("p50_ns"),
            "p50 drift: {key:?}"
        );
        assert_eq!(text(actual, "git_sha"), text(expected, "git_sha"));
    }

    let bench = read_repo_file(BENCH_PATH);
    for required in [
        "benchmark_group(\"sched/task_state\")",
        "bench_function(\"locked_read_cycle\"",
        "BenchmarkId::new(\"locked_read_contended\", readers)",
        "for readers in [4usize, 8]",
        "run_phase6_p50_gate(\"sched/task_state/\")",
    ] {
        assert!(bench.contains(required), "benchmark lost {required}");
    }
}

#[test]
fn replacement_matrix_identity_and_migration_are_fail_closed() {
    let artifact = repo_json(ARTIFACT_PATH);
    let comparator = Value::Object(object(&artifact, "replacement_comparator_spec").clone());
    assert_eq!(text(&comparator, "namespace"), "sched/hotread/v2/");
    assert_eq!(
        string_set(&comparator, "comparator_roles"),
        expected_set(&[
            "current_production",
            "locked_rich_task_state",
            "existing_task_phase_cell",
            "existing_wake_fast_cancel",
        ])
    );
    let operations = string_set(&comparator, "operation_ids");
    assert_eq!(operations.len(), 19);
    assert!(
        operations
            .iter()
            .all(|operation| operation.starts_with("sched/hotread/v2/"))
    );
    for required in [
        "sched/hotread/v2/task_table_lookup/rich_state",
        "sched/hotread/v2/task_table_lookup/phase",
        "sched/hotread/v2/task_table_lookup/stale_generation_miss",
        "sched/hotread/v2/phase_scan/mixed_1024",
        "sched/hotread/v2/poll_cycle/global",
        "sched/hotread/v2/poll_cycle/local",
        "sched/hotread/v2/inject_ready/global_idle",
        "sched/hotread/v2/inject_ready/global_dedup",
        "sched/hotread/v2/inject_timed/global_idle",
        "sched/hotread/v2/inject_cancel/global_promotion",
        "sched/hotread/v2/waker/ordinary_global_healthy",
        "sched/hotread/v2/waker/ordinary_global_cancelled",
        "sched/hotread/v2/waker/ordinary_local_healthy",
        "sched/hotread/v2/waker/ordinary_local_cancelled",
        "sched/hotread/v2/waker/cancel_global_reason",
        "sched/hotread/v2/waker/cancel_local_reason",
        "sched/hotread/v2/checkpoint/healthy",
        "sched/hotread/v2/checkpoint/cancel_requested",
        "sched/hotread/v2/recycle_generation/1024",
    ] {
        assert!(
            operations.contains(required),
            "missing operation {required}"
        );
    }

    let profiles = row_id_set(&artifact, "profile_corpus", "profile_id");
    assert_eq!(
        profiles,
        expected_set(&[
            "steady_healthy_r1",
            "steady_healthy_r4",
            "steady_healthy_r8",
            "cancel_transition_r4_w1",
            "wake_idle",
            "wake_dedup",
            "lifecycle_churn_6p25",
            "mixed_phase_scan",
            "mixed_poll",
            "checkpoint_healthy",
            "checkpoint_cancelled",
        ])
    );
    for profile in array(&artifact, "profile_corpus") {
        assert!(unsigned(profile, "task_count") > 0);
        assert!(unsigned(profile, "measured_operations") > 0);
        text(profile, "description");
    }

    let identity = string_set(&artifact, "required_observation_identity_fields");
    for required in [
        "operation_id",
        "profile_id",
        "profile_version",
        "comparator_role",
        "candidate_id",
        "source_revision",
        "dirty_overlay_sha256",
        "environment",
        "os_hostname",
        "target_triple",
        "cpu_model",
        "numa_nodes",
        "memory_total_bytes",
        "allocator",
        "timer_source",
        "toolchain",
        "build_profile",
        "feature_set",
        "sample_count",
        "repetition_index",
        "repetition_count",
        "spread_pct",
        "outcome_checksum",
    ] {
        assert!(
            identity.contains(required),
            "missing identity field {required}"
        );
    }

    let migration = array(&artifact, "migration_rules")
        .iter()
        .map(|rule| rule.as_str().expect("migration rule string"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "six incumbent",
        "never reinterpret",
        "sched/hotread/v2",
        "at least three same-process",
        "matching ownership, generation, cancellation reason, wake, and queue-publication",
        "standalone atomic-load result cannot authorize",
        "peer-owned baseline",
    ] {
        assert!(
            migration.contains(required),
            "migration rules missing {required}"
        );
    }

    let decisions = object(&artifact, "ecosystem_scan")
        .get("decisions")
        .and_then(Value::as_array)
        .expect("ecosystem decisions array")
        .iter()
        .map(|row| (text(row, "candidate"), text(row, "disposition")))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(decisions["existing scalar atomics"], "KEEP_INCUMBENT");
    assert_eq!(decisions["rich state owner locks"], "KEEP_PENDING_PROFILE");
    assert_eq!(
        decisions["torn non-atomic seqlock"],
        "REJECT_UNCONDITIONALLY"
    );
}

#[test]
fn static_validation_and_documentation_keep_the_no_claim_boundary() {
    let artifact = repo_json(ARTIFACT_PATH);
    let authority = Value::Object(object(&artifact, "authority").clone());
    for field in [
        "production_behavior_changed",
        "production_conversion_authorized",
        "performance_claim_made",
        "baseline_rewrite_authorized",
        "new_dependency_authorized",
        "unsafe_code_authorized",
    ] {
        assert!(!boolean(&authority, field), "{field} must remain false");
    }

    let validation = Value::Object(object(&artifact, "validation_state").clone());
    assert!(boolean(&validation, "source_hashes_checked"));
    assert!(boolean(&validation, "source_anchors_checked"));
    assert!(boolean(&validation, "json_shape_checked"));
    assert!(boolean(&validation, "rust_contract_authored"));
    for field in [
        "rust_contract_executed",
        "compiler_or_toolchain_invoked",
        "tests_executed",
        "benchmarks_executed",
        "remote_jobs_executed",
    ] {
        assert!(!boolean(&validation, field), "{field} must remain false");
    }

    let no_claims = string_set(&artifact, "no_claims");
    for claim in [
        "compilation",
        "test execution",
        "runtime correctness",
        "wake correctness",
        "cancellation correctness",
        "deterministic replay",
        "performance improvement",
        "performance regression freedom",
        "final scheduler shape",
        "live host or remote fleet availability",
        "broad workspace health",
        "production conversion",
        "dependency change",
        "unsafe code approval",
        "baseline rewrite",
        "default flip",
    ] {
        assert!(
            no_claims.contains(claim),
            "missing no-claim boundary {claim}"
        );
    }

    let doc = read_repo_file(DOC_PATH);
    assert_eq!(doc.matches(BEGIN_MARKER).count(), 1);
    assert_eq!(doc.matches(END_MARKER).count(), 1);
    assert!(doc.find(BEGIN_MARKER) < doc.find(END_MARKER));
    for required in [
        BEAD_ID,
        ARTIFACT_PATH,
        "tests/scheduler_hot_read_inventory_contract.rs",
        "HISTORICAL_NON_EQUIVALENT",
        "sched/hotread/v2/",
        "steady_healthy_r1",
        "cancel_transition_r4_w1",
        "lifecycle_churn_6p25",
        "torn non-atomic seqlock",
        "No compiler, test, benchmark, profiler, or remote worker was invoked.",
    ] {
        assert!(doc.contains(required), "inventory doc missing {required}");
    }
    for operation in string_set(
        &Value::Object(object(&artifact, "replacement_comparator_spec").clone()),
        "operation_ids",
    ) {
        assert!(
            doc.contains(&operation),
            "inventory doc missing {operation}"
        );
    }
    for profile in array(&artifact, "profile_corpus") {
        let profile_id = text(profile, "profile_id");
        assert!(
            doc.contains(profile_id),
            "inventory doc missing {profile_id}"
        );
    }

    let runbook = read_repo_file(PERF_RUNBOOK_PATH);
    assert!(runbook.contains("historical non-equivalent task-state microbench rows"));
    assert!(runbook.contains(DOC_PATH));
    assert!(runbook.contains(ARTIFACT_PATH));
    assert!(runbook.contains("sched/hotread/v2/"));
}
