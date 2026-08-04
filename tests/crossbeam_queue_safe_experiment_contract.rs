//! Contract checks for the safe queue experiment and terminal decision.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const ARTIFACT_PATH: &str = "artifacts/crossbeam_queue_safe_experiment_v1.json";
const RUNBOOK_PATH: &str = "docs/crossbeam_queue_safe_experiment.md";
const BENCHMARK_PATH: &str = "benches/otlp_queue_contention.rs";

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo_path(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn artifact() -> &'static Value {
    static ARTIFACT: OnceLock<Value> = OnceLock::new();
    ARTIFACT.get_or_init(|| {
        serde_json::from_str(&read(ARTIFACT_PATH))
            .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
    })
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value[key]
        .as_object()
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn identity_and_terminal_keep_are_fail_closed() {
    let artifact = artifact();
    assert_eq!(number(artifact, "schema_version"), 1);
    assert_eq!(
        text(artifact, "artifact_id"),
        "crossbeam-queue-safe-experiment-v1"
    );
    assert_eq!(text(artifact, "bead_id"), "asupersync-0h6myr.2");
    assert_eq!(text(artifact, "capability_id"), "CAP-CONCURRENT-QUEUES");
    assert_eq!(
        text(artifact, "benchmark_baseline_commit"),
        "06c08d95a35acb93494be16778ad04eb3e96c0a1"
    );
    assert_eq!(
        text(artifact, "evidence_packet_baseline_commit"),
        "876110528f810c3334a99450a521daa27995a3ec"
    );
    assert_eq!(
        text(artifact, "authority"),
        "EXPERIMENT_AND_DOCUMENTATION_EVIDENCE_ONLY"
    );
    assert_eq!(artifact["production_behavior_change_made"], false);

    let decision = object(artifact, "decision");
    assert_eq!(decision["status"], "KEEP");
    assert_eq!(decision["disposition"], "KEEP_INCUMBENT");
    assert_eq!(decision["dependency_exit_allowed"], false);
    assert_eq!(decision["production_cutover_authorized"], false);
    assert_eq!(decision["cutover_bead_filed"], false);
    assert_eq!(
        decision["implementation_followups_authorized"],
        serde_json::json!([])
    );
    assert!(!text(&Value::Object(decision.clone()), "reason").is_empty());

    let gate = object(artifact, "gate");
    assert_eq!(gate["early_stop_applied"], true);
    assert_eq!(gate["full_matrix_required_for_cutover"], true);
    assert_eq!(gate["full_matrix_completed"], false);
    assert_eq!(gate["decisive_cell"], "OTLP-64-PRODUCERS");
}

#[test]
fn dependency_and_claim_time_surface_inventory_are_exact() {
    let dependency = object(artifact(), "dependency");
    assert_eq!(dependency["manifest_name"], "crossbeam-queue");
    assert_eq!(dependency["requirement"], "0.3");
    assert_eq!(dependency["locked_version"], "0.3.13");

    let drift = object(artifact(), "claim_time_drift");
    assert_eq!(drift["direct_production_module_count"], 5);
    assert_eq!(
        drift["mpsc_disposition"],
        "EXCLUDED_NOT_A_CROSSBEAM_QUEUE_SURFACE"
    );

    let mpsc = read("src/channel/mpsc.rs");
    assert!(mpsc.contains("parking_lot::Mutex<ChannelInner>"));
    assert!(mpsc.contains("queue: VecDeque<T>"));
    assert!(!mpsc.contains("use crossbeam_queue::"));

    let inventory = array(artifact(), "surface_inventory");
    assert_eq!(inventory.len(), 5);
    assert_eq!(
        inventory
            .iter()
            .map(|row| text(row, "surface_id"))
            .collect::<BTreeSet<_>>(),
        [
            "QUEUE-BLOCKING-POOL",
            "QUEUE-EPOCH-GC",
            "QUEUE-EPOCH-TRACKING",
            "QUEUE-OTLP-EXPORT",
            "QUEUE-SCHEDULER-GLOBAL-FIFO",
        ]
        .into_iter()
        .collect()
    );
    for row in inventory {
        assert!(repo_path(text(row, "source_path")).is_file());
        assert!(!text(row, "primitive").is_empty());
        assert!(!text(row, "semantics").is_empty());
    }
}

#[test]
fn corrected_benchmark_uses_production_queue_and_fixed_work() {
    let benchmark = read(BENCHMARK_PATH);
    assert!(
        benchmark
            .contains("use asupersync::observability::otlp_trace_exporter::BoundedExportQueue;")
    );
    assert!(benchmark.contains("use parking_lot::Mutex;"));
    assert!(benchmark.contains("const TOTAL_OPERATIONS: usize = 65_536;"));
    assert!(benchmark.contains("const THREAD_COUNTS: [usize; 4] = [1, 8, 32, 64];"));
    assert!(benchmark.contains("group.sample_size(10);"));
    assert!(benchmark.contains("BoundedExportQueue::new(QUEUE_CAPACITY)"));
    assert!(!benchmark.contains("mod lock_free"));
    assert!(!benchmark.contains("crossbeam_queue::ArrayQueue"));
    assert!(!benchmark.contains("10x+"));

    let correction = object(artifact(), "benchmark_correction");
    assert_eq!(correction["old_fixed_speedup_claim_removed"], true);
    assert_eq!(
        correction["old_hand_written_array_queue_approximation_removed"],
        true
    );
    assert_eq!(correction["fixed_total_work_per_cell"], true);
    assert_eq!(correction["total_operations_per_cell"], 65_536);
    assert_eq!(
        correction["not_a_pure_queue_operation_latency_measurement"],
        true
    );
    assert!(
        array(
            &Value::Object(correction.clone()),
            "timed_workload_includes"
        )
        .iter()
        .any(|item| item == "producer thread spawn and join")
    );
    assert_eq!(
        correction["producer_thread_counts"],
        serde_json::json!([1, 8, 32, 64])
    );

    let source = read("src/observability/otlp_trace_exporter.rs");
    assert!(!source.contains("100K+ spans/sec"));
    assert!(!source.contains("zero-contention access"));
}

#[test]
fn formal_receipt_has_a_separated_candidate_regression() {
    let execution = object(artifact(), "formal_execution");
    assert_eq!(execution["status"], "PASS");
    assert_eq!(execution["exit_code"], 0);
    assert_eq!(number(&Value::Object(execution.clone()), "sample_size"), 10);

    let execution_value = Value::Object(execution.clone());
    let host = object(&execution_value, "host");
    assert_eq!(host["logical_cpus"], 16);
    assert_eq!(host["physical_cores"], 8);
    assert_eq!(host["architecture"], "x86_64");

    let results = array(&execution_value, "results");
    assert_eq!(results.len(), 4);
    assert_eq!(
        results
            .iter()
            .map(|row| number(row, "producer_threads"))
            .collect::<BTreeSet<_>>(),
        [1, 8, 32, 64].into_iter().collect()
    );

    let decisive = results
        .iter()
        .find(|row| text(row, "cell_id") == "OTLP-64-PRODUCERS")
        .expect("decisive 64-producer row");
    assert_eq!(decisive["oversubscribed"], true);
    assert_eq!(decisive["candidate_verdict"], "REGRESSION");
    let safe = object(decisive, "safe_mutex_queue");
    let incumbent = object(decisive, "incumbent_array_queue");
    assert!(
        safe["time_lower_ns"].as_f64().expect("safe lower")
            > incumbent["time_upper_ns"]
                .as_f64()
                .expect("incumbent upper"),
        "the candidate's entire time interval must be slower"
    );
}

#[test]
fn evidence_gaps_and_historical_harness_are_not_overclaimed() {
    let historical = object(artifact(), "historical_harness_replay");
    assert_eq!(historical["admissible_for_gate"], false);
    assert_eq!(historical["status"], "PASS_NOT_GATE_EVIDENCE");
    assert!(array(&Value::Object(historical.clone()), "reasons").len() >= 4);

    let gaps = array(artifact(), "evidence_gaps_after_stop");
    let axes = gaps
        .iter()
        .map(|row| text(row, "axis"))
        .collect::<BTreeSet<_>>();
    for required in [
        "physical-core scaling",
        "Apple Silicon",
        "p50/p95/p99/p999 operation latency",
        "fairness and starvation",
        "allocation and RSS",
        "isolated queue cost and end-to-end exporter service",
        "scheduler, blocking-pool, and epoch workloads",
    ] {
        assert!(axes.contains(required), "missing no-claim axis {required}");
    }
    for row in gaps {
        assert_ne!(row["status"], "PASS");
        assert!(!text(row, "detail").is_empty());
    }

    let no_claims = array(artifact(), "no_claims");
    assert!(no_claims.len() >= 5);
    let joined = no_claims
        .iter()
        .map(|claim| claim.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join("\n");
    for phrase in [
        "No crossbeam-queue removal",
        "physical-core",
        "p999",
        "No unsafe code",
    ] {
        assert!(joined.contains(phrase), "missing no-claim phrase {phrase}");
    }
}

#[test]
fn source_pins_and_operator_markers_are_current() {
    for pin in array(artifact(), "source_pins") {
        let path = text(pin, "path");
        let bytes = std::fs::read(repo_path(path))
            .unwrap_or_else(|error| panic!("read source pin {path}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "source pin changed for {path}"
        );
        assert_eq!(
            std::str::from_utf8(&bytes)
                .unwrap_or_else(|error| panic!("source pin {path} is not UTF-8: {error}"))
                .lines()
                .count() as u64,
            number(pin, "line_count"),
            "line count changed for {path}"
        );
    }

    let runbook = read(RUNBOOK_PATH);
    for marker in [
        "<!-- BEGIN CROSSBEAM QUEUE SAFE EXPERIMENT -->",
        "KEEP_INCUMBENT",
        "OTLP-64-PRODUCERS",
        "No-claim boundary",
        "No local Cargo fallback is approved.",
        "<!-- END CROSSBEAM QUEUE SAFE EXPERIMENT -->",
    ] {
        assert!(runbook.contains(marker), "missing runbook marker {marker}");
    }

    assert!(read(".gitignore").contains("!artifacts/crossbeam_queue_safe_experiment_v1.json"));
}
