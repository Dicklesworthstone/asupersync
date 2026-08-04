//! Contract checks for the scoped cache-alignment experiment.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const ARTIFACT_PATH: &str = "artifacts/cache_padded_alignment_experiment_v1.json";
const RUNBOOK_PATH: &str = "docs/cache_padded_alignment_experiment.md";
const BENCH_PATH: &str = "benches/lab_iocap_contention.rs";

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
fn identity_policy_and_terminal_verdict_are_fail_closed() {
    let artifact = artifact();
    assert_eq!(number(artifact, "schema_version"), 1);
    assert_eq!(
        text(artifact, "artifact_id"),
        "cache-padded-alignment-experiment-v1"
    );
    assert_eq!(text(artifact, "bead_id"), "asupersync-0h6myr.6");
    assert_eq!(text(artifact, "capability_id"), "CAP-CACHE-LAYOUT");
    assert_eq!(text(artifact, "authority"), "EXPERIMENT_EVIDENCE_ONLY");

    let policy = object(artifact, "production_policy");
    assert_eq!(policy["global_alignment_bytes"], 64);
    assert_eq!(policy["global_change_made"], false);
    assert_eq!(policy["per_structure_change_made"], false);
    assert_eq!(policy["adoption_requires_separate_bead"], true);

    let verdict = object(artifact, "verdict");
    let verdict_value = Value::Object(verdict.clone());
    assert!(
        ["ADOPT_PER_STRUCTURE", "KEEP", "DEFER"].contains(&text(&verdict_value, "status")),
        "verdict must be terminal"
    );
    assert!(
        !text(&verdict_value, "reason").is_empty(),
        "terminal verdict needs a reason"
    );
}

#[test]
fn inventory_names_every_candidate_and_footprint_tradeoff() {
    let inventory = array(artifact(), "inventory");
    let actual = inventory
        .iter()
        .map(|row| text(row, "candidate_id"))
        .collect::<BTreeSet<_>>();
    let expected = [
        "CACHE-WRAPPER-POLICY",
        "CACHE-GLOBAL-FIFO-COUNTERS",
        "CACHE-READY-COMBINER-METRICS",
        "CACHE-TIMED-LANE-PAIR",
        "CACHE-WORKER-WAKE-INDEX",
        "CACHE-SPAWN-ID-SHARDS",
        "CACHE-EPOCH-PIN-VECTOR",
        "CACHE-LAB-IOCAP-SHARDS",
        "CACHE-CONTENDED-MUTEX-METRICS",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    for row in inventory {
        assert!(
            repo_path(text(row, "source_path")).is_file(),
            "inventory source path must exist"
        );
        assert!(
            !array(row, "fields").is_empty(),
            "candidate must name exact fields"
        );
        assert!(
            !text(row, "correctness_boundary").is_empty(),
            "candidate must state its correctness boundary"
        );
    }

    let by_id = |candidate_id: &str| {
        inventory
            .iter()
            .find(|row| text(row, "candidate_id") == candidate_id)
            .unwrap_or_else(|| panic!("missing {candidate_id}"))
    };
    assert_eq!(
        number(by_id("CACHE-GLOBAL-FIFO-COUNTERS"), "current_padded_bytes"),
        128
    );
    assert_eq!(
        number(
            by_id("CACHE-GLOBAL-FIFO-COUNTERS"),
            "experimental_padded_bytes"
        ),
        256
    );
    assert_eq!(
        number(by_id("CACHE-READY-COMBINER-METRICS"), "padded_field_count"),
        12
    );
    assert_eq!(
        number(by_id("CACHE-LAB-IOCAP-SHARDS"), "experimental_padded_bytes"),
        2048
    );
    assert_eq!(
        text(by_id("CACHE-CONTENDED-MUTEX-METRICS"), "status"),
        "NO_CLAIM_UNMODELED_PRIVATE_LAYOUT"
    );
}

#[test]
fn benchmark_contract_covers_latency_throughput_fairness_memory_and_scaling() {
    let benchmark = object(artifact(), "benchmark_contract");
    let benchmark_value = Value::Object(benchmark.clone());
    assert_eq!(text(&benchmark_value, "harness"), BENCH_PATH);
    assert_eq!(
        text(&benchmark_value, "profile_id"),
        "cache-alignment-bounded-v1"
    );
    assert_eq!(benchmark["alignment_cells"], serde_json::json!([64, 128]));
    assert_eq!(
        benchmark["core_scaling_cells"],
        serde_json::json!([1, 2, 4, 8, 16, 32, 64])
    );

    let axes = array(&benchmark_value, "required_axes")
        .iter()
        .map(|value| value.as_str().expect("axis must be text"))
        .collect::<BTreeSet<_>>();
    for required in [
        "throughput_ops_per_second",
        "p50_ns",
        "p95_ns",
        "p99_ns",
        "p999_ns",
        "fairness_millionths",
        "entry_and_array_footprint_bytes",
    ] {
        assert!(axes.contains(required), "missing benchmark axis {required}");
    }

    let bounds = object(&benchmark_value, "bounds");
    assert_eq!(bounds["chunk_operations"], 256);
    assert_eq!(bounds["maximum_workers"], 64);
    assert!(
        bounds["default_operations_per_writer"]
            .as_u64()
            .expect("default operations")
            <= bounds["maximum_operations_per_writer"]
                .as_u64()
                .expect("maximum operations")
    );
}

#[test]
fn platform_matrix_records_one_measured_cell_and_explicit_missing_cells() {
    let matrix = array(artifact(), "platform_matrix");
    let measured = matrix
        .iter()
        .filter(|row| text(row, "status") == "MEASURED")
        .collect::<Vec<_>>();
    assert_eq!(measured.len(), 1, "exactly one available host was admitted");
    let measured = measured[0];
    for key in ["worker", "topology", "result_summary"] {
        assert!(
            !measured[key].is_null(),
            "measured platform row needs {key}"
        );
    }
    assert_eq!(text(measured, "profile_id"), "cache-alignment-bounded-v1");
    assert!(
        measured["process_rss_kib"]
            .as_u64()
            .expect("measured RSS must be numeric")
            > 0
    );
    let counters = object(measured, "cache_counters");
    assert!(
        counters["cache_references"]
            .as_u64()
            .expect("cache references")
            > 0
    );
    assert!(counters["cache_misses"].as_u64().expect("cache misses") > 0);

    let missing = matrix
        .iter()
        .filter(|row| text(row, "status").starts_with("NO_CLAIM"))
        .map(|row| text(row, "cell_id"))
        .collect::<BTreeSet<_>>();
    assert!(missing.contains("APPLE-SILICON-128-LINE"));
    assert!(missing.contains("SECOND-X86-VENDOR"));
}

#[test]
fn measured_receipt_contains_every_required_axis_and_footprint_cell() {
    let receipt = object(artifact(), "measurement_receipt");
    assert_eq!(receipt["schema_version"], 1);
    assert_eq!(
        receipt["profile_id"],
        serde_json::json!("cache-alignment-bounded-v1")
    );
    assert_eq!(receipt["available_parallelism"], 8);
    assert_eq!(receipt["operations_per_writer"], 65_536);
    assert_eq!(receipt["chunk_operations"], 256);

    let receipt_value = Value::Object(receipt.clone());
    let layouts = array(&receipt_value, "layouts");
    assert_eq!(layouts.len(), 2);
    assert_eq!(layouts[0]["entry_bytes"], 64);
    assert_eq!(layouts[1]["entry_bytes"], 128);
    assert_eq!(layouts[0]["array_64_bytes"], 4096);
    assert_eq!(layouts[1]["array_64_bytes"], 8192);

    let rows = array(&receipt_value, "rows");
    assert_eq!(rows.len(), 16);
    for row in rows {
        for key in [
            "operations",
            "elapsed_ns",
            "throughput_ops_per_second",
            "p50_ns",
            "p95_ns",
            "p99_ns",
            "p999_ns",
            "fairness_millionths",
        ] {
            assert!(row[key].as_u64().is_some(), "row missing numeric {key}");
        }
        assert!([64, 128].contains(&number(row, "alignment_bytes")));
    }

    let write_workers = rows
        .iter()
        .filter(|row| text(row, "workload_id") == "independent_hot_counters")
        .map(|row| number(row, "workers"))
        .collect::<BTreeSet<_>>();
    assert_eq!(write_workers, [1, 2, 4, 8].into_iter().collect());
    let scan_entries = rows
        .iter()
        .filter(|row| text(row, "workload_id") == "snapshot_scan_density")
        .map(|row| number(row, "entries"))
        .collect::<BTreeSet<_>>();
    assert_eq!(scan_entries, [8, 16, 32, 64].into_iter().collect());
}

#[test]
fn execution_receipts_are_terminal_and_green() {
    let receipts = array(artifact(), "execution_receipts");
    let expected = [
        "CACHE-ALIGNMENT-BENCH-CHECK",
        "CACHE-ALIGNMENT-AVAILABLE-HOST-RUN",
        "CACHE-ALIGNMENT-CONTRACT",
        "CACHE-ALIGNMENT-ALL-TARGET-CHECK",
        "CACHE-ALIGNMENT-ALL-TARGET-CLIPPY",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual = receipts
        .iter()
        .map(|receipt| text(receipt, "receipt_id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    for receipt in receipts {
        assert_eq!(text(receipt, "status"), "PASS");
        assert_eq!(receipt["exit_code"], 0);
    }
}

#[test]
fn source_pins_match_the_inventory_revision() {
    let pins = array(artifact(), "source_pins");
    let expected = [
        ".gitignore",
        BENCH_PATH,
        "src/util/cache.rs",
        "src/runtime/scheduler/global_queue.rs",
        "src/runtime/scheduler/global_injector.rs",
        "src/runtime/scheduler/three_lane.rs",
        "src/runtime/spawn_mailbox.rs",
        "src/runtime/epoch_tracking.rs",
        "src/io/cap.rs",
        "src/sync/contended_mutex.rs",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual = pins
        .iter()
        .map(|pin| text(pin, "path"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    for pin in pins {
        let path = text(pin, "path");
        let bytes = std::fs::read(repo_path(path))
            .unwrap_or_else(|error| panic!("read source pin {path}: {error}"));
        assert_eq!(sha256_hex(&bytes), text(pin, "sha256"), "{path} hash");
        assert_eq!(
            bytes.split(|byte| *byte == b'\n').count() - 1,
            usize::try_from(number(pin, "line_count")).expect("line count fits usize"),
            "{path} line count"
        );
    }
}

#[test]
fn bench_and_runbook_keep_the_experiment_scoped() {
    let bench = read(BENCH_PATH);
    for marker in [
        "#[repr(C, align(64))]",
        "#[repr(C, align(128))]",
        "independent_hot_counters",
        "snapshot_scan_density",
        "throughput_ops_per_second",
        "p999_ns",
        "fairness_millionths",
        "CACHE_ALIGNMENT_RECEIPT=",
        "ASUP_CACHE_ALIGNMENT_OPS",
    ] {
        assert!(bench.contains(marker), "benchmark missing {marker}");
    }

    let runbook = read(RUNBOOK_PATH);
    for marker in [
        "does not change `CachePadded<T>`",
        "Host and topology provenance",
        "`ADOPT_PER_STRUCTURE`",
        "`KEEP`",
        "`DEFER`",
        "There is no `ADOPT_GLOBAL` outcome.",
        "explicit no-claim",
    ] {
        assert!(runbook.contains(marker), "runbook missing {marker}");
    }

    let boundaries = array(artifact(), "no_claim_boundaries");
    assert!(boundaries.len() >= 7);
    assert!(
        boundaries
            .iter()
            .all(|boundary| !boundary.as_str().expect("boundary text").is_empty())
    );
}
