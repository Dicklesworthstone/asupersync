//! Runtime tail-latency taxonomy contract invariants (AA-01.1).

#![allow(missing_docs)]

use asupersync::observability::{
    TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION, TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION,
    TailLatencyCompactSample, TailLatencyEmitterConfig, emit_tail_latency_compact_event,
    tail_latency_taxonomy_contract,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_tail_latency_taxonomy_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_tail_latency_taxonomy_v1.json";
const RUNNER_PATH: &str = "scripts/run_tail_causal_attribution_emitters_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load runtime tail latency taxonomy doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load runtime tail latency taxonomy artifact");
    serde_json::from_str(&raw).expect("failed to parse taxonomy artifact")
}

fn load_runner() -> String {
    std::fs::read_to_string(repo_root().join(RUNNER_PATH))
        .expect("failed to load compact tail causal attribution runner")
}

fn artifact_required_fields(value: &Value) -> BTreeMap<String, (String, bool)> {
    value["required_log_fields"]
        .as_array()
        .expect("required_log_fields must be an array")
        .iter()
        .map(|field| {
            (
                field["key"]
                    .as_str()
                    .expect("field key must be string")
                    .to_string(),
                (
                    field["unit"]
                        .as_str()
                        .expect("field unit must be string")
                        .to_string(),
                    field["required"]
                        .as_bool()
                        .expect("field required must be bool"),
                ),
            )
        })
        .collect()
}

fn artifact_signal_inventory(value: &Value) -> BTreeMap<String, BTreeSet<String>> {
    value["terms"]
        .as_array()
        .expect("terms must be array")
        .iter()
        .map(|term| {
            let term_id = term["term_id"]
                .as_str()
                .expect("term_id must be string")
                .to_string();
            let signals = term["signals"]
                .as_array()
                .expect("signals must be array")
                .iter()
                .map(|signal| {
                    format!(
                        "{}|{}|{}|{}|{}|{}",
                        signal["structured_log_key"]
                            .as_str()
                            .expect("structured_log_key must be string"),
                        signal["unit"].as_str().expect("unit must be string"),
                        signal["producer_symbol"]
                            .as_str()
                            .expect("producer_symbol must be string"),
                        signal["producer_file"]
                            .as_str()
                            .expect("producer_file must be string"),
                        signal["measurement_class"]
                            .as_str()
                            .expect("measurement_class must be string"),
                        signal["core"].as_bool().expect("core must be bool"),
                    )
                })
                .collect();
            (term_id, signals)
        })
        .collect()
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "runtime tail latency taxonomy doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.1.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Canonical Equation",
        "Required Core Log Fields",
        "Term Mapping",
        "Unknown Bucket Policy",
        "Sampling Policy",
        "Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }
    assert!(
        missing.is_empty(),
        "doc missing sections:\n{}",
        missing
            .iter()
            .map(|section| format!("  - {section}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_test_and_source() {
    let doc = load_doc();
    let refs = [
        "artifacts/runtime_tail_latency_taxonomy_v1.json",
        "tests/runtime_tail_latency_taxonomy_contract.rs",
        "src/observability/diagnostics.rs",
        "scripts/run_tail_causal_attribution_emitters_smoke.sh",
    ];
    for reference in refs {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tail_latency_taxonomy cargo test -p asupersync --test runtime_tail_latency_taxonomy_contract --features test-internals -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

#[test]
fn artifact_contract_version_and_equation_match_code() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();

    assert_eq!(
        artifact["contract_version"].as_str(),
        Some(TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION)
    );
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some(contract.contract_version.as_str())
    );
    assert_eq!(
        artifact["equation"].as_str(),
        Some(contract.equation.as_str())
    );
    assert_eq!(
        artifact["total_latency_key"].as_str(),
        Some(contract.total_latency_key.as_str())
    );
    assert_eq!(
        artifact["unknown_bucket_key"].as_str(),
        Some(contract.unknown_bucket_key.as_str())
    );
}

#[test]
fn artifact_required_field_inventory_matches_code() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();

    let expected: BTreeMap<String, (String, bool)> = contract
        .required_log_fields
        .into_iter()
        .map(|field| (field.key, (field.unit, field.required)))
        .collect();
    assert_eq!(artifact_required_fields(&artifact), expected);
}

#[test]
fn artifact_term_and_signal_inventory_matches_code() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();

    let expected: BTreeMap<String, BTreeSet<String>> = contract
        .terms
        .into_iter()
        .map(|term| {
            (
                term.term_id,
                term.signals
                    .into_iter()
                    .map(|signal| {
                        format!(
                            "{}|{}|{}|{}|{}|{}",
                            signal.structured_log_key,
                            signal.unit,
                            signal.producer_symbol,
                            signal.producer_file,
                            signal.measurement_class,
                            signal.core
                        )
                    })
                    .collect(),
            )
        })
        .collect();

    assert_eq!(artifact_signal_inventory(&artifact), expected);
}

#[test]
fn artifact_producer_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();

    for term in artifact["terms"].as_array().expect("terms must be array") {
        for signal in term["signals"].as_array().expect("signals must be array") {
            let producer_file = signal["producer_file"]
                .as_str()
                .expect("producer_file must be string");
            assert!(
                root.join(producer_file).exists(),
                "producer file must exist: {producer_file}"
            );
        }
    }
}

#[test]
fn contract_covers_all_required_terms() {
    let contract = tail_latency_taxonomy_contract();
    let term_ids: BTreeSet<&str> = contract
        .terms
        .iter()
        .map(|term| term.term_id.as_str())
        .collect();
    assert_eq!(
        term_ids,
        BTreeSet::from([
            "allocator_or_cache",
            "io_or_network",
            "queueing",
            "retries",
            "service",
            "synchronization",
            "unknown",
        ]),
        "contract must cover the canonical decomposition terms"
    );
}

#[test]
fn artifact_declares_compact_tail_emitter_contract() {
    let artifact = load_artifact();
    let emitter = &artifact["compact_tail_emitter"];

    assert_eq!(
        emitter["event_schema_version"].as_str(),
        Some(TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION)
    );
    assert_eq!(emitter["bead_id"].as_str(), Some("asupersync-d87ytw.5"));
    assert_eq!(emitter["disabled_by_default"].as_bool(), Some(true));
    assert_eq!(emitter["smoke_runner"].as_str(), Some(RUNNER_PATH));

    let required_event_fields: BTreeSet<&str> = emitter["required_event_fields"]
        .as_array()
        .expect("required_event_fields must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required_event_fields entries must be strings")
        })
        .collect();
    for required in [
        "scenario_id",
        "event_id",
        "taxonomy_version",
        "fields",
        "unknown_unmeasured_ns",
        "overhead_estimate_bytes",
        "missing_producers",
    ] {
        assert!(
            required_event_fields.contains(required),
            "compact emitter contract must require {required}"
        );
    }

    assert!(
        emitter["smoke_scenarios"]
            .as_array()
            .expect("smoke_scenarios must be array")
            .len()
            >= 3,
        "compact emitter contract must include complete, missing-producer, and disabled scenarios"
    );
}

#[test]
fn runner_script_exists_and_routes_execute_through_rch() {
    let runner = load_runner();
    assert!(Path::new(RUNNER_PATH).exists(), "runner must exist");
    assert!(runner.contains("--list"), "runner must support --list");
    assert!(
        runner.contains("--dry-run"),
        "runner must support --dry-run"
    );
    assert!(
        runner.contains("--execute"),
        "runner must support --execute"
    );
    assert!(
        runner.contains("rch exec -- env CARGO_INCREMENTAL=0"),
        "runner execute mode must route cargo through rch"
    );
    assert!(
        runner.contains("ASUPERSYNC_TAIL_CAUSAL_ATTRIBUTION_REPORT_PATH"),
        "runner must pass the report path to the Rust smoke test"
    );
    assert!(
        runner.contains("COMMAND_EXIT_CODE=$?"),
        "runner must preserve the real rch wrapper exit code in run_report.json"
    );
    assert!(
        !runner.contains("if ! bash -lc \"$COMMAND\""),
        "runner must not lose the command status through shell boolean negation"
    );
}

fn smoke_sample_complete() -> TailLatencyCompactSample {
    TailLatencyCompactSample::new(18_000)
        .with_ready_queue_depth(64)
        .with_poll_count(11)
        .with_events_received(7)
        .with_retries_total_delay_ns(2_000)
        .with_synchronization_lock_wait_ns(3_000)
        .with_allocator_live_allocations(128)
        .with_allocator_bytes_live(32_768)
}

#[test]
fn compact_tail_causal_attribution_smoke_emits_report() {
    let report_path = std::env::var("ASUPERSYNC_TAIL_CAUSAL_ATTRIBUTION_REPORT_PATH")
        .unwrap_or_else(|_| "target/tail-causal-attribution-smoke/report.json".to_string());
    let replay_command =
        format!("bash {RUNNER_PATH} --execute --output-root target/tail-causal-attribution-smoke");

    let complete_event = emit_tail_latency_compact_event(
        TailLatencyEmitterConfig::enabled_core().with_extended_allocator_bytes_live(),
        "TAIL-CAUSAL-COMPLETE-CORE",
        "tail-event-0001",
        smoke_sample_complete(),
    )
    .expect("complete event should emit")
    .expect("complete event should be present");

    let missing_producer_event = emit_tail_latency_compact_event(
        TailLatencyEmitterConfig::enabled_core(),
        "TAIL-CAUSAL-MISSING-PRODUCER",
        "tail-event-0002",
        TailLatencyCompactSample::new(10_000)
            .with_ready_queue_depth(4)
            .with_retries_total_delay_ns(1_000)
            .with_allocator_live_allocations(12),
    )
    .expect("missing-producer event should emit")
    .expect("missing-producer event should be present");

    let disabled_event = emit_tail_latency_compact_event(
        TailLatencyEmitterConfig::default(),
        "TAIL-CAUSAL-DISABLED",
        "tail-event-0003",
        smoke_sample_complete(),
    )
    .expect("disabled emitter should not fail validation");

    assert_eq!(
        complete_event.taxonomy_version,
        TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION
    );
    assert_eq!(complete_event.unknown_unmeasured_ns, 13_000);
    assert!(complete_event.missing_producers.is_empty());
    assert!(
        missing_producer_event.unknown_unmeasured_ns > 0,
        "missing producers must leave a visible unknown residual"
    );
    assert!(
        missing_producer_event
            .missing_producers
            .iter()
            .any(|producer| producer == "tail.service.poll_count")
    );
    assert!(
        disabled_event.is_none(),
        "disabled mode must not emit a row"
    );

    let report = json!({
        "schema_version": "tail-causal-attribution-smoke-report-v1",
        "bead_id": "asupersync-d87ytw.5",
        "status": "passed",
        "artifact_path": report_path,
        "replay_command": replay_command,
        "rows": [
            {
                "scenario_id": complete_event.scenario_id,
                "event_id": complete_event.event_id,
                "taxonomy_version": complete_event.taxonomy_version,
                "compact_fields": complete_event.fields,
                "residual_unknown_ns": complete_event.unknown_unmeasured_ns,
                "overhead_estimate_bytes": complete_event.overhead_estimate_bytes,
                "missing_producers": complete_event.missing_producers,
                "verdict": "pass"
            },
            {
                "scenario_id": missing_producer_event.scenario_id,
                "event_id": missing_producer_event.event_id,
                "taxonomy_version": missing_producer_event.taxonomy_version,
                "compact_fields": missing_producer_event.fields,
                "residual_unknown_ns": missing_producer_event.unknown_unmeasured_ns,
                "overhead_estimate_bytes": missing_producer_event.overhead_estimate_bytes,
                "missing_producers": missing_producer_event.missing_producers,
                "verdict": "fallback_unknown"
            },
            {
                "scenario_id": "TAIL-CAUSAL-DISABLED",
                "event_id": "tail-event-0003",
                "taxonomy_version": TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION,
                "compact_fields": {},
                "residual_unknown_ns": null,
                "overhead_estimate_bytes": 0,
                "missing_producers": [],
                "verdict": "disabled_noop"
            }
        ]
    });

    println!("TAIL_CAUSAL_ATTRIBUTION_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
    println!("TAIL_CAUSAL_ATTRIBUTION_REPORT_JSON_END");

    let report_path = PathBuf::from(
        report["artifact_path"]
            .as_str()
            .expect("report path should be string"),
    );
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).expect("create report directory");
    }
    std::fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("serialize report file"),
    )
    .expect("write report file");
}
