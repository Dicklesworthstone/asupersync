#![allow(missing_docs)]

#[allow(dead_code)]
#[path = "../src/atp/autotune.rs"]
mod autotune;

use autotune::{
    ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION, AtpAutotuneDecisionReceipt, AtpAutotunePolicy,
    AtpAutotuneSettings, AtpAutotuneTelemetryError, AtpAutotuneTelemetryReport,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

const CORPUS_JSON: &str = include_str!("fixtures/atp_autotune_replay_corpus/corpus.json");
const CORPUS_SCHEMA_VERSION: &str = "atp-autotune-noisy-pressure-replay-corpus-v1";
const REPLAY_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p5 cargo test -p asupersync --test atp_autotune_replay_corpus -- --nocapture";

#[derive(Debug, Deserialize)]
struct Corpus {
    schema_version: String,
    update_command: String,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Fixture {
    Decision {
        fixture_id: String,
        report: AtpAutotuneTelemetryReport,
        current_settings: AtpAutotuneSettings,
        expected_receipt: Value,
    },
    AggregationError {
        fixture_id: String,
        report: AtpAutotuneTelemetryReport,
        expected_error: Value,
    },
}

#[test]
fn noisy_pressure_corpus_replays_to_golden_receipts() {
    let corpus: Corpus = serde_json::from_str(CORPUS_JSON).expect("corpus JSON");
    assert_eq!(corpus.schema_version, CORPUS_SCHEMA_VERSION);
    assert_eq!(corpus.update_command, REPLAY_COMMAND);

    let mut fixture_ids = BTreeSet::new();
    for fixture in corpus.fixtures {
        match fixture {
            Fixture::Decision {
                fixture_id,
                report,
                current_settings,
                expected_receipt,
            } => {
                assert!(
                    fixture_ids.insert(fixture_id.clone()),
                    "duplicate fixture id"
                );
                let telemetry = report
                    .clone()
                    .into_telemetry()
                    .unwrap_or_else(|err| panic!("{fixture_id} telemetry should aggregate: {err}"));
                let receipt =
                    AtpAutotunePolicy::default().decide_with_receipt(current_settings, &telemetry);
                let actual = decision_receipt_summary(&report, &receipt);
                assert_redaction_safe(&actual);
                assert_eq!(
                    actual, expected_receipt,
                    "{fixture_id} golden autotune receipt drifted; update only with `{REPLAY_COMMAND}` and a reviewed fixture diff",
                );
            }
            Fixture::AggregationError {
                fixture_id,
                report,
                expected_error,
            } => {
                assert!(
                    fixture_ids.insert(fixture_id.clone()),
                    "duplicate fixture id"
                );
                let actual = telemetry_error_summary(
                    report
                        .into_telemetry()
                        .expect_err("fixture must fail telemetry aggregation"),
                );
                assert_redaction_safe(&actual);
                assert_eq!(
                    actual, expected_error,
                    "{fixture_id} aggregation error golden drifted",
                );
            }
        }
    }

    for required in [
        "clean_path_growth",
        "lossy_high_repair_roi",
        "high_pto_backoff",
        "disk_read_write_lag",
        "encode_decode_backlog",
        "relay_expensive_path",
        "migration_event_backoff",
        "duplicate_metric_latest_wins",
        "zero_samples_hold",
        "blank_trace_id_malformed",
        "out_of_range_loss_sample",
    ] {
        assert!(
            fixture_ids.contains(required),
            "missing required ATP autotune replay fixture {required}",
        );
    }
}

fn decision_receipt_summary(
    report: &AtpAutotuneTelemetryReport,
    receipt: &AtpAutotuneDecisionReceipt,
) -> Value {
    assert_eq!(
        receipt.schema_version,
        ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION
    );

    let samples: Vec<Value> = report
        .samples
        .iter()
        .map(|sample| {
            json!({
                "metric": sample.metric.as_str(),
                "value": sample.value,
            })
        })
        .collect();
    let bottlenecks: Vec<Value> = receipt
        .decision
        .bottlenecks
        .iter()
        .map(|signal| {
            json!({
                "kind": format!("{:?}", signal.kind),
                "metric": signal.metric.map(|metric| metric.as_str()),
                "observed": signal.observed,
                "threshold": signal.threshold,
            })
        })
        .collect();
    let changes: Vec<Value> = receipt
        .changes
        .iter()
        .map(|change| {
            json!({
                "knob": change.knob.as_str(),
                "previous": change.previous,
                "next": change.next,
                "direction": format!("{:?}", change.direction),
                "delta": change.delta,
            })
        })
        .collect();
    let selected_knobs: Vec<Value> = receipt
        .selected_knobs()
        .iter()
        .map(|knob| json!(knob.as_str()))
        .collect();
    let caveats: Vec<Value> = receipt.caveats.iter().map(|caveat| json!(caveat)).collect();
    let stale_sources: Vec<Value> = receipt
        .stale_sources
        .iter()
        .map(|source| json!(source))
        .collect();

    json!({
        "schema_version": receipt.schema_version.as_str(),
        "trace_id": receipt.trace_id.as_str(),
        "workload_id": receipt.workload_id.as_str(),
        "sample_count": receipt.sample_count,
        "consumer_status": receipt.consumer_status.as_str(),
        "samples": samples,
        "outcome": format!("{:?}", receipt.outcome),
        "reason_code": receipt.decision.reason_code.as_str(),
        "fail_closed": receipt.decision.fail_closed,
        "confidence": receipt.confidence.as_str(),
        "caveats": caveats,
        "stale_sources": stale_sources,
        "proof_pointer": {
            "receipt_schema_version": receipt.proof_pointer.receipt_schema_version.as_str(),
            "trace_id": receipt.proof_pointer.trace_id.as_str(),
            "workload_id": receipt.proof_pointer.workload_id.as_str(),
            "sample_count": receipt.proof_pointer.sample_count,
        },
        "bottlenecks": bottlenecks,
        "current_settings": settings_summary(receipt.current_settings),
        "candidate_settings": settings_summary(receipt.decision.settings),
        "selected_knobs": selected_knobs,
        "changes": changes,
    })
}

fn settings_summary(settings: AtpAutotuneSettings) -> Value {
    json!({
        "in_flight_bytes": settings.in_flight_bytes,
        "stream_count": settings.stream_count,
        "chunk_size_bytes": settings.chunk_size_bytes,
        "repair_symbols_per_second": settings.repair_symbols_per_second,
    })
}

fn telemetry_error_summary(error: AtpAutotuneTelemetryError) -> Value {
    match error {
        AtpAutotuneTelemetryError::MetricValueOutOfRange { metric, value, max } => json!({
            "error": "metric_value_out_of_range",
            "metric": metric.as_str(),
            "value": value,
            "max": max,
        }),
    }
}

fn assert_redaction_safe(value: &Value) {
    let text = serde_json::to_string(value).expect("receipt summary JSON");
    for forbidden in [
        "/home/",
        "/data/",
        "created_at",
        "hostname",
        "timestamp",
        "wall_clock",
    ] {
        assert!(
            !text.contains(forbidden),
            "golden receipt leaked nondeterministic or host-specific token {forbidden}",
        );
    }
}
