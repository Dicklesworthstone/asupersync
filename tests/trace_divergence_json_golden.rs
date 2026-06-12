#![allow(missing_docs)]

use asupersync::trace::{
    CompactTaskId, DiagnosticConfig, DivergenceError, ReplayEvent, ReplayTrace, TraceMetadata,
    diagnose_divergence, diagnose_replay_trace_divergence,
};
use serde_json::Value;

fn make_trace(seed: u64, events: Vec<ReplayEvent>) -> ReplayTrace {
    ReplayTrace {
        metadata: TraceMetadata::new(seed),
        events,
        cursor: 0,
    }
}

fn make_error(index: usize, expected: ReplayEvent, actual: ReplayEvent) -> DivergenceError {
    DivergenceError {
        index,
        expected: Some(expected),
        actual,
        context: String::new(),
    }
}

fn scrub_divergence_json(mut value: Value) -> Value {
    if let Some(seed) = value.get_mut("seed") {
        *seed = Value::String("[SEED]".to_string());
    }
    value
}

#[test]
fn divergence_report_json_scrubbed() {
    let trace = make_trace(
        0xBEEF,
        vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(2),
                outcome: 0,
            },
        ],
    );

    let error = make_error(
        1,
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 1,
        },
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(3),
            at_tick: 1,
        },
    );

    let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
    let json = report.to_json().expect("serialize report");
    let value: Value = serde_json::from_str(&json).expect("parse report json");
    insta::assert_json_snapshot!(
        "divergence_report_json_scrubbed",
        scrub_divergence_json(value)
    );
}

#[test]
fn full_trace_divergence_json_includes_actual_after_context() {
    let expected = make_trace(
        0xCAFE,
        vec![
            ReplayEvent::RngValue { value: 10 },
            ReplayEvent::RngValue { value: 11 },
            ReplayEvent::RngValue { value: 12 },
            ReplayEvent::RngValue { value: 13 },
        ],
    );
    let actual = make_trace(
        0xCAFE,
        vec![
            ReplayEvent::RngValue { value: 10 },
            ReplayEvent::RngValue { value: 99 },
            ReplayEvent::RngValue { value: 100 },
            ReplayEvent::RngValue { value: 101 },
        ],
    );
    let config = DiagnosticConfig {
        context_before: 1,
        context_after: 2,
        ..DiagnosticConfig::default()
    };

    let report = diagnose_replay_trace_divergence(&expected, &actual, &config)
        .expect("rng drift should produce divergence report");
    let json = report.to_json().expect("serialize report");
    let value: Value = serde_json::from_str(&json).expect("parse report json");

    let actual_after = value
        .get("context_after_actual")
        .and_then(Value::as_array)
        .expect("full-trace report must serialize actual post-divergence context");

    assert_eq!(actual_after.len(), 2);
    assert_eq!(actual_after[0]["event_type"], "RngValue");
    assert_eq!(actual_after[0]["index"], 2);
}
