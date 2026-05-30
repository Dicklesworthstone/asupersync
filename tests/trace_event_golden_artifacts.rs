//! Current trace-event golden contract tests.
//!
//! This file used to contain a permanently gated speculative schema draft.
//! It now exercises the real `TraceEvent`/`TraceData` serde surface and the
//! browser trace structured-log exporter that downstream replay tooling consumes.

use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::event::{
    BROWSER_TRACE_SCHEMA_VERSION, TRACE_EVENT_SCHEMA_VERSION, TraceData, TraceEvent,
    TraceEventKind, browser_trace_log_fields, browser_trace_schema_v1,
    validate_browser_trace_schema,
};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};

fn task_id(n: u32) -> TaskId {
    TaskId::new_for_test(n, 1)
}

fn region_id(n: u32) -> RegionId {
    RegionId::new_for_test(n, 1)
}

fn obligation_id(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 1)
}

fn time_ns(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn fixture_events() -> Vec<(&'static str, TraceEvent)> {
    vec![
        (
            "spawn",
            TraceEvent::spawn(1, time_ns(100), task_id(1), region_id(1)),
        ),
        (
            "cancel_request",
            TraceEvent::cancel_request(
                2,
                time_ns(200),
                task_id(1),
                region_id(1),
                CancelReason::user("trace-golden-cancel"),
            ),
        ),
        (
            "obligation_abort",
            TraceEvent::obligation_abort(
                3,
                time_ns(300),
                obligation_id(7),
                task_id(1),
                region_id(1),
                ObligationKind::SendPermit,
                42,
                ObligationAbortReason::Cancel,
            ),
        ),
        (
            "timer_scheduled",
            TraceEvent::timer_scheduled(4, time_ns(400), 99, time_ns(1_000)),
        ),
        (
            "worker_cancel_requested",
            TraceEvent::worker_cancel_requested(
                5,
                time_ns(500),
                "worker-alpha",
                11,
                12,
                13,
                task_id(2),
                region_id(2),
                obligation_id(8),
            ),
        ),
    ]
}

#[test]
fn trace_events_round_trip_through_current_json_schema() {
    for (expected_name, event) in fixture_events() {
        assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
        assert_eq!(event.kind.stable_name(), expected_name);

        let encoded = serde_json::to_value(&event).expect("trace event serializes");
        assert_eq!(encoded["version"], TRACE_EVENT_SCHEMA_VERSION);
        assert_eq!(encoded["seq"], event.seq);
        assert_eq!(encoded["kind"], expected_name);

        let decoded: TraceEvent =
            serde_json::from_value(encoded).expect("trace event json round-trips");
        assert_eq!(decoded, event);
    }
}

#[test]
fn trace_data_json_contains_expected_current_variant_names() {
    let variants = fixture_events()
        .into_iter()
        .map(|(name, event)| {
            let data = serde_json::to_value(&event.data).expect("trace data serializes");
            (
                name,
                data.as_object().expect("externally tagged enum").clone(),
            )
        })
        .collect::<Vec<_>>();

    assert!(variants.iter().any(|(_, data)| data.contains_key("Task")));
    assert!(variants.iter().any(|(_, data)| data.contains_key("Cancel")));
    assert!(
        variants
            .iter()
            .any(|(_, data)| data.contains_key("Obligation"))
    );
    assert!(variants.iter().any(|(_, data)| data.contains_key("Timer")));
    assert!(variants.iter().any(|(_, data)| data.contains_key("Worker")));
}

#[test]
fn browser_trace_schema_and_log_fields_match_current_event_taxonomy() {
    let schema = browser_trace_schema_v1();
    validate_browser_trace_schema(&schema).expect("browser trace schema validates");

    assert_eq!(schema.schema_version, BROWSER_TRACE_SCHEMA_VERSION);
    assert_eq!(schema.event_specs.len(), TraceEventKind::ALL.len());

    for kind in TraceEventKind::ALL {
        assert!(
            schema
                .event_specs
                .iter()
                .any(|spec| spec.event_kind == kind.stable_name()),
            "missing browser trace schema event kind {}",
            kind.stable_name()
        );
    }

    let worker_event = TraceEvent::worker_cancel_requested(
        9,
        time_ns(900),
        "worker-alpha",
        101,
        202,
        303,
        task_id(3),
        region_id(3),
        obligation_id(9),
    );
    let fields = browser_trace_log_fields(&worker_event, "trace-golden-v1", None);

    assert_eq!(fields["schema_version"], BROWSER_TRACE_SCHEMA_VERSION);
    assert_eq!(fields["trace_id"], "trace-golden-v1");
    assert_eq!(fields["event_kind"], "worker_cancel_requested");
    assert_eq!(fields["validation_status"], "valid");
    assert_eq!(fields["worker_id"], "<redacted>");
    assert_eq!(fields["job_id"], "101");
    assert_eq!(fields["decision_seq"], "202");
    assert_eq!(fields["replay_hash"], "303");
}

#[test]
fn trace_data_pattern_matching_uses_real_current_variants() {
    let (_, event) = fixture_events()
        .into_iter()
        .find(|(name, _)| *name == "obligation_abort")
        .expect("fixture includes obligation abort");

    match event.data {
        TraceData::Obligation {
            kind,
            duration_ns,
            abort_reason,
            ..
        } => {
            assert_eq!(kind, ObligationKind::SendPermit);
            assert_eq!(duration_ns, Some(42));
            assert_eq!(abort_reason, Some(ObligationAbortReason::Cancel));
        }
        other => panic!("expected current obligation trace data, got {other:?}"),
    }
}
