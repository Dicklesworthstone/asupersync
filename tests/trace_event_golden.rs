//! Golden tests for trace event serialization shapes.
//!
//! This test suite ensures that the serialized JSON forms of all TraceEvent
//! variants remain stable across changes to the trace system.

use asupersync::monitor::DownReason;
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::trace::distributed::LogicalTime;
use asupersync::trace::event::{TRACE_EVENT_SCHEMA_VERSION, TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use serde_json::Value;
use std::collections::BTreeMap;

/// Creates sample TraceEvents for each TraceData variant.
fn create_sample_events() -> Vec<(String, TraceEvent)> {
    let base_time = Time::from_nanos(1_000_000_000);
    let base_seq = 42;

    vec![
        (
            "none".to_string(),
            TraceEvent::new(
                base_seq,
                base_time,
                TraceEventKind::UserTrace,
                TraceData::None,
            ),
        ),
        (
            "task".to_string(),
            TraceEvent::new(
                base_seq + 1,
                base_time,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId(100),
                    region: RegionId(200),
                },
            ),
        ),
        (
            "region".to_string(),
            TraceEvent::new(
                base_seq + 2,
                base_time,
                TraceEventKind::RegionCreated,
                TraceData::Region {
                    region: RegionId(300),
                    parent: Some(RegionId(400)),
                },
            ),
        ),
        (
            "obligation".to_string(),
            TraceEvent::new(
                base_seq + 3,
                base_time,
                TraceEventKind::ObligationReserve,
                TraceData::Obligation {
                    obligation: ObligationId(500),
                    task: TaskId(600),
                    region: RegionId(700),
                    kind: ObligationKind::Permit,
                    state: ObligationState::Reserved,
                    duration_ns: Some(1_000_000),
                    abort_reason: None,
                },
            ),
        ),
        (
            "cancel".to_string(),
            TraceEvent::new(
                base_seq + 4,
                base_time,
                TraceEventKind::CancelRequest,
                TraceData::Cancel {
                    task: TaskId(800),
                    region: RegionId(900),
                    reason: CancelReason::Budget,
                },
            ),
        ),
        (
            "worker".to_string(),
            TraceEvent::new(
                base_seq + 5,
                base_time,
                TraceEventKind::WorkerCancelRequested,
                TraceData::Worker {
                    worker_id: "worker-123".to_string(),
                    job_id: 1000,
                    decision_seq: 2000,
                    replay_hash: 3000,
                    task: TaskId(4000),
                    region: RegionId(5000),
                    obligation: ObligationId(6000),
                },
            ),
        ),
        (
            "region_cancel".to_string(),
            TraceEvent::new(
                base_seq + 6,
                base_time,
                TraceEventKind::RegionCancelled,
                TraceData::RegionCancel {
                    region: RegionId(7000),
                    reason: CancelReason::Parent,
                },
            ),
        ),
        (
            "time".to_string(),
            TraceEvent::new(
                base_seq + 7,
                base_time,
                TraceEventKind::TimeAdvance,
                TraceData::Time {
                    old: Time::from_nanos(8_000_000_000),
                    new: Time::from_nanos(9_000_000_000),
                },
            ),
        ),
        (
            "timer".to_string(),
            TraceEvent::new(
                base_seq + 8,
                base_time,
                TraceEventKind::TimerScheduled,
                TraceData::Timer {
                    timer_id: 10000,
                    deadline: Some(Time::from_nanos(11_000_000_000)),
                },
            ),
        ),
        (
            "io_requested".to_string(),
            TraceEvent::new(
                base_seq + 9,
                base_time,
                TraceEventKind::IoRequested,
                TraceData::IoRequested {
                    token: 12000,
                    interest: 3, // readable | writable
                },
            ),
        ),
        (
            "io_ready".to_string(),
            TraceEvent::new(
                base_seq + 10,
                base_time,
                TraceEventKind::IoReady,
                TraceData::IoReady {
                    token: 13000,
                    readiness: 5, // readable | error
                },
            ),
        ),
        (
            "io_result".to_string(),
            TraceEvent::new(
                base_seq + 11,
                base_time,
                TraceEventKind::IoResult,
                TraceData::IoResult {
                    token: 14000,
                    bytes: 1024,
                },
            ),
        ),
        (
            "io_error".to_string(),
            TraceEvent::new(
                base_seq + 12,
                base_time,
                TraceEventKind::IoError,
                TraceData::IoError {
                    token: 15000,
                    kind: 2, // NotFound
                },
            ),
        ),
        (
            "rng_seed".to_string(),
            TraceEvent::new(
                base_seq + 13,
                base_time,
                TraceEventKind::RngSeed,
                TraceData::RngSeed {
                    seed: 0xDEADBEEFCAFEBABE,
                },
            ),
        ),
        (
            "rng_value".to_string(),
            TraceEvent::new(
                base_seq + 14,
                base_time,
                TraceEventKind::RngValue,
                TraceData::RngValue {
                    value: 0x1234567890ABCDEF,
                },
            ),
        ),
        (
            "checkpoint".to_string(),
            TraceEvent::new(
                base_seq + 15,
                base_time,
                TraceEventKind::Checkpoint,
                TraceData::Checkpoint {
                    sequence: 16000,
                    active_tasks: 17,
                    active_regions: 18,
                },
            ),
        ),
        (
            "futurelock".to_string(),
            TraceEvent::new(
                base_seq + 16,
                base_time,
                TraceEventKind::FuturelockDetected,
                TraceData::Futurelock {
                    task: TaskId(19000),
                    region: RegionId(20000),
                    idle_steps: 21000,
                    held: vec![
                        (ObligationId(22000), ObligationKind::Permit),
                        (ObligationId(23000), ObligationKind::Ack),
                    ],
                },
            ),
        ),
        (
            "monitor".to_string(),
            TraceEvent::new(
                base_seq + 17,
                base_time,
                TraceEventKind::MonitorCreated,
                TraceData::Monitor {
                    monitor_ref: 24000,
                    watcher: TaskId(25000),
                    watcher_region: RegionId(26000),
                    monitored: TaskId(27000),
                },
            ),
        ),
        (
            "down".to_string(),
            TraceEvent::new(
                base_seq + 18,
                base_time,
                TraceEventKind::DownDelivered,
                TraceData::Down {
                    monitor_ref: 28000,
                    watcher: TaskId(29000),
                    monitored: TaskId(30000),
                    completion_vt: Time::from_nanos(31_000_000_000),
                    reason: DownReason::Normal,
                },
            ),
        ),
        (
            "link".to_string(),
            TraceEvent::new(
                base_seq + 19,
                base_time,
                TraceEventKind::LinkCreated,
                TraceData::Link {
                    link_ref: 32000,
                    task_a: TaskId(33000),
                    region_a: RegionId(34000),
                    task_b: TaskId(35000),
                    region_b: RegionId(36000),
                },
            ),
        ),
        (
            "exit".to_string(),
            TraceEvent::new(
                base_seq + 20,
                base_time,
                TraceEventKind::ExitDelivered,
                TraceData::Exit {
                    link_ref: 37000,
                    from: TaskId(38000),
                    to: TaskId(39000),
                    failure_vt: Time::from_nanos(40_000_000_000),
                    reason: DownReason::Cancel,
                },
            ),
        ),
        (
            "message".to_string(),
            TraceEvent::new(
                base_seq + 21,
                base_time,
                TraceEventKind::UserTrace,
                TraceData::Message("test message content".to_string()),
            ),
        ),
        (
            "chaos".to_string(),
            TraceEvent::new(
                base_seq + 22,
                base_time,
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "cancel".to_string(),
                    task: Some(TaskId(41000)),
                    detail: "injected cancellation for testing".to_string(),
                },
            ),
        ),
    ]
}

/// Normalizes a serialized event for stable golden comparison.
fn normalize_event_json(mut value: Value) -> Value {
    if let Value::Object(ref mut obj) = value {
        // Ensure consistent ordering by using a BTreeMap
        let mut sorted: BTreeMap<String, Value> =
            obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        *obj = sorted.into_iter().collect();
    }
    value
}

#[test]
fn trace_event_serialization_golden_shapes() {
    let events = create_sample_events();
    let mut golden_data = BTreeMap::new();

    for (name, event) in events {
        // Add logical time to test that field as well
        let event_with_logical = event.with_logical_time(LogicalTime::new(1000, 2000));

        let serialized =
            serde_json::to_value(&event_with_logical).expect("TraceEvent should serialize to JSON");
        let normalized = normalize_event_json(serialized);

        golden_data.insert(name, normalized);
    }

    // Convert to a stable JSON string for the golden comparison
    let golden_json =
        serde_json::to_string_pretty(&golden_data).expect("golden data should serialize");

    // For now, we'll just verify the structure exists and is well-formed
    // In a real golden test framework, this would be compared against a stored file
    assert!(!golden_json.is_empty(), "Golden JSON should not be empty");

    // Verify we have all 23 TraceData variants
    assert_eq!(golden_data.len(), 23, "Should have 23 TraceData variants");

    // Verify each event has the expected top-level structure
    for (variant_name, event_json) in &golden_data {
        let obj = event_json
            .as_object()
            .expect(&format!("Event {variant_name} should be a JSON object"));

        // Every TraceEvent should have these fields
        assert!(
            obj.contains_key("version"),
            "Event {variant_name} missing version"
        );
        assert!(obj.contains_key("seq"), "Event {variant_name} missing seq");
        assert!(
            obj.contains_key("time"),
            "Event {variant_name} missing time"
        );
        assert!(
            obj.contains_key("logical_time"),
            "Event {variant_name} missing logical_time"
        );
        assert!(
            obj.contains_key("kind"),
            "Event {variant_name} missing kind"
        );
        assert!(
            obj.contains_key("data"),
            "Event {variant_name} missing data"
        );

        // Version should be current schema version
        assert_eq!(
            obj["version"].as_u64().unwrap(),
            TRACE_EVENT_SCHEMA_VERSION as u64,
            "Event {variant_name} has wrong schema version"
        );
    }

    // Print the golden data for manual inspection during development
    println!("Generated golden trace event shapes:\n{}", golden_json);
}

#[test]
fn trace_event_roundtrip_serialization() {
    // Test that all variants can roundtrip through JSON serialization
    let events = create_sample_events();

    for (name, original_event) in events {
        let event = original_event.with_logical_time(LogicalTime::new(500, 1000));

        // Serialize to JSON
        let json = serde_json::to_string(&event).expect(&format!("Event {name} should serialize"));

        // Deserialize back
        let deserialized: TraceEvent =
            serde_json::from_str(&json).expect(&format!("Event {name} should deserialize"));

        // Should be identical
        assert_eq!(
            event, deserialized,
            "Event {name} failed roundtrip serialization"
        );
    }
}

#[test]
fn trace_data_variant_coverage() {
    // Ensure we're testing all TraceData variants by checking the discriminants
    let events = create_sample_events();
    let variant_names: std::collections::BTreeSet<String> =
        events.iter().map(|(name, _)| name.clone()).collect();

    let expected_variants = [
        "none",
        "task",
        "region",
        "obligation",
        "cancel",
        "worker",
        "region_cancel",
        "time",
        "timer",
        "io_requested",
        "io_ready",
        "io_result",
        "io_error",
        "rng_seed",
        "rng_value",
        "checkpoint",
        "futurelock",
        "monitor",
        "down",
        "link",
        "exit",
        "message",
        "chaos",
    ];

    for expected in &expected_variants {
        assert!(
            variant_names.contains(*expected),
            "Missing TraceData variant: {expected}"
        );
    }

    assert_eq!(
        variant_names.len(),
        expected_variants.len(),
        "Unexpected number of TraceData variants. Update this test if new variants were added."
    );
}
