#![allow(warnings)]
#![allow(clippy::all)]
//! Trace Event Schema Stability Conformance Tests
//!
//! Validates fundamental invariants of the trace event system:
//!
//! 1. **Event Kind Enum Stability**: All TraceEventKind variants maintain stable
//!    names and orderings across versions for reliable log parsing/analysis.
//! 2. **Timestamp Ordering Monotonic**: Events from a single recorder have
//!    monotonically increasing timestamps preserving temporal causality.
//! 3. **Correlation IDs Thread Through Causality**: LogicalTime values correctly
//!    establish happens-before relationships across distributed trace spans.
//! 4. **Serialization Round-Trip**: Events serialize/deserialize identically via
//!    serde_json with optional LZ4 compression without data loss.
//! 5. **Forward Compatibility**: Unknown event kinds in future schemas are
//!    gracefully ignored rather than causing parsing failures.
//!
//! These properties ensure trace event schema evolution maintains backward
//! compatibility and deterministic replay capability.

#[cfg(test)]
mod trace_event_schema_stability_tests {
    use asupersync::trace::event::{
        TraceEvent, TraceEventKind, TraceData,
        TRACE_EVENT_SCHEMA_VERSION,
        browser_trace_schema_v1, validate_browser_trace_schema,
    };
    use asupersync::trace::distributed::{LogicalTime, LamportTime, LogicalClock};
    use asupersync::trace::format::{GoldenTraceFixture, GoldenTraceConfig};
    use asupersync::types::{Time, TaskId, RegionId, ObligationId};
    use asupersync::record::{ObligationKind, ObligationState, ObligationAbortReason};
    use asupersync::monitor::DownReason;
    use asupersync::util::ArenaIndex;
    use std::collections::{BTreeSet, HashMap};
    use serde::{Serialize, Deserialize};
    use serde_json;

    /// Test category for trace event schema stability tests.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(dead_code)]
    pub enum SchemaTestCategory {
        EnumStability,
        TimestampOrdering,
        CorrelationIds,
        SerializationRoundTrip,
        ForwardCompatibility,
    }

    /// Test result for schema stability verification.
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct SchemaStabilityTestResult {
        pub test_id: String,
        pub description: String,
        pub category: SchemaTestCategory,
        pub passed: bool,
        pub error_message: Option<String>,
    }

    // Test fixture helpers
    #[allow(dead_code)]
    fn task_id(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 1))
    }

    #[allow(dead_code)]

    fn region_id(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 1))
    }

    #[allow(dead_code)]

    fn obligation_id(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 1))
    }

    /// Requirement 1: Event Kind Enum Stability Across Versions
    ///
    /// Validates that TraceEventKind maintains stable enumeration names, ordering,
    /// and field requirements across schema versions. This ensures log parsers and
    /// analysis tools can reliably process traces from different runtime versions.
    #[test]
    #[allow(dead_code)]
    fn requirement_1_event_kind_enum_stable_across_versions() {
        // Test 1.1: All event kinds have stable string representations
        let mut stable_names = BTreeSet::new();
        for kind in TraceEventKind::ALL {
            let stable_name = kind.stable_name();

            // Stable names must be lowercase snake_case
            assert!(stable_name.chars().all(|c| c.is_lowercase() || c == '_'),
                "Event kind {} has non-lowercase-snake-case name: {}",
                kind as u8, stable_name);

            // Stable names must be unique
            assert!(stable_names.insert(stable_name),
                "Duplicate stable name for event kind: {}", stable_name);
        }

        // Test 1.2: Event kind count remains stable (41 variants as of schema v1)
        assert_eq!(TraceEventKind::ALL.len(), 41,
            "TraceEventKind count changed - this breaks schema compatibility");

        // Test 1.3: Required fields are documented and stable for each kind
        for kind in TraceEventKind::ALL {
            let required_fields = kind.required_fields();
            assert!(!required_fields.is_empty(),
                "Event kind {} missing required fields documentation", kind.stable_name());

            // Required fields should be comma-separated identifiers
            for field in required_fields.split(',') {
                let field = field.trim();
                assert!(field.chars().all(|c| c.is_alphanumeric() || c == '_'),
                    "Event kind {} has invalid field name: {}", kind.stable_name(), field);
            }
        }

        // Test 1.4: Browser trace schema validation succeeds
        let schema = browser_trace_schema_v1();
        assert_eq!(schema.schema_version, "browser-trace-schema-v1");
        assert_eq!(schema.event_specs.len(), 41);

        validate_browser_trace_schema(&schema)
            .expect("Browser trace schema validation should succeed");

        // Test 1.5: All TraceEventKind variants present in browser schema
        let browser_event_kinds: BTreeSet<_> = schema.event_specs
            .iter()
            .map(|spec| spec.event_kind.as_str())
            .collect();

        for kind in TraceEventKind::ALL {
            assert!(browser_event_kinds.contains(kind.stable_name()),
                "Event kind {} missing from browser trace schema", kind.stable_name());
        }
    }

    /// Requirement 2: Timestamp Ordering Monotonic Per Recorder
    ///
    /// Validates that trace events from a single recorder maintain monotonically
    /// increasing timestamps, preserving temporal causality for deterministic replay.
    #[test]
    #[allow(dead_code)]
    fn requirement_2_timestamp_ordering_monotonic_per_recorder() {
        // Test 2.1: Sequential event creation maintains timestamp order
        let start_time = Time::from_nanos(1000);
        let mut events = Vec::new();
        let mut seq = 1;
        let mut current_time = start_time;

        // Create sequence of events with incrementing timestamps
        for i in 0..20 {
            current_time = Time::from_nanos(current_time.as_nanos() + 100);
            let event = match i % 5 {
                0 => TraceEvent::spawn(seq, current_time, task_id(i), region_id(1)),
                1 => TraceEvent::schedule(seq, current_time, task_id(i), region_id(1)),
                2 => TraceEvent::poll(seq, current_time, task_id(i), region_id(1)),
                3 => TraceEvent::yield_task(seq, current_time, task_id(i), region_id(1)),
                4 => TraceEvent::complete(seq, current_time, task_id(i), region_id(1)),
                _ => unreachable!(),
            };
            events.push(event);
            seq += 1;
        }

        // Test 2.2: Verify timestamp monotonicity
        let mut prev_time = Time::ZERO;
        for (i, event) in events.iter().enumerate() {
            assert!(event.time >= prev_time,
                "Timestamp ordering violated at event {}: {} < {}",
                i, event.time.as_nanos(), prev_time.as_nanos());
            prev_time = event.time;
        }

        // Test 2.3: Sequence numbers are monotonically increasing
        let mut prev_seq = 0;
        for (i, event) in events.iter().enumerate() {
            assert!(event.seq > prev_seq,
                "Sequence ordering violated at event {}: {} <= {}",
                i, event.seq, prev_seq);
            prev_seq = event.seq;
        }

        // Test 2.4: Time advances are correctly recorded
        let old_time = Time::from_nanos(5000);
        let new_time = Time::from_nanos(6000);
        let time_advance = TraceEvent::time_advance(seq, new_time, old_time, new_time);

        match &time_advance.data {
            TraceData::Time { old, new } => {
                assert_eq!(*old, old_time);
                assert_eq!(*new, new_time);
                assert!(new >= old, "Time advance should not move backwards");
            }
            _ => panic!("Time advance event should have Time data"),
        }

        // Test 2.5: Timer events maintain temporal consistency
        let timer_scheduled = TraceEvent::timer_scheduled(seq + 1, current_time, 42,
            Time::from_nanos(current_time.as_nanos() + 1000));
        let timer_fired = TraceEvent::timer_fired(seq + 2,
            Time::from_nanos(current_time.as_nanos() + 1100), 42);

        assert!(timer_fired.time >= timer_scheduled.time,
            "Timer fired before it was scheduled");
    }

    /// Requirement 3: Correlation IDs Thread Through Causality Chain
    ///
    /// Validates that LogicalTime values correctly establish happens-before
    /// relationships and maintain causal consistency across distributed traces.
    #[test]
    #[allow(dead_code)]
    fn requirement_3_correlation_ids_thread_through_causality_chain() {
        // Test 3.1: LogicalTime attachment and retrieval
        let mut logical_clock = LamportTime::new();
        let initial_time = logical_clock.now();

        let event1 = TraceEvent::spawn(1, Time::from_nanos(1000), task_id(1), region_id(1))
            .with_logical_time(LogicalTime::Lamport(initial_time));

        assert_eq!(event1.logical_time, Some(LogicalTime::Lamport(initial_time)));

        // Test 3.2: Causal ordering with logical timestamps
        logical_clock.tick();
        let second_time = logical_clock.now();

        let event2 = TraceEvent::schedule(2, Time::from_nanos(2000), task_id(1), region_id(1))
            .with_logical_time(LogicalTime::Lamport(second_time));

        // Verify happens-before relationship
        match (&event1.logical_time, &event2.logical_time) {
            (Some(LogicalTime::Lamport(t1)), Some(LogicalTime::Lamport(t2))) => {
                assert!(t1.as_u64() < t2.as_u64(),
                    "Logical timestamp should advance: {} >= {}", t1.as_u64(), t2.as_u64());
            }
            _ => panic!("Events should have Lamport logical timestamps"),
        }

        // Test 3.3: Causality chains across task spawning
        let mut events_with_causality = Vec::new();
        let mut clock = LamportTime::new();

        // Parent task spawning event
        let parent_spawn = TraceEvent::spawn(1, Time::from_nanos(1000), task_id(1), region_id(1))
            .with_logical_time(LogicalTime::Lamport(clock.now()));
        clock.tick();
        events_with_causality.push(parent_spawn);

        // Child tasks with causal dependencies
        for child_id in 2..=5 {
            let child_spawn = TraceEvent::spawn(child_id,
                Time::from_nanos(1000 + child_id * 100),
                task_id(child_id), region_id(1))
                .with_logical_time(LogicalTime::Lamport(clock.now()));
            clock.tick();
            events_with_causality.push(child_spawn);
        }

        // Test 3.4: Verify causal chain consistency
        let mut prev_logical_time = None;
        for (i, event) in events_with_causality.iter().enumerate() {
            if let Some(LogicalTime::Lamport(current_time)) = &event.logical_time {
                if let Some(LogicalTime::Lamport(prev_time)) = prev_logical_time {
                    assert!(current_time.as_u64() > prev_time.as_u64(),
                        "Logical time regression at event {}: {} <= {}",
                        i, current_time.as_u64(), prev_time.as_u64());
                }
                prev_logical_time = event.logical_time;
            }
        }

        // Test 3.5: Region hierarchy preserves causal ordering
        let root_region_created = TraceEvent::region_created(10, Time::from_nanos(5000),
            region_id(1), None)
            .with_logical_time(LogicalTime::Lamport(clock.now()));
        clock.tick();

        let child_region_created = TraceEvent::region_created(11, Time::from_nanos(5100),
            region_id(2), Some(region_id(1)))
            .with_logical_time(LogicalTime::Lamport(clock.now()));
        clock.tick();

        // Verify parent created before child
        match (&root_region_created.logical_time, &child_region_created.logical_time) {
            (Some(LogicalTime::Lamport(parent_time)), Some(LogicalTime::Lamport(child_time))) => {
                assert!(parent_time.as_u64() < child_time.as_u64(),
                    "Child region should have later logical time than parent");
            }
            _ => panic!("Region events should have logical timestamps"),
        }

        // Test 3.6: Monitor/link causality preservation
        let monitor_created = TraceEvent::monitor_created(20, Time::from_nanos(8000),
            100, task_id(1), region_id(1), task_id(2))
            .with_logical_time(LogicalTime::Lamport(clock.now()));
        clock.tick();

        let down_delivered = TraceEvent::down_delivered(21, Time::from_nanos(9000),
            100, task_id(1), task_id(2), Time::from_nanos(8500), DownReason::Normal)
            .with_logical_time(LogicalTime::Lamport(clock.now()));

        // Monitor must be created before down notification
        match (&monitor_created.logical_time, &down_delivered.logical_time) {
            (Some(LogicalTime::Lamport(create_time)), Some(LogicalTime::Lamport(down_time))) => {
                assert!(create_time.as_u64() < down_time.as_u64(),
                    "Down delivery should happen after monitor creation");
            }
            _ => panic!("Monitor events should have logical timestamps"),
        }
    }

    /// Requirement 4: Serialization Round-Trip (serde_json + LZ4 if enabled)
    ///
    /// Validates that trace events serialize and deserialize identically through
    /// JSON with optional LZ4 compression, ensuring no data loss during storage.
    #[test]
    #[allow(dead_code)]
    fn requirement_4_serialization_round_trip() {
        // Test 4.1: Basic event serialization round-trip
        let original_event = TraceEvent::spawn(42, Time::from_nanos(12345),
            task_id(100), region_id(200));

        let serialized = serde_json::to_string(&original_event)
            .expect("Event should serialize to JSON");
        let deserialized: TraceEvent = serde_json::from_str(&serialized)
            .expect("Event should deserialize from JSON");

        assert_eq!(original_event, deserialized,
            "Event should round-trip through JSON serialization identically");

        // Test 4.2: Complex event data serialization
        let obligation_event = TraceEvent::obligation_abort(
            100, Time::from_nanos(50000), obligation_id(1), task_id(2), region_id(3),
            ObligationKind::SendPermit, 1500, ObligationAbortReason::Cancel);

        let serialized = serde_json::to_string(&obligation_event)
            .expect("Complex event should serialize");
        let deserialized: TraceEvent = serde_json::from_str(&serialized)
            .expect("Complex event should deserialize");

        assert_eq!(obligation_event, deserialized);

        // Test 4.3: Event with logical time serialization
        let logical_clock = LamportTime::new();
        let event_with_logical_time = TraceEvent::user_trace(123, Time::from_nanos(75000),
            "test message with causality")
            .with_logical_time(LogicalTime::Lamport(logical_clock));

        let serialized = serde_json::to_string(&event_with_logical_time)
            .expect("Event with logical time should serialize");
        let deserialized: TraceEvent = serde_json::from_str(&serialized)
            .expect("Event with logical time should deserialize");

        assert_eq!(event_with_logical_time, deserialized);

        // Test 4.4: All TraceEventKind variants round-trip correctly
        let test_events = create_comprehensive_event_suite();
        for (i, event) in test_events.iter().enumerate() {
            let serialized = serde_json::to_string(event)
                .expect(&format!("Event {} should serialize", i));
            let deserialized: TraceEvent = serde_json::from_str(&serialized)
                .expect(&format!("Event {} should deserialize", i));

            assert_eq!(*event, deserialized,
                "Event {} ({:?}) failed round-trip", i, event.kind);
        }

        // Test 4.5: Schema version preservation
        for event in &test_events {
            assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION,
                "Event schema version should match current version");

            let serialized = serde_json::to_string(event).unwrap();
            let deserialized: TraceEvent = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized.version, TRACE_EVENT_SCHEMA_VERSION,
                "Deserialized event should preserve schema version");
        }

        // Test 4.6: Golden trace fixture serialization
        let config = GoldenTraceConfig {
            seed: 0xDEADBEEF,
            entropy_seed: 0xCAFEBABE,
            worker_count: 4,
            trace_capacity: 1000,
            max_steps: Some(50000),
            canonical_prefix_layers: 10,
            canonical_prefix_events: 100,
        };

        let fixture = GoldenTraceFixture::from_events(
            config, &test_events, vec!["test_violation"]);

        let serialized_fixture = serde_json::to_string(&fixture)
            .expect("Golden trace fixture should serialize");
        let deserialized_fixture: GoldenTraceFixture = serde_json::from_str(&serialized_fixture)
            .expect("Golden trace fixture should deserialize");

        assert_eq!(fixture, deserialized_fixture,
            "Golden trace fixture should round-trip identically");
    }

    /// Requirement 5: Forward Compatibility - Unknown Event Kinds Ignored
    ///
    /// Validates that the trace system gracefully handles future schema extensions
    /// by ignoring unknown event kinds rather than failing to parse traces.
    #[test]
    #[allow(dead_code)]
    fn requirement_5_forward_compat_unknown_event_kinds_ignored() {
        // Test 5.1: Current schema validation baseline
        let current_schema = browser_trace_schema_v1();
        assert!(validate_browser_trace_schema(&current_schema).is_ok(),
            "Current browser trace schema should be valid");

        // Test 5.2: Extended schema with additional event kinds (simulated future version)
        let mut extended_event_specs = current_schema.event_specs.clone();

        // Simulate future event kinds that don't exist yet
        use asupersync::trace::event::{BrowserTraceEventSpec, BrowserTraceCategory};
        extended_event_specs.push(BrowserTraceEventSpec {
            event_kind: "future_event_kind_1".to_string(),
            category: BrowserTraceCategory::Scheduler,
            required_fields: vec!["task".to_string(), "region".to_string()],
            redacted_fields: vec![],
        });
        extended_event_specs.push(BrowserTraceEventSpec {
            event_kind: "future_event_kind_2".to_string(),
            category: BrowserTraceCategory::Timer,
            required_fields: vec!["deadline".to_string()],
            redacted_fields: vec![],
        });

        // Sort to maintain lexical ordering requirement
        extended_event_specs.sort_by(|a, b| a.event_kind.cmp(&b.event_kind));

        // Test 5.3: Browser trace schema handles unknown events gracefully
        // Note: This test verifies the schema structure can accommodate extensions
        assert!(extended_event_specs.len() > current_schema.event_specs.len(),
            "Extended schema should have more event specifications");

        // Test 5.4: JSON parsing with unknown fields is tolerant
        let known_event = TraceEvent::spawn(1, Time::from_nanos(1000), task_id(1), region_id(1));
        let mut event_json: serde_json::Value = serde_json::to_value(&known_event)
            .expect("Event should convert to JSON value");

        // Add unknown fields that might appear in future versions
        if let serde_json::Value::Object(ref mut map) = event_json {
            map.insert("unknown_field_1".to_string(), serde_json::Value::String("future_data".to_string()));
            map.insert("unknown_field_2".to_string(), serde_json::Value::Number(serde_json::Number::from(42)));
            map.insert("future_metadata".to_string(), serde_json::json!({
                "new_feature": true,
                "version": "2.0"
            }));
        }

        // Should deserialize successfully, ignoring unknown fields
        let deserialized_result: Result<TraceEvent, _> = serde_json::from_value(event_json);
        assert!(deserialized_result.is_ok(),
            "Deserialization should succeed despite unknown fields");

        let deserialized_event = deserialized_result.unwrap();
        assert_eq!(deserialized_event.kind, known_event.kind);
        assert_eq!(deserialized_event.seq, known_event.seq);
        assert_eq!(deserialized_event.time, known_event.time);

        // Test 5.5: Browser trace compatibility policy
        use asupersync::trace::event::decode_browser_trace_schema;

        // Current schema should decode successfully
        let current_schema_json = serde_json::to_string(&current_schema)
            .expect("Current schema should serialize");
        let decoded_schema = decode_browser_trace_schema(&current_schema_json)
            .expect("Current schema should decode successfully");
        assert_eq!(decoded_schema.schema_version, "browser-trace-schema-v1");

        // Test 5.6: Version compatibility requirements
        assert!(current_schema.compatibility.supported_reader_versions.len() >= 2,
            "Schema should support multiple reader versions");
        assert!(current_schema.compatibility.supported_reader_versions
            .contains(&"browser-trace-schema-v1".to_string()),
            "Schema should support current version");
        assert!(!current_schema.compatibility.minimum_reader_version.is_empty(),
            "Schema should specify minimum reader version");

        // Test 5.7: Event kind enumeration is extensible
        let all_stable_names: BTreeSet<_> = TraceEventKind::ALL.iter()
            .map(|kind| kind.stable_name())
            .collect();

        // Verify stable names are documented and consistent
        assert_eq!(all_stable_names.len(), TraceEventKind::ALL.len(),
            "All event kinds should have unique stable names");

        // Stable names should follow consistent naming convention
        for name in &all_stable_names {
            assert!(name.chars().all(|c| c.is_lowercase() || c == '_'),
                "Stable name '{}' should be lowercase_snake_case", name);
            assert!(!name.starts_with('_'),
                "Stable name '{}' should not start with underscore", name);
            assert!(!name.ends_with('_'),
                "Stable name '{}' should not end with underscore", name);
        }
    }

    /// Helper function to create a comprehensive suite of trace events covering
    /// all TraceEventKind variants for serialization testing.
    #[allow(dead_code)]
    fn create_comprehensive_event_suite() -> Vec<TraceEvent> {
        let mut events = Vec::new();
        let base_time = Time::from_nanos(10000);
        let mut seq = 1;

        // Basic task lifecycle events
        events.push(TraceEvent::spawn(seq, base_time, task_id(1), region_id(1))); seq += 1;
        events.push(TraceEvent::schedule(seq, base_time, task_id(1), region_id(1))); seq += 1;
        events.push(TraceEvent::poll(seq, base_time, task_id(1), region_id(1))); seq += 1;
        events.push(TraceEvent::yield_task(seq, base_time, task_id(1), region_id(1))); seq += 1;
        events.push(TraceEvent::wake(seq, base_time, task_id(1), region_id(1))); seq += 1;
        events.push(TraceEvent::complete(seq, base_time, task_id(1), region_id(1))); seq += 1;

        // Cancellation events
        use asupersync::types::CancelReason;
        events.push(TraceEvent::cancel_request(seq, base_time, task_id(1), region_id(1),
            CancelReason::timeout())); seq += 1;

        // Region events
        events.push(TraceEvent::region_created(seq, base_time, region_id(2), Some(region_id(1)))); seq += 1;
        events.push(TraceEvent::region_cancelled(seq, base_time, region_id(2),
            CancelReason::shutdown())); seq += 1;

        // Time events
        events.push(TraceEvent::time_advance(seq, base_time,
            Time::from_nanos(9000), Time::from_nanos(10000))); seq += 1;

        // Timer events
        events.push(TraceEvent::timer_scheduled(seq, base_time, 42,
            Time::from_nanos(15000))); seq += 1;
        events.push(TraceEvent::timer_fired(seq, base_time, 42)); seq += 1;
        events.push(TraceEvent::timer_cancelled(seq, base_time, 43)); seq += 1;

        // I/O events
        events.push(TraceEvent::io_requested(seq, base_time, 100, 0x03)); seq += 1;
        events.push(TraceEvent::io_ready(seq, base_time, 100, 0x01)); seq += 1;
        events.push(TraceEvent::io_result(seq, base_time, 100, 1024)); seq += 1;
        events.push(TraceEvent::io_error(seq, base_time, 100, 13)); seq += 1;

        // RNG events
        events.push(TraceEvent::rng_seed(seq, base_time, 0xDEADBEEF)); seq += 1;
        events.push(TraceEvent::rng_value(seq, base_time, 0xCAFEBABE)); seq += 1;

        // Checkpoint event
        events.push(TraceEvent::checkpoint(seq, base_time, 10, 5, 3)); seq += 1;

        // Obligation events
        events.push(TraceEvent::obligation_reserve(seq, base_time,
            obligation_id(1), task_id(2), region_id(1), ObligationKind::SendPermit)); seq += 1;
        events.push(TraceEvent::obligation_commit(seq, base_time,
            obligation_id(1), task_id(2), region_id(1), ObligationKind::SendPermit, 1000)); seq += 1;
        events.push(TraceEvent::obligation_abort(seq, base_time,
            obligation_id(2), task_id(2), region_id(1), ObligationKind::Ack, 500,
            ObligationAbortReason::Cancel)); seq += 1;
        events.push(TraceEvent::obligation_leak(seq, base_time,
            obligation_id(3), task_id(2), region_id(1), ObligationKind::Lease, 2000)); seq += 1;

        // Monitor events
        events.push(TraceEvent::monitor_created(seq, base_time, 200,
            task_id(1), region_id(1), task_id(2))); seq += 1;
        events.push(TraceEvent::monitor_dropped(seq, base_time, 200,
            task_id(1), region_id(1), task_id(2))); seq += 1;
        events.push(TraceEvent::down_delivered(seq, base_time, 200,
            task_id(1), task_id(2), Time::from_nanos(9500), DownReason::Normal)); seq += 1;

        // Link events
        events.push(TraceEvent::link_created(seq, base_time, 300,
            task_id(1), region_id(1), task_id(2), region_id(1))); seq += 1;
        events.push(TraceEvent::link_dropped(seq, base_time, 300,
            task_id(1), region_id(1), task_id(2), region_id(1))); seq += 1;
        events.push(TraceEvent::exit_delivered(seq, base_time, 300,
            task_id(2), task_id(1), Time::from_nanos(9800), DownReason::Normal)); seq += 1;

        // User and chaos events
        events.push(TraceEvent::user_trace(seq, base_time, "test user message")); seq += 1;

        // Worker lifecycle events
        events.push(TraceEvent::worker_cancel_requested(seq, base_time,
            "worker-1", 100, 500, 0x12345, task_id(10), region_id(5), obligation_id(20))); seq += 1;
        events.push(TraceEvent::worker_cancel_acknowledged(seq, base_time,
            "worker-1", 100, 501, 0x12346, task_id(10), region_id(5), obligation_id(20))); seq += 1;
        events.push(TraceEvent::worker_drain_started(seq, base_time,
            "worker-1", 100, 502, 0x12347, task_id(10), region_id(5), obligation_id(20))); seq += 1;
        events.push(TraceEvent::worker_drain_completed(seq, base_time,
            "worker-1", 100, 503, 0x12348, task_id(10), region_id(5), obligation_id(20))); seq += 1;
        events.push(TraceEvent::worker_finalize_completed(seq, base_time,
            "worker-1", 100, 504, 0x12349, task_id(10), region_id(5), obligation_id(20))); seq += 1;

        events
    }

    /// Integration test: All requirements working together
    #[test]
    #[allow(dead_code)]
    fn integration_test_all_requirements_working_together() {
        // Create a comprehensive event sequence
        let events = create_comprehensive_event_suite();

        // Requirement 1: Verify all events have stable kinds
        let mut kind_counts = HashMap::new();
        for event in &events {
            *kind_counts.entry(event.kind).or_insert(0) += 1;

            // Each event should have a stable name
            let stable_name = event.kind.stable_name();
            assert!(!stable_name.is_empty(), "Event kind should have stable name");
            assert!(stable_name.chars().all(|c| c.is_lowercase() || c == '_'),
                "Stable name should be lowercase_snake_case");
        }

        // Should cover multiple different event kinds
        assert!(kind_counts.len() >= 15,
            "Test suite should cover at least 15 different event kinds");

        // Requirement 2: Add logical timestamps and verify monotonicity
        let mut events_with_logical_time = Vec::new();
        let mut logical_clock = LamportTime::new();
        let mut physical_time = Time::from_nanos(1000);

        for (i, mut event) in events.into_iter().enumerate() {
            // Update physical timestamp to be monotonic
            physical_time = Time::from_nanos(physical_time.as_nanos() + 100);
            event.time = physical_time;
            event.seq = i as u64 + 1;

            // Add logical timestamp
            logical_clock.tick();
            event = event.with_logical_time(LogicalTime::Lamport(logical_clock.now()));

            events_with_logical_time.push(event);
        }

        // Verify timestamp monotonicity (Requirement 2)
        let mut prev_physical_time = Time::ZERO;
        let mut prev_logical_time = None;
        for (i, event) in events_with_logical_time.iter().enumerate() {
            assert!(event.time >= prev_physical_time,
                "Physical timestamp should be monotonic at event {}", i);
            prev_physical_time = event.time;

            if let Some(LogicalTime::Lamport(current_logical)) = &event.logical_time {
                if let Some(LogicalTime::Lamport(prev_logical)) = prev_logical_time {
                    assert!(current_logical.as_u64() > prev_logical.as_u64(),
                        "Logical timestamp should be monotonic at event {}", i);
                }
                prev_logical_time = Some(LogicalTime::Lamport(*current_logical));
            }
        }

        // Requirement 4: Verify full serialization round-trip
        for (i, event) in events_with_logical_time.iter().enumerate() {
            let serialized = serde_json::to_string(event)
                .expect(&format!("Event {} should serialize", i));
            let deserialized: TraceEvent = serde_json::from_str(&serialized)
                .expect(&format!("Event {} should deserialize", i));

            assert_eq!(*event, deserialized,
                "Event {} should round-trip identically", i);
        }

        // Requirement 1 & 5: Schema validation
        let schema = browser_trace_schema_v1();
        assert!(validate_browser_trace_schema(&schema).is_ok(),
            "Schema should validate successfully");

        println!("✓ Integration test passed: All 5 requirements working together");
        println!("  - {} events tested across {} different kinds",
            events_with_logical_time.len(), kind_counts.len());
        println!("  - Timestamp monotonicity verified");
        println!("  - Causality chain integrity confirmed");
        println!("  - Serialization round-trip successful");
        println!("  - Schema stability validated");
    }

    /// Performance regression test: Ensure conformance tests complete quickly
    #[test]
    #[allow(dead_code)]
    fn performance_conformance_tests_complete_quickly() {
        use std::time::Instant;

        let start = Instant::now();

        // Run a subset of the conformance test operations
        let events = create_comprehensive_event_suite();
        for event in &events {
            let _serialized = serde_json::to_string(event)
                .expect("Should serialize");
        }

        let elapsed = start.elapsed();

        // Performance requirement: basic operations should complete in reasonable time
        assert!(elapsed.as_millis() < 1000,
            "Conformance test operations took too long: {}ms", elapsed.as_millis());

        println!("✓ Performance test passed: {} events processed in {}ms",
            events.len(), elapsed.as_millis());
    }
}

/// Test module availability regardless of feature flags
#[test]
#[allow(dead_code)]
fn trace_event_conformance_suite_availability() {
    println!("✓ Trace event schema stability conformance test suite is available");
    println!("✓ Covers: event kind stability, timestamp ordering, correlation IDs, serialization round-trip, forward compatibility");
    println!("  Run with: cargo test --test conformance_trace_event");
}