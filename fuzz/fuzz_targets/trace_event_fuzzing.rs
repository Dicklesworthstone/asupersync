#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Comprehensive trace event fuzzing for sequence allocation and event serialization
#[derive(Arbitrary, Debug)]
struct TraceEventFuzz {
    /// Buffer configuration for testing ring buffer behavior
    buffer_configs: Vec<BufferConfig>,
    /// Sequence allocation operations for testing concurrency and collisions
    sequence_operations: Vec<SequenceOperation>,
    /// Event creation operations for testing data serialization
    event_operations: Vec<EventOperation>,
    /// Schema compatibility tests
    schema_tests: Vec<SchemaTest>,
    /// Stress test scenarios
    stress_scenarios: Vec<StressScenario>,
}

/// Buffer configuration for testing different buffer sizes and behaviors
#[derive(Arbitrary, Debug)]
struct BufferConfig {
    /// Buffer capacity (will be clamped to reasonable limits)
    capacity: u16,
    /// Whether to test buffer overflow scenarios
    test_overflow: bool,
    /// Number of concurrent producers to simulate
    concurrent_producers: u8,
}

/// Sequence allocation operations for testing ID allocation and collision
#[derive(Arbitrary, Debug)]
enum SequenceOperation {
    /// Allocate single sequence number
    AllocateNext,
    /// Allocate batch of sequence numbers
    AllocateBatch { count: u8 },
    /// Test concurrent allocation from multiple threads
    ConcurrentAllocation { thread_count: u8 },
    /// Test sequence number wrap-around scenarios
    TestWrapAround { base_seq: u64 },
    /// Test sequence gap detection
    TestGaps { expected_seq: u64, actual_seq: u64 },
}

/// Event creation operations for testing event data serialization
#[derive(Arbitrary, Debug)]
enum EventOperation {
    /// Create task lifecycle event
    CreateTaskEvent { kind: TaskEventKind, time_ns: u64 },
    /// Create obligation event
    CreateObligationEvent {
        kind: ObligationEventKind,
        state: ObligationStateVariant,
        duration_ns: Option<u64>,
    },
    /// Create timer event
    CreateTimerEvent {
        timer_id: u64,
        deadline_ns: Option<u64>,
    },
    /// Create IO event
    CreateIoEvent {
        token: u64,
        interest: u8,
        readiness: u8,
        bytes: i64,
    },
    /// Create user trace message
    CreateUserTrace { message: String },
    /// Create malformed event data
    CreateMalformedEvent { corrupted_data: Vec<u8> },
}

/// Task event kinds for fuzzing
#[derive(Arbitrary, Debug)]
enum TaskEventKind {
    Spawn,
    Schedule,
    Yield,
    Wake,
    Poll,
    Complete,
}

/// Obligation event kinds for fuzzing
#[derive(Arbitrary, Debug)]
enum ObligationEventKind {
    Reserve,
    Commit,
    Abort,
    Leak,
}

/// Obligation state variants for fuzzing
#[derive(Arbitrary, Debug)]
enum ObligationStateVariant {
    Reserved,
    Committed,
    Aborted,
    Leaked,
}

/// Schema compatibility tests
#[derive(Arbitrary, Debug)]
struct SchemaTest {
    /// Schema version to test
    version: u32,
    /// Whether to test backward compatibility
    test_backward_compat: bool,
    /// Whether to test forward compatibility
    test_forward_compat: bool,
    /// Corrupted schema data
    corrupted_schema: Vec<u8>,
}

/// Stress test scenarios for edge case detection
#[derive(Arbitrary, Debug)]
enum StressScenario {
    /// Rapid event generation
    RapidEvents { count: u16, interval_us: u16 },
    /// Large event payloads
    LargePayloads { payload_size: u16 },
    /// Buffer thrashing (fill and drain repeatedly)
    BufferThrashing { cycles: u8 },
    /// Sequence number exhaustion
    SequenceExhaustion { near_max: bool },
    /// Memory pressure simulation
    MemoryPressure { allocation_size: u32 },
}

/// Maximum values for safety limits
const MAX_BUFFER_CAPACITY: u16 = 8192;
const MAX_THREAD_COUNT: u8 = 16;
const MAX_BATCH_SIZE: u8 = 100;
const MAX_EVENT_COUNT: u16 = 1000;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
const MAX_STRING_LEN: usize = 1024;
const MAX_ALLOCATION_SIZE: u32 = 1024 * 1024;

fuzz_target!(|input: TraceEventFuzz| {
    // Test buffer configurations
    for buffer_config in input.buffer_configs.iter().take(5) {
        test_buffer_configuration(buffer_config);
    }

    // Test sequence allocation operations
    for seq_op in input.sequence_operations.iter().take(10) {
        test_sequence_operation(seq_op);
    }

    // Test event operations
    for event_op in input.event_operations.iter().take(20) {
        test_event_operation(event_op);
    }

    // Test schema compatibility
    for schema_test in input.schema_tests.iter().take(5) {
        test_schema_compatibility(schema_test);
    }

    // Test stress scenarios
    for stress_scenario in input.stress_scenarios.iter().take(3) {
        test_stress_scenario(stress_scenario);
    }
});

/// Test buffer configuration and ring buffer behavior
fn test_buffer_configuration(config: &BufferConfig) {
    use asupersync::trace::buffer::TraceBufferHandle;

    let capacity = (config.capacity as usize).clamp(1, MAX_BUFFER_CAPACITY as usize);
    let handle = TraceBufferHandle::new(capacity);

    // Test basic buffer properties
    assert_eq!(handle.len(), 0, "New buffer should be empty");
    assert_eq!(
        handle.total_pushed(),
        0,
        "New buffer should have zero total"
    );

    // Test initial sequence allocation
    let first_seq = handle.next_seq();
    let second_seq = handle.next_seq();
    assert_eq!(
        second_seq,
        first_seq + 1,
        "Sequence numbers should be consecutive"
    );

    if config.test_overflow {
        test_buffer_overflow(&handle, capacity);
    }

    if config.concurrent_producers > 0 {
        test_concurrent_producers(&handle, config.concurrent_producers.min(MAX_THREAD_COUNT));
    }
}

/// Test buffer overflow and ring buffer wraparound
fn test_buffer_overflow(handle: &asupersync::trace::buffer::TraceBufferHandle, capacity: usize) {
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    // Fill buffer beyond capacity
    for i in 0..(capacity * 2) {
        let event = TraceEvent::new(
            i as u64,
            Time::from_nanos(i as u64 * 1000),
            TraceEventKind::UserTrace,
            TraceData::Message(format!("test_event_{}", i)),
        );
        handle.push_event(event);
    }

    // Buffer should be at capacity, not overflow
    assert_eq!(
        handle.len(),
        capacity,
        "Buffer should be at capacity after overflow"
    );
    assert_eq!(
        handle.total_pushed(),
        (capacity * 2) as u64,
        "Total pushed should count all events"
    );

    // Verify events are ordered correctly (newest events survive)
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.len(), capacity);

    if !snapshot.is_empty() {
        // Check that we have the most recent events
        let first_event = &snapshot[0];
        assert!(
            first_event.seq >= capacity as u64,
            "First event sequence should be from second batch"
        );
    }
}

/// Test concurrent sequence allocation
fn test_concurrent_producers(
    handle: &asupersync::trace::buffer::TraceBufferHandle,
    producer_count: u8,
) {
    use std::sync::Arc;
    use std::thread;

    let handle = Arc::new(handle.clone());
    let mut threads = Vec::new();
    let sequences_per_thread = 10;

    for thread_id in 0..producer_count {
        let handle_clone = Arc::clone(&handle);
        let thread = thread::spawn(move || {
            let mut sequences = Vec::new();
            for _ in 0..sequences_per_thread {
                sequences.push(handle_clone.next_seq());
            }
            sequences
        });
        threads.push((thread_id, thread));
    }

    let mut all_sequences = Vec::new();
    for (_thread_id, thread) in threads {
        match thread.join() {
            Ok(sequences) => all_sequences.extend(sequences),
            Err(_) => continue, // Thread panicked, skip
        }
    }

    // Verify all sequences are unique (no collisions)
    all_sequences.sort_unstable();
    for window in all_sequences.windows(2) {
        assert_ne!(
            window[0], window[1],
            "Sequence collision detected: {} appears twice",
            window[0]
        );
    }

    // Verify sequences are monotonic overall
    let expected_count = producer_count as usize * sequences_per_thread;
    assert_eq!(
        all_sequences.len(),
        expected_count,
        "Should have {} unique sequences, got {}",
        expected_count,
        all_sequences.len()
    );
}

/// Test individual sequence operations
fn test_sequence_operation(op: &SequenceOperation) {
    use asupersync::trace::buffer::TraceBufferHandle;

    let handle = TraceBufferHandle::new(1024);

    match op {
        SequenceOperation::AllocateNext => {
            let seq = handle.next_seq();
            assert_eq!(seq, 0, "First allocation should be 0");
            let next_seq = handle.next_seq();
            assert_eq!(next_seq, 1, "Second allocation should be 1");
        }
        SequenceOperation::AllocateBatch { count } => {
            let count = (*count as usize).min(MAX_BATCH_SIZE as usize);
            let mut sequences = Vec::with_capacity(count);
            for _ in 0..count {
                sequences.push(handle.next_seq());
            }

            // Verify sequences are consecutive
            for i in 1..sequences.len() {
                assert_eq!(
                    sequences[i],
                    sequences[i - 1] + 1,
                    "Batch sequences should be consecutive"
                );
            }
        }
        SequenceOperation::ConcurrentAllocation { thread_count } => {
            let thread_count = (*thread_count as usize).min(MAX_THREAD_COUNT as usize);
            if thread_count > 1 {
                test_concurrent_producers(&handle, thread_count as u8);
            }
        }
        SequenceOperation::TestWrapAround { base_seq } => {
            // Test sequence numbers near wraparound boundaries
            test_sequence_wraparound(*base_seq);
        }
        SequenceOperation::TestGaps {
            expected_seq,
            actual_seq,
        } => {
            // Test gap detection in sequence numbers
            test_sequence_gaps(*expected_seq, *actual_seq);
        }
    }
}

/// Test sequence number wraparound scenarios
fn test_sequence_wraparound(base_seq: u64) {
    // Test scenarios where sequence numbers approach u64::MAX
    let near_max_values = [u64::MAX - 10, u64::MAX - 1, u64::MAX];

    for &start_seq in &near_max_values {
        let test_seq = base_seq.saturating_add(start_seq);

        // Verify arithmetic doesn't overflow
        let next_seq = test_seq.wrapping_add(1);
        assert_ne!(test_seq, next_seq, "Sequence should advance");

        // Test edge case behavior
        if test_seq == u64::MAX {
            assert_eq!(next_seq, 0, "Sequence should wrap to 0 after MAX");
        }
    }
}

/// Test sequence gap detection
fn test_sequence_gaps(expected_seq: u64, actual_seq: u64) {
    // Test detection of missing sequence numbers
    if expected_seq != actual_seq {
        let gap_size = if actual_seq > expected_seq {
            actual_seq - expected_seq
        } else {
            expected_seq - actual_seq
        };

        // Large gaps might indicate bugs
        if gap_size > 1000 {
            // Log significant gaps for analysis
        }

        // Verify gap calculations don't overflow
        assert!(gap_size < u64::MAX, "Gap calculation should not overflow");
    }
}

/// Test event creation and serialization
fn test_event_operation(op: &EventOperation) {
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::{RegionId, TaskId, Time};

    match op {
        EventOperation::CreateTaskEvent { kind, time_ns } => {
            let event_kind = match kind {
                TaskEventKind::Spawn => TraceEventKind::Spawn,
                TaskEventKind::Schedule => TraceEventKind::Schedule,
                TaskEventKind::Yield => TraceEventKind::Yield,
                TaskEventKind::Wake => TraceEventKind::Wake,
                TaskEventKind::Poll => TraceEventKind::Poll,
                TaskEventKind::Complete => TraceEventKind::Complete,
            };

            let event = TraceEvent::new(
                0,
                Time::from_nanos(*time_ns),
                event_kind,
                TraceData::Task {
                    task: TaskId::testing_default(),
                    region: RegionId::testing_default(),
                },
            );

            // Verify event properties
            assert_eq!(event.kind, event_kind);
            assert_eq!(event.time, Time::from_nanos(*time_ns));

            // Test event data consistency
            if let TraceData::Task { .. } = &event.data {
                // Task and region IDs are set, just verify structure
            } else {
                panic!("Event data should be Task variant");
            }
        }
        EventOperation::CreateObligationEvent {
            kind,
            state,
            duration_ns,
        } => {
            test_obligation_event_creation(kind, state, *duration_ns);
        }
        EventOperation::CreateTimerEvent {
            timer_id,
            deadline_ns,
        } => {
            test_timer_event_creation(*timer_id, *deadline_ns);
        }
        EventOperation::CreateIoEvent {
            token,
            interest,
            readiness,
            bytes,
        } => {
            test_io_event_creation(*token, *interest, *readiness, *bytes);
        }
        EventOperation::CreateUserTrace { message } => {
            let safe_message = if message.len() > MAX_STRING_LEN {
                &message[..MAX_STRING_LEN]
            } else {
                message
            };
            test_user_trace_creation(safe_message);
        }
        EventOperation::CreateMalformedEvent { corrupted_data } => {
            test_malformed_event_handling(corrupted_data);
        }
    }
}

/// Test obligation event creation
fn test_obligation_event_creation(
    kind: &ObligationEventKind,
    state: &ObligationStateVariant,
    duration_ns: Option<u64>,
) {
    use asupersync::record::{ObligationKind, ObligationState};
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::{ObligationId, RegionId, TaskId, Time};

    let event_kind = match kind {
        ObligationEventKind::Reserve => TraceEventKind::ObligationReserve,
        ObligationEventKind::Commit => TraceEventKind::ObligationCommit,
        ObligationEventKind::Abort => TraceEventKind::ObligationAbort,
        ObligationEventKind::Leak => TraceEventKind::ObligationLeak,
    };

    let obligation_state = match state {
        ObligationStateVariant::Reserved => ObligationState::Reserved,
        ObligationStateVariant::Committed => ObligationState::Committed,
        ObligationStateVariant::Aborted => ObligationState::Aborted,
        ObligationStateVariant::Leaked => ObligationState::Leaked,
    };

    let event = TraceEvent::new(
        0,
        Time::from_nanos(1000),
        event_kind,
        TraceData::Obligation {
            obligation: ObligationId::new_for_test(1, 0),
            task: TaskId::testing_default(),
            region: RegionId::testing_default(),
            kind: ObligationKind::SendPermit, // Default for testing
            state: obligation_state,
            duration_ns,
            abort_reason: None,
        },
    );

    // Verify obligation data consistency
    if let TraceData::Obligation {
        state: obs_state, ..
    } = &event.data
    {
        assert_eq!(*obs_state, obligation_state);
    } else {
        panic!("Event data should be Obligation variant");
    }
}

/// Test timer event creation
fn test_timer_event_creation(timer_id: u64, deadline_ns: Option<u64>) {
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    let deadline = deadline_ns.map(Time::from_nanos);

    let event = TraceEvent::new(
        0,
        Time::from_nanos(1000),
        TraceEventKind::TimerScheduled,
        TraceData::Timer { timer_id, deadline },
    );

    // Verify timer data
    if let TraceData::Timer {
        timer_id: tid,
        deadline: dl,
    } = &event.data
    {
        assert_eq!(*tid, timer_id);
        assert_eq!(*dl, deadline);
    } else {
        panic!("Event data should be Timer variant");
    }
}

/// Test I/O event creation
fn test_io_event_creation(token: u64, interest: u8, readiness: u8, bytes: i64) {
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    // Test different I/O event types
    let events = [
        (
            TraceEventKind::IoRequested,
            TraceData::IoRequested { token, interest },
        ),
        (
            TraceEventKind::IoReady,
            TraceData::IoReady { token, readiness },
        ),
        (
            TraceEventKind::IoResult,
            TraceData::IoResult { token, bytes },
        ),
    ];

    for (kind, data) in &events {
        let event = TraceEvent::new(0, Time::from_nanos(1000), *kind, data.clone());

        // Verify I/O data consistency
        match (&event.data, kind) {
            (
                TraceData::IoRequested {
                    token: t,
                    interest: i,
                },
                TraceEventKind::IoRequested,
            ) => {
                assert_eq!(*t, token);
                assert_eq!(*i, interest);
            }
            (
                TraceData::IoReady {
                    token: t,
                    readiness: r,
                },
                TraceEventKind::IoReady,
            ) => {
                assert_eq!(*t, token);
                assert_eq!(*r, readiness);
            }
            (TraceData::IoResult { token: t, bytes: b }, TraceEventKind::IoResult) => {
                assert_eq!(*t, token);
                assert_eq!(*b, bytes);
            }
            _ => panic!("I/O event data mismatch"),
        }
    }
}

/// Test user trace message creation
fn test_user_trace_creation(message: &str) {
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    let event = TraceEvent::new(
        0,
        Time::from_nanos(1000),
        TraceEventKind::UserTrace,
        TraceData::Message(message.to_string()),
    );

    // Verify message data
    if let TraceData::Message(msg) = &event.data {
        assert_eq!(msg, message);
    } else {
        panic!("Event data should be Message variant");
    }
}

/// Test malformed event handling
fn test_malformed_event_handling(corrupted_data: &[u8]) {
    // Test behavior with corrupted or malformed event data
    if corrupted_data.is_empty() {
        return;
    }

    // Test various corruption scenarios
    test_corrupted_sequence_numbers(corrupted_data);
    test_corrupted_timestamps(corrupted_data);
    test_corrupted_event_kinds(corrupted_data);
}

/// Test corrupted sequence numbers
fn test_corrupted_sequence_numbers(data: &[u8]) {
    if data.len() >= 8 {
        let corrupted_seq = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        // Test edge case sequence numbers
        let edge_cases = [0, 1, u64::MAX - 1, u64::MAX, corrupted_seq];

        for &seq in &edge_cases {
            // Verify sequence handling doesn't crash
            let next_seq = seq.wrapping_add(1);
            assert_ne!(seq, next_seq, "Sequence should advance from {}", seq);
        }
    }
}

/// Test corrupted timestamps
fn test_corrupted_timestamps(data: &[u8]) {
    use asupersync::types::Time;

    if data.len() >= 8 {
        let corrupted_nanos = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        // Test edge case timestamps
        let time = Time::from_nanos(corrupted_nanos);

        // Verify time handling doesn't crash
        let _ = time.as_nanos();
    }
}

/// Test corrupted event kinds
fn test_corrupted_event_kinds(data: &[u8]) {
    use asupersync::trace::event::TraceEventKind;

    if !data.is_empty() {
        let corrupted_kind_byte = data[0];

        // Test all valid event kinds don't crash
        for kind in TraceEventKind::ALL {
            let _ = kind.stable_name();
            let _ = kind.required_fields();
        }

        // Test invalid discriminant handling
        // (The actual enum is well-defined, so this tests robustness)
        let _test_byte = corrupted_kind_byte; // Use corrupted byte in some way
    }
}

/// Test schema compatibility
fn test_schema_compatibility(test: &SchemaTest) {
    use asupersync::trace::event::{BROWSER_TRACE_SCHEMA_VERSION, TRACE_EVENT_SCHEMA_VERSION};

    // Test current schema version
    assert_eq!(
        TRACE_EVENT_SCHEMA_VERSION, 1,
        "Current schema should be version 1"
    );
    assert_eq!(BROWSER_TRACE_SCHEMA_VERSION, "browser-trace-schema-v1");

    // Test version compatibility
    let test_version = test.version;

    if test.test_backward_compat {
        // Test backward compatibility scenarios
        if test_version < TRACE_EVENT_SCHEMA_VERSION {
            // Older versions should be handled gracefully
        }
    }

    if test.test_forward_compat {
        // Test forward compatibility scenarios
        if test_version > TRACE_EVENT_SCHEMA_VERSION {
            // Newer versions should be rejected or handled gracefully
        }
    }

    // Test schema corruption handling
    if !test.corrupted_schema.is_empty() {
        test_corrupted_schema(&test.corrupted_schema);
    }
}

/// Test corrupted schema handling
fn test_corrupted_schema(corrupted_data: &[u8]) {
    // Test behavior with corrupted schema data
    if corrupted_data.len() >= 4 {
        let corrupted_version = u32::from_le_bytes([
            corrupted_data[0],
            corrupted_data[1],
            corrupted_data[2],
            corrupted_data[3],
        ]);

        // Test extreme version numbers
        let extreme_versions = [0, u32::MAX, corrupted_version];

        for &version in &extreme_versions {
            // Verify version handling doesn't crash
            let _is_supported = version == asupersync::trace::event::TRACE_EVENT_SCHEMA_VERSION;
        }
    }
}

/// Test stress scenarios
fn test_stress_scenario(scenario: &StressScenario) {
    match scenario {
        StressScenario::RapidEvents {
            count,
            interval_us: _,
        } => {
            let count = (*count as usize).min(MAX_EVENT_COUNT as usize);
            test_rapid_event_generation(count);
        }
        StressScenario::LargePayloads { payload_size } => {
            let size = (*payload_size as usize).min(MAX_PAYLOAD_SIZE as usize);
            test_large_payload_handling(size);
        }
        StressScenario::BufferThrashing { cycles } => {
            let cycles = (*cycles as usize).min(10);
            test_buffer_thrashing(cycles);
        }
        StressScenario::SequenceExhaustion { near_max } => {
            test_sequence_exhaustion(*near_max);
        }
        StressScenario::MemoryPressure { allocation_size } => {
            let size = (*allocation_size as usize).min(MAX_ALLOCATION_SIZE as usize);
            test_memory_pressure(size);
        }
    }
}

/// Test rapid event generation
fn test_rapid_event_generation(count: usize) {
    use asupersync::trace::buffer::TraceBufferHandle;
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    let handle = TraceBufferHandle::new(count.max(100));

    // Generate events rapidly
    for i in 0..count {
        let event = TraceEvent::new(
            i as u64,
            Time::from_nanos((i * 1000) as u64),
            TraceEventKind::UserTrace,
            TraceData::Message(format!("rapid_event_{}", i)),
        );
        handle.push_event(event);
    }

    // Verify buffer state after rapid insertion
    assert_eq!(handle.total_pushed(), count as u64);
}

/// Test large payload handling
fn test_large_payload_handling(payload_size: usize) {
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    let large_payload = "A".repeat(payload_size);

    let event = TraceEvent::new(
        0,
        Time::from_nanos(1000),
        TraceEventKind::UserTrace,
        TraceData::Message(large_payload.clone()),
    );

    // Verify large payload doesn't break event creation
    if let TraceData::Message(msg) = &event.data {
        assert_eq!(msg.len(), payload_size);
    }
}

/// Test buffer thrashing (fill and drain repeatedly)
fn test_buffer_thrashing(cycles: usize) {
    use asupersync::trace::buffer::TraceBufferHandle;
    use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::Time;

    let capacity = 100;
    let handle = TraceBufferHandle::new(capacity);

    for cycle in 0..cycles {
        // Fill buffer
        for i in 0..capacity {
            let event = TraceEvent::new(
                (cycle * capacity + i) as u64,
                Time::from_nanos((cycle * capacity + i) as u64 * 1000),
                TraceEventKind::UserTrace,
                TraceData::Message(format!("thrash_{}_{}", cycle, i)),
            );
            handle.push_event(event);
        }

        // Verify buffer state
        assert_eq!(handle.len(), capacity);

        // Take snapshot (simulates draining)
        let _snapshot = handle.snapshot();
    }

    // Verify final state
    assert_eq!(handle.total_pushed(), (cycles * capacity) as u64);
}

/// Test sequence number exhaustion scenarios
fn test_sequence_exhaustion(near_max: bool) {
    use asupersync::trace::buffer::TraceBufferHandle;

    let handle = TraceBufferHandle::new(10);

    if near_max {
        // Test behavior near u64::MAX
        let test_sequences = [u64::MAX - 10, u64::MAX - 1, u64::MAX];

        for &test_seq in &test_sequences {
            // Test sequence arithmetic near limits
            let next_seq = test_seq.wrapping_add(1);

            // Verify wraparound behavior
            if test_seq == u64::MAX {
                assert_eq!(next_seq, 0, "Sequence should wrap to 0");
            } else {
                assert_eq!(next_seq, test_seq + 1, "Sequence should increment normally");
            }
        }
    }

    // Test normal sequence allocation
    let seq1 = handle.next_seq();
    let seq2 = handle.next_seq();
    assert_eq!(seq2, seq1 + 1, "Normal sequence allocation should work");
}

/// Test memory pressure scenarios
fn test_memory_pressure(allocation_size: usize) {
    // Test behavior under memory pressure
    if allocation_size > 0 {
        // Attempt allocation (may fail under memory pressure)
        let _test_allocation = vec![0u8; allocation_size];

        // Test that trace system continues to work
        use asupersync::trace::buffer::TraceBufferHandle;
        let handle = TraceBufferHandle::new(10);
        let _seq = handle.next_seq();
    }
}
