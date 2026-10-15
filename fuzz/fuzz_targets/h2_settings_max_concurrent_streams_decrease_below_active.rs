#![no_main]

//! Fuzz target for HTTP/2 MAX_CONCURRENT_STREAMS decrease below current active count
//!
//! Tests the scenario where MAX_CONCURRENT_STREAMS is set to a value lower than
//! the current number of active streams. Per RFC 7540 §6.5.2, existing streams
//! continue but no new streams can be created until the count drops below the
//! new limit.
//!
//! Test scenario:
//! 1. Set MAX_CONCURRENT_STREAMS=10 (allow up to 10 streams)
//! 2. Create 8 active streams
//! 3. Set MAX_CONCURRENT_STREAMS=5 (below current 8)
//! 4. Verify: existing 8 streams continue, new streams refused until count ≤ 4
//!
//! Key validations:
//! - Existing streams remain unaffected by limit decrease
//! - New stream creation is blocked when at or above new limit
//! - Stream closure allows new stream creation when count drops below limit

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 connection for testing MAX_CONCURRENT_STREAMS decrease behavior
struct MockConcurrentStreamsDecreaseConnection {
    /// Current MAX_CONCURRENT_STREAMS setting
    max_concurrent_streams: u32,

    /// Active streams by stream ID
    active_streams: HashMap<u32, StreamInfo>,

    /// Next stream ID to assign (client = odd, server = even)
    next_stream_id: u32,

    /// Statistics tracking
    stats: ConcurrentStreamsStats,

    /// Violation tracking
    violations: Vec<ViolationType>,

    /// History of settings changes and their effects
    settings_history: Vec<SettingsChange>,
}

#[derive(Clone, Debug)]
struct StreamInfo {
    stream_id: u32,
    state: StreamState,
    created_at_limit: u32, // What MAX_CONCURRENT_STREAMS was when this stream was created
    is_client_stream: bool,
}

#[derive(Clone, Debug)]
struct SettingsChange {
    old_limit: u32,
    new_limit: u32,
    active_count_at_time: u32,
    streams_above_new_limit: bool,
}

#[derive(Clone, Debug)]
enum StreamState {
    Open,
    Closed,
}

#[derive(Default, Clone, Debug)]
struct ConcurrentStreamsStats {
    settings_changes: u32,
    streams_created: u32,
    streams_closed: u32,
    streams_refused: u32,
    limit_decreases: u32,
    limit_increases: u32,
    refused_due_to_decreased_limit: u32,
    existing_streams_continued: u32,
}

#[derive(Clone, Debug)]
enum ViolationType {
    ExistingStreamTerminated,   // Existing stream was incorrectly terminated
    NewStreamAllowedAboveLimit, // New stream created when above limit
    StateInconsistency,         // Stream count doesn't match reality
}

impl MockConcurrentStreamsDecreaseConnection {
    fn new() -> Self {
        Self {
            max_concurrent_streams: 100, // Default high limit
            active_streams: HashMap::new(),
            next_stream_id: 1,
            stats: ConcurrentStreamsStats::default(),
            violations: Vec::new(),
            settings_history: Vec::new(),
        }
    }

    /// Process SETTINGS frame with MAX_CONCURRENT_STREAMS
    fn handle_settings_max_concurrent_streams(&mut self, new_limit: u32) -> Result<(), H2Error> {
        self.stats.settings_changes += 1;

        let old_limit = self.max_concurrent_streams;
        let current_active = self.get_active_stream_count();

        // Track whether streams are above the new limit
        let streams_above_new_limit = current_active > new_limit;

        // Record the settings change
        let change = SettingsChange {
            old_limit,
            new_limit,
            active_count_at_time: current_active,
            streams_above_new_limit,
        };
        self.settings_history.push(change);

        // Update statistics
        if new_limit < old_limit {
            self.stats.limit_decreases += 1;
        } else if new_limit > old_limit {
            self.stats.limit_increases += 1;
        }

        // Apply the new limit
        self.max_concurrent_streams = new_limit;

        // Important: Per RFC 7540 §6.5.2, existing streams are NOT closed
        // when the limit is decreased. They continue to operate normally.
        // Only new stream creation is affected.

        if streams_above_new_limit {
            // We have more active streams than the new limit allows
            // This is valid - existing streams continue, but new ones will be refused
            self.stats.existing_streams_continued = current_active;
        }

        Ok(())
    }

    fn expect_settings_update(&mut self, new_limit: u32, context: &str) {
        if let Err(err) = self.handle_settings_max_concurrent_streams(new_limit) {
            self.violations.push(ViolationType::StateInconsistency);
            panic!(
                "{context}: MAX_CONCURRENT_STREAMS update to {new_limit} failed unexpectedly: {err:?}"
            );
        }
    }

    /// Attempt to create a new stream
    fn create_stream(&mut self, is_client: bool) -> Result<u32, H2Error> {
        let current_active = self.get_active_stream_count();

        // Check if we can create a new stream
        if current_active >= self.max_concurrent_streams {
            self.stats.streams_refused += 1;

            // Check if this refusal is due to a decreased limit
            if let Some(last_change) = self.settings_history.last()
                && last_change.streams_above_new_limit
                && current_active >= last_change.new_limit
            {
                self.stats.refused_due_to_decreased_limit += 1;
            }

            return Err(H2Error::RefusedStream);
        }

        // Assign stream ID
        let stream_id = self.next_stream_id;
        if is_client {
            self.next_stream_id += 2; // Client streams are odd (1, 3, 5, ...)
        } else {
            // For server streams, we'd use even IDs starting from 2
            // But for simplicity, we'll just increment by 2
            self.next_stream_id += 2;
        }

        // Create the stream
        let stream = StreamInfo {
            stream_id,
            state: StreamState::Open,
            created_at_limit: self.max_concurrent_streams,
            is_client_stream: is_client,
        };

        self.active_streams.insert(stream_id, stream);
        self.stats.streams_created += 1;

        Ok(stream_id)
    }

    /// Close a stream
    fn close_stream(&mut self, stream_id: u32) -> Result<(), H2Error> {
        if let Some(stream) = self.active_streams.get_mut(&stream_id) {
            stream.state = StreamState::Closed;
            self.stats.streams_closed += 1;

            // Remove from active streams
            self.active_streams.remove(&stream_id);

            Ok(())
        } else {
            Err(H2Error::StreamNotFound)
        }
    }

    fn expect_tracked_stream_close(&mut self, stream_id: u32, context: &str) {
        if let Err(err) = self.close_stream(stream_id) {
            self.violations.push(ViolationType::StateInconsistency);
            panic!("{context}: tracked stream {stream_id} failed to close: {err:?}");
        }
    }

    fn observe_stream_create(&mut self, is_client: bool, context: &str) -> Option<u32> {
        let before_count = self.get_active_stream_count();
        let before_created = self.stats.streams_created;
        let before_refused = self.stats.streams_refused;

        match self.create_stream(is_client) {
            Ok(stream_id) => {
                assert!(
                    before_count < self.max_concurrent_streams,
                    "{context}: stream {stream_id} was created at/above limit {} with count {}",
                    self.max_concurrent_streams,
                    before_count
                );
                assert_eq!(
                    self.get_active_stream_count(),
                    before_count.saturating_add(1),
                    "{context}: accepted stream did not increase active count"
                );
                assert_eq!(
                    self.stats.streams_created,
                    before_created.saturating_add(1),
                    "{context}: accepted stream did not advance created counter"
                );
                assert!(
                    matches!(
                        self.active_streams.get(&stream_id),
                        Some(StreamInfo {
                            state: StreamState::Open,
                            ..
                        })
                    ),
                    "{context}: accepted stream was not tracked as open"
                );
                Some(stream_id)
            }
            Err(H2Error::RefusedStream) => {
                assert!(
                    before_count >= self.max_concurrent_streams,
                    "{context}: stream refused below limit {} with count {}",
                    self.max_concurrent_streams,
                    before_count
                );
                assert_eq!(
                    self.get_active_stream_count(),
                    before_count,
                    "{context}: refused stream mutated active count"
                );
                assert_eq!(
                    self.stats.streams_refused,
                    before_refused.saturating_add(1),
                    "{context}: refused stream did not advance refusal counter"
                );
                None
            }
            Err(H2Error::StreamNotFound) => {
                panic!("{context}: stream creation returned StreamNotFound")
            }
        }
    }

    /// Get current active stream count
    fn get_active_stream_count(&self) -> u32 {
        self.active_streams.len() as u32
    }

    /// Test the specific decrease scenario
    fn test_decrease_scenario(&mut self) -> DecreaseScenarioResult {
        let mut result = DecreaseScenarioResult::default();

        // Step 1: Set MAX_CONCURRENT_STREAMS=10
        self.expect_settings_update(10, "scenario step 1 initial limit");
        result.step1_success = true;

        // Step 2: Create 8 active streams
        let mut created_streams = Vec::new();
        for _ in 0..8 {
            if let Some(stream_id) = self.observe_stream_create(true, "scenario step 2 create") {
                created_streams.push(stream_id);
            } else {
                break;
            }
        }
        result.streams_created = created_streams.len() as u32;
        result.active_before_decrease = self.get_active_stream_count();

        // Step 3: Set MAX_CONCURRENT_STREAMS=5 (below current 8)
        self.expect_settings_update(5, "scenario step 3 decreased limit");
        result.step3_success = true;
        result.active_after_decrease = self.get_active_stream_count();

        // Step 4: Verify existing streams are still active
        for &stream_id in &created_streams {
            if !self.active_streams.contains_key(&stream_id) {
                self.violations
                    .push(ViolationType::ExistingStreamTerminated);
                result.existing_streams_terminated = true;
            }
        }

        // Step 5: Try to create a new stream - should be refused
        if self
            .observe_stream_create(true, "scenario step 5 above-limit create")
            .is_some()
        {
            self.violations
                .push(ViolationType::NewStreamAllowedAboveLimit);
            result.new_stream_incorrectly_allowed = true;
        } else {
            result.new_stream_correctly_refused = true;
        }

        // Step 6: Close streams until below the limit (5), then try creating
        let streams_to_close =
            (self.get_active_stream_count().saturating_sub(4)).min(created_streams.len() as u32);
        for &stream_id in created_streams.iter().take(streams_to_close as usize) {
            self.expect_tracked_stream_close(stream_id, "scenario step 6 close");
        }
        result.active_after_closures = self.get_active_stream_count();

        // Step 7: Now try to create a new stream - should succeed if under limit
        if self.get_active_stream_count() < self.max_concurrent_streams {
            result.new_stream_allowed_after_closure = self
                .observe_stream_create(true, "scenario step 7 below-limit create")
                .is_some();
            result.new_stream_refused_after_closure = !result.new_stream_allowed_after_closure;
        }

        result
    }

    /// Validate stream count consistency
    fn validate_stream_count_consistency(&self) -> Vec<String> {
        let mut violations = Vec::new();

        let actual_count = self.get_active_stream_count();
        let expected_count = self.active_streams.len() as u32;

        if actual_count != expected_count {
            violations.push(format!(
                "Stream count mismatch: actual {} != expected {}",
                actual_count, expected_count
            ));
        }

        // Check that no closed streams are in active map
        for stream in self.active_streams.values() {
            if matches!(stream.state, StreamState::Closed) {
                violations.push(format!(
                    "Closed stream {} still in active map",
                    stream.stream_id
                ));
            }

            if stream.created_at_limit == 0 {
                violations.push(format!(
                    "Stream {} was created while MAX_CONCURRENT_STREAMS was zero",
                    stream.stream_id
                ));
            }

            let stream_is_client = stream.stream_id % 2 == 1;
            if stream_is_client != stream.is_client_stream {
                violations.push(format!(
                    "Stream {} parity does not match client/server ownership",
                    stream.stream_id
                ));
            }
        }

        for change in &self.settings_history {
            let active_exceeded_new_limit = change.active_count_at_time > change.new_limit;
            if change.streams_above_new_limit != active_exceeded_new_limit {
                violations.push(format!(
                    "Settings change {} -> {} recorded inconsistent above-limit state",
                    change.old_limit, change.new_limit
                ));
            }
        }

        violations
    }

    /// Get comprehensive statistics
    fn get_stats(&self) -> &ConcurrentStreamsStats {
        &self.stats
    }

    /// Get violations
    fn get_violations(&self) -> &[ViolationType] {
        &self.violations
    }

    /// Get settings change history
    fn get_settings_history(&self) -> &[SettingsChange] {
        &self.settings_history
    }
}

#[derive(Default, Clone, Debug)]
struct DecreaseScenarioResult {
    step1_success: bool,
    step3_success: bool,
    streams_created: u32,
    active_before_decrease: u32,
    active_after_decrease: u32,
    active_after_closures: u32,
    existing_streams_terminated: bool,
    new_stream_incorrectly_allowed: bool,
    new_stream_correctly_refused: bool,
    new_stream_allowed_after_closure: bool,
    new_stream_refused_after_closure: bool,
}

#[derive(Clone, Debug)]
enum H2Error {
    RefusedStream,
    StreamNotFound,
}

/// Fuzz input structure
#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Initial MAX_CONCURRENT_STREAMS setting
    initial_limit: u32,

    /// Number of streams to create initially
    initial_stream_count: u32,

    /// New (decreased) MAX_CONCURRENT_STREAMS setting
    decreased_limit: u32,

    /// Sequence of operations after decrease
    operations: Vec<StreamOperation>,

    /// Whether to run the specific scenario test
    run_scenario_test: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum StreamOperation {
    /// Try to create a new stream
    CreateStream { is_client: bool },

    /// Close an existing stream
    CloseStream { stream_index: u8 },

    /// Change MAX_CONCURRENT_STREAMS again
    ChangeLimit { new_limit: u32 },

    /// Validate state consistency
    ValidateState,
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive resource usage
    if input.operations.len() > 50 {
        return;
    }

    let mut connection = MockConcurrentStreamsDecreaseConnection::new();

    // Step 1: Set initial limit
    let initial_limit = input.initial_limit.min(100); // Reasonable limit
    connection.expect_settings_update(initial_limit, "fuzz step 1 initial limit");

    // Step 2: Create initial streams
    let initial_count = input.initial_stream_count.min(initial_limit + 5); // Allow some above limit for testing
    let mut created_streams = Vec::new();
    for _ in 0..initial_count {
        if let Ok(stream_id) = connection.create_stream(true) {
            created_streams.push(stream_id);
        }
    }

    let streams_before_decrease = connection.get_active_stream_count();

    // Step 3: Decrease the limit
    let decreased_limit = input.decreased_limit.min(100);
    connection.expect_settings_update(decreased_limit, "fuzz step 3 decreased limit");

    let streams_after_decrease = connection.get_active_stream_count();

    // Critical validation: existing streams should NOT be closed
    assert_eq!(
        streams_after_decrease, streams_before_decrease,
        "Existing streams were closed when limit decreased"
    );

    // Process additional operations
    for operation in input.operations {
        match operation {
            StreamOperation::CreateStream { is_client } => {
                if let Some(stream_id) =
                    connection.observe_stream_create(is_client, "operation create stream")
                {
                    created_streams.push(stream_id);
                }
            }

            StreamOperation::CloseStream { stream_index } => {
                if !created_streams.is_empty() {
                    let index = (stream_index as usize) % created_streams.len();
                    let stream_id = created_streams[index];
                    connection.expect_tracked_stream_close(stream_id, "operation close stream");
                    created_streams.remove(index);
                }
            }

            StreamOperation::ChangeLimit { new_limit } => {
                let safe_limit = new_limit.min(100);
                let before_count = connection.get_active_stream_count();
                connection.expect_settings_update(safe_limit, "operation change limit");
                let after_count = connection.get_active_stream_count();

                // Existing streams should never be closed due to limit changes
                assert_eq!(
                    after_count, before_count,
                    "Stream count changed after limit change"
                );
            }

            StreamOperation::ValidateState => {
                let violations = connection.validate_stream_count_consistency();
                if !violations.is_empty() {
                    panic!("State consistency violations: {:?}", violations);
                }
            }
        }
    }

    // Run specific scenario test if requested
    if input.run_scenario_test {
        let scenario_result = connection.test_decrease_scenario();

        // Validate scenario-specific requirements
        if scenario_result.step1_success && scenario_result.step3_success {
            // Existing streams should not be terminated
            assert!(
                !scenario_result.existing_streams_terminated,
                "Existing streams were incorrectly terminated"
            );

            // New stream creation should be refused when above limit
            assert!(
                scenario_result.new_stream_correctly_refused,
                "New stream should have been refused when above limit"
            );

            // Should not allow new streams when above limit
            assert!(
                !scenario_result.new_stream_incorrectly_allowed,
                "New stream was incorrectly allowed when above limit"
            );
        }
    }

    // Final validations
    let violations = connection.get_violations();
    if let Some(violation) = violations.iter().next() {
        match violation {
            ViolationType::ExistingStreamTerminated => {
                panic!("CRITICAL: Existing stream was terminated when limit decreased");
            }
            ViolationType::NewStreamAllowedAboveLimit => {
                panic!("CRITICAL: New stream allowed when above limit");
            }
            ViolationType::StateInconsistency => {
                panic!("CRITICAL: Stream state inconsistency detected");
            }
        }
    }

    assert_eq!(
        connection.get_stats().settings_changes as usize,
        connection.get_settings_history().len(),
        "Every settings update should have a matching history entry"
    );

    // Validate final state consistency
    let consistency_violations = connection.validate_stream_count_consistency();
    if !consistency_violations.is_empty() {
        panic!("Final state inconsistency: {:?}", consistency_violations);
    }

    // Test edge cases
    test_edge_cases(&mut connection);
});

/// Test specific edge cases for concurrent stream limit decrease
fn test_edge_cases(connection: &mut MockConcurrentStreamsDecreaseConnection) {
    let original_limit = connection.max_concurrent_streams;
    let original_count = connection.get_active_stream_count();

    // Edge case 1: Decrease to 0 (no new streams allowed)
    connection.expect_settings_update(0, "edge case decrease to zero");
    let count_after_zero = connection.get_active_stream_count();

    // Existing streams should still be active
    assert_eq!(
        count_after_zero, original_count,
        "Streams closed when limit set to 0"
    );

    // New stream should be refused
    let created_at_zero = connection.observe_stream_create(true, "edge case limit zero create");
    assert!(
        created_at_zero.is_none(),
        "Stream creation should be refused with limit=0"
    );

    // Edge case 2: Increase limit again
    connection.expect_settings_update(original_limit, "edge case restore original limit");

    // Should be able to create streams again (if below limit)
    if connection.get_active_stream_count() < original_limit {
        let result = connection.observe_stream_create(true, "edge case restored limit create");
        assert!(
            result.is_some(),
            "Stream creation should succeed after limit increase"
        );
    }
}
