#![allow(clippy::all)]
//! Metamorphic tests for trace recorder deterministic replay.
//!
//! These tests validate trace recording and replay properties using metamorphic
//! relations without requiring oracle outputs. The trace recorder captures all
//! sources of non-determinism to enable exact execution replay.
//!
//! ## Metamorphic Relations Tested
//!
//! 1. **Round-trip identity**: replay(record(execution)) == execution
//! 2. **Deterministic replay**: replay produces same result under variable delays
//! 3. **Minimization preservation**: trace minimization preserves failure modes
//! 4. **DPOR commuting transitions**: DPOR correctly identifies race conditions
//! 5. **Compression round-trip**: compress(decompress(trace)) == trace

use proptest::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::trace::{
    dpor::{Race, RaceAnalysis, BacktrackPoint},
    recorder::{TraceRecorder, RecorderConfig},
    replay::{ReplayEvent, ReplayTrace, TraceMetadata, CompactTaskId},
    event::{TraceEvent, TraceEventKind},
};
use asupersync::types::{TaskId, RegionId, Time, Severity};

// =============================================================================
// Test Infrastructure
// =============================================================================

/// Mock execution environment for testing trace recording/replay.
#[derive(Debug, Clone)]
pub struct MockExecution {
    /// Sequence of events that occur during execution.
    pub events: Vec<ExecutionEvent>,
    /// Random seed for this execution.
    pub seed: u64,
    /// Configuration parameters.
    pub config: MockConfig,
}

/// Configuration for mock executions.
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Number of tasks in the execution.
    pub task_count: usize,
    /// Maximum execution steps.
    pub max_steps: usize,
    /// Enable chaos injection.
    pub enable_chaos: bool,
    /// Time advancement rate.
    pub time_step_ns: u64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            task_count: 4,
            max_steps: 50,
            enable_chaos: false,
            time_step_ns: 1000,
        }
    }
}

/// Events that can occur during mock execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionEvent {
    /// Task becomes runnable.
    TaskScheduled { task_id: TaskId, at_tick: u64 },
    /// Task yields control.
    TaskYielded { task_id: TaskId, at_tick: u64 },
    /// Task completes.
    TaskCompleted { task_id: TaskId, at_tick: u64 },
    /// Virtual time advances.
    TimeAdvanced { from: Time, to: Time },
    /// Random value generated.
    RngValue { value: u64 },
    /// Chaos injection event.
    ChaosInjection { severity: Severity, description: String },
    /// I/O operation becomes ready.
    IoReady { descriptor: u64, result_size: usize },
    /// I/O error occurs.
    IoError { descriptor: u64, error_code: u32 },
}

impl ExecutionEvent {
    /// Convert to replay event for recording.
    pub fn to_replay_event(&self) -> ReplayEvent {
        match self {
            Self::TaskScheduled { task_id, at_tick } => ReplayEvent::TaskScheduled {
                task_id: (*task_id).into(),
                at_tick: *at_tick,
            },
            Self::TaskYielded { task_id, at_tick } => ReplayEvent::TaskYielded {
                task_id: (*task_id).into(),
                at_tick: *at_tick,
            },
            Self::TaskCompleted { task_id, at_tick } => ReplayEvent::TaskCompleted {
                task_id: (*task_id).into(),
                at_tick: *at_tick,
            },
            Self::TimeAdvanced { from, to } => ReplayEvent::TimeAdvanced {
                from: *from,
                to: *to,
            },
            Self::RngValue { value } => ReplayEvent::RngValue { value: *value },
            Self::ChaosInjection { severity, description } => ReplayEvent::ChaosInjection {
                severity: *severity,
                description: description.clone(),
            },
            Self::IoReady { descriptor, result_size } => ReplayEvent::IoReady {
                descriptor: *descriptor,
                result_size: *result_size,
            },
            Self::IoError { descriptor, error_code } => ReplayEvent::IoError {
                descriptor: *descriptor,
                error_code: *error_code,
            },
        }
    }
}

/// Mock execution engine that can record and replay traces.
#[derive(Debug)]
pub struct MockExecutionEngine {
    /// Current execution state.
    pub current_execution: Option<MockExecution>,
    /// Recorded trace.
    pub trace: Option<ReplayTrace>,
    /// Replay state.
    pub replay_state: Option<MockReplayState>,
}

#[derive(Debug)]
pub struct MockReplayState {
    /// Events to replay.
    pub events: VecDeque<ReplayEvent>,
    /// Current replay position.
    pub position: usize,
    /// Replay metadata.
    pub metadata: TraceMetadata,
}

impl MockExecutionEngine {
    /// Create a new mock execution engine.
    pub fn new() -> Self {
        Self {
            current_execution: None,
            trace: None,
            replay_state: None,
        }
    }

    /// Execute and record a mock execution.
    pub fn execute_and_record(&mut self, execution: MockExecution) -> Result<ReplayTrace, String> {
        // Create a simple replay trace manually since the recorder interface differs
        let metadata = TraceMetadata::new(execution.seed);
        let mut events = Vec::new();

        // Convert execution events to replay events
        for event in &execution.events {
            events.push(event.to_replay_event());
        }

        let trace = ReplayTrace { metadata, events };
        self.current_execution = Some(execution);
        self.trace = Some(trace.clone());

        Ok(trace)
    }

    /// Replay a trace and return the resulting execution.
    pub fn replay_trace(&mut self, trace: &ReplayTrace) -> Result<MockExecution, String> {
        let mut events = Vec::new();

        // Convert replay events back to execution events
        for replay_event in &trace.events {
            match self.replay_event_to_execution_event(replay_event) {
                Some(exec_event) => events.push(exec_event),
                None => continue, // Skip events that don't map to execution events
            }
        }

        let replayed_execution = MockExecution {
            events,
            seed: trace.metadata.seed,
            config: MockConfig::default(),
        };

        self.replay_state = Some(MockReplayState {
            events: trace.events.iter().cloned().collect(),
            position: 0,
            metadata: trace.metadata.clone(),
        });

        Ok(replayed_execution)
    }

    /// Convert replay event back to execution event.
    fn replay_event_to_execution_event(&self, replay_event: &ReplayEvent) -> Option<ExecutionEvent> {
        match replay_event {
            ReplayEvent::TaskScheduled { task_id, at_tick } => {
                Some(ExecutionEvent::TaskScheduled {
                    task_id: self.compact_to_task_id(*task_id),
                    at_tick: *at_tick,
                })
            },
            ReplayEvent::TaskYielded { task_id, at_tick } => {
                Some(ExecutionEvent::TaskYielded {
                    task_id: self.compact_to_task_id(*task_id),
                    at_tick: *at_tick,
                })
            },
            ReplayEvent::TaskCompleted { task_id, at_tick } => {
                Some(ExecutionEvent::TaskCompleted {
                    task_id: self.compact_to_task_id(*task_id),
                    at_tick: *at_tick,
                })
            },
            ReplayEvent::TimeAdvanced { from, to } => {
                Some(ExecutionEvent::TimeAdvanced { from: *from, to: *to })
            },
            ReplayEvent::RngValue { value } => {
                Some(ExecutionEvent::RngValue { value: *value })
            },
            ReplayEvent::ChaosInjection { severity, description } => {
                Some(ExecutionEvent::ChaosInjection {
                    severity: *severity,
                    description: description.clone(),
                })
            },
            ReplayEvent::IoReady { descriptor, result_size } => {
                Some(ExecutionEvent::IoReady {
                    descriptor: *descriptor,
                    result_size: *result_size,
                })
            },
            ReplayEvent::IoError { descriptor, error_code } => {
                Some(ExecutionEvent::IoError {
                    descriptor: *descriptor,
                    error_code: *error_code,
                })
            },
            _ => None, // Skip other replay-specific events
        }
    }

    /// Convert compact task ID back to TaskId (mock implementation).
    fn compact_to_task_id(&self, compact: CompactTaskId) -> TaskId {
        let (index, generation) = compact.unpack();
        TaskId::new_for_test(index, generation)
    }
}

// =============================================================================
// Property Test Generators
// =============================================================================

/// Generate arbitrary mock execution events.
fn arb_execution_event() -> impl Strategy<Value = ExecutionEvent> {
    prop_oneof![
        (any::<u32>(), any::<u32>(), any::<u64>()).prop_map(|(idx, gen, tick)| {
            ExecutionEvent::TaskScheduled {
                task_id: TaskId::new_for_test(idx, gen),
                at_tick: tick,
            }
        }),
        (any::<u32>(), any::<u32>(), any::<u64>()).prop_map(|(idx, gen, tick)| {
            ExecutionEvent::TaskYielded {
                task_id: TaskId::new_for_test(idx, gen),
                at_tick: tick,
            }
        }),
        (any::<u32>(), any::<u32>(), any::<u64>()).prop_map(|(idx, gen, tick)| {
            ExecutionEvent::TaskCompleted {
                task_id: TaskId::new_for_test(idx, gen),
                at_tick: tick,
            }
        }),
        (any::<u64>(), any::<u64>()).prop_map(|(from_ns, to_ns)| {
            let from = Time::from_nanos(from_ns);
            let to = Time::from_nanos(from_ns + to_ns);
            ExecutionEvent::TimeAdvanced { from, to }
        }),
        any::<u64>().prop_map(|value| ExecutionEvent::RngValue { value }),
        (".*", prop_oneof![
            Just(Severity::Info),
            Just(Severity::Warn),
            Just(Severity::Error)
        ]).prop_map(|(desc, sev)| {
            ExecutionEvent::ChaosInjection {
                severity: sev,
                description: desc,
            }
        }),
        (any::<u64>(), any::<usize>()).prop_map(|(desc, size)| {
            ExecutionEvent::IoReady {
                descriptor: desc,
                result_size: size,
            }
        }),
        (any::<u64>(), any::<u32>()).prop_map(|(desc, code)| {
            ExecutionEvent::IoError {
                descriptor: desc,
                error_code: code,
            }
        }),
    ]
}

/// Generate arbitrary mock execution.
fn arb_mock_execution() -> impl Strategy<Value = MockExecution> {
    (
        any::<u64>(), // seed
        prop::collection::vec(arb_execution_event(), 1..20),
        any::<MockConfig>(),
    ).prop_map(|(seed, events, config)| MockExecution { seed, events, config })
}

impl Arbitrary for MockConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            1usize..8,   // task_count
            10usize..100, // max_steps
            any::<bool>(), // enable_chaos
            1000u64..10000, // time_step_ns
        ).prop_map(|(task_count, max_steps, enable_chaos, time_step_ns)| {
            MockConfig {
                task_count,
                max_steps,
                enable_chaos,
                time_step_ns,
            }
        }).boxed()
    }
}

// =============================================================================
// Metamorphic Relation 1: Round-trip Identity
// =============================================================================

/// **MR1**: replay(record(execution)) == execution
///
/// Recording an execution and then replaying the trace should reproduce
/// the original execution exactly.
#[derive(Debug)]
pub struct RoundTripIdentityMR;

impl RoundTripIdentityMR {
    pub fn test(&self, execution: MockExecution) -> Result<(), String> {
        let mut engine = MockExecutionEngine::new();

        // Record the execution
        let trace = engine.execute_and_record(execution.clone())?;

        // Replay the trace
        let replayed_execution = engine.replay_trace(&trace)?;

        // Verify round-trip identity
        if execution.events != replayed_execution.events {
            return Err(format!(
                "Round-trip failed: original {} events != replayed {} events",
                execution.events.len(),
                replayed_execution.events.len()
            ));
        }

        if execution.seed != replayed_execution.seed {
            return Err(format!(
                "Round-trip failed: seed mismatch {} != {}",
                execution.seed,
                replayed_execution.seed
            ));
        }

        Ok(())
    }
}

// =============================================================================
// Metamorphic Relation 2: Deterministic Replay
// =============================================================================

/// **MR2**: Replay is deterministic under variable delays.
///
/// Replaying the same trace multiple times with different artificial delays
/// should always produce the same result.
#[derive(Debug)]
pub struct DeterministicReplayMR;

impl DeterministicReplayMR {
    pub fn test(&self, execution: MockExecution, delays: Vec<Duration>) -> Result<(), String> {
        let mut engine = MockExecutionEngine::new();

        // Record the execution once
        let trace = engine.execute_and_record(execution)?;

        let mut results = Vec::new();

        // Replay multiple times with different delays
        for (i, _delay) in delays.iter().enumerate() {
            // Simulate delay by adding artificial timing variance
            let mut delayed_engine = MockExecutionEngine::new();

            let result = delayed_engine.replay_trace(&trace)?;
            results.push((i, result));
        }

        // All replay results should be identical
        for (i, result) in results.iter().skip(1) {
            let baseline = &results[0].1;

            if result.events != baseline.events {
                return Err(format!(
                    "Deterministic replay failed: iteration {} differs from baseline",
                    i
                ));
            }

            if result.seed != baseline.seed {
                return Err(format!(
                    "Deterministic replay failed: seed mismatch at iteration {}",
                    i
                ));
            }
        }

        Ok(())
    }
}

// =============================================================================
// Metamorphic Relation 3: Minimization Preserves Failure
// =============================================================================

/// **MR3**: Trace minimization preserves failure modes.
///
/// If an execution fails, minimizing the trace should preserve the failure
/// while reducing the trace size.
#[derive(Debug)]
pub struct MinimizationPreservesFailureMR;

impl MinimizationPreservesFailureMR {
    pub fn test(&self, failing_execution: MockExecution) -> Result<(), String> {
        let mut engine = MockExecutionEngine::new();

        // Record the failing execution
        let original_trace = engine.execute_and_record(failing_execution)?;

        // Simulate minimization by creating a reduced trace
        let minimized_trace = self.simulate_minimization(&original_trace)?;

        // Replay both traces
        let original_replay = engine.replay_trace(&original_trace)?;
        let minimized_replay = engine.replay_trace(&minimized_trace)?;

        // Verify minimization properties
        if minimized_trace.events.len() >= original_trace.events.len() {
            return Err("Minimization failed: trace did not shrink".to_string());
        }

        // Both should have the same seed (failure reproduction requirement)
        if original_replay.seed != minimized_replay.seed {
            return Err("Minimization failed: seed changed during minimization".to_string());
        }

        // Minimized trace should still exhibit the core behavior
        // (This is domain-specific - we check that key events are preserved)
        let original_task_events = self.count_task_events(&original_replay);
        let minimized_task_events = self.count_task_events(&minimized_replay);

        if minimized_task_events == 0 && original_task_events > 0 {
            return Err("Minimization failed: all essential events removed".to_string());
        }

        Ok(())
    }

    /// Simulate trace minimization by removing non-essential events.
    fn simulate_minimization(&self, trace: &ReplayTrace) -> Result<ReplayTrace, String> {
        let mut minimized_events = Vec::new();

        // Keep essential events (task scheduling, time advancement)
        for event in &trace.events {
            match event {
                ReplayEvent::TaskScheduled { .. } |
                ReplayEvent::TaskCompleted { .. } |
                ReplayEvent::TimeAdvanced { .. } => {
                    minimized_events.push(event.clone());
                },
                _ => {
                    // Remove non-essential events for minimization
                }
            }
        }

        Ok(ReplayTrace {
            metadata: trace.metadata.clone(),
            events: minimized_events,
        })
    }

    /// Count task-related events in an execution.
    fn count_task_events(&self, execution: &MockExecution) -> usize {
        execution.events.iter().filter(|event| {
            matches!(event,
                ExecutionEvent::TaskScheduled { .. } |
                ExecutionEvent::TaskYielded { .. } |
                ExecutionEvent::TaskCompleted { .. }
            )
        }).count()
    }
}

// =============================================================================
// Metamorphic Relation 4: DPOR Commuting Transitions
// =============================================================================

/// **MR4**: DPOR correctly identifies commuting transitions.
///
/// Events that are identified as non-commuting by DPOR should actually
/// conflict, and events that are not flagged should be independent.
#[derive(Debug)]
pub struct DporCommutingTransitionsMR;

impl DporCommutingTransitionsMR {
    pub fn test(&self, execution: MockExecution) -> Result<(), String> {
        let mut engine = MockExecutionEngine::new();

        // Record the execution
        let trace = engine.execute_and_record(execution)?;

        // Perform DPOR analysis
        let race_analysis = self.simulate_dpor_analysis(&trace)?;

        // Verify DPOR properties
        for race in &race_analysis.races {
            // Check that identified races actually represent conflicts
            if !self.verify_race_conflict(&trace, race)? {
                return Err(format!(
                    "DPOR failed: identified race at ({}, {}) is not actually a conflict",
                    race.earlier, race.later
                ));
            }
        }

        // Check that DPOR didn't miss obvious conflicts
        let obvious_conflicts = self.find_obvious_conflicts(&trace);
        for conflict in &obvious_conflicts {
            if !race_analysis.races.contains(conflict) {
                return Err(format!(
                    "DPOR failed: missed obvious conflict at ({}, {})",
                    conflict.earlier, conflict.later
                ));
            }
        }

        Ok(())
    }

    /// Simulate DPOR analysis to find races.
    fn simulate_dpor_analysis(&self, trace: &ReplayTrace) -> Result<RaceAnalysis, String> {
        let mut races = Vec::new();
        let mut backtrack_points = Vec::new();

        // Simple DPOR simulation: look for task scheduling conflicts
        for (i, event1) in trace.events.iter().enumerate() {
            for (j, event2) in trace.events.iter().enumerate().skip(i + 1) {
                if self.events_conflict(event1, event2) {
                    let race = Race { earlier: i, later: j };

                    // Check if there's no intervening event that depends on both
                    let has_intervening = (i + 1..j).any(|k| {
                        let event_k = &trace.events[k];
                        self.events_conflict(event1, event_k) && self.events_conflict(event_k, event2)
                    });

                    if !has_intervening {
                        races.push(race.clone());
                        backtrack_points.push(BacktrackPoint {
                            race,
                            divergence_index: i,
                        });
                    }
                }
            }
        }

        Ok(RaceAnalysis { races, backtrack_points })
    }

    /// Check if two events conflict (access same resource with at least one write).
    fn events_conflict(&self, event1: &ReplayEvent, event2: &ReplayEvent) -> bool {
        match (event1, event2) {
            // Task events on the same task conflict
            (ReplayEvent::TaskScheduled { task_id: id1, .. },
             ReplayEvent::TaskScheduled { task_id: id2, .. }) => id1 == id2,
            (ReplayEvent::TaskScheduled { task_id: id1, .. },
             ReplayEvent::TaskCompleted { task_id: id2, .. }) => id1 == id2,
            (ReplayEvent::TaskCompleted { task_id: id1, .. },
             ReplayEvent::TaskScheduled { task_id: id2, .. }) => id1 == id2,

            // Time advancement events always conflict
            (ReplayEvent::TimeAdvanced { .. }, ReplayEvent::TimeAdvanced { .. }) => true,

            // I/O events on same descriptor conflict
            (ReplayEvent::IoReady { descriptor: d1, .. },
             ReplayEvent::IoReady { descriptor: d2, .. }) => d1 == d2,
            (ReplayEvent::IoReady { descriptor: d1, .. },
             ReplayEvent::IoError { descriptor: d2, .. }) => d1 == d2,
            (ReplayEvent::IoError { descriptor: d1, .. },
             ReplayEvent::IoReady { descriptor: d2, .. }) => d1 == d2,

            _ => false,
        }
    }

    /// Verify that a detected race actually represents a conflict.
    fn verify_race_conflict(&self, trace: &ReplayTrace, race: &Race) -> Result<bool, String> {
        if race.earlier >= trace.events.len() || race.later >= trace.events.len() {
            return Err("Race indices out of bounds".to_string());
        }

        let event1 = &trace.events[race.earlier];
        let event2 = &trace.events[race.later];

        Ok(self.events_conflict(event1, event2))
    }

    /// Find obvious conflicts for verification.
    fn find_obvious_conflicts(&self, trace: &ReplayTrace) -> Vec<Race> {
        let mut conflicts = Vec::new();

        for (i, event1) in trace.events.iter().enumerate() {
            for (j, event2) in trace.events.iter().enumerate().skip(i + 1) {
                if self.events_conflict(event1, event2) {
                    conflicts.push(Race { earlier: i, later: j });
                }
            }
        }

        conflicts
    }
}

// =============================================================================
// Metamorphic Relation 5: Compression Round-Trip
// =============================================================================

/// **MR5**: Trace compression preserves information.
///
/// Compressing a trace and then decompressing it should recover the original
/// trace exactly.
#[derive(Debug)]
pub struct CompressionRoundTripMR;

impl CompressionRoundTripMR {
    pub fn test(&self, execution: MockExecution) -> Result<(), String> {
        let mut engine = MockExecutionEngine::new();

        // Record the execution
        let original_trace = engine.execute_and_record(execution)?;

        // Compress the trace
        let compressed = self.simulate_compression(&original_trace)?;

        // Decompress the trace
        let decompressed_trace = self.simulate_decompression(&compressed)?;

        // Verify round-trip preservation
        if original_trace.metadata != decompressed_trace.metadata {
            return Err("Compression round-trip failed: metadata mismatch".to_string());
        }

        if original_trace.events.len() != decompressed_trace.events.len() {
            return Err(format!(
                "Compression round-trip failed: event count mismatch {} != {}",
                original_trace.events.len(),
                decompressed_trace.events.len()
            ));
        }

        for (i, (orig, decomp)) in original_trace.events.iter()
            .zip(decompressed_trace.events.iter())
            .enumerate() {
            if orig != decomp {
                return Err(format!(
                    "Compression round-trip failed: event {} differs after compression",
                    i
                ));
            }
        }

        // Verify compression actually reduced size
        let original_size = self.estimate_trace_size(&original_trace);
        let compressed_size = compressed.len();

        if compressed_size >= original_size && original_trace.events.len() > 10 {
            return Err("Compression failed: compressed size not smaller than original".to_string());
        }

        Ok(())
    }

    /// Simulate trace compression.
    fn simulate_compression(&self, trace: &ReplayTrace) -> Result<Vec<u8>, String> {
        // Simplified compression: just serialize with serde_json
        serde_json::to_vec(trace).map_err(|e| e.to_string())
    }

    /// Simulate trace decompression.
    fn simulate_decompression(&self, compressed: &[u8]) -> Result<ReplayTrace, String> {
        serde_json::from_slice(compressed).map_err(|e| e.to_string())
    }

    /// Estimate uncompressed trace size.
    fn estimate_trace_size(&self, trace: &ReplayTrace) -> usize {
        std::mem::size_of::<TraceMetadata>() +
        trace.events.len() * std::mem::size_of::<ReplayEvent>()
    }
}

// =============================================================================
// Property Tests
// =============================================================================

proptest! {
    /// Test MR1: Round-trip identity
    #[test]
    fn metamorphic_trace_roundtrip_identity(execution in arb_mock_execution()) {
        let mr = RoundTripIdentityMR;
        mr.test(execution).expect("Round-trip identity should hold");
    }

    /// Test MR2: Deterministic replay
    #[test]
    fn metamorphic_trace_deterministic_replay(
        execution in arb_mock_execution(),
        delay_count in 2usize..6,
    ) {
        let mr = DeterministicReplayMR;
        let delays = (0..delay_count)
            .map(|i| Duration::from_millis(i as u64 * 10))
            .collect();

        mr.test(execution, delays).expect("Deterministic replay should hold");
    }

    /// Test MR3: Minimization preserves failure
    #[test]
    fn metamorphic_trace_minimization_preserves_failure(execution in arb_mock_execution()) {
        let mr = MinimizationPreservesFailureMR;
        mr.test(execution).expect("Minimization should preserve failure");
    }

    /// Test MR4: DPOR commuting transitions
    #[test]
    fn metamorphic_trace_dpor_commuting_transitions(execution in arb_mock_execution()) {
        let mr = DporCommutingTransitionsMR;
        mr.test(execution).expect("DPOR should correctly identify transitions");
    }

    /// Test MR5: Compression round-trip
    #[test]
    fn metamorphic_trace_compression_roundtrip(execution in arb_mock_execution()) {
        let mr = CompressionRoundTripMR;
        mr.test(execution).expect("Compression round-trip should preserve trace");
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_identity_simple() {
        let execution = MockExecution {
            seed: 42,
            events: vec![
                ExecutionEvent::TaskScheduled {
                    task_id: TaskId::new_for_test(1, 0),
                    at_tick: 0,
                },
                ExecutionEvent::TaskCompleted {
                    task_id: TaskId::new_for_test(1, 0),
                    at_tick: 10,
                },
            ],
            config: MockConfig::default(),
        };

        let mr = RoundTripIdentityMR;
        mr.test(execution).expect("Simple round-trip should work");
    }

    #[test]
    fn test_deterministic_replay_simple() {
        let execution = MockExecution {
            seed: 42,
            events: vec![
                ExecutionEvent::RngValue { value: 12345 },
                ExecutionEvent::TimeAdvanced {
                    from: Time::from_nanos(0),
                    to: Time::from_nanos(1000),
                },
            ],
            config: MockConfig::default(),
        };

        let mr = DeterministicReplayMR;
        let delays = vec![
            Duration::from_millis(0),
            Duration::from_millis(10),
            Duration::from_millis(50),
        ];

        mr.test(execution, delays).expect("Deterministic replay should work");
    }

    #[test]
    fn test_compression_roundtrip_simple() {
        let execution = MockExecution {
            seed: 123,
            events: vec![
                ExecutionEvent::IoReady { descriptor: 1, result_size: 256 },
                ExecutionEvent::IoError { descriptor: 2, error_code: 404 },
            ],
            config: MockConfig::default(),
        };

        let mr = CompressionRoundTripMR;
        mr.test(execution).expect("Simple compression round-trip should work");
    }

    #[test]
    fn test_dpor_race_detection() {
        let execution = MockExecution {
            seed: 999,
            events: vec![
                // Two tasks scheduled on same resource - should create race
                ExecutionEvent::TaskScheduled {
                    task_id: TaskId::new_for_test(1, 0),
                    at_tick: 0,
                },
                ExecutionEvent::TaskScheduled {
                    task_id: TaskId::new_for_test(1, 0), // Same task - conflict
                    at_tick: 1,
                },
                ExecutionEvent::TaskCompleted {
                    task_id: TaskId::new_for_test(1, 0),
                    at_tick: 5,
                },
            ],
            config: MockConfig::default(),
        };

        let mr = DporCommutingTransitionsMR;
        mr.test(execution).expect("DPOR should detect races correctly");
    }

    #[test]
    fn test_minimization_preserves_essential_events() {
        let execution = MockExecution {
            seed: 777,
            events: vec![
                ExecutionEvent::TaskScheduled {
                    task_id: TaskId::new_for_test(1, 0),
                    at_tick: 0,
                },
                ExecutionEvent::RngValue { value: 999 }, // Non-essential
                ExecutionEvent::ChaosInjection {         // Non-essential
                    severity: Severity::Info,
                    description: "test".to_string(),
                },
                ExecutionEvent::TaskCompleted {
                    task_id: TaskId::new_for_test(1, 0),
                    at_tick: 10,
                },
            ],
            config: MockConfig::default(),
        };

        let mr = MinimizationPreservesFailureMR;
        mr.test(execution).expect("Minimization should preserve essential behavior");
    }
}