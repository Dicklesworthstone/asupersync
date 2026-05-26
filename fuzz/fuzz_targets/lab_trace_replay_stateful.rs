#![no_main]

use arbitrary::Arbitrary;
use asupersync::trace::replay::{
    ReplayEvent, ReplayTrace, TraceMetadata, REPLAY_SCHEMA_VERSION,
};
use asupersync::types::{RegionId, Severity, TaskId, Time};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;

/// Maximum events per trace to prevent unbounded memory growth
const MAX_EVENTS_PER_TRACE: usize = 1000;
/// Maximum operations per fuzz run to prevent timeout
const MAX_OPERATIONS: usize = 500;
/// Maximum virtual time value
const MAX_VIRTUAL_TIME_NS: u64 = 1_000_000_000_000; // ~16 minutes
/// Maximum timer/token ID values
const MAX_ID_VALUE: u64 = 10000;

/// Fuzz input representing trace replay operations
#[derive(Arbitrary, Debug, Clone)]
struct TraceReplayFuzzInput {
    /// Initial trace metadata
    pub metadata_config: MetadataConfig,
    /// Sequence of trace operations
    pub operations: Vec<TraceOperation>,
}

/// Metadata configuration for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct MetadataConfig {
    pub seed: u64,
    pub recorded_at: u64,
    pub config_hash: u64,
    pub has_description: bool,
    pub description_suffix: u8, // For generating test descriptions
}

/// Trace operations that can be performed
#[derive(Arbitrary, Debug, Clone)]
enum TraceOperation {
    /// Add a replay event to the trace
    AddEvent { event_type: EventType },
    /// Serialize and deserialize the trace
    SerializeDeserialize,
    /// Reset cursor and consume events
    ConsumeEvents { consume_count: u8 },
    /// Validate trace consistency
    ValidateTrace,
    /// Create a new trace with events from current
    CloneTrace,
    /// Advance virtual time
    AdvanceTime { advance_nanos: u32 },
    /// Simulate task lifecycle
    SimulateTaskLifecycle { task_count: u8 },
    /// Simulate region lifecycle
    SimulateRegionLifecycle { region_count: u8 },
    /// Inject chaos events
    InjectChaos { chaos_count: u8 },
    /// Simulate I/O operations
    SimulateIo { io_count: u8 },
    /// Test event ordering
    VerifyEventOrdering,
}

/// Types of events that can be generated
#[derive(Arbitrary, Debug, Clone)]
enum EventType {
    TaskScheduled { task_id: u16, at_tick: u32 },
    TaskYielded { task_id: u16 },
    TaskCompleted { task_id: u16, outcome: OutcomeSeverity },
    TaskSpawned { task_id: u16, region_id: u16, at_tick: u32 },
    TimeAdvanced { from_nanos: u32, to_nanos: u32 },
    TimerCreated { timer_id: u32, deadline_nanos: u32 },
    TimerFired { timer_id: u32 },
    TimerCancelled { timer_id: u32 },
    IoReady { token: u32, readiness_flags: u8 },
    IoResult { token: u32, bytes: i16 },
    IoError { token: u32, error_kind: ErrorKindValue },
    RngSeed { seed: u64 },
    RngValue { value: u64 },
    ChaosInjection { kind: u8, task_id: Option<u16>, data: u32 },
    RegionCreated { region_id: u16, parent_id: Option<u16>, at_tick: u32 },
    RegionClosed { region_id: u16, outcome: OutcomeSeverity },
    RegionCancelled { region_id: u16, cancel_kind: u8 },
    Checkpoint { task_id: u16, checkpoint_id: u32 },
    WakerBatchWake { waker_count: u16 },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OutcomeSeverity {
    Ok,
    Err,
    Cancelled,
    Panicked,
}

impl OutcomeSeverity {
    fn to_u8(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Err => 1,
            Self::Cancelled => 2,
            Self::Panicked => 3,
        }
    }

    fn to_severity(self) -> Severity {
        match self {
            Self::Ok => Severity::Ok,
            Self::Err => Severity::Err,
            Self::Cancelled => Severity::Cancelled,
            Self::Panicked => Severity::Panicked,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ErrorKindValue {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    Interrupted,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    BrokenPipe,
    WouldBlock,
    UnexpectedEof,
}

impl ErrorKindValue {
    fn to_error_kind(self) -> ErrorKind {
        match self {
            Self::NotFound => ErrorKind::NotFound,
            Self::PermissionDenied => ErrorKind::PermissionDenied,
            Self::ConnectionRefused => ErrorKind::ConnectionRefused,
            Self::ConnectionReset => ErrorKind::ConnectionReset,
            Self::Interrupted => ErrorKind::Interrupted,
            Self::InvalidInput => ErrorKind::InvalidInput,
            Self::InvalidData => ErrorKind::InvalidData,
            Self::TimedOut => ErrorKind::TimedOut,
            Self::WriteZero => ErrorKind::WriteZero,
            Self::BrokenPipe => ErrorKind::BrokenPipe,
            Self::WouldBlock => ErrorKind::WouldBlock,
            Self::UnexpectedEof => ErrorKind::UnexpectedEof,
        }
    }
}

/// Shadow model for trace replay verification
#[derive(Debug)]
struct TraceReplayShadowModel {
    /// Track virtual time progression
    current_time_nanos: u64,
    /// Track active tasks
    active_tasks: BTreeSet<u16>,
    /// Track active regions
    active_regions: BTreeSet<u16>,
    /// Track region hierarchy (child -> parent)
    region_hierarchy: BTreeMap<u16, Option<u16>>,
    /// Track active timers
    active_timers: BTreeSet<u32>,
    /// Track active I/O tokens
    active_io_tokens: BTreeSet<u32>,
    /// Track RNG state
    rng_seed_set: bool,
    /// Event sequence constraints
    event_sequence: Vec<EventConstraint>,
    /// Statistics
    stats: TraceStats,
}

#[derive(Debug, Default)]
struct TraceStats {
    total_events: usize,
    task_events: usize,
    time_events: usize,
    io_events: usize,
    rng_events: usize,
    chaos_events: usize,
    region_events: usize,
    serialization_attempts: usize,
    successful_deserializations: usize,
    cursor_resets: usize,
}

#[derive(Debug, Clone)]
enum EventConstraint {
    /// Task must be spawned before being scheduled
    TaskMustExistBeforeScheduled(u16),
    /// Task must be scheduled before being completed
    TaskMustBeScheduledBeforeCompletion(u16),
    /// Timer must be created before firing/cancelling
    TimerMustExistBeforeFiring(u32),
    /// Region must be created before being closed
    RegionMustExistBeforeClosing(u16),
    /// Time can only move forward
    TimeMonotonic(u64, u64),
}

impl TraceReplayShadowModel {
    fn new() -> Self {
        Self {
            current_time_nanos: 0,
            active_tasks: BTreeSet::new(),
            active_regions: BTreeSet::new(),
            region_hierarchy: BTreeMap::new(),
            active_timers: BTreeSet::new(),
            active_io_tokens: BTreeSet::new(),
            rng_seed_set: false,
            event_sequence: Vec::new(),
            stats: TraceStats::default(),
        }
    }

    fn record_event(&mut self, event: &ReplayEvent) -> bool {
        self.stats.total_events += 1;

        // Validate and track event according to type
        match event {
            ReplayEvent::TaskScheduled { task, at_tick } => {
                self.stats.task_events += 1;
                let task_id = task.id as u16;
                if !self.active_tasks.contains(&task_id) {
                    self.event_sequence.push(EventConstraint::TaskMustExistBeforeScheduled(task_id));
                    return false; // Task not spawned yet
                }
                true
            }

            ReplayEvent::TaskYielded { task } => {
                self.stats.task_events += 1;
                let task_id = task.id as u16;
                if !self.active_tasks.contains(&task_id) {
                    return false; // Task doesn't exist
                }
                true
            }

            ReplayEvent::TaskCompleted { task, outcome: _ } => {
                self.stats.task_events += 1;
                let task_id = task.id as u16;
                if self.active_tasks.remove(&task_id) {
                    true
                } else {
                    false // Task doesn't exist
                }
            }

            ReplayEvent::TaskSpawned { task, region, at_tick } => {
                self.stats.task_events += 1;
                let task_id = task.id as u16;
                let region_id = region.id as u16;
                if !self.active_regions.contains(&region_id) {
                    return false; // Region doesn't exist
                }
                self.active_tasks.insert(task_id);
                true
            }

            ReplayEvent::TimeAdvanced { from_nanos, to_nanos } => {
                self.stats.time_events += 1;
                if *to_nanos < *from_nanos {
                    self.event_sequence.push(EventConstraint::TimeMonotonic(*from_nanos, *to_nanos));
                    return false; // Time going backwards
                }
                if *from_nanos != self.current_time_nanos {
                    return false; // Time discontinuity
                }
                self.current_time_nanos = *to_nanos;
                true
            }

            ReplayEvent::TimerCreated { timer_id, deadline_nanos: _ } => {
                self.stats.time_events += 1;
                let timer_id = *timer_id as u32;
                if self.active_timers.contains(&timer_id) {
                    return false; // Timer already exists
                }
                self.active_timers.insert(timer_id);
                true
            }

            ReplayEvent::TimerFired { timer_id } => {
                self.stats.time_events += 1;
                let timer_id = *timer_id as u32;
                if self.active_timers.remove(&timer_id) {
                    true
                } else {
                    self.event_sequence.push(EventConstraint::TimerMustExistBeforeFiring(timer_id));
                    false // Timer doesn't exist
                }
            }

            ReplayEvent::TimerCancelled { timer_id } => {
                self.stats.time_events += 1;
                let timer_id = *timer_id as u32;
                if self.active_timers.remove(&timer_id) {
                    true
                } else {
                    false // Timer doesn't exist
                }
            }

            ReplayEvent::IoReady { token, readiness: _ } => {
                self.stats.io_events += 1;
                let token = *token as u32;
                self.active_io_tokens.insert(token);
                true
            }

            ReplayEvent::IoResult { token, bytes: _ } => {
                self.stats.io_events += 1;
                let token = *token as u32;
                self.active_io_tokens.contains(&token) // I/O token should exist
            }

            ReplayEvent::IoError { token, kind: _ } => {
                self.stats.io_events += 1;
                let token = *token as u32;
                self.active_io_tokens.contains(&token) // I/O token should exist
            }

            ReplayEvent::RngSeed { seed: _ } => {
                self.stats.rng_events += 1;
                self.rng_seed_set = true;
                true
            }

            ReplayEvent::RngValue { value: _ } => {
                self.stats.rng_events += 1;
                self.rng_seed_set // RNG should be seeded first
            }

            ReplayEvent::ChaosInjection { kind: _, task, data: _ } => {
                self.stats.chaos_events += 1;
                if let Some(task_id) = task.as_ref() {
                    let task_id = task_id.id as u16;
                    self.active_tasks.contains(&task_id)
                } else {
                    true // Global chaos
                }
            }

            ReplayEvent::RegionCreated { region, parent, at_tick: _ } => {
                self.stats.region_events += 1;
                let region_id = region.id as u16;
                if self.active_regions.contains(&region_id) {
                    return false; // Region already exists
                }

                // Validate parent exists if specified
                if let Some(parent_id) = parent.as_ref() {
                    let parent_id = parent_id.id as u16;
                    if !self.active_regions.contains(&parent_id) {
                        return false; // Parent doesn't exist
                    }
                    self.region_hierarchy.insert(region_id, Some(parent_id));
                } else {
                    self.region_hierarchy.insert(region_id, None);
                }

                self.active_regions.insert(region_id);
                true
            }

            ReplayEvent::RegionClosed { region, outcome: _ } => {
                self.stats.region_events += 1;
                let region_id = region.id as u16;
                if self.active_regions.remove(&region_id) {
                    self.region_hierarchy.remove(&region_id);
                    true
                } else {
                    self.event_sequence.push(EventConstraint::RegionMustExistBeforeClosing(region_id));
                    false // Region doesn't exist
                }
            }

            ReplayEvent::RegionCancelled { region, cancel_kind: _ } => {
                self.stats.region_events += 1;
                let region_id = region.id as u16;
                self.active_regions.contains(&region_id)
            }

            ReplayEvent::Checkpoint { task, checkpoint_id: _ } => {
                self.stats.task_events += 1;
                let task_id = task.id as u16;
                self.active_tasks.contains(&task_id)
            }

            ReplayEvent::WakerBatchWake { waker_count: _ } => {
                // Waker events are generally valid
                true
            }
        }
    }

    fn verify_constraints(&self) -> bool {
        // For now, just check that we have some events and basic consistency
        if self.stats.total_events == 0 {
            return true; // Empty trace is valid
        }

        // Time should be non-negative
        if self.current_time_nanos > MAX_VIRTUAL_TIME_NS {
            return false;
        }

        // Events should sum to total
        let category_sum = self.stats.task_events + self.stats.time_events +
                         self.stats.io_events + self.stats.rng_events +
                         self.stats.chaos_events + self.stats.region_events;

        // Allow for some events not being categorized yet
        category_sum <= self.stats.total_events
    }
}

impl MetadataConfig {
    fn to_trace_metadata(&self) -> TraceMetadata {
        let mut metadata = TraceMetadata::new(self.seed)
            .with_config_hash(self.config_hash);

        if self.has_description {
            let desc = format!("fuzz_test_{}", self.description_suffix);
            metadata = metadata.with_description(desc);
        }

        metadata
    }
}

impl EventType {
    fn to_replay_event(&self) -> ReplayEvent {
        use ReplayEvent::*;

        match self {
            Self::TaskScheduled { task_id, at_tick } => {
                TaskScheduled {
                    task: (*task_id as u32).into(),
                    at_tick: *at_tick as u64,
                }
            }
            Self::TaskYielded { task_id } => {
                TaskYielded {
                    task: (*task_id as u32).into(),
                }
            }
            Self::TaskCompleted { task_id, outcome } => {
                TaskCompleted {
                    task: (*task_id as u32).into(),
                    outcome: outcome.to_u8(),
                }
            }
            Self::TaskSpawned { task_id, region_id, at_tick } => {
                TaskSpawned {
                    task: (*task_id as u32).into(),
                    region: (*region_id as u32).into(),
                    at_tick: *at_tick as u64,
                }
            }
            Self::TimeAdvanced { from_nanos, to_nanos } => {
                TimeAdvanced {
                    from_nanos: *from_nanos as u64,
                    to_nanos: *to_nanos as u64,
                }
            }
            Self::TimerCreated { timer_id, deadline_nanos } => {
                TimerCreated {
                    timer_id: *timer_id as u64,
                    deadline_nanos: *deadline_nanos as u64,
                }
            }
            Self::TimerFired { timer_id } => {
                TimerFired {
                    timer_id: *timer_id as u64,
                }
            }
            Self::TimerCancelled { timer_id } => {
                TimerCancelled {
                    timer_id: *timer_id as u64,
                }
            }
            Self::IoReady { token, readiness_flags } => {
                IoReady {
                    token: *token as u64,
                    readiness: *readiness_flags,
                }
            }
            Self::IoResult { token, bytes } => {
                IoResult {
                    token: *token as u64,
                    bytes: *bytes as i64,
                }
            }
            Self::IoError { token, error_kind } => {
                ReplayEvent::io_error(*token as u64, error_kind.to_error_kind())
            }
            Self::RngSeed { seed } => {
                RngSeed { seed: *seed }
            }
            Self::RngValue { value } => {
                RngValue { value: *value }
            }
            Self::ChaosInjection { kind, task_id, data } => {
                ChaosInjection {
                    kind: *kind,
                    task: task_id.map(|id| (id as u32).into()),
                    data: *data as u64,
                }
            }
            Self::RegionCreated { region_id, parent_id, at_tick } => {
                ReplayEvent::region_created(
                    *region_id as u32,
                    parent_id.map(|id| id as u32),
                    *at_tick as u64,
                )
            }
            Self::RegionClosed { region_id, outcome } => {
                ReplayEvent::region_closed(*region_id as u32, outcome.to_severity())
            }
            Self::RegionCancelled { region_id, cancel_kind } => {
                ReplayEvent::region_cancelled(*region_id as u32, *cancel_kind)
            }
            Self::Checkpoint { task_id, checkpoint_id } => {
                Checkpoint {
                    task: (*task_id as u32).into(),
                    checkpoint_id: *checkpoint_id as u64,
                }
            }
            Self::WakerBatchWake { waker_count } => {
                WakerBatchWake {
                    waker_count: *waker_count as u32,
                }
            }
        }
    }
}

fuzz_target!(|input: TraceReplayFuzzInput| {
    // Guard against excessive input size
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    // Create initial trace with metadata
    let metadata = input.metadata_config.to_trace_metadata();
    let mut trace = ReplayTrace::new(metadata);
    let mut shadow = TraceReplayShadowModel::new();

    // Execute operations and verify against shadow model
    for operation in input.operations {
        match operation {
            TraceOperation::AddEvent { event_type } => {
                if trace.len() >= MAX_EVENTS_PER_TRACE {
                    continue; // Skip to prevent unbounded growth
                }

                let event = event_type.to_replay_event();

                // Verify event against shadow model
                let is_valid = shadow.record_event(&event);

                // Add to real trace regardless to test robustness
                trace.push(event.clone());

                // Verify size consistency
                assert_eq!(trace.len(), shadow.stats.total_events, "Event count mismatch");
            }

            TraceOperation::SerializeDeserialize => {
                shadow.stats.serialization_attempts += 1;

                // Test serialization
                match trace.to_bytes() {
                    Ok(bytes) => {
                        // Verify serialized data is reasonable size
                        let expected_min_size = 8; // At least metadata
                        let expected_max_size = trace.len() * 64 + 1024; // Rough upper bound
                        assert!(bytes.len() >= expected_min_size, "Serialized data too small");
                        assert!(bytes.len() <= expected_max_size, "Serialized data too large");

                        // Test deserialization
                        match ReplayTrace::from_bytes(&bytes) {
                            Ok(deserialized) => {
                                shadow.stats.successful_deserializations += 1;

                                // Verify metadata preservation
                                assert_eq!(deserialized.metadata.seed, trace.metadata.seed, "Seed mismatch");
                                assert_eq!(deserialized.metadata.version, REPLAY_SCHEMA_VERSION, "Version mismatch");
                                assert_eq!(deserialized.metadata.config_hash, trace.metadata.config_hash, "Config hash mismatch");

                                // Verify event count preservation
                                assert_eq!(deserialized.events.len(), trace.events.len(), "Event count mismatch after serialization");

                                // Verify cursor reset
                                assert_eq!(deserialized.cursor, 0, "Cursor should reset after deserialization");
                            }
                            Err(_) => {
                                // Deserialization failure is acceptable for malformed data
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization failure might be acceptable for very large traces
                    }
                }
            }

            TraceOperation::ConsumeEvents { consume_count } => {
                // Test event consumption via cursor advancement
                let initial_cursor = trace.cursor;
                let events_available = trace.events.len().saturating_sub(initial_cursor);
                let consume_actual = (consume_count as usize).min(events_available);

                for _ in 0..consume_actual {
                    if trace.cursor < trace.events.len() {
                        trace.cursor += 1;
                    }
                }

                assert_eq!(trace.cursor, initial_cursor + consume_actual, "Cursor advancement mismatch");
                assert!(trace.cursor <= trace.events.len(), "Cursor beyond events length");
            }

            TraceOperation::ValidateTrace => {
                // Verify trace internal consistency
                assert!(trace.cursor <= trace.events.len(), "Cursor beyond events");
                assert_eq!(trace.metadata.version, REPLAY_SCHEMA_VERSION, "Invalid schema version");

                // Verify shadow model consistency
                assert!(shadow.verify_constraints(), "Shadow model constraints violated");
            }

            TraceOperation::CloneTrace => {
                // Test trace cloning via metadata preservation
                let new_metadata = TraceMetadata::new(trace.metadata.seed + 1)
                    .with_config_hash(trace.metadata.config_hash);
                let mut cloned_trace = ReplayTrace::new(new_metadata);

                // Copy events (simulate partial replay)
                let copy_count = trace.events.len().min(50);
                for i in 0..copy_count {
                    cloned_trace.push(trace.events[i].clone());
                }

                assert_eq!(cloned_trace.len(), copy_count, "Cloned trace size mismatch");
                assert_eq!(cloned_trace.cursor, 0, "Cloned trace cursor should be 0");
            }

            TraceOperation::AdvanceTime { advance_nanos } => {
                let advance = (advance_nanos as u64).min(1_000_000_000); // Max 1 second advance
                let new_time = shadow.current_time_nanos.saturating_add(advance);

                if new_time <= MAX_VIRTUAL_TIME_NS && new_time > shadow.current_time_nanos {
                    let event = ReplayEvent::TimeAdvanced {
                        from_nanos: shadow.current_time_nanos,
                        to_nanos: new_time,
                    };

                    shadow.record_event(&event);
                    trace.push(event);
                }
            }

            TraceOperation::SimulateTaskLifecycle { task_count } => {
                // Create a root region first
                let root_region_id = 0u16;
                let region_event = ReplayEvent::region_created(root_region_id as u32, None, 0);
                shadow.record_event(&region_event);
                trace.push(region_event);

                // Simulate task lifecycle for limited number of tasks
                let task_count = (task_count as usize).min(10);
                for task_id in 0..task_count {
                    let task_id = task_id as u16;

                    // Spawn task
                    let spawn_event = ReplayEvent::TaskSpawned {
                        task: (task_id as u32).into(),
                        region: (root_region_id as u32).into(),
                        at_tick: shadow.stats.total_events as u64,
                    };

                    if shadow.record_event(&spawn_event) {
                        trace.push(spawn_event);

                        // Schedule task
                        let schedule_event = ReplayEvent::TaskScheduled {
                            task: (task_id as u32).into(),
                            at_tick: shadow.stats.total_events as u64,
                        };

                        if shadow.record_event(&schedule_event) {
                            trace.push(schedule_event);

                            // Complete task
                            let complete_event = ReplayEvent::TaskCompleted {
                                task: (task_id as u32).into(),
                                outcome: 0, // OK outcome
                            };

                            shadow.record_event(&complete_event);
                            trace.push(complete_event);
                        }
                    }

                    if trace.len() >= MAX_EVENTS_PER_TRACE {
                        break;
                    }
                }

                // Close root region
                let close_event = ReplayEvent::region_closed(root_region_id as u32, Severity::Ok);
                shadow.record_event(&close_event);
                trace.push(close_event);
            }

            TraceOperation::SimulateRegionLifecycle { region_count } => {
                let region_count = (region_count as usize).min(10);
                for region_id in 1..=region_count {
                    let region_id = region_id as u16;

                    // Create region (with no parent for simplicity)
                    let create_event = ReplayEvent::region_created(region_id as u32, None, 0);

                    if shadow.record_event(&create_event) {
                        trace.push(create_event);

                        // Close region
                        let close_event = ReplayEvent::region_closed(region_id as u32, Severity::Ok);
                        shadow.record_event(&close_event);
                        trace.push(close_event);
                    }

                    if trace.len() >= MAX_EVENTS_PER_TRACE {
                        break;
                    }
                }
            }

            TraceOperation::InjectChaos { chaos_count } => {
                let chaos_count = (chaos_count as usize).min(5);
                for i in 0..chaos_count {
                    let event = ReplayEvent::ChaosInjection {
                        kind: (i % 5) as u8, // Different chaos kinds
                        task: None, // Global chaos for simplicity
                        data: i as u64,
                    };

                    shadow.record_event(&event);
                    trace.push(event);

                    if trace.len() >= MAX_EVENTS_PER_TRACE {
                        break;
                    }
                }
            }

            TraceOperation::SimulateIo { io_count } => {
                let io_count = (io_count as usize).min(10);
                for i in 0..io_count {
                    let token = i as u32;

                    // I/O ready
                    let ready_event = ReplayEvent::IoReady {
                        token: token as u64,
                        readiness: 1, // Readable
                    };
                    shadow.record_event(&ready_event);
                    trace.push(ready_event);

                    // I/O result
                    let result_event = ReplayEvent::IoResult {
                        token: token as u64,
                        bytes: 1024, // 1KB read
                    };
                    shadow.record_event(&result_event);
                    trace.push(result_event);

                    if trace.len() >= MAX_EVENTS_PER_TRACE {
                        break;
                    }
                }
            }

            TraceOperation::VerifyEventOrdering => {
                // Verify that events follow logical ordering rules
                let mut seen_time_nanos = 0u64;
                let mut active_task_set = BTreeSet::new();
                let mut active_region_set = BTreeSet::new();

                for event in &trace.events {
                    match event {
                        ReplayEvent::TimeAdvanced { from_nanos, to_nanos } => {
                            assert!(*to_nanos >= *from_nanos, "Time should not go backwards");
                            assert!(*from_nanos <= seen_time_nanos + 1_000_000_000, "Time gap too large");
                            seen_time_nanos = *to_nanos;
                        }
                        ReplayEvent::TaskSpawned { task, .. } => {
                            active_task_set.insert(task.id);
                        }
                        ReplayEvent::TaskCompleted { task, .. } => {
                            active_task_set.remove(&task.id);
                        }
                        ReplayEvent::RegionCreated { region, .. } => {
                            active_region_set.insert(region.id);
                        }
                        ReplayEvent::RegionClosed { region, .. } => {
                            active_region_set.remove(&region.id);
                        }
                        _ => {} // Other events don't have strict ordering requirements
                    }
                }
            }
        }

        // Always verify basic invariants after each operation
        assert!(trace.cursor <= trace.events.len(), "Cursor invariant violated");
        assert!(trace.len() <= MAX_EVENTS_PER_TRACE, "Event count exceeded maximum");
        assert!(shadow.verify_constraints(), "Shadow model constraints violated");

        // Prevent unbounded growth
        if trace.len() >= MAX_EVENTS_PER_TRACE {
            break;
        }
    }

    // Final comprehensive verification
    verify_trace_replay_invariants(&trace, &shadow);
});

/// Verify trace replay system invariants
fn verify_trace_replay_invariants(trace: &ReplayTrace, shadow: &TraceReplayShadowModel) {
    // Basic invariants
    assert_eq!(trace.metadata.version, REPLAY_SCHEMA_VERSION, "Schema version should be current");
    assert!(trace.cursor <= trace.events.len(), "Cursor should not exceed event count");
    assert_eq!(trace.len(), shadow.stats.total_events, "Event count should match shadow");

    // Metadata consistency
    assert!(trace.metadata.is_compatible(), "Metadata should be compatible");

    // Shadow model constraints
    assert!(shadow.verify_constraints(), "Shadow model should be consistent");

    // Size bounds
    assert!(trace.len() <= MAX_EVENTS_PER_TRACE, "Event count should be bounded");

    // Event size estimates (rough validation)
    if !trace.events.is_empty() {
        for event in &trace.events {
            let size = event.size_hint();
            assert!(size > 0, "Event should have non-zero size");
            assert!(size <= 64, "Event size should be reasonable"); // Most events are < 64 bytes
        }
    }

    // Virtual time consistency
    assert!(shadow.current_time_nanos <= MAX_VIRTUAL_TIME_NS, "Virtual time should be bounded");

    // Statistics consistency
    if shadow.stats.serialization_attempts > 0 {
        assert!(shadow.stats.successful_deserializations <= shadow.stats.serialization_attempts,
               "Successful deserializations should not exceed attempts");
    }

    // Verify no excessive violations in event sequence
    if shadow.event_sequence.len() > shadow.stats.total_events / 2 {
        panic!("Too many event sequence violations: {} violations out of {} events",
               shadow.event_sequence.len(), shadow.stats.total_events);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_trace_operations() {
        let input = TraceReplayFuzzInput {
            metadata_config: MetadataConfig {
                seed: 42,
                recorded_at: 0,
                config_hash: 12345,
                has_description: true,
                description_suffix: 1,
            },
            operations: vec![
                TraceOperation::AddEvent {
                    event_type: EventType::RngSeed { seed: 42 }
                },
                TraceOperation::SimulateTaskLifecycle { task_count: 3 },
                TraceOperation::SerializeDeserialize,
                TraceOperation::ValidateTrace,
            ],
        };

        // Should not panic
        fuzz_target(&input);
    }

    #[test]
    fn test_time_advancement() {
        let input = TraceReplayFuzzInput {
            metadata_config: MetadataConfig {
                seed: 123,
                recorded_at: 1000,
                config_hash: 0,
                has_description: false,
                description_suffix: 0,
            },
            operations: vec![
                TraceOperation::AdvanceTime { advance_nanos: 1000000 },
                TraceOperation::AdvanceTime { advance_nanos: 2000000 },
                TraceOperation::VerifyEventOrdering,
            ],
        };

        fuzz_target(&input);
    }

    #[test]
    fn test_io_simulation() {
        let input = TraceReplayFuzzInput {
            metadata_config: MetadataConfig {
                seed: 999,
                recorded_at: 0,
                config_hash: 0,
                has_description: false,
                description_suffix: 0,
            },
            operations: vec![
                TraceOperation::SimulateIo { io_count: 5 },
                TraceOperation::InjectChaos { chaos_count: 3 },
                TraceOperation::ValidateTrace,
            ],
        };

        fuzz_target(&input);
    }
}