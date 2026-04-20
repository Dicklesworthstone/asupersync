//! Channel Flow Control Invariant Validator
//!
//! Ensures flow control mechanisms don't violate channel atomicity or cause deadlocks
//! when combined with cancellation and backpressure. This is critical for maintaining
//! the two-phase commit protocol integrity under load.
//!
//! # Flow Control Invariants
//!
//! 1. **Backpressure Safety**: Flow control never blocks reserve operations indefinitely
//! 2. **Cancel Compatibility**: Cancellation properly unblocks flow-controlled operations
//! 3. **Deadlock Prevention**: Circular wait conditions are detected and prevented
//! 4. **Atomicity Preservation**: Two-phase protocol remains atomic under backpressure
//! 5. **Resource Fairness**: Flow control doesn't cause starvation of any producers

use crate::types::{TaskId, Time};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

/// Configuration for flow control monitoring.
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    /// Enable real-time flow control verification.
    pub enable_verification: bool,
    /// Threshold for detecting potential deadlocks (seconds).
    pub deadlock_detection_threshold_s: u64,
    /// Maximum time to wait for flow control before flagging starvation.
    pub starvation_threshold_s: u64,
    /// Enable detailed flow control tracing (higher overhead).
    pub enable_detailed_tracing: bool,
    /// Maximum number of flow control events to track.
    pub max_tracked_events: usize,
    /// Enable deadlock prevention mechanisms.
    pub enable_deadlock_prevention: bool,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            enable_verification: true,
            deadlock_detection_threshold_s: 5,
            starvation_threshold_s: 10,
            enable_detailed_tracing: false,
            max_tracked_events: 10_000,
            enable_deadlock_prevention: true,
        }
    }
}

/// Types of flow control mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowControlType {
    /// Channel capacity limits (bounded channels).
    CapacityLimit,
    /// Backpressure from slow consumers.
    ConsumerBackpressure,
    /// Rate limiting on producers.
    RateLimit,
    /// Credit-based flow control.
    CreditBased,
    /// Window-based flow control.
    WindowBased,
}

/// Flow control events that can affect channel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowControlEvent {
    /// Producer blocked due to flow control.
    ProducerBlocked {
        channel_id: u64,
        task_id: TaskId,
        reason: FlowControlType,
        timestamp: Time,
    },
    /// Producer unblocked from flow control.
    ProducerUnblocked {
        channel_id: u64,
        task_id: TaskId,
        reason: FlowControlType,
        blocked_duration_ms: u64,
        timestamp: Time,
    },
    /// Consumer applying backpressure.
    BackpressureApplied {
        channel_id: u64,
        consumer_task: TaskId,
        queue_depth: usize,
        timestamp: Time,
    },
    /// Consumer releasing backpressure.
    BackpressureReleased {
        channel_id: u64,
        consumer_task: TaskId,
        new_queue_depth: usize,
        timestamp: Time,
    },
    /// Reserve operation blocked by flow control.
    ReserveBlocked {
        channel_id: u64,
        task_id: TaskId,
        permit_id: u64,
        timestamp: Time,
    },
    /// Reserve operation unblocked.
    ReserveUnblocked {
        channel_id: u64,
        task_id: TaskId,
        permit_id: u64,
        blocked_duration_ms: u64,
        timestamp: Time,
    },
    /// Commit operation affected by flow control.
    CommitFlowControlled {
        channel_id: u64,
        task_id: TaskId,
        permit_id: u64,
        timestamp: Time,
    },
    /// Abort operation due to flow control timeout.
    AbortDueToFlowControl {
        channel_id: u64,
        task_id: TaskId,
        permit_id: u64,
        timeout_reason: String,
        timestamp: Time,
    },
}

/// Flow control violations that compromise channel safety.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum FlowControlViolation {
    /// Potential deadlock detected in flow control.
    PotentialDeadlock {
        involved_channels: Vec<u64>,
        involved_tasks: Vec<TaskId>,
        cycle_description: String,
        detection_time: Time,
    },
    /// Producer starved by unfair flow control.
    ProducerStarvation {
        channel_id: u64,
        starved_task: TaskId,
        starvation_duration_s: u64,
        other_producers_served: usize,
        timestamp: Time,
    },
    /// Flow control violated atomicity of two-phase protocol.
    AtomicityViolation {
        channel_id: u64,
        task_id: TaskId,
        permit_id: u64,
        violation_type: String,
        timestamp: Time,
    },
    /// Flow control caused indefinite blocking.
    IndefiniteBlocking {
        channel_id: u64,
        blocked_task: TaskId,
        flow_control_type: FlowControlType,
        block_duration_s: u64,
        timestamp: Time,
    },
    /// Cancellation didn't properly unblock flow control.
    CancellationUnblockFailure {
        channel_id: u64,
        cancelled_task: TaskId,
        flow_control_type: FlowControlType,
        time_since_cancel_s: u64,
        timestamp: Time,
    },
    /// Flow control mechanism inconsistency.
    FlowControlInconsistency {
        channel_id: u64,
        expected_state: String,
        actual_state: String,
        timestamp: Time,
    },
}

impl FlowControlViolation {
    /// Returns the severity of this violation (0=low, 1=medium, 2=high, 3=critical).
    pub fn severity(&self) -> u8 {
        match self {
            Self::FlowControlInconsistency { .. } => 1,
            Self::ProducerStarvation { .. } => 2,
            Self::IndefiniteBlocking { .. } => 2,
            Self::CancellationUnblockFailure { .. } => 2,
            Self::AtomicityViolation { .. } => 3,
            Self::PotentialDeadlock { .. } => 3,
        }
    }

    /// Returns a human-readable description.
    pub fn description(&self) -> String {
        match self {
            Self::PotentialDeadlock { involved_channels, involved_tasks, cycle_description, .. } => {
                format!("Deadlock detected: {} channels, {} tasks - {}",
                       involved_channels.len(), involved_tasks.len(), cycle_description)
            }
            Self::ProducerStarvation { channel_id, starved_task, starvation_duration_s, .. } => {
                format!("Producer {:?} starved on channel {} for {}s",
                       starved_task, channel_id, starvation_duration_s)
            }
            Self::AtomicityViolation { channel_id, task_id, violation_type, .. } => {
                format!("Atomicity violated on channel {} by task {:?}: {}",
                       channel_id, task_id, violation_type)
            }
            Self::IndefiniteBlocking { channel_id, blocked_task, flow_control_type, block_duration_s, .. } => {
                format!("Task {:?} blocked indefinitely on channel {} ({:?}) for {}s",
                       blocked_task, channel_id, flow_control_type, block_duration_s)
            }
            Self::CancellationUnblockFailure { channel_id, cancelled_task, time_since_cancel_s, .. } => {
                format!("Cancelled task {:?} still blocked on channel {} after {}s",
                       cancelled_task, channel_id, time_since_cancel_s)
            }
            Self::FlowControlInconsistency { channel_id, expected_state, actual_state, .. } => {
                format!("Flow control inconsistency on channel {}: expected '{}', got '{}'",
                       channel_id, expected_state, actual_state)
            }
        }
    }
}

/// State tracking for a task's interaction with flow control.
#[derive(Debug, Clone)]
struct TaskFlowState {
    /// Current channels this task is blocked on.
    blocked_channels: HashSet<u64>,
    /// Time when task was first blocked (if currently blocked).
    first_block_time: Option<Time>,
    /// Number of times this task has been blocked by flow control.
    block_count: u64,
    /// Total time spent blocked by flow control (milliseconds).
    total_blocked_time_ms: u64,
    /// Current permit IDs this task is waiting for.
    pending_permits: HashSet<u64>,
    /// Whether this task has been cancelled.
    is_cancelled: bool,
    /// Time when task was cancelled (if applicable).
    cancel_time: Option<Time>,
}

/// State tracking for a channel's flow control.
#[derive(Debug, Clone)]
struct ChannelFlowState {
    /// Current flow control mechanisms active on this channel.
    active_controls: HashSet<FlowControlType>,
    /// Tasks currently blocked on this channel.
    blocked_tasks: HashSet<TaskId>,
    /// Current capacity/credits available.
    #[allow(dead_code)]
    available_capacity: Option<usize>,
    /// Maximum observed queue depth.
    max_queue_depth: usize,
    /// Whether backpressure is currently applied.
    backpressure_active: bool,
    /// Consumer tasks applying backpressure.
    backpressure_consumers: HashSet<TaskId>,
    /// Time when backpressure was first applied.
    backpressure_start_time: Option<Time>,
}

fn new_task_flow_state() -> TaskFlowState {
    TaskFlowState {
        blocked_channels: HashSet::new(),
        first_block_time: None,
        block_count: 0,
        total_blocked_time_ms: 0,
        pending_permits: HashSet::new(),
        is_cancelled: false,
        cancel_time: None,
    }
}

fn new_channel_flow_state() -> ChannelFlowState {
    ChannelFlowState {
        active_controls: HashSet::new(),
        blocked_tasks: HashSet::new(),
        available_capacity: None,
        max_queue_depth: 0,
        backpressure_active: false,
        backpressure_consumers: HashSet::new(),
        backpressure_start_time: None,
    }
}

/// Detailed violation report with context.
#[derive(Debug, Clone)]
pub struct FlowControlViolationReport {
    /// The specific violation that occurred.
    pub violation: FlowControlViolation,
    /// Timestamp when violation was detected.
    pub detection_time: Time,
    /// Additional context about the violation.
    pub context: HashMap<String, String>,
    /// Call stack when violation was detected (if available).
    pub stack_trace: Option<String>,
    /// Recent flow control events leading to this violation.
    pub related_events: Vec<FlowControlEvent>,
}

/// Statistics about flow control behavior.
#[derive(Debug, Clone, Default)]
pub struct FlowControlStats {
    /// Total number of flow control violations by severity.
    pub violations_by_severity: [u64; 4],
    /// Total flow control events processed.
    pub total_events: u64,
    /// Average time tasks spend blocked by flow control.
    pub avg_block_time_ms: u64,
    /// Maximum time any task spent blocked.
    pub max_block_time_ms: u64,
    /// Number of potential deadlocks detected.
    pub deadlocks_detected: u64,
    /// Number of starvation events detected.
    pub starvation_events: u64,
    /// Number of atomicity violations detected.
    pub atomicity_violations: u64,
    /// Number of channels currently under flow control.
    pub channels_under_flow_control: u64,
    /// Number of tasks currently blocked by flow control.
    pub tasks_currently_blocked: u64,
}

/// Deadlock detection state for cycle detection.
#[derive(Debug, Clone)]
struct DeadlockDetector {
    /// Graph of task->channel dependencies (task waiting on channel).
    task_to_channel: HashMap<TaskId, HashSet<u64>>,
    /// Graph of channel->task dependencies (channel owned by task).
    channel_to_task: HashMap<u64, TaskId>,
    /// Last time deadlock detection was run.
    last_detection_time: Option<Time>,
}

impl DeadlockDetector {
    fn new() -> Self {
        Self {
            task_to_channel: HashMap::new(),
            channel_to_task: HashMap::new(),
            last_detection_time: None,
        }
    }

    /// Detects potential deadlocks using cycle detection.
    fn detect_deadlocks(&mut self, current_time: Time) -> Vec<FlowControlViolation> {
        let mut violations = Vec::new();

        // Use DFS to detect cycles in the task-channel dependency graph
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();
        let mut current_path = Vec::new();

        for &task in self.task_to_channel.keys() {
            if !visited.contains(&task) {
                if let Some(cycle) = self.dfs_detect_cycle(
                    task,
                    &mut visited,
                    &mut recursion_stack,
                    &mut current_path,
                ) {
                    violations.push(FlowControlViolation::PotentialDeadlock {
                        involved_channels: cycle.channels,
                        involved_tasks: cycle.tasks,
                        cycle_description: cycle.description,
                        detection_time: current_time,
                    });
                }
            }
        }

        self.last_detection_time = Some(current_time);
        violations
    }

    fn dfs_detect_cycle(
        &self,
        task: TaskId,
        visited: &mut HashSet<TaskId>,
        recursion_stack: &mut HashSet<TaskId>,
        current_path: &mut Vec<(TaskId, u64)>,
    ) -> Option<DeadlockCycle> {
        visited.insert(task);
        recursion_stack.insert(task);

        if let Some(channels) = self.task_to_channel.get(&task) {
            for &channel in channels {
                current_path.push((task, channel));

                if let Some(&next_task) = self.channel_to_task.get(&channel) {
                    if recursion_stack.contains(&next_task) {
                        // Found cycle
                        let cycle_start_idx = current_path
                            .iter()
                            .position(|(t, _)| *t == next_task)
                            .unwrap_or(0);

                        let cycle_path = &current_path[cycle_start_idx..];
                        return Some(DeadlockCycle::from_path(cycle_path));
                    }

                    if !visited.contains(&next_task) {
                        if let Some(cycle) = self.dfs_detect_cycle(next_task, visited, recursion_stack, current_path) {
                            return Some(cycle);
                        }
                    }
                }

                current_path.pop();
            }
        }

        recursion_stack.remove(&task);
        None
    }

    fn add_dependency(&mut self, task: TaskId, channel: u64) {
        self.task_to_channel
            .entry(task)
            .or_insert_with(HashSet::new)
            .insert(channel);
    }

    fn remove_dependency(&mut self, task: TaskId, channel: u64) {
        if let Some(channels) = self.task_to_channel.get_mut(&task) {
            channels.remove(&channel);
            if channels.is_empty() {
                self.task_to_channel.remove(&task);
            }
        }
    }

    #[allow(dead_code)]
    fn add_channel_owner(&mut self, channel: u64, owner: TaskId) {
        self.channel_to_task.insert(channel, owner);
    }

    #[allow(dead_code)]
    fn remove_channel_owner(&mut self, channel: u64) {
        self.channel_to_task.remove(&channel);
    }
}

#[derive(Debug, Clone)]
struct DeadlockCycle {
    tasks: Vec<TaskId>,
    channels: Vec<u64>,
    description: String,
}

impl DeadlockCycle {
    fn from_path(path: &[(TaskId, u64)]) -> Self {
        let tasks: Vec<TaskId> = path.iter().map(|(t, _)| *t).collect();
        let channels: Vec<u64> = path.iter().map(|(_, c)| *c).collect();

        let description = format!(
            "Circular dependency: {}",
            path.iter()
                .map(|(task, channel)| format!("T{:?}→C{}", task, channel))
                .collect::<Vec<_>>()
                .join("→")
        );

        Self {
            tasks,
            channels,
            description,
        }
    }
}

/// Comprehensive flow control monitoring and violation detection.
#[derive(Debug)]
pub struct FlowControlMonitor {
    /// Configuration for monitoring behavior.
    config: FlowControlConfig,
    /// Recent flow control events.
    events: VecDeque<FlowControlEvent>,
    /// Detected violations.
    violations: VecDeque<FlowControlViolationReport>,
    /// Per-task flow control state.
    task_states: HashMap<TaskId, TaskFlowState>,
    /// Per-channel flow control state.
    channel_states: HashMap<u64, ChannelFlowState>,
    /// Deadlock detector.
    deadlock_detector: DeadlockDetector,
    /// Statistics.
    stats: FlowControlStats,
    /// Total events processed.
    total_events: AtomicU64,
}

impl FlowControlMonitor {
    /// Creates a new flow control monitor.
    pub fn new(config: FlowControlConfig) -> Self {
        Self {
            config,
            events: VecDeque::new(),
            violations: VecDeque::new(),
            task_states: HashMap::new(),
            channel_states: HashMap::new(),
            deadlock_detector: DeadlockDetector::new(),
            stats: FlowControlStats::default(),
            total_events: AtomicU64::new(0),
        }
    }

    /// Creates a monitor with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(FlowControlConfig::default())
    }

    /// Records a flow control event.
    pub fn record_event(&mut self, event: FlowControlEvent) {
        if !self.config.enable_verification {
            return;
        }

        self.total_events.fetch_add(1, Ordering::Relaxed);

        // Update state based on event type
        self.update_state_from_event(&event);

        // Check for violations after state update
        self.check_violations_after_event(&event);

        // Store event with size limits
        self.events.push_back(event);
        while self.events.len() > self.config.max_tracked_events {
            self.events.pop_front();
        }

        self.stats.total_events += 1;
    }

    /// Updates internal state based on a flow control event.
    fn update_state_from_event(&mut self, event: &FlowControlEvent) {
        match event {
            FlowControlEvent::ProducerBlocked { channel_id, task_id, reason, timestamp, .. } => {
                let task_state = self
                    .task_states
                    .entry(*task_id)
                    .or_insert_with(new_task_flow_state);

                task_state.blocked_channels.insert(*channel_id);
                if task_state.first_block_time.is_none() {
                    task_state.first_block_time = Some(*timestamp);
                }
                task_state.block_count += 1;

                let channel_state = self
                    .channel_states
                    .entry(*channel_id)
                    .or_insert_with(new_channel_flow_state);

                channel_state.active_controls.insert(*reason);
                channel_state.blocked_tasks.insert(*task_id);

                // Update deadlock detection graph
                self.deadlock_detector.add_dependency(*task_id, *channel_id);
            }

            FlowControlEvent::ProducerUnblocked { channel_id, task_id, blocked_duration_ms, .. } => {
                if let Some(task_state) = self.task_states.get_mut(task_id) {
                    task_state.blocked_channels.remove(channel_id);
                    task_state.total_blocked_time_ms += blocked_duration_ms;

                    if task_state.blocked_channels.is_empty() {
                        task_state.first_block_time = None;
                    }
                }

                if let Some(channel_state) = self.channel_states.get_mut(channel_id) {
                    channel_state.blocked_tasks.remove(task_id);
                }

                // Update deadlock detection graph
                self.deadlock_detector.remove_dependency(*task_id, *channel_id);

                // Update statistics
                if *blocked_duration_ms > self.stats.max_block_time_ms {
                    self.stats.max_block_time_ms = *blocked_duration_ms;
                }
            }

            FlowControlEvent::BackpressureApplied { channel_id, consumer_task, queue_depth, timestamp } => {
                let channel_state = self
                    .channel_states
                    .entry(*channel_id)
                    .or_insert_with(new_channel_flow_state);

                channel_state.backpressure_active = true;
                channel_state.backpressure_consumers.insert(*consumer_task);
                channel_state.max_queue_depth = channel_state.max_queue_depth.max(*queue_depth);

                if channel_state.backpressure_start_time.is_none() {
                    channel_state.backpressure_start_time = Some(*timestamp);
                }
            }

            FlowControlEvent::BackpressureReleased { channel_id, consumer_task, .. } => {
                if let Some(channel_state) = self.channel_states.get_mut(channel_id) {
                    channel_state.backpressure_consumers.remove(consumer_task);

                    if channel_state.backpressure_consumers.is_empty() {
                        channel_state.backpressure_active = false;
                        channel_state.backpressure_start_time = None;
                    }
                }
            }

            FlowControlEvent::ReserveBlocked { channel_id, task_id, permit_id, timestamp, .. } => {
                let task_state = self
                    .task_states
                    .entry(*task_id)
                    .or_insert_with(new_task_flow_state);
                task_state.pending_permits.insert(*permit_id);
                task_state.blocked_channels.insert(*channel_id);
                if task_state.first_block_time.is_none() {
                    task_state.first_block_time = Some(*timestamp);
                }

                let channel_state = self
                    .channel_states
                    .entry(*channel_id)
                    .or_insert_with(new_channel_flow_state);
                channel_state.blocked_tasks.insert(*task_id);

                self.deadlock_detector.add_dependency(*task_id, *channel_id);
            }

            FlowControlEvent::ReserveUnblocked {
                channel_id,
                task_id,
                permit_id,
                blocked_duration_ms,
                ..
            } => {
                if let Some(task_state) = self.task_states.get_mut(task_id) {
                    task_state.pending_permits.remove(permit_id);
                    task_state.blocked_channels.remove(channel_id);
                    task_state.total_blocked_time_ms += blocked_duration_ms;
                    if task_state.blocked_channels.is_empty() {
                        task_state.first_block_time = None;
                    }
                }

                if let Some(channel_state) = self.channel_states.get_mut(channel_id) {
                    channel_state.blocked_tasks.remove(task_id);
                }
                self.deadlock_detector.remove_dependency(*task_id, *channel_id);

                if *blocked_duration_ms > self.stats.max_block_time_ms {
                    self.stats.max_block_time_ms = *blocked_duration_ms;
                }
            }

            FlowControlEvent::AbortDueToFlowControl {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                if let Some(task_state) = self.task_states.get_mut(task_id) {
                    task_state.pending_permits.remove(permit_id);
                    task_state.blocked_channels.remove(channel_id);
                    if task_state.blocked_channels.is_empty() {
                        task_state.first_block_time = None;
                    }
                }

                if let Some(channel_state) = self.channel_states.get_mut(channel_id) {
                    channel_state.blocked_tasks.remove(task_id);
                }
                self.deadlock_detector.remove_dependency(*task_id, *channel_id);
            }

            FlowControlEvent::CommitFlowControlled { .. } | FlowControlEvent::AbortDueToFlowControl { .. } => {} // Handle other events as needed
        }
    }

    /// Checks for violations after processing an event.
    fn check_violations_after_event(&mut self, event: &FlowControlEvent) {
        let current_time = match event {
            FlowControlEvent::ProducerBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ProducerUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureApplied { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureReleased { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::CommitFlowControlled { timestamp, .. } => *timestamp,
            FlowControlEvent::AbortDueToFlowControl { timestamp, .. } => *timestamp,
        };

        // Check for potential deadlocks
        if self.config.enable_deadlock_prevention {
            let deadlocks = self.deadlock_detector.detect_deadlocks(current_time);
            for violation in deadlocks {
                self.record_violation(violation, current_time);
            }
        }

        // Check for starvation
        self.check_starvation(current_time);

        // Check for indefinite blocking
        self.check_indefinite_blocking(current_time);

        // Check for cancelled tasks that stayed blocked under flow control.
        self.check_cancellation_unblock_failures(current_time);

        // Check reserve/commit/abort atomicity for two-phase sends.
        self.check_atomicity(event, current_time);
    }

    /// Checks for producer starvation.
    fn check_starvation(&mut self, current_time: Time) {
        let starvation_threshold_ns = self.config.starvation_threshold_s * 1_000_000_000;
        let mut new_violations = Vec::new();

        for (&task_id, task_state) in &self.task_states {
            if let Some(first_block_time) = task_state.first_block_time {
                let blocked_duration_ns = current_time.as_nanos().saturating_sub(first_block_time.as_nanos());

                if blocked_duration_ns >= starvation_threshold_ns && !task_state.blocked_channels.is_empty() {
                    for &channel_id in &task_state.blocked_channels {
                        // Count other producers that were served recently
                        let other_producers_served = self.count_recently_served_producers(channel_id, current_time);

                        let violation = FlowControlViolation::ProducerStarvation {
                            channel_id,
                            starved_task: task_id,
                            starvation_duration_s: blocked_duration_ns / 1_000_000_000,
                            other_producers_served,
                            timestamp: current_time,
                        };

                        new_violations.push(violation);
                    }
                }
            }
        }

        for violation in new_violations {
            self.record_violation(violation, current_time);
        }
    }

    /// Checks for indefinite blocking.
    fn check_indefinite_blocking(&mut self, current_time: Time) {
        let blocking_threshold_ns = self.config.deadlock_detection_threshold_s * 1_000_000_000;
        let mut new_violations = Vec::new();

        for (&task_id, task_state) in &self.task_states {
            if let Some(first_block_time) = task_state.first_block_time {
                let blocked_duration_ns = current_time.as_nanos().saturating_sub(first_block_time.as_nanos());

                if blocked_duration_ns >= blocking_threshold_ns {
                    for &channel_id in &task_state.blocked_channels {
                        if let Some(channel_state) = self.channel_states.get(&channel_id) {
                            for &flow_control_type in &channel_state.active_controls {
                                let violation = FlowControlViolation::IndefiniteBlocking {
                                    channel_id,
                                    blocked_task: task_id,
                                    flow_control_type,
                                    block_duration_s: blocked_duration_ns / 1_000_000_000,
                                    timestamp: current_time,
                                };

                                new_violations.push(violation);
                            }
                        }
                    }
                }
            }
        }

        for violation in new_violations {
            self.record_violation(violation, current_time);
        }
    }

    fn check_cancellation_unblock_failures(&mut self, current_time: Time) {
        let cancellation_threshold_ns = self.config.deadlock_detection_threshold_s * 1_000_000_000;
        let mut new_violations = Vec::new();

        for (&task_id, task_state) in &self.task_states {
            let Some(cancel_time) = task_state.cancel_time else {
                continue;
            };

            if !task_state.is_cancelled || task_state.blocked_channels.is_empty() {
                continue;
            }

            let time_since_cancel_ns =
                current_time.as_nanos().saturating_sub(cancel_time.as_nanos());
            if time_since_cancel_ns < cancellation_threshold_ns {
                continue;
            }

            for &channel_id in &task_state.blocked_channels {
                if let Some(channel_state) = self.channel_states.get(&channel_id) {
                    for &flow_control_type in &channel_state.active_controls {
                        new_violations.push(FlowControlViolation::CancellationUnblockFailure {
                            channel_id,
                            cancelled_task: task_id,
                            flow_control_type,
                            time_since_cancel_s: time_since_cancel_ns / 1_000_000_000,
                            timestamp: current_time,
                        });
                    }
                }
            }
        }

        for violation in new_violations {
            self.record_violation(violation, current_time);
        }
    }

    fn check_atomicity(&mut self, event: &FlowControlEvent, current_time: Time) {
        match event {
            FlowControlEvent::CommitFlowControlled {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let has_pending_permit = self
                    .task_states
                    .get(task_id)
                    .is_some_and(|task_state| task_state.pending_permits.contains(permit_id));

                if !has_pending_permit {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type:
                                "commit_flow_controlled_without_pending_reserve".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            FlowControlEvent::AbortDueToFlowControl {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let saw_reserve_block = self.events.iter().rev().any(|past_event| {
                    matches!(
                        past_event,
                        FlowControlEvent::ReserveBlocked {
                            channel_id: past_channel_id,
                            task_id: past_task_id,
                            permit_id: past_permit_id,
                            ..
                        } if past_channel_id == channel_id
                            && past_task_id == task_id
                            && past_permit_id == permit_id
                    )
                });

                if !saw_reserve_block {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type: "abort_without_pending_reserve".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            _ => {}
        }
    }

    /// Counts producers served recently on a channel.
    fn count_recently_served_producers(&self, channel_id: u64, current_time: Time) -> usize {
        const RECENT_WINDOW_NS: u64 = 60_000_000_000; // 60 seconds
        let cutoff_time = current_time.as_nanos().saturating_sub(RECENT_WINDOW_NS);

        self.events
            .iter()
            .filter(|event| {
                match event {
                    FlowControlEvent::ProducerUnblocked { channel_id: cid, timestamp, .. } => {
                        *cid == channel_id && timestamp.as_nanos() >= cutoff_time
                    }
                    _ => false,
                }
            })
            .count()
    }

    /// Records a flow control violation.
    fn record_violation(&mut self, violation: FlowControlViolation, detection_time: Time) {
        let severity = violation.severity();
        self.stats.violations_by_severity[severity as usize] += 1;

        match &violation {
            FlowControlViolation::PotentialDeadlock { .. } => {
                self.stats.deadlocks_detected += 1;
            }
            FlowControlViolation::ProducerStarvation { .. } => {
                self.stats.starvation_events += 1;
            }
            FlowControlViolation::AtomicityViolation { .. } => {
                self.stats.atomicity_violations += 1;
            }
            _ => {}
        }

        let related_events = self.events
            .iter()
            .rev()
            .take(10) // Last 10 events for context
            .cloned()
            .collect();

        let report = FlowControlViolationReport {
            violation,
            detection_time,
            context: HashMap::new(),
            stack_trace: if self.config.enable_detailed_tracing {
                Some(format!("{:?}", std::backtrace::Backtrace::capture()))
            } else {
                None
            },
            related_events,
        };

        self.violations.push_back(report);

        // Limit violation history
        while self.violations.len() > self.config.max_tracked_events {
            self.violations.pop_front();
        }
    }

    /// Marks a task as cancelled for violation checking.
    pub fn record_task_cancel(&mut self, task_id: TaskId, timestamp: Time) {
        if let Some(task_state) = self.task_states.get_mut(&task_id) {
            task_state.is_cancelled = true;
            task_state.cancel_time = Some(timestamp);
        }
    }

    /// Returns current flow control statistics.
    pub fn stats(&self) -> FlowControlStats {
        let mut stats = self.stats.clone();

        // Update dynamic statistics
        stats.channels_under_flow_control = self.channel_states
            .values()
            .filter(|state| !state.active_controls.is_empty())
            .count() as u64;

        stats.tasks_currently_blocked = self.task_states
            .values()
            .filter(|state| !state.blocked_channels.is_empty())
            .count() as u64;

        // Calculate average block time
        if stats.total_events > 0 {
            let total_block_time: u64 = self.task_states
                .values()
                .map(|state| state.total_blocked_time_ms)
                .sum();
            stats.avg_block_time_ms = total_block_time / stats.total_events.max(1);
        }

        stats
    }

    /// Returns all recorded violations.
    pub fn violations(&self) -> &VecDeque<FlowControlViolationReport> {
        &self.violations
    }

    /// Returns recent flow control events.
    pub fn recent_events(&self, count: usize) -> Vec<&FlowControlEvent> {
        self.events.iter().rev().take(count).collect()
    }

    /// Returns whether monitoring is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enable_verification
    }

    /// Cleans up old state to prevent memory growth.
    pub fn cleanup_old_state(&mut self, current_time: Time) {
        const MAX_TASK_AGE_S: u64 = 300; // 5 minutes
        let cutoff_time = Time::from_nanos(
            current_time.as_nanos().saturating_sub(MAX_TASK_AGE_S * 1_000_000_000)
        );

        // Remove old task states for completed/cancelled tasks
        self.task_states.retain(|_, state| {
            if state.blocked_channels.is_empty() {
                if let Some(cancel_time) = state.cancel_time {
                    cancel_time.as_nanos() >= cutoff_time.as_nanos()
                } else {
                    // Keep active states
                    true
                }
            } else {
                // Keep blocked states
                true
            }
        });

        // Clean up empty channel states
        self.channel_states.retain(|_, state| {
            !state.blocked_tasks.is_empty() ||
            state.backpressure_active ||
            !state.active_controls.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_monitor_basic_operations() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        // Test producer blocked event
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::CapacityLimit,
            timestamp: now,
        });

        let stats = monitor.stats();
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.tasks_currently_blocked, 1);
        assert_eq!(stats.channels_under_flow_control, 1);
    }

    #[test]
    fn test_starvation_detection() {
        let mut config = FlowControlConfig::default();
        config.starvation_threshold_s = 1; // 1 second threshold

        let mut monitor = FlowControlMonitor::new(config);
        let start_time = Time::from_nanos(1_000_000_000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        // Task gets blocked
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::ConsumerBackpressure,
            timestamp: start_time,
        });

        // Much later, another event should trigger starvation detection
        let later_time = Time::from_nanos(3_000_000_000); // 2 seconds later
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: TaskId::new_for_test(2, 0),
            queue_depth: 10,
            timestamp: later_time,
        });

        // Should detect starvation
        assert!(!monitor.violations.is_empty());

        let violation = &monitor.violations[0];
        match &violation.violation {
            FlowControlViolation::ProducerStarvation { starved_task, starvation_duration_s, .. } => {
                assert_eq!(*starved_task, task_id);
                assert_eq!(*starvation_duration_s, 2);
            }
            _ => panic!("Expected ProducerStarvation violation"),
        }
    }

    #[test]
    fn test_deadlock_detection() {
        let mut config = FlowControlConfig::default();
        config.enable_deadlock_prevention = true;

        let mut monitor = FlowControlMonitor::new(config);
        let now = Time::from_nanos(1000);

        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);
        let channel1 = 10;
        let channel2 = 20;

        // Create potential deadlock: task1 blocks on channel1, task2 blocks on channel2
        monitor.deadlock_detector.add_dependency(task1, channel1);
        monitor.deadlock_detector.add_channel_owner(channel1, task2);
        monitor.deadlock_detector.add_dependency(task2, channel2);
        monitor.deadlock_detector.add_channel_owner(channel2, task1);

        // Trigger deadlock detection
        let deadlocks = monitor.deadlock_detector.detect_deadlocks(now);

        assert!(!deadlocks.is_empty());
        match &deadlocks[0] {
            FlowControlViolation::PotentialDeadlock { involved_tasks, involved_channels, .. } => {
                assert!(involved_tasks.contains(&task1));
                assert!(involved_tasks.contains(&task2));
                assert!(involved_channels.contains(&channel1));
                assert!(involved_channels.contains(&channel2));
            }
            _ => panic!("Expected PotentialDeadlock violation"),
        }
    }

    #[test]
    fn test_indefinite_blocking_detection() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1; // 1 second

        let mut monitor = FlowControlMonitor::new(config);
        let start_time = Time::from_nanos(1_000_000_000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        // Task gets blocked
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::RateLimit,
            timestamp: start_time,
        });

        // Later event triggers indefinite blocking check
        let later_time = Time::from_nanos(3_000_000_000); // 2 seconds later
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 99,
            consumer_task: TaskId::new_for_test(2, 0),
            queue_depth: 5,
            timestamp: later_time,
        });

        // Should detect indefinite blocking
        assert!(!monitor.violations.is_empty());

        let violation = &monitor.violations[0];
        match &violation.violation {
            FlowControlViolation::IndefiniteBlocking { blocked_task, block_duration_s, .. } => {
                assert_eq!(*blocked_task, task_id);
                assert_eq!(*block_duration_s, 2);
            }
            _ => panic!("Expected IndefiniteBlocking violation"),
        }
    }

    #[test]
    fn test_producer_unblock_updates_stats() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason: FlowControlType::CapacityLimit,
            blocked_duration_ms: 500,
            timestamp: now,
        });

        let stats = monitor.stats();
        assert_eq!(stats.max_block_time_ms, 500);
    }

    #[test]
    fn test_reserve_blocked_creates_task_and_channel_state() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let now = Time::from_nanos(1_000);
        let task_id = TaskId::new_for_test(7, 0);
        let channel_id = 99;
        let permit_id = 1234;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: now,
        });

        let stats = monitor.stats();
        assert_eq!(stats.tasks_currently_blocked, 1);

        let task_state = monitor.task_states.get(&task_id).expect("task state");
        assert!(task_state.pending_permits.contains(&permit_id));
        assert!(task_state.blocked_channels.contains(&channel_id));
        assert_eq!(task_state.first_block_time, Some(now));

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.contains(&task_id));
    }

    #[test]
    fn test_reserve_unblocked_clears_blocked_state() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(8, 0);
        let channel_id = 77;
        let permit_id = 4321;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_nanos(1_000),
        });
        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 5,
            timestamp: Time::from_nanos(2_000),
        });

        let stats = monitor.stats();
        assert_eq!(stats.tasks_currently_blocked, 0);

        let task_state = monitor.task_states.get(&task_id).expect("task state");
        assert!(task_state.pending_permits.is_empty());
        assert!(task_state.blocked_channels.is_empty());
        assert!(task_state.first_block_time.is_none());

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.is_empty());
    }

    #[test]
    fn test_commit_without_pending_reserve_reports_atomicity_violation() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(9, 0);
        let channel_id = 55;
        let permit_id = 808;
        let now = Time::from_nanos(10_000);

        monitor.record_event(FlowControlEvent::CommitFlowControlled {
            channel_id,
            task_id,
            permit_id,
            timestamp: now,
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::AtomicityViolation {
                channel_id: violation_channel,
                task_id: violation_task,
                permit_id: violation_permit,
                violation_type,
                ..
            } if *violation_channel == channel_id
                && *violation_task == task_id
                && *violation_permit == permit_id
                && violation_type == "commit_flow_controlled_without_pending_reserve"
        )));
    }

    #[test]
    fn test_abort_without_pending_reserve_reports_atomicity_violation() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(10, 0);
        let channel_id = 66;
        let permit_id = 909;
        let now = Time::from_nanos(20_000);

        monitor.record_event(FlowControlEvent::AbortDueToFlowControl {
            channel_id,
            task_id,
            permit_id,
            timeout_reason: "timed out".to_string(),
            timestamp: now,
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::AtomicityViolation {
                channel_id: violation_channel,
                task_id: violation_task,
                permit_id: violation_permit,
                violation_type,
                ..
            } if *violation_channel == channel_id
                && *violation_task == task_id
                && *violation_permit == permit_id
                && violation_type == "abort_without_pending_reserve"
        )));
    }

    #[test]
    fn test_cancelled_task_still_blocked_reports_unblock_failure() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;

        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(11, 0);
        let channel_id = 77;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::ConsumerBackpressure,
            timestamp: Time::from_nanos(1_000_000_000),
        });
        monitor.record_task_cancel(task_id, Time::from_nanos(2_000_000_000));
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: TaskId::new_for_test(12, 0),
            queue_depth: 4,
            timestamp: Time::from_nanos(4_000_000_000),
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::CancellationUnblockFailure {
                channel_id: violation_channel,
                cancelled_task,
                flow_control_type,
                time_since_cancel_s,
                ..
            } if *violation_channel == channel_id
                && *cancelled_task == task_id
                && *flow_control_type == FlowControlType::ConsumerBackpressure
                && *time_since_cancel_s == 2
        )));
    }
}
