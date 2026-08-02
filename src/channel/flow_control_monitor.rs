#![allow(missing_docs)]
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
use std::collections::{HashMap, HashSet, VecDeque, hash_map::Entry};
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

/// Reserve waits are capacity ownership waits when the event carries no finer reason.
const RESERVE_FLOW_CONTROL: FlowControlType = FlowControlType::CapacityLimit;

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
            Self::PotentialDeadlock {
                involved_channels,
                involved_tasks,
                cycle_description,
                ..
            } => {
                format!(
                    "Deadlock detected: {} channels, {} tasks - {}",
                    involved_channels.len(),
                    involved_tasks.len(),
                    cycle_description
                )
            }
            Self::ProducerStarvation {
                channel_id,
                starved_task,
                starvation_duration_s,
                ..
            } => {
                format!(
                    "Producer {:?} starved on channel {} for {}s",
                    starved_task, channel_id, starvation_duration_s
                )
            }
            Self::AtomicityViolation {
                channel_id,
                task_id,
                violation_type,
                ..
            } => {
                format!(
                    "Atomicity violated on channel {} by task {:?}: {}",
                    channel_id, task_id, violation_type
                )
            }
            Self::IndefiniteBlocking {
                channel_id,
                blocked_task,
                flow_control_type,
                block_duration_s,
                ..
            } => {
                format!(
                    "Task {:?} blocked indefinitely on channel {} ({:?}) for {}s",
                    blocked_task, channel_id, flow_control_type, block_duration_s
                )
            }
            Self::CancellationUnblockFailure {
                channel_id,
                cancelled_task,
                time_since_cancel_s,
                ..
            } => {
                format!(
                    "Cancelled task {:?} still blocked on channel {} after {}s",
                    cancelled_task, channel_id, time_since_cancel_s
                )
            }
            Self::FlowControlInconsistency {
                channel_id,
                expected_state,
                actual_state,
                ..
            } => {
                format!(
                    "Flow control inconsistency on channel {}: expected '{}', got '{}'",
                    channel_id, expected_state, actual_state
                )
            }
        }
    }
}

/// The operation-specific part of a live flow-control wait identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlowWaitKind {
    Producer(FlowControlType),
    Reserve(u64),
}

/// Canonical identity for one live flow-control wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowWaitIdentity {
    task_id: TaskId,
    channel_id: u64,
    kind: FlowWaitKind,
}

impl FlowWaitIdentity {
    fn producer(task_id: TaskId, channel_id: u64, reason: FlowControlType) -> Self {
        Self {
            task_id,
            channel_id,
            kind: FlowWaitKind::Producer(reason),
        }
    }

    fn reserve(task_id: TaskId, channel_id: u64, permit_id: u64) -> Self {
        Self {
            task_id,
            channel_id,
            kind: FlowWaitKind::Reserve(permit_id),
        }
    }

    fn control_type(self) -> FlowControlType {
        match self.kind {
            FlowWaitKind::Producer(reason) => reason,
            FlowWaitKind::Reserve(_) => RESERVE_FLOW_CONTROL,
        }
    }
}

/// State tracking for a task's interaction with flow control.
#[derive(Debug, Clone)]
struct TaskFlowState {
    /// Current channels this task is blocked on and their live-wait counts.
    blocked_channels: HashMap<u64, usize>,
    /// Time when task was first blocked (if currently blocked).
    first_block_time: Option<Time>,
    /// Number of times this task has been blocked by flow control.
    block_count: u64,
    /// Total time spent blocked by flow control (milliseconds).
    total_blocked_time_ms: u64,
    /// Whether this task has been cancelled.
    is_cancelled: bool,
    /// Time when task was cancelled (if applicable).
    cancel_time: Option<Time>,
}

/// State tracking for a channel's flow control.
#[derive(Debug, Clone)]
struct ChannelFlowState {
    /// Current flow control mechanisms and their live-owner counts.
    active_controls: HashMap<FlowControlType, usize>,
    /// Tasks currently blocked on this channel and their live-wait counts.
    blocked_tasks: HashMap<TaskId, usize>,
    /// Current capacity/credits available.
    #[allow(dead_code)]
    available_capacity: Option<usize>,
    /// Maximum observed queue depth.
    max_queue_depth: usize,
    /// Whether backpressure is currently applied.
    backpressure_active: bool,
    /// Consumer tasks applying backpressure and their first observed timestamps.
    backpressure_consumers: HashMap<TaskId, Time>,
    /// Time when backpressure was first applied.
    backpressure_start_time: Option<Time>,
}

fn new_task_flow_state() -> TaskFlowState {
    TaskFlowState {
        blocked_channels: HashMap::new(),
        first_block_time: None,
        block_count: 0,
        total_blocked_time_ms: 0,
        is_cancelled: false,
        cancel_time: None,
    }
}

fn new_channel_flow_state() -> ChannelFlowState {
    ChannelFlowState {
        active_controls: HashMap::new(),
        blocked_tasks: HashMap::new(),
        available_capacity: None,
        max_queue_depth: 0,
        backpressure_active: false,
        backpressure_consumers: HashMap::new(),
        backpressure_start_time: None,
    }
}

impl ChannelFlowState {
    fn add_active_control(&mut self, control: FlowControlType) {
        *self.active_controls.entry(control).or_default() += 1;
    }

    fn remove_active_control(&mut self, control: FlowControlType) -> bool {
        match self.active_controls.entry(control) {
            Entry::Occupied(mut active) if *active.get() > 1 => {
                *active.get_mut() -= 1;
                true
            }
            Entry::Occupied(active) => {
                active.remove();
                true
            }
            Entry::Vacant(_) => false,
        }
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
    /// Graph of task->channel dependencies and their live-wait counts.
    task_to_channel: HashMap<TaskId, HashMap<u64, usize>>,
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
            for &channel in channels.keys() {
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
                        if let Some(cycle) =
                            self.dfs_detect_cycle(next_task, visited, recursion_stack, current_path)
                        {
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
        *self
            .task_to_channel
            .entry(task)
            .or_default()
            .entry(channel)
            .or_default() += 1;
    }

    fn remove_dependency(&mut self, task: TaskId, channel: u64) {
        if let Some(channels) = self.task_to_channel.get_mut(&task) {
            if let Some(wait_count) = channels.get_mut(&channel) {
                *wait_count -= 1;
                if *wait_count == 0 {
                    channels.remove(&channel);
                }
            }
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
    /// Canonical live waits keyed by their complete operation identity.
    active_waits: HashMap<FlowWaitIdentity, Time>,
    /// Deadlock detector.
    deadlock_detector: DeadlockDetector,
    /// Statistics.
    stats: FlowControlStats,
    /// Cumulative blocked time for all tasks.
    total_blocked_time_ms: u64,
    /// Total number of unblock events.
    total_unblocks: u64,
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
            active_waits: HashMap::new(),
            deadlock_detector: DeadlockDetector::new(),
            stats: FlowControlStats::default(),
            total_blocked_time_ms: 0,
            total_unblocks: 0,
            total_events: AtomicU64::new(0),
        }
    }

    /// Creates a monitor with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(FlowControlConfig::default())
    }

    /// Registers one canonical wait and increments its derived graph edges.
    /// Exact duplicate begin events are idempotent.
    fn register_wait(&mut self, identity: FlowWaitIdentity, timestamp: Time) -> bool {
        match self.active_waits.entry(identity) {
            Entry::Occupied(mut active_wait) => {
                let first_observed = active_wait.get_mut();
                *first_observed = (*first_observed).min(timestamp);
                if let Some(task_state) = self.task_states.get_mut(&identity.task_id) {
                    task_state.first_block_time = Some(
                        task_state
                            .first_block_time
                            .map_or(timestamp, |first| first.min(timestamp)),
                    );
                }
                return false;
            }
            Entry::Vacant(active_wait) => {
                active_wait.insert(timestamp);
            }
        }

        let task_state = self
            .task_states
            .entry(identity.task_id)
            .or_insert_with(new_task_flow_state);
        *task_state
            .blocked_channels
            .entry(identity.channel_id)
            .or_default() += 1;
        task_state.first_block_time = Some(
            task_state
                .first_block_time
                .map_or(timestamp, |first| first.min(timestamp)),
        );
        if matches!(identity.kind, FlowWaitKind::Producer(_)) {
            task_state.block_count += 1;
        }

        let channel_state = self
            .channel_states
            .entry(identity.channel_id)
            .or_insert_with(new_channel_flow_state);
        *channel_state
            .blocked_tasks
            .entry(identity.task_id)
            .or_default() += 1;
        channel_state.add_active_control(identity.control_type());

        self.deadlock_detector
            .add_dependency(identity.task_id, identity.channel_id);
        true
    }

    /// Removes one exact wait and decrements only the edges derived from it.
    fn remove_wait(&mut self, identity: FlowWaitIdentity) -> bool {
        if self.active_waits.remove(&identity).is_none() {
            return false;
        }

        let next_first_block_time = self
            .active_waits
            .iter()
            .filter_map(|(wait, timestamp)| {
                (wait.task_id == identity.task_id).then_some(*timestamp)
            })
            .min();

        if let Some(task_state) = self.task_states.get_mut(&identity.task_id) {
            let remove_channel = if let Some(wait_count) =
                task_state.blocked_channels.get_mut(&identity.channel_id)
            {
                *wait_count -= 1;
                *wait_count == 0
            } else {
                false
            };
            if remove_channel {
                task_state.blocked_channels.remove(&identity.channel_id);
            }
            task_state.first_block_time = next_first_block_time;
        }

        if let Some(channel_state) = self.channel_states.get_mut(&identity.channel_id) {
            let remove_task =
                if let Some(wait_count) = channel_state.blocked_tasks.get_mut(&identity.task_id) {
                    *wait_count -= 1;
                    *wait_count == 0
                } else {
                    false
                };
            if remove_task {
                channel_state.blocked_tasks.remove(&identity.task_id);
            }
            let removed_control = channel_state.remove_active_control(identity.control_type());
            debug_assert!(
                removed_control,
                "live wait must have a matching active-control owner"
            );
        }

        self.deadlock_detector
            .remove_dependency(identity.task_id, identity.channel_id);
        true
    }

    fn has_wait(&self, identity: FlowWaitIdentity) -> bool {
        self.active_waits.contains_key(&identity)
    }

    fn typed_active_waits(&self) -> HashMap<(TaskId, u64, FlowControlType), Time> {
        let mut typed_waits: HashMap<(TaskId, u64, FlowControlType), Time> = HashMap::new();
        for (&identity, &timestamp) in &self.active_waits {
            let key = (
                identity.task_id,
                identity.channel_id,
                identity.control_type(),
            );
            match typed_waits.entry(key) {
                Entry::Occupied(mut first_observed) => {
                    *first_observed.get_mut() = (*first_observed.get()).min(timestamp);
                }
                Entry::Vacant(first_observed) => {
                    first_observed.insert(timestamp);
                }
            }
        }
        typed_waits
    }

    /// Records a flow control event.
    pub fn record_event(&mut self, event: FlowControlEvent) {
        if !self.config.enable_verification {
            return;
        }

        self.total_events.fetch_add(1, Ordering::Relaxed);

        let current_time = match &event {
            FlowControlEvent::ProducerBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ProducerUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureApplied { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureReleased { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::CommitFlowControlled { timestamp, .. } => *timestamp,
            FlowControlEvent::AbortDueToFlowControl { timestamp, .. } => *timestamp,
        };

        // Check terminal-event identity before mutating the corresponding wait.
        self.check_terminal_identity(&event, current_time);

        // Update state based on event type
        self.update_state_from_event(&event);

        // Check for violations after state update
        self.check_violations_after_event(&event, current_time);

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
            FlowControlEvent::ProducerBlocked {
                channel_id,
                task_id,
                reason,
                timestamp,
                ..
            } => {
                self.register_wait(
                    FlowWaitIdentity::producer(*task_id, *channel_id, *reason),
                    *timestamp,
                );
            }

            FlowControlEvent::ProducerUnblocked {
                channel_id,
                task_id,
                reason,
                blocked_duration_ms,
                ..
            } => {
                let identity = FlowWaitIdentity::producer(*task_id, *channel_id, *reason);
                if self.remove_wait(identity) {
                    self.total_blocked_time_ms += *blocked_duration_ms;
                    self.total_unblocks += 1;
                    let task_state = self
                        .task_states
                        .get_mut(task_id)
                        .expect("removed wait must retain its task state");
                    task_state.total_blocked_time_ms += blocked_duration_ms;
                    self.stats.max_block_time_ms =
                        self.stats.max_block_time_ms.max(*blocked_duration_ms);
                }
            }

            FlowControlEvent::BackpressureApplied {
                channel_id,
                consumer_task,
                queue_depth,
                timestamp,
            } => {
                let channel_state = self
                    .channel_states
                    .entry(*channel_id)
                    .or_insert_with(new_channel_flow_state);

                channel_state.backpressure_active = true;
                match channel_state.backpressure_consumers.entry(*consumer_task) {
                    Entry::Occupied(mut consumer) => {
                        *consumer.get_mut() = (*consumer.get()).min(*timestamp);
                    }
                    Entry::Vacant(consumer) => {
                        consumer.insert(*timestamp);
                        channel_state.add_active_control(FlowControlType::ConsumerBackpressure);
                    }
                }
                channel_state.max_queue_depth = channel_state.max_queue_depth.max(*queue_depth);
                channel_state.backpressure_start_time = Some(
                    channel_state
                        .backpressure_start_time
                        .map_or(*timestamp, |first| first.min(*timestamp)),
                );
            }

            FlowControlEvent::BackpressureReleased {
                channel_id,
                consumer_task,
                ..
            } => {
                if let Some(channel_state) = self.channel_states.get_mut(channel_id) {
                    if channel_state
                        .backpressure_consumers
                        .remove(consumer_task)
                        .is_some()
                    {
                        channel_state.remove_active_control(FlowControlType::ConsumerBackpressure);
                        channel_state.backpressure_active =
                            !channel_state.backpressure_consumers.is_empty();
                        channel_state.backpressure_start_time =
                            channel_state.backpressure_consumers.values().copied().min();
                    }
                }
            }

            FlowControlEvent::ReserveBlocked {
                channel_id,
                task_id,
                permit_id,
                timestamp,
                ..
            } => {
                self.register_wait(
                    FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id),
                    *timestamp,
                );
            }

            FlowControlEvent::ReserveUnblocked {
                channel_id,
                task_id,
                permit_id,
                blocked_duration_ms,
                ..
            } => {
                let identity = FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id);
                if self.remove_wait(identity) {
                    self.total_blocked_time_ms += *blocked_duration_ms;
                    self.total_unblocks += 1;
                    let task_state = self
                        .task_states
                        .get_mut(task_id)
                        .expect("removed wait must retain its task state");
                    task_state.total_blocked_time_ms += blocked_duration_ms;
                    self.stats.max_block_time_ms =
                        self.stats.max_block_time_ms.max(*blocked_duration_ms);
                }
            }

            FlowControlEvent::AbortDueToFlowControl {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                self.remove_wait(FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id));
            }

            FlowControlEvent::CommitFlowControlled {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                self.remove_wait(FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id));
            }
        }
    }

    /// Checks for violations after processing an event.
    fn check_violations_after_event(&mut self, _event: &FlowControlEvent, current_time: Time) {
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
    }

    /// Checks for producer starvation.
    fn check_starvation(&mut self, current_time: Time) {
        let starvation_threshold_ns = self.config.starvation_threshold_s * 1_000_000_000;
        let mut new_violations = Vec::new();

        for (&task_id, task_state) in &self.task_states {
            if let Some(first_block_time) = task_state.first_block_time {
                let blocked_duration_ns = current_time
                    .as_nanos()
                    .saturating_sub(first_block_time.as_nanos());

                if blocked_duration_ns >= starvation_threshold_ns
                    && !task_state.blocked_channels.is_empty()
                {
                    for &channel_id in task_state.blocked_channels.keys() {
                        // Count other producers that were served recently
                        let other_producers_served =
                            self.count_recently_served_producers(channel_id, current_time);

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

        for ((task_id, channel_id, flow_control_type), first_block_time) in
            self.typed_active_waits()
        {
            let blocked_duration_ns = current_time
                .as_nanos()
                .saturating_sub(first_block_time.as_nanos());
            if blocked_duration_ns >= blocking_threshold_ns {
                new_violations.push(FlowControlViolation::IndefiniteBlocking {
                    channel_id,
                    blocked_task: task_id,
                    flow_control_type,
                    block_duration_s: blocked_duration_ns / 1_000_000_000,
                    timestamp: current_time,
                });
            }
        }

        for violation in new_violations {
            self.record_violation(violation, current_time);
        }
    }

    fn check_cancellation_unblock_failures(&mut self, current_time: Time) {
        let cancellation_threshold_ns = self.config.deadlock_detection_threshold_s * 1_000_000_000;
        let mut new_violations = Vec::new();

        for ((task_id, channel_id, flow_control_type), _) in self.typed_active_waits() {
            let Some(task_state) = self.task_states.get(&task_id) else {
                continue;
            };
            let Some(cancel_time) = task_state.cancel_time else {
                continue;
            };

            if !task_state.is_cancelled {
                continue;
            }

            let time_since_cancel_ns = current_time
                .as_nanos()
                .saturating_sub(cancel_time.as_nanos());
            if time_since_cancel_ns < cancellation_threshold_ns {
                continue;
            }

            new_violations.push(FlowControlViolation::CancellationUnblockFailure {
                channel_id,
                cancelled_task: task_id,
                flow_control_type,
                time_since_cancel_s: time_since_cancel_ns / 1_000_000_000,
                timestamp: current_time,
            });
        }

        for violation in new_violations {
            self.record_violation(violation, current_time);
        }
    }

    fn check_terminal_identity(&mut self, event: &FlowControlEvent, current_time: Time) {
        match event {
            FlowControlEvent::BackpressureReleased {
                channel_id,
                consumer_task,
                ..
            } => {
                let has_matching_owner = self
                    .channel_states
                    .get(channel_id)
                    .is_some_and(|state| state.backpressure_consumers.contains_key(consumer_task));
                if !has_matching_owner {
                    self.record_violation(
                        FlowControlViolation::FlowControlInconsistency {
                            channel_id: *channel_id,
                            expected_state: format!(
                                "matching backpressure owner task {consumer_task:?}"
                            ),
                            actual_state: "backpressure release without matching owner".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            FlowControlEvent::ProducerUnblocked {
                channel_id,
                task_id,
                reason,
                ..
            } => {
                let identity = FlowWaitIdentity::producer(*task_id, *channel_id, *reason);
                if !self.has_wait(identity) {
                    self.record_violation(
                        FlowControlViolation::FlowControlInconsistency {
                            channel_id: *channel_id,
                            expected_state: format!(
                                "matching producer wait for task {task_id:?} and reason {reason:?}"
                            ),
                            actual_state: "producer unblock without matching wait".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            FlowControlEvent::ReserveUnblocked {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let identity = FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id);
                if !self.has_wait(identity) {
                    self.record_violation(
                        FlowControlViolation::FlowControlInconsistency {
                            channel_id: *channel_id,
                            expected_state: format!(
                                "matching reserve wait for task {task_id:?} and permit {permit_id}"
                            ),
                            actual_state: "reserve unblock without matching wait".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            FlowControlEvent::CommitFlowControlled {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let has_pending_permit =
                    self.has_wait(FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id));

                if !has_pending_permit {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type: "commit_flow_controlled_without_pending_reserve"
                                .to_string(),
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
                let has_pending_permit =
                    self.has_wait(FlowWaitIdentity::reserve(*task_id, *channel_id, *permit_id));

                if !has_pending_permit {
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
            .filter(|event| match event {
                FlowControlEvent::ProducerUnblocked {
                    channel_id: cid,
                    timestamp,
                    ..
                } => *cid == channel_id && timestamp.as_nanos() >= cutoff_time,
                _ => false,
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

        let related_events = self
            .events
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
        if !self.config.enable_verification {
            return;
        }

        let task_state = self
            .task_states
            .entry(task_id)
            .or_insert_with(new_task_flow_state);
        task_state.is_cancelled = true;
        task_state.cancel_time = Some(
            task_state
                .cancel_time
                .map_or(timestamp, |cancel_time| cancel_time.min(timestamp)),
        );
    }

    /// Returns current flow control statistics.
    pub fn stats(&self) -> FlowControlStats {
        let mut stats = self.stats.clone();

        // Update dynamic statistics
        stats.channels_under_flow_control = self
            .channel_states
            .values()
            .filter(|state| !state.active_controls.is_empty())
            .count() as u64;

        stats.tasks_currently_blocked = self
            .task_states
            .values()
            .filter(|state| !state.blocked_channels.is_empty())
            .count() as u64;

        // Calculate average block time
        if self.total_unblocks > 0 {
            stats.avg_block_time_ms = self.total_blocked_time_ms / self.total_unblocks;
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
            current_time
                .as_nanos()
                .saturating_sub(MAX_TASK_AGE_S * 1_000_000_000),
        );

        // Remove old task states to prevent memory growth
        self.task_states.retain(|_, state| {
            if !state.blocked_channels.is_empty() {
                true
            } else if let Some(cancel_time) = state.cancel_time {
                cancel_time.as_nanos() >= cutoff_time.as_nanos()
            } else {
                false
            }
        });

        // Clean up empty channel states
        self.channel_states.retain(|_, state| {
            !state.blocked_tasks.is_empty()
                || state.backpressure_active
                || !state.active_controls.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
            FlowControlViolation::ProducerStarvation {
                starved_task,
                starvation_duration_s,
                ..
            } => {
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
            FlowControlViolation::PotentialDeadlock {
                involved_tasks,
                involved_channels,
                ..
            } => {
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
            FlowControlViolation::IndefiniteBlocking {
                blocked_task,
                block_duration_s,
                ..
            } => {
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

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::CapacityLimit,
            timestamp: Time::from_nanos(500),
        });
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
        assert!(monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert!(task_state.blocked_channels.contains_key(&channel_id));
        assert_eq!(task_state.first_block_time, Some(now));

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.contains_key(&task_id));
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
        assert!(!monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
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
    fn test_commit_with_pending_reserve_clears_state_without_violation() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(12, 0);
        let channel_id = 88;
        let permit_id = 707;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_nanos(10_000),
        });
        monitor.record_event(FlowControlEvent::CommitFlowControlled {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_nanos(20_000),
        });

        assert!(
            !monitor.violations().iter().any(|report| matches!(
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
            )),
            "valid commit after reserve must not be reported as an atomicity violation"
        );

        let task_state = monitor.task_states.get(&task_id).expect("task state");
        assert!(!monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert!(task_state.blocked_channels.is_empty());
        assert!(task_state.first_block_time.is_none());

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.is_empty());
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
    fn two_permits_on_one_edge_retain_the_remaining_wait() {
        let mut config = FlowControlConfig::default();
        config.starvation_threshold_s = 3;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(13, 0);
        let channel_id = 101;
        let first_permit = 1_001;
        let second_permit = 1_002;
        let first_time = Time::from_secs(1);
        let second_time = Time::from_secs(2);

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: first_permit,
            timestamp: first_time,
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: second_permit,
            timestamp: second_time,
        });

        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            2
        );
        assert_eq!(
            monitor.channel_states[&channel_id].blocked_tasks[&task_id],
            2
        );
        assert_eq!(
            monitor.deadlock_detector.task_to_channel[&task_id][&channel_id],
            2
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(first_time)
        );

        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id: first_permit,
            blocked_duration_ms: 10,
            timestamp: Time::from_secs(3),
        });

        assert!(!monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, first_permit)));
        assert!(monitor.has_wait(FlowWaitIdentity::reserve(
            task_id,
            channel_id,
            second_permit
        )));
        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            monitor.channel_states[&channel_id].blocked_tasks[&task_id],
            1
        );
        assert_eq!(
            monitor.deadlock_detector.task_to_channel[&task_id][&channel_id],
            1
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(second_time)
        );
        assert_eq!(monitor.stats().tasks_currently_blocked, 1);

        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 999,
            consumer_task: TaskId::new_for_test(99, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(4),
        });
        assert!(!monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::ProducerStarvation {
                channel_id: violation_channel,
                starved_task,
                ..
            } if *violation_channel == channel_id && *starved_task == task_id
        )));

        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 999,
            consumer_task: TaskId::new_for_test(99, 0),
            queue_depth: 2,
            timestamp: Time::from_secs(5),
        });
        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::ProducerStarvation {
                channel_id: violation_channel,
                starved_task,
                starvation_duration_s: 3,
                ..
            } if *violation_channel == channel_id && *starved_task == task_id
        )));

        monitor.record_event(FlowControlEvent::CommitFlowControlled {
            channel_id,
            task_id,
            permit_id: second_permit,
            timestamp: Time::from_secs(6),
        });

        assert!(monitor.task_states[&task_id].blocked_channels.is_empty());
        assert!(monitor.channel_states[&channel_id].blocked_tasks.is_empty());
        assert!(
            !monitor
                .deadlock_detector
                .task_to_channel
                .contains_key(&task_id)
        );
        assert_eq!(monitor.stats().tasks_currently_blocked, 0);
    }

    #[test]
    fn mixed_wait_completions_preserve_the_other_wait_on_same_edge() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(14, 0);
        let channel_id = 102;
        let permit_id = 2_001;
        let reason = FlowControlType::CapacityLimit;
        let reserve_time = Time::from_secs(2);

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: reserve_time,
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason,
            blocked_duration_ms: 7,
            timestamp: Time::from_secs(3),
        });

        assert!(!monitor.has_wait(FlowWaitIdentity::producer(task_id, channel_id, reason)));
        assert!(monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(reserve_time)
        );
        assert_eq!(
            monitor.deadlock_detector.task_to_channel[&task_id][&channel_id],
            1
        );

        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 5,
            timestamp: Time::from_secs(4),
        });
        assert!(monitor.task_states[&task_id].blocked_channels.is_empty());

        let mut inverse = FlowControlMonitor::with_defaults();
        inverse.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason,
            timestamp: Time::from_secs(1),
        });
        inverse.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: reserve_time,
        });
        inverse.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 5,
            timestamp: Time::from_secs(3),
        });

        assert!(inverse.has_wait(FlowWaitIdentity::producer(task_id, channel_id, reason)));
        assert!(!inverse.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert_eq!(
            inverse.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            inverse.deadlock_detector.task_to_channel[&task_id][&channel_id],
            1
        );

        inverse.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason,
            blocked_duration_ms: 7,
            timestamp: Time::from_secs(4),
        });
        assert!(inverse.task_states[&task_id].blocked_channels.is_empty());
    }

    #[test]
    fn wrong_channel_terminal_events_preserve_the_real_reserve_wait() {
        let task_id = TaskId::new_for_test(15, 0);
        let real_channel = 103;
        let wrong_channel = 104;
        let permit_id = 3_001;

        let terminal_events = [
            (
                FlowControlEvent::ReserveUnblocked {
                    channel_id: wrong_channel,
                    task_id,
                    permit_id,
                    blocked_duration_ms: 1,
                    timestamp: Time::from_secs(2),
                },
                None,
            ),
            (
                FlowControlEvent::CommitFlowControlled {
                    channel_id: wrong_channel,
                    task_id,
                    permit_id,
                    timestamp: Time::from_secs(2),
                },
                Some("commit_flow_controlled_without_pending_reserve"),
            ),
            (
                FlowControlEvent::AbortDueToFlowControl {
                    channel_id: wrong_channel,
                    task_id,
                    permit_id,
                    timeout_reason: "wrong channel".to_string(),
                    timestamp: Time::from_secs(2),
                },
                Some("abort_without_pending_reserve"),
            ),
        ];

        for (terminal_event, expected_atomicity_type) in terminal_events {
            let mut monitor = FlowControlMonitor::with_defaults();
            monitor.record_event(FlowControlEvent::ReserveBlocked {
                channel_id: real_channel,
                task_id,
                permit_id,
                timestamp: Time::from_secs(1),
            });
            monitor.record_event(terminal_event);

            assert!(monitor.has_wait(FlowWaitIdentity::reserve(task_id, real_channel, permit_id)));
            assert_eq!(
                monitor.task_states[&task_id].blocked_channels[&real_channel],
                1
            );
            assert_eq!(
                monitor.channel_states[&real_channel].blocked_tasks[&task_id],
                1
            );
            assert_eq!(
                monitor.deadlock_detector.task_to_channel[&task_id][&real_channel],
                1
            );
            assert_eq!(monitor.stats().tasks_currently_blocked, 1);
            assert_eq!(monitor.violations().len(), 1);
            let violation = &monitor.violations().back().expect("violation").violation;
            if let Some(expected_type) = expected_atomicity_type {
                assert!(matches!(
                    violation,
                    FlowControlViolation::AtomicityViolation {
                        channel_id: violation_channel,
                        task_id: violation_task,
                        permit_id: violation_permit,
                        violation_type,
                        ..
                    } if *violation_channel == wrong_channel
                        && *violation_task == task_id
                        && *violation_permit == permit_id
                        && violation_type.as_str() == expected_type
                ));
            } else {
                assert!(matches!(
                    violation,
                    FlowControlViolation::FlowControlInconsistency {
                        channel_id: violation_channel,
                        ..
                    } if *violation_channel == wrong_channel
                ));
            }
        }
    }

    #[test]
    fn producer_unblock_requires_the_exact_reason() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(16, 0);
        let channel_id = 105;
        let real_reason = FlowControlType::CreditBased;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: real_reason,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason: FlowControlType::WindowBased,
            blocked_duration_ms: 50,
            timestamp: Time::from_secs(2),
        });

        assert!(monitor.has_wait(FlowWaitIdentity::producer(task_id, channel_id, real_reason)));
        assert_eq!(monitor.total_unblocks, 0);
        assert_eq!(monitor.total_blocked_time_ms, 0);
        assert!(matches!(
            monitor.violations().back().map(|report| &report.violation),
            Some(FlowControlViolation::FlowControlInconsistency { .. })
        ));
    }

    #[test]
    fn duplicate_wait_events_are_idempotent() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(18, 0);
        let channel_id = 107;
        let permit_id = 4_001;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_secs(1),
        });

        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            monitor.channel_states[&channel_id].blocked_tasks[&task_id],
            1
        );
        assert_eq!(
            monitor.deadlock_detector.task_to_channel[&task_id][&channel_id],
            1
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(Time::from_secs(1))
        );

        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 10,
            timestamp: Time::from_secs(3),
        });
        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 50,
            timestamp: Time::from_secs(4),
        });

        assert_eq!(monitor.total_unblocks, 1);
        assert_eq!(monitor.total_blocked_time_ms, 10);
        assert_eq!(monitor.stats().max_block_time_ms, 10);
        assert!(monitor.task_states[&task_id].blocked_channels.is_empty());
        assert!(monitor.channel_states[&channel_id].blocked_tasks.is_empty());
        assert!(
            !monitor
                .deadlock_detector
                .task_to_channel
                .contains_key(&task_id)
        );
        assert!(matches!(
            monitor.violations().back().map(|report| &report.violation),
            Some(FlowControlViolation::FlowControlInconsistency { .. })
        ));
    }

    #[test]
    fn cancellation_before_first_block_is_retained() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(17, 0);
        let channel_id = 106;
        let cancel_time = Time::from_secs(1);

        monitor.record_task_cancel(task_id, cancel_time);
        let cancelled_state = monitor.task_states.get(&task_id).expect("cancelled state");
        assert!(cancelled_state.is_cancelled);
        assert_eq!(cancelled_state.cancel_time, Some(cancel_time));

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::ConsumerBackpressure,
            timestamp: Time::from_secs(2),
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::CancellationUnblockFailure {
                channel_id: violation_channel,
                cancelled_task,
                time_since_cancel_s: 1,
                ..
            } if *violation_channel == channel_id && *cancelled_task == task_id
        )));
    }

    #[test]
    fn disabled_monitor_ignores_task_cancellation() {
        let mut config = FlowControlConfig::default();
        config.enable_verification = false;
        let mut monitor = FlowControlMonitor::new(config);

        monitor.record_task_cancel(TaskId::new_for_test(19, 0), Time::from_secs(1));

        assert!(monitor.task_states.is_empty());
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

    #[test]
    fn producer_control_refcounts_follow_live_waits() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let channel_id = 201;
        let reason = FlowControlType::RateLimit;
        let first_task = TaskId::new_for_test(21, 0);
        let second_task = TaskId::new_for_test(22, 0);

        for task_id in [first_task, second_task] {
            monitor.record_event(FlowControlEvent::ProducerBlocked {
                channel_id,
                task_id,
                reason,
                timestamp: Time::from_secs(1),
            });
        }

        assert_eq!(
            monitor.channel_states[&channel_id]
                .active_controls
                .get(&reason),
            Some(&2)
        );
        assert_eq!(monitor.stats().channels_under_flow_control, 1);

        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id: first_task,
            reason,
            blocked_duration_ms: 1,
            timestamp: Time::from_secs(2),
        });
        assert_eq!(
            monitor.channel_states[&channel_id]
                .active_controls
                .get(&reason),
            Some(&1)
        );
        assert_eq!(monitor.stats().channels_under_flow_control, 1);

        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id: second_task,
            reason,
            blocked_duration_ms: 1,
            timestamp: Time::from_secs(2),
        });
        assert!(
            monitor.channel_states[&channel_id]
                .active_controls
                .is_empty()
        );
        assert_eq!(monitor.stats().channels_under_flow_control, 0);

        monitor.cleanup_old_state(Time::from_secs(400));
        assert!(!monitor.channel_states.contains_key(&channel_id));
    }

    #[test]
    fn backpressure_control_refcounts_follow_consumer_owners() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let channel_id = 202;
        let first_consumer = TaskId::new_for_test(23, 0);
        let second_consumer = TaskId::new_for_test(24, 0);
        let unknown_consumer = TaskId::new_for_test(25, 0);

        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: first_consumer,
            queue_depth: 2,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: first_consumer,
            queue_depth: 3,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: second_consumer,
            queue_depth: 4,
            timestamp: Time::from_secs(3),
        });

        let state = &monitor.channel_states[&channel_id];
        assert_eq!(
            state
                .active_controls
                .get(&FlowControlType::ConsumerBackpressure),
            Some(&2)
        );
        assert_eq!(state.backpressure_start_time, Some(Time::from_secs(1)));

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id,
            consumer_task: unknown_consumer,
            new_queue_depth: 3,
            timestamp: Time::from_secs(4),
        });
        assert_eq!(
            monitor.channel_states[&channel_id]
                .active_controls
                .get(&FlowControlType::ConsumerBackpressure),
            Some(&2)
        );
        assert!(matches!(
            monitor.violations().back().map(|report| &report.violation),
            Some(FlowControlViolation::FlowControlInconsistency { .. })
        ));

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id,
            consumer_task: first_consumer,
            new_queue_depth: 2,
            timestamp: Time::from_secs(5),
        });
        let state = &monitor.channel_states[&channel_id];
        assert_eq!(
            state
                .active_controls
                .get(&FlowControlType::ConsumerBackpressure),
            Some(&1)
        );
        assert!(state.backpressure_active);
        assert_eq!(state.backpressure_start_time, Some(Time::from_secs(3)));

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id,
            consumer_task: second_consumer,
            new_queue_depth: 0,
            timestamp: Time::from_secs(6),
        });
        let state = &monitor.channel_states[&channel_id];
        assert!(state.active_controls.is_empty());
        assert!(!state.backpressure_active);
        assert!(state.backpressure_start_time.is_none());
        assert_eq!(monitor.stats().channels_under_flow_control, 0);
    }

    #[test]
    fn reserve_wait_reports_capacity_for_indefinite_and_cancellation() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(26, 0);
        let channel_id = 203;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: 5_001,
            timestamp: Time::from_secs(1),
        });
        monitor.record_task_cancel(task_id, Time::from_secs(2));
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 999,
            consumer_task: TaskId::new_for_test(27, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(4),
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::IndefiniteBlocking {
                channel_id: violation_channel,
                blocked_task,
                flow_control_type: FlowControlType::CapacityLimit,
                block_duration_s: 3,
                ..
            } if *violation_channel == channel_id && *blocked_task == task_id
        )));
        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::CancellationUnblockFailure {
                channel_id: violation_channel,
                cancelled_task,
                flow_control_type: FlowControlType::CapacityLimit,
                time_since_cancel_s: 2,
                ..
            } if *violation_channel == channel_id && *cancelled_task == task_id
        )));
    }

    #[test]
    fn typed_wait_violations_do_not_cross_attribute_channel_controls() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let channel_id = 204;
        let rate_limited = TaskId::new_for_test(28, 0);
        let capacity_limited = TaskId::new_for_test(29, 0);

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id: rate_limited,
            reason: FlowControlType::RateLimit,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id: capacity_limited,
            reason: FlowControlType::CapacityLimit,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 998,
            consumer_task: TaskId::new_for_test(30, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(3),
        });

        let typed_reports: Vec<_> = monitor
            .violations()
            .iter()
            .filter_map(|report| match report.violation {
                FlowControlViolation::IndefiniteBlocking {
                    channel_id: violation_channel,
                    blocked_task,
                    flow_control_type,
                    ..
                } if violation_channel == channel_id => Some((blocked_task, flow_control_type)),
                _ => None,
            })
            .collect();
        assert_eq!(typed_reports.len(), 2);
        assert!(typed_reports.contains(&(rate_limited, FlowControlType::RateLimit)));
        assert!(typed_reports.contains(&(capacity_limited, FlowControlType::CapacityLimit)));
    }

    #[test]
    fn removed_producer_reason_does_not_label_later_reserve_wait() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(31, 0);
        let channel_id = 205;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::RateLimit,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason: FlowControlType::RateLimit,
            blocked_duration_ms: 1,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: 5_002,
            timestamp: Time::from_secs(3),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 997,
            consumer_task: TaskId::new_for_test(32, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(5),
        });

        let reported_types: Vec<_> = monitor
            .violations()
            .iter()
            .filter_map(|report| match report.violation {
                FlowControlViolation::IndefiniteBlocking {
                    channel_id: violation_channel,
                    blocked_task,
                    flow_control_type,
                    ..
                } if violation_channel == channel_id && blocked_task == task_id => {
                    Some(flow_control_type)
                }
                _ => None,
            })
            .collect();
        assert_eq!(reported_types, vec![FlowControlType::CapacityLimit]);
    }
}
