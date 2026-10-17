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
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque, hash_map::Entry};
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

type DeadlockCycleKey = Vec<(TaskId, u64)>;

#[derive(Debug, Clone, Copy)]
struct DeadlockGraphEdge {
    waiting_task: TaskId,
    channel_id: u64,
    owner_task: TaskId,
    live_since: Time,
}

/// Deadlock detection state that cannot drift from the canonical live records.
///
/// Wait and ownership edges are derived for every detection pass from
/// `active_waits` and `ChannelFlowState::backpressure_consumers`. The only
/// retained state is the map of continuous live episodes and whether each has
/// crossed the reporting threshold.
#[derive(Debug, Clone)]
struct DeadlockDetector {
    live_episodes: BTreeMap<DeadlockCycleKey, DeadlockEpisode>,
}

#[derive(Debug, Clone)]
struct DeadlockEpisode {
    cycle: DeadlockCycle,
    first_live_at: Time,
    reported: bool,
}

impl DeadlockDetector {
    fn new() -> Self {
        Self {
            live_episodes: BTreeMap::new(),
        }
    }

    fn detect_deadlocks(
        &mut self,
        active_waits: &HashMap<FlowWaitIdentity, Time>,
        channel_states: &HashMap<u64, ChannelFlowState>,
        current_time: Time,
        threshold_s: u64,
    ) -> Vec<FlowControlViolation> {
        let adjacency = Self::build_adjacency(active_waits, channel_states);
        self.live_episodes
            .retain(|key, _| Self::cycle_key_is_live(key, &adjacency));

        for cycle in Self::find_cycles(&adjacency) {
            match self.live_episodes.entry(cycle.key.clone()) {
                std::collections::btree_map::Entry::Occupied(mut episode) => {
                    let episode = episode.get_mut();
                    episode.first_live_at = episode.first_live_at.min(cycle.live_since);
                }
                std::collections::btree_map::Entry::Vacant(episode) => {
                    let first_live_at = cycle.live_since;
                    episode.insert(DeadlockEpisode {
                        cycle,
                        first_live_at,
                        reported: false,
                    });
                }
            }
        }

        let threshold_ns = threshold_s.saturating_mul(1_000_000_000);
        let mut violations = Vec::new();
        for episode in self.live_episodes.values_mut() {
            let age_ns = current_time
                .as_nanos()
                .saturating_sub(episode.first_live_at.as_nanos());
            if age_ns < threshold_ns || episode.reported {
                continue;
            }
            episode.reported = true;
            violations.push(FlowControlViolation::PotentialDeadlock {
                involved_channels: episode.cycle.channels.clone(),
                involved_tasks: episode.cycle.tasks.clone(),
                cycle_description: episode.cycle.description.clone(),
                detection_time: current_time,
            });
        }
        violations
    }

    fn build_adjacency(
        active_waits: &HashMap<FlowWaitIdentity, Time>,
        channel_states: &HashMap<u64, ChannelFlowState>,
    ) -> BTreeMap<TaskId, Vec<DeadlockGraphEdge>> {
        let mut wait_starts = BTreeMap::new();
        for (identity, timestamp) in active_waits {
            wait_starts
                .entry((identity.task_id, identity.channel_id))
                .and_modify(|first: &mut Time| *first = (*first).min(*timestamp))
                .or_insert(*timestamp);
        }

        let mut adjacency: BTreeMap<TaskId, Vec<DeadlockGraphEdge>> = BTreeMap::new();
        for ((waiting_task, channel_id), wait_since) in wait_starts {
            let Some(channel_state) = channel_states.get(&channel_id) else {
                continue;
            };
            let mut owners: Vec<_> = channel_state
                .backpressure_consumers
                .iter()
                .map(|(&owner_task, &owner_since)| (owner_task, owner_since))
                .collect();
            owners.sort_by_key(|(owner_task, _)| *owner_task);

            let edges = adjacency.entry(waiting_task).or_default();
            for (owner_task, owner_since) in owners {
                edges.push(DeadlockGraphEdge {
                    waiting_task,
                    channel_id,
                    owner_task,
                    live_since: wait_since.max(owner_since),
                });
            }
        }
        adjacency
    }

    fn cycle_key_is_live(
        key: &DeadlockCycleKey,
        adjacency: &BTreeMap<TaskId, Vec<DeadlockGraphEdge>>,
    ) -> bool {
        !key.is_empty()
            && key.iter().zip(key.iter().cycle().skip(1)).all(
                |((waiting_task, channel_id), (next_task, _))| {
                    adjacency.get(waiting_task).is_some_and(|edges| {
                        edges.iter().any(|edge| {
                            edge.channel_id == *channel_id && edge.owner_task == *next_task
                        })
                    })
                },
            )
    }

    fn find_cycles(adjacency: &BTreeMap<TaskId, Vec<DeadlockGraphEdge>>) -> Vec<DeadlockCycle> {
        let mut visited = HashSet::new();
        let mut cycles = Vec::new();

        for &root in adjacency.keys() {
            if visited.contains(&root) {
                continue;
            }
            visited.insert(root);
            let mut stack_positions = HashMap::from([(root, 0)]);
            let mut current_path = Vec::new();
            let mut frames = vec![(root, 0usize)];

            while let Some((task, next_edge)) = frames.last_mut() {
                let edges = adjacency.get(task).map_or(&[][..], Vec::as_slice);
                if *next_edge == edges.len() {
                    let completed_task = *task;
                    let _ = frames.pop();
                    let _ = stack_positions.remove(&completed_task);
                    if !frames.is_empty() {
                        let _ = current_path.pop();
                    }
                    continue;
                }

                let edge = edges[*next_edge];
                *next_edge += 1;
                current_path.push(edge);
                if let Some(&cycle_start) = stack_positions.get(&edge.owner_task) {
                    cycles.push(DeadlockCycle::from_path(&current_path[cycle_start..]));
                } else if visited.insert(edge.owner_task) {
                    let _ = stack_positions.insert(edge.owner_task, current_path.len());
                    frames.push((edge.owner_task, 0));
                    continue;
                }
                let _ = current_path.pop();
            }
        }
        cycles
    }
}

#[derive(Debug, Clone)]
struct DeadlockCycle {
    key: DeadlockCycleKey,
    tasks: Vec<TaskId>,
    channels: Vec<u64>,
    description: String,
    live_since: Time,
}

impl DeadlockCycle {
    fn from_path(path: &[DeadlockGraphEdge]) -> Self {
        let mut key: DeadlockCycleKey = path
            .iter()
            .map(|edge| (edge.waiting_task, edge.channel_id))
            .collect();
        if let Some((canonical_start, _)) = key.iter().enumerate().min_by_key(|(_, edge)| **edge) {
            key.rotate_left(canonical_start);
        }

        let tasks: Vec<TaskId> = key.iter().map(|(task, _)| *task).collect();
        let channels: Vec<u64> = key.iter().map(|(_, channel)| *channel).collect();

        let description = format!(
            "Circular dependency: {}",
            key.iter()
                .map(|(task, channel)| format!("T{:?}→C{}", task, channel))
                .collect::<Vec<_>>()
                .join("→")
        );
        let live_since = path
            .iter()
            .map(|edge| edge.live_since)
            .fold(Time::ZERO, Time::max);

        Self {
            key,
            tasks,
            channels,
            description,
            live_since,
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
            let deadlocks = self.deadlock_detector.detect_deadlocks(
                &self.active_waits,
                &self.channel_states,
                current_time,
                self.config.deadlock_detection_threshold_s,
            );
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
#[path = "flow_control_monitor_inline_tests.rs"]
mod tests;
