#![allow(clippy::all)]
//! Channel state consistency validation during cancellation scenarios.

use crate::cancel_harness::{ChannelType, CancelScenario, ProtocolViolation};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::fmt::Debug;

/// Validates that channel state remains consistent during cancellation operations.
#[allow(dead_code)]
pub struct StateValidator {
    /// Tracked state snapshots by channel ID.
    state_snapshots: Arc<Mutex<HashMap<String, Vec<StateSnapshot>>>>,
    /// Configuration for validation.
    config: StateValidationConfig,
}

/// Configuration for state validation behavior.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StateValidationConfig {
    /// Whether to track detailed state transitions.
    pub track_transitions: bool,
    /// Maximum number of snapshots to retain per channel.
    pub max_snapshots: usize,
    /// Whether to validate state immediately or defer.
    pub immediate_validation: bool,
    /// Timeout for state consistency checks.
    pub consistency_timeout: Duration,
}

impl Default for StateValidationConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            track_transitions: true,
            max_snapshots: 100,
            immediate_validation: true,
            consistency_timeout: Duration::from_millis(100),
        }
    }
}

#[allow(dead_code)]

impl StateValidator {
    /// Create a new state validator.
    #[allow(dead_code)]
    pub fn new(config: StateValidationConfig) -> Self {
        Self {
            state_snapshots: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Take a snapshot of channel state.
    #[allow(dead_code)]
    pub fn snapshot_state<T: Debug + Clone + Send + 'static>(
        &self,
        channel_id: &str,
        channel_type: ChannelType,
        state: ChannelState<T>,
    ) {
        if let Ok(mut snapshots) = self.state_snapshots.lock() {
            let snapshot = StateSnapshot {
                timestamp: Instant::now(),
                channel_type,
                state: Box::new(state),
                operation_context: None,
            };

            let channel_snapshots = snapshots.entry(channel_id.to_string()).or_insert_with(Vec::new);

            // Add snapshot
            channel_snapshots.push(snapshot);

            // Limit retention
            if channel_snapshots.len() > self.config.max_snapshots {
                channel_snapshots.remove(0);
            }
        }
    }

    /// Validate state consistency for a channel.
    #[allow(dead_code)]
    pub fn validate_consistency(&self, channel_id: &str) -> Vec<ProtocolViolation> {
        let snapshots = if let Ok(state_map) = self.state_snapshots.lock() {
            state_map.get(channel_id).cloned().unwrap_or_default()
        } else {
            return vec![];
        };

        let mut violations = Vec::new();

        // Check for state transition violations
        for window in snapshots.windows(2) {
            if let [prev, curr] = window {
                if let Some(violation) = self.check_state_transition(prev, curr) {
                    violations.push(violation);
                }
            }
        }

        // Check for state invariant violations
        for snapshot in &snapshots {
            if let Some(violation) = self.check_state_invariants(snapshot) {
                violations.push(violation);
            }
        }

        violations
    }

    /// Reset state tracking for a channel.
    #[allow(dead_code)]
    pub fn reset_channel(&self, channel_id: &str) {
        if let Ok(mut snapshots) = self.state_snapshots.lock() {
            snapshots.remove(channel_id);
        }
    }

    /// Reset all state tracking.
    #[allow(dead_code)]
    pub fn reset_all(&self) {
        if let Ok(mut snapshots) = self.state_snapshots.lock() {
            snapshots.clear();
        }
    }

    /// Get state snapshots for a channel.
    #[allow(dead_code)]
    pub fn get_snapshots(&self, channel_id: &str) -> Vec<StateSnapshot> {
        self.state_snapshots
            .lock()
            .ok()
            .and_then(|snapshots| snapshots.get(channel_id).cloned())
            .unwrap_or_default()
    }

    /// Check if a state transition is valid.
    #[allow(dead_code)]
    fn check_state_transition(
        &self,
        prev: &StateSnapshot,
        curr: &StateSnapshot,
    ) -> Option<ProtocolViolation> {
        // Ensure timestamps are ordered
        if curr.timestamp < prev.timestamp {
            return Some(ProtocolViolation::StateInconsistency {
                channel_type: curr.channel_type,
                expected_state: "chronological order".to_string(),
                actual_state: "backwards timestamp".to_string(),
            });
        }

        // Channel-specific transition validation
        match (prev.channel_type, curr.channel_type) {
            (ChannelType::Mpsc, ChannelType::Mpsc) => self.validate_mpsc_transition(prev, curr),
            (ChannelType::Broadcast, ChannelType::Broadcast) => self.validate_broadcast_transition(prev, curr),
            (ChannelType::Watch, ChannelType::Watch) => self.validate_watch_transition(prev, curr),
            (ChannelType::Oneshot, ChannelType::Oneshot) => self.validate_oneshot_transition(prev, curr),
            _ => Some(ProtocolViolation::StateInconsistency {
                channel_type: curr.channel_type,
                expected_state: format!("{}", prev.channel_type),
                actual_state: format!("{}", curr.channel_type),
            }),
        }
    }

    /// Check state invariants for a snapshot.
    #[allow(dead_code)]
    fn check_state_invariants(&self, snapshot: &StateSnapshot) -> Option<ProtocolViolation> {
        // Channel-specific invariant validation
        match snapshot.channel_type {
            ChannelType::Mpsc => self.validate_mpsc_invariants(snapshot),
            ChannelType::Broadcast => self.validate_broadcast_invariants(snapshot),
            ChannelType::Watch => self.validate_watch_invariants(snapshot),
            ChannelType::Oneshot => self.validate_oneshot_invariants(snapshot),
        }
    }

    /// Validate MPSC state transitions.
    #[allow(dead_code)]
    fn validate_mpsc_transition(
        &self,
        prev: &StateSnapshot,
        curr: &StateSnapshot,
    ) -> Option<ProtocolViolation> {
        // MPSC-specific validation logic would go here
        // For now, placeholder validation
        None
    }

    /// Validate broadcast state transitions.
    #[allow(dead_code)]
    fn validate_broadcast_transition(
        &self,
        prev: &StateSnapshot,
        curr: &StateSnapshot,
    ) -> Option<ProtocolViolation> {
        // Broadcast-specific validation logic would go here
        None
    }

    /// Validate watch state transitions.
    #[allow(dead_code)]
    fn validate_watch_transition(
        &self,
        prev: &StateSnapshot,
        curr: &StateSnapshot,
    ) -> Option<ProtocolViolation> {
        // Watch-specific validation logic would go here
        None
    }

    /// Validate oneshot state transitions.
    #[allow(dead_code)]
    fn validate_oneshot_transition(
        &self,
        prev: &StateSnapshot,
        curr: &StateSnapshot,
    ) -> Option<ProtocolViolation> {
        // Oneshot-specific validation logic would go here
        None
    }

    /// Validate MPSC state invariants.
    #[allow(dead_code)]
    fn validate_mpsc_invariants(&self, snapshot: &StateSnapshot) -> Option<ProtocolViolation> {
        // MPSC invariant validation would go here
        None
    }

    /// Validate broadcast state invariants.
    #[allow(dead_code)]
    fn validate_broadcast_invariants(&self, snapshot: &StateSnapshot) -> Option<ProtocolViolation> {
        // Broadcast invariant validation would go here
        None
    }

    /// Validate watch state invariants.
    #[allow(dead_code)]
    fn validate_watch_invariants(&self, snapshot: &StateSnapshot) -> Option<ProtocolViolation> {
        // Watch invariant validation would go here
        None
    }

    /// Validate oneshot state invariants.
    #[allow(dead_code)]
    fn validate_oneshot_invariants(&self, snapshot: &StateSnapshot) -> Option<ProtocolViolation> {
        // Oneshot invariant validation would go here
        None
    }
}

/// A snapshot of channel state at a specific point in time.
#[derive(Debug)]
#[allow(dead_code)]
pub struct StateSnapshot {
    /// When the snapshot was taken.
    pub timestamp: Instant,
    /// Type of channel.
    pub channel_type: ChannelType,
    /// The actual channel state.
    pub state: Box<dyn StateContainer>,
    /// Optional operation context.
    pub operation_context: Option<OperationContext>,
}

/// Context about the operation that led to this state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OperationContext {
    /// Type of operation performed.
    pub operation_type: OperationType,
    /// Whether the operation was cancelled.
    pub was_cancelled: bool,
    /// Duration of the operation.
    pub duration: Duration,
    /// Additional operation-specific metadata.
    pub metadata: HashMap<String, String>,
}

/// Types of operations that can be performed on channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum OperationType {
    Send,
    Receive,
    Reserve,
    Commit,
    Drop,
    Cancel,
    Clone,
}

impl std::fmt::Display for OperationType {
    #[allow(dead_code)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationType::Send => write!(f, "send"),
            OperationType::Receive => write!(f, "receive"),
            OperationType::Reserve => write!(f, "reserve"),
            OperationType::Commit => write!(f, "commit"),
            OperationType::Drop => write!(f, "drop"),
            OperationType::Cancel => write!(f, "cancel"),
            OperationType::Clone => write!(f, "clone"),
        }
    }
}

/// Trait for types that can be stored in state snapshots.
pub trait StateContainer: Debug + Send + Sync {
    /// Get a description of the state.
    #[allow(dead_code)]
    fn describe(&self) -> String;

    /// Check if the state is consistent.
    #[allow(dead_code)]
    fn is_consistent(&self) -> bool;

    /// Get state-specific metrics.
    #[allow(dead_code)]
    fn get_metrics(&self) -> HashMap<String, f64>;
}

/// Generic channel state representation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChannelState<T: Debug + Clone> {
    /// Number of active senders.
    pub sender_count: usize,
    /// Number of active receivers.
    pub receiver_count: usize,
    /// Number of queued items.
    pub queue_length: usize,
    /// Channel capacity.
    pub capacity: Option<usize>,
    /// Whether the channel is closed.
    pub is_closed: bool,
    /// Whether the channel is in a cancelled state.
    pub is_cancelled: bool,
    /// Number of waiting operations.
    pub waiting_operations: usize,
    /// Channel-specific state data.
    pub specific_state: T,
}

impl<T: Debug + Clone + Send + Sync + 'static> StateContainer for ChannelState<T> {
    #[allow(dead_code)]
    fn describe(&self) -> String {
        format!(
            "senders: {}, receivers: {}, queue: {}/{:?}, closed: {}, cancelled: {}, waiting: {}",
            self.sender_count,
            self.receiver_count,
            self.queue_length,
            self.capacity,
            self.is_closed,
            self.is_cancelled,
            self.waiting_operations
        )
    }

    #[allow(dead_code)]

    fn is_consistent(&self) -> bool {
        // Basic consistency checks
        if let Some(capacity) = self.capacity {
            if self.queue_length > capacity {
                return false;
            }
        }

        // Can't have waiting operations if closed and empty
        if self.is_closed && self.queue_length == 0 && self.waiting_operations > 0 {
            return false;
        }

        // Channel-specific consistency would be checked here
        true
    }

    #[allow(dead_code)]

    fn get_metrics(&self) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();
        metrics.insert("sender_count".to_string(), self.sender_count as f64);
        metrics.insert("receiver_count".to_string(), self.receiver_count as f64);
        metrics.insert("queue_length".to_string(), self.queue_length as f64);
        metrics.insert("waiting_operations".to_string(), self.waiting_operations as f64);
        metrics.insert("is_closed".to_string(), if self.is_closed { 1.0 } else { 0.0 });
        metrics.insert("is_cancelled".to_string(), if self.is_cancelled { 1.0 } else { 0.0 });
        if let Some(capacity) = self.capacity {
            metrics.insert("capacity".to_string(), capacity as f64);
            metrics.insert("utilization".to_string(),
                          self.queue_length as f64 / capacity as f64);
        }
        metrics
    }
}

/// Specific state for MPSC channels.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MpscChannelState {
    /// Number of permits currently reserved.
    pub reserved_permits: usize,
    /// Number of permits available.
    pub available_permits: usize,
    /// Whether the receiver is currently polling.
    pub receiver_polling: bool,
}

/// Specific state for broadcast channels.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BroadcastChannelState {
    /// Current sequence number.
    pub sequence_number: u64,
    /// Number of lagging receivers.
    pub lagging_receivers: usize,
    /// Whether the channel is overflowing.
    pub is_overflowing: bool,
}

/// Specific state for watch channels.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WatchChannelState {
    /// Current version number.
    pub version: u64,
    /// Whether the value has been seen by all receivers.
    pub all_seen: bool,
    /// Number of receivers waiting for changes.
    pub waiting_receivers: usize,
}

/// Specific state for oneshot channels.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OneshotChannelState {
    /// Whether the value has been sent.
    pub value_sent: bool,
    /// Whether the value has been received.
    pub value_received: bool,
    /// Whether the sender was dropped.
    pub sender_dropped: bool,
    /// Whether the receiver was dropped.
    pub receiver_dropped: bool,
}

/// RAII guard for automatic state validation within a scope.
#[allow(dead_code)]
pub struct StateValidationScope<'a> {
    validator: &'a StateValidator,
    channel_id: String,
    initial_snapshot_count: usize,
}

impl<'a> StateValidationScope<'a> {
    /// Create a new validation scope.
    #[allow(dead_code)]
    pub fn new(validator: &'a StateValidator, channel_id: impl Into<String>) -> Self {
        let channel_id = channel_id.into();
        let initial_snapshot_count = validator.get_snapshots(&channel_id).len();

        Self {
            validator,
            channel_id,
            initial_snapshot_count,
        }
    }

    /// Validate state consistency for this scope.
    #[allow(dead_code)]
    pub fn validate(&self) -> Vec<ProtocolViolation> {
        self.validator.validate_consistency(&self.channel_id)
    }

    /// Get the number of new snapshots taken in this scope.
    #[allow(dead_code)]
    pub fn snapshot_count_delta(&self) -> usize {
        let current_count = self.validator.get_snapshots(&self.channel_id).len();
        current_count.saturating_sub(self.initial_snapshot_count)
    }
}

impl<'a> Drop for StateValidationScope<'a> {
    #[allow(dead_code)]
    fn drop(&mut self) {
        // Automatically validate on drop if configured to do so
        if self.validator.config.immediate_validation {
            let violations = self.validate();
            if !violations.is_empty() {
                eprintln!("State validation failures in scope for channel '{}': {:?}",
                         self.channel_id, violations);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_state_validator_basic() {
        let validator = StateValidator::new(StateValidationConfig::default());

        let mpsc_state = ChannelState {
            sender_count: 1,
            receiver_count: 1,
            queue_length: 0,
            capacity: Some(10),
            is_closed: false,
            is_cancelled: false,
            waiting_operations: 0,
            specific_state: MpscChannelState {
                reserved_permits: 0,
                available_permits: 10,
                receiver_polling: false,
            },
        };

        validator.snapshot_state("test_channel", ChannelType::Mpsc, mpsc_state);

        let violations = validator.validate_consistency("test_channel");
        assert!(violations.is_empty());
    }

    #[test]
    #[allow(dead_code)]
    fn test_state_validation_scope() {
        let validator = StateValidator::new(StateValidationConfig::default());

        {
            let scope = StateValidationScope::new(&validator, "scoped_channel");

            let state = ChannelState {
                sender_count: 1,
                receiver_count: 1,
                queue_length: 0,
                capacity: Some(5),
                is_closed: false,
                is_cancelled: false,
                waiting_operations: 0,
                specific_state: MpscChannelState {
                    reserved_permits: 0,
                    available_permits: 5,
                    receiver_polling: false,
                },
            };

            validator.snapshot_state("scoped_channel", ChannelType::Mpsc, state);

            assert_eq!(scope.snapshot_count_delta(), 1);
        }
        // Scope automatically validates on drop
    }

    #[test]
    #[allow(dead_code)]
    fn test_channel_state_consistency() {
        // Test with inconsistent state (queue length exceeds capacity)
        let bad_state = ChannelState {
            sender_count: 1,
            receiver_count: 1,
            queue_length: 15,  // Exceeds capacity
            capacity: Some(10),
            is_closed: false,
            is_cancelled: false,
            waiting_operations: 0,
            specific_state: MpscChannelState {
                reserved_permits: 0,
                available_permits: 0,
                receiver_polling: false,
            },
        };

        assert!(!bad_state.is_consistent());

        // Test with consistent state
        let good_state = ChannelState {
            sender_count: 1,
            receiver_count: 1,
            queue_length: 5,
            capacity: Some(10),
            is_closed: false,
            is_cancelled: false,
            waiting_operations: 0,
            specific_state: MpscChannelState {
                reserved_permits: 0,
                available_permits: 5,
                receiver_polling: false,
            },
        };

        assert!(good_state.is_consistent());
    }
}