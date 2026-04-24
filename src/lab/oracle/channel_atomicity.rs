//! Channel Atomicity Verification Framework
//!
//! This oracle verifies that channel operations maintain atomicity guarantees
//! in the presence of cancellation, ensuring that the two-phase reserve/commit
//! protocol prevents data loss and maintains consistent state.
//!
//! # Core Guarantees Verified
//!
//! 1. **Reservation Lifecycle**: Every reservation must be either committed or aborted
//! 2. **No Double Operations**: Cannot commit/abort the same reservation twice
//! 3. **No Use After Operations**: Cannot use reservation after commit/abort
//! 4. **Waker Consistency**: Lost/spurious wakeups detection and prevention
//! 5. **Cancel-Safe Operations**: No data loss when operations are cancelled
//!
//! # Usage
//!
//! ```rust
//! use asupersync::lab::oracle::channel_atomicity::{ChannelAtomicityOracle, ChannelAtomicityConfig};
//!
//! let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
//!     track_reservations: true,
//!     track_wakers: true,
//!     enforcement: EnforcementMode::Panic,
//!     structured_logging: true,
//!     ..Default::default()
//! });
//!
//! // Hook into channel operations
//! oracle.on_reservation_created(reservation_id, channel_id, Some(trace_id));
//! oracle.on_reservation_committed(reservation_id, data_size);
//! oracle.on_reservation_aborted(reservation_id, reason);
//! ```

use crate::trace::distributed::TraceId;
use crate::util::stack_trace;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique identifier for a channel reservation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReservationId(pub u64);

/// Unique identifier for a channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub u64);

/// Unique identifier for a waker
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WakerId(pub u64);

/// Configuration for the Channel Atomicity Oracle
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChannelAtomicityConfig {
    /// Whether to track reservation lifecycles
    pub track_reservations: bool,
    /// Whether to track waker patterns
    pub track_wakers: bool,
    /// Enforcement mode for violations
    pub enforcement: EnforcementMode,
    /// Enable structured logging for violations
    pub structured_logging: bool,
    /// Include stack traces in violation records
    pub include_stack_traces: bool,
    /// Enable replay command generation for violations
    pub enable_replay_commands: bool,
    /// Maximum number of violations to track before dropping oldest
    pub max_violations_tracked: usize,
    /// Maximum age of reservations to track (for cleanup)
    pub max_reservation_age_seconds: u64,
    /// Maximum number of reservations to track per channel
    pub max_reservations_per_channel: usize,
}

impl Default for ChannelAtomicityConfig {
    fn default() -> Self {
        Self {
            track_reservations: true,
            track_wakers: true,
            enforcement: EnforcementMode::Warn,
            structured_logging: false,
            include_stack_traces: false,
            enable_replay_commands: false,
            max_violations_tracked: 1000,
            max_reservation_age_seconds: 3600, // 1 hour
            max_reservations_per_channel: 10000,
        }
    }
}

/// Enforcement mode for atomicity violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Only collect violations, no immediate action
    Collect,
    /// Emit warnings for violations
    Warn,
    /// Panic on violations (for testing)
    Panic,
}

/// Types of channel atomicity violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelAtomicityViolation {
    /// Reservation was created but never committed or aborted
    ReservationLeak {
        /// ID of the leaked reservation.
        reservation_id: ReservationId,
        /// ID of the channel where the leak occurred.
        channel_id: ChannelId,
        /// Timestamp when the reservation was created.
        created_at: SystemTime,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Attempt to commit an already committed reservation
    DoubleCommit {
        /// ID of the reservation that was double-committed.
        reservation_id: ReservationId,
        /// ID of the channel where the double commit occurred.
        channel_id: ChannelId,
        /// Timestamp of the first commit.
        first_commit_at: SystemTime,
        /// Timestamp of the second (invalid) commit.
        second_commit_at: SystemTime,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Attempt to abort an already aborted reservation
    DoubleAbort {
        /// ID of the reservation that was double-aborted.
        reservation_id: ReservationId,
        /// ID of the channel where the double abort occurred.
        channel_id: ChannelId,
        /// Timestamp of the first abort.
        first_abort_at: SystemTime,
        /// Timestamp of the second (invalid) abort.
        second_abort_at: SystemTime,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Attempt to use reservation after commit
    UseAfterCommit {
        /// ID of the reservation used after commit.
        reservation_id: ReservationId,
        /// ID of the channel where the violation occurred.
        channel_id: ChannelId,
        /// Timestamp when the reservation was committed.
        commit_at: SystemTime,
        /// Timestamp of the invalid use attempt.
        use_at: SystemTime,
        /// Description of the invalid operation attempted.
        operation: String,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Attempt to use reservation after abort
    UseAfterAbort {
        /// ID of the reservation used after abort.
        reservation_id: ReservationId,
        /// ID of the channel where the violation occurred.
        channel_id: ChannelId,
        /// Timestamp when the reservation was aborted.
        abort_at: SystemTime,
        /// Timestamp of the invalid use attempt.
        use_at: SystemTime,
        /// Description of the invalid operation attempted.
        operation: String,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Wakeup lost during channel operation
    LostWakeup {
        /// ID of the waker that lost its wakeup.
        waker_id: WakerId,
        /// ID of the channel where the wakeup was lost.
        channel_id: ChannelId,
        /// Timestamp when the wakeup was expected.
        expected_at: SystemTime,
        /// Timestamp when the loss was detected.
        detected_at: SystemTime,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Spurious wakeup without corresponding channel event
    SpuriousWakeup {
        /// ID of the waker that had a spurious wakeup.
        waker_id: WakerId,
        /// ID of the channel where the spurious wakeup occurred.
        channel_id: ChannelId,
        /// Timestamp of the spurious wakeup.
        wakeup_at: SystemTime,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
    /// Data loss detected during cancellation
    DataLossOnCancel {
        /// ID of the channel where data loss occurred.
        channel_id: ChannelId,
        /// Size of the lost data in bytes.
        data_size: usize,
        /// Timestamp when cancellation occurred.
        cancel_at: SystemTime,
        /// Optional trace ID for debugging context.
        trace_id: Option<TraceId>,
    },
}

impl std::fmt::Display for ChannelAtomicityViolation {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReservationLeak {
                reservation_id,
                channel_id,
                created_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Reservation leak: {reservation_id:?} on channel {channel_id:?} created at {created_at:?}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::DoubleCommit {
                reservation_id,
                channel_id,
                first_commit_at,
                second_commit_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Double commit: {reservation_id:?} on channel {channel_id:?} first at {first_commit_at:?}, second at {second_commit_at:?}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::DoubleAbort {
                reservation_id,
                channel_id,
                first_abort_at,
                second_abort_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Double abort: {reservation_id:?} on channel {channel_id:?} first at {first_abort_at:?}, second at {second_abort_at:?}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::UseAfterCommit {
                reservation_id,
                channel_id,
                commit_at,
                use_at,
                operation,
                trace_id,
            } => {
                write!(
                    f,
                    "Use after commit: {reservation_id:?} on channel {channel_id:?} committed at {commit_at:?}, used at {use_at:?} for {operation}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::UseAfterAbort {
                reservation_id,
                channel_id,
                abort_at,
                use_at,
                operation,
                trace_id,
            } => {
                write!(
                    f,
                    "Use after abort: {reservation_id:?} on channel {channel_id:?} aborted at {abort_at:?}, used at {use_at:?} for {operation}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::LostWakeup {
                waker_id,
                channel_id,
                expected_at,
                detected_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Lost wakeup: {waker_id:?} on channel {channel_id:?} expected at {expected_at:?}, detected at {detected_at:?}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::SpuriousWakeup {
                waker_id,
                channel_id,
                wakeup_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Spurious wakeup: {waker_id:?} on channel {channel_id:?} at {wakeup_at:?}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
            Self::DataLossOnCancel {
                channel_id,
                data_size,
                cancel_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Data loss on cancel: channel {channel_id:?} lost {data_size} bytes at {cancel_at:?}"
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {trace:?})")?;
                }
                Ok(())
            }
        }
    }
}

/// Enhanced violation record with diagnostics
/// Record of a channel atomicity violation with metadata.
#[derive(Debug, Clone)]
pub struct ViolationRecord {
    /// The specific violation that occurred.
    pub violation: ChannelAtomicityViolation,
    /// Timestamp when the violation was recorded.
    pub timestamp: SystemTime,
    /// Optional trace ID for correlation.
    pub trace_id: Option<TraceId>,
    /// Optional stack trace at violation time.
    pub stack_trace: Option<String>,
    /// Optional command to replay the violation scenario.
    pub replay_command: Option<String>,
}

impl ViolationRecord {
    /// Creates a new violation record with metadata from the given violation and config.
    #[must_use]
    pub fn new(violation: ChannelAtomicityViolation, config: &ChannelAtomicityConfig) -> Self {
        let trace_id = match &violation {
            ChannelAtomicityViolation::ReservationLeak { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::DoubleCommit { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::DoubleAbort { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::UseAfterCommit { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::UseAfterAbort { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::LostWakeup { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::SpuriousWakeup { trace_id, .. } => *trace_id,
            ChannelAtomicityViolation::DataLossOnCancel { trace_id, .. } => *trace_id,
        };

        let stack_trace = if config.include_stack_traces {
            Some(Self::capture_stack_trace())
        } else {
            None
        };

        let replay_command = if config.enable_replay_commands {
            trace_id.map(|tid| format!("asupersync-replay --trace-id {tid:?}"))
        } else {
            None
        };

        Self {
            violation,
            timestamp: SystemTime::now(),
            trace_id,
            stack_trace,
            replay_command,
        }
    }

    /// Emits a structured JSON log entry for this violation record.
    #[allow(unused_variables)]
    pub fn emit_structured_log(&self) {
        let timestamp_millis = self
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());

        crate::tracing_compat::error!(
            violation_type = "channel_atomicity_violation",
            timestamp_millis = timestamp_millis,
            violation = %self.violation,
            trace_id = ?self.trace_id,
            replay_command = ?self.replay_command,
            stack_trace = ?self.stack_trace,
            "channel atomicity violation"
        );
    }

    fn capture_stack_trace() -> String {
        stack_trace::capture_stack_trace()
    }
}

/// State tracking for a channel reservation
#[derive(Debug, Clone)]
pub struct ReservationState {
    /// Unique identifier for this reservation.
    pub reservation_id: ReservationId,
    /// ID of the channel this reservation belongs to.
    pub channel_id: ChannelId,
    /// Timestamp when the reservation was created.
    pub created_at: SystemTime,
    /// Optional trace ID for debugging context.
    pub trace_id: Option<TraceId>,
    /// Current status of the reservation.
    pub status: ReservationStatus,
}

/// Status of a channel reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationStatus {
    /// Reservation is active and can be used.
    Active,
    /// Reservation has been committed.
    Committed {
        /// Timestamp when the reservation was committed.
        at: SystemTime,
        /// Size of data committed with the reservation.
        data_size: usize,
    },
    /// Reservation has been aborted.
    Aborted {
        /// Timestamp when the reservation was aborted.
        at: SystemTime,
        /// Reason for the abort.
        reason: String,
    },
}

/// State tracking for wakers
#[derive(Debug, Clone)]
pub struct WakerState {
    /// Unique identifier for this waker.
    pub waker_id: WakerId,
    /// ID of the channel this waker is associated with.
    pub channel_id: ChannelId,
    /// Timestamp when the waker was registered.
    pub registered_at: SystemTime,
    /// Optional timestamp when wakeup is expected.
    pub expected_wakeup_at: Option<SystemTime>,
    /// Optional timestamp when wakeup actually occurred.
    pub actual_wakeup_at: Option<SystemTime>,
    /// Optional trace ID for debugging context.
    pub trace_id: Option<TraceId>,
}

/// Channel Atomicity Oracle
#[derive(Debug)]
pub struct ChannelAtomicityOracle {
    config: ChannelAtomicityConfig,
    /// Track active reservations by ID
    reservations: HashMap<ReservationId, ReservationState>,
    /// Track reservations by channel for cleanup
    channel_reservations: HashMap<ChannelId, HashSet<ReservationId>>,
    /// Track waker state
    wakers: HashMap<WakerId, WakerState>,
    /// Track wakers by channel
    channel_wakers: HashMap<ChannelId, HashSet<WakerId>>,
    /// Violations found (legacy format for compatibility)
    violations: Vec<ChannelAtomicityViolation>,
    /// Enhanced violation records with diagnostics
    violation_records: VecDeque<ViolationRecord>,
    /// Statistics
    stats: ChannelAtomicityStatistics,
}

/// Statistics tracked by the Channel Atomicity Oracle.
#[derive(Debug, Clone, Default)]
pub struct ChannelAtomicityStatistics {
    /// Total number of reservations created.
    pub total_reservations_created: u64,
    /// Total number of reservations successfully committed.
    pub total_reservations_committed: u64,
    /// Total number of reservations aborted.
    pub total_reservations_aborted: u64,
    /// Total number of reservations that leaked (never committed or aborted).
    pub total_reservations_leaked: u64,
    /// Total number of wakers registered.
    pub total_wakers_registered: u64,
    /// Total number of expected wakeups.
    pub total_wakeups_expected: u64,
    /// Total number of actual wakeups that occurred.
    pub total_wakeups_actual: u64,
    /// Total number of lost wakeups detected.
    pub total_lost_wakeups: u64,
    /// Total number of spurious wakeups detected.
    pub total_spurious_wakeups: u64,
    /// Total number of atomicity violations detected.
    pub total_violations: u64,
}

impl Default for ChannelAtomicityOracle {
    fn default() -> Self {
        Self::new(ChannelAtomicityConfig::default())
    }
}

impl ChannelAtomicityOracle {
    /// Create a new oracle with the given configuration
    #[must_use]
    pub fn new(config: ChannelAtomicityConfig) -> Self {
        Self {
            config,
            reservations: HashMap::new(),
            channel_reservations: HashMap::new(),
            wakers: HashMap::new(),
            channel_wakers: HashMap::new(),
            violations: Vec::new(),
            violation_records: VecDeque::new(),
            stats: ChannelAtomicityStatistics::default(),
        }
    }

    /// Create oracle with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ChannelAtomicityConfig::default())
    }

    /// Create oracle for runtime use with enhanced enforcement
    #[must_use]
    pub fn for_runtime() -> Self {
        Self::new(ChannelAtomicityConfig {
            track_reservations: true,
            track_wakers: true,
            enforcement: EnforcementMode::Panic,
            structured_logging: true,
            include_stack_traces: true,
            enable_replay_commands: true,
            max_violations_tracked: 100,
            max_reservation_age_seconds: 300, // 5 minutes
            max_reservations_per_channel: 1000,
        })
    }

    /// Record a reservation creation event
    pub fn on_reservation_created(
        &mut self,
        reservation_id: ReservationId,
        channel_id: ChannelId,
        trace_id: Option<TraceId>,
    ) {
        if !self.config.track_reservations {
            return;
        }

        let state = ReservationState {
            reservation_id,
            channel_id,
            created_at: SystemTime::now(),
            trace_id,
            status: ReservationStatus::Active,
        };

        self.reservations.insert(reservation_id, state);
        self.channel_reservations
            .entry(channel_id)
            .or_default()
            .insert(reservation_id);

        self.stats.total_reservations_created += 1;
        self.cleanup_old_reservations();
    }

    /// Record a reservation commit event
    pub fn on_reservation_committed(&mut self, reservation_id: ReservationId, data_size: usize) {
        if !self.config.track_reservations {
            return;
        }

        if let Some(state) = self.reservations.get_mut(&reservation_id) {
            let commit_time = SystemTime::now();
            match &state.status {
                ReservationStatus::Active => {
                    state.status = ReservationStatus::Committed {
                        at: commit_time,
                        data_size,
                    };
                    self.stats.total_reservations_committed += 1;
                }
                ReservationStatus::Committed { at, .. } => {
                    let violation = ChannelAtomicityViolation::DoubleCommit {
                        reservation_id,
                        channel_id: state.channel_id,
                        first_commit_at: *at,
                        second_commit_at: commit_time,
                        trace_id: state.trace_id,
                    };
                    self.record_violation(violation);
                }
                ReservationStatus::Aborted { .. } => {
                    let violation = ChannelAtomicityViolation::UseAfterAbort {
                        reservation_id,
                        channel_id: state.channel_id,
                        abort_at: match state.status {
                            ReservationStatus::Aborted { at, .. } => at,
                            _ => unreachable!(),
                        },
                        use_at: commit_time,
                        operation: "commit".to_string(),
                        trace_id: state.trace_id,
                    };
                    self.record_violation(violation);
                }
            }
        }
    }

    /// Record a reservation abort event
    pub fn on_reservation_aborted(&mut self, reservation_id: ReservationId, reason: String) {
        if !self.config.track_reservations {
            return;
        }

        if let Some(state) = self.reservations.get_mut(&reservation_id) {
            let abort_time = SystemTime::now();
            match &state.status {
                ReservationStatus::Active => {
                    state.status = ReservationStatus::Aborted {
                        at: abort_time,
                        reason,
                    };
                    self.stats.total_reservations_aborted += 1;
                }
                ReservationStatus::Aborted { at, .. } => {
                    let violation = ChannelAtomicityViolation::DoubleAbort {
                        reservation_id,
                        channel_id: state.channel_id,
                        first_abort_at: *at,
                        second_abort_at: abort_time,
                        trace_id: state.trace_id,
                    };
                    self.record_violation(violation);
                }
                ReservationStatus::Committed { at, .. } => {
                    let violation = ChannelAtomicityViolation::UseAfterCommit {
                        reservation_id,
                        channel_id: state.channel_id,
                        commit_at: *at,
                        use_at: abort_time,
                        operation: "abort".to_string(),
                        trace_id: state.trace_id,
                    };
                    self.record_violation(violation);
                }
            }
        }
    }

    /// Record a waker registration
    pub fn on_waker_registered(
        &mut self,
        waker_id: WakerId,
        channel_id: ChannelId,
        trace_id: Option<TraceId>,
    ) {
        if !self.config.track_wakers {
            return;
        }

        let state = WakerState {
            waker_id,
            channel_id,
            registered_at: SystemTime::now(),
            expected_wakeup_at: None,
            actual_wakeup_at: None,
            trace_id,
        };

        self.wakers.insert(waker_id, state);
        self.channel_wakers
            .entry(channel_id)
            .or_default()
            .insert(waker_id);

        self.stats.total_wakers_registered += 1;
    }

    /// Record an expected wakeup
    pub fn on_waker_expected(&mut self, waker_id: WakerId, expected_at: SystemTime) {
        if !self.config.track_wakers {
            return;
        }

        if let Some(state) = self.wakers.get_mut(&waker_id) {
            state.expected_wakeup_at = Some(expected_at);
            self.stats.total_wakeups_expected += 1;
        }
    }

    /// Record an actual wakeup
    pub fn on_waker_wakeup(&mut self, waker_id: WakerId, actual_at: SystemTime) {
        if !self.config.track_wakers {
            return;
        }

        if let Some(state) = self.wakers.get_mut(&waker_id) {
            state.actual_wakeup_at = Some(actual_at);
            self.stats.total_wakeups_actual += 1;

            // Check for lost wakeups (expected but significantly delayed)
            if let Some(expected_at) = state.expected_wakeup_at {
                if let Ok(delay) = actual_at.duration_since(expected_at) {
                    if delay.as_millis() > 100 {
                        // 100ms threshold for "lost" wakeup
                        let violation = ChannelAtomicityViolation::LostWakeup {
                            waker_id,
                            channel_id: state.channel_id,
                            expected_at,
                            detected_at: actual_at,
                            trace_id: state.trace_id,
                        };
                        self.record_violation(violation);
                        self.stats.total_lost_wakeups += 1;
                    }
                }
            } else {
                // Spurious wakeup (actual without expected)
                let violation = ChannelAtomicityViolation::SpuriousWakeup {
                    waker_id,
                    channel_id: state.channel_id,
                    wakeup_at: actual_at,
                    trace_id: state.trace_id,
                };
                self.record_violation(violation);
                self.stats.total_spurious_wakeups += 1;
            }
        }
    }

    /// Record potential data loss during cancellation
    pub fn on_cancel_data_loss(
        &mut self,
        channel_id: ChannelId,
        data_size: usize,
        trace_id: Option<TraceId>,
    ) {
        let violation = ChannelAtomicityViolation::DataLossOnCancel {
            channel_id,
            data_size,
            cancel_at: SystemTime::now(),
            trace_id,
        };
        self.record_violation(violation);
    }

    /// Check for violations and return them
    pub fn check_for_violations(&mut self) -> Result<Vec<ChannelAtomicityViolation>, String> {
        self.check_for_reservation_leaks();
        Ok(self.violations.clone())
    }

    /// Get current statistics
    #[must_use]
    pub fn statistics(&self) -> ChannelAtomicityStatistics {
        self.stats.clone()
    }

    /// Reset the oracle state
    pub fn reset(&mut self) {
        self.reservations.clear();
        self.channel_reservations.clear();
        self.wakers.clear();
        self.channel_wakers.clear();
        self.violations.clear();
        self.violation_records.clear();
        self.stats = ChannelAtomicityStatistics::default();
    }

    /// Get violation records with diagnostics
    #[must_use]
    pub fn violation_records(&self) -> Vec<ViolationRecord> {
        self.violation_records.iter().cloned().collect()
    }

    /// Record a violation with appropriate enforcement
    fn record_violation(&mut self, violation: ChannelAtomicityViolation) {
        // Legacy format for backward compatibility
        self.violations.push(violation.clone());

        // Enhanced format with diagnostics
        let record = ViolationRecord::new(violation.clone(), &self.config);

        // Emit structured log if enabled
        if self.config.structured_logging {
            record.emit_structured_log();
        }

        // Store the record
        self.violation_records.push_back(record);

        // Limit memory usage
        if self.violation_records.len() > self.config.max_violations_tracked {
            self.violation_records.pop_front();
        }

        self.stats.total_violations += 1;

        // Apply enforcement mode
        match self.config.enforcement {
            EnforcementMode::Panic => panic!("Channel atomicity violation detected: {violation}"),
            EnforcementMode::Warn => {
                crate::tracing_compat::warn!(
                    violation = %violation,
                    "channel atomicity violation"
                );
            }
            EnforcementMode::Collect => {} // Just collect, no immediate action
        }
    }

    /// Check for reservation leaks
    fn check_for_reservation_leaks(&mut self) {
        let now = SystemTime::now();
        let mut leaked_reservations = Vec::new();
        let mut violations_to_record = Vec::new();

        for (reservation_id, state) in &self.reservations {
            if matches!(state.status, ReservationStatus::Active) {
                if let Ok(age) = now.duration_since(state.created_at) {
                    // Use >= so that setting `max_reservation_age_seconds = 0`
                    // enables immediate leak detection (any positive age counts).
                    if age.as_secs() >= self.config.max_reservation_age_seconds {
                        leaked_reservations.push(*reservation_id);
                        let violation = ChannelAtomicityViolation::ReservationLeak {
                            reservation_id: *reservation_id,
                            channel_id: state.channel_id,
                            created_at: state.created_at,
                            trace_id: state.trace_id,
                        };
                        violations_to_record.push(violation);
                    }
                }
            }
        }

        // Record violations
        for violation in violations_to_record {
            self.record_violation(violation);
            self.stats.total_reservations_leaked += 1;
        }

        // Remove leaked reservations from tracking
        for reservation_id in leaked_reservations {
            if let Some(state) = self.reservations.remove(&reservation_id) {
                if let Some(channel_set) = self.channel_reservations.get_mut(&state.channel_id) {
                    channel_set.remove(&reservation_id);
                }
            }
        }
    }

    /// Clean up old reservations to prevent memory leaks
    fn cleanup_old_reservations(&mut self) {
        // Clean up per-channel reservation tracking
        for reservation_set in self.channel_reservations.values_mut() {
            if reservation_set.len() > self.config.max_reservations_per_channel {
                // Remove oldest reservations (this is a simplified cleanup)
                let to_remove: Vec<ReservationId> = reservation_set
                    .iter()
                    .take(reservation_set.len() - self.config.max_reservations_per_channel)
                    .copied()
                    .collect();

                for reservation_id in to_remove {
                    reservation_set.remove(&reservation_id);
                    self.reservations.remove(&reservation_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_reservation_lifecycle_happy_path() {
        let mut oracle = ChannelAtomicityOracle::with_defaults();

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        // Create reservation
        oracle.on_reservation_created(reservation_id, channel_id, None);

        // Commit reservation
        oracle.on_reservation_committed(reservation_id, 100);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_reservations_created, 1);
        assert_eq!(stats.total_reservations_committed, 1);
        assert_eq!(stats.total_violations, 0);
    }

    #[test]
    fn test_double_commit_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        oracle.on_reservation_created(reservation_id, channel_id, None);
        oracle.on_reservation_committed(reservation_id, 100);
        oracle.on_reservation_committed(reservation_id, 200); // This should be a violation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::DoubleCommit { .. }
        ));
    }

    #[test]
    fn test_use_after_abort_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        oracle.on_reservation_created(reservation_id, channel_id, None);
        oracle.on_reservation_aborted(reservation_id, "cancelled".to_string());
        oracle.on_reservation_committed(reservation_id, 100); // This should be a violation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::UseAfterAbort { .. }
        ));
    }

    #[test]
    fn test_reservation_leak_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            max_reservation_age_seconds: 0, // Immediate leak detection
            ..Default::default()
        });

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        oracle.on_reservation_created(reservation_id, channel_id, None);

        // Let some time pass
        std::thread::sleep(Duration::from_millis(10));

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::ReservationLeak { .. }
        ));
    }

    #[test]
    fn test_spurious_wakeup_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, None);
        oracle.on_waker_wakeup(waker_id, SystemTime::now()); // Wakeup without expectation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::SpuriousWakeup { .. }
        ));
    }

    #[test]
    fn test_lost_wakeup_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);
        let now = SystemTime::now();

        oracle.on_waker_registered(waker_id, channel_id, None);
        oracle.on_waker_expected(waker_id, now);

        // Simulate significant delay
        let delayed_wakeup = now + Duration::from_millis(200);
        oracle.on_waker_wakeup(waker_id, delayed_wakeup);

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::LostWakeup { .. }
        ));
    }

    #[test]
    fn test_data_loss_on_cancel() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let channel_id = ChannelId(1);
        oracle.on_cancel_data_loss(channel_id, 1024, None);

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::DataLossOnCancel { .. }
        ));
    }

    #[test]
    fn test_violation_record_creation() {
        let config = ChannelAtomicityConfig {
            include_stack_traces: true,
            enable_replay_commands: true,
            structured_logging: false,
            ..Default::default()
        };

        let violation = ChannelAtomicityViolation::ReservationLeak {
            reservation_id: ReservationId(1),
            channel_id: ChannelId(1),
            created_at: SystemTime::now(),
            trace_id: Some(TraceId::new_for_test(1)),
        };

        let record = ViolationRecord::new(violation, &config);

        assert!(record.trace_id.is_some());
        assert!(record.stack_trace.is_some());
        assert!(record.replay_command.is_some());
    }

    #[test]
    fn test_oracle_reset() {
        let mut oracle = ChannelAtomicityOracle::with_defaults();

        // Add some state
        oracle.on_reservation_created(ReservationId(1), ChannelId(1), None);
        oracle.on_waker_registered(WakerId(1), ChannelId(1), None);
        oracle.on_cancel_data_loss(ChannelId(1), 100, None);

        // Verify state exists
        assert!(!oracle.reservations.is_empty());
        assert!(!oracle.wakers.is_empty());
        assert!(!oracle.violations.is_empty());

        // Reset and verify clean state
        oracle.reset();

        assert!(oracle.reservations.is_empty());
        assert!(oracle.wakers.is_empty());
        assert!(oracle.violations.is_empty());
        assert_eq!(oracle.statistics().total_reservations_created, 0);
    }
}
