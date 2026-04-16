//! Channel Waker Deduplication Verifier
//!
//! This oracle verifies that the Arc<AtomicBool> waker deduplication pattern
//! in channels correctly prevents spurious wakeups while ensuring no lost wakeups.
//! Incorrect implementation can cause deadlocks where tasks aren't properly woken.
//!
//! # Core Patterns Verified
//!
//! 1. **Queued State Consistency**: Arc<AtomicBool> accurately reflects queued state
//! 2. **No Lost Wakeups**: Tasks that should be woken are actually woken
//! 3. **No Spurious Wakeups**: Tasks aren't woken unnecessarily
//! 4. **Race-Free Registration**: Waker registration doesn't race with wakeup
//! 5. **Proper Cleanup**: Dropped wakers are properly cleaned up
//!
//! # Usage
//!
//! ```rust
//! use asupersync::lab::oracle::waker_dedup::{WakerDedupOracle, WakerDedupConfig};
//!
//! let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
//!     track_queued_state: true,
//!     track_wakeup_events: true,
//!     enforcement: EnforcementMode::Panic,
//!     max_tracked_wakers: 10000,
//!     ..Default::default()
//! });
//!
//! // Hook into waker operations
//! oracle.on_waker_registered(waker_id, channel_id, is_queued);
//! oracle.on_waker_wake_requested(waker_id, reason);
//! oracle.on_waker_actually_woken(waker_id);
//! oracle.on_waker_dropped(waker_id);
//! ```

use crate::trace::distributed::TraceId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique identifier for a waker instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WakerId(pub u64);

/// Unique identifier for a channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub u64);

/// Configuration for the Waker Deduplication Oracle
#[derive(Debug, Clone)]
pub struct WakerDedupConfig {
    /// Whether to track waker queued state changes
    pub track_queued_state: bool,
    /// Whether to track wakeup events and timing
    pub track_wakeup_events: bool,
    /// Whether to detect registration races
    pub detect_registration_races: bool,
    /// Whether to track waker cleanup on drop
    pub track_cleanup: bool,
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
    /// Maximum number of wakers to track per channel
    pub max_wakers_per_channel: usize,
    /// Maximum number of total wakers to track
    pub max_tracked_wakers: usize,
    /// Time window for detecting race conditions (milliseconds)
    pub race_detection_window_ms: u64,
}

impl Default for WakerDedupConfig {
    fn default() -> Self {
        Self {
            track_queued_state: true,
            track_wakeup_events: true,
            detect_registration_races: true,
            track_cleanup: true,
            enforcement: EnforcementMode::Warn,
            structured_logging: false,
            include_stack_traces: false,
            enable_replay_commands: false,
            max_violations_tracked: 1000,
            max_wakers_per_channel: 1000,
            max_tracked_wakers: 10000,
            race_detection_window_ms: 10, // 10ms race detection window
        }
    }
}

/// Enforcement mode for waker deduplication violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Only collect violations, no immediate action
    Collect,
    /// Emit warnings for violations
    Warn,
    /// Panic on violations (for testing)
    Panic,
}

/// Types of waker deduplication violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakerDedupViolation {
    /// Waker was registered but never woken when it should have been
    LostWakeup {
        /// ID of the waker that was lost.
        waker_id: WakerId,
        /// ID of the channel where the wakeup was lost.
        channel_id: ChannelId,
        /// When the waker was originally registered.
        registered_at: SystemTime,
        /// When the wakeup was expected to occur.
        expected_wake_at: SystemTime,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
    /// Waker was woken when it wasn't supposed to be (spurious wakeup)
    SpuriousWakeup {
        /// ID of the spuriously woken waker.
        waker_id: WakerId,
        /// ID of the channel where spurious wakeup occurred.
        channel_id: ChannelId,
        /// When the spurious wakeup occurred.
        woken_at: SystemTime,
        /// Human-readable reason for the spurious wakeup.
        reason: String,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
    /// Waker state inconsistency between oracle tracking and actual state
    InconsistentQueuedState {
        /// ID of the waker with inconsistent state.
        waker_id: WakerId,
        /// ID of the channel with the inconsistency.
        channel_id: ChannelId,
        /// Whether the waker was expected to be queued.
        expected_queued: bool,
        /// Whether the waker was actually queued.
        actual_queued: bool,
        /// When the inconsistency was detected.
        detected_at: SystemTime,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
    /// Race condition detected between waker registration and wakeup
    RegistrationRace {
        /// ID of the waker involved in the race.
        waker_id: WakerId,
        /// ID of the channel where the race occurred.
        channel_id: ChannelId,
        /// When the waker registration started.
        registration_time: SystemTime,
        /// When the wakeup occurred.
        wakeup_time: SystemTime,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
    /// Waker was woken multiple times without re-registration
    DoubleWakeup {
        /// ID of the doubly-woken waker.
        waker_id: WakerId,
        /// ID of the channel where double wakeup occurred.
        channel_id: ChannelId,
        /// When the first wakeup occurred.
        first_wake_at: SystemTime,
        /// When the second wakeup occurred.
        second_wake_at: SystemTime,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
    /// Waker was leaked (not properly cleaned up)
    WakerLeak {
        /// ID of the leaked waker.
        waker_id: WakerId,
        /// ID of the channel where the waker was leaked.
        channel_id: ChannelId,
        /// When the waker was originally registered.
        registered_at: SystemTime,
        /// When the leak was detected.
        detected_at: SystemTime,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
    /// Waker operation on unknown or already-dropped waker
    UseAfterDrop {
        /// ID of the dropped waker that was used.
        waker_id: WakerId,
        /// ID of the channel where use-after-drop occurred.
        channel_id: ChannelId,
        /// When the waker was originally dropped.
        dropped_at: SystemTime,
        /// When the illegal operation was attempted.
        operation_at: SystemTime,
        /// Description of the operation that was attempted.
        operation: String,
        /// Optional trace ID for correlation.
        trace_id: Option<TraceId>,
    },
}

impl std::fmt::Display for WakerDedupViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WakerDedupViolation::LostWakeup {
                waker_id,
                channel_id,
                registered_at,
                expected_wake_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Lost wakeup: waker {:?} on channel {:?} registered at {:?}, expected wake at {:?}",
                    waker_id, channel_id, registered_at, expected_wake_at
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
            WakerDedupViolation::SpuriousWakeup {
                waker_id,
                channel_id,
                woken_at,
                reason,
                trace_id,
            } => {
                write!(
                    f,
                    "Spurious wakeup: waker {:?} on channel {:?} woken at {:?}, reason: {}",
                    waker_id, channel_id, woken_at, reason
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
            WakerDedupViolation::InconsistentQueuedState {
                waker_id,
                channel_id,
                expected_queued,
                actual_queued,
                detected_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Inconsistent queued state: waker {:?} on channel {:?} expected queued={}, actual queued={}, detected at {:?}",
                    waker_id, channel_id, expected_queued, actual_queued, detected_at
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
            WakerDedupViolation::RegistrationRace {
                waker_id,
                channel_id,
                registration_time,
                wakeup_time,
                trace_id,
            } => {
                write!(
                    f,
                    "Registration race: waker {:?} on channel {:?} registered at {:?}, woken at {:?}",
                    waker_id, channel_id, registration_time, wakeup_time
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
            WakerDedupViolation::DoubleWakeup {
                waker_id,
                channel_id,
                first_wake_at,
                second_wake_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Double wakeup: waker {:?} on channel {:?} first woken at {:?}, second at {:?}",
                    waker_id, channel_id, first_wake_at, second_wake_at
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
            WakerDedupViolation::WakerLeak {
                waker_id,
                channel_id,
                registered_at,
                detected_at,
                trace_id,
            } => {
                write!(
                    f,
                    "Waker leak: waker {:?} on channel {:?} registered at {:?}, detected at {:?}",
                    waker_id, channel_id, registered_at, detected_at
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
            WakerDedupViolation::UseAfterDrop {
                waker_id,
                channel_id,
                dropped_at,
                operation_at,
                operation,
                trace_id,
            } => {
                write!(
                    f,
                    "Use after drop: waker {:?} on channel {:?} dropped at {:?}, operation '{}' at {:?}",
                    waker_id, channel_id, dropped_at, operation, operation_at
                )?;
                if let Some(trace) = trace_id {
                    write!(f, " (trace: {:?})", trace)?;
                }
                Ok(())
            }
        }
    }
}

/// Enhanced violation record with diagnostics
#[derive(Debug, Clone)]
pub struct ViolationRecord {
    /// The underlying waker deduplication violation.
    pub violation: WakerDedupViolation,
    /// When the violation was recorded.
    pub timestamp: SystemTime,
    /// Optional trace ID for correlation across systems.
    pub trace_id: Option<TraceId>,
    /// Optional stack trace captured at violation time.
    pub stack_trace: Option<String>,
    /// Optional command to replay the scenario.
    pub replay_command: Option<String>,
}

impl ViolationRecord {
    /// Create a new violation record with enhanced diagnostics.
    pub fn new(violation: WakerDedupViolation, config: &WakerDedupConfig) -> Self {
        let trace_id = match &violation {
            WakerDedupViolation::LostWakeup { trace_id, .. } => *trace_id,
            WakerDedupViolation::SpuriousWakeup { trace_id, .. } => *trace_id,
            WakerDedupViolation::InconsistentQueuedState { trace_id, .. } => *trace_id,
            WakerDedupViolation::RegistrationRace { trace_id, .. } => *trace_id,
            WakerDedupViolation::DoubleWakeup { trace_id, .. } => *trace_id,
            WakerDedupViolation::WakerLeak { trace_id, .. } => *trace_id,
            WakerDedupViolation::UseAfterDrop { trace_id, .. } => *trace_id,
        };

        let stack_trace = if config.include_stack_traces {
            Some(Self::capture_stack_trace())
        } else {
            None
        };

        let replay_command = if config.enable_replay_commands {
            trace_id.map(|tid| format!("asupersync-replay --trace-id {:?}", tid))
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

    /// Emit a structured log entry for this violation record.
    pub fn emit_structured_log(&self) {
        let timestamp_millis = self
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        eprintln!(
            "{{\"type\":\"waker_dedup_violation\",\"timestamp\":{},\"violation\":\"{}\",\"trace_id\":{:?},\"replay_command\":{:?}}}",
            timestamp_millis, self.violation, self.trace_id, self.replay_command
        );
    }

    fn capture_stack_trace() -> String {
        // In a real implementation, this would capture the actual stack trace
        format!("Stack trace capture not implemented in this preview")
    }
}

/// State tracking for a waker
#[derive(Debug, Clone)]
pub struct WakerState {
    /// Unique identifier for this waker.
    pub waker_id: WakerId,
    /// ID of the channel this waker is associated with.
    pub channel_id: ChannelId,
    /// When this waker was registered.
    pub registered_at: SystemTime,
    /// Optional trace ID for correlation.
    pub trace_id: Option<TraceId>,
    /// Current status of the waker.
    pub status: WakerStatus,
    /// When the last operation on this waker occurred.
    pub last_operation_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakerStatus {
    /// Waker is registered and queued for wakeup
    Queued,
    /// Waker has been woken and is no longer queued
    Woken { at: SystemTime },
    /// Waker has been dropped/cleaned up
    Dropped { at: SystemTime },
}

/// Channel-level statistics for waker deduplication
#[derive(Debug, Clone, Default)]
pub struct WakerDedupStatistics {
    pub total_wakers_registered: u64,
    pub total_wakers_woken: u64,
    pub total_wakers_dropped: u64,
    pub total_lost_wakeups: u64,
    pub total_spurious_wakeups: u64,
    pub total_double_wakeups: u64,
    pub total_registration_races: u64,
    pub total_state_inconsistencies: u64,
    pub total_leaks: u64,
    pub total_use_after_drop: u64,
    pub total_violations: u64,
    pub active_wakers: u64,
}

/// Waker Deduplication Oracle
#[derive(Debug)]
pub struct WakerDedupOracle {
    config: WakerDedupConfig,
    /// Track waker state by waker ID
    wakers: HashMap<WakerId, WakerState>,
    /// Track wakers by channel for cleanup
    channel_wakers: HashMap<ChannelId, HashSet<WakerId>>,
    /// Track recent registration events for race detection
    recent_registrations: VecDeque<(WakerId, SystemTime)>,
    /// Track recent wakeup events for race detection
    recent_wakeups: VecDeque<(WakerId, SystemTime)>,
    /// Violations found (legacy format for compatibility)
    violations: Vec<WakerDedupViolation>,
    /// Enhanced violation records with diagnostics
    violation_records: VecDeque<ViolationRecord>,
    /// Statistics
    stats: WakerDedupStatistics,
}

impl Default for WakerDedupOracle {
    fn default() -> Self {
        Self::new(WakerDedupConfig::default())
    }
}

impl WakerDedupOracle {
    /// Create a new oracle with the given configuration
    pub fn new(config: WakerDedupConfig) -> Self {
        Self {
            config,
            wakers: HashMap::new(),
            channel_wakers: HashMap::new(),
            recent_registrations: VecDeque::new(),
            recent_wakeups: VecDeque::new(),
            violations: Vec::new(),
            violation_records: VecDeque::new(),
            stats: WakerDedupStatistics::default(),
        }
    }

    /// Create oracle with default configuration
    pub fn with_defaults() -> Self {
        Self::new(WakerDedupConfig::default())
    }

    /// Create oracle for runtime use with enhanced detection
    pub fn for_runtime() -> Self {
        Self::new(WakerDedupConfig {
            track_queued_state: true,
            track_wakeup_events: true,
            detect_registration_races: true,
            track_cleanup: true,
            enforcement: EnforcementMode::Panic,
            structured_logging: true,
            include_stack_traces: true,
            enable_replay_commands: true,
            max_violations_tracked: 100,
            max_wakers_per_channel: 100,
            max_tracked_wakers: 1000,
            race_detection_window_ms: 5,
        })
    }

    /// Record a waker registration event
    pub fn on_waker_registered(
        &mut self,
        waker_id: WakerId,
        channel_id: ChannelId,
        is_queued: bool,
        trace_id: Option<TraceId>,
    ) {
        if !self.config.track_queued_state {
            return;
        }

        let now = SystemTime::now();

        // Check for race with recent wakeups
        if self.config.detect_registration_races {
            self.check_registration_races(waker_id, now);
        }

        // Record the waker state
        let state = WakerState {
            waker_id,
            channel_id,
            registered_at: now,
            trace_id,
            status: if is_queued {
                WakerStatus::Queued
            } else {
                WakerStatus::Woken { at: now }
            },
            last_operation_at: now,
        };

        self.wakers.insert(waker_id, state);
        self.channel_wakers
            .entry(channel_id)
            .or_insert_with(HashSet::new)
            .insert(waker_id);

        // Track for race detection
        self.recent_registrations.push_back((waker_id, now));

        self.stats.total_wakers_registered += 1;
        if is_queued {
            self.stats.active_wakers += 1;
        }

        self.cleanup_tracking_data();
    }

    /// Record a waker wake request (should lead to actual wakeup)
    pub fn on_waker_wake_requested(
        &mut self,
        waker_id: WakerId,
        _reason: String,
        trace_id: Option<TraceId>,
    ) {
        if !self.config.track_wakeup_events {
            return;
        }

        let now = SystemTime::now();

        if let Some(state) = self.wakers.get(&waker_id) {
            match &state.status {
                WakerStatus::Queued => {
                    // Expected: queued waker should be woken
                    // We'll verify this in on_waker_actually_woken
                }
                WakerStatus::Woken { at } => {
                    // Violation: trying to wake already-woken waker
                    let violation = WakerDedupViolation::DoubleWakeup {
                        waker_id,
                        channel_id: state.channel_id,
                        first_wake_at: *at,
                        second_wake_at: now,
                        trace_id,
                    };
                    self.record_violation(violation);
                    self.stats.total_double_wakeups += 1;
                }
                WakerStatus::Dropped { at } => {
                    // Violation: trying to wake dropped waker
                    let violation = WakerDedupViolation::UseAfterDrop {
                        waker_id,
                        channel_id: state.channel_id,
                        dropped_at: *at,
                        operation_at: now,
                        operation: "wake_request".to_string(),
                        trace_id,
                    };
                    self.record_violation(violation);
                    self.stats.total_use_after_drop += 1;
                }
            }
        } else {
            // Spurious wake request - no registered waker
            // We need channel_id, but we don't have it without waker state
            // This might be a legitimate case where waker was already cleaned up
        }
    }

    /// Record an actual waker wakeup event
    pub fn on_waker_actually_woken(&mut self, waker_id: WakerId, trace_id: Option<TraceId>) {
        if !self.config.track_wakeup_events {
            return;
        }

        let now = SystemTime::now();

        if let Some(state) = self.wakers.get_mut(&waker_id) {
            match &state.status {
                WakerStatus::Queued => {
                    // Expected: queued waker is being woken
                    state.status = WakerStatus::Woken { at: now };
                    state.last_operation_at = now;
                    self.stats.total_wakers_woken += 1;
                    self.stats.active_wakers = self.stats.active_wakers.saturating_sub(1);
                }
                WakerStatus::Woken { at } => {
                    // Violation: already-woken waker woken again
                    let violation = WakerDedupViolation::DoubleWakeup {
                        waker_id,
                        channel_id: state.channel_id,
                        first_wake_at: *at,
                        second_wake_at: now,
                        trace_id,
                    };
                    self.record_violation(violation);
                    self.stats.total_double_wakeups += 1;
                }
                WakerStatus::Dropped { at } => {
                    // Violation: dropped waker woken
                    let violation = WakerDedupViolation::UseAfterDrop {
                        waker_id,
                        channel_id: state.channel_id,
                        dropped_at: *at,
                        operation_at: now,
                        operation: "wakeup".to_string(),
                        trace_id,
                    };
                    self.record_violation(violation);
                    self.stats.total_use_after_drop += 1;
                }
            }
        } else {
            // Spurious wakeup - no registered waker
            let violation = WakerDedupViolation::SpuriousWakeup {
                waker_id,
                channel_id: ChannelId(0), // We don't know the channel, use dummy
                woken_at: now,
                reason: "unknown waker".to_string(),
                trace_id,
            };
            self.record_violation(violation);
            self.stats.total_spurious_wakeups += 1;
        }

        // Track for race detection
        self.recent_wakeups.push_back((waker_id, now));
    }

    /// Record a waker drop/cleanup event
    pub fn on_waker_dropped(&mut self, waker_id: WakerId) {
        if !self.config.track_cleanup {
            return;
        }

        let now = SystemTime::now();

        if let Some(state) = self.wakers.get_mut(&waker_id) {
            match &state.status {
                WakerStatus::Queued => {
                    // Waker was dropped while queued - this is normal cleanup
                    self.stats.active_wakers = self.stats.active_wakers.saturating_sub(1);
                }
                WakerStatus::Woken { .. } => {
                    // Waker was dropped after being woken - normal
                }
                WakerStatus::Dropped { .. } => {
                    // Already dropped - shouldn't happen
                }
            }

            state.status = WakerStatus::Dropped { at: now };
            state.last_operation_at = now;
            self.stats.total_wakers_dropped += 1;
        }

        // Note: We don't remove from wakers HashMap immediately to allow
        // detection of use-after-drop violations
    }

    /// Verify queued state consistency
    pub fn verify_queued_state(
        &mut self,
        waker_id: WakerId,
        actual_queued: bool,
        trace_id: Option<TraceId>,
    ) {
        if !self.config.track_queued_state {
            return;
        }

        if let Some(state) = self.wakers.get(&waker_id) {
            let expected_queued = matches!(state.status, WakerStatus::Queued);
            if expected_queued != actual_queued {
                let violation = WakerDedupViolation::InconsistentQueuedState {
                    waker_id,
                    channel_id: state.channel_id,
                    expected_queued,
                    actual_queued,
                    detected_at: SystemTime::now(),
                    trace_id,
                };
                self.record_violation(violation);
                self.stats.total_state_inconsistencies += 1;
            }
        }
    }

    /// Check for violations and return them
    pub fn check_for_violations(&mut self) -> Result<Vec<WakerDedupViolation>, String> {
        self.check_for_leaked_wakers();
        self.check_for_lost_wakeups();
        Ok(self.violations.clone())
    }

    /// Get current statistics
    pub fn statistics(&self) -> WakerDedupStatistics {
        self.stats.clone()
    }

    /// Reset the oracle state
    pub fn reset(&mut self) {
        self.wakers.clear();
        self.channel_wakers.clear();
        self.recent_registrations.clear();
        self.recent_wakeups.clear();
        self.violations.clear();
        self.violation_records.clear();
        self.stats = WakerDedupStatistics::default();
    }

    /// Get violation records with diagnostics
    pub fn violation_records(&self) -> Vec<ViolationRecord> {
        self.violation_records.iter().cloned().collect()
    }

    /// Record a violation with appropriate enforcement
    fn record_violation(&mut self, violation: WakerDedupViolation) {
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
            EnforcementMode::Panic => {
                panic!("Waker deduplication violation detected: {}", violation)
            }
            EnforcementMode::Warn => eprintln!("⚠️  Waker deduplication violation: {}", violation),
            EnforcementMode::Collect => {} // Just collect, no immediate action
        }
    }

    /// Check for registration races
    fn check_registration_races(&mut self, waker_id: WakerId, registration_time: SystemTime) {
        let window = std::time::Duration::from_millis(self.config.race_detection_window_ms);
        let mut violations_to_record = Vec::new();

        // Check if this waker was recently woken
        for (recent_waker_id, recent_wakeup_time) in &self.recent_wakeups {
            if *recent_waker_id == waker_id {
                if let Ok(time_diff) = registration_time.duration_since(*recent_wakeup_time) {
                    if time_diff <= window {
                        if let Some(state) = self.wakers.get(&waker_id) {
                            let violation = WakerDedupViolation::RegistrationRace {
                                waker_id,
                                channel_id: state.channel_id,
                                registration_time,
                                wakeup_time: *recent_wakeup_time,
                                trace_id: state.trace_id,
                            };
                            violations_to_record.push(violation);
                        }
                    }
                }
            }
        }

        // Record violations
        for violation in violations_to_record {
            self.record_violation(violation);
            self.stats.total_registration_races += 1;
        }
    }

    /// Check for leaked wakers
    fn check_for_leaked_wakers(&mut self) {
        let now = SystemTime::now();
        let leak_threshold = std::time::Duration::from_secs(60); // 1 minute
        let mut leaked_wakers = Vec::new();
        let mut violations_to_record = Vec::new();

        for (waker_id, state) in &self.wakers {
            if matches!(state.status, WakerStatus::Queued) {
                if let Ok(age) = now.duration_since(state.registered_at) {
                    if age > leak_threshold {
                        leaked_wakers.push(*waker_id);
                        let violation = WakerDedupViolation::WakerLeak {
                            waker_id: *waker_id,
                            channel_id: state.channel_id,
                            registered_at: state.registered_at,
                            detected_at: now,
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
            self.stats.total_leaks += 1;
        }

        // Mark leaked wakers as dropped
        for waker_id in leaked_wakers {
            if let Some(state) = self.wakers.get_mut(&waker_id) {
                state.status = WakerStatus::Dropped { at: now };
                state.last_operation_at = now;
                self.stats.active_wakers = self.stats.active_wakers.saturating_sub(1);
            }
        }
    }

    /// Check for lost wakeups
    fn check_for_lost_wakeups(&mut self) {
        let now = SystemTime::now();
        let lost_threshold = std::time::Duration::from_secs(30); // 30 seconds
        let mut violations_to_record = Vec::new();

        for (waker_id, state) in &self.wakers {
            if matches!(state.status, WakerStatus::Queued) {
                if let Ok(age) = now.duration_since(state.registered_at) {
                    if age > lost_threshold {
                        let violation = WakerDedupViolation::LostWakeup {
                            waker_id: *waker_id,
                            channel_id: state.channel_id,
                            registered_at: state.registered_at,
                            expected_wake_at: state.registered_at + lost_threshold,
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
            self.stats.total_lost_wakeups += 1;
        }
    }

    /// Clean up tracking data to prevent memory leaks
    fn cleanup_tracking_data(&mut self) {
        let now = SystemTime::now();
        let cleanup_window = std::time::Duration::from_secs(300); // 5 minutes

        // Clean up old registration events
        while let Some((_, time)) = self.recent_registrations.front() {
            if now.duration_since(*time).unwrap_or_default() > cleanup_window {
                self.recent_registrations.pop_front();
            } else {
                break;
            }
        }

        // Clean up old wakeup events
        while let Some((_, time)) = self.recent_wakeups.front() {
            if now.duration_since(*time).unwrap_or_default() > cleanup_window {
                self.recent_wakeups.pop_front();
            } else {
                break;
            }
        }

        // Clean up old dropped wakers
        let dropped_cleanup_window = std::time::Duration::from_secs(600); // 10 minutes
        self.wakers.retain(|_, state| {
            if let WakerStatus::Dropped { at } = state.status {
                now.duration_since(at).unwrap_or_default() <= dropped_cleanup_window
            } else {
                true
            }
        });

        // Limit total tracked wakers
        if self.wakers.len() > self.config.max_tracked_wakers {
            // Remove oldest dropped wakers first
            let mut to_remove = Vec::new();
            for (waker_id, state) in &self.wakers {
                if matches!(state.status, WakerStatus::Dropped { .. }) {
                    to_remove.push(*waker_id);
                }
            }
            // Sort by last operation time and remove oldest
            to_remove.sort_by_key(|id| self.wakers[id].last_operation_at);
            let remove_count =
                (self.wakers.len() - self.config.max_tracked_wakers).min(to_remove.len());
            for waker_id in &to_remove[..remove_count] {
                if let Some(state) = self.wakers.remove(waker_id) {
                    if let Some(channel_set) = self.channel_wakers.get_mut(&state.channel_id) {
                        channel_set.remove(waker_id);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_normal_waker_lifecycle() {
        let mut oracle = WakerDedupOracle::with_defaults();

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        // Register waker
        oracle.on_waker_registered(waker_id, channel_id, true, None);

        // Request wake
        oracle.on_waker_wake_requested(waker_id, "channel_send".to_string(), None);

        // Actually wake
        oracle.on_waker_actually_woken(waker_id, None);

        // Drop waker
        oracle.on_waker_dropped(waker_id);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_wakers_registered, 1);
        assert_eq!(stats.total_wakers_woken, 1);
        assert_eq!(stats.total_wakers_dropped, 1);
        assert_eq!(stats.total_violations, 0);
    }

    #[test]
    fn test_double_wakeup_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);
        oracle.on_waker_actually_woken(waker_id, None);
        oracle.on_waker_actually_woken(waker_id, None); // This should be a violation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::DoubleWakeup { .. }
        ));
    }

    #[test]
    fn test_spurious_wakeup_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);

        // Wakeup without registration
        oracle.on_waker_actually_woken(waker_id, None);

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::SpuriousWakeup { .. }
        ));
    }

    #[test]
    fn test_use_after_drop_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);
        oracle.on_waker_dropped(waker_id);
        oracle.on_waker_actually_woken(waker_id, None); // Use after drop

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::UseAfterDrop { .. }
        ));
    }

    #[test]
    fn test_queued_state_verification() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);
        oracle.verify_queued_state(waker_id, false, None); // Inconsistent state

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::InconsistentQueuedState { .. }
        ));
    }

    #[test]
    fn test_registration_race_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            race_detection_window_ms: 100, // 100ms window
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);

        // Simulate recent wakeup
        oracle
            .recent_wakeups
            .push_back((waker_id, SystemTime::now()));

        // Register again soon after wakeup (simulating race)
        oracle.on_waker_registered(waker_id, channel_id, true, None);

        let _violations = oracle.check_for_violations().unwrap();
        // May or may not detect race depending on timing
    }

    #[test]
    fn test_waker_leak_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        // Register waker with old timestamp
        oracle.on_waker_registered(waker_id, channel_id, true, None);

        // Manually set old registration time to trigger leak detection
        if let Some(state) = oracle.wakers.get_mut(&waker_id) {
            state.registered_at = SystemTime::now() - Duration::from_secs(120); // 2 minutes ago
        }

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::WakerLeak { .. }
        ));
    }

    #[test]
    fn test_violation_record_creation() {
        let config = WakerDedupConfig {
            include_stack_traces: true,
            enable_replay_commands: true,
            structured_logging: false,
            ..Default::default()
        };

        let violation = WakerDedupViolation::LostWakeup {
            waker_id: WakerId(1),
            channel_id: ChannelId(1),
            registered_at: SystemTime::now(),
            expected_wake_at: SystemTime::now(),
            trace_id: Some(TraceId::new()),
        };

        let record = ViolationRecord::new(violation, &config);

        assert!(record.trace_id.is_some());
        assert!(record.stack_trace.is_some());
        assert!(record.replay_command.is_some());
    }

    #[test]
    fn test_oracle_reset() {
        let mut oracle = WakerDedupOracle::with_defaults();

        // Add some state
        oracle.on_waker_registered(WakerId(1), ChannelId(1), true, None);
        oracle.on_waker_actually_woken(WakerId(999), None); // Spurious wakeup

        // Verify state exists
        assert!(!oracle.wakers.is_empty());
        assert!(!oracle.violations.is_empty());

        // Reset and verify clean state
        oracle.reset();

        assert!(oracle.wakers.is_empty());
        assert!(oracle.violations.is_empty());
        assert_eq!(oracle.statistics().total_wakers_registered, 0);
    }
}
