//! Runtime Epoch Consistency Tracker
//!
//! This module provides runtime epoch boundary monitoring to ensure state
//! transitions happen atomically without tearing or inconsistency across modules.
//!
//! # Purpose
//!
//! The epoch tracker monitors epoch transitions across all runtime modules
//! to detect when different parts of the runtime get out of sync. Epoch
//! consistency is fundamental for deterministic behavior and state machine
//! correctness.
//!
//! # Key Detection Capabilities
//!
//! - Module epoch synchronization violations (modules operating on different epochs)
//! - Slow epoch transitions that cause temporary inconsistency windows
//! - Missing epoch transition notifications between modules
//! - Epoch advancement order violations (modules advancing out of order)
//! - Cross-module state synchronization failures during epoch boundaries
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::runtime::epoch_tracker::{EpochConsistencyTracker, ModuleId};
//!
//! let tracker = EpochConsistencyTracker::new();
//!
//! // Notify tracker of epoch transitions
//! tracker.notify_epoch_transition(ModuleId::Scheduler, old_epoch, new_epoch, now);
//! tracker.notify_epoch_transition(ModuleId::RegionTable, old_epoch, new_epoch, now);
//!
//! // Check for consistency violations
//! if let Some(violation) = tracker.check_consistency() {
//!     eprintln!("Epoch consistency violation: {}", violation);
//! }
//! ```

use crate::epoch::EpochId;
use crate::tracing_compat::{debug, error, info, warn};
use crate::types::Time;
use crate::util::det_hash::DetHashMap;
use crossbeam_queue::ArrayQueue;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

type TimeGetter = Arc<dyn Fn() -> Time + Send + Sync>;

const DEFAULT_TELEMETRY_CAPACITY: usize = 1024;
const DEFAULT_TELEMETRY_DRAIN_LIMIT: usize = 64;

/// Identifier for runtime modules that participate in epoch transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ModuleId {
    /// Three-lane scheduler
    Scheduler,
    /// Region table (region creation/destruction)
    RegionTable,
    /// Task table (task lifecycle)
    TaskTable,
    /// Obligation table (permit/ack/lease)
    ObligationTable,
    /// Timer wheel (timer epoch advancement)
    TimerWheel,
    /// I/O reactor (reactor epoch synchronization)
    IoReactor,
    /// Cancel protocol (cancellation epoch consistency)
    CancelProtocol,
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheduler => write!(f, "Scheduler"),
            Self::RegionTable => write!(f, "RegionTable"),
            Self::TaskTable => write!(f, "TaskTable"),
            Self::ObligationTable => write!(f, "ObligationTable"),
            Self::TimerWheel => write!(f, "TimerWheel"),
            Self::IoReactor => write!(f, "IoReactor"),
            Self::CancelProtocol => write!(f, "CancelProtocol"),
        }
    }
}

/// An epoch consistency violation detected by the tracker.
#[derive(Debug, Clone)]
pub enum EpochConsistencyViolation {
    /// Module epoch synchronization violation.
    ///
    /// Different modules are operating on different epochs when they should be synchronized.
    ModuleDesync {
        /// The modules that are out of sync.
        modules: Vec<(ModuleId, EpochId)>,
        /// When the violation was detected.
        detected_at: Time,
        /// Maximum epoch skew between modules.
        max_skew: u64,
    },

    /// Slow epoch transition detected.
    ///
    /// A module took too long to transition to a new epoch, causing a temporary
    /// inconsistency window.
    SlowTransition {
        /// The module that was slow to transition.
        module: ModuleId,
        /// The epoch transition that was slow.
        from_epoch: EpochId,
        /// The epoch being transitioned to.
        to_epoch: EpochId,
        /// When the transition started.
        started_at: Time,
        /// When the slow transition was detected.
        detected_at: Time,
        /// How long the transition has been in progress.
        duration_ns: u64,
    },

    /// Missing epoch transition notification.
    ///
    /// A module failed to notify the tracker of an epoch transition.
    MissingTransition {
        /// The module that failed to notify.
        module: ModuleId,
        /// The expected epoch the module should be on.
        expected_epoch: EpochId,
        /// The actual epoch the module reported.
        actual_epoch: EpochId,
        /// When the missing transition was detected.
        detected_at: Time,
    },

    /// Epoch advancement order violation.
    ///
    /// Modules advanced epochs in the wrong order, violating dependency relationships.
    AdvancementOrderViolation {
        /// The module that advanced out of order.
        module: ModuleId,
        /// The epoch the module advanced to.
        advanced_to: EpochId,
        /// The dependency module that should have advanced first.
        dependency_module: ModuleId,
        /// The epoch the dependency is currently on.
        dependency_epoch: EpochId,
        /// When the violation was detected.
        detected_at: Time,
    },
}

impl fmt::Display for EpochConsistencyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleDesync {
                modules,
                detected_at,
                max_skew,
            } => {
                write!(
                    f,
                    "Module desync (skew={}) at {}: ",
                    max_skew,
                    detected_at.as_nanos()
                )?;
                for (i, (module, epoch)) in modules.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{module}@{epoch}")?;
                }
                Ok(())
            }
            Self::SlowTransition {
                module,
                from_epoch,
                to_epoch,
                started_at,
                detected_at,
                duration_ns,
            } => {
                write!(
                    f,
                    "Slow transition: {} {}→{} started={} detected={} duration={}ns",
                    module,
                    from_epoch,
                    to_epoch,
                    started_at.as_nanos(),
                    detected_at.as_nanos(),
                    duration_ns
                )
            }
            Self::MissingTransition {
                module,
                expected_epoch,
                actual_epoch,
                detected_at,
            } => {
                write!(
                    f,
                    "Missing transition: {} expected={} actual={} detected={}",
                    module,
                    expected_epoch,
                    actual_epoch,
                    detected_at.as_nanos()
                )
            }
            Self::AdvancementOrderViolation {
                module,
                advanced_to,
                dependency_module,
                dependency_epoch,
                detected_at,
            } => {
                write!(
                    f,
                    "Order violation: {} advanced to {} before {}@{} at {}",
                    module,
                    advanced_to,
                    dependency_module,
                    dependency_epoch,
                    detected_at.as_nanos()
                )
            }
        }
    }
}

impl std::error::Error for EpochConsistencyViolation {}

/// Epoch transition record for a module.
#[derive(Debug, Clone)]
struct EpochTransitionRecord {
    /// Current epoch for the module.
    current_epoch: EpochId,
    /// When the module last transitioned epochs.
    last_transition_time: Time,
    /// When the current epoch transition started (if in progress).
    transition_start_time: Option<Time>,
    /// Total number of epoch transitions for this module.
    transition_count: u64,
}

/// Callback-free counters for the bounded epoch telemetry outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTelemetryStatistics {
    /// Receipts waiting for an explicit out-of-lock dispatch point.
    pub pending: usize,
    /// Maximum number of receipts retained by the outbox.
    pub capacity: usize,
    /// Receipts dropped because the bounded outbox was full.
    pub overflow_count: u64,
    /// One-shot dispatches that contained a tracing subscriber panic.
    pub dispatch_panic_count: u64,
    /// Receipts successfully emitted before a dispatch completed or panicked.
    pub emitted_count: u64,
}

struct EpochTelemetryOutbox {
    receipts: ArrayQueue<EpochTelemetryReceipt>,
    overflow_count: AtomicU64,
    dispatch_panic_count: AtomicU64,
    emitted_count: AtomicU64,
}

impl EpochTelemetryOutbox {
    fn new(capacity: usize) -> Self {
        Self {
            receipts: ArrayQueue::new(capacity.max(1)),
            overflow_count: AtomicU64::new(0),
            dispatch_panic_count: AtomicU64::new(0),
            emitted_count: AtomicU64::new(0),
        }
    }

    fn push(&self, receipt: EpochTelemetryReceipt) {
        if self.receipts.push(receipt).is_err() {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pop_batch(&self, limit: usize) -> Vec<EpochTelemetryReceipt> {
        let mut receipts = Vec::with_capacity(limit.min(self.receipts.len()));
        for _ in 0..limit {
            let Some(receipt) = self.receipts.pop() else {
                break;
            };
            receipts.push(receipt);
        }
        receipts
    }

    fn delivery(self: &Arc<Self>, limit: usize) -> EpochTelemetryDispatch {
        EpochTelemetryDispatch {
            outbox: Arc::clone(self),
            limit,
        }
    }

    fn statistics(&self) -> EpochTelemetryStatistics {
        EpochTelemetryStatistics {
            pending: self.receipts.len(),
            capacity: self.receipts.capacity(),
            overflow_count: self.overflow_count.load(Ordering::Relaxed),
            dispatch_panic_count: self.dispatch_panic_count.load(Ordering::Relaxed),
            emitted_count: self.emitted_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
enum EpochTelemetryReceipt {
    TransitionDuplicate {
        module: ModuleId,
        current_epoch: EpochId,
        reported_from_epoch: EpochId,
        reported_to_epoch: EpochId,
        transition_time_ns: u64,
    },
    TransitionIgnored {
        module: ModuleId,
        current_epoch: EpochId,
        reported_from_epoch: EpochId,
        reported_to_epoch: EpochId,
        transition_time_ns: u64,
        sync_status: &'static str,
    },
    Transition {
        module: ModuleId,
        old_epoch: EpochId,
        new_epoch: EpochId,
        transition_time_ns: u64,
        sync_status: &'static str,
        correlation_id: u64,
        transition_count: u64,
        transition_latency_ns: u64,
    },
    TransitionLatency {
        module: ModuleId,
        transition_latency_ns: u64,
        correlation_id: u64,
        threshold_ns: u64,
    },
    ConsistencyCheckLatency {
        correlation_id: u64,
        processing_latency_ns: u64,
    },
    TransitionStartIgnored {
        module: ModuleId,
        current_epoch: EpochId,
        reported_from_epoch: EpochId,
        transition_time_ns: u64,
    },
    Violation {
        violation: EpochConsistencyViolation,
        violation_id: u64,
        strict_ordering: bool,
        slow_transition_threshold_ns: u64,
    },
    ViolationBufferTrimmed {
        violations_trimmed: usize,
        max_violations: usize,
    },
    TrackerState {
        total_modules: usize,
        total_transitions: u64,
        violation_count: usize,
        strict_ordering: bool,
        max_epoch_skew_allowed: u64,
        slow_transition_threshold_ns: u64,
    },
    ModuleState {
        module: ModuleId,
        current_epoch: EpochId,
        transition_count: u64,
        last_transition_time_ns: u64,
        is_transitioning: bool,
    },
    RecentViolation {
        violation_index: usize,
        violation: EpochConsistencyViolation,
    },
    EnabledChanged {
        enabled: bool,
    },
    ThresholdUpdated {
        old_threshold_ns: u64,
        new_threshold_ns: u64,
    },
}

impl EpochTelemetryReceipt {
    #[allow(unused_variables)]
    fn emit(self) {
        match self {
            Self::TransitionDuplicate {
                module,
                current_epoch,
                reported_from_epoch,
                reported_to_epoch,
                transition_time_ns,
            } => {
                debug!(
                    module_id = %module,
                    current_epoch = %current_epoch,
                    reported_from_epoch = %reported_from_epoch,
                    reported_to_epoch = %reported_to_epoch,
                    transition_time_ns,
                    "epoch_transition_duplicate_ignored"
                );
            }
            Self::TransitionIgnored {
                module,
                current_epoch,
                reported_from_epoch,
                reported_to_epoch,
                transition_time_ns,
                sync_status,
            } => {
                debug!(
                    module_id = %module,
                    current_epoch = %current_epoch,
                    reported_from_epoch = %reported_from_epoch,
                    reported_to_epoch = %reported_to_epoch,
                    transition_time_ns,
                    sync_status,
                    "epoch_transition_ignored"
                );
            }
            Self::Transition {
                module,
                old_epoch,
                new_epoch,
                transition_time_ns,
                sync_status,
                correlation_id,
                transition_count,
                transition_latency_ns,
            } => {
                info!(
                    module_id = %module,
                    old_epoch = %old_epoch,
                    new_epoch = %new_epoch,
                    transition_time_ns,
                    sync_status,
                    correlation_id,
                    transition_count,
                    transition_latency_ns,
                    "epoch_transition"
                );
            }
            Self::TransitionLatency {
                module,
                transition_latency_ns,
                correlation_id,
                threshold_ns,
            } => {
                debug!(
                    module_id = %module,
                    transition_latency_ns,
                    correlation_id,
                    threshold_ns,
                    "epoch_transition_latency"
                );
            }
            Self::ConsistencyCheckLatency {
                correlation_id,
                processing_latency_ns,
            } => {
                debug!(
                    correlation_id,
                    processing_latency_ns, "epoch_consistency_check_latency"
                );
            }
            Self::TransitionStartIgnored {
                module,
                current_epoch,
                reported_from_epoch,
                transition_time_ns,
            } => {
                debug!(
                    module_id = %module,
                    current_epoch = %current_epoch,
                    reported_from_epoch = %reported_from_epoch,
                    transition_time_ns,
                    "epoch_transition_start_ignored"
                );
            }
            Self::Violation {
                violation,
                violation_id,
                strict_ordering,
                slow_transition_threshold_ns,
            } => emit_violation(
                &violation,
                violation_id,
                strict_ordering,
                slow_transition_threshold_ns,
            ),
            Self::ViolationBufferTrimmed {
                violations_trimmed,
                max_violations,
            } => {
                warn!(
                    violations_trimmed,
                    max_violations, "epoch_violation_buffer_trimmed"
                );
            }
            Self::TrackerState {
                total_modules,
                total_transitions,
                violation_count,
                strict_ordering,
                max_epoch_skew_allowed,
                slow_transition_threshold_ns,
            } => {
                info!(
                    total_modules,
                    total_transitions,
                    violation_count,
                    consistency_level = if strict_ordering { "strict" } else { "relaxed" },
                    max_epoch_skew_allowed,
                    slow_transition_threshold_ns,
                    "epoch_tracker_state"
                );
            }
            Self::ModuleState {
                module,
                current_epoch,
                transition_count,
                last_transition_time_ns,
                is_transitioning,
            } => {
                debug!(
                    module_id = %module,
                    current_epoch = %current_epoch,
                    transition_count,
                    last_transition_time_ns,
                    is_transitioning,
                    "module_epoch_state"
                );
            }
            Self::RecentViolation {
                violation_index,
                violation,
            } => {
                debug!(
                    violation_index,
                    violation_type = violation_kind(&violation),
                    violation_summary = %violation,
                    "recent_epoch_violation"
                );
            }
            Self::EnabledChanged { enabled } => {
                info!(enabled, "epoch_tracker_enabled_changed");
            }
            Self::ThresholdUpdated {
                old_threshold_ns,
                new_threshold_ns,
            } => {
                info!(
                    old_threshold_ns,
                    new_threshold_ns, "epoch_tracker_threshold_updated"
                );
            }
        }
    }
}

/// Owned one-shot epoch telemetry delivery token.
///
/// Receipts remain in the bounded outbox until [`dispatch`](Self::dispatch), so
/// abandoning a deferred runtime effect cannot silently discard telemetry.
/// Callers must dispatch this only after publishing the corresponding runtime
/// mutation and releasing runtime/tracker locks. A subscriber panic aborts the
/// remainder of the drained batch, is counted without tracing, and is never
/// retried.
#[must_use = "epoch telemetry must be dispatched after publication and outside locks"]
pub struct EpochTelemetryDispatch {
    outbox: Arc<EpochTelemetryOutbox>,
    limit: usize,
}

impl EpochTelemetryDispatch {
    /// Returns whether the outbox currently has no receipts to deliver.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outbox.receipts.is_empty()
    }

    /// Emits this batch once while containing subscriber `enabled`/`on_event`
    /// panics across the entire batch.
    pub fn dispatch(self) {
        let Self { outbox, limit } = self;
        let receipts = outbox.pop_batch(limit);
        Self::dispatch_receipts(&outbox, receipts);
    }

    fn dispatch_receipts(outbox: &EpochTelemetryOutbox, receipts: Vec<EpochTelemetryReceipt>) {
        let mut emitted = 0u64;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for receipt in receipts {
                receipt.emit();
                emitted = emitted.saturating_add(1);
            }
        }));
        if emitted != 0 {
            outbox.emitted_count.fetch_add(emitted, Ordering::Relaxed);
        }
        if let Err(payload) = result {
            // ubs:ignore -- the subscriber controls this payload's destructor;
            // leaking it prevents a second panic while containment is active.
            std::mem::forget(payload);
            outbox.dispatch_panic_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "tracing-integration")]
fn violation_kind(violation: &EpochConsistencyViolation) -> &'static str {
    match violation {
        EpochConsistencyViolation::ModuleDesync { .. } => "module_desync",
        EpochConsistencyViolation::SlowTransition { .. } => "slow_transition",
        EpochConsistencyViolation::MissingTransition { .. } => "missing_transition",
        EpochConsistencyViolation::AdvancementOrderViolation { .. } => {
            "advancement_order_violation"
        }
    }
}

#[allow(unused_variables)]
fn emit_violation(
    violation: &EpochConsistencyViolation,
    violation_id: u64,
    strict_ordering: bool,
    slow_transition_threshold_ns: u64,
) {
    match violation {
        EpochConsistencyViolation::ModuleDesync {
            modules,
            detected_at,
            max_skew,
        } => {
            let affected_modules: Vec<String> = modules
                .iter()
                .map(|(module, epoch)| format!("{module}@{epoch}"))
                .collect();
            debug!(
                violation_type = "module_desync",
                affected_modules = ?affected_modules,
                epoch_skew = max_skew,
                consistency_level = if strict_ordering { "strict" } else { "relaxed" },
                correlation_id = violation_id,
                detected_at_ns = detected_at.as_nanos(),
                replay_command = %format!("epoch-tracker-replay --violation-id {} --type module_desync", violation_id),
                "epoch_consistency_violation"
            );
        }
        EpochConsistencyViolation::SlowTransition {
            module,
            from_epoch,
            to_epoch,
            started_at,
            detected_at,
            duration_ns,
        } => {
            error!(
                violation_type = "slow_transition",
                affected_modules = ?[format!("{}@{}->{}", module, from_epoch, to_epoch)],
                epoch_skew = 0u64,
                consistency_level = if strict_ordering { "strict" } else { "relaxed" },
                correlation_id = violation_id,
                module_id = %module,
                transition_duration_ns = duration_ns,
                threshold_ns = slow_transition_threshold_ns,
                started_at_ns = started_at.as_nanos(),
                detected_at_ns = detected_at.as_nanos(),
                replay_command = %format!("epoch-tracker-replay --violation-id {} --type slow_transition --module {}", violation_id, module),
                "epoch_consistency_violation"
            );
        }
        EpochConsistencyViolation::MissingTransition {
            module,
            expected_epoch,
            actual_epoch,
            detected_at,
        } => {
            let epoch_skew = actual_epoch.distance(*expected_epoch);
            error!(
                violation_type = "missing_transition",
                affected_modules = ?[format!("{}@{}", module, actual_epoch)],
                epoch_skew,
                consistency_level = if strict_ordering { "strict" } else { "relaxed" },
                correlation_id = violation_id,
                module_id = %module,
                expected_epoch = %expected_epoch,
                actual_epoch = %actual_epoch,
                detected_at_ns = detected_at.as_nanos(),
                replay_command = %format!("epoch-tracker-replay --violation-id {} --type missing_transition --module {} --expected-epoch {} --actual-epoch {}", violation_id, module, expected_epoch, actual_epoch),
                "epoch_consistency_violation"
            );
        }
        EpochConsistencyViolation::AdvancementOrderViolation {
            module,
            advanced_to,
            dependency_module,
            dependency_epoch,
            detected_at,
        } => {
            let epoch_skew = advanced_to.distance(*dependency_epoch);
            error!(
                violation_type = "advancement_order_violation",
                affected_modules = ?[format!("{}@{}", module, advanced_to), format!("{}@{}", dependency_module, dependency_epoch)],
                epoch_skew,
                consistency_level = if strict_ordering { "strict" } else { "relaxed" },
                correlation_id = violation_id,
                violating_module = %module,
                advanced_to = %advanced_to,
                dependency_module = %dependency_module,
                dependency_epoch = %dependency_epoch,
                detected_at_ns = detected_at.as_nanos(),
                replay_command = %format!("epoch-tracker-replay --violation-id {} --type order_violation --module {} --dependency-module {}", violation_id, module, dependency_module),
                "epoch_consistency_violation"
            );
        }
    }
}

/// Configuration for epoch consistency checking.
#[derive(Debug, Clone)]
pub struct EpochConsistencyConfig {
    /// Maximum allowed epoch skew between modules before flagging as violation.
    pub max_epoch_skew: u64,
    /// Maximum duration for epoch transitions before flagging as slow.
    pub slow_transition_threshold_ns: u64,
    /// Whether to enable strict order checking for dependent modules.
    pub strict_ordering: bool,
    /// Whether to enable checking (can be disabled for performance).
    pub enabled: bool,
}

impl Default for EpochConsistencyConfig {
    fn default() -> Self {
        Self {
            max_epoch_skew: 2,
            slow_transition_threshold_ns: 1_000_000, // 1ms
            strict_ordering: true,
            enabled: true,
        }
    }
}

impl EpochConsistencyConfig {
    /// Creates a relaxed configuration suitable for production.
    #[inline]
    #[must_use]
    pub fn relaxed() -> Self {
        Self {
            max_epoch_skew: 5,
            slow_transition_threshold_ns: 10_000_000, // 10ms
            strict_ordering: false,
            enabled: true,
        }
    }

    /// Creates a strict configuration suitable for testing.
    #[inline]
    #[must_use]
    pub fn strict() -> Self {
        Self {
            // In strict mode any cross-module skew is actionable.
            max_epoch_skew: 0,
            slow_transition_threshold_ns: 100_000, // 100μs
            strict_ordering: true,
            enabled: true,
        }
    }

    /// Creates a disabled configuration (no checking).
    #[inline]
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_epoch_skew: 0,
            slow_transition_threshold_ns: 0,
            strict_ordering: false,
            enabled: false,
        }
    }
}

/// Runtime epoch consistency tracker.
///
/// Monitors epoch transitions across all runtime modules and detects
/// consistency violations.
pub struct EpochConsistencyTracker {
    /// Configuration for consistency checking.
    config: EpochConsistencyConfig,
    /// Source of wall-clock time for current-health checks.
    time_getter: TimeGetter,
    /// Per-module epoch transition records.
    module_records: RwLock<DetHashMap<ModuleId, EpochTransitionRecord>>,
    /// Global epoch transition counter.
    global_transition_count: AtomicU64,
    /// Detected violations (bounded to prevent memory growth).
    violations: RwLock<Vec<EpochConsistencyViolation>>,
    /// Maximum number of violations to retain.
    max_violations: usize,
    /// Bounded callback-free receipts awaiting an explicit safe dispatch.
    telemetry: Arc<EpochTelemetryOutbox>,
}

impl EpochConsistencyTracker {
    /// Creates a new epoch consistency tracker with default configuration.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EpochConsistencyConfig::default())
    }

    /// Creates a new epoch consistency tracker with the given configuration.
    #[must_use]
    pub fn with_config(config: EpochConsistencyConfig) -> Self {
        Self::with_config_and_time_getter(config, Arc::new(crate::time::wall_now))
    }

    /// Creates a new epoch consistency tracker with a custom time source.
    #[must_use]
    pub fn with_config_and_time_getter(
        config: EpochConsistencyConfig,
        time_getter: TimeGetter,
    ) -> Self {
        Self::with_config_time_getter_and_telemetry_capacity(
            config,
            time_getter,
            DEFAULT_TELEMETRY_CAPACITY,
        )
    }

    fn with_config_time_getter_and_telemetry_capacity(
        config: EpochConsistencyConfig,
        time_getter: TimeGetter,
        telemetry_capacity: usize,
    ) -> Self {
        Self {
            config,
            time_getter,
            module_records: RwLock::new(DetHashMap::default()),
            global_transition_count: AtomicU64::new(0),
            violations: RwLock::new(Vec::new()),
            max_violations: 1000, // Bounded to prevent memory growth
            telemetry: Arc::new(EpochTelemetryOutbox::new(telemetry_capacity)),
        }
    }

    fn enqueue_telemetry(&self, receipt: EpochTelemetryReceipt) {
        self.telemetry.push(receipt);
    }

    /// Creates a bounded delivery token for use after the corresponding runtime
    /// mutation is published and all runtime/tracker locks are released.
    /// Receipts are removed from the outbox only when the token is dispatched.
    #[must_use]
    pub fn drain_telemetry(&self) -> EpochTelemetryDispatch {
        self.telemetry.delivery(DEFAULT_TELEMETRY_DRAIN_LIMIT)
    }

    /// Returns callback-free outbox counters without emitting telemetry.
    #[inline]
    #[must_use]
    pub fn telemetry_statistics(&self) -> EpochTelemetryStatistics {
        self.telemetry.statistics()
    }

    /// Notifies the tracker of an epoch transition for a module.
    #[allow(unused_variables)]
    pub fn notify_epoch_transition(
        &self,
        module: ModuleId,
        from_epoch: EpochId,
        to_epoch: EpochId,
        now: Time,
    ) {
        if !self.config.enabled {
            return;
        }

        // Generate correlation ID for cross-module analysis
        let correlation_id = self.global_transition_count.load(Ordering::Relaxed) + 1;

        let mut records = self.module_records.write();
        let record = records
            .entry(module)
            .or_insert_with(|| EpochTransitionRecord {
                current_epoch: from_epoch,
                last_transition_time: now,
                transition_start_time: None,
                transition_count: 0,
            });

        let exact_duplicate_completion = record.current_epoch == to_epoch
            && to_epoch
                .prev()
                .is_some_and(|expected_from| expected_from == from_epoch);
        if exact_duplicate_completion {
            self.enqueue_telemetry(EpochTelemetryReceipt::TransitionDuplicate {
                module,
                current_epoch: record.current_epoch,
                reported_from_epoch: from_epoch,
                reported_to_epoch: to_epoch,
                transition_time_ns: now.as_nanos(),
            });
            return;
        }

        // Check for expected transition sequence. Forward skips are accepted but
        // reported; stale/backward reports remain visible as violations without
        // rewinding the tracker's internal epoch state.
        let expected_epoch = record.current_epoch.next();
        let (sync_status, should_update) = if record.current_epoch == from_epoch {
            if to_epoch == expected_epoch {
                ("synchronized", true)
            } else if to_epoch.is_after(expected_epoch) {
                let violation = EpochConsistencyViolation::MissingTransition {
                    module,
                    expected_epoch,
                    actual_epoch: to_epoch,
                    detected_at: now,
                };
                self.record_violation(violation);
                ("skipped_forward", true)
            } else {
                let violation = EpochConsistencyViolation::MissingTransition {
                    module,
                    expected_epoch,
                    actual_epoch: to_epoch,
                    detected_at: now,
                };
                self.record_violation(violation);
                ("non_advancing", false)
            }
        } else {
            let violation = EpochConsistencyViolation::MissingTransition {
                module,
                expected_epoch,
                actual_epoch: to_epoch,
                detected_at: now,
            };
            self.record_violation(violation);
            ("violated", to_epoch.is_after(record.current_epoch))
        };
        if !should_update {
            self.enqueue_telemetry(EpochTelemetryReceipt::TransitionIgnored {
                module,
                current_epoch: record.current_epoch,
                reported_from_epoch: from_epoch,
                reported_to_epoch: to_epoch,
                transition_time_ns: now.as_nanos(),
                sync_status,
            });
            return;
        }

        // Calculate transition latency if there was a transition start time
        let transition_latency_ns = record
            .transition_start_time
            .map_or(0, |start| now.duration_since(start));

        // Update record
        record.current_epoch = to_epoch;
        record.last_transition_time = now;
        record.transition_start_time = None;
        record.transition_count += 1;

        // Increment global counter
        self.global_transition_count.fetch_add(1, Ordering::Relaxed);

        self.enqueue_telemetry(EpochTelemetryReceipt::Transition {
            module,
            old_epoch: from_epoch,
            new_epoch: to_epoch,
            transition_time_ns: now.as_nanos(),
            sync_status,
            correlation_id,
            transition_count: record.transition_count,
            transition_latency_ns,
        });

        // Log performance metrics for epoch transition latency
        if transition_latency_ns > 0 {
            self.enqueue_telemetry(EpochTelemetryReceipt::TransitionLatency {
                module,
                transition_latency_ns,
                correlation_id,
                threshold_ns: self.config.slow_transition_threshold_ns,
            });
        }

        // Check for consistency violations after this transition
        drop(records); // Release lock before consistency check
        let processing_start = std::time::Instant::now();
        self.check_consistency_internal(now);
        let processing_latency = processing_start.elapsed().as_nanos() as u64;

        self.enqueue_telemetry(EpochTelemetryReceipt::ConsistencyCheckLatency {
            correlation_id,
            processing_latency_ns: processing_latency,
        });
    }

    /// Notifies the tracker that a module is starting an epoch transition.
    pub fn notify_epoch_transition_start(&self, module: ModuleId, from_epoch: EpochId, now: Time) {
        if !self.config.enabled {
            return;
        }

        let mut records = self.module_records.write();
        let record = records
            .entry(module)
            .or_insert_with(|| EpochTransitionRecord {
                current_epoch: from_epoch,
                last_transition_time: now,
                transition_start_time: None,
                transition_count: 0,
            });

        if record.current_epoch != from_epoch {
            let current_epoch = record.current_epoch;
            let violation = EpochConsistencyViolation::MissingTransition {
                module,
                expected_epoch: current_epoch,
                actual_epoch: from_epoch,
                detected_at: now,
            };
            drop(records);
            self.record_violation(violation);

            self.enqueue_telemetry(EpochTelemetryReceipt::TransitionStartIgnored {
                module,
                current_epoch,
                reported_from_epoch: from_epoch,
                transition_time_ns: now.as_nanos(),
            });
            return;
        }

        record.transition_start_time = Some(
            record
                .transition_start_time
                .map_or(now, |existing_start| existing_start.min(now)),
        );
    }

    /// Checks for currently active epoch consistency violations.
    ///
    /// This reports only violations that are still true of the current tracker
    /// state. Historical transition anomalies remain available through
    /// [`all_violations`](Self::all_violations) and
    /// [`latest_violation`](Self::latest_violation), but do not permanently
    /// poison the runtime's current-health signal.
    pub fn check_consistency(&self) -> Option<EpochConsistencyViolation> {
        if !self.config.enabled {
            return None;
        }

        let records = self.module_records.read();
        let recorded_now = records
            .values()
            .map(|record| {
                record
                    .transition_start_time
                    .unwrap_or(record.last_transition_time)
            })
            .max()
            .unwrap_or(Time::ZERO);
        let sampled_now = (self.time_getter)();
        let now = if sampled_now.as_nanos() >= recorded_now.as_nanos() {
            sampled_now
        } else {
            recorded_now
        };
        if let Some(violation) = self.current_module_desync_violation(&records, now, false) {
            return Some(violation);
        }
        if let Some(violation) = self.current_slow_transition_violation(&records, now) {
            return Some(violation);
        }
        if self.config.strict_ordering {
            return self.current_advancement_order_violation(&records, now);
        }
        None
    }

    /// Internal consistency checking with proper timestamp.
    fn check_consistency_internal(&self, now: Time) {
        let records = self.module_records.read();

        // Check for module desync
        self.check_module_desync(&records, now);

        // Check for slow transitions
        self.check_slow_transitions(&records, now);

        // Check for advancement order violations if strict ordering is enabled
        if self.config.strict_ordering {
            self.check_advancement_order(&records, now);
        }
    }

    /// Checks for module epoch desynchronization.
    fn check_module_desync(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        if let Some(violation) = self.current_module_desync_violation(records, now, true) {
            self.record_violation(violation);
        }
    }

    fn current_module_desync_violation(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
        suppress_single_step_batch: bool,
    ) -> Option<EpochConsistencyViolation> {
        let mut epochs: BTreeMap<EpochId, Vec<ModuleId>> = BTreeMap::new();

        for (&module, record) in records {
            epochs.entry(record.current_epoch).or_default().push(module);
        }

        if epochs.len() <= 1 {
            return None;
        }

        let epoch_ids: Vec<EpochId> = epochs.keys().copied().collect();
        let min_epoch = epoch_ids.first().copied().unwrap_or(EpochId::GENESIS);
        let max_epoch = epoch_ids.last().copied().unwrap_or(EpochId::GENESIS);
        let skew = max_epoch.distance(min_epoch);

        if skew <= self.config.max_epoch_skew {
            return None;
        }

        // Multiple modules often advance within the same logical time tick.
        // Suppress the transient "some at N, some at N+1" shape while that
        // single-step batch is still being reported. Without this, the first
        // module in a coherent same-timestamp wave records a permanent
        // false-positive desync before the remaining modules notify.
        if suppress_single_step_batch
            && self.is_single_step_batch_transition(records, min_epoch, max_epoch, now)
        {
            return None;
        }

        let mut modules_with_epochs = Vec::new();
        for (&epoch, modules) in &epochs {
            for &module in modules {
                modules_with_epochs.push((module, epoch));
            }
        }
        modules_with_epochs.sort_by_key(|(module, epoch)| (*epoch, *module));

        Some(EpochConsistencyViolation::ModuleDesync {
            modules: modules_with_epochs,
            detected_at: now,
            max_skew: skew,
        })
    }

    fn is_single_step_batch_transition(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        min_epoch: EpochId,
        max_epoch: EpochId,
        now: Time,
    ) -> bool {
        if max_epoch.distance(min_epoch) != 1 {
            return false;
        }

        let expected_next_epoch = min_epoch.next();
        if expected_next_epoch != max_epoch {
            return false;
        }

        let mut saw_advanced_module = false;
        for record in records.values() {
            if record.current_epoch == max_epoch {
                if record.last_transition_time != now {
                    return false;
                }
                saw_advanced_module = true;
            } else if record.current_epoch != min_epoch {
                return false;
            }
        }

        saw_advanced_module
    }

    /// Checks for slow epoch transitions.
    fn check_slow_transitions(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        if let Some(violation) = self.current_slow_transition_violation(records, now) {
            self.record_violation(violation);
        }
    }

    fn current_slow_transition_violation(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) -> Option<EpochConsistencyViolation> {
        let mut candidate: Option<(ModuleId, EpochId, Time, u64)> = None;

        for (&module, record) in records {
            let Some(transition_start) = record.transition_start_time else {
                continue;
            };

            let duration_ns = now.duration_since(transition_start);
            if duration_ns <= self.config.slow_transition_threshold_ns {
                continue;
            }

            match candidate {
                Some((best_module, _best_epoch, best_start, best_duration))
                    if best_duration > duration_ns
                        || (best_duration == duration_ns
                            && (best_start < transition_start
                                || (best_start == transition_start && best_module <= module))) => {}
                _ => {
                    candidate = Some((module, record.current_epoch, transition_start, duration_ns));
                }
            }
        }

        candidate.map(|(module, from_epoch, started_at, duration_ns)| {
            EpochConsistencyViolation::SlowTransition {
                module,
                from_epoch,
                to_epoch: from_epoch.next(),
                started_at,
                detected_at: now,
                duration_ns,
            }
        })
    }

    /// Checks for epoch advancement order violations.
    ///
    /// In strict ordering mode, we enforce that certain modules must advance
    /// epochs in a specific order (e.g., Scheduler before TaskTable).
    fn check_advancement_order(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        if let Some(violation) = self.current_advancement_order_violation(records, now) {
            self.record_violation(violation);
        }
    }

    fn current_advancement_order_violation(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) -> Option<EpochConsistencyViolation> {
        // Define dependency relationships: (dependent_module, dependency_module)
        let dependencies = [
            (ModuleId::TaskTable, ModuleId::Scheduler),
            (ModuleId::RegionTable, ModuleId::Scheduler),
            (ModuleId::ObligationTable, ModuleId::TaskTable),
            (ModuleId::TimerWheel, ModuleId::Scheduler),
            (ModuleId::CancelProtocol, ModuleId::TaskTable),
        ];

        for (dependent, dependency) in dependencies {
            if let (Some(dependent_record), Some(dependency_record)) =
                (records.get(&dependent), records.get(&dependency))
            {
                if dependent_record
                    .current_epoch
                    .is_after(dependency_record.current_epoch)
                {
                    return Some(EpochConsistencyViolation::AdvancementOrderViolation {
                        module: dependent,
                        advanced_to: dependent_record.current_epoch,
                        dependency_module: dependency,
                        dependency_epoch: dependency_record.current_epoch,
                        detected_at: now,
                    });
                }
            }
        }

        None
    }

    /// Records a violation, maintaining bounded storage.
    // Structured logging fields in this function are compiled out when
    // `tracing-integration` is disabled, so the bindings only become "unused"
    // in no-op builds.
    #[allow(unused_variables)]
    fn record_violation(&self, violation: EpochConsistencyViolation) {
        {
            let violations = self.violations.read();
            if let Some(last) = violations.last() {
                match (last, &violation) {
                    (
                        EpochConsistencyViolation::ModuleDesync {
                            modules: modules1,
                            max_skew: skew1,
                            ..
                        },
                        EpochConsistencyViolation::ModuleDesync {
                            modules: modules2,
                            max_skew: skew2,
                            ..
                        },
                    ) if skew1 == skew2 && modules1 == modules2 => return,
                    (
                        EpochConsistencyViolation::AdvancementOrderViolation {
                            module: m1,
                            advanced_to: a1,
                            ..
                        },
                        EpochConsistencyViolation::AdvancementOrderViolation {
                            module: m2,
                            advanced_to: a2,
                            ..
                        },
                    ) if m1 == m2 && a1 == a2 => return,
                    (
                        EpochConsistencyViolation::SlowTransition {
                            module: m1,
                            to_epoch: t1,
                            ..
                        },
                        EpochConsistencyViolation::SlowTransition {
                            module: m2,
                            to_epoch: t2,
                            ..
                        },
                    ) if m1 == m2 && t1 == t2 => return,
                    _ => {}
                }
            }
        }

        let violation_id = self.global_transition_count.load(Ordering::Relaxed);

        let mut violations = self.violations.write();
        violations.push(violation.clone());
        self.enqueue_telemetry(EpochTelemetryReceipt::Violation {
            violation,
            violation_id,
            strict_ordering: self.config.strict_ordering,
            slow_transition_threshold_ns: self.config.slow_transition_threshold_ns,
        });

        // Trim violations if we've exceeded the limit
        if violations.len() > self.max_violations {
            let excess = violations.len() - self.max_violations;
            violations.drain(0..excess);
            self.enqueue_telemetry(EpochTelemetryReceipt::ViolationBufferTrimmed {
                violations_trimmed: excess,
                max_violations: self.max_violations,
            });
        }
    }

    /// Returns all detected violations.
    #[inline]
    #[must_use]
    pub fn all_violations(&self) -> Vec<EpochConsistencyViolation> {
        self.violations.read().clone()
    }

    /// Returns the most recently recorded historical violation, if any.
    ///
    /// Unlike [`check_consistency`](Self::check_consistency), this does not
    /// require the violation to still be active in the current tracker state.
    #[inline]
    #[must_use]
    pub fn latest_violation(&self) -> Option<EpochConsistencyViolation> {
        self.violations.read().last().cloned()
    }

    /// Returns the number of violations detected.
    #[inline]
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.read().len()
    }

    /// Returns statistics about epoch transitions.
    #[must_use]
    pub fn transition_statistics(&self) -> EpochTransitionStatistics {
        let records = self.module_records.read();
        let total_transitions = self.global_transition_count.load(Ordering::Relaxed);

        let mut per_module_stats = DetHashMap::default();
        let mut latest_epoch = EpochId::GENESIS;

        for (&module, record) in records.iter() {
            per_module_stats.insert(
                module,
                EpochModuleStatistics {
                    current_epoch: record.current_epoch,
                    transition_count: record.transition_count,
                    last_transition_time: record.last_transition_time,
                },
            );

            if record.current_epoch.is_after(latest_epoch) {
                latest_epoch = record.current_epoch;
            }
        }
        drop(records);

        EpochTransitionStatistics {
            total_transitions,
            per_module_stats,
            latest_epoch,
            violation_count: self.violation_count(),
        }
    }

    /// Clears all violations and statistics.
    pub fn reset(&self) {
        self.module_records.write().clear();
        self.violations.write().clear();
        self.global_transition_count.store(0, Ordering::Relaxed);
        while self.telemetry.receipts.pop().is_some() {}
        self.telemetry.overflow_count.store(0, Ordering::Relaxed);
        self.telemetry
            .dispatch_panic_count
            .store(0, Ordering::Relaxed);
        self.telemetry.emitted_count.store(0, Ordering::Relaxed);
    }
}

impl Default for EpochConsistencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about epoch transitions.
#[derive(Debug, Clone)]
pub struct EpochTransitionStatistics {
    /// Total number of epoch transitions across all modules.
    pub total_transitions: u64,
    /// Per-module statistics.
    pub per_module_stats: DetHashMap<ModuleId, EpochModuleStatistics>,
    /// Latest epoch across all modules.
    pub latest_epoch: EpochId,
    /// Number of violations detected.
    pub violation_count: usize,
}

/// Statistics for a single module.
#[derive(Debug, Clone)]
pub struct EpochModuleStatistics {
    /// Current epoch for the module.
    pub current_epoch: EpochId,
    /// Number of transitions for this module.
    pub transition_count: u64,
    /// When this module last transitioned.
    pub last_transition_time: Time,
}

impl EpochConsistencyTracker {
    /// Generates a replay command for reproducing epoch inconsistency scenarios.
    ///
    /// This method is useful for creating diagnostic commands that can reproduce
    /// specific epoch consistency issues for debugging purposes.
    #[must_use]
    pub fn generate_replay_command(
        &self,
        scenario_type: &str,
        additional_args: &[(&str, &str)],
    ) -> String {
        let base_cmd = format!("epoch-tracker-replay --scenario {scenario_type}");

        let args: Vec<String> = additional_args
            .iter()
            .map(|(key, value)| format!("--{key} {value}"))
            .collect();

        if args.is_empty() {
            base_cmd
        } else {
            format!("{} {}", base_cmd, args.join(" "))
        }
    }

    /// Queues comprehensive epoch state telemetry for debugging and monitoring.
    ///
    /// This method snapshots the complete epoch state across all modules. Call
    /// [`drain_telemetry`](Self::drain_telemetry) and dispatch the returned token
    /// after releasing any surrounding runtime locks to emit that snapshot.
    // `tracing_compat` expands to no-op macros without tracing integration,
    // so these locals are only consumed in tracing-enabled builds.
    #[allow(unused_variables)]
    pub fn log_epoch_state(&self) {
        let records = self.module_records.read();
        let total_transitions = self.global_transition_count.load(Ordering::Relaxed);
        let module_states: Vec<_> = records
            .iter()
            .map(|(&module, record)| EpochTelemetryReceipt::ModuleState {
                module,
                current_epoch: record.current_epoch,
                transition_count: record.transition_count,
                last_transition_time_ns: record.last_transition_time.as_nanos(),
                is_transitioning: record.transition_start_time.is_some(),
            })
            .collect();
        let total_modules = records.len();
        drop(records);

        let violations = self.violations.read();
        let violation_count = violations.len();
        let recent_violations: Vec<_> = violations
            .iter()
            .enumerate()
            .take(5)
            .map(
                |(violation_index, violation)| EpochTelemetryReceipt::RecentViolation {
                    violation_index,
                    violation: violation.clone(),
                },
            )
            .collect();
        drop(violations);

        self.enqueue_telemetry(EpochTelemetryReceipt::TrackerState {
            total_modules,
            total_transitions,
            violation_count,
            strict_ordering: self.config.strict_ordering,
            max_epoch_skew_allowed: self.config.max_epoch_skew,
            slow_transition_threshold_ns: self.config.slow_transition_threshold_ns,
        });
        for module_state in module_states {
            self.enqueue_telemetry(module_state);
        }
        for recent_violation in recent_violations {
            self.enqueue_telemetry(recent_violation);
        }
    }

    /// Enables or disables epoch consistency checking at runtime.
    ///
    /// This can be useful for temporarily disabling checking during
    /// performance-critical sections or enabling it for debugging. The change
    /// queues telemetry for later delivery through
    /// [`drain_telemetry`](Self::drain_telemetry).
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
        self.enqueue_telemetry(EpochTelemetryReceipt::EnabledChanged { enabled });
    }

    /// Updates the slow transition threshold dynamically.
    ///
    /// This allows tuning the sensitivity of slow transition detection
    /// based on runtime conditions or performance requirements. The change
    /// queues telemetry for later delivery through
    /// [`drain_telemetry`](Self::drain_telemetry).
    #[allow(unused_variables)]
    pub fn set_slow_transition_threshold(&mut self, threshold_ns: u64) {
        let old_threshold = self.config.slow_transition_threshold_ns;
        self.config.slow_transition_threshold_ns = threshold_ns;
        self.enqueue_telemetry(EpochTelemetryReceipt::ThresholdUpdated {
            old_threshold_ns: old_threshold,
            new_threshold_ns: threshold_ns,
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// Regression for #42: ModuleDesync is a heuristic skew
    /// observation, not a runtime invariant violation. The event is
    /// kept (so callers can query `all_violations()`) but its tracing
    /// emit level must be DEBUG, not ERROR — otherwise the routine
    /// pattern of TaskTable advancing past unused RegionTable spams
    /// the default-level log with `epoch_consistency_violation
    /// violation_type="module_desync"`.
    ///
    /// AdvancementOrderViolation, the *real* invariant violation
    /// (dependent module ahead of its dependency), still emits at
    /// ERROR — sibling test below.
    #[cfg(feature = "tracing-integration")]
    #[test]
    fn module_desync_emits_at_debug_not_error() {
        use parking_lot::Mutex;
        use std::sync::Arc;
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        init_test("module_desync_emits_at_debug_not_error");

        #[derive(Clone)]
        struct Captured {
            level: tracing::Level,
            violation_type: Option<String>,
        }
        struct Recorder {
            events: Arc<Mutex<Vec<Captured>>>,
        }
        struct VisitField {
            violation_type: Option<String>,
        }
        impl tracing::field::Visit for VisitField {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "violation_type" && self.violation_type.is_none() {
                    let rendered = format!("{value:?}");
                    self.violation_type = Some(rendered.trim_matches('"').to_string());
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "violation_type" {
                    self.violation_type = Some(value.to_string());
                }
            }
        }
        impl<S> Layer<S> for Recorder
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let mut v = VisitField {
                    violation_type: None,
                };
                event.record(&mut v);
                self.events.lock().push(Captured {
                    level: *event.metadata().level(),
                    violation_type: v.violation_type,
                });
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(recorder);

        tracing::subscriber::with_default(subscriber, || {
            let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
            // Reproduce the #42 repro shape: TaskTable advances past
            // RegionTable@Genesis (skew > max_epoch_skew).
            let now = Time::from_nanos(1000);
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
            tracker.notify_epoch_transition(
                ModuleId::TaskTable,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
            for to in 2u64..=5 {
                tracker.notify_epoch_transition(
                    ModuleId::TaskTable,
                    EpochId::new(to - 1),
                    EpochId::new(to),
                    Time::from_nanos(1000 + to * 100),
                );
            }
            tracker.notify_epoch_transition(
                ModuleId::RegionTable,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
            tracker.drain_telemetry().dispatch();
        });

        let captured = events.lock();
        let desync_events: Vec<&Captured> = captured
            .iter()
            .filter(|c| c.violation_type.as_deref() == Some("module_desync"))
            .collect();
        crate::assert_with_log!(
            !desync_events.is_empty(),
            "module_desync events must still be emitted (just at debug level)",
            true,
            !desync_events.is_empty()
        );
        for ev in &desync_events {
            crate::assert_with_log!(
                ev.level == tracing::Level::DEBUG,
                "module_desync events must emit at DEBUG (regression #42)",
                tracing::Level::DEBUG,
                ev.level
            );
            crate::assert_with_log!(
                ev.level != tracing::Level::ERROR,
                "module_desync events must NOT emit at ERROR — that was the #42 noise",
                "not ERROR",
                ev.level
            );
        }
        crate::test_complete!("module_desync_emits_at_debug_not_error");
    }

    #[test]
    fn epoch_telemetry_outbox_is_bounded_and_drains_in_receipt_order() {
        init_test("epoch_telemetry_outbox_is_bounded_and_drains_in_receipt_order");

        let tracker = EpochConsistencyTracker::with_config_time_getter_and_telemetry_capacity(
            EpochConsistencyConfig::default(),
            Arc::new(|| Time::ZERO),
            3,
        );
        let now = Time::from_nanos(10);
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let full = tracker.telemetry_statistics();
        assert_eq!(full.pending, 3);
        assert_eq!(full.capacity, 3);
        assert_eq!(full.overflow_count, 1);

        let first = tracker.telemetry.pop_batch(2);
        assert!(matches!(
            first.as_slice(),
            [
                EpochTelemetryReceipt::Transition { .. },
                EpochTelemetryReceipt::ConsistencyCheckLatency { .. }
            ]
        ));
        assert_eq!(tracker.telemetry_statistics().pending, 1);
        EpochTelemetryDispatch::dispatch_receipts(&tracker.telemetry, first);

        let second = tracker.telemetry.pop_batch(2);
        assert!(matches!(
            second.as_slice(),
            [EpochTelemetryReceipt::TransitionDuplicate { .. }]
        ));
        EpochTelemetryDispatch::dispatch_receipts(&tracker.telemetry, second);

        let drained = tracker.telemetry_statistics();
        assert_eq!(drained.pending, 0);
        assert_eq!(drained.emitted_count, 3);
        assert_eq!(drained.overflow_count, 1);
        crate::test_complete!("epoch_telemetry_outbox_is_bounded_and_drains_in_receipt_order");
    }

    #[test]
    fn epoch_telemetry_public_drain_enforces_production_batch_limit() {
        init_test("epoch_telemetry_public_drain_enforces_production_batch_limit");

        let tracker = EpochConsistencyTracker::with_config_time_getter_and_telemetry_capacity(
            EpochConsistencyConfig::default(),
            Arc::new(|| Time::ZERO),
            DEFAULT_TELEMETRY_CAPACITY,
        );
        let now = Time::from_nanos(10);
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        for _ in 0..DEFAULT_TELEMETRY_DRAIN_LIMIT {
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
        }

        let first = tracker.drain_telemetry();
        assert_eq!(
            tracker.telemetry_statistics().pending,
            DEFAULT_TELEMETRY_DRAIN_LIMIT + 2,
            "creating a delivery token must not remove receipts"
        );
        first.dispatch();
        assert_eq!(tracker.telemetry_statistics().pending, 2);
        assert_eq!(
            tracker.telemetry_statistics().emitted_count,
            DEFAULT_TELEMETRY_DRAIN_LIMIT as u64
        );

        let second = tracker.drain_telemetry();
        second.dispatch();
        assert_eq!(tracker.telemetry_statistics().pending, 0);
        crate::test_complete!("epoch_telemetry_public_drain_enforces_production_batch_limit");
    }

    #[test]
    fn epoch_telemetry_abandoned_delivery_leaves_receipts_pending() {
        init_test("epoch_telemetry_abandoned_delivery_leaves_receipts_pending");

        let tracker = EpochConsistencyTracker::new();
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(10),
        );
        assert_eq!(tracker.telemetry_statistics().pending, 2);

        let abandoned = tracker.drain_telemetry();
        assert!(!abandoned.is_empty());
        drop(abandoned);
        assert_eq!(
            tracker.telemetry_statistics().pending,
            2,
            "dropping an undispatched token must leave receipts available"
        );

        tracker.drain_telemetry().dispatch();
        let delivered = tracker.telemetry_statistics();
        assert_eq!(delivered.pending, 0);
        assert_eq!(delivered.emitted_count, 2);
        crate::test_complete!("epoch_telemetry_abandoned_delivery_leaves_receipts_pending");
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn epoch_telemetry_dispatch_allows_subscriber_reentry_after_tracker_unlock() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        init_test("epoch_telemetry_dispatch_allows_subscriber_reentry_after_tracker_unlock");

        struct ReenteringLayer {
            tracker: Arc<EpochConsistencyTracker>,
            events: Arc<AtomicUsize>,
        }
        impl<S> Layer<S> for ReenteringLayer
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let _ = self.tracker.transition_statistics();
                self.events.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        let tracker = Arc::new(EpochConsistencyTracker::new());
        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(ReenteringLayer {
                tracker: Arc::clone(&tracker),
                events: Arc::clone(&events),
            });

        tracing::subscriber::with_default(subscriber, || {
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                Time::from_nanos(10),
            );
            assert_eq!(events.load(AtomicOrdering::Relaxed), 0);
            tracker.drain_telemetry().dispatch();
        });

        assert_eq!(events.load(AtomicOrdering::Relaxed), 2);
        assert_eq!(tracker.telemetry_statistics().dispatch_panic_count, 0);
        crate::test_complete!(
            "epoch_telemetry_dispatch_allows_subscriber_reentry_after_tracker_unlock"
        );
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn epoch_telemetry_dispatch_contains_enabled_and_on_event_panics() {
        const PANIC_SITE_ENV: &str = "ASUPERSYNC_EPOCH_TELEMETRY_PANIC_SITE";
        const TEST_NAME: &str = concat!(
            "runtime::epoch_tracker::tests::",
            "epoch_telemetry_dispatch_contains_enabled_and_on_event_panics"
        );

        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Clone, Copy)]
        enum PanicSite {
            Enabled,
            OnEvent,
        }
        struct PanickingLayer(PanicSite);
        impl<S> Layer<S> for PanickingLayer
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            fn enabled(&self, _metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
                if matches!(self.0, PanicSite::Enabled) {
                    panic!("enabled panic"); // ubs:ignore -- adversarial containment fixture
                }
                true
            }

            fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                if matches!(self.0, PanicSite::OnEvent) {
                    panic!("on_event panic"); // ubs:ignore -- adversarial containment fixture
                }
            }
        }

        if let Some(site) = std::env::var_os(PANIC_SITE_ENV) {
            let panic_site = match site.to_str() {
                Some("enabled") => PanicSite::Enabled,
                Some("on_event") => PanicSite::OnEvent,
                // ubs:ignore -- child-process test protocol rejects invalid modes.
                other => panic!("unknown epoch telemetry panic site: {other:?}"),
            };
            let tracker = EpochConsistencyTracker::new();
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                Time::from_nanos(10),
            );
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::TRACE)
                .with(PanickingLayer(panic_site));
            let delivery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tracing::subscriber::with_default(subscriber, || {
                    tracker.drain_telemetry().dispatch();
                });
            }));
            if let Err(payload) = delivery {
                assert!(
                    matches!(panic_site, PanicSite::Enabled),
                    "on_event panic must be fully contained by dispatch"
                );
                drop(payload);
            }

            let after_panic = tracker.telemetry_statistics();
            assert_eq!(after_panic.pending, 0);
            assert_eq!(after_panic.dispatch_panic_count, 1);

            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::new(1),
                EpochId::new(2),
                Time::from_nanos(20),
            );
            assert_eq!(tracker.transition_statistics().total_transitions, 2);
            assert_eq!(tracker.telemetry_statistics().dispatch_panic_count, 1);
            return;
        }

        init_test("epoch_telemetry_dispatch_contains_enabled_and_on_event_panics");
        for panic_site in ["enabled", "on_event"] {
            let status = std::process::Command::new(
                std::env::current_exe().expect("current epoch telemetry test executable"),
            )
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(PANIC_SITE_ENV, panic_site)
            .status()
            .expect("run isolated epoch telemetry panic test");
            assert!(
                status.success(),
                "isolated {panic_site} panic test failed with {status}"
            );
        }
        crate::test_complete!("epoch_telemetry_dispatch_contains_enabled_and_on_event_panics");
    }

    #[test]
    fn tracker_detects_module_desync() {
        init_test("tracker_detects_module_desync");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Advance scheduler to epoch 2
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(ModuleId::Scheduler, EpochId::new(1), EpochId::new(2), now);

        // Keep task table at epoch 1 (creating desync)
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Should detect desync violation
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_some(),
            "violation detected",
            true,
            violation.is_some()
        );

        if let Some(EpochConsistencyViolation::ModuleDesync { max_skew, .. }) = violation {
            crate::assert_with_log!(max_skew == 1, "skew is 1", 1, max_skew);
        } else {
            panic!("Expected ModuleDesync violation"); // ubs:ignore - test logic
        }

        crate::test_complete!("tracker_detects_module_desync");
    }

    #[test]
    fn tracker_records_distinct_desync_states_with_same_skew() {
        init_test("tracker_records_distinct_desync_states_with_same_skew");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(1100),
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(2),
            EpochId::new(3),
            Time::from_nanos(1200),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1300),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(1400),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1500),
        );

        let violations = tracker.all_violations();
        let desyncs: Vec<Vec<(ModuleId, EpochId)>> = violations
            .into_iter()
            .filter_map(|violation| match violation {
                EpochConsistencyViolation::ModuleDesync { modules, .. } => Some(modules),
                _ => None,
            })
            .collect();

        crate::assert_with_log!(
            desyncs.len() == 3,
            "strict mode records each distinct desync state, including intermediate skew changes",
            3,
            desyncs.len()
        );
        crate::assert_with_log!(
            desyncs[0]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(1)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ],
            "first desync captures scheduler/task skew",
            true,
            desyncs[0]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(1)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ]
        );
        crate::assert_with_log!(
            desyncs[1]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ],
            "second desync captures the intermediate scheduler/task skew state",
            true,
            desyncs[1]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ]
        );
        crate::assert_with_log!(
            desyncs[2]
                == vec![
                    (ModuleId::RegionTable, EpochId::new(1)),
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ],
            "third desync captures the expanded module set with renewed skew",
            true,
            desyncs[2]
                == vec![
                    (ModuleId::RegionTable, EpochId::new(1)),
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ]
        );

        crate::test_complete!("tracker_records_distinct_desync_states_with_same_skew");
    }

    #[test]
    fn tracker_allows_synchronized_modules() {
        init_test("tracker_allows_synchronized_modules");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Advance all modules synchronously
        for module in [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ] {
            tracker.notify_epoch_transition(module, EpochId::GENESIS, EpochId::new(1), now);
            tracker.notify_epoch_transition(module, EpochId::new(1), EpochId::new(2), now);
        }

        // Should not detect any violations
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_none(),
            "no violation",
            None::<EpochConsistencyViolation>,
            violation
        );

        crate::test_complete!("tracker_allows_synchronized_modules");
    }

    #[test]
    fn tracker_allows_same_timestamp_second_wave_without_false_desync() {
        init_test("tracker_allows_same_timestamp_second_wave_without_false_desync");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let first_wave = Time::from_nanos(1000);
        let second_wave = Time::from_nanos(2000);

        for module in [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ] {
            tracker.notify_epoch_transition(module, EpochId::GENESIS, EpochId::new(1), first_wave);
        }

        for module in [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ] {
            tracker.notify_epoch_transition(module, EpochId::new(1), EpochId::new(2), second_wave);
        }

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "no desync recorded for coherent second-wave rollout",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                )),
            "second-wave rollout does not leave behind latent desync evidence",
            true,
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                ))
        );

        crate::test_complete!("tracker_allows_same_timestamp_second_wave_without_false_desync");
    }

    #[test]
    fn tracker_check_consistency_surfaces_stuck_single_step_wave() {
        init_test("tracker_check_consistency_surfaces_stuck_single_step_wave");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let baseline = Time::from_nanos(1000);
        let stuck_wave = Time::from_nanos(2000);

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            baseline,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            baseline,
        );

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(2),
            stuck_wave,
        );

        crate::assert_with_log!(
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                )),
            "notify-time batch suppression leaves no stored desync evidence yet",
            true,
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                ))
        );

        let violation = tracker.check_consistency();
        let expected_modules = vec![
            (ModuleId::TaskTable, EpochId::new(1)),
            (ModuleId::Scheduler, EpochId::new(2)),
        ];
        let has_stuck_half_wave_desync = matches!(
            violation.as_ref(),
            Some(EpochConsistencyViolation::ModuleDesync {
                modules,
                max_skew,
                ..
            }) if *max_skew == 1 && modules == &expected_modules
        );
        crate::assert_with_log!(
            has_stuck_half_wave_desync,
            "explicit consistency check must surface a stuck half-wave desync",
            true,
            has_stuck_half_wave_desync
        );

        crate::test_complete!("tracker_check_consistency_surfaces_stuck_single_step_wave");
    }

    #[test]
    fn tracker_statistics() {
        init_test("tracker_statistics");

        let tracker = EpochConsistencyTracker::new();
        let now = Time::from_nanos(1000);

        // Perform some transitions
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 2,
            "total transitions",
            2,
            stats.total_transitions
        );
        crate::assert_with_log!(
            stats.latest_epoch == EpochId::new(1),
            "latest epoch",
            EpochId::new(1),
            stats.latest_epoch
        );
        crate::assert_with_log!(
            stats.per_module_stats.len() == 2,
            "module count",
            2,
            stats.per_module_stats.len()
        );

        crate::test_complete!("tracker_statistics");
    }

    #[test]
    fn tracker_ignores_duplicate_completion_notifications() {
        init_test("tracker_ignores_duplicate_completion_notifications");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(2000),
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 1,
            "duplicate transition does not increment totals",
            1,
            stats.total_transitions
        );
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.transition_count == 1),
            "duplicate transition does not increment module count",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.transition_count == 1)
        );
        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "duplicate completion is not reported as missing transition",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );

        crate::test_complete!("tracker_ignores_duplicate_completion_notifications");
    }

    #[test]
    fn tracker_does_not_mask_backward_transition_as_duplicate() {
        init_test("tracker_does_not_mask_backward_transition_as_duplicate");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(1500),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(2000),
        );

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "stale backward report does not poison current consistency",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            ),
            "backward transition still records historical violation evidence",
            true,
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            )
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2)),
            "stale backward report must not rewind tracked epoch",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2))
        );
        crate::assert_with_log!(
            stats.total_transitions == 2,
            "ignored stale report must not increment totals",
            2,
            stats.total_transitions
        );

        crate::test_complete!("tracker_does_not_mask_backward_transition_as_duplicate");
    }

    #[test]
    fn tracker_records_skipped_forward_transition_from_current_epoch() {
        init_test("tracker_records_skipped_forward_transition_from_current_epoch");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );

        let violation = tracker.latest_violation();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(1) && actual_epoch == EpochId::new(2)
            ),
            "initial skipped-forward report must surface missing-transition evidence",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(1) && actual_epoch == EpochId::new(2)
            )
        );
        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "historical skipped-forward evidence does not imply current inconsistency",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2)),
            "skipped-forward transition still advances tracked epoch",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2))
        );
        crate::assert_with_log!(
            stats.total_transitions == 1,
            "skipped-forward transition counts once",
            1,
            stats.total_transitions
        );

        crate::test_complete!("tracker_records_skipped_forward_transition_from_current_epoch");
    }

    #[test]
    fn tracker_does_not_mask_skipped_transition_as_duplicate() {
        init_test("tracker_does_not_mask_skipped_transition_as_duplicate");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(2000),
        );

        let violation = tracker.latest_violation();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(3) && actual_epoch == EpochId::new(2)
            ),
            "late skipped-transition report must remain visible as missing-transition evidence",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(3) && actual_epoch == EpochId::new(2)
            )
        );
        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "duplicate skipped-forward reports remain historical only once state stabilizes",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );

        crate::test_complete!("tracker_does_not_mask_skipped_transition_as_duplicate");
    }

    #[test]
    fn tracker_separates_current_health_from_historical_violation_log() {
        init_test("tracker_separates_current_health_from_historical_violation_log");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "current state is healthy once modules converge on the same epoch",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            ),
            "historical skipped-forward evidence remains queryable separately",
            true,
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            )
        );

        crate::test_complete!("tracker_separates_current_health_from_historical_violation_log");
    }

    #[test]
    fn disabled_tracker_does_nothing() {
        init_test("disabled_tracker_does_nothing");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::disabled());
        let now = Time::from_nanos(1000);

        // Create obvious desync
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(10),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Should not detect violations when disabled
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_none(),
            "no violation when disabled",
            None::<EpochConsistencyViolation>,
            violation
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 0,
            "no transitions tracked when disabled",
            0,
            stats.total_transitions
        );

        crate::test_complete!("disabled_tracker_does_nothing");
    }

    #[test]
    fn tracker_structured_logging_integration() {
        init_test("tracker_structured_logging_integration");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Test epoch transition logging
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Test violation logging - create a desync violation
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(3), // Skip epoch 2
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Check that violations are detected and logged
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_some(),
            "violation logged",
            true,
            violation.is_some()
        );

        // Test state logging
        tracker.log_epoch_state();
        tracker.drain_telemetry().dispatch();

        // Test replay command generation
        let replay_cmd = tracker
            .generate_replay_command("test_scenario", &[("module", "Scheduler"), ("epoch", "1")]);
        crate::assert_with_log!(
            replay_cmd.contains("epoch-tracker-replay"),
            "replay command generated",
            true,
            replay_cmd.contains("epoch-tracker-replay")
        );

        crate::test_complete!("tracker_structured_logging_integration");
    }

    #[test]
    fn tracker_performance_metrics() {
        init_test("tracker_performance_metrics");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Start a transition to test latency tracking
        tracker.notify_epoch_transition_start(ModuleId::Scheduler, EpochId::GENESIS, now);

        // Simulate some delay
        let later = Time::from_nanos(1_001_000); // 1ms later
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            later,
        );

        // Verify transition completed
        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions >= 1,
            "transition tracked",
            true,
            stats.total_transitions >= 1
        );

        crate::test_complete!("tracker_performance_metrics");
    }

    #[test]
    fn tracker_runtime_configuration() {
        init_test("tracker_runtime_configuration");

        let mut tracker = EpochConsistencyTracker::new();

        // Test enable/disable
        tracker.set_enabled(false);
        let now = Time::from_nanos(1000);

        // Should not track when disabled
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 0,
            "no tracking when disabled",
            0,
            stats.total_transitions
        );

        // Test threshold update
        tracker.set_slow_transition_threshold(5_000_000); // 5ms

        // Re-enable and verify it works
        tracker.set_enabled(true);
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions >= 1,
            "tracking enabled again",
            true,
            stats.total_transitions >= 1
        );

        crate::test_complete!("tracker_runtime_configuration");
    }

    #[test]
    fn tracker_check_consistency_surfaces_active_slow_transition() {
        init_test("tracker_check_consistency_surfaces_active_slow_transition");

        let now = Arc::new(AtomicU64::new(500));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 100,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(100),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(500),
        );

        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition {
                    module: ModuleId::Scheduler,
                    from_epoch,
                    to_epoch,
                    started_at,
                    duration_ns,
                    ..
                }) if from_epoch == EpochId::GENESIS
                    && to_epoch == EpochId::new(1)
                    && started_at == Time::from_nanos(100)
                    && duration_ns == 400
            ),
            "active slow transitions must be surfaced by current-health checks",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition { .. })
            )
        );

        crate::test_complete!("tracker_check_consistency_surfaces_active_slow_transition");
    }

    #[test]
    fn tracker_transition_start_preserves_earliest_witness_timestamp() {
        init_test("tracker_transition_start_preserves_earliest_witness_timestamp");

        let now = Arc::new(AtomicU64::new(1_000));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 500,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(100),
        );
        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(900),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1000),
        );

        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition {
                    module: ModuleId::Scheduler,
                    started_at,
                    duration_ns,
                    ..
                }) if started_at == Time::from_nanos(100) && duration_ns == 900
            ),
            "duplicate start witnesses must preserve the original transition start time",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition { .. })
            )
        );

        crate::test_complete!("tracker_transition_start_preserves_earliest_witness_timestamp");
    }

    #[test]
    fn tracker_transition_start_ignores_stale_epoch_snapshot() {
        init_test("tracker_transition_start_ignores_stale_epoch_snapshot");

        let now = Arc::new(AtomicU64::new(500));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 100,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(100),
        );
        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(200),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(500),
        );

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "stale transition-start witnesses must not manufacture an in-flight slow transition",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::Scheduler,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(1) && actual_epoch == EpochId::GENESIS
            ),
            "stale transition-start witness must remain visible as historical evidence",
            true,
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            )
        );

        crate::test_complete!("tracker_transition_start_ignores_stale_epoch_snapshot");
    }

    #[test]
    fn tracker_check_consistency_uses_live_time_for_idle_slow_transition() {
        init_test("tracker_check_consistency_uses_live_time_for_idle_slow_transition");

        let now = Arc::new(AtomicU64::new(100));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 25,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(100),
        );
        now.store(200, Ordering::Relaxed);

        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition {
                    module: ModuleId::Scheduler,
                    from_epoch,
                    to_epoch,
                    started_at,
                    duration_ns,
                    ..
                }) if from_epoch == EpochId::GENESIS
                    && to_epoch == EpochId::new(1)
                    && started_at == Time::from_nanos(100)
                    && duration_ns == 100
            ),
            "idle in-flight transitions must age against the live clock",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition { .. })
            )
        );

        crate::test_complete!("tracker_check_consistency_uses_live_time_for_idle_slow_transition");
    }

    #[test]
    fn tracker_violation_correlation_ids() {
        init_test("tracker_violation_correlation_ids");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let _now = Time::from_nanos(1000);

        // Create multiple violations to test correlation ID uniqueness
        for i in 0..3 {
            let epoch_time = Time::from_nanos(1000 + i * 1000);
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::new(i),
                EpochId::new(i + 2), // Skip epoch i+1
                epoch_time,
            );
        }

        let violations = tracker.all_violations();
        crate::assert_with_log!(
            violations.len() >= 2,
            "multiple violations detected",
            true,
            violations.len() >= 2
        );

        // Verify each violation has structured information
        for violation in &violations {
            match violation {
                EpochConsistencyViolation::MissingTransition { module, .. } => {
                    crate::assert_with_log!(
                        matches!(module, ModuleId::Scheduler),
                        "correct module in violation",
                        true,
                        matches!(module, ModuleId::Scheduler)
                    );
                }
                _ => {} // Other violation types are also valid
            }
        }

        crate::test_complete!("tracker_violation_correlation_ids");
    }
}
