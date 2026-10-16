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
use parking_lot::{Mutex, MutexGuard, RwLock};
use std::collections::VecDeque;
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
    // Enqueue order and delivery-watermark capture share this linearization
    // point. The tracker separately prevents watermark capture while a
    // telemetry-producing operation is still in flight.
    state: Mutex<EpochTelemetryOutboxState>,
    overflow_count: AtomicU64,
    dispatch_panic_count: AtomicU64,
    emitted_count: AtomicU64,
}

struct EpochTelemetryOutboxState {
    receipts: VecDeque<SequencedEpochTelemetryReceipt>,
    capacity: usize,
    next_sequence: u128,
}

struct SequencedEpochTelemetryReceipt {
    sequence: u128,
    receipt: EpochTelemetryReceipt,
}

/// One dispatch's receipts. A spawn or completion yields one or two, which
/// fit inline, so a dispatch allocates nothing.
type ReceiptBatch = smallvec::SmallVec<[EpochTelemetryReceipt; 4]>;

impl EpochTelemetryOutbox {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            state: Mutex::new(EpochTelemetryOutboxState {
                receipts: VecDeque::with_capacity(capacity),
                capacity,
                next_sequence: 0,
            }),
            overflow_count: AtomicU64::new(0),
            dispatch_panic_count: AtomicU64::new(0),
            emitted_count: AtomicU64::new(0),
        }
    }

    fn push(&self, receipt: EpochTelemetryReceipt) {
        let mut state = self.state.lock();
        if state.receipts.len() == state.capacity || state.next_sequence == u128::MAX {
            drop(state);
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state
            .receipts
            .push_back(SequencedEpochTelemetryReceipt { sequence, receipt });
    }

    fn pop_batch_through(&self, watermark: Option<u128>, limit: usize) -> ReceiptBatch {
        let Some(watermark) = watermark else {
            return ReceiptBatch::new();
        };
        let mut state = self.state.lock();
        let eligible = state
            .receipts
            .iter()
            .take(limit)
            .take_while(|receipt| receipt.sequence <= watermark)
            .count();
        state
            .receipts
            .drain(..eligible)
            .map(|receipt| receipt.receipt)
            .collect()
    }

    #[cfg(test)]
    fn pop_batch(&self, limit: usize) -> ReceiptBatch {
        let watermark = self.watermark();
        self.pop_batch_through(watermark, limit)
    }

    fn watermark(&self) -> Option<u128> {
        self.state
            .lock()
            .receipts
            .back()
            .map(|receipt| receipt.sequence)
    }

    fn has_pending_through(&self, watermark: Option<u128>) -> bool {
        let Some(watermark) = watermark else {
            return false;
        };
        self.state
            .lock()
            .receipts
            .front()
            .is_some_and(|receipt| receipt.sequence <= watermark)
    }

    fn delivery(
        self: &Arc<Self>,
        _publication: &MutexGuard<'_, ()>,
        limit: usize,
    ) -> EpochTelemetryDispatch {
        EpochTelemetryDispatch {
            outbox: Arc::clone(self),
            watermark: self.watermark(),
            limit,
        }
    }

    fn statistics(&self) -> EpochTelemetryStatistics {
        let state = self.state.lock();
        EpochTelemetryStatistics {
            pending: state.receipts.len(),
            capacity: state.capacity,
            overflow_count: self.overflow_count.load(Ordering::Relaxed),
            dispatch_panic_count: self.dispatch_panic_count.load(Ordering::Relaxed),
            emitted_count: self.emitted_count.load(Ordering::Relaxed),
        }
    }

    fn clear(&self) {
        let mut state = self.state.lock();
        state.receipts.clear();
        // Keep the sequence frontier monotonic so tokens created before a
        // reset can never retarget receipts published after the reset.
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
/// Each token is bounded by the newest receipt visible when it was created, so
/// a delayed token cannot emit telemetry for a later, unpublished mutation.
/// Callers must dispatch this only after publishing the corresponding runtime
/// mutation and releasing runtime/tracker locks. A subscriber panic aborts the
/// remainder of the drained batch, is counted without tracing, and is never
/// retried.
#[must_use = "epoch telemetry must be dispatched after publication and outside locks"]
pub struct EpochTelemetryDispatch {
    outbox: Arc<EpochTelemetryOutbox>,
    watermark: Option<u128>,
    limit: usize,
}

impl EpochTelemetryDispatch {
    /// Returns whether the outbox has no pending receipts visible to this token.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.outbox.has_pending_through(self.watermark)
    }

    /// Emits this batch once while containing subscriber `enabled`/`on_event`
    /// panics across the entire batch.
    pub fn dispatch(self) {
        let Self {
            outbox,
            watermark,
            limit,
        } = self;
        let receipts = outbox.pop_batch_through(watermark, limit);
        Self::dispatch_receipts(&outbox, receipts);
    }

    fn dispatch_receipts(outbox: &EpochTelemetryOutbox, receipts: ReceiptBatch) {
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

    /// Checks each module's own transition sequence only.
    ///
    /// For a tracker fed by independent per-module counters, like the runtime
    /// state's region, task and obligation tables: each bumps its own epoch
    /// once per mutation of that table, so their values are not comparable,
    /// and cross-module skew or ordering checks would flag normal operation on
    /// every transition. Skipped and non-advancing epochs within a module are
    /// still recorded.
    #[inline]
    #[must_use]
    pub fn independent_modules() -> Self {
        Self {
            max_epoch_skew: u64::MAX,
            slow_transition_threshold_ns: 1_000_000, // 1ms
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
    /// Serializes telemetry-producing tracker operations with delivery
    /// watermark capture. This prevents one caller from capturing receipts
    /// enqueued by another caller whose tracker mutation has not returned yet.
    telemetry_publication: Mutex<()>,
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

    /// The tracker a runtime state keeps for its independent per-table epoch
    /// counters (see [`EpochConsistencyConfig::independent_modules`]).
    ///
    /// The runtime advances each table counter itself, under its own lock,
    /// from the value it last published, so in production the tracker can
    /// only re-confirm that arithmetic; its receipts reach observers only
    /// through `tracing` events. It is therefore enabled where it can find or
    /// report something: this crate's tests, debug builds, and builds with
    /// `tracing-integration`. Release builds without tracing skip a mutex, an
    /// `RwLock` write, a map update, telemetry receipts and two clock reads on
    /// every task spawn and completion
    /// (br-asupersync-issue65-criticisms-kpmoy5.1.7).
    #[must_use]
    pub(crate) fn for_runtime_tables() -> Self {
        let mut config = EpochConsistencyConfig::independent_modules();
        config.enabled = cfg!(any(test, debug_assertions, feature = "tracing-integration"));
        Self::with_config(config)
    }

    /// Whether transitions are recorded at all.
    #[inline]
    #[must_use]
    pub(crate) fn is_enabled(&self) -> bool {
        self.config.enabled
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
            telemetry_publication: Mutex::new(()),
            telemetry: Arc::new(EpochTelemetryOutbox::new(telemetry_capacity)),
        }
    }

    fn enqueue_telemetry(&self, _publication: &MutexGuard<'_, ()>, receipt: EpochTelemetryReceipt) {
        self.telemetry.push(receipt);
    }

    /// Creates a bounded delivery token for use after the corresponding runtime
    /// mutation is published and all runtime/tracker locks are released.
    /// Receipts are removed from the outbox only when the token is dispatched.
    #[must_use]
    pub fn drain_telemetry(&self) -> EpochTelemetryDispatch {
        let publication = self.telemetry_publication.lock();
        self.telemetry
            .delivery(&publication, DEFAULT_TELEMETRY_DRAIN_LIMIT)
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
        let publication = self.telemetry_publication.lock();

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
            self.enqueue_telemetry(
                &publication,
                EpochTelemetryReceipt::TransitionDuplicate {
                    module,
                    current_epoch: record.current_epoch,
                    reported_from_epoch: from_epoch,
                    reported_to_epoch: to_epoch,
                    transition_time_ns: now.as_nanos(),
                },
            );
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
                self.record_violation(&publication, violation);
                ("skipped_forward", true)
            } else {
                let violation = EpochConsistencyViolation::MissingTransition {
                    module,
                    expected_epoch,
                    actual_epoch: to_epoch,
                    detected_at: now,
                };
                self.record_violation(&publication, violation);
                ("non_advancing", false)
            }
        } else {
            let violation = EpochConsistencyViolation::MissingTransition {
                module,
                expected_epoch,
                actual_epoch: to_epoch,
                detected_at: now,
            };
            self.record_violation(&publication, violation);
            ("violated", to_epoch.is_after(record.current_epoch))
        };
        if !should_update {
            self.enqueue_telemetry(
                &publication,
                EpochTelemetryReceipt::TransitionIgnored {
                    module,
                    current_epoch: record.current_epoch,
                    reported_from_epoch: from_epoch,
                    reported_to_epoch: to_epoch,
                    transition_time_ns: now.as_nanos(),
                    sync_status,
                },
            );
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

        self.enqueue_telemetry(
            &publication,
            EpochTelemetryReceipt::Transition {
                module,
                old_epoch: from_epoch,
                new_epoch: to_epoch,
                transition_time_ns: now.as_nanos(),
                sync_status,
                correlation_id,
                transition_count: record.transition_count,
                transition_latency_ns,
            },
        );

        // Log performance metrics for epoch transition latency
        if transition_latency_ns > 0 {
            self.enqueue_telemetry(
                &publication,
                EpochTelemetryReceipt::TransitionLatency {
                    module,
                    transition_latency_ns,
                    correlation_id,
                    threshold_ns: self.config.slow_transition_threshold_ns,
                },
            );
        }

        // Check for consistency violations after this transition
        drop(records); // Release lock before consistency check
        #[cfg(not(target_arch = "wasm32"))]
        let processing_start = std::time::Instant::now();
        #[cfg(target_arch = "wasm32")]
        let processing_start = crate::time::wasm_monotonic_nanos();

        self.check_consistency_internal(&publication, now);

        #[cfg(not(target_arch = "wasm32"))]
        let processing_latency = processing_start.elapsed().as_nanos() as u64;
        #[cfg(target_arch = "wasm32")]
        let processing_latency =
            crate::time::wasm_monotonic_nanos().saturating_sub(processing_start);

        self.enqueue_telemetry(
            &publication,
            EpochTelemetryReceipt::ConsistencyCheckLatency {
                correlation_id,
                processing_latency_ns: processing_latency,
            },
        );
    }

    /// Notifies the tracker that a module is starting an epoch transition.
    pub fn notify_epoch_transition_start(&self, module: ModuleId, from_epoch: EpochId, now: Time) {
        if !self.config.enabled {
            return;
        }
        let publication = self.telemetry_publication.lock();

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
            self.record_violation(&publication, violation);

            self.enqueue_telemetry(
                &publication,
                EpochTelemetryReceipt::TransitionStartIgnored {
                    module,
                    current_epoch,
                    reported_from_epoch: from_epoch,
                    transition_time_ns: now.as_nanos(),
                },
            );
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
    fn check_consistency_internal(&self, publication: &MutexGuard<'_, ()>, now: Time) {
        let records = self.module_records.read();

        // Check for module desync
        self.check_module_desync(publication, &records, now);

        // Check for slow transitions
        self.check_slow_transitions(publication, &records, now);

        // Check for advancement order violations if strict ordering is enabled
        if self.config.strict_ordering {
            self.check_advancement_order(publication, &records, now);
        }
    }

    /// Checks for module epoch desynchronization.
    fn check_module_desync(
        &self,
        publication: &MutexGuard<'_, ()>,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        if let Some(violation) = self.current_module_desync_violation(records, now, true) {
            self.record_violation(publication, violation);
        }
    }

    fn current_module_desync_violation(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
        suppress_single_step_batch: bool,
    ) -> Option<EpochConsistencyViolation> {
        let mut epochs = records.values().map(|record| record.current_epoch);
        let first_epoch = epochs.next()?;
        let (min_epoch, max_epoch) = epochs
            .fold((first_epoch, first_epoch), |(min, max), epoch| {
                (min.min(epoch), max.max(epoch))
            });
        if min_epoch == max_epoch {
            return None;
        }
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

        let mut modules_with_epochs: Vec<_> = records
            .iter()
            .map(|(&module, record)| (module, record.current_epoch))
            .collect();
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
        publication: &MutexGuard<'_, ()>,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        if let Some(violation) = self.current_slow_transition_violation(records, now) {
            self.record_violation(publication, violation);
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
        publication: &MutexGuard<'_, ()>,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        if let Some(violation) = self.current_advancement_order_violation(records, now) {
            self.record_violation(publication, violation);
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
    fn record_violation(
        &self,
        publication: &MutexGuard<'_, ()>,
        violation: EpochConsistencyViolation,
    ) {
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
        self.enqueue_telemetry(
            publication,
            EpochTelemetryReceipt::Violation {
                violation,
                violation_id,
                strict_ordering: self.config.strict_ordering,
                slow_transition_threshold_ns: self.config.slow_transition_threshold_ns,
            },
        );

        // Trim violations if we've exceeded the limit
        if violations.len() > self.max_violations {
            let excess = violations.len() - self.max_violations;
            violations.drain(0..excess);
            self.enqueue_telemetry(
                publication,
                EpochTelemetryReceipt::ViolationBufferTrimmed {
                    violations_trimmed: excess,
                    max_violations: self.max_violations,
                },
            );
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
        let _publication = self.telemetry_publication.lock();
        self.module_records.write().clear();
        self.violations.write().clear();
        self.global_transition_count.store(0, Ordering::Relaxed);
        self.telemetry.clear();
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
        let publication = self.telemetry_publication.lock();
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

        self.enqueue_telemetry(
            &publication,
            EpochTelemetryReceipt::TrackerState {
                total_modules,
                total_transitions,
                violation_count,
                strict_ordering: self.config.strict_ordering,
                max_epoch_skew_allowed: self.config.max_epoch_skew,
                slow_transition_threshold_ns: self.config.slow_transition_threshold_ns,
            },
        );
        for module_state in module_states {
            self.enqueue_telemetry(&publication, module_state);
        }
        for recent_violation in recent_violations {
            self.enqueue_telemetry(&publication, recent_violation);
        }
    }

    /// Enables or disables epoch consistency checking at runtime.
    ///
    /// This can be useful for temporarily disabling checking during
    /// performance-critical sections or enabling it for debugging. The change
    /// queues telemetry for later delivery through
    /// [`drain_telemetry`](Self::drain_telemetry).
    pub fn set_enabled(&mut self, enabled: bool) {
        let publication = self.telemetry_publication.lock();
        self.config.enabled = enabled;
        self.enqueue_telemetry(
            &publication,
            EpochTelemetryReceipt::EnabledChanged { enabled },
        );
    }

    /// Updates the slow transition threshold dynamically.
    ///
    /// This allows tuning the sensitivity of slow transition detection
    /// based on runtime conditions or performance requirements. The change
    /// queues telemetry for later delivery through
    /// [`drain_telemetry`](Self::drain_telemetry).
    #[allow(unused_variables)]
    pub fn set_slow_transition_threshold(&mut self, threshold_ns: u64) {
        let publication = self.telemetry_publication.lock();
        let old_threshold = self.config.slow_transition_threshold_ns;
        self.config.slow_transition_threshold_ns = threshold_ns;
        self.enqueue_telemetry(
            &publication,
            EpochTelemetryReceipt::ThresholdUpdated {
                old_threshold_ns: old_threshold,
                new_threshold_ns: threshold_ns,
            },
        );
    }
}

#[cfg(test)]
#[path = "epoch_tracker_inline_tests.rs"]
mod tests;
