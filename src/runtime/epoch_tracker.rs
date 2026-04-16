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
use crate::types::Time;
use crate::util::det_hash::DetHashMap;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

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
                    write!(f, "{}@{}", module, epoch)?;
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
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_epoch_skew: 1,
            slow_transition_threshold_ns: 100_000, // 100μs
            strict_ordering: true,
            enabled: true,
        }
    }

    /// Creates a disabled configuration (no checking).
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
    /// Per-module epoch transition records.
    module_records: RwLock<DetHashMap<ModuleId, EpochTransitionRecord>>,
    /// Global epoch transition counter.
    global_transition_count: AtomicU64,
    /// Detected violations (bounded to prevent memory growth).
    violations: RwLock<Vec<EpochConsistencyViolation>>,
    /// Maximum number of violations to retain.
    max_violations: usize,
}

impl EpochConsistencyTracker {
    /// Creates a new epoch consistency tracker with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EpochConsistencyConfig::default())
    }

    /// Creates a new epoch consistency tracker with the given configuration.
    #[must_use]
    pub fn with_config(config: EpochConsistencyConfig) -> Self {
        Self {
            config,
            module_records: RwLock::new(DetHashMap::default()),
            global_transition_count: AtomicU64::new(0),
            violations: RwLock::new(Vec::new()),
            max_violations: 1000, // Bounded to prevent memory growth
        }
    }

    /// Notifies the tracker of an epoch transition for a module.
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

        let mut records = self.module_records.write();
        let record = records
            .entry(module)
            .or_insert_with(|| EpochTransitionRecord {
                current_epoch: EpochId::GENESIS,
                last_transition_time: now,
                transition_start_time: None,
                transition_count: 0,
            });

        // Check for expected transition sequence
        if record.current_epoch != from_epoch {
            let violation = EpochConsistencyViolation::MissingTransition {
                module,
                expected_epoch: record.current_epoch.next(),
                actual_epoch: to_epoch,
                detected_at: now,
            };
            self.record_violation(violation);
        }

        // Update record
        record.current_epoch = to_epoch;
        record.last_transition_time = now;
        record.transition_start_time = None;
        record.transition_count += 1;

        // Increment global counter
        self.global_transition_count.fetch_add(1, Ordering::Relaxed);

        // Check for consistency violations after this transition
        drop(records); // Release lock before consistency check
        self.check_consistency_internal(now);
    }

    /// Notifies the tracker that a module is starting an epoch transition.
    pub fn notify_epoch_transition_start(&self, module: ModuleId, from_epoch: EpochId, now: Time) {
        if !self.config.enabled {
            return;
        }

        let mut records = self.module_records.write();
        if let Some(record) = records.get_mut(&module) {
            record.transition_start_time = Some(now);
        }
    }

    /// Checks for epoch consistency violations.
    ///
    /// Returns the first violation found, if any.
    pub fn check_consistency(&self) -> Option<EpochConsistencyViolation> {
        if !self.config.enabled {
            return None;
        }

        self.check_consistency_internal(Time::from_nanos(0)); // Use epoch 0 for external checks
        let violations = self.violations.read();
        violations.last().cloned()
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
        let mut epochs: BTreeMap<EpochId, Vec<ModuleId>> = BTreeMap::new();

        for (&module, record) in records.iter() {
            epochs.entry(record.current_epoch).or_default().push(module);
        }

        if epochs.len() <= 1 {
            return; // All modules on same epoch or no modules
        }

        let epoch_ids: Vec<EpochId> = epochs.keys().copied().collect();
        let min_epoch = epoch_ids.first().copied().unwrap_or(EpochId::GENESIS);
        let max_epoch = epoch_ids.last().copied().unwrap_or(EpochId::GENESIS);
        let skew = max_epoch.distance(min_epoch);

        if skew > self.config.max_epoch_skew {
            let mut modules_with_epochs = Vec::new();
            for (&epoch, modules) in &epochs {
                for &module in modules {
                    modules_with_epochs.push((module, epoch));
                }
            }

            let violation = EpochConsistencyViolation::ModuleDesync {
                modules: modules_with_epochs,
                detected_at: now,
                max_skew: skew,
            };
            self.record_violation(violation);
        }
    }

    /// Checks for slow epoch transitions.
    fn check_slow_transitions(
        &self,
        records: &DetHashMap<ModuleId, EpochTransitionRecord>,
        now: Time,
    ) {
        for (&module, record) in records.iter() {
            if let Some(transition_start) = record.transition_start_time {
                let duration_ns = now.duration_since(transition_start);
                if duration_ns > self.config.slow_transition_threshold_ns {
                    let violation = EpochConsistencyViolation::SlowTransition {
                        module,
                        from_epoch: record.current_epoch.prev().unwrap_or(EpochId::GENESIS),
                        to_epoch: record.current_epoch,
                        started_at: transition_start,
                        detected_at: now,
                        duration_ns,
                    };
                    self.record_violation(violation);
                }
            }
        }
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
                    let violation = EpochConsistencyViolation::AdvancementOrderViolation {
                        module: dependent,
                        advanced_to: dependent_record.current_epoch,
                        dependency_module: dependency,
                        dependency_epoch: dependency_record.current_epoch,
                        detected_at: now,
                    };
                    self.record_violation(violation);
                }
            }
        }
    }

    /// Records a violation, maintaining bounded storage.
    fn record_violation(&self, violation: EpochConsistencyViolation) {
        let mut violations = self.violations.write();
        violations.push(violation);

        // Trim violations if we've exceeded the limit
        if violations.len() > self.max_violations {
            let excess = violations.len() - self.max_violations;
            violations.drain(0..excess);
        }
    }

    /// Returns all detected violations.
    #[must_use]
    pub fn all_violations(&self) -> Vec<EpochConsistencyViolation> {
        self.violations.read().clone()
    }

    /// Returns the number of violations detected.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
            panic!("Expected ModuleDesync violation");
        }

        crate::test_complete!("tracker_detects_module_desync");
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
}
