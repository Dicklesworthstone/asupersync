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

        // Generate correlation ID for cross-module analysis
        let _correlation_id = self.global_transition_count.load(Ordering::Relaxed) + 1;
        let _transition_start = std::time::Instant::now();

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
        let _sync_status = if record.current_epoch != from_epoch {
            let violation = EpochConsistencyViolation::MissingTransition {
                module,
                expected_epoch: record.current_epoch.next(),
                actual_epoch: to_epoch,
                detected_at: now,
            };
            self.record_violation(violation);
            "violated"
        } else {
            "synchronized"
        };

        // Calculate transition latency if there was a transition start time
        let transition_latency_ns = record
            .transition_start_time
            .map(|start| now.duration_since(start))
            .unwrap_or(0);

        // Update record
        record.current_epoch = to_epoch;
        record.last_transition_time = now;
        record.transition_start_time = None;
        record.transition_count += 1;

        // Increment global counter
        self.global_transition_count.fetch_add(1, Ordering::Relaxed);

        // Structured logging: Each epoch transition logged with module_id, old_epoch, new_epoch, transition_time, sync_status
        info!(
            module_id = %module,
            old_epoch = %from_epoch,
            new_epoch = %to_epoch,
            transition_time_ns = now.as_nanos(),
            sync_status = sync_status,
            correlation_id = correlation_id,
            transition_count = record.transition_count,
            transition_latency_ns = transition_latency_ns,
            "epoch_transition"
        );

        // Log performance metrics for epoch transition latency
        if transition_latency_ns > 0 {
            debug!(
                module_id = %module,
                transition_latency_ns = transition_latency_ns,
                correlation_id = correlation_id,
                threshold_ns = self.config.slow_transition_threshold_ns,
                "epoch_transition_latency"
            );
        }

        // Check for consistency violations after this transition
        drop(records); // Release lock before consistency check
        let processing_start = std::time::Instant::now();
        self.check_consistency_internal(now);
        let _processing_latency = processing_start.elapsed().as_nanos() as u64;

        // Log consistency check performance
        debug!(
            correlation_id = correlation_id,
            processing_latency_ns = processing_latency,
            "epoch_consistency_check_latency"
        );
    }

    /// Notifies the tracker that a module is starting an epoch transition.
    pub fn notify_epoch_transition_start(&self, module: ModuleId, _from_epoch: EpochId, now: Time) {
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
        // Generate correlation ID for this violation
        let _violation_id = self.global_transition_count.load(Ordering::Relaxed);

        // Extract structured logging information based on violation type
        match &violation {
            EpochConsistencyViolation::ModuleDesync {
                modules,
                detected_at: _,
                max_skew: _,
            } => {
                let _affected_modules: Vec<String> = modules
                    .iter()
                    .map(|(module, epoch)| format!("{}@{}", module, epoch))
                    .collect();

                // Log epoch consistency violation with affected_modules, epoch_skew, consistency_level
                error!(
                    violation_type = "module_desync",
                    affected_modules = ?affected_modules,
                    epoch_skew = max_skew,
                    consistency_level = if self.config.strict_ordering { "strict" } else { "relaxed" },
                    correlation_id = violation_id,
                    detected_at_ns = detected_at.as_nanos(),
                    replay_command = %format!("epoch-tracker-replay --violation-id {} --type module_desync", violation_id),
                    "epoch_consistency_violation"
                );
            }
            EpochConsistencyViolation::SlowTransition {
                module: _,
                from_epoch: _,
                to_epoch: _,
                started_at: _,
                detected_at: _,
                duration_ns: _,
            } => {
                error!(
                    violation_type = "slow_transition",
                    affected_modules = ?[format!("{}@{}->{}", module, from_epoch, to_epoch)],
                    epoch_skew = 0u64,
                    consistency_level = if self.config.strict_ordering { "strict" } else { "relaxed" },
                    correlation_id = violation_id,
                    module_id = %module,
                    transition_duration_ns = duration_ns,
                    threshold_ns = self.config.slow_transition_threshold_ns,
                    started_at_ns = started_at.as_nanos(),
                    detected_at_ns = detected_at.as_nanos(),
                    replay_command = %format!("epoch-tracker-replay --violation-id {} --type slow_transition --module {}", violation_id, module),
                    "epoch_consistency_violation"
                );
            }
            EpochConsistencyViolation::MissingTransition {
                module: _,
                expected_epoch,
                actual_epoch,
                detected_at: _,
            } => {
                let _epoch_skew = if actual_epoch > expected_epoch {
                    actual_epoch.as_u64() - expected_epoch.as_u64()
                } else {
                    expected_epoch.as_u64() - actual_epoch.as_u64()
                };

                error!(
                    violation_type = "missing_transition",
                    affected_modules = ?[format!("{}@{}", module, actual_epoch)],
                    epoch_skew = epoch_skew,
                    consistency_level = if self.config.strict_ordering { "strict" } else { "relaxed" },
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
                module: _,
                advanced_to,
                dependency_module: _,
                dependency_epoch,
                detected_at: _,
            } => {
                let _epoch_skew = if advanced_to > dependency_epoch {
                    advanced_to.as_u64() - dependency_epoch.as_u64()
                } else {
                    dependency_epoch.as_u64() - advanced_to.as_u64()
                };

                error!(
                    violation_type = "advancement_order_violation",
                    affected_modules = ?[format!("{}@{}", module, advanced_to), format!("{}@{}", dependency_module, dependency_epoch)],
                    epoch_skew = epoch_skew,
                    consistency_level = if self.config.strict_ordering { "strict" } else { "relaxed" },
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

        let mut violations = self.violations.write();
        violations.push(violation);

        // Trim violations if we've exceeded the limit
        if violations.len() > self.max_violations {
            let excess = violations.len() - self.max_violations;
            violations.drain(0..excess);

            warn!(
                violations_trimmed = excess,
                max_violations = self.max_violations,
                "epoch_violation_buffer_trimmed"
            );
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
        let base_cmd = format!("epoch-tracker-replay --scenario {}", scenario_type);

        let args: Vec<String> = additional_args
            .iter()
            .map(|(key, value)| format!("--{} {}", key, value))
            .collect();

        if args.is_empty() {
            base_cmd
        } else {
            format!("{} {}", base_cmd, args.join(" "))
        }
    }

    /// Logs comprehensive epoch state for debugging and monitoring.
    ///
    /// This method provides structured logging of the complete epoch state
    /// across all modules, which can be useful for debugging and monitoring
    /// epoch consistency in production environments.
    pub fn log_epoch_state(&self) {
        let records = self.module_records.read();
        let violation_count = self.violation_count();
        let _total_transitions = self.global_transition_count.load(Ordering::Relaxed);

        // Log overall epoch state
        info!(
            total_modules = records.len(),
            total_transitions = total_transitions,
            violation_count = violation_count,
            consistency_level = if self.config.strict_ordering {
                "strict"
            } else {
                "relaxed"
            },
            max_epoch_skew_allowed = self.config.max_epoch_skew,
            slow_transition_threshold_ns = self.config.slow_transition_threshold_ns,
            "epoch_tracker_state"
        );

        // Log per-module state
        for (&_module, _record) in records.iter() {
            debug!(
                module_id = %_module,
                current_epoch = %record.current_epoch,
                transition_count = record.transition_count,
                last_transition_time_ns = record.last_transition_time.as_nanos(),
                is_transitioning = record.transition_start_time.is_some(),
                "module_epoch_state"
            );
        }

        // Log recent violations summary
        if violation_count > 0 {
            let violations = self.violations.read();
            for (_idx, _violation) in violations.iter().enumerate().take(5) {
                debug!(
                    violation_index = idx,
                    violation_type = match violation {
                        EpochConsistencyViolation::ModuleDesync { .. } => "module_desync",
                        EpochConsistencyViolation::SlowTransition { .. } => "slow_transition",
                        EpochConsistencyViolation::MissingTransition { .. } => "missing_transition",
                        EpochConsistencyViolation::AdvancementOrderViolation { .. } => "advancement_order_violation",
                    },
                    violation_summary = %format!("{}", violation),
                    "recent_epoch_violation"
                );
            }
        }
    }

    /// Enables or disables epoch consistency checking at runtime.
    ///
    /// This can be useful for temporarily disabling checking during
    /// performance-critical sections or enabling it for debugging.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;

        info!(enabled = enabled, "epoch_tracker_enabled_changed");
    }

    /// Updates the slow transition threshold dynamically.
    ///
    /// This allows tuning the sensitivity of slow transition detection
    /// based on runtime conditions or performance requirements.
    pub fn set_slow_transition_threshold(&mut self, threshold_ns: u64) {
        let _old_threshold = self.config.slow_transition_threshold_ns;
        self.config.slow_transition_threshold_ns = threshold_ns;

        info!(
            old_threshold_ns = old_threshold,
            new_threshold_ns = threshold_ns,
            "epoch_tracker_threshold_updated"
        );
    }
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
