//! Runtime Epoch Consistency Tracker
//!
//! This oracle monitors runtime epoch boundaries to ensure state transitions happen
//! atomically without tearing or inconsistency across modules. It detects when different
//! parts of the runtime get out of sync.
//!
//! # Epoch Consistency Model
//!
//! Asupersync's runtime operates in epochs to maintain consistency across:
//! - Scheduler (three-lane scheduler state)
//! - Region table (region lifecycle)
//! - Task table (task management)
//! - Obligation table (permits/acks/leases)
//! - Timer wheel (timer advancement)
//! - I/O reactor (reactor state)
//! - Cancel protocol (cancellation state)
//!
//! # Key Detection Capabilities
//!
//! - **Module sync violations**: Modules operating on different epochs
//! - **Slow transitions**: Epoch transitions taking too long
//! - **Missing notifications**: Modules not receiving epoch updates
//! - **Stale state**: Updates using outdated epoch information
//! - **Order violations**: Modules advancing epochs out of sequence

use crate::epoch::EpochId;
use crate::runtime::epoch_tracker::ModuleId;
use crate::types::Time;
use parking_lot::RwLock;
use std::backtrace::Backtrace;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Runtime modules that participate in epoch synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeModule {
    Scheduler,
    RegionTable,
    TaskTable,
    ObligationTable,
    TimerWheel,
    IoReactor,
    CancelProtocol,
}

impl RuntimeModule {
    /// Returns the module name as a string.
    pub fn name(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::RegionTable => "region_table",
            Self::TaskTable => "task_table",
            Self::ObligationTable => "obligation_table",
            Self::TimerWheel => "timer_wheel",
            Self::IoReactor => "io_reactor",
            Self::CancelProtocol => "cancel_protocol",
        }
    }

    /// Returns all runtime modules.
    pub fn all_modules() -> &'static [RuntimeModule] {
        &[
            Self::Scheduler,
            Self::RegionTable,
            Self::TaskTable,
            Self::ObligationTable,
            Self::TimerWheel,
            Self::IoReactor,
            Self::CancelProtocol,
        ]
    }
}

/// Configuration for the runtime epoch consistency tracker.
#[derive(Debug, Clone)]
pub struct RuntimeEpochConfig {
    /// Maximum allowed epoch skew between modules before flagging a violation.
    pub max_epoch_skew: u64,

    /// Maximum time allowed for epoch transitions across modules.
    pub max_transition_duration_ns: u64,

    /// Time window for considering epoch transitions as "simultaneous".
    pub sync_window_ns: u64,

    /// Maximum number of violations to track before dropping old ones.
    pub max_violations: usize,

    /// Whether to panic immediately on violations (vs just recording them).
    pub panic_on_violation: bool,

    /// Whether to capture stack traces for violations (expensive).
    pub capture_stack_traces: bool,

    /// Maximum depth of stack traces to capture.
    pub max_stack_trace_depth: usize,

    /// Consistency checking level.
    pub consistency_level: ConsistencyLevel,
}

/// Level of epoch consistency checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyLevel {
    /// Relaxed checking - allow minor skews for performance
    Relaxed,
    /// Strict checking - enforce tight epoch synchronization
    Strict,
    /// Development checking - maximum validation for debugging
    Development,
}

impl Default for RuntimeEpochConfig {
    fn default() -> Self {
        Self {
            max_epoch_skew: 2, // Allow 2 epochs of skew
            max_transition_duration_ns: 1_000_000_000, // 1 second max transition
            sync_window_ns: 10_000_000, // 10ms sync window
            max_violations: 1000,
            panic_on_violation: false,
            capture_stack_traces: true,
            max_stack_trace_depth: 32,
            consistency_level: ConsistencyLevel::Strict,
        }
    }
}

/// A runtime epoch consistency violation detected by the oracle.
#[derive(Debug, Clone)]
pub enum RuntimeEpochViolation {
    /// Modules are operating on different epochs beyond allowed skew.
    EpochSkew {
        module_a: RuntimeModule,
        epoch_a: EpochId,
        module_b: RuntimeModule,
        epoch_b: EpochId,
        skew_amount: u64,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Epoch transition took longer than expected.
    SlowTransition {
        module: RuntimeModule,
        from_epoch: EpochId,
        to_epoch: EpochId,
        transition_duration_ns: u64,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Module missed an epoch transition notification.
    MissedTransition {
        module: RuntimeModule,
        expected_epoch: EpochId,
        actual_epoch: EpochId,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Module used stale epoch information for state updates.
    StaleEpochUpdate {
        module: RuntimeModule,
        update_epoch: EpochId,
        current_epoch: EpochId,
        staleness_amount: u64,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Modules advanced epochs in incorrect order.
    OrderViolation {
        first_module: RuntimeModule,
        first_epoch: EpochId,
        second_module: RuntimeModule,
        second_epoch: EpochId,
        expected_order: String,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// General epoch consistency failure across multiple modules.
    ConsistencyFailure {
        affected_modules: Vec<(RuntimeModule, EpochId)>,
        consistency_level: ConsistencyLevel,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },
}

impl fmt::Display for RuntimeEpochViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochSkew {
                module_a,
                epoch_a,
                module_b,
                epoch_b,
                skew_amount,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Epoch skew: {} at epoch {} and {} at epoch {} (skew: {}) at {}",
                    module_a.name(),
                    epoch_a.as_u64(),
                    module_b.name(),
                    epoch_b.as_u64(),
                    skew_amount,
                    detected_at.as_nanos()
                )
            }
            Self::SlowTransition {
                module,
                from_epoch,
                to_epoch,
                transition_duration_ns,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Slow transition: {} from epoch {} to {} took {}ns at {}",
                    module.name(),
                    from_epoch.as_u64(),
                    to_epoch.as_u64(),
                    transition_duration_ns,
                    detected_at.as_nanos()
                )
            }
            Self::MissedTransition {
                module,
                expected_epoch,
                actual_epoch,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Missed transition: {} expected epoch {} but at {} (detected at {})",
                    module.name(),
                    expected_epoch.as_u64(),
                    actual_epoch.as_u64(),
                    detected_at.as_nanos()
                )
            }
            Self::StaleEpochUpdate {
                module,
                update_epoch,
                current_epoch,
                staleness_amount,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Stale update: {} used epoch {} when current is {} (stale by {}) at {}",
                    module.name(),
                    update_epoch.as_u64(),
                    current_epoch.as_u64(),
                    staleness_amount,
                    detected_at.as_nanos()
                )
            }
            Self::OrderViolation {
                first_module,
                first_epoch,
                second_module,
                second_epoch,
                expected_order,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Order violation: {} at {} and {} at {} violates expected order '{}' at {}",
                    first_module.name(),
                    first_epoch.as_u64(),
                    second_module.name(),
                    second_epoch.as_u64(),
                    expected_order,
                    detected_at.as_nanos()
                )
            }
            Self::ConsistencyFailure {
                affected_modules,
                consistency_level,
                detected_at,
                ..
            } => {
                let modules_str = affected_modules
                    .iter()
                    .map(|(module, epoch)| format!("{}:{}", module.name(), epoch.as_u64()))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "Consistency failure ({:?}): modules [{}] at {}",
                    consistency_level,
                    modules_str,
                    detected_at.as_nanos()
                )
            }
        }
    }
}

/// Current epoch state for a runtime module.
#[derive(Debug, Clone)]
struct ModuleEpochState {
    module: RuntimeModule,
    current_epoch: EpochId,
    last_transition_time: Time,
    transition_start_time: Option<Time>,
    transition_history: VecDeque<(EpochId, Time, u64)>, // (epoch, time, duration_ns)
}

impl ModuleEpochState {
    fn new(module: RuntimeModule, initial_epoch: EpochId, now: Time) -> Self {
        Self {
            module,
            current_epoch: initial_epoch,
            last_transition_time: now,
            transition_start_time: None,
            transition_history: VecDeque::new(),
        }
    }

    fn start_transition(&mut self, now: Time) {
        self.transition_start_time = Some(now);
    }

    fn complete_transition(&mut self, new_epoch: EpochId, now: Time) -> u64 {
        let duration_ns = if let Some(start_time) = self.transition_start_time.take() {
            now.as_nanos().saturating_sub(start_time.as_nanos())
        } else {
            0
        };

        self.transition_history.push_back((new_epoch, now, duration_ns));

        // Keep history bounded
        while self.transition_history.len() > 100 {
            self.transition_history.pop_front();
        }

        self.current_epoch = new_epoch;
        self.last_transition_time = now;
        duration_ns
    }

    fn is_transitioning(&self) -> bool {
        self.transition_start_time.is_some()
    }

    fn transition_duration_so_far(&self, now: Time) -> Option<u64> {
        self.transition_start_time
            .map(|start| now.as_nanos().saturating_sub(start.as_nanos()))
    }
}

/// The runtime epoch consistency tracker.
#[derive(Debug)]
pub struct RuntimeEpochOracle {
    config: RuntimeEpochConfig,

    /// Current epoch states for each module.
    module_states: RwLock<HashMap<RuntimeModule, ModuleEpochState>>,

    /// Global epoch counter for the runtime.
    global_epoch: AtomicU64,

    /// Detected violations.
    violations: RwLock<VecDeque<RuntimeEpochViolation>>,

    /// Statistics counters.
    transitions_tracked: AtomicU64,
    violations_detected: AtomicU64,
    consistency_checks_performed: AtomicU64,
}

impl Default for RuntimeEpochOracle {
    fn default() -> Self {
        Self::with_default_config()
    }
}

impl RuntimeEpochOracle {
    /// Creates a new runtime epoch oracle with the given configuration.
    pub fn new(config: RuntimeEpochConfig) -> Self {
        let oracle = Self {
            config,
            module_states: RwLock::new(HashMap::new()),
            global_epoch: AtomicU64::new(1),
            violations: RwLock::new(VecDeque::new()),
            transitions_tracked: AtomicU64::new(0),
            violations_detected: AtomicU64::new(0),
            consistency_checks_performed: AtomicU64::new(0),
        };

        // Initialize all modules to epoch 1
        let initial_epoch = EpochId::new(1);
        let now = Time::ZERO;
        {
            let mut states = oracle.module_states.write();
            for &module in RuntimeModule::all_modules() {
                states.insert(module, ModuleEpochState::new(module, initial_epoch, now));
            }
        }

        oracle
    }

    /// Creates a new oracle with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(RuntimeEpochConfig::default())
    }

    /// Notify the oracle that a module is starting an epoch transition.
    pub fn notify_epoch_transition_start(&self, module: RuntimeModule, from_epoch: EpochId, now: Time) {
        let mut states = self.module_states.write();
        if let Some(state) = states.get_mut(&module) {
            state.start_transition(now);
        }
    }

    /// Notify the oracle that a module has completed an epoch transition.
    pub fn notify_epoch_transition_complete(&self, module: RuntimeModule, to_epoch: EpochId, now: Time) {
        self.transitions_tracked.fetch_add(1, Ordering::Relaxed);

        let transition_duration = {
            let mut states = self.module_states.write();
            if let Some(state) = states.get_mut(&module) {
                state.complete_transition(to_epoch, now)
            } else {
                0
            }
        };

        // Check for slow transition violation
        if transition_duration > self.config.max_transition_duration_ns {
            let violation = RuntimeEpochViolation::SlowTransition {
                module,
                from_epoch: EpochId::new(to_epoch.as_u64().saturating_sub(1)),
                to_epoch,
                transition_duration_ns: transition_duration,
                detected_at: now,
                stack_trace: self.capture_stack_trace(),
            };
            self.record_violation(violation);
        }

        // Update global epoch to the maximum across all modules
        let max_epoch = {
            let states = self.module_states.read();
            states.values().map(|s| s.current_epoch.as_u64()).max().unwrap_or(1)
        };
        self.global_epoch.store(max_epoch, Ordering::Relaxed);
    }

    /// Notify the oracle of a state update using a specific epoch.
    pub fn notify_epoch_update(&self, module: RuntimeModule, update_epoch: EpochId, now: Time) {
        let current_epoch = {
            let states = self.module_states.read();
            states.get(&module).map(|s| s.current_epoch).unwrap_or(EpochId::new(1))
        };

        // Check for stale epoch usage
        let staleness = current_epoch.as_u64().saturating_sub(update_epoch.as_u64());
        if staleness > 0 {
            let violation = RuntimeEpochViolation::StaleEpochUpdate {
                module,
                update_epoch,
                current_epoch,
                staleness_amount: staleness,
                detected_at: now,
                stack_trace: self.capture_stack_trace(),
            };
            self.record_violation(violation);
        }
    }

    /// Check for epoch consistency violations across all modules.
    pub fn check_epoch_consistency(&self, now: Time) {
        self.consistency_checks_performed.fetch_add(1, Ordering::Relaxed);

        let states = self.module_states.read();
        let modules: Vec<_> = states.keys().copied().collect();

        // Check for epoch skew between all module pairs
        for i in 0..modules.len() {
            for j in (i + 1)..modules.len() {
                let module_a = modules[i];
                let module_b = modules[j];

                if let (Some(state_a), Some(state_b)) = (states.get(&module_a), states.get(&module_b)) {
                    let epoch_a = state_a.current_epoch;
                    let epoch_b = state_b.current_epoch;
                    let skew = epoch_a.as_u64().abs_diff(epoch_b.as_u64());

                    if skew > self.config.max_epoch_skew {
                        let violation = RuntimeEpochViolation::EpochSkew {
                            module_a,
                            epoch_a,
                            module_b,
                            epoch_b,
                            skew_amount: skew,
                            detected_at: now,
                            stack_trace: self.capture_stack_trace(),
                        };
                        self.record_violation(violation);
                    }
                }
            }
        }

        // Check for slow ongoing transitions
        for state in states.values() {
            if let Some(transition_duration) = state.transition_duration_so_far(now) {
                if transition_duration > self.config.max_transition_duration_ns {
                    let violation = RuntimeEpochViolation::SlowTransition {
                        module: state.module,
                        from_epoch: state.current_epoch,
                        to_epoch: EpochId::new(state.current_epoch.as_u64() + 1),
                        transition_duration_ns: transition_duration,
                        detected_at: now,
                        stack_trace: self.capture_stack_trace(),
                    };
                    self.record_violation(violation);
                }
            }
        }
    }

    /// Check for violations following the oracle pattern.
    pub fn check(&self, now: Time) -> Result<(), RuntimeEpochViolation> {
        // First check for new consistency violations
        self.check_epoch_consistency(now);

        // Return the first violation if any exist
        let violations = self.violations.read();
        if let Some(violation) = violations.front() {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Reset the oracle to its initial state.
    pub fn reset(&self) {
        // Reset all modules to epoch 1
        let initial_epoch = EpochId::new(1);
        let now = Time::ZERO;
        {
            let mut states = self.module_states.write();
            states.clear();
            for &module in RuntimeModule::all_modules() {
                states.insert(module, ModuleEpochState::new(module, initial_epoch, now));
            }
        }

        self.global_epoch.store(1, Ordering::Relaxed);
        self.violations.write().clear();
        self.transitions_tracked.store(0, Ordering::Relaxed);
        self.violations_detected.store(0, Ordering::Relaxed);
        self.consistency_checks_performed.store(0, Ordering::Relaxed);
    }

    /// Get the current global epoch.
    pub fn global_epoch(&self) -> EpochId {
        EpochId::new(self.global_epoch.load(Ordering::Relaxed))
    }

    /// Get the current epoch for a specific module.
    pub fn module_epoch(&self, module: RuntimeModule) -> Option<EpochId> {
        let states = self.module_states.read();
        states.get(&module).map(|s| s.current_epoch)
    }

    /// Get statistics about oracle operation.
    pub fn get_statistics(&self) -> RuntimeEpochStatistics {
        let states = self.module_states.read();
        let violations = self.violations.read();

        let epochs: Vec<u64> = states.values().map(|s| s.current_epoch.as_u64()).collect();
        let min_epoch = epochs.iter().copied().min().unwrap_or(1);
        let max_epoch = epochs.iter().copied().max().unwrap_or(1);
        let epoch_variance = max_epoch - min_epoch;

        RuntimeEpochStatistics {
            transitions_tracked: self.transitions_tracked.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            consistency_checks_performed: self.consistency_checks_performed.load(Ordering::Relaxed),
            global_epoch: self.global_epoch(),
            tracked_modules: states.len(),
            min_module_epoch: EpochId::new(min_epoch),
            max_module_epoch: EpochId::new(max_epoch),
            epoch_variance,
            total_violations: violations.len(),
        }
    }

    /// Get recent violations for debugging.
    pub fn get_recent_violations(&self, limit: usize) -> Vec<RuntimeEpochViolation> {
        let violations = self.violations.read();
        violations.iter().rev().take(limit).cloned().collect()
    }

    /// Get detailed module states for debugging.
    pub fn get_module_states(&self) -> Vec<(RuntimeModule, EpochId, bool)> {
        let states = self.module_states.read();
        states.values()
            .map(|s| (s.module, s.current_epoch, s.is_transitioning()))
            .collect()
    }

    fn record_violation(&self, violation: RuntimeEpochViolation) {
        self.violations_detected.fetch_add(1, Ordering::Relaxed);

        if self.config.panic_on_violation {
            panic!("Runtime epoch violation detected: {}", violation);
        }

        // Record violation for later inspection
        let mut violations = self.violations.write();
        violations.push_back(violation);

        // Keep violations bounded
        while violations.len() > self.config.max_violations {
            violations.pop_front();
        }
    }

    fn capture_stack_trace(&self) -> Option<Arc<Backtrace>> {
        if self.config.capture_stack_traces {
            Some(Arc::new(Backtrace::capture()))
        } else {
            None
        }
    }
}

/// Statistics about runtime epoch oracle operation.
#[derive(Debug, Clone)]
pub struct RuntimeEpochStatistics {
    /// Number of epoch transitions tracked.
    pub transitions_tracked: u64,
    /// Number of violations detected.
    pub violations_detected: u64,
    /// Number of consistency checks performed.
    pub consistency_checks_performed: u64,
    /// Current global epoch.
    pub global_epoch: EpochId,
    /// Number of modules being tracked.
    pub tracked_modules: usize,
    /// Minimum epoch across all modules.
    pub min_module_epoch: EpochId,
    /// Maximum epoch across all modules.
    pub max_module_epoch: EpochId,
    /// Variance in epochs across modules.
    pub epoch_variance: u64,
    /// Total number of violations recorded.
    pub total_violations: usize,
}

impl fmt::Display for RuntimeEpochStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RuntimeEpochStats {{ transitions: {}, violations: {}, checks: {}, global_epoch: {}, modules: {}, epoch_range: {}-{}, variance: {}, total_violations: {} }}",
            self.transitions_tracked,
            self.violations_detected,
            self.consistency_checks_performed,
            self.global_epoch.as_u64(),
            self.tracked_modules,
            self.min_module_epoch.as_u64(),
            self.max_module_epoch.as_u64(),
            self.epoch_variance,
            self.total_violations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    #[test]
    fn test_normal_epoch_transitions() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();
        let now = Time::ZERO;

        // All modules start at epoch 1
        assert_eq!(oracle.module_epoch(RuntimeModule::Scheduler), Some(EpochId::new(1)));

        // Normal transition for scheduler
        oracle.notify_epoch_transition_start(RuntimeModule::Scheduler, EpochId::new(1), now);
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(2), Time::from_nanos(1000));

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.transitions_tracked, 1);
        assert_eq!(oracle.module_epoch(RuntimeModule::Scheduler), Some(EpochId::new(2)));
    }

    #[test]
    fn test_epoch_skew_detection() {
        init_test_logging();

        let config = RuntimeEpochConfig {
            max_epoch_skew: 1, // Very low tolerance for testing
            ..Default::default()
        };
        let oracle = RuntimeEpochOracle::new(config);
        let now = Time::ZERO;

        // Advance scheduler to epoch 3
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(3), now);

        // Leave region table at epoch 1 - should cause skew violation
        oracle.check_epoch_consistency(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);
        assert_eq!(stats.epoch_variance, 2); // epochs 1 and 3

        let violations = oracle.get_recent_violations(1);
        assert!(!violations.is_empty());
        assert!(matches!(violations[0], RuntimeEpochViolation::EpochSkew { .. }));
    }

    #[test]
    fn test_slow_transition_detection() {
        init_test_logging();

        let config = RuntimeEpochConfig {
            max_transition_duration_ns: 100_000, // 100μs max for testing
            ..Default::default()
        };
        let oracle = RuntimeEpochOracle::new(config);
        let now = Time::ZERO;

        // Start transition
        oracle.notify_epoch_transition_start(RuntimeModule::Scheduler, EpochId::new(1), now);

        // Complete much later (should trigger violation)
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(2),
            Time::from_nanos(1_000_000), // 1ms later
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(violations[0], RuntimeEpochViolation::SlowTransition { .. }));
    }

    #[test]
    fn test_stale_epoch_update_detection() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();
        let now = Time::ZERO;

        // Advance scheduler to epoch 3
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(3), now);

        // Try to update using old epoch 1 - should trigger stale update violation
        oracle.notify_epoch_update(RuntimeModule::Scheduler, EpochId::new(1), now);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(violations[0], RuntimeEpochViolation::StaleEpochUpdate { .. }));
    }

    #[test]
    fn test_oracle_check_method() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        // Normal operation should pass
        let result = oracle.check(Time::ZERO);
        assert!(result.is_ok());

        // Create a violation by advancing one module too far
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(10), Time::ZERO);

        // Check should now return error
        let result = oracle.check(Time::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_reset() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        // Advance some epochs and create violations
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(5), Time::ZERO);
        oracle.check_epoch_consistency(Time::ZERO);

        let stats_before = oracle.get_statistics();
        assert!(stats_before.violations_detected > 0);
        assert!(stats_before.global_epoch.as_u64() > 1);

        // Reset should restore initial state
        oracle.reset();

        let stats_after = oracle.get_statistics();
        assert_eq!(stats_after.violations_detected, 0);
        assert_eq!(stats_after.transitions_tracked, 0);
        assert_eq!(stats_after.global_epoch.as_u64(), 1);
        assert_eq!(stats_after.epoch_variance, 0);

        // All modules should be back at epoch 1
        for &module in RuntimeModule::all_modules() {
            assert_eq!(oracle.module_epoch(module), Some(EpochId::new(1)));
        }
    }

    #[test]
    fn test_global_epoch_tracking() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();
        assert_eq!(oracle.global_epoch().as_u64(), 1);

        // Advance some modules
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(3), Time::ZERO);
        oracle.notify_epoch_transition_complete(RuntimeModule::TaskTable, EpochId::new(2), Time::ZERO);

        // Global epoch should be the maximum
        assert_eq!(oracle.global_epoch().as_u64(), 3);
    }

    #[test]
    fn test_all_modules_tracked() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        // Verify all expected modules are tracked
        let module_states = oracle.get_module_states();
        assert_eq!(module_states.len(), RuntimeModule::all_modules().len());

        for &expected_module in RuntimeModule::all_modules() {
            assert!(module_states.iter().any(|(module, _, _)| *module == expected_module));
        }
    }
}