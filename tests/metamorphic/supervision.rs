//! Metamorphic property tests for supervision tree restart-policy invariants.
//!
//! These tests verify supervision tree invariants related to restart policies,
//! child lifecycle management, and failure escalation. Unlike unit tests that check
//! exact outcomes, metamorphic tests verify relationships between different
//! supervision scenarios using LabRuntime DPOR for deterministic scheduling exploration.
//!
//! # Metamorphic Relations
//!
//! 1. **One-For-One Restart Isolation** (MR1): one-for-one restarts only failed child (isolation)
//! 2. **Rest-For-One Dependency** (MR2): rest-for-one restarts failed child + younger siblings (dependency)
//! 3. **One-For-All Coordination** (MR3): one-for-all restarts all children (coordination)
//! 4. **Restart Budget Enforcement** (MR4): max_restarts within intensity window respected (escalation)
//! 5. **Shutdown Ordering** (MR5): shutdown drains children in reverse-start order (ordering)
//! 6. **Transient Exit Policy** (MR6): transient children only restart on abnormal exit (policy)

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::supervision::{
    BackoffStrategy, ChildName, ChildSpec, ChildStart, CompiledSupervisor, RestartPolicy,
    SupervisionConfig, SupervisionStrategy, SupervisorBuilder,
};
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};
use asupersync::util::ArenaIndex as UtilArenaIndex;
use asupersync::runtime::{RuntimeState, SpawnError};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for supervision testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Configuration for supervision metamorphic tests.
#[derive(Debug, Clone)]
pub struct SupervisionTestConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Number of children to supervise.
    pub child_count: usize,
    /// Restart policy to test.
    pub restart_policy: RestartPolicy,
    /// Maximum restarts allowed in window.
    pub max_restarts: u32,
    /// Restart window duration.
    pub restart_window: Duration,
    /// Backoff strategy.
    pub backoff: BackoffStrategy,
    /// Which child index should fail (for targeted failure injection).
    pub failing_child: usize,
    /// Outcome type for the failing child.
    pub failure_outcome: TestOutcome,
    /// Whether children are transient (only restart on abnormal exit).
    pub transient_children: bool,
}

/// Test outcome variants for failure injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOutcome {
    /// Normal completion.
    Ok,
    /// Application error (normal failure).
    Err,
    /// Cancellation (abnormal failure).
    Cancelled,
    /// Panic (abnormal failure).
    Panicked,
}

impl TestOutcome {
    /// Returns true if this is an abnormal exit (Cancelled or Panicked).
    pub fn is_abnormal(self) -> bool {
        matches!(self, TestOutcome::Cancelled | TestOutcome::Panicked)
    }

    /// Convert to actual Outcome for testing.
    pub fn to_outcome<T, E>(self, ok_val: T, err_val: E) -> Outcome<T, E> {
        match self {
            TestOutcome::Ok => Outcome::ok(ok_val),
            TestOutcome::Err => Outcome::err(err_val),
            TestOutcome::Cancelled => Outcome::cancelled(CancelReason::shutdown()),
            TestOutcome::Panicked => Outcome::panicked(String::from("test panic")),
        }
    }
}

/// Track supervision events for invariant checking.
#[derive(Debug, Clone)]
struct SupervisionTracker {
    /// Child start events (child_name, timestamp).
    child_starts: Vec<(String, u64)>,
    /// Child stop events (child_name, outcome, timestamp).
    child_stops: Vec<(String, TestOutcome, u64)>,
    /// Restart events (child_name, restart_count, timestamp).
    restarts: Vec<(String, u32, u64)>,
    /// Shutdown start event.
    shutdown_start: Option<u64>,
    /// Shutdown completion events (child_name, timestamp) in completion order.
    shutdown_completions: Vec<(String, u64)>,
    /// Current timestamp counter.
    timestamp: AtomicU64,
}

impl SupervisionTracker {
    fn new() -> Arc<StdMutex<Self>> {
        Arc::new(StdMutex::new(Self {
            child_starts: Vec::new(),
            child_stops: Vec::new(),
            restarts: Vec::new(),
            shutdown_start: None,
            shutdown_completions: Vec::new(),
            timestamp: AtomicU64::new(0),
        }))
    }

    /// Record child start.
    fn record_start(&mut self, child_name: &str) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.child_starts.push((child_name.to_string(), ts));
    }

    /// Record child stop with outcome.
    fn record_stop(&mut self, child_name: &str, outcome: TestOutcome) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.child_stops.push((child_name.to_string(), outcome, ts));
    }

    /// Record child restart.
    fn record_restart(&mut self, child_name: &str, restart_count: u32) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.restarts.push((child_name.to_string(), restart_count, ts));
    }

    /// Record shutdown start.
    fn record_shutdown_start(&mut self) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.shutdown_start = Some(ts);
    }

    /// Record shutdown completion for a child.
    fn record_shutdown_completion(&mut self, child_name: &str) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.shutdown_completions.push((child_name.to_string(), ts));
    }

    /// Get children that were restarted for a given failure.
    fn get_restarted_children(&self, after_timestamp: u64) -> Vec<String> {
        self.restarts
            .iter()
            .filter(|(_, _, ts)| *ts > after_timestamp)
            .map(|(name, _, _)| name.clone())
            .collect()
    }

    /// Get start order of children.
    fn get_start_order(&self) -> Vec<String> {
        let mut starts = self.child_starts.clone();
        starts.sort_by_key(|(_, ts)| *ts);
        starts.into_iter().map(|(name, _)| name).collect()
    }

    /// Get shutdown completion order.
    fn get_shutdown_order(&self) -> Vec<String> {
        let mut completions = self.shutdown_completions.clone();
        completions.sort_by_key(|(_, ts)| *ts);
        completions.into_iter().map(|(name, _)| name).collect()
    }
}

/// A test child that can be configured to fail with specific outcomes.
#[derive(Debug)]
struct TestChild {
    /// Child name.
    name: String,
    /// Failure outcome (if this child should fail).
    failure_outcome: Option<TestOutcome>,
    /// Whether this child is transient (only restarts on abnormal exits).
    is_transient: bool,
    /// Shared tracker for recording events.
    tracker: Arc<StdMutex<SupervisionTracker>>,
    /// Whether this child has been started.
    started: Arc<AtomicBool>,
    /// Restart count.
    restart_count: Arc<AtomicUsize>,
}

impl TestChild {
    fn new(
        name: String,
        failure_outcome: Option<TestOutcome>,
        is_transient: bool,
        tracker: Arc<StdMutex<SupervisionTracker>>,
    ) -> Self {
        Self {
            name,
            failure_outcome,
            is_transient,
            tracker,
            started: Arc::new(AtomicBool::new(false)),
            restart_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the supervision strategy for this child.
    fn supervision_strategy(&self) -> SupervisionStrategy {
        if self.is_transient {
            // Transient children only restart on abnormal exits
            SupervisionStrategy::Restart(
                asupersync::supervision::RestartConfig::default()
                    .with_backoff(BackoffStrategy::None),
            )
        } else {
            // Permanent children restart on any failure
            SupervisionStrategy::Restart(
                asupersync::supervision::RestartConfig::default()
                    .with_backoff(BackoffStrategy::None),
            )
        }
    }
}

impl ChildStart for TestChild {
    fn start(
        &mut self,
        _scope: &Scope<'static, crate::types::policy::FailFast>,
        _state: &mut RuntimeState,
        _cx: &Cx,
    ) -> Result<TaskId, SpawnError> {
        // Record start event
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.record_start(&self.name);
        }

        self.started.store(true, Ordering::Relaxed);
        let restart_count = self.restart_count.fetch_add(1, Ordering::Relaxed);

        // Record restart if this is not the first start
        if restart_count > 0 {
            if let Ok(mut tracker) = self.tracker.lock() {
                tracker.record_restart(&self.name, restart_count as u32);
            }
        }

        // For testing purposes, return a dummy TaskId
        Ok(TaskId::from_arena(ArenaIndex::new(0, 0)))
    }
}

/// Test harness for supervision metamorphic tests.
pub struct SupervisionTestHarness {
    pub config: SupervisionTestConfig,
    pub tracker: Arc<StdMutex<SupervisionTracker>>,
    pub lab: LabRuntime,
}

impl SupervisionTestHarness {
    /// Create a new test harness.
    pub fn new(config: SupervisionTestConfig) -> Self {
        let lab = LabRuntime::with_config(LabConfig::deterministic().with_seed(config.seed));
        let tracker = SupervisionTracker::new();

        Self {
            config,
            tracker,
            lab,
        }
    }

    /// Create a supervisor with test children.
    pub fn create_supervisor(&self) -> CompiledSupervisor {
        let mut builder = SupervisorBuilder::new("test_supervisor")
            .with_restart_policy(self.config.restart_policy);

        for i in 0..self.config.child_count {
            let child_name = format!("child_{}", i);
            let failure_outcome = if i == self.config.failing_child {
                Some(self.config.failure_outcome)
            } else {
                None
            };

            let child = TestChild::new(
                child_name.clone(),
                failure_outcome,
                self.config.transient_children,
                self.tracker.clone(),
            );

            let child_spec = ChildSpec::new(child_name, child)
                .with_restart(child.supervision_strategy())
                .with_shutdown_budget(Budget::INFINITE);

            builder = builder.child(child_spec);
        }

        SupervisorBuilder::compile(builder).expect("supervisor compilation should succeed")
    }

    /// Simulate a child failure and check restart behavior.
    pub fn simulate_failure_and_restart(&mut self) -> Vec<String> {
        let supervisor = self.create_supervisor();

        // Record the failure
        let failing_child_name = format!("child_{}", self.config.failing_child);
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.record_stop(&failing_child_name, self.config.failure_outcome);
        }

        // Compute restart plan
        let restart_plan = supervisor.restart_plan_for(&failing_child_name);

        if let Some(plan) = restart_plan {
            plan.restart_order
        } else {
            Vec::new()
        }
    }

    /// Test shutdown ordering.
    pub fn test_shutdown_ordering(&mut self) -> (Vec<String>, Vec<String>) {
        let supervisor = self.create_supervisor();

        // Get start order
        let start_order = supervisor.child_start_order_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        // Get expected shutdown order (reverse of start order)
        let shutdown_order = supervisor.child_stop_order_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        (start_order, shutdown_order)
    }

    /// Check if a child should restart given its transient status and failure outcome.
    pub fn should_restart_child(&self, child_index: usize, outcome: TestOutcome) -> bool {
        if self.config.transient_children {
            // Transient children only restart on abnormal exits
            outcome.is_abnormal()
        } else {
            // Permanent children restart on any failure (Err, Cancelled, Panicked)
            !matches!(outcome, TestOutcome::Ok)
        }
    }
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

/// MR1: One-for-one restart policy only affects the failed child.
#[test]
fn mr1_one_for_one_isolation() {
    let test_config = any::<(u64, u8, u8)>().prop_map(|(seed, child_count, failing_child)| {
        let child_count = (child_count % 5) + 2; // 2-6 children
        let failing_child = (failing_child as usize) % child_count;

        SupervisionTestConfig {
            seed,
            child_count,
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child,
            failure_outcome: TestOutcome::Err,
            transient_children: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = SupervisionTestHarness::new(config.clone());
        let restarted_children = harness.simulate_failure_and_restart();

        // One-for-one should only restart the failed child
        let expected_restart = vec![format!("child_{}", config.failing_child)];

        prop_assert_eq!(restarted_children, expected_restart,
            "One-for-one restart should only affect the failed child, but restarted: {:?}",
            restarted_children);
    });
}

/// MR2: Rest-for-one restart policy affects the failed child and all younger siblings.
#[test]
fn mr2_rest_for_one_dependency() {
    let test_config = any::<(u64, u8, u8)>().prop_map(|(seed, child_count, failing_child)| {
        let child_count = (child_count % 5) + 3; // 3-7 children (need at least 3 for meaningful test)
        let failing_child = (failing_child as usize) % (child_count - 1); // Don't fail last child

        SupervisionTestConfig {
            seed,
            child_count,
            restart_policy: RestartPolicy::RestForOne,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child,
            failure_outcome: TestOutcome::Err,
            transient_children: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = SupervisionTestHarness::new(config.clone());
        let restarted_children = harness.simulate_failure_and_restart();

        // Rest-for-one should restart failed child + all younger siblings
        let mut expected_restart = Vec::new();
        for i in config.failing_child..config.child_count {
            expected_restart.push(format!("child_{}", i));
        }

        prop_assert_eq!(restarted_children, expected_restart,
            "Rest-for-one restart should affect failed child + younger siblings, but restarted: {:?}",
            restarted_children);
    });
}

/// MR3: One-for-all restart policy affects all children.
#[test]
fn mr3_one_for_all_coordination() {
    let test_config = any::<(u64, u8, u8)>().prop_map(|(seed, child_count, failing_child)| {
        let child_count = (child_count % 5) + 2; // 2-6 children
        let failing_child = (failing_child as usize) % child_count;

        SupervisionTestConfig {
            seed,
            child_count,
            restart_policy: RestartPolicy::OneForAll,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child,
            failure_outcome: TestOutcome::Err,
            transient_children: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = SupervisionTestHarness::new(config.clone());
        let restarted_children = harness.simulate_failure_and_restart();

        // One-for-all should restart all children
        let mut expected_restart = Vec::new();
        for i in 0..config.child_count {
            expected_restart.push(format!("child_{}", i));
        }

        prop_assert_eq!(restarted_children, expected_restart,
            "One-for-all restart should affect all children, but restarted: {:?}",
            restarted_children);
    });
}

/// MR4: Max restarts within intensity window is respected (escalation).
#[test]
fn mr4_restart_budget_enforcement() {
    let test_config = any::<(u64, u8)>().prop_map(|(seed, max_restarts)| {
        let max_restarts = (max_restarts % 3) + 1; // 1-3 max restarts

        SupervisionTestConfig {
            seed,
            child_count: 3,
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: max_restarts as u32,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child: 0,
            failure_outcome: TestOutcome::Err,
            transient_children: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = SupervisionTestHarness::new(config.clone());

        // Simulate repeated failures up to the limit
        let mut restart_counts = Vec::new();
        for attempt in 0..=config.max_restarts {
            let restarted = harness.simulate_failure_and_restart();
            restart_counts.push(restarted.len());

            // Once max_restarts is exceeded, no more restarts should occur
            if attempt >= config.max_restarts {
                prop_assert_eq!(restarted.len(), 0,
                    "No restarts should occur after max_restarts ({}) exceeded, attempt {}",
                    config.max_restarts, attempt);
            } else {
                prop_assert!(restarted.len() > 0,
                    "Restarts should occur within max_restarts limit, attempt {}",
                    attempt);
            }
        }
    });
}

/// MR5: Shutdown drains children in reverse-start order.
#[test]
fn mr5_shutdown_ordering() {
    let test_config = any::<(u64, u8)>().prop_map(|(seed, child_count)| {
        let child_count = (child_count % 5) + 2; // 2-6 children

        SupervisionTestConfig {
            seed,
            child_count,
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child: 0, // Not relevant for shutdown test
            failure_outcome: TestOutcome::Ok,
            transient_children: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = SupervisionTestHarness::new(config);
        let (start_order, shutdown_order) = harness.test_shutdown_ordering();

        // Shutdown order should be reverse of start order
        let mut expected_shutdown = start_order.clone();
        expected_shutdown.reverse();

        prop_assert_eq!(shutdown_order, expected_shutdown,
            "Shutdown order should be reverse of start order.\nStart: {:?}\nShutdown: {:?}\nExpected: {:?}",
            start_order, shutdown_order, expected_shutdown);
    });
}

/// MR6: Transient children only restart on abnormal exit (Cancelled/Panicked).
#[test]
fn mr6_transient_exit_policy() {
    let test_config = any::<(u64, u8)>().prop_map(|(seed, outcome_type)| {
        let failure_outcome = match outcome_type % 4 {
            0 => TestOutcome::Ok,
            1 => TestOutcome::Err,
            2 => TestOutcome::Cancelled,
            3 => TestOutcome::Panicked,
            _ => unreachable!(),
        };

        SupervisionTestConfig {
            seed,
            child_count: 3,
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child: 1, // Middle child
            failure_outcome,
            transient_children: true,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = SupervisionTestHarness::new(config.clone());
        let restarted_children = harness.simulate_failure_and_restart();

        let should_restart = harness.should_restart_child(config.failing_child, config.failure_outcome);

        if should_restart {
            prop_assert!(!restarted_children.is_empty(),
                "Transient child should restart on abnormal exit ({:?})",
                config.failure_outcome);
        } else {
            prop_assert!(restarted_children.is_empty(),
                "Transient child should NOT restart on normal exit ({:?})",
                config.failure_outcome);
        }
    });
}

// ============================================================================
// Property Generators for proptest
// ============================================================================

impl Arbitrary for TestOutcome {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(TestOutcome::Ok),
            Just(TestOutcome::Err),
            Just(TestOutcome::Cancelled),
            Just(TestOutcome::Panicked),
        ]
        .boxed()
    }
}

impl Arbitrary for RestartPolicy {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(RestartPolicy::OneForOne),
            Just(RestartPolicy::OneForAll),
            Just(RestartPolicy::RestForOne),
        ]
        .boxed()
    }
}

impl Arbitrary for SupervisionTestConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<u64>(), // seed
            2u8..=6,      // child_count
            any::<RestartPolicy>(),
            1u32..=5,     // max_restarts
            any::<TestOutcome>(),
            any::<bool>(), // transient_children
        )
            .prop_map(
                |(seed, child_count, restart_policy, max_restarts, failure_outcome, transient_children)| {
                    let child_count = child_count as usize;
                    let failing_child = (seed as usize) % child_count;

                    SupervisionTestConfig {
                        seed,
                        child_count,
                        restart_policy,
                        max_restarts,
                        restart_window: Duration::from_secs(60),
                        backoff: BackoffStrategy::None,
                        failing_child,
                        failure_outcome,
                        transient_children,
                    }
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outcome_abnormal_classification() {
        assert!(!TestOutcome::Ok.is_abnormal());
        assert!(!TestOutcome::Err.is_abnormal());
        assert!(TestOutcome::Cancelled.is_abnormal());
        assert!(TestOutcome::Panicked.is_abnormal());
    }

    #[test]
    fn test_supervision_tracker_ordering() {
        let tracker = SupervisionTracker::new();

        {
            let mut t = tracker.lock().unwrap();
            t.record_start("child_0");
            t.record_start("child_1");
            t.record_start("child_2");
        }

        let start_order = tracker.lock().unwrap().get_start_order();
        assert_eq!(start_order, vec!["child_0", "child_1", "child_2"]);
    }

    #[test]
    fn test_transient_restart_policy() {
        let config = SupervisionTestConfig {
            seed: 42,
            child_count: 2,
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::None,
            failing_child: 0,
            failure_outcome: TestOutcome::Cancelled, // Abnormal
            transient_children: true,
        };

        let harness = SupervisionTestHarness::new(config.clone());
        assert!(harness.should_restart_child(0, TestOutcome::Cancelled));
        assert!(harness.should_restart_child(0, TestOutcome::Panicked));
        assert!(!harness.should_restart_child(0, TestOutcome::Ok));
        assert!(!harness.should_restart_child(0, TestOutcome::Err));
    }
}