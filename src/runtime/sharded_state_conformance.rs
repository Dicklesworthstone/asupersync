//! Conformance harness for ShardedState lock ordering and concurrency contracts.
//!
//! This module implements comprehensive conformance testing for the documented
//! specifications in [`ShardedState`], particularly:
//!
//! - **Lock Ordering Contract**: E (Config) → D (Instrumentation) → B (Regions) → A (Tasks) → C (Obligations)
//! - **Shard Responsibility Contract**: Each guard method accesses only its documented shards
//! - **Concurrency Safety Contract**: No deadlocks under concurrent access patterns
//! - **State Consistency Contract**: Atomic operations maintain consistency
//!
//! # Specification Source
//!
//! The specifications being tested are documented in:
//! - `src/runtime/sharded_state.rs` comments and doc strings
//! - Lock ordering table in module documentation
//! - Method → ShardGuard mapping table
//! - Debug assertions in `lock_order` module
//!
//! # Test Organization
//!
//! This follows **Pattern 4: Spec-Derived Test Matrix** - one test per documented requirement.

use crate::observability::ObservabilityConfig;
use crate::observability::metrics::{MetricsProvider, NoOpMetrics};
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::sharded_state::{
    ShardGuard, ShardedConfig, ShardedObservability, ShardedState,
};
use crate::trace::TraceBufferHandle;
use crate::trace::distributed::LogicalClockMode;
use crate::types::{CancelAttributionConfig, RegionId, Time};
use crate::util::{ArenaIndex, OsEntropy};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

// Conditional access to lock order tracking functions
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn held_count() -> usize {
    crate::runtime::sharded_state::lock_order::held_count()
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn held_labels() -> Vec<&'static str> {
    crate::runtime::sharded_state::lock_order::held_labels()
}

#[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
fn held_count() -> usize {
    0
}

#[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
fn held_labels() -> Vec<&'static str> {
    Vec::new()
}

fn lock_order_tracking_skip() -> Option<ConformanceResult> {
    if cfg!(any(debug_assertions, feature = "lock-metrics")) {
        None
    } else {
        Some(ConformanceResult::Skip {
            reason: "lock-order tracking is compiled out in release builds without lock-metrics"
                .to_string(),
        })
    }
}

/// Conformance test result for structured reporting.
#[derive(Debug, Clone, PartialEq)]
pub enum ConformanceResult {
    Pass,
    Fail { reason: String },
    Skip { reason: String },
}

/// Requirement levels for coverage tracking.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequirementLevel {
    Must,   // MUST requirements from specification
    Should, // SHOULD requirements
    May,    // MAY requirements or edge cases
}

/// Conformance test case for structured execution.
#[derive(Debug)]
pub struct ConformanceTestCase {
    pub id: &'static str,
    pub section: &'static str,
    pub level: RequirementLevel,
    pub description: &'static str,
}

impl ConformanceTestCase {
    pub const fn new(
        id: &'static str,
        section: &'static str,
        level: RequirementLevel,
        description: &'static str,
    ) -> Self {
        Self {
            id,
            section,
            level,
            description,
        }
    }
}

/// Test fixture for creating consistent ShardedState instances.
pub struct ConformanceFixture {
    pub state: ShardedState,
}

impl ConformanceFixture {
    pub fn new() -> Self {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let config = ShardedConfig {
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            observability: Some(ShardedObservability::new(ObservabilityConfig::default())),
        };

        let state = ShardedState::new(trace, metrics, config);
        Self { state }
    }
}

/// Comprehensive conformance test suite for ShardedState.
pub struct ShardedStateConformanceSuite;

impl ShardedStateConformanceSuite {
    /// Execute the complete conformance test suite.
    pub fn run_all() -> (usize, usize) {
        let test_cases = [
            // ─── Lock Ordering Compliance Tests ───
            ConformanceTestCase::new(
                "LOCK-ORD-001",
                "lock_order",
                RequirementLevel::Must,
                "tasks_only guard must acquire only Task shard (A)",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-002",
                "lock_order",
                RequirementLevel::Must,
                "regions_only guard must acquire only Region shard (B)",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-003",
                "lock_order",
                RequirementLevel::Must,
                "obligations_only guard must acquire only Obligation shard (C)",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-004",
                "lock_order",
                RequirementLevel::Must,
                "for_spawn guard must acquire B→A in correct order",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-005",
                "lock_order",
                RequirementLevel::Must,
                "for_obligation guard must acquire B→C in correct order",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-006",
                "lock_order",
                RequirementLevel::Must,
                "for_task_completed guard must acquire B→A→C in correct order",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-007",
                "lock_order",
                RequirementLevel::Must,
                "for_cancel guard must acquire B→A→C in correct order",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-008",
                "lock_order",
                RequirementLevel::Must,
                "for_obligation_resolve guard must acquire B→A→C in correct order",
            ),
            ConformanceTestCase::new(
                "LOCK-ORD-009",
                "lock_order",
                RequirementLevel::Must,
                "all guard must acquire B→A→C in correct order",
            ),
            // ─── Shard Access Compliance Tests ───
            ConformanceTestCase::new(
                "SHARD-ACC-001",
                "shard_access",
                RequirementLevel::Must,
                "tasks_only guard provides tasks access, no regions/obligations",
            ),
            ConformanceTestCase::new(
                "SHARD-ACC-002",
                "shard_access",
                RequirementLevel::Must,
                "regions_only guard provides regions access, no tasks/obligations",
            ),
            ConformanceTestCase::new(
                "SHARD-ACC-003",
                "shard_access",
                RequirementLevel::Must,
                "obligations_only guard provides obligations access, no regions/tasks",
            ),
            ConformanceTestCase::new(
                "SHARD-ACC-004",
                "shard_access",
                RequirementLevel::Must,
                "for_spawn guard provides regions+tasks access, no obligations",
            ),
            ConformanceTestCase::new(
                "SHARD-ACC-005",
                "shard_access",
                RequirementLevel::Must,
                "for_obligation guard provides regions+obligations access, no tasks",
            ),
            // ─── State Consistency Tests ───
            ConformanceTestCase::new(
                "STATE-CON-001",
                "state_consistency",
                RequirementLevel::Must,
                "root_region atomic operations are consistent",
            ),
            ConformanceTestCase::new(
                "STATE-CON-002",
                "state_consistency",
                RequirementLevel::Must,
                "leak_count atomic operations are consistent",
            ),
            ConformanceTestCase::new(
                "STATE-CON-003",
                "state_consistency",
                RequirementLevel::Must,
                "current_time atomic operations are consistent",
            ),
            // ─── Deadlock Prevention Tests ───
            ConformanceTestCase::new(
                "DEADLOCK-001",
                "deadlock_prevention",
                RequirementLevel::Must,
                "concurrent guard acquisition must not deadlock",
            ),
            ConformanceTestCase::new(
                "DEADLOCK-002",
                "deadlock_prevention",
                RequirementLevel::Should,
                "stress test: high-concurrency guard operations complete",
            ),
        ];

        let mut passed = 0;
        let mut failed = 0;

        for case in &test_cases {
            let result = Self::run_test_case(case);
            match result {
                ConformanceResult::Pass => {
                    passed += 1;
                }
                ConformanceResult::Fail { reason: _ } => {
                    failed += 1;
                }
                ConformanceResult::Skip { reason: _ } => {
                    // Test skipped
                }
            }
        }

        let _total = passed + failed;
        // ShardedState Conformance: tests completed

        (passed, failed)
    }

    /// Run a specific conformance test case.
    fn run_test_case(case: &ConformanceTestCase) -> ConformanceResult {
        match case.id {
            // Lock ordering compliance tests
            "LOCK-ORD-001" => Self::test_tasks_only_lock_order(),
            "LOCK-ORD-002" => Self::test_regions_only_lock_order(),
            "LOCK-ORD-003" => Self::test_obligations_only_lock_order(),
            "LOCK-ORD-004" => Self::test_for_spawn_lock_order(),
            "LOCK-ORD-005" => Self::test_for_obligation_lock_order(),
            "LOCK-ORD-006" => Self::test_for_task_completed_lock_order(),
            "LOCK-ORD-007" => Self::test_for_cancel_lock_order(),
            "LOCK-ORD-008" => Self::test_for_obligation_resolve_lock_order(),
            "LOCK-ORD-009" => Self::test_all_lock_order(),

            // Shard access compliance tests
            "SHARD-ACC-001" => Self::test_tasks_only_shard_access(),
            "SHARD-ACC-002" => Self::test_regions_only_shard_access(),
            "SHARD-ACC-003" => Self::test_obligations_only_shard_access(),
            "SHARD-ACC-004" => Self::test_for_spawn_shard_access(),
            "SHARD-ACC-005" => Self::test_for_obligation_shard_access(),

            // State consistency tests
            "STATE-CON-001" => Self::test_root_region_consistency(),
            "STATE-CON-002" => Self::test_leak_count_consistency(),
            "STATE-CON-003" => Self::test_current_time_consistency(),

            // Deadlock prevention tests
            "DEADLOCK-001" => Self::test_concurrent_guard_acquisition(),
            "DEADLOCK-002" => Self::test_stress_concurrency(),

            _ => ConformanceResult::Skip {
                reason: format!("Unknown conformance test case id {}", case.id),
            },
        }
    }

    // ─── Lock Ordering Compliance Tests ───

    fn test_tasks_only_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::tasks_only(&fixture.state);
            let held = held_labels();
            if held != vec!["A:Tasks"] {
                return ConformanceResult::Fail {
                    reason: format!("Expected ['A:Tasks'], got {:?}", held),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Lock not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_regions_only_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::regions_only(&fixture.state);
            let held = held_labels();
            if held != vec!["B:Regions"] {
                return ConformanceResult::Fail {
                    reason: format!("Expected ['B:Regions'], got {:?}", held),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Lock not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_obligations_only_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::obligations_only(&fixture.state);
            let held = held_labels();
            if held != vec!["C:Obligations"] {
                return ConformanceResult::Fail {
                    reason: format!("Expected ['C:Obligations'], got {:?}", held),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Lock not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_spawn_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::for_spawn(&fixture.state);
            let held = held_labels();
            // Must be B→A order
            if held != vec!["B:Regions", "A:Tasks"] {
                return ConformanceResult::Fail {
                    reason: format!("Expected ['B:Regions', 'A:Tasks'], got {:?}", held),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Locks not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_obligation_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::for_obligation(&fixture.state);
            let held = held_labels();
            // Must be B→C order
            if held != vec!["B:Regions", "C:Obligations"] {
                return ConformanceResult::Fail {
                    reason: format!("Expected ['B:Regions', 'C:Obligations'], got {:?}", held),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Locks not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_task_completed_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::for_task_completed(&fixture.state);
            let held = held_labels();
            // Must be B→A→C order
            if held != vec!["B:Regions", "A:Tasks", "C:Obligations"] {
                return ConformanceResult::Fail {
                    reason: format!(
                        "Expected ['B:Regions', 'A:Tasks', 'C:Obligations'], got {:?}",
                        held
                    ),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Locks not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_cancel_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::for_cancel(&fixture.state);
            let held = held_labels();
            // Must be B→A→C order
            if held != vec!["B:Regions", "A:Tasks", "C:Obligations"] {
                return ConformanceResult::Fail {
                    reason: format!(
                        "Expected ['B:Regions', 'A:Tasks', 'C:Obligations'], got {:?}",
                        held
                    ),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Locks not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_obligation_resolve_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::for_obligation_resolve(&fixture.state);
            let held = held_labels();
            // Must be B→A→C order
            if held != vec!["B:Regions", "A:Tasks", "C:Obligations"] {
                return ConformanceResult::Fail {
                    reason: format!(
                        "Expected ['B:Regions', 'A:Tasks', 'C:Obligations'], got {:?}",
                        held
                    ),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Locks not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    fn test_all_lock_order() -> ConformanceResult {
        if let Some(result) = lock_order_tracking_skip() {
            return result;
        }

        let fixture = ConformanceFixture::new();
        assert_eq!(held_count(), 0, "no locks held before test");

        {
            let _guard = ShardGuard::all(&fixture.state);
            let held = held_labels();
            // Must be B→A→C order
            if held != vec!["B:Regions", "A:Tasks", "C:Obligations"] {
                return ConformanceResult::Fail {
                    reason: format!(
                        "Expected ['B:Regions', 'A:Tasks', 'C:Obligations'], got {:?}",
                        held
                    ),
                };
            }
        }

        if held_count() != 0 {
            return ConformanceResult::Fail {
                reason: format!("Locks not released: {} locks still held", held_count()),
            };
        }

        ConformanceResult::Pass
    }

    // ─── Shard Access Compliance Tests ───

    fn test_tasks_only_shard_access() -> ConformanceResult {
        let fixture = ConformanceFixture::new();
        let guard = ShardGuard::tasks_only(&fixture.state);

        if guard.tasks.is_none() {
            return ConformanceResult::Fail {
                reason: "tasks_only guard missing tasks access".to_string(),
            };
        }
        if guard.regions.is_some() {
            return ConformanceResult::Fail {
                reason: "tasks_only guard should not have regions access".to_string(),
            };
        }
        if guard.obligations.is_some() {
            return ConformanceResult::Fail {
                reason: "tasks_only guard should not have obligations access".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    fn test_regions_only_shard_access() -> ConformanceResult {
        let fixture = ConformanceFixture::new();
        let guard = ShardGuard::regions_only(&fixture.state);

        if guard.regions.is_none() {
            return ConformanceResult::Fail {
                reason: "regions_only guard missing regions access".to_string(),
            };
        }
        if guard.tasks.is_some() {
            return ConformanceResult::Fail {
                reason: "regions_only guard should not have tasks access".to_string(),
            };
        }
        if guard.obligations.is_some() {
            return ConformanceResult::Fail {
                reason: "regions_only guard should not have obligations access".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    fn test_obligations_only_shard_access() -> ConformanceResult {
        let fixture = ConformanceFixture::new();
        let guard = ShardGuard::obligations_only(&fixture.state);

        if guard.obligations.is_none() {
            return ConformanceResult::Fail {
                reason: "obligations_only guard missing obligations access".to_string(),
            };
        }
        if guard.regions.is_some() {
            return ConformanceResult::Fail {
                reason: "obligations_only guard should not have regions access".to_string(),
            };
        }
        if guard.tasks.is_some() {
            return ConformanceResult::Fail {
                reason: "obligations_only guard should not have tasks access".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_spawn_shard_access() -> ConformanceResult {
        let fixture = ConformanceFixture::new();
        let guard = ShardGuard::for_spawn(&fixture.state);

        if guard.regions.is_none() {
            return ConformanceResult::Fail {
                reason: "for_spawn guard missing regions access".to_string(),
            };
        }
        if guard.tasks.is_none() {
            return ConformanceResult::Fail {
                reason: "for_spawn guard missing tasks access".to_string(),
            };
        }
        if guard.obligations.is_some() {
            return ConformanceResult::Fail {
                reason: "for_spawn guard should not have obligations access".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    fn test_for_obligation_shard_access() -> ConformanceResult {
        let fixture = ConformanceFixture::new();
        let guard = ShardGuard::for_obligation(&fixture.state);

        if guard.regions.is_none() {
            return ConformanceResult::Fail {
                reason: "for_obligation guard missing regions access".to_string(),
            };
        }
        if guard.obligations.is_none() {
            return ConformanceResult::Fail {
                reason: "for_obligation guard missing obligations access".to_string(),
            };
        }
        if guard.tasks.is_some() {
            return ConformanceResult::Fail {
                reason: "for_obligation guard should not have tasks access".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    // ─── State Consistency Tests ───

    fn test_root_region_consistency() -> ConformanceResult {
        let fixture = ConformanceFixture::new();

        // Initially no root region
        if fixture.state.root_region().is_some() {
            return ConformanceResult::Fail {
                reason: "root_region should be None initially".to_string(),
            };
        }

        // Set root region
        let region = RegionId::from_arena(ArenaIndex::new(1, 0));
        if !fixture.state.set_root_region(region) {
            return ConformanceResult::Fail {
                reason: "set_root_region should return true on first set".to_string(),
            };
        }

        // Verify it's set
        if fixture.state.root_region() != Some(region) {
            return ConformanceResult::Fail {
                reason: "root_region should return the set value".to_string(),
            };
        }

        // Second set should fail
        let region2 = RegionId::from_arena(ArenaIndex::new(2, 0));
        if fixture.state.set_root_region(region2) {
            return ConformanceResult::Fail {
                reason: "set_root_region should return false on second set".to_string(),
            };
        }

        // Value should be unchanged
        if fixture.state.root_region() != Some(region) {
            return ConformanceResult::Fail {
                reason: "root_region should be unchanged after failed second set".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    fn test_leak_count_consistency() -> ConformanceResult {
        let fixture = ConformanceFixture::new();

        // Initially zero
        if fixture.state.leak_count() != 0 {
            return ConformanceResult::Fail {
                reason: "leak_count should be 0 initially".to_string(),
            };
        }

        // Increment and verify
        let new_count = fixture.state.increment_leak_count();
        if new_count != 1 {
            return ConformanceResult::Fail {
                reason: format!("increment_leak_count should return 1, got {}", new_count),
            };
        }

        if fixture.state.leak_count() != 1 {
            return ConformanceResult::Fail {
                reason: "leak_count should be 1 after increment".to_string(),
            };
        }

        // Multiple increments
        for i in 2..=10 {
            let count = fixture.state.increment_leak_count();
            if count != i {
                return ConformanceResult::Fail {
                    reason: format!("increment_leak_count should return {}, got {}", i, count),
                };
            }
        }

        if fixture.state.leak_count() != 10 {
            return ConformanceResult::Fail {
                reason: "leak_count should be 10 after 10 increments".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    fn test_current_time_consistency() -> ConformanceResult {
        let fixture = ConformanceFixture::new();

        // Initially zero
        if fixture.state.current_time() != Time::ZERO {
            return ConformanceResult::Fail {
                reason: "current_time should be Time::ZERO initially".to_string(),
            };
        }

        // Set time and verify
        let new_time = Time::from_nanos(42_000_000);
        fixture.state.set_time(new_time);

        if fixture.state.current_time() != new_time {
            return ConformanceResult::Fail {
                reason: "current_time should return the set value".to_string(),
            };
        }

        ConformanceResult::Pass
    }

    // ─── Deadlock Prevention Tests ───

    fn test_concurrent_guard_acquisition() -> ConformanceResult {
        let fixture = Arc::new(ConformanceFixture::new());
        let barrier = Arc::new(Barrier::new(4)); // 4 threads
        let mut handles = vec![];

        // Thread 1: tasks_only
        let fixture1 = Arc::clone(&fixture);
        let barrier1 = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier1.wait();
            for _ in 0..100 {
                let _guard = ShardGuard::tasks_only(&fixture1.state);
                thread::sleep(Duration::from_micros(10));
            }
        }));

        // Thread 2: regions_only
        let fixture2 = Arc::clone(&fixture);
        let barrier2 = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier2.wait();
            for _ in 0..100 {
                let _guard = ShardGuard::regions_only(&fixture2.state);
                thread::sleep(Duration::from_micros(10));
            }
        }));

        // Thread 3: for_spawn (B→A)
        let fixture3 = Arc::clone(&fixture);
        let barrier3 = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier3.wait();
            for _ in 0..50 {
                let _guard = ShardGuard::for_spawn(&fixture3.state);
                thread::sleep(Duration::from_micros(20));
            }
        }));

        // Thread 4: for_obligation (B→C)
        let fixture4 = Arc::clone(&fixture);
        let barrier4 = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier4.wait();
            for _ in 0..50 {
                let _guard = ShardGuard::for_obligation(&fixture4.state);
                thread::sleep(Duration::from_micros(20));
            }
        }));

        // Wait for all threads to complete (should not deadlock)
        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();

        for handle in handles {
            if start.elapsed() > timeout {
                return ConformanceResult::Fail {
                    reason: "Concurrent guard acquisition timed out - possible deadlock"
                        .to_string(),
                };
            }
            if let Err(e) = handle.join() {
                return ConformanceResult::Fail {
                    reason: format!("Thread panicked: {:?}", e),
                };
            }
        }

        ConformanceResult::Pass
    }

    fn test_stress_concurrency() -> ConformanceResult {
        let fixture = Arc::new(ConformanceFixture::new());
        let barrier = Arc::new(Barrier::new(8)); // 8 threads for stress
        let mut handles = vec![];

        // Higher contention stress test
        for i in 0..8 {
            let fixture_clone = Arc::clone(&fixture);
            let barrier_clone = Arc::clone(&barrier);

            handles.push(thread::spawn(move || {
                barrier_clone.wait();

                for _ in 0..200 {
                    match i % 4 {
                        0 => {
                            let _guard = ShardGuard::tasks_only(&fixture_clone.state);
                        }
                        1 => {
                            let _guard = ShardGuard::regions_only(&fixture_clone.state);
                        }
                        2 => {
                            let _guard = ShardGuard::for_spawn(&fixture_clone.state);
                        }
                        3 => {
                            let _guard = ShardGuard::for_task_completed(&fixture_clone.state);
                        }
                        _ => unreachable!(),
                    }

                    // Interleave atomic operations
                    fixture_clone.state.increment_leak_count();
                    fixture_clone
                        .state
                        .set_time(Time::from_nanos(42 + i as u64));
                }
            }));
        }

        // Stress test timeout
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();

        for handle in handles {
            if start.elapsed() > timeout {
                return ConformanceResult::Fail {
                    reason: "Stress test timed out - possible deadlock or livelock".to_string(),
                };
            }
            if let Err(e) = handle.join() {
                return ConformanceResult::Fail {
                    reason: format!("Stress test thread panicked: {:?}", e),
                };
            }
        }

        ConformanceResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_sharded_state_conformance_suite() {
        let (passed, failed) = ShardedStateConformanceSuite::run_all();
        assert_eq!(failed, 0, "All conformance tests must pass");
        assert!(passed > 15, "Expected at least 15 conformance tests");
    }

    #[test]
    fn conformance_fixture_basic() {
        let fixture = ConformanceFixture::new();
        assert_eq!(fixture.state.leak_count(), 0);
        assert_eq!(fixture.state.current_time(), Time::ZERO);
        assert!(fixture.state.root_region().is_none());
    }
}
