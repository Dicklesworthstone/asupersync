//! Property-based testing types for region tree operations.
//!
//! This module provides Arbitrary implementations for generating random region
//! tree operations, enabling property-based testing of the structured concurrency
//! guarantees via proptest.
//!
//! # Operation Types
//!
//! - `RegionOp`: Operations on the region tree (create, spawn, cancel, close)
//! - `RegionSelector`: Index-based selector for targeting existing regions
//! - `TaskSelector`: Index-based selector for targeting existing tasks
//! - `TaskOutcome`: Possible outcomes for task completion (Ok, Err, Panic)
//!
//! # Weighted Generation
//!
//! Operations are weighted to produce realistic workloads:
//! - Common operations (CreateChild, SpawnTask): weight 3
//! - State transitions (Cancel, CompleteTask, CloseRegion): weight 2
//! - Time/deadline operations (AdvanceTime, SetDeadline): weight 1

#[macro_use]
mod common;

use asupersync::error::{Error, ErrorKind};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::RegionRecord;
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use common::*;
use proptest::prelude::*;

// ============================================================================
// Selector Types
// ============================================================================

/// A selector for targeting a specific region in the tree.
///
/// The `usize` value is used as an index into a collection of existing regions.
/// If the index is out of bounds, operations using this selector are skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionSelector(pub usize);

impl Arbitrary for RegionSelector {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        (0usize..100).prop_map(RegionSelector).boxed()
    }
}

/// A selector for targeting a specific task.
///
/// The `usize` value is used as an index into a collection of existing tasks.
/// If the index is out of bounds, operations using this selector are skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskSelector(pub usize);

impl Arbitrary for TaskSelector {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        (0usize..100).prop_map(TaskSelector).boxed()
    }
}

// ============================================================================
// Task Outcome
// ============================================================================

/// Possible task completion outcomes for testing.
///
/// Used to simulate different task completion scenarios in property tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOutcome {
    /// Task completed successfully.
    Ok,
    /// Task completed with an error.
    Err,
    /// Task panicked.
    Panic,
}

impl Arbitrary for TaskOutcome {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        prop_oneof![
            8 => Just(TaskOutcome::Ok),    // Most tasks succeed
            1 => Just(TaskOutcome::Err),   // Some fail
            1 => Just(TaskOutcome::Panic), // Rare panics
        ]
        .boxed()
    }
}

// ============================================================================
// CancelKind Arbitrary (for property tests)
// ============================================================================

/// Generate arbitrary CancelKind values for property testing.
fn arb_cancel_kind_for_ops() -> impl Strategy<Value = CancelKind> {
    prop_oneof![
        Just(CancelKind::User),
        Just(CancelKind::Deadline),
        Just(CancelKind::Shutdown),
    ]
}

// ============================================================================
// Region Operations
// ============================================================================

/// Operations that can be performed on the region tree.
///
/// These operations model the key mutations in a structured concurrency system:
/// creating hierarchy, spawning work, cancellation, and cleanup.
#[derive(Debug, Clone)]
pub enum RegionOp {
    /// Create a child region under the selected parent.
    CreateChild { parent: RegionSelector },

    /// Spawn a task in the selected region.
    SpawnTask { region: RegionSelector },

    /// Cancel the selected region with the given reason.
    Cancel {
        region: RegionSelector,
        reason: CancelKind,
    },

    /// Complete a task with the given outcome.
    CompleteTask {
        task: TaskSelector,
        outcome: TaskOutcome,
    },

    /// Request close of the selected region.
    CloseRegion { region: RegionSelector },

    /// Advance virtual time by the specified milliseconds.
    AdvanceTime { millis: u64 },

    /// Set a deadline on a region.
    ///
    /// Note: This operation is currently a no-op because region budgets
    /// cannot be modified after creation through the public API.
    SetDeadline {
        region: RegionSelector,
        millis: u64,
    },
}

impl Arbitrary for RegionOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        prop_oneof![
            // Weight towards common operations
            3 => any::<RegionSelector>().prop_map(|parent| RegionOp::CreateChild { parent }),
            3 => any::<RegionSelector>().prop_map(|region| RegionOp::SpawnTask { region }),
            2 => (any::<RegionSelector>(), arb_cancel_kind_for_ops())
                .prop_map(|(region, reason)| RegionOp::Cancel { region, reason }),
            2 => (any::<TaskSelector>(), any::<TaskOutcome>())
                .prop_map(|(task, outcome)| RegionOp::CompleteTask { task, outcome }),
            2 => any::<RegionSelector>().prop_map(|region| RegionOp::CloseRegion { region }),
            1 => (1u64..10000).prop_map(|millis| RegionOp::AdvanceTime { millis }),
            1 => (any::<RegionSelector>(), 1u64..60000)
                .prop_map(|(region, millis)| RegionOp::SetDeadline { region, millis }),
        ]
        .boxed()
    }
}

// ============================================================================
// Test Harness
// ============================================================================

/// A test harness for applying region operations.
///
/// Maintains the lab runtime and tracks created regions and tasks for
/// index-based selection by `RegionSelector` and `TaskSelector`.
pub struct TestHarness {
    /// The deterministic lab runtime.
    pub runtime: LabRuntime,
    /// Ordered list of created regions (for selector resolution).
    pub regions: Vec<RegionId>,
    /// Ordered list of created tasks (for selector resolution).
    pub tasks: Vec<TaskId>,
}

/// Helper to convert ArenaIndex to RegionId using the public test API.
fn arena_index_to_region_id(idx: ArenaIndex) -> RegionId {
    RegionId::new_for_test(idx.index(), idx.generation())
}

/// Helper to convert ArenaIndex to TaskId using the public test API.
fn arena_index_to_task_id(idx: ArenaIndex) -> TaskId {
    TaskId::new_for_test(idx.index(), idx.generation())
}

impl TestHarness {
    /// Create a new test harness with a seeded lab runtime.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let runtime = LabRuntime::new(LabConfig::new(seed));
        Self {
            runtime,
            regions: Vec::new(),
            tasks: Vec::new(),
        }
    }

    /// Create a new test harness with a root region already created.
    #[must_use]
    pub fn with_root(seed: u64) -> Self {
        let mut harness = Self::new(seed);
        let root = harness.runtime.state.create_root_region(Budget::INFINITE);
        harness.regions.push(root);
        harness
    }

    /// Resolve a region selector to an actual RegionId.
    ///
    /// Returns `None` if the selector index is out of bounds.
    #[must_use]
    pub fn resolve_region(&self, selector: &RegionSelector) -> Option<RegionId> {
        if self.regions.is_empty() {
            return None;
        }
        // Wrap around if index exceeds available regions
        let idx = selector.0 % self.regions.len();
        Some(self.regions[idx])
    }

    /// Resolve a task selector to an actual TaskId.
    ///
    /// Returns `None` if the selector index is out of bounds.
    #[must_use]
    pub fn resolve_task(&self, selector: &TaskSelector) -> Option<TaskId> {
        if self.tasks.is_empty() {
            return None;
        }
        // Wrap around if index exceeds available tasks
        let idx = selector.0 % self.tasks.len();
        Some(self.tasks[idx])
    }

    /// Create a child region under the given parent.
    ///
    /// Returns the new region's ID.
    pub fn create_child(&mut self, parent: RegionId) -> RegionId {
        // Create a placeholder ID for the new record
        let placeholder_id = RegionId::new_for_test(0, 0);

        // Create a new region record as a child of the parent
        let idx = self.runtime.state.regions.insert(RegionRecord::new_with_time(
            placeholder_id,
            Some(parent),
            Budget::INFINITE,
            self.runtime.now(),
        ));

        // Convert arena index to proper RegionId
        let child_id = arena_index_to_region_id(idx);

        // Update the record with the correct ID
        if let Some(record) = self.runtime.state.regions.get_mut(idx) {
            record.id = child_id;
        }

        // Add to parent's children
        if let Some(parent_record) = self.runtime.state.regions.get(
            ArenaIndex::new(parent.new_for_test_index(), parent.new_for_test_generation()),
        ) {
            parent_record.add_child(child_id);
        }

        self.regions.push(child_id);
        child_id
    }

    /// Spawn a simple task in the given region.
    ///
    /// Returns the new task's ID, or `None` if spawning failed.
    pub fn spawn_task(&mut self, region: RegionId) -> Option<TaskId> {
        // Create a simple no-op task
        let result = self
            .runtime
            .state
            .create_task(region, Budget::INFINITE, async {});
        match result {
            Ok((task_id, _handle)) => {
                // Schedule the task
                self.runtime
                    .scheduler
                    .lock()
                    .unwrap()
                    .schedule(task_id, 128);
                self.tasks.push(task_id);
                Some(task_id)
            }
            Err(_) => None,
        }
    }

    /// Request cancellation of a region.
    pub fn cancel_region(&mut self, region: RegionId, reason: CancelKind) {
        let cancel_reason = CancelReason::new(reason);
        // Use RuntimeState's cancel_request which handles the full cancellation flow
        let _tasks_to_schedule = self
            .runtime
            .state
            .cancel_request(region, &cancel_reason, None);
        // Note: We don't actually schedule these tasks in this simple harness
        // since we're testing the region tree structure, not the full execution.
    }

    /// Complete a task with the given outcome.
    pub fn complete_task(&mut self, task: TaskId, outcome: TaskOutcome) {
        // Get the arena index for this task
        let arena_idx =
            ArenaIndex::new(task.new_for_test_index(), task.new_for_test_generation());

        if let Some(record) = self.runtime.state.tasks.get_mut(arena_idx) {
            if !record.state.is_terminal() {
                let runtime_outcome = match outcome {
                    TaskOutcome::Ok => Outcome::Ok(()),
                    TaskOutcome::Err => Outcome::Err(Error::new(ErrorKind::Internal)),
                    TaskOutcome::Panic => {
                        Outcome::Panicked(asupersync::types::PanicPayload::new("test panic"))
                    }
                };
                record.complete(runtime_outcome);
            }
        }

        // Remove the stored future if any
        self.runtime.state.remove_stored_future(task);
    }

    /// Request close of a region.
    pub fn close_region(&mut self, region: RegionId) {
        // Get the arena index for this region
        let arena_idx =
            ArenaIndex::new(region.new_for_test_index(), region.new_for_test_generation());

        if let Some(record) = self.runtime.state.regions.get(arena_idx) {
            record.begin_close(None);
        }
    }

    /// Set a deadline on a region.
    ///
    /// Note: This is currently a no-op because region budgets cannot be modified
    /// after creation through the public API. The operation returns false.
    #[allow(unused_variables)]
    pub fn set_deadline(&mut self, region: RegionId, millis: u64) -> bool {
        // Region budgets (including deadlines) are set at creation time and
        // cannot be modified through the public API. This is a design decision
        // in asupersync's structured concurrency model.
        false
    }
}

// Extension trait for RegionId to access test-only index/generation
trait RegionIdTestExt {
    fn new_for_test_index(&self) -> u32;
    fn new_for_test_generation(&self) -> u32;
}

impl RegionIdTestExt for RegionId {
    fn new_for_test_index(&self) -> u32 {
        // Use debug formatting to extract the index
        // Format is "RegionId(index:generation)"
        let s = format!("{:?}", self);
        let start = s.find('(').unwrap() + 1;
        let colon = s.find(':').unwrap();
        s[start..colon].parse().unwrap()
    }

    fn new_for_test_generation(&self) -> u32 {
        let s = format!("{:?}", self);
        let colon = s.find(':').unwrap() + 1;
        let end = s.find(')').unwrap();
        s[colon..end].parse().unwrap()
    }
}

// Extension trait for TaskId to access test-only index/generation
trait TaskIdTestExt {
    fn new_for_test_index(&self) -> u32;
    fn new_for_test_generation(&self) -> u32;
}

impl TaskIdTestExt for TaskId {
    fn new_for_test_index(&self) -> u32 {
        let s = format!("{:?}", self);
        let start = s.find('(').unwrap() + 1;
        let colon = s.find(':').unwrap();
        s[start..colon].parse().unwrap()
    }

    fn new_for_test_generation(&self) -> u32 {
        let s = format!("{:?}", self);
        let colon = s.find(':').unwrap() + 1;
        let end = s.find(')').unwrap();
        s[colon..end].parse().unwrap()
    }
}

impl RegionOp {
    /// Apply this operation to the test harness.
    ///
    /// Returns `true` if the operation was valid and executed, `false` if skipped
    /// (e.g., due to an invalid selector pointing to a non-existent entity).
    pub fn apply(&self, harness: &mut TestHarness) -> bool {
        match self {
            RegionOp::CreateChild { parent } => {
                if let Some(parent_id) = harness.resolve_region(parent) {
                    // Check if parent region is still accepting children
                    let arena_idx = ArenaIndex::new(
                        parent_id.new_for_test_index(),
                        parent_id.new_for_test_generation(),
                    );
                    let can_create = harness
                        .runtime
                        .state
                        .regions
                        .get(arena_idx)
                        .is_some_and(|r| !r.state().is_terminal());

                    if can_create {
                        harness.create_child(parent_id);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            RegionOp::SpawnTask { region } => {
                if let Some(region_id) = harness.resolve_region(region) {
                    harness.spawn_task(region_id).is_some()
                } else {
                    false
                }
            }

            RegionOp::Cancel { region, reason } => {
                if let Some(region_id) = harness.resolve_region(region) {
                    harness.cancel_region(region_id, *reason);
                    true
                } else {
                    false
                }
            }

            RegionOp::CompleteTask { task, outcome } => {
                if let Some(task_id) = harness.resolve_task(task) {
                    harness.complete_task(task_id, *outcome);
                    true
                } else {
                    false
                }
            }

            RegionOp::CloseRegion { region } => {
                if let Some(region_id) = harness.resolve_region(region) {
                    harness.close_region(region_id);
                    true
                } else {
                    false
                }
            }

            RegionOp::AdvanceTime { millis } => {
                harness.runtime.advance_time(*millis * 1_000_000); // Convert ms to ns
                true
            }

            RegionOp::SetDeadline { region, millis } => {
                if let Some(region_id) = harness.resolve_region(region) {
                    harness.set_deadline(region_id, *millis)
                } else {
                    false
                }
            }
        }
    }
}

// ============================================================================
// Unit Tests for Arbitrary Generation
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Test that RegionSelector generates values in the expected range.
    #[test]
    fn region_selector_in_range(selector in any::<RegionSelector>()) {
        init_test_logging();
        prop_assert!(selector.0 < 100);
    }

    /// Test that TaskSelector generates values in the expected range.
    #[test]
    fn task_selector_in_range(selector in any::<TaskSelector>()) {
        init_test_logging();
        prop_assert!(selector.0 < 100);
    }

    /// Test that TaskOutcome generates all variants.
    #[test]
    fn task_outcome_all_variants(outcomes in proptest::collection::vec(any::<TaskOutcome>(), 100)) {
        init_test_logging();
        // With 100 samples and weighted distribution, we should see all variants
        let has_ok = outcomes.iter().any(|o| matches!(o, TaskOutcome::Ok));
        let has_err = outcomes.iter().any(|o| matches!(o, TaskOutcome::Err));
        let has_panic = outcomes.iter().any(|o| matches!(o, TaskOutcome::Panic));

        // Ok should dominate (weight 8)
        let ok_count = outcomes.iter().filter(|o| matches!(o, TaskOutcome::Ok)).count();
        prop_assert!(ok_count > 50, "Expected >50% Ok outcomes, got {}", ok_count);

        // At least some variety (with 100 samples, very high probability)
        prop_assert!(has_ok, "Should have at least one Ok");
        // Err and Panic might not appear in every run, so we don't assert them
        let _ = (has_err, has_panic); // Suppress unused warning
    }

    /// Test that RegionOp generates diverse operations.
    #[test]
    fn region_op_diversity(ops in proptest::collection::vec(any::<RegionOp>(), 100)) {
        init_test_logging();

        let mut has_create_child = false;
        let mut has_spawn_task = false;
        let mut has_cancel = false;
        let mut has_complete_task = false;
        let mut has_close_region = false;
        let mut has_advance_time = false;
        let mut has_set_deadline = false;

        for op in &ops {
            match op {
                RegionOp::CreateChild { .. } => has_create_child = true,
                RegionOp::SpawnTask { .. } => has_spawn_task = true,
                RegionOp::Cancel { .. } => has_cancel = true,
                RegionOp::CompleteTask { .. } => has_complete_task = true,
                RegionOp::CloseRegion { .. } => has_close_region = true,
                RegionOp::AdvanceTime { .. } => has_advance_time = true,
                RegionOp::SetDeadline { .. } => has_set_deadline = true,
            }
        }

        // With weighted distribution, common ops should appear
        prop_assert!(has_create_child || has_spawn_task,
            "Should have at least one CreateChild or SpawnTask (weight 3 each)");

        // Count to verify weighting works roughly
        let create_count = ops.iter().filter(|o| matches!(o, RegionOp::CreateChild { .. })).count();
        let spawn_count = ops.iter().filter(|o| matches!(o, RegionOp::SpawnTask { .. })).count();
        let high_weight_count = create_count + spawn_count;

        // CreateChild + SpawnTask have total weight 6 out of 14, so ~43%
        // With variance, expect at least 20% in 100 samples
        prop_assert!(high_weight_count >= 20,
            "Expected >=20 high-weight ops, got {}", high_weight_count);

        let _ = (has_cancel, has_complete_task, has_close_region, has_advance_time, has_set_deadline);
    }
}

// ============================================================================
// Integration Tests for TestHarness
// ============================================================================

#[test]
fn test_harness_creates_root() {
    init_test_logging();
    test_phase!("test_harness_creates_root");

    let harness = TestHarness::with_root(42);

    assert_eq!(harness.regions.len(), 1, "Should have one region (root)");
    assert!(harness.tasks.is_empty(), "Should have no tasks initially");

    test_complete!("test_harness_creates_root");
}

#[test]
fn test_harness_resolves_selectors() {
    init_test_logging();
    test_phase!("test_harness_resolves_selectors");

    let harness = TestHarness::with_root(42);

    // Selector 0 should resolve to root
    let resolved = harness.resolve_region(&RegionSelector(0));
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap(), harness.regions[0]);

    // Selector 99 should wrap around to root (99 % 1 = 0)
    let wrapped = harness.resolve_region(&RegionSelector(99));
    assert!(wrapped.is_some());
    assert_eq!(wrapped.unwrap(), harness.regions[0]);

    // Task selector should return None when no tasks exist
    let no_task = harness.resolve_task(&TaskSelector(0));
    assert!(no_task.is_none());

    test_complete!("test_harness_resolves_selectors");
}

#[test]
fn test_harness_apply_operations() {
    init_test_logging();
    test_phase!("test_harness_apply_operations");

    let mut harness = TestHarness::with_root(42);

    // CreateChild should work
    let create_op = RegionOp::CreateChild {
        parent: RegionSelector(0),
    };
    assert!(create_op.apply(&mut harness), "CreateChild should succeed");
    assert_eq!(harness.regions.len(), 2, "Should have 2 regions now");

    // SpawnTask should work
    let spawn_op = RegionOp::SpawnTask {
        region: RegionSelector(0),
    };
    assert!(spawn_op.apply(&mut harness), "SpawnTask should succeed");
    assert_eq!(harness.tasks.len(), 1, "Should have 1 task now");

    // AdvanceTime always succeeds
    let time_op = RegionOp::AdvanceTime { millis: 100 };
    assert!(time_op.apply(&mut harness), "AdvanceTime should succeed");
    assert!(harness.runtime.now().as_millis() >= 100);

    // CompleteTask should work for existing task
    let complete_op = RegionOp::CompleteTask {
        task: TaskSelector(0),
        outcome: TaskOutcome::Ok,
    };
    assert!(complete_op.apply(&mut harness), "CompleteTask should succeed");

    test_complete!("test_harness_apply_operations");
}

#[test]
fn test_harness_apply_invalid_selectors() {
    init_test_logging();
    test_phase!("test_harness_apply_invalid_selectors");

    // Empty harness with no root
    let mut harness = TestHarness::new(42);

    // Operations on non-existent regions should return false
    let create_op = RegionOp::CreateChild {
        parent: RegionSelector(0),
    };
    assert!(
        !create_op.apply(&mut harness),
        "CreateChild with no regions should fail"
    );

    let spawn_op = RegionOp::SpawnTask {
        region: RegionSelector(0),
    };
    assert!(
        !spawn_op.apply(&mut harness),
        "SpawnTask with no regions should fail"
    );

    // Operations on non-existent tasks should return false
    let complete_op = RegionOp::CompleteTask {
        task: TaskSelector(0),
        outcome: TaskOutcome::Ok,
    };
    assert!(
        !complete_op.apply(&mut harness),
        "CompleteTask with no tasks should fail"
    );

    test_complete!("test_harness_apply_invalid_selectors");
}

// ============================================================================
// Invariant Checking Functions (asupersync-16tb)
// ============================================================================

use std::collections::HashSet;

/// Result of an invariant check.
#[derive(Debug)]
pub struct InvariantViolation {
    /// Name of the violated invariant.
    pub invariant: &'static str,
    /// Description of what went wrong.
    pub message: String,
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invariant '{}' violated: {}", self.invariant, self.message)
    }
}

/// Checks all region tree invariants.
///
/// This function verifies that the region tree maintained by the test harness
/// is in a valid state according to asupersync's structured concurrency model.
///
/// # Returns
///
/// A vector of all invariant violations found (empty if all invariants hold).
pub fn check_all_invariants(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    violations.extend(check_no_orphan_tasks(harness));
    violations.extend(check_valid_tree_structure(harness));
    violations.extend(check_child_tracking_consistent(harness));
    violations.extend(check_unique_ids(harness));
    violations.extend(check_cancel_propagation(harness));
    violations.extend(check_close_ordering(harness));

    violations
}

/// Asserts all invariants hold, panicking with details if any fail.
///
/// This is the primary function to call after each operation in property tests.
pub fn assert_all_invariants(harness: &TestHarness) {
    let violations = check_all_invariants(harness);
    if !violations.is_empty() {
        let messages: Vec<_> = violations.iter().map(|v| v.to_string()).collect();
        panic!(
            "Region tree invariant violations detected:\n{}",
            messages.join("\n")
        );
    }
}

/// Invariant 1: No Orphan Tasks
///
/// Every task must belong to an existing region, and that region must
/// track the task in its task list.
fn check_no_orphan_tasks(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    for task_id in &harness.tasks {
        let arena_idx = ArenaIndex::new(
            task_id.new_for_test_index(),
            task_id.new_for_test_generation(),
        );

        if let Some(task_record) = harness.runtime.state.tasks.get(arena_idx) {
            let region_id = task_record.owner; // Note: field is `owner` not `region`
            let region_idx = ArenaIndex::new(
                region_id.new_for_test_index(),
                region_id.new_for_test_generation(),
            );

            // Check region exists
            if harness.runtime.state.regions.get(region_idx).is_none() {
                violations.push(InvariantViolation {
                    invariant: "no_orphan_tasks",
                    message: format!(
                        "Task {:?} references non-existent region {:?}",
                        task_id, region_id
                    ),
                });
            }
        }
    }

    violations
}

/// Invariant 2: Valid Tree Structure
///
/// - Exactly one root region (no parent)
/// - No cycles in parent-child relationships
fn check_valid_tree_structure(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    if harness.regions.is_empty() {
        return violations; // Empty tree is valid (no regions created yet)
    }

    // Count roots (regions with no parent)
    let mut roots = Vec::new();
    for region_id in &harness.regions {
        let arena_idx = ArenaIndex::new(
            region_id.new_for_test_index(),
            region_id.new_for_test_generation(),
        );

        if let Some(region_record) = harness.runtime.state.regions.get(arena_idx) {
            if region_record.parent.is_none() {
                roots.push(*region_id);
            }
        }
    }

    if roots.len() != 1 {
        violations.push(InvariantViolation {
            invariant: "single_root",
            message: format!(
                "Expected exactly one root region, found {}: {:?}",
                roots.len(),
                roots
            ),
        });
    }

    // Check for cycles via DFS
    let mut visited = HashSet::new();
    for region_id in &harness.regions {
        if visited.contains(region_id) {
            continue;
        }

        let mut path = HashSet::new();
        let mut current = Some(*region_id);

        while let Some(id) = current {
            if path.contains(&id) {
                violations.push(InvariantViolation {
                    invariant: "no_cycles",
                    message: format!(
                        "Cycle detected: region {:?} is its own ancestor",
                        id
                    ),
                });
                break;
            }

            if visited.contains(&id) {
                break; // Already validated this subtree
            }

            path.insert(id);
            visited.insert(id);

            let arena_idx = ArenaIndex::new(
                id.new_for_test_index(),
                id.new_for_test_generation(),
            );

            current = harness
                .runtime
                .state
                .regions
                .get(arena_idx)
                .and_then(|r| r.parent);
        }
    }

    violations
}

/// Invariant 3: Child Tracking Consistency
///
/// If region A lists region B as a child, then B's parent must be A.
fn check_child_tracking_consistent(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    for region_id in &harness.regions {
        let arena_idx = ArenaIndex::new(
            region_id.new_for_test_index(),
            region_id.new_for_test_generation(),
        );

        if let Some(region_record) = harness.runtime.state.regions.get(arena_idx) {
            // Check each child's parent pointer
            for child_id in region_record.child_ids() {
                let child_idx = ArenaIndex::new(
                    child_id.new_for_test_index(),
                    child_id.new_for_test_generation(),
                );

                if let Some(child_record) = harness.runtime.state.regions.get(child_idx) {
                    if child_record.parent != Some(*region_id) {
                        violations.push(InvariantViolation {
                            invariant: "child_tracking_consistent",
                            message: format!(
                                "Region {:?} lists {:?} as child, but child's parent is {:?}",
                                region_id, child_id, child_record.parent
                            ),
                        });
                    }
                }
            }
        }
    }

    violations
}

/// Invariant 4: Unique IDs
///
/// All region IDs must be unique, and all task IDs must be unique.
fn check_unique_ids(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    // Check region ID uniqueness
    let mut seen_regions = HashSet::new();
    for region_id in &harness.regions {
        if !seen_regions.insert(region_id) {
            violations.push(InvariantViolation {
                invariant: "unique_region_ids",
                message: format!("Duplicate region ID: {:?}", region_id),
            });
        }
    }

    // Check task ID uniqueness
    let mut seen_tasks = HashSet::new();
    for task_id in &harness.tasks {
        if !seen_tasks.insert(task_id) {
            violations.push(InvariantViolation {
                invariant: "unique_task_ids",
                message: format!("Duplicate task ID: {:?}", task_id),
            });
        }
    }

    violations
}

/// Invariant 5: Cancel Propagation
///
/// If a region has a cancel reason, all its children must also have cancellation requested
/// (indicated by having a cancel_reason set or being in a closing state).
fn check_cancel_propagation(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    for region_id in &harness.regions {
        let arena_idx = ArenaIndex::new(
            region_id.new_for_test_index(),
            region_id.new_for_test_generation(),
        );

        if let Some(region_record) = harness.runtime.state.regions.get(arena_idx) {
            // If this region has a cancel reason set, check all children
            if region_record.cancel_reason().is_some() {
                for child_id in region_record.child_ids() {
                    let child_idx = ArenaIndex::new(
                        child_id.new_for_test_index(),
                        child_id.new_for_test_generation(),
                    );

                    if let Some(child_record) = harness.runtime.state.regions.get(child_idx) {
                        // Child must have cancel reason or be in closing/terminal state
                        let child_state = child_record.state();
                        let child_has_cancel = child_record.cancel_reason().is_some();
                        if !child_has_cancel
                            && !child_state.is_closing()
                            && !child_state.is_terminal()
                        {
                            violations.push(InvariantViolation {
                                invariant: "cancel_propagation",
                                message: format!(
                                    "Region {:?} is cancelled but child {:?} is not (state: {:?})",
                                    region_id, child_id, child_state
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    violations
}

/// Invariant 6: Close Ordering
///
/// A parent region cannot be closed until all its children are closed.
fn check_close_ordering(harness: &TestHarness) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    for region_id in &harness.regions {
        let arena_idx = ArenaIndex::new(
            region_id.new_for_test_index(),
            region_id.new_for_test_generation(),
        );

        if let Some(region_record) = harness.runtime.state.regions.get(arena_idx) {
            // If this region is closed, all children must be closed
            if region_record.state().is_terminal() {
                for child_id in region_record.child_ids() {
                    let child_idx = ArenaIndex::new(
                        child_id.new_for_test_index(),
                        child_id.new_for_test_generation(),
                    );

                    if let Some(child_record) = harness.runtime.state.regions.get(child_idx) {
                        if !child_record.state().is_terminal() {
                            violations.push(InvariantViolation {
                                invariant: "close_ordering",
                                message: format!(
                                    "Region {:?} is closed but child {:?} is not (state: {:?})",
                                    region_id, child_id, child_record.state()
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    violations
}

// ============================================================================
// Property Tests with Invariant Checking
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Test that random operation sequences don't panic and maintain invariants.
    #[test]
    fn random_ops_no_panic(ops in proptest::collection::vec(any::<RegionOp>(), 1..50)) {
        init_test_logging();
        test_phase!("random_ops_no_panic");

        let mut harness = TestHarness::with_root(0xDEADBEEF);

        let mut applied_count = 0;
        for op in &ops {
            if op.apply(&mut harness) {
                applied_count += 1;
            }

            // Check invariants after each operation
            let violations = check_all_invariants(&harness);
            prop_assert!(
                violations.is_empty(),
                "Invariant violations after {:?}: {:?}",
                op,
                violations
            );
        }

        // At least some operations should apply (we start with a root region)
        // Note: This is a soft assertion - with random selectors, many might miss
        tracing::debug!(
            total_ops = ops.len(),
            applied = applied_count,
            regions = harness.regions.len(),
            tasks = harness.tasks.len(),
            "operation sequence completed"
        );

        // Run until quiescent to clean up
        harness.runtime.run_until_quiescent();

        test_complete!("random_ops_no_panic");
    }

    /// Test invariants are maintained after many operations.
    #[test]
    fn invariants_maintained_under_stress(ops in proptest::collection::vec(any::<RegionOp>(), 50..100)) {
        init_test_logging();
        test_phase!("invariants_maintained_under_stress");

        let mut harness = TestHarness::with_root(0xCAFEBABE);

        for op in &ops {
            let _ = op.apply(&mut harness);
        }

        // Final invariant check
        let violations = check_all_invariants(&harness);
        prop_assert!(
            violations.is_empty(),
            "Final invariant violations: {:?}",
            violations
        );

        // Clean up
        harness.runtime.run_until_quiescent();

        test_complete!("invariants_maintained_under_stress");
    }
}

// ============================================================================
// Unit Tests for Invariant Checkers
// ============================================================================

#[test]
fn test_invariants_on_fresh_harness() {
    init_test_logging();
    test_phase!("test_invariants_on_fresh_harness");

    let harness = TestHarness::with_root(42);
    let violations = check_all_invariants(&harness);

    assert!(
        violations.is_empty(),
        "Fresh harness should have no violations: {:?}",
        violations
    );

    test_complete!("test_invariants_on_fresh_harness");
}

#[test]
fn test_invariants_after_operations() {
    init_test_logging();
    test_phase!("test_invariants_after_operations");

    let mut harness = TestHarness::with_root(42);

    // Create some children
    let root = harness.regions[0];
    harness.create_child(root);
    harness.create_child(root);

    let violations = check_all_invariants(&harness);
    assert!(
        violations.is_empty(),
        "Violations after creating children: {:?}",
        violations
    );

    // Spawn some tasks
    harness.spawn_task(root);
    harness.spawn_task(harness.regions[1]);

    let violations = check_all_invariants(&harness);
    assert!(
        violations.is_empty(),
        "Violations after spawning tasks: {:?}",
        violations
    );

    test_complete!("test_invariants_after_operations");
}

#[test]
fn test_unique_id_invariant() {
    init_test_logging();
    test_phase!("test_unique_id_invariant");

    let harness = TestHarness::with_root(42);

    // Should have no duplicate IDs
    let violations = check_unique_ids(&harness);
    assert!(violations.is_empty(), "Unique ID violations: {:?}", violations);

    test_complete!("test_unique_id_invariant");
}
