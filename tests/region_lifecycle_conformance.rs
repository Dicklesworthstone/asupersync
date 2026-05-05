//! Region lifecycle conformance tests.
//!
//! These tests verify the region lifecycle invariants as specified in
//! asupersync_v4_formal_semantics.md. They cover creation, nesting, closing,
//! and orphan prevention using oracle-based verification.
//!
//! # Spec References
//!
//! - Spec 2.1: Region ownership tree
//! - Spec 2.1.1: Region creation and nesting
//! - Spec 2.1.2: Region close protocol
//! - Spec 2.1.3: Close blocks until all children complete
//! - Spec 2.1.4: No orphan tasks invariant (INV-TREE)
//! - Spec 5: Formal invariants (INV-TREE definition)

#[macro_use]
mod common;

use asupersync::lab::oracle::{
    DeadlineMonotoneOracle, OracleSuite, QuiescenceOracle, RegionTreeOracle, TaskLeakOracle,
};
use asupersync::types::{Budget, RegionId, TaskId, Time};
use common::*;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Region Creation Tests (Spec 2.1.1)
// ============================================================================

/// Validates: Spec 2.1.1 - "A root region can be created"
#[test]
fn region_root_can_be_created() {
    init_test("region_root_can_be_created");

    let mut oracle = RegionTreeOracle::new();
    let root = region(0);

    oracle.on_region_create(root, None, t(0));

    // Verify tree structure is valid
    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "root creation valid", true, ok);

    // Verify root is recognized
    let detected_root = oracle.root();
    assert_with_log!(
        detected_root == Some(root),
        "root detected",
        Some(root),
        detected_root
    );

    test_complete!("region_root_can_be_created");
}

/// Validates: Spec 2.1.1 - "Root region has no parent"
#[test]
fn region_root_has_no_parent() {
    init_test("region_root_has_no_parent");

    let mut oracle = RegionTreeOracle::new();
    let root = region(0);

    oracle.on_region_create(root, None, t(0));

    // Root depth should be 0 (no ancestors)
    let depth = oracle.depth(root);
    assert_with_log!(depth == Some(0), "root depth is 0", Some(0), depth);

    test_complete!("region_root_has_no_parent");
}

// ============================================================================
// Region Nesting Tests (Spec 2.1.1)
// ============================================================================

/// Validates: Spec 2.1.1 - "Child regions can be created under a parent"
#[test]
fn region_child_can_be_created() {
    init_test("region_child_can_be_created");

    let mut oracle = RegionTreeOracle::new();
    let root = region(0);
    let child = region(1);

    oracle.on_region_create(root, None, t(0));
    oracle.on_region_create(child, Some(root), t(10));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "child creation valid", true, ok);

    // Verify child has correct depth
    let child_depth = oracle.depth(child);
    assert_with_log!(
        child_depth == Some(1),
        "child depth is 1",
        Some(1),
        child_depth
    );

    test_complete!("region_child_can_be_created");
}

/// Validates: Spec 2.1.1 - "Regions can be nested multiple levels deep"
#[test]
fn region_deep_nesting() {
    init_test("region_deep_nesting");

    let mut oracle = RegionTreeOracle::new();

    // Create a chain: root -> child -> grandchild -> great_grandchild
    oracle.on_region_create(region(0), None, t(0));
    oracle.on_region_create(region(1), Some(region(0)), t(10));
    oracle.on_region_create(region(2), Some(region(1)), t(20));
    oracle.on_region_create(region(3), Some(region(2)), t(30));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "deep nesting valid", true, ok);

    // Verify depths
    let depth0 = oracle.depth(region(0));
    assert_with_log!(depth0 == Some(0), "root depth", Some(0), depth0);

    let depth1 = oracle.depth(region(1));
    assert_with_log!(depth1 == Some(1), "child depth", Some(1), depth1);

    let depth2 = oracle.depth(region(2));
    assert_with_log!(depth2 == Some(2), "grandchild depth", Some(2), depth2);

    let depth3 = oracle.depth(region(3));
    assert_with_log!(depth3 == Some(3), "great grandchild depth", Some(3), depth3);

    test_complete!("region_deep_nesting");
}

/// Validates: Spec 2.1.1 - "A region can have multiple children (branching tree)"
#[test]
fn region_multiple_children() {
    init_test("region_multiple_children");

    let mut oracle = RegionTreeOracle::new();
    let root = region(0);

    // Create root with three children
    oracle.on_region_create(root, None, t(0));
    oracle.on_region_create(region(1), Some(root), t(10));
    oracle.on_region_create(region(2), Some(root), t(20));
    oracle.on_region_create(region(3), Some(root), t(30));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "multiple children valid", true, ok);

    // All children should have depth 1
    for i in 1..=3 {
        let depth = oracle.depth(region(i));
        assert_with_log!(depth == Some(1), "child depth", Some(1), depth);
    }

    let count = oracle.region_count();
    assert_with_log!(count == 4, "region count", 4, count);

    test_complete!("region_multiple_children");
}

// ============================================================================
// Tree Structure Invariant Tests (INV-TREE from Spec 5)
// ============================================================================

/// Validates: Spec 5 INV-TREE - "Exactly one root region exists"
#[test]
fn inv_tree_single_root() {
    init_test("inv_tree_single_root");

    let mut oracle = RegionTreeOracle::new();

    // Valid: single root with children
    oracle.on_region_create(region(0), None, t(0));
    oracle.on_region_create(region(1), Some(region(0)), t(10));
    oracle.on_region_create(region(2), Some(region(0)), t(20));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "single root valid", true, ok);

    let root = oracle.root();
    assert_with_log!(
        root == Some(region(0)),
        "root is region 0",
        Some(region(0)),
        root
    );

    test_complete!("inv_tree_single_root");
}

/// Validates: Spec 5 INV-TREE - "Multiple roots is a violation"
#[test]
fn inv_tree_multiple_roots_detected() {
    init_test("inv_tree_multiple_roots_detected");

    let mut oracle = RegionTreeOracle::new();

    // Invalid: two roots
    oracle.on_region_create(region(0), None, t(0));
    oracle.on_region_create(region(1), None, t(10)); // Second root!

    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "multiple roots detected", true, is_err);

    match result.unwrap_err() {
        asupersync::lab::oracle::RegionTreeViolation::MultipleRoots { roots } => {
            let count = roots.len();
            assert_with_log!(count == 2, "detected 2 roots", 2, count);
        }
        other => panic!("expected MultipleRoots, got {other:?}"),
    }

    test_complete!("inv_tree_multiple_roots_detected");
}

/// Validates: Spec 5 INV-TREE - "Invalid parent reference is detected"
#[test]
fn inv_tree_invalid_parent_detected() {
    init_test("inv_tree_invalid_parent_detected");

    let mut oracle = RegionTreeOracle::new();

    oracle.on_region_create(region(0), None, t(0));
    // Region 1 claims region 99 as parent, but 99 doesn't exist
    oracle.on_region_create(region(1), Some(region(99)), t(10));

    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "invalid parent detected", true, is_err);

    match result.unwrap_err() {
        asupersync::lab::oracle::RegionTreeViolation::InvalidParent {
            region: r,
            claimed_parent,
        } => {
            assert_with_log!(r == region(1), "region is 1", region(1), r);
            assert_with_log!(
                claimed_parent == region(99),
                "claimed parent is 99",
                region(99),
                claimed_parent
            );
        }
        other => panic!("expected InvalidParent, got {other:?}"),
    }

    test_complete!("inv_tree_invalid_parent_detected");
}

/// Validates: Spec 5 INV-TREE - "No root means violation"
#[test]
fn inv_tree_no_root_detected() {
    init_test("inv_tree_no_root_detected");

    let mut oracle = RegionTreeOracle::new();

    // Create a cycle (no root) - manually construct invalid state
    // Region 0 claims 1 as parent, region 1 claims 0 as parent
    oracle.on_region_create(region(0), Some(region(1)), t(0));
    oracle.on_region_create(region(1), Some(region(0)), t(10));

    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "no root detected", true, is_err);

    test_complete!("inv_tree_no_root_detected");
}

// ============================================================================
// Region Close and Quiescence Tests (Spec 2.1.2, 2.1.3)
// ============================================================================

/// Validates: Spec 2.1.2 - "Region close waits for tasks to complete"
#[test]
fn region_close_waits_for_tasks() {
    init_test("region_close_waits_for_tasks");

    let mut oracle = QuiescenceOracle::new();

    let root = region(0);
    let worker = task(1);

    // Setup: region with task
    oracle.on_region_create(root, None);
    oracle.on_spawn(worker, root);

    // Task must complete before region closes
    oracle.on_task_complete(worker);
    oracle.on_region_close(root, t(100));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "no quiescence violations", true, ok);

    test_complete!("region_close_waits_for_tasks");
}

/// Validates: Spec 2.1.3 - "Region close waits for child regions"
#[test]
fn region_close_waits_for_children() {
    init_test("region_close_waits_for_children");

    let mut oracle = QuiescenceOracle::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);

    // Setup: parent with child region containing a task
    oracle.on_region_create(root, None);
    oracle.on_region_create(child, Some(root));
    oracle.on_spawn(worker, child);

    // Task completes, then child closes, then parent closes
    oracle.on_task_complete(worker);
    oracle.on_region_close(child, t(50));
    oracle.on_region_close(root, t(100));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "proper close order", true, ok);

    test_complete!("region_close_waits_for_children");
}

// ============================================================================
// No Orphan Tasks Tests (Spec 2.1.4)
// ============================================================================

/// Validates: Spec 2.1.4 - "Tasks belong to exactly one region"
#[test]
fn no_orphan_task_belongs_to_region() {
    init_test("no_orphan_task_belongs_to_region");

    let mut oracle = TaskLeakOracle::new();

    let root = region(0);
    let worker = task(1);

    // Task spawned in region and completed before region closes
    oracle.on_spawn(worker, root, t(10));
    oracle.on_complete(worker, t(50));
    oracle.on_region_close(root, t(100));

    let result = oracle.check(t(100));
    let ok = result.is_ok();
    assert_with_log!(ok, "no leaked tasks", true, ok);

    test_complete!("no_orphan_task_belongs_to_region");
}

/// Validates: Spec 2.1.4 - "Task leak is detected when task incomplete at region close"
#[test]
fn no_orphan_task_leak_detected() {
    init_test("no_orphan_task_leak_detected");

    let mut oracle = TaskLeakOracle::new();

    let root = region(0);
    let worker = task(1);

    // Task spawned but NOT completed before region closes
    oracle.on_spawn(worker, root, t(10));
    // Missing: oracle.on_complete(worker, t(50));
    oracle.on_region_close(root, t(100));

    let result = oracle.check(t(100));
    let is_err = result.is_err();
    assert_with_log!(is_err, "task leak detected", true, is_err);

    test_complete!("no_orphan_task_leak_detected");
}

// ============================================================================
// Deadline Monotonicity Tests
// ============================================================================

/// Validates: Spec - "Child region deadline must not exceed parent deadline"
#[test]
fn deadline_child_not_exceeds_parent() {
    init_test("deadline_child_not_exceeds_parent");

    let mut oracle = DeadlineMonotoneOracle::new();

    let root = region(0);
    let child = region(1);

    // Parent has 100ms deadline, child has 50ms (stricter - valid)
    let parent_budget = Budget::new().with_deadline(Time::from_millis(100));
    let child_budget = Budget::new().with_deadline(Time::from_millis(50));

    oracle.on_region_create(root, None, &parent_budget, t(0));
    oracle.on_region_create(child, Some(root), &child_budget, t(10));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "monotone deadlines valid", true, ok);

    test_complete!("deadline_child_not_exceeds_parent");
}

// ============================================================================
// Oracle Suite Integration Tests
// ============================================================================

/// Validates: Spec 5 - "OracleSuite can verify all region invariants"
#[test]
fn oracle_suite_verifies_valid_region_lifecycle() {
    init_test("oracle_suite_verifies_valid_region_lifecycle");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);

    // Record valid lifecycle events
    suite.region_tree.on_region_create(root, None, t(0));
    suite.region_tree.on_region_create(child, Some(root), t(10));

    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child, Some(root));

    suite.task_leak.on_spawn(worker, child, t(20));
    suite.quiescence.on_spawn(worker, child);

    suite.task_leak.on_complete(worker, t(30));
    suite.quiescence.on_task_complete(worker);

    suite.quiescence.on_region_close(child, t(40));
    suite.task_leak.on_region_close(child, t(40));

    suite.quiescence.on_region_close(root, t(50));
    suite.task_leak.on_region_close(root, t(50));

    let violations = suite.check_all(t(60));
    let is_empty = violations.is_empty();
    assert_with_log!(is_empty, "no violations", true, is_empty);

    test_complete!("oracle_suite_verifies_valid_region_lifecycle");
}

/// Validates: Spec 5 - "RegionTreeOracle can verify complex tree structures"
#[test]
fn oracle_verifies_complex_tree_structure() {
    init_test("oracle_verifies_complex_tree_structure");

    let mut oracle = RegionTreeOracle::new();

    // Create a complex tree:
    //          r0 (root)
    //        /    \
    //       r1     r2
    //      /  \     |
    //    r3   r4   r5
    //    |
    //   r6

    oracle.on_region_create(region(0), None, t(0));
    oracle.on_region_create(region(1), Some(region(0)), t(10));
    oracle.on_region_create(region(2), Some(region(0)), t(20));
    oracle.on_region_create(region(3), Some(region(1)), t(30));
    oracle.on_region_create(region(4), Some(region(1)), t(40));
    oracle.on_region_create(region(5), Some(region(2)), t(50));
    oracle.on_region_create(region(6), Some(region(3)), t(60));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "complex tree valid", true, ok);

    let count = oracle.region_count();
    assert_with_log!(count == 7, "7 regions total", 7, count);

    // Verify specific depths
    let depth0 = oracle.depth(region(0));
    assert_with_log!(depth0 == Some(0), "root depth 0", Some(0), depth0);

    let depth6 = oracle.depth(region(6));
    assert_with_log!(depth6 == Some(3), "deepest depth 3", Some(3), depth6);

    test_complete!("oracle_verifies_complex_tree_structure");
}

/// Validates: Spec 2.1 - "Empty regions are valid"
#[test]
fn region_empty_is_valid() {
    init_test("region_empty_is_valid");

    let mut oracle = RegionTreeOracle::new();

    // Create tree with empty regions (no tasks)
    oracle.on_region_create(region(0), None, t(0));
    oracle.on_region_create(region(1), Some(region(0)), t(10));
    oracle.on_region_create(region(2), Some(region(0)), t(20));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "empty regions valid", true, ok);

    test_complete!("region_empty_is_valid");
}

/// Validates: Spec - "Many siblings at same level is valid"
#[test]
fn region_many_siblings() {
    init_test("region_many_siblings");

    let mut oracle = RegionTreeOracle::new();

    oracle.on_region_create(region(0), None, t(0));

    // Create 20 children of root
    for i in 1..=20 {
        oracle.on_region_create(region(i), Some(region(0)), t(u64::from(i) * 10));
    }

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "many siblings valid", true, ok);

    let count = oracle.region_count();
    assert_with_log!(count == 21, "21 regions total", 21, count);

    // All children should have depth 1
    for i in 1..=20 {
        let depth = oracle.depth(region(i));
        assert_with_log!(depth == Some(1), "child depth", Some(1), depth);
    }

    test_complete!("region_many_siblings");
}
