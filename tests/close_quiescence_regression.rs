//! Close → Quiescence regression tests (bd-sbi6e).
//!
//! Exercises region close on nested regions with oracle evidence.
//! Validates: Lean theorems close_implies_quiescent,
//! close_quiescence_decomposition, close_children_exist_completed,
//! close_subregions_exist_closed.
//!
//! Cross-references:
//!   - Region close state machine: src/record/region.rs:659-720
//!   - Quiescence check: src/runtime/state.rs:1945-1980
//!   - Obligation drain: src/record/region.rs:502-532

#[macro_use]
mod common;

use asupersync::lab::oracle::{ObligationLeakOracle, QuiescenceOracle, TaskLeakOracle};
use asupersync::record::obligation::ObligationKind;
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use common::*;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn obligation(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Nested Region Close Tests
// Validates: close of parent requires close of all children (Quiescent)
// ============================================================================

/// Single region with tasks: close requires all tasks complete.
/// Validates: close_implies_quiescent — quiescence at close.
#[test]
fn close_single_region_all_tasks_complete() {
    init_test("close_single_region_all_tasks_complete");

    let mut quiescence = QuiescenceOracle::new();
    let mut task_leak = TaskLeakOracle::new();
    let root = region(0);

    quiescence.on_region_create(root, None);

    // Spawn 3 tasks
    for i in 1..=3 {
        let tid = task(i);
        quiescence.on_spawn(tid, root);
        task_leak.on_spawn(tid, root, t(u64::from(i) * 10));
    }

    // All tasks complete
    for i in 1..=3 {
        let tid = task(i);
        quiescence.on_task_complete(tid);
        task_leak.on_complete(tid, t(100 + u64::from(i) * 10));
    }

    // Close region
    quiescence.on_region_close(root, t(200));
    task_leak.on_region_close(root, t(200));

    let q = quiescence.check();
    let tl = task_leak.check(t(200));
    let ok = q.is_ok() && tl.is_ok();
    assert_with_log!(ok, "single region all tasks complete", true, ok);

    test_complete!("close_single_region_all_tasks_complete");
}

/// Nested region: parent has child region, both have tasks.
/// Close order: child tasks → child close → parent tasks → parent close.
/// Validates: close_quiescence_decomposition + allRegionsClosed.
#[test]
fn close_nested_region_child_before_parent() {
    init_test("close_nested_region_child_before_parent");

    let mut quiescence = QuiescenceOracle::new();
    let mut task_leak = TaskLeakOracle::new();

    let parent = region(0);
    let child = region(1);

    // Create parent region, then child
    quiescence.on_region_create(parent, None);
    quiescence.on_region_create(child, Some(parent));

    // Spawn tasks in both regions
    let parent_task = task(1);
    let child_task = task(2);

    quiescence.on_spawn(parent_task, parent);
    task_leak.on_spawn(parent_task, parent, t(10));

    quiescence.on_spawn(child_task, child);
    task_leak.on_spawn(child_task, child, t(20));

    // Child task completes first
    quiescence.on_task_complete(child_task);
    task_leak.on_complete(child_task, t(100));

    // Child region closes (quiescent: its task is complete)
    quiescence.on_region_close(child, t(150));
    task_leak.on_region_close(child, t(150));

    // Parent task completes
    quiescence.on_task_complete(parent_task);
    task_leak.on_complete(parent_task, t(200));

    // Parent region closes (quiescent: task complete + child region closed)
    quiescence.on_region_close(parent, t(250));
    task_leak.on_region_close(parent, t(250));

    let q = quiescence.check();
    let tl = task_leak.check(t(250));
    let ok = q.is_ok() && tl.is_ok();
    assert_with_log!(ok, "nested child before parent", true, ok);

    test_complete!("close_nested_region_child_before_parent");
}

/// Three-level nesting: grandchild → child → root.
/// Validates: close_subregions_exist_closed for recursive structure.
#[test]
fn close_three_level_nesting() {
    init_test("close_three_level_nesting");

    let mut quiescence = QuiescenceOracle::new();
    let mut task_leak = TaskLeakOracle::new();

    let root = region(0);
    let mid = region(1);
    let leaf = region(2);

    quiescence.on_region_create(root, None);
    quiescence.on_region_create(mid, Some(root));
    quiescence.on_region_create(leaf, Some(mid));

    // One task per region
    let t_root = task(1);
    let t_mid = task(2);
    let t_leaf = task(3);

    quiescence.on_spawn(t_root, root);
    task_leak.on_spawn(t_root, root, t(10));
    quiescence.on_spawn(t_mid, mid);
    task_leak.on_spawn(t_mid, mid, t(10));
    quiescence.on_spawn(t_leaf, leaf);
    task_leak.on_spawn(t_leaf, leaf, t(10));

    // Close from bottom up: leaf tasks → leaf close → mid tasks → mid close → root
    quiescence.on_task_complete(t_leaf);
    task_leak.on_complete(t_leaf, t(50));
    quiescence.on_region_close(leaf, t(60));
    task_leak.on_region_close(leaf, t(60));

    quiescence.on_task_complete(t_mid);
    task_leak.on_complete(t_mid, t(100));
    quiescence.on_region_close(mid, t(110));
    task_leak.on_region_close(mid, t(110));

    quiescence.on_task_complete(t_root);
    task_leak.on_complete(t_root, t(200));
    quiescence.on_region_close(root, t(210));
    task_leak.on_region_close(root, t(210));

    let q = quiescence.check();
    let tl = task_leak.check(t(210));
    let ok = q.is_ok() && tl.is_ok();
    assert_with_log!(ok, "three-level nesting close", true, ok);

    test_complete!("close_three_level_nesting");
}

/// Wide tree: root with multiple child regions, each with tasks.
/// Validates: allRegionsClosed across sibling subregions.
#[test]
fn close_wide_tree_siblings() {
    init_test("close_wide_tree_siblings");

    let mut quiescence = QuiescenceOracle::new();
    let mut task_leak = TaskLeakOracle::new();

    let root = region(0);
    quiescence.on_region_create(root, None);

    // Create 4 child regions
    let children: Vec<RegionId> = (1..=4).map(region).collect();
    let child_tasks: Vec<TaskId> = (1..=4).map(task).collect();

    for (i, &child) in children.iter().enumerate() {
        quiescence.on_region_create(child, Some(root));
        quiescence.on_spawn(child_tasks[i], child);
        task_leak.on_spawn(child_tasks[i], child, t(10 * (i as u64 + 1)));
    }

    // Root also has a direct task
    let root_task = task(10);
    quiescence.on_spawn(root_task, root);
    task_leak.on_spawn(root_task, root, t(50));

    // Close children in arbitrary order (2, 4, 1, 3)
    for &idx in &[1usize, 3, 0, 2] {
        quiescence.on_task_complete(child_tasks[idx]);
        task_leak.on_complete(child_tasks[idx], t(100 + 10 * idx as u64));
        quiescence.on_region_close(children[idx], t(150 + 10 * idx as u64));
        task_leak.on_region_close(children[idx], t(150 + 10 * idx as u64));
    }

    // Root task completes, then root closes
    quiescence.on_task_complete(root_task);
    task_leak.on_complete(root_task, t(300));
    quiescence.on_region_close(root, t(350));
    task_leak.on_region_close(root, t(350));

    let q = quiescence.check();
    let tl = task_leak.check(t(350));
    let ok = q.is_ok() && tl.is_ok();
    assert_with_log!(ok, "wide tree siblings close", true, ok);

    test_complete!("close_wide_tree_siblings");
}

// ============================================================================
// Obligation Drain Tests
// Validates: quiescent_no_obligations — ledger empty at close
// ============================================================================

/// Region with obligations: all resolved before close.
/// Validates: close_implies_ledger_empty + obligation drain code path.
#[test]
fn close_obligations_resolved_before_close() {
    init_test("close_obligations_resolved_before_close");

    let mut quiescence = QuiescenceOracle::new();
    let mut task_leak = TaskLeakOracle::new();
    let mut obligation_leak = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);

    quiescence.on_region_create(root, None);
    quiescence.on_spawn(worker, root);
    task_leak.on_spawn(worker, root, t(10));

    // Create obligations
    let ob1 = obligation(1);
    let ob2 = obligation(2);
    obligation_leak.on_create(ob1, ObligationKind::SendPermit, worker, root);
    obligation_leak.on_create(ob2, ObligationKind::SendPermit, worker, root);

    // Resolve both obligations (commit + abort)
    obligation_leak.on_resolve(
        ob1,
        asupersync::record::obligation::ObligationState::Committed,
    );
    obligation_leak.on_resolve(
        ob2,
        asupersync::record::obligation::ObligationState::Aborted,
    );

    // Task completes, region closes
    quiescence.on_task_complete(worker);
    task_leak.on_complete(worker, t(100));
    quiescence.on_region_close(root, t(150));
    task_leak.on_region_close(root, t(150));
    obligation_leak.on_region_close(root, t(150));

    let q = quiescence.check();
    let tl = task_leak.check(t(150));
    let ol = obligation_leak.check(t(150));
    let ok = q.is_ok() && tl.is_ok() && ol.is_ok();
    assert_with_log!(ok, "obligations resolved before close", true, ok);

    test_complete!("close_obligations_resolved_before_close");
}

// ============================================================================
// Negative Tests (Violation Detection)
// Validates: oracle correctly detects quiescence violations
// ============================================================================

/// Attempt to close parent while child region still open → violation.
#[test]
fn close_parent_with_open_child_violates_quiescence() {
    init_test("close_parent_with_open_child_violates_quiescence");

    let mut quiescence = QuiescenceOracle::new();

    let parent = region(0);
    let child = region(1);
    let child_task = task(1);

    quiescence.on_region_create(parent, None);
    quiescence.on_region_create(child, Some(parent));
    quiescence.on_spawn(child_task, child);

    // Close parent without closing child or completing child's task
    quiescence.on_region_close(parent, t(100));

    let result = quiescence.check();
    let is_err = result.is_err();
    assert_with_log!(
        is_err,
        "violation: parent closed with open child",
        true,
        is_err
    );

    test_complete!("close_parent_with_open_child_violates_quiescence");
}

/// Close region with incomplete task → TaskLeakOracle detects violation.
#[test]
fn close_region_with_live_task_violates_leak() {
    init_test("close_region_with_live_task_violates_leak");

    let mut task_leak = TaskLeakOracle::new();
    let root = region(0);
    let worker = task(1);

    task_leak.on_spawn(worker, root, t(10));
    // Task NOT completed
    task_leak.on_region_close(root, t(100));

    let result = task_leak.check(t(100));
    let is_err = result.is_err();
    assert_with_log!(is_err, "violation: live task at close", true, is_err);

    test_complete!("close_region_with_live_task_violates_leak");
}
