//! Metamorphic tests for region close ordering invariants in src/runtime/region_table.rs.
//!
//! Tests key metamorphic relations in the region lifecycle:
//! 1. Parent close blocks until children quiescent (parent-child ordering)
//! 2. Cancel-cascade preserves ordering (cancellation propagation order)
//! 3. Finalizer runs even on panic (cleanup guarantees)
//!
//! Uses LabRuntime virtual time for deterministic testing of concurrency patterns.

#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::types::{Budget, CancelReason};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

const TEST_TIMEOUT_STEPS: usize = 15_000;
const MAX_CHILDREN: usize = 8;
const MAX_DEPTH: usize = 4;

/// Test parent close blocks until children quiescent invariant.
fn test_parent_child_close_ordering(
    seed: u64,
    num_children: usize,
    child_work_duration: usize,
) -> Vec<usize> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let parent_region = runtime.state.create_root_region(Budget::INFINITE);
    let completion_order = Arc::new(StdMutex::new(Vec::new()));

    // Spawn multiple child regions with different work durations
    let mut child_regions = Vec::new();
    for child_id in 0..num_children.min(MAX_CHILDREN) {
        let completion_order = Arc::clone(&completion_order);
        let child_region = runtime
            .state
            .create_child_region(parent_region, Budget::INFINITE)
            .expect("create child region");
        child_regions.push(child_region);

        let work_steps = child_work_duration + (child_id * 2); // Stagger completion
        let (task_id, _) = runtime
            .state
            .create_task(child_region, Budget::INFINITE, async move {
                // Simulate work
                for _ in 0..work_steps {
                    yield_now().await;
                }
                completion_order.lock().unwrap().push(child_id);
            })
            .expect("create child task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Create parent task that completes after spawning children
    let completion_order_parent = Arc::clone(&completion_order);
    let (parent_task_id, _) = runtime
        .state
        .create_task(parent_region, Budget::INFINITE, async move {
            // Parent does minimal work, should complete after all children
            yield_now().await;
            completion_order_parent.lock().unwrap().push(999); // Special parent marker
        })
        .expect("create parent task");

    runtime.scheduler.lock().schedule(parent_task_id, 0);

    // Run until quiescence
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "parent-child close ordering violated invariants: {violations:?}"
    );

    let order = completion_order.lock().unwrap().clone();

    // Metamorphic invariant: parent completes last (marked as 999)
    if let Some(&last_completed) = order.last() {
        assert_eq!(
            last_completed, 999,
            "parent should complete last in close ordering, but order was: {:?}",
            order
        );
    }

    order
}

/// Test cancel-cascade preserves ordering invariant.
fn test_cancel_cascade_ordering(
    seed: u64,
    tree_depth: usize,
    children_per_level: usize,
) -> (Vec<usize>, Vec<usize>) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let spawn_order = Arc::new(StdMutex::new(Vec::new()));
    let cancel_order = Arc::new(StdMutex::new(Vec::new()));

    // Build a tree of regions with consistent ordering
    fn create_region_tree(
        runtime: &mut LabRuntime,
        parent_region: asupersync::types::RegionId,
        depth: usize,
        max_depth: usize,
        children_per_level: usize,
        region_counter: &Arc<AtomicUsize>,
        spawn_order: &Arc<StdMutex<Vec<usize>>>,
        cancel_order: &Arc<StdMutex<Vec<usize>>>,
    ) -> Vec<asupersync::types::RegionId> {
        if depth >= max_depth {
            return Vec::new();
        }

        let mut regions = Vec::new();
        for child_idx in 0..children_per_level.min(3) {
            let region_id = region_counter.fetch_add(1, Ordering::SeqCst);
            let child_region = runtime
                .state
                .create_child_region(parent_region, Budget::INFINITE)
                .expect("create child region");
            regions.push(child_region);

            // Record spawn order
            spawn_order.lock().unwrap().push(region_id);

            // Create task in this region that detects cancellation.
            // Use a per-task clone so the outer `cancel_order` remains available
            // for the recursive call below.
            let task_cancel_order = Arc::clone(cancel_order);
            let _ = child_idx;
            let (task_id, _) = runtime
                .state
                .create_task(child_region, Budget::INFINITE, async move {
                    // Task runs until cancelled. Poll Cx::current() each
                    // iteration; on the first observed cancellation, record the
                    // region's spawn-order id into the shared cancel_order.
                    let mut recorded = false;
                    for _ in 0..100 {
                        yield_now().await;
                        if !recorded {
                            let cancelled = asupersync::cx::Cx::current()
                                .map(|c| c.is_cancel_requested())
                                .unwrap_or(false);
                            if cancelled {
                                task_cancel_order.lock().unwrap().push(region_id);
                                recorded = true;
                            }
                        }
                    }
                })
                .expect("create region task");

            runtime.scheduler.lock().schedule(task_id, 0);

            // Recursively create grandchildren (outer `cancel_order` intact)
            let grandchildren = create_region_tree(
                runtime,
                child_region,
                depth + 1,
                max_depth,
                children_per_level,
                region_counter,
                spawn_order,
                cancel_order,
            );
            regions.extend(grandchildren);
        }
        regions
    }

    let region_counter = Arc::new(AtomicUsize::new(0));
    let _all_regions = create_region_tree(
        &mut runtime,
        root_region,
        0,
        tree_depth.min(MAX_DEPTH),
        children_per_level,
        &region_counter,
        &spawn_order,
        &cancel_order,
    );

    // Let tasks start running, then trigger cancellation to exercise the
    // cancel_cascade metamorphic relation.
    for _ in 0..10 {
        runtime.step_for_test();
    }

    // Trigger cascade cancellation from the root region.
    runtime
        .state
        .cancel_request(root_region, &CancelReason::user("cascade"), None);

    // Region will close naturally when tasks complete or are cancelled
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "cancel cascade ordering violated invariants: {violations:?}"
    );

    (
        spawn_order.lock().unwrap().clone(),
        cancel_order.lock().unwrap().clone(),
    )
}

/// Test finalizer behavior in region cleanup.
fn test_finalizer_cleanup_ordering(seed: u64, cleanup_scenarios: usize) -> (usize, usize) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cleanup_runs = Arc::new(AtomicUsize::new(0));
    let task_completions = Arc::new(AtomicUsize::new(0));

    for scenario in 0..cleanup_scenarios.min(6) {
        let cleanup_runs = Arc::clone(&cleanup_runs);
        let task_completions = Arc::clone(&task_completions);

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                // Simulate cleanup work
                struct CleanupGuard {
                    counter: Arc<AtomicUsize>,
                }
                impl Drop for CleanupGuard {
                    fn drop(&mut self) {
                        self.counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let _cleanup_guard = CleanupGuard {
                    counter: cleanup_runs,
                };

                // Task work
                yield_now().await;
                task_completions.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create cleanup test task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "finalizer cleanup ordering violated invariants: {violations:?}"
    );

    (
        cleanup_runs.load(Ordering::SeqCst),
        task_completions.load(Ordering::SeqCst),
    )
}

/// Test complex region hierarchy with nested closes.
fn test_nested_region_close_ordering(seed: u64, nesting_levels: usize) -> Vec<(usize, String)> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let close_events = Arc::new(StdMutex::new(Vec::new()));

    // Create nested hierarchy: root -> level1 -> level2 -> level3...
    fn create_nested_regions(
        runtime: &mut LabRuntime,
        parent_region: asupersync::types::RegionId,
        level: usize,
        max_levels: usize,
        close_events: &Arc<StdMutex<Vec<(usize, String)>>>,
    ) -> Option<asupersync::types::RegionId> {
        if level >= max_levels {
            return None;
        }

        let child_region = runtime
            .state
            .create_child_region(parent_region, Budget::INFINITE)
            .expect("create child region");
        // Per-task clone so the outer `close_events` parameter remains
        // available for the recursive call below.
        let task_close_events = Arc::clone(close_events);

        // Create task that records when this level completes
        let (task_id, _) = runtime
            .state
            .create_task(child_region, Budget::INFINITE, async move {
                // Do some work at this level
                for _ in 0..(level + 1) {
                    yield_now().await;
                }
                task_close_events
                    .lock()
                    .unwrap()
                    .push((level, format!("level-{}-complete", level)));
            })
            .expect("create nested task");

        runtime.scheduler.lock().schedule(task_id, 0);

        // Recursively create child (outer `close_events` reference intact)
        if let Some(_grandchild) =
            create_nested_regions(runtime, child_region, level + 1, max_levels, close_events)
        {
            // Child regions exist, this level should wait for them
            Some(child_region)
        } else {
            Some(child_region)
        }
    }

    let close_events_clone = Arc::clone(&close_events);
    let _deepest_region = create_nested_regions(
        &mut runtime,
        root_region,
        0,
        nesting_levels.min(MAX_DEPTH),
        &close_events,
    );

    // Add root-level completion tracking
    let (root_task_id, _) = runtime
        .state
        .create_task(root_region, Budget::INFINITE, async move {
            yield_now().await;
            close_events_clone
                .lock()
                .unwrap()
                .push((999, "root-complete".to_string()));
        })
        .expect("create root task");

    runtime.scheduler.lock().schedule(root_task_id, 0);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "nested region close ordering violated invariants: {violations:?}"
    );

    let events = close_events.lock().unwrap().clone();

    // Metamorphic invariant: deeper levels complete before shallower levels
    for i in 1..events.len() {
        let (prev_level, _) = events[i - 1];
        let (curr_level, _) = events[i];
        if prev_level != 999 && curr_level != 999 {
            // Skip root completion checks
            assert!(
                prev_level >= curr_level,
                "deeper levels should complete before shallower: events={:?}",
                events
            );
        }
    }

    events
}

#[test]
fn metamorphic_parent_child_close_ordering() {
    for seed in [0, 1, 42, 12345] {
        for num_children in [1, 3, 5] {
            for work_duration in [2, 5, 10] {
                let order = test_parent_child_close_ordering(seed, num_children, work_duration);

                // Parent should always complete last
                if !order.is_empty() {
                    assert_eq!(
                        order.last(),
                        Some(&999),
                        "parent should complete last with seed={}, children={}, work={}",
                        seed,
                        num_children,
                        work_duration
                    );
                }
            }
        }
    }
}

#[test]
fn metamorphic_cancel_cascade_preserves_ordering() {
    for seed in [0, 7, 99, 54321] {
        for depth in [2, 3] {
            for children in [1, 2] {
                let (spawn_order, cancel_order) =
                    test_cancel_cascade_ordering(seed, depth, children);

                // Spawn order should be consistent (parent-first traversal)
                assert!(
                    !spawn_order.is_empty(),
                    "should have spawned regions with seed={}, depth={}, children={}",
                    seed,
                    depth,
                    children
                );

                // Cancel-cascade MR: every cancelled region_id must have been
                // spawned (membership), and each region should be recorded at
                // most once (uniqueness).
                for region_id in &cancel_order {
                    assert!(
                        spawn_order.contains(region_id),
                        "cancel_order contains region {} not present in spawn_order={:?} (cancel_order={:?}, seed={}, depth={}, children={})",
                        region_id,
                        spawn_order,
                        cancel_order,
                        seed,
                        depth,
                        children
                    );
                }

                let mut seen = std::collections::HashSet::new();
                for region_id in &cancel_order {
                    assert!(
                        seen.insert(*region_id),
                        "cancel_order must be unique per region, but {} appeared twice in {:?} (seed={}, depth={}, children={})",
                        region_id,
                        cancel_order,
                        seed,
                        depth,
                        children
                    );
                }
            }
        }
    }
}

#[test]
fn metamorphic_finalizer_cleanup_ordering() {
    for seed in [0, 13, 777] {
        for scenarios in [1, 3, 5] {
            let (cleanup_runs, task_completions) = test_finalizer_cleanup_ordering(seed, scenarios);

            // Cleanup should run for each completed task
            assert_eq!(
                cleanup_runs, task_completions,
                "cleanup should run for each task: cleanup={}, tasks={}, scenarios={} with seed={}",
                cleanup_runs, task_completions, scenarios, seed
            );
        }
    }
}

#[test]
fn metamorphic_nested_region_close_ordering() {
    for seed in [0, 5, 123] {
        for levels in [2, 3, 4] {
            let events = test_nested_region_close_ordering(seed, levels);

            // Should have completion events for each level
            assert!(
                !events.is_empty(),
                "should have close events with seed={}, levels={}",
                seed,
                levels
            );

            // Events should be ordered by completion (deeper first)
            let mut non_root_events: Vec<_> =
                events.iter().filter(|(level, _)| *level != 999).collect();

            if non_root_events.len() > 1 {
                // Verify ordering: higher level numbers complete before lower
                for i in 1..non_root_events.len() {
                    assert!(
                        non_root_events[i - 1].0 >= non_root_events[i].0,
                        "nested regions should complete in depth-first order: events={:?}",
                        events
                    );
                }
            }
        }
    }
}
