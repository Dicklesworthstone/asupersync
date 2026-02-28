//! Browser scheduler determinism regression tests.
//!
//! These tests validate browser-specific scheduling invariants:
//! - Ready handoff limit enforcement (burst never exceeds limit)
//! - Cancel priority preserved under browser mode
//! - Deterministic dispatch order (same config = same order)
//! - Fairness metrics consistency
//! - Browser profile throughput baselines
//!
//! Run with:
//!   cargo test --test scheduler_browser_determinism --release -- --nocapture

use std::time::Instant;

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::ThreeLaneScheduler;
use asupersync::runtime::scheduler::ThreeLaneWorker;
use asupersync::runtime::scheduler::three_lane::PreemptionMetrics;
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::sync::Arc;

// =============================================================================
// HELPERS
// =============================================================================

fn task(index: u32, generation: u32) -> TaskId {
    TaskId::new_for_test(index, generation)
}

fn region() -> RegionId {
    RegionId::from_arena(ArenaIndex::new(0, 0))
}

fn setup_state(max_task_id: u32) -> Arc<ContendedMutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for i in 0..=max_task_id {
        let id = task(1, i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = state.tasks.insert(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(ContendedMutex::new("runtime_state", state))
}

/// Dispatches all tasks from a single worker, returning the dispatch
/// order and preemption metrics. Handles handoff yields by re-entering.
///
/// The ready-handoff mechanism causes `next_task()` to return `None` when
/// a yield is forced, but the worker still has work. We use a consecutive-
/// None counter to detect true exhaustion (2+ consecutive Nones).
fn dispatch_all(
    worker: &mut ThreeLaneWorker,
    max_steps: usize,
) -> (Vec<TaskId>, PreemptionMetrics) {
    let mut order = Vec::new();
    let mut consecutive_nones = 0u32;

    loop {
        match worker.next_task() {
            Some(tid) => {
                order.push(tid);
                consecutive_nones = 0;
            }
            None => {
                consecutive_nones += 1;
                // A single None can be a handoff yield. Two consecutive
                // Nones means the worker truly has no more work.
                if consecutive_nones >= 2 {
                    break;
                }
                continue;
            }
        }
        if order.len() >= max_steps {
            break;
        }
    }
    let metrics = worker.preemption_metrics().clone();
    (order, metrics)
}

/// Like dispatch_all but tracks consecutive ready bursts.
///
/// A "burst" is a sequence of consecutive dispatches between handoff
/// yields (None returns). Each None boundary starts a new burst.
fn dispatch_tracking_bursts(
    worker: &mut ThreeLaneWorker,
    max_steps: usize,
) -> (Vec<TaskId>, Vec<usize>, PreemptionMetrics) {
    let mut order = Vec::new();
    let mut burst_sizes = Vec::new();
    let mut current_burst = 0usize;
    let mut consecutive_nones = 0u32;

    loop {
        match worker.next_task() {
            Some(tid) => {
                order.push(tid);
                current_burst += 1;
                consecutive_nones = 0;
            }
            None => {
                consecutive_nones += 1;
                if current_burst > 0 {
                    burst_sizes.push(current_burst);
                    current_burst = 0;
                }
                if consecutive_nones >= 2 {
                    break;
                }
                continue;
            }
        }
        if order.len() >= max_steps {
            if current_burst > 0 {
                burst_sizes.push(current_burst);
            }
            break;
        }
    }

    if current_burst > 0 {
        burst_sizes.push(current_burst);
    }

    let metrics = worker.preemption_metrics().clone();
    (order, burst_sizes, metrics)
}

// =============================================================================
// READY HANDOFF LIMIT ENFORCEMENT
// =============================================================================

/// Verifies that with browser_ready_handoff_limit = L, no single
/// ready burst exceeds L consecutive dispatches before a yield.
#[test]
fn browser_ready_handoff_limit_bounds_burst_size() {
    for &limit in &[2usize, 4, 8, 16, 32] {
        let task_count = limit as u32 * 10;
        let state = setup_state(task_count);
        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
        sched.set_browser_ready_handoff_limit(limit);

        for i in 0..task_count {
            sched.inject_ready(task(1, i), 50);
        }

        let mut workers = sched.take_workers().into_iter();
        let mut worker = workers.next().unwrap();
        let (_, burst_sizes, metrics) =
            dispatch_tracking_bursts(&mut worker, task_count as usize + 100);

        // Every burst must be <= limit
        for (idx, &burst) in burst_sizes.iter().enumerate() {
            assert!(
                burst <= limit,
                "limit={limit}: burst[{idx}] = {burst} exceeds limit"
            );
        }

        // Must have had at least one handoff yield
        assert!(
            metrics.browser_ready_handoff_yields > 0,
            "limit={limit}: expected handoff yields, got 0"
        );
    }
}

/// Verifies that handoff limit=0 disables yielding entirely.
#[test]
fn browser_ready_handoff_limit_zero_disables() {
    let task_count = 64u32;
    let state = setup_state(task_count);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
    // Default: browser_ready_handoff_limit = 0

    for i in 0..task_count {
        sched.inject_ready(task(1, i), 50);
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let (order, metrics) = dispatch_all(&mut worker, task_count as usize + 10);

    assert_eq!(
        order.len(),
        task_count as usize,
        "all tasks should dispatch"
    );
    assert_eq!(
        metrics.browser_ready_handoff_yields, 0,
        "limit=0 should produce zero handoff yields"
    );
}

// =============================================================================
// CANCEL PRIORITY PRESERVED IN BROWSER MODE
// =============================================================================

/// With handoff active, cancel tasks must still dispatch before ready tasks.
/// The cancel > timed > ready invariant is non-negotiable.
#[test]
fn browser_cancel_priority_preserved_with_handoff() {
    let state = setup_state(20);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
    sched.set_browser_ready_handoff_limit(4);

    // Inject ready first, then cancel - cancel should still come first
    for i in 0..10u32 {
        sched.inject_ready(task(1, i), 50);
    }
    for i in 10..20u32 {
        sched.inject_cancel(task(1, i), 100);
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let (order, _, metrics) = dispatch_tracking_bursts(&mut worker, 100);

    // All cancel tasks (10-19) should appear before any ready task (0-9)
    // in the dispatch order (modulo fairness yields from cancel streak limit).
    let cancel_ids: Vec<TaskId> = (10..20).map(|i| task(1, i)).collect();
    let first_ready_pos = order.iter().position(|t| !cancel_ids.contains(t));
    let last_cancel_pos = order.iter().rposition(|t| cancel_ids.contains(t));

    if let (Some(first_ready), Some(last_cancel)) = (first_ready_pos, last_cancel_pos) {
        // The cancel_lane_max_streak is 16, and we have 10 cancel tasks,
        // so all cancel tasks should dispatch before any ready task.
        assert!(
            last_cancel < first_ready || metrics.fairness_yields > 0,
            "cancel tasks should dispatch before ready unless fairness yield intervened: \
             first_ready_pos={first_ready}, last_cancel_pos={last_cancel}"
        );
    }
}

/// Cancel injection during a ready burst should preempt the next dispatch.
#[test]
fn browser_cancel_preempts_ready_burst() {
    let state = setup_state(12);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
    sched.set_browser_ready_handoff_limit(100); // High limit so handoff doesn't interfere

    // Load ready tasks
    for i in 0..10u32 {
        sched.inject_ready(task(1, i), 50);
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();

    // Dispatch a few ready tasks
    let first = worker.next_task();
    assert!(first.is_some(), "should dispatch first ready task");

    // Now inject cancel work
    let cancel_id = task(1, 10);
    worker.global.inject_cancel(cancel_id, 100);

    // Next dispatch should be the cancel task
    let next = worker.next_task();
    assert_eq!(next, Some(cancel_id), "cancel should preempt ready burst");
}

// =============================================================================
// DETERMINISTIC DISPATCH ORDER
// =============================================================================

/// The same scheduler configuration and task set must produce the same
/// dispatch order. This is critical for deterministic replay.
#[test]
fn browser_deterministic_dispatch_order() {
    fn dispatch_order(handoff_limit: usize) -> Vec<TaskId> {
        let state = setup_state(63);
        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
        sched.set_browser_ready_handoff_limit(handoff_limit);

        // Mix of cancel and ready work
        for i in 0..16u32 {
            sched.inject_cancel(task(1, i), 100);
        }
        for i in 16..64u32 {
            sched.inject_ready(task(1, i), (i % 32) as u8);
        }

        let mut workers = sched.take_workers().into_iter();
        let mut worker = workers.next().unwrap();
        let (order, _) = dispatch_all(&mut worker, 200);
        order
    }

    // Same config must produce identical ordering
    let run1 = dispatch_order(8);
    let run2 = dispatch_order(8);
    assert_eq!(
        run1, run2,
        "same config must produce identical dispatch order"
    );

    // Different handoff limit produces different ordering
    let run3 = dispatch_order(4);
    // The total dispatched should be the same
    assert_eq!(run1.len(), run3.len(), "total dispatched should match");
    // But the ordering may differ due to handoff yield points
    // (not guaranteed to differ, but the mechanism is different)
}

// =============================================================================
// FAIRNESS METRICS CONSISTENCY
// =============================================================================

/// Metrics must be internally consistent after a dispatch run.
#[test]
fn browser_fairness_metrics_consistent() {
    let task_count = 100u32;
    let state = setup_state(task_count);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
    sched.set_browser_ready_handoff_limit(16);

    let cancel_n = 30u32;

    for i in 0..cancel_n {
        sched.inject_cancel(task(1, i), 100);
    }
    for i in cancel_n..task_count {
        sched.inject_ready(task(1, i), 50);
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let (order, metrics) = dispatch_all(&mut worker, task_count as usize + 50);

    // Total dispatches == cancel + ready + timed + fallback
    let total_metric_dispatches = metrics.cancel_dispatches
        + metrics.ready_dispatches
        + metrics.timed_dispatches
        + metrics.fallback_cancel_dispatches;
    assert_eq!(
        total_metric_dispatches,
        order.len() as u64,
        "metrics dispatch sum must equal actual dispatch count: \
         cancel={}, ready={}, timed={}, fallback={}, actual={}",
        metrics.cancel_dispatches,
        metrics.ready_dispatches,
        metrics.timed_dispatches,
        metrics.fallback_cancel_dispatches,
        order.len()
    );

    // effective_limit_exceedances should be zero for healthy runs
    assert_eq!(
        metrics.effective_limit_exceedances, 0,
        "effective limit should never be exceeded in normal operation"
    );

    // Handoff yields should be reasonable
    if metrics.browser_ready_handoff_yields > 0 {
        // Each yield represents a break in ready dispatch, so we should
        // have dispatched at least `yield_count * handoff_limit` ready tasks
        // (approximately).
        assert!(
            metrics.ready_dispatches >= metrics.browser_ready_handoff_yields,
            "ready dispatches ({}) should >= handoff yields ({})",
            metrics.ready_dispatches,
            metrics.browser_ready_handoff_yields
        );
    }
}

/// Max cancel streak must respect the configured limit.
#[test]
fn browser_max_cancel_streak_within_bounds() {
    for &streak_limit in &[2usize, 4, 8, 16] {
        let state = setup_state(199);
        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, streak_limit);
        sched.set_browser_ready_handoff_limit(8);

        // Heavy cancel + some ready to trigger fairness yields
        for i in 0..100u32 {
            sched.inject_cancel(task(1, i), 100);
        }
        for i in 100..200u32 {
            sched.inject_ready(task(1, i), 50);
        }

        let mut workers = sched.take_workers().into_iter();
        let mut worker = workers.next().unwrap();
        let (_, metrics) = dispatch_all(&mut worker, 500);

        // Effective limit can be 2x base limit during drain boost
        let max_allowed = streak_limit * 2;
        assert!(
            metrics.max_cancel_streak <= max_allowed,
            "limit={streak_limit}: max_cancel_streak={} exceeds 2*limit={}",
            metrics.max_cancel_streak,
            max_allowed
        );
    }
}

// =============================================================================
// BROWSER THROUGHPUT REGRESSION BASELINES
// =============================================================================

/// Browser profile throughput: 1K mixed tasks under browser config
/// must complete in < 50ms even in debug mode.
#[test]
fn regression_browser_profile_1k_mixed() {
    let task_count = 1000u32;
    let state = setup_state(task_count);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
    sched.set_browser_ready_handoff_limit(16);

    let start = Instant::now();

    for i in 0..task_count {
        if i % 10 == 0 {
            sched.inject_cancel(task(1, i), 100);
        } else {
            sched.inject_ready(task(1, i), (i % 32) as u8);
        }
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let mut dispatched = 0u32;
    let mut consecutive_nones = 0u32;
    loop {
        match worker.next_task() {
            Some(_) => {
                dispatched += 1;
                consecutive_nones = 0;
            }
            None => {
                consecutive_nones += 1;
                if consecutive_nones >= 2 {
                    break;
                }
                continue;
            }
        }
    }

    let elapsed = start.elapsed();
    assert_eq!(dispatched, task_count, "all tasks must dispatch");
    assert!(
        elapsed.as_millis() < 50,
        "browser profile regression: 1K mixed took {}ms (threshold: 50ms)",
        elapsed.as_millis()
    );
}

/// Ready handoff throughput: 5K ready tasks with handoff limit=16
/// must complete in < 200ms.
#[test]
fn regression_browser_ready_handoff_5k() {
    let task_count = 5000u32;
    let state = setup_state(task_count);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
    sched.set_browser_ready_handoff_limit(16);

    let start = Instant::now();

    for i in 0..task_count {
        sched.inject_ready(task(1, i), 50);
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let mut dispatched = 0u32;
    loop {
        match worker.next_task() {
            Some(_) => dispatched += 1,
            None => {
                if dispatched >= task_count {
                    break;
                }
                // Handoff yield: re-enter (simulates browser returning control)
                continue;
            }
        }
    }

    let elapsed = start.elapsed();
    assert_eq!(dispatched, task_count, "all tasks must dispatch");
    assert!(
        elapsed.as_millis() < 200,
        "browser handoff regression: 5K ready took {}ms (threshold: 200ms)",
        elapsed.as_millis()
    );
}

/// Cancel + ready fairness under browser mode: 500 cancel + 500 ready
/// must all dispatch in < 100ms.
#[test]
fn regression_browser_cancel_ready_fairness_1k() {
    let cancel_n = 500u32;
    let ready_n = 500u32;
    let total = cancel_n + ready_n;
    let state = setup_state(total);
    let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
    sched.set_browser_ready_handoff_limit(16);

    let start = Instant::now();

    for i in 0..cancel_n {
        sched.inject_cancel(task(1, i), 100);
    }
    for i in cancel_n..total {
        sched.inject_ready(task(1, i), 50);
    }

    let mut workers = sched.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let mut dispatched = 0u32;
    let mut consecutive_nones = 0u32;
    loop {
        match worker.next_task() {
            Some(_) => {
                dispatched += 1;
                consecutive_nones = 0;
            }
            None => {
                consecutive_nones += 1;
                if consecutive_nones >= 2 {
                    break;
                }
                continue;
            }
        }
    }

    let elapsed = start.elapsed();
    assert_eq!(dispatched, total, "all tasks must dispatch");
    assert!(
        elapsed.as_millis() < 100,
        "browser fairness regression: 1K cancel+ready took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}
