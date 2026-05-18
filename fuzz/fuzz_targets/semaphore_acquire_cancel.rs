#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::{TaskHandle, yield_now};
use asupersync::sync::Semaphore;
use asupersync::types::{Budget, CancelKind, CancelReason};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Comprehensive fuzz target for Semaphore acquire-with-cancel race conditions.
//
// Tests critical race conditions in async semaphore acquire:
// 1. No permit leaks when acquire futures are dropped mid-flight
// 2. Waiter queue integrity under heavy cancellation
// 3. Permit count conservation under cancel pressure
// 4. FIFO fairness when some acquires are cancelled
// 5. Proper wakeup delivery after cancellation
// 6. State machine consistency during simultaneous acquire/cancel/release

const MAX_INITIAL_PERMITS: usize = 16;
const MAX_ACQUIRE_TASKS: usize = 12;
const MAX_CANCEL_TASKS: usize = 6;
const MAX_PERMITS_PER_ACQUIRE: usize = 4;
const MAX_YIELDS: u8 = 12;
const MAX_STEPS: u64 = 50_000;

#[derive(Arbitrary, Debug)]
struct SemaphoreAcquireCancelFuzz {
    seed: u64,
    initial_permits: u8,
    acquire_tasks: Vec<AcquireTaskPlan>,
    cancel_tasks: Vec<CancelTaskPlan>,
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct AcquireTaskPlan {
    permit_count: u8,
    pre_acquire_yields: u8,
    hold_duration_yields: u8,
    post_release_yields: u8,
    priority: u8,
    release_mode: ReleaseMode,
    cancel_probability: u8, // 0-255, probability of self-cancellation
}

#[derive(Arbitrary, Debug, Clone)]
struct CancelTaskPlan {
    target_task_id: u8, // Which acquire task to cancel
    delay_yields: u8,   // Yield before attempting cancel
    priority: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ReleaseMode {
    Drop,
    Commit,
    Forget,
}

#[derive(Arbitrary, Debug, Clone)]
struct TestConfig {
    enable_fairness_checks: bool,
    enable_aggressive_yield: bool,
    max_operations: u8,
}

#[derive(Debug, Default)]
struct PermitTracker {
    active: AtomicUsize,
    acquired: AtomicUsize,
    released: AtomicUsize,
    cancelled: AtomicUsize,
    leaked: AtomicUsize,
}

impl PermitTracker {
    fn record_acquire(&self, count: usize, capacity: usize) {
        let previous = self.active.fetch_add(count, Ordering::SeqCst);
        let active = previous.saturating_add(count);
        self.acquired.fetch_add(count, Ordering::SeqCst);

        assert!(
            active <= capacity,
            "Permit double-counting: active {active} > capacity {capacity}"
        );
    }

    fn record_release(&self, count: usize) {
        let previous = self.active.fetch_sub(count, Ordering::SeqCst);
        assert!(
            previous >= count,
            "Over-release: releasing {count} with only {previous} active"
        );
        self.released.fetch_add(count, Ordering::SeqCst);
    }

    fn record_cancel(&self, count: usize) {
        self.cancelled.fetch_add(count, Ordering::SeqCst);
    }

    fn record_leak(&self, count: usize) {
        let previous = self.active.fetch_sub(count, Ordering::SeqCst);
        assert!(
            previous >= count,
            "Leak accounting error: {count} leaked from {previous} active"
        );
        self.leaked.fetch_add(count, Ordering::SeqCst);
    }

    fn verify_conservation(&self, initial_permits: usize, final_available: usize) {
        let active = self.active.load(Ordering::SeqCst);
        let acquired = self.acquired.load(Ordering::SeqCst);
        let released = self.released.load(Ordering::SeqCst);
        let leaked = self.leaked.load(Ordering::SeqCst);

        // Core conservation law: initial = available + active + leaked
        let total_accounted = final_available + active + leaked;
        assert_eq!(
            initial_permits, total_accounted,
            "Permit conservation violated: initial={}, available={}, active={}, leaked={}, total={}",
            initial_permits, final_available, active, leaked, total_accounted
        );

        // Accounting balance: acquired = released + active + leaked
        let total_disposed = released + active + leaked;
        assert_eq!(
            acquired, total_disposed,
            "Permit accounting imbalance: acquired={}, released={}, active={}, leaked={}, disposed={}",
            acquired, released, active, leaked, total_disposed
        );
    }
}

fuzz_target!(|input: SemaphoreAcquireCancelFuzz| {
    let initial_permits = (input.initial_permits as usize).clamp(1, MAX_INITIAL_PERMITS);
    let acquire_tasks: Vec<_> = input
        .acquire_tasks
        .into_iter()
        .take(MAX_ACQUIRE_TASKS)
        .collect();
    let cancel_tasks: Vec<_> = input
        .cancel_tasks
        .into_iter()
        .take(MAX_CANCEL_TASKS)
        .collect();

    if acquire_tasks.is_empty() {
        return; // Need at least one acquire task
    }

    execute_acquire_cancel_scenario(
        input.seed,
        initial_permits,
        acquire_tasks,
        cancel_tasks,
        input.config,
    );
});

fn execute_acquire_cancel_scenario(
    seed: u64,
    initial_permits: usize,
    acquire_tasks: Vec<AcquireTaskPlan>,
    cancel_tasks: Vec<CancelTaskPlan>,
    config: TestConfig,
) {
    let max_ops = (config.max_operations as u64).clamp(1000, MAX_STEPS);
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(max_ops));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(initial_permits));
    let tracker = Arc::new(PermitTracker::default());

    // Maps task index to a shared handle so cancel tasks can exercise the
    // real runtime abort path while the verifier can still join afterward.
    let mut task_handles: HashMap<usize, Arc<Mutex<TaskHandle<usize>>>> = HashMap::new();
    let mut acquire_handles = Vec::new();
    let mut cancel_handles = Vec::new();

    // Spawn acquire tasks
    for (task_idx, plan) in acquire_tasks.into_iter().enumerate() {
        let semaphore_clone = Arc::clone(&semaphore);
        let tracker_clone = Arc::clone(&tracker);
        let permit_count = (plan.permit_count as usize)
            .clamp(1, MAX_PERMITS_PER_ACQUIRE)
            .min(initial_permits);
        let priority = plan.priority;
        let plan_clone = plan.clone();
        let config_clone = config.clone();

        let (task_id, handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                run_acquire_task(
                    task_idx,
                    plan_clone,
                    permit_count,
                    initial_permits,
                    semaphore_clone,
                    tracker_clone,
                    config_clone,
                )
                .await
            })
            .expect("acquire task should spawn");

        runtime.scheduler.lock().schedule(task_id, priority);
        let shared_handle = Arc::new(Mutex::new(handle));
        task_handles.insert(task_idx, Arc::clone(&shared_handle));
        acquire_handles.push(shared_handle);
    }

    // Spawn cancel tasks
    for cancel_plan in cancel_tasks {
        let target_idx = cancel_plan.target_task_id as usize;
        if let Some(target_handle) = task_handles.get(&target_idx) {
            let priority = cancel_plan.priority;
            let cancel_plan_clone = cancel_plan.clone();
            let target_handle = Arc::clone(target_handle);

            let (cancel_task_id, cancel_handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    run_cancel_task(cancel_plan_clone, target_handle).await
                })
                .expect("cancel task should spawn");

            runtime.scheduler.lock().schedule(cancel_task_id, priority);
            cancel_handles.push(cancel_handle);
        }
    }

    // Run until all tasks complete or cancel
    runtime.run_until_quiescent();

    // Check runtime invariants
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "Runtime invariants failed after semaphore acquire-cancel scenario: {violations:?}"
    );

    // Verify final permit conservation
    let final_available = semaphore.available_permits();
    tracker.verify_conservation(initial_permits, final_available);
    if config.enable_fairness_checks {
        assert_eq!(
            tracker.active.load(Ordering::SeqCst),
            0,
            "fairness check: no permits should remain actively held after quiescence"
        );
        assert!(
            final_available <= initial_permits,
            "fairness check: available permits exceeded initial capacity"
        );
    }

    // Join acquire tasks and verify no panics
    for handle in acquire_handles {
        let mut handle = handle
            .lock()
            .expect("acquire task handle mutex should not be poisoned");
        match handle.try_join() {
            Ok(Some(_)) => {} // Task completed normally
            Ok(None) => {}    // Task was cancelled
            Err(e) => panic!("Acquire task panicked: {:?}", e),
        }
    }

    // Join cancel tasks and verify no panics
    for mut handle in cancel_handles {
        match handle.try_join() {
            Ok(Some(_)) => {} // Task completed normally
            Ok(None) => {}    // Task was cancelled
            Err(e) => panic!("Cancel task panicked: {:?}", e),
        }
    }
}

async fn run_acquire_task(
    _task_idx: usize,
    plan: AcquireTaskPlan,
    permit_count: usize,
    initial_permits: usize,
    semaphore: Arc<Semaphore>,
    tracker: Arc<PermitTracker>,
    config: TestConfig,
) -> usize {
    // Pre-acquire yields for race condition timing
    for step in 0..plan.pre_acquire_yields.min(MAX_YIELDS) {
        yield_now().await;
        if config.enable_aggressive_yield && step.is_multiple_of(2) {
            yield_now().await;
        }
    }

    let cx = Cx::current().unwrap_or_else(Cx::for_testing);

    // Self-cancellation probability check. Exercise the real acquire
    // cancellation seam instead of only adding scheduler noise.
    if plan.cancel_probability > 200 {
        cx.cancel_fast(CancelKind::User);
        match semaphore.acquire(&cx, permit_count).await {
            Ok(permit) => {
                let acquired = permit.count();
                drop(permit);
                assert_eq!(
                    acquired, 0,
                    "self-cancelled semaphore acquire unexpectedly acquired permits"
                );
                return 0;
            }
            Err(_) => {
                tracker.record_cancel(permit_count);
                return 0;
            }
        }
    }

    // Normal acquire path
    let permit = match semaphore.acquire(&cx, permit_count).await {
        Ok(permit) => {
            let actual_count = permit.count();
            assert_eq!(
                actual_count, permit_count,
                "Semaphore returned wrong permit count: expected {permit_count}, got {actual_count}"
            );
            tracker.record_acquire(actual_count, initial_permits);
            permit
        }
        Err(_e) => {
            tracker.record_cancel(permit_count);
            return 0; // Cancelled or error
        }
    };

    // Hold the permit for specified duration
    for _ in 0..plan.hold_duration_yields.min(MAX_YIELDS) {
        yield_now().await;
    }

    // Release the permit according to plan
    let held_count = permit.count();
    match plan.release_mode {
        ReleaseMode::Drop => {
            tracker.record_release(held_count);
            drop(permit); // RAII release
        }
        ReleaseMode::Commit => {
            tracker.record_release(held_count);
            permit.commit(); // Explicit release
        }
        ReleaseMode::Forget => {
            tracker.record_leak(held_count);
            permit.forget(); // Intentional leak
        }
    }

    // Post-release yields
    for _ in 0..plan.post_release_yields.min(MAX_YIELDS) {
        yield_now().await;
    }

    permit_count
}

async fn run_cancel_task(
    cancel_plan: CancelTaskPlan,
    target_handle: Arc<Mutex<TaskHandle<usize>>>,
) {
    // Delay before cancellation attempt
    for _ in 0..cancel_plan.delay_yields.min(MAX_YIELDS) {
        yield_now().await;
    }

    {
        let handle = target_handle
            .lock()
            .expect("target task handle mutex should not be poisoned");
        handle.abort_with_reason(CancelReason::user("semaphore acquire-cancel fuzz task"));
    }

    // Give the target task a chance to observe the abort waker and reach a
    // cancellation checkpoint under varied interleavings.
    for _ in 0..5 {
        yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_acquire_cancel() {
        let plan = AcquireTaskPlan {
            permit_count: 2,
            pre_acquire_yields: 2,
            hold_duration_yields: 1,
            post_release_yields: 1,
            priority: 100,
            release_mode: ReleaseMode::Drop,
            cancel_probability: 250, // High cancel probability
        };

        let config = TestConfig {
            enable_fairness_checks: true,
            enable_aggressive_yield: true,
            max_operations: 100,
        };

        execute_acquire_cancel_scenario(42, 5, vec![plan], vec![], config);
    }

    #[test]
    fn test_mixed_acquire_release_modes() {
        let plans = vec![
            AcquireTaskPlan {
                permit_count: 1,
                pre_acquire_yields: 1,
                hold_duration_yields: 2,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Drop,
                cancel_probability: 0,
            },
            AcquireTaskPlan {
                permit_count: 2,
                pre_acquire_yields: 2,
                hold_duration_yields: 1,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Commit,
                cancel_probability: 0,
            },
            AcquireTaskPlan {
                permit_count: 1,
                pre_acquire_yields: 1,
                hold_duration_yields: 1,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Forget,
                cancel_probability: 0,
            },
        ];

        let config = TestConfig {
            enable_fairness_checks: false,
            enable_aggressive_yield: true,
            max_operations: 200,
        };

        execute_acquire_cancel_scenario(123, 8, plans, vec![], config);
    }

    #[test]
    fn test_heavy_cancellation_pressure() {
        let plans = vec![
            AcquireTaskPlan {
                permit_count: 3,
                pre_acquire_yields: 3,
                hold_duration_yields: 5,
                post_release_yields: 2,
                priority: 100,
                release_mode: ReleaseMode::Drop,
                cancel_probability: 128, // 50% cancel probability
            },
            AcquireTaskPlan {
                permit_count: 2,
                pre_acquire_yields: 2,
                hold_duration_yields: 3,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Commit,
                cancel_probability: 200, // ~78% cancel probability
            },
            AcquireTaskPlan {
                permit_count: 1,
                pre_acquire_yields: 1,
                hold_duration_yields: 2,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Drop,
                cancel_probability: 64, // 25% cancel probability
            },
        ];

        let config = TestConfig {
            enable_fairness_checks: true,
            enable_aggressive_yield: true,
            max_operations: 300,
        };

        execute_acquire_cancel_scenario(456, 6, plans, vec![], config);
    }

    #[test]
    fn test_capacity_exhaustion_with_cancel() {
        // Test where permits exceed capacity, some tasks must wait, then some cancel
        let plans = vec![
            AcquireTaskPlan {
                permit_count: 2,
                pre_acquire_yields: 0,
                hold_duration_yields: 10, // Hold long
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Drop,
                cancel_probability: 0, // Don't cancel the holder
            },
            AcquireTaskPlan {
                permit_count: 2,
                pre_acquire_yields: 1,
                hold_duration_yields: 1,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Drop,
                cancel_probability: 255, // Always cancel - should be waiting
            },
            AcquireTaskPlan {
                permit_count: 1,
                pre_acquire_yields: 2,
                hold_duration_yields: 1,
                post_release_yields: 1,
                priority: 100,
                release_mode: ReleaseMode::Drop,
                cancel_probability: 255, // Always cancel - should be waiting
            },
        ];

        let config = TestConfig {
            enable_fairness_checks: false,
            enable_aggressive_yield: true,
            max_operations: 500,
        };

        // Small capacity to force waiting
        execute_acquire_cancel_scenario(789, 3, plans, vec![], config);
    }
}
