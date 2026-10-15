#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::sync::Semaphore;
use asupersync::types::Budget;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_INITIAL_PERMITS: usize = 8;
const MAX_TASKS: usize = 8;
const MAX_ACQUIRE_PER_TASK: usize = 4;
const MAX_YIELDS: u8 = 8;
const MAX_STEPS: u64 = 20_000;

#[derive(Debug, Arbitrary)]
struct SemaphoreConcurrentCase {
    seed: u64,
    initial_permits: u8,
    tasks: Vec<TaskPlan>,
}

#[derive(Debug, Clone, Arbitrary)]
struct TaskPlan {
    acquire_count: u8,
    pre_yields: u8,
    hold_yields: u8,
    post_yields: u8,
    priority: u8,
    release_mode: ReleaseMode,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ReleaseMode {
    DropPermit,
    CommitPermit,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TaskTotals {
    acquired: usize,
    released: usize,
}

#[derive(Debug, Default)]
struct PermitTracker {
    active: AtomicUsize,
    acquired: AtomicUsize,
    released: AtomicUsize,
    max_active: AtomicUsize,
}

impl PermitTracker {
    fn record_acquire(&self, count: usize, capacity: usize) {
        let previous = self.active.fetch_add(count, Ordering::SeqCst);
        let active = previous.saturating_add(count);
        self.acquired.fetch_add(count, Ordering::SeqCst);
        self.max_active.fetch_max(active, Ordering::SeqCst);
        assert!(
            active <= capacity,
            "semaphore double-counted permits: active {active} > capacity {capacity}"
        );
    }

    fn record_release(&self, count: usize) {
        let previous = self.active.fetch_sub(count, Ordering::SeqCst);
        assert!(
            previous >= count,
            "semaphore released more permits than were logically active"
        );
        self.released.fetch_add(count, Ordering::SeqCst);
    }
}

fuzz_target!(|case: SemaphoreConcurrentCase| {
    let initial_permits = usize::from(case.initial_permits).clamp(1, MAX_INITIAL_PERMITS);
    let tasks: Vec<_> = case.tasks.into_iter().take(MAX_TASKS).collect();

    if tasks.len() < 2 {
        return;
    }

    drive_concurrent_acquires(case.seed, initial_permits, tasks);
});

fn drive_concurrent_acquires(seed: u64, initial_permits: usize, tasks: Vec<TaskPlan>) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(MAX_STEPS));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(initial_permits));
    let tracker = Arc::new(PermitTracker::default());
    let mut handles = Vec::with_capacity(tasks.len());

    for plan in tasks {
        let semaphore_for_task = Arc::clone(&semaphore);
        let tracker_for_task = Arc::clone(&tracker);
        let acquire_count = bounded_acquire_count(plan.acquire_count, initial_permits);
        let pre_yields = plan.pre_yields.min(MAX_YIELDS);
        let hold_yields = plan.hold_yields.min(MAX_YIELDS);
        let post_yields = plan.post_yields.min(MAX_YIELDS);
        let release_mode = plan.release_mode;

        let (task_id, handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..pre_yields {
                    yield_now().await;
                }

                let cx = Cx::current().unwrap_or_else(Cx::for_testing);
                let permit = semaphore_for_task
                    .acquire(&cx, acquire_count)
                    .await
                    .expect("semaphore acquire should complete without cancellation or close");

                let held = permit.count();
                assert_eq!(
                    held, acquire_count,
                    "semaphore returned a permit with the wrong count"
                );
                tracker_for_task.record_acquire(held, initial_permits);

                for _ in 0..hold_yields {
                    yield_now().await;
                }

                tracker_for_task.record_release(held);
                match release_mode {
                    ReleaseMode::DropPermit => drop(permit),
                    ReleaseMode::CommitPermit => permit.commit(),
                }

                for _ in 0..post_yields {
                    yield_now().await;
                }

                TaskTotals {
                    acquired: held,
                    released: held,
                }
            })
            .expect("lab semaphore task should spawn");

        runtime.scheduler.lock().schedule(task_id, plan.priority);
        handles.push(handle);
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab runtime invariants failed after semaphore fuzz case: {violations:?}"
    );

    let mut joined = TaskTotals::default();
    for mut handle in handles {
        let totals = handle
            .try_join()
            .expect("semaphore task should not panic or cancel")
            .expect("semaphore task should be finished after quiescence");
        assert_eq!(
            totals.acquired, totals.released,
            "task-local semaphore permit accounting drifted"
        );
        joined.acquired = joined.acquired.saturating_add(totals.acquired);
        joined.released = joined.released.saturating_add(totals.released);
    }

    let active = tracker.active.load(Ordering::SeqCst);
    let acquired = tracker.acquired.load(Ordering::SeqCst);
    let released = tracker.released.load(Ordering::SeqCst);
    let available = semaphore.available_permits();

    assert_eq!(active, 0, "semaphore permits leaked from active set");
    assert_eq!(
        acquired, released,
        "semaphore global acquire/release totals diverged"
    );
    assert_eq!(
        joined.acquired, acquired,
        "joined task totals disagree with global acquired count"
    );
    assert_eq!(
        joined.released, released,
        "joined task totals disagree with global released count"
    );
    assert_eq!(
        available, initial_permits,
        "semaphore leaked or double-counted permits: available {available} != initial {initial_permits}"
    );
}

fn bounded_acquire_count(raw: u8, initial_permits: usize) -> usize {
    usize::from(raw)
        .clamp(1, MAX_ACQUIRE_PER_TASK)
        .min(initial_permits)
}
