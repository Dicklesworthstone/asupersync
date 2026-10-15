#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    cx::Cx,
    lab::{LabConfig, LabRuntime},
    runtime::yield_now,
    sync::{LockError, Mutex, OwnedMutexGuard},
    types::{Budget, CancelKind},
};
use libfuzzer_sys::fuzz_target;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicUsize, Ordering},
};

const INITIAL_OWNER: usize = usize::MAX;
const MAX_TASKS: usize = 8;
const MAX_YIELDS: u8 = 8;
const MAX_PRIME_STEPS: u8 = 32;
const MAX_STEPS: u64 = 20_000;

#[derive(Debug, Arbitrary)]
struct MutexConcurrentCase {
    seed: u64,
    prime_steps: u8,
    tasks: Vec<TaskPlan>,
}

#[derive(Debug, Clone, Arbitrary)]
struct TaskPlan {
    pre_yields: u8,
    hold_yields: u8,
    post_yields: u8,
    priority: u8,
    cancel_point: CancelPoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum CancelPoint {
    Never,
    BeforeLock,
    WhileQueued,
    AfterAcquire,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TaskTotals {
    acquired: usize,
    cancelled: usize,
}

#[derive(Debug, Default)]
struct MutexPayload {
    value: usize,
    last_owner: Option<usize>,
}

#[derive(Debug, Default)]
struct OwnershipTracker {
    active_owner_count: AtomicUsize,
    acquired: AtomicUsize,
    cancelled: AtomicUsize,
    max_active_owner_count: AtomicUsize,
    owner_log: StdMutex<Vec<usize>>,
}

fuzz_target!(|case: MutexConcurrentCase| {
    let mut tasks: Vec<_> = case.tasks.into_iter().take(MAX_TASKS).collect();
    tasks.push(TaskPlan {
        pre_yields: 1,
        hold_yields: 1,
        post_yields: 0,
        priority: u8::MAX,
        cancel_point: CancelPoint::Never,
    });

    drive_mutex_concurrent_acquires(case.seed, case.prime_steps.min(MAX_PRIME_STEPS), tasks);
});

fn drive_mutex_concurrent_acquires(seed: u64, prime_steps: u8, tasks: Vec<TaskPlan>) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(MAX_STEPS));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mutex = Arc::new(Mutex::new(MutexPayload {
        value: 0,
        last_owner: Some(INITIAL_OWNER),
    }));
    let tracker = Arc::new(OwnershipTracker::default());
    let published_cx = Arc::new(StdMutex::new(Vec::<(usize, Cx)>::new()));
    let cancel_points: Vec<_> = tasks.iter().map(|plan| plan.cancel_point).collect();

    let initial_guard =
        OwnedMutexGuard::try_lock(Arc::clone(&mutex)).expect("new mutex should lock immediately");
    let mut handles = Vec::with_capacity(tasks.len());

    for (task_index, plan) in tasks.into_iter().enumerate() {
        let mutex_for_task = Arc::clone(&mutex);
        let tracker_for_task = Arc::clone(&tracker);
        let published_cx_for_task = Arc::clone(&published_cx);
        let pre_yields = plan.pre_yields.min(MAX_YIELDS);
        let hold_yields = plan.hold_yields.min(MAX_YIELDS);
        let post_yields = plan.post_yields.min(MAX_YIELDS);
        let cancel_point = plan.cancel_point;

        let (task_id, handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap_or_else(Cx::for_testing);
                published_cx_for_task
                    .lock()
                    .expect("published Cx registry should not poison")
                    .push((task_index, cx.clone()));

                for _ in 0..pre_yields {
                    yield_now().await;
                }

                if cancel_point == CancelPoint::BeforeLock {
                    cx.cancel_fast(CancelKind::User);
                }

                let guard = OwnedMutexGuard::lock(Arc::clone(&mutex_for_task), &cx).await;
                let mut guard = match guard {
                    Ok(guard) => guard,
                    Err(LockError::Cancelled) => {
                        tracker_for_task.cancelled.fetch_add(1, Ordering::SeqCst);
                        return TaskTotals {
                            acquired: 0,
                            cancelled: 1,
                        };
                    }
                    Err(other) => panic!("mutex lock failed unexpectedly: {other:?}"),
                };

                tracker_for_task.record_acquire(task_index);
                assert_eq!(
                    guard.value,
                    tracker_for_task
                        .acquired
                        .load(Ordering::SeqCst)
                        .saturating_sub(1),
                    "mutex payload counter must reflect exclusive prior ownership"
                );
                guard.value = guard.value.saturating_add(1);
                guard.last_owner = Some(task_index);

                if cancel_point == CancelPoint::AfterAcquire {
                    cx.cancel_fast(CancelKind::User);
                    assert!(
                        cx.checkpoint().is_err(),
                        "after-acquire cancellation must be observable"
                    );
                }

                for _ in 0..hold_yields {
                    yield_now().await;
                }

                tracker_for_task.record_release();
                drop(guard);

                for _ in 0..post_yields {
                    yield_now().await;
                }

                TaskTotals {
                    acquired: 1,
                    cancelled: 0,
                }
            })
            .expect("lab mutex task should spawn");

        runtime.scheduler.lock().schedule(task_id, plan.priority);
        handles.push(handle);
    }

    for _ in 0..prime_steps {
        runtime.step_for_test();
    }

    cancel_published_waiters(&published_cx, &cancel_points);
    drop(initial_guard);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab runtime invariants failed after mutex fuzz case: {violations:?}"
    );

    let mut joined = TaskTotals::default();
    for mut handle in handles {
        let totals = handle
            .try_join()
            .expect("mutex task should not panic")
            .expect("mutex task should finish after quiescence");
        joined.acquired = joined.acquired.saturating_add(totals.acquired);
        joined.cancelled = joined.cancelled.saturating_add(totals.cancelled);
    }

    let acquired = tracker.acquired.load(Ordering::SeqCst);
    let cancelled = tracker.cancelled.load(Ordering::SeqCst);
    let active = tracker.active_owner_count.load(Ordering::SeqCst);
    let max_active = tracker.max_active_owner_count.load(Ordering::SeqCst);

    assert_eq!(active, 0, "mutex ownership leaked after all tasks finished");
    assert!(
        max_active <= 1,
        "mutex admitted concurrent owners: max active owners={max_active}"
    );
    assert_eq!(
        joined.acquired, acquired,
        "joined task totals disagree with global acquire count"
    );
    assert_eq!(
        joined.cancelled, cancelled,
        "joined task totals disagree with global cancellation count"
    );
    assert!(
        acquired >= 1,
        "sentinel task should prove ownership transfers after initial guard release"
    );
    assert_eq!(
        mutex.waiters(),
        0,
        "cancelled mutex waiters must be cleaned up"
    );
    assert!(
        !mutex.is_locked(),
        "mutex must not remain locked after quiescence"
    );

    let guard = mutex
        .try_lock()
        .expect("mutex must be synchronously acquirable after all task drops");
    assert_eq!(
        guard.value, acquired,
        "mutex payload value must equal successful ownership transfers"
    );
    assert!(
        guard.last_owner.is_some_and(|owner| owner != INITIAL_OWNER),
        "at least one task must take ownership after the initial guard"
    );
}

fn cancel_published_waiters(
    published_cx: &StdMutex<Vec<(usize, Cx)>>,
    cancel_points: &[CancelPoint],
) {
    let contexts = published_cx
        .lock()
        .expect("published Cx registry should not poison")
        .clone();
    for (task_index, cx) in contexts {
        if cancel_points.get(task_index) == Some(&CancelPoint::WhileQueued) {
            cx.cancel_fast(CancelKind::User);
        }
    }
}

impl OwnershipTracker {
    fn record_acquire(&self, task_index: usize) {
        let previous = self.active_owner_count.fetch_add(1, Ordering::SeqCst);
        let active = previous.saturating_add(1);
        self.max_active_owner_count
            .fetch_max(active, Ordering::SeqCst);
        assert_eq!(
            previous, 0,
            "mutex transferred ownership while another owner was active"
        );
        self.acquired.fetch_add(1, Ordering::SeqCst);
        self.owner_log
            .lock()
            .expect("owner log should not poison")
            .push(task_index);
    }

    fn record_release(&self) {
        let previous = self.active_owner_count.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(
            previous, 1,
            "mutex released without exactly one active logical owner"
        );
    }
}
