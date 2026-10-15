//! Behavioral proof for the runtime defaults chosen by `#[asupersync::main]`
//! and `#[asupersync::test]`.
//!
//! What green proves on this host: `#[main]` runs two spawned tasks truly in
//! parallel (multi-thread default), the `#[test]` default serializes them on
//! one worker, an explicit `flavor = "multi_thread"` test runs them in
//! parallel again, and `spawn_blocking` leaves the async worker thread with
//! the default on-demand pool but stays on it with `blocking = 0`.
//!
//! No-claim: this does not prove scheduler fairness, blocking-pool sizing
//! policy, wall-clock bounds, or shutdown ordering.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use asupersync::Cx;

const PROBE_TASKS: usize = 2;
const PROBE_DEADLINE: Duration = Duration::from_secs(3);

/// Spawns two tasks that each spin until both have arrived. Only a runtime
/// with at least two workers lets both tasks observe full arrival before the
/// deadline; on a single worker the first spinner starves the second until
/// its own deadline passes, so exactly one task reports full arrival.
async fn tasks_that_saw_full_arrival(cx: &Cx) -> usize {
    let arrived = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(PROBE_TASKS);
    for _ in 0..PROBE_TASKS {
        let arrived = Arc::clone(&arrived);
        let handle = cx
            .spawn(move |_task_cx| async move {
                arrived.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + PROBE_DEADLINE;
                while arrived.load(Ordering::SeqCst) < PROBE_TASKS {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::hint::spin_loop();
                }
                true
            })
            .expect("spawn arrival probe task");
        handles.push(handle);
    }
    let mut saw_full_arrival = 0;
    for mut handle in handles {
        if handle.join(cx).await.expect("join arrival probe task") {
            saw_full_arrival += 1;
        }
    }
    saw_full_arrival
}

async fn worker_thread_id(cx: &Cx) -> ThreadId {
    cx.spawn(|_task_cx| async move { std::thread::current().id() })
        .expect("spawn worker probe")
        .join(cx)
        .await
        .expect("join worker probe")
}

async fn blocking_thread_id(cx: &Cx) -> ThreadId {
    cx.spawn_blocking(|_task_cx| std::thread::current().id())
        .expect("spawn_blocking probe")
        .join(cx)
        .await
        .expect("join spawn_blocking probe")
}

mod main_default {
    use super::*;

    static SAW_FULL_ARRIVAL: AtomicUsize = AtomicUsize::new(usize::MAX);

    // `#[asupersync::main]` must decorate `async fn main`; inside a module that
    // is an ordinary function we can call from a test.
    #[asupersync::main]
    async fn main(cx: &Cx) {
        SAW_FULL_ARRIVAL.store(tasks_that_saw_full_arrival(cx).await, Ordering::SeqCst);
    }

    #[test]
    fn main_default_runs_spawned_tasks_in_parallel() {
        main();
        assert_eq!(
            SAW_FULL_ARRIVAL.load(Ordering::SeqCst),
            PROBE_TASKS,
            "#[asupersync::main] should default to the multi-thread scheduler"
        );
    }
}

#[asupersync::test]
async fn test_default_is_single_worker_so_spinners_serialize(cx: &Cx) {
    assert_eq!(
        tasks_that_saw_full_arrival(cx).await,
        1,
        "#[asupersync::test] should default to one worker"
    );
}

#[asupersync::test(flavor = "multi_thread")]
async fn explicit_multi_thread_test_runs_spinners_in_parallel(cx: &Cx) {
    assert_eq!(tasks_that_saw_full_arrival(cx).await, PROBE_TASKS);
}

#[asupersync::test]
async fn test_default_spawn_blocking_leaves_the_worker_thread(cx: &Cx) {
    let worker = worker_thread_id(cx).await;
    let blocking = blocking_thread_id(cx).await;
    assert_ne!(
        blocking, worker,
        "the default entry-macro blocking pool should run the closure off the async worker"
    );
}

#[asupersync::test(blocking = 0)]
async fn blocking_zero_runs_inline_on_the_worker_thread(cx: &Cx) {
    let worker = worker_thread_id(cx).await;
    let blocking = blocking_thread_id(cx).await;
    assert_eq!(
        blocking, worker,
        "blocking = 0 should restore the inline fallback on the async worker"
    );
}
