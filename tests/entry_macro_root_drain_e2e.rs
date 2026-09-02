//! Behavioral proof that the root region is drained when the entry future
//! returns, and that `Runtime::drain_root_region` is bounded.
//!
//! Before this change nothing closed the root region: `block_on` returned as
//! soon as its future completed and teardown joined the workers and dropped
//! state, so a root-region task that outlived `main` was abort-by-dropped
//! and its cleanup never ran. Now the entry macros request cancellation of
//! the root region and wait (default 2 s) for quiescence.
//!
//! What green proves:
//! - a cooperative task spawned from `main` that outlives it observes the
//!   shutdown cancellation and runs its cleanup before `main()` returns (the
//!   cleanup counter is read after the macro-expanded function returns);
//! - `drain_ms = 0` restores the old behaviour: the same task's cleanup has
//!   not run when the function returns (planted negative);
//! - `Runtime::drain_root_region` reports `Quiescent` for cooperative work
//!   and `TimedOut` within the bound for non-cooperative work.
//!
//! No-claim: non-cooperative code is not bounded beyond the wait; LabRuntime
//! semantics are unchanged.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::observability::TaskInspectorConfig;
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder, yield_now};

/// Spawns a task that keeps checkpointing until cancelled, then bumps
/// `cleanup` once. The handle is deliberately dropped: the task outlives the
/// caller and only the root-region drain can make its cleanup run.
///
/// Returns a flag the task sets on its first poll. Spawns are admitted
/// asynchronously through the mailbox, so a caller that wants "a task that is
/// running when the entry future returns" must wait for this flag; otherwise
/// the drain may cancel a still-pending spawn, which then never runs at all.
fn spawn_outliving_worker(cx: &Cx, cleanup: Arc<AtomicUsize>) -> Arc<AtomicBool> {
    let started = Arc::new(AtomicBool::new(false));
    let started_for_task = Arc::clone(&started);
    let _ = cx
        .spawn(move |task_cx| async move {
            started_for_task.store(true, Ordering::SeqCst);
            loop {
                if task_cx.checkpoint().is_err() {
                    break;
                }
                yield_now().await;
            }
            cleanup.fetch_add(1, Ordering::SeqCst);
        })
        .expect("spawn outliving worker");
    started
}

/// Yields until `started` is set (bounded so a broken spawn path fails
/// instead of hanging).
async fn wait_started(started: &AtomicBool) {
    for _ in 0..100_000 {
        if started.load(Ordering::SeqCst) {
            return;
        }
        yield_now().await;
    }
    panic!("spawned task never started");
}

mod drained {
    use super::*;

    thread_local! {
        static SHARED: std::cell::RefCell<Option<Arc<AtomicUsize>>> = const { std::cell::RefCell::new(None) };
    }

    #[asupersync::main]
    async fn main(cx: &Cx) {
        let cleanup = Arc::new(AtomicUsize::new(0));
        let started = spawn_outliving_worker(cx, Arc::clone(&cleanup));
        // Wait until the worker is really running, then leave it running.
        wait_started(&started).await;
        // Publish the shared counter so the test can read it after return
        // (block_on drives this future on the test thread).
        SHARED.with(|slot| *slot.borrow_mut() = Some(cleanup));
    }

    #[test]
    fn main_drains_outliving_task_before_returning() {
        main();
        let cleanup = SHARED
            .with(|slot| slot.borrow().clone())
            .expect("main published counter");
        assert_eq!(
            cleanup.load(Ordering::SeqCst),
            1,
            "the outliving task's cleanup must have run before #[asupersync::main] returned"
        );
    }
}

mod undrained_planted_negative {
    use super::*;

    thread_local! {
        static SHARED: std::cell::RefCell<Option<Arc<AtomicUsize>>> = const { std::cell::RefCell::new(None) };
    }

    #[asupersync::main(drain_ms = 0)]
    async fn main(cx: &Cx) {
        let cleanup = Arc::new(AtomicUsize::new(0));
        let started = spawn_outliving_worker(cx, Arc::clone(&cleanup));
        wait_started(&started).await;
        SHARED.with(|slot| *slot.borrow_mut() = Some(cleanup));
    }

    #[test]
    fn drain_zero_leaves_the_outliving_task_undrained() {
        main();
        let cleanup = SHARED
            .with(|slot| slot.borrow().clone())
            .expect("main published counter");
        assert_eq!(
            cleanup.load(Ordering::SeqCst),
            0,
            "with drain_ms = 0 the task is dropped at teardown and its cleanup never runs"
        );
    }
}

fn drain_reports_quiescent_for_cooperative_work(runtime: asupersync::runtime::Runtime) {
    let cleanup = Arc::new(AtomicUsize::new(0));
    let cleanup_for_task = Arc::clone(&cleanup);
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let started = spawn_outliving_worker(&cx, cleanup_for_task);
        wait_started(&started).await;
    });
    assert_eq!(
        cleanup.load(Ordering::SeqCst),
        0,
        "still running when block_on returns"
    );
    let outcome = runtime.drain_root_region(Duration::from_secs(5));
    if outcome != RootDrainOutcome::Quiescent {
        // Diagnostics for a red run: what does the runtime think the task is
        // doing? (state, phase, poll count, time since last poll)
        let inspector = runtime.task_inspector(TaskInspectorConfig::default());
        eprintln!(
            "drain timed out; inspector snapshot:\n{}",
            inspector
                .wire_snapshot_pretty_json()
                .unwrap_or_else(|e| format!("<snapshot failed: {e}>"))
        );
        for task in inspector.list_tasks() {
            eprintln!(
                "task {:?} region {:?} state {:?} phase {:?} polls {} since_last_poll {:?} wake_pending {}",
                task.id,
                task.region_id,
                task.state,
                task.phase,
                task.poll_count,
                task.time_since_last_poll,
                task.wake_pending
            );
        }
    }
    assert_eq!(outcome, RootDrainOutcome::Quiescent);
    assert_eq!(cleanup.load(Ordering::SeqCst), 1);
    // Informational: full runtime quiescence additionally requires the root
    // region to have left its close lifecycle and the I/O driver to hold no
    // wakers; report it rather than assert it (the drain contract is
    // task-and-obligation quiescence).
    eprintln!(
        "runtime.is_quiescent() after drain = {}",
        runtime.is_quiescent()
    );
}

#[test]
fn drain_root_region_reports_quiescent_for_cooperative_work() {
    drain_reports_quiescent_for_cooperative_work(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
    );
}

#[test]
fn drain_root_region_reports_quiescent_for_cooperative_work_current_thread() {
    drain_reports_quiescent_for_cooperative_work(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
    );
}

#[test]
fn drain_root_region_times_out_within_bound_for_non_cooperative_work() {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let started = Arc::new(AtomicBool::new(false));
        let started_for_task = Arc::clone(&started);
        let _ = cx
            .spawn(move |_task_cx| async move {
                started_for_task.store(true, Ordering::SeqCst);
                // Never checkpoints: cannot be drained cooperatively.
                std::thread::sleep(Duration::from_millis(1500));
            })
            .expect("spawn non-cooperative task");
        wait_started(&started).await;
    });
    let started = Instant::now();
    let outcome = runtime.drain_root_region(Duration::from_millis(200));
    let waited = started.elapsed();
    assert_eq!(outcome, RootDrainOutcome::TimedOut);
    assert!(
        waited < Duration::from_millis(1200),
        "the drain must give up at its bound, not wait for the blocking task; waited {waited:?}"
    );
}
