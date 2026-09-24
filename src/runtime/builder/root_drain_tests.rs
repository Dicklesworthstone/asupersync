//! Native root-close regressions for br-asupersync-bi2462.92.

use super::*;
use crate::cx::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::types::{CancelKind, Outcome, TaskId};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn runtime_for(case: u8) -> Runtime {
    match case {
        0 => RuntimeBuilder::current_thread(),
        1 => RuntimeBuilder::new().worker_threads(1),
        2 => RuntimeBuilder::new().worker_threads(2),
        _ => RuntimeBuilder::new()
            .worker_threads(2)
            .with_sharded_state(true),
    }
    .build()
    .expect("build native root-drain runtime")
}

fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
    let started = Instant::now();
    while !predicate() {
        assert!(started.elapsed() < Duration::from_secs(3), "{message}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_parked(runtime: &Runtime, task: TaskId) {
    wait_until(
        || {
            if let Some(table) = runtime.inner.scheduler.dispatch_task_table() {
                let mut table = table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                table.get_stored_future(task).is_some()
                    && table
                        .task(task)
                        .is_some_and(|record| !record.wake_state.is_notified())
            } else {
                let mut state = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.get_stored_future(task).is_some()
                    && state
                        .task(task)
                        .is_some_and(|record| !record.wake_state.is_notified())
            }
        },
        "finalizer/child must return Pending to native dispatch with no pending wake",
    );
}

#[derive(Default)]
struct ReleaseGate {
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ReleaseGate {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct RootFinalizer {
    gate: Arc<ReleaseGate>,
    parked: Option<std::sync::mpsc::Sender<TaskId>>,
    completed: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}

impl Future for RootFinalizer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        let cx = Cx::current().expect("native finalizer context");
        assert!(
            cx.inner.read().mask_depth > 0,
            "root finalizer executes masked"
        );
        assert!(cx.checkpoint().is_ok());
        *self.gate.waker.lock() = Some(task.waker().clone());
        if self.gate.released.load(Ordering::Acquire) {
            self.completed.store(true, Ordering::Release);
            return Poll::Ready(());
        }
        if let Some(parked) = self.parked.take() {
            parked
                .send(cx.task_id())
                .expect("publish pending finalizer");
        }
        // Only the external release owns a wake. The drain must not mistake
        // this real parked finalizer for completed work.
        Poll::Pending
    }
}

impl Drop for RootFinalizer {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn finalizer_only_root_closes_after_pending_async_and_sync_cleanup() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let root = runtime.inner.root_region;
        let gate = Arc::new(ReleaseGate::default());
        let asynchronous = Arc::new(AtomicBool::new(false));
        let synchronous = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let returned = Arc::new(AtomicBool::new(false));
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        {
            let mut state = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let sync_flag = Arc::clone(&synchronous);
            let async_flag = Arc::clone(&asynchronous);
            assert!(state.register_sync_finalizer(root, move || {
                assert!(
                    async_flag.load(Ordering::Acquire),
                    "LIFO async cleanup completed first"
                );
                sync_flag.store(true, Ordering::Release);
            }));
            assert!(state.register_async_finalizer(
                root,
                RootFinalizer {
                    gate: Arc::clone(&gate),
                    parked: Some(parked_tx),
                    completed: Arc::clone(&asynchronous),
                    drops: Arc::clone(&drops),
                }
            ));
            assert_eq!(state.live_task_count(), 0);
            assert_eq!(state.pending_obligation_count(), 0);
        }
        let observer_runtime = runtime.clone();
        let observer_returned = Arc::clone(&returned);
        let release = std::thread::spawn(move || {
            let task = parked_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("empty root started its finalizer");
            wait_parked(&observer_runtime, task);
            assert!(
                !observer_returned.load(Ordering::Acquire),
                "drain returned before finalizer receipt"
            );
            std::thread::sleep(Duration::from_millis(20));
            assert!(!observer_returned.load(Ordering::Acquire));
            gate.release();
        });
        let outcome = runtime.drain_root_region(Duration::from_secs(2));
        returned.store(true, Ordering::Release);
        release.join().expect("release pending root finalizer");
        assert_eq!(outcome, RootDrainOutcome::Quiescent);
        assert!(asynchronous.load(Ordering::Acquire));
        assert!(synchronous.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::Acquire), 1);
        let state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.region(root).is_none(),
            "Quiescent requires actual root removal"
        );
        assert_eq!(state.live_region_count(), 0);
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"case\":{case},\"scenario\":\"finalizer-only-root\",\"outcome\":\"Quiescent\",\"async_done\":true,\"sync_done\":true,\"root_removed\":true}}"
        );
    }
}

#[test]
fn root_drain_timeout_retains_pending_finalizer_until_a_later_drain() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let root = runtime.inner.root_region;
        let gate = Arc::new(ReleaseGate::default());
        let completed = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        assert!(
            runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .register_async_finalizer(
                    root,
                    RootFinalizer {
                        gate: Arc::clone(&gate),
                        parked: Some(parked_tx),
                        completed: Arc::clone(&completed),
                        drops: Arc::clone(&drops),
                    }
                )
        );
        let report = runtime.shutdown_drained(Duration::from_millis(100));
        assert!(
            report.elapsed < Duration::from_secs(1),
            "bounded wait: {report:?}"
        );
        let task = parked_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("root finalizer was polled");
        wait_parked(&runtime, task);
        assert_eq!(report.outcome, RootDrainOutcome::TimedOut);
        assert_eq!(report.live_tasks, 1);
        assert_eq!(report.live_regions, 1);
        assert_eq!(report.queued_finalizers, 0);
        assert!(!completed.load(Ordering::Acquire));
        assert_eq!(
            drops.load(Ordering::Acquire),
            0,
            "timeout preserves pending cleanup ownership"
        );
        gate.release();
        let finished = runtime.shutdown_drained(Duration::from_secs(2));
        assert_eq!(finished.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(finished.live_tasks, 0);
        assert_eq!(finished.live_regions, 0);
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::Acquire), 1);
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"case\":{case},\"scenario\":\"pending-finalizer-timeout\",\"timed_out\":\"{report:?}\",\"later\":\"{finished:?}\"}}"
        );
    }
}

#[test]
fn handle_drain_of_an_already_closed_root_preserves_bounded_teardown() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let handle = runtime.handle();
        assert_eq!(
            runtime.shutdown_drained(Duration::ZERO).outcome,
            RootDrainOutcome::Quiescent
        );
        let repeated = handle
            .shutdown_drained(Duration::ZERO)
            .expect("live handle drains closed root");
        assert_eq!(repeated.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(repeated.live_tasks, 0);
        assert_eq!(repeated.live_regions, 0);
        assert_eq!(
            runtime
                .trace_snapshot()
                .iter()
                .filter(|event| event.kind == crate::trace::TraceEventKind::RegionCloseBegin)
                .count(),
            1,
            "repeat drain must not invent another root close"
        );
        drop(handle);
        assert!(
            runtime.shutdown_timeout(Duration::from_secs(2)),
            "borrowed root drain must preserve teardown-reaper ownership"
        );
    }
}

#[test]
fn shutdown_drained_cancels_parked_child_settles_obligation_and_runs_finalizer() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let root = runtime.inner.root_region;
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let settled = Arc::new(AtomicBool::new(false));
        let child_settled = Arc::clone(&settled);
        let mut child = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            cx.spawn(move |child| async move {
                let obligation = child
                    .try_register_obligation_checked(ObligationKind::Lease, child.task_id())
                    .expect("admit native obligation")
                    .expect("runtime obligation token");
                let mut cancelled = std::pin::pin!(child.cancelled());
                let mut parked = Some(parked_tx);
                std::future::poll_fn(|task| {
                    let result = cancelled.as_mut().poll(task);
                    if result.is_pending()
                        && let Some(parked) = parked.take()
                    {
                        parked.send(child.task_id()).expect("publish parked child");
                    }
                    result
                })
                .await;
                child.checkpoint().expect_err("child acknowledges shutdown");
                let reason = child
                    .cancel_reason()
                    .expect("the shutdown drain records its cancel reason");
                assert_eq!(reason.kind, CancelKind::Shutdown);
                assert!(obligation.abort(ObligationAbortReason::Cancel));
                child_settled.store(true, Ordering::Release);
                Outcome::<(), ()>::Cancelled(reason)
            })
            .expect("spawn parked root child")
        });
        let task = parked_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("child actually polled");
        wait_parked(&runtime, task);
        wait_until(
            || {
                runtime
                    .root_drain_snapshot(Duration::ZERO)
                    .pending_obligations
                    == 1
            },
            "obligation publication must materialize before shutdown",
        );
        let finalized = Arc::new(AtomicBool::new(false));
        let finalizer_flag = Arc::clone(&finalized);
        assert!(
            runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .register_async_finalizer(root, async move {
                    assert!(
                        settled.load(Ordering::Acquire),
                        "child settled before root finalization"
                    );
                    finalizer_flag.store(true, Ordering::Release);
                })
        );
        let report = runtime.shutdown_drained(Duration::from_secs(2));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
        assert_eq!(report.live_regions, 0);
        assert_eq!(report.queued_finalizers, 0);
        assert_eq!(report.pending_spawns, 0);
        assert!(!report.has_pending_obligation_posts);
        assert!(finalized.load(Ordering::Acquire));
        let Some(Outcome::Cancelled(reason)) = child
            .try_join()
            .expect("typed child result survives shutdown")
        else {
            panic!("expected a completed domain cancellation");
        };
        assert_eq!(reason.kind, CancelKind::Shutdown);
        let events = runtime.trace_snapshot();
        assert!(events.iter().any(
            |event| matches!(&event.data, crate::trace::TraceData::Message(message)
            if message.starts_with("root_drain outcome=drain_completed"))
        ));
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"case\":{case},\"scenario\":\"child-obligation-finalizer\",\"task\":\"{task:?}\",\"report\":\"{report:?}\"}}"
        );
    }
}
