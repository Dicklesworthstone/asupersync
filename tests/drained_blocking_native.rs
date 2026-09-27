//! Real blocking-pool ownership through cancellation, capture destruction and
//! abandoned return-value destruction. Gates establish the queued/running/Drop
//! states before each shutdown observation; deadlines only bound failed tests.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::observability::TaskInspectorConfig;
use asupersync::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
use asupersync::types::{Budget, CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(45))
        .expect("native drained blocking scenario must terminate");
    worker.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    builder.blocking_threads(1, 1).build().unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert!(!report.has_pending_obligation_posts);
}

fn assert_owned_timeout(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_millis(20));
    assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
    assert!(report.live_tasks > 0, "unfinished pool work must retain a real task: {report:?}");
}

#[test]
fn running_work_retains_root_and_preserves_typed_cancellation() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let (started, mut start) = oneshot::channel();
            let (release, wait_release) = mpsc::channel();
            let handle = runtime.handle();
            let mut task = handle.spawn_blocking_drained(move |cx| {
                started.send_blocking(cx.clone()).unwrap();
                wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
                cx.checkpoint().expect_err("root close reaches the actual blocking context");
                Err::<usize, _>(cx.cancel_reason().unwrap().kind)
            }).unwrap();
            drop(handle);
            let actual_cx = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                start.recv(&cx).await.unwrap()
            });
            assert_eq!(actual_cx.task_id(), task.task_id());
            let inspector = runtime.task_inspector(TaskInspectorConfig::default());
            runtime.block_on(async {
                let deadline = Instant::now() + Duration::from_secs(5);
                while inspector.inspect_task(task.task_id()).unwrap().poll_count == 0 {
                    assert!(Instant::now() < deadline, "controller must reach its Pending wait");
                    yield_now().await;
                }
            });
            assert_owned_timeout(&runtime);
            assert_eq!(actual_cx.cancel_reason().unwrap().kind, CancelKind::Shutdown);
            assert!(!task.is_finished());
            let before = inspector.inspect_task(task.task_id()).unwrap().poll_count;
            assert_owned_timeout(&runtime);
            let after = inspector.inspect_task(task.task_id()).unwrap().poll_count;
            assert!(after.saturating_sub(before) <= 8,
                "acknowledged cancellation must park instead of self-repolling: {before} -> {after}");
            release.send(()).unwrap();
            drained(&runtime);
            assert!(task.is_finished());
            assert_eq!(futures_lite::future::block_on(task.join()).unwrap(), Err(CancelKind::Shutdown));
            println!("drained_blocking workers={workers} phase=running polls={before}->{after} result=typed_shutdown root=quiescent");
        }
    });
}

struct ParkedDrop {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    dropped: Arc<AtomicUsize>,
}

impl Drop for ParkedDrop {
    fn drop(&mut self) {
        self.entered.take().unwrap().send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn parked_drop() -> (ParkedDrop, mpsc::Receiver<()>, mpsc::Sender<()>, Arc<AtomicUsize>) {
    let (entered, wait_entered) = mpsc::channel();
    let (release, wait_release) = mpsc::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    (ParkedDrop { entered: Some(entered), release: wait_release, dropped: Arc::clone(&dropped) },
     wait_entered, release, dropped)
}

#[test]
fn queued_cancellation_waits_for_capture_destruction_even_after_handle_drop() {
    bounded(|| {
        for workers in [1, 2] {
            for abandon in [false, true] {
                let runtime = runtime(workers);
                let (occupied, wait_occupied) = mpsc::channel();
                let (release_pool, pool_gate) = mpsc::channel();
                let occupying = runtime.spawn_blocking(move || {
                    occupied.send(()).unwrap();
                    pool_gate.recv_timeout(Duration::from_secs(10)).unwrap();
                }).unwrap();
                wait_occupied.recv_timeout(Duration::from_secs(5)).unwrap();
                let (capture, dropping, release_drop, dropped) = parked_drop();
                let calls = Arc::new(AtomicUsize::new(0));
                let called = Arc::clone(&calls);
                let mut task = Some(runtime.spawn_blocking_drained(move |_cx| {
                    called.fetch_add(1, Ordering::SeqCst);
                    drop(capture);
                    99_u8
                }).unwrap());
                let pool = runtime.blocking_handle().unwrap();
                runtime.block_on(async {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while pool.pending_count() == 0 {
                        assert!(Instant::now() < deadline, "second job must reach the actual pool queue");
                        yield_now().await;
                    }
                });
                assert_eq!(pool.pending_count(), 1);
                task.as_ref().unwrap().abort_with_reason(CancelReason::user("queued cancellation"));
                if abandon { drop(task.take()); }
                assert_owned_timeout(&runtime);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                release_pool.send(()).unwrap();
                dropping.recv_timeout(Duration::from_secs(5)).unwrap();
                // The pool's completion bit may already be true here. The
                // controller must instead await our blocked capture destructor.
                assert_owned_timeout(&runtime);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                if let Some(task) = &task { assert!(!task.is_finished()); }
                release_drop.send(()).unwrap();
                drained(&runtime);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
                assert!(occupying.wait_timeout(Duration::from_secs(1)));
                if let Some(mut task) = task {
                    assert!(matches!(futures_lite::future::block_on(task.join()),
                        Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Shutdown));
                }
                println!("drained_blocking workers={workers} abandon={abandon} phase=queued calls=0 capture_drops=1 root=quiescent");
            }
        }
    });
}

#[test]
fn abandoned_return_value_retires_before_root_closes() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let (started, mut start) = oneshot::channel();
            let (release_work, work_gate) = mpsc::channel();
            let (result, dropping, release_drop, dropped) = parked_drop();
            let task = runtime.spawn_blocking_drained(move |_cx| {
                started.send_blocking(()).unwrap();
                work_gate.recv_timeout(Duration::from_secs(10)).unwrap();
                result
            }).unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                start.recv(&cx).await.unwrap();
            });
            drop(task);
            assert_owned_timeout(&runtime);
            release_work.send(()).unwrap();
            dropping.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_owned_timeout(&runtime);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            release_drop.send(()).unwrap();
            drained(&runtime);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            println!("drained_blocking workers={workers} phase=abandoned_result result_drops=1 root=quiescent");
        }
    });
}

#[test]
fn scope_close_waits_for_targeted_work_and_join_wait_can_resume() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let expected_region = region.region_id();
                let scope = region.cx().scope();
                let (started, mut start) = oneshot::channel();
                let (release, wait_release) = mpsc::channel();
                let mut task = cx.spawn_blocking_drained_in(&scope, move |child| {
                    assert_eq!(child.region_id(), expected_region);
                    started.send_blocking(()).unwrap();
                    wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
                    assert!(child.checkpoint().is_err());
                    73_u8
                }).unwrap();
                start.recv(&cx).await.unwrap();
                let mut joining = Box::pin(task.join());
                poll_fn(|poll_cx| {
                    assert!(joining.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                }).await;
                drop(joining);
                let mut closing = Box::pin(region.close());
                poll_fn(|poll_cx| {
                    assert!(closing.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(!task.is_finished());
                // Wait for the actual child cancellation envelope before the
                // synchronous closure may return; a sleeping guess is unnecessary.
                let inspector = runtime.task_inspector(TaskInspectorConfig::default());
                let deadline = Instant::now() + Duration::from_secs(5);
                while !inspector.inspect_task(task.task_id()).unwrap().is_cancelling() {
                    assert!(Instant::now() < deadline, "close must cancel the target task");
                    yield_now().await;
                }
                release.send(()).unwrap();
                closing.await.unwrap();
                assert_eq!(task.join().await.unwrap(), 73);
                println!("drained_blocking workers={workers} phase=scope region={expected_region:?} result=73 close=complete");
            });
            drained(&runtime);
        }
    });
}

#[test]
fn success_panic_prestart_abort_and_missing_pool_have_exact_results() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let mut success = cx.spawn_blocking_drained(|child| {
                    child.checkpoint().unwrap();
                    41_u8
                }).unwrap();
                assert_eq!(success.join().await.unwrap(), 41);
                let mut panicked = cx.spawn_blocking_drained(|_| -> u8 {
                    panic!("drained closure panic sentinel");
                }).unwrap();
                assert!(matches!(panicked.join().await,
                    Err(JoinError::Panicked(payload)) if payload.message() == "drained closure panic sentinel"));
            });
            drained(&runtime);
        }
        // The loaned current-thread worker cannot dispatch another task during
        // this root poll. Submission and abort occur before its first await.
        let runtime = runtime(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut task = cx.spawn_blocking_drained(move |_| {
                called.fetch_add(1, Ordering::SeqCst);
            }).unwrap();
            task.abort();
            assert_eq!(calls.load(Ordering::SeqCst), 0, "abort precedes first admission poll");
            assert!(matches!(task.join().await,
                Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::User));
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drained(&runtime);
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        assert!(matches!(runtime.spawn_blocking_drained(|_| ()),
            Err(asupersync::runtime::SpawnError::RuntimeUnavailable)));
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        assert!(matches!(cx.spawn_blocking_drained(|_| ()),
            Err(asupersync::runtime::SpawnError::RuntimeUnavailable)));
        drained(&runtime);
    });
}
