//! Native public-API regressions for whole-operation pool acquisition bounds.
//!
//! A manager is deliberately parked before the caller expires or cancels it.
//! Native workers execute the tasks; an explicit virtual timer makes deadline
//! ordering deterministic. The host watchdog only releases a broken fixture so
//! a missing wake fails instead of hanging, and its intervention fails the test.
#![cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "sqlite", feature = "postgres", feature = "mysql")
))]

use asupersync::Cx;
use asupersync::database::{
    AsyncConnectionManager, AsyncDbPool, AsyncPooledConnection, DbPoolConfig, DbPoolError,
};
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use asupersync::sync::Notify;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{CancelReason, Outcome, Time};
use std::future::{Future, poll_fn};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Default)]
struct Gate {
    released: AtomicBool,
    pending: AtomicUsize,
    retired: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    async fn wait(&self) {
        self.pending.fetch_add(1, Ordering::SeqCst);
        let _retirement = PendingOperation(self);
        poll_fn(|task| {
            if self.released.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            let replacement = task.waker().clone();
            let previous = self.waker.lock().expect("gate waker").replace(replacement);
            drop(previous);
            if self.released.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        let waker = self.waker.lock().expect("gate waker").take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct PendingOperation<'a>(&'a Gate);

impl Drop for PendingOperation<'_> {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
        self.0.retired.fetch_add(1, Ordering::SeqCst);
        let waker = self.0.waker.lock().expect("gate waker").take();
        drop(waker);
    }
}

#[derive(Default)]
struct Controls {
    pause_connect: AtomicBool,
    pause_validation: AtomicBool,
    connects: AtomicUsize,
    validations: AtomicUsize,
    live: AtomicUsize,
    disconnects: AtomicUsize,
    gate: Gate,
}

struct TestConnection(Arc<Controls>);

impl Drop for TestConnection {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ControlledManager(Arc<Controls>);

impl AsyncConnectionManager for ControlledManager {
    type Connection = TestConnection;
    type Error = io::Error;

    async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
        self.0.connects.fetch_add(1, Ordering::SeqCst);
        if self.0.pause_connect.load(Ordering::Acquire) {
            self.0.gate.wait().await;
        }
        self.0.live.fetch_add(1, Ordering::SeqCst);
        Outcome::Ok(TestConnection(Arc::clone(&self.0)))
    }

    async fn is_valid(&self, _cx: &Cx, _conn: &mut Self::Connection) -> bool {
        self.0.validations.fetch_add(1, Ordering::SeqCst);
        if self.0.pause_validation.load(Ordering::Acquire) {
            self.0.gate.wait().await;
        }
        true
    }

    fn disconnect(&self, conn: Self::Connection) {
        self.0.disconnects.fetch_add(1, Ordering::SeqCst);
        drop(conn);
    }
}

struct Watchdog {
    done: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    fn start(controls: Arc<Controls>, started: Arc<Notify>, fired: Arc<AtomicBool>) -> Self {
        let (done, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            if matches!(
                receiver.recv_timeout(Duration::from_secs(5)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                fired.store(true, Ordering::Release);
                controls.gate.release();
                let _ = started.notify_one();
            }
        });
        Self {
            done: Some(done),
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn runtime(multithread: bool, timer: TimerDriverHandle) -> Runtime {
    let builder = if multithread {
        RuntimeBuilder::new().worker_threads(2).with_sharded_state(true)
    } else {
        RuntimeBuilder::current_thread()
    };
    builder.with_timer_driver(timer).build().expect("native runtime")
}

async fn acquire<'a>(
    pool: &'a AsyncDbPool<ControlledManager>,
    cx: &Cx,
    client_scoped: bool,
) -> AsyncPooledConnection<'a, ControlledManager> {
    let outcome = if client_scoped {
        pool.get_for_client_outcome(cx, "tenant").await
    } else {
        pool.get_outcome(cx).await
    };
    match outcome {
        Outcome::Ok(connection) => connection,
        other => panic!("connection admission must recover: {other:?}"),
    }
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    Connect,
    Validate,
}

fn parked_acquisition(multithread: bool, stage: Stage, client_scoped: bool, cancel: bool) {
    let clock = Arc::new(VirtualClock::new());
    let timers = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = runtime(multithread, timers.clone());
    let controls = Arc::new(Controls::default());
    let started = Arc::new(Notify::new());
    let fired = Arc::new(AtomicBool::new(false));
    let watchdog = Watchdog::start(
        Arc::clone(&controls),
        Arc::clone(&started),
        Arc::clone(&fired),
    );
    let check_timers = timers.clone();
    let check_controls = Arc::clone(&controls);

    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("native root context");
        let pool = Arc::new(AsyncDbPool::new(
            ControlledManager(Arc::clone(&controls)),
            DbPoolConfig::with_max_size(1)
                .max_connections_per_client(Some(1))
                .connection_timeout(Duration::from_secs(30)),
        ));
        if matches!(stage, Stage::Validate) {
            acquire(&pool, &cx, client_scoped).await.return_to_pool();
            controls.pause_validation.store(true, Ordering::Release);
        } else {
            controls.pause_connect.store(true, Ordering::Release);
        }

        let parked = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(Mutex::new(None));
        let child_owner = Arc::clone(&owner);
        let child_parked = Arc::clone(&parked);
        let child_started = Arc::clone(&started);
        let child_pool = Arc::clone(&pool);
        let deadline = Time::from_millis(100);
        let mut child = cx
            .spawn(move |child_cx| async move {
                *child_owner.lock().expect("acquisition owner") = Some(child_cx.clone());
                let operation = async {
                    if client_scoped {
                        child_pool
                            .get_for_client_with_deadline_outcome(&child_cx, "tenant", deadline)
                            .await
                    } else {
                        child_pool.get_with_deadline_outcome(&child_cx, deadline).await
                    }
                };
                let mut operation = std::pin::pin!(operation);
                poll_fn(|task| {
                    let result = operation.as_mut().poll(task);
                    if result.is_pending() && !child_parked.swap(true, Ordering::AcqRel) {
                        let _ = child_started.notify_one();
                    }
                    result
                })
                .await
                .map(|connection| connection.return_to_pool())
            })
            .expect("spawn native acquisition");

        started.notified().await;
        let reached_pending = parked.load(Ordering::Acquire);
        let pending_operations = controls.gate.pending.load(Ordering::SeqCst);
        let reserved = pool.stats();
        let reason = CancelReason::timeout()
            .with_message("native pool caller cancelled")
            .with_cause(CancelReason::user("request ended"));
        if cancel {
            let owner = owner.lock().expect("acquisition owner").clone();
            if let Some(owner) = owner {
                let reason = reason.clone();
                thread::spawn(move || owner.set_cancel_reason(reason))
                    .join()
                    .expect("cross-thread owner cancellation");
            }
        } else {
            clock.advance_to(deadline);
            let _ = timers.process_timers();
        }

        let joined = child.join(&cx).await;
        let after = pool.stats();
        assert!(reached_pending, "{stage:?} must park before its stop boundary");
        assert_eq!(pending_operations, 1, "{stage:?} manager operation must be pending");
        assert_eq!(reserved.total, 1, "the pending operation owns one pool slot");
        if cancel {
            assert!(
                matches!(&joined, Ok(Outcome::Cancelled(actual)) if actual == &reason),
                "native cancellation must retain its exact domain outcome: {joined:?}"
            );
            assert_eq!(after.total_timeouts, 0);
        } else {
            assert!(
                matches!(&joined, Ok(Outcome::Err(DbPoolError::AcquireTimeout))),
                "the explicit deadline must wake the parked manager: {joined:?}"
            );
            assert_eq!(after.total_timeouts, 1);
        }
        assert_eq!(after.total, 0);
        assert_eq!(after.pending_waiters, 0);
        assert_eq!(controls.gate.pending.load(Ordering::SeqCst), 0);
        assert_eq!(controls.gate.retired.load(Ordering::SeqCst), 1);
        assert_eq!(controls.live.load(Ordering::SeqCst), 0);
        assert_eq!(
            controls.disconnects.load(Ordering::SeqCst),
            usize::from(matches!(stage, Stage::Validate))
        );
        assert!(timers.is_empty(), "terminal acquisition must retire its timer");

        // A same-client checkout proves both physical capacity and its private
        // quota recovered, without reaching into the pool's internal mutex.
        controls.pause_connect.store(false, Ordering::Release);
        controls.pause_validation.store(false, Ordering::Release);
        acquire(&pool, &cx, client_scoped).await.return_to_pool();
        assert_eq!(pool.stats().idle, 1);
        pool.close();
        assert_eq!(pool.stats().total, 0);
        assert_eq!(controls.live.load(Ordering::SeqCst), 0);
    }));

    drop(watchdog);
    assert!(!fired.load(Ordering::Acquire), "a manager completion must not be needed to wake the caller");
    assert!(check_timers.is_empty());
    assert_eq!(check_controls.live.load(Ordering::SeqCst), 0);
    let drain = runtime.shutdown_drained(Duration::from_secs(3));
    assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
    assert_eq!(drain.live_tasks, 0);
    assert_eq!(drain.live_regions, 0);
    assert_eq!(drain.pending_spawns, 0);
    assert_eq!(drain.pending_obligations, 0);
    assert_eq!(drain.queued_finalizers, 0);
    assert!(!drain.has_pending_obligation_posts);
    assert!(runtime.is_quiescent());
}

#[test]
fn native_deadline_retires_parked_connect_and_validation_with_quota_recovery() {
    for multithread in [false, true] {
        for stage in [Stage::Connect, Stage::Validate] {
            for client_scoped in [false, true] {
                parked_acquisition(multithread, stage, client_scoped, false);
            }
        }
    }
}

#[test]
fn native_cross_thread_cancellation_retires_parked_managers_with_exact_reason() {
    for multithread in [false, true] {
        for stage in [Stage::Connect, Stage::Validate] {
            for client_scoped in [false, true] {
                parked_acquisition(multithread, stage, client_scoped, true);
            }
        }
    }
}
