//! Native worker, publication and retirement witnesses for offloaded sends.
#![cfg(not(target_arch = "wasm32"))]

use super::super::{
    AuthenticatedEcError, AuthenticatedEcReceiver, AuthenticatedEcSender, EcConfig, EcError,
    authenticated_channel,
};
use crate::cx::Cx;
use crate::cx::macaroon::MacaroonToken;
use crate::runtime::blocking_pool::{BlockingPoolHandle, BlockingTaskHandle};
use crate::runtime::{
    BlockingAdmissionPolicy, RootDrainOutcome, Runtime, RuntimeBuilder, SpawnError,
};
use crate::security::{AuthKey, SecurityContext};
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = std_mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("offloaded erasure send must finish within its wall watchdog");
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn runtime() -> Runtime {
    runtime_with_workers(1)
}

fn runtime_with_workers(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .enable_platform_reactor(false)
        .blocking_threads(1, 1)
        .root_region_limits(crate::record::RegionLimits {
            max_obligations: Some(1),
            ..crate::record::RegionLimits::UNLIMITED
        })
        .build()
        .unwrap()
}

fn config() -> EcConfig {
    EcConfig {
        symbol_size: 64,
        repair_overhead: 6,
        max_message_size: 16 * 1024,
    }
}

fn pair(capacity: usize) -> (AuthenticatedEcSender, AuthenticatedEcReceiver) {
    authenticated_channel(
        config(),
        capacity,
        &SecurityContext::for_testing(0xec_2026),
        [17; 32],
    )
    .unwrap()
}

struct HeldWorker {
    release: Option<std_mpsc::Sender<()>>,
    work: BlockingTaskHandle,
}

impl HeldWorker {
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            release.send(()).unwrap();
        }
        assert!(self.work.wait_timeout(WAIT));
    }
}

impl Drop for HeldWorker {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let _ = self.work.wait_timeout(WAIT);
    }
}

fn hold_worker(pool: &BlockingPoolHandle) -> HeldWorker {
    let (started, entered) = std_mpsc::channel();
    let (release, wait) = std_mpsc::channel();
    let work = pool
        .try_spawn(move || {
            started.send(()).unwrap();
            wait.recv_timeout(WAIT).unwrap();
        })
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    HeldWorker {
        release: Some(release),
        work,
    }
}

async fn pending_once<F: Future>(future: F) {
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "expected worker state was not reached"
        );
        crate::runtime::yield_now().await;
    }
}

fn quiescent(runtime: &Runtime) {
    let report = runtime.shutdown_drained(WAIT);
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
}

#[derive(Clone)]
struct SerializeProbe {
    calls: Arc<AtomicUsize>,
    on_worker: Arc<AtomicBool>,
    text: &'static str,
}

impl SerializeProbe {
    fn new(text: &'static str) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            on_worker: Arc::new(AtomicBool::new(false)),
            text,
        }
    }

    fn observe(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.on_worker.store(
            std::thread::current()
                .name()
                .is_some_and(|name| name.contains("-blocking-")),
            Ordering::SeqCst,
        );
    }
}

impl serde::Serialize for SerializeProbe {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.observe();
        serializer.serialize_str(self.text)
    }
}

struct BlockedValue {
    probe: SerializeProbe,
    entered: std_mpsc::Sender<()>,
    release: std_mpsc::Receiver<()>,
}

impl serde::Serialize for BlockedValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.probe.observe();
        self.entered.send(()).unwrap();
        self.release.recv_timeout(WAIT).unwrap();
        serializer.serialize_str(self.probe.text)
    }
}

#[test]
fn queued_send_resumes_once_and_matches_inline_authenticated_output() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime_with_workers(workers);
            let pool = runtime.blocking_handle().unwrap();
            let mut held = hold_worker(&pool);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let (mut tx, mut rx) = pair(1);
                let data: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
                let expected = config()
                    .encode_message_authenticated(0, &data, &tx.auth)
                    .unwrap();
                let mut session = tx.start_send_offloaded(&cx, data.clone()).await.unwrap();
                assert_eq!(pool.pending_count(), 0, "construction dispatches no worker");
                assert_eq!(
                    rx.rx.telemetry_snapshot(1).reserved_uncommitted_obligations,
                    1
                );
                pending_once(session.run()).await;
                until(|| pool.pending_count() == 1).await;
                let mut heartbeat = cx.spawn(|_| async { 17 }).unwrap();
                assert_eq!(heartbeat.join(&cx).await.unwrap(), 17);
                for _ in 0..3 {
                    pending_once(session.run()).await;
                    crate::runtime::yield_now().await;
                    assert_eq!(pool.pending_count(), 1);
                    assert!(
                        rx.rx.is_empty(),
                        "an unfinished encode publishes no envelope"
                    );
                }
                assert!(!session.is_finished());
                held.release();
                assert_eq!(session.run().await.unwrap(), 0);
                assert!(session.is_finished());
                assert!(matches!(
                    session.run().await,
                    Err(AuthenticatedEcError::InvalidSession(_))
                ));
                drop(session);
                let message = rx.rx.try_recv().unwrap();
                assert_eq!(message.header, expected.0);
                assert_eq!(
                    message.symbols, expected.1,
                    "tags and repair symbols match the inline oracle"
                );
                assert_eq!(rx.decode(&message).unwrap(), data);
                assert_eq!(tx.next_message_id, Some(1));
                assert_eq!(
                    rx.rx.telemetry_snapshot(1).reserved_uncommitted_obligations,
                    0
                );
                assert_eq!(tx.send_offloaded(&cx, Vec::new()).await.unwrap(), 1);
                assert!(rx.recv(&cx).await.unwrap().is_empty());
            }));
            quiescent(&runtime);
        }
    });
}

#[test]
fn typed_send_waits_for_capacity_and_serializes_only_on_the_worker() {
    bounded(|| {
        let runtime = runtime();
        let pool = runtime.blocking_handle().unwrap();
        let mut held = hold_worker(&pool);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, mut rx) = pair(1);
            assert_eq!(tx.send(&cx, b"full").await.unwrap(), 0);
            let probe = SerializeProbe::new("after capacity");
            let mut abandoned = Box::pin(tx.start_send_value_offloaded(&cx, probe.clone()));
            pending_once(abandoned.as_mut()).await;
            assert_eq!(rx.rx.telemetry_snapshot(2).send_waiter_count, 1);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            assert_eq!(pool.pending_count(), 0);
            drop(abandoned);
            assert_eq!(rx.rx.telemetry_snapshot(2).send_waiter_count, 0);

            let mut waiting = Box::pin(tx.start_send_value_offloaded(&cx, probe.clone()));
            pending_once(waiting.as_mut()).await;
            assert_eq!(rx.recv(&cx).await.unwrap(), b"full");
            let mut session = waiting.await.unwrap();
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            pending_once(session.run()).await;
            until(|| pool.pending_count() == 1).await;
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            held.release();
            assert_eq!(session.run().await.unwrap(), 1);
            drop(session);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert!(probe.on_worker.load(Ordering::SeqCst));
            assert_eq!(
                rx.recv_value::<String>(&cx).await.unwrap(),
                "after capacity"
            );
            assert_eq!(
                rx.rx.telemetry_snapshot(2).reserved_uncommitted_obligations,
                0
            );
        }));
        quiescent(&runtime);
    });
}

#[test]
fn cancelled_or_dropped_running_serializer_retains_the_endpoint_work_slot() {
    bounded(|| {
        for cancel in [false, true] {
            let runtime = runtime();
            let pool = runtime.blocking_handle().unwrap();
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let (tx, mut rx) = pair(1);
                let first = SerializeProbe::new("never published");
                let (entered, started) = std_mpsc::channel();
                let (release, wait_release) = std_mpsc::channel();
                let (finish, mut command) = crate::channel::oneshot::channel::<()>();
                let value = BlockedValue {
                    probe: first.clone(),
                    entered,
                    release: wait_release,
                };
                let mut owner = cx
                    .spawn(move |owner| async move {
                        let mut tx = tx;
                        let mut session =
                            tx.start_send_value_offloaded(&owner, value).await.unwrap();
                        pending_once(session.run()).await;
                        let _ = command.recv(&owner).await;
                        if cancel {
                            assert!(matches!(
                                session.run().await,
                                Err(AuthenticatedEcError::Message(EcError::Cancelled))
                            ));
                            assert!(session.is_finished());
                        }
                        drop(session);
                        tx
                    })
                    .unwrap();
                until(move || started.try_recv().is_ok()).await;
                assert_eq!(first.calls.load(Ordering::SeqCst), 1);
                assert!(first.on_worker.load(Ordering::SeqCst));
                if cancel {
                    owner.abort();
                } else {
                    finish.send_blocking(()).unwrap();
                }
                let mut tx = owner.join(&cx).await.unwrap();
                assert!(rx.rx.is_empty());
                assert_eq!(tx.next_message_id, Some(0));
                assert_eq!(
                    tx.offload.available_permits(),
                    0,
                    "abandoned running input still owns the only encoding slot"
                );
                assert_eq!(
                    rx.rx.telemetry_snapshot(3).reserved_uncommitted_obligations,
                    0
                );

                let next = SerializeProbe::new("successor");
                let mut session = tx
                    .start_send_value_offloaded(&cx, next.clone())
                    .await
                    .unwrap();
                for _ in 0..3 {
                    pending_once(session.run()).await;
                    crate::runtime::yield_now().await;
                    assert_eq!(
                        pool.pending_count(),
                        0,
                        "a successor must wait for the endpoint slot before dispatching"
                    );
                    assert_eq!(next.calls.load(Ordering::SeqCst), 0);
                }
                release.send(()).unwrap();
                assert_eq!(session.run().await.unwrap(), 0);
                drop(session);
                assert_eq!(next.calls.load(Ordering::SeqCst), 1);
                assert_eq!(rx.recv_value::<String>(&cx).await.unwrap(), "successor");
                assert_eq!(tx.offload.available_permits(), 1);
            }));
            quiescent(&runtime);
        }
    });
}

#[test]
fn unavailable_or_forbidden_workers_and_spawn_denial_publish_nothing() {
    bounded(|| {
        for mode in 0..3 {
            let builder = RuntimeBuilder::current_thread().enable_platform_reactor(false);
            let runtime = match mode {
                0 => builder.blocking_threads(0, 0),
                1 => builder
                    .blocking_threads(1, 1)
                    .blocking_admission_policy(BlockingAdmissionPolicy::Forbidden),
                _ => builder
                    .blocking_threads(1, 1)
                    .require_spawn_authorization(AuthKey::from_seed(999)),
            }
            .build()
            .unwrap();
            runtime.block_on(async move {
                let root = Cx::current().unwrap();
                let parent = if mode == 2 {
                    root.clone().with_macaroon(MacaroonToken::mint(
                        &AuthKey::from_seed(999),
                        &format!("spawn:region_{}", root.region_id().as_u64()),
                        "erasure-admission-test",
                    ))
                } else {
                    root.clone()
                };
                let mut task = parent
                    .spawn(move |cx| async move {
                        // Admit the actual task with valid authority, then test its
                        // nested encoding admission using a wrong-key capability.
                        let cx = if mode == 2 {
                            let target = format!("spawn:region_{}", cx.region_id().as_u64());
                            cx.with_macaroon(MacaroonToken::mint(
                                &AuthKey::from_seed(1000),
                                &target,
                                "denied-encoding-worker",
                            ))
                        } else {
                            cx
                        };
                        let (mut tx, rx) = pair(1);
                        let probe = SerializeProbe::new("must not serialize");
                        let result = tx.send_value_offloaded(&cx, probe.clone()).await;
                        if mode == 2 {
                            assert!(matches!(
                                result,
                                Err(AuthenticatedEcError::WorkerAdmission(
                                    SpawnError::AuthorizationDenied { .. }
                                ))
                            ));
                        } else {
                            assert!(matches!(
                                result,
                                Err(AuthenticatedEcError::WorkerAdmission(
                                    SpawnError::RuntimeUnavailable
                                ))
                            ));
                        }
                        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
                        assert!(rx.rx.is_empty());
                        assert_eq!(tx.next_message_id, Some(0));
                        assert_eq!(tx.offload.available_permits(), 1);
                        assert_eq!(
                            rx.rx.telemetry_snapshot(4).reserved_uncommitted_obligations,
                            0
                        );
                    })
                    .unwrap();
                task.join(&root).await.unwrap();
            });
            quiescent(&runtime);
        }
    });
}

#[test]
fn dropped_queued_send_keeps_worker_owned_until_actual_root_retirement() {
    bounded(|| {
        let runtime = runtime();
        let pool = runtime.blocking_handle().unwrap();
        let held = hold_worker(&pool);
        let (tx, rx, mut held) = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, rx) = pair(1);
            let mut session = tx.start_send_offloaded(&cx, vec![7; 513]).await.unwrap();
            pending_once(session.run()).await;
            until(|| pool.pending_count() == 1).await;
            drop(session);
            assert_eq!(tx.offload.available_permits(), 0);
            assert!(rx.rx.is_empty());
            assert_eq!(
                rx.rx.telemetry_snapshot(5).reserved_uncommitted_obligations,
                0
            );
            (tx, rx, held)
        }));
        let report = runtime.shutdown_drained(Duration::from_millis(20));
        assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
        assert!(report.live_tasks > 0, "queued captures remain region-owned");
        held.release();
        quiescent(&runtime);
        assert_eq!(tx.offload.available_permits(), 1);
        assert_eq!(tx.next_message_id, Some(0));
        assert!(rx.rx.is_empty());
    });
}

#[test]
fn publication_retires_id_before_panicking_receiver_wake_and_cannot_replay() {
    struct PanicWake;
    impl Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("receiver wake after offloaded publication");
        }
    }

    bounded(|| {
        let runtime = runtime();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, mut rx) = pair(1);
            {
                let waker = Waker::from(Arc::new(PanicWake));
                let mut task = Context::from_waker(&waker);
                assert!(rx.rx.poll_recv(&cx, &mut task).is_pending());
            }
            let permit = tx.reserve(&cx).await.unwrap();
            let mut session = permit.start_send_offloaded(b"committed".to_vec()).unwrap();
            let mut waiting = Box::pin(session.run());
            poll_fn(|task| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    waiting.as_mut().poll(task)
                })) {
                    Ok(Poll::Pending) => Poll::Pending,
                    Ok(Poll::Ready(result)) => panic!("receiver wake did not panic: {result:?}"),
                    Err(_) => Poll::Ready(()),
                }
            })
            .await;
            drop(waiting);
            assert!(session.is_finished());
            assert!(matches!(
                session.run().await,
                Err(AuthenticatedEcError::InvalidSession(_))
            ));
            drop(session);
            assert_eq!(tx.next_message_id, Some(1));
            assert_eq!(rx.rx.len(), 1);
            assert_eq!(rx.recv(&cx).await.unwrap(), b"committed");
            assert_eq!(tx.send_offloaded(&cx, b"next".to_vec()).await.unwrap(), 1);
            assert_eq!(rx.recv(&cx).await.unwrap(), b"next");
        }));
        quiescent(&runtime);
    });
}

#[test]
fn serialization_overflow_and_worker_panic_abort_without_consuming_message_id() {
    struct PanicSerialize;
    impl serde::Serialize for PanicSerialize {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            panic!("offloaded serializer panic");
        }
    }

    bounded(|| {
        let runtime = runtime();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, mut rx) = authenticated_channel(
                EcConfig {
                    max_message_size: 32,
                    ..config()
                },
                1,
                &SecurityContext::for_testing(11),
                [7; 32],
            )
            .unwrap();
            assert!(matches!(
                tx.send_value_offloaded(&cx, "x".repeat(64)).await,
                Err(AuthenticatedEcError::Message(
                    EcError::MessageTooLarge { .. }
                ))
            ));
            assert!(rx.rx.is_empty());
            assert_eq!(tx.next_message_id, Some(0));
            assert!(matches!(
                tx.send_value_offloaded(&cx, PanicSerialize).await,
                Err(AuthenticatedEcError::WorkerFailed(_))
            ));
            assert!(rx.rx.is_empty());
            assert_eq!(tx.next_message_id, Some(0));
            assert_eq!(tx.offload.available_permits(), 1);
            assert_eq!(
                rx.rx.telemetry_snapshot(6).reserved_uncommitted_obligations,
                0
            );
            assert_eq!(tx.send_value_offloaded(&cx, "recovered").await.unwrap(), 0);
            assert_eq!(rx.recv_value::<String>(&cx).await.unwrap(), "recovered");
        }));
        quiescent(&runtime);
    });
}

#[test]
fn queued_receive_resumes_one_worker_and_preserves_fifo_on_both_schedulers() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime_with_workers(workers);
            let pool = runtime.blocking_handle().unwrap();
            let mut held = hold_worker(&pool);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let (mut tx, mut rx) = pair(2);
                let first: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
                tx.send(&cx, &first).await.unwrap();
                tx.send(&cx, b"second").await.unwrap();
                let mut session = rx.start_recv_offloaded(&cx).unwrap();
                assert_eq!(tx.tx.telemetry_snapshot(11).queued_messages, 2);
                assert_eq!(pool.pending_count(), 0);
                pending_once(session.run()).await;
                until(|| pool.pending_count() == 1).await;
                assert_eq!(tx.tx.telemetry_snapshot(11).queued_messages, 1);
                let mut heartbeat = cx.spawn(|_| async { 23 }).unwrap();
                assert_eq!(heartbeat.join(&cx).await.unwrap(), 23);
                for _ in 0..3 {
                    pending_once(session.run()).await;
                    crate::runtime::yield_now().await;
                    assert_eq!(pool.pending_count(), 1);
                    assert_eq!(tx.tx.telemetry_snapshot(11).queued_messages, 1);
                }
                assert!(!session.is_finished());
                held.release();
                assert_eq!(session.run().await.unwrap(), first);
                assert!(session.is_finished());
                assert!(matches!(
                    session.run().await,
                    Err(AuthenticatedEcError::InvalidSession(_))
                ));
                drop(session);
                assert!(rx.pending.is_none());
                assert_eq!(rx.recv_offloaded(&cx).await.unwrap(), b"second");
                assert!(rx.pending.is_none());
                assert_eq!(rx.offload.available_permits(), 1);
            }));
            quiescent(&runtime);
        }
    });
}

#[test]
fn dropped_receive_retains_fifo_and_gates_only_the_next_offloaded_decode() {
    bounded(|| {
        for inline in [false, true] {
            let runtime = runtime();
            let pool = runtime.blocking_handle().unwrap();
            let mut held = hold_worker(&pool);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let (mut tx, mut rx) = pair(2);
                tx.send(&cx, b"retained first").await.unwrap();
                tx.send(&cx, b"queued second").await.unwrap();
                let mut session = rx.start_recv_offloaded(&cx).unwrap();
                pending_once(session.run()).await;
                until(|| pool.pending_count() == 1).await;
                drop(session);
                assert_eq!(rx.pending.as_ref().unwrap().header.header.message_id, 0);
                assert_eq!(rx.offload.available_permits(), 0);
                assert_eq!(tx.tx.telemetry_snapshot(12).queued_messages, 1);

                if inline {
                    // The legacy inline path deliberately permits its own
                    // workspace while abandoned offloaded work retires.
                    assert_eq!(rx.recv(&cx).await.unwrap(), b"retained first");
                    assert!(rx.pending.is_none());
                    assert_eq!(tx.tx.telemetry_snapshot(12).queued_messages, 1);
                    assert_eq!(rx.recv(&cx).await.unwrap(), b"queued second");
                    assert_eq!(tx.tx.telemetry_snapshot(12).queued_messages, 0);
                    assert_eq!(pool.pending_count(), 1);
                    held.release();
                    until(|| rx.offload.available_permits() == 1).await;
                } else {
                    let mut retry = rx.start_recv_offloaded(&cx).unwrap();
                    for _ in 0..3 {
                        pending_once(retry.run()).await;
                        crate::runtime::yield_now().await;
                        assert_eq!(tx.tx.telemetry_snapshot(12).queued_messages, 1);
                        assert_eq!(
                            pool.pending_count(),
                            1,
                            "retry waits before admitting a second decode"
                        );
                    }
                    held.release();
                    assert_eq!(retry.run().await.unwrap(), b"retained first");
                    drop(retry);
                    assert!(rx.pending.is_none());
                    assert_eq!(rx.recv_offloaded(&cx).await.unwrap(), b"queued second");
                }
                assert!(rx.pending.is_none());
                assert_eq!(rx.offload.available_permits(), 1);
            }));
            quiescent(&runtime);
        }
    });
}

#[test]
fn cancelled_receive_keeps_pending_message_for_a_fresh_live_owner() {
    bounded(|| {
        let runtime = runtime();
        let pool = runtime.blocking_handle().unwrap();
        let mut held = hold_worker(&pool);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, rx) = pair(2);
            tx.send(&cx, b"cancel does not consume").await.unwrap();
            tx.send(&cx, b"next message").await.unwrap();
            let mut owner = cx
                .spawn(move |owner| async move {
                    let mut rx = rx;
                    let mut session = rx.start_recv_offloaded(&owner).unwrap();
                    assert!(matches!(
                        session.run().await,
                        Err(AuthenticatedEcError::Message(EcError::Cancelled))
                    ));
                    assert!(session.is_finished());
                    drop(session);
                    rx
                })
                .unwrap();
            until(|| pool.pending_count() == 1).await;
            owner.abort();
            let mut rx = owner.join(&cx).await.unwrap();
            assert_eq!(rx.pending.as_ref().unwrap().header.header.message_id, 0);
            assert_eq!(tx.tx.telemetry_snapshot(13).queued_messages, 1);
            let mut retry = rx.start_recv_offloaded(&cx).unwrap();
            pending_once(retry.run()).await;
            assert_eq!(pool.pending_count(), 1);
            held.release();
            assert_eq!(retry.run().await.unwrap(), b"cancel does not consume");
            drop(retry);
            assert!(rx.pending.is_none());
            assert_eq!(rx.recv_offloaded(&cx).await.unwrap(), b"next message");
        }));
        quiescent(&runtime);
    });
}

#[test]
fn receive_resource_refusal_and_worker_authorization_failure_preserve_delivery() {
    bounded(|| {
        for forbidden in [false, true] {
            let builder = RuntimeBuilder::current_thread().enable_platform_reactor(false);
            let runtime = if forbidden {
                builder
                    .blocking_threads(1, 1)
                    .blocking_admission_policy(BlockingAdmissionPolicy::Forbidden)
            } else {
                builder.blocking_threads(0, 0)
            }
            .build()
            .unwrap();
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let (mut tx, mut rx) = pair(1);
                tx.send(&cx, b"still queued").await.unwrap();
                assert!(matches!(
                    rx.start_recv_offloaded(&cx),
                    Err(AuthenticatedEcError::WorkerAdmission(
                        SpawnError::RuntimeUnavailable
                    ))
                ));
                assert!(
                    rx.pending.is_none(),
                    "resource refusal happens before dequeue"
                );
                assert_eq!(tx.tx.telemetry_snapshot(14).queued_messages, 1);
                assert_eq!(rx.recv(&cx).await.unwrap(), b"still queued");
            }));
            quiescent(&runtime);
        }

        let key = AuthKey::from_seed(101);
        let runtime = RuntimeBuilder::current_thread()
            .enable_platform_reactor(false)
            .blocking_threads(1, 1)
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let parent = root.clone().with_macaroon(MacaroonToken::mint(
                &key,
                &format!("spawn:region_{}", root.region_id().as_u64()),
                "receive-admission-test",
            ));
            let mut task = parent
                .spawn(|cx| async move {
                    let target = format!("spawn:region_{}", cx.region_id().as_u64());
                    let denied = cx.clone().with_macaroon(MacaroonToken::mint(
                        &AuthKey::from_seed(102),
                        &target,
                        "denied-decode-worker",
                    ));
                    let (mut tx, mut rx) = pair(1);
                    tx.send(&cx, b"retry after refusal").await.unwrap();
                    let mut session = rx.start_recv_offloaded(&denied).unwrap();
                    assert!(matches!(
                        session.run().await,
                        Err(AuthenticatedEcError::WorkerAdmission(
                            SpawnError::AuthorizationDenied { .. }
                        ))
                    ));
                    drop(session);
                    assert_eq!(tx.tx.telemetry_snapshot(14).queued_messages, 0);
                    assert_eq!(rx.pending.as_ref().unwrap().header.header.message_id, 0);
                    assert_eq!(rx.offload.available_permits(), 1);
                    assert_eq!(
                        rx.recv_offloaded(&cx).await.unwrap(),
                        b"retry after refusal"
                    );
                    assert!(rx.pending.is_none());
                })
                .unwrap();
            task.join(&root).await.unwrap();
        });
        quiescent(&runtime);
    });
}

#[test]
fn offloaded_receive_repairs_loss_and_tampering_and_consumes_invalid_envelopes() {
    bounded(|| {
        let runtime = runtime();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, mut rx) = pair(3);
            let data: Vec<u8> = (0_u8..=255).cycle().take(900).collect();
            let mut messages = Vec::new();
            for bytes in [&data[..], b"invalid header", b"after invalid"] {
                tx.send(&cx, bytes).await.unwrap();
                messages.push(rx.rx.try_recv().unwrap());
            }
            let repairable = &mut messages[0];
            repairable.symbols.remove(0);
            let mut corrupted = repairable.symbols[0].symbol().clone();
            corrupted.data_mut()[0] ^= 1;
            repairable.symbols[0] = crate::security::AuthenticatedSymbol::from_parts(
                corrupted,
                *repairable.symbols[0].tag(),
            );
            repairable.symbols.push(repairable.symbols[1].clone());
            repairable.symbols.reverse();
            messages[1].header.header.message_size -= 1;
            for message in messages {
                tx.tx.try_send(message).unwrap();
            }
            assert_eq!(rx.recv_offloaded(&cx).await.unwrap(), data);
            assert!(matches!(
                rx.recv_offloaded(&cx).await,
                Err(AuthenticatedEcError::Message(EcError::AuthenticationFailed))
            ));
            assert!(
                rx.pending.is_none(),
                "completed invalid message is consumed once"
            );
            assert_eq!(rx.recv_offloaded(&cx).await.unwrap(), b"after invalid");
            assert!(rx.pending.is_none());
            assert!(rx.rx.is_empty());
        }));
        quiescent(&runtime);
    });
}

#[test]
fn typed_receive_resumes_off_thread_and_json_failure_consumes_only_one_message() {
    #[derive(Debug)]
    struct ObservedValue {
        text: String,
        on_worker: bool,
    }
    impl<'de> serde::Deserialize<'de> for ObservedValue {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let on_worker = std::thread::current()
                .name()
                .is_some_and(|name| name.contains("-blocking-"));
            Ok(Self {
                text: serde::Deserialize::deserialize(deserializer)?,
                on_worker,
            })
        }
    }

    bounded(|| {
        let runtime = runtime();
        let pool = runtime.blocking_handle().unwrap();
        let mut held = hold_worker(&pool);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, mut rx) = pair(2);
            tx.send_value(&cx, &"typed first").await.unwrap();
            let mut session = rx.start_recv_value_offloaded::<ObservedValue>(&cx).unwrap();
            pending_once(session.run()).await;
            until(|| pool.pending_count() == 1).await;
            for _ in 0..3 {
                pending_once(session.run()).await;
                assert_eq!(pool.pending_count(), 1);
            }
            held.release();
            let value = session.run().await.unwrap();
            assert_eq!(value.text, "typed first");
            assert!(value.on_worker);
            assert!(session.is_finished());
            assert!(matches!(
                session.run().await,
                Err(AuthenticatedEcError::InvalidSession(_))
            ));
            drop(session);
            tx.send(&cx, b"{ malformed JSON").await.unwrap();
            tx.send_value(&cx, &"after JSON error").await.unwrap();
            assert!(matches!(
                rx.recv_value_offloaded::<String>(&cx).await,
                Err(AuthenticatedEcError::Message(EcError::Serialization(_)))
            ));
            assert!(rx.pending.is_none());
            assert_eq!(
                rx.recv_value_offloaded::<String>(&cx).await.unwrap(),
                "after JSON error"
            );
            assert!(rx.rx.is_empty());
        }));
        quiescent(&runtime);
    });
}

#[test]
fn deserializer_panic_retains_the_message_for_another_decode_type() {
    struct PanicDeserialize;
    impl<'de> serde::Deserialize<'de> for PanicDeserialize {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            panic!("typed receiver worker panic");
        }
    }

    bounded(|| {
        let runtime = runtime();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let (mut tx, mut rx) = pair(1);
            tx.send_value(&cx, &"survives worker panic").await.unwrap();
            let mut session = rx
                .start_recv_value_offloaded::<PanicDeserialize>(&cx)
                .unwrap();
            assert!(matches!(
                session.run().await,
                Err(AuthenticatedEcError::WorkerFailed(_))
            ));
            assert!(session.is_finished());
            assert!(matches!(
                session.run().await,
                Err(AuthenticatedEcError::WorkerFailed(_))
            ));
            drop(session);
            assert_eq!(rx.pending.as_ref().unwrap().header.header.message_id, 0);
            assert_eq!(rx.offload.available_permits(), 1);
            assert_eq!(tx.tx.telemetry_snapshot(15).queued_messages, 0);
            assert_eq!(
                rx.recv_value_offloaded::<String>(&cx).await.unwrap(),
                "survives worker panic"
            );
            assert!(rx.pending.is_none());
            assert!(rx.rx.is_empty());
        }));
        quiescent(&runtime);
    });
}
