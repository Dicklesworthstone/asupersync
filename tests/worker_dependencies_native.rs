//! Actual managed prerequisites and native dependency-subtree cancellation.
//! Gates witness Pending before startup release, stop, or TCP acknowledgement.
#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx, DynamicChildId, DynamicSupervisor};
use asupersync::cx::{DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::cx::worker_readiness::{WorkerReadiness, WorkerReadinessPhase};
use asupersync::cx::worker_readiness::dependencies::{
    DependencyScopeConfig, DependencyScopeReport, DependencyStop, WorkerDependencies,
};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::supervision::{BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig};
use asupersync::types::{Budget, Outcome};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

async fn witness_pending<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut signal = Some(signal);
    poll_fn(|task| {
        let result = future.as_mut().poll(task);
        if result.is_pending() {
            if let Some(signal) = signal.take() { signal.send_blocking(()).unwrap(); }
        }
        result
    }).await
}

/// Poll post-acknowledgement cleanup with cancellation masked, as bracket
/// release does: runtime I/O refuses an unmasked cancelled Cx (Interrupted).
async fn cleanup_masked<F: Future>(cx: &Cx, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    poll_fn(|task| cx.masked(|| future.as_mut().poll(task))).await
}

async fn prerequisite(
    owner: &mut DynamicSupervisor<&'static str>,
    name: &'static str,
) -> (DynamicChildId, WorkerReadiness, oneshot::Sender<()>, oneshot::Receiver<()>) {
    let (allow, gate) = oneshot::channel();
    let (parked, witness) = oneshot::channel();
    let input = Arc::new(Mutex::new(Some((gate, parked))));
    let policy = DynamicWorkerConfig::new(ManagedRestartMode::Temporary,
        SupervisionConfig::new(1, Duration::from_secs(60)).with_backoff(BackoffStrategy::None));
    let (id, view) = owner.start_initialized_worker(name, policy,
        move |cx, _| {
            let (mut gate, parked) = input.lock().unwrap().take().unwrap();
            async move {
                witness_pending(gate.recv(&cx), parked).await.unwrap();
                Outcome::Ok(())
            }
        },
        |cx, _, ()| async move {
            cx.cancelled().await;
            assert!(cx.checkpoint().is_err());
            Outcome::Cancelled(cx.cancel_reason().unwrap())
        },
    ).await.unwrap();
    (id, view, allow, witness)
}

fn cleanup_peer() -> (SocketAddr, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (allow, incoming) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut bytes = [0; 5];
        socket.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"DRAIN");
        incoming.recv_timeout(Duration::from_secs(20)).unwrap();
        socket.write_all(b"ACK").unwrap();
        let mut eof = [0; 1];
        assert_eq!(socket.read(&mut eof).unwrap(), 0);
    });
    (address, allow, peer)
}

async fn scenario(cx: Cx, trigger: u8) {
    let mut supervisor = cx.open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(2))
        .await.unwrap();
    let (first_id, first, allow_first, mut first_parked) = prerequisite(&mut supervisor, "first").await;
    let (_second_id, second, allow_second, mut second_parked) = prerequisite(&mut supervisor, "second").await;
    first_parked.recv(&cx).await.unwrap();
    second_parked.recv(&cx).await.unwrap();
    let dependencies = WorkerDependencies::new(vec![first.clone(), second.clone()], 2).unwrap();
    let (address, allow_ack, peer) = cleanup_peer();
    let (startup_parked, mut startup_witness) = oneshot::channel();
    let (body_parked, mut body_witness) = oneshot::channel();
    let (descendant_parked, mut descendant_witness) = oneshot::channel();
    let (cleanup_parked, mut cleanup_witness) = oneshot::channel();
    let (drop_operation, mut drop_request) = oneshot::channel::<()>();
    let mut drop_operation = Some(drop_operation);
    let invoked = Arc::new(AtomicUsize::new(0));
    let started = Arc::clone(&invoked);
    let finished = Arc::new(AtomicUsize::new(0));
    let completed = Arc::clone(&finished);
    let boundary = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let mut controller = boundary.cx().spawn(move |driver| async move {
        let operation = dependencies.run(&driver, DependencyScopeConfig::new(Budget::INFINITE),
            move |body, snapshot| async move {
                assert_eq!(snapshot.generations().map(|g| g.number).collect::<Vec<_>>(), [1, 1]);
                started.fetch_add(1, Ordering::SeqCst);
                let descendant = body.spawn(move |child| async move {
                    let mut socket = TcpStream::connect(address).await.unwrap();
                    witness_pending(child.cancelled(), descendant_parked).await;
                    assert!(child.checkpoint().is_err(), "acknowledge before asynchronous cleanup");
                    cleanup_masked(&child, async {
                        socket.write_all(b"DRAIN").await.unwrap();
                        let mut ack = [0; 3];
                        witness_pending(socket.read_exact(&mut ack), cleanup_parked).await.unwrap();
                        assert_eq!(&ack, b"ACK");
                        AsyncWriteExt::shutdown(&mut socket).await.unwrap();
                    }).await;
                    completed.fetch_add(1, Ordering::SeqCst);
                }).unwrap();
                drop(descendant); // Its actual region must retain drain ownership.
                witness_pending(body.cancelled(), body_parked).await;
                assert!(body.checkpoint().is_err());
                Outcome::<(), &'static str>::Err("dependent stopped after acknowledgement")
            },
        );
        let mut operation = Box::pin(witness_pending(operation, startup_parked));
        // This command is independent of driver cancellation: abort must flow
        // through run's protocol, not accidentally become the explicit Drop case.
        let mut drop_wait = std::pin::pin!(poll_fn(|task| drop_request.poll_recv_uninterruptible(task)));
        let result = poll_fn(|task| {
            if let Poll::Ready(command) = drop_wait.as_mut().poll(task) {
                command.unwrap();
                return Poll::Ready(None);
            }
            operation.as_mut().poll(task).map(Some)
        }).await;
        drop(operation);
        result
    }).unwrap();

    startup_witness.recv(&cx).await.unwrap();
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    allow_first.send_blocking(()).unwrap();
    let first_ready = first.wait_ready(&cx).await.unwrap();
    assert_eq!(second.state().phase, WorkerReadinessPhase::Initializing);
    assert_eq!(invoked.load(Ordering::SeqCst), 0, "one prerequisite is insufficient");
    allow_second.send_blocking(()).unwrap();
    let second_ready = second.wait_ready(&cx).await.unwrap();
    body_witness.recv(&cx).await.unwrap();
    descendant_witness.recv(&cx).await.unwrap();
    assert_eq!(invoked.load(Ordering::SeqCst), 1);

    match trigger {
        0 => supervisor.request_stop(&first_id).unwrap(),
        1 => controller.abort(),
        2 => drop_operation.take().unwrap().send_blocking(()).unwrap(),
        _ => unreachable!(),
    }
    cleanup_witness.recv(&cx).await.unwrap();
    assert_eq!(finished.load(Ordering::SeqCst), 0);
    assert!(second.is_current(&second_ready), "unrelated prerequisite was cancelled");
    if trigger == 2 {
        assert!(controller.join(&cx).await.unwrap().is_none());
        let mut close = Box::pin(boundary.close());
        let pending = poll_fn(|task| Poll::Ready(close.as_mut().poll(task).is_pending())).await;
        assert!(pending, "owner boundary must retain abandoned descendant cleanup");
        allow_ack.send(()).unwrap();
        close.await.unwrap();
    } else {
        let mut join = Box::pin(controller.join(&cx));
        let pending = poll_fn(|task| Poll::Ready(join.as_mut().poll(task).is_pending())).await;
        assert!(pending, "a joined body is not a quiescent dependent region");
        allow_ack.send(()).unwrap();
        let report = join.await.unwrap().unwrap().unwrap();
        assert!(report.invoked);
        assert!(report.spawn_error.is_none());
        assert!(report.cancellation_error.is_none());
        assert!(report.close.is_ok());
        assert!(!report.is_success());
        assert!(matches!(&report.work, Some(Ok(Outcome::Err("dependent stopped after acknowledgement")))));
        match trigger {
            0 => {
                let Some(DependencyStop::Lost(loss)) = &report.stop else { panic!("exact dependency loss"); };
                assert_eq!(loss.index, 0);
                assert_eq!(loss.expected, first_ready.generation());
                assert!(report.cancellation.is_none());
            }
            1 => {
                assert!(matches!(report.stop, Some(DependencyStop::Cancelled(_))));
                assert!(report.cancellation.is_some());
                assert!(first.is_current(&first_ready));
            }
            _ => unreachable!(),
        }
        boundary.close().await.unwrap();
    }
    assert_eq!(finished.load(Ordering::SeqCst), 1);
    assert!(second.is_current(&second_ready));
    assert!(supervisor.shutdown().await.close.is_ok());
    peer.join().unwrap();
}

async fn restart_dependency_chain(cx: Cx) {
    let policy = || DynamicWorkerConfig::new(ManagedRestartMode::Transient,
        SupervisionConfig::new(2, Duration::from_secs(60)).with_backoff(BackoffStrategy::None));
    let (fail, first_command) = oneshot::channel::<()>();
    let first_command = Arc::new(Mutex::new(Some(first_command)));
    let (allow_replacement, replacement_gate) = oneshot::channel::<()>();
    let (replacement_parked, mut replacement_witness) = oneshot::channel();
    let replacement_init = Arc::new(Mutex::new(Some((replacement_gate, replacement_parked))));
    let mut prerequisites = cx.open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(1))
        .await.unwrap();
    let (_id, readiness) = prerequisites.start_initialized_worker("upstream", policy(),
        move |worker, generation: ManagedGeneration| {
            let replacement = if generation.number == 1 { None } else {
                Some(replacement_init.lock().unwrap().take().unwrap())
            };
            async move {
                if let Some((mut gate, parked)) = replacement {
                    witness_pending(gate.recv(&worker), parked).await.unwrap();
                }
                Outcome::Ok(())
            }
        },
        move |worker, generation: ManagedGeneration, ()| {
            let command = if generation.number == 1 {
                Some(first_command.lock().unwrap().take().unwrap())
            } else { None };
            async move {
                if let Some(mut command) = command {
                    command.recv(&worker).await.unwrap();
                    Outcome::Err("upstream restart sentinel")
                } else {
                    worker.cancelled().await;
                    assert!(worker.checkpoint().is_err());
                    Outcome::Cancelled(worker.cancel_reason().unwrap())
                }
            }
        },
    ).await.unwrap();
    let previous = readiness.wait_ready(&cx).await.unwrap();
    let dependencies = WorkerDependencies::new(vec![readiness.clone()], 1).unwrap();
    let (body_parked, mut body_witness) = oneshot::channel();
    let (descendant_parked, mut descendant_witness) = oneshot::channel();
    let (cleanup_parked, mut cleanup_witness) = oneshot::channel();
    let (release_cleanup, cleanup_gate) = oneshot::channel::<()>();
    let first_run = Arc::new(Mutex::new(Some((body_parked, descendant_parked, cleanup_parked, cleanup_gate))));
    let (second_started, mut second_witness) = oneshot::channel();
    let second_started = Arc::new(Mutex::new(Some(second_started)));
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&attempts);
    let retired = Arc::new(AtomicUsize::new(0));
    let cleanup_done = Arc::clone(&retired);
    type Failure = Box<DependencyScopeReport<(), &'static str>>;
    let mut consumers = cx.open_dynamic_supervisor::<Failure>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let dependent = consumers.start_worker("dependent", policy(),
        move |driver: Cx, generation: ManagedGeneration| {
            count.fetch_add(1, Ordering::SeqCst);
            let dependencies = dependencies.clone();
            let first = if generation.number == 1 { first_run.lock().unwrap().take() } else { None };
            let second = Arc::clone(&second_started);
            let cleanup_done = Arc::clone(&cleanup_done);
            async move {
                let report = dependencies.run(&driver, DependencyScopeConfig::new(Budget::INFINITE),
                    move |body, snapshot| async move {
                        assert_eq!(snapshot.generations().next().unwrap().number, generation.number);
                        if let Some((body_parked, descendant_parked, cleanup_parked, mut gate)) = first {
                            let descendant = body.spawn(move |child| async move {
                                witness_pending(child.cancelled(), descendant_parked).await;
                                assert!(child.checkpoint().is_err());
                                witness_pending(poll_fn(|task| gate.poll_recv_uninterruptible(task)), cleanup_parked)
                                    .await.unwrap();
                                cleanup_done.store(1, Ordering::SeqCst);
                            }).unwrap();
                            drop(descendant);
                            witness_pending(body.cancelled(), body_parked).await;
                            assert!(body.checkpoint().is_err());
                            Outcome::Err("dependent generation one stopped")
                        } else {
                            assert_eq!(generation.number, 2);
                            assert_eq!(cleanup_done.load(Ordering::SeqCst), 1,
                                "replacement overlapped prior dependent cleanup");
                            second.lock().unwrap().take().unwrap().send_blocking(()).unwrap();
                            Outcome::Ok(())
                        }
                    },
                ).await.expect("valid dependency-scope admission");
                if report.is_success() { Outcome::Ok(()) } else {
                    assert!(matches!(&report.stop, Some(DependencyStop::Lost(loss))
                        if loss.expected.number == 1));
                    assert!(report.close.is_ok());
                    Outcome::Err(Box::new(report))
                }
            }
        },
    ).await.unwrap();
    body_witness.recv(&cx).await.unwrap();
    descendant_witness.recv(&cx).await.unwrap();
    fail.send_blocking(()).unwrap();
    cleanup_witness.recv(&cx).await.unwrap();
    replacement_witness.recv(&cx).await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    allow_replacement.send_blocking(()).unwrap();
    let replacement = readiness.wait_ready_after(&cx, &previous).await.unwrap();
    assert_eq!(replacement.generation().number, 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 1,
        "new prerequisite readiness must not bypass dependent cleanup");
    release_cleanup.send_blocking(()).unwrap();
    second_witness.recv(&cx).await.unwrap();
    let completion = consumers.wait_child(&dependent).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined), (2, 2));
    assert!(report.outcome.is_ok());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(consumers.shutdown().await.close.is_ok());
    assert!(prerequisites.shutdown().await.close.is_ok());
}

fn journey(multithread: bool, trigger: u8) {
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let boundary = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let mut task = boundary.cx().spawn(move |cx| async move {
            if trigger == 3 { restart_dependency_chain(cx).await; }
            else { scenario(cx, trigger).await; }
        }).unwrap();
        task.join(&owner).await.unwrap();
        boundary.close().await.unwrap();
    });
}

fn bounded(multithread: bool, trigger: u8) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| journey(multithread, trigger)));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native dependency journey must finish including subtree cleanup");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

#[test]
fn dependency_loss_drains_only_dependents_current_thread() { bounded(false, 0); }
#[test]
fn dependency_loss_drains_only_dependents_two_workers() { bounded(true, 0); }
#[test]
fn caller_abort_preserves_dependency_scope_report_current_thread() { bounded(false, 1); }
#[test]
fn caller_abort_preserves_dependency_scope_report_two_workers() { bounded(true, 1); }
#[test]
fn dropped_operation_still_belongs_to_region_barrier_current_thread() { bounded(false, 2); }
#[test]
fn dropped_operation_still_belongs_to_region_barrier_two_workers() { bounded(true, 2); }
#[test]
fn dependent_restart_waits_for_prior_cleanup_current_thread() { bounded(false, 3); }
#[test]
fn dependent_restart_waits_for_prior_cleanup_two_workers() { bounded(true, 3); }
