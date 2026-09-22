//! Public native initialization/readiness/restart contracts. No sleeps select
//! the schedule: handshakes and cleanup have externally witnessed Pending gates.
#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx, DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::cx::worker_readiness::{WorkerReadinessError, WorkerReadinessPhase};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::supervision::{BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig};
use asupersync::types::{Budget, Outcome};
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

async fn witness_pending<F: Future>(future: F, observed: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut observed = Some(observed);
    poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if result.is_pending() {
            if let Some(observed) = observed.take() { observed.send_blocking(()).unwrap(); }
        }
        result
    }).await
}

fn policy(mode: ManagedRestartMode) -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(mode,
        SupervisionConfig::new(2, Duration::from_secs(60)).with_backoff(BackoffStrategy::None))
}

// The peer cannot send READY until the runtime has witnessed an actual pending
// socket read. Blocking network work stays on this external peer thread.
fn peer(rounds: usize) -> (SocketAddr, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release, allow) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        for round in 0..rounds {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"INIT");
            allow.recv_timeout(Duration::from_secs(20)).unwrap();
            stream.write_all(b"READY").unwrap();
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, if round + 1 == rounds { b"DONE" } else { b"FAIL" });
            let mut eof = [0; 1];
            assert_eq!(stream.read(&mut eof).unwrap(), 0);
        }
    });
    (address, release, thread)
}

async fn start_and_cancel_observer(cx: Cx) {
    let (address, release, peer) = peer(1);
    let (parked, mut witness) = oneshot::channel();
    let parked = Arc::new(Mutex::new(Some(parked)));
    let (finish, incoming) = oneshot::channel::<()>();
    let incoming = Arc::new(Mutex::new(Some(incoming)));
    let mut supervisor = cx.open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let (id, readiness) = supervisor.start_initialized_worker("socket-service", policy(ManagedRestartMode::Temporary),
        move |_, _| {
            let parked = parked.lock().unwrap().take().unwrap();
            async move {
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(b"INIT").await.unwrap();
                let mut response = [0; 5];
                witness_pending(stream.read_exact(&mut response), parked).await.unwrap();
                assert_eq!(&response, b"READY");
                Outcome::Ok(stream)
            }
        },
        move |worker, _, mut stream| {
            let mut incoming = incoming.lock().unwrap().take().unwrap();
            async move {
                incoming.recv(&worker).await.unwrap();
                stream.write_all(b"DONE").await.unwrap();
                AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                Outcome::Ok(())
            }
        },
    ).await.unwrap();
    assert_eq!(supervisor.len(), 1, "admitted while initializer can still be parked");
    witness.recv(&cx).await.unwrap();
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Initializing);
    assert!(readiness.try_ready().unwrap().is_none());
    let observed = readiness.clone();
    let (parked, mut observer_witness) = oneshot::channel();
    let mut observer = cx.spawn(move |observer| async move {
        let result = witness_pending(observed.wait_ready(&observer), parked).await;
        (result, observed)
    }).unwrap();
    observer_witness.recv(&cx).await.unwrap();
    observer.abort();
    let (result, observed) = observer.join(&cx).await.unwrap();
    assert_eq!(result.unwrap_err(), WorkerReadinessError::Cancelled);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Initializing);
    release.send(()).unwrap();
    let ready = observed.wait_ready(&cx).await.unwrap();
    assert_eq!(ready.generation().number, 1);
    assert!(readiness.is_current(&ready));
    finish.send_blocking(()).unwrap();
    let completion = supervisor.wait_child(&id).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined), (1, 1));
    assert!(report.children[0].outcome.is_ok());
    assert!(!readiness.is_current(&ready));
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
    assert!(supervisor.shutdown().await.close.is_ok());
    peer.join().unwrap();
}

async fn restart_after_descendant_drain(cx: Cx) {
    let (address, release, peer) = peer(2);
    let (init_one, mut init_one_witness) = oneshot::channel();
    let (init_two, mut init_two_witness) = oneshot::channel();
    let initializations = Arc::new(Mutex::new(VecDeque::from([init_one, init_two])));
    let (fail, first_command) = oneshot::channel::<()>();
    let (finish, second_command) = oneshot::channel::<()>();
    let commands = Arc::new(Mutex::new(VecDeque::from([first_command, second_command])));
    let (descendant_parked, mut descendant_witness) = oneshot::channel();
    let (cleanup_parked, mut cleanup_witness) = oneshot::channel();
    let (finish_cleanup, cleanup_gate) = oneshot::channel::<()>();
    let descendant = Arc::new(Mutex::new(Some((descendant_parked, cleanup_parked, cleanup_gate))));
    let initialized = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&initialized);
    let mut supervisor = cx.open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let (id, readiness) = supervisor.start_initialized_worker("restartable", policy(ManagedRestartMode::Transient),
        move |_, _| {
            let parked = initializations.lock().unwrap().pop_front().unwrap();
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(b"INIT").await.unwrap();
                let mut response = [0; 5];
                witness_pending(stream.read_exact(&mut response), parked).await.unwrap();
                assert_eq!(&response, b"READY");
                Outcome::Ok(stream)
            }
        },
        move |worker, generation: ManagedGeneration, mut stream| {
            let mut command = commands.lock().unwrap().pop_front().unwrap();
            let descendant = if generation.number == 1 { descendant.lock().unwrap().take() } else { None };
            async move {
                if let Some((parked, cleanup_parked, mut cleanup_gate)) = descendant {
                    let _owned_by_generation = worker.spawn(move |child| async move {
                        witness_pending(child.cancelled(), parked).await;
                        // Observing cancellation is not protocol acknowledgement.
                        // Acknowledge explicitly before parking in async cleanup.
                        assert!(child.checkpoint().is_err());
                        witness_pending(cleanup_gate.recv_uninterruptible(), cleanup_parked).await.unwrap();
                    }).unwrap();
                    // Dropping the handle is not cancellation. The generation's
                    // region owns this descendant and must drain it on restart.
                }
                command.recv(&worker).await.unwrap();
                let failed = generation.number == 1;
                stream.write_all(if failed { b"FAIL" } else { b"DONE" }).await.unwrap();
                AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                if failed { Outcome::Err("restart this initialized worker") } else { Outcome::Ok(()) }
            }
        },
    ).await.unwrap();
    init_one_witness.recv(&cx).await.unwrap();
    assert!(readiness.try_ready().unwrap().is_none());
    release.send(()).unwrap();
    let first = readiness.wait_ready(&cx).await.unwrap();
    descendant_witness.recv(&cx).await.unwrap();
    fail.send_blocking(()).unwrap();
    cleanup_witness.recv(&cx).await.unwrap();
    assert!(!readiness.is_current(&first));
    assert_eq!(initialized.load(Ordering::SeqCst), 1, "no restart before descendant cleanup");
    {
        let mut wait = std::pin::pin!(readiness.wait_ready_after(&cx, &first));
        poll_fn(|task| {
            assert!(wait.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
    }
    finish_cleanup.send_blocking(()).unwrap();
    init_two_witness.recv(&cx).await.unwrap();
    assert_eq!(initialized.load(Ordering::SeqCst), 2);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Initializing);
    assert!(readiness.try_ready().unwrap().is_none());
    release.send(()).unwrap();
    let second = readiness.wait_ready_after(&cx, &first).await.unwrap();
    assert_eq!(second.generation().number, 2);
    assert_ne!(first.generation().region, second.generation().region);
    assert_ne!(first.generation().task, second.generation().task);
    assert!(!readiness.is_current(&first));
    assert!(readiness.is_current(&second));
    finish.send_blocking(()).unwrap();
    let completion = supervisor.wait_child(&id).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 1));
    assert!(report.outcome.is_ok());
    assert!(!readiness.is_current(&second));
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
    assert!(supervisor.shutdown().await.close.is_ok());
    peer.join().unwrap();
}

async fn cancelled_initialization_still_hands_off_state(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"INIT");
        let mut eof = [0; 1];
        assert_eq!(stream.read(&mut eof).unwrap(), 0, "late acquired socket was released");
    });
    let (parked, mut witness) = oneshot::channel();
    let (cancelled, mut cancel_witness) = oneshot::channel();
    let (release, incoming) = oneshot::channel::<()>();
    let controls = Arc::new(Mutex::new(Some((parked, cancelled, incoming))));
    let handed_off = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&handed_off);
    let mut supervisor = cx.open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let (id, readiness) = supervisor.start_initialized_worker("late-state", policy(ManagedRestartMode::Temporary),
        move |worker, _| {
            let (parked, cancelled, mut incoming) = controls.lock().unwrap().take().unwrap();
            async move {
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(b"INIT").await.unwrap();
                let mut parked = Some(parked);
                let mut cancelled = Some(cancelled);
                // Deliberately allow acquisition to return an owned socket AFTER
                // cancellation. The readiness wrapper must not discard that state.
                poll_fn(|task| {
                    let result = incoming.poll_recv_uninterruptible(task);
                    if result.is_pending() {
                        if let Some(parked) = parked.take() { parked.send_blocking(()).unwrap(); }
                        if worker.is_cancel_requested() {
                            // The initializer explicitly acknowledges cleanup;
                            // the readiness wrapper must not do this for it.
                            assert!(worker.checkpoint().is_err());
                            if let Some(cancelled) = cancelled.take() { cancelled.send_blocking(()).unwrap(); }
                        }
                    }
                    result
                }).await.unwrap();
                Outcome::Ok(stream)
            }
        },
        move |worker, _, stream| {
            let observed = Arc::clone(&observed);
            async move {
                assert!(worker.checkpoint().is_err());
                drop(stream); // explicit cleanup by the successful state's new owner
                observed.fetch_add(1, Ordering::SeqCst);
                Outcome::Cancelled(worker.cancel_reason().unwrap())
            }
        },
    ).await.unwrap();
    witness.recv(&cx).await.unwrap();
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Initializing);
    supervisor.request_stop(&id).unwrap();
    cancel_witness.recv(&cx).await.unwrap();
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Stopping);
    assert_eq!(handed_off.load(Ordering::SeqCst), 0);
    assert!(readiness.try_ready().unwrap().is_none());
    release.send_blocking(()).unwrap();
    let completion = supervisor.wait_child(&id).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined), (1, 1));
    assert!(report.children[0].outcome.is_cancelled());
    assert_eq!(handed_off.load(Ordering::SeqCst), 1);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
    assert!(supervisor.shutdown().await.close.is_ok());
    peer.join().unwrap();
}

fn journey(multithread: bool, scenario: u8) {
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let boundary = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let mut task = boundary.cx().spawn(move |cx| async move {
            match scenario {
                0 => start_and_cancel_observer(cx).await,
                1 => restart_after_descendant_drain(cx).await,
                2 => cancelled_initialization_still_hands_off_state(cx).await,
                _ => unreachable!(),
            }
        }).unwrap();
        task.join(&owner).await.unwrap();
        boundary.close().await.unwrap();
    });
}

fn bounded(multithread: bool, scenario: u8) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| journey(multithread, scenario)));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native worker readiness journey must finish including subtree closure");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

#[test]
fn startup_and_observer_cancellation_current_thread() { bounded(false, 0); }
#[test]
fn startup_and_observer_cancellation_two_workers() { bounded(true, 0); }
#[test]
fn restart_readiness_waits_for_descendant_drain_current_thread() { bounded(false, 1); }
#[test]
fn restart_readiness_waits_for_descendant_drain_two_workers() { bounded(true, 1); }
#[test]
fn late_state_after_startup_cancellation_current_thread() { bounded(false, 2); }
#[test]
fn late_state_after_startup_cancellation_two_workers() { bounded(true, 2); }
