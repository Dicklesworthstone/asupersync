//! Native worker/TCP startup ownership. Virtual time selects deadline races;
//! every I/O/cancellation boundary has an actual observed Pending witness.
#![cfg(all(feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::cx::worker_readiness::WorkerReadinessPhase;
use asupersync::cx::worker_readiness::dependencies::supervisor::{
    InitializedChildBinding, InitializedExit, InitializedRunResult, InitializedStartCause,
    InitializedStartConfig, InitializedSupervisor, InitializedTopologyLimits,
};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::supervision::{BackoffStrategy, ManagedRestartMode, SupervisionConfig, SupervisorBuilder};
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, Outcome, Time};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type Failure = Box<InitializedRunResult<&'static str>>;

fn classify(result: InitializedRunResult<&'static str>) -> Outcome<(), Failure> {
    if result.as_ref().is_ok_and(|report| report.is_success()) {
        Outcome::Ok(())
    } else {
        Outcome::Err(Box::new(result))
    }
}

async fn witnessed<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut signal = Some(signal);
    poll_fn(|task| {
        let poll = future.as_mut().poll(task);
        if poll.is_pending() {
            if let Some(signal) = signal.take() { signal.send_blocking(()).unwrap(); }
        }
        poll
    }).await
}

// TCP polls perform their own cancellation checkpoints. The application owns
// this finite mask for its acknowledged protocol cleanup; the startup API does
// not silently grant one or make arbitrary cleanup uninterruptible.
async fn cleanup_io<F: Future>(cx: &Cx, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut remaining = 128u32;
    poll_fn(|task| {
        assert!(remaining != 0, "test cleanup exceeded its explicit poll allowance");
        remaining -= 1;
        cx.masked(|| future.as_mut().poll(task))
    }).await
}

// The blocking peer is outside the runtime. Neither reply is authorized before
// the corresponding runtime read has observably returned Pending.
struct Peer {
    address: SocketAddr,
    initialize: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

fn peer(complete_startup: bool) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (initialize, initialization) = std::sync::mpsc::channel();
    let (release, cleanup) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"INIT");
        if complete_startup {
            initialization.recv_timeout(Duration::from_secs(20)).unwrap();
            stream.write_all(b"READY").unwrap();
        }
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"STOP");
        cleanup.recv_timeout(Duration::from_secs(20)).unwrap();
        stream.write_all(b"ACK").unwrap();
        assert_eq!(stream.read(&mut bytes).unwrap(), 0, "exactly one cleanup and actual transport retirement");
    });
    Peer { address, initialize, release, thread }
}

fn prepared(
    address: SocketAddr,
    initial_pending: oneshot::Sender<()>,
    cleanup_pending: oneshot::Sender<()>,
    handed_off: Arc<AtomicUsize>,
) -> InitializedSupervisor<Failure> {
    let initial_pending = Arc::new(Mutex::new(Some(initial_pending)));
    let cleanup_pending = Arc::new(Mutex::new(Some(cleanup_pending)));
    let binding = InitializedChildBinding::new("socket-worker", ManagedRestartMode::Temporary,
        move |cx, _| {
            let signal = initial_pending.lock().unwrap().take().unwrap();
            async move {
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(b"INIT").await.unwrap();
                let mut response = [0; 5];
                // Startup cancellation is explicitly acknowledged. A resource
                // acquired before that cancellation must still reach run cleanup.
                let completed = {
                    let reading = stream.read_exact(&mut response);
                    let mut reading = std::pin::pin!(witnessed(reading, signal));
                    let mut cancelled = std::pin::pin!(cx.cancelled());
                    poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() {
                            assert!(cx.checkpoint().is_err());
                            return Poll::Ready(false);
                        }
                        match reading.as_mut().poll(task) {
                            Poll::Ready(Ok(_)) => Poll::Ready(true),
                            Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted
                                && cx.is_cancel_requested() => {
                                // Cancellation can arrive after the observer
                                // check but before the TCP checkpoint.
                                assert!(cx.checkpoint().is_err());
                                Poll::Ready(false)
                            }
                            Poll::Ready(Err(error)) => panic!("startup read failed: {error}"),
                            Poll::Pending => Poll::Pending,
                        }
                    }).await
                };
                if completed { assert_eq!(&response, b"READY"); }
                Outcome::<_, &'static str>::Ok(stream)
            }
        },
        move |cx, _, mut stream: TcpStream| {
            let signal = cleanup_pending.lock().unwrap().take().unwrap();
            let handed_off = Arc::clone(&handed_off);
            async move {
                handed_off.fetch_add(1, Ordering::SeqCst);
                cx.cancelled().await;
                assert!(cx.checkpoint().is_err());
                cleanup_io(&cx, async {
                    stream.write_all(b"STOP").await.unwrap();
                    let mut ack = [0; 3];
                    witnessed(stream.read_exact(&mut ack), signal).await.unwrap();
                    assert_eq!(&ack, b"ACK");
                    AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                }).await;
                Outcome::<(), &'static str>::Cancelled(cx.cancel_reason().unwrap())
            }
        }, classify);
    SupervisorBuilder::new("owned-startup").child(binding.spec()).compile().unwrap()
        .bind_initialized_owned(vec![binding],
            SupervisionConfig::new(0, Duration::from_secs(60)).with_backoff(BackoffStrategy::None),
            InitializedTopologyLimits { max_children: 1, max_edges: 0 }).unwrap()
}

fn config() -> InitializedStartConfig {
    InitializedStartConfig::new(Duration::from_secs(1), Budget::INFINITE)
}

fn assert_closed(exit: InitializedExit<Failure>) {
    assert!(exit.stop_requested);
    assert!(exit.stop_error.is_none());
    assert!(exit.close.is_ok());
    let report = exit.controller.unwrap().unwrap();
    assert_eq!((report.started, report.joined), (1, 1));
    assert!(report.region_outcome.is_some());
    assert!(report.cleanup_outcome.as_ref().is_none_or(|value| value.is_ok()));
    assert_eq!(report.children.len(), 1);
    let child = &report.children[0];
    assert!(child.region_outcome.is_some());
    assert!(child.cleanup_outcome.as_ref().is_none_or(|value| value.is_ok()));
    // Cooperative initialization/run cancellation returns its complete typed
    // dependency report, not a missing result or generic channel closure.
    let Outcome::Err(original) = &child.outcome else { panic!("typed worker report missing: {child:?}"); };
    let original = original.as_ref().as_ref().unwrap();
    assert!(original.close.is_ok());
    assert!(matches!(&original.work, Some(Ok(Outcome::Cancelled(_)))));
}

async fn success_outlives_deadline(cx: Cx, clock: Arc<VirtualClock>, timer: TimerDriverHandle) {
    let peer = peer(true);
    let (initial, mut initial_witness) = oneshot::channel();
    let (cleanup, mut cleanup_witness) = oneshot::channel();
    let handoffs = Arc::new(AtomicUsize::new(0));
    let prepared = prepared(peer.address, initial, cleanup, Arc::clone(&handoffs));
    let readiness = prepared.readiness().clone();
    let mut starter = cx.spawn(move |cx| async move { prepared.start(&cx, config()).await }).unwrap();
    initial_witness.recv(&cx).await.unwrap();
    assert_eq!(readiness.child("socket-worker").unwrap().state().phase, WorkerReadinessPhase::Initializing);
    assert!(readiness.all().try_ready().unwrap().is_none());
    peer.initialize.send(()).unwrap();
    let mut running = starter.join(&cx).await.unwrap().unwrap();
    assert!(running.initial_readiness().is_current());
    clock.advance_to(Time::from_secs(2));
    let _ = timer.process_timers();
    for _ in 0..8 { asupersync::runtime::yield_now().await; }
    assert!(running.initial_readiness().is_current(), "startup deadline must not become a lifetime deadline");
    assert_eq!(handoffs.load(Ordering::SeqCst), 1);
    {
        let mut stop = std::pin::pin!(running.shutdown());
        assert!(stop.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    cleanup_witness.recv(&cx).await.unwrap();
    for _ in 0..3 {
        let mut join = std::pin::pin!(running.join());
        assert!(join.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    peer.release.send(()).unwrap();
    assert_closed(running.join().await.unwrap());
    assert!(matches!(running.join().await, Err(JoinError::PolledAfterCompletion)));
    assert_eq!(readiness.child("socket-worker").unwrap().state().phase, WorkerReadinessPhase::Closed);
    peer.thread.join().unwrap();
}

async fn timeout_and_late_caller_abort(cx: Cx, clock: Arc<VirtualClock>, timer: TimerDriverHandle) {
    let peer = peer(false);
    let (initial, mut initial_witness) = oneshot::channel();
    let (cleanup, mut cleanup_witness) = oneshot::channel();
    let handoffs = Arc::new(AtomicUsize::new(0));
    let prepared = prepared(peer.address, initial, cleanup, Arc::clone(&handoffs));
    let readiness = prepared.readiness().clone();
    let starter = cx.spawn(move |cx| async move { prepared.start(&cx, config()).await }).unwrap();
    initial_witness.recv(&cx).await.unwrap();
    assert_eq!(handoffs.load(Ordering::SeqCst), 0);
    // Timeout is impossible before this explicit clock advance, so the witness
    // proves it interrupted a real pending socket read, not an unstarted factory.
    clock.advance_to(Time::from_secs(2));
    let _ = timer.process_timers();
    cleanup_witness.recv(&cx).await.unwrap();
    assert_eq!(handoffs.load(Ordering::SeqCst), 1, "late acquired state must reach cleanup");
    assert!(readiness.all().try_ready().unwrap().is_none());
    assert!(!starter.is_finished(), "startup error cannot escape before async drain");
    let mut starter = std::thread::spawn(move || { starter.abort(); starter }).join().unwrap();
    // Drive the cancelled startup until its cleanup remains Pending. The peer
    // still cannot acknowledge, so acknowledgement cannot precede the abort.
    for _ in 0..8 { asupersync::runtime::yield_now().await; }
    assert!(!starter.is_finished());
    peer.release.send(()).unwrap();
    let error = starter.join(&cx).await.unwrap().unwrap_err();
    assert!(matches!(error.cause, InitializedStartCause::Deadline { deadline } if deadline == Time::from_secs(1)));
    assert!(error.cancellation.is_some(), "late caller cancellation must not erase the deadline cause");
    assert_closed(error.cleanup.unwrap());
    assert_eq!(readiness.child("socket-worker").unwrap().state().phase, WorkerReadinessPhase::Closed);
    peer.thread.join().unwrap();
}

async fn abandoned_start_drains_through_outer_owner(cx: Cx) {
    let peer = peer(false);
    let (initial, mut initial_witness) = oneshot::channel();
    let (cleanup, mut cleanup_witness) = oneshot::channel();
    let (abandon, mut command) = oneshot::channel();
    let handoffs = Arc::new(AtomicUsize::new(0));
    let prepared = prepared(peer.address, initial, cleanup, Arc::clone(&handoffs));
    let readiness = prepared.readiness().clone();
    let boundary = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let mut starter = boundary.cx().spawn(move |cx| async move {
        let mut start = Box::pin(prepared.start(&cx, config()));
        poll_fn(|task| {
            assert!(start.as_mut().poll(task).is_pending(), "peer has not made initialization ready");
            command.poll_recv_uninterruptible(task)
        }).await.unwrap();
        drop(start); // Drop the owned future, not merely a Pin<&mut _> reference.
    }).unwrap();
    initial_witness.recv(&cx).await.unwrap();
    abandon.send_blocking(()).unwrap();
    starter.join(&cx).await.unwrap();
    cleanup_witness.recv(&cx).await.unwrap();
    assert_eq!(handoffs.load(Ordering::SeqCst), 1);
    let mut closing = Box::pin(boundary.close());
    assert!(closing.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    peer.release.send(()).unwrap();
    closing.await.unwrap();
    assert_eq!(readiness.child("socket-worker").unwrap().state().phase, WorkerReadinessPhase::Closed);
    peer.thread.join().unwrap();
}

fn journey(multithread: bool, scenario: u8) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let builder = if multithread {
        RuntimeBuilder::new().worker_threads(2)
    } else { RuntimeBuilder::current_thread() };
    let runtime = builder.with_timer_driver(timer.clone()).build().unwrap();
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let observed_timer = timer.clone();
    runtime.block_on_with_cx(owner.clone(), async move {
        let boundary = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let mut worker = boundary.cx().spawn(move |cx| async move {
            match scenario {
                0 => success_outlives_deadline(cx, clock, timer).await,
                1 => timeout_and_late_caller_abort(cx, clock, timer).await,
                2 => abandoned_start_drains_through_outer_owner(cx).await,
                _ => unreachable!(),
            }
        }).unwrap();
        worker.join(&owner).await.unwrap();
        boundary.close().await.unwrap();
    });
    assert!(observed_timer.next_deadline().is_none(), "startup timer and waiters must be retired");
}

fn bounded(multithread: bool, scenario: u8) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| journey(multithread, scenario)));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30)).expect("native startup journey including cleanup");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

#[test]
fn startup_success_outlives_allowance_current_thread() { bounded(false, 0); }
#[test]
fn startup_success_outlives_allowance_two_workers() { bounded(true, 0); }
#[test]
fn timeout_then_caller_abort_preserves_cleanup_current_thread() { bounded(false, 1); }
#[test]
fn timeout_then_caller_abort_preserves_cleanup_two_workers() { bounded(true, 1); }
#[test]
fn abandoned_startup_retains_region_cleanup_current_thread() { bounded(false, 2); }
#[test]
fn abandoned_startup_retains_region_cleanup_two_workers() { bounded(true, 2); }
