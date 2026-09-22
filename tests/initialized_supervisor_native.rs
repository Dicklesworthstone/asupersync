//! Compiled readiness-DAG journeys on native current-thread/two-worker runtimes.
//! Gates witness Pending; no sleeps are used to choose the failing schedule.
#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx, DynamicSupervisorConfig, Scope};
use asupersync::cx::worker_readiness::{WorkerReadinessError, WorkerReadinessPhase};
use asupersync::cx::worker_readiness::dependencies::{DependencyScopeReport, DependencyStop};
use asupersync::cx::worker_readiness::dependencies::supervisor::{
    InitializedChildBinding, InitializedRunResult, InitializedTopologyLimits,
};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::{JoinError, RuntimeBuilder, RuntimeState, SpawnError};
use asupersync::supervision::{
    BackoffStrategy, ChildSpec, ChildStart, ManagedRestartMode,
    RestartPolicy, SupervisionConfig, SupervisorBuilder,
};
use asupersync::types::{Budget, CancelReason, Outcome, TaskId, policy::FailFast};
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

type Fault = Box<InitializedRunResult<&'static str>>;

struct Legacy;
impl ChildStart for Legacy {
    fn start(&mut self, _: &Scope<'static, FailFast>, _: &mut RuntimeState, _: &Cx)
        -> Result<TaskId, SpawnError>
    {
        panic!("legacy factory is not the initialized execution path")
    }
}

// This state is deliberately neither Clone nor Sync.
struct Resource(Cell<u64>);

fn config(policy: RestartPolicy) -> SupervisionConfig {
    let mut config = SupervisionConfig::new(12, Duration::from_secs(60))
        .with_backoff(BackoffStrategy::None);
    config.restart_policy = policy;
    config
}

fn limits() -> InitializedTopologyLimits {
    InitializedTopologyLimits { max_children: 4, max_edges: 4 }
}

fn classify(result: InitializedRunResult<&'static str>) -> Outcome<(), Fault> {
    if result.as_ref().is_ok_and(DependencyScopeReport::is_success) {
        return Outcome::Ok(());
    }
    if let Ok(report) = &result {
        let clean_close = report.close.as_ref().is_ok_and(|close| {
            matches!(&close.outcome, Outcome::Ok(()) | Outcome::Cancelled(_))
                && close.cleanup_outcome.as_ref().is_none_or(|outcome| outcome.is_ok())
        });
        let clean_cancel = matches!(&report.work,
            None | Some(Ok(Outcome::Cancelled(_))) | Some(Err(JoinError::Cancelled(_))));
        if clean_close && clean_cancel && report.spawn_error.is_none()
            && report.cancellation_error.is_none()
            && matches!(&report.stop, Some(DependencyStop::Cancelled(_)))
        {
            return Outcome::Cancelled(report.cancellation.clone().expect("caller stop has a reason"));
        }
    }
    // Preserve typed work, dependency vector and actual close evidence on failure.
    Outcome::Err(Box::new(result))
}

async fn stop(cx: &Cx) -> Outcome<(), &'static str> {
    cx.cancelled().await;
    assert!(cx.checkpoint().is_err(), "acknowledge before async cleanup/return");
    Outcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::shutdown))
}

async fn witnessed<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut signal = Some(signal);
    poll_fn(|cx| {
        let polled = future.as_mut().poll(cx);
        if polled.is_pending() {
            if let Some(signal) = signal.take() { signal.send_blocking(()).unwrap(); }
        }
        polled
    }).await
}

fn passive(name: &str, mode: ManagedRestartMode, calls: Arc<AtomicUsize>) -> InitializedChildBinding<Fault> {
    InitializedChildBinding::new(name, mode,
        move |cx, generation| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(generation.task, cx.task_id());
                assert_eq!(generation.region, cx.region_id());
                Outcome::Ok(Resource(Cell::new(generation.number)))
            }
        },
        |cx, generation, state: Resource| async move {
            assert_eq!(state.0.get(), generation.number);
            stop(&cx).await
        },
        classify,
    )
}

async fn startup_waits_for_tcp_and_all_named_edges(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (allow, release) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut bytes = [0; 4];
        socket.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"INIT");
        release.recv_timeout(Duration::from_secs(20)).unwrap();
        socket.write_all(b"READY").unwrap();
        assert_eq!(socket.read(&mut bytes).unwrap(), 0);
    });
    let (parked, mut startup) = oneshot::channel();
    let parked = Arc::new(Mutex::new(Some(parked)));
    let cache = Arc::new(AtomicUsize::new(0));
    let front = Arc::new(AtomicUsize::new(0));
    let metrics = Arc::new(AtomicUsize::new(0));
    let storage = InitializedChildBinding::new("storage", ManagedRestartMode::Temporary,
        move |_, _| {
            let parked = parked.lock().unwrap().take().unwrap();
            async move {
                let mut socket = TcpStream::connect(address).await.unwrap();
                socket.write_all(b"INIT").await.unwrap();
                let mut bytes = [0; 5];
                witnessed(socket.read_exact(&mut bytes), parked).await.unwrap();
                assert_eq!(&bytes, b"READY");
                Outcome::Ok(socket)
            }
        },
        |cx, _, socket: TcpStream| async move {
            let result = stop(&cx).await;
            drop(socket);
            result
        },
        classify,
    );
    let front_binding = passive("front", ManagedRestartMode::Temporary, Arc::clone(&front));
    let metrics_binding = passive("metrics", ManagedRestartMode::Temporary, Arc::clone(&metrics));
    let cache_binding = passive("cache", ManagedRestartMode::Temporary, Arc::clone(&cache));
    let topology = SupervisorBuilder::new("diamond")
        .child(front_binding.spec().depends_on("cache").depends_on("storage"))
        .child(cache_binding.spec().depends_on("storage"))
        .child(storage.spec())
        .child(metrics_binding.spec()).compile().unwrap();
    let (managed, readiness) = topology.bind_initialized(vec![
        front_binding, storage, metrics_binding, cache_binding,
    ], config(RestartPolicy::OneForOne), limits()).unwrap();
    let mut owner = cx.open_dynamic_supervisor::<Fault>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let id = owner.start_child("application", managed).await.unwrap();
    startup.recv(&cx).await.unwrap();
    readiness.child("metrics").unwrap().wait_ready(&cx).await.unwrap();
    assert_eq!(readiness.child("storage").unwrap().state().phase, WorkerReadinessPhase::Initializing);
    assert_eq!((cache.load(Ordering::SeqCst), front.load(Ordering::SeqCst)), (0, 0));
    let observed = readiness.clone();
    let (barrier_parked, mut barrier_witness) = oneshot::channel();
    let mut waiter = cx.spawn(move |waiter| async move {
        witnessed(observed.all().wait_ready(&waiter), barrier_parked).await
    }).unwrap();
    barrier_witness.recv(&cx).await.unwrap();
    allow.send(()).unwrap();
    let ready = waiter.join(&cx).await.unwrap().unwrap();
    assert!(ready.is_current());
    assert_eq!(ready.len(), 4);
    assert_eq!((cache.load(Ordering::SeqCst), front.load(Ordering::SeqCst), metrics.load(Ordering::SeqCst)), (1, 1, 1));
    let completion = owner.terminate_child(&id).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined), (4, 4));
    assert!(!ready.is_current());
    assert!(owner.shutdown().await.close.is_ok());
    peer.join().unwrap();
}

async fn restart_preserves_old_drain_and_policy(cx: Cx, policy: RestartPolicy) {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let front_count = Arc::new(AtomicUsize::new(0));
    let metrics_count = Arc::new(AtomicUsize::new(0));
    let (fail, command) = oneshot::channel();
    let command = Arc::new(Mutex::new(Some(command)));
    let count = Arc::clone(&upstream_count);
    let upstream = InitializedChildBinding::new("upstream", ManagedRestartMode::Transient,
        move |_, generation| {
            count.fetch_add(1, Ordering::SeqCst);
            async move { Outcome::Ok(Resource(Cell::new(generation.number))) }
        },
        move |cx, generation, _state: Resource| {
            let command = if generation.number == 1 { command.lock().unwrap().take() } else { None };
            async move {
                if let Some(mut command) = command {
                    command.recv(&cx).await.unwrap();
                    Outcome::Err("upstream attempt failed")
                } else {
                    stop(&cx).await
                }
            }
        },
        classify,
    );
    let (descendant_parked, mut descendant_witness) = oneshot::channel();
    let (cleanup_parked, mut cleanup_witness) = oneshot::channel();
    let (release, cleanup) = oneshot::channel::<()>();
    let gates = Arc::new(Mutex::new(Some((descendant_parked, cleanup_parked, cleanup))));
    let cleanup_done = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&cleanup_done);
    let count = Arc::clone(&front_count);
    let loss = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&loss);
    let checked_cleanup = Arc::clone(&cleanup_done);
    let front = InitializedChildBinding::new("front", ManagedRestartMode::Transient,
        move |_, generation| {
            count.fetch_add(1, Ordering::SeqCst);
            async move { Outcome::Ok(Resource(Cell::new(generation.number))) }
        },
        move |cx, generation, _state: Resource| {
            let gates = if generation.number == 1 { gates.lock().unwrap().take() } else { None };
            let done = Arc::clone(&done);
            async move {
                if let Some((parked, cleanup_parked, mut cleanup)) = gates {
                    let _child = cx.spawn(move |child| async move {
                        witnessed(child.cancelled(), parked).await;
                        assert!(child.checkpoint().is_err());
                        witnessed(poll_fn(|task| cleanup.poll_recv_uninterruptible(task)), cleanup_parked)
                            .await.unwrap();
                        done.store(true, Ordering::SeqCst);
                    }).unwrap();
                }
                stop(&cx).await
            }
        },
        move |result| {
            if let Ok(report) = &result {
                if let Some(DependencyStop::Lost(lost)) = &report.stop {
                    assert!(checked_cleanup.load(Ordering::SeqCst));
                    assert!(report.close.is_ok());
                    *captured.lock().unwrap() = Some(lost.expected);
                }
            }
            classify(result)
        },
    );
    let topology = SupervisorBuilder::new("restarting")
        .with_restart_policy(policy)
        .child(ChildSpec::new("front", Legacy).depends_on("upstream"))
        .child(ChildSpec::new("upstream", Legacy))
        .child(ChildSpec::new("metrics", Legacy)).compile().unwrap();
    let (managed, readiness) = topology.bind_initialized(vec![front, upstream,
        passive("metrics", ManagedRestartMode::Transient, Arc::clone(&metrics_count)),
    ], config(policy), limits()).unwrap();
    let mut owner = cx.open_dynamic_supervisor::<Fault>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let id = owner.start_child("application", managed).await.unwrap();
    let initial = readiness.all().wait_ready(&cx).await.unwrap();
    let old_upstream = readiness.child("upstream").unwrap().wait_ready(&cx).await.unwrap();
    let old_front = readiness.child("front").unwrap().wait_ready(&cx).await.unwrap();
    descendant_witness.recv(&cx).await.unwrap();
    fail.send_blocking(()).unwrap();
    cleanup_witness.recv(&cx).await.unwrap();
    assert!(!initial.is_current());
    assert_eq!(front_count.load(Ordering::SeqCst), 1, "no replacement before old descendant cleanup");
    if policy == RestartPolicy::OneForOne {
        let replacement = readiness.child("upstream").unwrap().wait_ready_after(&cx, &old_upstream).await.unwrap();
        assert_eq!(replacement.generation().number, 2);
        assert_eq!(front_count.load(Ordering::SeqCst), 1, "ready upstream is not permission to overlap old dependent");
        assert_eq!(metrics_count.load(Ordering::SeqCst), 1);
    } else {
        assert_eq!(upstream_count.load(Ordering::SeqCst), 1, "collateral batch waits for all drains");
    }
    release.send_blocking(()).unwrap();
    let replacement = readiness.child("front").unwrap().wait_ready_after(&cx, &old_front).await.unwrap();
    assert_eq!(replacement.generation().number, 2);
    let ready = readiness.all().wait_ready(&cx).await.unwrap();
    assert!(ready.is_current());
    assert_eq!(upstream_count.load(Ordering::SeqCst), 2);
    assert_eq!(front_count.load(Ordering::SeqCst), 2);
    if policy == RestartPolicy::OneForOne {
        assert_eq!(*loss.lock().unwrap(), Some(old_upstream.generation()));
        assert_eq!(metrics_count.load(Ordering::SeqCst), 1);
    } else {
        // A transient sibling returned Cancelled under collateral shutdown.
        // That must NOT permanently poison its reusable initialization factory.
        assert_eq!(metrics_count.load(Ordering::SeqCst), 2);
        assert_eq!(readiness.child("metrics").unwrap().wait_ready(&cx).await.unwrap().generation().number, 2);
    }
    let completion = owner.terminate_child(&id).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!(report.started, report.joined);
    assert!(report.children.iter().all(|child| child.region_outcome.is_some()));
    assert!(owner.shutdown().await.close.is_ok());
}

async fn temporary_failure_unblocks_dependents_while_sibling_keeps_owner_alive(cx: Cx) {
    let (release, gate) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some(gate)));
    let (parked, mut witness) = oneshot::channel();
    let parked = Arc::new(Mutex::new(Some(parked)));
    let front_calls = Arc::new(AtomicUsize::new(0));
    let metrics_calls = Arc::new(AtomicUsize::new(0));
    let storage = InitializedChildBinding::new("storage", ManagedRestartMode::Temporary,
        move |_, _| {
            let mut gate = gate.lock().unwrap().take().unwrap();
            let parked = parked.lock().unwrap().take().unwrap();
            async move {
                witnessed(poll_fn(|task| gate.poll_recv_uninterruptible(task)), parked).await.unwrap();
                Outcome::<Resource, _>::Err("storage initialization failed")
            }
        },
        |_, _, _: Resource| async { panic!("failed initialization must not run") },
        classify,
    );
    let topology = SupervisorBuilder::new("unavailable")
        .child(ChildSpec::new("front", Legacy).depends_on("storage"))
        .child(ChildSpec::new("storage", Legacy))
        .child(ChildSpec::new("metrics", Legacy)).compile().unwrap();
    let (managed, readiness) = topology.bind_initialized(vec![storage,
        passive("front", ManagedRestartMode::Temporary, Arc::clone(&front_calls)),
        passive("metrics", ManagedRestartMode::Temporary, Arc::clone(&metrics_calls)),
    ], config(RestartPolicy::OneForOne), limits()).unwrap();
    let mut owner = cx.open_dynamic_supervisor::<Fault>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let id = owner.start_child("application", managed).await.unwrap();
    witness.recv(&cx).await.unwrap();
    let metrics = readiness.child("metrics").unwrap().wait_ready(&cx).await.unwrap();
    release.send_blocking(()).unwrap();
    let error = readiness.child("front").unwrap().wait_ready(&cx).await.unwrap_err();
    assert_eq!(error, WorkerReadinessError::Closed);
    assert_eq!(front_calls.load(Ordering::SeqCst), 0);
    assert!(readiness.child("metrics").unwrap().is_current(&metrics), "unrelated sibling keeps the controller and factories retained");
    let completion = owner.terminate_child(&id).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    let storage = report.children.iter().find(|child| child.name.as_str() == "storage").unwrap();
    let Outcome::Err(error) = &storage.outcome else { panic!("typed initialization failure retained") };
    let result = error.as_ref().as_ref().unwrap();
    assert!(matches!(&result.work, Some(Ok(Outcome::Err("storage initialization failed")))));
    assert!(owner.shutdown().await.close.is_ok());
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
                0 => startup_waits_for_tcp_and_all_named_edges(cx).await,
                1 => restart_preserves_old_drain_and_policy(cx, RestartPolicy::OneForOne).await,
                2 => restart_preserves_old_drain_and_policy(cx, RestartPolicy::OneForAll).await,
                3 => temporary_failure_unblocks_dependents_while_sibling_keeps_owner_alive(cx).await,
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
    let result = receive.recv_timeout(Duration::from_secs(30)).expect("compiled initialized topology must finish including drain");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

#[test]
fn tcp_gated_diamond_current_thread() { bounded(false, 0); }
#[test]
fn tcp_gated_diamond_two_workers() { bounded(true, 0); }
#[test]
fn dependency_restart_waits_for_old_descendants_current_thread() { bounded(false, 1); }
#[test]
fn dependency_restart_waits_for_old_descendants_two_workers() { bounded(true, 1); }
#[test]
fn collateral_restart_keeps_transient_factories_reusable_current_thread() { bounded(false, 2); }
#[test]
fn collateral_restart_keeps_transient_factories_reusable_two_workers() { bounded(true, 2); }
#[test]
fn temporary_startup_failure_is_not_an_infinite_readiness_wait_current_thread() { bounded(false, 3); }
#[test]
fn temporary_startup_failure_is_not_an_infinite_readiness_wait_two_workers() { bounded(true, 3); }
