//! Native accept-loop cancellation through independent owner and coordinator
//! contexts. Every trigger follows a real quiet TCP accept returning Pending.

#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::{Runtime, RuntimeBuilder, RuntimeHandle, TaskHandle};
use asupersync::server::connection::ConnectionManager;
use asupersync::server::shutdown::{ShutdownPhase, ShutdownStats};
use asupersync::types::CancelReason;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Http1,
    Http2,
}

#[derive(Clone, Copy, Debug)]
enum Trigger {
    RootCoordinator,
    ExplicitOwner,
    OwnedCoordinator,
}

type ListenerFuture = Pin<Box<dyn Future<Output = io::Result<ShutdownStats>> + Send>>;

struct BoundListener {
    address: SocketAddr,
    manager: ConnectionManager,
    requests: Arc<AtomicUsize>,
    run: ListenerFuture,
}

/// Assertion failure cleanup is separate from the cancellation verdict.
struct StopListener(ConnectionManager);

impl Drop for StopListener {
    fn drop(&mut self) {
        let _ = self.0.begin_force_close();
    }
}

async fn answer(_: Request) -> Response {
    Response::new(200, "OK", b"unrelated-listener-alive".to_vec())
}

async fn bind(
    protocol: Protocol,
    runtime: RuntimeHandle,
    owner: Option<Cx>,
) -> BoundListener {
    match protocol {
        Protocol::Http1 => {
            let config = Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_all(),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(4));
            let listener = Http1Listener::bind_with_config("127.0.0.1:0", answer, config)
                .await
                .unwrap();
            BoundListener {
                address: listener.local_addr().unwrap(),
                manager: listener.connection_manager().clone(),
                requests: listener.in_flight_requests(),
                run: Box::pin(async move {
                    match owner {
                        Some(owner) => listener.run_in(&owner).await,
                        None => listener.run(&runtime).await,
                    }
                }),
            }
        }
        Protocol::Http2 => {
            let config = Http2ListenerConfig::default()
                .host_policy(HostPolicy::allow_all())
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(4));
            let listener = Http2Listener::bind_with_config("127.0.0.1:0", answer, config)
                .await
                .unwrap();
            BoundListener {
                address: listener.local_addr().unwrap(),
                manager: listener.connection_manager().clone(),
                requests: listener.in_flight_requests(),
                run: Box::pin(async move {
                    match owner {
                        Some(owner) => listener.run_in(&owner).await,
                        None => listener.run(&runtime).await,
                    }
                }),
            }
        }
    }
}

async fn start_at_pending_accept(
    cx: &Cx,
    mut run: ListenerFuture,
) -> (TaskHandle<io::Result<ShutdownStats>>, Cx) {
    let (pending_tx, mut pending_rx) = oneshot::channel();
    let handle = cx
        .spawn(move |coordinator| async move {
            let mut pending_tx = Some(pending_tx);
            poll_fn(|task| {
                let result = run.as_mut().poll(task);
                if result.is_pending()
                    && let Some(pending_tx) = pending_tx.take()
                {
                    // No connection or drain exists yet. This first Pending
                    // is the actual TCP accept, with its reactor wake armed.
                    pending_tx.send_blocking(coordinator.clone()).unwrap();
                }
                result
            })
            .await
            // Deliberately no wrapper checkpoint: the listener must preserve
            // its own shutdown report when its coordinator is cancelled.
        })
        .unwrap();
    let coordinator = asupersync::time::timeout(cx.now(), WATCHDOG, pending_rx.recv(cx))
        .await
        .expect("listener reaches a real Pending accept")
        .unwrap();
    (handle, coordinator)
}

async fn finish(
    cx: &Cx,
    task: &mut TaskHandle<io::Result<ShutdownStats>>,
    manager: &ConnectionManager,
) -> ShutdownStats {
    let verdict = asupersync::time::timeout(cx.now(), WATCHDOG, task.join(cx)).await;
    if verdict.is_err() {
        // A pre-fix listener can ignore cancellation indefinitely. Wake its
        // shutdown lane only after recording the failed liveness verdict.
        let _ = manager.begin_force_close();
        let _ = asupersync::time::timeout(cx.now(), WATCHDOG, task.join(cx)).await;
    }
    verdict
        .expect("cancellation must end the quiet accept without another connection")
        .expect("listener acknowledged cancellation and retained its report")
        .expect("listener completed its existing drain")
}

async fn assert_unrelated_request(cx: &Cx, address: SocketAddr) {
    asupersync::time::timeout(cx.now(), WATCHDOG, async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /still-live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(response.ends_with(b"unrelated-listener-alive"));
    })
    .await
    .expect("an unrelated listener still serves real requests");
}

fn assert_retired(runtime: &Runtime) {
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < WATCHDOG, "all listener and owner tasks retire");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

fn exercise(protocol: Protocol, trigger: Trigger, workers: usize) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap()
    };
    let runtime_handle = runtime.handle();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let (owner_tx, mut owner_rx) = oneshot::channel();
        let mut owner_task = cx.spawn(move |owner| async move {
            owner_tx.send_blocking(owner.clone()).unwrap();
            owner.cancelled().await;
            let _ = owner.checkpoint();
        }).unwrap();
        let owner = owner_rx.recv(&cx).await.unwrap();
        let explicit_owner = (!matches!(trigger, Trigger::RootCoordinator)).then(|| owner.clone());
        let BoundListener { address, manager, requests, run } =
            bind(protocol, runtime_handle.clone(), explicit_owner).await;
        let _stop = StopListener(manager.clone());
        let (mut serving, coordinator) = start_at_pending_accept(&cx, run).await;
        assert_ne!(owner.task_id(), coordinator.task_id());
        assert!(!owner.is_cancel_requested());
        assert!(!coordinator.is_cancel_requested());
        assert!(manager.is_empty());

        let healthy = bind(Protocol::Http1, runtime_handle, None).await;
        let _stop_healthy = StopListener(healthy.manager.clone());
        let (mut serving_healthy, healthy_coordinator) = start_at_pending_accept(&cx, healthy.run).await;
        let reason = CancelReason::user("cancel dedicated HTTP listener authority");
        match trigger {
            Trigger::ExplicitOwner => owner_task.abort_with_reason(reason.clone()),
            Trigger::RootCoordinator | Trigger::OwnedCoordinator => {
                serving.abort_with_reason(reason.clone());
            }
        }
        let stats = finish(&cx, &mut serving, &manager).await;
        assert!(serving.is_finished());
        assert_eq!(manager.shutdown_signal().phase(), ShutdownPhase::Stopped);
        assert!(manager.is_empty());
        assert_eq!(requests.load(Ordering::Acquire), 0);
        assert_eq!(stats.drained, 0);
        assert_eq!(stats.force_closed, 0);
        assert_eq!(stats.drain_report.unwrap().requests_at_drain_start, 0);
        match trigger {
            Trigger::ExplicitOwner => {
                assert_eq!(owner.cancel_reason(), Some(reason));
                assert!(!coordinator.is_cancel_requested());
            }
            Trigger::RootCoordinator | Trigger::OwnedCoordinator => {
                assert_eq!(coordinator.cancel_reason(), Some(reason));
                assert!(!owner.is_cancel_requested());
            }
        }
        assert!(!cx.is_cancel_requested());
        assert!(!healthy_coordinator.is_cancel_requested());
        let refused = asupersync::time::timeout(cx.now(), WATCHDOG, TcpStream::connect(address))
            .await
            .expect("closed listener refuses a new connection");
        assert!(matches!(refused, Err(error) if error.kind() == io::ErrorKind::ConnectionRefused));
        assert_unrelated_request(&cx, healthy.address).await;
        assert!(healthy.manager.begin_drain(Duration::from_secs(2)));
        let _ = finish(&cx, &mut serving_healthy, &healthy.manager).await;
        assert_eq!(healthy.manager.shutdown_signal().phase(), ShutdownPhase::Stopped);
        assert!(healthy.manager.is_empty());
        assert_eq!(healthy.requests.load(Ordering::Acquire), 0);
        if !owner_task.is_finished() {
            owner_task.abort();
        }
        owner_task.join(&cx).await.unwrap();
        eprintln!("{{\"bead\":\"asupersync-313vbb\",\"scenario\":\"dedicated-listener-cancel\",\"protocol\":\"{protocol:?}\",\"trigger\":\"{trigger:?}\",\"workers\":{workers},\"phase\":\"Stopped\",\"unrelated_request\":\"200\",\"connections\":0,\"requests\":0}}");
    });
    assert_retired(&runtime);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn root_owned_listeners_stop_when_their_parked_coordinator_is_cancelled() {
    for protocol in [Protocol::Http1, Protocol::Http2] {
        for workers in [1, 2] {
            exercise(protocol, Trigger::RootCoordinator, workers);
        }
    }
}

#[test]
fn region_owned_listeners_wake_for_a_distinct_explicit_owner_cancellation() {
    for protocol in [Protocol::Http1, Protocol::Http2] {
        for workers in [1, 2] {
            exercise(protocol, Trigger::ExplicitOwner, workers);
        }
    }
}

#[test]
fn region_owned_listeners_stop_when_only_their_coordinator_is_cancelled() {
    for protocol in [Protocol::Http1, Protocol::Http2] {
        for workers in [1, 2] {
            exercise(protocol, Trigger::OwnedCoordinator, workers);
        }
    }
}
