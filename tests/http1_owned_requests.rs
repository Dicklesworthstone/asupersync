//! Native buffered HTTP/1 request-ownership contracts.
//!
//! Every journey uses a real reactor-backed TCP socket on current-thread and
//! two-worker runtimes, with both unified and sharded state. Cancellation and
//! cleanup readiness are witnessed by actual Pending polls, never sleeps.
//! Replay: rch exec -- env CARGO_TARGET_DIR=target/rch-h1-owned cargo test
//! --test http1_owned_requests -- --test-threads=1

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{
    HostPolicy, Http1Config, Http1Response, Http1Server, IntoHttp1Response,
};
use asupersync::http::h1::types::{Request, Response};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder, yield_now};
use asupersync::server::shutdown::ShutdownSignal;
use asupersync::types::{CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                for sharded in [false, true] {
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::new().worker_threads(workers)
                    };
                    let runtime = builder
                        .with_sharded_state(sharded)
                        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                        .build()
                        .unwrap();
                    runtime.block_on(async {
                        let root = Cx::current().unwrap();
                        let mut owner = root.spawn(scenario).unwrap();
                        owner.join(&root).await.unwrap();
                    });
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            }
        }));
        let _ = send.send(result);
    });
    // This watchdog bounds a broken journey; it never establishes readiness.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("owned HTTP/1 request journey must finish and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn config() -> Http1Config {
    Http1Config::default()
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .idle_timeout(None)
        .request_drain_grace(Duration::from_millis(100))
}

#[derive(Default)]
struct WireWitness {
    written: AtomicUsize,
    dropped: AtomicUsize,
}

struct ObservedSocket {
    inner: TcpStream,
    witness: Arc<WireWitness>,
}

impl AsyncRead for ObservedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObservedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            self.witness.written.fetch_add(*written, Ordering::SeqCst);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for ObservedSocket {
    fn drop(&mut self) {
        self.witness.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn pair(request: &[u8]) -> (ObservedSocket, TcpStream, Arc<WireWitness>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.write_all(request).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let witness = Arc::new(WireWitness::default());
    (
        ObservedSocket {
            inner: TcpStream::from_std(server).unwrap(),
            witness: Arc::clone(&witness),
        },
        TcpStream::from_std(peer).unwrap(),
        witness,
    )
}

async fn response(peer: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn parked_until_cancelled(cx: &Cx, ready: oneshot::Sender<Cx>) -> CancelReason {
    let mut ready = Some(ready);
    let mut cancelled = pin!(cx.cancelled());
    poll_fn(|task| match cancelled.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                ready.send_blocking(cx.clone()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
    assert!(cx.checkpoint().is_err(), "acknowledge before cleanup");
    cx.cancel_reason().unwrap()
}

async fn parked_until_released(
    cleanup_owner: &Cx,
    ready: oneshot::Sender<Cx>,
    mut release: oneshot::Receiver<()>,
) {
    let mut ready = Some(ready);
    let mut receive = pin!(release.recv(cleanup_owner));
    poll_fn(|task| match receive.as_mut().poll(task) {
        Poll::Ready(result) => Poll::Ready(result.unwrap()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                ready.send_blocking(Cx::current().unwrap()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
}

async fn pipeline_waits_for_descendants(cx: Cx) {
    let (socket, mut peer, wire) = pair(
        b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let peer_addr = socket.inner.peer_addr().unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let identities = Arc::new(Mutex::new(Vec::new()));
    let (child_ready, mut child_parked) = oneshot::channel();
    let (body_ready, mut body_started) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release_cleanup, cleanup_release) = oneshot::channel();
    let first = Arc::new(Mutex::new(Some((
        child_ready,
        body_ready,
        finished,
        cleanup_ready,
        cleanup_release,
    ))));
    let cleanup_owner = cx.clone();
    let handler_drops = Arc::clone(&drops);
    let handler_calls = Arc::clone(&calls);
    let handler_ids = Arc::clone(&identities);
    let handler = move |request: Request| {
        let factory_cx = Cx::current().expect("factory runs in admitted task");
        assert_eq!(request.peer_addr, Some(peer_addr));
        let first = if request.uri == "/first" {
            Some(first.lock().unwrap().take().unwrap())
        } else {
            None
        };
        let cleanup_owner = cleanup_owner.clone();
        let drops = Arc::clone(&handler_drops);
        let calls = Arc::clone(&handler_calls);
        let identities = Arc::clone(&handler_ids);
        async move {
            let body_cx = Cx::current().unwrap();
            assert_eq!(factory_cx.task_id(), body_cx.task_id());
            assert_eq!(factory_cx.region_id(), body_cx.region_id());
            identities.lock().unwrap().push(body_cx.clone());
            calls.fetch_add(1, Ordering::SeqCst);
            if let Some((ready, body_ready, mut finish, cleanup_ready, cleanup_release)) = first {
                body_cx
                    .spawn(move |child_cx| async move {
                        let _dropped = Dropped(drops);
                        parked_until_cancelled(&child_cx, ready).await;
                        parked_until_released(&cleanup_owner, cleanup_ready, cleanup_release).await;
                    })
                    .unwrap();
                body_ready.send_blocking(body_cx.clone()).unwrap();
                finish.recv(&body_cx).await.unwrap();
                Response::new(200, "OK", b"first".to_vec())
            } else {
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                Response::new(200, "OK", b"second".to_vec())
            }
        }
    };
    let server =
        Http1Server::with_config(handler, config()).with_in_flight_requests(Arc::clone(&in_flight));
    let mut serving = cx
        .spawn(move |connection_cx| async move {
            server
                .serve_owned_with_peer_addr(&connection_cx, socket, Some(peer_addr))
                .await
        })
        .unwrap();
    let body_cx = body_started.recv(&cx).await.unwrap();
    let child_cx = child_parked.recv(&cx).await.unwrap();
    assert_ne!(body_cx.task_id(), serving.task_id());
    assert_ne!(body_cx.region_id(), cx.region_id());
    assert_eq!(child_cx.region_id(), body_cx.region_id());
    assert_ne!(child_cx.task_id(), body_cx.task_id());
    let body_monitor = cx.monitor(body_cx.task_id()).await.unwrap();
    finish.send_blocking(()).unwrap();
    let cleanup_cx = cleanup_parked.recv(&cx).await.unwrap();
    assert_eq!(cleanup_cx.task_id(), child_cx.task_id());
    body_monitor.down(&cx).await.unwrap();

    // The body is retired and real descendant cleanup is parked. These
    // assertions cannot pass just because the handler has not finished yet.
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    release_cleanup.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    let state = serving.join(&cx).await.unwrap().unwrap();
    assert_eq!(state.requests_served, 2);
    assert_eq!(received.matches("HTTP/1.1 200").count(), 2, "{received}");
    assert!(received.ends_with("second"), "{received}");
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    let identities = identities.lock().unwrap();
    assert_eq!(identities.len(), 2);
    assert_ne!(identities[0].task_id(), identities[1].task_id());
    assert_ne!(identities[0].region_id(), identities[1].region_id());
}

#[test]
fn owned_pipeline_waits_for_actual_request_subtree_before_response_and_reuse() {
    native(pipeline_waits_for_descendants);
}

async fn cancellation_joins_cleanup(cx: Cx) {
    for force_close in [false, true] {
        let (socket, mut peer, wire) =
            pair(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let shutdown = ShutdownSignal::new();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let acknowledged = Arc::new(AtomicUsize::new(0));
        let (child_ready, mut child_parked) = oneshot::channel();
        let (body_ready, mut body_parked) = oneshot::channel();
        let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let signals = Arc::new(Mutex::new(Some((
            child_ready,
            body_ready,
            cleanup_ready,
            released,
        ))));
        let cleanup_owner = cx.clone();
        let handler_drops = Arc::clone(&drops);
        let handler_acks = Arc::clone(&acknowledged);
        let server = Http1Server::with_config(
            move |_| {
                let (child_ready, body_ready, cleanup_ready, released) =
                    signals.lock().unwrap().take().unwrap();
                let cleanup_owner = cleanup_owner.clone();
                let drops = Arc::clone(&handler_drops);
                let acks = Arc::clone(&handler_acks);
                async move {
                    let _body_drop = Dropped(Arc::clone(&drops));
                    let body_cx = Cx::current().unwrap();
                    let child_acks = Arc::clone(&acks);
                    body_cx
                        .spawn(move |child_cx| async move {
                            let _child_drop = Dropped(drops);
                            parked_until_cancelled(&child_cx, child_ready).await;
                            child_acks.fetch_add(1, Ordering::SeqCst);
                            parked_until_released(&cleanup_owner, cleanup_ready, released).await;
                        })
                        .unwrap();
                    parked_until_cancelled(&body_cx, body_ready).await;
                    acks.fetch_add(1, Ordering::SeqCst);
                    yield_now().await;
                    Response::new(200, "OK", b"cancel acknowledged".to_vec())
                }
            },
            config(),
        )
        .with_shutdown_signal(shutdown.clone())
        .with_in_flight_requests(Arc::clone(&in_flight));
        let mut serving =
            cx.spawn(move |connection_cx| async move {
                server.serve_owned(&connection_cx, socket).await
            })
            .unwrap();
        let body = body_parked.recv(&cx).await.unwrap();
        let child = child_parked.recv(&cx).await.unwrap();
        assert_eq!(body.region_id(), child.region_id());
        if force_close {
            assert!(shutdown.begin_drain(Duration::from_secs(5)));
            assert!(shutdown.begin_force_close());
        } else {
            serving.abort_with_reason(CancelReason::user("owned H1 parent cancellation"));
        }
        cleanup_parked.recv(&cx).await.unwrap();
        assert_eq!(wire.written.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        poll_fn(|task| {
            assert!(
                serving.poll_join(task).is_pending(),
                "cleanup is still admitted"
            );
            Poll::Ready(())
        })
        .await;
        release.send_blocking(()).unwrap();
        let result = serving.join(&cx).await;
        assert!(!matches!(result, Err(JoinError::Panicked(_))), "{result:?}");
        assert_eq!(acknowledged.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(wire.written.load(Ordering::SeqCst), 0);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
        assert!(response(&mut peer).await.is_empty());
    }
}

#[test]
fn owner_cancel_and_force_close_wait_for_acknowledged_descendant_cleanup() {
    native(cancellation_joins_cleanup);
}

async fn deadline_drains_before_reuse(cx: Cx) {
    let (socket, mut peer, wire) = pair(
        b"GET /slow HTTP/1.1\r\nHost: localhost\r\nRequest-Timeout: 1000ms\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (child_ready, mut child_parked) = oneshot::channel();
    let (body_ready, mut body_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((
        child_ready,
        body_ready,
        cleanup_ready,
        released,
    ))));
    let cleanup_owner = cx.clone();
    let handler_drops = Arc::clone(&drops);
    let handler_calls = Arc::clone(&calls);
    let server = Http1Server::with_config(
        move |request: Request| {
            let signals = if request.uri == "/slow" {
                signals.lock().unwrap().take()
            } else {
                None
            };
            let cleanup_owner = cleanup_owner.clone();
            let drops = Arc::clone(&handler_drops);
            let calls = Arc::clone(&handler_calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some((child_ready, body_ready, cleanup_ready, released)) = signals {
                    let _body_drop = Dropped(Arc::clone(&drops));
                    let body_cx = Cx::current().unwrap();
                    body_cx
                        .spawn(move |child_cx| async move {
                            let _child_drop = Dropped(drops);
                            parked_until_cancelled(&child_cx, child_ready).await;
                            parked_until_released(&cleanup_owner, cleanup_ready, released).await;
                        })
                        .unwrap();
                    let reason = parked_until_cancelled(&body_cx, body_ready).await;
                    assert!(matches!(
                        reason.kind,
                        CancelKind::Deadline | CancelKind::Timeout
                    ));
                    // The protocol grace must retire this future; it must not
                    // claim the still-parked descendant retired at the same time.
                    std::future::pending::<()>().await;
                    unreachable!("unreleased deadline handler")
                } else {
                    assert_eq!(drops.load(Ordering::SeqCst), 2);
                    Response::new(200, "OK", b"next".to_vec())
                }
            }
        },
        config().request_timeout_header_cap(Some(Duration::from_secs(2))),
    )
    .with_in_flight_requests(Arc::clone(&in_flight));
    let mut serving = cx
        .spawn(move |connection_cx| async move { server.serve_owned(&connection_cx, socket).await })
        .unwrap();
    let body = body_parked.recv(&cx).await.unwrap();
    child_parked.recv(&cx).await.unwrap();
    let monitor = cx.monitor(body.task_id()).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    release.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    let state = serving.join(&cx).await.unwrap().unwrap();
    assert_eq!(state.requests_served, 2);
    assert!(received.starts_with("HTTP/1.1 503"), "{received}");
    assert_eq!(received.matches("HTTP/1.1 200").count(), 1, "{received}");
    assert!(received.ends_with("next"), "{received}");
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn deadline_retires_handler_but_withholds_503_until_descendants_close_before_reuse() {
    native(deadline_drains_before_reuse);
}

async fn factory_and_poll_panics_are_isolated(cx: Cx) {
    for in_factory in [false, true] {
        let (socket, mut peer, wire) =
            pair(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let identities = Arc::new(Mutex::new(Vec::new()));
        let handler_calls = Arc::clone(&calls);
        let handler_ids = Arc::clone(&identities);
        let server = Http1Server::with_config(
            move |_| {
                let factory_cx = Cx::current().unwrap();
                handler_ids.lock().unwrap().push(factory_cx.clone());
                handler_calls.fetch_add(1, Ordering::SeqCst);
                assert!(!in_factory, "owned H1 factory panic");
                async move {
                    assert_eq!(Cx::current().unwrap().task_id(), factory_cx.task_id());
                    assert!(in_factory, "owned H1 poll panic");
                    Response::new(200, "OK", Vec::new())
                }
            },
            config(),
        );
        let mut serving =
            cx.spawn(move |connection_cx| async move {
                server.serve_owned(&connection_cx, socket).await
            })
            .unwrap();
        let received = response(&mut peer).await;
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
        assert!(received.starts_with("HTTP/1.1 500"), "{received}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
        {
            let identities = identities.lock().unwrap();
            assert_eq!(identities.len(), 1);
            assert_ne!(identities[0].task_id(), serving.task_id());
            assert_ne!(identities[0].region_id(), cx.region_id());
        }
    }

    // A new connection under the same owner still serves normally.
    let (socket, mut peer, _) =
        pair(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut healthy = cx
        .spawn(move |connection_cx| async move {
            Http1Server::with_config(
                |_| async { Response::new(200, "OK", b"healthy".to_vec()) },
                config(),
            )
            .serve_owned(&connection_cx, socket)
            .await
        })
        .unwrap();
    assert!(response(&mut peer).await.ends_with("healthy"));
    healthy.join(&cx).await.unwrap().unwrap();
}

#[test]
fn owned_factory_and_future_panics_close_with_500_without_poisoning_owner() {
    native(factory_and_poll_panics_are_isolated);
}

struct PanicWhenRetired(Arc<AtomicUsize>);

impl Drop for PanicWhenRetired {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("owned H1 handler destructor panic");
    }
}

async fn handler_drop_panic_waits_for_child(cx: Cx) {
    let (socket, mut peer, wire) =
        pair(b"GET / HTTP/1.1\r\nHost: localhost\r\nRequest-Timeout: 1000ms\r\nConnection: close\r\n\r\n");
    let drops = Arc::new(AtomicUsize::new(0));
    let (body_ready, mut body_parked) = oneshot::channel();
    let (child_ready, mut child_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((
        body_ready,
        child_ready,
        cleanup_ready,
        released,
    ))));
    let cleanup_owner = cx.clone();
    let handler_drops = Arc::clone(&drops);
    let server = Http1Server::with_config(
        move |_| {
            let (body_ready, child_ready, cleanup_ready, released) =
                signals.lock().unwrap().take().unwrap();
            let drops = Arc::clone(&handler_drops);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                let _panicking_drop = PanicWhenRetired(Arc::clone(&drops));
                let body_cx = Cx::current().unwrap();
                body_cx
                    .spawn(move |child_cx| async move {
                        let _child_drop = Dropped(drops);
                        parked_until_cancelled(&child_cx, child_ready).await;
                        parked_until_released(&cleanup_owner, cleanup_ready, released).await;
                    })
                    .unwrap();
                parked_until_cancelled(&body_cx, body_ready).await;
                std::future::pending::<Response>().await
            }
        },
        config().request_timeout_header_cap(Some(Duration::from_secs(2))),
    );
    let mut serving = cx
        .spawn(move |connection_cx| async move { server.serve_owned(&connection_cx, socket).await })
        .unwrap();
    let body = body_parked.recv(&cx).await.unwrap();
    child_parked.recv(&cx).await.unwrap();
    let monitor = cx.monitor(body.task_id()).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "handler destructor ran once"
    );
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    release.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    serving.join(&cx).await.unwrap().unwrap();
    assert!(received.starts_with("HTTP/1.1 500"), "{received}");
    assert!(!received.contains("HTTP/1.1 503"), "{received}");
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn handler_destructor_panic_isolated_after_deadline_and_before_child_drain_response() {
    native(handler_drop_panic_waits_for_child);
}

async fn abandoned_serving_future_closes_subtree(cx: Cx) {
    let (socket, mut peer, wire) =
        pair(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let enclosing = cx
        .open_child_region(ChildRegionSpec::inherit())
        .await
        .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let (body_ready, mut body_parked) = oneshot::channel();
    let (child_ready, mut child_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (abandon, mut abandoned) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((
        body_ready,
        child_ready,
        cleanup_ready,
        released,
    ))));
    let cleanup_owner = cx.clone();
    let handler_drops = Arc::clone(&drops);
    let server = Http1Server::with_config(
        move |_| {
            let (body_ready, child_ready, cleanup_ready, released) =
                signals.lock().unwrap().take().unwrap();
            let drops = Arc::clone(&handler_drops);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                let _body_drop = Dropped(Arc::clone(&drops));
                let body_cx = Cx::current().unwrap();
                body_cx
                    .spawn(move |child_cx| async move {
                        let _child_drop = Dropped(drops);
                        parked_until_cancelled(&child_cx, child_ready).await;
                        parked_until_released(&cleanup_owner, cleanup_ready, released).await;
                    })
                    .unwrap();
                parked_until_cancelled(&body_cx, body_ready).await;
                yield_now().await;
                Response::new(200, "OK", Vec::new())
            }
        },
        config(),
    );
    let mut serving = enclosing
        .cx()
        .spawn(move |connection_cx| async move {
            let mut serving = Box::pin(server.serve_owned(&connection_cx, socket));
            let mut abandon = pin!(abandoned.recv(&connection_cx));
            poll_fn(|task| {
                assert!(serving.as_mut().poll(task).is_pending());
                abandon.as_mut().poll(task)
            })
            .await
            .unwrap();
            drop(serving);
        })
        .unwrap();
    body_parked.recv(&cx).await.unwrap();
    child_parked.recv(&cx).await.unwrap();
    abandon.send_blocking(()).unwrap();
    serving.join(&cx).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    let mut close = Box::pin(enclosing.close());
    poll_fn(|task| {
        assert!(
            close.as_mut().poll(task).is_pending(),
            "drop requested cleanup, not quiescence"
        );
        Poll::Ready(())
    })
    .await;
    release.send_blocking(()).unwrap();
    close.await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(response(&mut peer).await.is_empty());
}

#[test]
fn dropping_owned_serving_future_requests_cleanup_and_parent_close_proves_retirement() {
    native(abandoned_serving_future_closes_subtree);
}

async fn listener_owns_buffered_requests(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let (child_ready, mut child_parked) = oneshot::channel();
    let (body_ready, mut body_started) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((child_ready, body_ready, finished))));
    let handler_drops = Arc::clone(&drops);
    let listener = Http1Listener::bind_with_config(
        "127.0.0.1:0",
        move |request: Request| {
            assert!(request.peer_addr.is_some());
            let (child_ready, body_ready, mut finish) = signals.lock().unwrap().take().unwrap();
            let drops = Arc::clone(&handler_drops);
            async move {
                let _body_drop = Dropped(Arc::clone(&drops));
                let body_cx = Cx::current().unwrap();
                body_cx
                    .spawn(move |child_cx| async move {
                        let _child_drop = Dropped(drops);
                        parked_until_cancelled(&child_cx, child_ready).await;
                        yield_now().await;
                    })
                    .unwrap();
                body_ready.send_blocking(body_cx.clone()).unwrap();
                finish.recv(&body_cx).await.unwrap();
                Response::new(200, "OK", b"listener".to_vec())
            }
        },
        Http1ListenerConfig::default()
            .http_config(config())
            .drain_timeout(Duration::from_secs(5))
            .hard_drain_timeout(Duration::from_secs(10)),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx
        .spawn(move |listener_cx| async move {
            // This native spawn is also a compile-time Send requirement for the
            // concrete listener dispatch future; no erased-future shortcut.
            listener.run_owned_in(&listener_cx).await
        })
        .unwrap();
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let body = body_started.recv(&cx).await.unwrap();
    let child = child_parked.recv(&cx).await.unwrap();
    assert_eq!(body.region_id(), child.region_id());
    assert_ne!(body.region_id(), cx.region_id());
    assert_ne!(body.task_id(), serving.task_id());
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    finish.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    assert!(received.ends_with("listener"), "{received}");
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(manager.begin_drain(Duration::from_secs(5)));
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    assert_eq!(manager.active_count(), 0);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn owned_listener_preserves_request_identity_and_drains_admitted_connections() {
    native(listener_owns_buffered_requests);
}

struct LocalReply(Rc<str>);

impl IntoHttp1Response for LocalReply {
    fn into_h1_response(self) -> Http1Response {
        Http1Response::new(Response::new(200, "OK", self.0.as_bytes().to_vec()))
    }
}

#[test]
fn legacy_server_still_accepts_borrowed_handler_and_send_future_with_non_send_output() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async {
        let local = String::from("borrowed local response");
        let borrowed = local.as_str();
        let handler = move |_: Request| {
            // Rc is created only at Ready. The future remains Send, its output
            // does not, and the factory/future both borrow non-static data.
            poll_fn(move |_| Poll::Ready(LocalReply(Rc::from(borrowed))))
        };
        let (socket, mut peer, _) =
            pair(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let state = Http1Server::with_config_upgradeable(handler, config())
            .serve(socket)
            .await
            .unwrap();
        assert_eq!(state.requests_served, 1);
        assert!(response(&mut peer).await.ends_with(&local));
    });
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

#[cfg(not(target_arch = "wasm32"))]
mod listener_body_budget {
    use asupersync::Cx;
    use asupersync::http::h1::Http1Config;
    use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig, Http1ListenerStats};
    use asupersync::http::h1::server::HostPolicy;
    use asupersync::http::h1::types::{Request, Response};
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::server::connection::ConnectionManager;
    use asupersync::sync::Notify;
    use asupersync::types::CancelKind;
    use std::future::{Future, poll_fn};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    struct Peer(BufReader<TcpStream>);

    struct Head {
        status: u16,
        headers: Vec<(String, String)>,
    }

    impl Peer {
        fn connect(address: SocketAddr) -> Self {
            let socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            Self(BufReader::new(socket))
        }

        fn send(&mut self, bytes: &[u8]) {
            self.0.get_mut().write_all(bytes).unwrap();
        }

        fn fixed(&mut self, path: &str, length: usize, expect_continue: bool) {
            let expect = if expect_continue {
                "Expect: 100-continue\r\n"
            } else {
                ""
            };
            self.send(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\n{expect}\r\n"
                )
                .as_bytes(),
            );
        }

        fn chunked(&mut self, path: &str) {
            self.send(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nTrailer: x-budget\r\n\r\n"
                )
                .as_bytes(),
            );
            assert_eq!(self.head().status, 100);
        }

        fn head(&mut self) -> Head {
            let mut line = String::new();
            assert_ne!(self.0.read_line(&mut line).unwrap(), 0, "response status");
            assert!(line.ends_with("\r\n"), "HTTP status line: {line:?}");
            let mut words = line.split_whitespace();
            assert_eq!(words.next(), Some("HTTP/1.1"));
            let status = words.next().unwrap().parse().unwrap();
            let mut headers = Vec::new();
            let mut total = line.len();
            loop {
                line.clear();
                assert_ne!(self.0.read_line(&mut line).unwrap(), 0, "response headers");
                total += line.len();
                assert!(total <= 16 * 1024, "bounded response head");
                if line == "\r\n" {
                    break;
                }
                assert!(line.ends_with("\r\n"));
                let (name, value) = line.trim_end().split_once(':').unwrap();
                headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
            }
            Head { status, headers }
        }

        fn continued(&mut self) {
            assert_eq!(
                self.head().status,
                100,
                "admission must precede 100 Continue"
            );
        }

        fn refusal(&mut self, status: u16) {
            // Fixed-length callers have not consumed any response yet, so a
            // premature 100 Continue fails the expected final-status assertion.
            let head = self.head();
            assert_eq!(head.status, status);
            assert!(head.headers.iter().any(|(name, value)| {
                name == "connection" && value.eq_ignore_ascii_case("close")
            }));
            let mut body = Vec::new();
            self.0.read_to_end(&mut body).unwrap();
        }

        fn response(&mut self, expected: &[u8]) {
            let head = self.head();
            assert_eq!(head.status, 200);
            let length = head
                .headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .expect("buffered response declares its body length")
                .1
                .parse::<usize>()
                .unwrap();
            assert_eq!(length, expected.len());
            let mut body = vec![0; length];
            self.0.read_exact(&mut body).unwrap();
            assert_eq!(body, expected);
        }

        fn echo(address: SocketAddr, body: &[u8]) {
            let mut peer = Self::connect(address);
            peer.fixed("/echo", body.len(), true);
            peer.continued();
            peer.send(body);
            peer.response(body);
        }

        fn bodyless(address: SocketAddr) {
            let mut peer = Self::connect(address);
            peer.fixed("/echo", 0, false);
            peer.response(b"");
        }
    }

    struct HandlerState {
        parked: std::sync::mpsc::Sender<(usize, Cx)>,
        cleaning: std::sync::mpsc::Sender<usize>,
        release: Notify,
        released: AtomicBool,
        child_started: Notify,
        child_pending: AtomicBool,
        calls: AtomicUsize,
        body_drops: AtomicUsize,
        body_verified: AtomicUsize,
    }

    struct BodyDrop(Arc<HandlerState>);

    impl Drop for BodyDrop {
        fn drop(&mut self) {
            self.0.body_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn release_after_pending(
        state: &HandlerState,
        body_length: usize,
        cleaning: bool,
        cx: &Cx,
    ) {
        let mut release = std::pin::pin!(
            state
                .release
                .wait_until(|| state.released.load(Ordering::Acquire))
        );
        let mut witnessed = false;
        poll_fn(|task| {
            let result = release.as_mut().poll(task);
            if result.is_pending() && !witnessed {
                if cleaning {
                    state.cleaning.send(body_length).unwrap();
                } else {
                    state.parked.send((body_length, cx.clone())).unwrap();
                }
                witnessed = true;
            }
            result
        })
        .await;
    }

    async fn answer(request: Request, state: Arc<HandlerState>) -> Response {
        state.calls.fetch_add(1, Ordering::SeqCst);
        let cx = Cx::current().expect("owned request context");
        if request.uri == "/descendant" {
            let child_state = Arc::clone(&state);
            let body = request.body;
            let _child = cx
                .spawn(move |child| async move {
                    let _drop = BodyDrop(Arc::clone(&child_state));
                    let mut cancelled = std::pin::pin!(child.cancelled());
                    let mut witnessed = false;
                    poll_fn(|task| {
                        let result = cancelled.as_mut().poll(task);
                        if result.is_pending() && !witnessed {
                            child_state.child_pending.store(true, Ordering::Release);
                            child_state.child_started.notify_waiters();
                            witnessed = true;
                        }
                        result
                    })
                    .await;
                    assert!(child.checkpoint().is_err());
                    release_after_pending(&child_state, body.len(), true, &child).await;
                    assert_eq!(body.as_slice(), b"retained");
                    child_state.body_verified.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            // A body that returns before its child is admitted could prevent
            // the child's factory from ever running. Observe actual Pending.
            state
                .child_started
                .wait_until(|| state.child_pending.load(Ordering::Acquire))
                .await;
            return Response::new(200, "OK", Vec::new());
        }
        if request.uri == "/park" || request.uri == "/cancel" {
            let _drop = BodyDrop(Arc::clone(&state));
            if request.uri == "/cancel" {
                let mut cancelled = std::pin::pin!(cx.cancelled());
                let mut witnessed = false;
                poll_fn(|task| {
                    let result = cancelled.as_mut().poll(task);
                    if result.is_pending() && !witnessed {
                        state.parked.send((request.body.len(), cx.clone())).unwrap();
                        witnessed = true;
                    }
                    result
                })
                .await;
                assert!(cx.checkpoint().is_err());
            }
            release_after_pending(&state, request.body.len(), request.uri == "/cancel", &cx).await;
            // The original Vec remains live across both ordinary parking and
            // cancellation cleanup, not merely a copied length or marker.
            assert_eq!(request.body.as_slice(), b"retained");
            state.body_verified.fetch_add(1, Ordering::SeqCst);
        }
        if request.uri == "/trailers" {
            assert_eq!(
                request.trailers,
                vec![("x-budget".to_owned(), "complete".to_owned())],
            );
        }
        Response::new(200, "OK", request.body)
    }

    struct Fixture {
        address: SocketAddr,
        stats: Arc<Http1ListenerStats>,
        state: Arc<HandlerState>,
        parked: std::sync::mpsc::Receiver<(usize, Cx)>,
        cleaning: std::sync::mpsc::Receiver<usize>,
        manager: ConnectionManager,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Assertion failures must not strand a cooperatively parked task
            // while the runtime's destructor waits for request retirement.
            self.state.released.store(true, Ordering::Release);
            self.state.release.notify_waiters();
            self.manager.force_close();
        }
    }

    fn observe(label: &str, condition: impl Fn() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "HTTP/1 body-budget watchdog: {label}"
            );
            std::thread::yield_now();
        }
    }

    fn execute(workers: usize, limit: Option<NonZeroUsize>, workflow: impl FnOnce(&Fixture)) {
        let runtime = RuntimeBuilder::new()
            .worker_threads(workers)
            .with_sharded_state(workers == 2)
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let (parked, pending) = std::sync::mpsc::channel();
        let (cleaning, cleanup) = std::sync::mpsc::channel();
        let state = Arc::new(HandlerState {
            parked,
            cleaning,
            release: Notify::new(),
            released: AtomicBool::new(false),
            child_started: Notify::new(),
            child_pending: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            body_drops: AtomicUsize::new(0),
            body_verified: AtomicUsize::new(0),
        });
        let handler_state = Arc::clone(&state);
        let listener = runtime
            .block_on(Http1Listener::bind_with_config(
                "127.0.0.1:0",
                move |request| answer(request, Arc::clone(&handler_state)),
                Http1ListenerConfig::default()
                    .http_config(
                        Http1Config::default()
                            .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                            .max_body_size(16)
                            .request_drain_grace(Duration::from_secs(10)),
                    )
                    .drain_timeout(Duration::from_secs(2))
                    .hard_drain_timeout(Duration::from_secs(5)),
            ))
            .unwrap();
        let listener = if let Some(limit) = limit {
            listener.max_buffered_request_bytes(limit)
        } else {
            listener
        };
        let fixture = Fixture {
            address: listener.local_addr().unwrap(),
            stats: listener.stats_handle(),
            state,
            parked: pending,
            cleaning: cleanup,
            manager: listener.connection_manager().clone(),
        };
        let in_flight = listener.in_flight_requests();
        let serving: Pin<Box<dyn Future<Output = _> + Send>> = Box::pin(async move {
            let cx = Cx::current().expect("native listener owner");
            listener.run_owned_in(&cx).await
        });
        let run = runtime.handle().spawn(serving);

        workflow(&fixture);

        assert!(fixture.manager.begin_drain(Duration::from_secs(2)));
        assert!(
            runtime
                .block_on(run)
                .unwrap()
                .drain_report
                .unwrap()
                .reached_quiescence
        );
        observe("all request and connection tasks retired", || {
            runtime.is_quiescent()
        });
        assert_eq!(fixture.stats.reserved_request_body_bytes(), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.manager.active_count(), 0);
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert_eq!(runtime.draining_region_count(), 0);
    }

    fn exercise(
        workers: usize,
        limit: Option<NonZeroUsize>,
        workflow: impl FnOnce(&Fixture) + Send + 'static,
    ) {
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                execute(workers, limit, workflow);
            }));
            let _ = send.send(result);
        });
        let result = receive
            .recv_timeout(Duration::from_secs(45))
            .expect("HTTP/1 body-budget scenario must finish its native drain");
        worker.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn fixed_length_reservations_are_shared_before_continue_and_reusable_after_disconnect() {
        for workers in [1, 2] {
            exercise(workers, NonZeroUsize::new(8), |fixture| {
                let mut first = Peer::connect(fixture.address);
                first.fixed("/echo", 6, true);
                first.continued();
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 6);
                let mut second = Peer::connect(fixture.address);
                second.fixed("/echo", 2, true);
                second.continued();
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 8);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);

                let mut refused = Peer::connect(fixture.address);
                refused.fixed("/never", 1, true);
                refused.refusal(503);
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 8);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
                Peer::bodyless(fixture.address);
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 8);

                drop(first);
                observe("incomplete fixed body released its declaration", || {
                    fixture.stats.reserved_request_body_bytes() == 2
                });
                Peer::echo(fixture.address, b"reuse!");
                observe("replacement response retired", || {
                    fixture.stats.reserved_request_body_bytes() == 2
                });
                drop(second);
                observe("second incomplete fixed body retired", || {
                    fixture.stats.reserved_request_body_bytes() == 0
                });
                Peer::echo(fixture.address, b"12345678");
                observe("exact-cap response retired", || {
                    fixture.stats.reserved_request_body_bytes() == 0
                });
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 3);
            });
        }
    }

    #[test]
    fn chunk_sizes_reserve_before_payload_and_trailers_keep_the_completed_charge() {
        for workers in [1, 2] {
            exercise(workers, NonZeroUsize::new(8), |fixture| {
                let mut chunks = Peer::connect(fixture.address);
                chunks.chunked("/trailers");
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 0);
                chunks.send(b"6\r\n");
                observe("chunk declaration admitted before payload arrival", || {
                    fixture.stats.reserved_request_body_bytes() == 6
                });
                let mut refused = Peer::connect(fixture.address);
                refused.fixed("/never", 3, true);
                refused.refusal(503);
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 6);
                chunks.send(b"123456\r\n2\r\n");
                observe("second chunk declaration reaches exact global cap", || {
                    fixture.stats.reserved_request_body_bytes() == 8
                });
                Peer::bodyless(fixture.address);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
                chunks.send(b"78\r\n0\r\nx-budget: complete\r\n\r\n");
                chunks.response(b"12345678");
                observe("trailer-completed request and response retired", || {
                    fixture.stats.reserved_request_body_bytes() == 0
                });

                let mut overflow = Peer::connect(fixture.address);
                overflow.chunked("/never");
                overflow.send(b"6\r\n123456\r\n3\r\n");
                overflow.refusal(503);
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 0);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 2);

                let mut abandoned = Peer::connect(fixture.address);
                abandoned.chunked("/never");
                abandoned.send(b"4\r\n");
                observe("truncated chunk retains its declared reservation", || {
                    fixture.stats.reserved_request_body_bytes() == 4
                });
                drop(abandoned);
                observe("truncated chunk release", || {
                    fixture.stats.reserved_request_body_bytes() == 0
                });
                // Reuse the trailer-completed connection to exercise codec
                // reservation transfer/reset across keep-alive requests.
                chunks.fixed("/echo", 8, true);
                chunks.continued();
                chunks.send(b"reusable");
                chunks.response(b"reusable");
                assert_eq!(fixture.stats.body_budget_refusals_total(), 2);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 3);
            });
        }
    }

    #[test]
    fn completed_body_stays_reserved_through_handler_and_cancellation_cleanup() {
        for workers in [1, 2] {
            for cancel in [false, true] {
                exercise(workers, NonZeroUsize::new(8), move |fixture| {
                    let mut first = Peer::connect(fixture.address);
                    first.fixed(if cancel { "/cancel" } else { "/park" }, 8, true);
                    first.continued();
                    first.send(b"retained");
                    let (length, cx) = fixture.parked.recv_timeout(Duration::from_secs(5)).unwrap();
                    assert_eq!(length, 8);
                    assert_eq!(fixture.stats.reserved_request_body_bytes(), 8);
                    assert_eq!(fixture.state.body_drops.load(Ordering::SeqCst), 0);

                    let mut refused = Peer::connect(fixture.address);
                    refused.fixed("/never", 1, true);
                    refused.refusal(503);
                    Peer::bodyless(fixture.address);
                    if cancel {
                        cx.cancel_with(CancelKind::User, Some("body-budget cleanup witness"));
                        assert_eq!(
                            fixture
                                .cleaning
                                .recv_timeout(Duration::from_secs(5))
                                .unwrap(),
                            8,
                        );
                        assert_eq!(fixture.stats.reserved_request_body_bytes(), 8);
                        assert_eq!(fixture.state.body_drops.load(Ordering::SeqCst), 0);
                        let mut during_cleanup = Peer::connect(fixture.address);
                        during_cleanup.fixed("/never", 1, true);
                        during_cleanup.refusal(503);
                    }
                    fixture.state.released.store(true, Ordering::Release);
                    fixture.state.release.notify_waiters();
                    if !cancel {
                        first.response(b"retained");
                    }
                    observe("actual handler cleanup and response retirement", || {
                        fixture.stats.reserved_request_body_bytes() == 0
                    });
                    assert_eq!(fixture.state.body_drops.load(Ordering::SeqCst), 1);
                    assert_eq!(fixture.state.body_verified.load(Ordering::SeqCst), 1);
                    drop(first);
                    Peer::echo(fixture.address, b"reusable");
                    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 3);
                    assert_eq!(
                        fixture.stats.body_budget_refusals_total(),
                        if cancel { 2 } else { 1 },
                    );
                });
            }
        }
    }

    #[test]
    fn owned_descendant_keeps_original_body_reserved_after_handler_returns() {
        for workers in [1, 2] {
            exercise(workers, NonZeroUsize::new(8), |fixture| {
                let mut first = Peer::connect(fixture.address);
                first.fixed("/descendant", 8, true);
                first.continued();
                first.send(b"retained");
                assert_eq!(
                    fixture
                        .cleaning
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap(),
                    8,
                );
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 8);
                assert_eq!(fixture.state.body_drops.load(Ordering::SeqCst), 0);
                let mut refused = Peer::connect(fixture.address);
                refused.fixed("/never", 1, true);
                refused.refusal(503);
                Peer::bodyless(fixture.address);

                fixture.state.released.store(true, Ordering::Release);
                fixture.state.release.notify_waiters();
                first.response(b"");
                observe("owned descendant and region cleanup retired", || {
                    fixture.stats.reserved_request_body_bytes() == 0
                });
                assert_eq!(fixture.state.body_drops.load(Ordering::SeqCst), 1);
                assert_eq!(fixture.state.body_verified.load(Ordering::SeqCst), 1);
                Peer::echo(fixture.address, b"reusable");
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 3);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
            });
        }
    }

    #[test]
    fn unlimited_default_still_enforces_per_request_limit_without_global_refusals() {
        for workers in [1, 2] {
            exercise(workers, None, |fixture| {
                let mut first = Peer::connect(fixture.address);
                first.fixed("/echo", 16, true);
                first.continued();
                let mut second = Peer::connect(fixture.address);
                second.fixed("/echo", 16, true);
                second.continued();
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 32);

                let mut too_large = Peer::connect(fixture.address);
                too_large.fixed("/never", 17, true);
                too_large.refusal(413);
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 32);
                let mut large_chunk = Peer::connect(fixture.address);
                large_chunk.chunked("/never");
                large_chunk.send(b"11\r\n");
                large_chunk.refusal(413);
                assert_eq!(fixture.stats.reserved_request_body_bytes(), 32);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 0);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);

                drop(first);
                observe("unlimited partial body retired", || {
                    fixture.stats.reserved_request_body_bytes() == 16
                });
                second.send(b"0123456789abcdef");
                second.response(b"0123456789abcdef");
                observe("unlimited completed body retired", || {
                    fixture.stats.reserved_request_body_bytes() == 0
                });
                assert_eq!(fixture.stats.body_budget_refusals_total(), 0);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
            });
        }
    }
}
