//! Native ownership contracts for streaming incoming HTTP/1 requests.
//!
//! Real socket and body Pending polls establish readiness. Every journey runs
//! on current-thread and two-worker runtimes with unified and sharded state.

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::http::body::{Body, Frame, HeaderName};
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{
    HostPolicy, Http1Config, Http1StreamingConfig, Http1StreamingServer,
};
use asupersync::http::h1::stream::{IncomingBodyError, StreamingServerRequest};
use asupersync::http::h1::types::Response;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder, RuntimeHandle};
use asupersync::server::shutdown::ShutdownSignal;
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{CancelKind, CancelReason, ObligationId};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    native_with_trace(move |cx, _runtime| scenario(cx));
}

fn native_with_trace<F, Fut>(scenario: F)
where
    F: Fn(Cx, RuntimeHandle) -> Fut + Copy + Send + 'static,
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
                        let handle = runtime.handle();
                        let mut owner = root.spawn(move |cx| scenario(cx, handle)).unwrap();
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
    // Bounds a failed journey, never a readiness witness.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("owned streaming request must retire and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn config() -> Http1StreamingConfig {
    Http1StreamingConfig::from(
        Http1Config::default()
            .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
            .idle_timeout(None)
            .request_drain_grace(Duration::from_millis(100)),
    )
    .incoming_body_queue(1, 64)
}

#[derive(Default)]
struct WireWitness {
    written: AtomicUsize,
    dropped: AtomicUsize,
    read_pending_armed: AtomicBool,
    read_pending: Mutex<Option<oneshot::Sender<Cx>>>,
}

struct ObservedSocket {
    inner: TcpStream,
    witness: Arc<WireWitness>,
}

impl AsyncRead for ObservedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(task, buffer);
        if result.is_pending() && self.witness.read_pending_armed.load(Ordering::SeqCst) {
            let ready = self.witness.read_pending.lock().unwrap().take();
            if let Some(ready) = ready {
                ready.send_blocking(Cx::current().unwrap()).unwrap();
            }
        }
        result
    }
}

impl AsyncWrite for ObservedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(task, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.witness.written.fetch_add(*count, Ordering::SeqCst);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(task)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(task)
    }
}

impl Drop for ObservedSocket {
    fn drop(&mut self) {
        self.witness.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn pair(head: &[u8]) -> (ObservedSocket, TcpStream, Arc<WireWitness>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.write_all(head).unwrap();
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
    assert!(cx.checkpoint().is_err());
    cx.cancel_reason().unwrap()
}

async fn parked_cleanup(
    owner: &Cx,
    ready: oneshot::Sender<Cx>,
    mut release: oneshot::Receiver<()>,
) {
    let mut ready = Some(ready);
    let mut receive = pin!(release.recv(owner));
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

async fn streaming_pipeline_owns_body_and_children(cx: Cx) {
    let (socket, mut peer, wire) = pair(
        b"POST /first HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    let peer_addr = socket.inner.peer_addr().unwrap();
    let (read_ready, mut read_parked) = oneshot::channel();
    *wire.read_pending.lock().unwrap() = Some(read_ready);
    let (body_ready, mut body_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let first = Arc::new(Mutex::new(Some((body_ready, cleanup_ready, released))));
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let identities = Arc::new(Mutex::new(Vec::new()));
    let handler_drops = Arc::clone(&drops);
    let handler_calls = Arc::clone(&calls);
    let handler_ids = Arc::clone(&identities);
    let handler_wire = Arc::clone(&wire);
    let cleanup_owner = cx.clone();
    let server = Http1StreamingServer::with_config(
        move |request_cx: Cx, mut request: StreamingServerRequest| {
            let factory = Cx::current().unwrap();
            assert_eq!(factory.task_id(), request_cx.task_id());
            assert_eq!(factory.region_id(), request_cx.region_id());
            assert_eq!(request.peer_addr, Some(peer_addr));
            let signals = if request.head.uri == "/first" {
                first.lock().unwrap().take()
            } else {
                None
            };
            let drops = Arc::clone(&handler_drops);
            let calls = Arc::clone(&handler_calls);
            let identities = Arc::clone(&handler_ids);
            let wire = Arc::clone(&handler_wire);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                identities.lock().unwrap().push(request_cx.clone());
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some((ready, cleanup_ready, released)) = signals {
                    let mut ready = Some(ready);
                    let mut bytes = Vec::new();
                    let mut trailers = None;
                    loop {
                        let frame = poll_fn(|task| {
                            let result = Pin::new(&mut request.body).poll_frame(task);
                            if result.is_pending()
                                && let Some(ready) = ready.take()
                            {
                                wire.read_pending_armed.store(true, Ordering::SeqCst);
                                ready.send_blocking(request_cx.clone()).unwrap();
                            }
                            result
                        })
                        .await;
                        match frame {
                            Some(Ok(Frame::Data(data))) => {
                                bytes.extend_from_slice(data.into_inner().as_ref());
                            }
                            Some(Ok(Frame::Trailers(value))) => {
                                assert!(trailers.replace(value).is_none());
                            }
                            Some(Err(error)) => panic!("valid chunked body: {error:?}"),
                            None => break,
                        }
                    }
                    assert_eq!(bytes, b"hello");
                    let trailers = trailers.expect("one terminal trailer frame");
                    assert_eq!(trailers.len(), 1);
                    assert_eq!(
                        trailers.get(&HeaderName::from_static("x-end")).unwrap().as_bytes(),
                        b"yes",
                    );
                    let (child_ready, mut child_parked) = oneshot::channel();
                    request_cx.spawn(move |child_cx| async move {
                        let _dropped = Dropped(drops);
                        parked_until_cancelled(&child_cx, child_ready).await;
                        parked_cleanup(&cleanup_owner, cleanup_ready, released).await;
                    }).unwrap();
                    let child_cx = child_parked.recv(&request_cx).await.unwrap();
                    assert_eq!(child_cx.region_id(), request_cx.region_id());
                    Response::new(200, "OK", b"first".to_vec())
                } else {
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    Response::new(200, "OK", b"second".to_vec())
                }
            }
        },
        config(),
    )
    .with_in_flight_requests(Arc::clone(&in_flight));
    let mut serving = cx.spawn(move |connection_cx| async move {
        server.serve_owned_with_peer_addr(&connection_cx, socket, Some(peer_addr)).await
    }).unwrap();
    let body_cx = body_parked.recv(&cx).await.unwrap();
    let driver_cx = read_parked.recv(&cx).await.unwrap();
    assert_eq!(body_cx.task_id(), driver_cx.task_id());
    assert_eq!(body_cx.region_id(), driver_cx.region_id());
    assert_ne!(body_cx.task_id(), serving.task_id());
    assert_ne!(body_cx.region_id(), cx.region_id());
    let monitor = cx.monitor(body_cx.task_id()).await.unwrap();
    // No body bytes existed before the handler and real body driver parked.
    peer.write_all(
        b"5\r\nhello\r\n0\r\nx-end: yes\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    ).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    poll_fn(|task| {
        assert!(serving.poll_join(task).is_pending());
        Poll::Ready(())
    }).await;
    release.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 2);
    assert_eq!(received.matches("HTTP/1.1 200").count(), 2, "{received}");
    assert!(received.ends_with("second"), "{received}");
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    let identities = identities.lock().unwrap();
    assert_eq!(identities.len(), 2);
    assert_ne!(identities[0].task_id(), identities[1].task_id());
    assert_ne!(identities[0].region_id(), identities[1].region_id());
}

#[test]
fn owned_streaming_body_is_live_and_pipeline_waits_for_real_subtree_cleanup() {
    native(streaming_pipeline_owns_body_and_children);
}

async fn cancellation_drains_pending_stream(cx: Cx) {
    for forced in [false, true] {
        let (socket, mut peer, wire) = pair(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
        );
        let shutdown = ShutdownSignal::new();
        let (body_ready, mut body_parked) = oneshot::channel();
        let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let signals = Arc::new(Mutex::new(Some((body_ready, cleanup_ready, released))));
        let drops = Arc::new(AtomicUsize::new(0));
        let acknowledgements = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let handler_drops = Arc::clone(&drops);
        let handler_acks = Arc::clone(&acknowledgements);
        let cleanup_owner = cx.clone();
        let server = Http1StreamingServer::with_config(
            move |request_cx: Cx, mut request: StreamingServerRequest| {
                let (body_ready, cleanup_ready, released) = signals.lock().unwrap().take().unwrap();
                let drops = Arc::clone(&handler_drops);
                let acks = Arc::clone(&handler_acks);
                let cleanup_owner = cleanup_owner.clone();
                async move {
                    let _body_dropped = Dropped(Arc::clone(&drops));
                    let (child_ready, mut child_parked) = oneshot::channel();
                    let child_acks = Arc::clone(&acks);
                    request_cx.spawn(move |child_cx| async move {
                        let _child_dropped = Dropped(drops);
                        parked_until_cancelled(&child_cx, child_ready).await;
                        child_acks.fetch_add(1, Ordering::SeqCst);
                        parked_cleanup(&cleanup_owner, cleanup_ready, released).await;
                    }).unwrap();
                    child_parked.recv(&request_cx).await.unwrap();
                    let mut ready = Some(body_ready);
                    let frame = poll_fn(|task| {
                        let result = Pin::new(&mut request.body).poll_frame(task);
                        if result.is_pending()
                            && let Some(ready) = ready.take()
                        {
                            ready.send_blocking(request_cx.clone()).unwrap();
                        }
                        result
                    }).await;
                    assert!(matches!(frame, Some(Err(IncomingBodyError::Cancelled { .. }))));
                    assert!(request_cx.checkpoint().is_err());
                    acks.fetch_add(1, Ordering::SeqCst);
                    Response::new(200, "OK", b"cancelled response must stay private".to_vec())
                }
            },
            config(),
        )
        .with_shutdown_signal(shutdown.clone())
        .with_in_flight_requests(Arc::clone(&in_flight));
        let mut serving = cx.spawn(move |connection_cx| async move {
            server.serve_owned(&connection_cx, socket).await
        }).unwrap();
        body_parked.recv(&cx).await.unwrap();
        if forced {
            assert!(shutdown.begin_drain(Duration::from_secs(5)));
            assert!(shutdown.begin_force_close());
        } else {
            serving.abort_with_reason(CancelReason::user("cancel owned streaming request"));
        }
        cleanup_parked.recv(&cx).await.unwrap();
        assert_eq!(wire.written.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        poll_fn(|task| {
            assert!(serving.poll_join(task).is_pending());
            Poll::Ready(())
        }).await;
        release.send_blocking(()).unwrap();
        let joined = serving.join(&cx).await;
        assert!(!matches!(joined, Err(JoinError::Panicked(_))), "{joined:?}");
        assert_eq!(acknowledgements.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert!(response(&mut peer).await.is_empty());
    }
}

#[test]
fn owned_streaming_cancel_and_force_close_join_real_cleanup_without_response() {
    native(cancellation_drains_pending_stream);
}

async fn streaming_deadline_preserves_transport(cx: Cx) {
    let (socket, mut peer, wire) = pair(
        b"POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nRequest-Timeout: 1000ms\r\n\r\nxGET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let (body_ready, mut body_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((body_ready, cleanup_ready, released))));
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_drops = Arc::clone(&drops);
    let handler_calls = Arc::clone(&calls);
    let cleanup_owner = cx.clone();
    let mut settings = config();
    settings.connection.request_timeout_header_cap = Some(Duration::from_secs(2));
    let server = Http1StreamingServer::with_config(
        move |request_cx: Cx, mut request: StreamingServerRequest| {
            let signals = if request.head.uri == "/slow" {
                signals.lock().unwrap().take()
            } else {
                None
            };
            let drops = Arc::clone(&handler_drops);
            let calls = Arc::clone(&handler_calls);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some((body_ready, cleanup_ready, released)) = signals {
                    let _body_drop = Dropped(Arc::clone(&drops));
                    while let Some(frame) =
                        poll_fn(|task| Pin::new(&mut request.body).poll_frame(task)).await
                    {
                        frame.unwrap();
                    }
                    let (child_ready, mut child_parked) = oneshot::channel();
                    request_cx.spawn(move |child_cx| async move {
                        let _child_drop = Dropped(drops);
                        parked_until_cancelled(&child_cx, child_ready).await;
                        parked_cleanup(&cleanup_owner, cleanup_ready, released).await;
                    }).unwrap();
                    child_parked.recv(&request_cx).await.unwrap();
                    let reason = parked_until_cancelled(&request_cx, body_ready).await;
                    assert!(matches!(reason.kind, CancelKind::Deadline | CancelKind::Timeout));
                    std::future::pending::<Response>().await
                } else {
                    assert_eq!(drops.load(Ordering::SeqCst), 2);
                    Response::new(200, "OK", b"next".to_vec())
                }
            }
        },
        settings,
    );
    let mut serving = cx.spawn(move |connection_cx| async move {
        server.serve_owned(&connection_cx, socket).await
    }).unwrap();
    let body_cx = body_parked.recv(&cx).await.unwrap();
    let monitor = cx.monitor(body_cx.task_id()).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 2);
    assert!(received.starts_with("HTTP/1.1 503"), "{received}");
    assert!(received.contains("[ASUP-E501]"), "{received}");
    assert_eq!(received.matches("HTTP/1.1 200").count(), 1, "{received}");
    assert!(received.ends_with("next"), "{received}");
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn owned_streaming_deadline_retains_503_and_read_ahead_until_subtree_closes() {
    native(streaming_deadline_preserves_transport);
}

async fn streaming_body_refusals(cx: Cx) {
    for (wire_request, expected, discard, maximum) in [
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nz\r\nGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            400,
            false,
            32,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            413,
            false,
            3,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            413,
            true,
            32,
        ),
    ] {
        let (socket, mut peer, witness) = pair(wire_request);
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let mut settings = config().unread_body_drain(0, 0, Duration::from_millis(100));
        settings.connection.max_body_size = maximum;
        let server = Http1StreamingServer::with_config(
            move |_request_cx, mut request: StreamingServerRequest| {
                let calls = Arc::clone(&handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if !discard {
                        while let Some(frame) =
                            poll_fn(|task| Pin::new(&mut request.body).poll_frame(task)).await
                        {
                            if frame.is_err() {
                                break;
                            }
                        }
                    }
                    Response::new(200, "OK", b"must not publish".to_vec())
                }
            },
            settings,
        );
        let mut serving = cx.spawn(move |connection_cx| async move {
            server.serve_owned(&connection_cx, socket).await
        }).unwrap();
        let received = response(&mut peer).await;
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
        assert!(received.starts_with(&format!("HTTP/1.1 {expected} ")), "{received}");
        assert!(received.to_ascii_lowercase().contains("\r\nconnection: close\r\n"));
        assert!(!received.contains("must not publish"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(witness.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn owned_streaming_malformed_limit_and_unread_drain_refusals_keep_exact_wire_policy() {
    native(streaming_body_refusals);
}

async fn streaming_panics_return_transport(cx: Cx) {
    for factory_panic in [false, true] {
        let (socket, mut peer, witness) = pair(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let server = Http1StreamingServer::with_config(
            move |request_cx: Cx, _request| {
                assert_eq!(Cx::current().unwrap().task_id(), request_cx.task_id());
                handler_calls.fetch_add(1, Ordering::SeqCst);
                assert!(!factory_panic, "owned streaming factory panic");
                async move {
                    assert!(factory_panic, "owned streaming poll panic");
                    Response::new(200, "OK", Vec::new())
                }
            },
            config(),
        );
        let mut serving = cx.spawn(move |connection_cx| async move {
            server.serve_owned(&connection_cx, socket).await
        }).unwrap();
        let received = response(&mut peer).await;
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
        assert!(received.starts_with("HTTP/1.1 500"), "{received}");
        assert!(!received.contains("HTTP/1.1 200"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(witness.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn owned_streaming_factory_and_poll_panics_return_500_and_forbid_reuse() {
    native(streaming_panics_return_transport);
}

async fn streaming_abandonment_stays_owned(cx: Cx) {
    let (socket, mut peer, wire) = pair(
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
    );
    let enclosing = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let (body_ready, mut body_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (abandon, mut abandoned) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((body_ready, cleanup_ready, released))));
    let drops = Arc::new(AtomicUsize::new(0));
    let handler_drops = Arc::clone(&drops);
    let cleanup_owner = cx.clone();
    let server = Http1StreamingServer::with_config(
        move |request_cx: Cx, _request| {
            let (body_ready, cleanup_ready, released) = signals.lock().unwrap().take().unwrap();
            let drops = Arc::clone(&handler_drops);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                let _body_drop = Dropped(Arc::clone(&drops));
                let (child_ready, mut child_parked) = oneshot::channel();
                request_cx.spawn(move |child_cx| async move {
                    let _child_drop = Dropped(drops);
                    parked_until_cancelled(&child_cx, child_ready).await;
                    parked_cleanup(&cleanup_owner, cleanup_ready, released).await;
                }).unwrap();
                child_parked.recv(&request_cx).await.unwrap();
                parked_until_cancelled(&request_cx, body_ready).await;
                Response::new(200, "OK", Vec::new())
            }
        },
        config(),
    );
    let mut serving = enclosing.cx().spawn(move |connection_cx| async move {
        let mut serving = Box::pin(server.serve_owned(&connection_cx, socket));
        let mut abandon = pin!(abandoned.recv(&connection_cx));
        poll_fn(|task| {
            assert!(serving.as_mut().poll(task).is_pending());
            abandon.as_mut().poll(task)
        }).await.unwrap();
        drop(serving);
    }).unwrap();
    let body_cx = body_parked.recv(&cx).await.unwrap();
    let monitor = cx.monitor(body_cx.task_id()).await.unwrap();
    abandon.send_blocking(()).unwrap();
    serving.join(&cx).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(wire.written.load(Ordering::SeqCst), 0);
    let mut closing = Box::pin(enclosing.close());
    poll_fn(|task| {
        assert!(closing.as_mut().poll(task).is_pending());
        Poll::Ready(())
    }).await;
    release.send_blocking(()).unwrap();
    closing.await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(response(&mut peer).await.is_empty());
}

#[test]
fn dropping_owned_streaming_future_closes_transport_and_keeps_descendants_owned() {
    native(streaming_abandonment_stays_owned);
}

async fn legacy_streaming_borrows_still_work(cx: Cx) {
    let message = String::from("borrowed handler and transport");
    let (mut socket, mut peer, _) = pair(
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let server = Http1StreamingServer::with_config(
        |_request_cx, _request| async { Response::new(200, "OK", message.as_bytes().to_vec()) },
        config(),
    );
    let serving = server.serve(&cx, &mut socket);
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&serving);
    assert_eq!(serving.await.unwrap().requests_served, 1);
    assert!(response(&mut peer).await.ends_with(&message));
}

#[test]
fn legacy_streaming_keeps_borrowed_handler_and_transport_send_contract() {
    native(legacy_streaming_borrows_still_work);
}

async fn streaming_listener_drains_owned_requests(cx: Cx) {
    let (body_ready, mut body_parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((body_ready, cleanup_ready, released))));
    let drops = Arc::new(AtomicUsize::new(0));
    let handler_drops = Arc::clone(&drops);
    let cleanup_owner = cx.clone();
    let listener = Http1Listener::bind_streaming_with_config(
        "127.0.0.1:0",
        move |request_cx: Cx, mut request: StreamingServerRequest| {
            assert!(request.peer_addr.is_some());
            assert_eq!(Cx::current().unwrap().task_id(), request_cx.task_id());
            let (body_ready, cleanup_ready, released) = signals.lock().unwrap().take().unwrap();
            let drops = Arc::clone(&handler_drops);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                let _body_drop = Dropped(Arc::clone(&drops));
                let (child_ready, mut child_parked) = oneshot::channel();
                request_cx.spawn(move |child_cx| async move {
                    let _child_drop = Dropped(drops);
                    parked_until_cancelled(&child_cx, child_ready).await;
                    parked_cleanup(&cleanup_owner, cleanup_ready, released).await;
                }).unwrap();
                let child = child_parked.recv(&request_cx).await.unwrap();
                assert_eq!(child.region_id(), request_cx.region_id());
                let mut ready = Some(body_ready);
                let mut bytes = Vec::new();
                while let Some(frame) = poll_fn(|task| {
                    let frame = Pin::new(&mut request.body).poll_frame(task);
                    if frame.is_pending()
                        && let Some(ready) = ready.take()
                    {
                        ready.send_blocking(request_cx.clone()).unwrap();
                    }
                    frame
                }).await {
                    if let Some(data) = frame.unwrap().into_data() {
                        bytes.extend_from_slice(data.into_inner().as_ref());
                    }
                }
                assert_eq!(bytes, b"hello");
                Response::new(200, "OK", b"listener completed".to_vec())
            }
        },
        Http1ListenerConfig::default()
            .http_config(config().connection)
            .drain_timeout(Duration::from_secs(5))
            .hard_drain_timeout(Duration::from_secs(10)),
    ).await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx.spawn(move |listener_cx| async move {
        // Also requires the concrete owned streaming listener future be Send.
        listener.run_streaming_owned_in(&listener_cx).await
    }).unwrap();
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n")
        .await.unwrap();
    let body = body_parked.recv(&cx).await.unwrap();
    assert_ne!(body.task_id(), serving.task_id());
    assert_ne!(body.region_id(), cx.region_id());
    let monitor = cx.monitor(body.task_id()).await.unwrap();
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert!(manager.begin_drain(Duration::from_secs(5)));
    peer.write_all(b"hello").await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    poll_fn(|task| {
        assert!(serving.poll_join(task).is_pending(), "request cleanup still admitted");
        Poll::Ready(())
    }).await;
    release.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    assert!(received.ends_with("listener completed"), "{received}");
    assert!(received.to_ascii_lowercase().contains("\r\nconnection: close\r\n"));
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(manager.active_count(), 0);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn owned_streaming_listener_drains_live_request_and_descendants_before_quiescence() {
    native(streaming_listener_drains_owned_requests);
}

fn body_events<'trace>(
    trace: &'trace [TraceEvent],
    request: &Cx,
) -> Vec<(usize, &'trace TraceEvent)> {
    trace.iter().enumerate().filter(|(_, event)| matches!(event.data,
        TraceData::Obligation { task, region, kind: ObligationKind::IoOp, .. }
        if task == request.task_id() && region == request.region_id()
    )).collect()
}

async fn pending_body_obligation(runtime: &RuntimeHandle, request: &Cx) -> ObligationId {
    loop {
        let trace = runtime.trace_snapshot().expect("live runtime trace");
        let events = body_events(&trace, request);
        if let Some((_, reserved)) = events.iter().find(|(_, event)| {
            event.kind == TraceEventKind::ObligationReserve
        }) {
            assert_eq!(events.len(), 1, "a parked live body has one unresolved credit");
            let TraceData::Obligation { obligation, .. } = reserved.data else {
                unreachable!("filtered obligation event");
            };
            return obligation;
        }
        // A checked admission owns its quota before the runtime projects its
        // mailbox record. Wait for that actual record, never a scheduling delay.
        asupersync::runtime::yield_now().await;
    }
}

fn assert_body_retired(
    runtime: &RuntimeHandle,
    request: &Cx,
    obligation: ObligationId,
    abort: Option<ObligationAbortReason>,
) {
    let trace = runtime.trace_snapshot().expect("live runtime trace");
    let events = body_events(&trace, request);
    assert_eq!(events.len(), 2, "one reserve and one terminal event for the body");
    assert_eq!(events[0].1.kind, TraceEventKind::ObligationReserve);
    let terminal = events[1];
    assert_eq!(terminal.1.kind, if abort.is_some() {
        TraceEventKind::ObligationAbort
    } else {
        TraceEventKind::ObligationCommit
    });
    assert!(matches!(terminal.1.data,
        TraceData::Obligation { obligation: id, abort_reason, .. }
        if id == obligation && abort_reason == abort
    ));
    let complete = trace.iter().position(|event| event.kind == TraceEventKind::Complete
        && matches!(event.data, TraceData::Task { task, .. } if task == request.task_id())
    ).expect("actual request task retired");
    assert!(terminal.0 < complete, "body credit settles before its holder retires");
}

async fn streaming_body_credit_tracks_eof_and_unread_drain(cx: Cx, runtime: RuntimeHandle) {
    for unread in [false, true] {
        let (socket, mut peer, wire) = pair(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        );
        let (body_ready, mut body_parked) = oneshot::channel();
        let (read_ready, mut read_parked) = oneshot::channel();
        *wire.read_pending.lock().unwrap() = Some(read_ready);
        let ready = Arc::new(Mutex::new(Some(body_ready)));
        let handler_wire = Arc::clone(&wire);
        let server = Http1StreamingServer::with_config(
            move |request_cx: Cx, mut request: StreamingServerRequest| {
                let mut ready = ready.lock().unwrap().take();
                let wire = Arc::clone(&handler_wire);
                async move {
                    if unread {
                        drop(request.body);
                        wire.read_pending_armed.store(true, Ordering::SeqCst);
                        ready.take().unwrap().send_blocking(request_cx.clone()).unwrap();
                    } else {
                        let mut received = Vec::new();
                        loop {
                            let frame = poll_fn(|task| {
                                let result = Pin::new(&mut request.body).poll_frame(task);
                                if result.is_pending()
                                    && let Some(ready) = ready.take()
                                {
                                    wire.read_pending_armed.store(true, Ordering::SeqCst);
                                    ready.send_blocking(request_cx.clone()).unwrap();
                                }
                                result
                            }).await;
                            match frame {
                                Some(Ok(Frame::Data(bytes))) => {
                                    received.extend_from_slice(bytes.into_inner().as_ref());
                                }
                                None => break,
                                other => panic!("valid Content-Length body: {other:?}"),
                            }
                        }
                        assert_eq!(received, b"hello");
                    }
                    Response::new(200, "OK", b"settled".to_vec())
                }
            },
            config(),
        );
        let mut serving = cx.spawn(move |connection_cx| async move {
            server.serve_owned(&connection_cx, socket).await
        }).unwrap();
        let request = body_parked.recv(&cx).await.unwrap();
        let driver = read_parked.recv(&cx).await.unwrap();
        assert_eq!(request.task_id(), driver.task_id());
        assert_eq!(request.region_id(), driver.region_id());
        assert_ne!(request.task_id(), serving.task_id());
        assert_ne!(request.region_id(), cx.region_id());
        let credit = pending_body_obligation(&runtime, &request).await;
        assert_eq!(wire.written.load(Ordering::SeqCst), 0);
        peer.write_all(b"hello").await.unwrap();
        let reply = response(&mut peer).await;
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.ends_with("settled"), "{reply}");
        assert_body_retired(&runtime, &request, credit, None);
    }
}

#[test]
fn owned_streaming_body_credit_survives_pending_consumer_and_unread_drain_until_eof() {
    native_with_trace(streaming_body_credit_tracks_eof_and_unread_drain);
}

async fn streaming_body_credit_aborts_on_force_close(cx: Cx, runtime: RuntimeHandle) {
    let (socket, mut peer, wire) = pair(
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
    );
    let (body_ready, mut body_parked) = oneshot::channel();
    let (read_ready, mut read_parked) = oneshot::channel();
    *wire.read_pending.lock().unwrap() = Some(read_ready);
    let ready = Arc::new(Mutex::new(Some(body_ready)));
    let handler_wire = Arc::clone(&wire);
    let shutdown = ShutdownSignal::new();
    let acknowledged = Arc::new(AtomicBool::new(false));
    let handler_acknowledged = Arc::clone(&acknowledged);
    let server = Http1StreamingServer::with_config(
        move |request_cx: Cx, mut request: StreamingServerRequest| {
            let mut ready = ready.lock().unwrap().take();
            let wire = Arc::clone(&handler_wire);
            let acknowledged = Arc::clone(&handler_acknowledged);
            async move {
                let frame = poll_fn(|task| {
                    let result = Pin::new(&mut request.body).poll_frame(task);
                    if result.is_pending() && let Some(ready) = ready.take() {
                        wire.read_pending_armed.store(true, Ordering::SeqCst);
                        ready.send_blocking(request_cx.clone()).unwrap();
                    }
                    result
                }).await;
                assert!(matches!(frame, Some(Err(IncomingBodyError::Cancelled {
                    kind: CancelKind::Shutdown,
                }))));
                request_cx.checkpoint().expect_err("request acknowledged force close");
                acknowledged.store(true, Ordering::SeqCst);
                Response::new(200, "OK", b"must stay private".to_vec())
            }
        },
        config(),
    ).with_shutdown_signal(shutdown.clone());
    let mut serving = cx.spawn(move |connection_cx| async move {
        server.serve_owned(&connection_cx, socket).await
    }).unwrap();
    let request = body_parked.recv(&cx).await.unwrap();
    let driver = read_parked.recv(&cx).await.unwrap();
    assert_eq!(request.task_id(), driver.task_id());
    let credit = pending_body_obligation(&runtime, &request).await;
    assert!(shutdown.begin_drain(Duration::from_secs(5)));
    assert!(shutdown.begin_force_close());
    serving.join(&cx).await.unwrap().unwrap();
    assert!(acknowledged.load(Ordering::SeqCst));
    assert!(response(&mut peer).await.is_empty());
    assert_body_retired(&runtime, &request, credit, Some(ObligationAbortReason::Cancel));
}

#[test]
fn owned_streaming_force_close_aborts_one_body_credit_before_task_retirement() {
    native_with_trace(streaming_body_credit_aborts_on_force_close);
}
