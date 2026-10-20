//! Native HTTPS ownership for live incoming bodies, produced responses, and SSE.
//!
//! Readiness comes from actual body/source Pending polls and decrypted HTTP
//! frames. Successful responses are parsed through their framing boundary,
//! without treating a TLS transport drop as a required close-notify receipt.

#![cfg(all(feature = "tls", not(target_arch = "wasm32")))]

use asupersync::bytes::{Buf, Bytes, BytesMut};
use asupersync::channel::oneshot;
use asupersync::codec::Decoder;
use asupersync::cx::Cx;
use asupersync::http::body::{Body, Frame};
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::stream::{Http1ProducedResponse, StreamingServerRequest};
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h1::{Http1Client, Http1ClientCodec, HttpError};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
    TlsConnectorBuilder,
};
use asupersync::web::sse::{SseEvent, StreamingSse, StreamingSseError, StreamingSseSource};
use std::fmt::Debug;
use std::future::{Future, poll_fn};
use std::io;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");

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
                        let mut task = root.spawn(scenario).unwrap();
                        task.join(&root).await.unwrap();
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
    // Bounds a broken journey; it never supplies a readiness witness.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("owned HTTPS streaming journey must retire and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn acceptor(protocol: &[u8]) -> TlsAcceptor {
    TlsAcceptorBuilder::new(
        CertificateChain::from_pem(CERT).unwrap(),
        PrivateKey::from_pem(KEY).unwrap(),
    )
    .alpn_protocols(vec![protocol.to_vec()])
    .build()
    .unwrap()
}

fn connector(protocol: &[u8]) -> TlsConnector {
    let root = Certificate::from_pem(CERT).unwrap().remove(0);
    TlsConnectorBuilder::new()
        .add_root_certificate(&root)
        .alpn_protocols_required(vec![protocol.to_vec()])
        .build()
        .unwrap()
}

fn config() -> Http1ListenerConfig {
    Http1ListenerConfig::default()
        .http_config(
            Http1Config::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                .idle_timeout(None)
                .request_drain_grace(Duration::from_millis(100)),
        )
        .drain_timeout(Duration::from_secs(5))
        .hard_drain_timeout(Duration::from_secs(10))
}

fn assert_task(cx: &Cx) {
    let current = Cx::current().unwrap();
    assert_eq!(current.task_id(), cx.task_id());
    assert_eq!(current.region_id(), cx.region_id());
}

// The upload test writes its head separately from its body. Decode the response
// to its explicit HTTP boundary, without sending a second request or reading
// through an unclean TLS EOF after a successful Content-Length response.
async fn framed_response<T: AsyncRead + Unpin>(peer: &mut T) -> Response {
    let mut codec = Http1ClientCodec::new()
        .max_headers_size(4096)
        .max_body_size(1024);
    let mut buffered = BytesMut::new();
    let mut total = 0;
    loop {
        if let Some(response) = codec.decode(&mut buffered).unwrap() {
            assert!(buffered.is_empty());
            return response;
        }
        let mut scratch = [0; 1024];
        let read = peer.read(&mut scratch).await.unwrap();
        assert_ne!(read, 0, "response ended before its framing boundary");
        total += read;
        assert!(total <= 8192, "unexpectedly large test response");
        buffered.extend_from_slice(&scratch[..read]);
    }
}

async fn read_data<B>(body: &mut B, expected: &[u8])
where
    B: Body + Unpin,
    B::Error: Debug,
{
    let mut received = Vec::new();
    while received.len() < expected.len() {
        let frame = poll_fn(|task| Pin::new(&mut *body).poll_frame(task))
            .await
            .expect("body must contain the expected data")
            .unwrap();
        let Frame::Data(mut data) = frame else {
            panic!("unexpected trailers before the expected data");
        };
        while data.has_remaining() {
            let chunk = data.chunk();
            received.extend_from_slice(chunk);
            data.advance(chunk.len());
        }
        assert!(received.len() <= expected.len());
    }
    assert_eq!(received, expected);
}

async fn assert_body_pending<B: Body + Unpin>(body: &mut B) {
    poll_fn(|task| {
        assert!(Pin::new(&mut *body).poll_frame(task).is_pending());
        Poll::Ready(())
    })
    .await;
}

struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct CleanupGate {
    owner: Cx,
    ready: oneshot::Sender<Cx>,
    release: oneshot::Receiver<()>,
    drops: Arc<AtomicUsize>,
}

fn gate(
    cx: &Cx,
) -> (
    CleanupGate,
    oneshot::Receiver<Cx>,
    oneshot::Sender<()>,
    Arc<AtomicUsize>,
) {
    let (ready, parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    (
        CleanupGate {
            owner: cx.clone(),
            ready,
            release: released,
            drops: Arc::clone(&drops),
        },
        parked,
        release,
        drops,
    )
}

async fn admit_child(cx: &Cx, cleanup: CleanupGate) {
    let (started, mut start) = oneshot::channel();
    let _child = cx
        .spawn(move |child| async move {
            let _dropped = Dropped(cleanup.drops);
            let mut started = Some(started);
            let mut cancelled = pin!(child.cancelled());
            poll_fn(|task| match cancelled.as_mut().poll(task) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending => {
                    if let Some(started) = started.take() {
                        started.send_blocking(child.clone()).unwrap();
                    }
                    Poll::Pending
                }
            })
            .await;
            assert!(child.checkpoint().is_err());
            let mut ready = Some(cleanup.ready);
            let mut release = cleanup.release;
            let mut released = pin!(release.recv(&cleanup.owner));
            poll_fn(|task| match released.as_mut().poll(task) {
                Poll::Ready(result) => Poll::Ready(result.unwrap()),
                Poll::Pending => {
                    if let Some(ready) = ready.take() {
                        ready.send_blocking(child.clone()).unwrap();
                    }
                    Poll::Pending
                }
            })
            .await;
        })
        .unwrap();
    let child = start.recv(cx).await.unwrap();
    assert_eq!(child.region_id(), cx.region_id());
    assert_ne!(child.task_id(), cx.task_id());
}

async fn incoming_body_is_live_over_tls(cx: Cx) {
    let (ready, mut body_parked) = oneshot::channel();
    let ready = Arc::new(Mutex::new(Some(ready)));
    let listener = Http1Listener::bind_streaming_with_config(
        "127.0.0.1:0",
        move |request_cx: Cx, mut request: StreamingServerRequest| {
            assert_task(&request_cx);
            assert!(request.peer_addr.is_some());
            let mut ready = ready.lock().unwrap().take();
            async move {
                let mut received = Vec::new();
                loop {
                    let frame = poll_fn(|task| {
                        assert_task(&request_cx);
                        let result = Pin::new(&mut request.body).poll_frame(task);
                        if result.is_pending()
                            && let Some(ready) = ready.take()
                        {
                            ready.send_blocking(request_cx.clone()).unwrap();
                        }
                        result
                    })
                    .await;
                    match frame {
                        Some(Ok(Frame::Data(data))) => {
                            received.extend_from_slice(data.into_inner().as_ref());
                        }
                        None => break,
                        other => panic!("valid fixed-length upload: {other:?}"),
                    }
                }
                assert_eq!(received, b"live upload");
                Response::new(200, "OK", received)
            }
        },
        config(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx
        .spawn(move |listener_cx| async move {
            listener
                .run_streaming_tls_owned_in(&listener_cx, acceptor(b"http/1.1"))
                .await
        })
        .unwrap();
    let mut tls = connector(b"http/1.1")
        .connect("localhost", TcpStream::connect(address).await.unwrap())
        .await
        .unwrap();
    assert_eq!(tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
    tls.write_all(
        b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    tls.flush().await.unwrap();
    let request = body_parked.recv(&cx).await.unwrap();
    assert_ne!(request.task_id(), serving.task_id());
    assert_ne!(request.region_id(), cx.region_id());
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    let monitor = cx.monitor(request.task_id()).await.unwrap();
    // The handler has already polled the real incoming body to Pending, even
    // though no upload bytes have yet been sent through TLS.
    tls.write_all(b"live upload").await.unwrap();
    tls.flush().await.unwrap();
    let response = framed_response(&mut tls).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"live upload");
    monitor.down(&cx).await.unwrap();
    assert!(manager.begin_drain(Duration::from_secs(5)));
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    assert!(manager.is_empty());
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn native_owned_tls_incoming_body_is_live_before_upload() {
    native(incoming_body_is_live_over_tls);
}

async fn produced_terminal_waits_for_tls_cleanup(cx: Cx) {
    let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
    let setup = Arc::new(Mutex::new(Some(cleanup)));
    let identities = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&identities);
    let listener = Http1Listener::bind_produced_with_config(
        "127.0.0.1:0",
        move |request_cx: Cx, request: StreamingServerRequest| {
            assert_task(&request_cx);
            assert!(request.peer_addr.is_some());
            observed.lock().unwrap().push(request_cx.clone());
            let cleanup = setup.lock().unwrap().take().unwrap();
            async move {
                admit_child(&request_cx, cleanup).await;
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    move |producer_cx, mut sender| async move {
                        assert_task(&producer_cx);
                        assert_eq!(producer_cx.task_id(), request_cx.task_id());
                        assert_eq!(producer_cx.region_id(), request_cx.region_id());
                        sender
                            .send_bytes(&producer_cx, Bytes::from_static(b"hello"))
                            .await?;
                        sender
                            .send_bytes(&producer_cx, Bytes::from_static(b"world"))
                            .await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            }
        },
        config(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx
        .spawn(move |listener_cx| async move {
            listener
                .run_produced_tls_owned_in(&listener_cx, acceptor(b"http/1.1"))
                .await
        })
        .unwrap();
    let tls = connector(b"http/1.1")
        .connect("localhost", TcpStream::connect(address).await.unwrap())
        .await
        .unwrap();
    let mut response = Http1Client::request_streaming(
        tls,
        Request::get("/produced")
            .header("Host", "localhost")
            .build(),
    )
    .await
    .unwrap();
    assert_eq!(response.head.status, 200);
    read_data(&mut response.body, b"helloworld").await;
    let child = cleanup_parked.recv(&cx).await.unwrap();
    let request = identities.lock().unwrap()[0].clone();
    assert_ne!(request.task_id(), serving.task_id());
    assert_ne!(request.region_id(), cx.region_id());
    assert_eq!(child.region_id(), request.region_id());
    assert_ne!(child.task_id(), request.task_id());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    // Both data chunks crossed TLS, but parsing the terminal chunk must park
    // while a cancelled descendant still owns its withheld cleanup.
    assert_body_pending(&mut response.body).await;
    assert!(manager.begin_drain(Duration::from_secs(5)));
    poll_fn(|task| {
        assert!(serving.poll_join(task).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    release.send_blocking(()).unwrap();
    assert!(
        poll_fn(|task| Pin::new(&mut response.body).poll_frame(task))
            .await
            .is_none(),
        "successful chunked completion must survive the TLS transport boundary"
    );
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(manager.is_empty());
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn native_owned_tls_produced_terminal_and_drain_wait_for_cleanup() {
    native(produced_terminal_waits_for_tls_cleanup);
}

struct IdleSource {
    request: Cx,
    event: Option<SseEvent>,
    ready: Option<oneshot::Sender<Cx>>,
    waker: Option<Waker>,
    cancelled: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl StreamingSseSource for IdleSource {
    fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
        assert_task(cx);
        assert_eq!(cx.task_id(), self.request.task_id());
        Ok(self.event.take())
    }

    fn poll_next_event(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
    ) -> Poll<Result<Option<SseEvent>, StreamingSseError>> {
        assert_task(cx);
        assert_eq!(cx.task_id(), self.request.task_id());
        assert_eq!(cx.region_id(), self.request.region_id());
        if self.event.is_some() {
            return Poll::Ready(self.next_event(cx));
        }
        if self
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task.waker()))
        {
            self.waker = Some(task.waker().clone());
        }
        if let Some(ready) = self.ready.take() {
            ready.send_blocking(cx.clone()).unwrap();
        }
        Poll::Pending
    }

    fn cancel(&mut self) {
        assert_task(&self.request);
        self.cancelled.fetch_add(1, Ordering::SeqCst);
        self.waker = None;
    }
}

impl Drop for IdleSource {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

async fn idle_sse_cancellation_truncates_tls(cx: Cx) {
    let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
    let (ready, mut source_parked) = oneshot::channel();
    let setup = Arc::new(Mutex::new(Some((cleanup, ready))));
    let cancelled = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let source_cancelled = Arc::clone(&cancelled);
    let source_dropped = Arc::clone(&dropped);
    let listener = Http1Listener::bind_sse_with_config(
        "127.0.0.1:0",
        move |request_cx: Cx, request: StreamingServerRequest| {
            assert_task(&request_cx);
            assert!(request.peer_addr.is_some());
            let (cleanup, ready) = setup.lock().unwrap().take().unwrap();
            let cancelled = Arc::clone(&source_cancelled);
            let dropped = Arc::clone(&source_dropped);
            async move {
                admit_child(&request_cx, cleanup).await;
                StreamingSse::from_source(IdleSource {
                    request: request_cx,
                    event: Some(SseEvent::default().event("update").data("owned TLS event")),
                    ready: Some(ready),
                    waker: None,
                    cancelled,
                    dropped,
                })
                .into_http1_response(NonZeroUsize::MIN)
            }
        },
        config(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let shutdown = listener.shutdown_signal();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx
        .spawn(move |listener_cx| async move {
            listener
                .run_sse_tls_owned_in(&listener_cx, acceptor(b"http/1.1"))
                .await
        })
        .unwrap();
    let tls = connector(b"http/1.1")
        .connect("localhost", TcpStream::connect(address).await.unwrap())
        .await
        .unwrap();
    let mut response = Http1Client::request_streaming(
        tls,
        Request::get("/events").header("Host", "localhost").build(),
    )
    .await
    .unwrap();
    assert_eq!(response.head.status, 200);
    assert!(response.head.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value == "text/event-stream"
    }));
    read_data(
        &mut response.body,
        b"event: update\ndata: owned TLS event\n\n",
    )
    .await;
    // Require both a decrypted event at the peer and a real source Pending.
    // Merely constructing the source or enqueueing its event is insufficient.
    let request = source_parked.recv(&cx).await.unwrap();
    assert_ne!(request.task_id(), serving.task_id());
    assert_ne!(request.region_id(), cx.region_id());
    assert_body_pending(&mut response.body).await;
    assert_eq!(cancelled.load(Ordering::SeqCst), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(manager.begin_drain(Duration::from_secs(5)));
    assert!(shutdown.begin_force_close());
    let child = cleanup_parked.recv(&cx).await.unwrap();
    assert_eq!(child.region_id(), request.region_id());
    assert_ne!(child.task_id(), request.task_id());
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert_body_pending(&mut response.body).await;
    poll_fn(|task| {
        assert!(serving.poll_join(task).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send_blocking(()).unwrap();
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    // This stream was deliberately cancelled. A missing TLS close_notify may
    // surface before the HTTP parser reports its missing terminal chunk; both
    // must remain errors, never a successful EOF or a replacement response.
    let terminal = poll_fn(|task| Pin::new(&mut response.body).poll_frame(task)).await;
    match terminal {
        Some(Err(HttpError::BadChunkedEncoding)) => {}
        Some(Err(HttpError::Io(error)))
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("cancelled SSE must remain visibly truncated: {other:?}"),
    }
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(manager.is_empty());
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn native_owned_tls_idle_sse_cancel_keeps_cleanup_owned_and_truncates() {
    native(idle_sse_cancellation_truncates_tls);
}

async fn non_http1_alpn_retires_before_dispatch(cx: Cx) {
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let listener = Http1Listener::bind_streaming_with_config(
        "127.0.0.1:0",
        move |_: Cx, _: StreamingServerRequest| {
            handler_calls.fetch_add(1, Ordering::SeqCst);
            async { Response::new(200, "OK", b"must not dispatch".to_vec()) }
        },
        config(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx
        .spawn(move |listener_cx| async move {
            listener
                .run_streaming_tls_owned_in(&listener_cx, acceptor(b"h2"))
                .await
        })
        .unwrap();
    let tls = connector(b"h2")
        .connect("localhost", TcpStream::connect(address).await.unwrap())
        .await
        .unwrap();
    assert_eq!(tls.alpn_protocol(), Some(b"h2".as_slice()));
    // Keep the peer alive and leave the listener Running. The non-H1
    // handshake must itself retire the accepted connection: no client EOF,
    // shutdown signal, idle timeout, or rejected-I/O allowance supplies it.
    manager.wait_all_closed().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert!(manager.is_empty());
    assert!(manager.begin_drain(Duration::from_secs(5)));
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    drop(tls);
}

#[test]
fn native_owned_streaming_tls_refuses_non_http1_alpn_before_dispatch() {
    native(non_http1_alpn_retires_before_dispatch);
}
