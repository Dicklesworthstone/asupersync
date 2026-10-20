//! Native ownership contracts for produced HTTP/1 responses and live SSE.
//!
//! Actual Pending polls witness descendant cleanup and cancellation. Wire
//! bytes prove which response boundaries are visible before subtree retirement.
//! Each journey runs on current-thread/two-worker, unified/sharded runtimes.

#![cfg(not(target_arch = "wasm32"))]

use asupersync::bytes::Bytes;
use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::http::body::{HeaderMap, HeaderName, HeaderValue};
use asupersync::http::h1::codec::HttpError;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{
    HostPolicy, Http1Config, Http1StreamingConfig, Http1StreamingServer,
};
use asupersync::http::h1::stream::{
    Http1ProducedResponse, OutgoingBodySender, StreamingServerRequest,
};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder};
use asupersync::server::shutdown::ShutdownSignal;
use asupersync::types::CancelReason;
use asupersync::web::sse::{SseEvent, StreamingSse, StreamingSseError, StreamingSseSource};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
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
    // A failed journey is bounded; elapsed time is never a readiness witness.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("owned produced response must retire and drain");
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
            .request_drain_grace(Duration::from_millis(40)),
    )
    .incoming_body_queue(1, 64)
}

#[derive(Default)]
struct Wire {
    bytes: Mutex<Vec<u8>>,
    dropped: AtomicUsize,
}

impl Wire {
    fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
    }
}

struct Socket {
    inner: TcpStream,
    wire: Arc<Wire>,
}

impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(task, buffer)
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(task, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.wire.bytes.lock().unwrap().extend_from_slice(&bytes[..*count]);
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

impl Drop for Socket {
    fn drop(&mut self) {
        self.wire.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn pair(head: &[u8]) -> (Socket, TcpStream, Arc<Wire>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.write_all(head).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let wire = Arc::new(Wire::default());
    (
        Socket { inner: TcpStream::from_std(server).unwrap(), wire: Arc::clone(&wire) },
        TcpStream::from_std(peer).unwrap(),
        wire,
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

struct CleanupGate {
    owner: Cx,
    ready: oneshot::Sender<Cx>,
    release: oneshot::Receiver<()>,
    drops: Arc<AtomicUsize>,
}

fn gate(cx: &Cx) -> (CleanupGate, oneshot::Receiver<Cx>, oneshot::Sender<()>, Arc<AtomicUsize>) {
    let (ready, parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    (
        CleanupGate { owner: cx.clone(), ready, release: released, drops: Arc::clone(&drops) },
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
            parked_until_cancelled(&child, started).await;
            let mut ready = Some(cleanup.ready);
            let mut released = cleanup.release;
            let mut receive = pin!(released.recv(&cleanup.owner));
            poll_fn(|task| match receive.as_mut().poll(task) {
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

fn assert_task(cx: &Cx) {
    let current = Cx::current().unwrap();
    assert_eq!(current.task_id(), cx.task_id());
    assert_eq!(current.region_id(), cx.region_id());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ending {
    Chunked,
    Trailers,
    Fixed,
    Empty,
    Head,
}

async fn terminal_bytes_wait_for_subtree_retirement(cx: Cx) {
    for ending in [Ending::Chunked, Ending::Trailers, Ending::Fixed, Ending::Empty, Ending::Head] {
        let head: &[u8] = if ending == Ending::Head {
            b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        } else {
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        };
        let (socket, mut peer, wire) = pair(head);
        let peer_addr = socket.inner.peer_addr().unwrap();
        let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
        let cleanup = Arc::new(Mutex::new(Some(cleanup)));
        let calls = Arc::new(AtomicUsize::new(0));
        let producer_calls = Arc::clone(&calls);
        let identities = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&identities);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let server = Http1StreamingServer::with_config_produced(
            move |request_cx: Cx, request: StreamingServerRequest| {
                assert_task(&request_cx);
                assert_eq!(request.peer_addr, Some(peer_addr));
                observed.lock().unwrap().push(request_cx.clone());
                let cleanup = cleanup.lock().unwrap().take().unwrap();
                let calls = Arc::clone(&producer_calls);
                async move {
                    admit_child(&request_cx, cleanup).await;
                    let producer = move |producer_cx: Cx, mut sender: OutgoingBodySender| {
                        assert_task(&producer_cx);
                        assert_eq!(producer_cx.task_id(), request_cx.task_id());
                        calls.fetch_add(1, Ordering::SeqCst);
                        async move {
                            assert_task(&producer_cx);
                            if ending != Ending::Empty {
                                sender.send_bytes(&producer_cx, Bytes::from_static(b"hello")).await?;
                                sender.send_bytes(&producer_cx, Bytes::from_static(b"world")).await?;
                            }
                            if ending == Ending::Trailers {
                                let mut trailers = HeaderMap::new();
                                trailers.insert(HeaderName::from_static("x-end"), HeaderValue::from_static("yes"));
                                sender.send_trailers(&producer_cx, trailers).await?;
                            } else {
                                sender.finish(&producer_cx)?;
                            }
                            Ok(sender)
                        }
                    };
                    if matches!(ending, Ending::Fixed | Ending::Empty | Ending::Head) {
                        Http1ProducedResponse::with_content_length_and_max_frame_bytes(
                            NonZeroUsize::MIN, NonZeroUsize::new(5).unwrap(), 200, "OK",
                            if ending == Ending::Empty { 0 } else { 10 }, producer,
                        )
                    } else {
                        Http1ProducedResponse::chunked_with_max_frame_bytes(
                            NonZeroUsize::MIN, NonZeroUsize::new(5).unwrap(), 200, "OK", producer,
                        )
                    }
                }
            },
            config(),
        )
        .with_in_flight_requests(Arc::clone(&in_flight));
        let mut serving = cx.spawn(move |connection| async move {
            server.serve_produced_owned_with_peer_addr(&connection, socket, Some(peer_addr)).await
        }).unwrap();
        let child = cleanup_parked.recv(&cx).await.unwrap();
        let request = identities.lock().unwrap()[0].clone();
        assert_ne!(request.task_id(), serving.task_id());
        assert_ne!(request.region_id(), cx.region_id());
        assert_eq!(child.region_id(), request.region_id());
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let pending = wire.text();
        match ending {
            Ending::Chunked | Ending::Trailers => {
                assert!(pending.contains("5\r\nhello\r\n5\r\nworld\r\n"), "{ending:?}: {pending:?}");
                assert!(!pending.contains("\r\n0\r\n"));
                assert!(!pending.contains("x-end"));
            }
            Ending::Fixed => {
                assert!(pending.ends_with("hello"), "{pending:?}");
                assert!(!pending.contains("world"));
            }
            Ending::Empty | Ending::Head => assert!(pending.is_empty(), "{pending:?}"),
        }
        poll_fn(|task| {
            assert!(serving.poll_join(task).is_pending());
            Poll::Ready(())
        }).await;
        release.send_blocking(()).unwrap();
        let received = response(&mut peer).await;
        let state = serving.join(&cx).await.unwrap().unwrap();
        assert_eq!(state.requests_served, 1);
        assert!(received.starts_with("HTTP/1.1 200"), "{received:?}");
        match ending {
            Ending::Chunked => assert!(received.ends_with("0\r\n\r\n")),
            Ending::Trailers => assert!(received.ends_with("0\r\nx-end: yes\r\n\r\n")),
            Ending::Fixed => assert!(received.ends_with("helloworld")),
            Ending::Empty | Ending::Head => assert!(received.ends_with("\r\n\r\n")),
        }
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(ending != Ending::Head));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn native_owned_produced_terminal_bytes_wait_for_subtree_retirement() {
    native(terminal_bytes_wait_for_subtree_retirement);
}

async fn cancel_and_force_close_keep_cleanup_owned(cx: Cx) {
    for force_close in [false, true] {
        let (socket, mut peer, wire) = pair(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
        let (ready, mut parked) = oneshot::channel();
        let setup = Arc::new(Mutex::new(Some((cleanup, ready))));
        let acknowledged = Arc::new(AtomicUsize::new(0));
        let acknowledgements = Arc::clone(&acknowledged);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let shutdown = ShutdownSignal::new();
        let server = Http1StreamingServer::with_config_produced(
            move |request_cx: Cx, _request: StreamingServerRequest| {
                assert_task(&request_cx);
                let (cleanup, ready) = setup.lock().unwrap().take().unwrap();
                let acknowledged = Arc::clone(&acknowledgements);
                async move {
                    Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", move |producer_cx, mut sender| async move {
                        assert_task(&producer_cx);
                        assert_eq!(producer_cx.task_id(), request_cx.task_id());
                        admit_child(&producer_cx, cleanup).await;
                        sender.send_bytes(&producer_cx, Bytes::from_static(b"started")).await?;
                        parked_until_cancelled(&producer_cx, ready).await;
                        acknowledged.fetch_add(1, Ordering::SeqCst);
                        Err(HttpError::BodyCancelled)
                    })
                }
            },
            config(),
        )
        .with_shutdown_signal(shutdown.clone())
        .with_in_flight_requests(Arc::clone(&in_flight));
        let mut serving = cx.spawn(move |connection| async move {
            server.serve_produced_owned(&connection, socket).await
        }).unwrap();
        let producer = parked.recv(&cx).await.unwrap();
        assert_ne!(producer.task_id(), serving.task_id());
        assert_ne!(producer.region_id(), cx.region_id());
        if force_close {
            assert!(shutdown.begin_drain(Duration::from_secs(5)));
            assert!(shutdown.begin_force_close());
        } else {
            serving.abort();
        }
        cleanup_parked.recv(&cx).await.unwrap();
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!wire.text().contains("\r\n0\r\n"));
        poll_fn(|task| {
            assert!(serving.poll_join(task).is_pending());
            Poll::Ready(())
        }).await;
        release.send_blocking(()).unwrap();
        let joined = serving.join(&cx).await;
        assert!(!matches!(joined, Err(JoinError::Panicked(_))), "{joined:?}");
        assert_eq!(acknowledged.load(Ordering::SeqCst), 1);
        let received = response(&mut peer).await;
        assert!(received.starts_with("HTTP/1.1 200"), "{received:?}");
        assert!(!received.contains("HTTP/1.1 500"));
        assert!(!received.contains("\r\n0\r\n"));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn native_owned_produced_cancel_and_force_close_keep_cleanup_owned() {
    native(cancel_and_force_close_keep_cleanup_owned);
}

async fn factory_and_poll_panics_preserve_terminal_gate(cx: Cx) {
    for in_factory in [false, true] {
        let (socket, mut peer, wire) = pair(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
        let setup = Arc::new(Mutex::new(Some(cleanup)));
        let server = Http1StreamingServer::with_config_produced(
            move |request_cx: Cx, _request: StreamingServerRequest| {
                assert_task(&request_cx);
                let cleanup = setup.lock().unwrap().take().unwrap();
                async move {
                    admit_child(&request_cx, cleanup).await;
                    Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", move |producer_cx, sender| {
                        assert_task(&producer_cx);
                        assert!(!in_factory, "owned produced factory panic");
                        async move {
                            assert!(in_factory, "owned produced poll panic");
                            Ok(sender)
                        }
                    })
                }
            },
            config(),
        );
        let mut serving = cx.spawn(move |connection| async move {
            server.serve_produced_owned(&connection, socket).await
        }).unwrap();
        cleanup_parked.recv(&cx).await.unwrap();
        if in_factory {
            assert!(wire.text().is_empty());
        } else {
            assert!(wire.text().starts_with("HTTP/1.1 200"));
        }
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 0);
        release.send_blocking(()).unwrap();
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
        let received = response(&mut peer).await;
        assert!(received.starts_with(if in_factory { "HTTP/1.1 500" } else { "HTTP/1.1 200" }), "{received:?}");
        assert_eq!(received.matches("HTTP/1.1 ").count(), 1);
        assert!(!received.contains("\r\n0\r\n"));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn native_owned_produced_factory_and_poll_panics_preserve_terminal_gate() {
    native(factory_and_poll_panics_preserve_terminal_gate);
}

async fn early_deadline_waits_for_cleanup_before_503(cx: Cx) {
    let (socket, mut peer, wire) = pair(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
    let (ready, mut parked) = oneshot::channel();
    let setup = Arc::new(Mutex::new(Some((cleanup, ready))));
    let handler_drops = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::clone(&handler_drops);
    let mut limits = config();
    limits.connection.request_timeout = Some(Duration::from_secs(1));
    let server = Http1StreamingServer::with_config_produced(
        move |request_cx: Cx, _request: StreamingServerRequest| {
            assert_task(&request_cx);
            let (cleanup, ready) = setup.lock().unwrap().take().unwrap();
            let dropped = Arc::clone(&dropped);
            async move {
                let _dropped = Dropped(dropped);
                admit_child(&request_cx, cleanup).await;
                parked_until_cancelled(&request_cx, ready).await;
                std::future::pending::<Http1ProducedResponse>().await
            }
        },
        limits,
    );
    let mut serving = cx.spawn(move |connection| async move {
        server.serve_produced_owned(&connection, socket).await
    }).unwrap();
    parked.recv(&cx).await.unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    assert!(wire.text().is_empty());
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 0);
    release.send_blocking(()).unwrap();
    assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
    let received = response(&mut peer).await;
    assert!(received.starts_with("HTTP/1.1 503"), "{received:?}");
    assert!(received.contains("ASUP-E501"));
    assert_eq!(received.matches("HTTP/1.1 ").count(), 1);
    assert_eq!(handler_drops.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn native_owned_produced_early_deadline_waits_for_cleanup_before_503() {
    native(early_deadline_waits_for_cleanup_before_503);
}

#[cfg(feature = "test-internals")]
async fn finalizer_panic_never_publishes_successful_completion(cx: Cx) {
    for length in [None, Some(10), Some(0)] {
        let (socket, mut peer, wire) = pair(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalizers = Arc::clone(&finalized);
        let server = Http1StreamingServer::with_config_produced(
            move |request_cx: Cx, _request: StreamingServerRequest| {
                assert_task(&request_cx);
                let finalized = Arc::clone(&finalizers);
                assert!(asupersync::runtime::Runtime::current_handle().unwrap()
                    .register_sync_finalizer_for_testing(request_cx.region_id(), move || {
                        finalized.fetch_add(1, Ordering::SeqCst);
                        panic!("intentional owned HTTP/1 finalizer failure");
                    }));
                async move {
                    let producer = move |producer_cx: Cx, mut sender: OutgoingBodySender| async move {
                        assert_task(&producer_cx);
                        if length != Some(0) {
                            sender.send_bytes(&producer_cx, Bytes::from_static(b"hello")).await?;
                            sender.send_bytes(&producer_cx, Bytes::from_static(b"world")).await?;
                        }
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    };
                    if let Some(length) = length {
                        Http1ProducedResponse::with_content_length(
                            NonZeroUsize::MIN, 200, "OK", length, producer,
                        )
                    } else {
                        Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", producer)
                    }
                }
            },
            config(),
        );
        let mut serving = cx.spawn(move |connection| async move {
            server.serve_produced_owned(&connection, socket).await
        }).unwrap();
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 1);
        let received = response(&mut peer).await;
        assert_eq!(finalized.load(Ordering::SeqCst), 1);
        assert!(!received.contains("\r\n0\r\n"));
        if length == Some(0) {
            assert!(received.starts_with("HTTP/1.1 500"), "{received:?}");
        } else {
            assert!(received.starts_with("HTTP/1.1 200"), "{received:?}");
            assert!(!received.contains("HTTP/1.1 500"));
            if length.is_some() {
                assert!(received.ends_with("hello"), "{received:?}");
            }
        }
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    }
}

#[cfg(feature = "test-internals")]
#[test]
fn native_owned_produced_finalizer_panic_never_publishes_successful_completion() {
    native(finalizer_panic_never_publishes_successful_completion);
}

struct Source {
    request: Cx,
    event: Option<SseEvent>,
    idle: bool,
    ready: Option<oneshot::Sender<Cx>>,
    waker: Option<Waker>,
    cancelled: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    wire: Arc<Wire>,
}

impl StreamingSseSource for Source {
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
        if self.event.is_some() || !self.idle {
            return Poll::Ready(self.next_event(cx));
        }
        if self.waker.as_ref().is_none_or(|waker| !waker.will_wake(task.waker())) {
            self.waker = Some(task.waker().clone());
        }
        // The source can park after queuing an event but before the transport
        // writes it. Require the actual wire event as well as source Pending
        // before the test cancels the connection.
        if self.wire.text().contains("data: owned event\n\n")
            && let Some(ready) = self.ready.take()
        {
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

impl Drop for Source {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

async fn sse_source_and_terminal_follow_request_retirement(cx: Cx) {
    for idle in [false, true] {
        let (socket, mut peer, wire) = pair(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
        let (ready, mut source_parked) = oneshot::channel();
        let setup = Arc::new(Mutex::new(Some((cleanup, ready))));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let source_cancelled = Arc::clone(&cancelled);
        let source_dropped = Arc::clone(&dropped);
        let source_wire = Arc::clone(&wire);
        let shutdown = ShutdownSignal::new();
        let server = Http1StreamingServer::with_config_sse(
            move |request_cx: Cx, _request: StreamingServerRequest| {
                assert_task(&request_cx);
                let (cleanup, ready) = setup.lock().unwrap().take().unwrap();
                let cancelled = Arc::clone(&source_cancelled);
                let dropped = Arc::clone(&source_dropped);
                let wire = Arc::clone(&source_wire);
                async move {
                    admit_child(&request_cx, cleanup).await;
                    let source = Source {
                        request: request_cx,
                        event: Some(SseEvent::default().event("update").data("owned event")),
                        idle,
                        ready: Some(ready),
                        waker: None,
                        cancelled,
                        dropped,
                        wire,
                    };
                    StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN)
                }
            },
            config(),
        )
        .with_shutdown_signal(shutdown.clone());
        let mut serving = cx.spawn(move |connection| async move {
            server.serve_sse_owned(&connection, socket).await
        }).unwrap();
        if idle {
            let source = source_parked.recv(&cx).await.unwrap();
            assert_ne!(source.task_id(), serving.task_id());
            assert_ne!(source.region_id(), cx.region_id());
            assert!(shutdown.begin_drain(Duration::from_secs(5)));
            assert!(shutdown.begin_force_close());
        }
        cleanup_parked.recv(&cx).await.unwrap();
        assert!(wire.text().contains("event: update\ndata: owned event\n\n"), "{:?}", wire.text());
        assert!(!wire.text().contains("\r\n0\r\n"));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(cancelled.load(Ordering::SeqCst), usize::from(idle));
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 0);
        release.send_blocking(()).unwrap();
        let joined = serving.join(&cx).await;
        assert!(!matches!(joined, Err(JoinError::Panicked(_))), "{joined:?}");
        let received = response(&mut peer).await;
        assert!(received.starts_with("HTTP/1.1 200"), "{received:?}");
        assert!(received.to_ascii_lowercase().contains("content-type: text/event-stream"));
        assert_eq!(received.ends_with("0\r\n\r\n"), !idle, "{received:?}");
        assert_eq!(cancelled.load(Ordering::SeqCst), usize::from(idle));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn native_owned_sse_source_and_terminal_follow_request_retirement() {
    native(sse_source_and_terminal_follow_request_retirement);
}

async fn borrowed_legacy_contract(cx: Cx) {
    let (mut socket, mut peer, _wire) = pair(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let message = String::from("borrowed handler and transport");
    let borrowed = message.as_str();
    let server = Http1StreamingServer::with_config_produced(
        move |_request_cx: Cx, _request: StreamingServerRequest| async move {
            let bytes = Bytes::copy_from_slice(borrowed.as_bytes());
            Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", move |producer_cx, mut sender| async move {
                sender.send_bytes(&producer_cx, bytes).await?;
                sender.finish(&producer_cx)?;
                Ok(sender)
            })
        },
        config(),
    );
    let serving = server.serve_produced(&cx, &mut socket);
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&serving);
    assert_eq!(serving.await.unwrap().requests_served, 1);
    let received = response(&mut peer).await;
    assert!(received.contains(&message), "{received:?}");
    assert!(received.ends_with("0\r\n\r\n"));
}

#[test]
fn legacy_produced_keeps_borrowed_handler_and_transport_send_contract() {
    native(borrowed_legacy_contract);
}

async fn listener_drain_includes_request_cleanup(cx: Cx) {
    let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
    let setup = Arc::new(Mutex::new(Some(cleanup)));
    let listener = Http1Listener::bind_produced_with_config(
        "127.0.0.1:0",
        move |request_cx: Cx, request: StreamingServerRequest| {
            assert_task(&request_cx);
            assert!(request.peer_addr.is_some());
            let cleanup = setup.lock().unwrap().take().unwrap();
            async move {
                Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", move |producer_cx, mut sender| async move {
                    assert_task(&producer_cx);
                    assert_eq!(producer_cx.task_id(), request_cx.task_id());
                    admit_child(&producer_cx, cleanup).await;
                    sender.send_bytes(&producer_cx, Bytes::from_static(b"listener event")).await?;
                    sender.finish(&producer_cx)?;
                    Ok(sender)
                })
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
        listener.run_produced_owned_in(&listener_cx).await
    }).unwrap();
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let child = cleanup_parked.recv(&cx).await.unwrap();
    assert_ne!(child.region_id(), cx.region_id());
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert!(manager.begin_drain(Duration::from_secs(5)));
    poll_fn(|task| {
        assert!(serving.poll_join(task).is_pending());
        Poll::Ready(())
    }).await;
    assert_eq!(manager.active_count(), 1);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    release.send_blocking(()).unwrap();
    let received = response(&mut peer).await;
    assert!(received.contains("listener event"), "{received:?}");
    assert!(received.ends_with("0\r\n\r\n"));
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(manager.active_count(), 0);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
}

#[test]
fn native_owned_produced_listener_drain_includes_request_cleanup() {
    native(listener_drain_includes_request_cleanup);
}

#[derive(Debug)]
struct ProducerError {
    token: Mutex<Option<asupersync::runtime::obligation_mailbox::ObligationToken>>,
    drops: Arc<AtomicUsize>,
}

impl std::fmt::Display for ProducerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("producer failed with an owned resource")
    }
}

impl std::error::Error for ProducerError {}

impl Drop for ProducerError {
    fn drop(&mut self) {
        if let Some(token) = self.token.lock().unwrap().take() {
            assert!(token.abort(asupersync::record::ObligationAbortReason::Error));
        }
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

async fn error_does_not_hold_an_obligation_across_close(cx: Cx) {
    let (socket, mut peer, wire) = pair(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (cleanup, mut cleanup_parked, release, drops) = gate(&cx);
    let setup = Arc::new(Mutex::new(Some(cleanup)));
    let error_drops = Arc::new(AtomicUsize::new(0));
    let errors_dropped = Arc::clone(&error_drops);
    let server = Http1StreamingServer::with_config_produced(
        move |request_cx: Cx, _request: StreamingServerRequest| {
            let cleanup = setup.lock().unwrap().take().unwrap();
            let errors_dropped = Arc::clone(&errors_dropped);
            async move {
                admit_child(&request_cx, cleanup).await;
                Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", move |producer_cx, _sender| async move {
                    let token = producer_cx.try_register_obligation_checked(
                        asupersync::record::ObligationKind::IoOp,
                        producer_cx.task_id(),
                    ).unwrap().unwrap();
                    Err(HttpError::Io(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        ProducerError { token: Mutex::new(Some(token)), drops: errors_dropped },
                    )))
                })
            }
        },
        config(),
    );
    let mut serving = cx.spawn(move |connection| async move {
        server.serve_produced_owned(&connection, socket).await
    }).unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    assert_eq!(error_drops.load(Ordering::SeqCst), 1, "opaque source must retire before close");
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    release.send_blocking(()).unwrap();
    let error = serving.join(&cx).await.unwrap().unwrap_err();
    let HttpError::Io(error) = error else { panic!("unexpected error: {error:?}") };
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "producer failed with an owned resource");
    assert_eq!(error_drops.load(Ordering::SeqCst), 1);
    let received = response(&mut peer).await;
    assert!(received.starts_with("HTTP/1.1 200"), "{received:?}");
    assert!(!received.contains("\r\n0\r\n"));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wire.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn native_owned_produced_error_does_not_hold_an_obligation_across_close() {
    native(error_does_not_hold_an_obligation_across_close);
}
