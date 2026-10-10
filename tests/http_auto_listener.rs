//! `HttpAutoListener`: HTTP/1.1 and HTTP/2 on one port. Real clients of each
//! protocol reach the same handler, which reports the version it served:
//! cleartext HTTP/1.1 and HTTP/2 with prior knowledge are told apart by the
//! connection preface, and over TLS by the negotiated ALPN protocol.

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder as _;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::http::h1::listener::Http1ListenerConfig;
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h2::client::Http2Client;
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::frame::{Frame, HeadersFrame, PingFrame, Setting, SettingsFrame};
use asupersync::http::h2::listener::Http2ListenerConfig;
use asupersync::http::h2::{ErrorCode, FrameCodec, Header, HpackEncoder};
use asupersync::http::{HttpAutoListener, HttpAutoListenerConfig};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::record::RegionLimits;
use asupersync::runtime::{Runtime, RuntimeBuilder, RuntimeHandle, yield_now};
use asupersync::server::shutdown::ShutdownPhase;
use asupersync::sync::Notify;
use asupersync::trace::{TraceData, TraceEventKind};
use asupersync::types::{CancelReason, RegionId, TaskId};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

fn config() -> HttpAutoListenerConfig {
    let localhost = HostPolicy::allow_list(vec!["localhost".to_owned()]);
    HttpAutoListenerConfig::default()
        .http1(
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: localhost.clone(),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(Duration::from_secs(10)),
        )
        .http2(
            Http2ListenerConfig::default()
                .host_policy(localhost)
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(Duration::from_secs(10)),
        )
}

async fn report(request: Request) -> Response {
    let body = format!(
        "{:?} {} peer={}",
        request.version,
        request.uri,
        request.peer_addr.is_some()
    );
    Response::new(200, "OK", body.into_bytes())
}

/// One `Connection: close` HTTP/1.1 request over `stream`; the whole response.
async fn http1_get<S>(stream: &mut S, target: &str) -> String
where
    S: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
{
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    AsyncWriteExt::write_all(stream, request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    AsyncReadExt::read_to_end(stream, &mut response)
        .await
        .expect("read response");
    String::from_utf8(response).expect("UTF-8 response")
}

/// This watchdog observes a native operation without cancelling its task or
/// the listener. In particular, it must not turn a missing configured timeout
/// into an apparent server close.
async fn bounded<F: Future>(future: F) -> F::Output {
    let now = Cx::current().expect("native runtime Cx").now();
    asupersync::time::timeout(now, Duration::from_secs(5), future)
        .await
        .expect("native operation completed within five seconds")
}

struct H2Peer {
    stream: TcpStream,
    codec: FrameCodec,
    input: BytesMut,
}

impl H2Peer {
    async fn connect(addr: SocketAddr, settings: Vec<Setting>) -> Self {
        let mut peer = Self {
            stream: bounded(TcpStream::connect(addr)).await.expect("connect raw HTTP/2"),
            codec: FrameCodec::new(),
            input: BytesMut::new(),
        };
        bounded(peer.stream.write_all(CLIENT_PREFACE))
            .await
            .expect("write HTTP/2 preface");
        peer.send(Frame::Settings(SettingsFrame::new(settings)))
            .await;
        loop {
            if let Frame::Settings(settings) = bounded(peer.next())
                .await
                .expect("server completed the HTTP/2 handshake")
                && !settings.ack
            {
                peer.send(Frame::Settings(SettingsFrame::ack())).await;
                return peer;
            }
        }
    }

    async fn send(&mut self, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).expect("encode client frame");
        bounded(self.stream.write_all(&bytes))
            .await
            .expect("write client frame");
    }

    async fn request(&mut self, stream_id: u32, path: &str) {
        let mut block = BytesMut::new();
        HpackEncoder::new().encode(
            &[
                Header::new(":method", "GET"),
                Header::new(":scheme", "http"),
                Header::new(":path", path),
                Header::new(":authority", "localhost"),
            ],
            &mut block,
        );
        self.send(Frame::Headers(HeadersFrame::new(
            stream_id,
            block.freeze(),
            true,
            true,
        )))
        .await;
    }

    async fn next(&mut self) -> Option<Frame> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.input).expect("server frame") {
                return Some(frame);
            }
            let mut bytes = [0u8; 4096];
            match self.stream.read(&mut bytes).await {
                Ok(0) => {
                    assert!(self.input.is_empty(), "server closed mid-frame");
                    return None;
                }
                Ok(len) => self.input.extend_from_slice(&bytes[..len]),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                    return None;
                }
                Err(error) => panic!("read server frame: {error}"),
            }
        }
    }

    async fn next_for(&mut self, stream_id: u32) -> Frame {
        bounded(async {
            loop {
                let frame = self.next().await.expect("HTTP/2 connection is still open");
                assert!(!matches!(frame, Frame::GoAway(_)), "{frame:?}");
                if frame.stream_id() == stream_id {
                    return frame;
                }
            }
        })
        .await
    }

    async fn response_body(&mut self, stream_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            match self.next_for(stream_id).await {
                Frame::Headers(headers) if headers.end_stream => return body,
                Frame::Data(data) => {
                    body.extend_from_slice(&data.data);
                    if data.end_stream {
                        return body;
                    }
                }
                Frame::RstStream(reset) => panic!("response reset: {reset:?}"),
                _ => {}
            }
        }
    }
}

fn native_runtime(workers: usize) -> RuntimeBuilder {
    if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    }
}

fn run_lifecycle<F, Fut>(runtime: Runtime, body: F)
where
    F: FnOnce(RuntimeHandle) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let work = body(runtime.handle());
    runtime.block_on(async move {
        asupersync::time::timeout(
            Cx::current().unwrap().now(),
            Duration::from_secs(20),
            work,
        )
        .await
        .expect("shared-port lifecycle must finish");
    });
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < Duration::from_secs(5), "HTTP tasks must retire");
        runtime.block_on(yield_now());
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}

async fn wait_for_service_tasks(
    handle: &RuntimeHandle,
    region: RegionId,
    count: usize,
) -> BTreeSet<TaskId> {
    let inspector = handle.task_inspector(Default::default()).unwrap();
    bounded(async {
        loop {
            let tasks: Vec<_> = inspector
                .by_region(region)
                .into_iter()
                .filter(|task| !task.is_terminal())
                .collect();
            if tasks.len() == count && tasks.iter().all(|task| task.poll_count > 0) {
                return tasks.into_iter().map(|task| task.id).collect();
            }
            yield_now().await;
        }
    })
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnedStop {
    Region,
    Owner,
    Coordinator,
    DropFuture,
}

async fn owned_service_lifecycle(handle: RuntimeHandle, stop: OwnedStop) {
    let cx = Cx::current().unwrap();
    let service = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let service_id = service.region_id();
    assert_ne!(service_id, cx.region_id());
    let owner = service.cx().clone();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let handler_observed = Arc::clone(&observed);
    let listener = HttpAutoListener::bind(
        "127.0.0.1:0",
        move |request: Request| {
            let observed = Arc::clone(&handler_observed);
            async move {
                observed.lock().unwrap().push((
                    request.uri.clone(),
                    Cx::current().unwrap().region_id(),
                ));
                report(request).await
            }
        },
        config().detect_timeout(Duration::from_secs(60)),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = listener.shutdown_signal();
    let drop_future = Arc::new(Notify::new());
    let drop_signal = Arc::clone(&drop_future);
    let supplied = owner.clone();
    let mut run = service
        .cx()
        .spawn(move |coordinator| async move {
            // This principal context and the actual polling task are distinct.
            // Aborting only the latter must still stop native accept/backoff.
            assert_ne!(coordinator.task_id(), supplied.task_id());
            let mut serving = Box::pin(listener.run_in(&supplied));
            let mut dropped = Box::pin(drop_signal.notified());
            std::future::poll_fn(|task| {
                if stop == OwnedStop::DropFuture && dropped.as_mut().poll(task).is_ready() {
                    return Poll::Ready(None);
                }
                serving.as_mut().poll(task).map(Some)
            })
            .await
        })
        .unwrap();

    let mut http1 = bounded(TcpStream::connect(address)).await.unwrap();
    assert!(
        bounded(http1_get(&mut http1, "/owned-http1"))
            .await
            .ends_with("Http11 /owned-http1 peer=true")
    );
    drop(http1);
    let mut http2 = H2Peer::connect(address, Vec::new()).await;
    http2.request(1, "/owned-http2").await;
    assert_eq!(
        http2.response_body(1).await,
        b"Http2 /owned-http2 peer=true"
    );

    // Cleanup alone could pass with root-spawned connections. Verify the real
    // handler contexts belong to the chosen service subtree before stopping it.
    let parents: BTreeMap<_, _> = handle
        .trace_snapshot()
        .unwrap()
        .into_iter()
        .filter_map(|event| match (event.kind, event.data) {
            (TraceEventKind::RegionCreated, TraceData::Region { region, parent: Some(parent) }) => {
                Some((region, parent))
            }
            _ => None,
        })
        .collect();
    let observed = observed.lock().unwrap().clone();
    assert_eq!(observed.len(), 2);
    for (request, mut region) in observed {
        let mut visited = BTreeSet::new();
        while region != service_id {
            assert!(visited.insert(region), "cyclic region ancestry for {request}");
            region = *parents
                .get(&region)
                .unwrap_or_else(|| panic!("{request} escaped service region {service_id:?}"));
        }
    }

    // The steady baseline is the coordinator, two protocol drivers and the
    // idle HTTP/2 connection. Each additional silent peer must add a task in
    // this same region, proving detector admission instead of assuming accept.
    wait_for_service_tasks(&handle, service_id, 4).await;
    let mut undecided = bounded(TcpStream::connect(address)).await.unwrap();
    let baseline = wait_for_service_tasks(&handle, service_id, 5).await;
    let mut partial_http1 = bounded(TcpStream::connect(address)).await.unwrap();
    let with_detector = wait_for_service_tasks(&handle, service_id, 6).await;
    assert!(baseline.is_subset(&with_detector));
    let added: Vec<_> = with_detector.difference(&baseline).copied().collect();
    assert_eq!(added.len(), 1, "the silent peer admits exactly one detector");
    let detector = added[0];
    bounded(partial_http1.write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n"))
        .await
        .unwrap();
    // Wait for this exact detector to retire and a newly polled connection
    // task to replace it. The task count alone cannot prove HTTP/1 handoff.
    bounded(async {
        loop {
            let tasks = wait_for_service_tasks(&handle, service_id, 6).await;
            if !tasks.contains(&detector) {
                assert!(baseline.is_subset(&tasks));
                assert_eq!(tasks.difference(&baseline).count(), 1);
                break;
            }
            yield_now().await;
        }
    })
    .await;
    assert_eq!(shutdown.phase(), ShutdownPhase::Running);

    let reason = CancelReason::user("stop owned shared-port service");
    match stop {
        OwnedStop::Region => service.cancel(reason).unwrap(),
        OwnedStop::Owner => owner.cancel_with_reason(reason),
        OwnedStop::Coordinator => {
            assert!(!owner.is_cancel_requested());
            run.abort_with_reason(reason);
        }
        OwnedStop::DropFuture => drop_future.notify_one(),
    }
    let result = bounded(run.join(&cx))
        .await
        .expect("the coordinator retains its completed shutdown result");
    if stop == OwnedStop::DropFuture {
        assert!(result.is_none());
        assert_eq!(shutdown.phase(), ShutdownPhase::ForceClosing);
    } else {
        let stats = result.unwrap().expect("both protocols drained");
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert!(stats.http1.drain_report.unwrap().reached_quiescence);
        assert!(stats.http2.drain_report.unwrap().reached_quiescence);
    }
    if stop == OwnedStop::Coordinator {
        assert!(!owner.is_cancel_requested(), "only the ambient task was aborted");
    }
    bounded(service.close()).await.unwrap();
    assert!(handle.task_inspector(Default::default()).unwrap().by_region(service_id).is_empty());
    assert!(!cx.is_cancel_requested(), "closing the service must not cancel its parent");

    // Region close is a resource barrier, including undecided and partial
    // requests. No timer or task cancellation on these clients creates EOF.
    let mut bytes = Vec::new();
    bounded(undecided.read_to_end(&mut bytes)).await.unwrap();
    assert!(bytes.is_empty());
    let closed = bounded(partial_http1.read_to_end(&mut bytes)).await;
    assert!(
        closed.is_ok()
            || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset),
        "an incomplete HTTP/1 head must release its socket"
    );
    bounded(async { while http2.next().await.is_some() {} }).await;
}

#[test]
fn a_child_region_owns_both_protocols_and_every_pending_detector() {
    for workers in [1, 2] {
        run_lifecycle(native_runtime(workers).build().unwrap(), |handle| {
            owned_service_lifecycle(handle, OwnedStop::Region)
        });
    }
}

#[test]
fn either_explicit_owner_or_ambient_coordinator_cancellation_drains_run_in() {
    for workers in [1, 2] {
        for stop in [OwnedStop::Owner, OwnedStop::Coordinator] {
            run_lifecycle(native_runtime(workers).build().unwrap(), move |handle| {
                owned_service_lifecycle(handle, stop)
            });
        }
    }
}

#[test]
fn dropping_run_in_keeps_cleanup_owned_until_the_region_closes() {
    for workers in [1, 2] {
        run_lifecycle(native_runtime(workers).build().unwrap(), |handle| {
            owned_service_lifecycle(handle, OwnedStop::DropFuture)
        });
    }
}

#[test]
fn a_refused_protocol_task_wakes_a_quiet_accept_and_drains_its_sibling() {
    for workers in [1, 2] {
        let runtime = native_runtime(workers)
            .root_region_limits(RegionLimits {
                // The block_on coordinator and first listener fit. The second
                // listener is refused asynchronously by Cx's spawn gateway.
                max_tasks: Some(2),
                ..RegionLimits::unlimited()
            })
            .build()
            .unwrap();
        run_lifecycle(runtime, |handle| async move {
            let cx = Cx::current().unwrap();
            let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
                .await
                .unwrap();
            let shutdown = listener.shutdown_signal();
            // No peer and no shutdown signal wake accept. Only the retained
            // child-terminal observer can stop and drain this listener.
            let error = bounded(listener.run_in(&cx)).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            let active = handle
                .task_inspector(Default::default())
                .unwrap()
                .list_tasks()
                .into_iter()
                .filter(|task| !task.is_terminal())
                .count();
            assert_eq!(active, 1, "the admitted sibling must retire before return");
        });
    }
}

/// br-asupersync-313vbb F7: shared-port gRPC/HTTP/2 keepalive survives the
/// handoff, renews on an ACK, and releases a client that stops responding.
#[test]
fn http2_keepalive_on_a_shared_port_renews_then_reclaims_the_connection() {
    let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .unwrap()
            .http2_keepalive(Duration::from_millis(100), Duration::from_secs(1));
        let addr = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle.spawn(async move { listener.run(&run_runtime).await });
        let mut peer = H2Peer::connect(addr, Vec::new()).await;

        for (index, answer) in [true, true, false].into_iter().enumerate() {
            let ping = bounded(async {
                loop {
                    let frame = peer.next().await.expect("connection alive until PING");
                    if let Frame::Ping(ping) = frame
                        && !ping.ack
                    {
                        break ping;
                    }
                }
            })
            .await;
            if answer {
                peer.send(Frame::Ping(PingFrame::ack(ping.opaque_data)))
                    .await;
                if index == 1 {
                    // No request was sent between the first two PINGs: the
                    // first ACK alone renewed liveness. Also prove that the
                    // connection still completes application requests.
                    peer.request(1, "/after-ack").await;
                    assert_eq!(peer.response_body(1).await, b"Http2 /after-ack peer=true");
                }
            }
        }
        bounded(async { while peer.next().await.is_some() {} }).await;

        let mut http1 = TcpStream::connect(addr).await.unwrap();
        let response = bounded(http1_get(&mut http1, "/after-keepalive")).await;
        assert!(
            response.ends_with("Http11 /after-keepalive peer=true"),
            "{response}"
        );
        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let stats = bounded(run).await.unwrap();
        assert!(stats.http1.drain_report.unwrap().reached_quiescence);
        assert!(stats.http2.drain_report.unwrap().reached_quiescence);
    }));
}

#[test]
fn shared_port_http2_keepalive_stays_off_by_default() {
    let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle.spawn(async move { listener.run(&run_runtime).await });
        let mut peer = H2Peer::connect(addr, Vec::new()).await;
        let quiet = asupersync::time::timeout(
            Cx::current().unwrap().now(),
            Duration::from_millis(400),
            async {
                loop {
                    match peer.next().await {
                        Some(Frame::Ping(ping)) if !ping.ack => {
                            panic!("unsolicited keepalive PING");
                        }
                        None => panic!("default listener closed a healthy idle client"),
                        _ => {}
                    }
                }
            },
        )
        .await;
        assert!(quiet.is_err(), "the idle observation interval elapsed");
        peer.request(1, "/still-open").await;
        assert_eq!(peer.response_body(1).await, b"Http2 /still-open peer=true");
        drop(peer);
        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let stats = bounded(run).await.unwrap();
        assert!(stats.http2.drain_report.unwrap().reached_quiescence);
    }));
}

#[derive(Default)]
struct HandlerRelease {
    released: AtomicBool,
    changed: Notify,
}

impl HandlerRelease {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

struct ReleaseHandlersOnDrop(Arc<HandlerRelease>);

impl Drop for ReleaseHandlersOnDrop {
    fn drop(&mut self) {
        // Keep a failed assertion from stranding deliberately held handlers,
        // including one that has signalled entry but has not parked yet.
        self.0.release();
    }
}

/// Hold real handler futures before sending excess requests. A refused stream
/// must never enter the handler, and HTTP/1.1 remains usable at the HTTP/2 cap.
#[test]
fn shared_port_http2_enforces_connection_and_global_request_limits() {
    let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(HandlerRelease::default());
        let _release_on_drop = ReleaseHandlersOnDrop(Arc::clone(&release));
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let calls = Arc::clone(&calls);
            move |request: Request| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                let calls = Arc::clone(&calls);
                async move {
                    if request.uri == "/hold" {
                        calls.fetch_add(1, Ordering::SeqCst);
                        entered.notify_one();
                        release.changed.wait_until(|| release.released.load(Ordering::Acquire)).await;
                    }
                    report(request).await
                }
            }
        };
        let listener = HttpAutoListener::bind("127.0.0.1:0", handler, config())
            .await
            .unwrap()
            .http2_max_in_flight_requests(NonZeroUsize::new(2).unwrap())
            .http2_max_connection_in_flight_requests(NonZeroUsize::new(1).unwrap());
        let addr = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle.spawn(async move { listener.run(&run_runtime).await });
        let mut first = H2Peer::connect(addr, Vec::new()).await;
        first.request(1, "/hold").await;
        bounded(entered.notified()).await;
        first.request(3, "/hold").await;
        assert!(matches!(first.next_for(3).await,
            Frame::RstStream(reset) if reset.error_code == ErrorCode::RefusedStream));

        let mut second = H2Peer::connect(addr, Vec::new()).await;
        second.request(1, "/hold").await;
        bounded(entered.notified()).await;
        let mut excess = H2Peer::connect(addr, Vec::new()).await;
        excess.request(1, "/hold").await;
        assert!(matches!(excess.next_for(1).await,
            Frame::RstStream(reset) if reset.error_code == ErrorCode::RefusedStream));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let mut http1 = TcpStream::connect(addr).await.unwrap();
        let response = bounded(http1_get(&mut http1, "/outside-h2-cap")).await;
        assert!(
            response.ends_with("Http11 /outside-h2-cap peer=true"),
            "{response}"
        );
        release.release();
        assert_eq!(first.response_body(1).await, b"Http2 /hold peer=true");
        assert_eq!(second.response_body(1).await, b"Http2 /hold peer=true");
        drop((first, second, excess));
        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let stats = bounded(run).await.unwrap();
        assert!(stats.http1.drain_report.unwrap().reached_quiescence);
        assert!(stats.http2.drain_report.unwrap().reached_quiescence);
    }));
}

#[test]
fn shared_port_http2_flow_control_timeout_resets_only_the_stalled_stream() {
    let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .unwrap()
            .http2_flow_control_progress_timeout(Duration::from_millis(200));
        let addr = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle.spawn(async move { listener.run(&run_runtime).await });
        let mut peer = H2Peer::connect(addr, vec![Setting::InitialWindowSize(0)]).await;
        peer.request(1, "/no-credit").await;
        // The response head witnesses dispatch and the DATA credit stall.
        assert!(matches!(peer.next_for(1).await, Frame::Headers(_)));
        assert!(matches!(peer.next_for(1).await,
            Frame::RstStream(reset) if reset.error_code == ErrorCode::Cancel));

        peer.send(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(65_535),
        ])))
        .await;
        peer.request(3, "/credit-restored").await;
        assert_eq!(peer.response_body(3).await, b"Http2 /credit-restored peer=true");
        let mut http1 = TcpStream::connect(addr).await.unwrap();
        let response = bounded(http1_get(&mut http1, "/after-flow-timeout")).await;
        assert!(
            response.ends_with("Http11 /after-flow-timeout peer=true"),
            "{response}"
        );
        drop(peer);
        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let stats = bounded(run).await.unwrap();
        assert!(stats.http2.drain_report.unwrap().reached_quiescence);
    }));
}

#[test]
fn cleartext_http1_and_http2_prior_knowledge_share_one_port() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        // HTTP/1.1, including a POST whose first byte matches the preface.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let response = http1_get(&mut stream, "/one").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("Http11 /one peer=true"), "{response}");
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(
            &mut stream,
            b"POST /posted HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        )
        .await
        .expect("write POST");
        let mut response = Vec::new();
        AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .expect("read POST response");
        let response = String::from_utf8(response).expect("UTF-8");
        assert!(response.ends_with("Http11 /posted peer=true"), "{response}");

        // HTTP/2 with prior knowledge on the same port.
        for target in ["/two", "/three"] {
            let stream = TcpStream::connect(addr).await.expect("connect");
            let response = Http2Client::new()
                .get(format!("http://localhost:{}{target}", addr.port()))
                .send_on(&cx, stream)
                .await
                .expect("HTTP/2 request");
            assert_eq!(response.status, 200);
            assert_eq!(
                response.text().expect("UTF-8"),
                format!("Http2 {target} peer=true")
            );
        }

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let stats = run.await.expect("auto listener run");
        assert!(
            stats
                .http1
                .drain_report
                .expect("HTTP/1.1 drain report")
                .reached_quiescence
        );
        assert!(
            stats
                .http2
                .drain_report
                .expect("HTTP/2 drain report")
                .reached_quiescence
        );
    }));
}

#[test]
fn a_connection_that_never_finishes_the_preface_is_dropped_at_the_detect_timeout() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let listener = HttpAutoListener::bind(
            "127.0.0.1:0",
            report,
            config().detect_timeout(Duration::from_millis(200)),
        )
        .await
        .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        // A preface prefix that never completes: neither protocol can be chosen.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(&mut stream, b"PRI * HTTP/2.0")
            .await
            .expect("write partial preface");
        let mut rest = Vec::new();
        let read = AsyncReadExt::read_to_end(&mut stream, &mut rest).await;
        assert!(
            read.is_err() || rest.is_empty(),
            "the stalled connection is closed without a response: {rest:?}"
        );

        // The port still serves both protocols afterwards.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let response = http1_get(&mut stream, "/after").await;
        assert!(response.ends_with("Http11 /after peer=true"), "{response}");

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("auto listener run");
    }));
}

#[cfg(feature = "tls")]
#[test]
fn tls_alpn_selects_http2_or_http1_on_one_port() {
    use asupersync::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };

    const SERVER_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
    const SERVER_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");

    let chain = CertificateChain::from_pem(SERVER_CERT_PEM).expect("chain");
    let key = PrivateKey::from_pem(SERVER_KEY_PEM).expect("key");
    let acceptor = TlsAcceptorBuilder::new(chain, key)
        .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .build()
        .expect("acceptor");
    let root = Certificate::from_pem(SERVER_CERT_PEM)
        .expect("root")
        .into_iter()
        .next()
        .expect("certificate");
    let connector = |alpn: &[u8]| {
        TlsConnectorBuilder::new()
            .add_root_certificate(&root)
            .alpn_protocols_required(vec![alpn.to_vec()])
            .build()
            .expect("connector")
    };
    let http1_connector = connector(b"http/1.1");
    let http2_connector = connector(b"h2");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .expect("bind")
            .with_tls(acceptor)
            .http2_preface_timeout(Duration::from_secs(1));
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        // ALPN selected HTTP/2 and the TLS handshake completed, but this
        // connection never sends an HTTP/2 preface. The H2 timeout starts
        // after detection hands over the established TLS stream.
        let tcp = TcpStream::connect(addr).await.expect("connect stalled TLS");
        let mut stalled = http2_connector
            .connect("localhost", tcp)
            .await
            .expect("negotiate h2 before stalling");
        assert_eq!(stalled.alpn_protocol(), Some(b"h2".as_slice()));
        let mut before_preface = Vec::new();
        let close = bounded(stalled.read_to_end(&mut before_preface)).await;
        assert!(
            close.is_ok()
                || close.as_ref().is_err_and(|error| matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                )),
            "stalled TLS connection must close: {close:?}"
        );
        assert!(before_preface.is_empty());
        drop(stalled);

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let mut tls = http1_connector
            .connect("localhost", tcp)
            .await
            .expect("TLS with http/1.1");
        let response = http1_get(&mut tls, "/tls-one").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.ends_with("Http11 /tls-one peer=true"),
            "{response}"
        );

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let tls = http2_connector
            .connect("localhost", tcp)
            .await
            .expect("TLS with h2");
        assert_eq!(tls.alpn_protocol(), Some(b"h2".as_slice()));
        let response = Http2Client::new()
            .get(format!("https://localhost:{}/tls-two", addr.port()))
            .send_on(&cx, tls)
            .await
            .expect("HTTP/2 over TLS");
        assert_eq!(response.status, 200);
        assert_eq!(response.text().expect("UTF-8"), "Http2 /tls-two peer=true");

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("auto listener run");
    }));
}
