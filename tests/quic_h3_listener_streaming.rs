//! Native Router HTTP/3 request streaming over authenticated loopback UDP.
//!
//! TLS identities are loaded from the existing shared ATP test fixture.

#![cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
#![allow(missing_docs)]

use std::future::Future;
use std::io::BufReader;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::http::h3_native::{H3PseudoHeaders, H3RequestHead, H3ResponseHead, H3Settings};
use asupersync::http::h3_quic::{NativeH3Event, NativeH3Session};
use asupersync::net::quic_core::{ConnectionId, TransportParameters};
use asupersync::net::quic_native::handshake_driver::{
    QuicHandshakeDriver, client_config, server_config,
};
use asupersync::net::quic_native::{
    NativeQuicConnectionConfig, NativeQuicUdpConnection, QuicConnection, QuicUdpEndpoint,
    QuicUdpEndpointConfig,
};
use asupersync::web::{
    AsyncCxFnHandler1, FnHandler, NativeH3Listener, NativeH3ListenerConfig, Response, Router,
    StatusCode, post,
};
use futures_lite::future::zip;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};

const H3_ALPN: &[u8] = b"h3";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}

fn certificate(name: &str) -> CertificateDer<'static> {
    let fixtures = fixtures();
    let pem = if name == "ca" {
        fixtures["ca"].as_str().unwrap()
    } else {
        fixtures["identities"][name]["certificate"].as_str().unwrap()
    };
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes()))
        .next()
        .expect("shared test certificate")
        .expect("valid shared certificate PEM")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    let fixtures = fixtures();
    let pem = fixtures["identities"]["server"]["key"].as_str().unwrap();
    PrivateKeyDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes()))
        .next()
        .expect("shared server key")
        .expect("valid shared server key PEM")
}

fn connection_config() -> NativeQuicConnectionConfig {
    NativeQuicConnectionConfig {
        max_local_bidi: 16,
        max_local_uni: 8,
        send_window: 1 << 18,
        recv_window: 1 << 18,
        connection_send_limit: 4 << 20,
        connection_recv_limit: 4 << 20,
        ..NativeQuicConnectionConfig::default()
    }
}

fn transport_parameters(config: NativeQuicConnectionConfig) -> Vec<u8> {
    let parameters = TransportParameters {
        max_udp_payload_size: Some(1_200),
        initial_max_data: Some(config.connection_recv_limit),
        initial_max_stream_data_bidi_local: Some(config.recv_window),
        initial_max_stream_data_bidi_remote: Some(config.recv_window),
        initial_max_stream_data_uni: Some(config.recv_window),
        initial_max_streams_bidi: Some(config.max_local_bidi),
        initial_max_streams_uni: Some(config.max_local_uni),
        disable_active_migration: true,
        max_datagram_frame_size: Some(config.max_datagram_frame_size as u64),
        ..TransportParameters::default()
    };
    let mut encoded = Vec::new();
    parameters
        .encode(&mut encoded)
        .expect("encode RFC 9000 transport parameters");
    encoded
}

fn drain_h3_events(
    cx: &Cx,
    session: &mut NativeH3Session,
    connection: &mut QuicConnection,
) -> Vec<NativeH3Event> {
    let mut events = Vec::new();
    while let Some(event) = session
        .next_event(cx, connection)
        .expect("decode live HTTP/3 event")
    {
        events.push(event);
    }
    events
}

fn managed_assert_runtime_cleanup(runtime: &asupersync::runtime::Runtime) {
    // GH#58: this wait used to run inside `block_on` with `yield_now`. On a
    // current-thread runtime the root of `block_on` is now itself a live
    // task, so `is_quiescent()` is false by design for as long as the root
    // runs and the wait can never succeed from inside it. It therefore runs
    // on this thread, outside any root. That is sufficient because
    // `block_on` drains runnable work before it returns, and the runtime's
    // background worker thread resumes the worker afterwards, so the managed
    // cleanup keeps progressing while this thread sleeps. Same oracle, same
    // 5 s bound, same diagnostics.
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "managed native task and obligation cleanup must drain: {:?}",
            runtime
                .task_inspector(Default::default())
                .list_active_tasks(),
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(runtime.is_quiescent());
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
}

mod native_h3_listener_live {
    use super::*;

    async fn connect(
        cx: &Cx,
        server_addr: std::net::SocketAddr,
        peer: u8,
    ) -> (NativeQuicUdpConnection, NativeH3Session) {
        connect_with_config(cx, server_addr, peer, connection_config()).await
    }

    async fn connect_with_config(
        cx: &Cx,
        server_addr: std::net::SocketAddr,
        peer: u8,
        config: NativeQuicConnectionConfig,
    ) -> (NativeQuicUdpConnection, NativeH3Session) {
        let socket = QuicUdpEndpoint::bind(
            cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let mut owner = NativeQuicUdpConnection::connect(
            cx,
            socket,
            server_addr,
            QuicHandshakeDriver::client(
                client_config(vec![certificate("ca")], vec![H3_ALPN.to_vec()]).unwrap(),
                ServerName::try_from("localhost").unwrap(),
                transport_parameters(config),
            )
            .unwrap(),
            ConnectionId::new(format!("listener-init-{peer}").as_bytes()).unwrap(),
            ConnectionId::new(format!("listener-client-{peer}").as_bytes()).unwrap(),
            config,
            H3_ALPN,
        )
        .await
        .expect("public listener authenticates an unknown real UDP peer");
        assert_eq!(owner.negotiated_alpn(), H3_ALPN);
        assert_eq!(owner.peer_addr(), server_addr);
        let mut session = NativeH3Session::client();
        session
            .initialize(cx, owner.connection_mut(), H3Settings::default())
            .unwrap();
        owner.flush(cx).await.unwrap();
        loop {
            owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
            let events = drain_h3_events(cx, &mut session, owner.connection_mut());
            if !events.is_empty() {
                assert_eq!(events, vec![NativeH3Event::Settings(H3Settings::default())]);
                break;
            }
        }
        (owner, session)
    }

    async fn receive_response(
        cx: &Cx,
        owner: &mut NativeQuicUdpConnection,
        session: &mut NativeH3Session,
        stream: asupersync::net::quic_native::StreamId,
        expected_head: &H3ResponseHead,
        expected_body: &[u8],
    ) {
        let mut received_head = None;
        let mut received_body = Vec::new();
        loop {
            owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
            for event in drain_h3_events(cx, session, owner.connection_mut()) {
                match event {
                    NativeH3Event::ResponseHeaders { stream_id, head } => {
                        assert_eq!(stream_id, stream);
                        assert!(received_head.replace(head).is_none());
                    }
                    NativeH3Event::Data { stream_id, bytes } => {
                        assert_eq!(stream_id, stream);
                        received_body.extend_from_slice(&bytes);
                        assert!(received_body.len() <= expected_body.len());
                    }
                    NativeH3Event::Finished { stream_id } => {
                        assert_eq!(stream_id, stream);
                        assert_eq!(received_head.as_ref(), Some(expected_head));
                        assert_eq!(received_body, expected_body);
                        return;
                    }
                    other => panic!("unexpected listener response event: {other:?}"),
                }
            }
        }
    }

    async fn acknowledge_shutdown_goaway(
        cx: &Cx,
        owner: &mut NativeQuicUdpConnection,
        session: &mut NativeH3Session,
        expected_goaway: u64,
        cancelled_stream: Option<asupersync::net::quic_native::StreamId>,
    ) {
        let mut goaway_seen = false;
        loop {
            // GOAWAY closes admission, not the transport. A late answer to
            // STOP_SENDING can still elicit ACK/credit traffic after GOAWAY.
            // Keep driving this authenticated peer until the listener's final
            // CONNECTION_CLOSE proves its normal acknowledgement drain ended.
            owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
            if owner.connection().close_was_peer_initiated() {
                assert!(goaway_seen, "authenticated close must follow GOAWAY");
                assert_eq!(owner.connection().inner().transport().close_code(), Some(0));
                return;
            }
            for event in drain_h3_events(cx, session, owner.connection_mut()) {
                match event {
                    NativeH3Event::Goaway(id) => {
                        assert_eq!(id, expected_goaway);
                        assert!(!goaway_seen);
                        goaway_seen = true;
                    }
                    NativeH3Event::StreamReset {
                        stream_id,
                        error_code,
                        ..
                    } => {
                        assert_eq!(Some(stream_id), cancelled_stream);
                        assert_eq!(error_code, asupersync::http::h3_quic::H3_REQUEST_CANCELLED);
                    }
                    other => panic!("unexpected listener shutdown event: {other:?}"),
                }
            }
            owner.flush(cx).await.unwrap();
        }
    }

    struct ProducerRetired(Arc<AtomicUsize>);

    impl Drop for ProducerRetired {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }


    mod streaming_request {
        use super::*;
        use std::pin::Pin;
        use std::sync::Mutex;

        use asupersync::bytes::Buf;
        use asupersync::http::body::{Body, Frame};
        use asupersync::http::h1::stream::IncomingBodyError;
        use asupersync::http::h3_native::{H3Frame, qpack_encode_request_field_section};
        use asupersync::net::quic_native::StreamId;
        use asupersync::web::{RequestBodyPolicy, StreamingRawBody};

        fn run(workers: usize, future: impl Future<Output = ()> + Send + 'static) {
            let builder = if workers == 1 {
                asupersync::runtime::RuntimeBuilder::current_thread()
            } else {
                asupersync::runtime::RuntimeBuilder::multi_thread()
                    .worker_threads(workers)
                    .with_sharded_state(true)
            };
            let runtime = builder
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .build()
                .unwrap();
            let parent: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(30), future)
                    .await
                    .expect("native streaming listener workflow watchdog");
                assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
            });
            runtime.block_on(runtime.handle().spawn(parent));
            managed_assert_runtime_cleanup(&runtime);
            assert_eq!(runtime.draining_region_count(), 0);
        }

        fn config(queue_bytes: usize) -> NativeH3ListenerConfig {
            let mut config = NativeH3ListenerConfig::default();
            config.endpoint.max_connections = 1;
            config.endpoint.packet_batch_size = 1;
            config.endpoint.connection_config = connection_config();
            config.streaming_request_body_buffer_bytes = NonZeroUsize::new(queue_bytes);
            assert!(config.streaming_request_body_buffer_bytes.is_some());
            config
        }

        async fn bind(cx: &Cx, router: Router, config: NativeH3ListenerConfig) -> NativeH3Listener {
            let transport = config.endpoint.connection_config;
            NativeH3Listener::bind(
                cx,
                "127.0.0.1:0".parse().unwrap(),
                router.without_default_trace(),
                server_config(
                    vec![certificate("server")],
                    leaf_key(),
                    vec![H3_ALPN.to_vec()],
                )
                .unwrap(),
                transport_parameters(transport),
                config,
            )
            .await
            .unwrap()
        }

        async fn open_upload(
            cx: &Cx,
            owner: &mut NativeQuicUdpConnection,
            path: &str,
            content_length: Option<usize>,
        ) -> StreamId {
            let head = H3RequestHead::new(
                H3PseudoHeaders {
                    method: Some("POST".to_owned()),
                    scheme: Some("https".to_owned()),
                    authority: Some("localhost".to_owned()),
                    path: Some(path.to_owned()),
                    ..H3PseudoHeaders::default()
                },
                content_length
                    .map(|bytes| vec![("content-length".to_owned(), bytes.to_string())])
                    .unwrap_or_default(),
            )
            .unwrap();
            let stream = owner.connection_mut().open_bidi_stream(cx).unwrap();
            let mut wire = Vec::new();
            H3Frame::Headers(qpack_encode_request_field_section(&head).unwrap())
                .encode(&mut wire)
                .unwrap();
            owner
                .connection_mut()
                .write_stream(cx, stream, Bytes::from(wire), false)
                .unwrap();
            owner.flush(cx).await.unwrap();
            stream
        }

        fn data_wire(bytes: &[u8]) -> Vec<u8> {
            let mut wire = Vec::new();
            H3Frame::Data(bytes.to_vec()).encode(&mut wire).unwrap();
            wire
        }

        async fn write_data(
            cx: &Cx,
            owner: &mut NativeQuicUdpConnection,
            stream: StreamId,
            bytes: &[u8],
            fin: bool,
        ) {
            owner
                .connection_mut()
                .write_stream(cx, stream, Bytes::from(data_wire(bytes)), fin)
                .unwrap();
            owner.flush(cx).await.unwrap();
        }

        async fn response(
            cx: &Cx,
            owner: &mut NativeQuicUdpConnection,
            session: &mut NativeH3Session,
            path: &str,
            expected_head: &H3ResponseHead,
            expected_body: &[u8],
        ) {
            // These tests own the request wire so they can leave uploads open.
            // Keep subsequent stream allocation on that same public QUIC path;
            // NativeH3Session::send_request owns a separate sequential allocator.
            let stream = open_upload(cx, owner, path, None).await;
            owner
                .connection_mut()
                .write_stream(cx, stream, Bytes::new(), true)
                .unwrap();
            owner.flush(cx).await.unwrap();
            receive_response(cx, owner, session, stream, expected_head, expected_body).await;
        }

        fn write_capacity(cx: &Cx, owner: &mut NativeQuicUdpConnection, stream: StreamId) -> usize {
            let mut task_cx = Context::from_waker(Waker::noop());
            match owner
                .connection_mut()
                .poll_stream_write_ready(cx, stream, 1, &mut task_cx)
            {
                Poll::Ready(Ok(capacity)) => usize::try_from(capacity).unwrap(),
                Poll::Ready(Err(error)) => panic!("live upload write credit: {error}"),
                Poll::Pending => 0,
            }
        }

        async fn receive_cancelled(
            cx: &Cx,
            owner: &mut NativeQuicUdpConnection,
            session: &mut NativeH3Session,
            expected_stream: StreamId,
            expected_error_code: u64,
        ) {
            loop {
                owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
                let mut reset_seen = false;
                for event in drain_h3_events(cx, session, owner.connection_mut()) {
                    match event {
                        NativeH3Event::StreamReset {
                            stream_id,
                            error_code,
                            ..
                        } => {
                            assert_eq!(stream_id, expected_stream);
                            assert_eq!(error_code, expected_error_code);
                            assert!(!reset_seen);
                            reset_seen = true;
                        }
                        other => panic!("malformed upload must reset only its stream: {other:?}"),
                    }
                }
                if reset_seen {
                    return;
                }
            }
        }

        async fn wait_region_closed(cx: &Cx) {
            let region = cx.region_id();
            std::future::poll_fn(|task_cx| {
                let closed = asupersync::runtime::Runtime::current_handle()
                    .unwrap()
                    .diagnostics()
                    .unwrap()
                    .explain_region_open(region)
                    .region_state
                    .is_none();
                if closed {
                    Poll::Ready(())
                } else {
                    task_cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }

        #[test]
        fn authenticated_listener_streams_prefix_before_fin_current_thread() {
            prefix_before_fin(1);
        }

        #[test]
        fn authenticated_listener_streams_prefix_before_fin_multi_worker() {
            prefix_before_fin(2);
        }

        fn prefix_before_fin(workers: usize) {
            // Both declared and unknown lengths must expose the same live
            // frames. Payload resembling HTTP/1 chunk syntax remains payload.
            for declared in [false, true] {
                run(workers, async move {
                    const PREFIX: &[u8] = b"3\r\nabc\r\n0\r\n\r\n";
                    const TAIL: &[u8] = b"\0tail after the parked read\xff";
                    const QUEUE_BYTES: usize = 8;
                    let cx = Cx::current().unwrap();
                    let expected: Vec<u8> = PREFIX.iter().chain(TAIL).copied().collect();
                    let expected_handler = expected.clone();
                    let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                    let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                    let router = Router::new().route(
                        "/live",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |request_cx: Cx, mut body: StreamingRawBody| {
                                let mut parked = parked_slot.lock().unwrap().take();
                                let expected = expected_handler.clone();
                                async move {
                                    let mut received = Vec::new();
                                    loop {
                                        let frame = std::future::poll_fn(|task_cx| {
                                            let poll = Pin::new(&mut body).poll_frame(task_cx);
                                            if poll.is_pending() && received.len() == PREFIX.len() {
                                                assert_eq!(received, PREFIX);
                                                assert!(!body.is_end_stream());
                                                if let Some(signal) = parked.take() {
                                                    signal
                                                        .send(&request_cx, request_cx.clone())
                                                        .unwrap();
                                                }
                                            }
                                            poll
                                        })
                                        .await;
                                        let Some(frame) = frame else { break };
                                        let Frame::Data(bytes) = frame.unwrap() else {
                                            panic!("upload has no trailers");
                                        };
                                        received.extend_from_slice(bytes.chunk());
                                    }
                                    assert_eq!(received, expected);
                                    assert!(body.queued_bytes_peak() <= QUEUE_BYTES);
                                    assert!(
                                        parked.is_none(),
                                        "prefix was consumed before client FIN"
                                    );
                                    Response::new(StatusCode::OK, received)
                                }
                            },
                        )),
                    );
                    let listener = bind(&cx, router, config(QUEUE_BYTES)).await;
                    let address = listener.local_addr();
                    let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                    let serving = listener.serve_with_shutdown(&cx, async {
                        shutdown_rx.recv(&cx).await.unwrap();
                    });
                    let client = async {
                        let (mut owner, mut session) = connect(&cx, address, 61).await;
                        let stream = open_upload(
                            &cx,
                            &mut owner,
                            "/live",
                            declared.then_some(expected.len()),
                        )
                        .await;
                        write_data(&cx, &mut owner, stream, PREFIX, false).await;
                        let request_cx: Cx = parked_rx.recv(&cx).await.unwrap();
                        assert_ne!(request_cx.task_id(), cx.task_id());
                        assert_ne!(request_cx.region_id(), cx.region_id());
                        assert!(!request_cx.is_cancel_requested());
                        write_data(&cx, &mut owner, stream, TAIL, true).await;
                        receive_response(
                            &cx,
                            &mut owner,
                            &mut session,
                            stream,
                            &H3ResponseHead::new(200, Vec::new()).unwrap(),
                            &expected,
                        )
                        .await;
                        shutdown_tx.send(&cx, ()).unwrap();
                        acknowledge_shutdown_goaway(
                            &cx,
                            &mut owner,
                            &mut session,
                            stream.0 + 4,
                            None,
                        )
                        .await;
                    };
                    let (report, ()) = zip(serving, client).await;
                    let report = report.unwrap();
                    assert_eq!(report.accepted_connections, 1);
                    assert_eq!(report.completed_requests, 1);
                    assert_eq!(report.cancelled_requests, 0);
                    assert_eq!(report.refused_requests, 0);
                    assert_eq!(report.failed_connections, 0);
                    assert!(!report.drain_timed_out);
                });
            }
        }

        #[test]
        fn authenticated_listener_zero_content_length_waits_for_explicit_fin() {
            run(1, async {
                let cx = Cx::current().unwrap();
                let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                let router = Router::new().route(
                    "/empty",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, mut body: StreamingRawBody| {
                            let mut parked = parked_slot.lock().unwrap().take();
                            async move {
                                let terminal = std::future::poll_fn(|task_cx| {
                                    let poll = Pin::new(&mut body).poll_frame(task_cx);
                                    if poll.is_pending() {
                                        assert!(!body.is_end_stream());
                                        if let Some(signal) = parked.take() {
                                            signal.send(&request_cx, ()).unwrap();
                                        }
                                    }
                                    poll
                                })
                                .await;
                                assert!(terminal.is_none());
                                assert!(parked.is_none(), "zero length must not synthesize FIN");
                                Response::new(StatusCode::OK, "explicit FIN")
                            }
                        },
                    )),
                );
                let listener = bind(&cx, router, config(8)).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 62).await;
                    let stream = open_upload(&cx, &mut owner, "/empty", Some(0)).await;
                    parked_rx.recv(&cx).await.unwrap();
                    owner
                        .connection_mut()
                        .write_stream(&cx, stream, Bytes::new(), true)
                        .unwrap();
                    owner.flush(&cx).await.unwrap();
                    receive_response(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"explicit FIN",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 4, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 0);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_streaming_backpressure_preserves_sibling_and_buffered_resume() {
            run(2, async {
                const QUEUE_BYTES: usize = 8;
                const WINDOW: u64 = 128;
                const BODY_BYTES: usize = 4096;
                let cx = Cx::current().unwrap();
                let expected: Vec<u8> = (0..BODY_BYTES)
                    .map(|index| u8::try_from(index % 251).unwrap())
                    .collect();
                let expected_handler = expected.clone();
                let (admitted_tx, mut admitted_rx) = asupersync::channel::oneshot::channel();
                let admitted_slot = Arc::new(Mutex::new(Some(admitted_tx)));
                let (resume_tx, resume_rx) = asupersync::channel::oneshot::channel();
                let resume_slot = Arc::new(Mutex::new(Some(resume_rx)));
                let (drained_tx, mut drained_rx) = asupersync::channel::oneshot::channel();
                let drained_slot = Arc::new(Mutex::new(Some(drained_tx)));
                let sibling_calls = Arc::new(AtomicUsize::new(0));
                let sibling_handler = Arc::clone(&sibling_calls);
                let router = Router::new()
                    .route(
                        "/blocked",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |request_cx: Cx, mut body: StreamingRawBody| {
                                let admitted = admitted_slot.lock().unwrap().take().unwrap();
                                let mut resume = resume_slot.lock().unwrap().take().unwrap();
                                let mut drained = drained_slot.lock().unwrap().take();
                                let expected = expected_handler.clone();
                                async move {
                                    admitted.send(&request_cx, ()).unwrap();
                                    // The client fills the queue and proves its stream
                                    // has no credit while this consumer remains gated.
                                    let buffered_payload_bytes: usize =
                                        resume.recv(&request_cx).await.unwrap();
                                    let queued = body.queued_bytes();
                                    assert!(queued > 0 && queued <= QUEUE_BYTES);
                                    let mut received = Vec::new();
                                    while let Some(frame) = std::future::poll_fn(|task_cx| {
                                        Pin::new(&mut body).poll_frame(task_cx)
                                    })
                                    .await
                                    {
                                        let Frame::Data(bytes) = frame.unwrap() else {
                                            panic!("upload has no trailers");
                                        };
                                        received.extend_from_slice(bytes.chunk());
                                        if received.len() == buffered_payload_bytes {
                                            if let Some(signal) = drained.take() {
                                                signal.send(&request_cx, ()).unwrap();
                                            }
                                        }
                                    }
                                    assert!(drained.is_none());
                                    assert_eq!(received, expected);
                                    assert!(body.queued_bytes_peak() <= QUEUE_BYTES);
                                    Response::new(StatusCode::OK, received)
                                }
                            },
                        )),
                    )
                    .route(
                        "/sibling",
                        post(FnHandler::new(move || {
                            sibling_handler.fetch_add(1, Ordering::SeqCst);
                            Response::new(StatusCode::OK, "sibling progressed")
                        })),
                    );
                let mut listener_config = config(QUEUE_BYTES);
                listener_config.endpoint.connection_config.recv_window = WINDOW;
                listener_config.receive_window_bytes = WINDOW;
                let listener = bind(&cx, router, listener_config).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 63).await;
                    let stream = open_upload(&cx, &mut owner, "/blocked", None).await;
                    admitted_rx.recv(&cx).await.unwrap();
                    let wire = data_wire(&expected);
                    let framing_bytes = wire.len() - expected.len();
                    let mut offset = 0;
                    let mut probes = 0_u64;
                    let last_stream = loop {
                        let capacity = write_capacity(&cx, &mut owner, stream);
                        if capacity > 0 {
                            let end = (offset + capacity).min(wire.len());
                            owner
                                .connection_mut()
                                .write_stream(
                                    &cx,
                                    stream,
                                    Bytes::copy_from_slice(&wire[offset..end]),
                                    false,
                                )
                                .unwrap();
                            offset = end;
                            owner.flush(&cx).await.unwrap();
                        }
                        assert!(
                            offset < wire.len(),
                            "gated consumer must bound transport read-ahead"
                        );
                        assert_eq!(write_capacity(&cx, &mut owner, stream), 0);
                        let sibling_stream = open_upload(&cx, &mut owner, "/sibling", None).await;
                        owner
                            .connection_mut()
                            .write_stream(&cx, sibling_stream, Bytes::new(), true)
                            .unwrap();
                        owner.flush(&cx).await.unwrap();
                        receive_response(
                            &cx,
                            &mut owner,
                            &mut session,
                            sibling_stream,
                            &H3ResponseHead::new(200, Vec::new()).unwrap(),
                            b"sibling progressed",
                        )
                        .await;
                        probes += 1;
                        assert_eq!(sibling_calls.load(Ordering::SeqCst), probes as usize);
                        assert!(
                            probes <= 8,
                            "blocked queue must reach a stable finite credit ceiling"
                        );
                        if write_capacity(&cx, &mut owner, stream) == 0 {
                            break sibling_stream;
                        }
                    };
                    assert!(offset > framing_bytes + QUEUE_BYTES);
                    assert!(offset <= WINDOW as usize * 2 + QUEUE_BYTES * 2);
                    let existing_payload_bytes = offset - framing_bytes;
                    resume_tx.send(&cx, existing_payload_bytes).unwrap();
                    // No client flush, receive, or new packet occurs while
                    // awaiting this signal. Queue credit alone must wake the
                    // server and release DATA already in its native receive buffer.
                    drained_rx.recv(&cx).await.unwrap();
                    while offset < wire.len() {
                        let capacity = write_capacity(&cx, &mut owner, stream);
                        if capacity == 0 {
                            owner.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                            continue;
                        }
                        let end = (offset + capacity).min(wire.len());
                        owner
                            .connection_mut()
                            .write_stream(
                                &cx,
                                stream,
                                Bytes::copy_from_slice(&wire[offset..end]),
                                end == wire.len(),
                            )
                            .unwrap();
                        offset = end;
                        owner.flush(&cx).await.unwrap();
                    }
                    receive_response(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        &expected,
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(
                        &cx,
                        &mut owner,
                        &mut session,
                        last_stream.0 + 4,
                        None,
                    )
                    .await;
                    probes
                };
                let (report, probes) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.accepted_connections, 1);
                assert_eq!(report.completed_requests, probes + 1);
                assert_eq!(report.cancelled_requests, 0);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_streaming_bad_lengths_fail_only_the_upload() {
            for workers in [1, 2] {
                for (declared, bytes, fin) in [
                    (Some(4), b"abc".as_slice(), true),
                    (Some(2), b"abc".as_slice(), false),
                    (Some(0), b"x".as_slice(), false),
                ] {
                    failed_upload(
                        workers,
                        declared,
                        bytes,
                        fin,
                        None,
                        IncomingBodyError::BadContentLength,
                    );
                }
            }
        }

        #[test]
        fn authenticated_listener_streaming_route_limit_fails_live_unknown_length() {
            failed_upload(
                2,
                None,
                b"abcde",
                false,
                Some(4),
                IncomingBodyError::BodyTooLarge {
                    actual: Some(5),
                    limit: 4,
                },
            );
        }

        fn failed_upload(
            workers: usize,
            declared: Option<usize>,
            bytes: &'static [u8],
            fin: bool,
            route_limit: Option<usize>,
            expected_error: IncomingBodyError,
        ) {
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let terminal = Arc::new(Mutex::new(None));
                let handler_terminal = Arc::clone(&terminal);
                let retired = Arc::new(AtomicUsize::new(0));
                let handler_retired = Arc::clone(&retired);
                let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                let mut route = post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, mut body: StreamingRawBody| {
                        let mut parked = parked_slot.lock().unwrap().take();
                        let terminal = Arc::clone(&handler_terminal);
                        let retired = Arc::clone(&handler_retired);
                        async move {
                            let _retired = ProducerRetired(retired);
                            loop {
                                let frame = std::future::poll_fn(|task_cx| {
                                    let poll = Pin::new(&mut body).poll_frame(task_cx);
                                    if poll.is_pending() {
                                        if let Some(signal) = parked.take() {
                                            signal.send(&request_cx, request_cx.clone()).unwrap();
                                        }
                                    }
                                    poll
                                })
                                .await;
                                match frame {
                                    Some(Ok(Frame::Data(_))) => {}
                                    Some(Ok(Frame::Trailers(_))) => {
                                        panic!("unexpected upload trailers")
                                    }
                                    Some(Err(error)) => {
                                        // Record the exact domain result independently of the
                                        // now-cancelled request's effect capabilities.
                                        *terminal.lock().unwrap() = Some(error);
                                        break;
                                    }
                                    None => {
                                        panic!("malformed upload must never publish successful EOF")
                                    }
                                }
                            }
                            // Catching a body failure cannot make the listener publish success.
                            Response::new(StatusCode::OK, "must not be emitted")
                        }
                    },
                ));
                if let Some(limit) = route_limit {
                    route =
                        route.with_body_policy(RequestBodyPolicy::new().max_total_body_size(limit));
                }
                let router = Router::new().route("/invalid", route).route(
                    "/survivor",
                    post(FnHandler::new(|| Response::new(StatusCode::OK, "survived"))),
                );
                let mut listener_config = config(8);
                listener_config.max_concurrent_requests = 1;
                let listener = bind(&cx, router, listener_config).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 64).await;
                    let stream = open_upload(&cx, &mut owner, "/invalid", declared).await;
                    let request_cx: Cx = parked_rx.recv(&cx).await.unwrap();
                    assert!(!request_cx.is_cancel_requested());
                    write_data(&cx, &mut owner, stream, bytes, fin).await;
                    let reset_code = if expected_error == IncomingBodyError::BadContentLength {
                        0x10e // RFC 9114 H3_MESSAGE_ERROR for a valid frame with a bad length.
                    } else {
                        asupersync::http::h3_quic::H3_REQUEST_CANCELLED
                    };
                    receive_cancelled(&cx, &mut owner, &mut session, stream, reset_code).await;
                    wait_region_closed(&request_cx).await;
                    assert_eq!(*terminal.lock().unwrap(), Some(expected_error));
                    assert_eq!(retired.load(Ordering::SeqCst), 1);
                    assert!(request_cx.is_cancel_requested());
                    response(
                        &cx,
                        &mut owner,
                        &mut session,
                        "/survivor",
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"survived",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 8, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.accepted_connections, 1);
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 1);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_streaming_declared_route_limit_refuses_before_handler() {
            run(1, async {
                let cx = Cx::current().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let handler_calls = Arc::clone(&calls);
                let router = Router::new()
                    .route(
                        "/limited",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |_request_cx: Cx, _body: StreamingRawBody| {
                                handler_calls.fetch_add(1, Ordering::SeqCst);
                                async { Response::new(StatusCode::OK, "must not be admitted") }
                            },
                        ))
                        .with_body_policy(RequestBodyPolicy::new().max_total_body_size(4)),
                    )
                    .route(
                        "/survivor",
                        post(FnHandler::new(|| Response::new(StatusCode::OK, "survived"))),
                    );
                let listener = bind(&cx, router, config(8)).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 65).await;
                    let stream = open_upload(&cx, &mut owner, "/limited", Some(5)).await;
                    receive_cancelled(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        asupersync::http::h3_quic::H3_REQUEST_CANCELLED,
                    )
                    .await;
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    response(
                        &cx,
                        &mut owner,
                        &mut session,
                        "/survivor",
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"survived",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 8, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 0);
                assert_eq!(report.refused_requests, 1);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_streaming_reset_wakes_parked_body_and_reclaims_owner() {
            for workers in [1, 2] {
                run(workers, async {
                    let cx = Cx::current().unwrap();
                    let terminal = Arc::new(Mutex::new(None));
                    let handler_terminal = Arc::clone(&terminal);
                    let retired = Arc::new(AtomicUsize::new(0));
                    let handler_retired = Arc::clone(&retired);
                    let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                    let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                    let router = Router::new()
                        .route(
                            "/reset",
                            post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                                move |request_cx: Cx, mut body: StreamingRawBody| {
                                    let mut parked = parked_slot.lock().unwrap().take();
                                    let terminal = Arc::clone(&handler_terminal);
                                    let retired = Arc::clone(&handler_retired);
                                    async move {
                                        let _retired = ProducerRetired(retired);
                                        let frame = std::future::poll_fn(|task_cx| {
                                            let poll = Pin::new(&mut body).poll_frame(task_cx);
                                            if poll.is_pending() {
                                                if let Some(signal) = parked.take() {
                                                    signal.send(&request_cx, request_cx.clone()).unwrap();
                                                }
                                            }
                                            poll
                                        })
                                        .await;
                                        match frame {
                                            Some(Err(error)) => *terminal.lock().unwrap() = Some(error),
                                            other => panic!("peer reset must terminate the parked read: {other:?}"),
                                        }
                                        Response::new(StatusCode::OK, "must not be emitted")
                                    }
                                },
                            )),
                        )
                        .route(
                            "/survivor",
                            post(FnHandler::new(|| Response::new(StatusCode::OK, "owner reclaimed"))),
                        );
                    let mut listener_config = config(8);
                    listener_config.max_concurrent_requests = 1;
                    // One live request reserves its eight-byte body queue and
                    // one eight-byte pending frame. A successful sibling after
                    // reset therefore proves both ownership and byte credit
                    // were released, not only that a wire reset was emitted.
                    listener_config.router = listener_config
                        .router
                        .max_in_flight_dispatches(1)
                        .max_total_buffered_body_bytes(16);
                    let listener = bind(&cx, router, listener_config).await;
                    let address = listener.local_addr();
                    let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                    let serving = listener.serve_with_shutdown(&cx, async {
                        shutdown_rx.recv(&cx).await.unwrap();
                    });
                    let client = async {
                        let (mut owner, mut session) = connect(&cx, address, 66).await;
                        let stream = open_upload(&cx, &mut owner, "/reset", None).await;
                        let request_cx: Cx = parked_rx.recv(&cx).await.unwrap();
                        assert!(!request_cx.is_cancel_requested());
                        owner
                            .connection_mut()
                            .reset_stream(
                                &cx,
                                stream,
                                asupersync::http::h3_quic::H3_REQUEST_CANCELLED,
                            )
                            .unwrap();
                        owner.flush(&cx).await.unwrap();
                        asupersync::time::timeout(
                            cx.now(),
                            Duration::from_secs(2),
                            wait_region_closed(&request_cx),
                        )
                        .await
                        .expect("peer reset must retire the parked body without another packet");
                        assert_eq!(
                            *terminal.lock().unwrap(),
                            Some(IncomingBodyError::ClientAborted)
                        );
                        assert_eq!(retired.load(Ordering::SeqCst), 1);
                        asupersync::time::timeout(
                            cx.now(),
                            Duration::from_secs(2),
                            receive_cancelled(
                                &cx,
                                &mut owner,
                                &mut session,
                                stream,
                                asupersync::http::h3_quic::H3_REQUEST_CANCELLED,
                            ),
                        )
                        .await
                        .expect("peer reset must also terminate the independent response half");
                        response(
                            &cx,
                            &mut owner,
                            &mut session,
                            "/survivor",
                            &H3ResponseHead::new(200, Vec::new()).unwrap(),
                            b"owner reclaimed",
                        )
                        .await;
                        shutdown_tx.send(&cx, ()).unwrap();
                        acknowledge_shutdown_goaway(
                            &cx,
                            &mut owner,
                            &mut session,
                            stream.0 + 8,
                            None,
                        )
                        .await;
                    };
                    let (report, ()) = zip(serving, client).await;
                    let report = report.unwrap();
                    assert_eq!(report.completed_requests, 1);
                    assert_eq!(report.cancelled_requests, 1);
                    assert_eq!(report.refused_requests, 0);
                    assert_eq!(report.failed_connections, 0);
                    assert!(!report.drain_timed_out);
                });
            }
        }

        #[test]
        fn authenticated_listener_streaming_early_drop_preserves_response_without_fin() {
            run(2, async {
                let cx = Cx::current().unwrap();
                let (dropped_tx, mut dropped_rx) = asupersync::channel::oneshot::channel();
                let dropped_slot = Arc::new(Mutex::new(Some(dropped_tx)));
                let (release_tx, release_rx) = asupersync::channel::oneshot::channel();
                let release_slot = Arc::new(Mutex::new(Some(release_rx)));
                let router = Router::new()
                    .route(
                        "/early",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |request_cx: Cx, body: StreamingRawBody| {
                                let dropped = dropped_slot.lock().unwrap().take().unwrap();
                                let mut release = release_slot.lock().unwrap().take().unwrap();
                                async move {
                                    assert!(!body.is_end_stream());
                                    drop(body);
                                    dropped.send(&request_cx, request_cx.clone()).unwrap();
                                    // A completed response must not conceal a false
                                    // cancellation when the peer acknowledges input stop.
                                    release.recv(&request_cx).await.unwrap();
                                    Response::new(StatusCode::OK, "early response retained")
                                }
                            },
                        )),
                    )
                    .route(
                        "/survivor",
                        post(FnHandler::new(|| Response::new(StatusCode::OK, "survived"))),
                    );
                let listener = bind(&cx, router, config(8)).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 67).await;
                    // No DATA or FIN is sent. The application abandons input
                    // before it is permitted to produce the response.
                    let stream = open_upload(&cx, &mut owner, "/early", None).await;
                    let request_cx: Cx = dropped_rx.recv(&cx).await.unwrap();
                    loop {
                        let stopped = owner
                            .connection()
                            .inner()
                            .streams()
                            .stream(stream)
                            .unwrap()
                            .stop_sending_error_code;
                        if let Some(error_code) = stopped {
                            assert_eq!(
                                error_code, 0x100,
                                "early response stops input with H3_NO_ERROR"
                            );
                            break;
                        }
                        owner.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                        assert!(
                            drain_h3_events(&cx, &mut session, owner.connection_mut()).is_empty()
                        );
                    }
                    let state = owner
                        .connection()
                        .inner()
                        .streams()
                        .stream(stream)
                        .unwrap();
                    assert_eq!(state.send_reset, Some((0x100, state.send_offset)));
                    assert!(
                        owner.connection().path_stats().bytes_in_flight > 0,
                        "the native client automatically sent RESET_STREAM after STOP_SENDING"
                    );
                    // Drive the actual RESET_STREAM acknowledgement while the
                    // handler is gated; no successful response can overtake it.
                    while owner.connection().path_stats().bytes_in_flight > 0 {
                        owner.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                        assert!(
                            drain_h3_events(&cx, &mut session, owner.connection_mut()).is_empty()
                        );
                    }
                    assert!(
                        !request_cx.is_cancel_requested(),
                        "acknowledging input stop must preserve response ownership"
                    );
                    release_tx.send(&cx, ()).unwrap();
                    receive_response(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"early response retained",
                    )
                    .await;
                    wait_region_closed(&request_cx).await;
                    response(
                        &cx,
                        &mut owner,
                        &mut session,
                        "/survivor",
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"survived",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 8, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.completed_requests, 2);
                assert_eq!(report.cancelled_requests, 0);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[cfg(feature = "test-internals")]
        #[test]
        fn authenticated_listener_finalizer_failure_preserves_parked_peer_and_admission() {
            use asupersync::web::AsyncCxFnHandler;

            for workers in [1, 2] {
                for streaming in [false, true] {
                    run(workers, async move {
                        let started = Instant::now();
                        let cx = Cx::current().unwrap();
                        let finalizers = Arc::new(AtomicUsize::new(0));
                        let handler_finalizers = Arc::clone(&finalizers);
                        let (fault_ready_tx, mut fault_ready_rx) =
                            asupersync::channel::oneshot::channel();
                        let fault_ready = Arc::new(Mutex::new(Some(fault_ready_tx)));
                        let (fault_release_tx, fault_release_rx) =
                            asupersync::channel::oneshot::channel();
                        let fault_release = Arc::new(Mutex::new(Some(fault_release_rx)));
                        let (peer_parked_tx, mut peer_parked_rx) =
                            asupersync::channel::oneshot::channel();
                        let peer_parked = Arc::new(Mutex::new(Some(peer_parked_tx)));
                        let (peer_release_tx, peer_release_rx) =
                            asupersync::channel::oneshot::channel();
                        let peer_release = Arc::new(Mutex::new(Some(peer_release_rx)));
                        let router = Router::new()
                            .route(
                                "/bad-cleanup",
                                post(AsyncCxFnHandler::new(move |request_cx: Cx| {
                                    let ready = fault_ready.lock().unwrap().take().unwrap();
                                    let mut release = fault_release.lock().unwrap().take().unwrap();
                                    let finalizers = Arc::clone(&handler_finalizers);
                                    async move {
                                        assert!(asupersync::runtime::Runtime::current_handle()
                                            .unwrap()
                                            .register_sync_finalizer_for_testing(
                                                request_cx.region_id(),
                                                move || {
                                                    finalizers.fetch_add(1, Ordering::SeqCst);
                                                    panic!("intentional HTTP/3 request finalizer failure");
                                                },
                                            ));
                                        ready.send(&request_cx, request_cx.clone()).unwrap();
                                        release.recv(&request_cx).await.unwrap();
                                        Response::new(StatusCode::OK, "cleanup still has to run")
                                    }
                                })),
                            )
                            .route(
                                "/parked-peer",
                                post(AsyncCxFnHandler::new(move |request_cx: Cx| {
                                    let mut parked = peer_parked.lock().unwrap().take();
                                    let mut release = peer_release.lock().unwrap().take().unwrap();
                                    async move {
                                        std::future::poll_fn(|task_cx| {
                                            let poll = release.poll_recv_uninterruptible(task_cx);
                                            if poll.is_pending() {
                                                if let Some(signal) = parked.take() {
                                                    signal.send(&request_cx, request_cx.clone()).unwrap();
                                                }
                                            }
                                            poll
                                        })
                                        .await
                                        .unwrap();
                                        assert!(!request_cx.is_cancel_requested());
                                        Response::new(StatusCode::OK, "peer survived finalizer failure")
                                    }
                                })),
                            )
                            .route(
                                "/later",
                                post(FnHandler::new(|| Response::new(StatusCode::OK, "still accepting"))),
                            );
                        let mut listener_config = config(8);
                        listener_config.endpoint.max_connections = 2;
                        listener_config.max_concurrent_requests = 2;
                        listener_config.router = listener_config
                            .router
                            .max_in_flight_dispatches(1)
                            .max_total_buffered_body_bytes(16);
                        if !streaming {
                            listener_config.streaming_request_body_buffer_bytes = None;
                        }
                        let listener = bind(&cx, router, listener_config).await;
                        let address = listener.local_addr();
                        let (shutdown_tx, mut shutdown_rx) =
                            asupersync::channel::oneshot::channel();
                        let serving = listener.serve_with_shutdown(&cx, async {
                            shutdown_rx.recv(&cx).await.unwrap();
                        });
                        let client = async {
                            let (mut peer, mut peer_h3) = connect(&cx, address, 81).await;
                            let peer_stream =
                                open_upload(&cx, &mut peer, "/parked-peer", Some(0)).await;
                            peer.connection_mut()
                                .write_stream(&cx, peer_stream, Bytes::new(), true)
                                .unwrap();
                            peer.flush(&cx).await.unwrap();
                            let peer_cx: Cx = peer_parked_rx.recv(&cx).await.unwrap();
                            let (mut fault, mut fault_h3) = connect(&cx, address, 82).await;
                            let fault_stream =
                                open_upload(&cx, &mut fault, "/bad-cleanup", Some(0)).await;
                            fault
                                .connection_mut()
                                .write_stream(&cx, fault_stream, Bytes::new(), true)
                                .unwrap();
                            fault.flush(&cx).await.unwrap();
                            let fault_cx: Cx = fault_ready_rx.recv(&cx).await.unwrap();
                            assert_ne!(fault_cx.region_id(), peer_cx.region_id());
                            assert!(!peer_cx.is_cancel_requested());
                            fault_release_tx.send(&cx, ()).unwrap();
                            asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
                                loop {
                                    fault.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                                    for event in drain_h3_events(&cx, &mut fault_h3, fault.connection_mut()) {
                                        match event {
                                            NativeH3Event::StreamReset { stream_id, error_code, .. } => {
                                                assert_eq!(stream_id, fault_stream);
                                                assert_eq!(error_code, 0x102, "failed cleanup resets only its response with H3_INTERNAL_ERROR");
                                                return;
                                            }
                                            NativeH3Event::ResponseHeaders { stream_id, .. }
                                            | NativeH3Event::Data { stream_id, .. }
                                            | NativeH3Event::Finished { stream_id } => {
                                                assert_eq!(stream_id, fault_stream);
                                            }
                                            other => panic!("unexpected cleanup failure event: {other:?}"),
                                        }
                                    }
                                }
                            })
                            .await
                            .expect("a failed finalizer must produce a scoped reset, not stop the listener");
                            wait_region_closed(&fault_cx).await;
                            assert_eq!(finalizers.load(Ordering::SeqCst), 1);
                            assert!(
                                !peer_cx.is_cancel_requested(),
                                "other connection's parked region remains live"
                            );
                            peer_release_tx.send(&cx, ()).unwrap();
                            receive_response(
                                &cx,
                                &mut peer,
                                &mut peer_h3,
                                peer_stream,
                                &H3ResponseHead::new(200, Vec::new()).unwrap(),
                                b"peer survived finalizer failure",
                            )
                            .await;
                            wait_region_closed(&peer_cx).await;
                            response(
                                &cx,
                                &mut fault,
                                &mut fault_h3,
                                "/later",
                                &H3ResponseHead::new(200, Vec::new()).unwrap(),
                                b"still accepting",
                            )
                            .await;
                            shutdown_tx.send(&cx, ()).unwrap();
                            zip(
                                acknowledge_shutdown_goaway(
                                    &cx,
                                    &mut peer,
                                    &mut peer_h3,
                                    peer_stream.0 + 4,
                                    None,
                                ),
                                acknowledge_shutdown_goaway(
                                    &cx,
                                    &mut fault,
                                    &mut fault_h3,
                                    fault_stream.0 + 8,
                                    None,
                                ),
                            )
                            .await;
                        };
                        let (report, ()) = zip(serving, client).await;
                        let report =
                            report.expect("request cleanup failure must not fail the endpoint");
                        assert_eq!(report.accepted_connections, 2);
                        assert_eq!(report.completed_requests, 2);
                        assert_eq!(report.cancelled_requests, 1);
                        assert_eq!(report.failed_request_cleanups, 1);
                        assert_eq!(report.failed_connections, 0);
                        assert_eq!(report.refused_requests, 0);
                        assert!(!report.drain_timed_out);
                        eprintln!(
                            "event=h3_cleanup_isolated workers={workers} streaming={streaming} completed={} cancelled={} cleanup_failures={} elapsed_ms={}",
                            report.completed_requests,
                            report.cancelled_requests,
                            report.failed_request_cleanups,
                            started.elapsed().as_millis(),
                        );
                    });
                }
            }
        }

        struct TightenQueuedBody {
            admitted: Mutex<Option<asupersync::channel::oneshot::Sender<Cx>>>,
            resume: Mutex<Option<asupersync::channel::oneshot::Receiver<()>>>,
            terminal: Arc<Mutex<Option<IncomingBodyError>>>,
        }

        impl asupersync::web::handler::Handler for TightenQueuedBody {
            fn call(
                &self,
                cx: &Cx,
                mut request: asupersync::web::extract::Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                use asupersync::web::extract::FromRequest;

                let request_cx = cx.clone();
                let admitted = self.admitted.lock().unwrap().take().unwrap();
                let mut resume = self.resume.lock().unwrap().take().unwrap();
                let terminal = Arc::clone(&self.terminal);
                Box::pin(async move {
                    admitted.send(&request_cx, request_cx.clone()).unwrap();
                    resume.recv(&request_cx).await.unwrap();
                    // Model authentication or application policy tightening
                    // after the transport admitted the body, using public APIs.
                    request
                        .extensions
                        .insert_typed(RequestBodyPolicy::new().max_total_body_size(4));
                    let mut body = StreamingRawBody::from_request(request).unwrap();
                    assert_eq!(body.queued_bytes(), 8);
                    let frame =
                        std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                            .await;
                    match frame {
                        Some(Err(error)) => *terminal.lock().unwrap() = Some(error),
                        other => panic!("tightened body policy must fail queued DATA: {other:?}"),
                    }
                    // This ordinary-looking response must not hide the failure
                    // from the listener's retained body lifecycle observer.
                    Response::new(StatusCode::OK, "must not be emitted")
                })
            }
        }

        #[test]
        fn authenticated_listener_streaming_caught_queued_body_error_cannot_complete_request() {
            run(2, async {
                const WINDOW: u64 = 64;
                let cx = Cx::current().unwrap();
                let terminal = Arc::new(Mutex::new(None));
                let (admitted_tx, mut admitted_rx) = asupersync::channel::oneshot::channel();
                let (resume_tx, resume_rx) = asupersync::channel::oneshot::channel();
                let router = Router::new()
                    .route(
                        "/tighten",
                        post(TightenQueuedBody {
                            admitted: Mutex::new(Some(admitted_tx)),
                            resume: Mutex::new(Some(resume_rx)),
                            terminal: Arc::clone(&terminal),
                        }),
                    )
                    .route(
                        "/survivor",
                        post(FnHandler::new(|| Response::new(StatusCode::OK, "survived"))),
                    );
                let mut listener_config = config(16);
                listener_config.endpoint.connection_config.recv_window = WINDOW;
                listener_config.receive_window_bytes = WINDOW;
                listener_config.max_concurrent_requests = 1;
                let listener = bind(&cx, router, listener_config).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 68).await;
                    let stream = open_upload(&cx, &mut owner, "/tighten", None).await;
                    let request_cx: Cx = admitted_rx.recv(&cx).await.unwrap();
                    write_data(&cx, &mut owner, stream, b"12345678", true).await;
                    let sent = owner
                        .connection()
                        .inner()
                        .streams()
                        .stream(stream)
                        .unwrap()
                        .send_offset;
                    loop {
                        owner.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                        let peer_credit = owner
                            .connection()
                            .inner()
                            .streams()
                            .stream(stream)
                            .unwrap()
                            .send_credit
                            .limit();
                        if peer_credit >= sent + WINDOW {
                            break;
                        }
                    }
                    // MAX_STREAM_DATA derived from the server's read offset
                    // witnesses transport consumption while extraction is gated.
                    assert!(terminal.lock().unwrap().is_none());
                    resume_tx.send(&cx, ()).unwrap();
                    receive_cancelled(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        asupersync::http::h3_quic::H3_REQUEST_CANCELLED,
                    )
                    .await;
                    wait_region_closed(&request_cx).await;
                    assert_eq!(
                        *terminal.lock().unwrap(),
                        Some(IncomingBodyError::BodyTooLarge {
                            actual: Some(8),
                            limit: 4,
                        })
                    );
                    response(
                        &cx,
                        &mut owner,
                        &mut session,
                        "/survivor",
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"survived",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 8, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 1);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_streaming_mid_frame_fin_closes_connection_with_frame_error() {
            run(2, async {
                let cx = Cx::current().unwrap();
                let terminal = Arc::new(Mutex::new(None));
                let handler_terminal = Arc::clone(&terminal);
                let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                let router = Router::new()
                    .route(
                        "/truncated",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |request_cx: Cx, mut body: StreamingRawBody| {
                                let mut parked = parked_slot.lock().unwrap().take();
                                let terminal = Arc::clone(&handler_terminal);
                                async move {
                                    loop {
                                        let frame = std::future::poll_fn(|task_cx| {
                                            let poll = Pin::new(&mut body).poll_frame(task_cx);
                                            if poll.is_pending() {
                                                if let Some(signal) = parked.take() {
                                                    signal.send(&request_cx, request_cx.clone()).unwrap();
                                                }
                                            }
                                            poll
                                        })
                                        .await;
                                        match frame {
                                            Some(Ok(Frame::Data(_))) => {}
                                            Some(Err(error)) => {
                                                *terminal.lock().unwrap() = Some(error);
                                                break;
                                            }
                                            other => panic!("truncated wire frame has no successful EOF: {other:?}"),
                                        }
                                    }
                                    Response::new(StatusCode::OK, "must not be emitted")
                                }
                            },
                        )),
                    )
                    .route(
                        "/healthy",
                        post(FnHandler::new(|| Response::new(StatusCode::OK, "listener retained"))),
                    );
                let mut listener_config = config(8);
                listener_config.endpoint.max_connections = 2;
                let listener = bind(&cx, router, listener_config).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, _session) = connect(&cx, address, 69).await;
                    let stream = open_upload(&cx, &mut owner, "/truncated", None).await;
                    let request_cx: Cx = parked_rx.recv(&cx).await.unwrap();
                    let mut wire = data_wire(b"truncated");
                    wire.truncate(wire.len() - 2);
                    owner
                        .connection_mut()
                        .write_stream(&cx, stream, Bytes::from(wire), true)
                        .unwrap();
                    owner.flush(&cx).await.unwrap();
                    while !owner.connection().close_was_peer_initiated() {
                        owner.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                    }
                    assert_eq!(
                        owner.connection().inner().transport().close_code(),
                        Some(0x106),
                        "RFC 9114 H3_FRAME_ERROR closes the connection for FIN inside a frame"
                    );
                    wait_region_closed(&request_cx).await;
                    assert_eq!(
                        *terminal.lock().unwrap(),
                        Some(IncomingBodyError::ClientAborted)
                    );
                    // A malformed frame cannot preserve sibling streams on its
                    // connection. A separately authenticated peer still works.
                    let (mut healthy, mut healthy_h3) = connect(&cx, address, 70).await;
                    response(
                        &cx,
                        &mut healthy,
                        &mut healthy_h3,
                        "/healthy",
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"listener retained",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut healthy, &mut healthy_h3, 4, None).await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.accepted_connections, 2);
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 1);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 1);
                assert!(!report.drain_timed_out);
            });
        }
        async fn write_trailers(
            cx: &Cx,
            owner: &mut NativeQuicUdpConnection,
            stream: StreamId,
            fields: &[(String, String)],
            fin: bool,
        ) {
            let field_section =
                asupersync::http::h3_native::qpack_encode_trailer_field_section(fields).unwrap();
            let mut wire = Vec::new();
            H3Frame::Headers(field_section).encode(&mut wire).unwrap();
            owner
                .connection_mut()
                .write_stream(cx, stream, Bytes::from(wire), fin)
                .unwrap();
            owner.flush(cx).await.unwrap();
        }

        fn assert_trailer_fields(
            trailers: &asupersync::http::body::HeaderMap,
            expected: &[(String, String)],
        ) {
            let actual: Vec<_> = trailers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect();
            let expected: Vec<_> = expected
                .iter()
                .map(|(name, value)| (name.clone(), value.as_bytes().to_vec()))
                .collect();
            assert_eq!(actual, expected);
        }

        #[test]
        fn authenticated_listener_request_trailers_wait_for_fin_with_known_and_unknown_length() {
            for workers in [1, 2] {
                for declared in [None, Some(8)] {
                    trailers_before_fin(workers, b"payload\0", declared);
                }
            }
        }

        #[test]
        fn authenticated_listener_trailers_only_zero_length_waits_for_fin() {
            for workers in [1, 2] {
                trailers_before_fin(workers, b"", Some(0));
            }
        }

        fn trailers_before_fin(workers: usize, payload: &'static [u8], declared: Option<usize>) {
            run(workers, async move {
                const QUEUE_BYTES: usize = 64;
                let cx = Cx::current().unwrap();
                let fields = vec![
                    ("x-checksum".to_owned(), "checked".to_owned()),
                    ("x-part".to_owned(), "one".to_owned()),
                    ("x-part".to_owned(), "two".to_owned()),
                ];
                let handler_fields = fields.clone();
                let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                let router = Router::new().route(
                    "/trailers",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, mut body: StreamingRawBody| {
                            let fields = handler_fields.clone();
                            let mut parked = parked_slot.lock().unwrap().take();
                            async move {
                                let mut received = Vec::new();
                                let mut trailers_seen = false;
                                loop {
                                    let frame = std::future::poll_fn(|task_cx| {
                                        let poll = Pin::new(&mut body).poll_frame(task_cx);
                                        if poll.is_pending() && trailers_seen {
                                            assert!(!body.is_end_stream());
                                            if let Some(signal) = parked.take() {
                                                signal.send(&request_cx, request_cx.clone()).unwrap();
                                            }
                                        }
                                        poll
                                    })
                                    .await;
                                    match frame {
                                        Some(Ok(Frame::Data(bytes))) => {
                                            assert!(!trailers_seen, "DATA cannot follow trailers");
                                            received.extend_from_slice(bytes.chunk());
                                        }
                                        Some(Ok(Frame::Trailers(trailers))) => {
                                            assert!(!trailers_seen, "exactly one trailer block");
                                            assert_eq!(received, payload);
                                            assert_trailer_fields(&trailers, &fields);
                                            trailers_seen = true;
                                        }
                                        Some(Err(error)) => panic!("valid request trailers: {error}"),
                                        None => break,
                                    }
                                }
                                assert_eq!(received, payload);
                                assert!(trailers_seen);
                                assert!(parked.is_none(), "trailers must not manufacture body EOF");
                                assert!(body.queued_bytes_peak() <= QUEUE_BYTES);
                                Response::new(StatusCode::OK, received)
                            }
                        },
                    )),
                );
                let listener = bind(&cx, router, config(QUEUE_BYTES)).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 71).await;
                    let stream = open_upload(&cx, &mut owner, "/trailers", declared).await;
                    if !payload.is_empty() {
                        write_data(&cx, &mut owner, stream, payload, false).await;
                    }
                    write_trailers(&cx, &mut owner, stream, &fields, false).await;
                    let request_cx: Cx = parked_rx.recv(&cx).await.unwrap();
                    assert!(!request_cx.is_cancel_requested());
                    owner
                        .connection_mut()
                        .write_stream(&cx, stream, Bytes::new(), true)
                        .unwrap();
                    owner.flush(&cx).await.unwrap();
                    receive_response(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        payload,
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 4, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.accepted_connections, 1);
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 0);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_trailer_backpressure_resumes_without_another_client_packet() {
            run(2, async {
                const QUEUE_BYTES: usize = 32;
                const WINDOW: u64 = 128;
                const PAYLOAD: &[u8] = b"abcdefghijklmnopqrstuvwx";
                let cx = Cx::current().unwrap();
                let fields = vec![("x-proof".to_owned(), "value".to_owned())];
                let handler_fields = fields.clone();
                let (admitted_tx, mut admitted_rx) = asupersync::channel::oneshot::channel();
                let admitted_slot = Arc::new(Mutex::new(Some(admitted_tx)));
                let (resume_tx, resume_rx) = asupersync::channel::oneshot::channel();
                let resume_slot = Arc::new(Mutex::new(Some(resume_rx)));
                let (trailers_tx, mut trailers_rx) = asupersync::channel::oneshot::channel();
                let trailers_slot = Arc::new(Mutex::new(Some(trailers_tx)));
                let router = Router::new().route(
                    "/queued-trailers",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, mut body: StreamingRawBody| {
                            let admitted = admitted_slot.lock().unwrap().take().unwrap();
                            let mut resume = resume_slot.lock().unwrap().take().unwrap();
                            let mut trailers_signal = trailers_slot.lock().unwrap().take();
                            let fields = handler_fields.clone();
                            async move {
                                admitted.send(&request_cx, ()).unwrap();
                                resume.recv(&request_cx).await.unwrap();
                                // DATA charges 24 bytes. The trailer charges 16;
                                // both cannot occupy this 32-byte queue together.
                                assert_eq!(body.queued_bytes(), PAYLOAD.len());
                                let mut received = Vec::new();
                                let mut trailers_seen = false;
                                loop {
                                    let frame = std::future::poll_fn(|task_cx| {
                                        let poll = Pin::new(&mut body).poll_frame(task_cx);
                                        if poll.is_pending() && trailers_seen {
                                            if let Some(signal) = trailers_signal.take() {
                                                signal.send(&request_cx, ()).unwrap();
                                            }
                                        }
                                        poll
                                    })
                                    .await;
                                    match frame {
                                        Some(Ok(Frame::Data(bytes))) => {
                                            assert!(!trailers_seen);
                                            received.extend_from_slice(bytes.chunk());
                                        }
                                        Some(Ok(Frame::Trailers(trailers))) => {
                                            assert!(!trailers_seen);
                                            assert_eq!(received, PAYLOAD);
                                            assert_trailer_fields(&trailers, &fields);
                                            trailers_seen = true;
                                        }
                                        Some(Err(error)) => panic!("queued trailer failed: {error}"),
                                        None => break,
                                    }
                                }
                                assert!(trailers_seen && trailers_signal.is_none());
                                assert_eq!(received, PAYLOAD);
                                assert!(body.queued_bytes_peak() <= QUEUE_BYTES);
                                Response::new(StatusCode::OK, received)
                            }
                        },
                    )),
                );
                let mut listener_config = config(QUEUE_BYTES);
                listener_config.endpoint.connection_config.recv_window = WINDOW;
                listener_config.receive_window_bytes = WINDOW;
                let listener = bind(&cx, router, listener_config).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 72).await;
                    let stream = open_upload(
                        &cx,
                        &mut owner,
                        "/queued-trailers",
                        Some(PAYLOAD.len()),
                    )
                    .await;
                    admitted_rx.recv(&cx).await.unwrap();
                    write_data(&cx, &mut owner, stream, PAYLOAD, false).await;
                    write_trailers(&cx, &mut owner, stream, &fields, false).await;
                    let sent = owner
                        .connection()
                        .inner()
                        .streams()
                        .stream(stream)
                        .unwrap()
                        .send_offset;
                    loop {
                        owner.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                        let credit = owner
                            .connection()
                            .inner()
                            .streams()
                            .stream(stream)
                            .unwrap()
                            .send_credit
                            .limit();
                        if credit >= sent + WINDOW {
                            break;
                        }
                    }
                    // Credit witnesses that the trailer wire bytes reached
                    // the server parser while the sole consumer was gated.
                    resume_tx.send(&cx, ()).unwrap();
                    // Do not send or receive a client packet here: consuming
                    // queued DATA alone must wake and deliver the parked trailer.
                    trailers_rx.recv(&cx).await.unwrap();
                    owner
                        .connection_mut()
                        .write_stream(&cx, stream, Bytes::new(), true)
                        .unwrap();
                    owner.flush(&cx).await.unwrap();
                    receive_response(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        PAYLOAD,
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 4, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 0);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }

        #[test]
        fn authenticated_listener_oversized_request_trailers_cancel_only_the_upload() {
            failed_trailers(
                32,
                vec![(
                    "x-proof".to_owned(),
                    "012345678901234567890123456789".to_owned(),
                )],
                IncomingBodyError::TrailersTooLarge,
                asupersync::http::h3_quic::H3_REQUEST_CANCELLED,
            );
        }

        #[test]
        fn authenticated_listener_forbidden_request_trailers_are_message_errors() {
            for (name, value) in [("content-length", "0"), ("host", "localhost")] {
                // Both fields fit the 64-byte metadata budget, so these cases
                // reach field-policy validation rather than the size rejection.
                failed_trailers(
                    64,
                    vec![(name.to_owned(), value.to_owned())],
                    IncomingBodyError::BadHeader,
                    0x10e,
                );
            }
        }

        fn failed_trailers(
            queue_bytes: usize,
            fields: Vec<(String, String)>,
            expected_error: IncomingBodyError,
            expected_reset_code: u64,
        ) {
            run(2, async move {
                let cx = Cx::current().unwrap();
                let terminal = Arc::new(Mutex::new(None));
                let handler_terminal = Arc::clone(&terminal);
                let retired = Arc::new(AtomicUsize::new(0));
                let handler_retired = Arc::clone(&retired);
                let (parked_tx, mut parked_rx) = asupersync::channel::oneshot::channel();
                let parked_slot = Arc::new(Mutex::new(Some(parked_tx)));
                let router = Router::new()
                    .route(
                        "/invalid-trailers",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |request_cx: Cx, mut body: StreamingRawBody| {
                                let mut parked = parked_slot.lock().unwrap().take();
                                let terminal = Arc::clone(&handler_terminal);
                                let retired = Arc::clone(&handler_retired);
                                async move {
                                    let _retired = ProducerRetired(retired);
                                    let frame = std::future::poll_fn(|task_cx| {
                                        let poll = Pin::new(&mut body).poll_frame(task_cx);
                                        if poll.is_pending() {
                                            if let Some(signal) = parked.take() {
                                                signal.send(&request_cx, request_cx.clone()).unwrap();
                                            }
                                        }
                                        poll
                                    })
                                    .await;
                                    match frame {
                                        Some(Err(error)) => *terminal.lock().unwrap() = Some(error),
                                        other => panic!("invalid trailer must fail the body: {other:?}"),
                                    }
                                    Response::new(StatusCode::OK, "must not be emitted")
                                }
                            },
                        )),
                    )
                    .route(
                        "/survivor",
                        post(FnHandler::new(|| Response::new(StatusCode::OK, "survived"))),
                    );
                let mut listener_config = config(queue_bytes);
                listener_config.max_concurrent_requests = 1;
                let listener = bind(&cx, router, listener_config).await;
                let address = listener.local_addr();
                let (shutdown_tx, mut shutdown_rx) = asupersync::channel::oneshot::channel();
                let serving = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                });
                let client = async {
                    let (mut owner, mut session) = connect(&cx, address, 73).await;
                    let stream = open_upload(
                        &cx,
                        &mut owner,
                        "/invalid-trailers",
                        None,
                    )
                    .await;
                    let request_cx: Cx = parked_rx.recv(&cx).await.unwrap();
                    assert!(!request_cx.is_cancel_requested());
                    write_trailers(&cx, &mut owner, stream, &fields, false).await;
                    receive_cancelled(
                        &cx,
                        &mut owner,
                        &mut session,
                        stream,
                        expected_reset_code,
                    )
                    .await;
                    wait_region_closed(&request_cx).await;
                    assert_eq!(*terminal.lock().unwrap(), Some(expected_error));
                    assert_eq!(retired.load(Ordering::SeqCst), 1);
                    response(
                        &cx,
                        &mut owner,
                        &mut session,
                        "/survivor",
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                        b"survived",
                    )
                    .await;
                    shutdown_tx.send(&cx, ()).unwrap();
                    acknowledge_shutdown_goaway(&cx, &mut owner, &mut session, stream.0 + 8, None)
                        .await;
                };
                let (report, ()) = zip(serving, client).await;
                let report = report.unwrap();
                assert_eq!(report.accepted_connections, 1);
                assert_eq!(report.completed_requests, 1);
                assert_eq!(report.cancelled_requests, 1);
                assert_eq!(report.refused_requests, 0);
                assert_eq!(report.failed_connections, 0);
                assert!(!report.drain_timed_out);
            });
        }
    }
}
