//! Real RFC 8441 streams share the native listener's request ownership.

use super::{Message, WebSocketAcceptor};
use crate::bytes::{Bytes, BytesMut};
use crate::channel::oneshot;
use crate::codec::Decoder as _;
use crate::cx::Cx;
use crate::http::h1::Response;
use crate::http::h1::server::HostPolicy;
use crate::http::h1::stream::StreamingServerRequest;
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::listener::{
    Http2Listener, Http2ProducedResponse, Http2StreamingListenerConfig,
};
use crate::http::h2::{Connection, ConnectionState, ErrorCode, FrameCodec, Header, Settings};
use crate::io::{AsyncReadExt as _, AsyncWriteExt as _};
use crate::net::TcpStream;
use crate::net::websocket::{CloseReason, Frame as WsFrame, FrameCodec as WsCodec, Opcode};
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::types::CancelKind;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(10);
const AUTHORIZATION: &str = "Bearer native-websocket-credential";
const ORIGIN: &str = "https://application.example";
const TEXT: &[u8] = b"masked text crosses HTTP/2 DATA boundaries";
const BULK_BYTES: usize = 256 * 1024;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                let builder = if workers == 1 {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::new().worker_threads(workers)
                };
                let runtime = builder.build().unwrap();
                runtime.block_on(async {
                    let root = Cx::current().unwrap();
                    let mut task = root.spawn(scenario).unwrap();
                    task.join(&root).await.unwrap();
                });
                let report = runtime.shutdown_drained(WATCHDOG);
                assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                assert_eq!(report.live_tasks, 0);
                assert_eq!(report.pending_spawns, 0);
                assert_eq!(report.pending_obligations, 0);
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(30))
        .expect("native HTTP/2 WebSocket workflow must finish and quiesce");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn configuration(tunnel_limit: Option<u64>) -> Http2StreamingListenerConfig {
    let mut config = Http2StreamingListenerConfig::default();
    config.listener = config
        .listener
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .max_body_size(8)
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5))
        .flow_control_progress_timeout(WATCHDOG);
    if let Some(limit) = tunnel_limit {
        config = config.with_extended_connect(NonZeroU64::new(limit).unwrap());
    }
    config
}

struct Controls {
    owner: Cx,
    server: Cx,
    in_flight: Arc<AtomicUsize>,
}

async fn exercise<H, HFut, F, Fut>(
    owner: Cx,
    handler: H,
    config: Http2StreamingListenerConfig,
    client_settings: Settings,
    enabled: bool,
    workflow: F,
) where
    H: Fn(StreamingServerRequest) -> HFut + Send + Sync + 'static,
    HFut: Future<Output = Http2ProducedResponse> + Send + 'static,
    F: FnOnce(Peer, Controls) -> Fut + Send,
    Fut: Future<Output = Peer> + Send,
{
    let listener =
        Http2Listener::bind_streaming_produced_with_config("127.0.0.1:0", handler, config)
            .await
            .unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let (started, mut starting) = oneshot::channel();
    let mut service = owner
        .spawn(move |server| async move {
            started.send_blocking(server.clone()).unwrap();
            listener.run_streaming_produced_in(&server).await
        })
        .unwrap();
    let server = starting.recv(&owner).await.unwrap();
    let peer = Peer::connect(address, client_settings, enabled).await;
    drop(
        workflow(
            peer,
            Controls {
                owner: owner.clone(),
                server,
                in_flight: Arc::clone(&in_flight),
            },
        )
        .await,
    );
    if !manager.is_draining() {
        assert!(manager.begin_drain(Duration::from_secs(2)));
    }
    let stats = service.join(&owner).await.unwrap().unwrap();
    let report = stats.drain_report.expect("request-aware native drain");
    assert!(report.reached_quiescence, "{report}");
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active_count(), 0);
}

// Read complete wire frames without overread. The public Setting enum keeps
// unknown extensions opaque, so inspect the actual SETTINGS payload before
// giving its decoded frame to the production connection state machine.
struct Peer {
    socket: TcpStream,
    codec: FrameCodec,
    connection: Connection,
    connect_settings: Vec<u32>,
    ws_codec: WsCodec,
    ws_input: BytesMut,
    ws_end: bool,
}

impl Peer {
    async fn connect(address: SocketAddr, settings: Settings, enabled: bool) -> Self {
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(CLIENT_PREFACE).await.unwrap();
        let mut peer = Self {
            socket,
            codec: FrameCodec::new(),
            connection: Connection::client(settings),
            connect_settings: Vec::new(),
            ws_codec: WsCodec::client(),
            ws_input: BytesMut::new(),
            ws_end: false,
        };
        peer.connection.queue_initial_settings();
        peer.flush().await;
        while peer.connection.state() == ConnectionState::Handshaking {
            assert!(peer.receive().await.is_none());
        }
        assert_eq!(
            peer.connect_settings,
            if enabled { vec![1] } else { vec![] }
        );
        peer
    }

    async fn flush(&mut self) {
        while let Some(frame) = self.connection.next_frame() {
            let mut bytes = BytesMut::new();
            frame.encode(&mut bytes).unwrap();
            self.socket.write_all(&bytes).await.unwrap();
        }
        self.socket.flush().await.unwrap();
    }

    async fn receive(&mut self) -> Option<ReceivedFrame> {
        let mut head = [0u8; 9];
        self.socket.read_exact(&mut head).await.unwrap();
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        assert!(
            length <= 16_384,
            "peer did not advertise a larger frame size"
        );
        let mut payload = vec![0; length];
        self.socket.read_exact(&mut payload).await.unwrap();
        if head[3] == 4 && head[4] & 1 == 0 {
            assert_eq!(payload.len() % 6, 0);
            for setting in payload.chunks_exact(6) {
                if setting[..2] == [0, 8] {
                    self.connect_settings
                        .push(u32::from_be_bytes(setting[2..].try_into().unwrap()));
                }
            }
        }
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&head);
        bytes.extend_from_slice(&payload);
        let frame = self.codec.decode(&mut bytes).unwrap().unwrap();
        assert!(bytes.is_empty());
        let event = self.connection.process_frame(frame).unwrap();
        self.flush().await;
        event
    }

    async fn websocket(&mut self) -> u32 {
        self.websocket_with(Vec::new()).await
    }

    async fn websocket_with(&mut self, extra: Vec<Header>) -> u32 {
        let mut headers = vec![
            Header::new(":method", "CONNECT"),
            Header::new(":protocol", "websocket"),
            Header::new(":scheme", "http"),
            Header::new(":authority", "localhost"),
            Header::new(":path", "/socket"),
            Header::new("sec-websocket-version", "13"),
            Header::new("sec-websocket-protocol", "chat, unused"),
            Header::new("authorization", AUTHORIZATION),
            Header::new("origin", ORIGIN),
        ];
        headers.extend(extra);
        let stream = self.connection.open_stream(headers, false).unwrap();
        self.flush().await;
        stream
    }

    async fn upgraded(&mut self, stream: u32) {
        loop {
            match self.receive().await {
                Some(ReceivedFrame::Headers {
                    stream_id,
                    headers,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert!(!end_stream, "200 must retain the duplex response half");
                    assert_eq!(header(&headers, ":status"), Some("200"));
                    assert_eq!(header(&headers, "sec-websocket-protocol"), Some("chat"));
                    for name in [
                        "connection",
                        "upgrade",
                        "sec-websocket-key",
                        "sec-websocket-accept",
                        "transfer-encoding",
                        "content-length",
                        "authorization",
                        "origin",
                    ] {
                        assert!(header(&headers, name).is_none(), "unexpected {name}");
                    }
                    return;
                }
                None => {}
                other => panic!("expected HTTP/2 WebSocket response head: {other:?}"),
            }
        }
    }

    async fn data(&mut self, stream: u32, bytes: Bytes, end: bool) {
        self.connection.send_data(stream, bytes, end).unwrap();
        self.flush().await;
    }

    async fn ws_frame(&mut self, stream: u32) -> WsFrame {
        loop {
            if let Some(frame) = self.ws_codec.decode(&mut self.ws_input).unwrap() {
                assert!(!frame.masked, "server WebSocket frames are unmasked");
                return frame;
            }
            assert!(
                !self.ws_end,
                "response ended before a complete WebSocket frame"
            );
            match self.receive().await {
                Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    self.ws_input.extend_from_slice(&data);
                    self.ws_end = end_stream;
                }
                None => {}
                other => panic!("expected WebSocket DATA: {other:?}"),
            }
        }
    }

    async fn clean_end(&mut self, stream: u32) {
        while !self.ws_end {
            match self.receive().await {
                Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert!(data.is_empty(), "no frame may follow the echoed Close");
                    self.ws_end = end_stream;
                }
                None => {}
                other => panic!("clean close must emit END_STREAM, not RST: {other:?}"),
            }
        }
        assert!(self.ws_input.is_empty());
        assert!(self.ws_codec.decode(&mut self.ws_input).unwrap().is_none());
    }

    async fn ordinary(&mut self, empty: bool) {
        let stream = self
            .connection
            .open_stream(
                vec![
                    Header::new(":method", "GET"),
                    Header::new(":scheme", "http"),
                    Header::new(":authority", "localhost"),
                    Header::new(":path", if empty { "/empty" } else { "/ordinary" }),
                ],
                true,
            )
            .unwrap();
        self.flush().await;
        let mut seen_head = false;
        let mut body = Vec::new();
        loop {
            match self.receive().await {
                Some(ReceivedFrame::Headers {
                    stream_id,
                    headers,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert!(!seen_head);
                    seen_head = true;
                    assert_eq!(header(&headers, ":status"), Some("200"));
                    if end_stream {
                        break;
                    }
                }
                Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert!(seen_head);
                    body.extend_from_slice(&data);
                    if end_stream {
                        break;
                    }
                }
                None => {}
                other => panic!("ordinary sibling must stay usable: {other:?}"),
            }
        }
        assert!(seen_head);
        assert_eq!(body, if empty { &b""[..] } else { &b"ok"[..] });
    }

    async fn reset(&mut self, stream: u32, code: ErrorCode) {
        loop {
            match self.receive().await {
                Some(ReceivedFrame::Reset {
                    stream_id,
                    error_code,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert_eq!(error_code, code);
                    return;
                }
                None => {}
                other => panic!("failed tunnel must reset only its stream: {other:?}"),
            }
        }
    }

    async fn eof(&mut self) {
        let mut bytes = [0; 4096];
        for _ in 0..32 {
            if self.socket.read(&mut bytes).await.unwrap() == 0 {
                return;
            }
        }
        panic!("cancelled listener must retire the real socket");
    }
}

fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name == name)
        .map(|header| header.value.as_str())
}

fn ordinary_response(request: &StreamingServerRequest) -> Option<Http2ProducedResponse> {
    if request.head.uri == "/socket" {
        return None;
    }
    assert!(request.extended_connect_protocol().is_none());
    assert!(request.extended_connect_scheme().is_none());
    assert!(request.extended_connect_authority().is_none());
    Some(Http2ProducedResponse::buffered(Response::new(
        200,
        "OK",
        if request.head.uri == "/empty" {
            Vec::new()
        } else {
            b"ok".to_vec()
        },
    )))
}

fn assert_request(request: &StreamingServerRequest) {
    assert_eq!(request.extended_connect_protocol(), Some("websocket"));
    assert_eq!(request.extended_connect_scheme(), Some("http"));
    assert_eq!(request.extended_connect_authority(), Some("localhost"));
    for (name, value) in [("authorization", AUTHORIZATION), ("origin", ORIGIN)] {
        assert_eq!(
            request
                .head
                .headers
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec![value]
        );
    }
}

// Independent masked client bytes, including a split inside the masking key.
fn masked(opcode: u8, payload: &[u8]) -> Bytes {
    let mut bytes = vec![0x80 | opcode];
    if payload.len() <= 125 {
        bytes.push(0x80 | u8::try_from(payload.len()).unwrap());
    } else {
        bytes.push(0xfe);
        bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    }
    let key = [1, 3, 5, 7];
    bytes.extend_from_slice(&key);
    bytes.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % 4]),
    );
    Bytes::from(bytes)
}

fn close_bytes() -> Bytes {
    masked(8, b"\x03\xe8done")
}

fn assert_close(frame: WsFrame) {
    assert_eq!(frame.opcode, Opcode::Close);
    let reason = CloseReason::parse(&frame.payload).unwrap();
    assert_eq!(reason.raw_code, Some(1000));
    // The existing handshake echoes the code and retains the original text
    // for the application receipt; it does not echo that text onto the wire.
    assert!(reason.text.is_none());
}

async fn wait_in_flight(in_flight: &AtomicUsize, expected: usize) {
    poll_fn(|task| {
        if in_flight.load(Ordering::SeqCst) == expected {
            Poll::Ready(())
        } else {
            task.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

async fn wait_retired(request: &Cx, in_flight: &AtomicUsize) {
    let diagnostics = Runtime::current_handle().unwrap().diagnostics().unwrap();
    poll_fn(|task| {
        if in_flight.load(Ordering::SeqCst) == 0
            && diagnostics
                .explain_region_open(request.region_id())
                .region_state
                .is_none()
        {
            Poll::Ready(())
        } else {
            task.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

struct SessionDrop {
    count: Arc<AtomicUsize>,
    cancelled: Arc<AtomicBool>,
    cx: Cx,
}

impl Drop for SessionDrop {
    fn drop(&mut self) {
        self.cancelled
            .store(self.cx.is_cancel_requested(), Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn negotiated_websocket_exchanges_frames_and_closes_its_output_before_peer_eof() {
    native(|owner| async move {
        let delivered_close = Arc::new(AtomicUsize::new(0));
        let handler_close = Arc::clone(&delivered_close);
        let handler = move |request: StreamingServerRequest| {
            let delivered_close = Arc::clone(&handler_close);
            async move {
                if let Some(response) = ordinary_response(&request) {
                    return response;
                }
                assert_request(&request);
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, move |cx, mut socket| async move {
                        assert_eq!(socket.protocol(), Some("chat"));
                        assert!(socket.extensions().is_empty());
                        assert!(socket.is_open());
                        assert_eq!(Cx::current().unwrap().task_id(), cx.task_id());
                        let message = socket.recv(&cx).await?.unwrap();
                        assert!(matches!(&message, Message::Text(text) if text.as_bytes() == TEXT));
                        socket.send(&cx, message).await?;
                        let message = socket.recv(&cx).await?.unwrap();
                        let Message::Close(Some(reason)) = message else {
                            panic!("one close notification");
                        };
                        assert_eq!(reason.raw_code, Some(1000));
                        assert_eq!(reason.text.as_deref(), Some("done"));
                        delivered_close.fetch_add(1, Ordering::SeqCst);
                        assert!(socket.is_closed());
                        assert!(socket.recv(&cx).await?.is_none());
                        socket.finish(&cx).await
                    })
                    .unwrap()
            }
        };
        exercise(
            owner,
            handler,
            configuration(Some(1024)),
            Settings::client(),
            true,
            move |mut peer, controls| async move {
                let stream = peer.websocket().await;
                peer.upgraded(stream).await;
                let encoded = masked(1, TEXT);
                peer.data(stream, encoded.slice(..3), false).await;
                peer.data(stream, encoded.slice(3..), false).await;
                let echoed = peer.ws_frame(stream).await;
                assert_eq!(echoed.opcode, Opcode::Text);
                assert_eq!(&echoed.payload[..], TEXT);
                assert!(!peer.ws_end);
                peer.ordinary(false).await;
                wait_in_flight(&controls.in_flight, 1).await;
                assert_eq!(controls.in_flight.load(Ordering::SeqCst), 1);

                // RFC 8441 section 5.1 explicitly permits server END_STREAM
                // before client END_STREAM. Waiting for the client's half
                // here would deadlock a peer following WebSocket close order.
                peer.data(stream, close_bytes(), false).await;
                assert_close(peer.ws_frame(stream).await);
                peer.clean_end(stream).await;
                assert_eq!(controls.in_flight.load(Ordering::SeqCst), 1);
                peer.data(stream, Bytes::new(), true).await;
                wait_in_flight(&controls.in_flight, 0).await;
                assert_eq!(delivered_close.load(Ordering::SeqCst), 1);
                peer.ordinary(false).await;
                peer
            },
        )
        .await;
    });
}

#[test]
fn websocket_flow_control_stalls_only_its_stream_and_resumes_on_credit() {
    native(|owner| async move {
        let (parked, mut parking) = oneshot::channel();
        let parked = Arc::new(Mutex::new(Some(parked)));
        let sent = Arc::new(AtomicBool::new(false));
        let handler_sent = Arc::clone(&sent);
        let handler = move |request: StreamingServerRequest| {
            let parked = Arc::clone(&parked);
            let sent = Arc::clone(&handler_sent);
            async move {
                if let Some(response) = ordinary_response(&request) {
                    return response;
                }
                let parked = parked.lock().unwrap().take().unwrap();
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, move |cx, mut socket| async move {
                        {
                            let sending = socket.send(&cx, Message::binary(vec![0x5a; BULK_BYTES]));
                            let mut sending = std::pin::pin!(sending);
                            let mut parked = Some(parked);
                            poll_fn(|task| {
                                let result = sending.as_mut().poll(task);
                                if result.is_pending()
                                    && let Some(parked) = parked.take()
                                {
                                    parked.send_blocking(cx.clone()).unwrap();
                                }
                                result
                            })
                            .await?;
                            assert!(parked.is_none(), "bounded output must apply backpressure");
                        }
                        sent.store(true, Ordering::SeqCst);
                        assert!(matches!(socket.recv(&cx).await?, Some(Message::Close(_))));
                        socket.finish(&cx).await
                    })
                    .unwrap()
            }
        };
        let mut settings = Settings::client();
        settings.initial_window_size = 0;
        exercise(
            owner,
            handler,
            configuration(Some(1024)),
            settings,
            true,
            move |mut peer, controls| async move {
                let stream = peer.websocket().await;
                peer.upgraded(stream).await;
                let request = parking.recv(&controls.owner).await.unwrap();
                assert!(!sent.load(Ordering::SeqCst));
                peer.ordinary(true).await;
                assert!(!sent.load(Ordering::SeqCst));
                assert!(!request.is_cancel_requested());
                peer.connection
                    .send_stream_window_update(stream, (BULK_BYTES * 2) as u32)
                    .unwrap();
                peer.flush().await;
                let received = peer.ws_frame(stream).await;
                assert_eq!(received.opcode, Opcode::Binary);
                assert_eq!(received.payload.len(), BULK_BYTES);
                assert!(received.payload.iter().all(|byte| *byte == 0x5a));
                peer.data(stream, close_bytes(), true).await;
                assert_close(peer.ws_frame(stream).await);
                peer.clean_end(stream).await;
                wait_retired(&request, &controls.in_flight).await;
                assert!(sent.load(Ordering::SeqCst));
                peer.ordinary(true).await;
                peer
            },
        )
        .await;
    });
}

#[derive(Clone, Copy)]
enum Abort {
    PeerReset,
    OwnerCancel,
    TunnelLimit,
    RawEnd,
    ServerCloseRawEnd,
}

#[test]
fn parked_tunnels_retire_on_reset_owner_cancel_limit_and_unclosed_eof() {
    for abort in [
        Abort::PeerReset,
        Abort::OwnerCancel,
        Abort::TunnelLimit,
        Abort::RawEnd,
        Abort::ServerCloseRawEnd,
    ] {
        native(move |owner| async move {
            let (parked, mut parking) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked)));
            let drops = Arc::new(AtomicUsize::new(0));
            let cancelled = Arc::new(AtomicBool::new(false));
            let raw_eof_refused = Arc::new(AtomicBool::new(false));
            let handler_drops = Arc::clone(&drops);
            let handler_cancelled = Arc::clone(&cancelled);
            let handler_eof = Arc::clone(&raw_eof_refused);
            let handler = move |request: StreamingServerRequest| {
                let parked = Arc::clone(&parked);
                let drops = Arc::clone(&handler_drops);
                let cancelled = Arc::clone(&handler_cancelled);
                let raw_eof_refused = Arc::clone(&handler_eof);
                async move {
                    if let Some(response) = ordinary_response(&request) {
                        return response;
                    }
                    let parked = parked.lock().unwrap().take().unwrap();
                    WebSocketAcceptor::new()
                        .protocol("chat")
                        .close_timeout(WATCHDOG)
                        .accept_http2(request, move |cx, mut socket| async move {
                            let _retirement = SessionDrop {
                                count: drops,
                                cancelled,
                                cx: cx.clone(),
                            };
                            let result = {
                                let receiving = async {
                                    if matches!(abort, Abort::ServerCloseRawEnd) {
                                        socket
                                            .close(&cx, CloseReason::normal())
                                            .await
                                            .map(|()| None)
                                    } else {
                                        socket.recv(&cx).await
                                    }
                                };
                                let mut receiving = std::pin::pin!(receiving);
                                let mut parked = Some(parked);
                                poll_fn(|task| {
                                    let result = receiving.as_mut().poll(task);
                                    if result.is_pending()
                                        && let Some(parked) = parked.take()
                                    {
                                        parked.send_blocking(cx.clone()).unwrap();
                                    }
                                    result
                                })
                                .await
                            };
                            if matches!(abort, Abort::RawEnd | Abort::ServerCloseRawEnd) {
                                if matches!(abort, Abort::RawEnd) {
                                    assert!(result.unwrap().is_none());
                                }
                                let completion = socket.finish(&cx).await;
                                raw_eof_refused.store(completion.is_err(), Ordering::SeqCst);
                                completion
                            } else {
                                Err(result.expect_err("aborted input cannot become a clean Close"))
                            }
                        })
                        .unwrap()
                }
            };
            exercise(
                owner,
                handler,
                configuration(Some(32)),
                Settings::client(),
                true,
                move |mut peer, controls| async move {
                    let stream = peer.websocket().await;
                    peer.upgraded(stream).await;
                    let request = parking.recv(&controls.owner).await.unwrap();
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    match abort {
                        Abort::PeerReset => {
                            peer.connection.reset_stream(stream, ErrorCode::Cancel);
                            peer.flush().await;
                        }
                        Abort::OwnerCancel => {
                            controls.server.cancel_with(
                                CancelKind::User,
                                Some("test listener owner cancellation"),
                            );
                        }
                        Abort::TunnelLimit => {
                            peer.data(stream, masked(2, &[0x5a; 64]), false).await;
                            peer.reset(stream, ErrorCode::EnhanceYourCalm).await;
                        }
                        Abort::RawEnd => {
                            peer.data(stream, Bytes::new(), true).await;
                            peer.reset(stream, ErrorCode::Cancel).await;
                        }
                        Abort::ServerCloseRawEnd => {
                            assert_close(peer.ws_frame(stream).await);
                            assert!(
                                !peer.ws_end,
                                "server Close alone cannot authorize a clean half-close"
                            );
                            peer.data(stream, Bytes::new(), true).await;
                            peer.reset(stream, ErrorCode::Cancel).await;
                        }
                    }
                    wait_retired(&request, &controls.in_flight).await;
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    if matches!(abort, Abort::RawEnd | Abort::ServerCloseRawEnd) {
                        assert!(raw_eof_refused.load(Ordering::SeqCst));
                    } else {
                        assert!(request.is_cancel_requested());
                        assert!(cancelled.load(Ordering::SeqCst));
                    }
                    assert!(!controls.owner.is_cancel_requested());
                    if matches!(abort, Abort::OwnerCancel) {
                        peer.eof().await;
                    } else {
                        peer.ordinary(false).await;
                    }
                    peer
                },
            )
            .await;
        });
    }
}

#[test]
fn listener_refuses_unnegotiated_and_misdirected_tunnels_before_application() {
    for enabled in [false, true] {
        native(move |owner| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let handler_calls = Arc::clone(&calls);
            let handler = move |request: StreamingServerRequest| {
                handler_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    ordinary_response(&request)
                        .expect("unnegotiated tunnel never reaches application")
                }
            };
            exercise(
                owner,
                handler,
                configuration(enabled.then_some(1024)),
                Settings::client(),
                enabled,
                move |mut peer, _| async move {
                    let stream = if enabled {
                        peer.websocket_with(vec![Header::new("host", "attacker.invalid")])
                            .await
                    } else {
                        peer.websocket().await
                    };
                    peer.reset(stream, ErrorCode::ProtocolError).await;
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    peer.ordinary(false).await;
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    peer
                },
            )
            .await;
        });
    }
}

#[test]
fn dropped_close_receive_keeps_its_deadline_and_can_finish_after_peer_eof() {
    for expire in [false, true] {
        native(move |owner| async move {
            let (parked, mut parking) = oneshot::channel();
            let (resume, resuming) = oneshot::channel();
            let stages = Arc::new(Mutex::new(Some((parked, resuming))));
            let completed = Arc::new(AtomicBool::new(false));
            let handler_completed = Arc::clone(&completed);
            let handler = move |request: StreamingServerRequest| {
                let stages = Arc::clone(&stages);
                let completed = Arc::clone(&handler_completed);
                async move {
                    if let Some(response) = ordinary_response(&request) {
                        return response;
                    }
                    let (parked, mut resuming) = stages.lock().unwrap().take().unwrap();
                    WebSocketAcceptor::new()
                        .protocol("chat")
                        .close_timeout(WATCHDOG)
                        .accept_http2(request, move |cx, mut socket| async move {
                            // Drop each borrowing recv after its poll, then inspect
                            // transport state with no aliasing borrow still alive.
                            poll_fn(|task| {
                                let result = {
                                    let receiving = socket.recv(&cx);
                                    let mut receiving = std::pin::pin!(receiving);
                                    receiving.as_mut().poll(task)
                                };
                                assert!(result.is_pending(), "peer has withheld END_STREAM");
                                if socket.inner.io.shutdown_started {
                                    Poll::Ready(())
                                } else {
                                    Poll::Pending
                                }
                            })
                            .await;
                            assert!(!socket.inner.io.shutdown_complete);
                            assert!(socket.inner.close_handshake.has_pending_peer_close());
                            let deadline = socket.inner.close_handshake.deadline().unwrap();
                            let original_at = deadline.sleep().deadline();

                            // A second cancelled wait must retain the first
                            // absolute deadline and its shared expiry latch.
                            poll_fn(|task| {
                                let receiving = socket.recv(&cx);
                                let mut receiving = std::pin::pin!(receiving);
                                assert!(receiving.as_mut().poll(task).is_pending());
                                Poll::Ready(())
                            })
                            .await;
                            assert_eq!(
                                socket
                                    .inner
                                    .close_handshake
                                    .deadline()
                                    .unwrap()
                                    .sleep()
                                    .deadline(),
                                original_at,
                            );
                            parked.send_blocking((cx.clone(), deadline)).unwrap();
                            resuming.recv(&cx).await.unwrap();

                            let outcome = if expire {
                                let finishing = socket.finish(&cx);
                                let mut finishing = std::pin::pin!(finishing);
                                poll_fn(|task| match finishing.as_mut().poll(task) {
                                    Poll::Ready(result) => Poll::Ready(result),
                                    Poll::Pending => panic!(
                                        "an expired retained Close deadline cannot be renewed"
                                    ),
                                })
                                .await
                            } else {
                                socket.finish(&cx).await
                            };
                            assert_eq!(outcome.is_err(), expire);
                            completed.store(true, Ordering::SeqCst);
                            outcome
                        })
                        .unwrap()
                }
            };
            // A code-only Close is four wire bytes. Deferring stream credit
            // leaves exactly zero DATA capacity when its empty END_STREAM is due.
            let mut settings = Settings::client();
            settings.initial_window_size = 4;
            exercise(
                owner,
                handler,
                configuration(Some(1024)),
                settings,
                true,
                move |mut peer, controls| async move {
                    let stream = peer.websocket().await;
                    peer.upgraded(stream).await;
                    peer.connection.defer_stream_receive_window(stream).unwrap();
                    peer.data(stream, close_bytes(), false).await;
                    assert_close(peer.ws_frame(stream).await);
                    peer.clean_end(stream).await;
                    let (request, deadline) = parking.recv(&controls.owner).await.unwrap();
                    assert_eq!(controls.in_flight.load(Ordering::SeqCst), 1);
                    assert!(!completed.load(Ordering::SeqCst));
                    if expire {
                        // Expire the exact retained deadline, without sleeping or
                        // manufacturing a different owner/clock for the socket.
                        deadline.expire();
                    }
                    resume.send_blocking(()).unwrap();
                    if expire {
                        peer.reset(stream, ErrorCode::Cancel).await;
                    } else {
                        peer.data(stream, Bytes::new(), true).await;
                    }
                    wait_retired(&request, &controls.in_flight).await;
                    assert!(completed.load(Ordering::SeqCst));
                    peer.ordinary(false).await;
                    peer
                },
            )
            .await;
        });
    }
}

#[test]
fn receive_drives_the_last_accepted_write_after_a_dropped_send() {
    // A 64-bit WebSocket length uses a ten-byte unmasked header. At a zero
    // peer window, the driver cannot dequeue DATA: nine chunks fill eight
    // queued frames and one last frame accepted by the tunnel adapter.
    const WIRE_BYTES: usize = 9 * 16 * 1024;
    const PAYLOAD_BYTES: usize = WIRE_BYTES - 10;
    native(|owner| async move {
        let (parked, mut parking) = oneshot::channel();
        let parked = Arc::new(Mutex::new(Some(parked)));
        let handler = move |request: StreamingServerRequest| {
            let parked = Arc::clone(&parked);
            async move {
                if let Some(response) = ordinary_response(&request) {
                    return response;
                }
                let parked = parked.lock().unwrap().take().unwrap();
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, move |cx, mut socket| async move {
                        {
                            let sending =
                                socket.send(&cx, Message::binary(vec![0x6b; PAYLOAD_BYTES]));
                            let mut sending = std::pin::pin!(sending);
                            poll_fn(|task| {
                                assert!(sending.as_mut().poll(task).is_pending());
                                Poll::Ready(())
                            })
                            .await;
                        }
                        // Resume only the already-encoded bytes, dropping each
                        // flush poll. Any nonterminal Pending returns to the
                        // scheduler instead of spinning in the current task.
                        poll_fn(|task| {
                            let result = {
                                let flushing = socket.inner.flush_write_buf_with_cx(Some(&cx));
                                let mut flushing = std::pin::pin!(flushing);
                                flushing.as_mut().poll(task)
                            };
                            match result {
                                Poll::Ready(Ok(())) => panic!("the last channel write must park"),
                                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                                Poll::Pending => {
                                    if socket.inner.write_buf.is_empty()
                                        && socket.inner.io.pending.is_some()
                                    {
                                        Poll::Ready(Ok(()))
                                    } else {
                                        Poll::Pending
                                    }
                                }
                            }
                        })
                        .await?;
                        parked.send_blocking(cx.clone()).unwrap();

                        // No send/flush is polled again. recv must drive the last
                        // accepted write even though its WebSocket buffer is empty.
                        let received = socket.recv(&cx).await?.unwrap();
                        assert!(matches!(received, Message::Text(text) if text == "ack"));
                        assert!(matches!(socket.recv(&cx).await?, Some(Message::Close(_))));
                        socket.finish(&cx).await
                    })
                    .unwrap()
            }
        };
        let mut settings = Settings::client();
        settings.initial_window_size = 0;
        exercise(
            owner,
            handler,
            configuration(Some(1024)),
            settings,
            true,
            move |mut peer, controls| async move {
                let stream = peer.websocket().await;
                peer.upgraded(stream).await;
                let request = parking.recv(&controls.owner).await.unwrap();
                peer.connection
                    .send_stream_window_update(stream, (WIRE_BYTES * 2) as u32)
                    .unwrap();
                peer.flush().await;
                // The peer deliberately sends no message until the entire
                // accepted frame arrives, exposing a lost final-write drive.
                let received = peer.ws_frame(stream).await;
                assert_eq!(received.opcode, Opcode::Binary);
                assert_eq!(received.payload.len(), PAYLOAD_BYTES);
                assert!(received.payload.iter().all(|byte| *byte == 0x6b));
                peer.data(stream, masked(1, b"ack"), false).await;
                peer.data(stream, close_bytes(), false).await;
                assert_close(peer.ws_frame(stream).await);
                peer.clean_end(stream).await;
                assert_eq!(controls.in_flight.load(Ordering::SeqCst), 1);
                peer.data(stream, Bytes::new(), true).await;
                wait_retired(&request, &controls.in_flight).await;
                peer.ordinary(true).await;
                peer
            },
        )
        .await;
    });
}
