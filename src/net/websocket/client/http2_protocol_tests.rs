//! Deterministic wire boundaries for the owned H2 client transport.

use super::*;
use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::http::h2::connection::CLIENT_PREFACE;
use crate::http::h2::frame::{DataFrame, FrameHeader, FrameType, HeadersFrame};
use crate::http::h2::{Frame as H2Frame, FrameCodec as H2Codec, Header};
use crate::io::ReadBuf;
use crate::net::websocket::{CloseCode, Frame as WsFrame, FrameCodec as WsCodec};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, RegionId, TaskId, Time};
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[derive(Default)]
struct State {
    incoming: BytesMut,
    written: Vec<u8>,
    flush_blocked: bool,
    park_after_next_write: bool,
    read_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    drops: usize,
    reads: usize,
    seen_owner: Vec<TaskId>,
}

struct Scripted(Arc<Mutex<State>>);

impl Drop for Scripted {
    fn drop(&mut self) {
        self.0.lock().unwrap().drops += 1;
    }
}

impl AsyncRead for Scripted {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.reads += 1;
        if let Some(owner) = Cx::current() {
            state.seen_owner.push(owner.task_id());
        }
        if state.incoming.is_empty() {
            state.read_waker = Some(task.waker().clone());
            return Poll::Pending;
        }
        let length = buf.remaining().min(state.incoming.len());
        buf.put_slice(&state.incoming.split_to(length));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        if let Some(owner) = Cx::current() {
            state.seen_owner.push(owner.task_id());
        }
        state.written.extend_from_slice(bytes);
        if state.park_after_next_write {
            state.park_after_next_write = false;
            state.flush_blocked = true;
        }
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        if state.flush_blocked {
            state.flush_waker = Some(task.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(task)
    }
}

fn owner(budget: Budget) -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(701, 0),
        budget,
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    );
    (cx, clock, timer)
}

fn limits(tx: u64, rx: u64) -> Http2TunnelConfig {
    Http2TunnelConfig::new(NonZeroU64::new(tx).unwrap(), NonZeroU64::new(rx).unwrap())
}

fn options() -> WebSocketConnectOptions {
    WebSocketConnectOptions::new(
        WebSocketConfig::default()
            .protocol("chat")
            .ping_interval(None)
            .connect_timeout(Some(Duration::from_secs(5))),
    )
    .try_header("Authorization", "Bearer private-credential")
    .unwrap()
}

fn settings(enabled: bool) -> BytesMut {
    let mut wire = BytesMut::new();
    FrameHeader {
        length: 6,
        frame_type: FrameType::Settings as u8,
        flags: 0,
        stream_id: 0,
    }
    .write(&mut wire);
    wire.extend_from_slice(&[0, 8, 0, 0, 0, u8::from(enabled)]);
    wire
}

fn headers(fields: &[(&str, &str)], end: bool) -> BytesMut {
    let mut block = BytesMut::new();
    crate::http::h2::hpack::Encoder::new().encode(
        &fields
            .iter()
            .map(|(name, value)| Header::new(*name, *value))
            .collect::<Vec<_>>(),
        &mut block,
    );
    let mut wire = BytesMut::new();
    H2Frame::Headers(HeadersFrame::new(1, block.freeze(), end, true))
        .encode(&mut wire)
        .unwrap();
    wire
}

fn data(bytes: &[u8], end: bool) -> BytesMut {
    let mut wire = BytesMut::new();
    H2Frame::Data(DataFrame::new(1, Bytes::copy_from_slice(bytes), end))
        .encode(&mut wire)
        .unwrap();
    wire
}

fn feed(state: &Arc<Mutex<State>>, bytes: &[u8]) {
    let wake = {
        let mut state = state.lock().unwrap();
        state.incoming.extend_from_slice(bytes);
        state.read_waker.take()
    };
    if let Some(wake) = wake {
        wake.wake();
    }
}

fn release_flush(state: &Arc<Mutex<State>>) {
    let wake = {
        let mut state = state.lock().unwrap();
        state.flush_blocked = false;
        state.flush_waker.take()
    };
    if let Some(wake) = wake {
        wake.wake();
    }
}

fn scripted(fields: &[(&str, &str)], end: bool) -> (Scripted, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State::default()));
    feed(&state, &settings(true));
    feed(&state, &headers(fields, end));
    (Scripted(Arc::clone(&state)), state)
}

fn complete<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut task = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut task) {
            return output;
        }
    }
    panic!("scripted exchange did not complete in its bounded poll allowance");
}

fn outgoing(state: &Arc<Mutex<State>>) -> Vec<H2Frame> {
    let state = state.lock().unwrap();
    assert!(state.written.starts_with(CLIENT_PREFACE));
    let mut wire = BytesMut::from(&state.written[CLIENT_PREFACE.len()..]);
    let mut codec = H2Codec::new();
    let mut frames = Vec::new();
    while let Some(frame) = codec.decode(&mut wire).unwrap() {
        frames.push(frame);
    }
    assert!(
        wire.is_empty(),
        "only complete writes are admitted by Scripted"
    );
    frames
}

fn server_ws(frame: WsFrame) -> BytesMut {
    let mut bytes = BytesMut::new();
    WsCodec::server().encode(frame, &mut bytes).unwrap();
    bytes
}

#[test]
fn credentials_wait_for_later_permission_and_setup_timer_does_not_limit_the_session() {
    let (cx, clock, timer) = owner(Budget::INFINITE);
    let state = Arc::new(Mutex::new(State::default()));
    feed(&state, &settings(false));
    let client = Http2Client::new().timeout(Duration::from_secs(5));
    let mut opening = Box::pin(Http2ClientWebSocket::connect_on(
        &cx,
        &client,
        "ws://example.invalid/chat?room=7",
        Scripted(Arc::clone(&state)),
        options(),
        limits(1_000_000, 1_000_000),
    ));
    let mut task = Context::from_waker(Waker::noop());
    assert!(opening.as_mut().poll(&mut task).is_pending());
    assert!(
        !outgoing(&state)
            .iter()
            .any(|frame| matches!(frame, H2Frame::Headers(_)))
    );
    assert_eq!(timer.pending_count(), 1);
    feed(&state, &settings(true));
    feed(
        &state,
        &headers(
            &[(":status", "200"), ("sec-websocket-protocol", "chat")],
            false,
        ),
    );
    let mut socket = complete(opening).unwrap();
    complete(socket.inner.io.flush()).unwrap();
    assert_eq!(
        timer.pending_count(),
        0,
        "the successful setup timer is retired, with no MAX timer"
    );
    clock.advance_to(Time::from_secs(60));
    let _ = timer.process_timers();
    let message = server_ws(WsFrame::text("still open"));
    feed(&state, &data(&message, false));
    assert!(
        matches!(complete(socket.recv(&cx)).unwrap(), Some(Message::Text(text)) if text=="still open")
    );
    let requests: Vec<_> = outgoing(&state)
        .into_iter()
        .filter_map(|frame| {
            if let H2Frame::Headers(frame) = frame {
                Some(frame)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(requests.len(), 1);
    let mut block = requests[0].header_block.clone();
    let decoded = crate::http::h2::hpack::Decoder::new()
        .decode(&mut block)
        .unwrap();
    for (name, value) in [
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "http"),
        (":authority", "example.invalid"),
        (":path", "/chat?room=7"),
        ("authorization", "Bearer private-credential"),
        ("sec-websocket-version", "13"),
    ] {
        assert!(decoded.iter().any(|h| h.name == name && h.value == value));
    }
    for forbidden in [
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-accept",
    ] {
        assert!(!decoded.iter().any(|h| h.name == forbidden));
    }
    assert!(
        state
            .lock()
            .unwrap()
            .seen_owner
            .iter()
            .all(|id| *id == cx.task_id())
    );
    drop(socket);
    assert_eq!(state.lock().unwrap().drops, 1);
    assert!(cx.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn successful_connect_ignores_forged_content_length_and_retains_coalesced_data() {
    for declared in ["0", "999999999999999999999999999999", "not-a-length"] {
        let (cx, _, _) = owner(Budget::INFINITE);
        let (io, state) = scripted(
            &[
                (":status", "200"),
                ("content-length", declared),
                ("sec-websocket-accept", "not-an-h1-accept"),
                ("sec-websocket-protocol", "chat"),
            ],
            false,
        );
        let message = server_ws(WsFrame::text("coalesced"));
        feed(&state, &data(&message, false));
        let client = Http2Client::new();
        let mut socket = complete(Http2ClientWebSocket::connect_on(
            &cx,
            &client,
            "ws://example.invalid/",
            io,
            options(),
            limits(1_000_000, 1_000_000),
        ))
        .unwrap();
        assert!(
            matches!(complete(socket.recv(&cx)).unwrap(), Some(Message::Text(text)) if text=="coalesced")
        );
        drop(socket);
        assert_eq!(state.lock().unwrap().drops, 1);
    }
}

#[test]
fn peer_end_without_close_and_http_trailers_never_mint_clean_completion() {
    for trailers in [false, true] {
        let (cx, _, _) = owner(Budget::INFINITE);
        let (io, state) = scripted(&[(":status", "200")], false);
        let client = Http2Client::new();
        let mut socket = complete(Http2ClientWebSocket::connect_on(
            &cx,
            &client,
            "ws://example.invalid/",
            io,
            options(),
            limits(100_000, 100_000),
        ))
        .unwrap();
        if trailers {
            feed(
                &state,
                &headers(&[("x-trailer", "private-credential")], true),
            );
        } else {
            feed(&state, &data(&[], true));
        }
        let error = complete(socket.recv(&cx)).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-credential"));
        assert!(complete(socket.finish(&cx)).is_err());
        assert_eq!(state.lock().unwrap().drops, 1);
        assert!(
            !outgoing(&state)
                .iter()
                .any(|frame| matches!(frame,H2Frame::Data(d) if d.end_stream))
        );
    }
}

#[test]
fn invalid_handshake_selections_are_redacted_and_never_expose_a_socket() {
    for fields in [
        vec![
            (":status", "200"),
            ("sec-websocket-protocol", "private-credential"),
        ],
        vec![
            (":status", "200"),
            ("sec-websocket-protocol", "chat"),
            ("sec-websocket-protocol", "chat"),
        ],
        vec![
            (":status", "200"),
            ("sec-websocket-extensions", "private-credential"),
        ],
        vec![(":status", "200"), ("connection", "private-credential")],
        vec![
            (":status", "302"),
            ("location", "http://private-credential.invalid/"),
        ],
    ] {
        let (cx, _, _) = owner(Budget::INFINITE);
        let (io, state) = scripted(&fields, false);
        let client = Http2Client::new();
        let error = complete(Http2ClientWebSocket::connect_on(
            &cx,
            &client,
            "ws://example.invalid/",
            io,
            options(),
            limits(100_000, 100_000),
        ))
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-credential"));
        assert_eq!(state.lock().unwrap().drops, 1);
    }
}

#[test]
fn invalid_requests_retire_supplied_transport_before_any_io() {
    let (cx, _, _) = owner(Budget::INFINITE);
    let client = Http2Client::new();
    for case in 0..5 {
        let state = Arc::new(Mutex::new(State::default()));
        let io = Scripted(Arc::clone(&state));
        let request = match case {
            0 => client.get("http://example.invalid/"),
            1 => client
                .request(Method::Connect, "http://example.invalid/")
                .body("not allowed"),
            2 => client
                .request(Method::Connect, "http://example.invalid/")
                .header("content-length", "0"),
            3 => client
                .request(Method::Connect, "http://example.invalid/")
                .header("trailer", "x-end"),
            _ => client.request(Method::Connect, "http://example.invalid/"),
        };
        let protocol = if case == 4 {
            "bad protocol"
        } else {
            "websocket"
        };
        assert!(complete(request.connect_tunnel_on(&cx, io, protocol, limits(100, 100))).is_err());
        let state = state.lock().unwrap();
        assert_eq!(state.reads, 0);
        assert!(state.written.is_empty());
        assert_eq!(state.drops, 1);
    }
    let state = Arc::new(Mutex::new(State::default()));
    let io = Scripted(Arc::clone(&state));
    let future = Http2ClientWebSocket::connect_on(
        &cx,
        &client,
        "ws://example.invalid/",
        io,
        options(),
        limits(100, 100),
    );
    drop(future);
    assert_eq!(
        state.lock().unwrap().drops,
        1,
        "unpolled future owns its transport"
    );
}

#[test]
fn flush_waits_for_transport_ack_after_bytes_leave_framed_buffer() {
    let (cx, _, _) = owner(Budget::INFINITE);
    let (io, state) = scripted(&[(":status", "200")], false);
    let mut tunnel = complete(
        Http2Client::new()
            .request(Method::Connect, "http://example.invalid/")
            .connect_tunnel_on(&cx, io, "example", limits(100, 100)),
    )
    .unwrap();
    complete(tunnel.flush()).unwrap();
    state.lock().unwrap().park_after_next_write = true;
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut tunnel).poll_write(&mut task, b"accepted"),
        Poll::Ready(Ok(8))
    ));
    assert!(Pin::new(&mut tunnel).poll_flush(&mut task).is_pending());
    // The transport gate is after write acceptance, not socket writability.
    assert!(state.lock().unwrap().flush_waker.is_some());
    release_flush(&state);
    complete(tunnel.flush()).unwrap();
    let payload: Vec<u8> = outgoing(&state)
        .into_iter()
        .filter_map(|f| {
            if let H2Frame::Data(frame) = f {
                Some(frame.data.to_vec())
            } else {
                None
            }
        })
        .flatten()
        .collect();
    assert_eq!(payload, b"accepted");
    assert_eq!(tunnel.sent_bytes(), 8);
    drop(tunnel);
    assert_eq!(state.lock().unwrap().drops, 1);
}

#[test]
fn receive_resumes_final_accepted_websocket_write_without_replaying_bytes() {
    let (cx, _, _) = owner(Budget::INFINITE);
    let (io, state) = scripted(&[(":status", "200")], false);
    let client = Http2Client::new();
    let mut socket = complete(Http2ClientWebSocket::connect_on(
        &cx,
        &client,
        "ws://example.invalid/",
        io,
        options(),
        limits(100_000, 100_000),
    ))
    .unwrap();
    complete(socket.inner.io.flush()).unwrap();
    let mut zero_window = BytesMut::new();
    H2Frame::Settings(crate::http::h2::frame::SettingsFrame::new(vec![
        crate::http::h2::Setting::InitialWindowSize(0),
    ]))
    .encode(&mut zero_window)
    .unwrap();
    feed(&state, &zero_window);
    {
        let mut send = Box::pin(socket.send(&cx, Message::text("one message")));
        assert!(
            send.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(
        socket.inner.write_buf.is_empty(),
        "the final accepted write lives in the tunnel"
    );
    assert!(
        !outgoing(&state)
            .iter()
            .any(|f| matches!(f, H2Frame::Data(_))),
        "the final accepted frame is parked behind stream credit"
    );
    let mut credit = BytesMut::new();
    H2Frame::WindowUpdate(crate::http::h2::frame::WindowUpdateFrame::new(1, 1024))
        .encode(&mut credit)
        .unwrap();
    feed(&state, &credit);
    let reply = server_ws(WsFrame::text("reply"));
    feed(&state, &data(&reply, false));
    assert!(
        matches!(complete(socket.recv(&cx)).unwrap(),Some(Message::Text(text)) if text=="reply")
    );
    let payload: Vec<u8> = outgoing(&state)
        .into_iter()
        .filter_map(|f| {
            if let H2Frame::Data(frame) = f {
                Some(frame.data.to_vec())
            } else {
                None
            }
        })
        .flatten()
        .collect();
    let mut payload = BytesMut::from(payload.as_slice());
    let mut decoder = WsCodec::server();
    let frame = decoder.decode(&mut payload).unwrap().unwrap();
    assert_eq!(frame.payload.as_ref(), b"one message");
    assert!(payload.is_empty(), "only one masked message was written");
}

#[test]
fn close_receipt_survives_dropped_drain_and_uses_original_deadline() {
    for expire in [false, true] {
        let (cx, clock, timer) = owner(Budget::INFINITE);
        let (io, state) = scripted(&[(":status", "200")], false);
        let client = Http2Client::new();
        let mut config = WebSocketConfig::default().ping_interval(None);
        config.close_config.close_timeout = Duration::from_secs(5);
        let mut socket = complete(Http2ClientWebSocket::connect_on(
            &cx,
            &client,
            "ws://example.invalid/",
            io,
            WebSocketConnectOptions::new(config),
            limits(100_000, 100_000),
        ))
        .unwrap();
        let close = server_ws(CloseReason::with_text(CloseCode::Normal, "saved").to_frame());
        feed(&state, &data(&close, false));
        {
            let mut receive = Box::pin(socket.recv(&cx));
            assert!(
                receive
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        assert!(
            socket.pending_close.is_some(),
            "peer Close is retained while server END is pending"
        );
        assert!(
            !outgoing(&state)
                .iter()
                .any(|f| matches!(f,H2Frame::Data(d) if d.end_stream))
        );
        clock.advance_to(Time::from_secs(if expire { 5 } else { 4 }));
        let _ = timer.process_timers();
        feed(&state, &data(&[], true));
        if expire {
            assert!(
                matches!(complete(socket.recv(&cx)),Err(WsError::Io(e)) if e.kind()==io::ErrorKind::TimedOut)
            );
            assert!(
                !outgoing(&state)
                    .iter()
                    .any(|f| matches!(f,H2Frame::Data(d) if d.end_stream))
            );
        } else {
            assert!(
                matches!(complete(socket.recv(&cx)).unwrap(),Some(Message::Close(Some(r))) if r.text.as_deref()==Some("saved"))
            );
            assert!(complete(socket.recv(&cx)).unwrap().is_none());
            assert!(socket.is_closed());
            assert_eq!(
                outgoing(&state)
                    .iter()
                    .filter(|f| matches!(f,H2Frame::Data(d) if d.end_stream))
                    .count(),
                1
            );
            complete(socket.finish(&cx)).unwrap();
        }
        assert_eq!(state.lock().unwrap().drops, 1);
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }
}

#[test]
fn explicit_lifetime_byte_limits_and_owner_deadline_still_retire_the_tunnel() {
    for receive in [false, true] {
        let (cx, _, _) = owner(Budget::INFINITE);
        let (io, state) = scripted(&[(":status", "200")], false);
        let mut tunnel = complete(
            Http2Client::new()
                .request(Method::Connect, "http://example.invalid/")
                .connect_tunnel_on(&cx, io, "example", limits(2, 2)),
        )
        .unwrap();
        if receive {
            feed(&state, &data(b"abc", false));
            let mut bytes = [0; 3];
            assert!(complete(tunnel.read(&mut bytes)).is_err());
        } else {
            assert!(complete(tunnel.write_all(b"abc")).is_err());
        }
        assert_eq!(state.lock().unwrap().drops, 1);
    }
    let (cx, clock, timer) = owner(Budget::INFINITE.with_deadline(Time::from_secs(10)));
    let (io, state) = scripted(&[(":status", "200")], false);
    let mut tunnel = complete(
        Http2Client::new()
            .timeout(Duration::from_secs(2))
            .request(Method::Connect, "http://example.invalid/")
            .connect_tunnel_on(&cx, io, "example", limits(100, 100)),
    )
    .unwrap();
    clock.advance_to(Time::from_secs(9));
    complete(tunnel.write_all(b"live")).unwrap();
    assert_eq!(timer.next_deadline(), Some(Time::from_secs(10)));
    clock.advance_to(Time::from_secs(10));
    let _ = timer.process_timers();
    assert!(matches!(complete(tunnel.flush()),Err(e) if e.kind()==io::ErrorKind::TimedOut));
    assert_eq!(state.lock().unwrap().drops, 1);
}

#[cfg(feature = "tls")]
#[test]
fn native_wss_refuses_negotiated_http1_before_any_preface_or_credentials() {
    use crate::net::TcpListener;
    use crate::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    const CERT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.crt"
    ));
    const KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.key"
    ));
    super::tests::native(|driver, owner| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(CERT).unwrap(),
            PrivateKey::from_pem(KEY).unwrap(),
        )
        .alpn_protocols_required(vec![b"http/1.1".to_vec()])
        .build()
        .unwrap();
        let mut peer = driver
            .spawn(move |_cx| async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(stream).await.unwrap();
                assert_eq!(tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
                let mut byte = [0; 1];
                match tls.read(&mut byte).await {
                    Ok(0) | Err(_) => {}
                    other => {
                        panic!("unexpected application bytes before h2 ALPN validation: {other:?}")
                    }
                }
            })
            .unwrap();
        let root = Certificate::from_pem(CERT).unwrap().remove(0);
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&root)
            .alpn_http()
            .build()
            .unwrap();
        let client = Http2Client::new()
            .timeout(Duration::from_secs(5))
            .tls_connector(connector);
        let error = Http2ClientWebSocket::connect(
            &owner,
            &client,
            &format!("wss://localhost:{}/", address.port()),
            options(),
            limits(100_000, 100_000),
        )
        .await
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-credential"));
        peer.join(&driver).await.unwrap();
    });
}
