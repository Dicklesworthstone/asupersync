//! Per-peer response retention exercised through actual TLS and loopback UDP.
#![cfg(test)]

use super::{NativeH3Listener, NativeH3ListenerConfig};
use crate::bytes::Bytes;
use crate::channel::oneshot;
use crate::cx::Cx;
use crate::http::h3_native::{H3PseudoHeaders, H3RequestHead, H3ResponseHead, H3Settings};
use crate::http::h3_quic::{H3_REQUEST_CANCELLED, NativeH3Event, NativeH3Session};
use crate::net::quic_core::{ConnectionId, TransportParameters};
use crate::net::quic_native::handshake_driver::{
    QuicHandshakeDriver, client_config, server_config,
};
use crate::net::quic_native::{
    NativeQuicConnectionConfig, NativeQuicUdpConnection, QuicUdpEndpoint,
    QuicUdpEndpointConfig, StreamId,
};
use crate::web::{FnHandler, Response, Router, StatusCode, post};
use futures_lite::future::zip;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::collections::BTreeSet;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_POLL: Duration = Duration::from_millis(20);
const WINDOW: u64 = 64;
const BODY_BYTES: usize = 512;

fn parameters(config: NativeQuicConnectionConfig) -> Vec<u8> {
    let parameters = TransportParameters {
        max_udp_payload_size: Some(1_200),
        initial_max_data: Some(config.connection_recv_limit),
        initial_max_stream_data_bidi_local: Some(config.recv_window),
        initial_max_stream_data_bidi_remote: Some(config.recv_window),
        initial_max_stream_data_uni: Some(config.recv_window),
        initial_max_streams_bidi: Some(config.max_local_bidi),
        initial_max_streams_uni: Some(config.max_local_uni),
        disable_active_migration: true,
        ..TransportParameters::default()
    };
    let mut encoded = Vec::new();
    parameters.encode(&mut encoded).unwrap();
    encoded
}

fn certificate(pem: &str) -> CertificateDer<'static> {
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}

fn events(
    cx: &Cx,
    session: &mut NativeH3Session,
    owner: &mut NativeQuicUdpConnection,
) -> Vec<NativeH3Event> {
    let mut events = Vec::new();
    while let Some(event) = session.next_event(cx, owner.connection_mut()).unwrap() {
        events.push(event);
    }
    events
}

async fn connect(
    cx: &Cx,
    address: SocketAddr,
    peer: u8,
    config: NativeQuicConnectionConfig,
    ca: CertificateDer<'static>,
) -> (NativeQuicUdpConnection, NativeH3Session) {
    connect_with_settings(cx, address, peer, config, ca, H3Settings::default()).await
}

async fn connect_with_settings(
    cx: &Cx,
    address: SocketAddr,
    peer: u8,
    config: NativeQuicConnectionConfig,
    ca: CertificateDer<'static>,
    expected: H3Settings,
) -> (NativeQuicUdpConnection, NativeH3Session) {
    let socket = QuicUdpEndpoint::bind(
        cx,
        "127.0.0.1:0".parse().unwrap(),
        QuicUdpEndpointConfig::default(),
    )
    .await
    .unwrap();
    let driver = QuicHandshakeDriver::client(
        client_config(vec![ca], vec![b"h3".to_vec()]).unwrap(),
        ServerName::try_from("localhost").unwrap(),
        parameters(config),
    )
    .unwrap();
    let mut owner = NativeQuicUdpConnection::connect(
        cx,
        socket,
        address,
        driver,
        ConnectionId::new(format!("isolate-initial-{peer}").as_bytes()).unwrap(),
        ConnectionId::new(format!("isolate-client-{peer}").as_bytes()).unwrap(),
        config,
        b"h3",
    )
    .await
    .unwrap();
    assert_eq!(owner.negotiated_alpn(), b"h3");
    let mut session = NativeH3Session::client();
    session
        .initialize(cx, owner.connection_mut(), H3Settings::default())
        .unwrap();
    owner.flush(cx).await.unwrap();
    loop {
        owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
        let ready = events(cx, &mut session, &mut owner);
        if !ready.is_empty() {
            assert_eq!(ready, vec![NativeH3Event::Settings(expected)]);
            break;
        }
    }
    (owner, session)
}

async fn request(
    cx: &Cx,
    owner: &mut NativeQuicUdpConnection,
    session: &mut NativeH3Session,
    path: &str,
) -> StreamId {
    let head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_owned()),
            scheme: Some("https".to_owned()),
            authority: Some("localhost".to_owned()),
            path: Some(path.to_owned()),
            ..H3PseudoHeaders::default()
        },
        Vec::new(),
    )
    .unwrap();
    let stream = session
        .send_request(cx, owner.connection_mut(), &head, Bytes::new())
        .unwrap();
    owner.flush(cx).await.unwrap();
    stream
}

async fn response(
    cx: &Cx,
    owner: &mut NativeQuicUdpConnection,
    session: &mut NativeH3Session,
    stream: StreamId,
    expected: &[u8],
) {
    let mut head = None;
    let mut body = Vec::new();
    let mut finished = false;
    while !finished {
        owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
        for event in events(cx, session, owner) {
            match event {
                NativeH3Event::ResponseHeaders { stream_id, head: value } => {
                    assert_eq!(stream_id, stream);
                    assert!(head.replace(value).is_none());
                }
                NativeH3Event::Data { stream_id, bytes } => {
                    assert_eq!(stream_id, stream);
                    assert!(!finished);
                    body.extend_from_slice(&bytes);
                    assert!(body.len() <= expected.len());
                }
                NativeH3Event::Finished { stream_id } => {
                    assert_eq!(stream_id, stream);
                    assert!(!finished);
                    finished = true;
                }
                other => panic!("unexpected response event: {other:?}"),
            }
        }
    }
    assert_eq!(head, Some(H3ResponseHead::new(200, Vec::new()).unwrap()));
    assert_eq!(body, expected);
    owner.flush(cx).await.unwrap();
}

async fn reset(cx: &Cx, owner: &mut NativeQuicUdpConnection, stream: StreamId) -> u64 {
    loop {
        if let Some((code, final_size)) = owner
            .connection()
            .inner()
            .streams()
            .stream(stream)
            .unwrap()
            .recv_reset
        {
            assert_eq!(code, H3_REQUEST_CANCELLED);
            return final_size;
        }
        owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
    }
}

async fn acknowledge_goaway(
    cx: &Cx,
    owner: &mut NativeQuicUdpConnection,
    session: &mut NativeH3Session,
    expected: u64,
) {
    loop {
        owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
        let mut received = false;
        for event in events(cx, session, owner) {
            match event {
                NativeH3Event::Goaway(id) => {
                    assert_eq!(id, expected);
                    assert!(!received);
                    received = true;
                }
                other => panic!("unexpected shutdown event: {other:?}"),
            }
        }
        owner.flush(cx).await.unwrap();
        if received {
            return;
        }
    }
}

/// Keep both clients reading and acknowledging until the listener has drained.
///
/// A connection drains only after its peer acknowledges the final packets;
/// `drain_timeout` bounds a peer that went away. A client that stopped reading
/// at GOAWAY left its acknowledgement unsent: 320 bytes stayed in flight on the
/// held peer and the buffered ingress drain timed out (br-asupersync-psoqxr).
async fn acknowledge_until_drained(
    cx: &Cx,
    first: &mut NativeQuicUdpConnection,
    second: &mut NativeQuicUdpConnection,
    drained: &AtomicBool,
) {
    while !drained.load(Ordering::SeqCst) {
        for owner in [&mut *first, &mut *second] {
            owner.drive_io_once(cx, ACK_POLL).await.unwrap();
            owner.flush(cx).await.unwrap();
        }
    }
}

#[test]
fn native_buffered_listener_isolates_response_retention_and_reuses_cancelled_credit() {
    run_isolation(false);
}

#[test]
fn native_streaming_listener_isolates_response_retention_and_reuses_cancelled_credit() {
    run_isolation(true);
}

fn run_isolation(streaming: bool) {
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .with_reactor(crate::runtime::reactor::create_reactor().expect("native reactor"))
        .build()
        .unwrap();
    let parent: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
        let cx = Cx::current().unwrap();
        let identities: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atp_native_auth_identities.json"
        )))
        .unwrap();
        let server = &identities["identities"]["server"];
        let cert = certificate(server["certificate"].as_str().unwrap());
        let ca = certificate(identities["ca"].as_str().unwrap());
        let key = PrivateKeyDer::pem_reader_iter(&mut BufReader::new(
            server["key"].as_str().unwrap().as_bytes(),
        ))
        .next()
        .unwrap()
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new().without_default_trace();
        for (path, value) in [("/held", 1), ("/denied", 2), ("/survivor", 3)] {
            let calls = Arc::clone(&calls);
            router = router.route(
                path,
                post(FnHandler::new(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::OK, Bytes::from(vec![value; BODY_BYTES]))
                })),
            );
        }
        let recovery_calls = Arc::clone(&calls);
        router = router.route(
            "/recovered",
            post(FnHandler::new(move || {
                recovery_calls.fetch_add(1, Ordering::SeqCst);
                Response::new(StatusCode::OK, Bytes::from_static(b"recovered"))
            })),
        );
        let transport = NativeQuicConnectionConfig {
            max_local_bidi: 8,
            max_local_uni: 8,
            connection_recv_limit: 4 << 20,
            ..NativeQuicConnectionConfig::default()
        };
        let mut config = NativeH3ListenerConfig::default();
        config.endpoint.max_connections = 2;
        config.endpoint.connection_config = transport;
        config.max_requests_per_connection = 8;
        config.max_buffered_response_bytes = BODY_BYTES;
        config.max_total_buffered_response_bytes = BODY_BYTES * 2;
        config.max_buffered_response_bytes_per_connection = Some(BODY_BYTES);
        if streaming {
            config.streaming_request_body_buffer_bytes = std::num::NonZeroUsize::new(64);
        }
        let listener = NativeH3Listener::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            router,
            server_config(vec![cert], key, vec![b"h3".to_vec()]).unwrap(),
            parameters(transport),
            config,
        )
        .await
        .unwrap();
        let address = listener.local_addr();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let drained = AtomicBool::new(false);
        let serving = async {
            let report = listener
                .serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                })
                .await;
            drained.store(true, Ordering::SeqCst);
            report
        };
        let clients = async {
            let slow_config = NativeQuicConnectionConfig {
                recv_window: WINDOW,
                ..transport
            };
            let (mut slow, mut slow_h3) = connect(&cx, address, 1, slow_config, ca.clone()).await;
            let (mut survivor, mut survivor_h3) = connect(&cx, address, 2, transport, ca).await;
            let held = request(&cx, &mut slow, &mut slow_h3, "/held").await;
            assert_eq!(held, StreamId(0));
            loop {
                let state = slow.connection().inner().streams().stream(held).unwrap();
                assert_eq!(state.read_offset, 0, "do not consume or replenish the held body");
                assert_eq!(state.recv_credit.limit(), WINDOW);
                assert!(state.final_size.is_none() && state.recv_reset.is_none());
                if state.recv_offset == WINDOW {
                    break;
                }
                slow.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            cx.trace_with_fields("http3.response_peer_budget.parked", &[
                ("streaming", if streaming { "true" } else { "false" }),
                ("received_bytes", "64"),
                ("consumed_bytes", "0"),
                ("fin_received", "false"),
            ]);

            // There is still BODY_BYTES of free global capacity, but this
            // peer must not reserve a second backing while its first is held.
            let denied = request(&cx, &mut slow, &mut slow_h3, "/denied").await;
            assert_eq!(denied, StreamId(4));
            assert_eq!(reset(&cx, &mut slow, denied).await, 0);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let served = request(&cx, &mut survivor, &mut survivor_h3, "/survivor").await;
            assert_eq!(served, StreamId(0));
            response(&cx, &mut survivor, &mut survivor_h3, served, &[3; BODY_BYTES]).await;
            let held_state = slow.connection().inner().streams().stream(held).unwrap();
            assert_eq!(held_state.read_offset, 0);
            assert_eq!(held_state.recv_offset, WINDOW);
            assert!(held_state.final_size.is_none() && held_state.recv_reset.is_none());

            // Cancel over the wire. The server must drop the retained response
            // and both accounting charges; a return value alone is no witness.
            slow.connection_mut()
                .stop_stream_receiving(&cx, held, H3_REQUEST_CANCELLED)
                .unwrap();
            slow.flush(&cx).await.unwrap();
            assert!(reset(&cx, &mut slow, held).await <= WINDOW);
            let mut terminal_streams = BTreeSet::new();
            for event in events(&cx, &mut slow_h3, &mut slow) {
                match event {
                    NativeH3Event::StreamReset { stream_id, error_code, .. } => {
                        assert!(stream_id == held || stream_id == denied);
                        assert_eq!(error_code, H3_REQUEST_CANCELLED);
                        assert!(terminal_streams.insert(stream_id));
                    }
                    other => panic!("retired responses must not publish bytes or FIN: {other:?}"),
                }
            }
            let recovered = request(&cx, &mut slow, &mut slow_h3, "/recovered").await;
            assert_eq!(recovered, StreamId(8));
            response(&cx, &mut slow, &mut slow_h3, recovered, b"recovered").await;
            assert_eq!(calls.load(Ordering::SeqCst), 4);
            cx.trace_with_fields("http3.response_peer_budget.recovered", &[
                ("survivor_body", "exact_512_bytes"),
                ("same_peer_recovery_body", "recovered"),
                ("denied_response", "reset_before_headers"),
            ]);
            shutdown_tx.send(&cx, ()).unwrap();
            zip(
                acknowledge_goaway(&cx, &mut slow, &mut slow_h3, 12),
                acknowledge_goaway(&cx, &mut survivor, &mut survivor_h3, 4),
            )
            .await;
            acknowledge_until_drained(&cx, &mut slow, &mut survivor, &drained).await;
        };
        let (report, ()) = crate::time::timeout(
            cx.now(),
            Duration::from_secs(20),
            zip(serving, clients),
        )
        .await
        .expect("peer isolation and same-peer recovery must complete over native UDP");
        let report = report.unwrap();
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.failed_connections, 0);
        assert_eq!(report.completed_requests, 2);
        assert_eq!(report.cancelled_requests, 2);
        assert_eq!(report.refused_requests, 0);
        assert_eq!(report.failed_request_cleanups, 0);
        assert_eq!(report.rejected_buffered_responses, 1);
        assert_eq!(report.rejected_connection_buffered_responses, 1);
        assert_eq!(report.peak_buffered_response_bytes, BODY_BYTES * 2);
        assert!(!report.drain_timed_out);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
    });
    runtime.block_on(runtime.handle().spawn(parent));
    assert_eq!(runtime.draining_region_count(), 0);
}

#[test]
fn native_buffered_ingress_budget_covers_partial_headers_and_owned_cleanup() {
    run_ingress_budget(false);
}

#[test]
fn native_streaming_ingress_budget_covers_partial_headers_and_owned_cleanup() {
    run_ingress_budget(true);
}

async fn expect_ingress_refusal(
    cx: &Cx,
    owner: &mut NativeQuicUdpConnection,
    session: &mut NativeH3Session,
    expected_stream: StreamId,
) {
    loop {
        let mut refused = false;
        for event in events(cx, session, owner) {
            match event {
                NativeH3Event::StreamReset {
                    stream_id,
                    error_code,
                    final_size,
                } => {
                    assert_eq!(stream_id, expected_stream);
                    assert_eq!(error_code, crate::http::h3_quic::H3_REQUEST_REJECTED);
                    assert_eq!(final_size, 0, "no response bytes before admission refusal");
                    assert!(!refused, "one terminal notification per rejected stream");
                    refused = true;
                }
                other => panic!("ingress budget must reject before a response: {other:?}"),
            }
        }
        owner.flush(cx).await.unwrap();
        if refused {
            return;
        }
        owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
    }
}

fn run_ingress_budget(streaming: bool) {
    use crate::http::h3_native::{H3Frame, qpack_encode_request_field_section};
    use crate::web::AsyncCxFnHandler;
    use std::task::Poll;

    const SERVER_RECEIVE_WINDOW: u64 = 128;
    const QUEUE_BYTES: usize = 64;
    let reservation_bytes = if streaming { QUEUE_BYTES * 2 } else { BODY_BYTES };
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .with_reactor(crate::runtime::reactor::create_reactor().expect("native reactor"))
        .build()
        .unwrap();
    let parent: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
        let cx = Cx::current().unwrap();
        let identities: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atp_native_auth_identities.json"
        )))
        .unwrap();
        let server = &identities["identities"]["server"];
        let cert = certificate(server["certificate"].as_str().unwrap());
        let ca = certificate(identities["ca"].as_str().unwrap());
        let key = PrivateKeyDer::pem_reader_iter(&mut BufReader::new(
            server["key"].as_str().unwrap().as_bytes(),
        ))
        .next()
        .unwrap()
        .unwrap();
        let held_region = Arc::new(std::sync::Mutex::new(None));
        let calls = Arc::new(AtomicUsize::new(0));
        let denied_calls = Arc::new(AtomicUsize::new(0));
        let handler_region = Arc::clone(&held_region);
        let handler_calls = Arc::clone(&calls);
        let forbidden_calls = Arc::clone(&denied_calls);
        let survivor_calls = Arc::clone(&calls);
        let router = Router::new()
            .route(
                "/ingress-held",
                post(AsyncCxFnHandler::new(move |request_cx: Cx| {
                    let region = Arc::clone(&handler_region);
                    let calls = Arc::clone(&handler_calls);
                    async move {
                        assert!(region.lock().unwrap().replace(request_cx.region_id()).is_none());
                        calls.fetch_add(1, Ordering::SeqCst);
                        Response::new(StatusCode::OK, Bytes::from(vec![7; BODY_BYTES]))
                    }
                })),
            )
            .route(
                "/ingress-denied",
                post(FnHandler::new(move || {
                    forbidden_calls.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::OK, "must not dispatch")
                })),
            )
            .route(
                "/ingress-survivor",
                post(FnHandler::new(move || {
                    survivor_calls.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::OK, Bytes::from(vec![9; BODY_BYTES]))
                })),
            )
            .without_default_trace();
        let transport = NativeQuicConnectionConfig {
            max_local_bidi: 8,
            max_local_uni: 8,
            recv_window: WINDOW,
            connection_recv_limit: 4 << 20,
            ..NativeQuicConnectionConfig::default()
        };
        let mut config = NativeH3ListenerConfig::default();
        config.endpoint.max_connections = 2;
        config.endpoint.connection_config = transport;
        config.max_requests_per_connection = 8;
        config.receive_window_bytes = SERVER_RECEIVE_WINDOW;
        config.router = config
            .router
            .max_buffered_body_bytes(BODY_BYTES)
            .max_total_buffered_body_bytes(BODY_BYTES * 4);
        // Neither the per-connection body pool nor the request-count limits
        // can cause these refusals. Only one listener-wide reservation fits.
        config.max_total_request_body_reservation_bytes = Some(reservation_bytes);
        if streaming {
            config.streaming_request_body_buffer_bytes = std::num::NonZeroUsize::new(QUEUE_BYTES);
        }
        let listener = NativeH3Listener::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            router,
            server_config(vec![cert], key, vec![b"h3".to_vec()]).unwrap(),
            parameters(transport),
            config,
        )
        .await
        .unwrap();
        let address = listener.local_addr();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let drained = AtomicBool::new(false);
        let serving = async {
            let report = listener
                .serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                })
                .await;
            drained.store(true, Ordering::SeqCst);
            report
        };
        let clients = async {
            let (mut held, mut held_h3) = connect(&cx, address, 11, transport, ca.clone()).await;
            let survivor_config = NativeQuicConnectionConfig {
                recv_window: 4_096,
                ..transport
            };
            let (mut survivor, mut survivor_h3) =
                connect(&cx, address, 12, survivor_config, ca).await;
            let stream = held.connection_mut().open_bidi_stream(&cx).unwrap();
            assert_eq!(stream, StreamId(0));
            assert_eq!(
                held.connection().inner().streams().stream(stream).unwrap().send_credit.limit(),
                WINDOW
            );
            let head = H3RequestHead::new(
                H3PseudoHeaders {
                    method: Some("POST".to_owned()),
                    scheme: Some("https".to_owned()),
                    authority: Some("localhost".to_owned()),
                    path: Some("/ingress-held".to_owned()),
                    ..H3PseudoHeaders::default()
                },
                // An explicit zero length must not exempt this stream from
                // its whole-request reservation or release it before cleanup.
                vec![("content-length".to_owned(), "0".to_owned())],
            )
            .unwrap();
            let mut wire = Vec::new();
            H3Frame::Headers(qpack_encode_request_field_section(&head).unwrap())
                .encode(&mut wire)
                .unwrap();
            assert!(wire.len() > 1 && wire.len() <= SERVER_RECEIVE_WINDOW as usize);
            held.connection_mut()
                .write_stream(&cx, stream, Bytes::copy_from_slice(&wire[..1]), false)
                .unwrap();
            held.flush(&cx).await.unwrap();
            loop {
                let state = held.connection().inner().streams().stream(stream).unwrap();
                assert_eq!(state.send_offset, 1);
                assert!(state.recv_reset.is_none() && state.final_size.is_none());
                if state.send_credit.limit() >= SERVER_RECEIVE_WINDOW {
                    break;
                }
                held.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
                assert!(events(&cx, &mut held_h3, &mut held).is_empty());
            }
            // MAX_STREAM_DATA > the authenticated initial allowance proves
            // the actual listener observed/admitted this one-byte partial head.
            // It is stronger than a sleep, a sent packet, or a transport ACK.
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(held_region.lock().unwrap().is_none());
            cx.trace_with_fields("http3.ingress_budget.partial_head", &[
                ("streaming", if streaming { "true" } else { "false" }),
                ("request_bytes_sent", "1"),
                ("handler_calls", "0"),
                ("admission_witness", "max_stream_data_above_initial"),
            ]);
            let first_denied = request(
                &cx, &mut survivor, &mut survivor_h3, "/ingress-denied",
            ).await;
            assert_eq!(first_denied, stream, "different peers reuse the same stream ID");
            expect_ingress_refusal(&cx, &mut survivor, &mut survivor_h3, first_denied).await;
            assert_eq!(denied_calls.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);

            held.connection_mut()
                .write_stream(&cx, stream, Bytes::copy_from_slice(&wire[1..]), true)
                .unwrap();
            held.flush(&cx).await.unwrap();
            loop {
                let state = held.connection().inner().streams().stream(stream).unwrap();
                assert_eq!(state.read_offset, 0);
                assert_eq!(state.recv_credit.limit(), WINDOW);
                assert!(state.recv_reset.is_none() && state.final_size.is_none());
                if state.recv_offset == WINDOW {
                    break;
                }
                held.drive_io_once(&cx, IO_TIMEOUT).await.unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let region = held_region.lock().unwrap().expect("the actual request region ran");
            assert!(crate::runtime::Runtime::current_handle().unwrap()
                .diagnostics().unwrap().explain_region_open(region).region_state.is_some());
            // The upload is finished, but its region still owns a flow-blocked
            // response. Returning ingress credit at request FIN would admit this.
            let second_denied = request(
                &cx, &mut survivor, &mut survivor_h3, "/ingress-denied",
            ).await;
            assert_eq!(second_denied, StreamId(4));
            expect_ingress_refusal(&cx, &mut survivor, &mut survivor_h3, second_denied).await;
            assert_eq!(denied_calls.load(Ordering::SeqCst), 0);
            cx.trace_with_fields("http3.ingress_budget.owned_response", &[
                ("response_received_bytes", "64"),
                ("response_consumed_bytes", "0"),
                ("refused_requests", "2"),
                ("denied_handler_calls", "0"),
            ]);

            held.connection_mut()
                .stop_stream_receiving(&cx, stream, H3_REQUEST_CANCELLED).unwrap();
            held.flush(&cx).await.unwrap();
            assert!(reset(&cx, &mut held, stream).await <= WINDOW);
            let retired = events(&cx, &mut held_h3, &mut held);
            assert_eq!(retired.len(), 1);
            assert!(matches!(&retired[0], NativeH3Event::StreamReset {
                stream_id, error_code, ..
            } if *stream_id == stream && *error_code == H3_REQUEST_CANCELLED));
            let mut closed_seen = false;
            std::future::poll_fn(|task_cx| {
                let closed = crate::runtime::Runtime::current_handle().unwrap()
                    .diagnostics().unwrap().explain_region_open(region).region_state.is_none();
                if closed && closed_seen {
                    return Poll::Ready(());
                }
                closed_seen = closed;
                // The paired listener is polled on each turn. After observing
                // actual region retirement, give its owner-reap pass a turn
                // before testing admission; a wire reset alone is insufficient.
                task_cx.waker().wake_by_ref();
                Poll::Pending
            }).await;
            let served = request(
                &cx, &mut survivor, &mut survivor_h3, "/ingress-survivor",
            ).await;
            assert_eq!(served, StreamId(8));
            response(&cx, &mut survivor, &mut survivor_h3, served, &[9; BODY_BYTES]).await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(denied_calls.load(Ordering::SeqCst), 0);
            shutdown_tx.send(&cx, ()).unwrap();
            zip(
                acknowledge_goaway(&cx, &mut held, &mut held_h3, 4),
                acknowledge_goaway(&cx, &mut survivor, &mut survivor_h3, 12),
            ).await;
            acknowledge_until_drained(&cx, &mut held, &mut survivor, &drained).await;
        };
        let (report, ()) = crate::time::timeout(
            cx.now(), Duration::from_secs(20), zip(serving, clients),
        ).await.expect("shared ingress admission and cleanup must make native UDP progress");
        let report = report.unwrap();
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.failed_connections, 0);
        assert_eq!(report.completed_requests, 1);
        assert_eq!(report.cancelled_requests, 1);
        assert_eq!(report.refused_requests, 2);
        assert_eq!(report.rejected_request_body_reservations, 2);
        assert_eq!(report.peak_reserved_request_body_bytes, reservation_bytes);
        assert_eq!(report.failed_request_cleanups, 0);
        assert_eq!(report.rejected_buffered_responses, 0);
        assert!(!report.drain_timed_out);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
    });
    runtime.block_on(runtime.handle().spawn(parent));
    assert_eq!(runtime.draining_region_count(), 0);
}

mod field_section_limits {
    use super::*;
    use crate::http::h3_native::{H3Frame, qpack_encode_request_field_section};
    use crate::net::quic_core::QUIC_VARINT_MAX;
    use crate::net::quic_native::ManagedEndpointError;
    use crate::runtime::{RootDrainOutcome, Runtime};
    use crate::web::{AsyncCxFnHandler, NativeH3ListenerError};
    use std::task::Poll;

    const FIELD_LIMIT: u64 = 256;
    const SERVER_RECEIVE_WINDOW: u64 = 4_096;

    fn identity() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
        let identities: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atp_native_auth_identities.json"
        )))
        .unwrap();
        let server = &identities["identities"]["server"];
        let cert = certificate(server["certificate"].as_str().unwrap());
        let ca = certificate(identities["ca"].as_str().unwrap());
        let key = PrivateKeyDer::pem_reader_iter(&mut BufReader::new(
            server["key"].as_str().unwrap().as_bytes(),
        ))
        .next()
        .unwrap()
        .unwrap();
        (server_config(vec![cert], key, vec![b"h3".to_vec()]).unwrap(), ca)
    }

    fn field_head(extra: usize) -> Vec<u8> {
        // RFC field sizes: :method=43, :scheme=44, :authority=51,
        // :path=46, x-pad=37+35. The five fields total exactly 256 bytes,
        // independent of how QPACK compresses their wire representation.
        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_owned()),
                scheme: Some("https".to_owned()),
                authority: Some("localhost".to_owned()),
                path: Some("/field-ok".to_owned()),
                ..H3PseudoHeaders::default()
            },
            vec![("x-pad".to_owned(), "p".repeat(35 + extra))],
        )
        .unwrap();
        let mut wire = Vec::new();
        H3Frame::Headers(qpack_encode_request_field_section(&head).unwrap())
            .encode(&mut wire)
            .unwrap();
        assert!(wire.len() > 1);
        assert!(u64::try_from(wire.len()).unwrap() <= SERVER_RECEIVE_WINDOW);
        wire
    }

    async fn partial_head(
        cx: &Cx,
        owner: &mut NativeQuicUdpConnection,
        session: &mut NativeH3Session,
        wire: &[u8],
    ) -> StreamId {
        // Use the raw allocator consistently on this client, including its
        // later recovery request. Mixing it with send_request's allocator
        // would itself be an invalid session composition.
        let stream = owner.connection_mut().open_bidi_stream(cx).unwrap();
        assert_eq!(
            owner.connection().inner().streams().stream(stream).unwrap().send_credit.limit(),
            WINDOW
        );
        owner.connection_mut()
            .write_stream(cx, stream, Bytes::copy_from_slice(&wire[..1]), false)
            .unwrap();
        owner.flush(cx).await.unwrap();
        loop {
            let state = owner.connection().inner().streams().stream(stream).unwrap();
            assert_eq!(state.send_offset, 1);
            assert!(state.recv_reset.is_none() && state.final_size.is_none());
            if state.send_credit.limit() >= SERVER_RECEIVE_WINDOW {
                return stream;
            }
            owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
            assert!(events(cx, session, owner).is_empty());
        }
    }

    async fn field_refusal(
        cx: &Cx,
        owner: &mut NativeQuicUdpConnection,
        session: &mut NativeH3Session,
        stream: StreamId,
    ) {
        loop {
            let ready = events(cx, session, owner);
            if !ready.is_empty() {
                assert_eq!(ready, vec![NativeH3Event::StreamReset {
                    stream_id: stream,
                    error_code: 0x107,
                    final_size: 0,
                }]);
                let state = owner.connection().inner().streams().stream(stream).unwrap();
                assert_eq!(state.recv_reset, Some((0x107, 0)));
                assert_eq!(state.recv_offset, 0, "no response bytes before field refusal");
                owner.flush(cx).await.unwrap();
                return;
            }
            owner.drive_io_once(cx, IO_TIMEOUT).await.unwrap();
        }
    }

    #[test]
    fn native_buffered_listener_enforces_advertised_field_limit_before_fin() {
        run(false);
    }

    #[test]
    fn native_streaming_listener_enforces_advertised_field_limit_before_fin() {
        run(true);
    }

    #[test]
    fn invalid_field_limit_is_rejected_before_runtime_or_transport_admission() {
        let cx = Cx::for_testing();
        let (tls, _) = identity();
        for limit in [QUIC_VARINT_MAX + 1, u64::MAX] {
            let config = NativeH3ListenerConfig {
                max_request_field_section_size: Some(limit),
                ..NativeH3ListenerConfig::default()
            };
            // No spawn/timer capability and invalid transport bytes: the
            // precise configuration error must win before either is touched.
            let result = futures_lite::future::block_on(NativeH3Listener::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                Router::new(),
                Arc::clone(&tls),
                Vec::new(),
                config,
            ));
            assert!(matches!(result,
                Err(NativeH3ListenerError::Endpoint(ManagedEndpointError::InvalidConfig(message)))
                if message == "HTTP/3 request field-section limit exceeds the QUIC varint range"));
        }
    }

    // Keep the partial-header, refusal, admission and drain witnesses in the
    // same native journey. This is intentionally not a model of the listener.
    #[allow(clippy::too_many_lines)]
    fn run(streaming: bool) {
        let reservation_bytes = if streaming { 128 } else { BODY_BYTES };
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().expect("native reactor"))
            .build()
            .unwrap();
        let parent: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
            let cx = Cx::current().unwrap();
            let (tls, ca) = identity();
            let calls = Arc::new(AtomicUsize::new(0));
            let forbidden = Arc::new(AtomicUsize::new(0));
            let regions = Arc::new(std::sync::Mutex::new(Vec::new()));
            let handler_calls = Arc::clone(&calls);
            let handler_regions = Arc::clone(&regions);
            let denied_calls = Arc::clone(&forbidden);
            let router = Router::new()
                .route("/field-ok", post(AsyncCxFnHandler::new(move |request_cx: Cx| {
                    let calls = Arc::clone(&handler_calls);
                    let regions = Arc::clone(&handler_regions);
                    async move {
                        regions.lock().unwrap().push(request_cx.region_id());
                        calls.fetch_add(1, Ordering::SeqCst);
                        Response::new(StatusCode::OK, Bytes::from_static(b"field-ok"))
                    }
                })))
                .route("/field-denied", post(FnHandler::new(move || {
                    denied_calls.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::OK, "must not dispatch")
                })))
                .without_default_trace();
            let transport = NativeQuicConnectionConfig {
                max_local_bidi: 8,
                max_local_uni: 8,
                recv_window: WINDOW,
                connection_recv_limit: 4 << 20,
                ..NativeQuicConnectionConfig::default()
            };
            let mut config = NativeH3ListenerConfig::default();
            config.endpoint.max_connections = 2;
            config.endpoint.connection_config = transport;
            config.max_requests_per_connection = 8;
            config.receive_window_bytes = SERVER_RECEIVE_WINDOW;
            config.max_request_field_section_size = Some(FIELD_LIMIT);
            config.router = config.router
                .max_buffered_body_bytes(BODY_BYTES)
                .max_total_buffered_body_bytes(BODY_BYTES * 4);
            config.max_total_request_body_reservation_bytes = Some(reservation_bytes);
            if streaming {
                config.streaming_request_body_buffer_bytes = std::num::NonZeroUsize::new(64);
            }
            let listener = NativeH3Listener::bind(
                &cx, "127.0.0.1:0".parse().unwrap(), router, tls, parameters(transport), config,
            ).await.unwrap();
            let address = listener.local_addr();
            let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
            let drained = AtomicBool::new(false);
            let serving = async {
                let report = listener.serve_with_shutdown(&cx, async {
                    shutdown_rx.recv(&cx).await.unwrap();
                }).await;
                drained.store(true, Ordering::SeqCst);
                report
            };
            let clients = async {
                let client_transport = NativeQuicConnectionConfig {
                    recv_window: 4_096,
                    ..transport
                };
                let settings = H3Settings {
                    max_field_section_size: Some(FIELD_LIMIT),
                    ..H3Settings::default()
                };
                let (mut first, mut first_h3) = connect_with_settings(
                    &cx, address, 21, client_transport, ca.clone(), settings.clone(),
                ).await;
                let (mut second, mut second_h3) = connect_with_settings(
                    &cx, address, 22, client_transport, ca, settings,
                ).await;

                let oversized = field_head(1);
                let rejected = partial_head(&cx, &mut first, &mut first_h3, &oversized).await;
                assert_eq!(rejected, StreamId(0));
                // The real listener has expanded receive credit above the
                // authenticated initial window, admitting one partial head.
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(regions.lock().unwrap().is_empty());
                let denied = request(&cx, &mut second, &mut second_h3, "/field-denied").await;
                assert_eq!(denied, StreamId(0));
                expect_ingress_refusal(&cx, &mut second, &mut second_h3, denied).await;
                assert_eq!(forbidden.load(Ordering::SeqCst), 0);

                // Complete the 257-byte field section WITHOUT FIN. A size
                // check delayed to message completion cannot satisfy this.
                first.connection_mut().write_stream(
                    &cx, rejected, Bytes::copy_from_slice(&oversized[1..]), false,
                ).unwrap();
                first.flush(&cx).await.unwrap();
                field_refusal(&cx, &mut first, &mut first_h3, rejected).await;
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(regions.lock().unwrap().is_empty());

                // Reuse the sole shared reservation on the same connection,
                // with a valid field section exactly at the inclusive limit.
                let exact = field_head(0);
                let recovered = partial_head(&cx, &mut first, &mut first_h3, &exact).await;
                assert_eq!(recovered, StreamId(4));
                first.connection_mut().write_stream(
                    &cx, recovered, Bytes::copy_from_slice(&exact[1..]), true,
                ).unwrap();
                first.flush(&cx).await.unwrap();
                response(&cx, &mut first, &mut first_h3, recovered, b"field-ok").await;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let region = regions.lock().unwrap()[0];
                let mut closed_seen = false;
                std::future::poll_fn(|task| {
                    let closed = Runtime::current_handle().unwrap().diagnostics().unwrap()
                        .explain_region_open(region).region_state.is_none();
                    if closed && closed_seen {
                        return Poll::Ready(());
                    }
                    closed_seen = closed;
                    // Observe actual region retirement, then allow its owner
                    // reap pass before testing another peer's admission.
                    task.waker().wake_by_ref();
                    Poll::Pending
                }).await;
                let served = request(&cx, &mut second, &mut second_h3, "/field-ok").await;
                assert_eq!(served, StreamId(4));
                response(&cx, &mut second, &mut second_h3, served, b"field-ok").await;
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                assert_eq!(forbidden.load(Ordering::SeqCst), 0);
                assert_eq!(regions.lock().unwrap().len(), 2);
                shutdown_tx.send(&cx, ()).unwrap();
                zip(
                    acknowledge_goaway(&cx, &mut first, &mut first_h3, 8),
                    acknowledge_goaway(&cx, &mut second, &mut second_h3, 8),
                ).await;
                acknowledge_until_drained(&cx, &mut first, &mut second, &drained).await;
            };
            let (report, ()) = crate::time::timeout(
                cx.now(), Duration::from_secs(20), zip(serving, clients),
            ).await.expect("field-limit refusal and recovery must complete over native TLS/UDP");
            let report = report.unwrap();
            assert_eq!(report.accepted_connections, 2);
            assert_eq!(report.failed_connections, 0);
            assert_eq!(report.completed_requests, 2);
            assert_eq!(report.cancelled_requests, 0);
            // Session refusals are StreamReset events, not Router refusal
            // events. The sole counted refusal is the competing body budget.
            assert_eq!(report.refused_requests, 1);
            assert_eq!(report.rejected_request_body_reservations, 1);
            assert_eq!(report.peak_reserved_request_body_bytes, reservation_bytes);
            assert_eq!(report.failed_request_cleanups, 0);
            assert_eq!(report.rejected_buffered_responses, 0);
            assert!(!report.drain_timed_out);
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        });
        runtime.block_on(runtime.handle().spawn(parent));
        assert_eq!(runtime.draining_region_count(), 0);
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }
}
