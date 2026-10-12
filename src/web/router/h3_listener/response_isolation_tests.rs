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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
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
            assert_eq!(ready, vec![NativeH3Event::Settings(H3Settings::default())]);
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
        let serving = listener.serve_with_shutdown(&cx, async {
            shutdown_rx.recv(&cx).await.unwrap();
        });
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
