//! Authenticated HTTP/3 and Router composition over real loopback UDP.

#![cfg(all(feature = "http3", feature = "tls"))]
#![allow(missing_docs)]

#[cfg(feature = "test-internals")]
use std::future::Future;
use std::io::BufReader;
#[cfg(feature = "test-internals")]
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "test-internals")]
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::http::h3_native::{H3PseudoHeaders, H3RequestHead, H3ResponseHead, H3Settings};
use asupersync::http::h3_quic::{NativeH3Event, NativeH3Session};
use asupersync::net::quic_core::{ConnectionId, TransportParameters};
use asupersync::net::quic_native::handshake_driver::{
    QuicHandshakeDriver, client_config, server_config,
};
use asupersync::net::quic_native::{
    NativeQuicConnectionConfig, NativeQuicUdpConnection, NativeQuicUdpConnectionError,
    QuicConnection, QuicUdpEndpoint, QuicUdpEndpointConfig,
};
use asupersync::types::{CancelKind, CancelReason};
#[cfg(feature = "test-internals")]
use asupersync::web::{
    AsyncCxFnHandler1, Http3StreamResponder, NativeH3ProducedEvent, NativeH3RouterProducedDispatch,
};
use asupersync::web::{
    FnHandler, NativeH3Router, NativeH3RouterEvent, NativeH3RouterIngress, Response, Router,
    StatusCode, post,
};
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

const H3_ALPN: &[u8] = b"h3";
const OTHER_ALPN: &[u8] = b"hq-29";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// Canonical test CA + leaf chain. The leaf has SAN DNS:localhost and the
// serverAuth EKU; the client trusts only this CA, so the test crosses WebPKI's
// real chain/hostname/signature verifier without a skip-verify path.
const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
    rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .next()
        .expect("one certificate")
        .expect("valid certificate PEM")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(LEAF_KEY_PEM.as_bytes()))
        .expect("read private key PEM")
        .expect("one private key")
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

async fn live_pair(
    cx: &Cx,
    negotiated_alpn: &[u8],
    required_alpn: &[u8],
) -> (
    Result<(NativeQuicUdpConnection, NativeH3Session), NativeQuicUdpConnectionError>,
    Result<NativeQuicUdpConnection, NativeQuicUdpConnectionError>,
) {
    let udp_config = QuicUdpEndpointConfig {
        max_packet_size: 16_384,
        ..QuicUdpEndpointConfig::default()
    };
    let client_endpoint = QuicUdpEndpoint::bind(
        cx,
        "127.0.0.1:0".parse().expect("client bind address"),
        udp_config.clone(),
    )
    .await
    .expect("bind client UDP endpoint");
    let server_endpoint = QuicUdpEndpoint::bind(
        cx,
        "127.0.0.1:0".parse().expect("server bind address"),
        udp_config,
    )
    .await
    .expect("bind server UDP endpoint");
    let server_addr = server_endpoint.local_addr();

    let protocols = vec![negotiated_alpn.to_vec()];
    let client_tls = client_config(vec![parse_one_cert(CA_CERT_PEM)], protocols.clone())
        .expect("client TLS config");
    let server_tls = server_config(vec![parse_one_cert(LEAF_CERT_PEM)], leaf_key(), protocols)
        .expect("server TLS config");
    let client_connection_config = connection_config();
    let server_connection_config = connection_config();
    let client_driver = QuicHandshakeDriver::client(
        client_tls,
        ServerName::try_from("localhost").expect("server name"),
        transport_parameters(client_connection_config),
    )
    .expect("client handshake driver");
    let server_driver =
        QuicHandshakeDriver::server(server_tls, transport_parameters(server_connection_config))
            .expect("server handshake driver");

    let initial_dcid =
        ConnectionId::new(b"h3-init1").expect("valid initial destination connection ID");
    let client_cid = ConnectionId::new(b"h3-cli01").expect("valid client source connection ID");
    let server_cid = ConnectionId::new(b"h3-srv01").expect("valid server source connection ID");

    let client = async {
        let mut connection = NativeQuicUdpConnection::connect(
            cx,
            client_endpoint,
            server_addr,
            client_driver,
            initial_dcid,
            client_cid,
            client_connection_config,
            required_alpn,
        )
        .await?;
        let mut session = NativeH3Session::client();
        session
            .initialize(cx, connection.connection_mut(), H3Settings::default())
            .map_err(|error| NativeQuicUdpConnectionError::Packet(error.to_string()))?;
        connection.flush(cx).await?;
        Ok((connection, session))
    };
    zip(
        client,
        NativeQuicUdpConnection::accept(
            cx,
            server_endpoint,
            server_driver,
            initial_dcid,
            server_cid,
            server_connection_config,
            required_alpn,
        ),
    )
    .await
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

#[test]
fn authenticated_h3_router_request_response_crosses_real_udp() {
    block_on(async {
        let cx = Cx::for_testing();
        let (client, server) = live_pair(&cx, H3_ALPN, H3_ALPN).await;
        let (mut client, mut client_h3) = client.expect("authenticated client live handle");
        let mut server = server.expect("authenticated server live handle");

        assert_eq!(client.negotiated_alpn(), H3_ALPN);
        assert_eq!(server.negotiated_alpn(), H3_ALPN);
        assert_eq!(client.peer_addr(), server.local_addr());
        assert_eq!(server.peer_addr(), client.local_addr());
        assert_eq!(client.peer_connection_id(), server.local_connection_id());
        assert_eq!(server.peer_connection_id(), client.local_connection_id());

        let mut server_h3 = NativeH3Session::server();
        server_h3
            .initialize(&cx, server.connection_mut(), H3Settings::default())
            .expect("initialize server HTTP/3 session");

        let initial_progress = server
            .drive_io_once(&cx, IO_TIMEOUT)
            .await
            .expect("server receives early client SETTINGS");
        assert!(initial_progress.packets_received > 0);
        assert!(
            initial_progress.early_packets_replayed > 0,
            "client SETTINGS sent immediately after connect must survive server accept"
        );
        assert_eq!(
            drain_h3_events(&cx, &mut server_h3, server.connection_mut()),
            vec![NativeH3Event::Settings(H3Settings::default())]
        );
        assert!(
            client
                .drive_io_once(&cx, IO_TIMEOUT)
                .await
                .expect("client receives server SETTINGS")
                .packets_received
                > 0
        );
        assert_eq!(
            drain_h3_events(&cx, &mut client_h3, client.connection_mut()),
            vec![NativeH3Event::Settings(H3Settings::default())]
        );

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&handler_calls);
        let router = Router::new()
            .route(
                "/live",
                post(FnHandler::new(move || {
                    calls_for_handler.fetch_add(1, Ordering::SeqCst);
                    let mut response = Response::new(StatusCode::OK, "live-h3-response");
                    response.set_header("x-live-udp", "yes");
                    response
                })),
            )
            .without_default_trace();
        let mut bridge = NativeH3Router::new(router);
        let request_head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("localhost".to_string()),
                path: Some("/live?transport=udp".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![("content-type".to_string(), "text/plain".to_string())],
        )
        .expect("valid live request head");
        let request_stream = client_h3
            .send_request(
                &cx,
                client.connection_mut(),
                &request_head,
                Bytes::from_static(b"live-request"),
            )
            .expect("queue live HTTP/3 request");

        assert!(client.flush(&cx).await.expect("flush live request") > 0);
        assert!(
            server
                .drive_io_once(&cx, IO_TIMEOUT)
                .await
                .expect("server receives live request")
                .packets_received
                > 0
        );
        let server_events = drain_h3_events(&cx, &mut server_h3, server.connection_mut());
        assert!(server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::RequestHeaders { stream_id, head }
                if *stream_id == request_stream && head == &request_head
        )));
        assert!(server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::Data { stream_id, bytes }
                if *stream_id == request_stream && bytes.as_ref() == b"live-request"
        )));

        let mut response_sent = false;
        for event in server_events {
            match bridge
                .ingest_event_with_cx(&cx, &mut server_h3, server.connection_mut(), event)
                .expect("ingest live H3 Router event")
            {
                NativeH3RouterIngress::Event(_) => {}
                NativeH3RouterIngress::Dispatch(dispatch) => {
                    let prepared = dispatch.run(&cx).await;
                    let completed = bridge
                        .complete_dispatch_with_cx(
                            &cx,
                            &mut server_h3,
                            server.connection_mut(),
                            &prepared,
                        )
                        .expect("queue Router response on live H3 stream");
                    assert_eq!(
                        completed,
                        NativeH3RouterEvent::ResponseSent {
                            stream_id: request_stream,
                            status: 200,
                        }
                    );
                    response_sent = true;
                }
                _ => panic!("unexpected future NativeH3RouterIngress variant"),
            }
        }
        assert!(
            response_sent,
            "request FIN must dispatch the Router handler"
        );
        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);

        assert!(server.flush(&cx).await.expect("flush Router response") > 0);
        assert!(
            client
                .drive_io_once(&cx, IO_TIMEOUT)
                .await
                .expect("client receives Router response")
                .packets_received
                > 0
        );
        let response_events = drain_h3_events(&cx, &mut client_h3, client.connection_mut());
        let expected_head =
            H3ResponseHead::new(200, vec![("x-live-udp".to_string(), "yes".to_string())])
                .expect("valid expected response head");
        assert_eq!(
            response_events,
            vec![
                NativeH3Event::ResponseHeaders {
                    stream_id: request_stream,
                    head: expected_head,
                },
                NativeH3Event::Data {
                    stream_id: request_stream,
                    bytes: Bytes::from_static(b"live-h3-response"),
                },
                NativeH3Event::Finished {
                    stream_id: request_stream,
                },
            ]
        );
    });
}

#[test]
#[cfg(feature = "test-internals")]
fn authenticated_h3_produced_response_obeys_live_udp_credit_and_quiesces() {
    const FRAME_BYTES: usize = 64 * 1024;
    const BODY_FRAMES: usize = 64;
    const BODY_BYTES: usize = FRAME_BYTES * BODY_FRAMES;
    const FRAME_WIRE_BUDGET: u64 = FRAME_BYTES as u64 + 16;
    const STREAM_WINDOW: u64 = 2 * FRAME_BYTES as u64;
    const CONNECTION_LIMIT: u64 = (4 << 20) + (4 * FRAME_BYTES) as u64;
    const DRIVE_STEP: Duration = Duration::from_millis(250);

    block_on(async {
        let cx = Cx::for_testing();
        let (client, server) = live_pair(&cx, H3_ALPN, H3_ALPN).await;
        let (mut client, mut client_h3) = client.expect("authenticated client live handle");
        let mut server = server.expect("authenticated server live handle");
        let mut server_h3 = NativeH3Session::server();
        server_h3
            .initialize(&cx, server.connection_mut(), H3Settings::default())
            .expect("initialize server HTTP/3 session");

        assert!(
            server
                .drive_io_once(&cx, IO_TIMEOUT)
                .await
                .expect("server receives early client SETTINGS")
                .packets_received
                > 0
        );
        assert_eq!(
            drain_h3_events(&cx, &mut server_h3, server.connection_mut()),
            vec![NativeH3Event::Settings(H3Settings::default())]
        );
        assert!(
            client
                .drive_io_once(&cx, IO_TIMEOUT)
                .await
                .expect("client receives server SETTINGS")
                .packets_received
                > 0
        );
        assert_eq!(
            drain_h3_events(&cx, &mut client_h3, client.connection_mut()),
            vec![NativeH3Event::Settings(H3Settings::default())]
        );

        let attempted_bytes = Arc::new(AtomicUsize::new(0));
        let committed_bytes = Arc::new(AtomicUsize::new(0));
        let received_bytes = Arc::new(AtomicUsize::new(0));
        let peak_attempted_ahead = Arc::new(AtomicUsize::new(0));
        let peak_committed_ahead = Arc::new(AtomicUsize::new(0));
        let attempted_for_route = Arc::clone(&attempted_bytes);
        let committed_for_route = Arc::clone(&committed_bytes);
        let received_for_route = Arc::clone(&received_bytes);
        let peak_attempted_for_route = Arc::clone(&peak_attempted_ahead);
        let peak_committed_for_route = Arc::clone(&peak_committed_ahead);

        let router = Router::new()
            .route(
                "/produced",
                post(AsyncCxFnHandler1::<_, Http3StreamResponder>::new(
                    move |_handler_cx: Cx, responder: Http3StreamResponder| {
                        let attempted = Arc::clone(&attempted_for_route);
                        let committed = Arc::clone(&committed_for_route);
                        let received = Arc::clone(&received_for_route);
                        let peak_attempted = Arc::clone(&peak_attempted_for_route);
                        let peak_committed = Arc::clone(&peak_committed_for_route);
                        async move {
                            responder
                                .streaming(
                                    StatusCode::OK,
                                    NonZeroUsize::MIN,
                                    NonZeroUsize::new(FRAME_BYTES).expect("non-zero H3 frame size"),
                                    move |producer_cx, mut sender| async move {
                                        let mut chunk = vec![0_u8; FRAME_BYTES];
                                        for frame_index in 0..BODY_FRAMES {
                                            chunk.fill(
                                                u8::try_from(frame_index % 251)
                                                    .expect("pattern fits in one byte"),
                                            );
                                            let attempted_total = attempted
                                                .fetch_add(FRAME_BYTES, Ordering::SeqCst)
                                                + FRAME_BYTES;
                                            peak_attempted.fetch_max(
                                                attempted_total.saturating_sub(
                                                    received.load(Ordering::SeqCst),
                                                ),
                                                Ordering::SeqCst,
                                            );
                                            sender.send_chunk(&producer_cx, &chunk).await?;
                                            let committed_total = committed
                                                .fetch_add(FRAME_BYTES, Ordering::SeqCst)
                                                + FRAME_BYTES;
                                            peak_committed.fetch_max(
                                                committed_total.saturating_sub(
                                                    received.load(Ordering::SeqCst),
                                                ),
                                                Ordering::SeqCst,
                                            );
                                        }
                                        sender.finish(&producer_cx)?;
                                        Ok(sender)
                                    },
                                )
                                .header("x-live-udp", "produced")
                        }
                    },
                )),
            )
            .route(
                "/survivor",
                post(FnHandler::new(|| {
                    Response::new(StatusCode::OK, "survived").header("x-live-udp", "survivor")
                })),
            )
            .without_default_trace();
        let mut bridge = NativeH3Router::new(router);

        let produced_head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("localhost".to_string()),
                path: Some("/produced".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid produced request head");
        let produced_stream = client_h3
            .send_request(&cx, client.connection_mut(), &produced_head, Bytes::new())
            .expect("queue produced-response request");
        assert!(
            client
                .flush(&cx)
                .await
                .expect("flush produced-response request")
                > 0
        );

        let mut produced_dispatch = None;
        let mut produced_request_fin = 0;
        for _ in 0..8 {
            server
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("server drives produced-response request");
            let events = drain_h3_events(&cx, &mut server_h3, server.connection_mut());
            for event in events {
                if matches!(
                    &event,
                    NativeH3Event::Finished { stream_id } if *stream_id == produced_stream
                ) {
                    produced_request_fin += 1;
                }
                match bridge
                    .ingest_event_with_cx(&cx, &mut server_h3, server.connection_mut(), event)
                    .expect("ingest produced-response request")
                {
                    NativeH3RouterIngress::Event(_) => {}
                    NativeH3RouterIngress::Dispatch(dispatch) => {
                        assert!(
                            produced_dispatch.replace(dispatch).is_none(),
                            "request must detach exactly one Router dispatch"
                        );
                    }
                    _ => panic!("unexpected future NativeH3RouterIngress variant"),
                }
            }
            if produced_dispatch.is_some() {
                break;
            }
        }
        assert_eq!(produced_request_fin, 1);
        let produced_dispatch = produced_dispatch.expect("request FIN yields produced dispatch");
        assert_eq!(produced_dispatch.stream_id(), produced_stream);
        let prepared = match produced_dispatch.run_produced(&cx).await {
            NativeH3RouterProducedDispatch::Produced(prepared) => prepared,
            NativeH3RouterProducedDispatch::Buffered(_) => {
                panic!("produced route must retain its authored body plan")
            }
        };
        assert_eq!(
            bridge
                .start_produced_dispatch_with_cx(
                    &cx,
                    &mut server_h3,
                    server.connection_mut(),
                    prepared,
                )
                .expect("start produced response"),
            NativeH3RouterEvent::ResponseStarted {
                stream_id: produced_stream,
                status: 200,
            }
        );

        let mut task_cx = Context::from_waker(Waker::noop());
        let mut producer = match bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            server.connection_mut(),
            &mut task_cx,
        ) {
            Poll::Ready(Ok(NativeH3ProducedEvent::ProducerReady {
                stream_id,
                producer,
            })) => {
                assert_eq!(stream_id, produced_stream);
                Box::pin(producer)
            }
            _ => panic!("HEADERS admission must yield the produced body future"),
        };

        assert!(
            server
                .flush(&cx)
                .await
                .expect("flush produced response HEADERS")
                > 0
        );
        let mut header_events = Vec::new();
        for _ in 0..8 {
            client
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("client drives produced response HEADERS");
            header_events.extend(drain_h3_events(
                &cx,
                &mut client_h3,
                client.connection_mut(),
            ));
            if !header_events.is_empty() {
                break;
            }
        }
        assert_eq!(
            header_events,
            vec![NativeH3Event::ResponseHeaders {
                stream_id: produced_stream,
                head: H3ResponseHead::new(
                    200,
                    vec![("x-live-udp".to_string(), "produced".to_string())],
                )
                .expect("valid produced response head"),
            }]
        );

        let stream_send_offset = server
            .connection()
            .inner()
            .streams()
            .stream(produced_stream)
            .expect("produced response stream remains open")
            .send_offset;
        let connection_bytes_sent = connection_config()
            .connection_send_limit
            .checked_sub(
                server
                    .connection()
                    .inner()
                    .streams()
                    .connection_send_remaining(),
            )
            .expect("remaining connection credit cannot exceed its initial limit");
        assert_eq!(
            server
                .connection_mut()
                .constrain_stream_send_limit_for_testing(&cx, produced_stream, stream_send_offset,)
                .expect("plant exact stream-credit stall"),
            stream_send_offset
        );
        assert_eq!(
            server
                .connection_mut()
                .constrain_connection_send_limit_for_testing(&cx, connection_bytes_sent)
                .expect("plant exact connection-credit stall"),
            connection_bytes_sent
        );

        assert!(producer.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(attempted_bytes.load(Ordering::SeqCst), 2 * FRAME_BYTES);
        assert_eq!(committed_bytes.load(Ordering::SeqCst), FRAME_BYTES);
        assert!(
            bridge
                .poll_produced_response_with_cx(
                    &cx,
                    &mut server_h3,
                    server.connection_mut(),
                    &mut task_cx,
                )
                .is_pending(),
            "both flow-control scopes must hold the first body frame"
        );
        assert_eq!(
            server
                .connection()
                .pending_stream_data_bytes(produced_stream),
            0,
            "flow-controlled body must remain outside QUIC packet assembly"
        );

        let advertised_stream_limit = client
            .connection_mut()
            .configure_stream_receive_window(&cx, produced_stream, STREAM_WINDOW)
            .expect("queue live MAX_STREAM_DATA");
        assert!(client.flush(&cx).await.expect("flush live MAX_STREAM_DATA") > 0);
        let mut stream_credit_observed = false;
        for _ in 0..8 {
            server
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("server receives live MAX_STREAM_DATA");
            assert!(
                drain_h3_events(&cx, &mut server_h3, server.connection_mut()).is_empty(),
                "transport credit must not fabricate an HTTP/3 event"
            );
            if server
                .connection()
                .inner()
                .stream_send_credit_remaining(produced_stream)
                >= FRAME_WIRE_BUDGET
            {
                stream_credit_observed = true;
                break;
            }
        }
        assert!(stream_credit_observed);
        assert!(advertised_stream_limit >= stream_send_offset + STREAM_WINDOW);
        assert!(
            server
                .connection()
                .inner()
                .streams()
                .connection_send_remaining()
                < FRAME_WIRE_BUDGET
        );
        assert!(
            bridge
                .poll_produced_response_with_cx(
                    &cx,
                    &mut server_h3,
                    server.connection_mut(),
                    &mut task_cx,
                )
                .is_pending(),
            "MAX_STREAM_DATA alone must not bypass exhausted MAX_DATA"
        );

        client
            .connection_mut()
            .advertise_connection_receive_limit(&cx, CONNECTION_LIMIT)
            .expect("queue live MAX_DATA");
        assert!(client.flush(&cx).await.expect("flush live MAX_DATA") > 0);
        let mut connection_credit_observed = false;
        for _ in 0..8 {
            server
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("server receives live MAX_DATA");
            assert!(
                drain_h3_events(&cx, &mut server_h3, server.connection_mut()).is_empty(),
                "connection credit must stay below HTTP/3"
            );
            if server
                .connection()
                .inner()
                .streams()
                .connection_send_remaining()
                >= FRAME_WIRE_BUDGET
            {
                connection_credit_observed = true;
                break;
            }
        }
        assert!(connection_credit_observed);

        let mut producer_ready = false;
        let mut observed_congestion_admitted_prefix = false;
        for frame_index in 0..BODY_FRAMES {
            assert!(matches!(
                bridge.poll_produced_response_with_cx(
                    &cx,
                    &mut server_h3,
                    server.connection_mut(),
                    &mut task_cx,
                ),
                Poll::Ready(Ok(NativeH3ProducedEvent::DataQueued {
                    stream_id,
                    payload_bytes: FRAME_BYTES,
                })) if stream_id == produced_stream
            ));

            if !producer_ready {
                producer_ready = producer.as_mut().poll(&mut task_cx).is_ready();
            }
            let attempted = attempted_bytes.load(Ordering::SeqCst);
            let committed = committed_bytes.load(Ordering::SeqCst);
            let received = received_bytes.load(Ordering::SeqCst);
            assert!(committed.saturating_sub(received) <= 2 * FRAME_BYTES);
            assert!(attempted.saturating_sub(received) <= 3 * FRAME_BYTES);

            let mut data_events = Vec::new();
            for drive_attempt in 0..32 {
                let pending_before_flush = server
                    .connection()
                    .pending_stream_data_bytes(produced_stream);
                let packets_sent = server
                    .flush(&cx)
                    .await
                    .expect("flush congestion-admitted produced DATA packets");
                if frame_index == 0 && drive_attempt == 0 {
                    let pending_after_flush = server
                        .connection()
                        .pending_stream_data_bytes(produced_stream);
                    let transport = server.connection().inner().transport();
                    assert!(packets_sent > 0, "the admitted prefix must reach UDP");
                    assert!(pending_after_flush > 0);
                    assert!(pending_after_flush < pending_before_flush);
                    assert!(transport.bytes_in_flight() > 0);
                    assert!(
                        transport.bytes_in_flight() <= transport.congestion_window_bytes(),
                        "an admitted prefix must never overshoot cwnd"
                    );
                    assert!(
                        !transport.can_send(1_200),
                        "the first flush must stop with less than one protected-packet ceiling available"
                    );
                    observed_congestion_admitted_prefix = true;
                }
                client
                    .drive_io_once(&cx, DRIVE_STEP)
                    .await
                    .expect("client drives congestion-admitted produced DATA packets");
                data_events.extend(drain_h3_events(
                    &cx,
                    &mut client_h3,
                    client.connection_mut(),
                ));
                if frame_index == 0 && drive_attempt == 0 {
                    assert!(
                        data_events.is_empty(),
                        "an admitted packet prefix must not fabricate a partial H3 DATA event"
                    );
                }
                if !data_events.is_empty() {
                    break;
                }
                server
                    .drive_io_once(&cx, DRIVE_STEP)
                    .await
                    .expect("server receives partial-frame ACK and resumes packetization");
                assert!(
                    drain_h3_events(&cx, &mut server_h3, server.connection_mut()).is_empty(),
                    "transport ACK progress must stay below HTTP/3"
                );
            }
            match data_events.as_slice() {
                [NativeH3Event::Data { stream_id, bytes }]
                    if *stream_id == produced_stream && bytes.len() == FRAME_BYTES =>
                {
                    let expected =
                        u8::try_from(frame_index % 251).expect("pattern fits in one byte");
                    assert!(bytes.iter().all(|byte| *byte == expected));
                }
                _ => panic!("one queued frame must produce one exact live H3 DATA event"),
            }
            received_bytes.fetch_add(FRAME_BYTES, Ordering::SeqCst);

            let _ = client
                .flush(&cx)
                .await
                .expect("flush DATA acknowledgement and refreshed receive credit");
            if frame_index + 1 < BODY_FRAMES {
                let mut refreshed_credit_observed = false;
                for _ in 0..8 {
                    server
                        .drive_io_once(&cx, DRIVE_STEP)
                        .await
                        .expect("server receives DATA acknowledgement and refreshed credit");
                    assert!(
                        drain_h3_events(&cx, &mut server_h3, server.connection_mut()).is_empty(),
                        "ACK and flow-control packets must stay below HTTP/3"
                    );
                    if server
                        .connection()
                        .inner()
                        .stream_send_credit_remaining(produced_stream)
                        >= FRAME_WIRE_BUDGET
                    {
                        refreshed_credit_observed = true;
                        break;
                    }
                }
                assert!(
                    refreshed_credit_observed,
                    "the live MAX_STREAM_DATA packet must reach the server before more DATA"
                );
            }
        }

        assert!(
            producer_ready,
            "producer must finish after its final bounded send"
        );
        assert!(observed_congestion_admitted_prefix);
        assert!(matches!(
            bridge.poll_produced_response_with_cx(
                &cx,
                &mut server_h3,
                server.connection_mut(),
                &mut task_cx,
            ),
            Poll::Ready(Ok(NativeH3ProducedEvent::TerminalQueued { stream_id }))
                if stream_id == produced_stream
        ));
        assert!(
            server
                .flush(&cx)
                .await
                .expect("flush produced response FIN")
                > 0
        );

        let mut terminal_events = Vec::new();
        for _ in 0..8 {
            client
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("client drives produced response FIN");
            terminal_events.extend(drain_h3_events(
                &cx,
                &mut client_h3,
                client.connection_mut(),
            ));
            if !terminal_events.is_empty() {
                break;
            }
        }
        assert_eq!(
            terminal_events,
            vec![NativeH3Event::Finished {
                stream_id: produced_stream,
            }]
        );
        assert!(matches!(
            bridge.poll_produced_response_with_cx(
                &cx,
                &mut server_h3,
                server.connection_mut(),
                &mut task_cx,
            ),
            Poll::Ready(Ok(NativeH3ProducedEvent::ResponseSent {
                stream_id,
                status: 200,
            })) if stream_id == produced_stream
        ));

        assert_eq!(attempted_bytes.load(Ordering::SeqCst), BODY_BYTES);
        assert_eq!(committed_bytes.load(Ordering::SeqCst), BODY_BYTES);
        assert_eq!(received_bytes.load(Ordering::SeqCst), BODY_BYTES);
        assert_eq!(peak_committed_ahead.load(Ordering::SeqCst), 2 * FRAME_BYTES);
        assert_eq!(peak_attempted_ahead.load(Ordering::SeqCst), 3 * FRAME_BYTES);
        assert!(BODY_BYTES > 20 * peak_attempted_ahead.load(Ordering::SeqCst));
        assert_eq!(bridge.pending_request_count(), 0);
        assert_eq!(bridge.in_flight_dispatch_count(), 0);
        assert!(
            !server
                .connection()
                .has_pending_stream_frames(produced_stream)
        );
        assert_eq!(
            server
                .connection()
                .pending_stream_data_bytes(produced_stream),
            0
        );

        let _ = client
            .flush(&cx)
            .await
            .expect("flush terminal acknowledgement");
        for _ in 0..16 {
            if server.connection().path_stats().bytes_in_flight == 0
                && client.connection().path_stats().bytes_in_flight == 0
            {
                break;
            }
            server
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("server settles produced response ownership");
            assert!(
                drain_h3_events(&cx, &mut server_h3, server.connection_mut()).is_empty(),
                "settling produced response ownership must stay below HTTP/3"
            );
            if client.connection().path_stats().bytes_in_flight > 0 {
                client
                    .drive_io_once(&cx, DRIVE_STEP)
                    .await
                    .expect("client settles produced response control ownership");
                assert!(
                    drain_h3_events(&cx, &mut client_h3, client.connection_mut()).is_empty(),
                    "settling transport acknowledgements must not duplicate H3 terminal events"
                );
            }
        }
        assert_eq!(server.connection().path_stats().bytes_in_flight, 0);
        assert_eq!(client.connection().path_stats().bytes_in_flight, 0);
        assert!(!server.connection().inner().has_pending_stream_frames());
        assert!(!client.connection().inner().has_pending_stream_frames());
        assert_eq!(
            server
                .flush(&cx)
                .await
                .expect("produced server drain probe"),
            0
        );
        assert_eq!(
            client
                .flush(&cx)
                .await
                .expect("produced client drain probe"),
            0
        );

        let survivor_head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("localhost".to_string()),
                path: Some("/survivor".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid survivor request head");
        let survivor_stream = client_h3
            .send_request(
                &cx,
                client.connection_mut(),
                &survivor_head,
                Bytes::from_static(b"again"),
            )
            .expect("queue same-connection survivor request");
        assert_eq!(survivor_stream.0, produced_stream.0 + 4);
        assert!(client.flush(&cx).await.expect("flush survivor request") > 0);

        let mut survivor_dispatch = None;
        let mut survivor_request_fin = 0;
        for _ in 0..8 {
            server
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("server drives survivor request");
            let events = drain_h3_events(&cx, &mut server_h3, server.connection_mut());
            for event in events {
                if matches!(
                    &event,
                    NativeH3Event::Finished { stream_id } if *stream_id == survivor_stream
                ) {
                    survivor_request_fin += 1;
                }
                match bridge
                    .ingest_event_with_cx(&cx, &mut server_h3, server.connection_mut(), event)
                    .expect("ingest survivor request")
                {
                    NativeH3RouterIngress::Event(_) => {}
                    NativeH3RouterIngress::Dispatch(dispatch) => {
                        assert!(
                            survivor_dispatch.replace(dispatch).is_none(),
                            "survivor must detach exactly one Router dispatch"
                        );
                    }
                    _ => panic!("unexpected future NativeH3RouterIngress variant"),
                }
            }
            if survivor_dispatch.is_some() {
                break;
            }
        }
        assert_eq!(survivor_request_fin, 1);
        let survivor_prepared = match survivor_dispatch
            .expect("survivor request FIN yields Router dispatch")
            .run_produced(&cx)
            .await
        {
            NativeH3RouterProducedDispatch::Buffered(prepared) => prepared,
            NativeH3RouterProducedDispatch::Produced(_) => {
                panic!("ordinary survivor must stay on the buffered path")
            }
        };
        assert_eq!(
            bridge
                .complete_dispatch_with_cx(
                    &cx,
                    &mut server_h3,
                    server.connection_mut(),
                    &survivor_prepared,
                )
                .expect("queue buffered survivor response"),
            NativeH3RouterEvent::ResponseSent {
                stream_id: survivor_stream,
                status: 200,
            }
        );
        assert!(server.flush(&cx).await.expect("flush survivor response") > 0);

        let mut survivor_events = Vec::new();
        for _ in 0..8 {
            client
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("client drives survivor response");
            survivor_events.extend(drain_h3_events(
                &cx,
                &mut client_h3,
                client.connection_mut(),
            ));
            if survivor_events.iter().any(
                |event| matches!(event, NativeH3Event::Finished { stream_id } if *stream_id == survivor_stream),
            ) {
                break;
            }
        }
        assert_eq!(
            survivor_events,
            vec![
                NativeH3Event::ResponseHeaders {
                    stream_id: survivor_stream,
                    head: H3ResponseHead::new(
                        200,
                        vec![("x-live-udp".to_string(), "survivor".to_string())],
                    )
                    .expect("valid survivor response head"),
                },
                NativeH3Event::Data {
                    stream_id: survivor_stream,
                    bytes: Bytes::from_static(b"survived"),
                },
                NativeH3Event::Finished {
                    stream_id: survivor_stream,
                },
            ]
        );
        let _ = client
            .flush(&cx)
            .await
            .expect("flush survivor acknowledgement");
        for _ in 0..16 {
            if server.connection().path_stats().bytes_in_flight == 0
                && client.connection().path_stats().bytes_in_flight == 0
            {
                break;
            }
            server
                .drive_io_once(&cx, DRIVE_STEP)
                .await
                .expect("server settles survivor response ownership");
            assert!(
                drain_h3_events(&cx, &mut server_h3, server.connection_mut()).is_empty(),
                "settling survivor ownership must stay below HTTP/3"
            );
            if client.connection().path_stats().bytes_in_flight > 0 {
                client
                    .drive_io_once(&cx, DRIVE_STEP)
                    .await
                    .expect("client settles survivor control ownership");
                assert!(
                    drain_h3_events(&cx, &mut client_h3, client.connection_mut()).is_empty(),
                    "settling survivor acknowledgements must not duplicate H3 events"
                );
            }
        }
        assert_eq!(bridge.pending_request_count(), 0);
        assert_eq!(bridge.in_flight_dispatch_count(), 0);
        assert!(
            !server
                .connection()
                .has_pending_stream_frames(survivor_stream)
        );
        assert_eq!(
            server
                .connection()
                .pending_stream_data_bytes(survivor_stream),
            0
        );
        assert_eq!(server.connection().path_stats().bytes_in_flight, 0);
        assert_eq!(client.connection().path_stats().bytes_in_flight, 0);
        assert!(!server.connection().inner().has_pending_stream_frames());
        assert!(!client.connection().inner().has_pending_stream_frames());
        assert_eq!(
            server.flush(&cx).await.expect("final server drain probe"),
            0
        );
        assert_eq!(
            client.flush(&cx).await.expect("final client drain probe"),
            0
        );
    });
}

#[test]
fn cancellation_refuses_live_request_before_router_dispatch() {
    block_on(async {
        let cx = Cx::for_testing();
        let (client, server) = live_pair(&cx, H3_ALPN, H3_ALPN).await;
        let (mut client, mut client_h3) = client.expect("authenticated client live handle");
        let mut server = server.expect("authenticated server live handle");
        let mut server_h3 = NativeH3Session::server();
        server_h3
            .initialize(&cx, server.connection_mut(), H3Settings::default())
            .expect("initialize server HTTP/3 session");

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&handler_calls);
        let router = Router::new()
            .route(
                "/cancelled",
                post(FnHandler::new(move || {
                    calls_for_handler.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::OK, "must-not-run")
                })),
            )
            .without_default_trace();
        let mut bridge = NativeH3Router::new(router);
        let request_head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("localhost".to_string()),
                path: Some("/cancelled".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid cancelled request head");
        client_h3
            .send_request(
                &cx,
                client.connection_mut(),
                &request_head,
                Bytes::from_static(b"must-not-dispatch"),
            )
            .expect("queue request before cancellation");
        assert!(client.flush(&cx).await.expect("flush cancelled request") > 0);

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_reason(
            CancelReason::new(CancelKind::User).with_message("cancel before Router dispatch"),
        );
        assert!(matches!(
            server.drive_io_once(&cancelled_cx, IO_TIMEOUT).await,
            Err(NativeQuicUdpConnectionError::Cancelled)
        ));
        let events = drain_h3_events(&cx, &mut server_h3, server.connection_mut());
        assert!(
            events.is_empty(),
            "cancelled drive must not expose H3 events"
        );
        for event in events {
            let ingress = bridge
                .ingest_event_with_cx(&cx, &mut server_h3, server.connection_mut(), event)
                .expect("ingest event after cancelled drive");
            if let NativeH3RouterIngress::Dispatch(dispatch) = ingress {
                let _ = dispatch.run(&cx).await;
            }
        }
        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        assert_eq!(bridge.pending_request_count(), 0);
        assert_eq!(bridge.in_flight_dispatch_count(), 0);
    });
}

#[test]
fn negotiated_non_h3_alpn_refuses_live_application_handles() {
    block_on(async {
        let cx = Cx::for_testing();
        let (client, server) = live_pair(&cx, OTHER_ALPN, H3_ALPN).await;
        assert!(matches!(
            client,
            Err(NativeQuicUdpConnectionError::AlpnMismatch {
                ref expected,
                negotiated: Some(ref negotiated),
            }) if expected == H3_ALPN && negotiated == OTHER_ALPN
        ));
        assert!(matches!(
            server,
            Err(NativeQuicUdpConnectionError::AlpnMismatch {
                ref expected,
                negotiated: Some(ref negotiated),
            }) if expected == H3_ALPN && negotiated == OTHER_ALPN
        ));
    });
}
