//! Authenticated HTTP/3 and Router composition over real loopback UDP.

#![cfg(all(feature = "http3", feature = "tls"))]
#![allow(missing_docs)]

use std::future::Future;
use std::io::BufReader;
#[cfg(feature = "test-internals")]
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
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
    ManagedEndpointConfig, ManagedEndpointError, ManagedQuicEndpoint, NativeQuicConnectionConfig,
    NativeQuicUdpConnection, NativeQuicUdpConnectionError, QuicConnection, QuicUdpEndpoint,
    QuicUdpEndpointConfig,
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

// These additions exercise the public authenticated owner and the actual native
// managed loop. They do not construct an established connection or crypto keys
// through test internals, and do not claim same-router multi-peer fairness or
// a kernel WouldBlock result from two independent sockets.
const MANAGED_ALPN: &[u8] = b"asupersync-managed-test";

fn managed_runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(
            asupersync::runtime::reactor::create_reactor().expect("actual native reactor"),
        )
        .build()
        .expect("native managed QUIC runtime")
}

fn managed_assert_runtime_cleanup(runtime: &asupersync::runtime::Runtime) {
    runtime.block_on(async {
        let started = Instant::now();
        while !runtime.is_quiescent() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "managed native task and obligation cleanup must drain: {:?}",
                runtime
                    .task_inspector(Default::default())
                    .list_active_tasks(),
            );
            asupersync::runtime::yield_now().await;
        }
    });
    assert!(runtime.is_quiescent());
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
}

fn managed_ids() -> (ConnectionId, ConnectionId, ConnectionId) {
    (
        ConnectionId::new(b"managed-initial").unwrap(),
        ConnectionId::new(b"managed-client").unwrap(),
        ConnectionId::new(b"srv76").unwrap(),
    )
}

async fn managed_handshake(
    cx: &Cx,
    endpoint: QuicUdpEndpoint,
    server: bool,
    server_addr: std::net::SocketAddr,
) -> NativeQuicUdpConnection {
    let config = connection_config();
    let (initial, client_cid, server_cid) = managed_ids();
    assert_ne!(client_cid.len(), server_cid.len());
    if server {
        let tls = server_config(
            vec![parse_one_cert(LEAF_CERT_PEM)],
            leaf_key(),
            vec![MANAGED_ALPN.to_vec()],
        )
        .unwrap();
        let driver = QuicHandshakeDriver::server(tls, transport_parameters(config)).unwrap();
        NativeQuicUdpConnection::accept(
            cx,
            endpoint,
            driver,
            initial,
            server_cid,
            config,
            MANAGED_ALPN,
        )
        .await
        .expect("real TLS server handshake")
    } else {
        let tls = client_config(
            vec![parse_one_cert(CA_CERT_PEM)],
            vec![MANAGED_ALPN.to_vec()],
        )
        .unwrap();
        let driver = QuicHandshakeDriver::client(
            tls,
            ServerName::try_from("localhost").unwrap(),
            transport_parameters(config),
        )
        .unwrap();
        NativeQuicUdpConnection::connect(
            cx,
            endpoint,
            server_addr,
            driver,
            initial,
            client_cid,
            config,
            MANAGED_ALPN,
        )
        .await
        .expect("real CA, hostname and signature verified client handshake")
    }
}

fn managed_import(cx: &Cx, owner: NativeQuicUdpConnection, server: bool) -> ManagedQuicEndpoint {
    let local = owner.local_addr();
    let peer = owner.peer_addr();
    let local_cid = owner.local_connection_id();
    let peer_cid = owner.peer_connection_id();
    assert_ne!(local_cid, peer_cid);
    assert!(owner.connection().can_send_app_data());
    let config = ManagedEndpointConfig {
        is_server: server,
        packet_batch_size: 2,
        ..ManagedEndpointConfig::default()
    };
    let refusal = owner
        .into_managed(
            cx,
            ManagedEndpointConfig {
                packet_batch_size: 0,
                ..config.clone()
            },
        )
        .expect_err("invalid scheduling configuration must return the authenticated owner");
    assert!(matches!(
        refusal.error(),
        ManagedEndpointError::InvalidConfig(_)
    ));
    let owner = refusal.into_connection();
    assert_eq!(owner.local_addr(), local);
    assert_eq!(owner.peer_addr(), peer);
    assert_eq!(owner.local_connection_id(), local_cid);
    assert_eq!(owner.peer_connection_id(), peer_cid);
    assert_eq!(owner.negotiated_alpn(), MANAGED_ALPN);
    assert!(owner.connection().can_send_app_data());
    let mut endpoint = owner
        .into_managed(cx, config)
        .expect("lossless managed adoption");
    assert_eq!(endpoint.local_addr(), local);
    assert_eq!(endpoint.negotiated_alpn(local_cid).unwrap(), MANAGED_ALPN);
    assert_eq!(endpoint.connection_stats().active_connections, 1);
    assert_eq!(endpoint.connection_stats().established_connections, 1);
    endpoint
        .with_connection_mut(cx, local_cid, |connection| {
            assert!(connection.can_send_app_data());
        })
        .unwrap();
    assert!(matches!(
        endpoint.take_connection(cx, local_cid),
        Err(ManagedEndpointError::ConnectionRouter(
            asupersync::net::quic_native::ConnectionRouterError::InvalidConnectionState { .. }
        ))
    ));
    assert_eq!(endpoint.connection_stats().active_connections, 1);
    endpoint
}

async fn managed_exchange(
    cx: &Cx,
    endpoint: &mut ManagedQuicEndpoint,
    metrics: &asupersync::net::quic_native::endpoint::EndpointMetrics,
    server: bool,
    round: usize,
) -> serde_json::Value {
    let (_, client_cid, server_cid) = managed_ids();
    let cid = if server { server_cid } else { client_cid };
    let payload = format!(
        "managed-public-round-{round}:{}",
        "abcdef0123456789".repeat(32)
    );
    let sent_before = metrics.packets_sent.load(Ordering::SeqCst);
    let received_before = metrics.packets_received.load(Ordering::SeqCst);
    let mut stream = if server {
        None
    } else {
        Some(
            endpoint
                .with_connection_mut(cx, cid, |connection| {
                    let stream = connection.open_bidi_stream(cx).unwrap();
                    connection
                        .write_stream(cx, stream, Bytes::from(payload.clone()), true)
                        .unwrap();
                    stream
                })
                .unwrap(),
        )
    };
    let mut received = Vec::new();
    let mut fin = false;
    let mut reply_queued = !server;
    let mut send_floor = None;
    let mut polls = 0_u64;
    let started = Instant::now();
    endpoint.run_event_loop_with_application(cx, |cx, endpoint, task_cx| {
        polls += 1;
        assert!(polls <= 1_000_000 && started.elapsed() < Duration::from_secs(15),
            "managed public exchange must progress despite a self-waking application; server={server} round={round} polls={polls} received={}", received.len());
        let settled = endpoint.with_connection_mut(cx, cid, |connection| {
            for _ in 0..8 {
                let readiness = match connection.poll_next_readable_stream(cx, task_cx) {
                    Poll::Ready(Ok(readiness)) => readiness,
                    Poll::Ready(Err(error)) => panic!("authenticated stream readiness: {error}"),
                    Poll::Pending => break,
                };
                if let Some(expected) = stream {
                    assert_eq!(readiness.stream_id, expected, "one stream per exchange");
                } else {
                    stream = Some(readiness.stream_id);
                }
                let bytes = connection.read_stream(cx, readiness.stream_id, 256).unwrap();
                received.extend_from_slice(&bytes);
                assert!(received.len() <= payload.len(), "no duplicated or extra application bytes");
                fin |= connection.is_control_eof(readiness.stream_id).unwrap();
            }
            if fin && received.len() == payload.len() {
                assert_eq!(received.as_slice(), payload.as_bytes());
                send_floor.get_or_insert_with(|| metrics.packets_sent.load(Ordering::SeqCst));
                if !reply_queued {
                    connection.write_stream(cx, stream.unwrap(), Bytes::from(payload.clone()), true).unwrap();
                    reply_queued = true;
                }
                !connection.has_pending_stream_frames(stream.unwrap())
                    && connection.path_stats().bytes_in_flight == 0
                    && metrics.packets_sent.load(Ordering::SeqCst) > send_floor.unwrap()
            } else {
                false
            }
        }).unwrap();
        if settled {
            Poll::Ready(Ok(()))
        } else {
            // Intentional adversarial application readiness. Before the
            // fairness repair this selects the callback forever before UDP.
            task_cx.waker().wake_by_ref();
            Poll::Pending
        }
    }).await.expect("actual managed UDP application exchange");
    let sent = metrics.packets_sent.load(Ordering::SeqCst) - sent_before;
    let ingress = metrics.packets_received.load(Ordering::SeqCst) - received_before;
    assert!(
        sent > 0 && ingress > 0,
        "both native UDP directions must progress"
    );
    assert!(fin && reply_queued);
    assert_eq!(received.len(), payload.len());
    let receipt = serde_json::json!({
        "server": server, "round": round, "application_polls": polls,
        "received_bytes": received.len(), "packets_sent": sent,
        "packets_received": ingress, "elapsed_micros": started.elapsed().as_micros(),
        "stream": stream.unwrap().0, "fin": fin,
        "intentional_self_wake": true, "performance_claim": false,
    });
    println!("MANAGED_QUIC_ROUND {receipt}");
    receipt
}

struct ManagedParentWake {
    parent: Waker,
    wakes: AtomicUsize,
}

impl Wake for ManagedParentWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        self.parent.wake_by_ref();
    }
}

async fn managed_park_drop(cx: &Cx, endpoint: &mut ManagedQuicEndpoint) -> Waker {
    let proxy = std::sync::Mutex::new(None::<Waker>);
    let mut driver = Box::pin(
        endpoint.run_event_loop_with_application(cx, |_, _, task_cx| {
            *proxy.lock().unwrap() = Some(task_cx.waker().clone());
            Poll::<Result<(), ManagedEndpointError>>::Pending
        }),
    );
    let mut parent = None::<Arc<ManagedParentWake>>;
    let mut attempts = 0;
    std::future::poll_fn(|task_cx| {
        attempts += 1;
        assert!(
            attempts <= 512,
            "managed loop must actually park without application self-wakes"
        );
        let parent = parent.get_or_insert_with(|| {
            Arc::new(ManagedParentWake {
                parent: task_cx.waker().clone(),
                wakes: AtomicUsize::new(0),
            })
        });
        let waker = Waker::from(Arc::clone(parent));
        let before = parent.wakes.load(Ordering::SeqCst);
        let pending = driver
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending();
        assert!(pending, "idle managed driver cannot complete spontaneously");
        if proxy.lock().unwrap().is_some() && parent.wakes.load(Ordering::SeqCst) == before {
            Poll::Ready(())
        } else {
            task_cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
    drop(driver);
    let parent = parent.unwrap();
    let retained = proxy.into_inner().unwrap().unwrap();
    let before = parent.wakes.load(Ordering::SeqCst);
    retained.wake_by_ref();
    assert_eq!(
        parent.wakes.load(Ordering::SeqCst),
        before,
        "dropping the parked driver must detach its retained application proxy"
    );
    println!("MANAGED_QUIC_PARK_DROP attempts={attempts} old_parent_wakes={before} detached=true");
    retained
}

async fn managed_cancel_parked(cx: &Cx, mut endpoint: ManagedQuicEndpoint) -> ManagedQuicEndpoint {
    let parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let child_parked = Arc::clone(&parked);
    let mut task = cx
        .spawn(move |child_cx| {
            // Keep the native nested task Send check explicit without asking
            // the TLS lane to recursively expand both complete task types.
            let future: std::pin::Pin<
                Box<
                    dyn Future<Output = (ManagedQuicEndpoint, Result<(), ManagedEndpointError>)>
                        + Send,
                >,
            > = Box::pin(async move {
                let mut driver = Box::pin(
                    endpoint.run_event_loop_with_application(&child_cx, |_, _, _| {
                        Poll::<Result<(), ManagedEndpointError>>::Pending
                    }),
                );
                let mut parent = None::<Arc<ManagedParentWake>>;
                let result = std::future::poll_fn(|task_cx| {
                    let parent = parent.get_or_insert_with(|| {
                        Arc::new(ManagedParentWake {
                            parent: task_cx.waker().clone(),
                            wakes: AtomicUsize::new(0),
                        })
                    });
                    let waker = Waker::from(Arc::clone(parent));
                    let before = parent.wakes.load(Ordering::SeqCst);
                    let result = driver.as_mut().poll(&mut Context::from_waker(&waker));
                    if result.is_pending() && parent.wakes.load(Ordering::SeqCst) == before {
                        child_parked.store(true, Ordering::SeqCst);
                    }
                    result
                })
                .await;
                drop(driver);
                (endpoint, result)
            });
            future
        })
        .expect("spawn native managed driver with an owned authenticated endpoint");
    let started = Instant::now();
    while !parked.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "native driver must reach actual Pending before abort"
        );
        asupersync::runtime::yield_now().await;
    }
    task.abort();
    let (endpoint, result) =
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), task.join(cx))
            .await
            .expect("parked native cancellation watchdog")
            .expect("acknowledged native cancellation retains the owner and typed result");
    assert_eq!(result, Err(ManagedEndpointError::Cancelled));
    assert_eq!(endpoint.connection_stats().active_connections, 1);
    println!("MANAGED_QUIC_CANCEL parked=true result=Cancelled retained_connections=1");
    endpoint
}

#[test]
fn authenticated_managed_public_handoff_self_wake_and_restart_cross_real_udp() {
    let runtime = managed_runtime();
    // Erase the parent type before runtime storage while retaining a checked
    // Send boundary for the complete authenticated application state machine.
    let parent: std::pin::Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().expect("actual native task Cx");
        assert!(cx.has_timer());
        let client_socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let server_socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let server_addr = server_socket.local_addr();
        let client_metrics = client_socket.metrics();
        let server_metrics = server_socket.metrics();
        let (client, server) = zip(
            managed_handshake(&cx, client_socket, false, server_addr),
            managed_handshake(&cx, server_socket, true, server_addr),
        )
        .await;
        let mut client = managed_import(&cx, client, false);
        let mut server = managed_import(&cx, server, true);
        for round in 0..2 {
            let (client_receipt, server_receipt) = zip(
                managed_exchange(&cx, &mut client, &client_metrics, false, round),
                managed_exchange(&cx, &mut server, &server_metrics, true, round),
            )
            .await;
            assert_eq!(
                client_receipt["received_bytes"],
                server_receipt["received_bytes"]
            );
            assert_eq!(client_receipt["stream"], server_receipt["stream"]);
            if round == 0 {
                let old_client = managed_park_drop(&cx, &mut client).await;
                let old_server = managed_park_drop(&cx, &mut server).await;
                old_client.wake_by_ref();
                old_server.wake_by_ref();
                server = managed_cancel_parked(&cx, server).await;
            }
        }
        client.shutdown(&cx).await.unwrap();
        server.shutdown(&cx).await.unwrap();
        assert_eq!(client.connection_stats().active_connections, 0);
        assert_eq!(server.connection_stats().active_connections, 0);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
    });
    runtime.block_on(runtime.handle().spawn(parent));
    managed_assert_runtime_cleanup(&runtime);
}

fn managed_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn managed_source_identity() -> serde_json::Value {
    serde_json::json!({
        "test": managed_sha256(include_bytes!("quic_h3_live_udp.rs")),
        "runner": managed_sha256(include_bytes!("../scripts/run_quic_application_data_loopback_e2e.sh")),
        "manager": managed_sha256(include_bytes!("../src/net/quic_native/connection_manager.rs")),
        "managed": managed_sha256(include_bytes!("../src/net/quic_native/managed_endpoint.rs")),
        "owner": managed_sha256(include_bytes!("../src/net/quic_native/udp_connection.rs")),
        "endpoint": managed_sha256(include_bytes!("../src/net/quic_native/endpoint.rs")),
        "application": managed_sha256(include_bytes!("../src/net/quic_native/endpoint_api.rs")),
        "exports": managed_sha256(include_bytes!("../src/net/quic_native/mod.rs")),
    })
}

fn managed_executable_sha256() -> String {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let expected = file.metadata().unwrap().len();
    assert!(
        expected > 0 && expected <= 512 * 1024 * 1024,
        "bounded executable identity"
    );
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        total += count as u64;
        assert!(total <= expected);
        hasher.update(&buffer[..count]);
    }
    assert_eq!(total, expected);
    hex::encode(hasher.finalize())
}

fn managed_write_receipt(path: &std::path::Path, value: &serde_json::Value) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    serde_json::to_writer(&mut file, value).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "selected explicitly by the managed two-process parent with a bounded artifact directory"]
fn authenticated_managed_process_peer() {
    let role =
        std::env::var("ASUPERSYNC_MANAGED_QUIC_ROLE").expect("parent supplies the child role");
    assert!(role == "server" || role == "client");
    let server = role == "server";
    let artifacts = std::path::PathBuf::from(
        std::env::var_os("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_DIR")
            .expect("parent artifact directory"),
    );
    assert!(artifacts.is_dir());
    let source = managed_source_identity();
    let executable = managed_executable_sha256();
    let runtime = managed_runtime();
    // This checked Send coercion keeps nested task wrappers from recursively
    // expanding the complete parent type in the strict TLS contributor lane.
    let parent: std::pin::Pin<
        Box<dyn Future<Output = (std::path::PathBuf, String, serde_json::Value)> + Send>,
    > = Box::pin(async move {
        let cx = Cx::current().expect("actual native child-process task Cx");
        assert!(cx.has_timer());
        let socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let local = socket.local_addr();
        let metrics = socket.metrics();
        let server_addr = if server {
            managed_write_receipt(
                &artifacts.join("server-ready.json"),
                &serde_json::json!({
                    "server_addr": local.to_string(), "pid": std::process::id(),
                    "source": source, "executable_sha256": executable,
                }),
            );
            local
        } else {
            let address: std::net::SocketAddr =
                std::env::var("ASUPERSYNC_MANAGED_QUIC_SERVER_ADDR")
                    .expect("parent supplies actual bound server address")
                    .parse()
                    .unwrap();
            assert!(address.ip().is_loopback() && address.port() != 0);
            address
        };
        let owner = managed_handshake(&cx, socket, server, server_addr).await;
        let peer = owner.peer_addr();
        let local_cid = format!("{:?}", owner.local_connection_id());
        let peer_cid = format!("{:?}", owner.peer_connection_id());
        let handshake_sent = metrics.packets_sent.load(Ordering::SeqCst);
        let handshake_received = metrics.packets_received.load(Ordering::SeqCst);
        assert!(handshake_sent > 0 && handshake_received > 0);
        let mut endpoint = managed_import(&cx, owner, server);
        let mut rounds = Vec::new();
        for round in 0..2 {
            rounds.push(managed_exchange(&cx, &mut endpoint, &metrics, server, round).await);
            if round == 0 {
                let old_proxy = managed_park_drop(&cx, &mut endpoint).await;
                endpoint = managed_cancel_parked(&cx, endpoint).await;
                old_proxy.wake_by_ref();
                // Both peers finish the parked cancellation before the next
                // request. This is process orchestration, not UDP evidence.
                managed_write_receipt(
                    &artifacts.join(format!("{role}-restart-ready.json")),
                    &serde_json::json!({"pid": std::process::id()}),
                );
                let other = artifacts.join(if server {
                    "client-restart-ready.json"
                } else {
                    "server-restart-ready.json"
                });
                let started = Instant::now();
                while !other.exists() {
                    assert!(
                        started.elapsed() < Duration::from_secs(10),
                        "other real peer did not complete cancellation; artifacts={artifacts:?}"
                    );
                    asupersync::time::sleep(cx.now(), Duration::from_millis(10)).await;
                }
            }
        }
        endpoint.shutdown(&cx).await.unwrap();
        assert_eq!(endpoint.connection_stats().active_connections, 0);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        let receipt = serde_json::json!({
            "schema": "asupersync.managed_quic.process.v1", "role": role,
            "pid": std::process::id(), "source": source, "executable_sha256": executable,
            "local_addr": local.to_string(), "peer_addr": peer.to_string(),
            "local_cid": local_cid, "peer_cid": peer_cid,
            "alpn": String::from_utf8(MANAGED_ALPN.to_vec()).unwrap(),
            "handshake_packets_sent": handshake_sent, "handshake_packets_received": handshake_received,
            "rounds": rounds, "active_connections_after_shutdown": endpoint.connection_stats().active_connections,
            "parked_cancelled_and_restarted": true,
            "same_router_multi_peer_proof": false, "socket_would_block_proof": false,
            "performance_claim": false,
        });
        (artifacts, role, receipt)
    });
    let receipt = runtime.block_on(runtime.handle().spawn(parent));
    managed_assert_runtime_cleanup(&runtime);
    let (artifacts, role, mut receipt) = receipt;
    receipt["runtime_quiescent"] = serde_json::json!(runtime.is_quiescent());
    managed_write_receipt(&artifacts.join(format!("{role}-receipt.json")), &receipt);
    println!("MANAGED_QUIC_PROCESS {receipt}");
}

struct ManagedChild(std::process::Child);

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            // Only this harness's own child is stopped, and all output files
            // survive a failed assertion or watchdog for independent review.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn managed_spawn_peer(
    artifacts: &std::path::Path,
    role: &str,
    server_addr: Option<&str>,
) -> ManagedChild {
    let stdout = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join(format!("{role}.stdout.log")))
        .unwrap();
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join(format!("{role}.stderr.log")))
        .unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "authenticated_managed_process_peer",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ASUPERSYNC_MANAGED_QUIC_ROLE", role)
        .env("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_DIR", artifacts)
        .stdout(stdout)
        .stderr(stderr);
    if let Some(address) = server_addr {
        command.env("ASUPERSYNC_MANAGED_QUIC_SERVER_ADDR", address);
    } else {
        command.env_remove("ASUPERSYNC_MANAGED_QUIC_SERVER_ADDR");
    }
    ManagedChild(
        command
            .spawn()
            .expect("spawn the actual current public test executable"),
    )
}

fn managed_print_child_logs(artifacts: &std::path::Path, role: &str) {
    for stream in ["stdout", "stderr"] {
        let path = artifacts.join(format!("{role}.{stream}.log"));
        eprintln!(
            "MANAGED_QUIC_CHILD_LOG {}\n{}",
            path.display(),
            std::fs::read_to_string(&path).unwrap()
        );
    }
}

#[test]
fn authenticated_managed_two_process_public_exchange_cancel_and_restart() {
    let base = std::env::var_os("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE")
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let artifacts = base.join(format!(
        "asupersync-managed-quic-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&artifacts).expect("fresh, retained process artifact directory");
    println!("MANAGED_QUIC_ARTIFACTS {}", artifacts.display());
    let expected_source = managed_source_identity();
    let expected_executable = managed_executable_sha256();
    let mut server = managed_spawn_peer(&artifacts, "server", None);
    let started = Instant::now();
    let ready: serde_json::Value = loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            managed_print_child_logs(&artifacts, "server");
            panic!("server exited before publishing its actual UDP bind: {status}");
        }
        if let Ok(bytes) = std::fs::read(artifacts.join("server-ready.json")) {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                break value;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "server bind watchdog; artifacts={artifacts:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(ready["pid"], server.0.id());
    assert_eq!(ready["source"], expected_source);
    assert_eq!(ready["executable_sha256"], expected_executable);
    let address = ready["server_addr"].as_str().unwrap();
    let mut client = managed_spawn_peer(&artifacts, "client", Some(address));
    assert_ne!(client.0.id(), server.0.id());
    assert_ne!(client.0.id(), std::process::id());
    assert_ne!(server.0.id(), std::process::id());
    loop {
        let server_status = server.0.try_wait().unwrap();
        let client_status = client.0.try_wait().unwrap();
        if server_status.is_some_and(|status| !status.success())
            || client_status.is_some_and(|status| !status.success())
        {
            managed_print_child_logs(&artifacts, "server");
            managed_print_child_logs(&artifacts, "client");
            panic!(
                "actual managed child failure: server={server_status:?} client={client_status:?}; artifacts={artifacts:?}"
            );
        }
        if server_status.is_some() && client_status.is_some() {
            break;
        }
        if started.elapsed() >= Duration::from_secs(45) {
            managed_print_child_logs(&artifacts, "server");
            managed_print_child_logs(&artifacts, "client");
            panic!("actual managed two-process watchdog; artifacts={artifacts:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut receipts = Vec::new();
    for (role, pid) in [("client", client.0.id()), ("server", server.0.id())] {
        managed_print_child_logs(&artifacts, role);
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(artifacts.join(format!("{role}-receipt.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["pid"], pid);
        assert_eq!(receipt["role"], role);
        assert_eq!(receipt["source"], expected_source);
        assert_eq!(receipt["executable_sha256"], expected_executable);
        assert_eq!(receipt["alpn"], std::str::from_utf8(MANAGED_ALPN).unwrap());
        assert_eq!(receipt["runtime_quiescent"], true);
        assert_eq!(receipt["active_connections_after_shutdown"], 0);
        assert_eq!(receipt["parked_cancelled_and_restarted"], true);
        let rounds = receipt["rounds"].as_array().unwrap();
        assert_eq!(rounds.len(), 2);
        for (index, round) in rounds.iter().enumerate() {
            assert_eq!(round["round"], index);
            assert_eq!(
                round["received_bytes"],
                format!(
                    "managed-public-round-{index}:{}",
                    "abcdef0123456789".repeat(32)
                )
                .len()
            );
            assert!(round["packets_sent"].as_u64().unwrap() > 0);
            assert!(round["packets_received"].as_u64().unwrap() > 0);
            assert!(round["application_polls"].as_u64().unwrap() > 0);
            assert_eq!(round["fin"], true);
        }
        let stdout = std::fs::read_to_string(artifacts.join(format!("{role}.stdout.log"))).unwrap();
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "each helper must actually execute one successful test"
        );
        let emitted = stdout
            .lines()
            .filter_map(|line| {
                line.split_once("MANAGED_QUIC_PROCESS ")
                    .map(|(_, json)| json)
            })
            .map(|json| serde_json::from_str::<serde_json::Value>(json).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(emitted, vec![receipt.clone()]);
        receipts.push(receipt);
    }
    assert_eq!(receipts[0]["local_addr"], receipts[1]["peer_addr"]);
    assert_eq!(receipts[1]["local_addr"], receipts[0]["peer_addr"]);
    assert_eq!(receipts[0]["local_cid"], receipts[1]["peer_cid"]);
    assert_eq!(receipts[1]["local_cid"], receipts[0]["peer_cid"]);
    for round in 0..2 {
        assert_eq!(
            receipts[0]["rounds"][round]["stream"],
            receipts[1]["rounds"][round]["stream"]
        );
    }
    let summary = serde_json::json!({
        "schema": "asupersync.managed_quic.two_process.v1", "children": receipts,
        "actual_child_count": 2, "actual_authenticated_sessions": 1,
        "source": expected_source, "executable_sha256": expected_executable,
        "same_router_multi_peer_proof": false, "socket_would_block_proof": false,
        "performance_claim": false,
    });
    managed_write_receipt(&artifacts.join("summary.json"), &summary);
    println!("MANAGED_QUIC_TWO_PROCESS {summary}");
}

#[test]
#[ignore = "selected by the maintained runner; requires isolated Linux network namespaces and actual kernel EAGAIN"]
fn authenticated_managed_kernel_backpressure() {
    #[cfg(target_os = "linux")]
    managed_kernel_backpressure::run();
    #[cfg(not(target_os = "linux"))]
    panic!(
        "declared_unavailable: authenticated kernel backpressure requires Linux network namespaces"
    );
}

#[cfg(target_os = "linux")]
mod managed_kernel_backpressure {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;

    const ENTRY: &str = "authenticated_managed_kernel_backpressure";
    const PAYLOAD_LEN: usize = 32 * 1024;

    fn payload() -> Bytes {
        Bytes::from(
            (0..PAYLOAD_LEN)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>(),
        )
    }

    fn optional_receipt(path: &Path) -> Option<serde_json::Value> {
        match std::fs::read(path) {
            Ok(bytes) => {
                assert!(bytes.len() <= 64 * 1024, "bounded orchestration receipt");
                // A create_new writer may still be completing its first write.
                serde_json::from_slice(&bytes).ok()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read retained kernel receipt {path:?}: {error}"),
        }
    }

    async fn wait_receipt(cx: &Cx, path: &Path) -> serde_json::Value {
        let started = Instant::now();
        loop {
            if let Some(value) = optional_receipt(path) {
                return value;
            }
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "kernel orchestration watchdog: {path:?}"
            );
            // This is bounded external-process orchestration, not an idle-loop
            // or timer-performance observation of the managed driver.
            asupersync::time::sleep(cx.now(), Duration::from_millis(10)).await;
        }
    }

    #[derive(Default)]
    struct ParkState {
        parked: AtomicBool,
        polls: AtomicUsize,
        wakes: AtomicUsize,
    }

    struct DriverWake {
        parent: Waker,
        state: Arc<ParkState>,
    }

    impl Wake for DriverWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.state.wakes.fetch_add(1, Ordering::SeqCst);
            self.parent.wake_by_ref();
        }
    }

    async fn cancel_after_kernel_wait(
        cx: &Cx,
        mut endpoint: ManagedQuicEndpoint,
        artifacts: &Path,
    ) -> ManagedQuicEndpoint {
        let state = Arc::new(ParkState::default());
        let child_state = Arc::clone(&state);
        let mut task = cx
            .spawn(move |child_cx| {
                let future: std::pin::Pin<
                    Box<
                        dyn Future<Output = (ManagedQuicEndpoint, Result<(), ManagedEndpointError>)>
                            + Send,
                    >,
                > = Box::pin(async move {
                    let mut driver = Box::pin(
                        endpoint.run_event_loop_with_application(&child_cx, |_, _, _| {
                            Poll::<Result<(), ManagedEndpointError>>::Pending
                        }),
                    );
                    let mut wake = None::<Arc<DriverWake>>;
                    let result = std::future::poll_fn(|task_cx| {
                        child_state.parked.store(false, Ordering::SeqCst);
                        let polls = child_state.polls.fetch_add(1, Ordering::SeqCst) + 1;
                        assert!(
                            polls <= 1_000_000,
                            "bounded actual backpressure driver polls"
                        );
                        let wake = wake.get_or_insert_with(|| {
                            Arc::new(DriverWake {
                                parent: task_cx.waker().clone(),
                                state: Arc::clone(&child_state),
                            })
                        });
                        let waker = Waker::from(Arc::clone(wake));
                        let before = child_state.wakes.load(Ordering::SeqCst);
                        let result = driver.as_mut().poll(&mut Context::from_waker(&waker));
                        if result.is_pending() && child_state.wakes.load(Ordering::SeqCst) == before
                        {
                            child_state.parked.store(true, Ordering::SeqCst);
                        }
                        result
                    })
                    .await;
                    drop(driver);
                    (endpoint, result)
                });
                future
            })
            .expect("native task owns the actual authenticated backpressured endpoint");
        let started = Instant::now();
        let witness = loop {
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "real EAGAIN and stable Pending required before abort; artifacts={artifacts:?}"
            );
            if let Some(witness) = optional_receipt(&artifacts.join("kernel-eagain.json")) {
                // This parent and the driver run on the same current-thread
                // runtime. Clearing on every poll excludes an earlier idle
                // Pending while the driver is now making synchronous progress.
                if state.parked.load(Ordering::SeqCst) {
                    break witness;
                }
            }
            asupersync::runtime::yield_now().await;
        };
        assert_eq!(witness["pid"], std::process::id());
        assert_eq!(witness["errno"], "EAGAIN");
        assert!(witness["ciphertext_bytes"].as_u64().unwrap() > 20);
        assert!(witness["accepted_prefix_packets"].as_u64().unwrap() > 0);
        let polls_before = state.polls.load(Ordering::SeqCst);
        let wakes_before = state.wakes.load(Ordering::SeqCst);
        assert!(polls_before > 0);
        task.abort();
        let (endpoint, result) =
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), task.join(cx))
                .await
                .expect("actual parked abort wakes the driver")
                .expect("acknowledged cancellation returns its owned endpoint");
        assert_eq!(result, Err(ManagedEndpointError::Cancelled));
        assert!(
            state.polls.load(Ordering::SeqCst) > polls_before,
            "cancel must cause an actual driver repoll"
        );
        assert!(
            state.wakes.load(Ordering::SeqCst) > wakes_before,
            "cancel must wake the registered parked task"
        );
        assert_eq!(endpoint.connection_stats().active_connections, 1);
        assert!(
            cx.checkpoint().is_ok(),
            "the healthy parent Cx was never cleared or cancelled"
        );
        managed_write_receipt(
            &artifacts.join("kernel-cancelled.json"),
            &serde_json::json!({
                "pid": std::process::id(), "typed_result": "Cancelled", "parked_before_abort": true,
                "polls_before_abort": polls_before, "polls_after_abort": state.polls.load(Ordering::SeqCst),
                "wakes_before_abort": wakes_before, "wakes_after_abort": state.wakes.load(Ordering::SeqCst),
                "retained_connections": endpoint.connection_stats().active_connections,
                "ciphertext_sha256": witness["ciphertext_sha256"],
            }),
        );
        println!(
            "MANAGED_QUIC_KERNEL_CANCEL parked=true syscall=EAGAIN result=Cancelled retained_connections=1"
        );
        endpoint
    }

    async fn finish_payload(
        cx: &Cx,
        endpoint: &mut ManagedQuicEndpoint,
        metrics: &asupersync::net::quic_native::endpoint::EndpointMetrics,
        server: bool,
    ) -> serde_json::Value {
        let (_, client_cid, server_cid) = managed_ids();
        let cid = if server { server_cid } else { client_cid };
        let expected = payload();
        let stream = asupersync::net::quic_native::StreamId(4);
        let mut received = Vec::new();
        let mut fin = false;
        let mut response_queued = !server;
        let mut application_writes = 0_u64;
        let mut send_floor = None;
        let mut polls = 0_u64;
        let started = Instant::now();
        let sent_before = metrics.packets_sent.load(Ordering::SeqCst);
        let received_before = metrics.packets_received.load(Ordering::SeqCst);
        endpoint
            .run_event_loop_with_application(cx, |cx, endpoint, task_cx| {
                polls += 1;
                assert!(
                    polls <= 1_000_000 && started.elapsed() < Duration::from_secs(20),
                    "bounded authenticated retained-payload recovery; server={server}"
                );
                let settled = endpoint
                    .with_connection_mut(cx, cid, |connection| {
                        for _ in 0..32 {
                            let readiness = match connection.poll_next_readable_stream(cx, task_cx)
                            {
                                Poll::Ready(Ok(readiness)) => readiness,
                                Poll::Ready(Err(error)) => {
                                    panic!("live kernel recovery stream readiness: {error}")
                                }
                                Poll::Pending => break,
                            };
                            assert_eq!(readiness.stream_id, stream);
                            assert_eq!(readiness.reset, None);
                            assert_eq!(readiness.receive_stopped, None);
                            let bytes = connection.read_stream(cx, stream, 4096).unwrap();
                            received.extend_from_slice(&bytes);
                            assert!(
                                received.len() <= expected.len(),
                                "no duplicate application bytes"
                            );
                            fin |= connection.is_control_eof(stream).unwrap();
                        }
                        if fin && received.len() == expected.len() {
                            assert_eq!(received.as_slice(), expected.as_ref());
                            send_floor
                                .get_or_insert_with(|| metrics.packets_sent.load(Ordering::SeqCst));
                            if !response_queued {
                                connection
                                    .write_stream(cx, stream, expected.clone(), true)
                                    .unwrap();
                                application_writes += 1;
                                response_queued = true;
                            }
                            !connection.has_pending_stream_frames(stream)
                                && connection.path_stats().bytes_in_flight == 0
                                && metrics.packets_sent.load(Ordering::SeqCst) > send_floor.unwrap()
                        } else {
                            false
                        }
                    })
                    .unwrap();
                if settled {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await
            .expect(
                "same authenticated owner completes retained bytes after actual kernel recovery",
            );
        let sent = metrics.packets_sent.load(Ordering::SeqCst) - sent_before;
        let ingress = metrics.packets_received.load(Ordering::SeqCst) - received_before;
        assert!(sent > 0 && ingress > 0 && fin && response_queued);
        assert_eq!(received.len(), PAYLOAD_LEN);
        serde_json::json!({
            "stream": stream.0, "received_bytes": received.len(), "sha256": managed_sha256(&received),
            "fin": fin, "packets_sent": sent, "packets_received": ingress,
            "application_polls": polls, "application_self_wake": false,
            "application_writes": application_writes,
            "elapsed_micros": started.elapsed().as_micros(), "performance_claim": false,
        })
    }

    fn peer(role: String, artifacts: PathBuf) {
        let server = role == "server";
        assert!(server || role == "client");
        let runtime = managed_runtime();
        let parent: std::pin::Pin<Box<dyn Future<Output = serde_json::Value> + Send>> = Box::pin(
            async move {
                let cx = Cx::current().expect("actual native kernel peer task Cx");
                let socket = QuicUdpEndpoint::bind(
                    &cx,
                    if server { "192.0.2.2:0" } else { "192.0.2.1:0" }
                        .parse()
                        .unwrap(),
                    QuicUdpEndpointConfig {
                        socket_send_buffer_size: Some(
                            asupersync::net::udp::UDP_MIN_SOCKET_BUFFER_BYTES,
                        ),
                        max_batch_size: 1,
                        ..QuicUdpEndpointConfig::default()
                    },
                )
                .await
                .unwrap();
                let local = socket.local_addr();
                let metrics = socket.metrics();
                let buffers = socket.buffer_report();
                assert_eq!(
                    buffers.requested_send_buffer_bytes,
                    Some(asupersync::net::udp::UDP_MIN_SOCKET_BUFFER_BYTES)
                );
                assert!(
                    buffers.applied_send_buffer_bytes.unwrap()
                        >= buffers.requested_send_buffer_bytes.unwrap()
                );
                let source = managed_source_identity();
                let executable = managed_executable_sha256();
                let server_addr = if server {
                    managed_write_receipt(
                        &artifacts.join("kernel-server-ready.json"),
                        &serde_json::json!({
                            "pid": std::process::id(), "server_addr": local.to_string(),
                            "source": source, "executable_sha256": executable,
                        }),
                    );
                    local
                } else {
                    std::env::var("ASUPERSYNC_MANAGED_QUIC_SERVER_ADDR")
                        .unwrap()
                        .parse()
                        .unwrap()
                };
                let owner = managed_handshake(&cx, socket, server, server_addr).await;
                let peer = owner.peer_addr();
                let local_cid = owner.local_connection_id();
                let peer_cid = owner.peer_connection_id();
                let mut endpoint = managed_import(&cx, owner, server);
                let healthy = managed_exchange(&cx, &mut endpoint, &metrics, server, 0).await;
                let identity = serde_json::json!({
                    "pid": std::process::id(), "role": role, "source": source,
                    "executable_sha256": executable, "local_addr": local.to_string(), "peer_addr": peer.to_string(),
                    "local_cid": format!("{local_cid:?}"), "peer_cid": format!("{peer_cid:?}"),
                    "alpn": std::str::from_utf8(endpoint.negotiated_alpn(local_cid).unwrap()).unwrap(),
                    "netns": std::fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(),
                    "requested_send_buffer": buffers.requested_send_buffer_bytes,
                    "applied_send_buffer": buffers.applied_send_buffer_bytes,
                    "healthy_round": healthy,
                });
                managed_write_receipt(
                    &artifacts.join(format!("kernel-{role}-healthy.json")),
                    &identity,
                );
                let mut application_writes = 0_u64;
                if !server {
                    let blocked = wait_receipt(&cx, &artifacts.join("kernel-blocked.json")).await;
                    assert_eq!(blocked["client_pid"], std::process::id());
                    assert_eq!(blocked["peer_addr"], peer.to_string());
                    let stream = endpoint
                        .with_connection_mut(&cx, local_cid, |connection| {
                            let stream = connection.open_bidi_stream(&cx).unwrap();
                            // Exactly one application write; recovery never recreates
                            // these bytes or clears the cancellation on the old task.
                            connection
                                .write_stream(&cx, stream, payload(), true)
                                .unwrap();
                            application_writes += 1;
                            stream
                        })
                        .unwrap();
                    assert_eq!(stream.0, 4);
                    endpoint = cancel_after_kernel_wait(&cx, endpoint, &artifacts).await;
                    assert_eq!(endpoint.negotiated_alpn(local_cid).unwrap(), MANAGED_ALPN);
                    endpoint
                        .with_connection_mut(&cx, local_cid, |connection| {
                            assert!(connection.can_send_app_data())
                        })
                        .unwrap();
                    let recovered =
                        wait_receipt(&cx, &artifacts.join("kernel-recovered.json")).await;
                    assert_eq!(recovered["client_pid"], std::process::id());
                }
                let recovery = finish_payload(&cx, &mut endpoint, &metrics, server).await;
                application_writes += recovery["application_writes"].as_u64().unwrap();
                assert_eq!(
                    application_writes, 1,
                    "one successful payload publication across cancellation and recovery"
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
                serde_json::json!({
                    "identity": identity, "recovery": recovery,
                    "application_payload_writes": application_writes, "active_connections_after_shutdown": endpoint.connection_stats().active_connections,
                    "pending_timers_after_shutdown": cx.timer_driver().unwrap().pending_count(),
                    "same_router_multi_peer_proof": false, "performance_claim": false,
                })
            },
        );
        let mut receipt = runtime.block_on(runtime.handle().spawn(parent));
        managed_assert_runtime_cleanup(&runtime);
        receipt["runtime_quiescent"] = serde_json::json!(runtime.is_quiescent());
        let role = receipt["identity"]["role"].as_str().unwrap();
        let artifacts =
            PathBuf::from(std::env::var_os("ASUPERSYNC_MANAGED_QUIC_KERNEL_DIR").unwrap());
        managed_write_receipt(
            &artifacts.join(format!("kernel-{role}-receipt.json")),
            &receipt,
        );
        println!("MANAGED_QUIC_KERNEL_PEER {receipt}");
    }

    pub(super) fn run() {
        if let Ok(role) = std::env::var("ASUPERSYNC_MANAGED_QUIC_KERNEL_ROLE") {
            peer(
                role,
                PathBuf::from(std::env::var_os("ASUPERSYNC_MANAGED_QUIC_KERNEL_DIR").unwrap()),
            );
            return;
        }
        let base = std::env::var_os("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE")
            .map_or_else(std::env::temp_dir, PathBuf::from);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let artifacts = base.join(format!(
            "asupersync-managed-quic-kernel-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&artifacts).expect("fresh retained kernel artifact directory");
        let expected = serde_json::json!({
            "pid": std::process::id(), "source": managed_source_identity(),
            "executable_sha256": managed_executable_sha256(),
        });
        managed_write_receipt(&artifacts.join("kernel-parent.json"), &expected);
        println!("MANAGED_QUIC_KERNEL_ARTIFACTS {}", artifacts.display());
        let stdout = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(artifacts.join("kernel-controller.stdout.log"))
            .unwrap();
        let stderr = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(artifacts.join("kernel-controller.stderr.log"))
            .unwrap();
        let runner = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts/run_quic_application_data_loopback_e2e.sh");
        let mut controller = ManagedChild(
            std::process::Command::new("sudo")
                .args([
                    "-n",
                    "timeout",
                    "--signal=TERM",
                    "--kill-after=10s",
                    "55s",
                    "unshare",
                    "--net",
                    "bash",
                ])
                .arg(runner)
                .arg("--kernel-controller")
                .arg(std::env::current_exe().unwrap())
                .arg(&artifacts)
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .expect("start owned isolated kernel controller"),
        );
        let started = Instant::now();
        let status = loop {
            if let Some(status) = controller.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(75),
                "kernel controller watchdog; retained artifacts={artifacts:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        for role in ["controller", "client", "server"] {
            for stream in ["stdout", "stderr"] {
                let path = artifacts.join(format!("kernel-{role}.{stream}.log"));
                if path.exists() {
                    eprintln!(
                        "MANAGED_QUIC_KERNEL_LOG {}\n{}",
                        path.display(),
                        std::fs::read_to_string(path).unwrap()
                    );
                }
            }
        }
        assert!(
            status.success(),
            "kernel capability/setup/syscall/peer failure: {status}; artifacts={artifacts:?}"
        );
        let summary = optional_receipt(&artifacts.join("kernel-summary.json"))
            .expect("actual controller summary");
        assert_eq!(summary["source"], expected["source"]);
        assert_eq!(summary["executable_sha256"], expected["executable_sha256"]);
        assert_eq!(summary["actual_authenticated_sessions"], 1);
        assert_eq!(summary["actual_child_count"], 2);
        assert_eq!(summary["syscall_errno"], "EAGAIN");
        assert_eq!(summary["same_ciphertext_retry"], true);
        assert_eq!(summary["parked_cancellation_and_recovery"], true);
        for role in ["client", "server"] {
            let receipt =
                optional_receipt(&artifacts.join(format!("kernel-{role}-receipt.json"))).unwrap();
            assert_eq!(receipt["identity"]["source"], expected["source"]);
            assert_eq!(
                receipt["identity"]["executable_sha256"],
                expected["executable_sha256"]
            );
            assert_eq!(receipt["recovery"]["received_bytes"], PAYLOAD_LEN);
            assert_eq!(receipt["recovery"]["sha256"], managed_sha256(&payload()));
            assert_eq!(receipt["recovery"]["fin"], true);
            assert_eq!(receipt["application_payload_writes"], 1);
            assert_eq!(receipt["active_connections_after_shutdown"], 0);
            assert_eq!(receipt["pending_timers_after_shutdown"], 0);
            assert_eq!(receipt["runtime_quiescent"], true);
            let stdout =
                std::fs::read_to_string(artifacts.join(format!("kernel-{role}.stdout.log")))
                    .unwrap();
            assert!(stdout.contains(&format!("test {ENTRY} ...")));
            assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        }
        println!("MANAGED_QUIC_KERNEL_TWO_PROCESS {summary}");
    }
}
