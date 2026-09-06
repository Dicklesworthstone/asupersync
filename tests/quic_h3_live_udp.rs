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
        "handshake_driver": managed_sha256(include_bytes!("../src/net/quic_native/handshake_driver.rs")),
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
        // Request the maintained UDP normalization floor through the public config.
        const REQUESTED_SEND_BUFFER_BYTES: usize = 8 * 1024;
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
                        socket_send_buffer_size: Some(REQUESTED_SEND_BUFFER_BYTES),
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
                    Some(REQUESTED_SEND_BUFFER_BYTES)
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
                        std::fs::read_to_string(&path).unwrap()
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

// Public, real TLS admission on one retained server socket. File barriers only
// orchestrate owned processes; every application byte and TLS flight uses UDP.
mod managed_multi_peer {
    use super::*;
    use asupersync::net::quic_native::StreamId;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::pki_types::UnixTime;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Mutex;

    const ENTRY: &str = "managed_multi_peer::authenticated_same_socket_process_peer";
    const RECORD_BYTES: usize = 520;
    const LIMIT: Duration = Duration::from_secs(90);
    const ALPN_REFUSAL: &[u8] = b"asupersync-other-required-alpn";

    // Test-only P-256 CA and two distinct clientAuth leaves, generated with
    // OpenSSL on 2026-09-06, valid through 2126. Their private keys are fixtures.
    // Server authentication still uses the original localhost server CA above.
    const CLIENT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBwDCCAWWgAwIBAgIUEIMjYN1/OQpW639f3etdK1M0vyUwCgYIKoZIzj0EAwIw
LDEqMCgGA1UEAwwhYXN1cGVyc3luYy1tYW5hZ2VkLWNsaWVudC10ZXN0LWNhMCAX
DTI2MDkwNjAyMzk1NFoYDzIxMjYwODEzMDIzOTU0WjAsMSowKAYDVQQDDCFhc3Vw
ZXJzeW5jLW1hbmFnZWQtY2xpZW50LXRlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQoZx/RH9ebpolIH4QXsplFoSRZXBchn/K31jBxfhVKHNdF5FkCS2vQ
y3t8PwhN/Dbu4Sc3yuhaY2oJbfcPfwATo2MwYTAdBgNVHQ4EFgQU3CRASGP4f/wJ
G5eoDWt5VW0pRXEwHwYDVR0jBBgwFoAU3CRASGP4f/wJG5eoDWt5VW0pRXEwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIh
AJ2Ri/vKPTlHr3VivhgrgxVeQxdRiT/zJhu6mCMNmBCjAiEA2qsH/6O6+oV6lcRp
B0AVxuj0l00L4k/Cvbkl0+SI4LI=
-----END CERTIFICATE-----";
    const CLIENT_A: &str = "-----BEGIN CERTIFICATE-----
MIIBujCCAWCgAwIBAgIDASjhMAoGCCqGSM49BAMCMCwxKjAoBgNVBAMMIWFzdXBl
cnN5bmMtbWFuYWdlZC1jbGllbnQtdGVzdC1jYTAgFw0yNjA5MDYwMjQxNDFaGA8y
MTI2MDgxMzAyNDE0MVowJjEkMCIGA1UEAwwbYXN1cGVyc3luYy1tYW5hZ2VkLWNs
aWVudC1hMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcPdAe3nz/FEBv5k62h8t
KgFu++VsWA9lZR1g+YNi2f9vr+UIpwmTKEs/QXlKP63JCbwX8fxSCWjEYBCcuFQc
yKN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwHQYDVR0OBBYEFEiiFrGSmg8Sbz6vKjK0OUBQ2V59MB8GA1UdIwQY
MBaAFNwkQEhj+H/8CRuXqA1reVVtKUVxMAoGCCqGSM49BAMCA0gAMEUCIDHVkk9n
5RxjJ557vevZfKhr72qsd5lRyiw0sawqdBXnAiEAsg6QUyCkoWkwYy1fELmmxG1h
Y7gTYbi2PQ+Qp2L0/OU=
-----END CERTIFICATE-----";
    const KEY_A: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxfkvA8LCOsWS87m/
J3+yxpKv9tmiCf9hKa81BENuXKmhRANCAARw90B7efP8UQG/mTraHy0qAW775WxY
D2VlHWD5g2LZ/2+v5QinCZMoSz9BeUo/rckJvBfx/FIJaMRgEJy4VBzI
-----END PRIVATE KEY-----";
    const CLIENT_B: &str = "-----BEGIN CERTIFICATE-----
MIIBujCCAWCgAwIBAgIDASjiMAoGCCqGSM49BAMCMCwxKjAoBgNVBAMMIWFzdXBl
cnN5bmMtbWFuYWdlZC1jbGllbnQtdGVzdC1jYTAgFw0yNjA5MDYwMjQxNDJaGA8y
MTI2MDgxMzAyNDE0MlowJjEkMCIGA1UEAwwbYXN1cGVyc3luYy1tYW5hZ2VkLWNs
aWVudC1iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEin7EQaQE/jyQMedJCVsC
dZUvqfzmGLdV38dDRsTs8w2mQkpawCV7pPivlMYZqn1psFZM741n2c0BMIv6pg2R
R6N1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwHQYDVR0OBBYEFD9nDyeLuza7LhDn7O/TO/J5szk9MB8GA1UdIwQY
MBaAFNwkQEhj+H/8CRuXqA1reVVtKUVxMAoGCCqGSM49BAMCA0gAMEUCIHhXINXA
VZVhy1c0GI/ngUIqjaLNlD9giaB4pUnHpjyeAiEAr9eIyHhqnKFH2oo0NCnvjWvJ
BI3fS+5xW76cQv+CzQA=
-----END CERTIFICATE-----";
    const KEY_B: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgm6eVm3a91HGqmTuu
os0+hAWMCKuPdEau+XlPDfrjhsmhRANCAASKfsRBpAT+PJAx50kJWwJ1lS+p/OYY
t1Xfx0NGxOzzDaZCSlrAJXuk+K+UxhmqfWmwVkzvjWfZzQEwi/qmDZFH
-----END PRIVATE KEY-----";

    #[derive(Debug)]
    struct VerifiedClient {
        inner: Arc<dyn ClientCertVerifier>,
        signatures: Arc<Mutex<Vec<String>>>,
    }

    impl ClientCertVerifier for VerifiedClient {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            self.inner.root_hint_subjects()
        }
        fn verify_client_cert(
            &self,
            cert: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            self.inner.verify_client_cert(cert, intermediates, now)
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, signature)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            let verified = self
                .inner
                .verify_tls13_signature(message, cert, signature)?;
            self.signatures
                .lock()
                .unwrap()
                .push(managed_sha256(cert.as_ref()));
            Ok(verified)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    fn key(pem: &str) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut pem.as_bytes())
            .unwrap()
            .unwrap()
    }

    fn multi_config() -> NativeQuicConnectionConfig {
        NativeQuicConnectionConfig {
            send_window: 8 << 20,
            recv_window: 8 << 20,
            connection_send_limit: 16 << 20,
            connection_recv_limit: 16 << 20,
            ..connection_config()
        }
    }

    fn import(cx: &Cx, owner: NativeQuicUdpConnection, server: bool) -> ManagedQuicEndpoint {
        let local = owner.local_addr();
        let cid = owner.local_connection_id();
        assert_eq!(owner.negotiated_alpn(), MANAGED_ALPN);
        assert!(owner.connection().can_send_app_data());
        let endpoint = owner
            .into_managed(
                cx,
                ManagedEndpointConfig {
                    is_server: server,
                    max_connections: 4,
                    packet_batch_size: 1,
                    connection_config: multi_config(),
                    ..ManagedEndpointConfig::default()
                },
            )
            .unwrap();
        assert_eq!(endpoint.local_addr(), local);
        assert_eq!(endpoint.negotiated_alpn(cid).unwrap(), MANAGED_ALPN);
        assert_eq!(endpoint.connection_stats().active_connections, 1);
        endpoint
    }

    fn server_driver(signatures: &Arc<Mutex<Vec<String>>>) -> QuicHandshakeDriver {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(parse_one_cert(CLIENT_CA)).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        assert!(verifier.offer_client_auth() && verifier.client_auth_mandatory());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(VerifiedClient {
                inner: verifier,
                signatures: Arc::clone(signatures),
            }))
            .with_single_cert(vec![parse_one_cert(LEAF_CERT_PEM)], leaf_key())
            .unwrap();
        config.alpn_protocols = vec![MANAGED_ALPN.to_vec()];
        QuicHandshakeDriver::server(Arc::new(config), transport_parameters(multi_config())).unwrap()
    }

    fn client_driver(identity: Option<bool>) -> QuicHandshakeDriver {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(parse_one_cert(CA_CERT_PEM)).unwrap();
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
        let mut config = if let Some(a) = identity {
            builder
                .with_client_auth_cert(
                    vec![parse_one_cert(if a { CLIENT_A } else { CLIENT_B })],
                    key(if a { KEY_A } else { KEY_B }),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![MANAGED_ALPN.to_vec()];
        QuicHandshakeDriver::client(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
            transport_parameters(multi_config()),
        )
        .unwrap()
    }

    fn ids(attempt: usize) -> (ConnectionId, ConnectionId, ConnectionId) {
        (
            ConnectionId::new(format!("multi-init-{attempt}").as_bytes()).unwrap(),
            ConnectionId::new(format!("multi-client-{attempt}").as_bytes()).unwrap(),
            ConnectionId::new(format!("server-{attempt}").as_bytes()).unwrap(),
        )
    }

    fn maybe(path: &Path) -> Option<serde_json::Value> {
        match std::fs::read(path) {
            Ok(bytes) => {
                assert!(bytes.len() <= 1024 * 1024);
                serde_json::from_slice(&bytes).ok()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("receipt {path:?}: {error}"),
        }
    }

    async fn wait(cx: &Cx, path: &Path) -> serde_json::Value {
        let started = Instant::now();
        loop {
            if let Some(value) = maybe(path) {
                return value;
            }
            assert!(
                started.elapsed() < LIMIT,
                "owned peer barrier timed out: {path:?}"
            );
            asupersync::time::sleep(cx.now(), Duration::from_millis(5)).await;
        }
    }

    fn record(sequence: usize, tag: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(&u64::try_from(sequence).unwrap().to_be_bytes());
        bytes.extend((0..512).map(|index| tag.wrapping_add(u8::try_from(index % 251).unwrap())));
        bytes
    }

    #[derive(Default)]
    struct Echo {
        bytes: Vec<u8>,
        hashes: Vec<String>,
        fin: bool,
        hold_next_reply: bool,
        held_reply: Option<Vec<u8>>,
    }

    impl Echo {
        fn poll(
            &mut self,
            cx: &Cx,
            endpoint: &mut ManagedQuicEndpoint,
            task_cx: &mut Context<'_>,
            cid: ConnectionId,
            tag: u8,
        ) {
            endpoint
                .with_connection_mut(cx, cid, |connection| {
                    for _ in 0..8 {
                        let ready = match connection.poll_next_readable_stream(cx, task_cx) {
                            Poll::Ready(Ok(ready)) => ready,
                            Poll::Ready(Err(error)) => panic!("real peer stream: {error}"),
                            Poll::Pending => break,
                        };
                        assert_eq!(ready.stream_id, StreamId(0));
                        self.bytes.extend_from_slice(
                            &connection.read_stream(cx, ready.stream_id, 1024).unwrap(),
                        );
                        while self.bytes.len() >= RECORD_BYTES {
                            let bytes: Vec<_> = self.bytes.drain(..RECORD_BYTES).collect();
                            assert!(self.hashes.len() < 8192, "bounded retained real work trace");
                            assert_eq!(bytes, record(self.hashes.len(), tag));
                            self.hashes.push(managed_sha256(&bytes));
                            if self.hold_next_reply {
                                assert!(self.held_reply.is_none());
                                self.hold_next_reply = false;
                                self.held_reply = Some(bytes);
                            } else {
                                assert!(
                                    self.held_reply.is_none(),
                                    "one outstanding A record preserves held echo order"
                                );
                                connection
                                    .write_stream(cx, ready.stream_id, Bytes::from(bytes), false)
                                    .unwrap();
                            }
                        }
                        if connection.is_control_eof(ready.stream_id).unwrap() && !self.fin {
                            assert!(self.bytes.is_empty());
                            assert!(self.held_reply.is_none() && !self.hold_next_reply);
                            self.fin = true;
                            connection
                                .write_stream(cx, ready.stream_id, Bytes::new(), true)
                                .unwrap();
                        }
                    }
                })
                .unwrap();
        }
    }

    // A bounded, deliberately ready control callback services real streams.
    // The managed driver must still give UDP and due timers their turns.
    async fn drive<T>(
        cx: &Cx,
        endpoint: &mut ManagedQuicEndpoint,
        a: &mut Echo,
        mut application: impl FnMut(
            &Cx,
            &mut ManagedQuicEndpoint,
            &mut Context<'_>,
            &mut Echo,
        ) -> Option<T>,
    ) -> T {
        let started = Instant::now();
        endpoint
            .run_event_loop_with_application(cx, |cx, endpoint, task_cx| {
                assert!(
                    started.elapsed() < LIMIT,
                    "same-socket managed progress timeout"
                );
                a.poll(cx, endpoint, task_cx, ids(0).2, b'A');
                if let Some(value) = application(cx, endpoint, task_cx, a) {
                    Poll::Ready(Ok(value))
                } else {
                    task_cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await
            .expect("actual managed server loop")
    }

    async fn server(cx: &Cx, artifacts: &Path) -> serde_json::Value {
        let socket = QuicUdpEndpoint::bind(
            cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let local = socket.local_addr();
        let metrics = socket.metrics();
        let signatures = Arc::new(Mutex::new(Vec::new()));
        managed_write_receipt(
            &artifacts.join("multi-server-ready.json"),
            &serde_json::json!({"address":local.to_string(), "pid":std::process::id(), "source":managed_source_identity(), "executable_sha256":managed_executable_sha256()}),
        );
        let owner = NativeQuicUdpConnection::accept(
            cx,
            socket,
            server_driver(&signatures),
            ids(0).0,
            ids(0).2,
            multi_config(),
            MANAGED_ALPN,
        )
        .await
        .unwrap();
        assert_eq!(owner.local_addr(), local);
        assert_eq!(owner.peer_connection_id(), ids(0).1);
        let a_peer = owner.peer_addr();
        let mut endpoint = import(cx, owner, true);
        let endpoint_id = endpoint.endpoint_id();
        assert_eq!(
            *signatures.lock().unwrap(),
            vec![managed_sha256(parse_one_cert(CLIENT_A).as_ref())]
        );
        managed_write_receipt(
            &artifacts.join("multi-a-admitted.json"),
            &serde_json::json!({"server_addr":local.to_string(), "a_peer":a_peer.to_string(), "endpoint_id":endpoint_id}),
        );
        let mut a = Echo::default();
        let mut attempts = Vec::new();
        let mut timer_witness = None;
        for attempt in 1..=5 {
            let ready_path = artifacts.join(format!("multi-{attempt}-ready.json"));
            let ready = drive(cx, &mut endpoint, &mut a, |_, _, _, _| maybe(&ready_path)).await;
            let peer: SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
            assert_ne!(peer, a_peer);
            assert!(peer.ip().is_loopback() && peer.port() != 0);
            let (initial, client_cid, server_cid) = ids(attempt);
            assert_ne!(server_cid, ids(0).2);
            if attempt == 1 {
                let refused = endpoint
                    .begin_authenticated_accept(
                        cx,
                        server_driver(&signatures),
                        peer,
                        initial,
                        ids(0).2,
                        MANAGED_ALPN,
                    )
                    .unwrap_err();
                assert!(matches!(refused, ManagedEndpointError::ConnectionRouter(asupersync::net::quic_native::ConnectionRouterError::ConnectionCreationFailed(_))));
                assert!(endpoint.take_authenticated_accept_result().is_none());
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                managed_write_receipt(
                    &artifacts.join("multi-duplicate-cid.json"),
                    &serde_json::json!({"typed_refusal":format!("{refused:?}"), "active_connections":1}),
                );
            }
            let signatures_before = signatures.lock().unwrap().len();
            let a_before = a.hashes.len();
            let received_before = metrics.packets_received.load(Ordering::SeqCst);
            let mut pto_before = endpoint
                .with_connection_mut(cx, ids(0).2, |connection| connection.path_stats().pto_count)
                .unwrap();
            endpoint
                .begin_authenticated_accept(
                    cx,
                    server_driver(&signatures),
                    peer,
                    initial,
                    server_cid,
                    if attempt == 4 {
                        ALPN_REFUSAL
                    } else {
                        MANAGED_ALPN
                    },
                )
                .unwrap();
            managed_write_receipt(
                &artifacts.join(format!("multi-{attempt}-armed.json")),
                &serde_json::json!({"server_addr":local.to_string(), "endpoint_id":endpoint_id, "initial_cid":format!("{initial:?}"), "server_cid":format!("{server_cid:?}")}),
            );
            if attempt == 1 || attempt == 2 {
                // Do not poll the server socket until the client actually
                // sends its Initial and parks. A fast server cannot complete
                // TLS inside the client's first poll before its hold barrier.
                let initial =
                    wait(cx, &artifacts.join(format!("multi-{attempt}-initial.json"))).await;
                assert!(initial["actual_packets_sent"].as_u64().unwrap() > 0);
                assert_eq!(initial["local"], peer.to_string());
                assert_eq!(initial["peer"], local.to_string());
            }
            if attempt == 1 {
                a.hold_next_reply = true;
                let mut probe_send_floor = None;
                let mut held_witness = None;
                let mut released_reply = false;
                let witness = drive(cx, &mut endpoint, &mut a, |cx, endpoint, _, a| {
                    assert!(endpoint.take_authenticated_accept_result().is_none(), "B cannot complete before its held first-flight driver resumes");
                    if !released_reply {
                        let Some(bytes) = a.held_reply.as_ref() else { return None; };
                        assert!(a.hashes.len() > a_before);
                        let sequence = a.hashes.len() - 1;
                        let digest = managed_sha256(bytes);
                        assert_eq!(a.hashes.last().unwrap(), &digest);
                        if held_witness.is_none() {
                            let observed = serde_json::json!({"sequence":sequence, "sha256":digest, "bytes":bytes.len(), "a_records_before":a_before, "b_attempt":1});
                            managed_write_receipt(&artifacts.join("multi-a-observed.json"), &observed);
                            held_witness = Some(observed);
                        }
                        let Some(paused) = maybe(&artifacts.join("multi-a-paused.json")) else { return None; };
                        assert_eq!(paused["sequence"], sequence);
                        assert_eq!(paused["sha256"], digest);
                        assert_eq!(paused["records_written"], sequence + 1);
                        assert_eq!(paused["records_received"], sequence);
                        let bytes = a.held_reply.take().unwrap();
                        endpoint.with_connection_mut(cx, ids(0).2, |connection| {
                            pto_before = connection.path_stats().pto_count;
                            connection.write_stream(cx, StreamId(0), Bytes::from(bytes), false).unwrap();
                        }).unwrap();
                        released_reply = true;
                        return None;
                    }
                    assert!(a.held_reply.is_none() && !a.hold_next_reply);
                    let stats = endpoint.with_connection_mut(cx, ids(0).2, |connection| connection.path_stats()).unwrap();
                    if stats.pto_count <= pto_before { return None; }
                    let sent = metrics.packets_sent.load(Ordering::SeqCst);
                    let floor = probe_send_floor.get_or_insert(sent);
                    if sent <= *floor { return None; }
                    assert!(stats.bytes_in_flight > 0);
                    Some(serde_json::json!({"a_records_before":a_before, "a_records_during_b_handshake":a.hashes.len(), "a_last_record_sha256":a.hashes.last().unwrap(), "a_peer_observed_record":held_witness.as_ref().unwrap(), "a_reply_queued_after_pause":released_reply, "a_pto_before":pto_before, "a_pto_after":stats.pto_count, "sent_after_pto_observation":sent-*floor, "egress_counter_scope":"shared_socket_not_CID_specific_probe_delivery", "b_tls_held_after_real_initial":true}))
                }).await;
                assert!(released_reply && a.held_reply.is_none() && !a.hold_next_reply);
                managed_write_receipt(&artifacts.join("multi-1-continue.json"), &witness);
                timer_witness = Some(witness);
            } else if attempt == 2 {
                drive(cx, &mut endpoint, &mut a, |_, endpoint, _, a| {
                    assert!(endpoint.take_authenticated_accept_result().is_none());
                    (maybe(&artifacts.join("multi-2-initial.json")).is_some()
                        && a.hashes.len() > a_before
                        && metrics.packets_received.load(Ordering::SeqCst) > received_before)
                        .then_some(())
                })
                .await;
                // Actual owner cancellation of a parked loop retains A and
                // refuses only the still-owned B admission. No test Cx forgery.
                endpoint = managed_cancel_parked(cx, endpoint).await;
                assert!(matches!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                ));
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(signatures.lock().unwrap().len(), signatures_before);
                let receipt = serde_json::json!({"attempt":attempt, "result":"cancelled", "actual_initial_sent":true, "a_records_before":a_before, "a_records_after":a.hashes.len(), "active_connections":1, "peer":peer.to_string()});
                managed_write_receipt(
                    &artifacts.join(format!("multi-{attempt}-result.json")),
                    &receipt,
                );
                attempts.push(receipt);
                drive(cx, &mut endpoint, &mut a, |_, _, _, _| {
                    maybe(&artifacts.join(format!("multi-{attempt}-done.json")))
                })
                .await;
                continue;
            }
            let result = drive(cx, &mut endpoint, &mut a, |_, endpoint, _, _| {
                endpoint.take_authenticated_accept_result()
            })
            .await;
            assert_eq!(
                endpoint.local_addr(),
                local,
                "never replace or transplant the server socket"
            );
            assert_eq!(endpoint.endpoint_id(), endpoint_id);
            assert!(metrics.packets_received.load(Ordering::SeqCst) > received_before);
            if attempt == 3 || attempt == 4 {
                let error = result.expect_err("actual no-client-certificate or ALPN rejection");
                let diagnostic = format!("{error:?}");
                if attempt == 3 {
                    assert!(
                        diagnostic.contains("read_hs_fatal_alert"),
                        "exact fatal TLS refusal for the no-client-certificate input: {diagnostic}"
                    );
                    assert_eq!(
                        signatures.lock().unwrap().len(),
                        signatures_before,
                        "a missing certificate cannot gain a verified identity"
                    );
                } else {
                    assert!(
                        diagnostic.to_ascii_lowercase().contains("alpn"),
                        "actual post-TLS required ALPN refusal: {diagnostic}"
                    );
                    assert_eq!(signatures.lock().unwrap().len(), signatures_before + 1);
                }
                assert!(
                    endpoint
                        .with_connection_mut(cx, server_cid, |_| ())
                        .is_err()
                );
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                let receipt = serde_json::json!({"attempt":attempt, "result":if attempt==3 {"client_certificate_refused"} else {"alpn_refused"}, "error":diagnostic, "peer":peer.to_string(), "active_connections":1, "a_records_before":a_before, "a_records_after":a.hashes.len()});
                managed_write_receipt(
                    &artifacts.join(format!("multi-{attempt}-result.json")),
                    &receipt,
                );
                drive(cx, &mut endpoint, &mut a, |_, _, _, _| {
                    maybe(&artifacts.join(format!("multi-{attempt}-done.json")))
                })
                .await;
                attempts.push(receipt);
                continue;
            }
            assert_eq!(result.unwrap(), server_cid);
            assert_eq!(endpoint.connection_stats().active_connections, 2);
            assert_eq!(endpoint.connection_stats().established_connections, 2);
            assert_eq!(endpoint.negotiated_alpn(server_cid).unwrap(), MANAGED_ALPN);
            assert_eq!(signatures.lock().unwrap().len(), signatures_before + 1);
            assert_eq!(
                signatures.lock().unwrap().last().unwrap(),
                &managed_sha256(parse_one_cert(CLIENT_B).as_ref())
            );
            let mut b = Echo::default();
            drive(cx, &mut endpoint, &mut a, |cx, endpoint, task_cx, _| {
                b.poll(cx, endpoint, task_cx, server_cid, b'B');
                (b.fin && maybe(&artifacts.join(format!("multi-{attempt}-payload.json"))).is_some())
                    .then_some(())
            })
            .await;
            assert_eq!(b.hashes, vec![managed_sha256(&record(0, b'B'))]);
            let queued_stream = endpoint
                .with_connection_mut(cx, server_cid, |connection| {
                    let stream = connection.open_bidi_stream(cx).unwrap();
                    connection
                        .write_stream(
                            cx,
                            stream,
                            Bytes::from_static(b"must-not-survive-B-removal"),
                            true,
                        )
                        .unwrap();
                    assert!(connection.has_pending_stream_frames(stream));
                    stream
                })
                .unwrap();
            // No drive call intervenes: this is a real queued application
            // suffix, not a claim about an unobservable kernel ciphertext queue.
            endpoint.remove_connection(cx, server_cid).unwrap();
            assert!(
                endpoint
                    .with_connection_mut(cx, server_cid, |_| ())
                    .is_err()
            );
            assert_eq!(endpoint.connection_stats().active_connections, 1);
            let a_at_removal = a.hashes.len();
            drive(cx, &mut endpoint, &mut a, |_, _, _, a| {
                (a.hashes.len() > a_at_removal).then_some(())
            })
            .await;
            let receipt = serde_json::json!({"attempt":attempt, "result":"accepted_removed", "peer":peer.to_string(), "client_cid":format!("{client_cid:?}"), "server_cid":format!("{server_cid:?}"), "verified_client_sha256":managed_sha256(parse_one_cert(CLIENT_B).as_ref()), "alpn":String::from_utf8(MANAGED_ALPN.to_vec()).unwrap(), "b_records":b.hashes, "b_fin":b.fin, "queued_removed_stream":queued_stream.0, "queued_application_suffix":true, "retained_ciphertext_queue_claim":false, "a_records_before":a_before, "a_records_at_removal":a_at_removal, "a_records_after":a.hashes.len(), "active_connections":1});
            managed_write_receipt(
                &artifacts.join(format!("multi-{attempt}-result.json")),
                &receipt,
            );
            drive(cx, &mut endpoint, &mut a, |_, _, _, _| {
                maybe(&artifacts.join(format!("multi-{attempt}-done.json")))
            })
            .await;
            attempts.push(receipt);
        }
        managed_write_receipt(
            &artifacts.join("multi-stop-a.json"),
            &serde_json::json!({"attempts":attempts.len()}),
        );
        drive(cx, &mut endpoint, &mut a, |_, _, _, a| {
            (a.fin && maybe(&artifacts.join("multi-a-done.json")).is_some()).then_some(())
        })
        .await;
        assert!(!a.hashes.is_empty());
        endpoint.shutdown(cx).await.unwrap();
        assert_eq!(endpoint.connection_stats().active_connections, 0);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        serde_json::json!({"role":"server", "server_addr":local.to_string(), "endpoint_id":endpoint_id, "a_peer":a_peer.to_string(), "a_records":a.hashes, "a_fin":a.fin, "attempts":attempts, "timer_witness":timer_witness.unwrap(), "verified_client_signatures":*signatures.lock().unwrap(), "packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "packets_received":metrics.packets_received.load(Ordering::SeqCst), "active_connections_after_shutdown":0, "pending_timers_after_shutdown":0})
    }

    async fn client_records(
        cx: &Cx,
        endpoint: &mut ManagedQuicEndpoint,
        metrics: &asupersync::net::quic_native::endpoint::EndpointMetrics,
        artifacts: &Path,
        attempt: usize,
    ) -> serde_json::Value {
        let a = attempt == 0;
        let tag = if a { b'A' } else { b'B' };
        let cid = ids(attempt).1;
        let stream = endpoint
            .with_connection_mut(cx, cid, |connection| {
                let stream = connection.open_bidi_stream(cx).unwrap();
                assert_eq!(stream, StreamId(0));
                connection
                    .write_stream(cx, stream, Bytes::from(record(0, tag)), !a)
                    .unwrap();
                stream
            })
            .unwrap();
        let mut written = 1;
        let mut hashes = Vec::new();
        let mut received = Vec::new();
        let mut sent_fin = !a;
        let mut received_fin = false;
        let mut paused = false;
        let mut cadence = None;
        let started = Instant::now();
        loop {
            let done = endpoint.run_event_loop_with_application(cx, |cx, endpoint, task_cx| {
                assert!(started.elapsed() < LIMIT, "real client record progress bounded");
                let state = endpoint.with_connection_mut(cx, cid, |connection| {
                    // The real server has received this complete record but
                    // holds its echo until this driver has exited. This is a
                    // peer-observed byte witness, independent of whether an
                    // unrelated ACK changed the socket's send counter.
                    if a && !paused {
                        if let Some(observed) = maybe(&artifacts.join("multi-a-observed.json")) {
                            assert_eq!(observed["sequence"], hashes.len());
                            assert_eq!(written, hashes.len() + 1);
                            assert_eq!(observed["sha256"], managed_sha256(&record(hashes.len(), tag)));
                            assert_eq!(observed["bytes"], RECORD_BYTES);
                            assert!(metrics.packets_sent.load(Ordering::SeqCst) > 0);
                            paused = true;
                            return Some(false);
                        }
                    }
                    for _ in 0..8 {
                        let ready = match connection.poll_next_readable_stream(cx, task_cx) {
                            Poll::Ready(Ok(ready)) => ready,
                            Poll::Ready(Err(error)) => panic!("real client stream: {error}"),
                            Poll::Pending => break,
                        };
                        assert_eq!(ready.stream_id, stream, "removed B suffix must never arrive");
                        received.extend_from_slice(&connection.read_stream(cx, stream, 1024).unwrap());
                        while received.len() >= RECORD_BYTES {
                            let bytes: Vec<_> = received.drain(..RECORD_BYTES).collect();
                            assert!(hashes.len() < written, "no duplicate application delivery");
                            assert_eq!(bytes, record(hashes.len(), tag));
                            hashes.push(managed_sha256(&bytes));
                        }
                        received_fin |= connection.is_control_eof(stream).unwrap();
                    }
                    if a && hashes.len() == written && !sent_fin {
                        if maybe(&artifacts.join("multi-stop-a.json")).is_some() {
                            connection.write_stream(cx, stream, Bytes::new(), true).unwrap();
                            sent_fin = true;
                        } else {
                            // Bound this test's application workload to at
                            // most 50 new records/second, independently of
                            // how often the deliberately ready callback runs.
                            // This is not a managed-runtime polling timer or
                            // a throughput/idle-CPU measurement.
                            let pause = cadence.get_or_insert_with(|| Box::pin(asupersync::time::sleep(cx.now(), Duration::from_millis(20))));
                            if pause.as_mut().poll(task_cx).is_pending() { return None; }
                            cadence = None;
                            assert!(written < 8192, "explicit real stream work bound below negotiated 8 MiB credit");
                            connection.write_stream(cx, stream, Bytes::from(record(written, tag)), false).unwrap();
                            written += 1;
                        }
                    }
                    if received_fin && sent_fin && hashes.len() == written
                        && !connection.has_pending_stream_frames(stream)
                        && connection.path_stats().bytes_in_flight == 0 {
                        assert!(received.is_empty());
                        Some(true)
                    } else { None }
                }).unwrap();
                if let Some(done) = state { Poll::Ready(Ok(done)) }
                else { task_cx.waker().wake_by_ref(); Poll::Pending }
            }).await.unwrap();
            if done {
                break;
            }
            assert!(a && paused && !received_fin);
            managed_write_receipt(
                &artifacts.join("multi-a-paused.json"),
                &serde_json::json!({"actual_packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "sequence":hashes.len(), "sha256":managed_sha256(&record(hashes.len(),tag)), "records_written":written, "records_received":hashes.len(), "stream":stream.0}),
            );
            wait(cx, &artifacts.join("multi-1-continue.json")).await;
        }
        assert!(sent_fin && received_fin);
        serde_json::json!({"attempt":attempt, "records":hashes, "records_written":written, "bytes_received":written*RECORD_BYTES, "fin":received_fin, "packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "packets_received":metrics.packets_received.load(Ordering::SeqCst), "elapsed_micros":started.elapsed().as_micros()})
    }

    async fn client_a(cx: &Cx, artifacts: &Path, server_addr: SocketAddr) -> serde_json::Value {
        let socket = QuicUdpEndpoint::bind(
            cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let local = socket.local_addr();
        let metrics = socket.metrics();
        let owner = NativeQuicUdpConnection::connect(
            cx,
            socket,
            server_addr,
            client_driver(Some(true)),
            ids(0).0,
            ids(0).1,
            multi_config(),
            MANAGED_ALPN,
        )
        .await
        .unwrap();
        assert_eq!(owner.local_addr(), local);
        assert_eq!(owner.peer_addr(), server_addr);
        assert_eq!(owner.peer_connection_id(), ids(0).2);
        let mut endpoint = import(cx, owner, false);
        let mut receipt = client_records(cx, &mut endpoint, &metrics, artifacts, 0).await;
        endpoint.shutdown(cx).await.unwrap();
        assert_eq!(endpoint.connection_stats().active_connections, 0);
        receipt["local_addr"] = serde_json::json!(local.to_string());
        receipt["peer_addr"] = serde_json::json!(server_addr.to_string());
        receipt["active_connections_after_shutdown"] = serde_json::json!(0);
        managed_write_receipt(&artifacts.join("multi-a-done.json"), &receipt);
        receipt
    }

    async fn client_b(
        cx: &Cx,
        artifacts: &Path,
        server_addr: SocketAddr,
    ) -> Vec<serde_json::Value> {
        wait(cx, &artifacts.join("multi-a-admitted.json")).await;
        let mut attempts = Vec::new();
        for attempt in 1..=5 {
            let socket = QuicUdpEndpoint::bind(
                cx,
                "127.0.0.1:0".parse().unwrap(),
                QuicUdpEndpointConfig::default(),
            )
            .await
            .unwrap();
            let local = socket.local_addr();
            let metrics = socket.metrics();
            managed_write_receipt(
                &artifacts.join(format!("multi-{attempt}-ready.json")),
                &serde_json::json!({"address":local.to_string(), "attempt":attempt}),
            );
            let armed = wait(cx, &artifacts.join(format!("multi-{attempt}-armed.json"))).await;
            assert_eq!(armed["server_addr"], server_addr.to_string());
            let mut connecting = Box::pin(NativeQuicUdpConnection::connect(
                cx,
                socket,
                server_addr,
                client_driver((attempt != 3).then_some(false)),
                ids(attempt).0,
                ids(attempt).1,
                multi_config(),
                MANAGED_ALPN,
            ));
            if attempt == 1 || attempt == 2 {
                std::future::poll_fn(|task_cx| {
                    let result = connecting.as_mut().poll(task_cx);
                    assert!(
                        result.is_pending(),
                        "fresh TLS cannot finish in its first owned send turn"
                    );
                    if metrics.packets_sent.load(Ordering::SeqCst) > 0 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                managed_write_receipt(
                    &artifacts.join(format!("multi-{attempt}-initial.json")),
                    &serde_json::json!({"actual_packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "peer":server_addr.to_string(), "local":local.to_string()}),
                );
                if attempt == 2 {
                    let result = wait(cx, &artifacts.join("multi-2-result.json")).await;
                    assert_eq!(result["result"], "cancelled");
                    drop(connecting);
                    let receipt = serde_json::json!({"attempt":attempt, "result":"cancelled", "local_addr":local.to_string(), "initial_packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "owned_connect_future_retired":true});
                    managed_write_receipt(
                        &artifacts.join(format!("multi-{attempt}-done.json")),
                        &receipt,
                    );
                    attempts.push(receipt);
                    continue;
                }
                wait(cx, &artifacts.join("multi-1-continue.json")).await;
            }
            if attempt == 3 {
                let started = Instant::now();
                let mut client_result = None;
                let server_result = std::future::poll_fn(|task_cx| {
                    assert!(started.elapsed() < LIMIT);
                    if client_result.is_none() {
                        if let Poll::Ready(result) = connecting.as_mut().poll(task_cx) {
                            client_result = Some(result);
                        }
                    }
                    if let Some(receipt) = maybe(&artifacts.join("multi-3-result.json")) {
                        return Poll::Ready(receipt);
                    }
                    task_cx.waker().wake_by_ref();
                    Poll::Pending
                })
                .await;
                assert_eq!(server_result["result"], "client_certificate_refused");
                let diagnostic = client_result.as_ref().map(|result| format!("{result:?}"));
                drop(connecting);
                // TLS client completion can precede the server's verification
                // of its final flight. The authoritative negative is the
                // server's fatal TLS receipt and absence of an admitted CID.
                if let Some(Ok(owner)) = client_result.take() {
                    let mut endpoint = import(cx, owner, false);
                    endpoint.shutdown(cx).await.unwrap();
                    assert_eq!(endpoint.connection_stats().active_connections, 0);
                }
                assert!(metrics.packets_sent.load(Ordering::SeqCst) > 0);
                assert!(metrics.packets_received.load(Ordering::SeqCst) > 0);
                let receipt = serde_json::json!({"attempt":attempt, "result":"client_certificate_refused", "local_addr":local.to_string(), "client_terminal":diagnostic, "server_refusal":server_result["error"], "packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "packets_received":metrics.packets_received.load(Ordering::SeqCst), "owned_connect_future_retired":true});
                managed_write_receipt(
                    &artifacts.join(format!("multi-{attempt}-done.json")),
                    &receipt,
                );
                attempts.push(receipt);
                continue;
            }
            let owner = connecting.await.unwrap();
            assert_eq!(owner.peer_addr(), server_addr);
            assert_eq!(owner.peer_connection_id(), ids(attempt).2);
            assert_eq!(owner.negotiated_alpn(), MANAGED_ALPN);
            let mut endpoint = import(cx, owner, false);
            let payload = if attempt != 4 {
                let payload = client_records(cx, &mut endpoint, &metrics, artifacts, attempt).await;
                managed_write_receipt(
                    &artifacts.join(format!("multi-{attempt}-payload.json")),
                    &payload,
                );
                Some(payload)
            } else {
                None
            };
            let result = wait(cx, &artifacts.join(format!("multi-{attempt}-result.json"))).await;
            assert_eq!(
                result["result"],
                if attempt == 4 {
                    "alpn_refused"
                } else {
                    "accepted_removed"
                }
            );
            endpoint.shutdown(cx).await.unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            let receipt = serde_json::json!({"attempt":attempt, "result":result["result"], "local_addr":local.to_string(), "server_addr":server_addr.to_string(), "client_cid":format!("{:?}",ids(attempt).1), "server_cid":format!("{:?}",ids(attempt).2), "alpn":String::from_utf8(MANAGED_ALPN.to_vec()).unwrap(), "payload":payload, "packets_sent":metrics.packets_sent.load(Ordering::SeqCst), "packets_received":metrics.packets_received.load(Ordering::SeqCst), "active_connections_after_shutdown":0});
            managed_write_receipt(
                &artifacts.join(format!("multi-{attempt}-done.json")),
                &receipt,
            );
            attempts.push(receipt);
        }
        attempts
    }

    async fn clients(cx: &Cx, artifacts: &Path, address: SocketAddr) -> serde_json::Value {
        let a_artifacts = artifacts.to_path_buf();
        let mut a = cx
            .spawn(move |cx| {
                let future: Pin<Box<dyn Future<Output = serde_json::Value> + Send>> =
                    Box::pin(async move { client_a(&cx, &a_artifacts, address).await });
                future
            })
            .unwrap();
        let b_artifacts = artifacts.to_path_buf();
        let mut b = cx
            .spawn(move |cx| {
                let future: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
                    Box::pin(async move { client_b(&cx, &b_artifacts, address).await });
                future
            })
            .unwrap();
        let (a_result, attempts) = zip(a.join(cx), b.join(cx)).await;
        let task_ids = [a.task_id(), b.task_id()];
        let a = a_result.unwrap();
        let attempts = attempts.unwrap();
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        let sent = a["packets_sent"].as_u64().unwrap()
            + attempts
                .iter()
                .map(|row| {
                    row["packets_sent"]
                        .as_u64()
                        .or_else(|| row["initial_packets_sent"].as_u64())
                        .unwrap()
                })
                .sum::<u64>();
        let received = a["packets_received"].as_u64().unwrap()
            + attempts
                .iter()
                .map(|row| row["packets_received"].as_u64().unwrap_or(0))
                .sum::<u64>();
        serde_json::json!({"role":"clients", "server_addr":address.to_string(), "a":a, "attempts":attempts, "joined_client_tasks":task_ids.map(|id|format!("{id:?}")), "packets_sent":sent, "packets_received":received, "active_connections_after_shutdown":0, "pending_timers_after_shutdown":0})
    }

    #[test]
    #[ignore = "owned subprocess selected exactly by authenticated_same_socket_multi_peer"]
    fn authenticated_same_socket_process_peer() {
        let role = std::env::var("ASUPERSYNC_MULTI_QUIC_ROLE").expect("owned parent role");
        assert!(role == "server" || role == "clients");
        println!(
            "MANAGED_QUIC_MULTI_PEER_START role={role} pid={}",
            std::process::id()
        );
        let artifacts = PathBuf::from(
            std::env::var_os("ASUPERSYNC_MULTI_QUIC_ARTIFACT_DIR").expect("owned artifacts"),
        );
        assert!(artifacts.is_dir());
        let server_addr: Option<SocketAddr> = std::env::var("ASUPERSYNC_MULTI_QUIC_SERVER_ADDR")
            .ok()
            .map(|address| address.parse().unwrap());
        assert_eq!(server_addr.is_some(), role == "clients");
        let runtime = asupersync::runtime::RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .with_sharded_state(true)
            .trace_storage_profile(
                asupersync::runtime::config::TraceStorageProfile::LargeMemory256G,
            )
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        assert_eq!(runtime.config().worker_threads, 2);
        let owned_artifacts = artifacts.clone();
        let owned_role = role.clone();
        let started = Instant::now();
        let parent: Pin<
            Box<
                dyn Future<
                        Output = (
                            serde_json::Value,
                            asupersync::types::TaskId,
                            asupersync::types::RegionId,
                        ),
                    > + Send,
            >,
        > = Box::pin(async move {
            let cx = Cx::current().unwrap();
            let region = cx
                .open_child_region(asupersync::cx::ChildRegionSpec::inherit())
                .await
                .unwrap();
            let region_id = region.region_id();
            let mut task = region
                .cx()
                .spawn(move |cx| {
                    let future: Pin<Box<dyn Future<Output = serde_json::Value> + Send>> =
                        Box::pin(async move {
                            assert!(cx.has_timer());
                            if owned_role == "server" {
                                server(&cx, &owned_artifacts).await
                            } else {
                                clients(&cx, &owned_artifacts, server_addr.unwrap()).await
                            }
                        });
                    future
                })
                .unwrap();
            let receipt = task.join(&cx).await.unwrap();
            let task_id = task.task_id();
            region.close().await.unwrap();
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
            (receipt, task_id, region_id)
        });
        let (mut receipt, coordinator, region) = runtime.block_on(runtime.handle().spawn(parent));
        managed_assert_runtime_cleanup(&runtime);
        assert_eq!(runtime.draining_region_count(), 0);
        assert!(
            runtime
                .diagnostics()
                .explain_region_open(region)
                .region_state
                .is_none(),
            "actual owned child region reclaimed after close"
        );
        let trace = runtime.trace_snapshot();
        let mut task_ids = vec![format!("{coordinator:?}")];
        if let Some(ids) = receipt["joined_client_tasks"].as_array() {
            task_ids.extend(ids.iter().map(|id| id.as_str().unwrap().to_owned()));
        }
        let mut terminal_sequences = BTreeMap::new();
        for id in task_ids {
            let completions: Vec<_> = trace.iter().filter(|event| event.kind == asupersync::trace::TraceEventKind::Complete && matches!(event.data, asupersync::trace::TraceData::Task { task, region: actual } if format!("{task:?}")==id && actual==region)).collect();
            assert_eq!(completions.len(), 1, "exact actual task terminal for {id}");
            terminal_sequences.insert(id, completions[0].seq);
        }
        let close: Vec<_> = trace.iter().filter(|event| event.kind == asupersync::trace::TraceEventKind::RegionCloseComplete && matches!(event.data, asupersync::trace::TraceData::Region { region: actual, .. } if actual==region)).collect();
        assert_eq!(close.len(), 1);
        assert!(terminal_sequences.values().all(|seq| *seq < close[0].seq));
        receipt["schema"] = serde_json::json!("asupersync.managed_quic.multi_peer.process.v1");
        receipt["pid"] = serde_json::json!(std::process::id());
        receipt["source"] = managed_source_identity();
        receipt["executable_sha256"] = serde_json::json!(managed_executable_sha256());
        receipt["elapsed_micros"] = serde_json::json!(started.elapsed().as_micros());
        receipt["runtime_quiescent"] = serde_json::json!(runtime.is_quiescent());
        receipt["tasks_after_cleanup"] = serde_json::json!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .len()
        );
        receipt["leaked_obligations_after_cleanup"] =
            serde_json::json!(runtime.diagnostics().find_leaked_obligations().len());
        receipt["draining_regions_after_cleanup"] =
            serde_json::json!(runtime.draining_region_count());
        receipt["owned_region"] = serde_json::json!(format!("{region:?}"));
        receipt["owned_region_reclaimed"] = serde_json::json!(true);
        receipt["actual_terminal_sequences"] = serde_json::json!(terminal_sequences);
        receipt["owned_region_close_sequence"] = serde_json::json!(close[0].seq);
        managed_write_receipt(
            &artifacts.join(format!("multi-{role}-receipt.json")),
            &receipt,
        );
        println!("MANAGED_QUIC_MULTI_PEER_PROCESS {receipt}");
    }

    #[test]
    fn authenticated_same_socket_multi_peer() {
        use std::process::{Command, Stdio};
        let started = Instant::now();
        let executable = std::env::current_exe().unwrap();
        let executable_sha = managed_executable_sha256();
        let source = managed_source_identity();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::var_os("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let artifacts = base.join(format!(
            "asupersync-managed-multi-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&artifacts).unwrap();
        println!(
            "MANAGED_QUIC_MULTI_PEER_ARTIFACT_DIR {}",
            artifacts.display()
        );
        let spawn = |role: &str, address: Option<SocketAddr>| {
            let stdout = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(artifacts.join(format!("{role}.stdout.log")))
                .unwrap();
            let stderr = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(artifacts.join(format!("{role}.stderr.log")))
                .unwrap();
            let mut command = Command::new(&executable);
            command
                .args([
                    "--ignored",
                    "--exact",
                    ENTRY,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ASUPERSYNC_MULTI_QUIC_ROLE", role)
                .env("ASUPERSYNC_MULTI_QUIC_ARTIFACT_DIR", &artifacts)
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
            if let Some(address) = address {
                command.env("ASUPERSYNC_MULTI_QUIC_SERVER_ADDR", address.to_string());
            }
            ManagedChild(command.spawn().unwrap())
        };
        let mut server = spawn("server", None);
        let ready = loop {
            if let Some(ready) = maybe(&artifacts.join("multi-server-ready.json")) {
                break ready;
            }
            if server.0.try_wait().unwrap().is_some() || started.elapsed() > Duration::from_secs(30)
            {
                managed_print_child_logs(&artifacts, "server");
                panic!("owned server failed before real bind; artifacts={artifacts:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(ready["pid"], server.0.id());
        assert_eq!(ready["source"], source);
        assert_eq!(ready["executable_sha256"], executable_sha);
        let address: SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
        assert!(address.ip().is_loopback() && address.port() != 0);
        let mut clients = spawn("clients", Some(address));
        assert_ne!(server.0.id(), clients.0.id());
        assert_ne!(server.0.id(), std::process::id());
        assert_ne!(clients.0.id(), std::process::id());
        let mut statuses = [None, None];
        loop {
            statuses[0] = statuses[0].or_else(|| server.0.try_wait().unwrap());
            statuses[1] = statuses[1].or_else(|| clients.0.try_wait().unwrap());
            if statuses
                .iter()
                .any(|status| status.is_some_and(|status| !status.success()))
                || started.elapsed() > Duration::from_secs(120)
            {
                managed_print_child_logs(&artifacts, "server");
                managed_print_child_logs(&artifacts, "clients");
                panic!(
                    "owned multi-peer child failed or whole-process watchdog expired: {statuses:?}; artifacts={artifacts:?}"
                );
            }
            if statuses.iter().all(Option::is_some) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let server_receipt = maybe(&artifacts.join("multi-server-receipt.json")).unwrap();
        let clients_receipt = maybe(&artifacts.join("multi-clients-receipt.json")).unwrap();
        for (role, receipt, pid) in [
            ("server", &server_receipt, server.0.id()),
            ("clients", &clients_receipt, clients.0.id()),
        ] {
            managed_print_child_logs(&artifacts, role);
            assert_eq!(receipt["role"], role);
            assert_eq!(receipt["pid"], pid);
            assert_eq!(receipt["source"], source);
            assert_eq!(receipt["executable_sha256"], executable_sha);
            for field in [
                "tasks_after_cleanup",
                "leaked_obligations_after_cleanup",
                "draining_regions_after_cleanup",
                "active_connections_after_shutdown",
                "pending_timers_after_shutdown",
            ] {
                assert_eq!(receipt[field], 0, "{role} actual {field}");
            }
            assert_eq!(receipt["runtime_quiescent"], true);
            assert_eq!(receipt["owned_region_reclaimed"], true);
            assert!(
                receipt["packets_sent"].as_u64().unwrap() > 0
                    && receipt["packets_received"].as_u64().unwrap() > 0
            );
            assert!(receipt["elapsed_micros"].as_u64().unwrap() > 0);
            let stdout =
                std::fs::read_to_string(artifacts.join(format!("{role}.stdout.log"))).unwrap();
            assert!(stdout.contains(&format!("test {ENTRY} ...")));
            assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
            let rows: Vec<_> = stdout
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("MANAGED_QUIC_MULTI_PEER_PROCESS ")
                        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                })
                .collect();
            assert_eq!(rows, vec![receipt.clone()]);
        }
        assert_eq!(server_receipt["server_addr"], address.to_string());
        assert_eq!(clients_receipt["server_addr"], address.to_string());
        assert_eq!(server_receipt["a_peer"], clients_receipt["a"]["local_addr"]);
        assert_eq!(clients_receipt["a"]["peer_addr"], address.to_string());
        assert_eq!(server_receipt["a_records"], clients_receipt["a"]["records"]);
        assert_eq!(server_receipt["a_fin"], true);
        assert_eq!(clients_receipt["a"]["fin"], true);
        let a_records = server_receipt["a_records"].as_array().unwrap();
        assert!(!a_records.is_empty() && a_records.len() <= 8192);
        for (sequence, digest) in a_records.iter().enumerate() {
            assert_eq!(
                digest,
                &serde_json::json!(managed_sha256(&record(sequence, b'A')))
            );
        }
        let server_attempts = server_receipt["attempts"].as_array().unwrap();
        let client_attempts = clients_receipt["attempts"].as_array().unwrap();
        assert_eq!(server_attempts.len(), 5);
        assert_eq!(client_attempts.len(), 5);
        let expected = [
            "accepted_removed",
            "cancelled",
            "client_certificate_refused",
            "alpn_refused",
            "accepted_removed",
        ];
        for (index, (server, client)) in server_attempts.iter().zip(client_attempts).enumerate() {
            assert_eq!(server["attempt"], index + 1);
            assert_eq!(client["attempt"], index + 1);
            assert_eq!(server["result"], expected[index]);
            assert_eq!(client["result"], expected[index]);
            assert_eq!(server["peer"], client["local_addr"]);
            assert_ne!(server["peer"], server_receipt["a_peer"]);
            assert_eq!(server["active_connections"], 1);
            if index == 0 || index == 4 {
                assert_eq!(server["b_records"], client["payload"]["records"]);
                assert_eq!(
                    server["b_records"],
                    serde_json::json!([managed_sha256(&record(0, b'B'))])
                );
                assert_eq!(server["b_fin"], true);
                assert_eq!(client["payload"]["fin"], true);
                assert_eq!(server["client_cid"], client["client_cid"]);
                assert_eq!(server["server_cid"], client["server_cid"]);
                assert_eq!(
                    server["verified_client_sha256"],
                    managed_sha256(parse_one_cert(CLIENT_B).as_ref())
                );
                assert_eq!(server["queued_application_suffix"], true);
                assert_eq!(server["retained_ciphertext_queue_claim"], false);
                assert!(
                    server["a_records_after"].as_u64().unwrap()
                        > server["a_records_at_removal"].as_u64().unwrap()
                );
            }
        }
        assert_ne!(
            server_attempts[0]["server_cid"],
            server_attempts[4]["server_cid"]
        );
        let witness = &server_receipt["timer_witness"];
        assert!(
            witness["a_records_during_b_handshake"].as_u64().unwrap()
                > witness["a_records_before"].as_u64().unwrap()
        );
        assert!(
            witness["a_pto_after"].as_u64().unwrap() > witness["a_pto_before"].as_u64().unwrap()
        );
        assert!(witness["sent_after_pto_observation"].as_u64().unwrap() > 0);
        assert_eq!(witness["b_tls_held_after_real_initial"], true);
        assert_eq!(witness["a_reply_queued_after_pause"], true);
        let observed = &witness["a_peer_observed_record"];
        let held_sequence = usize::try_from(observed["sequence"].as_u64().unwrap()).unwrap();
        assert_eq!(observed["bytes"], RECORD_BYTES);
        assert_eq!(observed["sha256"], a_records[held_sequence]);
        let paused = maybe(&artifacts.join("multi-a-paused.json")).unwrap();
        assert_eq!(paused["sequence"], observed["sequence"]);
        assert_eq!(paused["sha256"], observed["sha256"]);
        assert_eq!(paused["records_written"], held_sequence + 1);
        assert_eq!(paused["records_received"], held_sequence);
        let a_identity = managed_sha256(parse_one_cert(CLIENT_A).as_ref());
        let b_identity = managed_sha256(parse_one_cert(CLIENT_B).as_ref());
        assert_ne!(a_identity, b_identity);
        assert_eq!(
            server_receipt["verified_client_signatures"],
            serde_json::json!([a_identity, b_identity, b_identity, b_identity])
        );
        let duplicate = maybe(&artifacts.join("multi-duplicate-cid.json")).unwrap();
        assert!(
            duplicate["typed_refusal"]
                .as_str()
                .unwrap()
                .contains("ConnectionCreationFailed")
        );
        let summary = serde_json::json!({"schema":"asupersync.managed_quic.multi_peer.v1", "source":source, "executable_sha256":executable_sha, "actual_children":2, "server":server_receipt, "clients":clients_receipt, "negative_controls":{"duplicate_cid":duplicate, "pending_handshake_cancel":true, "fatal_tls_no_client_certificate":true, "post_tls_alpn_refusal":true}, "same_server_socket":true, "distinct_verified_client_identities":true, "same_router_multi_peer_proof":true, "kernel_would_block_claim":false, "retained_ciphertext_queue_claim":false, "performance_claim":false, "elapsed_micros":started.elapsed().as_micros()});
        managed_write_receipt(&artifacts.join("multi-summary.json"), &summary);
        println!("MANAGED_QUIC_MULTI_PEER {summary}");
    }
}
