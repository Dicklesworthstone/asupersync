//! Authenticated HTTP/3 and Router composition over real loopback UDP.

#![cfg(all(feature = "http3", feature = "tls"))]
#![allow(missing_docs)]

use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
