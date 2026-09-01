#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements, clippy::let_unit_value)]

//! Real HTTP/2 gRPC Integration Tests (asupersync-zdgucf)
//!
//! Tests real gRPC/HTTP2 connections plus the public client's lazy and
//! fail-closed boundary semantics, including:
//! - Socket backpressure and real connection behavior
//! - HPACK/header framing over actual TCP
//! - Trailers over real connections
//! - TCP half-close and connection management
//! - GOAWAY/RST_STREAM handling
//! - Keepalive/deadline behavior
//! - Cross-stack interop with real HTTP/2

#[macro_use]
mod common;

use common::init_test_logging;

use asupersync::bytes::{Bytes, BytesMut};
#[cfg(feature = "tls")]
use asupersync::channel::oneshot;
use asupersync::codec::{Decoder as _, Encoder as _};
use asupersync::cx::Cx;
use asupersync::grpc::{
    CallContext, Channel, ChannelConfig, Code, GrpcClient, GrpcCodec, GrpcError, GrpcMessage,
    HealthService, Metadata, MetadataValue, MethodDescriptor, NamedService, Request, Response,
    Server, ServiceDescriptor, ServiceHandler, ServiceHandlerFuture, ServingStatus, Status,
};
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::frame::{DataFrame, HeadersFrame, Setting, SettingsFrame};
use asupersync::http::h2::{Connection, ConnectionState, Frame, FrameHeader, FrameType, Settings};
use asupersync::http::h2::{FrameCodec, Header, HpackDecoder, HpackEncoder};
#[cfg(feature = "tls")]
use asupersync::io::{AsyncReadExt as _, AsyncWriteExt as _};
use asupersync::net::TcpListener;
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "tls")]
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
    TlsConnectorBuilder,
};
#[cfg(feature = "tls")]
use asupersync::types::CancelReason;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn log_test_event(event: &str, details: Value) {
    let log_entry = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event": event,
        "test_framework": "grpc_http2_e2e",
        "details": details
    });
    eprintln!("{}", serde_json::to_string(&log_entry).unwrap());
}

fn find_available_port() -> u16 {
    // Use port 0 to let the OS choose an available port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn start_grpc_http2_server(port: u16) -> Result<(), GrpcError> {
    log_test_event(
        "server_start",
        json!({
            "port": port,
            "protocol": "HTTP/2",
            "host": "localhost"
        }),
    );

    let health = HealthService::new();
    health.set_server_status(ServingStatus::Serving);

    let mut server = Server::builder()
        .max_recv_message_size(1024 * 1024) // 1MB
        .max_send_message_size(1024 * 1024) // 1MB
        .keepalive_interval(30000) // 30 seconds
        .keepalive_timeout(5000) // 5 seconds
        .max_concurrent_streams(100)
        .add_service(health)
        .build();

    let addr = format!("127.0.0.1:{}", port);
    server.serve(&addr).await
}

// ============================================================================
// Section 1: Native HTTP/2 channel semantics
// ============================================================================

#[test]
fn http2_grpc_localhost_channel_construction_is_lazy() {
    init_test("http2_grpc_localhost_channel_construction_is_lazy");

    test_section!("setup_server_port");
    let port = find_available_port();

    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_localhost_channel_construction_is_lazy",
            "server_port": port,
            "expected_outcomes": ["successful_bind_validation", "lazy_channel_configuration", "no_socket_claim"]
        }),
    );

    test_section!("start_http2_server");
    futures_lite::future::block_on(async {
        // `serve` currently validates the address; the production listener is
        // exercised by the causal public-client round-trip below.
        let server_result = start_grpc_http2_server(port).await;
        assert!(server_result.is_ok(), "Server should bind successfully");

        log_test_event(
            "server_bind_success",
            json!({
                "port": port,
                "bind_result": "success"
            }),
        );

        test_section!("create_localhost_channel");
        let uri = format!("http://localhost:{}", port);
        let channel_result = Channel::connect(&uri).await;

        match channel_result {
            Ok(channel) => {
                log_test_event(
                    "channel_configuration_success",
                    json!({
                        "uri": uri,
                        "channel_uri": channel.uri(),
                        "transport_type": "native_http2_lazy"
                    }),
                );

                assert_eq!(channel.uri(), uri);
                test_complete!("http2_grpc_localhost_channel_construction_is_lazy");
            }
            Err(e) => {
                log_test_event(
                    "channel_connect_failure",
                    json!({
                        "uri": uri,
                        "error": e.to_string(),
                        "error_type": "connection_failure"
                    }),
                );
                panic!("Failed to configure localhost gRPC channel: {}", e);
            }
        }
    });
}

#[test]
fn http2_grpc_native_unary_requires_runtime_capability() {
    init_test("http2_grpc_native_unary_requires_runtime_capability");

    let port = find_available_port();
    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_native_unary_requires_runtime_capability",
            "server_port": port,
            "call_type": "unary",
            "expected_outcomes": ["no_loopback_fallback", "ambient_cx_required"]
        }),
    );

    futures_lite::future::block_on(async {
        test_section!("configure_localhost_channel");
        let uri = format!("http://localhost:{}", port);
        let channel = Channel::connect(&uri).await.unwrap();
        let mut client = GrpcClient::new(channel);

        log_test_event(
            "client_ready",
            json!({
                "uri": uri,
                "client_type": "native_http2_grpc_lazy"
            }),
        );

        test_section!("reject_call_without_runtime_capability");
        let request = Request::new(Bytes::from_static(b"test-payload"));
        let status = client
            .unary::<Bytes, Bytes>("/test.Service/TestMethod", request)
            .await;
        let status = status.expect_err("localhost must not fall back to in-memory success");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("ambient runtime Cx"));
        test_complete!("http2_grpc_native_unary_requires_runtime_capability");
    });
}

#[test]
fn http2_grpc_server_streaming_localhost_fails_closed() {
    init_test("http2_grpc_server_streaming_localhost_fails_closed");

    let port = find_available_port();
    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_server_streaming_localhost_fails_closed",
            "server_port": port,
            "call_type": "server_streaming",
            "expected_outcomes": ["typed_unimplemented_refusal", "no_loopback_fallback"]
        }),
    );

    futures_lite::future::block_on(async {
        let uri = format!("http://localhost:{}", port);
        let channel = Channel::connect(&uri).await.unwrap();
        let mut client = GrpcClient::new(channel);

        test_section!("initiate_server_streaming");
        let request = Request::new("stream_request".to_string());
        let response_result = client
            .server_streaming::<String, String>("/test.Service/StreamMethod", request)
            .await;

        let status = response_result.expect_err("native streaming is not wired yet");
        assert_eq!(status.code(), Code::Unimplemented);
        assert!(status.message().contains("not wired yet"));
        test_complete!("http2_grpc_server_streaming_localhost_fails_closed");
    });
}

#[test]
fn http2_grpc_connection_timeout_configuration() {
    init_test("http2_grpc_connection_timeout_configuration");

    let port = find_available_port();
    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_connection_timeout_configuration",
            "server_port": port,
            "test_type": "timeout_configuration",
            "expected_outcomes": ["connect_timeout_retained", "request_timeout_retained"]
        }),
    );

    futures_lite::future::block_on(async {
        test_section!("setup_channel_with_timeout");
        let uri = format!("http://localhost:{}", port);
        let channel = Channel::builder(uri)
            .connect_timeout(Duration::from_millis(100)) // Very short timeout
            .timeout(Duration::from_millis(500)) // Request timeout
            .connect()
            .await;

        match channel {
            Ok(ch) => {
                log_test_event(
                    "channel_with_timeout_created",
                    json!({
                        "connect_timeout_ms": 100,
                        "request_timeout_ms": 500
                    }),
                );

                assert_eq!(ch.config().connect_timeout, Duration::from_millis(100));
                assert_eq!(ch.config().timeout, Some(Duration::from_millis(500)));
                test_complete!("http2_grpc_connection_timeout_configuration");
            }
            Err(e) => {
                log_test_event(
                    "channel_timeout_config_failure",
                    json!({
                        "error": e.to_string()
                    }),
                );
                panic!("Failed to configure channel timeouts: {}", e);
            }
        }
    });
}

#[test]
fn http2_grpc_ipv4_127_0_0_1_channel_is_lazy() {
    init_test("http2_grpc_ipv4_127_0_0_1_channel_is_lazy");

    let port = find_available_port();
    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_ipv4_127_0_0_1_channel_is_lazy",
            "server_port": port,
            "address_type": "ipv4",
            "expected_outcomes": ["numeric_ip_target_support", "lazy_channel_configuration"]
        }),
    );

    futures_lite::future::block_on(async {
        let server_result = start_grpc_http2_server(port).await;
        assert!(server_result.is_ok());

        test_section!("connect_via_ipv4_address");
        let uri = format!("http://127.0.0.1:{}", port);
        let channel_result = Channel::connect(&uri).await;

        match channel_result {
            Ok(channel) => {
                log_test_event(
                    "ipv4_channel_configuration_success",
                    json!({
                        "uri": uri,
                        "address_type": "127.0.0.1",
                        "connection_type": "native_http2_lazy"
                    }),
                );

                assert_eq!(channel.uri(), uri);
                test_complete!("http2_grpc_ipv4_127_0_0_1_channel_is_lazy");
            }
            Err(e) => {
                log_test_event(
                    "ipv4_connection_failure",
                    json!({
                        "uri": uri,
                        "error": e.to_string()
                    }),
                );
                panic!("Failed to connect via IPv4 127.0.0.1: {}", e);
            }
        }
    });
}

#[test]
fn grpc_loopback_metadata_propagation() {
    init_test("grpc_loopback_metadata_propagation");

    log_test_event(
        "test_start",
        json!({
            "test_name": "grpc_loopback_metadata_propagation",
            "test_focus": ["deterministic_loopback", "metadata_propagation"],
            "expected_outcomes": ["request_metadata_retained", "transport_label_honest"]
        }),
    );

    futures_lite::future::block_on(async {
        let channel = Channel::connect("http://loopback:50051").await.unwrap();
        let mut client = GrpcClient::new(channel);

        test_section!("build_request_with_metadata");
        let mut request = Request::new("metadata_test".to_string());
        request.metadata_mut().insert("x-test-header", "test_value");
        request
            .metadata_mut()
            .insert("x-client-id", "grpc_http2_e2e_test");

        log_test_event(
            "request_metadata_added",
            json!({
                "headers": {
                    "x-test-header": "test_value",
                    "x-client-id": "grpc_http2_e2e_test"
                }
            }),
        );

        test_section!("execute_call_with_metadata");
        let response_result = client
            .unary::<String, String>("/test.Service/MetadataMethod", request)
            .await;

        let response = response_result.expect("loopback metadata call");
        assert_eq!(response.get_ref(), "metadata_test");
        assert!(matches!(
            response.metadata().get("x-test-header"),
            Some(MetadataValue::Ascii(value)) if value == "test_value"
        ));
        assert!(matches!(
            response.metadata().get("x-asupersync-grpc-transport"),
            Some(MetadataValue::Ascii(value)) if value == "loopback"
        ));
        test_complete!("grpc_loopback_metadata_propagation");
    });
}

// ============================================================================
// Section 2: Error Conditions and Edge Cases
// ============================================================================

#[test]
fn http2_grpc_invalid_host_rejection() {
    init_test("http2_grpc_invalid_host_rejection");

    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_invalid_host_rejection",
            "test_type": "security_validation",
            "expected_outcomes": ["host_validation", "security_boundary"]
        }),
    );

    futures_lite::future::block_on(async {
        test_section!("test_remote_host_rejection");
        let invalid_uris = vec![
            "http://example.com:50051",
            "http://evil.com:50051",
            "http://192.168.1.1:50051",
            "http://8.8.8.8:50051",
        ];

        for uri in invalid_uris {
            let result = Channel::connect(uri).await;
            match result {
                Ok(_) => {
                    log_test_event(
                        "security_violation",
                        json!({
                            "uri": uri,
                            "issue": "remote_host_allowed"
                        }),
                    );
                    panic!("Should not allow connection to remote host: {}", uri);
                }
                Err(e) => {
                    log_test_event(
                        "security_check_passed",
                        json!({
                            "uri": uri,
                            "rejected_with": e.to_string()
                        }),
                    );
                    assert!(e.to_string().contains("loopback and localhost only"));
                }
            }
        }

        test_section!("test_valid_hosts_accepted");
        let valid_uris = vec![
            "http://loopback:50051",
            "http://localhost:50051",
            "http://127.0.0.1:50051",
        ];

        for uri in valid_uris {
            let result = Channel::connect(uri).await;
            match result {
                Ok(_) => {
                    log_test_event(
                        "valid_host_accepted",
                        json!({
                            "uri": uri,
                            "result": "accepted"
                        }),
                    );
                }
                Err(e) => {
                    panic!("Should allow connection to valid host {}: {}", uri, e);
                }
            }
        }

        test_complete!("http2_grpc_invalid_host_rejection");
    });
}

#[test]
fn http2_grpc_channels_make_no_pooling_claim() {
    init_test("http2_grpc_channels_make_no_pooling_claim");

    let port = find_available_port();
    log_test_event(
        "test_start",
        json!({
            "test_name": "http2_grpc_channels_make_no_pooling_claim",
            "server_port": port,
            "test_focus": ["independent_channel_configuration"],
            "expected_outcomes": ["no_connection_pool_claim"]
        }),
    );

    futures_lite::future::block_on(async {
        test_section!("create_multiple_channels");
        let uri = format!("http://localhost:{}", port);

        // Create multiple channels to the same endpoint
        let channel1 = Channel::connect(&uri).await.unwrap();
        let channel2 = Channel::connect(&uri).await.unwrap();
        let channel3 = Channel::connect(&uri).await.unwrap();

        log_test_event(
            "multiple_channels_created",
            json!({
                "uri": uri,
                "channel_count": 3,
                "connection_pooling": "not_claimed"
            }),
        );

        test_section!("verify_channel_independence");
        let client1 = GrpcClient::new(channel1);
        let client2 = GrpcClient::new(channel2);
        let client3 = GrpcClient::new(channel3);
        assert_eq!(client1.channel().uri(), uri);
        assert_eq!(client2.channel().uri(), uri);
        assert_eq!(client3.channel().uri(), uri);

        log_test_event(
            "clients_ready",
            json!({
                "client_count": 3,
                "lazy_channels_configured": true,
                "pooling_claim": false
            }),
        );

        test_complete!("http2_grpc_channels_make_no_pooling_claim");
    });
}

#[derive(Debug, Default)]
struct ProductionGrpcH2Outcome {
    advertised_stream_window: Option<u32>,
    advertised_max_streams: Option<u32>,
    connection_window_increment: Option<u32>,
    http_status: Option<String>,
    grpc_status: Option<String>,
    grpc_message: Option<String>,
    grpc_status_details: Option<String>,
    framed_body: Vec<u8>,
}

fn production_grpc_h2_client(addr: SocketAddr) -> ProductionGrpcH2Outcome {
    production_grpc_h2_client_for_path(addr, "/test.Echo/Unary")
}

fn production_grpc_h2_client_for_path(addr: SocketAddr, path: &str) -> ProductionGrpcH2Outcome {
    let mut outcome = ProductionGrpcH2Outcome::default();
    let mut stream = std::net::TcpStream::connect(addr).expect("connect production gRPC H2");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set client read timeout");

    let mut request_body = BytesMut::new();
    let mut grpc_codec = GrpcCodec::with_max_size(64);
    grpc_codec
        .encode(
            GrpcMessage::new(Bytes::from_static(b"ping")),
            &mut request_body,
        )
        .expect("encode framed gRPC request");

    let mut hpack = HpackEncoder::new();
    let mut header_block = BytesMut::new();
    hpack.encode(
        &[
            Header::new(":method", "POST"),
            Header::new(":scheme", "http"),
            Header::new(":path", path),
            Header::new(":authority", "localhost"),
            Header::new("content-type", "application/grpc"),
            Header::new("te", "trailers"),
        ],
        &mut header_block,
    );
    let mut trailer_block = BytesMut::new();
    hpack.encode(
        &[
            Header::new("x-client-tail", "tail-value"),
            Header::new("x-client-token-bin", "AQI"),
        ],
        &mut trailer_block,
    );

    let mut outbound = BytesMut::new();
    stream.write_all(CLIENT_PREFACE).expect("write preface");
    Frame::Settings(SettingsFrame::new(Vec::new()))
        .encode(&mut outbound)
        .expect("encode client settings");
    Frame::Headers(HeadersFrame::new(1, header_block.freeze(), false, true))
        .encode(&mut outbound)
        .expect("encode gRPC headers");
    Frame::Data(DataFrame::new(1, request_body.freeze(), false))
        .encode(&mut outbound)
        .expect("encode gRPC data");
    Frame::Headers(HeadersFrame::new(1, trailer_block.freeze(), true, true))
        .encode(&mut outbound)
        .expect("encode gRPC request trailers");
    stream.write_all(&outbound).expect("write gRPC request");
    stream.flush().expect("flush gRPC request");

    let mut frame_codec = FrameCodec::new();
    let mut response_hpack = HpackDecoder::new();
    let mut inbound = BytesMut::new();
    let mut chunk = [0u8; 4096];
    loop {
        while let Some(frame) = frame_codec
            .decode(&mut inbound)
            .expect("decode server frame")
        {
            match frame {
                Frame::Settings(settings) if !settings.ack => {
                    for setting in settings.settings {
                        match setting {
                            Setting::InitialWindowSize(value) => {
                                outcome.advertised_stream_window = Some(value);
                            }
                            Setting::MaxConcurrentStreams(value) => {
                                outcome.advertised_max_streams = Some(value);
                            }
                            _ => {}
                        }
                    }
                    let mut ack = BytesMut::new();
                    Frame::Settings(SettingsFrame::ack())
                        .encode(&mut ack)
                        .expect("encode settings ack");
                    stream.write_all(&ack).expect("write settings ack");
                }
                Frame::WindowUpdate(update) if update.stream_id == 0 => {
                    outcome.connection_window_increment = Some(update.increment);
                }
                Frame::Headers(headers) => {
                    let mut block = Bytes::from(headers.header_block.to_vec());
                    let decoded = response_hpack
                        .decode(&mut block)
                        .expect("decode response headers");
                    for header in decoded {
                        if header.name == ":status" {
                            outcome.http_status = Some(header.value);
                        } else if header.name == "grpc-status" {
                            outcome.grpc_status = Some(header.value);
                        } else if header.name == "grpc-message" {
                            outcome.grpc_message = Some(header.value);
                        } else if header.name == "grpc-status-details-bin" {
                            outcome.grpc_status_details = Some(header.value);
                        }
                    }
                    if headers.end_stream && outcome.grpc_status.is_some() {
                        return outcome;
                    }
                }
                Frame::Data(data) => outcome.framed_body.extend_from_slice(&data.data),
                _ => {}
            }
        }

        match stream.read(&mut chunk) {
            Ok(0) => return outcome,
            Ok(read) => inbound.extend_from_slice(&chunk[..read]),
            Err(error) => panic!("production gRPC H2 response read failed: {error}; {outcome:?}"),
        }
    }
}

#[cfg(feature = "tls")]
const GRPC_TLS_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
#[cfg(feature = "tls")]
const GRPC_TLS_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");
#[cfg(feature = "tls")]
const GRPC_TLS_WRONG_CA_PEM: &[u8] = include_bytes!("fixtures/x509_adversarial/ca.crt");

#[cfg(feature = "tls")]
fn grpc_tls_acceptor(require_h2: bool) -> TlsAcceptor {
    let chain = CertificateChain::from_pem(GRPC_TLS_CERT_PEM).expect("parse gRPC TLS chain");
    let key = PrivateKey::from_pem(GRPC_TLS_KEY_PEM).expect("parse gRPC TLS key");
    let builder = TlsAcceptorBuilder::new(chain, key);
    let builder = if require_h2 {
        builder.alpn_grpc()
    } else {
        builder
    };
    builder.build().expect("build gRPC TLS acceptor")
}

#[cfg(feature = "tls")]
fn grpc_tls_connector(root_pem: &[u8], advertise_h2: bool) -> TlsConnector {
    let root = Certificate::from_pem(root_pem)
        .expect("parse gRPC TLS root")
        .into_iter()
        .next()
        .expect("gRPC TLS root fixture contains a certificate");
    let builder = TlsConnectorBuilder::new().add_root_certificate(&root);
    let builder = if advertise_h2 {
        builder.alpn_grpc()
    } else {
        builder
    };
    builder.build().expect("build gRPC TLS connector")
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct TlsGrpcObservation {
    scheme: String,
    authority: String,
    client_id: String,
    request_payload: Vec<u8>,
}

#[cfg(feature = "tls")]
async fn serve_tls_grpc_unary(
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> Result<TlsGrpcObservation, String> {
    let (tcp, _) = listener
        .accept()
        .await
        .map_err(|error| format!("accept gRPC TLS TCP: {error}"))?;
    let mut stream = acceptor
        .accept(tcp)
        .await
        .map_err(|error| format!("accept gRPC TLS handshake: {error}"))?;
    if stream.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("gRPC TLS server did not negotiate h2".to_owned());
    }

    let mut preface = [0_u8; CLIENT_PREFACE.len()];
    stream
        .read_exact(&mut preface)
        .await
        .map_err(|error| format!("read gRPC TLS H2 preface: {error}"))?;
    if preface != CLIENT_PREFACE {
        return Err("gRPC TLS client sent an invalid H2 preface".to_owned());
    }

    let mut frame_codec = FrameCodec::new();
    let mut hpack = HpackDecoder::new();
    let mut inbound = BytesMut::new();
    let mut chunk = [0_u8; 4096];
    let mut scheme = None;
    let mut authority = None;
    let mut client_id = None;
    let mut request_body = BytesMut::new();
    loop {
        while let Some(frame) = frame_codec
            .decode(&mut inbound)
            .map_err(|error| format!("decode gRPC TLS request frame: {error}"))?
        {
            match frame {
                Frame::Headers(headers) => {
                    if !headers.end_headers {
                        return Err(
                            "gRPC TLS fixture requires one-block request headers".to_owned()
                        );
                    }
                    let mut block = Bytes::from(headers.header_block.to_vec());
                    for header in hpack
                        .decode(&mut block)
                        .map_err(|error| format!("decode gRPC TLS request headers: {error}"))?
                    {
                        if header.name == ":scheme" {
                            scheme = Some(header.value);
                        } else if header.name == ":authority" {
                            authority = Some(header.value);
                        } else if header.name == "x-client-id" {
                            client_id = Some(header.value);
                        }
                    }
                }
                Frame::Data(data) => {
                    request_body.extend_from_slice(&data.data);
                    if data.end_stream {
                        let mut framed = request_body.clone();
                        let request = GrpcCodec::with_max_size(1024)
                            .decode(&mut framed)
                            .map_err(|error| format!("decode gRPC TLS request body: {error}"))?
                            .ok_or_else(|| "gRPC TLS request contained no message".to_owned())?;
                        if !framed.is_empty() {
                            return Err("gRPC TLS request contained trailing bytes".to_owned());
                        }

                        let mut response_body = BytesMut::new();
                        GrpcCodec::with_max_size(1024)
                            .encode(
                                GrpcMessage::new(Bytes::from_static(b"tls-public-pong")),
                                &mut response_body,
                            )
                            .map_err(|error| format!("encode gRPC TLS response body: {error}"))?;
                        let mut response_hpack = HpackEncoder::new();
                        let mut initial_block = BytesMut::new();
                        response_hpack.encode(
                            &[
                                Header::new(":status", "200"),
                                Header::new("content-type", "application/grpc"),
                                Header::new("x-server-id", "native-h2-tls"),
                                Header::new("x-server-token-bin", "AwQ"),
                            ],
                            &mut initial_block,
                        );
                        let mut trailer_block = BytesMut::new();
                        response_hpack.encode(
                            &[
                                Header::new("grpc-status", "0"),
                                Header::new("x-server-tail", "tls-complete"),
                            ],
                            &mut trailer_block,
                        );
                        let mut outbound = BytesMut::new();
                        Frame::Settings(SettingsFrame::new(Vec::new()))
                            .encode(&mut outbound)
                            .map_err(|error| format!("encode gRPC TLS settings: {error}"))?;
                        Frame::Headers(HeadersFrame::new(1, initial_block.freeze(), false, true))
                            .encode(&mut outbound)
                            .map_err(|error| {
                                format!("encode gRPC TLS response headers: {error}")
                            })?;
                        Frame::Data(DataFrame::new(1, response_body.freeze(), false))
                            .encode(&mut outbound)
                            .map_err(|error| format!("encode gRPC TLS response data: {error}"))?;
                        Frame::Headers(HeadersFrame::new(1, trailer_block.freeze(), true, true))
                            .encode(&mut outbound)
                            .map_err(|error| format!("encode gRPC TLS trailers: {error}"))?;
                        stream
                            .write_all(&outbound)
                            .await
                            .map_err(|error| format!("write gRPC TLS response: {error}"))?;
                        stream
                            .flush()
                            .await
                            .map_err(|error| format!("flush gRPC TLS response: {error}"))?;
                        return Ok(TlsGrpcObservation {
                            scheme: scheme
                                .ok_or_else(|| "gRPC TLS request omitted :scheme".to_owned())?,
                            authority: authority
                                .ok_or_else(|| "gRPC TLS request omitted :authority".to_owned())?,
                            client_id: client_id
                                .ok_or_else(|| "gRPC TLS request omitted x-client-id".to_owned())?,
                            request_payload: request.data.to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read gRPC TLS request: {error}"))?;
        if read == 0 {
            return Err("gRPC TLS client closed before request completion".to_owned());
        }
        inbound.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(feature = "tls")]
async fn accept_tls_probe(
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> Result<TlsProbeObservation, String> {
    let (tcp, _) = listener
        .accept()
        .await
        .map_err(|error| format!("accept TLS probe TCP: {error}"))?;
    let mut stream = acceptor
        .accept(tcp)
        .await
        .map_err(|error| format!("accept TLS probe handshake: {error}"))?;
    let alpn = stream.alpn_protocol().map(<[u8]>::to_vec);
    let mut application_byte = [0_u8; 1];
    let application_bytes = match stream.read(&mut application_byte).await {
        Ok(read) => application_byte[..read].to_vec(),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Vec::new()
        }
        Err(error) => return Err(format!("read TLS probe application byte: {error}")),
    };
    Ok(TlsProbeObservation {
        alpn,
        application_bytes,
    })
}

#[cfg(feature = "tls")]
#[derive(Debug, PartialEq, Eq)]
struct TlsProbeObservation {
    alpn: Option<Vec<u8>>,
    application_bytes: Vec<u8>,
}

#[derive(Clone)]
struct RegisteredEchoService {
    calls: Arc<AtomicUsize>,
}

impl NamedService for RegisteredEchoService {
    const NAME: &'static str = "test.Echo";
}

impl ServiceHandler for RegisteredEchoService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] =
            &[MethodDescriptor::unary("Unary", "/test.Echo/Unary")];
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Echo", "test", METHODS);
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Unary"]
    }

    fn call_unary<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        trailing_metadata: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async move {
            assert_eq!(path, "/test.Echo/Unary");
            assert!(!cx.is_cancel_requested());
            assert_eq!(request.get_ref().as_ref(), b"ping");
            assert!(matches!(
                trailing_metadata.get("x-client-tail"),
                Some(MetadataValue::Ascii(value)) if value == "tail-value"
            ));
            assert!(matches!(
                trailing_metadata.get("x-client-token-bin"),
                Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x01\x02"
            ));
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(Bytes::from_static(b"registered-pong")))
        })
    }
}

#[derive(Clone)]
struct PublicClientEchoService {
    calls: Arc<AtomicUsize>,
    observed_transport: Arc<Mutex<Option<String>>>,
}

impl NamedService for PublicClientEchoService {
    const NAME: &'static str = "test.PublicClient";
}

impl ServiceHandler for PublicClientEchoService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[
            MethodDescriptor::unary("Unary", "/test.PublicClient/Unary"),
            MethodDescriptor::unary("Fail", "/test.PublicClient/Fail"),
        ];
        static DESCRIPTOR: ServiceDescriptor =
            ServiceDescriptor::new("PublicClient", "test", METHODS);
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Unary", "Fail"]
    }

    fn call_unary<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        trailing_metadata: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async move {
            assert!(!cx.is_cancel_requested());
            assert!(trailing_metadata.is_empty());
            assert_eq!(request.get_ref().as_ref(), b"public-client-ping");
            assert!(matches!(
                request.metadata().get("x-client-id"),
                Some(MetadataValue::Ascii(value)) if value == "native-client"
            ));
            assert!(matches!(
                request.metadata().get("x-client-token-bin"),
                Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x01\x02"
            ));
            assert!(matches!(
                request.metadata().get("grpc-timeout"),
                Some(MetadataValue::Ascii(value)) if !value.is_empty()
            ));
            let transport = match request.metadata().get("x-asupersync-grpc-transport") {
                Some(MetadataValue::Ascii(value)) => value.clone(),
                other => panic!("missing native transport metadata: {other:?}"),
            };
            *self
                .observed_transport
                .lock()
                .expect("observed transport lock") = Some(transport);
            self.calls.fetch_add(1, Ordering::SeqCst);

            if path == "/test.PublicClient/Fail" {
                return Err(Status::with_details(
                    Code::ResourceExhausted,
                    "quota %\n café",
                    Bytes::from_static(b"public-details"),
                ));
            }

            assert_eq!(path, "/test.PublicClient/Unary");
            let mut response = Response::new(Bytes::from_static(b"public-client-pong"));
            assert!(response.metadata_mut().insert("x-server-id", "native-h2"));
            assert!(
                response
                    .metadata_mut()
                    .insert_bin("x-server-token-bin", Bytes::from_static(b"\x03\x04"),)
            );
            Ok(response)
        })
    }
}

/// The public client must cross the same real TCP/H2 boundary already proven
/// by the raw protocol fixture. This catches the old false-success path where
/// localhost `unary` merely cast the request value into the response value.
#[test]
fn public_grpc_client_unary_crosses_native_h2_and_maps_status_trailers() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_transport = Arc::new(Mutex::new(None));
        let server = Arc::new(
            Server::builder()
                .max_recv_message_size(1024)
                .max_send_message_size(1024)
                .stream_idle_timeout(Some(Duration::from_secs(2)))
                .add_service(PublicClientEchoService {
                    calls: Arc::clone(&calls),
                    observed_transport: Arc::clone(&observed_transport),
                })
                .build(),
        );
        let listener = server
            .bind_registered_http2(
                "127.0.0.1:0",
                HostPolicy::allow_list(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]),
            )
            .await
            .expect("bind registered-service gRPC H2 listener");
        let addr = listener.local_addr().expect("listener local addr");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn production gRPC H2 listener");

        let channel = Channel::builder(format!("http://127.0.0.1:{}", addr.port()))
            // The target runs alongside several other real-listener tests in
            // this integration binary. Keep the causal assertion about the
            // wire exchange, not scheduler timing under parallel load.
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(30))
            .max_send_message_size(1024)
            .max_recv_message_size(1024)
            .connect()
            .await
            .expect("construct native H2 gRPC channel");
        let mut client = GrpcClient::new(channel);

        let mut request = Request::new(Bytes::from_static(b"public-client-ping"));
        assert!(
            request
                .metadata_mut()
                .insert("x-client-id", "native-client")
        );
        assert!(
            request
                .metadata_mut()
                .insert_bin("x-client-token-bin", Bytes::from_static(b"\x01\x02"))
        );
        let response = client
            .unary::<Bytes, Bytes>("/test.PublicClient/Unary", request)
            .await
            .expect("native H2 unary response");
        assert_eq!(response.get_ref().as_ref(), b"public-client-pong");
        assert!(matches!(
            response.metadata().get("x-server-id"),
            Some(MetadataValue::Ascii(value)) if value == "native-h2"
        ));
        assert!(matches!(
            response.metadata().get("x-server-token-bin"),
            Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x03\x04"
        ));
        assert_eq!(
            observed_transport
                .lock()
                .expect("observed transport lock")
                .as_deref(),
            Some("native-h2")
        );

        let mut failure = Request::new(Bytes::from_static(b"public-client-ping"));
        assert!(
            failure
                .metadata_mut()
                .insert("x-client-id", "native-client")
        );
        assert!(
            failure
                .metadata_mut()
                .insert_bin("x-client-token-bin", Bytes::from_static(b"\x01\x02"))
        );
        let status = client
            .unary::<Bytes, Bytes>("/test.PublicClient/Fail", failure)
            .await
            .expect_err("terminal gRPC error trailers must map to Status");
        assert_eq!(status.code(), Code::ResourceExhausted);
        assert_eq!(status.message(), "quota %\n café");
        assert_eq!(
            status.details().map(Bytes::as_ref),
            Some(b"public-details".as_slice())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run join");
    });
}

/// asupersync-grpc-https-unary-iqer05: the public unary client must carry the
/// same payload and metadata over authenticated TLS, emit :scheme=https, and
/// refuse to write the H2 preface until ALPN has selected h2.
#[cfg(feature = "tls")]
#[test]
fn public_grpc_client_unary_crosses_authenticated_tls_h2() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gRPC TLS fixture");
        let addr = listener.local_addr().expect("gRPC TLS fixture address");
        let acceptor = grpc_tls_acceptor(true);
        let server = handle
            .clone()
            .try_spawn(async move { serve_tls_grpc_unary(listener, acceptor).await })
            .expect("spawn gRPC TLS fixture");

        let connector = grpc_tls_connector(GRPC_TLS_CERT_PEM, true);
        let channel = Channel::builder(format!("https://localhost:{}", addr.port()))
            .tls_connector(connector)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .max_send_message_size(1024)
            .max_recv_message_size(1024)
            .connect()
            .await
            .expect("construct authenticated gRPC TLS channel");
        let mut client = GrpcClient::new(channel);
        let mut request = Request::new(Bytes::from_static(b"tls-public-ping"));
        assert!(request.metadata_mut().insert("x-client-id", "tls-client"));
        let response = client
            .unary::<Bytes, Bytes>("/test.PublicClient/Unary", request)
            .await
            .expect("authenticated gRPC TLS unary response");
        assert_eq!(response.get_ref().as_ref(), b"tls-public-pong");
        assert!(matches!(
            response.metadata().get("x-server-id"),
            Some(MetadataValue::Ascii(value)) if value == "native-h2-tls"
        ));
        assert!(matches!(
            response.metadata().get("x-server-token-bin"),
            Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x03\x04"
        ));
        assert!(matches!(
            response.metadata().get("x-server-tail"),
            Some(MetadataValue::Ascii(value)) if value == "tls-complete"
        ));

        let observation = server.await.expect("gRPC TLS fixture exchange");
        assert_eq!(observation.scheme, "https");
        assert_eq!(observation.authority, format!("localhost:{}", addr.port()));
        assert_eq!(observation.client_id, "tls-client");
        assert_eq!(observation.request_payload, b"tls-public-ping");
    });
}

/// br-asupersync-server-stack-hardening-eeexl1.20: an explicit native socket
/// is a dial capability, not authority. The logical host remains on the wire
/// while TLS authenticates the explicitly selected server name and no DNS is
/// consulted.
#[cfg(feature = "tls")]
#[test]
fn public_grpc_client_unary_crosses_explicit_authenticated_dial_addr() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind explicit-dial gRPC TLS fixture");
        let addr = listener
            .local_addr()
            .expect("explicit-dial gRPC TLS fixture address");
        let acceptor = grpc_tls_acceptor(true);
        let server = handle
            .clone()
            .try_spawn(async move { serve_tls_grpc_unary(listener, acceptor).await })
            .expect("spawn explicit-dial gRPC TLS fixture");

        let logical_authority = "grpc.service.invalid:443";
        let channel = Channel::builder(format!("https://{logical_authority}"))
            .dial_addr(addr)
            .tls_connector(grpc_tls_connector(GRPC_TLS_CERT_PEM, true))
            .tls_server_name("localhost")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .max_send_message_size(1024)
            .max_recv_message_size(1024)
            .connect()
            .await
            .expect("construct authenticated explicit-dial gRPC channel");
        let mut client = GrpcClient::new(channel);
        let mut request = Request::new(Bytes::from_static(b"tls-public-ping"));
        assert!(
            request
                .metadata_mut()
                .insert("x-client-id", "explicit-dial-client")
        );
        let response = client
            .unary::<Bytes, Bytes>("/test.PublicClient/Unary", request)
            .await
            .expect("explicit-dial gRPC TLS unary response");
        assert_eq!(response.get_ref().as_ref(), b"tls-public-pong");
        assert!(matches!(
            response.metadata().get("x-server-id"),
            Some(MetadataValue::Ascii(value)) if value == "native-h2-tls"
        ));
        assert!(matches!(
            response.metadata().get("x-server-token-bin"),
            Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x03\x04"
        ));
        assert!(matches!(
            response.metadata().get("x-server-tail"),
            Some(MetadataValue::Ascii(value)) if value == "tls-complete"
        ));

        let observation = server
            .await
            .expect("explicit-dial gRPC TLS fixture exchange");
        assert_eq!(observation.scheme, "https");
        assert_eq!(observation.authority, logical_authority);
        assert_eq!(observation.client_id, "explicit-dial-client");
        assert_eq!(observation.request_payload, b"tls-public-ping");
    });
}

/// TLS authority and protocol mismatches must fail before any gRPC success is
/// synthesized: no connector, wrong CA, wrong certificate name, and missing
/// h2 ALPN are all planted refusals.
#[cfg(feature = "tls")]
#[test]
fn public_grpc_tls_unary_fails_closed_on_authority_and_alpn_mismatch() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let explicit_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443));
        let missing = Channel::builder("https://grpc.service.invalid:443")
            .dial_addr(explicit_addr)
            .tls()
            .connect()
            .await
            .expect_err("HTTPS without a connector must fail during channel validation");
        assert!(missing.to_string().contains("explicit TLS connector"));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind wrong-CA TLS fixture");
        let addr = listener.local_addr().expect("wrong-CA fixture address");
        let acceptor = grpc_tls_acceptor(true);
        let server = handle
            .clone()
            .try_spawn(async move { accept_tls_probe(listener, acceptor).await })
            .expect("spawn wrong-CA TLS fixture");
        let wrong_ca = grpc_tls_connector(GRPC_TLS_WRONG_CA_PEM, true);
        let channel = Channel::builder("https://grpc.service.invalid:443")
            .dial_addr(addr)
            .tls_connector(wrong_ca)
            .tls_server_name("localhost")
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("wrong-CA channel construction remains lazy");
        let status = GrpcClient::new(channel)
            .unary::<Bytes, Bytes>(
                "/test.PublicClient/Unary",
                Request::new(Bytes::from_static(b"must-not-dispatch")),
            )
            .await
            .expect_err("wrong CA must reject the TLS handshake");
        assert!(status.message().contains("TLS handshake failed"));
        assert!(
            server.await.is_err(),
            "wrong CA should also terminate the server handshake"
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind wrong-name TLS fixture");
        let addr = listener.local_addr().expect("wrong-name fixture address");
        let acceptor = grpc_tls_acceptor(true);
        let server = handle
            .clone()
            .try_spawn(async move { accept_tls_probe(listener, acceptor).await })
            .expect("spawn wrong-name TLS fixture");
        let channel = Channel::builder("https://grpc.service.invalid:443")
            .dial_addr(addr)
            .tls_connector(grpc_tls_connector(GRPC_TLS_CERT_PEM, true))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("wrong-name channel construction remains lazy");
        let status = GrpcClient::new(channel)
            .unary::<Bytes, Bytes>(
                "/test.PublicClient/Unary",
                Request::new(Bytes::from_static(b"must-not-dispatch")),
            )
            .await
            .expect_err("wrong certificate name must reject the TLS handshake");
        assert!(status.message().contains("TLS handshake failed"));
        assert!(
            server.await.is_err(),
            "wrong name should also terminate the server handshake"
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind no-ALPN TLS fixture");
        let addr = listener.local_addr().expect("no-ALPN fixture address");
        let acceptor = grpc_tls_acceptor(false);
        let server = handle
            .clone()
            .try_spawn(async move { accept_tls_probe(listener, acceptor).await })
            .expect("spawn no-ALPN TLS fixture");
        let channel = Channel::builder("https://grpc.service.invalid:443")
            .dial_addr(addr)
            .tls_connector(grpc_tls_connector(GRPC_TLS_CERT_PEM, false))
            .tls_server_name("localhost")
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("no-ALPN channel construction remains lazy");
        let status = GrpcClient::new(channel)
            .unary::<Bytes, Bytes>(
                "/test.PublicClient/Unary",
                Request::new(Bytes::from_static(b"must-not-dispatch")),
            )
            .await
            .expect_err("missing h2 ALPN must reject the gRPC TLS transport");
        assert!(status.message().contains("required h2 ALPN"));
        let observation = server.await.expect("no-ALPN TLS handshake may complete");
        assert_eq!(observation.alpn, None);
        assert_eq!(
            observation.application_bytes,
            Vec::<u8>::new(),
            "the client must not write the HTTP/2 preface before h2 ALPN succeeds"
        );
    });
}

/// A caller abort parked inside a real TLS handshake is terminal cancellation,
/// while the connection timeout independently bounds that handshake even when
/// the overall RPC deadline is much longer.
#[cfg(feature = "tls")]
#[test]
fn public_grpc_tls_handshake_honors_cancellation_and_connect_timeout() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");

    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime block_on installs an ambient Cx");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind cancellation TLS stall fixture");
        let addr = listener.local_addr().expect("cancellation fixture address");
        let (accepted_tx, mut accepted_rx) = oneshot::channel();
        let (release_tx, mut release_rx) = oneshot::channel();
        let mut server = cx
            .spawn(move |server_cx| async move {
                let (tcp, _) = listener.accept().await.expect("accept stalled TLS TCP");
                accepted_tx
                    .send_blocking(())
                    .expect("cancellation fixture receiver remains live");
                release_rx
                    .recv(&server_cx)
                    .await
                    .expect("cancellation fixture release remains live");
                drop(tcp);
            })
            .expect("spawn cancellation TLS stall fixture");
        let channel = Channel::builder(format!("https://localhost:{}", addr.port()))
            .tls_connector(grpc_tls_connector(GRPC_TLS_CERT_PEM, true))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("cancellation channel construction remains lazy");
        let mut call = cx
            .spawn(move |_call_cx| async move {
                GrpcClient::new(channel)
                    .unary::<Bytes, Bytes>(
                        "/test.PublicClient/Unary",
                        Request::new(Bytes::from_static(b"cancel-stalled-handshake")),
                    )
                    .await
            })
            .expect("spawn cancellable TLS call");
        accepted_rx
            .recv(&cx)
            .await
            .expect("TLS peer accepts before caller cancellation");
        call.abort_with_reason(CancelReason::user("cancel parked gRPC TLS handshake"));
        let status = call
            .join(&cx)
            .await
            .expect("cancel-aware gRPC call returns its typed result")
            .expect_err("caller cancellation must fail the unary RPC");
        assert_eq!(status.code(), Code::Cancelled);
        release_tx
            .send_blocking(())
            .expect("release cancellation TLS stall fixture");
        server
            .join(&cx)
            .await
            .expect("cancellation TLS stall fixture drains");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind connect-timeout TLS stall fixture");
        let addr = listener
            .local_addr()
            .expect("connect-timeout fixture address");
        let (accepted_tx, mut accepted_rx) = oneshot::channel();
        let (release_tx, mut release_rx) = oneshot::channel();
        let mut server = cx
            .spawn(move |server_cx| async move {
                let (tcp, _) = listener.accept().await.expect("accept timeout TLS TCP");
                accepted_tx
                    .send_blocking(())
                    .expect("connect-timeout fixture receiver remains live");
                release_rx
                    .recv(&server_cx)
                    .await
                    .expect("connect-timeout fixture release remains live");
                drop(tcp);
            })
            .expect("spawn connect-timeout TLS stall fixture");
        let channel = Channel::builder(format!("https://localhost:{}", addr.port()))
            .tls_connector(grpc_tls_connector(GRPC_TLS_CERT_PEM, true))
            .connect_timeout(Duration::from_millis(100))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("connect-timeout channel construction remains lazy");
        let mut call = cx
            .spawn(move |_call_cx| async move {
                GrpcClient::new(channel)
                    .unary::<Bytes, Bytes>(
                        "/test.PublicClient/Unary",
                        Request::new(Bytes::from_static(b"timeout-stalled-handshake")),
                    )
                    .await
            })
            .expect("spawn connect-timeout TLS call");
        accepted_rx
            .recv(&cx)
            .await
            .expect("TLS peer accepts before the connection timeout");
        let status = call
            .join(&cx)
            .await
            .expect("timed-out gRPC call returns its typed result")
            .expect_err("connection timeout must fail the unary RPC");
        assert_eq!(status.code(), Code::Unavailable);
        assert!(
            status
                .message()
                .contains("connection establishment exceeded")
        );
        release_tx
            .send_blocking(())
            .expect("release connect-timeout TLS stall fixture");
        server
            .join(&cx)
            .await
            .expect("connect-timeout TLS stall fixture drains");
    });
}

/// br-asupersync-v4ob51: the public gRPC transport adapter must exercise the
/// real H2 listener, advertise both configured flow-control windows and the
/// stream-admission cap, preserve a request trailer block separately from
/// initial metadata, decode/dispatch one framed request, then encode the
/// response and terminal grpc-status trailer on the same TCP stream.
/// Request-trailer coverage was added for br-asupersync-2rnlb0.
#[test]
fn production_grpc_adapter_wires_config_and_unary_codec_over_real_h2() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let server = Arc::new(
            Server::builder()
                .initial_connection_window_size(1024 * 1024)
                .initial_stream_window_size(32 * 1024)
                .max_concurrent_streams(3)
                .max_recv_message_size(64)
                .max_send_message_size(64)
                .stream_idle_timeout(Some(Duration::from_secs(2)))
                .build(),
        );
        let listener = server
            .bind_http2(
                "127.0.0.1:0",
                HostPolicy::allow_list(vec!["localhost".to_owned()]),
                |transport| async move {
                    assert_eq!(transport.path(), "/test.Echo/Unary");
                    assert!(matches!(
                        transport.trailing_metadata().get("x-client-tail"),
                        Some(MetadataValue::Ascii(value)) if value == "tail-value"
                    ));
                    assert!(matches!(
                        transport.trailing_metadata().get("x-client-token-bin"),
                        Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x01\x02"
                    ));
                    let (_, request, trailers) = transport.into_parts();
                    assert_eq!(request.get_ref().as_ref(), b"ping");
                    assert_eq!(trailers.iter().count(), 2);
                    Ok(Response::new(Bytes::from_static(b"pong")))
                },
            )
            .await
            .expect("bind production gRPC H2 listener");

        let addr = listener.local_addr().expect("listener local addr");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn production gRPC H2 listener");

        let outcome = std::thread::spawn(move || production_grpc_h2_client(addr))
            .join()
            .expect("raw gRPC H2 client thread");

        assert_eq!(outcome.advertised_stream_window, Some(32 * 1024));
        assert_eq!(outcome.advertised_max_streams, Some(3));
        assert_eq!(
            outcome.connection_window_increment,
            Some(1024 * 1024 - 65_535)
        );
        assert_eq!(outcome.http_status.as_deref(), Some("200"));
        assert_eq!(outcome.grpc_status.as_deref(), Some("0"));
        assert_eq!(outcome.grpc_message, None);
        assert_eq!(outcome.grpc_status_details, None);

        let mut framed_body = BytesMut::from(outcome.framed_body.as_slice());
        let decoded = GrpcCodec::with_max_size(64)
            .decode(&mut framed_body)
            .expect("decode framed response")
            .expect("one response frame");
        assert_eq!(decoded.data.as_ref(), b"pong");
        assert!(framed_body.is_empty());

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run join");
    });
}

/// br-asupersync-u0j91o: registered services must be the callable routing
/// authority for the native H2 adapter. An unknown method on a registered
/// service must produce terminal grpc-status=12 without invoking the service.
#[test]
fn registered_service_dispatches_and_unknown_method_is_unimplemented_over_real_h2() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let calls = Arc::new(AtomicUsize::new(0));
        let server = Arc::new(
            Server::builder()
                .max_recv_message_size(64)
                .max_send_message_size(64)
                .stream_idle_timeout(Some(Duration::from_secs(2)))
                .add_service(RegisteredEchoService {
                    calls: Arc::clone(&calls),
                })
                .build(),
        );
        let listener = server
            .bind_registered_http2(
                "127.0.0.1:0",
                HostPolicy::allow_list(vec!["localhost".to_owned()]),
            )
            .await
            .expect("bind registered-service gRPC H2 listener");

        let addr = listener.local_addr().expect("listener local addr");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn registered-service gRPC H2 listener");

        let registered = std::thread::spawn(move || {
            production_grpc_h2_client_for_path(addr, "/test.Echo/Unary")
        })
        .join()
        .expect("registered raw gRPC H2 client thread");
        assert_eq!(registered.http_status.as_deref(), Some("200"));
        assert_eq!(registered.grpc_status.as_deref(), Some("0"));
        let mut framed_body = BytesMut::from(registered.framed_body.as_slice());
        let decoded = GrpcCodec::with_max_size(64)
            .decode(&mut framed_body)
            .expect("decode registered response")
            .expect("one registered response frame");
        assert_eq!(decoded.data.as_ref(), b"registered-pong");
        assert!(framed_body.is_empty());

        let unknown = std::thread::spawn(move || {
            production_grpc_h2_client_for_path(addr, "/test.Echo/Missing")
        })
        .join()
        .expect("unknown-method raw gRPC H2 client thread");
        assert_eq!(unknown.http_status.as_deref(), Some("200"));
        assert_eq!(unknown.grpc_status.as_deref(), Some("12"));
        assert!(unknown.framed_body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run join");
    });
}

/// br-asupersync-2rnlb0: an error returned by the production adapter must keep
/// its code, percent-encoded UTF-8 message, and binary details in the terminal
/// H2 trailer block.
#[test]
fn production_grpc_adapter_preserves_error_status_over_real_h2() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let server = Arc::new(
            Server::builder()
                .max_recv_message_size(64)
                .max_send_message_size(64)
                .stream_idle_timeout(Some(Duration::from_secs(2)))
                .build(),
        );
        let listener = server
            .bind_http2(
                "127.0.0.1:0",
                HostPolicy::allow_list(vec!["localhost".to_owned()]),
                |transport| async move {
                    assert_eq!(transport.path(), "/test.Echo/Unary");
                    assert_eq!(
                        transport.trailing_metadata().iter().count(),
                        2,
                        "validated request trailers reach the erroring handler"
                    );
                    Err::<Response<Bytes>, _>(Status::with_details(
                        Code::ResourceExhausted,
                        "quota %\n café",
                        Bytes::from_static(b"detail"),
                    ))
                },
            )
            .await
            .expect("bind production gRPC H2 listener");

        let addr = listener.local_addr().expect("listener local addr");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn production gRPC H2 listener");

        let outcome = std::thread::spawn(move || production_grpc_h2_client(addr))
            .join()
            .expect("raw gRPC H2 client thread");

        assert_eq!(outcome.http_status.as_deref(), Some("200"));
        assert_eq!(outcome.grpc_status.as_deref(), Some("8"));
        assert_eq!(
            outcome.grpc_message.as_deref(),
            Some("quota %25%0A caf%C3%A9")
        );
        assert_eq!(outcome.grpc_status_details.as_deref(), Some("ZGV0YWls"));
        assert!(outcome.framed_body.is_empty());

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run join");
    });
}
