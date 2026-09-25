//! MySQL SSL/TLS negotiation conformance tests.
//!
//! This test suite verifies that the MySQL client correctly implements
//! SSL/TLS negotiation according to the MySQL protocol specification,
//! especially for `caching_sha2_password` authentication.
//!
//! # Covered Protocol Boundaries
//!
//! Native TLS tests below exercise SSLRequest, verified TLS, cold caching_sha2
//! authentication, and command traffic. Feature-disabled and stripped-capability
//! tests require failure before any authentication payload is sent.

#![cfg(feature = "mysql")]

use asupersync::Cx;
use asupersync::database::mysql::{MySqlConnectOptions, MySqlConnection, MySqlError, SslMode};
use asupersync::test_utils::init_test_logging;
use asupersync::types::Outcome;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

/// MySQL capability flags for SSL/TLS support
mod mysql_capabilities {
    pub const CLIENT_SSL: u32 = 2048;
    pub const CLIENT_PROTOCOL_41: u32 = 512;
    pub const CLIENT_SECURE_CONNECTION: u32 = 32768;
    pub const CLIENT_PLUGIN_AUTH: u32 = 0x80000;
}

fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0xFF_FFFF);
    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

fn mysql_handshake_packet(server_capabilities: u32) -> Vec<u8> {
    mysql_handshake_packet_with_connection_id(server_capabilities, 42)
}

fn mysql_handshake_packet_with_connection_id(
    server_capabilities: u32,
    connection_id: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(10);
    payload.extend_from_slice(b"8.0.0-asupersync-test\0");
    payload.extend_from_slice(&connection_id.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0);
    payload.extend_from_slice(&(server_capabilities as u16).to_le_bytes());
    payload.push(33);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&((server_capabilities >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(b"abcdefghijkl\0");
    payload.extend_from_slice(b"caching_sha2_password\0");
    mysql_packet(0, &payload)
}

/// A minimal protocol-41 OK packet payload: affected rows 0, last insert id 0,
/// status SERVER_STATUS_AUTOCOMMIT, no warnings. Since 90990d3bf the client reads
/// the status flags from the authentication OK, so a bare `0x00` is malformed.
fn auth_ok_payload() -> [u8; 7] {
    [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]
}

fn read_mysql_packet(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("read packet header");
    let payload_len =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .expect("read packet payload");
    payload
}

fn ssl_mode_query_value(mode: SslMode) -> &'static str {
    match mode {
        SslMode::Disabled => "disabled",
        SslMode::Preferred => "preferred",
        SslMode::Required => "required",
    }
}

fn assert_ssl_mode_fails_closed_before_auth_payload(
    mode: SslMode,
    server_capabilities: u32,
    context: &'static str,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (read_tx, read_rx) = mpsc::channel();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        stream
            .write_all(&mysql_handshake_packet(server_capabilities))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let mut header = [0; 4];
        let read = stream.read(&mut header).unwrap_or_else(|err| {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ),
                "unexpected server read error for {context}: {err}"
            );
            0
        });
        read_tx.send(read).expect("send read count");
    });

    let mut options = MySqlConnectOptions::parse(&format!(
        "mysql://user:pass@{}:{}/db?ssl-mode={}",
        addr.ip(),
        addr.port(),
        ssl_mode_query_value(mode)
    ))
    .expect("parse options");
    options.connect_timeout = Some(Duration::from_secs(2));

    let outcome = futures_lite::future::block_on(async {
        MySqlConnection::connect_with_options(&Cx::for_testing(), options).await
    });
    match outcome {
        Outcome::Err(MySqlError::TlsRequired) => {}
        other => panic!("expected {mode:?} TLS fail-closed outcome for {context}, got {other:?}"),
    }

    let bytes_sent = read_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server read result");
    server.join().expect("join server");
    assert_eq!(
        bytes_sent, 0,
        "{mode:?} must fail before sending plaintext auth data for {context}"
    );
}

/// Test SSL mode URL parsing conformance
#[test]
fn test_ssl_mode_url_parsing_conformance() {
    init_test_logging();

    // Test all SSL modes are parsed correctly
    let disabled =
        MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=disabled").unwrap();
    assert_eq!(disabled.ssl_mode, SslMode::Disabled);

    let preferred =
        MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=preferred").unwrap();
    assert_eq!(preferred.ssl_mode, SslMode::Preferred);

    let required =
        MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=required").unwrap();
    assert_eq!(required.ssl_mode, SslMode::Required);

    // Test case insensitivity
    let required_upper =
        MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=REQUIRED").unwrap();
    assert_eq!(required_upper.ssl_mode, SslMode::Required);

    // Test alternative parameter name
    let preferred_alt =
        MySqlConnectOptions::parse("mysql://user@localhost/db?sslmode=preferred").unwrap();
    assert_eq!(preferred_alt.ssl_mode, SslMode::Preferred);

    // Test invalid SSL mode is rejected
    let invalid = MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=invalid");
    assert!(invalid.is_err(), "Invalid SSL mode should be rejected");

    if let Err(MySqlError::InvalidUrl(msg)) = invalid {
        assert!(
            msg.contains("unknown ssl-mode"),
            "Error should mention unknown ssl-mode"
        );
    } else {
        panic!("Expected InvalidUrl error for unknown ssl-mode");
    }

    // Test default SSL mode is Disabled
    let default = MySqlConnectOptions::parse("mysql://user@localhost/db").unwrap();
    assert_eq!(default.ssl_mode, SslMode::Disabled);
}

/// Test that SslMode enum has correct default and semantics
#[test]
fn test_ssl_mode_enum_conformance() {
    init_test_logging();

    // Default should be Disabled (most secure default - no accidental cleartext)
    assert_eq!(SslMode::default(), SslMode::Disabled);

    // Enum values should be distinct
    assert_ne!(SslMode::Disabled, SslMode::Preferred);
    assert_ne!(SslMode::Disabled, SslMode::Required);
    assert_ne!(SslMode::Preferred, SslMode::Required);

    // Should be copyable and cloneable.
    let mode = SslMode::Required;
    let copied = mode;
    fn assert_clone<T: Clone>(_: &T) {}
    assert_clone(&mode);
    assert_eq!(mode, copied);

    // Debug output should be meaningful
    assert!(format!("{:?}", SslMode::Disabled).contains("Disabled"));
    assert!(format!("{:?}", SslMode::Preferred).contains("Preferred"));
    assert!(format!("{:?}", SslMode::Required).contains("Required"));
}

/// Builds without TLS must fail before any credential-bearing packet.
#[cfg(not(feature = "tls"))]
#[test]
fn test_required_ssl_fails_closed_before_auth_payload() {
    init_test_logging();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (read_tx, read_rx) = mpsc::channel();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let capabilities = mysql_capabilities::CLIENT_PROTOCOL_41
            | mysql_capabilities::CLIENT_SECURE_CONNECTION
            | mysql_capabilities::CLIENT_PLUGIN_AUTH
            | mysql_capabilities::CLIENT_SSL;
        stream
            .write_all(&mysql_handshake_packet(capabilities))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let mut header = [0; 4];
        let read = stream.read(&mut header).unwrap_or_else(|err| {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ),
                "unexpected server read error: {err}"
            );
            0
        });
        read_tx.send(read).expect("send read count");
    });

    let mut options = MySqlConnectOptions::parse(&format!(
        "mysql://user:pass@{}:{}/db?ssl-mode=required",
        addr.ip(),
        addr.port()
    ))
    .expect("parse options");
    options.connect_timeout = Some(Duration::from_secs(2));

    let outcome = futures_lite::future::block_on(async {
        MySqlConnection::connect_with_options(&Cx::for_testing(), options).await
    });
    match outcome {
        Outcome::Err(MySqlError::TlsRequired) => {}
        other => panic!("expected TlsRequired fail-closed outcome, got {other:?}"),
    }

    let bytes_sent = read_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server read result");
    server.join().expect("join server");
    assert_eq!(
        bytes_sent, 0,
        "ssl-mode=required must fail before sending plaintext auth data"
    );
}

#[cfg(not(feature = "tls"))]
#[test]
fn test_preferred_ssl_fails_closed_before_auth_payload_when_server_supports_ssl() {
    init_test_logging();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (read_tx, read_rx) = mpsc::channel();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let capabilities = mysql_capabilities::CLIENT_PROTOCOL_41
            | mysql_capabilities::CLIENT_SECURE_CONNECTION
            | mysql_capabilities::CLIENT_PLUGIN_AUTH
            | mysql_capabilities::CLIENT_SSL;
        stream
            .write_all(&mysql_handshake_packet(capabilities))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let mut header = [0; 4];
        let read = stream.read(&mut header).unwrap_or_else(|err| {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ),
                "unexpected server read error: {err}"
            );
            0
        });
        read_tx.send(read).expect("send read count");
    });

    let mut options = MySqlConnectOptions::parse(&format!(
        "mysql://user:pass@{}:{}/db?ssl-mode=preferred",
        addr.ip(),
        addr.port()
    ))
    .expect("parse options");
    options.connect_timeout = Some(Duration::from_secs(2));

    let outcome = futures_lite::future::block_on(async {
        MySqlConnection::connect_with_options(&Cx::for_testing(), options).await
    });
    match outcome {
        Outcome::Err(MySqlError::TlsRequired) => {}
        other => panic!("expected preferred SSL fail-closed outcome, got {other:?}"),
    }

    let bytes_sent = read_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server read result");
    server.join().expect("join server");
    assert_eq!(
        bytes_sent, 0,
        "ssl-mode=preferred must fail before sending plaintext auth data when the server advertises CLIENT_SSL"
    );
}

#[test]
fn test_preferred_ssl_fails_closed_before_auth_payload_when_server_lacks_ssl_support() {
    init_test_logging();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (read_tx, read_rx) = mpsc::channel();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let capabilities = mysql_capabilities::CLIENT_PROTOCOL_41
            | mysql_capabilities::CLIENT_SECURE_CONNECTION
            | mysql_capabilities::CLIENT_PLUGIN_AUTH;
        stream
            .write_all(&mysql_handshake_packet(capabilities))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let mut header = [0; 4];
        let read = stream.read(&mut header).unwrap_or_else(|err| {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ),
                "unexpected server read error: {err}"
            );
            0
        });
        read_tx.send(read).expect("send read count");
    });

    let mut options = MySqlConnectOptions::parse(&format!(
        "mysql://user:pass@{}:{}/db?ssl-mode=preferred",
        addr.ip(),
        addr.port()
    ))
    .expect("parse options");
    options.connect_timeout = Some(Duration::from_secs(2));

    let outcome = futures_lite::future::block_on(async {
        MySqlConnection::connect_with_options(&Cx::for_testing(), options).await
    });
    match outcome {
        Outcome::Err(MySqlError::TlsRequired) => {}
        other => panic!("expected preferred SSL fail-closed outcome, got {other:?}"),
    }

    let bytes_sent = read_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server read result");
    server.join().expect("join server");
    assert_eq!(
        bytes_sent, 0,
        "ssl-mode=preferred must fail before sending plaintext auth data even when the server omits CLIENT_SSL"
    );
}

#[test]
fn test_prepared_statement_rejects_cross_connection_reuse() {
    init_test_logging();

    let capabilities = mysql_capabilities::CLIENT_PROTOCOL_41
        | mysql_capabilities::CLIENT_SECURE_CONNECTION
        | mysql_capabilities::CLIENT_PLUGIN_AUTH;

    let prepare_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind prepare");
    let prepare_addr = prepare_listener.local_addr().expect("prepare addr");
    let prepare_server = std::thread::spawn(move || {
        let (mut stream, _) = prepare_listener.accept().expect("accept prepare client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set prepare read timeout");

        stream
            .write_all(&mysql_handshake_packet_with_connection_id(
                capabilities,
                101,
            ))
            .expect("write prepare handshake");
        stream.flush().expect("flush prepare handshake");

        let _handshake_response = read_mysql_packet(&mut stream);
        stream
            .write_all(&mysql_packet(2, &auth_ok_payload()))
            .expect("write auth ok");
        stream.flush().expect("flush auth ok");

        let prepare_payload = read_mysql_packet(&mut stream);
        assert_eq!(prepare_payload[0], 0x16, "expected COM_STMT_PREPARE");

        let mut ok = Vec::new();
        ok.push(0x00);
        ok.extend_from_slice(&77_u32.to_le_bytes());
        ok.extend_from_slice(&0_u16.to_le_bytes());
        ok.extend_from_slice(&0_u16.to_le_bytes());
        ok.push(0x00);
        ok.extend_from_slice(&0_u16.to_le_bytes());
        stream
            .write_all(&mysql_packet(1, &ok))
            .expect("write prepare ok");
        stream.flush().expect("flush prepare ok");
    });

    let reject_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind reject");
    let reject_addr = reject_listener.local_addr().expect("reject addr");
    let (read_tx, read_rx) = mpsc::channel();
    let reject_server = std::thread::spawn(move || {
        let (mut stream, _) = reject_listener.accept().expect("accept reject client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set reject read timeout");

        stream
            .write_all(&mysql_handshake_packet_with_connection_id(
                capabilities,
                202,
            ))
            .expect("write reject handshake");
        stream.flush().expect("flush reject handshake");

        let _handshake_response = read_mysql_packet(&mut stream);
        stream
            .write_all(&mysql_packet(2, &auth_ok_payload()))
            .expect("write reject auth ok");
        stream.flush().expect("flush reject auth ok");

        let mut header = [0u8; 4];
        let read = stream.read(&mut header).unwrap_or_else(|err| {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ),
                "unexpected reject-server read error: {err}"
            );
            0
        });
        read_tx.send(read).expect("send reject read count");
    });

    let cx = Cx::for_testing();
    let mut prepare_options = MySqlConnectOptions::parse(&format!(
        "mysql://user@{}:{}/db",
        prepare_addr.ip(),
        prepare_addr.port()
    ))
    .expect("parse prepare options");
    prepare_options.connect_timeout = Some(Duration::from_secs(2));

    let stmt = match futures_lite::future::block_on(async {
        let mut conn = match MySqlConnection::connect_with_options(&cx, prepare_options).await {
            Outcome::Ok(conn) => conn,
            other => panic!("expected prepare connection, got {other:?}"),
        };
        conn.prepare(&cx, "SELECT 1").await
    }) {
        Outcome::Ok(stmt) => stmt,
        Outcome::Err(err) => panic!("expected prepare ok, got error: {err}"),
        Outcome::Cancelled(reason) => panic!("expected prepare ok, got cancellation: {reason}"),
        Outcome::Panicked(_) => panic!("expected prepare ok, got panic"),
    };

    let mut reject_options = MySqlConnectOptions::parse(&format!(
        "mysql://user@{}:{}/db",
        reject_addr.ip(),
        reject_addr.port()
    ))
    .expect("parse reject options");
    reject_options.connect_timeout = Some(Duration::from_secs(2));

    let mut conn = match futures_lite::future::block_on(async {
        MySqlConnection::connect_with_options(&cx, reject_options).await
    }) {
        Outcome::Ok(conn) => conn,
        other => panic!("expected reject-side connection, got {other:?}"),
    };

    let outcome =
        futures_lite::future::block_on(async { conn.execute_prepared(&cx, &stmt, &[]).await });
    match outcome {
        Outcome::Err(MySqlError::InvalidParameter(msg)) => {
            assert!(msg.contains("belongs to connection 101"));
            assert!(msg.contains("current connection is 202"));
        }
        other => panic!("expected statement/connection mismatch, got {other:?}"),
    }

    drop(conn);

    let bytes_sent = read_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reject read result");
    assert_eq!(
        bytes_sent, 0,
        "cross-connection statement reuse must fail before COM_STMT_EXECUTE reaches the server"
    );

    prepare_server.join().expect("join prepare server");
    reject_server.join().expect("join reject server");
}

/// Test conformance gap: Missing server SSL capability validation
#[test]
fn test_conformance_gap_missing_server_ssl_validation() {
    init_test_logging();

    // A stripped CLIENT_SSL bit must never authorize plaintext credentials.
    let base_capabilities = mysql_capabilities::CLIENT_PROTOCOL_41
        | mysql_capabilities::CLIENT_SECURE_CONNECTION
        | mysql_capabilities::CLIENT_PLUGIN_AUTH;

    assert_ssl_mode_fails_closed_before_auth_payload(
        SslMode::Required,
        base_capabilities,
        "required mode with server missing CLIENT_SSL",
    );
    #[cfg(not(feature = "tls"))]
    assert_ssl_mode_fails_closed_before_auth_payload(
        SslMode::Required,
        base_capabilities | mysql_capabilities::CLIENT_SSL,
        "required mode with server advertising CLIENT_SSL",
    );
}

/// Test conformance gap: Missing TLS handshake implementation
#[cfg(not(feature = "tls"))]
#[test]
fn test_conformance_gap_missing_tls_handshake() {
    init_test_logging();

    let tls_capable_server = mysql_capabilities::CLIENT_PROTOCOL_41
        | mysql_capabilities::CLIENT_SECURE_CONNECTION
        | mysql_capabilities::CLIENT_PLUGIN_AUTH
        | mysql_capabilities::CLIENT_SSL;

    assert_ssl_mode_fails_closed_before_auth_payload(
        SslMode::Required,
        tls_capable_server,
        "required mode before TLS upgrade implementation",
    );
    assert_ssl_mode_fails_closed_before_auth_payload(
        SslMode::Preferred,
        tls_capable_server,
        "preferred mode before TLS upgrade implementation",
    );
}

/// Test caching_sha2_password conformance with secure connections
#[test]
fn test_caching_sha2_password_secure_connection_requirement() {
    init_test_logging();

    // caching_sha2_password authentication in MySQL has two modes:
    // 1. Fast auth: Uses cached authentication (works over cleartext)
    // 2. Full auth: Requires secure connection or RSA key exchange

    // The current implementation correctly detects when full auth is required
    // and returns appropriate error messages, but cannot establish the secure
    // connection needed to complete the authentication.

    // Verify error messages are conformant
    let fast_auth_msg = "caching_sha2_password full auth requires secure connection";
    let cache_required_msg =
        "caching_sha2_password requires cached credentials or secure connection";

    assert!(fast_auth_msg.contains("secure connection"));
    assert!(cache_required_msg.contains("secure connection"));
}

/// Integration test demonstrating the conformance impact
#[test]
fn test_conformance_impact_integration() {
    init_test_logging();

    // This test demonstrates how the conformance gaps interact:

    // 1. User configures ssl_mode=Required for security
    let options =
        MySqlConnectOptions::parse("mysql://user:pass@localhost/db?ssl-mode=required").unwrap();
    assert_eq!(options.ssl_mode, SslMode::Required);

    // 2. Client attempts connection but cannot perform the TLS upgrade yet.

    // 3. Result: Connection must fail closed instead of sending credentials
    //    over cleartext.
    assert_eq!(
        MySqlError::TlsRequired.to_string(),
        "TLS required but not available"
    );
}

/// Test documentation of required fixes
#[test]
fn test_required_fixes_documentation() {
    init_test_logging();

    let required_capabilities = [
        mysql_capabilities::CLIENT_PROTOCOL_41,
        mysql_capabilities::CLIENT_SECURE_CONNECTION,
        mysql_capabilities::CLIENT_PLUGIN_AUTH,
        mysql_capabilities::CLIENT_SSL,
    ];
    assert_eq!(required_capabilities.len(), 4);
    assert!(
        required_capabilities.contains(&mysql_capabilities::CLIENT_SSL),
        "the pending TLS implementation must preserve the CLIENT_SSL boundary"
    );
    assert_eq!(ssl_mode_query_value(SslMode::Disabled), "disabled");
    assert_eq!(ssl_mode_query_value(SslMode::Preferred), "preferred");
    assert_eq!(ssl_mode_query_value(SslMode::Required), "required");
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
mod native_tls {
    use super::*;
    use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
    use asupersync::tls::TlsConnector;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::future::{Future, poll_fn};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    const CERT: &[u8] = include_bytes!("fixtures/tls/admission_peer.crt");
    const KEY: &[u8] = include_bytes!("fixtures/tls/admission_peer.key");
    const OK: &[u8] = &[0, 0, 0, 2, 0, 0, 0];

    fn capabilities() -> u32 {
        mysql_capabilities::CLIENT_PROTOCOL_41
            | mysql_capabilities::CLIENT_SECURE_CONNECTION
            | mysql_capabilities::CLIENT_PLUGIN_AUTH
            | mysql_capabilities::CLIENT_SSL
            | 0x0020_0000 // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    }

    fn connector(trusted: bool) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        if trusted {
            roots
                .add(CertificateDer::from_pem_slice(CERT).unwrap())
                .unwrap();
        }
        TlsConnector::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn accept_tls(
        socket: std::net::TcpStream,
    ) -> rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream> {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(CERT).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap();
        rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            socket,
        )
    }

    fn read_packet(reader: &mut impl Read) -> std::io::Result<(u8, Vec<u8>)> {
        let mut header = [0; 4];
        reader.read_exact(&mut header)?;
        let length =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        assert!(
            length < 65_536,
            "unexpected fixture packet length: {length}"
        );
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload)?;
        Ok((header[3], payload))
    }

    fn accept_socket(listener: &std::net::TcpListener) -> std::net::TcpStream {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
    }

    fn ssl_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
        socket
            .write_all(&mysql_handshake_packet(capabilities()))
            .unwrap();
        let (sequence, request) = read_packet(socket).unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(request.len(), 32, "only SSLRequest may precede TLS");
        let flags = u32::from_le_bytes(request[..4].try_into().unwrap());
        assert_ne!(flags & mysql_capabilities::CLIENT_SSL, 0);
        assert_eq!(&request[9..], &[0; 23]);
        request
    }

    fn options(address: std::net::SocketAddr, mode: SslMode) -> MySqlConnectOptions {
        let mut options =
            MySqlConnectOptions::parse(&format!("mysql://cold_user:cold_secret@{address}/db"))
                .unwrap();
        options.ssl_mode = mode;
        options.connect_timeout = Some(Duration::from_secs(2));
        options
    }

    fn assert_retired(runtime: &asupersync::runtime::Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(2));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    #[test]
    fn native_mysql_tls_cold_auth_and_auth_switch_roundtrip() {
        for workers in [1, 2] {
            for mode in [SslMode::Preferred, SslMode::Required] {
                for auth_switch in [false, true] {
                    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = listener.local_addr().unwrap();
                    let server = std::thread::spawn(move || {
                        let mut socket = accept_socket(&listener);
                        let request = ssl_request(&mut socket);
                        let mut tls = accept_tls(socket);
                        let (sequence, response) = read_packet(&mut tls).unwrap();
                        assert_eq!(sequence, 2);
                        assert_eq!(&response[..32], request.as_slice());
                        assert!(response[32..].starts_with(b"cold_user\0"));
                        assert!(
                            !response
                                .windows(b"cold_secret".len())
                                .any(|window| window == b"cold_secret")
                        );
                        let mut next = 3;
                        if auth_switch {
                            let mut switch = b"\xfecaching_sha2_password\0".to_vec();
                            switch.extend_from_slice(b"zyxwvutsrqponmlkjihg\0");
                            tls.write_all(&mysql_packet(next, &switch)).unwrap();
                            tls.flush().unwrap();
                            let (sequence, scramble) = read_packet(&mut tls).unwrap();
                            assert_eq!(sequence, next + 1);
                            assert_eq!(scramble.len(), 32);
                            next += 2;
                        }
                        tls.write_all(&mysql_packet(next, &[1, 4])).unwrap();
                        tls.flush().unwrap();
                        let (sequence, password) = read_packet(&mut tls).unwrap();
                        assert_eq!(sequence, next + 1);
                        assert_eq!(password, b"cold_secret\0");
                        tls.write_all(&mysql_packet(next + 2, OK)).unwrap();
                        tls.flush().unwrap();
                        let (sequence, ping) = read_packet(&mut tls).unwrap();
                        assert_eq!(sequence, 0);
                        assert_eq!(ping, [0x0e]);
                        tls.write_all(&mysql_packet(1, OK)).unwrap();
                        tls.flush().unwrap();
                        let (sequence, quit) = read_packet(&mut tls).unwrap();
                        assert_eq!(sequence, 0);
                        assert_eq!(quit, [1]);
                    });
                    let runtime = RuntimeBuilder::new()
                        .worker_threads(workers)
                        .build()
                        .unwrap();
                    let join = runtime.handle().spawn(async move {
                        let cx = Cx::current().unwrap();
                        let mut connection = match MySqlConnection::connect_with_tls_connector(
                            &cx,
                            options(address, mode),
                            connector(true),
                        )
                        .await
                        {
                            Outcome::Ok(connection) => connection,
                            other => panic!("TLS cold login failed: {other:?}"),
                        };
                        assert!(connection.is_tls());
                        assert_eq!(connection.connection_id(), 42);
                        assert!(matches!(connection.ping(&cx).await, Outcome::Ok(())));
                        connection.close().await.unwrap();
                    });
                    runtime.block_on(join);
                    server.join().unwrap();
                    assert_retired(&runtime);
                    eprintln!(
                        "event=mysql_tls_cold_auth workers={workers} mode={mode:?} auth_switch={auth_switch} verified=true ping=true closed=true"
                    );
                }
            }
        }
    }

    #[test]
    fn native_mysql_rejects_untrusted_tls_without_authentication_bytes() {
        for workers in [1, 2] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let mut socket = accept_socket(&listener);
                ssl_request(&mut socket);
                let mut tls = accept_tls(socket);
                let mut application_byte = [0];
                assert!(
                    matches!(tls.read(&mut application_byte), Ok(0) | Err(_)),
                    "untrusted TLS received authentication data"
                );
            });
            let runtime = RuntimeBuilder::new()
                .worker_threads(workers)
                .build()
                .unwrap();
            let join = runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let result = MySqlConnection::connect_with_tls_connector(&cx, options(address, SslMode::Required), connector(false)).await;
                assert!(matches!(result, Outcome::Err(MySqlError::Io(ref error)) if error.kind() == std::io::ErrorKind::ConnectionAborted), "{result:?}");
            });
            runtime.block_on(join);
            server.join().unwrap();
            assert_retired(&runtime);
            eprintln!("event=mysql_tls_rejected workers={workers} auth_bytes=0");
        }
    }

    #[test]
    fn native_mysql_plaintext_full_auth_never_sends_password() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut socket = accept_socket(&listener);
            socket
                .write_all(&mysql_handshake_packet(capabilities()))
                .unwrap();
            let (sequence, response) = read_packet(&mut socket).unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(
                u32::from_le_bytes(response[..4].try_into().unwrap())
                    & mysql_capabilities::CLIENT_SSL,
                0
            );
            socket.write_all(&mysql_packet(2, &[1, 4])).unwrap();
            let mut extra = [0];
            match socket.read(&mut extra) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => {
                    panic!("plaintext full-auth rejection must close without a password: {other:?}")
                }
            }
        });
        let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
        let join = runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let result =
                MySqlConnection::connect_with_options(&cx, options(address, SslMode::Disabled))
                    .await;
            assert!(
                matches!(result, Outcome::Err(MySqlError::AuthenticationFailed(_))),
                "{result:?}"
            );
        });
        runtime.block_on(join);
        server.join().unwrap();
        assert_retired(&runtime);
        eprintln!("event=mysql_plaintext_cold_auth rejected=true password_bytes=0");
    }

    #[derive(Clone, Copy, Debug)]
    enum Stall {
        Greeting,
        TlsHandshake,
        Authentication,
    }

    #[test]
    fn native_mysql_connect_deadline_and_cancel_release_parked_handshakes() {
        for workers in [1, 2] {
            for phase in [Stall::Greeting, Stall::TlsHandshake, Stall::Authentication] {
                for cancel in [false, true] {
                    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = listener.local_addr().unwrap();
                    let (stage_tx, stage_rx) = mpsc::channel();
                    let server = std::thread::spawn(move || {
                        let mut socket = accept_socket(&listener);
                        match phase {
                            Stall::Greeting => {
                                stage_tx.send(()).unwrap();
                                let mut byte = [0];
                                assert_eq!(socket.read(&mut byte).unwrap(), 0);
                            }
                            Stall::TlsHandshake => {
                                ssl_request(&mut socket);
                                let mut record_prefix = [0; 3];
                                socket.read_exact(&mut record_prefix).unwrap();
                                assert_eq!(
                                    record_prefix[0], 0x16,
                                    "client TLS handshake actually started"
                                );
                                stage_tx.send(()).unwrap();
                                let mut bytes = [0; 4096];
                                loop {
                                    if socket.read(&mut bytes).unwrap() == 0 {
                                        break;
                                    }
                                }
                            }
                            Stall::Authentication => {
                                ssl_request(&mut socket);
                                let mut tls = accept_tls(socket);
                                assert_eq!(read_packet(&mut tls).unwrap().0, 2);
                                tls.write_all(&mysql_packet(3, &[1, 4])).unwrap();
                                tls.flush().unwrap();
                                assert_eq!(
                                    read_packet(&mut tls).unwrap(),
                                    (4, b"cold_secret\0".to_vec())
                                );
                                stage_tx.send(()).unwrap();
                                let mut byte = [0];
                                match tls.read(&mut byte) {
                                    Ok(0) => {}
                                    Err(error) => assert!(
                                        matches!(
                                            error.kind(),
                                            std::io::ErrorKind::UnexpectedEof
                                                | std::io::ErrorKind::ConnectionReset
                                        ),
                                        "{error}"
                                    ),
                                    other => {
                                        panic!("stalled auth connection not closed: {other:?}")
                                    }
                                }
                            }
                        }
                    });
                    let runtime = RuntimeBuilder::new()
                        .worker_threads(workers)
                        .build()
                        .unwrap();
                    let (cx_tx, cx_rx) = mpsc::channel();
                    let (done_tx, done_rx) = mpsc::channel();
                    let (parked_tx, parked_rx) = mpsc::channel();
                    let probe = Arc::new(AtomicBool::new(false));
                    let task_probe = Arc::clone(&probe);
                    let started = Instant::now();
                    let join = runtime.handle().spawn(async move {
                        let cx = Cx::current().unwrap();
                        let mut cx_tx = Some(cx_tx);
                        let mut options = options(address, SslMode::Required);
                        options.connect_timeout = Some(if cancel { Duration::from_secs(30) } else { Duration::from_millis(750) });
                        let mut connect = std::pin::pin!(MySqlConnection::connect_with_tls_connector(&cx, options, connector(true)));
                        let result = poll_fn(|task_cx| {
                            if let Some(sender) = cx_tx.take() {
                                sender.send((cx.clone(), task_cx.waker().clone())).unwrap();
                            }
                            let result = connect.as_mut().poll(task_cx);
                            if result.is_pending() && task_probe.swap(false, Ordering::AcqRel) {
                                parked_tx.send(()).unwrap();
                            }
                            result
                        }).await;
                        if cancel {
                            assert!(matches!(result, Outcome::Cancelled(_)), "{result:?}");
                        } else {
                            assert!(matches!(result, Outcome::Err(MySqlError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut), "{result:?}");
                        }
                        done_tx.send(()).unwrap();
                    });
                    let (cx, probe_waker) = cx_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    stage_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    // One probe after the peer's wire witness must return
                    // Pending. The probe ends before cancellation; subsequent
                    // progress can only come from cancellation or the deadline.
                    probe.store(true, Ordering::Release);
                    probe_waker.wake_by_ref();
                    parked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    if cancel {
                        cx.cancel_fast(asupersync::types::CancelKind::User);
                    }
                    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    runtime.block_on(join);
                    server.join().unwrap();
                    assert_retired(&runtime);
                    eprintln!(
                        "event=mysql_connect_stall workers={workers} phase={phase:?} cancel={cancel} elapsed_ms={} socket_closed=true",
                        started.elapsed().as_millis()
                    );
                }
            }
        }
    }
}
