//! `NativeQuicUdpConnection::drive_io_once_or_wake`: the bounded receive wait
//! also ends when the caller's wake future completes, so an owner with new
//! data to send can queue it without waiting out its receive timeout. Packets
//! already readable are received first, and a wake that never completes
//! leaves the wait exactly as `drive_io_once` has it.
//!
//! Two loopback UDP endpoints joined by a real TLS 1.3 / QUIC handshake,
//! driven with `futures_lite::block_on` and an explicit capability context.

#![cfg(all(feature = "tls", feature = "quic", feature = "test-internals"))]
#![allow(missing_docs)]

use std::future::{pending, ready};
use std::io::BufReader;
use std::pin::pin;
use std::time::{Duration, Instant};

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::net::quic_core::{ConnectionId, TransportParameters};
use asupersync::net::quic_native::handshake_driver::{
    QuicHandshakeDriver, client_config, server_config,
};
use asupersync::net::quic_native::{
    NativeQuicConnectionConfig, NativeQuicUdpConnection, NativeQuicUdpIoProgress, QuicUdpEndpoint,
    QuicUdpEndpointConfig,
};
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};

const ALPN: &[u8] = b"hq-29";

// Canonical test CA + leaf chain shared with `tests/quic_h3_live_udp.rs` and
// `tests/quic_native_idle_cpu.rs`. The leaf has SAN DNS:localhost and the
// serverAuth EKU; the client trusts only this CA.
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
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes()))
        .next()
        .expect("one certificate")
        .expect("valid certificate PEM")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::pem_reader_iter(&mut BufReader::new(LEAF_KEY_PEM.as_bytes()))
        .next()
        .transpose()
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
        ..TransportParameters::default()
    };
    let mut encoded = Vec::new();
    parameters
        .encode(&mut encoded)
        .expect("encode RFC 9000 transport parameters");
    encoded
}

async fn live_pair(cx: &Cx) -> (NativeQuicUdpConnection, NativeQuicUdpConnection) {
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
    let protocols = vec![ALPN.to_vec()];
    let client_tls = client_config(vec![parse_one_cert(CA_CERT_PEM)], protocols.clone())
        .expect("client TLS config");
    let server_tls = server_config(vec![parse_one_cert(LEAF_CERT_PEM)], leaf_key(), protocols)
        .expect("server TLS config");
    let client_driver = QuicHandshakeDriver::client(
        client_tls,
        ServerName::try_from("localhost").expect("server name"),
        transport_parameters(connection_config()),
    )
    .expect("client handshake driver");
    let server_driver =
        QuicHandshakeDriver::server(server_tls, transport_parameters(connection_config()))
            .expect("server handshake driver");
    let initial_dcid = ConnectionId::new(b"wake-in1").expect("initial destination connection ID");
    let client_cid = ConnectionId::new(b"wake-cl1").expect("client source connection ID");
    let server_cid = ConnectionId::new(b"wake-sv1").expect("server source connection ID");
    let (client, server) = zip(
        NativeQuicUdpConnection::connect(
            cx,
            client_endpoint,
            server_addr,
            client_driver,
            initial_dcid,
            client_cid,
            connection_config(),
            ALPN,
        ),
        NativeQuicUdpConnection::accept(
            cx,
            server_endpoint,
            server_driver,
            initial_dcid,
            server_cid,
            connection_config(),
            ALPN,
        ),
    )
    .await;
    (
        client.expect("client connects"),
        server.expect("server accepts"),
    )
}

fn is_quiet(progress: NativeQuicUdpIoProgress) -> bool {
    progress.receive_timed_out
        && progress.packets_received == 0
        && progress.packets_sent == 0
        && progress.early_packets_replayed == 0
        && progress.handshake_flights_retransmitted == 0
}

/// Drive both sides with short windows until neither has anything left to
/// send or acknowledge.
async fn settle(
    cx: &Cx,
    client: &mut NativeQuicUdpConnection,
    server: &mut NativeQuicUdpConnection,
) {
    let mut quiet_rounds = 0;
    for round in 0..60 {
        let a = client
            .drive_io_once(cx, Duration::from_millis(25))
            .await
            .expect("client settle drive");
        let b = server
            .drive_io_once(cx, Duration::from_millis(25))
            .await
            .expect("server settle drive");
        quiet_rounds = if is_quiet(a) && is_quiet(b) {
            quiet_rounds + 1
        } else {
            0
        };
        if quiet_rounds >= 2 {
            return;
        }
        assert!(round < 59, "never went quiet: client={a:?} server={b:?}");
    }
}

/// The server sends one stream record; the caller decides when the client
/// receives it.
async fn server_sends(cx: &Cx, server: &mut NativeQuicUdpConnection) {
    let connection = server.connection_mut();
    let stream = connection.open_bidi_stream(cx).expect("open stream");
    connection
        .write_stream(cx, stream, Bytes::from_static(b"picture"), false)
        .expect("queue record");
    assert!(server.flush(cx).await.expect("server flush") > 0);
}

#[test]
fn a_completed_wake_ends_a_long_receive_wait_as_a_quiet_timeout() {
    block_on(async {
        let cx = Cx::for_testing();
        let (mut client, mut server) = live_pair(&cx).await;
        settle(&cx, &mut client, &mut server).await;
        let started = Instant::now();
        let progress = client
            .drive_io_once_or_wake(&cx, Duration::from_secs(5), pin!(ready(())))
            .await
            .expect("woken drive");
        assert!(is_quiet(progress), "{progress:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the wait ran {:?}",
            started.elapsed()
        );
    });
}

#[test]
fn a_wake_that_never_completes_leaves_packets_and_the_timeout_in_charge() {
    block_on(async {
        let cx = Cx::for_testing();
        let (mut client, mut server) = live_pair(&cx).await;
        settle(&cx, &mut client, &mut server).await;
        server_sends(&cx, &mut server).await;
        let progress = client
            .drive_io_once_or_wake(&cx, Duration::from_secs(5), pin!(pending::<()>()))
            .await
            .expect("drive with a silent wake");
        assert!(progress.packets_received > 0, "{progress:?}");
        assert!(!progress.receive_timed_out);
        settle(&cx, &mut client, &mut server).await;
        let started = Instant::now();
        let progress = client
            .drive_io_once_or_wake(&cx, Duration::from_millis(40), pin!(pending::<()>()))
            .await
            .expect("drive to the timeout");
        assert!(is_quiet(progress), "{progress:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(30),
            "ended after {:?}",
            started.elapsed()
        );
    });
}

#[test]
fn a_readable_packet_is_received_before_a_completed_wake_ends_the_wait() {
    block_on(async {
        let cx = Cx::for_testing();
        let (mut client, mut server) = live_pair(&cx).await;
        settle(&cx, &mut client, &mut server).await;
        server_sends(&cx, &mut server).await;
        // Loopback delivery is immediate in practice; leave it time anyway.
        std::thread::sleep(Duration::from_millis(50));
        let progress = client
            .drive_io_once_or_wake(&cx, Duration::from_secs(5), pin!(ready(())))
            .await
            .expect("drive with a packet waiting");
        assert!(progress.packets_received > 0, "{progress:?}");
        assert!(!progress.receive_timed_out);
    });
}

/// The wake adds a pointer and the race's state to the drive future; both
/// forms stay within the bound the refusal path set for `drive_io_once`.
#[test]
fn both_drive_futures_stay_small() {
    block_on(async {
        let cx = Cx::for_testing();
        let (mut client, _server) = live_pair(&cx).await;
        let size = std::mem::size_of_val(&client.drive_io_once(&cx, Duration::from_millis(1)));
        eprintln!("drive_io_once future: {size} bytes");
        assert!(size <= 1536, "drive_io_once future is {size} bytes");
        let mut wake = pin!(pending::<()>());
        let size = std::mem::size_of_val(&client.drive_io_once_or_wake(
            &cx,
            Duration::from_millis(1),
            wake.as_mut(),
        ));
        eprintln!("drive_io_once_or_wake future: {size} bytes");
        assert!(size <= 1536, "drive_io_once_or_wake future is {size} bytes");
    });
}
