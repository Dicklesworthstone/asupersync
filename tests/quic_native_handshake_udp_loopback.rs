//! Real QUIC/TLS-1.3 handshake over real loopback UDP.
//!
//! This is the gate that the native QUIC handshake actually completes between two
//! endpoints that share only a UDP path (the cross-machine prerequisite). Unlike
//! the deterministic in-process `establish_loopback` substitute, this drives the
//! genuine `rustls::quic` handshake — ClientHello / ServerHello / Certificate /
//! CertVerify / Finished carried as CRYPTO frames inside protected long-header
//! Initial/Handshake packets — over two real `QuicUdpEndpoint` sockets on
//! 127.0.0.1, deriving 1-RTT keys from the wire transcript on both sides.

#![cfg(all(feature = "tls", feature = "test-internals"))]

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::net::atp::quic::{AtpPacketProtection, AtpPacketProtectionConfig};
use asupersync::net::quic_core::ConnectionId;
use asupersync::net::quic_native::handshake_driver::{
    ATP_QUIC_ALPN, QuicHandshakeDriver, client_config, client_handshake_over_udp, server_config,
    server_handshake_over_udp,
};
use asupersync::net::quic_native::{
    ConnectionRouter, NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
    QuicUdpEndpoint, QuicUdpEndpointConfig, RoutingResult, StreamId,
};
use asupersync::time::{timeout, wall_now};
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// Canonical CA + leaf chain (P-256), leaf has SAN DNS:localhost / IP:127.0.0.1 and
// the serverAuth EKU rustls-webpki requires; the client trusts the CA. Exercises
// the REAL WebPKI verifier path (no insecure skip-verify).
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
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .next()
        .expect("one cert")
        .expect("valid cert pem")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("read key pem")
        .expect("one key")
}

struct HandshakeDropProxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HandshakeDropProxy {
    fn spawn(server_addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind handshake drop proxy");
        socket
            .set_nonblocking(true)
            .expect("handshake proxy nonblocking");
        let addr = socket.local_addr().expect("handshake proxy addr");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            run_handshake_drop_proxy(socket, server_addr, thread_stop);
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for HandshakeDropProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.send_to(&[0], self.addr).map(|_| ()));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_handshake_drop_proxy(socket: UdpSocket, server_addr: SocketAddr, stop: Arc<AtomicBool>) {
    let mut client_addr = None;
    let mut dropped_client_initial = false;
    let mut dropped_server_flight = false;
    let started = Instant::now();
    let mut buf = vec![0u8; 65_535];

    while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(15) {
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let from_server = src == server_addr;
                    let target = if from_server {
                        let Some(client) = client_addr else {
                            continue;
                        };
                        client
                    } else {
                        client_addr = Some(src);
                        server_addr
                    };
                    if !from_server && !dropped_client_initial {
                        dropped_client_initial = true;
                        continue;
                    }
                    if from_server && !dropped_server_flight {
                        dropped_server_flight = true;
                        continue;
                    }
                    let _ = socket.send_to(&buf[..len], target);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn real_tls13_handshake_completes_over_real_loopback_udp() {
    block_on(async {
        let cx = Cx::for_testing();

        // Large datagrams so the server's full Handshake flight (cert chain) fits
        // in one loopback packet — no CRYPTO fragmentation needed for this gate.
        let udp_config = QuicUdpEndpointConfig {
            max_packet_size: 16384,
            ..QuicUdpEndpointConfig::default()
        };
        let mut client_ep =
            QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), udp_config.clone())
                .await
                .expect("bind client UDP");
        let mut server_ep = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), udp_config)
            .await
            .expect("bind server UDP");
        let client_addr = client_ep.local_addr();
        let server_addr = server_ep.local_addr();

        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg = server_config(
            vec![parse_one_cert(LEAF_CERT_PEM)],
            leaf_key(),
            alpn.clone(),
        )
        .expect("server config");
        let client_cfg =
            client_config(vec![parse_one_cert(CA_CERT_PEM)], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-transport-params".to_vec(),
        )
        .expect("client driver");
        let mut server =
            QuicHandshakeDriver::server(server_cfg, b"server-transport-params".to_vec())
                .expect("server driver");

        // Client's original Destination CID; both sides derive Initial keys from it.
        let dcid =
            ConnectionId::new(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        // Drive both sides concurrently (cooperatively) over the real sockets.
        let (client_result, server_result) = zip(
            client_handshake_over_udp(
                &cx,
                &mut client_ep,
                server_addr,
                &mut client,
                dcid,
                client_scid,
            ),
            server_handshake_over_udp(&cx, &mut server_ep, &mut server, dcid, server_scid),
        )
        .await;

        client_result.expect("client handshake completed");
        let learned_peer = server_result.expect("server handshake completed");
        assert_eq!(
            learned_peer, client_addr,
            "server learned the wrong client peer address"
        );

        assert!(client.is_complete(), "client not complete");
        assert!(server.is_complete(), "server not complete");
        assert!(
            client.one_rtt_keys_installed() && server.one_rtt_keys_installed(),
            "1-RTT keys not derived over the wire on both sides"
        );
        assert_eq!(
            client.peer_transport_parameters(),
            Some(b"server-transport-params".as_slice())
        );
        assert_eq!(
            server.peer_transport_parameters(),
            Some(b"client-transport-params".as_slice())
        );
    });
}

#[test]
fn real_tls13_handshake_survives_dropped_initial_flights() {
    block_on(async {
        let cx = Cx::for_testing();
        let udp_config = QuicUdpEndpointConfig {
            max_packet_size: 16384,
            ..QuicUdpEndpointConfig::default()
        };
        let mut client_ep =
            QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), udp_config.clone())
                .await
                .expect("bind client UDP");
        let mut server_ep = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), udp_config)
            .await
            .expect("bind server UDP");
        let server_addr = server_ep.local_addr();
        let proxy = HandshakeDropProxy::spawn(server_addr);

        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg = server_config(
            vec![parse_one_cert(LEAF_CERT_PEM)],
            leaf_key(),
            alpn.clone(),
        )
        .expect("server config");
        let client_cfg =
            client_config(vec![parse_one_cert(CA_CERT_PEM)], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-transport-params".to_vec(),
        )
        .expect("client driver");
        let mut server =
            QuicHandshakeDriver::server(server_cfg, b"server-transport-params".to_vec())
                .expect("server driver");

        let dcid =
            ConnectionId::new(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let (client_result, server_result) = zip(
            client_handshake_over_udp(
                &cx,
                &mut client_ep,
                proxy.addr,
                &mut client,
                dcid,
                client_scid,
            ),
            server_handshake_over_udp(&cx, &mut server_ep, &mut server, dcid, server_scid),
        )
        .await;

        client_result.expect("client handshake completed after PTO retransmit");
        let learned_peer = server_result.expect("server handshake completed after PTO retransmit");
        assert_eq!(
            learned_peer, proxy.addr,
            "server should learn the proxy as its UDP peer in this loss fixture"
        );
        assert!(
            client.is_complete(),
            "client not complete after lossy handshake"
        );
        assert!(
            server.is_complete(),
            "server not complete after lossy handshake"
        );
        assert!(client.one_rtt_keys_installed() && server.one_rtt_keys_installed());
    });
}

/// Advance a freshly-created connection's TLS level machine to the
/// application-data (Established) state. The actual AEAD keys live in the
/// installed `AtpPacketProtection`; this only moves the level/key-phase state.
fn establish_for_application_data(
    cx: &Cx,
    connection: &mut NativeQuicConnection,
) -> Result<(), NativeQuicConnectionError> {
    connection.begin_handshake(cx)?;
    connection.on_handshake_keys_available(cx)?;
    connection.on_1rtt_keys_available(cx)?;
    connection.record_verified_server_identity();
    connection.on_handshake_confirmed(cx)
}

/// End-to-end proof that application data flows over a connection whose 1-RTT
/// keys were agreed by a REAL handshake over real UDP: run the handshake, hand
/// the handshake-derived provider to the data plane via
/// `AtpPacketProtection::from_provider`, then cross a control stream + two
/// datagrams (the shapes ATP uses for its control protocol + RaptorQ symbols)
/// over the same real sockets.
#[test]
fn datagram_and_stream_cross_real_udp_after_real_handshake() {
    block_on(async {
        let cx = Cx::for_testing();
        let udp_config = QuicUdpEndpointConfig {
            max_packet_size: 16384,
            ..QuicUdpEndpointConfig::default()
        };
        let mut client_ep =
            QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), udp_config.clone())
                .await
                .expect("bind client UDP");
        let mut server_ep = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), udp_config)
            .await
            .expect("bind server UDP");
        let client_addr = client_ep.local_addr();
        let server_addr = server_ep.local_addr();

        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg = server_config(
            vec![parse_one_cert(LEAF_CERT_PEM)],
            leaf_key(),
            alpn.clone(),
        )
        .expect("server config");
        let client_cfg =
            client_config(vec![parse_one_cert(CA_CERT_PEM)], alpn).expect("client config");
        let mut client_driver = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-transport-params".to_vec(),
        )
        .expect("client driver");
        let mut server_driver =
            QuicHandshakeDriver::server(server_cfg, b"server-transport-params".to_vec())
                .expect("server driver");

        let dcid =
            ConnectionId::new(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        // 1. Real handshake over real UDP.
        let (client_result, server_result) = zip(
            client_handshake_over_udp(
                &cx,
                &mut client_ep,
                server_addr,
                &mut client_driver,
                dcid,
                client_scid,
            ),
            server_handshake_over_udp(&cx, &mut server_ep, &mut server_driver, dcid, server_scid),
        )
        .await;
        client_result.expect("client handshake");
        server_result.expect("server handshake");
        assert!(client_driver.one_rtt_keys_installed() && server_driver.one_rtt_keys_installed());

        // 2. Hand the handshake-derived 1-RTT keys to the existing data plane.
        let app_cid =
            ConnectionId::new(&[0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]).expect("app cid");
        let config = NativeQuicConnectionConfig::default();
        let mut client_router = ConnectionRouter::new(config);
        let mut server_router = ConnectionRouter::new(config);
        client_router
            .create_connection(&cx, app_cid, server_addr, false)
            .await
            .expect("create client connection");
        server_router
            .create_connection(&cx, app_cid, client_addr, true)
            .await
            .expect("create server connection");
        client_router
            .install_packet_protection(
                &cx,
                app_cid,
                AtpPacketProtection::from_provider(
                    Box::new(client_driver.into_provider()),
                    AtpPacketProtectionConfig::default(),
                ),
            )
            .expect("install client protection");
        server_router
            .install_packet_protection(
                &cx,
                app_cid,
                AtpPacketProtection::from_provider(
                    Box::new(server_driver.into_provider()),
                    AtpPacketProtectionConfig::default(),
                ),
            )
            .expect("install server protection");
        establish_for_application_data(
            &cx,
            client_router
                .connection_mut_for_testing(&cx, app_cid)
                .expect("client connection"),
        )
        .expect("client reaches app data");
        establish_for_application_data(
            &cx,
            server_router
                .connection_mut_for_testing(&cx, app_cid)
                .expect("server connection"),
        )
        .expect("server reaches app data");

        // 3. Enqueue an ATP-shaped control stream + two RaptorQ-shaped datagrams.
        let stream: StreamId;
        {
            let conn = client_router
                .connection_mut_for_testing(&cx, app_cid)
                .expect("client connection");
            stream = conn.open_local_bidi(&cx).expect("open control stream");
            conn.write_stream_bytes(
                &cx,
                stream,
                Bytes::from_static(b"ATP manifest over real QUIC"),
                true,
            )
            .expect("write control bytes");
            conn.send_datagram(&cx, Bytes::from_static(b"raptorq-symbol-0"))
                .expect("queue datagram 0");
            conn.send_datagram(&cx, Bytes::from_static(b"raptorq-symbol-1"))
                .expect("queue datagram 1");
        }

        let packets = client_router
            .drain_application_data_for_testing(&cx, app_cid, server_addr, Instant::now())
            .await
            .expect("drain app-data packets");
        assert!(!packets.is_empty(), "expected protected app-data packets");
        client_ep
            .send_batch(&cx, &packets)
            .await
            .expect("send app data over real UDP");

        // 4. Server receives, routes, then reads the stream + datagrams.
        let received = timeout(
            wall_now(),
            Duration::from_secs(10),
            server_ep.receive_batch(&cx, 16),
        )
        .await
        .expect("app-data recv timed out")
        .expect("receive app data over real UDP");
        assert!(!received.is_empty(), "expected app-data UDP batch");
        for packet in received {
            match server_router
                .route_packet(&cx, packet)
                .await
                .expect("route")
            {
                RoutingResult::Routed { .. } => {}
                other => panic!("expected routed app-data packet, got {other:?}"),
            }
        }

        let conn = server_router
            .connection_mut_for_testing(&cx, app_cid)
            .expect("server connection");
        let control = conn
            .read_stream_bytes(&cx, stream, 1024)
            .expect("read control bytes");
        assert_eq!(control.as_ref(), b"ATP manifest over real QUIC");
        assert!(conn.is_stream_read_eof(stream).expect("control eof"));
        assert_eq!(
            conn.recv_datagram().as_deref(),
            Some(&b"raptorq-symbol-0"[..])
        );
        assert_eq!(
            conn.recv_datagram().as_deref(),
            Some(&b"raptorq-symbol-1"[..])
        );
        assert!(conn.recv_datagram().is_none());
    });
}

// The original handshake tests above intentionally retain their existing
// transport models. This separate native journey measures the actual managed
// driver. No copied polling loop is an incumbent performance baseline.
#[cfg(target_os = "linux")]
mod managed_quiet {
    use super::*;
    use asupersync::net::quic_core::TransportParameters;
    use asupersync::net::quic_native::{
        ManagedEndpointConfig, ManagedEndpointError, ManagedQuicEndpoint, NativeQuicUdpConnection,
    };
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::future::Future;
    use std::io::{BufRead, Write};
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{Receiver, Sender};
    use std::task::{Context, Poll, Wake, Waker};

    const ALPN: &[u8] = b"asupersync-managed-quiet-v1";
    const RECORD_BYTES: usize = 520;
    const PREFIX: &str = "MANAGED_QUIC_QUIET_ROW ";
    const HELPER: &str = "managed_quiet::native_managed_quiet_process";
    const LIMIT: Duration = Duration::from_secs(120);
    const QUIET: Duration = Duration::from_millis(400);

    fn digest(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn executable_identity() -> Value {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let path = std::env::current_exe().unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let length = file.metadata().unwrap().len();
        assert!(
            length > 0 && length <= 512 * 1024 * 1024,
            "bounded actual executable"
        );
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 65536];
        let mut read = 0_u64;
        loop {
            let count = file.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            read += u64::try_from(count).unwrap();
            assert!(read <= length, "executable changed while hashing");
            hasher.update(&buffer[..count]);
        }
        assert_eq!(read, length);
        json!({"path":path.to_string_lossy(), "bytes":read, "sha256":hex::encode(hasher.finalize())})
    }

    fn source() -> Value {
        json!({
            "test": digest(include_bytes!("quic_native_handshake_udp_loopback.rs")),
            "manager": digest(include_bytes!("../src/net/quic_native/connection_manager.rs")),
            "managed": digest(include_bytes!("../src/net/quic_native/managed_endpoint.rs")),
            "owner": digest(include_bytes!("../src/net/quic_native/udp_connection.rs")),
            "endpoint": digest(include_bytes!("../src/net/quic_native/endpoint.rs")),
            "application": digest(include_bytes!("../src/net/quic_native/endpoint_api.rs")),
            "exports": digest(include_bytes!("../src/net/quic_native/mod.rs")),
            "handshake_driver": digest(include_bytes!("../src/net/quic_native/handshake_driver.rs")),
            "transport": digest(include_bytes!("../src/net/quic_native/transport.rs")),
            "connection": digest(include_bytes!("../src/net/quic_native/connection.rs")),
        })
    }

    fn emit(value: Value) {
        println!("{PREFIX}{value}");
        std::io::stdout().flush().unwrap();
    }

    fn record(sequence: u64) -> Vec<u8> {
        let mut data = sequence.to_be_bytes().to_vec();
        data.extend((0..512).map(|i| (sequence as u8).wrapping_add((i % 251) as u8)));
        data
    }

    #[derive(Default)]
    struct Counts {
        polls: AtomicU64,
        wakes: AtomicU64,
    }

    struct Relay {
        counts: Arc<Counts>,
        parent: Waker,
    }

    impl Wake for Relay {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.counts.wakes.fetch_add(1, Ordering::SeqCst);
            self.parent.wake_by_ref();
        }
    }

    #[derive(Default)]
    struct Shared {
        commands: Mutex<VecDeque<Value>>,
        application: Mutex<Option<Waker>>,
        relay: Mutex<Option<Waker>>,
        timer: Mutex<Option<asupersync::time::TimerDriverHandle>>,
        state: Mutex<Value>,
        counts: Arc<Counts>,
        paused: AtomicBool,
        parked: AtomicBool,
        last_pending: AtomicU64,
    }

    impl Shared {
        fn snapshot(&self, request: u64) -> Value {
            let timer = self
                .timer
                .lock()
                .unwrap()
                .clone()
                .expect("real runtime timer");
            json!({
                "event":"snapshot", "request":request, "pid":std::process::id(),
                "clock":"explicit_native_timer_driver_nanos", "now":timer.now().as_nanos(),
                "deadline":timer.next_deadline().map(|t|t.as_nanos()),
                "pending_timers":timer.pending_count(),
                "polls":self.counts.polls.load(Ordering::SeqCst),
                "wakes":self.counts.wakes.load(Ordering::SeqCst),
                "parked":self.parked.load(Ordering::SeqCst),
                "paused":self.paused.load(Ordering::SeqCst),
                "last_pending":self.last_pending.load(Ordering::SeqCst),
                "state":self.state.lock().unwrap().clone(),
            })
        }

        fn wake_application(&self) {
            let waker = self
                .application
                .lock()
                .unwrap()
                .clone()
                .expect("application registered");
            waker.wake();
        }
    }

    // A gate can withhold CLIENT polling without destroying its future or
    // connection. Server measurement never enables this gate. Relay counts
    // represent delivered inner polls and actual wake calls, not loop guesses.
    struct Measured<F> {
        future: Pin<Box<F>>,
        shared: Arc<Shared>,
    }

    impl<F: Future> Future for Measured<F> {
        type Output = F::Output;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            let relay = Waker::from(Arc::new(Relay {
                counts: Arc::clone(&this.shared.counts),
                parent: cx.waker().clone(),
            }));
            *this.shared.relay.lock().unwrap() = Some(relay.clone());
            this.shared.parked.store(false, Ordering::SeqCst);
            if this.shared.paused.load(Ordering::SeqCst) {
                this.shared.parked.store(true, Ordering::SeqCst);
                return Poll::Pending;
            }
            this.shared.counts.polls.fetch_add(1, Ordering::SeqCst);
            let result = this.future.as_mut().poll(&mut Context::from_waker(&relay));
            if result.is_pending() {
                let now = this.shared.timer.lock().unwrap().as_ref().unwrap().now();
                this.shared
                    .last_pending
                    .store(now.as_nanos(), Ordering::SeqCst);
                this.shared.parked.store(true, Ordering::SeqCst);
            }
            result
        }
    }

    fn commands(shared: Arc<Shared>, server: bool) -> JoinHandle<()> {
        thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let command: Value = serde_json::from_str(&line.unwrap()).unwrap();
                let name = command["command"].as_str().unwrap();
                match name {
                    // Snapshot neither calls a runtime callback nor wakes it.
                    "snapshot" => emit(shared.snapshot(command["request"].as_u64().unwrap())),
                    "wake" => shared.relay.lock().unwrap().clone().unwrap().wake(),
                    "pause" | "resume" => {
                        assert!(
                            !server,
                            "the measured server future must always stay enabled"
                        );
                        shared.paused.store(name == "pause", Ordering::SeqCst);
                        shared.relay.lock().unwrap().clone().unwrap().wake();
                    }
                    "send" | "fin" | "remove" | "stop" => {
                        let stop = name == "stop";
                        shared.commands.lock().unwrap().push_back(command);
                        shared.wake_application();
                        if stop {
                            break;
                        }
                    }
                    _ => panic!("unknown owned control command: {command}"),
                }
            }
        })
    }

    fn connection_config() -> NativeQuicConnectionConfig {
        NativeQuicConnectionConfig {
            max_local_bidi: 4,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 1 << 20,
            connection_recv_limit: 1 << 20,
            ..NativeQuicConnectionConfig::default()
        }
    }

    fn parameters(config: NativeQuicConnectionConfig) -> Vec<u8> {
        let parameters = TransportParameters {
            max_udp_payload_size: Some(1200),
            initial_max_data: Some(config.connection_recv_limit),
            initial_max_stream_data_bidi_local: Some(config.recv_window),
            initial_max_stream_data_bidi_remote: Some(config.recv_window),
            initial_max_streams_bidi: Some(config.max_local_bidi),
            disable_active_migration: true,
            ..TransportParameters::default()
        };
        let mut bytes = Vec::new();
        parameters.encode(&mut bytes).unwrap();
        bytes
    }

    async fn peer(
        cx: &Cx,
        shared: Arc<Shared>,
        server: bool,
        address: Option<SocketAddr>,
    ) -> Value {
        *shared.timer.lock().unwrap() = Some(cx.timer_driver().unwrap());
        let socket = QuicUdpEndpoint::bind(
            cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig {
                max_packet_size: 16384,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let local = socket.local_addr();
        let metrics = socket.metrics();
        emit(json!({"event":"bound", "pid":std::process::id(), "local":local.to_string()}));
        let config = connection_config();
        let initial = ConnectionId::new(b"quiet-initial").unwrap();
        let local_cid = ConnectionId::new(if server {
            b"quiet-server"
        } else {
            b"quiet-client"
        })
        .unwrap();
        let owner = if server {
            let tls = server_config(
                vec![parse_one_cert(LEAF_CERT_PEM)],
                leaf_key(),
                vec![ALPN.to_vec()],
            )
            .unwrap();
            NativeQuicUdpConnection::accept(
                cx,
                socket,
                QuicHandshakeDriver::server(tls, parameters(config)).unwrap(),
                initial,
                local_cid,
                config,
                ALPN,
            )
            .await
            .unwrap()
        } else {
            let tls =
                client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![ALPN.to_vec()]).unwrap();
            NativeQuicUdpConnection::connect(
                cx,
                socket,
                address.unwrap(),
                QuicHandshakeDriver::client(
                    tls,
                    ServerName::try_from("localhost").unwrap(),
                    parameters(config),
                )
                .unwrap(),
                initial,
                local_cid,
                config,
                ALPN,
            )
            .await
            .unwrap()
        };
        assert_eq!(owner.local_addr(), local);
        assert_eq!(owner.negotiated_alpn(), ALPN);
        assert!(owner.connection().can_send_app_data());
        assert_ne!(owner.local_connection_id(), owner.peer_connection_id());
        let authenticated = json!({"local":local.to_string(), "peer":owner.peer_addr().to_string(),
            "local_cid":format!("{:?}", owner.local_connection_id()), "peer_cid":format!("{:?}", owner.peer_connection_id()),
            "alpn":String::from_utf8(ALPN.to_vec()).unwrap(), "one_rtt":true,
            "verification":"real_rustls_CA_hostname_signature_server_auth"});
        let mut endpoint = owner
            .into_managed(
                cx,
                ManagedEndpointConfig {
                    is_server: server,
                    packet_batch_size: 2,
                    ..Default::default()
                },
            )
            .unwrap();
        if !server {
            assert_eq!(
                endpoint
                    .with_connection_mut(cx, local_cid, |c| c.open_bidi_stream(cx).unwrap())
                    .unwrap(),
                StreamId(0)
            );
        }
        let mut input = Vec::new();
        let mut received = Vec::new();
        let mut sent = Vec::new();
        let mut received_at = Vec::new();
        let mut received_hashes = Vec::new();
        let mut fin = false;
        let mut fin_sent = false;
        let mut removed = false;
        let mut announced = false;
        let driver = endpoint.run_event_loop_with_application(cx, |cx, endpoint, task_cx| {
            *shared.application.lock().unwrap() = Some(task_cx.waker().clone());
            if !removed {
                endpoint.with_connection_mut(cx, local_cid, |connection| {
                    for _ in 0..8 {
                        let ready = match connection.poll_next_readable_stream(cx, task_cx) {
                            Poll::Pending => break,
                            Poll::Ready(result) => result.unwrap(),
                        };
                        assert_eq!(ready.stream_id, StreamId(0));
                        input.extend_from_slice(&connection.read_stream(cx, StreamId(0), 8192).unwrap());
                        while input.len() >= RECORD_BYTES {
                            let bytes: Vec<_> = input.drain(..RECORD_BYTES).collect();
                            let sequence = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                            assert_eq!(bytes, record(sequence));
                            assert!(received.len() < 64 && !received.contains(&sequence), "bounded ordered stream, no duplicate delivery");
                            received.push(sequence);
                            received_at.push(cx.now().as_nanos());
                            received_hashes.push(digest(&bytes));
                            if server {
                                connection.write_stream(cx, StreamId(0), Bytes::from(bytes), false).unwrap();
                                sent.push(sequence);
                            }
                        }
                        if connection.is_stream_eof(StreamId(0)).unwrap() && !fin {
                            assert!(input.is_empty());
                            fin = true;
                            if server {
                                connection.write_stream(cx, StreamId(0), Bytes::new(), true).unwrap();
                                fin_sent = true;
                            }
                        }
                    }
                }).unwrap();
            }
            let pending: Vec<_> = shared.commands.lock().unwrap().drain(..).collect();
            let mut stop = false;
            for command in pending {
                match command["command"].as_str().unwrap() {
                    "send" => {
                        let sequence = command["sequence"].as_u64().unwrap();
                        assert!(!fin_sent && sent.len() < 64 && !sent.contains(&sequence));
                        endpoint.with_connection_mut(cx, local_cid, |connection| {
                            connection.write_stream(cx, StreamId(0), Bytes::from(record(sequence)), false).unwrap();
                        }).unwrap();
                        sent.push(sequence);
                    }
                    "fin" => {
                        assert!(!server && !fin_sent);
                        endpoint.with_connection_mut(cx, local_cid, |connection| {
                            connection.write_stream(cx, StreamId(0), Bytes::new(), true).unwrap();
                        }).unwrap();
                        fin_sent = true;
                    }
                    "remove" => {
                        assert!(fin && fin_sent && !removed);
                        endpoint.remove_connection(cx, local_cid).unwrap();
                        removed = true;
                    }
                    "stop" => { assert!(removed); stop = true; }
                    _ => unreachable!("owned command decoder"),
                }
            }
            let mut state = json!({"received":received, "received_at":received_at,
                "received_sha256":received_hashes, "sent":sent,
                "received_bytes":received.len()*RECORD_BYTES, "fin":fin, "fin_sent":fin_sent,
                "connections":endpoint.connection_stats().active_connections,
                "packets_sent":metrics.packets_sent.load(Ordering::SeqCst),
                "packets_received":metrics.packets_received.load(Ordering::SeqCst),
                "bytes_sent":metrics.bytes_sent.load(Ordering::SeqCst),
                "bytes_received":metrics.bytes_received.load(Ordering::SeqCst),
                "bytes_in_flight":0, "queued_stream_bytes":0, "pending_stream_frames":false});
            if !removed {
                endpoint.with_connection_mut(cx, local_cid, |connection| {
                    let stats = connection.path_stats();
                    state["bytes_in_flight"] = json!(stats.bytes_in_flight);
                    state["pto_count"] = json!(stats.pto_count);
                    state["packets_acked"] = json!(stats.packets_acked);
                    state["smoothed_rtt_micros"] = json!(stats.smoothed_rtt_micros);
                    state["rttvar_micros"] = json!(stats.rttvar_micros);
                    state["queued_stream_bytes"] = json!(connection.pending_stream_data_bytes(StreamId(0)));
                    state["pending_stream_frames"] = json!(connection.has_pending_stream_frames(StreamId(0)));
                }).unwrap();
            }
            *shared.state.lock().unwrap() = state;
            if !announced {
                announced = true;
                // The host may sample immediately after this message. Publish
                // a complete first snapshot before releasing that barrier.
                emit(json!({"event":"authenticated", "pid":std::process::id(), "identity":authenticated}));
            }
            if stop { Poll::Ready(Ok(())) } else { Poll::<Result<(), ManagedEndpointError>>::Pending }
        });
        Measured {
            future: Box::pin(driver),
            shared: Arc::clone(&shared),
        }
        .await
        .unwrap();
        endpoint.shutdown(cx).await.unwrap();
        assert_eq!(endpoint.connection_stats().active_connections, 0);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        shared.application.lock().unwrap().take();
        shared.relay.lock().unwrap().take();
        json!({"identity":authenticated, "state":shared.state.lock().unwrap().clone(),
            "driver_instances":1, "pending_timers_after_shutdown":0,
            "active_connections_after_shutdown":0})
    }

    #[test]
    #[ignore = "owned subprocess selected exactly by native_managed_quiet_burst_and_timer_recovery"]
    fn native_managed_quiet_process() {
        let role = std::env::var("ASUPERSYNC_QUIC_QUIET_ROLE").expect("owned parent role");
        assert!(role == "server" || role == "client");
        // libtest may leave its `test NAME ... ` prefix on this line. Keep
        // strict anchored JSON parsing by terminating that prefix first.
        println!(
            "\nMANAGED_QUIC_QUIET_PROCESS_START role={role} pid={}",
            std::process::id()
        );
        let executable = executable_identity();
        let server = role == "server";
        let address = std::env::var("ASUPERSYNC_QUIC_QUIET_ADDRESS")
            .ok()
            .map(|s| s.parse().unwrap());
        assert_eq!(address.is_none(), server);
        let shared = Arc::new(Shared::default());
        let reader = commands(Arc::clone(&shared), server);
        let runtime = asupersync::runtime::RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .with_sharded_state(true)
            .trace_storage_profile(
                asupersync::runtime::config::TraceStorageProfile::LargeMemory256G,
            )
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let owned = Arc::clone(&shared);
        let parent: Pin<
            Box<
                dyn Future<
                        Output = (
                            Value,
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
                    let future: Pin<Box<dyn Future<Output = Value> + Send>> =
                        Box::pin(async move { peer(&cx, owned, server, address).await });
                    future
                })
                .unwrap();
            let receipt = task.join(&cx).await.unwrap();
            // Before admission task_id() is only a provisional mailbox ID.
            let task_id = task.task_id();
            region.close().await.unwrap();
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
            (receipt, task_id, region_id)
        });
        let (mut receipt, task, region) = runtime.block_on(runtime.handle().spawn(parent));
        reader.join().unwrap();
        runtime.block_on(async {
            let started = Instant::now();
            while !runtime.is_quiescent() {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "actual task/obligation cleanup"
                );
                asupersync::runtime::yield_now().await;
            }
        });
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert_eq!(runtime.draining_region_count(), 0);
        assert!(
            runtime
                .diagnostics()
                .explain_region_open(region)
                .region_state
                .is_none()
        );
        let trace = runtime.trace_snapshot();
        let complete: Vec<_> = trace.iter().filter(|event| event.kind == asupersync::trace::TraceEventKind::Complete
            && matches!(event.data, asupersync::trace::TraceData::Task {task: actual, region: owner} if actual == task && owner == region)).collect();
        assert_eq!(
            complete.len(),
            1,
            "full admitted task identity terminates exactly once"
        );
        let close: Vec<_> = trace.iter().filter(|event| event.kind == asupersync::trace::TraceEventKind::RegionCloseComplete
            && matches!(event.data, asupersync::trace::TraceData::Region {region: actual, ..} if actual == region)).collect();
        assert_eq!(close.len(), 1);
        assert!(complete[0].seq < close[0].seq);
        receipt["event"] = json!("terminal");
        receipt["role"] = json!(role);
        receipt["pid"] = json!(std::process::id());
        receipt["source"] = source();
        receipt["executable"] = executable;
        receipt["task"] = json!(format!("{task:?}"));
        receipt["region"] = json!(format!("{region:?}"));
        receipt["complete_seq"] = json!(complete[0].seq);
        receipt["region_close_seq"] = json!(close[0].seq);
        receipt["tasks_after_cleanup"] = json!(0);
        receipt["leaked_obligations_after_cleanup"] = json!(0);
        receipt["draining_regions_after_cleanup"] = json!(0);
        shared.timer.lock().unwrap().take();
        drop(shared);
        assert!(
            runtime.shutdown_timeout(Duration::from_secs(5)),
            "actual runtime teardown"
        );
        receipt["runtime_shutdown"] = json!(true);
        emit(receipt);
    }

    // This guard exists immediately after spawn, including during pipe/log
    // reader construction. A later setup failure cannot orphan an accept task.
    struct OwnedChild(Child);

    impl OwnedChild {
        fn stop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    impl std::ops::Deref for OwnedChild {
        type Target = Child;
        fn deref(&self) -> &Child {
            &self.0
        }
    }

    impl std::ops::DerefMut for OwnedChild {
        fn deref_mut(&mut self) -> &mut Child {
            &mut self.0
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            self.stop();
        }
    }

    struct Process {
        child: OwnedChild,
        input: Option<ChildStdin>,
        messages: Receiver<Value>,
        reader: Option<JoinHandle<Option<Value>>>,
        started: Instant,
        request: u64,
    }

    impl Process {
        fn spawn(role: &str, address: Option<&str>, artifacts: &Path, started: Instant) -> Self {
            let mut log = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(artifacts.join(format!("{role}.stdout.log")))
                .unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", HELPER, "--ignored", "--nocapture"])
                .env("ASUPERSYNC_QUIC_QUIET_ROLE", role)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            if let Some(address) = address {
                command.env("ASUPERSYNC_QUIC_QUIET_ADDRESS", address);
            }
            let mut child = OwnedChild(command.spawn().expect("owned native QUIC helper"));
            let input = child.stdin.take().unwrap();
            let stdout = child.stdout.take().unwrap();
            let (sender, messages): (Sender<Value>, Receiver<Value>) = std::sync::mpsc::channel();
            let reader = thread::spawn(move || {
                let mut total = 0usize;
                let mut terminal = None;
                for line in std::io::BufReader::new(stdout).lines() {
                    let line = line.unwrap();
                    total += line.len();
                    assert!(
                        line.len() < 131072 && total < 16 * 1024 * 1024,
                        "bounded raw evidence"
                    );
                    writeln!(log, "{line}").unwrap();
                    log.flush().unwrap();
                    if let Some(row) = line.strip_prefix(PREFIX) {
                        let value = serde_json::from_str(row).expect("actual helper JSON");
                        if sender.send(value).is_err() {
                            break;
                        }
                    }
                    if line.starts_with("test result:") {
                        assert!(terminal.is_none(), "one selected libtest terminal");
                        let elapsed = line.strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in ")
                            .expect("exact helper selection must be 1/0/0/0/4");
                        let elapsed_seconds: f64 =
                            elapsed.strip_suffix('s').unwrap().parse().unwrap();
                        assert!(elapsed_seconds.is_finite() && elapsed_seconds >= 0.0);
                        terminal = Some(json!({"raw":line, "passed":1, "failed":0,
                            "ignored":0, "measured":0, "filtered":4, "elapsed_seconds":elapsed_seconds}));
                    }
                }
                terminal
            });
            Self {
                child,
                input: Some(input),
                messages,
                reader: Some(reader),
                started,
                request: 0,
            }
        }

        fn send(&mut self, value: Value) {
            assert!(
                self.started.elapsed() < LIMIT,
                "whole owned-process watchdog"
            );
            writeln!(self.input.as_mut().unwrap(), "{value}").unwrap();
            self.input.as_mut().unwrap().flush().unwrap();
        }

        fn event(&self, name: &str) -> Value {
            let left = LIMIT
                .checked_sub(self.started.elapsed())
                .expect("whole process watchdog expired");
            let row = self
                .messages
                .recv_timeout(left.min(Duration::from_secs(30)))
                .unwrap_or_else(|error| {
                    panic!(
                        "actual child {} waiting for {name}: {error}",
                        self.child.id()
                    )
                });
            assert_eq!(row["event"], name);
            assert_eq!(row["pid"].as_u64(), Some(u64::from(self.child.id())));
            row
        }

        fn sample(&mut self) -> Value {
            self.request += 1;
            self.send(json!({"command":"snapshot", "request":self.request}));
            let row = self.event("snapshot");
            assert_eq!(row["request"], self.request);
            row
        }

        fn until(&mut self, label: &str, mut predicate: impl FnMut(&Value) -> bool) -> Value {
            self.until_within(label, Duration::from_secs(25), &mut predicate)
        }

        fn until_within(
            &mut self,
            label: &str,
            limit: Duration,
            mut predicate: impl FnMut(&Value) -> bool,
        ) -> Value {
            let started = Instant::now();
            loop {
                let row = self.sample();
                if predicate(&row) {
                    return row;
                }
                assert!(started.elapsed() < limit, "{label} never attained: {row}");
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn finish(&mut self) -> Value {
            self.send(json!({"command":"stop"}));
            self.input.take();
            let mut receipt = self.event("terminal");
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "owned process failed: {status}");
                    break;
                }
                assert!(self.started.elapsed() < LIMIT, "owned process did not exit");
                thread::sleep(Duration::from_millis(10));
            }
            receipt["libtest"] = self
                .reader
                .take()
                .unwrap()
                .join()
                .unwrap()
                .expect("actual exact libtest selection and terminal");
            receipt
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            self.input.take();
            self.child.stop();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    fn number(value: &Value, key: &str) -> u64 {
        value[key].as_u64().unwrap()
    }

    fn cpu(pid: u32) -> Value {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let fields: Vec<_> = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        json!({"pid":pid, "user_ticks":fields[11].parse::<u64>().unwrap(),
            "system_ticks":fields[12].parse::<u64>().unwrap(), "start_ticks":fields[19].parse::<u64>().unwrap()})
    }

    fn settled(row: &Value) -> bool {
        row["parked"] == true
            && row["paused"] == false
            && row["pending_timers"] == 0
            && row["deadline"].is_null()
            && row["state"]["bytes_in_flight"] == 0
            && row["state"]["queued_stream_bytes"] == 0
            && row["state"]["pending_stream_frames"] == false
    }

    #[derive(Debug, PartialEq, Eq)]
    enum QuietRefusal {
        NotSettled,
        PeriodicWake,
        UnexplainedPoll,
        ProtocolTraffic,
    }

    fn quiet_oracle(before: &Value, after: &Value) -> Result<(), QuietRefusal> {
        if !settled(before) || !settled(after) {
            return Err(QuietRefusal::NotSettled);
        }
        if before["wakes"] != after["wakes"] {
            return Err(QuietRefusal::PeriodicWake);
        }
        if before["polls"] != after["polls"] {
            return Err(QuietRefusal::UnexplainedPoll);
        }
        if before["state"]["packets_sent"] != after["state"]["packets_sent"]
            || before["state"]["packets_received"] != after["state"]["packets_received"]
        {
            return Err(QuietRefusal::ProtocolTraffic);
        }
        Ok(())
    }

    fn stabilize(process: &mut Process) -> Value {
        let started = Instant::now();
        loop {
            let before = process.until("real ACK-settled Pending", settled);
            thread::sleep(Duration::from_millis(40));
            let after = process.sample();
            if quiet_oracle(&before, &after).is_ok() {
                return after;
            }
            assert!(
                started.elapsed() < Duration::from_secs(25),
                "no stable measurement boundary"
            );
        }
    }

    fn quiet(process: &mut Process, phase: &str, injected: bool) -> Value {
        let before = stabilize(process);
        let cpu_before = cpu(process.child.id());
        let started = Instant::now();
        if injected {
            // Actual calls to the same retained relay waker, not fabricated
            // counters or a replacement endpoint. No new runtime timer.
            for _ in 0..20 {
                process.send(json!({"command":"wake"}));
                thread::sleep(Duration::from_millis(20));
            }
        } else {
            thread::sleep(QUIET);
        }
        let elapsed = started.elapsed().as_nanos();
        let cpu_after = cpu(process.child.id());
        let after = process.sample();
        assert_eq!(cpu_before["start_ticks"], cpu_after["start_ticks"]);
        let verdict = quiet_oracle(&before, &after);
        if injected {
            assert_eq!(verdict, Err(QuietRefusal::PeriodicWake));
            assert!(
                number(&after, "polls") > number(&before, "polls"),
                "mutation actually delivered managed polls"
            );
        } else {
            assert_eq!(verdict, Ok(()), "quiet phase {phase}: {before} -> {after}");
        }
        json!({"phase":phase, "injected_periodic_wake":injected, "elapsed_nanos":elapsed,
            "before":before, "after":after, "cpu_before":cpu_before, "cpu_after":cpu_after,
            "oracle":if injected {"PeriodicWake"} else {"quiet"}})
    }

    fn contains_record(row: &Value, sequence: u64) -> bool {
        row["state"]["received"]
            .as_array()
            .unwrap()
            .contains(&json!(sequence))
    }

    fn burst(client: &mut Process, server: &mut Process, sequence: u64) -> Value {
        let started = Instant::now();
        client.send(json!({"command":"send", "sequence":sequence}));
        let server_received = server.until("protected server ingress", |row| {
            contains_record(row, sequence)
        });
        let client_received = client.until("protected ordered echo", |row| {
            contains_record(row, sequence)
        });
        stabilize(client);
        let server_settled = stabilize(server);
        json!({"sequence":sequence, "record_sha256":digest(&record(sequence)),
            "elapsed_nanos":started.elapsed().as_nanos(), "server_received":server_received,
            "client_received":client_received, "server_settled":server_settled})
    }

    fn pause(client: &mut Process) {
        let before = client.sample();
        client.send(json!({"command":"pause"}));
        client.until("retained client future gated", |row| {
            row["paused"] == true
                && row["parked"] == true
                && number(row, "wakes") > number(&before, "wakes")
        });
    }

    fn armed(row: &Value) -> bool {
        row["parked"] == true
            && row["pending_timers"] == 1
            && number(&row["state"], "bytes_in_flight") > 0
            && row["state"]["pending_stream_frames"] == false
            && row["deadline"]
                .as_u64()
                .is_some_and(|deadline| deadline > number(row, "now"))
    }

    #[test]
    fn native_managed_quiet_burst_and_timer_recovery() {
        let started = Instant::now();
        let executable = executable_identity();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::var_os("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let artifacts = base.join(format!(
            "asupersync-managed-quiet-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&artifacts).unwrap();
        println!("MANAGED_QUIC_QUIET_ARTIFACT_DIR {}", artifacts.display());
        let hz_output = Command::new("getconf").arg("CLK_TCK").output().unwrap();
        assert!(hz_output.status.success());
        let hz: u64 = std::str::from_utf8(&hz_output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(hz > 0);
        let mut server = Process::spawn("server", None, &artifacts, started);
        let bound = server.event("bound");
        let mut client = Process::spawn(
            "client",
            Some(bound["local"].as_str().unwrap()),
            &artifacts,
            started,
        );
        let client_bound = client.event("bound");
        let server_identity = server.event("authenticated");
        let client_identity = client.event("authenticated");
        assert_ne!(server.child.id(), client.child.id());
        assert_ne!(server.child.id(), std::process::id());
        assert_eq!(server_identity["identity"]["local"], bound["local"]);
        assert_eq!(client_identity["identity"]["local"], client_bound["local"]);
        assert_eq!(server_identity["identity"]["peer"], client_bound["local"]);
        assert_eq!(client_identity["identity"]["peer"], bound["local"]);
        assert_eq!(
            server_identity["identity"]["local_cid"],
            client_identity["identity"]["peer_cid"]
        );
        assert_eq!(
            client_identity["identity"]["local_cid"],
            server_identity["identity"]["peer_cid"]
        );
        assert_eq!(
            client_identity["identity"]["alpn"],
            String::from_utf8(ALPN.to_vec()).unwrap()
        );

        let mut bursts = Vec::new();
        let mut quiet_intervals = Vec::new();
        for sequence in 0..3 {
            bursts.push(burst(&mut client, &mut server, sequence));
            quiet_intervals.push(quiet(
                &mut server,
                &format!("after-burst-{sequence}"),
                false,
            ));
        }

        // A real protected write with withheld ACK processing arms recovery.
        // Later deadlines are produced by actual PTO handling, never by a test
        // registration or a public schedule_timer stand-in.
        pause(&mut client);
        server.send(json!({"command":"send", "sequence":9000}));
        let first = server.until("actual unacknowledged flight and timer", armed);
        let first_pto = number(&first["state"], "pto_count");
        let mut last_pto = first_pto;
        let mut rearms = vec![first.clone()];
        // Six expiries take nominally 63 initial PTO intervals before any
        // scheduling delay. The recovery fallback is 1.024s (64.512s total),
        // and genuine measured RTTs have no 25s upper bound. Preserve every
        // required event while bounding this setup inside the whole watchdog.
        let recovery_wait = LIMIT
            .saturating_sub(started.elapsed())
            .saturating_sub(Duration::from_secs(15))
            .min(Duration::from_secs(90));
        assert!(
            !recovery_wait.is_zero(),
            "no owned time remains for real PTO setup"
        );
        let later = server.until_within(
            "real backed-off deadline with packet-injection margin",
            recovery_wait,
            |row| {
                if !armed(row) {
                    return false;
                }
                let count = number(&row["state"], "pto_count");
                if count > last_pto {
                    rearms.push(row.clone());
                    last_pto = count;
                }
                count >= first_pto + 6
                    && number(row, "deadline") > number(&first, "deadline")
                    && number(row, "deadline") - number(row, "now") > 800_000_000
            },
        );
        assert!(rearms.len() >= 2);
        assert!(number(&later["state"], "packets_sent") > number(&first["state"], "packets_sent"));
        assert_eq!(
            later["state"]["packets_received"], first["state"]["packets_received"],
            "PTO progresses without new peer input"
        );
        assert_eq!(later["state"]["received"], json!([0, 1, 2]));
        let retained_deadline = number(&later, "deadline");

        // Application packet and ACK processing must win before the retained
        // future recovery deadline. All timestamps are the server's explicit
        // runtime clock, not cross-process Instant arithmetic.
        client.send(json!({"command":"send", "sequence":3}));
        client.send(json!({"command":"resume"}));
        let ingress = server.until("packet received before future deadline", |row| {
            contains_record(row, 3)
        });
        let received = ingress["state"]["received"].as_array().unwrap();
        let position = received.iter().position(|id| id == &json!(3)).unwrap();
        let received_at = ingress["state"]["received_at"][position].as_u64().unwrap();
        assert!(
            received_at < retained_deadline,
            "packet waited for timer: {ingress} / {later}"
        );
        client.until("withheld flight and echo delivered", |row| {
            contains_record(row, 9000) && contains_record(row, 3)
        });
        stabilize(&mut client);
        let removed_by_ack = stabilize(&mut server);
        assert_eq!(removed_by_ack["pending_timers"], 0);
        assert_eq!(removed_by_ack["state"]["pto_count"], 0);

        // This is an earlier *rearm after ACK*, and includes the observed
        // intervening timer removal. It does not claim an atomic active-handle
        // replacement. The actual strict inequality is required, not inferred
        // from configuration or a guessed initial RTT.
        pause(&mut client);
        server.send(json!({"command":"send", "sequence":9001}));
        let earlier = server.until("new real flight's earlier recovery deadline", armed);
        assert!(
            number(&earlier, "deadline") < retained_deadline,
            "setup failed to attain earlier recovery deadline: {earlier} / {later}"
        );
        client.send(json!({"command":"resume"}));
        client.until("second real server record delivered", |row| {
            contains_record(row, 9001)
        });
        stabilize(&mut client);
        quiet_intervals.push(quiet(&mut server, "after-real-timer-recovery", false));

        let mutation = quiet(&mut server, "injected-periodic-wake", true);
        quiet_intervals.push(quiet(&mut server, "after-periodic-wake-stopped", false));
        for sequence in 4..6 {
            bursts.push(burst(&mut client, &mut server, sequence));
            quiet_intervals.push(quiet(
                &mut server,
                &format!("recovered-burst-{sequence}"),
                false,
            ));
        }
        client.send(json!({"command":"fin"}));
        server.until("server consumed actual FIN", |row| {
            row["state"]["fin"] == true
        });
        client.until("client consumed actual echoed FIN", |row| {
            row["state"]["fin"] == true
        });
        stabilize(&mut client);
        stabilize(&mut server);
        for process in [&mut server, &mut client] {
            process.send(json!({"command":"remove"}));
            process.until("actual CID removal and no timer", |row| {
                row["state"]["connections"] == 0
                    && row["pending_timers"] == 0
                    && row["parked"] == true
            });
        }
        let server_terminal = server.finish();
        let client_terminal = client.finish();
        let sent = json!([0, 1, 2, 3, 4, 5]);
        let echoed = json!([0, 1, 2, 9000, 3, 9001, 4, 5]);
        assert_eq!(client_terminal["state"]["sent"], sent);
        assert_eq!(server_terminal["state"]["received"], sent);
        assert_eq!(server_terminal["state"]["sent"], echoed);
        assert_eq!(client_terminal["state"]["received"], echoed);
        assert_eq!(server_terminal["state"]["received_bytes"], 6 * RECORD_BYTES);
        assert_eq!(client_terminal["state"]["received_bytes"], 8 * RECORD_BYTES);
        for terminal in [&server_terminal, &client_terminal] {
            assert_eq!(terminal["source"], source());
            assert_eq!(terminal["executable"], executable);
            assert_eq!(terminal["driver_instances"], 1);
            assert_eq!(terminal["runtime_shutdown"], true);
            assert_eq!(terminal["state"]["fin"], true);
            assert_eq!(terminal["state"]["fin_sent"], true);
            assert_eq!(terminal["tasks_after_cleanup"], 0);
            assert_eq!(terminal["leaked_obligations_after_cleanup"], 0);
            assert_eq!(terminal["active_connections_after_shutdown"], 0);
            assert_eq!(terminal["pending_timers_after_shutdown"], 0);
            assert!(number(terminal, "complete_seq") < number(terminal, "region_close_seq"));
        }
        let summary = json!({"schema":"asupersync.managed_quic_quiet.v1", "source":source(), "executable":executable,
            "parent_pid":std::process::id(), "server_pid":server.child.id(), "client_pid":client.child.id(),
            "clock_ticks_per_second":hz, "quiet_intervals":quiet_intervals, "bursts":bursts,
            "recovery": {"setup_wait_limit_nanos":recovery_wait.as_nanos(),
                "initial":first, "rearms":rearms, "later":later,
                "packet_before_deadline":ingress, "packet_received_at":received_at,
                "retained_deadline":retained_deadline, "removed_by_ack":removed_by_ack,
                "earlier_rearm_after_ack":earlier},
            "periodic_wake_negative":mutation, "server":server_terminal, "client":client_terminal,
            "elapsed_nanos":started.elapsed().as_nanos(),
            "claim_boundary":"actual candidate measurements and planted wake control; no incumbent comparison",
            "remaining_acceptance":["identical-workload real incumbent distributions", "simultaneous packet/deadline readiness",
                "active earlier/later timer replacement", "relative-clock/receive-first/missing-wake mutations",
                "saturated cancellation and fresh endpoint recovery"]});
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(artifacts.join("summary.json"))
            .unwrap();
        writeln!(file, "{summary}").unwrap();
        println!("MANAGED_QUIC_QUIET_SUMMARY {summary}");
    }
}
