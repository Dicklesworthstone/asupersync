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
