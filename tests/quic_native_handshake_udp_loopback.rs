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

use asupersync::cx::Cx;
use asupersync::net::quic_core::ConnectionId;
use asupersync::net::quic_native::handshake_driver::{
    ATP_QUIC_ALPN, QuicHandshakeDriver, client_config, client_handshake_over_udp, server_config,
    server_handshake_over_udp,
};
use asupersync::net::quic_native::{QuicUdpEndpoint, QuicUdpEndpointConfig};
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

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
