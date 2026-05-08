#![allow(missing_docs)]
#![allow(clippy::all)]

//! br-asupersync-47reux — TLS+ALPN-h2 → h2 connection preface composition.
//!
//! `tests/conformance/tls_alpn.rs` (currently bit-rotted out of
//! `tests/conformance/mod.rs`) verifies ALPN selection in isolation.
//! `tests/grpc_http2_e2e.rs` runs gRPC over plain TCP. Nothing asserts
//! the COMPOSITION: after TLS+ALPN selects `h2`, the resulting
//! `TlsStream` carries the 24-byte HTTP/2 CLIENT_PREFACE
//! (RFC 9113 §3.4) and a SETTINGS frame intact, byte-for-byte.
//!
//! This is the minimal stack-readiness check for any gRPC-over-TLS
//! deployment: if it fails, no gRPC unary call can ever start. It runs
//! both sides over a `VirtualTcpStream::pair` so the test is
//! deterministic and CI-stable; the real-TCP follow-on is captured in
//! the bead's "follow-on" note.

#[cfg(feature = "tls")]
mod tls_h2_preface {
    use asupersync::bytes::BytesMut;
    use asupersync::http::h2::connection::CLIENT_PREFACE;
    use asupersync::http::h2::frame::SettingsFrame;
    use asupersync::http::h2::{Frame, FrameHeader};
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};
    use asupersync::lab::{config::LabConfig, runtime::LabRuntime};
    use asupersync::net::tcp::VirtualTcpStream;
    use asupersync::test_utils::run_test_with_cx;
    use asupersync::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    use futures_lite::future::zip;

    // Self-signed test materials (same as tests/conformance/tls_alpn.rs).
    const TEST_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUEOa/xZnL2Xclme2QSueCrHSMLnEwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIyNjIyMjk1MloXDTM2MDIy
NDIyMjk1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAx1JqCHpDIHPR4H1LDrb3gHVCzoKujANyHdOKw7CTLKdz
JbDybwJYqZ8vZpq0xwhYKpHdGO4yv7yLT7a2kThq3MrxohfXp9tv1Dop7siTQiWT
7uGYJzh1bOhw7ElLJc8bW/mBf7ksMyqkX8/8mRXRWqqDv3dKe5CrSt2Pqti9tYH0
DcT2fftUGT14VvL/Fq1kWPM16ebTRCFp/4ki/Th7SzFvTN99L45MAilHZFefRSzc
9xN1qQZNm7lT6oo0zD3wmOy70iiasqpLrmG51TRdbnBnGH6CIHvUIl3rCDteUuj1
pB9lh67qt5kipCn4+8zceXmUaO/nmRawC7Vz+6AsTwIDAQABo2QwYjALBgNVHQ8E
BAMCBLAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9jYWxob3N0
MAkGA1UdEwQCMAAwHQYDVR0OBBYEFEGZkeJqxBWpc24NHkE8k5PM8gTyMA0GCSqG
SIb3DQEBCwUAA4IBAQAzfQ4na2v1VhK/dyhC89rMHPN/8OX7CGWwrpWlEOYtpMds
OyQKTZjdz8aFSFl9rvnyGRHrdo4J1RoMGNR5wt1XQ7+k3l/iEWRlSRw+JU6+jqsx
xfjik55Dji36pN7ARGW4ADBpc3yTOHFhaH41GpSZ6s/2KdGG2gifo7UGNdkdgL60
nxRt1tfapaNtzpi90TfDx2w6MQmkNMKVOowbYX/zUY7kklJLP8KWTwXO7eovtIpr
FPAy+SbPl3+sqPbes5IqAQO9jhjb0w0/5RlSTPtiKetb6gAA7Yqw+yZWkBN0WDye
Lru15URJw9pE1Uae8IuzyzHiF1fnn45swnvW3Szb
-----END CERTIFICATE-----";

    const TEST_KEY_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHUmoIekMgc9Hg
fUsOtveAdULOgq6MA3Id04rDsJMsp3MlsPJvAlipny9mmrTHCFgqkd0Y7jK/vItP
traROGrcyvGiF9en22/UOinuyJNCJZPu4ZgnOHVs6HDsSUslzxtb+YF/uSwzKqRf
z/yZFdFaqoO/d0p7kKtK3Y+q2L21gfQNxPZ9+1QZPXhW8v8WrWRY8zXp5tNEIWn/
iSL9OHtLMW9M330vjkwCKUdkV59FLNz3E3WpBk2buVPqijTMPfCY7LvSKJqyqkuu
YbnVNF1ucGcYfoIge9QiXesIO15S6PWkH2WHruq3mSKkKfj7zNx5eZRo7+eZFrAL
tXP7oCxPAgMBAAECggEAOwgH+jnHfql+m4dP/uwmUgeogQPIERSGLBo2Ky208NEo
8507t6/QtW+9OJyR9K5eekEX46XMJuf+tF2PJWQ5lemO9awtBPwi2w5c0+jYYAtE
DEgI6Xi5okcXBovQc0KqvisfdMXRNtgmtW+iRm5lQf5lJYP9baoTaQlEXttxF/t+
g7RLjaPaJNvE/Yq+4FJUuL1fWSTXfH99If6rR8Zy+FXtFRpCVbNdpruUaOmIgjuT
TlRaXf/VfnIocRNVsEWTlfCJq8Ra4qLAFM4KYuEBoPaRxpOH9of4nZftzOHwiJ0m
8+GwXqNhySVKO3SPw194LCVSoje1+PEaA/tPlE1RZQKBgQDoJpCQ0SmKOCG/c0lD
QebhqSruFoqQqeEV6poZCO+HZMvszhIiUkvk3/uoZnFQmb3w4YwbRH05YQd6iXFk
048lbqPzfGQGepMpLAY9DWhnbDy+mbuOZp+04gZ/QUen+qKBOc3mNUGhCZNyAUl3
YXeGgPNtknRQ6ebNgO1PFLaoewKBgQDbzHjknGMAFcZXr4/MPOc03I8mQiLECfxa
5PJYhjq85ygCMePiH08xJC4RT6ld3EC4GxliPFubzLMXJhqGBgboSzXGcDZbAOdw
YqleUF/jBChl2oyawzf280FepJqFG6d5qFwISi4hnCZKC7PdIbaKjjRGU7flDBej
AfGjIuzlPQKBgETAjxXkbAn8P7pkWTErBkaUhBtI37aiKQAFn6eEZvPRHTe/e81g
VAuvbedcl3iIX6FEGutEaFWi78URiVyT7xPl5XZJw5HLoWOTHzHbk6z1eDP2cX5l
1CyMt+HeImuUJaZhySHBafNYU6tyyCAr5GsYK3+q3PnNm8YGxcEi4EmbAoGAYbvA
wb58Euybvh+1bBZkpE+yY0ujE9Jw4KXO0OgWtCqA0sEGWGSdnPc+eLoYUEEAkhyS
o+i8v0E9HPz3bEK/zYirx6nbsYlsX7+vGd3ZVSNjJy8PuD035Fnz5jaA8tECHglr
qs/5RT6ek+wyNRCpj2B+BAtzyKgg1n2lyWldNu0CgYEA4Ux9QV5s99W39vJlzGHD
ilKqHWetmrehbe0nIeCe2bJWqb08oSrQD8Q7om/MGAKjhFqNyYqqoJXcmbAvLygu
kMtbiQcfyyxjefyCA0OvdWEXrvnRZYNEBosyX/ko7Bl2IRBFP6ahQhj7jHqm2+/J
SrXuVI5uunTgPWuOtJOP+KM=
-----END PRIVATE KEY-----";

    fn create_tls_materials() -> (CertificateChain, PrivateKey, Vec<Certificate>) {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).expect("server cert chain");
        let key = PrivateKey::from_pem(TEST_KEY_PEM).expect("server private key");
        let trust = Certificate::from_pem(TEST_CERT_PEM).expect("client trust roots");
        (chain, key, trust)
    }

    /// br-asupersync-47reux: after TLS+ALPN selects `h2`, the resulting
    /// stream MUST carry the 24-byte HTTP/2 CLIENT_PREFACE byte-for-byte
    /// (RFC 9113 §3.4) and a SETTINGS frame parsable per RFC 9113 §6.5.
    /// If this composition is broken, no gRPC unary call can ever begin.
    #[test]
    fn alpn_h2_carries_client_preface_and_settings_frame() {
        let _lab = LabRuntime::new(LabConfig::default());

        run_test_with_cx(|_cx| async move {
            let (chain, key, trust) = create_tls_materials();

            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"h2".to_vec()])
                .build()
                .expect("acceptor build");
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(trust)
                .alpn_protocols(vec![b"h2".to_vec()])
                .build()
                .expect("connector build");

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5200".parse().unwrap(),
                "127.0.0.1:5201".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let mut client = client_res.expect("client TLS handshake");
            let mut server = server_res.expect("server TLS handshake");

            // RFC 7301: both peers MUST agree on the negotiated protocol,
            // and it MUST be the only one we offered.
            assert_eq!(
                client.alpn_protocol(),
                Some(b"h2".as_ref()),
                "client ALPN must be h2"
            );
            assert_eq!(
                server.alpn_protocol(),
                Some(b"h2".as_ref()),
                "server ALPN must be h2"
            );

            // RFC 9113 §3.4: the connection preface "is a sequence of 24 octets,
            // which in hex notation is 0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a".
            assert_eq!(CLIENT_PREFACE.len(), 24);
            client
                .write_all(CLIENT_PREFACE)
                .await
                .expect("write client preface");

            // Then a minimal client SETTINGS frame so the server has a real
            // h2 frame to parse over the TlsStream (RFC 9113 §6.5).
            let settings = SettingsFrame::new(Vec::new());
            let mut frame_buf = BytesMut::new();
            Frame::Settings(settings)
                .encode(&mut frame_buf)
                .expect("encode SETTINGS frame");
            client
                .write_all(&frame_buf)
                .await
                .expect("write SETTINGS frame");
            client.flush().await.expect("flush client side");

            // Server reads the preface, byte-for-byte.
            let mut preface_buf = vec![0u8; CLIENT_PREFACE.len()];
            server
                .read_exact(&mut preface_buf)
                .await
                .expect("server reads preface");
            assert_eq!(
                preface_buf, CLIENT_PREFACE,
                "TLS layer corrupted the h2 client preface"
            );

            // Server parses the SETTINGS frame header from the bytes that
            // followed the preface.
            let mut header_bytes = vec![0u8; 9];
            server
                .read_exact(&mut header_bytes)
                .await
                .expect("server reads frame header");
            let mut header_buf = BytesMut::from(&header_bytes[..]);
            let header = FrameHeader::parse(&mut header_buf)
                .expect("server parses frame header from TLS payload");
            assert_eq!(header.frame_type, 0x4, "first frame must be SETTINGS (0x4)");
            assert_eq!(
                header.stream_id, 0,
                "RFC 9113 §6.5: SETTINGS frame stream_id MUST be 0"
            );
            assert_eq!(
                header.length, 0,
                "empty SETTINGS frame must have payload length 0"
            );
            assert_eq!(
                header.flags & 0x1,
                0,
                "non-ACK SETTINGS must NOT have ACK flag set"
            );
        });
    }
}
