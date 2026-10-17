    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    // `Certificate` and the PEM fixtures below are only consumed by the
    // rustls-backed, `#[cfg(feature = "tls")]`-gated tests; gate the import
    // and constants the same way so the non-`tls` build has no unused items.
    #[cfg(feature = "tls")]
    use crate::tls::Certificate;

    // Self-signed test certificate and key (for testing only)
    // Generated with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
    #[cfg(feature = "tls")]
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

    #[cfg(feature = "tls")]
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

    // These builder/PEM-parsing tests exercise the rustls-backed
    // `from_pem` constructors, which only parse real certificates when the
    // `tls` feature is enabled (otherwise the disabled-mode stubs return an
    // error and `.unwrap()` panics). Gate them on `tls` to match the sibling
    // `test_build_acceptor` below, so the default/test-internals build that
    // omits `tls` does not run cert-parsing tests against the stub.
    #[cfg(feature = "tls")]
    #[test]
    fn test_builder_new() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key);
        assert!(builder.alpn_protocols.is_empty());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_builder_alpn_http() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key).alpn_http();
        assert_eq!(
            builder.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_builder_alpn_h2() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key).alpn_h2();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_builder_alpn_grpc() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key).alpn_grpc();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_client_auth_default() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key);
        assert!(matches!(builder.client_auth, ClientAuth::None));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_from_pem() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_private_key_from_pem() {
        let _key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_acceptor() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_http()
            .build()
            .unwrap();

        assert_eq!(
            acceptor.config().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[cfg(feature = "tls")]
    struct ClientHelloLayout {
        cipher_suites_len_pos: usize,
        extensions_len_pos: usize,
        sni_ext_len_pos: usize,
        sni_list_len_pos: usize,
        first_sni_entry_start: usize,
        first_sni_entry_end: usize,
    }

    #[cfg(feature = "tls")]
    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    #[cfg(feature = "tls")]
    fn set_u24(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset] = ((value >> 16) & 0xff) as u8;
        bytes[offset + 1] = ((value >> 8) & 0xff) as u8;
        bytes[offset + 2] = (value & 0xff) as u8;
    }

    #[cfg(feature = "tls")]
    fn adjust_u16(bytes: &mut [u8], offset: usize, delta: usize) {
        let value = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let adjusted = value
            .checked_add(u16::try_from(delta).expect("delta fits in u16"))
            .expect("length remains within u16");
        set_u16(bytes, offset, adjusted);
    }

    #[cfg(feature = "tls")]
    fn parse_client_hello_layout(bytes: &[u8]) -> ClientHelloLayout {
        assert!(bytes.len() >= 5, "TLS record header must be present");
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert!(
            bytes.len() >= 5 + record_len,
            "record payload must be complete"
        );

        let mut pos = 5;
        assert_eq!(bytes[pos], 0x01, "expected ClientHello handshake");
        pos += 4;
        pos += 2; // legacy_version
        pos += 32; // random

        let session_id_len = bytes[pos] as usize;
        pos += 1 + session_id_len;

        let cipher_suites_len_pos = pos;
        let cipher_suites_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        let compression_methods_len = bytes[pos] as usize;
        pos += 1 + compression_methods_len;

        let extensions_len_pos = pos;
        let extensions_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        let mut sni_ext_len_pos = None;
        let mut sni_list_len_pos = None;
        let mut first_sni_entry_start = None;
        let mut first_sni_entry_end = None;

        while pos + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let ext_len_pos = pos + 2;
            let ext_len = u16::from_be_bytes([bytes[ext_len_pos], bytes[ext_len_pos + 1]]) as usize;
            pos += 4;
            let ext_data_start = pos;
            let ext_data_end = pos + ext_len;
            assert!(ext_data_end <= extensions_end, "extension must fit");

            if ext_type == 0x0000 {
                sni_ext_len_pos = Some(ext_len_pos);
                sni_list_len_pos = Some(ext_data_start);
                let list_len =
                    u16::from_be_bytes([bytes[ext_data_start], bytes[ext_data_start + 1]]) as usize;
                let first_entry_start = ext_data_start + 2;
                let name_len_pos = first_entry_start + 1;
                let name_len =
                    u16::from_be_bytes([bytes[name_len_pos], bytes[name_len_pos + 1]]) as usize;
                let first_entry_end = first_entry_start + 3 + name_len;
                assert!(
                    first_entry_end <= ext_data_start + 2 + list_len,
                    "SNI entry must fit the advertised list"
                );
                first_sni_entry_start = Some(first_entry_start);
                first_sni_entry_end = Some(first_entry_end);
                break;
            }

            pos = ext_data_end;
        }

        ClientHelloLayout {
            cipher_suites_len_pos,
            extensions_len_pos,
            sni_ext_len_pos: sni_ext_len_pos.expect("ClientHello should include SNI"),
            sni_list_len_pos: sni_list_len_pos.expect("ClientHello should include SNI list"),
            first_sni_entry_start: first_sni_entry_start
                .expect("ClientHello should include an SNI entry"),
            first_sni_entry_end: first_sni_entry_end
                .expect("ClientHello should include an SNI entry"),
        }
    }

    #[cfg(feature = "tls")]
    fn make_client_hello(alpn_protocols: &[&[u8]]) -> Vec<u8> {
        use rustls::ClientConfig;
        use rustls::crypto::ring::default_provider;
        use rustls::pki_types::ServerName;

        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default client protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();

        let server_name = ServerName::try_from("localhost".to_string()).expect("server name");
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), server_name).expect("client config");
        let mut out = Vec::new();
        client.write_tls(&mut out).expect("client hello bytes");
        out
    }

    #[cfg(feature = "tls")]
    fn drive_server_parse(acceptor: &TlsAcceptor, bytes: &[u8]) -> Result<(), TlsError> {
        use std::io::Cursor;

        let mut server = rustls::ServerConnection::new(Arc::clone(acceptor.config()))
            .map_err(|err| TlsError::Configuration(err.to_string()))?;
        let mut cursor = Cursor::new(bytes);

        while (cursor.position() as usize) < bytes.len() {
            let read = server.read_tls(&mut cursor).map_err(TlsError::Io)?;
            if read == 0 {
                break;
            }
            server
                .process_new_packets()
                .map_err(|err| TlsError::Handshake(err.to_string()))?;
        }

        Ok(())
    }

    #[cfg(feature = "tls")]
    fn duplicate_first_sni_entry(bytes: &mut Vec<u8>) {
        let layout = parse_client_hello_layout(bytes);
        let duplicate = bytes[layout.first_sni_entry_start..layout.first_sni_entry_end].to_vec();
        bytes.splice(
            layout.first_sni_entry_end..layout.first_sni_entry_end,
            duplicate.iter().copied(),
        );

        let delta = duplicate.len();
        adjust_u16(bytes, layout.sni_list_len_pos, delta);
        adjust_u16(bytes, layout.sni_ext_len_pos, delta);
        adjust_u16(bytes, layout.extensions_len_pos, delta);

        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize + delta;
        set_u16(
            bytes,
            3,
            u16::try_from(record_len).expect("record length fits u16"),
        );

        let handshake_len =
            ((bytes[6] as usize) << 16) | ((bytes[7] as usize) << 8) | bytes[8] as usize;
        set_u24(bytes, 6, handshake_len + delta);
    }

    #[cfg(feature = "tls")]
    fn zero_cipher_suites(bytes: &mut [u8]) {
        let layout = parse_client_hello_layout(bytes);
        set_u16(bytes, layout.cipher_suites_len_pos, 0);
    }

    #[cfg(feature = "tls")]
    fn fragment_first_tls_record(bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() >= 6, "need a full record to fragment");
        let payload_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let payload = &bytes[5..5 + payload_len];
        let split_at = payload.len() / 2;
        assert!(
            split_at > 0 && split_at < payload.len(),
            "payload must split into two records"
        );

        let mut fragmented = Vec::with_capacity(bytes.len() + 5);
        fragmented.extend_from_slice(&[bytes[0], bytes[1], bytes[2]]);
        fragmented.extend_from_slice(&(split_at as u16).to_be_bytes());
        fragmented.extend_from_slice(&payload[..split_at]);
        fragmented.extend_from_slice(&[bytes[0], bytes[1], bytes[2]]);
        fragmented.extend_from_slice(&((payload.len() - split_at) as u16).to_be_bytes());
        fragmented.extend_from_slice(&payload[split_at..]);
        fragmented
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_acceptor_clone_is_cheap() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _clone = acceptor.clone();
        }
        let elapsed = start.elapsed();

        // Should be very fast (Arc clone)
        assert!(elapsed.as_millis() < 100);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_duplicate_sni_client_hello_is_rejected_cleanly() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let mut client_hello = make_client_hello(&[b"h2"]);
        duplicate_first_sni_entry(&mut client_hello);

        let err = drive_server_parse(&acceptor, &client_hello).unwrap_err();
        assert!(matches!(err, TlsError::Handshake(_)));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_zero_cipher_suite_list_is_rejected_cleanly() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let mut client_hello = make_client_hello(&[b"h2"]);
        zero_cipher_suites(&mut client_hello);

        let err = drive_server_parse(&acceptor, &client_hello).unwrap_err();
        assert!(matches!(err, TlsError::Handshake(_)));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_fragmented_client_hello_record_is_processed() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_h2()
            .build()
            .unwrap();

        let client_hello = make_client_hello(&[b"h2"]);
        let fragmented = fragment_first_tls_record(&client_hello);

        drive_server_parse(&acceptor, &fragmented).expect("fragmented client hello should parse");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_accept_handshake() {
        use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
        use crate::cx::Cx;
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::init_test_logging;
        use futures_lite::future::zip;

        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x715A_CCE7)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (
            client_ready,
            server_ready,
            client_protocol,
            server_protocol,
            client_alpn,
            server_alpn,
            checkpoints,
        ) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let _cx = Cx::current().expect("lab runtime should install a current Cx");

            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_http()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5000".parse().unwrap(),
                "127.0.0.1:5001".parse().unwrap(),
            );

            let checkpoints = vec![serde_json::json!({
                "phase": "virtual_stream_pair_created",
                "client_addr": "127.0.0.1:5000",
                "server_addr": "127.0.0.1:5001",
            })];

            for checkpoint in &checkpoints {
                tracing::info!(event = %checkpoint, "tls_lab_checkpoint");
            }

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;
            let client = client_res.expect("client handshake should succeed");
            let server = server_res.expect("server handshake should succeed");
            let client_ready = client.is_ready();
            let server_ready = server.is_ready();
            let client_protocol = client.protocol_version().is_some();
            let server_protocol = server.protocol_version().is_some();
            let client_alpn = client.alpn_protocol().map(|protocol| protocol.to_vec());
            let server_alpn = server.alpn_protocol().map(|protocol| protocol.to_vec());

            let mut checkpoints = checkpoints;
            checkpoints.push(serde_json::json!({
                    "phase": "handshake_completed",
                    "client_ready": client_ready,
                    "server_ready": server_ready,
                    "client_protocol_present": client_protocol,
                    "server_protocol_present": server_protocol,
                    "client_alpn": client_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                    "server_alpn": server_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                }));

            for checkpoint in checkpoints.iter().skip(1) {
                tracing::info!(event = %checkpoint, "tls_lab_checkpoint");
            }

            (
                client_ready,
                server_ready,
                client_protocol,
                server_protocol,
                client_alpn,
                server_alpn,
                checkpoints,
            )
        });

        assert!(client_ready);
        assert!(server_ready);
        assert!(client_protocol);
        assert!(server_protocol);
        assert_eq!(client_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(server_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(checkpoints.len(), 2);
        assert!(runtime.is_quiescent());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_server_preference_ordering() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Server prefers http/1.1 over h2; client prefers h2 over http/1.1.
            // Per TLS ALPN, the server selects from the intersection.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5100".parse().unwrap(),
                "127.0.0.1:5101".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_fallback_to_http11_when_server_h2_not_supported() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Server supports only http/1.1; client offers h2 + http/1.1.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5110".parse().unwrap(),
                "127.0.0.1:5111".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_none_when_server_has_no_alpn() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Server does not advertise ALPN; client offers h2 + http/1.1.
            // This should still succeed and return no negotiated ALPN.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5120".parse().unwrap(),
                "127.0.0.1:5121".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert!(client.alpn_protocol().is_none());
            assert!(server.alpn_protocol().is_none());
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_required_client_errors_on_no_overlap() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Client requires h2; server only offers http/1.1 -> no overlap.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_h2()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5130".parse().unwrap(),
                "127.0.0.1:5131".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            // Rustls 0.23 enforces RFC 7301: if both sides offer ALPN but there is no overlap,
            // the server aborts the handshake with `no_application_protocol`.
            let client_err = client_res.unwrap_err();
            assert!(matches!(client_err, TlsError::Handshake(_)));

            let server_err = server_res.unwrap_err();
            assert!(matches!(server_err, TlsError::Handshake(_)));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_required_server_errors_when_client_offers_none() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Server requires h2; client does not offer ALPN -> no negotiation.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_h2()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5140".parse().unwrap(),
                "127.0.0.1:5141".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            // Client doesn't require ALPN, so the handshake can succeed from its POV.
            let client = client_res.unwrap();
            assert!(client.alpn_protocol().is_none());

            // Server enforces ALPN and rejects post-handshake if nothing was
            // negotiated. Since br-asupersync-iz6751 the server-side failure is
            // the sanitized `Configuration` error: the message names neither
            // the expected nor the negotiated protocol. v0.4.3 shipped this
            // shape, so it is the compatibility contract.
            let server_err = server_res.unwrap_err();
            assert!(
                matches!(
                    &server_err,
                    TlsError::Configuration(message)
                        if message == "ALPN protocol negotiation failed - client protocol not supported"
                ),
                "unexpected server error: {server_err:?}"
            );
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_timeout() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;

        run_test_with_cx(|_cx| async move {
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .handshake_timeout(std::time::Duration::from_millis(5))
                .build()
                .unwrap();

            let (client_io, _server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5002".parse().unwrap(),
                "127.0.0.1:5003".parse().unwrap(),
            );

            let err = connector.connect("localhost", client_io).await.unwrap_err();
            assert!(matches!(err, TlsError::Timeout(_)));
        });
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn test_build_without_tls_feature() {
        let chain = CertificateChain::new();
        let key = PrivateKey::from_pkcs8_der(vec![]);
        let result = TlsAcceptorBuilder::new(chain, key).build();
        assert!(result.is_err());
    }

    // --- br-asupersync-q5i0bz: protocol-version pinning ----------------

    #[cfg(feature = "tls")]
    #[test]
    fn test_min_protocol_version_inverted_range_rejected_at_build() {
        // Setting min > max must fail config validation, not silently
        // disable the filter or pick one side. Symmetric with the
        // connector's same validation.
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let err = TlsAcceptorBuilder::new(chain, key)
            .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .max_protocol_version(rustls::ProtocolVersion::TLSv1_2)
            .build()
            .expect_err("inverted protocol-version range must be rejected");
        match err {
            TlsError::Configuration(msg) => {
                assert!(
                    msg.contains("greater than max_protocol_version"),
                    "expected inverted-range error, got: {msg}"
                );
            }
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn protocol_bounds_below_tls12_are_honoured_on_both_builders() {
        // Every version but 1.2 and 1.3 used to compare as 0xFFFF, so a
        // TLS 1.1 ceiling capped nothing (the build offered 1.2 and 1.3) and
        // a TLS 1.0 floor excluded everything.
        let acceptor = |min: Option<rustls::ProtocolVersion>, max| {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let mut builder = TlsAcceptorBuilder::new(chain, key);
            if let Some(min) = min {
                builder = builder.min_protocol_version(min);
            }
            if let Some(max) = max {
                builder = builder.max_protocol_version(max);
            }
            builder.build()
        };
        let connector = |min: Option<rustls::ProtocolVersion>, max| {
            let mut builder = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(Certificate::from_pem(TEST_CERT_PEM).unwrap());
            if let Some(min) = min {
                builder = builder.min_protocol_version(min);
            }
            if let Some(max) = max {
                builder = builder.max_protocol_version(max);
            }
            builder.build()
        };
        let tls11 = Some(rustls::ProtocolVersion::TLSv1_1);
        let tls10 = Some(rustls::ProtocolVersion::TLSv1_0);
        assert!(
            matches!(acceptor(None, tls11), Err(TlsError::Configuration(_))),
            "a TLS 1.1 ceiling leaves the acceptor no version"
        );
        assert!(
            matches!(connector(None, tls11), Err(TlsError::Configuration(_))),
            "a TLS 1.1 ceiling leaves the connector no version"
        );
        assert!(acceptor(tls10, None).is_ok(), "a TLS 1.0 floor admits 1.2+");
        assert!(
            connector(tls10, None).is_ok(),
            "a TLS 1.0 floor admits 1.2+"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_min_protocol_tls13_pin_builds_and_handshakes_with_matching_client() {
        // Positive control: when both ends are pinned to TLS 1.3, the
        // handshake succeeds and the negotiated protocol_version on
        // the server is TLSv1_3. This pins the success path that the
        // version-mismatch test below contrasts against.
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .build()
                .expect("TLS-1.3-only acceptor builds");

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .build()
                .expect("TLS-1.3-only connector builds");

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5160".parse().unwrap(),
                "127.0.0.1:5161".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            assert!(
                client_res.is_ok() && server_res.is_ok(),
                "TLS-1.3-only handshake must succeed (client={:?}, server={:?})",
                client_res.is_ok(),
                server_res.is_ok()
            );
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_acceptor_pinned_above_client_max_rejects_handshake() {
        // Negative control: acceptor pins floor at TLS 1.3 (rejects
        // anything below), client pins ceiling at TLS 1.2. No version
        // overlap — the handshake must fail. This is the analogue of
        // the bead's "min=TLS 1.2 rejects TLS 1.0" requirement: rustls
        // 0.23 doesn't even support TLS 1.0, so we exercise the same
        // defense by demonstrating that an acceptor pinned to a
        // higher floor than the client's ceiling rejects the
        // connection. With the previous (asymmetric) acceptor builder
        // this test could not have been written at all — there was
        // no API surface to pin the floor.
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .build()
                .expect("acceptor pinned to TLS 1.3 builds");

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_2)
                .build()
                .expect("connector capped at TLS 1.2 builds");

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5170".parse().unwrap(),
                "127.0.0.1:5171".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            assert!(
                client_res.is_err() || server_res.is_err(),
                "version-mismatched handshake must fail (client_ok={}, server_ok={})",
                client_res.is_ok(),
                server_res.is_ok()
            );
        });
    }

    // ── br-asupersync-y0gm5q: 0-RTT secure-by-default ───────────────

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_default_acceptor_disables_0rtt_early_data() {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        .build()
        .expect("build default acceptor");
        assert_eq!(
            acceptor.config.max_early_data_size, 0,
            "default acceptor must have max_early_data_size=0 \
             (TLS 1.3 0-RTT disabled — replay defense)"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_enable_early_data_opt_in_sets_max_size() {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        // `enable_early_data_with_protection` only sets the byte cap; the
        // replay-protection policy is a separate, explicit builder call.
        // `build()` refuses 0-RTT with `None`, and also with
        // `SafeMethodsOnly` because per-request replay enforcement is not
        // wired into the server pipeline yet (it says so in its error). The
        // only mode that builds today is the explicit testing mode, which is
        // enough for this test's purpose: the byte cap must reach
        // `ServerConfig::max_early_data_size`.
        .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
        .enable_early_data_with_protection(16384)
        .build()
        .expect("build with early data enabled");
        assert_eq!(
            acceptor.config.max_early_data_size, 16384,
            "enable_early_data(N) must propagate N to ServerConfig"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_disable_early_data_resets_to_zero() {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        .enable_early_data_with_protection(16384)
        .disable_early_data()
        .build()
        .expect("build with early data toggled off");
        assert_eq!(
            acceptor.config.max_early_data_size, 0,
            "disable_early_data must reset max_early_data_size=0"
        );
    }

    /// br-asupersync-58ixk6 — empty cert chain rejected by build().
    #[cfg(feature = "tls")]
    #[test]
    fn build_rejects_empty_cert_chain() {
        let chain: CertificateChain = Vec::<Certificate>::new().into();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let err = TlsAcceptorBuilder::new(chain, key)
            .build()
            .expect_err("empty cert chain must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("certificate chain is empty"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-58ixk6 — require_full_chain rejects single-cert
    /// chains (the most common pinning misconfiguration).
    #[cfg(feature = "tls")]
    #[test]
    fn build_with_require_full_chain_rejects_single_cert() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let err = TlsAcceptorBuilder::new(chain, key)
            .require_full_chain()
            .build()
            .expect_err("single-cert chain with require_full_chain must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("require_full_chain"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-vu10zb — `require_sni()` flips the corresponding
    /// builder flag and propagates to the produced acceptor.
    #[cfg(feature = "tls")]
    #[test]
    fn require_sni_propagates_to_acceptor() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .require_sni()
            .build()
            .expect("build should succeed");
        assert!(
            acceptor.require_sni,
            "require_sni() must flip the acceptor's flag"
        );
    }

    /// br-asupersync-2dxusr item 5: require_sni refused an SNI-less client
    /// only after the handshake had completed, so the client had already
    /// received the certificate it was meant to keep from probes. The
    /// server now refuses the hello before it sends any certificate.
    #[cfg(feature = "tls")]
    #[test]
    fn require_sni_refuses_a_hello_without_sni_before_sending_the_certificate() {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::crypto::ring::default_provider;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use std::sync::atomic::{AtomicBool, Ordering};

        /// Accepts any certificate and records that one arrived.
        #[derive(Debug)]
        struct RecordingVerifier(Arc<AtomicBool>);

        impl ServerCertVerifier for RecordingVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                self.0.store(true, Ordering::SeqCst);
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .require_sni()
            .build()
            .expect("build should succeed");

        let certificate_seen = Arc::new(AtomicBool::new(false));
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default client protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RecordingVerifier(Arc::clone(
                &certificate_seen,
            ))))
            .with_no_client_auth();
        config.enable_sni = false;
        let server_name = ServerName::try_from("localhost".to_string()).expect("server name");
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), server_name).expect("client config");
        let mut server =
            rustls::ServerConnection::new(Arc::clone(acceptor.config())).expect("server config");

        let mut server_error = None;
        for _ in 0..8 {
            let mut to_server = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut to_server).expect("client bytes");
            }
            let mut rest = to_server.as_slice();
            while !rest.is_empty() && server_error.is_none() {
                server.read_tls(&mut rest).expect("server reads");
                if let Err(err) = server.process_new_packets() {
                    server_error = Some(err);
                }
            }
            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).expect("server bytes");
            }
            if to_client.is_empty() && to_server.is_empty() {
                break;
            }
            let mut rest = to_client.as_slice();
            while !rest.is_empty() {
                client.read_tls(&mut rest).expect("client reads");
                if client.process_new_packets().is_err() {
                    break;
                }
            }
        }

        assert!(
            !certificate_seen.load(Ordering::SeqCst),
            "the SNI-less client received the server certificate"
        );
        assert!(
            server_error.is_some(),
            "the server refused the hello without SNI"
        );
        assert!(
            client.is_handshaking(),
            "the client never completed a handshake"
        );
    }

    /// The same refusal through the public API: the client's connect fails,
    /// and accept reports the missing SNI.
    #[cfg(feature = "tls")]
    #[test]
    fn require_sni_accept_reports_the_missing_sni_and_the_client_fails() {
        use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
        use crate::net::tcp::VirtualTcpStream;
        use futures_lite::future::zip;

        let config = TestConfig::new()
            .with_seed(0x2D_C5E5)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let (client_res, server_res) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .require_sni()
                .build()
                .unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .disable_sni()
                .build()
                .unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5100".parse().unwrap(),
                "127.0.0.1:5101".parse().unwrap(),
            );
            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;
            (client_res.map(|_| ()), server_res.map(|_| ()))
        });

        assert!(
            client_res.is_err(),
            "a client without SNI completed the handshake"
        );
        match server_res {
            Err(TlsError::Configuration(msg)) => assert!(
                msg.contains("did not send SNI"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected the SNI refusal, got {other:?}"),
        }
    }

    /// br-asupersync-i4n46s — sni_alpn_allow_list whose protocols are
    /// not advertised must be rejected at build() rather than
    /// silently failing every connection.
    #[cfg(feature = "tls")]
    #[test]
    fn build_rejects_sni_alpn_allow_list_without_advertised_protocol() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let mut allow = std::collections::BTreeMap::new();
        allow.insert("api.example.com".to_string(), vec![b"h2".to_vec()]);
        let err = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols_required(vec![b"http/1.1".to_vec()])
            .sni_alpn_allow_list(allow)
            .build()
            .expect_err("allow-list with non-advertised protocol must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("not advertised in alpn_protocols"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-i4n46s — sni_alpn_allow_list with consistent
    /// protocols builds successfully and propagates to the acceptor.
    #[cfg(feature = "tls")]
    #[test]
    fn build_accepts_sni_alpn_allow_list_consistent_with_protocols() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let mut allow = std::collections::BTreeMap::new();
        allow.insert("Api.Example.Com".to_string(), vec![b"h2".to_vec()]);
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols_required(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            .sni_alpn_allow_list(allow)
            .build()
            .expect("build should succeed");
        let list = acceptor
            .sni_alpn_allow_list
            .as_ref()
            .expect("allow-list must propagate");
        assert!(
            list.contains_key("api.example.com"),
            "allow-list keys must be normalised to lowercase"
        );
    }

    // ── br-asupersync-3iqbx3: SNI security validation tests ──────────

    #[cfg(feature = "tls")]
    #[test]
    fn test_require_sni_for_multi_tenant_sets_flag() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .require_sni_for_multi_tenant()
            .build()
            .unwrap();

        assert!(
            acceptor.require_sni,
            "require_sni_for_multi_tenant() must set require_sni flag"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_multi_tenant_warning_with_sni_alpn_allowlist_but_no_require_sni() {
        // This test verifies that the security warning is triggered when
        // a potentially multi-tenant configuration (SNI/ALPN allow-list)
        // is used without require_sni(). In production, this should be caught
        // during configuration validation.
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let mut allow = std::collections::BTreeMap::new();
        allow.insert("tenant1.example.com".to_string(), vec![b"h2".to_vec()]);

        // This should succeed but trigger a security warning
        let _acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols_required(vec![b"h2".to_vec()])
            .sni_alpn_allow_list(allow)
            // Note: deliberately NOT calling require_sni() to trigger warning
            .build()
            .expect("build should succeed but log security warning");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_multi_tenant_warning_with_multiple_alpn_but_no_require_sni() {
        // Multiple ALPN protocols suggest potential tenant-specific routing
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // This should succeed but trigger a security warning
        let _acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"grpc".to_vec()])
            // Note: deliberately NOT calling require_sni() to trigger warning
            .build()
            .expect("build should succeed but log security warning");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_sni_security_error_message_contains_security_context() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Create acceptor that requires SNI
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .require_sni_for_multi_tenant() // Use the security-focused variant
                .build()
                .unwrap();

            // Create client that doesn't send SNI
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .disable_sni() // This should cause the security error
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5200".parse().unwrap(),
                "127.0.0.1:5201".parse().unwrap(),
            );

            let (_client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            // Server should reject with security-focused error message
            let server_err = server_res.unwrap_err();
            match server_err {
                TlsError::Configuration(msg) => {
                    assert!(
                        msg.contains("SECURITY") && msg.contains("asupersync-3iqbx3"),
                        "error message should contain security context, got: {msg}"
                    );
                }
                other => {
                    panic!("expected Configuration error with security context, got {other:?}")
                }
            }
        });
    }

    // ── br-asupersync-jxzrs4: Certificate validation security tests ──

    /// Empty subject, critical SAN DNS:localhost, EC P-256, valid to 2126.
    /// `openssl req -x509 -subj "/" -addext "subjectAltName=critical,DNS:localhost"`.
    #[cfg(feature = "tls")]
    const SAN_ONLY_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBbzCCARagAwIBAgIUWfnf+Qbqhs8Afd0tAR76sZ2za6owCgYIKoZIzj0EAwIw
ADAgFw0yNjEwMDMwNDE4MzFaGA8yMTI2MDkwOTA0MTgzMVowADBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABFjD0VfSdEWfrlG2OsO1vLRWv1KyLM4ks/aXG0c1Bu2R
cpL3GI/H+y/TDwVpBSQrOsC++NTajsFg6HgzbV1yIwujbDBqMB0GA1UdDgQWBBRS
gXY7+GwPh48l2gUlFyTjomcgTzAfBgNVHSMEGDAWgBRSgXY7+GwPh48l2gUlFyTj
omcgTzAPBgNVHRMBAf8EBTADAQH/MBcGA1UdEQEB/wQNMAuCCWxvY2FsaG9zdDAK
BggqhkjOPQQDAgNHADBEAiBOO2mJ0xGv/VEt6OGcHYc6mK5OWbuMXcrz2JvYWxAG
AgIgWKIcqJZDfB9BgKQSbhhx+02tizbl6qi9xTnA8sfkRZU=
-----END CERTIFICATE-----
";

    /// The same key with an empty subject and no SAN, valid to 2126.
    #[cfg(feature = "tls")]
    const NAMELESS_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBVzCB/aADAgECAhRMuHqeb1mPWSxLcH2HlbyevLm6KDAKBggqhkjOPQQDAjAA
MCAXDTI2MTAwMzA0MTgzMVoYDzIxMjYwOTA5MDQxODMxWjAAMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEWMPRV9J0RZ+uUbY6w7W8tFa/UrIsziSz9pcbRzUG7ZFy
kvcYj8f7L9MPBWkFJCs6wL741NqOwWDoeDNtXXIjC6NTMFEwHQYDVR0OBBYEFFKB
djv4bA+HjyXaBSUXJOOiZyBPMB8GA1UdIwQYMBaAFFKBdjv4bA+HjyXaBSUXJOOi
ZyBPMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKJNraBFMdXo
ZIGTFola531RnBtvG1rCJaou4VpRVmPNAiEA0Pds0nOzs4y3KpKYs4A2fAuRLuLK
dEUXP8/OsohM4vU=
-----END CERTIFICATE-----
";

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_validation_accepts_a_san_only_certificate() {
        // RFC 5280 4.1.2.6 lets a certificate name its subject only in a
        // SAN; Let's Encrypt's tlsserver and shortlived profiles issue such
        // certificates.
        let chain = CertificateChain::from_pem(SAN_ONLY_CERT_PEM).unwrap();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&chain);
        assert!(
            result.is_ok(),
            "a SAN-only certificate is valid: {result:?}"
        );

        let chain = CertificateChain::from_pem(NAMELESS_CERT_PEM).unwrap();
        match TlsAcceptorBuilder::validate_certificate_chain(&chain) {
            Err(TlsError::Configuration(msg)) => {
                assert!(msg.contains("has empty subject and no SAN"), "{msg}");
            }
            other => panic!("a certificate naming no subject must be refused: {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_validation_passes_for_valid_cert() {
        // Test that a valid (though self-signed) certificate passes validation
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&chain);

        // Should pass since the test certificate is not expired
        assert!(
            result.is_ok(),
            "valid certificate should pass validation: {:?}",
            result
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_validation_rejects_empty_chain() {
        let empty_chain = CertificateChain::new();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&empty_chain);

        assert!(
            result.is_err(),
            "empty certificate chain should be rejected"
        );
        match result {
            Err(TlsError::Configuration(msg)) => {
                assert!(msg.contains("certificate chain is empty"));
            }
            other => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_with_certificate_validation_integration() {
        // Test that the build() method correctly calls certificate validation
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // Should succeed with valid certificate
        let result = TlsAcceptorBuilder::new(chain, key).build();
        assert!(
            result.is_ok(),
            "build should succeed with valid certificate: {:?}",
            result
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn build_refuses_a_max_fragment_size_rustls_would_refuse_per_connection() {
        let build = |size| {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            TlsAcceptorBuilder::new(chain, key)
                .max_fragment_size(size)
                .build()
        };
        for size in [0, 31, 16_390] {
            match build(size) {
                Err(TlsError::Configuration(msg)) => {
                    assert!(msg.contains("max_fragment_size"), "{msg}");
                }
                other => panic!("size {size} must fail build, got {:?}", other.err()),
            }
        }
        for size in [32, 1_024, 16_389] {
            let acceptor = build(size).expect("an in-range size builds");
            // The bound matches rustls: a connection can be created.
            ServerConnection::new(Arc::clone(acceptor.config()))
                .unwrap_or_else(|e| panic!("size {size}: {e}"));
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_fails_with_empty_certificate_chain() {
        // Test that build() fails when certificate validation detects empty chain
        let empty_chain = CertificateChain::new();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(empty_chain, key).build();
        assert!(
            result.is_err(),
            "build should fail with empty certificate chain"
        );

        match result {
            Err(TlsError::Configuration(msg)) => {
                assert!(
                    msg.contains("certificate chain is empty"),
                    "error should mention empty chain validation: {msg}"
                );
            }
            other => panic!(
                "expected Configuration error for empty chain, got {:?}",
                other
            ),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_validation_provides_security_context() {
        // Test that validation errors include proper security context
        let empty_chain = CertificateChain::new();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&empty_chain);

        match result {
            Err(TlsError::Configuration(msg)) => {
                // While this specific error doesn't include asupersync-jxzrs4,
                // it's part of the security validation system
                assert!(!msg.is_empty(), "error message should provide context");
            }
            other => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_disable_strict_cert_validation_allows_invalid_certs() {
        // Test that disabling strict validation bypasses certificate checks
        let empty_chain = CertificateChain::new();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // Build should fail with strict validation (default)
        let strict_result = TlsAcceptorBuilder::new(empty_chain.clone(), key.clone()).build();
        assert!(
            strict_result.is_err(),
            "strict validation should reject empty chain"
        );

        // Build should still fail with disabled validation due to rustls validation
        // (our strict validation is an additional layer on top of rustls)
        let relaxed_result = TlsAcceptorBuilder::new(empty_chain, key)
            .disable_strict_cert_validation()
            .build();
        // Note: This will still fail because rustls also validates, but at least
        // we can verify our flag is being respected by checking the error doesn't
        // contain our validation message
        assert!(
            relaxed_result.is_err(),
            "empty chain should still fail rustls validation"
        );
    }

    // ── br-asupersync-ycuuwy: 0-RTT replay protection tests ──────────

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_requires_replay_protection() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // Enabling 0-RTT without protection should fail
        let result = TlsAcceptorBuilder::new(chain, key)
            .enable_early_data_with_protection(16384)
            // Deliberately NOT setting replay protection
            .build();

        assert!(result.is_err(), "0-RTT without protection should fail");
        match result {
            Err(TlsError::Configuration(msg)) => {
                assert!(
                    msg.contains("no replay protection configured")
                        && msg.contains("asupersync-ycuuwy"),
                    "error should mention missing protection: {msg}"
                );
            }
            other => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_with_safe_methods_rejected_until_enforcement_wired() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::SafeMethodsOnly)
            .enable_early_data_with_protection(16384)
            .build();

        // br-asupersync-snv902: SafeMethodsOnly only protects when
        // validate_request_for_early_data() runs per request, which is not
        // wired into the server pipeline. Building 0-RTT here would be a
        // phantom control, so build() must fail closed.
        assert!(
            result.is_err(),
            "0-RTT with SafeMethodsOnly must fail closed until per-request \
             enforcement is wired (asupersync-snv902): {result:?}"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_with_idempotency_rejected_until_enforcement_wired() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::IdempotencyKeys)
            .enable_early_data_with_protection(8192)
            .build();

        // br-asupersync-snv902: idempotency-key enforcement is per-request and
        // unwired; 0-RTT must fail closed at build.
        assert!(
            result.is_err(),
            "0-RTT with IdempotencyKeys must fail closed until per-request \
             enforcement is wired (asupersync-snv902): {result:?}"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_with_nonce_rejected_until_enforcement_wired() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::NonceValidation)
            .enable_early_data_with_protection(32768)
            .build();

        // br-asupersync-snv902: nonce validation is per-request and unwired;
        // 0-RTT must fail closed at build.
        assert!(
            result.is_err(),
            "0-RTT with NonceValidation must fail closed until per-request \
             enforcement is wired (asupersync-snv902): {result:?}"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_unprotected_for_testing_logs_warning() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // This should succeed but log security warnings
        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
            .enable_early_data_with_protection(16384)
            .build();

        assert!(
            result.is_ok(),
            "unprotected testing mode should succeed but log warnings"
        );

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 16384);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::UnprotectedForTesting
        ));
    }

    /// br-asupersync-0n1dvh: the deprecated `enable_early_data` used to
    /// select UnprotectedForTesting, so `build()` succeeded with replayable
    /// 0-RTT on the wire. It now never selects a strategy: without one it
    /// leaves 0-RTT off (and `build()` still succeeds), and with one it sets
    /// the cap like `enable_early_data_with_protection`.
    #[cfg(feature = "tls")]
    #[test]
    fn test_deprecated_enable_early_data_never_selects_a_strategy() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        #[allow(deprecated)]
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
            .enable_early_data(16384)
            .build()
            .expect("the deprecated call alone still builds");
        assert_eq!(acceptor.config.max_early_data_size, 0, "0-RTT stays off");
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::None
        ));

        #[allow(deprecated)]
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
            .enable_early_data(16384)
            .build()
            .expect("an explicit testing strategy builds");
        assert_eq!(acceptor.config.max_early_data_size, 16384);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::UnprotectedForTesting
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_no_early_data_allows_no_protection() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // When 0-RTT is disabled (default), no protection is required
        let result = TlsAcceptorBuilder::new(chain, key)
            // Deliberately not setting any protection or enabling early data
            .build();

        assert!(result.is_ok(), "no 0-RTT should not require protection");

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 0);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::None
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_request_validation_helper() {
        // Test SafeMethodsOnly protection
        let safe_methods = EarlyDataReplayProtection::SafeMethodsOnly;
        assert!(
            safe_methods
                .validate_request_for_early_data("GET", false, false)
                .is_ok()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("HEAD", false, false)
                .is_ok()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("OPTIONS", false, false)
                .is_ok()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("POST", false, false)
                .is_err()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("PUT", false, false)
                .is_err()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("DELETE", false, false)
                .is_err()
        );

        // Test IdempotencyKeys protection
        let idempotency = EarlyDataReplayProtection::IdempotencyKeys;
        assert!(
            idempotency
                .validate_request_for_early_data("POST", true, false)
                .is_ok()
        );
        assert!(
            idempotency
                .validate_request_for_early_data("PUT", true, false)
                .is_ok()
        );
        assert!(
            idempotency
                .validate_request_for_early_data("GET", false, false)
                .is_err()
        );

        // Test NonceValidation protection
        let nonce = EarlyDataReplayProtection::NonceValidation;
        assert!(
            nonce
                .validate_request_for_early_data("POST", false, true)
                .is_ok()
        );
        assert!(
            nonce
                .validate_request_for_early_data("GET", false, true)
                .is_ok()
        );
        assert!(
            nonce
                .validate_request_for_early_data("PUT", false, false)
                .is_err()
        );

        // Test UnprotectedForTesting allows everything
        let unprotected = EarlyDataReplayProtection::UnprotectedForTesting;
        assert!(
            unprotected
                .validate_request_for_early_data("POST", false, false)
                .is_ok()
        );
        assert!(
            unprotected
                .validate_request_for_early_data("DELETE", false, false)
                .is_ok()
        );

        // Test None rejects everything
        let none = EarlyDataReplayProtection::None;
        assert!(
            none.validate_request_for_early_data("GET", false, false)
                .is_err()
        );
        assert!(
            none.validate_request_for_early_data("POST", true, true)
                .is_err()
        );
    }
