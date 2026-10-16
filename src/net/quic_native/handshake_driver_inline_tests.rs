    use super::*;

    #[test]
    fn handshake_ack_keeps_received_gaps_and_zero_delay() {
        let frame = handshake_ack_frame(&BTreeSet::from([0, 2, 3, 9])).unwrap();
        let QuicFrame::Ack {
            largest_acknowledged,
            ack_delay,
            ack_range_count,
            first_ack_range,
            ack_ranges,
            ecn_counts,
        } = frame
        else {
            panic!("expected ACK");
        };
        assert_eq!(largest_acknowledged.value(), 9);
        assert_eq!(ack_delay.value(), 0);
        assert_eq!(first_ack_range.value(), 0);
        assert_eq!(ack_range_count.value(), 2);
        assert_eq!(ack_ranges.len(), 2);
        // These ranges acknowledge exactly {9}, {3, 2}, {0}; never 1 or 4..8.
        assert_eq!(ack_ranges[0].gap.value(), 4);
        assert_eq!(ack_ranges[0].ack_range_length.value(), 1);
        assert_eq!(ack_ranges[1].gap.value(), 0);
        assert_eq!(ack_ranges[1].ack_range_length.value(), 0);
        assert!(ecn_counts.is_none());
    }

    #[test]
    fn client_pto_resends_its_initial_under_a_new_packet_number() {
        // A silent peer captures the client's first flight and its PTO copy.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        silent
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_addr = silent.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut datagrams = Vec::new();
            let mut buffer = vec![0_u8; 65_535];
            while datagrams.len() < 2 {
                let (length, _) = silent
                    .recv_from(&mut buffer)
                    .expect("client flight and its PTO copy");
                datagrams.push(buffer[..length].to_vec());
            }
            datagrams
        });
        let original_cid = ConnectionId::new(&[0x4f; 8]).unwrap();
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("native client context");
            let mut endpoint = QuicUdpEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                crate::net::quic_native::QuicUdpEndpointConfig::default(),
            )
            .await
            .unwrap();
            let mut driver = QuicHandshakeDriver::client(
                client_config(vec![ca_cert()], vec![ATP_QUIC_ALPN.to_vec()]).unwrap(),
                ServerName::try_from("localhost").unwrap(),
                Vec::new(),
            )
            .unwrap();
            // The peer never answers; stop once the first PTO has fired.
            let result = crate::time::timeout(
                cx.now(),
                HANDSHAKE_PTO + Duration::from_millis(500),
                client_handshake_over_udp(
                    &cx,
                    &mut endpoint,
                    server_addr,
                    &mut driver,
                    original_cid,
                    ConnectionId::new(&[0x50; 8]).unwrap(),
                ),
            )
            .await;
            assert!(result.is_err(), "a silent peer cannot complete TLS");
        });
        let datagrams = peer.join().unwrap();
        assert_eq!(
            datagrams[0].len(),
            datagrams[1].len(),
            "the same CRYPTO bytes"
        );
        assert_ne!(
            datagrams[0], datagrams[1],
            "a PTO copy never reuses a packet number"
        );
        let mut server = QuicHandshakeDriver::server(
            server_config(vec![leaf_cert()], leaf_key(), vec![ATP_QUIC_ALPN.to_vec()]).unwrap(),
            Vec::new(),
        )
        .unwrap();
        server
            .install_initial_keys(original_cid.as_bytes())
            .unwrap();
        server.recv_handshake_packet(&datagrams[0]).unwrap();
        server.recv_handshake_packet(&datagrams[1]).unwrap();
        assert_eq!(
            server.received_handshake_packet_numbers(HandshakeLevel::Initial),
            [0, 1],
            "the peer authenticates the PTO copy as a new packet"
        );
    }

    #[test]
    fn retry_integrity_tag_matches_rfc_9001_appendix_a4() {
        // RFC 9001 Appendix A.4: a Retry answering an Initial whose DCID was
        // 0x8394c8f03e515708, with source CID 0xf067a5502a4262b5 and token "token".
        let original =
            ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        let retry = [
            0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
            0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
        ];
        let (body, tag) = retry.split_at(retry.len() - QUIC_AEAD_TAG_LEN);
        assert_eq!(retry_integrity_tag(original, body).unwrap(), tag);
        assert!(validated_client_retry(&retry, original, ConnectionId::default()).is_some());
    }

    #[test]
    fn handshake_ack_bounds_sparse_history_and_handles_packet_number_edges() {
        assert!(handshake_ack_frame(&BTreeSet::new()).is_none());
        let largest = (1u64 << 62) - 1;
        let QuicFrame::Ack {
            largest_acknowledged,
            first_ack_range,
            ack_ranges,
            ..
        } = handshake_ack_frame(&BTreeSet::from([largest - 1, largest])).unwrap()
        else {
            panic!("expected ACK");
        };
        assert_eq!(largest_acknowledged.value(), largest);
        assert_eq!(first_ack_range.value(), 1);
        assert!(ack_ranges.is_empty());

        let sparse = (0..100).map(|number| number * 2).collect();
        let frame = handshake_ack_frame(&sparse).unwrap();
        let QuicFrame::Ack {
            largest_acknowledged,
            first_ack_range,
            ack_range_count,
            ref ack_ranges,
            ..
        } = frame
        else {
            panic!("expected ACK");
        };
        assert_eq!(largest_acknowledged.value(), 198);
        assert_eq!(first_ack_range.value(), 0);
        assert_eq!(ack_range_count.value(), 31);
        assert_eq!(ack_ranges.len(), 31);
        assert!(
            ack_ranges
                .iter()
                .all(|range| range.gap.value() == 0 && range.ack_range_length.value() == 0)
        );
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).unwrap();
        assert!(
            encoded.len() < 1200 - 128,
            "ACK leaves room for header and AEAD tag"
        );
    }

    // Canonical CA + leaf chain (P-256), valid ~100 years, generated with openssl
    // for the in-process handshake test. The leaf carries SAN DNS:localhost /
    // IP:127.0.0.1 and the serverAuth EKU that rustls-webpki requires; the client
    // trusts the CA, so this exercises the REAL WebPKI verifier path end-to-end
    // (no insecure skip-verify).
    pub const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

    pub const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

    pub fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
        use rustls::pki_types::pem::PemObject;

        let mut reader = std::io::BufReader::new(pem.as_bytes());
        CertificateDer::pem_reader_iter(&mut reader)
            .next()
            .expect("one cert")
            .expect("valid cert pem")
    }

    fn leaf_cert() -> CertificateDer<'static> {
        parse_one_cert(LEAF_CERT_PEM)
    }

    fn ca_cert() -> CertificateDer<'static> {
        parse_one_cert(CA_CERT_PEM)
    }

    fn cert_without_eku() -> CertificateDer<'static> {
        use rustls::pki_types::pem::PemObject;

        let mut reader = std::io::BufReader::new(
            include_bytes!("../../../tests/fixtures/tls/server.crt").as_slice(),
        );
        CertificateDer::pem_reader_iter(&mut reader)
            .next()
            .expect("one cert")
            .expect("valid cert pem")
    }

    fn fixture_valid_time() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000))
    }

    fn test_server_verifier(
        roots: Vec<CertificateDer<'static>>,
        pins: Vec<CertificateDer<'static>>,
    ) -> Arc<dyn ServerCertVerifier> {
        let mut root_store = RootCertStore::empty();
        for root in roots {
            root_store.add(root).expect("valid test root");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            provider,
        )
        .build()
        .expect("test WebPKI verifier");
        webpki_server_verifier_with_exact_leaf_fallback(webpki, pins)
    }

    fn mutate_extension_value(
        cert: CertificateDer<'static>,
        oid: &str,
        mutate: impl FnOnce(&mut [u8]),
    ) -> CertificateDer<'static> {
        let mut der = cert.as_ref().to_vec();
        let (offset, len) = {
            let (remaining, parsed) =
                x509_parser::parse_x509_certificate(&der).expect("parse test certificate");
            assert!(
                remaining.is_empty(),
                "test certificate must consume full DER"
            );
            let extension = parsed
                .extensions()
                .iter()
                .find(|extension| extension.oid.to_id_string() == oid)
                .expect("test extension");
            let offset = extension.value.as_ptr() as usize - der.as_ptr() as usize;
            (offset, extension.value.len())
        };
        mutate(&mut der[offset..offset + len]);
        CertificateDer::from(der)
    }

    pub fn leaf_key() -> PrivateKeyDer<'static> {
        use rustls::pki_types::pem::PemObject;

        let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
        PrivateKeyDer::pem_reader_iter(&mut reader)
            .next()
            .transpose()
            .expect("read key pem")
            .expect("one key")
    }

    fn drive_to_completion(client: &mut QuicHandshakeDriver, server: &mut QuicHandshakeDriver) {
        for _ in 0..16 {
            for seg in client.pump_outbound().expect("client pump") {
                server.read_handshake(&seg.data).expect("server read");
            }
            for seg in server.pump_outbound().expect("server pump") {
                client.read_handshake(&seg.data).expect("client read");
            }
            if client.is_complete() && server.is_complete() {
                return;
            }
        }
        panic!("handshake did not converge within bound");
    }

    fn client_rejects_server(
        client: &mut QuicHandshakeDriver,
        server: &mut QuicHandshakeDriver,
    ) -> bool {
        'drive: for _ in 0..16 {
            for seg in client.pump_outbound().expect("client pump") {
                let _ = server.read_handshake(&seg.data);
            }
            for seg in server.pump_outbound().expect("server pump") {
                if client.read_handshake(&seg.data).is_err() {
                    return true;
                }
            }
            if client.is_complete() {
                break 'drive;
            }
        }
        false
    }

    // Client's original Destination CID; both sides derive Initial keys from it.
    const DCID_BYTES: &[u8] = &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];

    fn client_retry_wire(
        original_dcid: ConnectionId,
        client_scid: ConnectionId,
        retry_scid: ConnectionId,
        token: &[u8],
    ) -> Vec<u8> {
        use aes_gcm::aead::{AeadInOut, KeyInit};
        use aes_gcm::{Aes128Gcm, Nonce};

        let mut wire = Vec::new();
        PacketHeader::Retry(RetryHeader {
            version: 1,
            dst_cid: client_scid,
            src_cid: retry_scid,
            token: token.to_vec(),
            integrity_tag: [0; 16],
        })
        .encode(&mut wire)
        .unwrap();
        wire.truncate(wire.len() - 16);
        wire[0] |= 0x0b; // Nonzero unused bits must be authenticated as received.
        let mut pseudo = vec![u8::try_from(original_dcid.len()).unwrap()];
        pseudo.extend_from_slice(original_dcid.as_bytes());
        pseudo.extend_from_slice(&wire);
        let cipher = Aes128Gcm::new_from_slice(&hex("be0c690b9f66575a1d766b54e368c84e")).unwrap();
        let nonce_bytes = hex("461599d35d632bf2239825bb");
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).unwrap();
        let mut empty = [];
        let tag = cipher
            .encrypt_inout_detached(&nonce, &pseudo, empty.as_mut_slice().into())
            .unwrap();
        wire.extend_from_slice(&tag);
        wire
    }

    #[test]
    fn client_retry_rfc9001_vector_and_invalid_wire_are_distinguished() {
        let original = ConnectionId::new(&hex("8394c8f03e515708")).unwrap();
        let client = ConnectionId::new(&[]).unwrap();
        // RFC 9001 Appendix A.4, independent of the test's signing helper.
        let vector =
            hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        let retry = validated_client_retry(&vector, original, client).unwrap();
        assert_eq!(retry.token, b"token");
        assert_eq!(retry.src_cid.as_bytes(), hex("f067a5502a4262b5"));
        for at in [0, 14, vector.len() - 1] {
            let mut corrupted = vector.clone();
            corrupted[at] ^= 1;
            assert!(validated_client_retry(&corrupted, original, client).is_none());
        }
        assert!(validated_client_retry(&vector, retry.src_cid, client).is_none());
        assert!(validated_client_retry(&vector[..15], original, client).is_none());

        for (destination, source, token) in [
            (retry.src_cid, retry.src_cid, b"token".as_slice()),
            (client, original, b"token".as_slice()),
            (client, retry.src_cid, b"".as_slice()),
        ] {
            let rejected = client_retry_wire(original, destination, source, token);
            assert!(validated_client_retry(&rejected, original, client).is_none());
        }
        let zero_cid_retry = client_retry_wire(original, client, client, b"token");
        assert!(
            validated_client_retry(&zero_cid_retry, original, client)
                .unwrap()
                .src_cid
                .is_empty()
        );
    }

    #[test]
    fn client_retry_zero_length_cid_rekeys_identical_initial_without_tls_restart() {
        let (mut client, mut server) = protected_pair();
        let original = ConnectionId::new(DCID_BYTES).unwrap();
        let client_cid = ConnectionId::new(b"retry-cl").unwrap();
        let retry_cid = ConnectionId::new(&[]).unwrap();
        let initial = client.pump_outbound().unwrap();
        let original_packet = client
            .assemble_handshake_packet(&initial[0], original, client_cid, 0)
            .unwrap();
        let retry = validated_client_retry(
            &client_retry_wire(original, client_cid, retry_cid, b"bound-token"),
            original,
            client_cid,
        )
        .unwrap();
        client.restart_initial_after_retry(retry, &initial);
        let replay = client.pump_outbound().unwrap();
        assert_eq!(replay.len(), initial.len());
        assert_eq!(replay[0].data, initial[0].data);
        let retried_packet = client
            .assemble_handshake_packet(&replay[0], retry_cid, client_cid, 1)
            .unwrap();
        assert_ne!(retried_packet, original_packet);
        let prefix = long_prefix(&retried_packet);
        assert!(prefix.dst_cid.is_empty());
        assert_eq!(prefix.token, b"bound-token");
        // The old Initial key cannot authenticate the re-encrypted flight.
        assert!(
            server
                .unprotect_long_header_packet(&prefix, &retried_packet)
                .is_err()
        );
        server
            .provider
            .install_retry_initial_keys(&[], &server.transcript);
        let (header, plaintext) = server
            .unprotect_long_header_packet(&prefix, &retried_packet)
            .unwrap();
        assert_eq!(header.packet_number, 1);
        let mut bytes = plaintext.as_slice();
        let Some(QuicFrame::Crypto { offset, data }) = QuicFrame::decode(&mut bytes).unwrap()
        else {
            panic!("repeated ClientHello starts with CRYPTO");
        };
        assert_eq!(offset.value(), 0);
        assert_eq!(data.as_ref(), initial[0].data.as_slice());
        server.recv_handshake_packet(&retried_packet).unwrap();
        assert!(!server.pump_outbound().unwrap().is_empty());
        assert!(server.handshake_keys_installed());
        assert!(initial_crypto_chunk_size(usize::MAX, retry_cid, client_cid, 65_507).is_none());
        assert!(initial_crypto_chunk_size(65_500, retry_cid, client_cid, 65_507).is_none());
        assert!(initial_crypto_chunk_size(1500, retry_cid, client_cid, 1500).is_none());
    }

    #[test]
    fn client_retry_initial_padding_keeps_minimum_at_length_varint_boundary() {
        let (mut client, mut server) = protected_pair();
        let original = ConnectionId::new(DCID_BYTES).unwrap();
        let client_cid = ConnectionId::new(b"retry-cl").unwrap();
        let retry_cid = ConnectionId::new(b"retry-id").unwrap();
        let initial = client.pump_outbound().unwrap();
        let retry = validated_client_retry(
            &client_retry_wire(original, client_cid, retry_cid, &vec![0xa5; 1110]),
            original,
            client_cid,
        )
        .unwrap();
        client.restart_initial_after_retry(retry, &initial);
        server
            .provider
            .install_retry_initial_keys(retry_cid.as_bytes(), &server.transcript);
        // Accepting this Retry would leave 10 CRYPTO bytes per Initial, so the
        // driver refuses it, as it does the 1-byte case of a 1427-byte token
        // at a 1500-byte limit. Assembly must still pad a tiny payload beneath
        // a large token correctly.
        assert!(initial_crypto_chunk_size(1110, retry_cid, client_cid, 1200).is_none());
        let empty = ConnectionId::new(&[]).unwrap();
        assert!(initial_crypto_chunk_size(1427, empty, client_cid, 1500).is_none());
        assert_eq!(
            initial_crypto_chunk_size(1000, retry_cid, client_cid, 16_384),
            Some(128)
        );
        assert_eq!(
            initial_crypto_chunk_size(0, retry_cid, client_cid, 1200),
            Some(1120)
        );
        let chunk_size = 10;
        let segment = HandshakeSegment {
            level: HandshakeLevel::Initial,
            data: initial[0].data[..chunk_size].to_vec(),
        };
        let packet = client
            .assemble_handshake_packet(&segment, retry_cid, client_cid, 1)
            .unwrap();
        let prefix = long_prefix(&packet);
        assert_eq!(
            prefix.payload_length, 63,
            "exercise the one-byte Length boundary"
        );
        assert_eq!(
            packet.len(),
            1200,
            "Initial must fit the configured path exactly"
        );
        server
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("wider Length encoding is covered by packet authentication");
    }

    fn client_retry_parameters(
        original: ConnectionId,
        retry: Option<ConnectionId>,
        server: ConnectionId,
        invalid_parameter: Option<u64>,
    ) -> Vec<u8> {
        use crate::net::quic_core::UnknownTransportParameter;

        let mut parameters = TransportParameters {
            max_udp_payload_size: Some(1200),
            initial_max_data: Some(65_536),
            initial_max_stream_data_bidi_local: Some(4096),
            initial_max_stream_data_bidi_remote: Some(4096),
            initial_max_stream_data_uni: Some(4096),
            initial_max_streams_bidi: Some(4),
            initial_max_streams_uni: Some(4),
            ..TransportParameters::default()
        };
        for (id, value) in [(0x00, Some(original)), (0x0f, Some(server)), (0x10, retry)] {
            if let Some(value) = value {
                parameters.unknown.push(UnknownTransportParameter {
                    id,
                    value: if invalid_parameter == Some(id) {
                        b"wrong-cid".to_vec()
                    } else {
                        value.as_bytes().to_vec()
                    },
                });
            }
        }
        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).unwrap();
        encoded
    }

    #[test]
    fn client_retry_requires_all_tls_authenticated_connection_ids() {
        let original = ConnectionId::new(DCID_BYTES).unwrap();
        let retry = ConnectionId::new(b"retry-id").unwrap();
        let server = ConnectionId::new(b"server-id").unwrap();
        let valid = client_retry_parameters(original, Some(retry), server, None);
        validate_retry_transport_parameters(&valid, original, retry, server).unwrap();
        for (id, code) in [
            (0x00, "retry_original_destination_cid_mismatch"),
            (0x0f, "retry_initial_source_cid_mismatch"),
            (0x10, "retry_source_cid_mismatch"),
        ] {
            let invalid = client_retry_parameters(original, Some(retry), server, Some(id));
            let error =
                validate_retry_transport_parameters(&invalid, original, retry, server).unwrap_err();
            assert_eq!(failure_code(&error), code);
        }
        let missing = client_retry_parameters(original, None, server, None);
        assert_eq!(
            failure_code(
                &validate_retry_transport_parameters(&missing, original, retry, server)
                    .unwrap_err()
            ),
            "retry_source_cid_mismatch"
        );
    }

    fn client_retry_crypto_bytes(plaintext: &[u8], ranges: &mut BTreeMap<u64, Vec<u8>>) {
        let mut input = plaintext;
        while let Some(frame) = QuicFrame::decode(&mut input).unwrap() {
            if let QuicFrame::Crypto { offset, data } = frame {
                if let Some(previous) = ranges.insert(offset.value(), data.to_vec()) {
                    assert_eq!(
                        previous,
                        data.as_ref(),
                        "retransmitted CRYPTO bytes changed"
                    );
                }
            }
        }
    }

    fn client_retry_join_crypto(ranges: &BTreeMap<u64, Vec<u8>>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (&offset, chunk) in ranges {
            assert_eq!(offset, bytes.len() as u64, "CRYPTO flight has a gap");
            bytes.extend_from_slice(chunk);
        }
        bytes
    }

    /// A real socket peer owns an independent server TLS driver. It witnesses
    /// the original ClientHello before sending Retry, inspects the re-encrypted
    /// Initials, then completes certificate-verified TLS with the native client.
    fn run_client_retry_native(
        workers: usize,
        token_len: Option<usize>,
        invalid_parameter: Option<u64>,
    ) {
        use crate::net::quic_native::{
            NativeQuicConnectionConfig, NativeQuicUdpConnection, NativeQuicUdpConnectionError,
            QuicConnectionState, QuicUdpEndpointConfig,
        };

        let original_cid = ConnectionId::new(DCID_BYTES).unwrap();
        let client_cid = ConnectionId::new(b"retry-cl").unwrap();
        let retry_cid = ConnectionId::new(b"retry-id").unwrap();
        let server_cid = ConnectionId::new(b"retry-sv").unwrap();
        let other_cid = ConnectionId::new(b"unwanted").unwrap();
        let peer_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        peer_socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server_addr = peer_socket.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let protocols = vec![ATP_QUIC_ALPN.to_vec()];
            let config = server_config(vec![leaf_cert()], leaf_key(), protocols).unwrap();
            // Without a Retry, an invalid 0x10 is one the server sends unasked.
            let sent_retry_cid = token_len
                .map(|_| retry_cid)
                .or((invalid_parameter == Some(0x10)).then_some(retry_cid));
            let parameters = client_retry_parameters(
                original_cid,
                sent_retry_cid,
                server_cid,
                invalid_parameter,
            );
            let mut original_inspector =
                QuicHandshakeDriver::server(config.clone(), parameters.clone()).unwrap();
            original_inspector.install_initial_keys(DCID_BYTES).unwrap();
            let mut buffer = vec![0; 16_384];
            let (length, client_addr) = peer_socket.recv_from(&mut buffer).unwrap();
            let first = buffer[..length].to_vec();
            let prefix = long_prefix(&first);
            assert_eq!(prefix.dst_cid, original_cid);
            assert_eq!(prefix.src_cid, client_cid);
            assert!(prefix.token.is_empty());
            let (first_header, first_plaintext) = original_inspector
                .unprotect_long_header_packet(&prefix, &first)
                .unwrap();
            let mut first_crypto = BTreeMap::new();
            client_retry_crypto_bytes(&first_plaintext, &mut first_crypto);
            let original_hello = client_retry_join_crypto(&first_crypto);
            assert!(
                original_hello.len() > 128,
                "large-token case must fragment this ClientHello"
            );

            let mut server = QuicHandshakeDriver::server(config, parameters).unwrap();
            server
                .install_initial_keys(if token_len.is_some() {
                    retry_cid.as_bytes()
                } else {
                    original_cid.as_bytes()
                })
                .unwrap();
            let token = token_len.map(|len| vec![0xa5; len]);
            let mut pending_first = Some(first);
            if let Some(token) = &token {
                pending_first = None;
                let retry = client_retry_wire(original_cid, client_cid, retry_cid, token);
                // A correctly signed Retry from another socket is not this
                // peer. The remaining rejects all come from the real address.
                let stray = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                stray.send_to(&retry, client_addr).unwrap();
                let mut bad_tag = retry.clone();
                *bad_tag.last_mut().unwrap() ^= 1;
                for rejected in [
                    vec![0xc0],
                    vec![0xc0, 0, 0, 0, 1, 21],
                    bad_tag,
                    client_retry_wire(original_cid, other_cid, retry_cid, token),
                    client_retry_wire(original_cid, client_cid, original_cid, token),
                    client_retry_wire(original_cid, client_cid, retry_cid, b""),
                ] {
                    peer_socket.send_to(&rejected, client_addr).unwrap();
                }
                peer_socket.send_to(&retry, client_addr).unwrap();
                // A second valid Retry must not replace the accepted token/CID.
                let second = client_retry_wire(original_cid, client_cid, other_cid, b"second");
                peer_socket.send_to(&second, client_addr).unwrap();
            }

            let mut initial_numbers = BTreeSet::new();
            let mut repeated_crypto = BTreeMap::new();
            let mut server_packet_number = 0;
            let mut initial_sent = false;
            for _ in 0..64 {
                let packet = match pending_first.take() {
                    Some(packet) => packet,
                    None => {
                        let (length, address) = peer_socket.recv_from(&mut buffer).unwrap();
                        assert_eq!(address, client_addr);
                        buffer[..length].to_vec()
                    }
                };
                let prefix = long_prefix(&packet);
                if prefix.packet_type == LongPacketType::Initial {
                    assert_eq!(prefix.src_cid, client_cid, "Retry must keep the client CID");
                    assert_eq!(
                        prefix.dst_cid,
                        if token.is_some() {
                            retry_cid
                        } else {
                            original_cid
                        }
                    );
                    assert_eq!(prefix.token, token.clone().unwrap_or_default());
                    let (header, plaintext) = server
                        .unprotect_long_header_packet(&prefix, &packet)
                        .unwrap();
                    if token.is_some() {
                        assert!(header.packet_number > first_header.packet_number);
                        assert!(
                            packet.len() <= 1200,
                            "test Retry Initial exceeds path budget"
                        );
                    }
                    initial_numbers.insert(header.packet_number);
                    client_retry_crypto_bytes(&plaintext, &mut repeated_crypto);
                }
                server.recv_handshake_packet(&packet).unwrap();
                for segment in server.pump_outbound().unwrap() {
                    if segment.level == HandshakeLevel::OneRtt {
                        continue;
                    }
                    let outgoing = server
                        .assemble_handshake_packet(
                            &segment,
                            client_cid,
                            server_cid,
                            server_packet_number,
                        )
                        .unwrap();
                    server_packet_number += 1;
                    peer_socket.send_to(&outgoing, client_addr).unwrap();
                    if segment.level == HandshakeLevel::Initial && !initial_sent {
                        initial_sent = true;
                        let late = client_retry_wire(original_cid, client_cid, other_cid, b"late");
                        peer_socket.send_to(&late, client_addr).unwrap();
                    }
                }
                if server.is_complete() {
                    assert!(server.one_rtt_keys_installed());
                    assert_eq!(client_retry_join_crypto(&repeated_crypto), original_hello);
                    if token_len == Some(1000) {
                        assert!(
                            initial_numbers.len() > 1,
                            "token must force ClientHello fragmentation"
                        );
                    }
                    return (initial_numbers.len(), original_hello.len(), initial_sent);
                }
            }
            panic!("Retry peer did not complete TLS");
        });

        let builder = if workers == 1 {
            crate::runtime::RuntimeBuilder::current_thread()
        } else {
            crate::runtime::RuntimeBuilder::multi_thread().worker_threads(workers)
        };
        let runtime = builder
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let cx = Cx::current().expect("native Retry caller context");
            let endpoint = QuicUdpEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                QuicUdpEndpointConfig {
                    max_packet_size: 16_384,
                    ..QuicUdpEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            let config = client_config(vec![ca_cert()], vec![ATP_QUIC_ALPN.to_vec()]).unwrap();
            let local_parameters = TransportParameters {
                initial_max_streams_bidi: Some(4),
                initial_max_streams_uni: Some(4),
                ..TransportParameters::default()
            };
            let mut encoded = Vec::new();
            local_parameters.encode(&mut encoded).unwrap();
            let driver = QuicHandshakeDriver::client(
                config,
                ServerName::try_from("localhost").unwrap(),
                encoded,
            )
            .unwrap();
            let result = crate::time::timeout(
                cx.now(),
                Duration::from_secs(8),
                NativeQuicUdpConnection::connect(
                    &cx,
                    endpoint,
                    server_addr,
                    driver,
                    original_cid,
                    client_cid,
                    NativeQuicConnectionConfig::default(),
                    ATP_QUIC_ALPN,
                ),
            )
            .await
            .expect("native Retry handshake must finish before the watchdog");
            let result = result.map(|connection| {
                assert_eq!(
                    connection.connection().state(),
                    QuicConnectionState::Established
                );
                assert!(connection.connection().can_send_app_data());
                drop(connection);
            });
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
            result
        });
        let (initial_packets, hello_bytes, initial_sent) = peer.join().unwrap();
        assert!(
            initial_sent,
            "peer sent an authenticated Initial before the late Retry"
        );
        match invalid_parameter {
            None => result.expect("native caller establishes despite ignored Retry datagrams"),
            Some(id) if token_len.is_none() => {
                let error = result.unwrap_err();
                let expected = match (id, &error) {
                    (0x00, NativeQuicUdpConnectionError::Handshake(error)) => {
                        failure_code(error) == "original_destination_cid_mismatch"
                    }
                    (0x10, NativeQuicUdpConnectionError::Handshake(error)) => {
                        failure_code(error) == "retry_source_cid_without_retry"
                    }
                    (0x0f, NativeQuicUdpConnectionError::TransportParameters(message)) => {
                        message.contains("initial_source_connection_id")
                    }
                    _ => false,
                };
                assert!(expected, "parameter {id:#x} without Retry: {error:?}");
            }
            Some(id) => {
                let NativeQuicUdpConnectionError::Handshake(error) = result.unwrap_err() else {
                    panic!("Retry CID mismatch must fail in authenticated handshake completion");
                };
                let expected = match id {
                    0x00 => "retry_original_destination_cid_mismatch",
                    0x0f => "retry_initial_source_cid_mismatch",
                    0x10 => "retry_source_cid_mismatch",
                    _ => panic!("unknown test parameter"),
                };
                assert_eq!(failure_code(&error), expected);
            }
        }
        assert!(
            runtime.is_quiescent(),
            "Retry test leaves no runtime tasks or obligations"
        );
        eprintln!(
            "bead=asupersync-bi2462.108 scenario=client_retry workers={workers} token_len={token_len:?} invalid_parameter={invalid_parameter:?} initial_packets={initial_packets} identical_client_hello_bytes={hello_bytes} tls_peer_complete=true runtime_quiescent=true"
        );
    }

    #[test]
    fn client_retry_native_establishes_with_token_fragmentation_and_ignored_forgeries() {
        for workers in [1, 2] {
            for token_len in [16, 1000] {
                run_client_retry_native(workers, Some(token_len), None);
            }
        }
    }

    #[test]
    fn client_retry_native_ignores_retry_after_authenticated_initial_without_prior_retry() {
        for workers in [1, 2] {
            run_client_retry_native(workers, None, None);
        }
    }

    #[test]
    fn client_retry_native_rejects_each_authenticated_cid_mismatch() {
        for workers in [1, 2] {
            for id in [0x00, 0x0f, 0x10] {
                run_client_retry_native(workers, Some(16), Some(id));
            }
        }
    }

    /// RFC 9000 section 7.3 without a Retry: a server that names another
    /// original DCID (a rewritten first Initial), another source CID, or a
    /// Retry source CID although no Retry was accepted is refused.
    #[test]
    fn client_without_retry_rejects_each_authenticated_cid_mismatch() {
        for workers in [1, 2] {
            for id in [0x00, 0x0f, 0x10] {
                run_client_retry_native(workers, None, Some(id));
            }
        }
    }

    #[test]
    fn crypto_reassembler_waits_for_gaps_and_rejects_conflicting_overlap() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        assert!(
            reassembler.push(4, b"ef").expect("buffer tail").is_empty(),
            "a tail beyond the receive offset must remain buffered"
        );
        assert_eq!(
            reassembler.push(0, b"abcd").expect("fill gap"),
            vec![b"abcdef".to_vec()],
            "filling the gap must release one contiguous CRYPTO stream chunk"
        );
        assert!(
            reassembler
                .push(2, b"cdef")
                .expect("duplicate delivered range")
                .is_empty(),
            "already delivered CRYPTO bytes must be idempotent"
        );

        let mut conflicting = HandshakeCryptoReassembler::default();
        assert!(
            conflicting
                .push(2, b"cd")
                .expect("buffer first range")
                .is_empty()
        );
        assert!(matches!(
            conflicting.push(1, b"XX"),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_overlap_conflict",
            })
        ));
    }

    #[test]
    fn crypto_reassembler_rejects_offset_or_end_exceeding_varint_max() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        let err = reassembler
            .push(VARINT_MAX, b"x")
            .expect_err("offset + len > VARINT_MAX must fail");
        assert!(matches!(
            err,
            QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_offset_overflow",
            }
        ));

        let err2 = reassembler
            .push(VARINT_MAX + 1, b"x")
            .expect_err("offset > VARINT_MAX must fail");
        assert!(matches!(
            err2,
            QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_offset_overflow",
            }
        ));
    }

    #[test]
    fn crypto_reassembler_bounds_disjoint_range_metadata() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        for index in 0..MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES {
            let offset = 1 + u64::try_from(index).expect("range index fits u64") * 2;
            assert!(
                reassembler
                    .push(offset, b"x")
                    .expect("range below metadata cap")
                    .is_empty()
            );
        }

        assert!(matches!(
            reassembler.push(
                1 + u64::try_from(MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES)
                    .expect("range limit fits u64")
                    * 2,
                b"x",
            ),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_range_limit",
            })
        ));
        assert_eq!(
            reassembler.pending.len(),
            MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES,
            "rejecting excess metadata must leave the accepted range set bounded"
        );

        assert_eq!(
            reassembler
                .push(0, b"x")
                .expect("receive-head data must remain admissible at the metadata cap"),
            vec![b"xx".to_vec()],
            "receive-head data and its adjacent successor are delivered immediately"
        );
        assert_eq!(
            reassembler.pending.len(),
            MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES - 1,
            "delivering the receive head must remove its adjacent retained range"
        );
        assert_eq!(
            reassembler
                .push(2, b"x")
                .expect("filling the remaining head gap must drain its successor"),
            vec![b"xx".to_vec()]
        );
        assert_eq!(
            reassembler.pending.len(),
            MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES - 2,
            "closing the head gap must reduce retained metadata"
        );
    }

    #[test]
    fn crypto_reassembler_rejection_preserves_accepted_ranges() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        reassembler
            .push(1, b"accepted")
            .expect("buffer accepted range behind initial gap");
        let accepted = reassembler.pending.clone();
        let accepted_bytes = reassembler.pending_bytes;

        assert!(matches!(
            reassembler.push(2, b"conflict"),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_overlap_conflict",
            })
        ));
        assert_eq!(reassembler.pending, accepted);
        assert_eq!(reassembler.pending_bytes, accepted_bytes);

        let mut oversized = vec![0_u8; MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES + 1];
        oversized[..8].copy_from_slice(b"accepted");
        assert!(matches!(
            reassembler.push(1, &oversized),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_buffer_limit",
            })
        ));
        assert_eq!(reassembler.pending, accepted);
        assert_eq!(reassembler.pending_bytes, accepted_bytes);
    }

    #[test]
    fn crypto_reassembler_byte_cap_does_not_block_receive_head() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        assert!(
            reassembler
                .push(2, &vec![0_u8; MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES])
                .expect("fill retained byte budget behind a gap")
                .is_empty()
        );
        assert_eq!(
            reassembler.pending_bytes,
            MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES
        );

        assert_eq!(
            reassembler
                .push(0, b"x")
                .expect("isolated receive-head byte must bypass retained byte cap"),
            vec![b"x".to_vec()]
        );
        let ready = reassembler
            .push(1, b"x")
            .expect("closing the final gap must drain byte-capped successor");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].len(), MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES + 1);
        assert_eq!(&ready[0][..2], b"x\0");
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.pending_bytes, 0);
    }

    #[test]
    fn crypto_reassembler_reuses_spare_capacity_from_both_ends_and_for_duplicates() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        reassembler.push(4096, &vec![17; 1024]).unwrap();
        let accepted = reassembler.pending.get_mut(&4096).unwrap();
        accepted.reserve(3072);
        let capacity = accepted.capacity();
        let marker = std::ptr::from_ref(&accepted[0]);

        // The accepted byte must keep its address while spare capacity exists.
        // This checks allocation reuse, not a wall-clock performance threshold.
        for index in 1..=1024_usize {
            let offset = 4096 - u64::try_from(index).unwrap();
            assert!(reassembler.push(offset, &[17]).unwrap().is_empty());
            let accepted = &reassembler.pending[&offset];
            assert_eq!(accepted.capacity(), capacity);
            assert_eq!(std::ptr::from_ref(&accepted[index]), marker);
        }
        for index in 0..1024_u64 {
            assert!(reassembler.push(5120 + index, &[17]).unwrap().is_empty());
            let accepted = &reassembler.pending[&3072];
            assert_eq!(accepted.capacity(), capacity);
            assert_eq!(std::ptr::from_ref(&accepted[1024]), marker);
        }
        assert_eq!(reassembler.pending.len(), 1);
        assert_eq!(reassembler.pending_bytes, 3072);
        for offset in [3072, 4096, 6143] {
            assert!(reassembler.push(offset, &[17]).unwrap().is_empty());
            let accepted = &reassembler.pending[&3072];
            assert_eq!(accepted.capacity(), capacity);
            assert_eq!(std::ptr::from_ref(&accepted[1024]), marker);
            assert_eq!(reassembler.pending_bytes, 3072);
        }
        let ready = reassembler.push(0, &vec![17; 3072]).unwrap();
        assert_eq!(ready, vec![vec![17; 6144]]);
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.pending_bytes, 0);
    }

    #[test]
    fn crypto_reassembler_bridges_ranges_without_replacing_the_largest_allocation() {
        for lengths in [[1024, 13, 29], [13, 1024, 29], [13, 29, 1024]] {
            let starts = [5, 5 + lengths[0] + 7, 5 + lengths[0] + 7 + lengths[1] + 11];
            let end = starts[2] + lengths[2];
            let expected: Vec<u8> = (0..end)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let mut reassembler = HandshakeCryptoReassembler::default();
            for (&start, &len) in starts.iter().zip(&lengths) {
                reassembler
                    .push(u64::try_from(start).unwrap(), &expected[start..start + len])
                    .unwrap();
            }
            let largest_index = lengths.iter().position(|&len| len == 1024).unwrap();
            let largest_start = u64::try_from(starts[largest_index]).unwrap();
            let largest = reassembler.pending.get_mut(&largest_start).unwrap();
            largest.reserve(end);
            let capacity = largest.capacity();
            let marker = std::ptr::from_ref(&largest[0]);
            let bridge_start = starts[0] + lengths[0] - 1;
            let bridge_end = starts[2] + 1;
            let before = reassembler.pending.clone();
            let mut conflicting = expected[bridge_start..bridge_end].to_vec();
            *conflicting.last_mut().unwrap() ^= 0x80;
            assert!(matches!(
                reassembler.push(u64::try_from(bridge_start).unwrap(), &conflicting),
                Err(QuicTlsError::CryptoProviderFailure {
                    provider: "rustls-quic-handshake",
                    code: "crypto_overlap_conflict",
                })
            ));
            assert_eq!(reassembler.pending, before);
            assert_eq!(reassembler.pending_bytes, lengths.iter().sum::<usize>());
            assert!(
                reassembler
                    .push(
                        u64::try_from(bridge_start).unwrap(),
                        &expected[bridge_start..bridge_end],
                    )
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(reassembler.pending.len(), 1);
            let merged = &reassembler.pending[&5];
            assert_eq!(merged.capacity(), capacity);
            assert_eq!(
                std::ptr::from_ref(&merged[starts[largest_index] - 5]),
                marker
            );
            assert!(merged.iter().eq(expected[5..].iter()));
            assert_eq!(reassembler.pending_bytes, end - 5);
            assert_eq!(reassembler.push(0, &expected[..5]).unwrap(), vec![expected]);
            assert!(reassembler.pending.is_empty());
        }
    }

    #[test]
    fn crypto_reassembler_matches_byte_oracle_under_overlap_reordering_and_conflicts() {
        fn check_push(
            reassembler: &mut HandshakeCryptoReassembler,
            oracle: &mut [Option<u8>],
            head: &mut usize,
            offset: usize,
            data: &[u8],
        ) {
            let before = reassembler.pending.clone();
            let before_bytes = reassembler.pending_bytes;
            let conflict = data.iter().enumerate().any(|(index, &byte)| {
                offset + index >= *head
                    && oracle[offset + index].is_some_and(|accepted| accepted != byte)
            });
            let result = reassembler.push(u64::try_from(offset).unwrap(), data);
            if conflict {
                assert!(matches!(
                    result,
                    Err(QuicTlsError::CryptoProviderFailure {
                        provider: "rustls-quic-handshake",
                        code: "crypto_overlap_conflict",
                    })
                ));
                assert_eq!(reassembler.pending, before);
                assert_eq!(reassembler.pending_bytes, before_bytes);
            } else {
                for (index, &byte) in data.iter().enumerate() {
                    if offset + index >= *head {
                        oracle[offset + index] = Some(byte);
                    }
                }
                let mut ready = Vec::new();
                while let Some(Some(byte)) = oracle.get(*head) {
                    ready.push(*byte);
                    *head += 1;
                }
                assert_eq!(result.unwrap().concat(), ready);
            }
            assert_eq!(reassembler.next_offset, u64::try_from(*head).unwrap());
            let mut retained = vec![None; oracle.len()];
            let mut previous_end = u64::try_from(*head).unwrap();
            let mut retained_bytes = 0;
            for (&start, bytes) in &reassembler.pending {
                assert!(
                    start > previous_end,
                    "accepted ranges must be separated by gaps"
                );
                previous_end = start + u64::try_from(bytes.len()).unwrap();
                let start = usize::try_from(start).unwrap();
                for (index, &byte) in bytes.iter().enumerate() {
                    retained[start + index] = Some(byte);
                }
                retained_bytes += bytes.len();
            }
            assert_eq!(&retained[*head..], &oracle[*head..]);
            assert_eq!(reassembler.pending_bytes, retained_bytes);
        }

        const LEN: usize = 2048;
        let input: Vec<u8> = (0..LEN)
            .map(|index| u8::try_from((index * 37 + index / 5) % 251).unwrap())
            .collect();
        for seed in [1_u64, 17, 0x5eed, 0xdead_beef] {
            let mut state = seed;
            let mut reassembler = HandshakeCryptoReassembler::default();
            let mut oracle = vec![None; LEN];
            let mut head = 0;
            for step in 0..512 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                // Leave the initial byte absent until the final drain. This
                // keeps randomized overlaps and conflicts in retained state.
                let offset = 1 + usize::try_from(state % 2047).unwrap();
                let len = (1 + usize::try_from((state >> 32) % 193).unwrap()).min(LEN - offset);
                let mut bytes = input[offset..offset + len].to_vec();
                if step % 7 == 0 {
                    bytes[len / 2] ^= 0x80;
                }
                check_push(&mut reassembler, &mut oracle, &mut head, offset, &bytes);
            }
            let completion: Vec<u8> = oracle
                .iter()
                .zip(&input)
                .map(|(accepted, &byte)| accepted.unwrap_or(byte))
                .collect();
            check_push(&mut reassembler, &mut oracle, &mut head, 0, &completion);
            assert_eq!(head, LEN);
            // Delivered bytes remain idempotent even if a retransmission's
            // discarded prefix differs; the receiver retains no TLS history.
            check_push(&mut reassembler, &mut oracle, &mut head, 0, &vec![0; LEN]);
            assert!(reassembler.push(u64::MAX, &[]).unwrap().is_empty());
            assert!(matches!(
                reassembler.push(u64::MAX, &[1]),
                Err(QuicTlsError::CryptoProviderFailure {
                    provider: "rustls-quic-handshake",
                    code: "crypto_offset_overflow",
                })
            ));
            assert_eq!(reassembler.next_offset, u64::try_from(LEN).unwrap());
            assert!(reassembler.pending.is_empty());
            eprintln!(
                "bead=asupersync-bi2462.108 scenario=crypto_reassembly_byte_oracle seed={seed} fragments=512 conflicts_transactional=true delivered={head} retained_bytes=0"
            );
        }
    }

    #[test]
    fn crypto_reassembler_completes_protected_tls_with_delayed_prefixes_and_retransmissions() {
        for reverse in [false, true] {
            let (mut client, mut server) = protected_pair();
            let dcid = ConnectionId::new(DCID_BYTES).unwrap();
            let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).unwrap();
            let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).unwrap();
            let mut client_pn = 0;
            let mut server_pn = 0;
            let mut flights: VecDeque<_> = client
                .pump_outbound()
                .unwrap()
                .into_iter()
                .map(|segment| (true, segment))
                .collect();
            let mut segments = 0;
            let mut reordered_spaces = BTreeSet::new();
            while let Some((from_client, segment)) = flights.pop_front() {
                if segment.level == HandshakeLevel::OneRtt {
                    continue;
                }
                segments += 1;
                assert!(segments <= 32, "fragmented TLS handshake must converge");
                let (sender, receiver, pn, dst, src) = if from_client {
                    (&mut client, &mut server, &mut client_pn, dcid, client_scid)
                } else {
                    (
                        &mut server,
                        &mut client,
                        &mut server_pn,
                        client_scid,
                        server_scid,
                    )
                };
                let space = level_index(segment.level);
                let start = sender.crypto_send_offset[space];
                let head = receiver.handshake_crypto_reassembly[space].next_offset;
                assert_eq!(start, head);
                let mut packets = Vec::new();
                for chunk in segment.data.chunks(17) {
                    packets.push(
                        sender
                            .assemble_handshake_packet(
                                &HandshakeSegment {
                                    level: segment.level,
                                    data: chunk.to_vec(),
                                },
                                dst,
                                src,
                                *pn,
                            )
                            .unwrap(),
                    );
                    *pn += 1;
                }
                assert!(!packets.is_empty());
                let mut order: Vec<_> = (1..packets.len()).collect();
                if reverse {
                    order.reverse();
                }
                for index in order {
                    receiver.recv_handshake_packet(&packets[index]).unwrap();
                    assert_eq!(
                        receiver.handshake_crypto_reassembly[space].next_offset,
                        head
                    );
                    assert!(receiver.pump_outbound().unwrap().is_empty());
                    reordered_spaces.insert(space);
                }
                if packets.len() > 1 {
                    // A new packet number carrying already buffered CRYPTO
                    // reaches reassembly, unlike packet-number replay filtering.
                    let end = sender.crypto_send_offset[space];
                    sender.crypto_send_offset[space] = start + 17;
                    let retransmission = sender
                        .assemble_handshake_packet(
                            &HandshakeSegment {
                                level: segment.level,
                                data: segment.data[17..].to_vec(),
                            },
                            dst,
                            src,
                            *pn,
                        )
                        .unwrap();
                    *pn += 1;
                    sender.crypto_send_offset[space] = end;
                    let retained = receiver.handshake_crypto_reassembly[space].pending_bytes;
                    receiver.recv_handshake_packet(&retransmission).unwrap();
                    assert_eq!(
                        receiver.handshake_crypto_reassembly[space].pending_bytes,
                        retained
                    );
                    assert_eq!(
                        receiver.handshake_crypto_reassembly[space].next_offset,
                        head
                    );
                    assert!(receiver.pump_outbound().unwrap().is_empty());
                }
                receiver.recv_handshake_packet(&packets[0]).unwrap();
                assert_eq!(
                    receiver.handshake_crypto_reassembly[space].next_offset,
                    head + u64::try_from(segment.data.len()).unwrap()
                );
                assert!(
                    receiver.handshake_crypto_reassembly[space]
                        .pending
                        .is_empty()
                );
                flights.extend(
                    receiver
                        .pump_outbound()
                        .unwrap()
                        .into_iter()
                        .map(|segment| (!from_client, segment)),
                );
            }
            assert!(client.is_complete() && server.is_complete());
            assert!(client.one_rtt_keys_installed() && server.one_rtt_keys_installed());
            assert_eq!(reordered_spaces, BTreeSet::from([0, 1]));
            assert_eq!(
                client.peer_transport_parameters(),
                Some(b"server-params".as_slice())
            );
            assert_eq!(
                server.peer_transport_parameters(),
                Some(b"client-params".as_slice())
            );
            for driver in [&client, &server] {
                for reassembler in &driver.handshake_crypto_reassembly {
                    assert!(reassembler.pending.is_empty());
                    assert_eq!(reassembler.pending_bytes, 0);
                }
            }
            eprintln!(
                "bead=asupersync-bi2462.108 scenario=crypto_reassembly_protected_tls reverse={reverse} segments={segments} client_packets={client_pn} server_packets={server_pn} both_crypto_spaces=true tls_complete=true retained_bytes=0"
            );
        }
    }

    #[test]
    fn protected_crypto_packets_reassemble_when_lower_packet_number_arrives_late() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");

        let mut flight = client.pump_outbound().expect("client initial flight");
        assert_eq!(flight.len(), 1, "test expects one Initial CRYPTO segment");
        let client_hello = flight.pop().expect("ClientHello segment");
        assert_eq!(client_hello.level, HandshakeLevel::Initial);
        let split = client_hello.data.len() / 2;
        assert!(split > 0, "ClientHello must be splittable");

        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let first = client
            .assemble_handshake_packet(
                &HandshakeSegment {
                    level: HandshakeLevel::Initial,
                    data: client_hello.data[..split].to_vec(),
                },
                dcid,
                client_scid,
                0,
            )
            .expect("assemble first ClientHello half");
        let second = client
            .assemble_handshake_packet(
                &HandshakeSegment {
                    level: HandshakeLevel::Initial,
                    data: client_hello.data[split..].to_vec(),
                },
                dcid,
                client_scid,
                1,
            )
            .expect("assemble second ClientHello half");

        server
            .recv_handshake_packet(&second)
            .expect("buffer higher packet number first");
        assert!(
            server
                .pump_outbound()
                .expect("pump while ClientHello has a gap")
                .is_empty(),
            "TLS must not observe a CRYPTO suffix before its missing prefix"
        );
        server
            .recv_handshake_packet(&first)
            .expect("accept reordered lower packet number");
        assert!(
            !server
                .pump_outbound()
                .expect("pump complete ClientHello")
                .is_empty(),
            "filling the CRYPTO gap must let TLS produce the server flight"
        );
        server
            .recv_handshake_packet(&second)
            .expect("exact packet-number duplicate must be idempotent");

        let mut forged_duplicate = second;
        let final_byte = forged_duplicate
            .last_mut()
            .expect("protected packet includes an authentication tag");
        *final_byte ^= 1;
        assert!(matches!(
            server.recv_handshake_packet(&forged_duplicate),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "packet_unprotect",
            })
        ));
    }

    /// GH#68 / RFC 9000 §14.1: an Initial packet leaves as a datagram of at
    /// least 1200 bytes, and the padded packet still authenticates and feeds
    /// TLS on the receiving side. Handshake-level packets are not expanded.
    #[test]
    fn initial_packets_are_padded_to_the_rfc_minimum_and_still_parse() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");

        let mut flight = client.pump_outbound().expect("client initial flight");
        assert_eq!(flight.len(), 1, "test expects one Initial CRYPTO segment");
        let client_hello = flight.pop().expect("ClientHello segment");
        assert!(
            client_hello.data.len() < MIN_INITIAL_DATAGRAM_BYTES / 2,
            "a bare ClientHello is far below the datagram minimum: {}",
            client_hello.data.len()
        );

        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let initial = client
            .assemble_handshake_packet(&client_hello, dcid, client_scid, 0)
            .expect("assemble ClientHello Initial");
        assert_eq!(
            initial.len(),
            MIN_INITIAL_DATAGRAM_BYTES,
            "the Initial datagram is expanded to exactly the RFC minimum"
        );
        // The packet is header-protected (GH#69), so only the invariant prefix
        // is readable on the wire; its Length field covers the packet number,
        // the padded ciphertext and the tag.
        let ProtectedHeaderPrefix::Long(header) =
            ProtectedHeaderPrefix::decode(&initial, 0).expect("padded Initial prefix")
        else {
            panic!("Initial packets use the long header");
        };
        assert_eq!(header.packet_type, LongPacketType::Initial);
        assert_eq!(
            header.payload_length as usize,
            initial.len() - header.packet_number_offset,
            "the Length field accounts for the padding inside the AEAD envelope"
        );
        assert_eq!(
            header
                .packet_len(initial.len())
                .expect("Length bounds the packet"),
            initial.len()
        );

        // The padded packet authenticates, and TLS consumes the ClientHello
        // through the PADDING frames.
        server
            .recv_handshake_packet(&initial)
            .expect("padded Initial authenticates and parses");
        let server_flight = server
            .pump_outbound()
            .expect("server flight after ClientHello");
        assert!(
            !server_flight.is_empty(),
            "TLS must have consumed the ClientHello behind the padding"
        );

        // Handshake-level packets are not expanded: header + CRYPTO frame
        // framing + tag stay well under 64 bytes of overhead.
        if let Some(segment) = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
        {
            let server_scid = ConnectionId::new(&[0x55, 0x66]).expect("server scid");
            let packet = server
                .assemble_handshake_packet(segment, client_scid, server_scid, 0)
                .expect("assemble Handshake packet");
            assert!(
                packet.len() <= segment.data.len() + 64,
                "Handshake packets carry no padding: {} bytes for a {}-byte segment",
                packet.len(),
                segment.data.len()
            );
        }
    }

    #[test]
    fn real_tls13_handshake_completes_over_protected_packets() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        // RFC 9001 §5.2: Initial keys are derived from the client's original DCID
        // on BOTH sides (the server reads the DCID from the first Initial packet).
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");

        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        // Per-sender packet-number counter (unique-within-space suffices).
        let mut client_pn = 0u64;
        let mut server_pn = 0u64;

        // Pump-after-each-recv is REQUIRED: e.g. the client must process the
        // server's Initial (ServerHello) and pump to install Handshake keys
        // BEFORE it can unprotect the server's Handshake-level flight. Batch
        // recv-then-pump would fail on the second packet.
        // OneRtt-level segments (e.g. post-handshake NewSessionTicket) belong to
        // the 1-RTT short-header data plane, not the handshake; they are optional
        // and not needed to prove the handshake completes, so skip them here.
        let assemble_client =
            |c: &mut QuicHandshakeDriver, pn: &mut u64, out: &mut Vec<Vec<u8>>| {
                for seg in c.pump_outbound().expect("client pump") {
                    if seg.level == HandshakeLevel::OneRtt {
                        continue;
                    }
                    out.push(
                        c.assemble_handshake_packet(&seg, dcid, client_scid, *pn)
                            .expect("client assemble"),
                    );
                    *pn += 1;
                }
            };
        let assemble_server =
            |s: &mut QuicHandshakeDriver, pn: &mut u64, out: &mut Vec<Vec<u8>>| {
                for seg in s.pump_outbound().expect("server pump") {
                    if seg.level == HandshakeLevel::OneRtt {
                        continue;
                    }
                    out.push(
                        s.assemble_handshake_packet(&seg, client_scid, server_scid, *pn)
                            .expect("server assemble"),
                    );
                    *pn += 1;
                }
            };

        // Seed: the client's first flight (ClientHello over Initial).
        let mut client_to_server: Vec<Vec<u8>> = Vec::new();
        assemble_client(&mut client, &mut client_pn, &mut client_to_server);

        for _ in 0..16 {
            let mut server_to_client: Vec<Vec<u8>> = Vec::new();
            for packet in client_to_server.drain(..) {
                server.recv_handshake_packet(&packet).expect("server recv");
                assemble_server(&mut server, &mut server_pn, &mut server_to_client);
            }

            let mut next_client_to_server: Vec<Vec<u8>> = Vec::new();
            for packet in server_to_client.drain(..) {
                client.recv_handshake_packet(&packet).expect("client recv");
                assemble_client(&mut client, &mut client_pn, &mut next_client_to_server);
            }
            client_to_server = next_client_to_server;

            if client.is_complete() && server.is_complete() {
                break;
            }
        }

        assert!(
            client.is_complete() && server.is_complete(),
            "handshake over real protected packets did not complete"
        );
        assert!(
            client.one_rtt_keys_installed() && server.one_rtt_keys_installed(),
            "1-RTT keys not installed after packet handshake"
        );
        // Real AEAD keys agreed over the wire: the client decrypted the server's
        // Handshake-level Certificate flight (protected with Handshake keys), which
        // only succeeds if both sides derived matching keys from the transcript.
        assert_eq!(
            client.peer_transport_parameters(),
            Some(b"server-params".as_slice())
        );
    }

    #[test]
    fn real_tls13_handshake_completes_and_installs_one_rtt_keys() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");

        // Distinct, non-empty transport-parameter blobs prove they cross.
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(!client.is_complete());
        assert!(!server.is_complete());

        drive_to_completion(&mut client, &mut server);

        // Both sides reached a verified, completed TLS-1.3 handshake.
        assert!(client.is_complete(), "client handshake incomplete");
        assert!(server.is_complete(), "server handshake incomplete");

        // 1-RTT (application) keys were derived from the wire transcript on both.
        assert!(client.one_rtt_keys_installed(), "client missing 1-RTT keys");
        assert!(server.one_rtt_keys_installed(), "server missing 1-RTT keys");

        // Transport parameters were exchanged in both directions.
        assert_eq!(
            client.peer_transport_parameters(),
            Some(b"server-params".as_slice())
        );
        assert_eq!(
            server.peer_transport_parameters(),
            Some(b"client-params".as_slice())
        );
    }

    #[test]
    fn real_tls13_handshake_completes_with_exact_pinned_leaf() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![leaf_cert()], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        drive_to_completion(&mut client, &mut server);

        assert!(client.is_complete(), "client handshake incomplete");
        assert!(server.is_complete(), "server handshake incomplete");
        assert!(client.one_rtt_keys_installed() && server.one_rtt_keys_installed());
    }

    #[test]
    fn exact_leaf_shape_enforces_validity_bounds() {
        let leaf = leaf_cert();
        let server_name = ServerName::try_from("localhost").expect("server name");

        let not_yet_valid = verify_pinned_end_entity_shape(
            &leaf,
            &server_name,
            UnixTime::since_unix_epoch(Duration::from_secs(1)),
        )
        .expect_err("future certificate must fail");
        assert!(matches!(
            not_yet_valid,
            RustlsError::InvalidCertificate(CertificateError::NotValidYet)
        ));

        let expired = verify_pinned_end_entity_shape(
            &leaf,
            &server_name,
            UnixTime::since_unix_epoch(Duration::from_secs(5_000_000_000)),
        )
        .expect_err("expired certificate must fail");
        assert!(matches!(
            expired,
            RustlsError::InvalidCertificate(CertificateError::Expired)
        ));
    }

    #[test]
    fn exact_leaf_shape_requires_server_auth_and_digital_signature() {
        let server_name = ServerName::try_from("localhost").expect("server name");

        let wrong_eku = mutate_extension_value(leaf_cert(), "2.5.29.37", |value| {
            let final_oid_byte = value.last_mut().expect("EKU value");
            assert_eq!(*final_oid_byte, 1, "fixture must carry serverAuth");
            *final_oid_byte = 2;
        });
        let wrong_eku_error =
            verify_pinned_end_entity_shape(&wrong_eku, &server_name, fixture_valid_time())
                .expect_err("clientAuth-only leaf must fail");
        assert!(matches!(
            wrong_eku_error,
            RustlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        ));

        let wrong_ku = mutate_extension_value(leaf_cert(), "2.5.29.15", |value| {
            *value.last_mut().expect("KeyUsage value") = 0;
        });
        let wrong_ku_error =
            verify_pinned_end_entity_shape(&wrong_ku, &server_name, fixture_valid_time())
                .expect_err("leaf without digitalSignature must fail");
        assert!(matches!(
            wrong_ku_error,
            RustlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        ));
    }

    #[test]
    fn exact_leaf_shape_rejects_missing_eku_and_trailing_der() {
        let server_name = ServerName::try_from("localhost").expect("server name");

        let missing_eku_error =
            verify_pinned_end_entity_shape(&cert_without_eku(), &server_name, fixture_valid_time())
                .expect_err("pinned leaf without explicit serverAuth must fail");
        assert!(matches!(
            missing_eku_error,
            RustlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        ));

        let mut trailing = leaf_cert().as_ref().to_vec();
        trailing.push(0);
        let trailing_error = verify_pinned_end_entity_shape(
            &CertificateDer::from(trailing),
            &server_name,
            fixture_valid_time(),
        )
        .expect_err("trailing DER must fail");
        assert!(matches!(
            trailing_error,
            RustlsError::InvalidCertificate(CertificateError::BadEncoding)
        ));
    }

    #[test]
    fn exact_leaf_fallback_never_overrides_standard_signature_or_name_errors() {
        let mut bad_signature = leaf_cert().as_ref().to_vec();
        let final_signature_byte = bad_signature.last_mut().expect("certificate byte");
        *final_signature_byte ^= 1;
        let bad_signature = CertificateDer::from(bad_signature);
        let verifier = test_server_verifier(vec![ca_cert()], vec![bad_signature.clone()]);
        let server_name = ServerName::try_from("localhost").expect("server name");
        let signature_error = verifier
            .verify_server_cert(&bad_signature, &[], &server_name, &[], fixture_valid_time())
            .expect_err("exact pin must not bypass bad chain signature");
        assert!(matches!(
            signature_error,
            RustlsError::InvalidCertificate(CertificateError::BadSignature)
        ));

        let leaf = leaf_cert();
        let verifier = test_server_verifier(vec![ca_cert()], vec![leaf.clone()]);
        let wrong_name = ServerName::try_from("not-localhost.example").expect("server name");
        let name_error = verifier
            .verify_server_cert(&leaf, &[], &wrong_name, &[], fixture_valid_time())
            .expect_err("exact pin must not bypass standard name rejection");
        assert!(matches!(
            name_error,
            RustlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            )
        ));
    }

    #[test]
    fn exact_pinned_leaf_still_rejects_wrong_server_name() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![leaf_cert()], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("not-localhost.example").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(
            client_rejects_server(&mut client, &mut server),
            "client must reject a pinned leaf with the wrong SAN"
        );
        assert!(
            !client.is_complete(),
            "client must not complete against a wrong-name pinned leaf"
        );
    }

    #[test]
    fn handshake_fails_closed_when_client_does_not_trust_server() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        // Client trusts NO roots: the config still builds, but verification of the
        // server's certificate must fail during the handshake (fail-closed), and
        // the client must never reach completion.
        let client_cfg = client_config(Vec::new(), alpn).expect("client config builds w/o roots");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(
            client_rejects_server(&mut client, &mut server),
            "client must reject the untrusted server certificate"
        );
        assert!(
            !client.is_complete(),
            "client must not complete against an untrusted server"
        );
    }

    // -----------------------------------------------------------------------
    // GH#69 / GH#70: header protection and coalesced datagrams.
    // -----------------------------------------------------------------------

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// RFC 9001 Appendix A: the client-chosen Destination Connection ID both
    /// sides derive Initial keys from.
    const RFC9001_DCID: &str = "8394c8f03e515708";
    /// RFC 9001 A.2: unprotected client Initial header (packet number 2, 4 bytes).
    const RFC9001_A2_HEADER: &str = "c300000001088394c8f03e5157080000449e00000002";
    /// RFC 9001 A.2: the CRYPTO frame; PADDING frames fill the payload to 1162 bytes.
    const RFC9001_A2_CRYPTO_FRAME: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113",
        "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1",
        "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806",
        "048000ffff",
    );
    /// RFC 9001 A.2: the complete protected client Initial (1200 bytes).
    const RFC9001_A2_PROTECTED_PACKET: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c",
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89",
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e",
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7",
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7",
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf",
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2",
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd",
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07",
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d",
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723",
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd",
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
    );
    /// RFC 9001 A.3: unprotected server Initial header (packet number 1, 2 bytes).
    const RFC9001_A3_HEADER: &str = "c1000000010008f067a5502a4262b50040750001";
    /// RFC 9001 A.3: ACK + CRYPTO payload, no padding.
    const RFC9001_A3_PAYLOAD: &str = concat!(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200",
        "130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00",
        "020304",
    );
    /// RFC 9001 A.3: the complete protected server Initial (135 bytes).
    const RFC9001_A3_PROTECTED_PACKET: &str = concat!(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3",
        "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
    );

    fn rfc9001_client() -> QuicHandshakeDriver {
        let client_cfg =
            client_config(vec![ca_cert()], vec![ATP_QUIC_ALPN.to_vec()]).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            Vec::new(),
        )
        .expect("client driver");
        client
            .install_initial_keys(&hex(RFC9001_DCID))
            .expect("client initial keys");
        client
    }

    fn rfc9001_server() -> QuicHandshakeDriver {
        let server_cfg = server_config(vec![leaf_cert()], leaf_key(), vec![ATP_QUIC_ALPN.to_vec()])
            .expect("server config");
        let mut server =
            QuicHandshakeDriver::server(server_cfg, Vec::new()).expect("server driver");
        server
            .install_initial_keys(&hex(RFC9001_DCID))
            .expect("server initial keys");
        server
    }

    fn long_prefix(packet: &[u8]) -> ProtectedLongHeaderPrefix {
        match ProtectedHeaderPrefix::decode(packet, 0).expect("protected prefix") {
            ProtectedHeaderPrefix::Long(prefix) => prefix,
            other => panic!("expected a long header, got {other:?}"),
        }
    }

    fn failure_code(error: &QuicTlsError) -> &'static str {
        match error {
            QuicTlsError::CryptoProviderFailure { provider, code } => {
                assert_eq!(*provider, "rustls-quic-handshake");
                code
            }
            other => panic!("expected a handshake failure code, got {other:?}"),
        }
    }

    #[test]
    fn rfc9001_a2_client_initial_protects_to_the_published_packet() {
        let mut client = rfc9001_client();
        let header = hex(RFC9001_A2_HEADER);
        let mut payload = hex(RFC9001_A2_CRYPTO_FRAME);
        payload.resize(1162, 0x00);
        let packet = client
            .protect_long_header_packet(PacketProtectionSpace::Initial, &header, 2, &payload)
            .expect("protect A.2");
        let expected = hex(RFC9001_A2_PROTECTED_PACKET);
        assert_eq!(packet.len(), 1200);
        assert_eq!(&packet[..22], &expected[..22], "protected header bytes");
        assert_eq!(packet, expected, "RFC 9001 A.2 protected client Initial");

        // The server removes header protection with the client's hp key,
        // reconstructs the packet number and authenticates the payload.
        let mut server = rfc9001_server();
        let prefix = long_prefix(&packet);
        assert_eq!(prefix.payload_length, 1182);
        assert_eq!(prefix.packet_number_offset, 18);
        assert_eq!(prefix.packet_len(packet.len()).expect("bounded"), 1200);
        let (recovered, plaintext) = server
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("server unprotects A.2");
        assert_eq!(recovered.packet_type, LongPacketType::Initial);
        assert_eq!(recovered.packet_number, 2);
        assert_eq!(recovered.packet_number_len, 4);
        assert_eq!(recovered.dst_cid.as_bytes(), &hex(RFC9001_DCID)[..]);
        assert!(recovered.src_cid.is_empty());
        assert_eq!(plaintext, payload);
    }

    #[test]
    fn rfc9001_a3_server_initial_protects_to_the_published_packet() {
        let mut server = rfc9001_server();
        let header = hex(RFC9001_A3_HEADER);
        let payload = hex(RFC9001_A3_PAYLOAD);
        let packet = server
            .protect_long_header_packet(PacketProtectionSpace::Initial, &header, 1, &payload)
            .expect("protect A.3");
        assert_eq!(
            packet,
            hex(RFC9001_A3_PROTECTED_PACKET),
            "RFC 9001 A.3 protected server Initial"
        );

        let mut client = rfc9001_client();
        let prefix = long_prefix(&packet);
        assert_eq!(prefix.payload_length, 0x75);
        assert_eq!(
            prefix.packet_len(packet.len()).expect("bounded"),
            packet.len()
        );
        let (recovered, plaintext) = client
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("client unprotects A.3");
        assert_eq!(
            recovered.packet_number, 1,
            "2-byte packet number reconstructed"
        );
        assert_eq!(recovered.packet_number_len, 2);
        assert!(recovered.dst_cid.is_empty());
        assert_eq!(recovered.src_cid.as_bytes(), &hex("f067a5502a4262b5")[..]);
        assert_eq!(plaintext, payload);
    }

    /// Planted negatives: every protected bit is bound to the AEAD.
    ///
    /// Flipping a masked first-byte bit, a protected packet-number byte, a
    /// ciphertext byte or a tag byte must fail authentication — and that
    /// failure is a live-key failure, never "stale".
    #[test]
    fn rfc9001_a2_planted_bit_flips_fail_authentication_and_are_not_stale() {
        let mut server = rfc9001_server();
        let packet = hex(RFC9001_A2_PROTECTED_PACKET);
        let prefix = long_prefix(&packet);
        let cases: [(&str, usize, u8); 5] = [
            ("masked packet-number-length bit", 0, 0x01),
            ("masked reserved bit", 0, 0x08),
            ("protected packet-number byte", 21, 0x80),
            ("ciphertext byte", 400, 0x01),
            ("authentication tag byte", packet.len() - 1, 0x01),
        ];
        for (label, index, bit) in cases {
            let mut tampered = packet.clone();
            tampered[index] ^= bit;
            let err = server
                .unprotect_long_header_packet(&prefix, &tampered)
                .expect_err(label);
            assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE, "{label}");
            assert!(
                !is_stale_handshake_packet_error(&err),
                "{label}: a live-key authentication failure is not stale traffic"
            );
            let err = server
                .recv_handshake_packet(&tampered)
                .expect_err("datagram entry point rejects it too");
            assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE, "{label}");
            assert!(!is_stale_handshake_packet_error(&err), "{label}");
        }
        let (recovered, _) = server
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("the untampered packet still authenticates afterwards");
        assert_eq!(recovered.packet_number, 2);
    }

    fn protected_pair() -> (QuicHandshakeDriver, QuicHandshakeDriver) {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");
        (client, server)
    }

    /// GH#70 / RFC 9000 §12.2: a coalesced Initial + Handshake datagram is
    /// processed completely.
    ///
    /// Each packet is bounded by its own Length field, the Handshake keys the
    /// first packet unlocks are installed before the second is tried, and
    /// output TLS emits mid-datagram is not lost.
    #[test]
    fn coalesced_initial_and_handshake_datagram_is_fully_processed() {
        let (mut client, mut server) = protected_pair();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let mut client_flight = client.pump_outbound().expect("client flight");
        assert_eq!(client_flight.len(), 1);
        let client_initial = client
            .assemble_handshake_packet(&client_flight.remove(0), dcid, client_scid, 0)
            .expect("client Initial");
        server
            .recv_handshake_packet(&client_initial)
            .expect("server accepts ClientHello");

        let server_flight = server.pump_outbound().expect("server flight");
        let mut datagram = Vec::new();
        let mut boundaries = Vec::new();
        let mut handshake_packets = 0usize;
        for (packet_number, segment) in server_flight
            .iter()
            .filter(|segment| segment.level != HandshakeLevel::OneRtt)
            .enumerate()
        {
            handshake_packets += usize::from(segment.level == HandshakeLevel::Handshake);
            let packet = server
                .assemble_handshake_packet(segment, client_scid, server_scid, packet_number as u64)
                .expect("server packet");
            datagram.extend_from_slice(&packet);
            boundaries.push(datagram.len());
        }
        assert!(
            boundaries.len() >= 2 && handshake_packets >= 1,
            "the server flight must span Initial and Handshake packets: {boundaries:?}"
        );
        // A duplicate of the Initial after the Handshake flight forces the
        // driver to stage TLS output (the client Finished) mid-datagram.
        let duplicate_start = datagram.len();
        let duplicate_initial = datagram[..boundaries[0]].to_vec();
        datagram.extend_from_slice(&duplicate_initial);
        // Trailing datagram padding must be ignored.
        datagram.extend_from_slice(&[0u8; 7]);

        // Each coalesced packet is bounded by its own Length field, not the
        // datagram end.
        let first = long_prefix(&datagram);
        assert_eq!(first.packet_type, LongPacketType::Initial);
        assert_eq!(
            first.packet_len(datagram.len()).expect("first bound"),
            boundaries[0]
        );
        let second = long_prefix(&datagram[boundaries[0]..]);
        assert_eq!(second.packet_type, LongPacketType::Handshake);
        assert_eq!(
            second
                .packet_len(datagram.len() - boundaries[0])
                .expect("second bound")
                + boundaries[0],
            boundaries[1]
        );
        let duplicate = long_prefix(&datagram[duplicate_start..]);
        assert_eq!(duplicate.packet_type, LongPacketType::Initial);

        assert!(!client.handshake_keys_installed());
        let peer = client
            .recv_handshake_packet(&datagram)
            .expect("coalesced datagram");
        assert_eq!(peer, server_scid);
        assert!(
            client.handshake_keys_installed(),
            "the ServerHello in the first packet installed Handshake keys mid-datagram"
        );
        assert!(
            client.handshake_recv_packet_numbers[0].contains(&0),
            "Initial packet 0 authenticated"
        );
        assert_eq!(
            client.handshake_recv_packet_numbers[1].len(),
            handshake_packets,
            "every coalesced Handshake packet authenticated"
        );
        assert!(
            client.is_complete(),
            "the client read the server Finished from the coalesced Handshake packet"
        );
        assert!(
            client
                .staged_segments
                .iter()
                .any(|segment| segment.level == HandshakeLevel::Handshake),
            "the client Finished emitted between coalesced packets is staged, not dropped"
        );
        let client_flight = client.pump_outbound().expect("client pump");
        assert!(
            client_flight
                .iter()
                .any(|segment| segment.level == HandshakeLevel::Handshake),
            "pump_outbound hands out the staged Finished"
        );
        assert!(client.staged_segments.is_empty());

        // The staged flight is a real Finished: the server completes on it.
        for (client_pn, segment) in (1u64..).zip(
            client_flight
                .iter()
                .filter(|segment| segment.level != HandshakeLevel::OneRtt),
        ) {
            let packet = client
                .assemble_handshake_packet(segment, server_scid, client_scid, client_pn)
                .expect("client packet");
            server
                .recv_handshake_packet(&packet)
                .expect("server accepts client Finished");
        }
        assert!(server.is_complete());
    }

    /// GH#70: `recv_handshake_packet` failures are classified by key state.
    /// Only traffic this driver holds no live keys for is stale; a bad tag
    /// under live keys surfaces as `packet_unprotect`.
    #[test]
    fn handshake_unprotect_failures_are_classified_by_key_state() {
        let (mut client, mut server) = protected_pair();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let mut client_flight = client.pump_outbound().expect("client flight");
        let client_initial = client
            .assemble_handshake_packet(&client_flight.remove(0), dcid, client_scid, 0)
            .expect("client Initial");
        server
            .recv_handshake_packet(&client_initial)
            .expect("server accepts ClientHello");
        let server_flight = server.pump_outbound().expect("server flight");
        let server_initial_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Initial)
            .expect("ServerHello segment");
        let server_handshake_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
            .expect("server Handshake segment");
        let server_initial = server
            .assemble_handshake_packet(server_initial_segment, client_scid, server_scid, 0)
            .expect("server Initial");
        let server_handshake = server
            .assemble_handshake_packet(server_handshake_segment, client_scid, server_scid, 1)
            .expect("server Handshake");

        // (1) Keys not derived yet: a Handshake packet before the ServerHello
        // was processed. Stale-class (ignorable), TLS state untouched.
        let err = client
            .recv_handshake_packet(&server_handshake)
            .expect_err("no Handshake keys yet");
        assert_eq!(failure_code(&err), PACKET_KEYS_UNAVAILABLE_CODE);
        assert!(is_stale_handshake_packet_error(&err));
        assert!(client.handshake_recv_packet_numbers[1].is_empty());

        // (2) Live keys, corrupted tag: a real authentication failure.
        let mut forged = server_initial.clone();
        *forged.last_mut().expect("tag byte") ^= 0x01;
        let err = client
            .recv_handshake_packet(&forged)
            .expect_err("bad tag under live Initial keys");
        assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE);
        assert!(
            !is_stale_handshake_packet_error(&err),
            "a live-key authentication failure must surface, not retry"
        );
        assert!(client.handshake_recv_packet_numbers[0].is_empty());

        // (3) The same packets in order authenticate once the keys exist.
        client
            .recv_handshake_packet(&server_initial)
            .expect("ServerHello");
        let _ = client.pump_outbound().expect("install Handshake keys");
        assert!(client.handshake_keys_installed());
        client
            .recv_handshake_packet(&server_handshake)
            .expect("Handshake packet after keys exist");

        // (4) Keys discarded: a retransmitted client Initial after the server
        // dropped its Initial keys is stale-class.
        server
            .provider_mut()
            .discard_keys(PacketProtectionSpace::Initial)
            .expect("discard Initial keys");
        let err = server
            .recv_handshake_packet(&client_initial)
            .expect_err("Initial after Initial keys were discarded");
        assert_eq!(failure_code(&err), PACKET_KEYS_DISCARDED_CODE);
        assert!(is_stale_handshake_packet_error(&err));

        // (5) A coalesced datagram whose first packet is stale but whose second
        // authenticates is a success; one that only contains stale packets
        // reports the first packet's classification.
        let mut mixed = client_initial.clone();
        let client_flight = client.pump_outbound().expect("client Finished");
        let finished = client_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
            .expect("client Finished segment");
        let client_handshake = client
            .assemble_handshake_packet(finished, server_scid, client_scid, 1)
            .expect("client Handshake");
        mixed.extend_from_slice(&client_handshake);
        assert_eq!(
            server
                .recv_handshake_packet(&mixed)
                .expect("stale Initial + live Handshake"),
            client_scid
        );
        assert!(server.is_complete());
        let mut only_stale = client_initial.clone();
        only_stale.extend_from_slice(&client_initial);
        let err = server
            .recv_handshake_packet(&only_stale)
            .expect_err("two stale packets");
        assert_eq!(failure_code(&err), PACKET_KEYS_DISCARDED_CODE);
        assert!(is_stale_handshake_packet_error(&err));
    }

    /// Encode a long header for `plaintext` and protect the packet with
    /// `driver`'s send keys, as anyone holding those keys could.
    fn protect_forged_long_packet(
        driver: &mut QuicHandshakeDriver,
        packet_type: LongPacketType,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let space = long_packet_type_space(packet_type).expect("long-header space");
        let header = PacketHeader::Long(LongHeader {
            packet_type,
            version: 1,
            dst_cid,
            src_cid,
            token: Vec::new(),
            payload_length: u64::from(HANDSHAKE_PACKET_NUMBER_LEN)
                + plaintext.len() as u64
                + QUIC_AEAD_TAG_LEN as u64,
            packet_number,
            packet_number_len: HANDSHAKE_PACKET_NUMBER_LEN,
        });
        let mut header_bytes = Vec::new();
        header
            .encode(&mut header_bytes)
            .expect("encode long header");
        driver
            .protect_long_header_packet(space, &header_bytes, packet_number, plaintext)
            .expect("protect forged packet")
    }

    fn assert_discarded(server: &mut QuicHandshakeDriver, packet: &[u8], code: &str) {
        let err = server.recv_handshake_packet(packet).expect_err(code);
        assert_eq!(failure_code(&err), code);
        assert!(
            is_unauthenticated_handshake_packet_error(&err),
            "{code}: the drive loops must discard it"
        );
        assert!(
            !is_stale_handshake_packet_error(&err),
            "{code}: a forgery must not earn a retransmission"
        );
    }

    /// A client, the server, and a second client for the same Destination
    /// Connection ID: it derives the same Initial keys, as an attacker who saw
    /// the client's first Initial can. Returns them with the client's
    /// ClientHello split into two halves, the first sent at offset 0.
    fn forgery_setup() -> (
        QuicHandshakeDriver,
        QuicHandshakeDriver,
        QuicHandshakeDriver,
        HandshakeSegment,
        HandshakeSegment,
    ) {
        let (mut client, server) = protected_pair();
        let (forger, _) = protected_pair();
        let client_hello = client
            .pump_outbound()
            .expect("client flight")
            .into_iter()
            .find(|segment| segment.level == HandshakeLevel::Initial)
            .expect("ClientHello");
        let split = client_hello.data.len() / 2;
        let first_half = HandshakeSegment {
            level: HandshakeLevel::Initial,
            data: client_hello.data[..split].to_vec(),
        };
        let second_half = HandshakeSegment {
            level: HandshakeLevel::Initial,
            data: client_hello.data[split..].to_vec(),
        };
        (client, server, forger, first_half, second_half)
    }

    /// `segment`'s bytes in a CRYPTO frame at `offset`, then a frame that
    /// does not decode (a CRYPTO type byte with no fields).
    fn crypto_then_undecodable_frame(segment: &HandshakeSegment, offset: u64) -> Vec<u8> {
        let mut payload = BytesMut::new();
        QuicFrame::Crypto {
            offset: VarInt::from_u64_unchecked(offset),
            data: Bytes::copy_from_slice(&segment.data),
        }
        .encode(&mut payload)
        .expect("encode CRYPTO");
        let mut plaintext = payload.to_vec();
        plaintext.push(0x06);
        plaintext
    }

    const CLIENT_SCID: &[u8] = &[0x11, 0x22, 0x33, 0x44];
    const FORGED_SCID: &[u8] = &[0x99, 0x99, 0x99, 0x99];

    /// br-asupersync-5f1fcj LOW 4 (RFC 9000 section 7.2): a forged Initial that
    /// arrives first and is refused does not pin its Source Connection ID, so
    /// the real client's packets are still accepted. A later packet under
    /// another Source Connection ID is discarded.
    #[test]
    fn a_refused_forged_initial_does_not_pin_its_source_connection_id() {
        let (mut client, mut server, mut forger, first_half, second_half) = forgery_setup();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(CLIENT_SCID).expect("client scid");
        let forged_scid = ConnectionId::new(FORGED_SCID).expect("forged scid");

        let forged = protect_forged_long_packet(
            &mut forger,
            LongPacketType::Initial,
            dcid,
            forged_scid,
            0,
            &crypto_then_undecodable_frame(&first_half, 0),
        );
        let err = server
            .recv_handshake_packet(&forged)
            .expect_err("malformed forged first Initial");
        assert!(
            server.peer_connection_id().is_none(),
            "a refused packet must not pin its Source Connection ID"
        );
        assert_eq!(failure_code(&err), INITIAL_FRAME_DECODE_CODE);

        for (segment, packet_number) in [(&first_half, 0), (&second_half, 1)] {
            let packet = client
                .assemble_handshake_packet(segment, dcid, client_scid, packet_number)
                .expect("client Initial");
            assert_eq!(
                server.recv_handshake_packet(&packet).expect("real Initial"),
                client_scid
            );
        }
        assert_eq!(server.peer_connection_id(), Some(client_scid));

        let forged = forger
            .assemble_handshake_packet_at(&first_half, 0, dcid, forged_scid, 5)
            .expect("forged Initial with another source CID");
        assert_discarded(&mut server, &forged, PEER_CONNECTION_ID_CHANGED_CODE);
        assert_eq!(server.peer_connection_id(), Some(client_scid));
        drive_to_completion(&mut client, &mut server);
    }

    /// br-asupersync-5f1fcj LOW 4: a forged Initial whose CRYPTO bytes
    /// contradict bytes the server holds behind a gap is discarded, and the
    /// real handshake completes.
    #[test]
    fn a_forged_initial_contradicting_buffered_crypto_is_discarded() {
        let (mut client, mut server, mut forger, first_half, second_half) = forgery_setup();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(CLIENT_SCID).expect("client scid");
        let first = client
            .assemble_handshake_packet(&first_half, dcid, client_scid, 0)
            .expect("first Initial");
        let second = client
            .assemble_handshake_packet(&second_half, dcid, client_scid, 1)
            .expect("second Initial");
        server
            .recv_handshake_packet(&second)
            .expect("buffered behind the gap");

        let mut contradicting = second_half.clone();
        contradicting.data[0] ^= 0xff;
        let offset = u64::try_from(first_half.data.len()).expect("offset");
        let forged = forger
            .assemble_handshake_packet_at(&contradicting, offset, dcid, client_scid, 6)
            .expect("forged Initial contradicting buffered bytes");
        assert_discarded(&mut server, &forged, INITIAL_CRYPTO_REJECTED_CODE);
        assert_eq!(
            server.received_handshake_packet_numbers(HandshakeLevel::Initial),
            vec![1]
        );

        server
            .recv_handshake_packet(&first)
            .expect("real first half");
        drive_to_completion(&mut client, &mut server);
    }

    /// br-asupersync-5f1fcj LOW 4: a forged Initial with a frame that does not
    /// decode is discarded before any of its frames takes effect, even a valid
    /// CRYPTO frame ahead of the bad one that would complete the ClientHello.
    #[test]
    fn a_malformed_forged_initial_applies_none_of_its_frames() {
        let (mut client, mut server, mut forger, first_half, second_half) = forgery_setup();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(CLIENT_SCID).expect("client scid");
        let first = client
            .assemble_handshake_packet(&first_half, dcid, client_scid, 0)
            .expect("first Initial");
        let second = client
            .assemble_handshake_packet(&second_half, dcid, client_scid, 1)
            .expect("second Initial");
        server
            .recv_handshake_packet(&second)
            .expect("buffered behind the gap");

        let forged = protect_forged_long_packet(
            &mut forger,
            LongPacketType::Initial,
            dcid,
            client_scid,
            7,
            &crypto_then_undecodable_frame(&first_half, 0),
        );
        let err = server
            .recv_handshake_packet(&forged)
            .expect_err("malformed forged Initial");
        assert!(
            server
                .pump_outbound()
                .expect("pump after the forgery")
                .is_empty(),
            "the forged packet's CRYPTO frame must not reach TLS"
        );
        assert_eq!(failure_code(&err), INITIAL_FRAME_DECODE_CODE);
        assert!(is_unauthenticated_handshake_packet_error(&err));
        assert_eq!(
            server.received_handshake_packet_numbers(HandshakeLevel::Initial),
            vec![1]
        );

        server
            .recv_handshake_packet(&first)
            .expect("real first half");
        drive_to_completion(&mut client, &mut server);
    }

    /// Handshake keys are known only to the peers, so an undecodable frame in a
    /// Handshake packet is the peer's protocol error and still fails the call.
    #[test]
    fn a_malformed_handshake_packet_still_fails_the_handshake() {
        let (mut client, mut server, _, first_half, second_half) = forgery_setup();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(CLIENT_SCID).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");
        for (segment, packet_number) in [(&first_half, 0), (&second_half, 1)] {
            let packet = client
                .assemble_handshake_packet(segment, dcid, client_scid, packet_number)
                .expect("client Initial");
            server.recv_handshake_packet(&packet).expect("real Initial");
        }
        drive_to_completion(&mut client, &mut server);

        // Four PINGs, then a CRYPTO type byte with no fields.
        let packet = protect_forged_long_packet(
            &mut client,
            LongPacketType::Handshake,
            server_scid,
            client_scid,
            9,
            &[0x01, 0x01, 0x01, 0x01, 0x06],
        );
        let err = server
            .recv_handshake_packet(&packet)
            .expect_err("malformed Handshake packet");
        assert_eq!(failure_code(&err), "frame_decode");
        assert!(!is_unauthenticated_handshake_packet_error(&err));
    }

    /// TLS alert 120, no_application_protocol (RFC 7301 section 3.2), as a
    /// QUIC CRYPTO_ERROR (RFC 9001 section 4.8).
    const NO_APPLICATION_PROTOCOL_CLOSE: u64 = 0x0100 + 120;

    /// A client offering ATP's ALPN and a server offering only `server_alpn`.
    fn alpn_pair(server_alpn: &[u8]) -> (QuicHandshakeDriver, QuicHandshakeDriver) {
        let client = QuicHandshakeDriver::client(
            client_config(vec![ca_cert()], vec![ATP_QUIC_ALPN.to_vec()]).expect("client config"),
            ServerName::try_from("localhost").expect("server name"),
            Vec::new(),
        )
        .expect("client driver");
        let server = QuicHandshakeDriver::server(
            server_config(vec![leaf_cert()], leaf_key(), vec![server_alpn.to_vec()])
                .expect("server config"),
            Vec::new(),
        )
        .expect("server driver");
        (client, server)
    }

    /// br-asupersync-2eqmd2 M3: a server that refuses the client's ALPN tells
    /// it with CONNECTION_CLOSE (CRYPTO_ERROR) in an Initial packet, and the
    /// client's handshake ends on that close.
    #[test]
    fn an_alpn_refusal_reaches_the_client_as_a_crypto_error_close() {
        let (mut client, mut server) = alpn_pair(b"h3");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server keys");
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11; 8]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55; 8]).expect("server scid");
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("address");

        let segments = client.pump_outbound().expect("client pump");
        let hello = client
            .assemble_handshake_packet(&segments[0], dcid, client_scid, 0)
            .expect("ClientHello");
        let refused = server
            .recv_handshake_packet(&hello)
            .expect_err("no common ALPN");
        assert_eq!(failure_code(&refused), "read_hs_fatal_alert");

        let mut server_packet_number = 0;
        let close =
            server.assemble_crypto_error_close(peer, server_scid, &mut server_packet_number);
        assert_eq!(close.len(), 1, "no Handshake keys: Initial only");
        assert_eq!(server_packet_number, 1);
        assert_eq!(close[0].dst_addr, peer);
        let prefix = long_prefix(&close[0].data);
        assert_eq!(prefix.packet_type, LongPacketType::Initial);
        assert_eq!(
            prefix.dst_cid, client_scid,
            "addressed to the refused packet's source"
        );
        assert_eq!(prefix.src_cid, server_scid);

        let closed = client
            .recv_handshake_packet(&close[0].data)
            .expect_err("the server closed");
        assert_eq!(failure_code(&closed), PEER_CRYPTO_ERROR_CLOSE_CODE);
        assert!(!is_unauthenticated_handshake_packet_error(&closed));
        assert!(!is_stale_handshake_packet_error(&closed));
        assert_eq!(
            client.peer_close_error_code(),
            Some(NO_APPLICATION_PROTOCOL_CLOSE)
        );
        assert!(
            client
                .assemble_crypto_error_close(peer, client_scid, &mut 0)
                .is_empty(),
            "a peer's close raises no alert here, so it is not answered"
        );
    }

    /// br-asupersync-2eqmd2 M3: a client that rejects the server's certificate
    /// already holds Handshake keys, so it closes in Handshake space only, and
    /// the server's handshake ends on that close with the client's alert.
    #[test]
    fn a_rejected_certificate_reaches_the_server_as_a_handshake_space_close() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let mut client = QuicHandshakeDriver::client(
            // No trust anchor, so the server's chain fails verification.
            client_config(Vec::new(), alpn.clone()).expect("client config"),
            ServerName::try_from("localhost").expect("server name"),
            Vec::new(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(
            server_config(vec![leaf_cert()], leaf_key(), alpn).expect("server config"),
            Vec::new(),
        )
        .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server keys");
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11; 8]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55; 8]).expect("server scid");
        let server_addr: SocketAddr = "127.0.0.1:4433".parse().expect("address");

        let segments = client.pump_outbound().expect("client pump");
        let hello = client
            .assemble_handshake_packet(&segments[0], dcid, client_scid, 0)
            .expect("ClientHello");
        server.recv_handshake_packet(&hello).expect("ClientHello");
        let mut refused = None;
        let flight = server.pump_outbound().expect("server pump");
        let long_header = flight
            .iter()
            .filter(|segment| segment.level != HandshakeLevel::OneRtt);
        for (packet_number, segment) in (0..).zip(long_header) {
            let packet = server
                .assemble_handshake_packet(segment, client_scid, server_scid, packet_number)
                .expect("server packet");
            match client.recv_handshake_packet(&packet) {
                // Install the Handshake keys the ServerHello unlocked.
                Ok(_) => {
                    client.pump_outbound().expect("client pump");
                }
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
        }
        let refused = refused.expect("the client rejects the untrusted chain");
        assert_eq!(failure_code(&refused), "read_hs_fatal_alert");
        let alert = client.tls.alert().expect("TLS raised an alert");

        let mut client_packet_number = 1;
        let close =
            client.assemble_crypto_error_close(server_addr, client_scid, &mut client_packet_number);
        assert_eq!(close.len(), 1, "Handshake keys: Handshake space only");
        let prefix = long_prefix(&close[0].data);
        assert_eq!(prefix.packet_type, LongPacketType::Handshake);
        assert_eq!(prefix.dst_cid, server_scid);

        let closed = server
            .recv_handshake_packet(&close[0].data)
            .expect_err("the client closed");
        assert_eq!(failure_code(&closed), PEER_CRYPTO_ERROR_CLOSE_CODE);
        assert_eq!(
            server.peer_close_error_code(),
            Some(0x0100 + u64::from(u8::from(alert)))
        );
    }

    /// Review r29-e8 of 168379675 (M1): mainstream servers coalesce their first
    /// flight as `[Initial(ServerHello)][Handshake(EE, Certificate, CV, Finished)]`.
    /// A client that rejects the chain in the Handshake packet must still end
    /// the call with the TLS alert, so its CRYPTO_ERROR close reaches the server
    /// (br-asupersync-2eqmd2 M3). The broken code swallowed every follower error
    /// once the Initial had authenticated: the call returned `Ok`, no close was
    /// sent, and the client retransmitted until its flight budget ran out.
    #[test]
    fn a_rejected_certificate_in_a_coalesced_server_flight_fails_the_handshake() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let mut client = QuicHandshakeDriver::client(
            // No trust anchor, so the server's chain fails verification.
            client_config(Vec::new(), alpn.clone()).expect("client config"),
            ServerName::try_from("localhost").expect("server name"),
            Vec::new(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(
            server_config(vec![leaf_cert()], leaf_key(), alpn).expect("server config"),
            Vec::new(),
        )
        .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server keys");
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11; 8]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55; 8]).expect("server scid");
        let server_addr: SocketAddr = "127.0.0.1:4433".parse().expect("address");

        let segments = client.pump_outbound().expect("client pump");
        let hello = client
            .assemble_handshake_packet(&segments[0], dcid, client_scid, 0)
            .expect("ClientHello");
        server.recv_handshake_packet(&hello).expect("ClientHello");
        // The server's whole first flight in one datagram.
        let mut datagram = Vec::new();
        let mut levels = Vec::new();
        let flight = server.pump_outbound().expect("server pump");
        let long_header = flight
            .iter()
            .filter(|segment| segment.level != HandshakeLevel::OneRtt);
        for (packet_number, segment) in (0..).zip(long_header) {
            let packet = server
                .assemble_handshake_packet(segment, client_scid, server_scid, packet_number)
                .expect("server packet");
            datagram.extend_from_slice(&packet);
            levels.push(segment.level);
        }
        assert_eq!(levels.first(), Some(&HandshakeLevel::Initial));
        assert!(levels.contains(&HandshakeLevel::Handshake), "{levels:?}");

        let refused = client
            .recv_handshake_packet(&datagram)
            .expect_err("the chain in the coalesced Handshake packet is rejected");
        assert_eq!(failure_code(&refused), "read_hs_fatal_alert");
        let alert = client.tls.alert().expect("TLS raised an alert");

        let mut client_packet_number = 1;
        let close =
            client.assemble_crypto_error_close(server_addr, client_scid, &mut client_packet_number);
        assert_eq!(close.len(), 1, "Handshake keys: Handshake space only");
        let prefix = long_prefix(&close[0].data);
        assert_eq!(prefix.packet_type, LongPacketType::Handshake);
        assert_eq!(prefix.dst_cid, server_scid);
        let closed = server
            .recv_handshake_packet(&close[0].data)
            .expect_err("the client closed");
        assert_eq!(failure_code(&closed), PEER_CRYPTO_ERROR_CLOSE_CODE);
        assert_eq!(
            server.peer_close_error_code(),
            Some(0x0100 + u64::from(u8::from(alert)))
        );
    }

    /// Review r29-e8 of 168379675 (M1): RFC 9000 section 12.2 says a receiver
    /// that cannot decrypt one coalesced packet must still process the rest.
    /// In `[Initial ok][Handshake, corrupted tag][Handshake ok]` only the
    /// corrupted packet is discarded. The broken code stopped at it, so the
    /// genuine Handshake packet behind it, with the server Finished, was never
    /// read: no Handshake packet number was recorded and the client did not
    /// complete.
    #[test]
    fn a_corrupted_coalesced_packet_is_discarded_and_the_rest_are_processed() {
        let (mut client, mut server) = protected_pair();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(CLIENT_SCID).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let mut client_flight = client.pump_outbound().expect("client flight");
        let client_initial = client
            .assemble_handshake_packet(&client_flight.remove(0), dcid, client_scid, 0)
            .expect("client Initial");
        server
            .recv_handshake_packet(&client_initial)
            .expect("server accepts ClientHello");
        let server_flight = server.pump_outbound().expect("server flight");
        let server_initial_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Initial)
            .expect("ServerHello segment");
        let server_handshake_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
            .expect("server Handshake segment");
        let mut datagram = server
            .assemble_handshake_packet(server_initial_segment, client_scid, server_scid, 0)
            .expect("server Initial");
        // The same CRYPTO bytes twice: under packet number 1 with a corrupted
        // tag, then intact under packet number 2.
        let mut corrupted = server
            .assemble_handshake_packet_at(server_handshake_segment, 0, client_scid, server_scid, 1)
            .expect("corrupted server Handshake");
        *corrupted.last_mut().expect("tag byte") ^= 0x01;
        datagram.extend_from_slice(&corrupted);
        let genuine = server
            .assemble_handshake_packet(server_handshake_segment, client_scid, server_scid, 2)
            .expect("server Handshake");
        datagram.extend_from_slice(&genuine);

        let peer = client
            .recv_handshake_packet(&datagram)
            .expect("the corrupted packet is discarded, not fatal");
        assert_eq!(peer, server_scid);
        assert_eq!(
            client.received_handshake_packet_numbers(HandshakeLevel::Initial),
            vec![0]
        );
        assert_eq!(
            client.received_handshake_packet_numbers(HandshakeLevel::Handshake),
            vec![2],
            "the genuine Handshake packet behind the corrupted one is processed"
        );
        assert!(client.is_complete(), "the client read the server Finished");
    }

    /// Fresh-eyes review of f08413312 (LOW-1.1): the discard holds wherever
    /// the corrupted packet sits, including first. In
    /// `[Initial, corrupted tag][Initial ok][Handshake ok]` the old code
    /// returned the first packet's PACKET_UNPROTECT_CODE before reading the
    /// genuine packets behind it.
    #[test]
    fn a_corrupted_first_coalesced_packet_is_discarded_and_the_rest_are_processed() {
        let (mut client, mut server) = protected_pair();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(CLIENT_SCID).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let mut client_flight = client.pump_outbound().expect("client flight");
        let client_initial = client
            .assemble_handshake_packet(&client_flight.remove(0), dcid, client_scid, 0)
            .expect("client Initial");
        server
            .recv_handshake_packet(&client_initial)
            .expect("server accepts ClientHello");
        let server_flight = server.pump_outbound().expect("server flight");
        let server_initial_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Initial)
            .expect("ServerHello segment");
        let server_handshake_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
            .expect("server Handshake segment");
        // The ServerHello twice: under packet number 0 with a corrupted tag,
        // then intact under packet number 1, followed by the Handshake packet.
        let mut datagram = server
            .assemble_handshake_packet_at(server_initial_segment, 0, client_scid, server_scid, 0)
            .expect("corrupted server Initial");
        *datagram.last_mut().expect("tag byte") ^= 0x01;
        let genuine_initial = server
            .assemble_handshake_packet_at(server_initial_segment, 0, client_scid, server_scid, 1)
            .expect("server Initial");
        datagram.extend_from_slice(&genuine_initial);
        let genuine_handshake = server
            .assemble_handshake_packet(server_handshake_segment, client_scid, server_scid, 0)
            .expect("server Handshake");
        datagram.extend_from_slice(&genuine_handshake);

        let peer = client
            .recv_handshake_packet(&datagram)
            .expect("the corrupted first packet is discarded, not fatal");
        assert_eq!(peer, server_scid);
        assert_eq!(
            client.received_handshake_packet_numbers(HandshakeLevel::Initial),
            vec![1]
        );
        assert_eq!(
            client.received_handshake_packet_numbers(HandshakeLevel::Handshake),
            vec![0]
        );
        assert!(client.is_complete(), "the client read the server Finished");

        // With nothing authenticated, the first discarded packet's error stands.
        let (mut client, _) = protected_pair();
        let _ = client.pump_outbound().expect("client flight");
        let mut forged = genuine_initial.clone();
        *forged.last_mut().expect("tag byte") ^= 0x01;
        forged.extend_from_slice(&forged.clone());
        let err = client
            .recv_handshake_packet(&forged)
            .expect_err("no packet authenticates");
        assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE);
    }

    /// br-asupersync-2eqmd2 M3, over UDP: a refused ALPN ends both handshake
    /// loops within a round trip. The client used to retransmit for its whole
    /// flight budget (64 PTOs of 1.5 s, 96 s); this test allows 10 s.
    #[test]
    fn a_refused_alpn_ends_both_udp_handshakes_promptly() {
        let original_cid = ConnectionId::new(DCID_BYTES).unwrap();
        let client_scid = ConnectionId::new(&[0x21; 8]).unwrap();
        let server_scid = ConnectionId::new(&[0x22; 8]).unwrap();
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("native context");
            let mut server_endpoint = loopback_endpoint(&cx).await;
            let mut client_endpoint = loopback_endpoint(&cx).await;
            let server_addr = server_endpoint.local_addr();
            let (mut client, mut server) = alpn_pair(b"h3");
            let (served, connected) = join_within(
                &cx,
                Duration::from_secs(10),
                server_handshake_over_udp(
                    &cx,
                    &mut server_endpoint,
                    &mut server,
                    original_cid,
                    server_scid,
                ),
                client_handshake_over_udp(
                    &cx,
                    &mut client_endpoint,
                    server_addr,
                    &mut client,
                    original_cid,
                    client_scid,
                ),
            )
            .await;
            let served = served
                .expect("the server's handshake ends within the bound")
                .expect_err("refused ALPN");
            assert_eq!(failure_code(&served), "read_hs_fatal_alert");
            let connected = connected
                .expect("the client's handshake ends long before its flight budget")
                .expect_err("refused ALPN");
            assert_eq!(failure_code(&connected), PEER_CRYPTO_ERROR_CLOSE_CODE);
            assert_eq!(
                client.peer_close_error_code(),
                Some(NO_APPLICATION_PROTOCOL_CLOSE)
            );
        });
    }

    async fn loopback_endpoint(cx: &Cx) -> QuicUdpEndpoint {
        QuicUdpEndpoint::bind(
            cx,
            "127.0.0.1:0".parse().unwrap(),
            crate::net::quic_native::QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap()
    }

    /// Polls `a` and `b` in one task until both finish or `limit` passes, and
    /// returns the results that arrived.
    async fn join_within<A: std::future::Future, B: std::future::Future>(
        cx: &Cx,
        limit: Duration,
        a: A,
        b: B,
    ) -> (Option<A::Output>, Option<B::Output>) {
        let mut a = std::pin::pin!(a);
        let mut b = std::pin::pin!(b);
        let mut a_out = None;
        let mut b_out = None;
        let _ = crate::time::timeout(
            cx.now(),
            limit,
            std::future::poll_fn(|task_cx| {
                if a_out.is_none() {
                    if let std::task::Poll::Ready(out) =
                        std::future::Future::poll(a.as_mut(), task_cx)
                    {
                        a_out = Some(out);
                    }
                }
                if b_out.is_none() {
                    if let std::task::Poll::Ready(out) =
                        std::future::Future::poll(b.as_mut(), task_cx)
                    {
                        b_out = Some(out);
                    }
                }
                if a_out.is_some() && b_out.is_some() {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            }),
        )
        .await;
        (a_out, b_out)
    }

    fn udp_runtime() -> crate::runtime::Runtime {
        crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
    }

    /// br-asupersync-2eqmd2 L1: datagrams that are not part of the handshake
    /// spend none of the standalone server's flight budget. More than 64
    /// batches of them used to end the server's handshake before it read the
    /// client's Initial, and the client then retransmitted into silence.
    #[test]
    fn stray_datagrams_do_not_spend_the_server_flight_budget() {
        let original_cid = ConnectionId::new(DCID_BYTES).unwrap();
        let client_scid = ConnectionId::new(&[0x31; 8]).unwrap();
        let server_scid = ConnectionId::new(&[0x32; 8]).unwrap();
        udp_runtime().block_on(async {
            let cx = Cx::current().expect("native context");
            let mut server_endpoint = loopback_endpoint(&cx).await;
            let mut client_endpoint = loopback_endpoint(&cx).await;
            let mut stray_endpoint = loopback_endpoint(&cx).await;
            let server_addr = server_endpoint.local_addr();
            let (mut client, mut server) = alpn_pair(ATP_QUIC_ALPN);
            let strays: Vec<OutgoingPacket> = (0..8)
                .map(|_| OutgoingPacket {
                    dst_addr: server_addr,
                    data: vec![0x40; 32],
                    send_time: None,
                })
                .collect();
            let connecting = async {
                // 140 rounds of 8: at least 70 receive batches (one holds at
                // most 16 datagrams) before the client's first Initial.
                for _ in 0..140 {
                    stray_endpoint.send_batch(&cx, &strays).await.unwrap();
                    crate::time::sleep(cx.now(), Duration::from_millis(5)).await;
                }
                client_handshake_over_udp(
                    &cx,
                    &mut client_endpoint,
                    server_addr,
                    &mut client,
                    original_cid,
                    client_scid,
                )
                .await
            };
            let (served, connected) = join_within(
                &cx,
                Duration::from_secs(20),
                server_handshake_over_udp(
                    &cx,
                    &mut server_endpoint,
                    &mut server,
                    original_cid,
                    server_scid,
                ),
                connecting,
            )
            .await;
            served
                .expect("the server's handshake ends")
                .expect("the strays are ignored and the handshake completes");
            connected
                .expect("the client's handshake ends")
                .expect("the client completes");
        });
    }

    /// br-asupersync-2eqmd2 L2: short-header packets that reach a client
    /// mid-handshake are kept only when addressed to it, and a full queue
    /// drops them instead of ending the handshake.
    #[test]
    fn a_full_early_one_rtt_queue_drops_packets_instead_of_ending_the_handshake() {
        let original_cid = ConnectionId::new(DCID_BYTES).unwrap();
        let client_scid = ConnectionId::new(&[0x41; 8]).unwrap();
        let server_scid = ConnectionId::new(&[0x42; 8]).unwrap();
        let other_cid = ConnectionId::new(&[0x43; 8]).unwrap();
        udp_runtime().block_on(async {
            let cx = Cx::current().expect("native context");
            let mut server_endpoint = loopback_endpoint(&cx).await;
            let mut client_endpoint = loopback_endpoint(&cx).await;
            let server_addr = server_endpoint.local_addr();
            let (mut client, mut server) = alpn_pair(ATP_QUIC_ALPN);
            server.install_initial_keys(DCID_BYTES).unwrap();
            // A scripted server: its Initial, then short-header packets, and
            // only then its Handshake flight.
            let scripted = async {
                let hello = loop {
                    let batch = server_endpoint.receive_batch(&cx, 1).await.unwrap();
                    if let Some(packet) = batch.into_iter().next() {
                        break packet;
                    }
                };
                server.recv_handshake_packet(&hello.data).unwrap();
                let mut packet_number = 0;
                let flight = server
                    .assemble_pending_flight(
                        1200,
                        hello.src_addr,
                        client_scid,
                        server_scid,
                        &mut packet_number,
                    )
                    .unwrap();
                let (initial, handshake): (Vec<_>, Vec<_>) =
                    flight.packets.into_iter().partition(|packet| {
                        long_prefix(&packet.data).packet_type == LongPacketType::Initial
                    });
                server_endpoint.send_batch(&cx, &initial).await.unwrap();
                // 48 packets for another connection, then 2000 for this
                // client: more than its 1024-packet early queue holds.
                for round in 0..256 {
                    let cid = if round < 6 { other_cid } else { client_scid };
                    let batch: Vec<OutgoingPacket> = (0..8)
                        .map(|_| {
                            let mut data = vec![0x40];
                            data.extend_from_slice(cid.as_bytes());
                            data.extend_from_slice(&[0xaa; 24]);
                            OutgoingPacket {
                                dst_addr: hello.src_addr,
                                data,
                                send_time: None,
                            }
                        })
                        .collect();
                    server_endpoint.send_batch(&cx, &batch).await.unwrap();
                    crate::time::sleep(cx.now(), Duration::from_millis(5)).await;
                }
                server_endpoint.send_batch(&cx, &handshake).await.unwrap();
            };
            let (scripted, connected) = join_within(
                &cx,
                Duration::from_secs(20),
                scripted,
                client_handshake_over_udp_with_early_data(
                    &cx,
                    &mut client_endpoint,
                    server_addr,
                    &mut client,
                    original_cid,
                    client_scid,
                ),
            )
            .await;
            scripted.expect("the scripted server finishes");
            let early = connected
                .expect("the client's handshake ends")
                .expect("a full early queue does not end the handshake");
            assert!(
                !early.is_empty() && early.len() <= MAX_EARLY_ONE_RTT_PACKETS,
                "{} early packets",
                early.len()
            );
            assert!(
                early
                    .iter()
                    .all(|packet| is_short_header_for(&packet.data, client_scid)),
                "packets for another connection are dropped"
            );
        });
    }

    /// A short-header packet for `cid` with an arbitrary protected body.
    fn short_packet_for(cid: ConnectionId) -> Vec<u8> {
        let mut data = vec![0x40];
        data.extend_from_slice(cid.as_bytes());
        data.extend_from_slice(&[0xaa; 24]);
        data
    }

    /// br-asupersync-1r3f5u L1: after the long-header packets of a datagram,
    /// the client hands only a 1-RTT packet addressed to it to the data
    /// plane. A short header for another connection, or a malformed long
    /// header, coalesced behind the server's Initial is dropped.
    #[test]
    fn only_a_coalesced_one_rtt_packet_for_this_client_is_kept_as_early_data() {
        let original_cid = ConnectionId::new(DCID_BYTES).unwrap();
        let client_scid = ConnectionId::new(&[0x51; 8]).unwrap();
        let server_scid = ConnectionId::new(&[0x52; 8]).unwrap();
        let other_cid = ConnectionId::new(&[0x53; 8]).unwrap();
        // A version-1 Initial header whose Length runs past the datagram.
        let mut malformed = vec![0xC0, 0, 0, 0, 1, 8];
        malformed.extend_from_slice(client_scid.as_bytes());
        malformed.extend_from_slice(&[0, 0, 0xBF, 0xFF, 0xFF, 0xFF]);
        malformed.extend_from_slice(&[0x5a; 16]);
        let kept = short_packet_for(client_scid);
        // Each handshake carries one kind of junk behind the server's Initial
        // and the client's own 1-RTT packet behind the last Handshake packet.
        for junk in [short_packet_for(other_cid), malformed] {
            udp_runtime().block_on(async {
                let cx = Cx::current().expect("native context");
                let mut server_endpoint = loopback_endpoint(&cx).await;
                let mut client_endpoint = loopback_endpoint(&cx).await;
                let server_addr = server_endpoint.local_addr();
                let (mut client, mut server) = alpn_pair(ATP_QUIC_ALPN);
                server.install_initial_keys(DCID_BYTES).unwrap();
                let scripted = async {
                    let hello = loop {
                        let batch = server_endpoint.receive_batch(&cx, 1).await.unwrap();
                        if let Some(packet) = batch.into_iter().next() {
                            break packet;
                        }
                    };
                    server.recv_handshake_packet(&hello.data).unwrap();
                    let mut packet_number = 0;
                    let flight = server
                        .assemble_pending_flight(
                            1200,
                            hello.src_addr,
                            client_scid,
                            server_scid,
                            &mut packet_number,
                        )
                        .unwrap();
                    let (mut initial, mut handshake): (Vec<_>, Vec<_>) =
                        flight.packets.into_iter().partition(|packet| {
                            long_prefix(&packet.data).packet_type == LongPacketType::Initial
                        });
                    assert!(
                        !initial.is_empty() && !handshake.is_empty(),
                        "{} Initial and {} Handshake packets",
                        initial.len(),
                        handshake.len()
                    );
                    initial[0].data.extend_from_slice(&junk);
                    handshake.last_mut().unwrap().data.extend_from_slice(&kept);
                    server_endpoint.send_batch(&cx, &initial).await.unwrap();
                    server_endpoint.send_batch(&cx, &handshake).await.unwrap();
                };
                let (scripted, connected) = join_within(
                    &cx,
                    Duration::from_secs(20),
                    scripted,
                    client_handshake_over_udp_with_early_data(
                        &cx,
                        &mut client_endpoint,
                        server_addr,
                        &mut client,
                        original_cid,
                        client_scid,
                    ),
                )
                .await;
                scripted.expect("the scripted server finishes");
                let early = connected
                    .expect("the client's handshake ends")
                    .expect("the client completes");
                assert_eq!(
                    early.len(),
                    1,
                    "only the 1-RTT packet for this client is kept"
                );
                assert_eq!(early[0].data, kept);
            });
        }
    }

    /// br-asupersync-1r3f5u L1, server side: a 1-RTT packet coalesced behind
    /// the client's handshake packets is kept only when it is addressed to
    /// this server.
    #[test]
    fn only_a_coalesced_one_rtt_packet_for_this_server_is_kept_as_early_data() {
        let original_cid = ConnectionId::new(DCID_BYTES).unwrap();
        let client_scid = ConnectionId::new(&[0x61; 8]).unwrap();
        let server_scid = ConnectionId::new(&[0x62; 8]).unwrap();
        let other_cid = ConnectionId::new(&[0x63; 8]).unwrap();
        let kept = short_packet_for(server_scid);
        udp_runtime().block_on(async {
            let cx = Cx::current().expect("native context");
            let mut server_endpoint = loopback_endpoint(&cx).await;
            let mut client_endpoint = loopback_endpoint(&cx).await;
            let server_addr = server_endpoint.local_addr();
            let (mut client, mut server) = alpn_pair(ATP_QUIC_ALPN);
            let scripted = async {
                client.install_initial_keys(DCID_BYTES).unwrap();
                let hello = client.pump_outbound().unwrap();
                assert_eq!(hello.len(), 1, "one ClientHello segment");
                let mut initial = client
                    .assemble_handshake_packet(&hello[0], original_cid, client_scid, 0)
                    .unwrap();
                initial.extend_from_slice(&short_packet_for(other_cid));
                let send = |data| OutgoingPacket {
                    dst_addr: server_addr,
                    data,
                    send_time: None,
                };
                client_endpoint
                    .send_batch(&cx, &[send(initial)])
                    .await
                    .unwrap();
                let mut finished = Vec::new();
                while !client.is_complete() {
                    for packet in client_endpoint.receive_batch(&cx, 16).await.unwrap() {
                        if client.recv_handshake_packet(&packet.data).is_ok() {
                            finished.extend(
                                client
                                    .pump_outbound()
                                    .unwrap()
                                    .into_iter()
                                    .filter(|segment| segment.level == HandshakeLevel::Handshake),
                            );
                        }
                    }
                }
                assert_eq!(finished.len(), 1, "the client's Finished");
                let mut data = client
                    .assemble_handshake_packet(&finished[0], server_scid, client_scid, 0)
                    .unwrap();
                data.extend_from_slice(&kept);
                client_endpoint
                    .send_batch(&cx, &[send(data)])
                    .await
                    .unwrap();
            };
            let (served, scripted) = join_within(
                &cx,
                Duration::from_secs(20),
                server_handshake_over_udp_with_early_data(
                    &cx,
                    &mut server_endpoint,
                    &mut server,
                    original_cid,
                    server_scid,
                ),
                scripted,
            )
            .await;
            scripted.expect("the scripted client finishes");
            let (_, early) = served
                .expect("the server's handshake ends")
                .expect("the server completes");
            assert_eq!(
                early.len(),
                1,
                "only the 1-RTT packet for this server is kept"
            );
            assert_eq!(early[0].data, kept);
        });
    }
