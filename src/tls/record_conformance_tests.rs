#![allow(clippy::all)]
//! TLS 1.3 record-layer conformance tests.
//!
//! Golden tests for TLS 1.3 record framing conformance per RFC 8446 §5.
//! These tests verify record-layer behavior using rustls internals with
//! handshake state machine integration.
//!
//! Test coverage:
//! 1. TLSInnerPlaintext opaque type 0x17/0x16/0x15
//! 2. Record padding edge cases (zero + max)
//! 3. Record length MUST-REJECT >16384+256
//! 4. Ciphertext record header not integrity-protected
//! 5. 0-RTT early_data record semantics

#[cfg(all(test, feature = "tls"))]
mod tests {
    use crate::test_utils::{init_test_logging, run_test_with_cx};
    use rustls::crypto::ring::default_provider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{
        ClientConfig, ClientConnection, Error as RustlsError, ServerConfig, ServerConnection,
    };
    use std::io::{self, Cursor};
    use std::sync::Arc;

    // Test certificate and key for handshake state machine testing
    const TEST_CERT_PEM: &str = include_str!("../../tests/fixtures/tls/server.crt");
    const TEST_KEY_PEM: &str = include_str!("../../tests/fixtures/tls/server.key");

    /// RFC 8446 §5.1 - Record layer constants
    mod rfc8446_constants {
        pub const MAX_RECORD_LENGTH: u16 = 16384; // 2^14 bytes
        pub const MAX_ENCRYPTED_RECORD_LENGTH: u16 = MAX_RECORD_LENGTH + 256; // With expansion

        // TLSInnerPlaintext ContentType values (RFC 8446 §5.4)
        pub const CONTENT_TYPE_ALERT: u8 = 0x15;
        pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
        pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

        // TLS record header
        pub const TLS_RECORD_HEADER_LEN: usize = 5;
        pub const TLS_13_RECORD_TYPE: u8 = 0x17; // Always application_data in TLS 1.3
        pub const TLS_13_VERSION: u16 = 0x0303; // Legacy version field (TLS 1.2)
    }

    use rfc8446_constants::*;

    /// Helper to create test TLS configurations
    struct TestTlsConfig;

    impl TestTlsConfig {
        fn client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
            let cert = Self::parse_cert(TEST_CERT_PEM)?;
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert.clone())?;

            let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Ok(config)
        }

        fn server_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
            let cert = Self::parse_cert(TEST_CERT_PEM)?;
            let key = Self::parse_key(TEST_KEY_PEM)?;
            let cert_chain = vec![cert];

            let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)?;

            Ok(config)
        }

        fn parse_cert(pem: &str) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
            let mut cursor = Cursor::new(pem.as_bytes());
            let certs: Vec<_> =
                rustls_pemfile::certs(&mut cursor).collect::<Result<Vec<_>, _>>()?;
            certs
                .into_iter()
                .next()
                .ok_or("No certificate found in PEM".into())
        }

        fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
            let mut cursor = Cursor::new(pem.as_bytes());
            let keys: Vec<_> =
                rustls_pemfile::pkcs8_private_keys(&mut cursor).collect::<Result<Vec<_>, _>>()?;
            if let Some(key) = keys.into_iter().next() {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }

            let mut cursor = Cursor::new(pem.as_bytes());
            let keys: Vec<_> =
                rustls_pemfile::rsa_private_keys(&mut cursor).collect::<Result<Vec<_>, _>>()?;
            if let Some(key) = keys.into_iter().next() {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }

            Err("No valid private key found in PEM".into())
        }
    }

    /// Raw TLS record structure for testing
    #[derive(Debug, Clone)]
    struct TlsRecord {
        content_type: u8,
        version: u16,
        length: u16,
        payload: Vec<u8>,
    }

    impl TlsRecord {
        fn new(content_type: u8, version: u16, payload: Vec<u8>) -> Self {
            // br-asupersync-lp1dpt: was `payload.len() as u16` which silently
            // truncates on overflow. All current callers stay under
            // MAX_ENCRYPTED_RECORD_LENGTH (16640), well below u16::MAX, but
            // a future test that constructs a >64KiB payload would silently
            // get a wrong header length and a 'malformed record rejected'
            // assertion could pass for the wrong reason. Fail loudly.
            let length = u16::try_from(payload.len())
                .expect("TlsRecord payload length exceeds u16; record header cannot encode it");
            Self {
                content_type,
                version,
                length,
                payload,
            }
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(TLS_RECORD_HEADER_LEN + self.payload.len());
            bytes.push(self.content_type);
            bytes.extend_from_slice(&self.version.to_be_bytes());
            bytes.extend_from_slice(&self.length.to_be_bytes());
            bytes.extend_from_slice(&self.payload);
            bytes
        }

        fn application_data(payload: Vec<u8>) -> Self {
            Self::new(TLS_13_RECORD_TYPE, TLS_13_VERSION, payload)
        }

        #[allow(dead_code)]
        fn handshake(payload: Vec<u8>) -> Self {
            Self::new(CONTENT_TYPE_HANDSHAKE, TLS_13_VERSION, payload)
        }

        #[allow(dead_code)]
        fn alert(payload: Vec<u8>) -> Self {
            Self::new(CONTENT_TYPE_ALERT, TLS_13_VERSION, payload)
        }
    }

    /// Test helper for TLS connections with raw record injection
    struct TlsTestHarness {
        client: ClientConnection,
        server: ServerConnection,
    }

    impl TlsTestHarness {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let client_config = TestTlsConfig::client_config()?;
            let server_config = TestTlsConfig::server_config()?;

            let server_name = ServerName::try_from("localhost")?;
            let client = ClientConnection::new(Arc::new(client_config), server_name)?;
            let server = ServerConnection::new(Arc::new(server_config))?;

            Ok(Self { client, server })
        }

        /// Perform a complete handshake
        fn complete_handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let mut client_buf = Vec::new();
            let mut server_buf = Vec::new();

            // Handshake loop
            for _ in 0..10 {
                // Limit iterations to prevent infinite loops
                // Process client -> server
                if self.client.wants_write() {
                    client_buf.clear();
                    self.client.write_tls(&mut client_buf)?;
                    if !client_buf.is_empty() {
                        self.server.read_tls(&mut Cursor::new(&client_buf))?;
                        self.server.process_new_packets()?;
                    }
                }

                // Process server -> client
                if self.server.wants_write() {
                    server_buf.clear();
                    self.server.write_tls(&mut server_buf)?;
                    if !server_buf.is_empty() {
                        self.client.read_tls(&mut Cursor::new(&server_buf))?;
                        self.client.process_new_packets()?;
                    }
                }

                // Check if handshake is complete
                if !self.client.is_handshaking() && !self.server.is_handshaking() {
                    return Ok(());
                }
            }

            Err("Handshake did not complete".into())
        }

        /// Inject a raw record into the client connection
        fn inject_client_record(&mut self, record: &TlsRecord) -> Result<(), RustlsError> {
            let record_bytes = record.to_bytes();
            self.client
                .read_tls(&mut Cursor::new(&record_bytes))
                .map_err(|e| {
                    RustlsError::General(format!("I/O error reading TLS record: {}", e))
                })?;
            self.client.process_new_packets().map(|_| ())
        }

        /// Inject a raw record into the server connection
        fn inject_server_record(&mut self, record: &TlsRecord) -> Result<(), RustlsError> {
            let record_bytes = record.to_bytes();
            self.server
                .read_tls(&mut Cursor::new(&record_bytes))
                .map_err(|e| {
                    RustlsError::General(format!("I/O error reading TLS record: {}", e))
                })?;
            self.server.process_new_packets().map(|_| ())
        }
    }

    // ---- Test 1: TLSCiphertext header wire image ----

    /// RFC 8446 §5.1 - TLSCiphertext uses outer ContentType=application_data and
    /// legacy_record_version=0x0303 with a 16-bit big-endian length field.
    #[test]
    fn test_tls_ciphertext_header_matches_rfc8446_wire_image() {
        init_test_logging();
        crate::test_phase!("test_tls_ciphertext_header_matches_rfc8446_wire_image");

        let record = TlsRecord::application_data(vec![0x01, 0x02, 0x03]);

        assert_eq!(
            record.to_bytes(),
            vec![
                CONTENT_TYPE_APPLICATION_DATA,
                0x03,
                0x03,
                0x00,
                0x03,
                0x01,
                0x02,
                0x03
            ]
        );

        crate::test_complete!("test_tls_ciphertext_header_matches_rfc8446_wire_image");
    }

    // ---- Test 2: TLSInnerPlaintext opaque type validation ----

    /// RFC 8446 §5.4 - Test TLSInnerPlaintext content types 0x17/0x16/0x15
    #[test]
    fn test_tls_inner_plaintext_content_types() {
        init_test_logging();
        crate::test_phase!("test_tls_inner_plaintext_content_types");

        run_test_with_cx(|_cx| async move {
            // Test valid content types that should be accepted
            let valid_content_types = [
                (CONTENT_TYPE_ALERT, "alert"),
                (CONTENT_TYPE_HANDSHAKE, "handshake"),
                (CONTENT_TYPE_APPLICATION_DATA, "application_data"),
            ];

            // br-asupersync-tt39ku: this test injects PLAINTEXT records
            // into a post-handshake rustls connection. After handshake
            // every wire record is AEAD-protected, so rustls's
            // process_new_packets() decrypts and rejects plaintext
            // payloads under the negotiated keys. The only honest
            // assertion across all "valid" outer-content-type bytes is
            // that BOTH sides report an error — the previous
            // `is_ok() || is_ok()` expression was inverted from the
            // actual contract and was masked by the tautology pattern
            // documented in br-asupersync-zt2i8r.
            for (content_type, name) in valid_content_types {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");

                // Create a minimal valid record with the content type
                let payload = vec![0x01, 0x00]; // Minimal payload
                let record = TlsRecord::new(content_type, TLS_13_VERSION, payload);

                let result_client = harness.inject_client_record(&record);
                let result_server = harness.inject_server_record(&record);

                crate::assert_with_log!(
                    result_client.is_err() && result_server.is_err(),
                    "post_handshake_plaintext_rejected",
                    "client_err && server_err",
                    format!(
                        "Plaintext content_type {} ({}) post-handshake must fail decryption on both sides; got client={:?} server={:?}",
                        content_type, name, result_client, result_server
                    )
                );
            }

            // Test invalid content types that should be rejected
            let invalid_content_types = [0x00, 0x14, 0x18, 0xFF]; // Invalid per RFC 8446

            for &invalid_type in &invalid_content_types {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");

                let payload = vec![0x01, 0x00];
                let record = TlsRecord::new(invalid_type, TLS_13_VERSION, payload);

                let result = harness.inject_client_record(&record);
                crate::assert_with_log!(
                    result.is_err(),
                    "invalid content type rejected",
                    true,
                    format!("Invalid content type {} should be rejected", invalid_type)
                );
            }
        });

        crate::test_complete!("test_tls_inner_plaintext_content_types");
    }

    // ---- Test 2: Record padding edge cases ----

    /// RFC 8446 §5.4 - Test record padding validation (zero padding)
    #[test]
    fn test_record_padding_zero_padding() {
        init_test_logging();
        crate::test_phase!("test_record_padding_zero_padding");

        run_test_with_cx(|_cx| async move {
            let mut harness = TlsTestHarness::new().expect("Failed to create test harness");

            harness.complete_handshake().expect("Handshake failed");

            // Test zero padding (no padding bytes)
            // In TLS 1.3, padding is implicit - just content followed by content type
            let plaintext_content = b"Hello, World!";
            let mut payload = plaintext_content.to_vec();
            payload.push(CONTENT_TYPE_APPLICATION_DATA); // Content type byte, no padding

            let record = TlsRecord::application_data(payload);
            let result = harness.inject_server_record(&record);

            // br-asupersync-tt39ku: post-handshake plaintext app data
            // fails AEAD decryption — pin the error rather than the
            // (wrong) `is_ok()` claim. The harness exercises wire
            // format injection, not the encryption layer; this test
            // does NOT actually validate RFC 8446 §5.4 padding
            // semantics, only that rustls rejects un-AEAD'd records.
            crate::assert_with_log!(
                result.is_err(),
                "post_handshake_plaintext_zero_padding_rejected",
                "Err",
                format!(
                    "Plaintext zero-padded record post-handshake must fail AEAD decryption, got {:?}",
                    result
                )
            );
        });

        crate::test_complete!("test_record_padding_zero_padding");
    }

    /// RFC 8446 §5.4 - Test record padding validation (maximum padding)
    #[test]
    fn test_record_padding_maximum_padding() {
        init_test_logging();
        crate::test_phase!("test_record_padding_maximum_padding");

        run_test_with_cx(|_cx| async move {
            let mut harness = TlsTestHarness::new().expect("Failed to create test harness");

            harness.complete_handshake().expect("Handshake failed");

            // Test maximum padding
            // RFC 8446 allows arbitrary padding up to record size limits
            let plaintext_content = b"Hi";
            let max_padding_len = MAX_RECORD_LENGTH as usize - plaintext_content.len() - 1; // -1 for content type

            let mut payload = plaintext_content.to_vec();
            payload.extend(vec![0x00; max_padding_len]); // Zero padding bytes
            payload.push(CONTENT_TYPE_APPLICATION_DATA); // Content type at end

            let record = TlsRecord::application_data(payload);
            let result = harness.inject_server_record(&record);

            // br-asupersync-tt39ku: rustls's process_new_packets()
            // empirically returns Ok(()) for plaintext records whose
            // wire payload reaches the ~16 KiB ciphertext threshold
            // (the bytes are accepted into the internal record buffer
            // without immediately surfacing the AEAD failure that
            // smaller records trip). Pin Ok rather than reading too
            // much into it — the only invariant the wire-injection
            // path can honestly assert at this size is "rustls accepts
            // the bytes without erroring". Smaller plaintext payloads
            // surface a decrypt error; this test exercises the
            // larger-record path.
            crate::assert_with_log!(
                result.is_ok(),
                "max_padding_plaintext_buffered_post_handshake",
                "Ok (rustls buffers large records before surfacing AEAD)",
                format!(
                    "Plaintext record with {}-byte padding post-handshake; got {:?}",
                    max_padding_len, result
                )
            );
        });

        crate::test_complete!("test_record_padding_maximum_padding");
    }

    // ---- Test 3: Record length validation ----

    /// RFC 8446 §5.1 - Test record length MUST-REJECT >16384+256
    #[test]
    fn test_record_length_exceeds_maximum() {
        init_test_logging();
        crate::test_phase!("test_record_length_exceeds_maximum");

        run_test_with_cx(|_cx| async move {
            // Test record length exactly at limit. The wire payload
            // is at the rustls accept threshold (16640 = 16384 + 256
            // ciphertext expansion); rustls accepts the bytes into
            // its buffer without surfacing an AEAD error. The honest
            // invariant: at-limit records are accepted by read_tls
            // and process_new_packets returns Ok(()). br-asupersync-tt39ku.
            let max_payload = vec![0x00; MAX_ENCRYPTED_RECORD_LENGTH as usize];
            let max_record = TlsRecord::application_data(max_payload);

            let result_max = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&max_record)
            };
            crate::assert_with_log!(
                result_max.is_ok(),
                "max_length_record_accepted_post_handshake",
                "Ok (record at MAX_ENCRYPTED_RECORD_LENGTH is buffered)",
                format!(
                    "Record at MAX_ENCRYPTED_RECORD_LENGTH ({} bytes) post-handshake; got {:?}",
                    MAX_ENCRYPTED_RECORD_LENGTH, result_max
                )
            );

            // Test record length exceeding limit (MUST be rejected)
            let oversized_payload = vec![0x00; (MAX_ENCRYPTED_RECORD_LENGTH + 1) as usize];
            let oversized_record = TlsRecord::application_data(oversized_payload);

            let result_oversized = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_client_record(&oversized_record)
            };
            crate::assert_with_log!(
                result_oversized.is_err(),
                "oversized record rejected",
                true,
                "Record exceeding maximum length by 1 byte MUST be rejected"
            );

            // Test significantly oversized record
            let huge_payload = vec![0x00; 32768]; // 2x maximum
            let huge_record = TlsRecord::application_data(huge_payload);

            let result_huge = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_client_record(&huge_record)
            };
            crate::assert_with_log!(
                result_huge.is_err(),
                "huge record rejected",
                true,
                "Significantly oversized records MUST be rejected"
            );
        });

        crate::test_complete!("test_record_length_exceeds_maximum");
    }

    /// RFC 8446 §5.1 - Test empty record handling
    #[test]
    fn test_record_length_edge_cases() {
        init_test_logging();
        crate::test_phase!("test_record_length_edge_cases");

        run_test_with_cx(|_cx| async move {
            let mut harness = TlsTestHarness::new().expect("Failed to create test harness");

            harness.complete_handshake().expect("Handshake failed");

            // Test empty record (length 0) - should be rejected
            let empty_record = TlsRecord::application_data(vec![]);
            let result_empty = harness.inject_server_record(&empty_record);

            crate::assert_with_log!(
                result_empty.is_err(),
                "empty record rejected",
                true,
                "Empty records should be rejected"
            );

            // Test minimal valid record (just content type byte). The
            // wire framing parses, but the 1-byte body is plaintext
            // and post-handshake records must be AEAD-protected, so
            // rustls returns Err. br-asupersync-tt39ku: pin Err.
            let minimal_record = TlsRecord::application_data(vec![CONTENT_TYPE_APPLICATION_DATA]);
            let result_minimal = harness.inject_server_record(&minimal_record);

            crate::assert_with_log!(
                result_minimal.is_err(),
                "minimal_plaintext_rejected_post_handshake",
                "Err",
                format!(
                    "Single-byte plaintext record post-handshake must fail AEAD decryption, got {:?}",
                    result_minimal
                )
            );
        });

        crate::test_complete!("test_record_length_edge_cases");
    }

    // ---- Test 4: Ciphertext record header integrity ----

    /// RFC 8446 §5.1 - Test ciphertext record header is NOT integrity-protected
    #[test]
    fn test_ciphertext_header_not_integrity_protected() {
        init_test_logging();
        crate::test_phase!("test_ciphertext_header_not_integrity_protected");

        run_test_with_cx(|_cx| async move {
            let mut harness = TlsTestHarness::new().expect("Failed to create test harness");

            harness.complete_handshake().expect("Handshake failed");

            // Create a valid record first
            let original_payload = b"Test message for header manipulation";
            let mut encrypted_payload = original_payload.to_vec();
            encrypted_payload.push(CONTENT_TYPE_APPLICATION_DATA);

            let original_record = TlsRecord::application_data(encrypted_payload.clone());
            let mut record_bytes = original_record.to_bytes();

            // Test: Modify the version field in the header (should not affect decryption)
            // TLS 1.3 records use legacy version 0x0303, try changing to 0x0301 (TLS 1.0)
            record_bytes[1] = 0x03; // High byte
            record_bytes[2] = 0x01; // Low byte (TLS 1.0)

            // Parse the modified record back
            let modified_record = TlsRecord {
                content_type: record_bytes[0],
                version: u16::from_be_bytes([record_bytes[1], record_bytes[2]]),
                length: u16::from_be_bytes([record_bytes[3], record_bytes[4]]),
                payload: record_bytes[5..].to_vec(),
            };

            let result = harness.inject_server_record(&modified_record);

            // br-asupersync-zt2i8r: previously this assertion pinned the
            // literal `true`, which made it a no-op. The invariant we
            // actually want to lock is "the outer header is parsed
            // identically regardless of crypto; i.e. modifying the
            // legacy_record_version does NOT cause a parse-level
            // success/failure flip vs an unmodified record." Compare
            // against a baseline run with the original record so any
            // future change to rustls' parser surfacing version checks
            // would flip the parity and trip the test.
            let mut harness_baseline =
                TlsTestHarness::new().expect("Failed to create baseline harness");
            harness_baseline
                .complete_handshake()
                .expect("Baseline handshake failed");
            let baseline = harness_baseline.inject_server_record(&original_record);
            crate::assert_with_log!(
                result.is_ok() == baseline.is_ok(),
                "header_version_modification_parity",
                true,
                format!(
                    "TLS record header is not integrity-protected: legacy_record_version mutation must produce same parse outcome as baseline. baseline_ok={}, modified_ok={}",
                    baseline.is_ok(),
                    result.is_ok()
                )
            );

            // Test: Modify the content type in header (outer record type, not inner)
            let mut record_bytes_2 = original_record.to_bytes();
            record_bytes_2[0] = CONTENT_TYPE_HANDSHAKE; // Change outer type

            let modified_record_2 = TlsRecord {
                content_type: CONTENT_TYPE_HANDSHAKE,
                version: TLS_13_VERSION,
                length: encrypted_payload.len() as u16,
                payload: encrypted_payload,
            };

            // br-asupersync-zt2i8r: same — assert the OUTER content type
            // mutation is parsed (not silently dropped at the wire). In
            // TLS 1.3 the outer type is always 0x17 in production; rustls
            // will typically reject 0x16 post-handshake with a decrypt
            // error. Pin "rustls returns Err for outer-type-mutated
            // application_data records once the handshake is complete"
            // — drift either way is a regression worth flagging.
            let result_2 = harness.inject_server_record(&modified_record_2);
            crate::assert_with_log!(
                result_2.is_err(),
                "outer_content_type_mutation_rejected",
                true,
                format!(
                    "Mutating outer record ContentType from 0x17 to 0x16 must produce a parse/decrypt error post-handshake, got Ok"
                )
            );
        });

        crate::test_complete!("test_ciphertext_header_not_integrity_protected");
    }

    // ---- Test 5: 0-RTT early data record semantics ----

    /// RFC 8446 §4.2.10 - Test 0-RTT early_data record handling
    #[test]
    fn test_early_data_record_semantics() {
        init_test_logging();
        crate::test_phase!("test_early_data_record_semantics");

        run_test_with_cx(|_cx| async move {
            // Note: 0-RTT requires PSK or session resumption, which is complex to set up.
            // This test validates the record-layer aspects rather than full 0-RTT flow.

            // Test early data records after handshake (should be rejected)
            // In a real 0-RTT scenario, these would come before ServerHello
            let early_data_content = b"Early data payload";
            let mut early_payload = early_data_content.to_vec();
            early_payload.push(CONTENT_TYPE_APPLICATION_DATA);

            let early_data_record = TlsRecord::application_data(early_payload);

            // br-asupersync-zt2i8r: previously this asserted the
            // tautology `result.is_ok() || result.is_err()` which is
            // always true. The actual invariant: an unsolicited
            // application_data record injected into a freshly-handshaken
            // ServerConnection that doesn't have valid ciphertext under
            // the negotiated keys MUST fail decryption (rustls returns
            // an Err). Pin that rather than the tautology.
            let result = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&early_data_record)
            };
            crate::assert_with_log!(
                result.is_err(),
                "post_handshake_unencrypted_app_data_rejected",
                true,
                format!(
                    "Post-handshake injection of plaintext application_data record without valid AEAD must fail decryption, got Ok"
                )
            );

            // Test that early data records have proper length limits
            // RFC 8446 specifies early data has same length limits as normal records
            let max_early_data = vec![0x00; MAX_RECORD_LENGTH as usize - 1]; // -1 for content type
            let mut max_early_payload = max_early_data;
            max_early_payload.push(CONTENT_TYPE_APPLICATION_DATA);

            let max_early_record = TlsRecord::application_data(max_early_payload);
            let result_max = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&max_early_record)
            };

            // br-asupersync-zt2i8r: same tautology fix. A 16383-byte
            // payload (= MAX_RECORD_LENGTH - 1) is BELOW the wire limit
            // of MAX_ENCRYPTED_RECORD_LENGTH (16384+256=16640), so the
            // record-length check allows it. Without valid ciphertext
            // it still fails decryption — pin Err.
            crate::assert_with_log!(
                result_max.is_err(),
                "max_record_length_unencrypted_rejected",
                true,
                format!(
                    "Length-valid but cryptographically-invalid record must fail decryption post-handshake, got Ok"
                )
            );

            // Test oversized early data (should be rejected)
            let oversized_early_data = vec![0x00; MAX_ENCRYPTED_RECORD_LENGTH as usize + 1];
            let oversized_early_record = TlsRecord::application_data(oversized_early_data);

            let result_oversized = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&oversized_early_record)
            };
            crate::assert_with_log!(
                result_oversized.is_err(),
                "oversized early data rejected",
                true,
                "Oversized early data records MUST be rejected"
            );
        });

        crate::test_complete!("test_early_data_record_semantics");
    }

    // ---- Additional conformance tests ----

    /// Test record layer fragmentation behavior
    #[test]
    fn test_record_fragmentation_conformance() {
        init_test_logging();
        crate::test_phase!("test_record_fragmentation_conformance");

        run_test_with_cx(|_cx| async move {
            // Test large message split across multiple records
            let large_message = vec![0x42; MAX_RECORD_LENGTH as usize * 2]; // 2x record size

            // Split into two records
            let first_half = &large_message[..MAX_RECORD_LENGTH as usize / 2];
            let second_half = &large_message[MAX_RECORD_LENGTH as usize / 2..];

            let mut first_payload = first_half.to_vec();
            first_payload.push(CONTENT_TYPE_APPLICATION_DATA);
            let first_record = TlsRecord::application_data(first_payload);

            let mut second_payload = second_half.to_vec();
            second_payload.push(CONTENT_TYPE_APPLICATION_DATA);
            let second_record = TlsRecord::application_data(second_payload);

            // br-asupersync-tt39ku: these are still PLAINTEXT post-handshake
            // application_data records, so each fragment must fail AEAD
            // decryption independently. Use fresh harnesses so the first
            // failure cannot poison the second result.
            let result_first = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&first_record)
            };
            let result_second = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&second_record)
            };

            crate::assert_with_log!(
                result_first.is_err() && result_second.is_err(),
                "fragmented_plaintext_records_rejected_post_handshake",
                "Err && Err",
                format!(
                    "Each plaintext fragment injected post-handshake must fail AEAD decryption independently; got first={:?} second={:?}",
                    result_first, result_second
                )
            );
        });

        crate::test_complete!("test_record_fragmentation_conformance");
    }

    /// Test malformed record structure handling
    #[test]
    fn test_malformed_record_handling() {
        init_test_logging();
        crate::test_phase!("test_malformed_record_handling");

        run_test_with_cx(|_cx| async move {
            // br-asupersync-tt39ku: rustls's read_tls() does NOT
            // immediately reject records whose stated length exceeds
            // the bytes provided — the read API is incremental and
            // simply buffers what it has. Likewise an oversized payload
            // for a stated zero length is treated as "remaining bytes
            // belong to the next record" rather than a parse error.
            // The honest assertion is therefore that read_tls returns
            // Ok in both cases (the bytes are accepted into the
            // internal buffer); a real malformed-record rejection
            // happens later, not at this entry point.
            let payload = vec![0x01, 0x02, 0x03]; // 3 bytes
            let mut record = TlsRecord::application_data(payload);
            record.length = 10; // Claim 10 bytes but only have 3

            let result_mismatch = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&record)
            };
            crate::assert_with_log!(
                result_mismatch.is_ok(),
                "incremental_read_tls_accepts_partial_record",
                "Ok (read_tls is incremental)",
                format!(
                    "rustls read_tls is incremental and buffers under-supplied records; got {:?}",
                    result_mismatch
                )
            );

            let payload = vec![0x42];
            let mut record = TlsRecord::application_data(payload);
            record.length = 0; // Claim 0 bytes but have 1

            let result_zero_length = {
                let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                harness.complete_handshake().expect("Handshake failed");
                harness.inject_server_record(&record)
            };
            crate::assert_with_log!(
                result_zero_length.is_ok(),
                "incremental_read_tls_accepts_overflow_byte",
                "Ok (overflow byte goes to next record)",
                format!(
                    "rustls read_tls treats a byte beyond the stated length as the start of the next record; got {:?}",
                    result_zero_length
                )
            );
        });

        crate::test_complete!("test_malformed_record_handling");
    }

    /// Integration test combining multiple record-layer edge cases
    #[test]
    fn test_record_layer_integration() {
        init_test_logging();
        crate::test_phase!("test_record_layer_integration");

        run_test_with_cx(|_cx| async move {
            // br-asupersync-tt39ku: these vectors are all PLAINTEXT
            // application_data records injected after handshake, so the
            // honest invariant is independent rejection, not connection
            // survivability or acceptance of the sequence.
            let test_sequence = [
                ("minimal", vec![CONTENT_TYPE_APPLICATION_DATA]),
                ("padded", {
                    let mut payload = b"Hello".to_vec();
                    payload.extend(vec![0x00; 100]); // 100 bytes padding
                    payload.push(CONTENT_TYPE_APPLICATION_DATA);
                    payload
                }),
                ("maximum", {
                    let max_content_size = MAX_RECORD_LENGTH as usize - 1; // -1 for content type
                    let mut payload = vec![0x42; max_content_size];
                    payload.push(CONTENT_TYPE_APPLICATION_DATA);
                    payload
                }),
            ];

            for (name, payload) in test_sequence {
                let record = TlsRecord::application_data(payload);
                let result = {
                    let mut harness = TlsTestHarness::new().expect("Failed to create test harness");
                    harness.complete_handshake().expect("Handshake failed");
                    harness.inject_server_record(&record)
                };

                crate::assert_with_log!(
                    result.is_err(),
                    "integration_plaintext_record_rejected_post_handshake",
                    "Err",
                    format!(
                        "Integration test record '{}' is plaintext post-handshake and must fail AEAD decryption, got {:?}",
                        name, result
                    )
                );
            }
        });

        crate::test_complete!("test_record_layer_integration");
    }
}
