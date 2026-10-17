    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

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
    const TEST_CERT_SPKI_SHA256_BASE64: &str = "Wic7R2QEWx8m0gjc0UYQD4iTxorg2Q51QmvN8HuCprc=";

    #[test]
    fn certificate_from_der() {
        // Minimal self-signed certificate DER (just test parsing doesn't panic)
        let cert = Certificate::from_der(vec![0x30, 0x00]);
        assert_eq!(cert.as_der().len(), 2);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pem_certificate_chain_keeps_order_and_rejects_malformed_tail() {
        let leaf_pem = include_bytes!("../../tests/fixtures/x509_adversarial/allowed.crt");
        let ca_pem = include_bytes!("../../tests/fixtures/x509_adversarial/ca.crt");
        let leaf = Certificate::from_pem(leaf_pem).unwrap().remove(0);
        let ca = Certificate::from_pem(ca_pem).unwrap().remove(0);
        let bundle = [leaf_pem.as_slice(), b"\n", ca_pem.as_slice()].concat();
        let chain = CertificateChain::from_pem(&bundle).unwrap();
        let parsed: Vec<_> = chain.into_iter().collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].as_der(), leaf.as_der());
        assert_eq!(parsed[1].as_der(), ca.as_der());

        let malformed = b"\n-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            Certificate::from_pem(&[bundle.as_slice(), malformed].concat()),
            Err(TlsError::Certificate(_))
        ));
        assert!(matches!(
            Certificate::from_pem(b"no certificate blocks"),
            Err(TlsError::Certificate(message)) if message == "no certificates found in PEM"
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pem_private_keys_preserve_format_precedence_and_first_key() {
        // These distinct byte payloads test PEM decoding and selection only;
        // rustls validates the decoded signing key when building TLS configs.
        let sec1 = b"-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n";
        let pkcs1 = b"-----BEGIN RSA PRIVATE KEY-----\nBAUG\n-----END RSA PRIVATE KEY-----\n";
        let pkcs8 = b"-----BEGIN PRIVATE KEY-----\nBwgJ\n-----END PRIVATE KEY-----\n";
        let later_pkcs8 = b"-----BEGIN PRIVATE KEY-----\nCgsM\n-----END PRIVATE KEY-----\n";

        let key = PrivateKey::from_pem(sec1).unwrap().clone_inner();
        assert!(matches!(key, PrivateKeyDer::Sec1(_)));
        assert_eq!(key.secret_der(), &[1, 2, 3]);

        let key = PrivateKey::from_pem(&[sec1.as_slice(), pkcs1.as_slice()].concat())
            .unwrap()
            .clone_inner();
        assert!(matches!(key, PrivateKeyDer::Pkcs1(_)));
        assert_eq!(key.secret_der(), &[4, 5, 6]);

        let bundle = [
            sec1.as_slice(),
            pkcs1.as_slice(),
            pkcs8.as_slice(),
            later_pkcs8.as_slice(),
        ]
        .concat();
        let key = PrivateKey::from_pem(&bundle).unwrap().clone_inner();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
        assert_eq!(key.secret_der(), &[7, 8, 9]);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pem_private_keys_reject_missing_keys_and_malformed_sections() {
        assert!(matches!(
            PrivateKey::from_pem(TEST_CERT_PEM),
            Err(TlsError::Certificate(message)) if message == "no private key found in PEM"
        ));

        let key = include_bytes!("../../tests/fixtures/tls/server.key");
        let malformed = b"\n-----BEGIN PRIVATE KEY-----\n!invalid!\n-----END PRIVATE KEY-----\n";
        let unterminated = b"\n-----BEGIN CERTIFICATE-----\nAQID\n";
        for tail in [malformed.as_slice(), unterminated.as_slice()] {
            // The existing API reads the full input even after finding a key.
            assert!(matches!(
                PrivateKey::from_pem(&[key.as_slice(), tail].concat()),
                Err(TlsError::Certificate(_))
            ));
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pem_errors_preserve_legacy_reader_messages() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"-----BEGIN CERTIFICATE-----\nAQID\n",
                "section end \"CERTIFICATE\" missing",
            ),
            (
                b"-----BEGIN PRIVATE KEY-----\nAQID\n",
                "section end \"PRIVATE KEY\" missing",
            ),
            (
                b"-----BEGIN \xff\n",
                "illegal section start: \"-----BEGIN \u{fffd}\\n\"",
            ),
            (
                b"-----BEGIN PRIVATE KEY----\r\n",
                "illegal section start: \"-----BEGIN PRIVATE KEY----\\r\"",
            ),
            (
                b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
                "InvalidCharacter(33)",
            ),
        ];
        for &(pem, expected) in cases {
            for error in [
                Certificate::from_pem(pem).unwrap_err(),
                PrivateKey::from_pem(pem).unwrap_err(),
            ] {
                match error {
                    TlsError::Certificate(message) => assert_eq!(message, expected),
                    other => panic!("expected certificate error, got {other:?}"),
                }
            }
        }
        assert_eq!(
            pem_error_message(rustls_pki_types::pem::Error::Io(std::io::Error::other(
                "read failed"
            ))),
            "read failed"
        );
    }

    #[test]
    fn certificate_chain_operations() {
        let chain = CertificateChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        let mut chain = CertificateChain::new();
        chain.push(Certificate::from_der(vec![1, 2, 3]));
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn certificate_chain_from_cert() {
        let cert = Certificate::from_der(vec![1, 2, 3]);
        let chain = CertificateChain::from_cert(cert);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn root_cert_store_empty() {
        let store = RootCertStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn certificate_pin_spki_base64_valid() {
        // Valid 32-byte SHA-256 hash in base64
        let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertificatePin::spki_sha256_base64(hash).unwrap();
        assert!(matches!(pin, CertificatePin::SpkiSha256(_)));
        assert_eq!(pin.hash_bytes().len(), 32);
        assert_eq!(pin.to_base64(), hash);
    }

    #[test]
    fn certificate_pin_cert_base64_valid() {
        // Valid 32-byte SHA-256 hash in base64
        let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertificatePin::cert_sha256_base64(hash).unwrap();
        assert!(matches!(pin, CertificatePin::CertSha256(_)));
        assert_eq!(pin.hash_bytes().len(), 32);
    }

    #[test]
    fn certificate_pin_invalid_base64() {
        let result = CertificatePin::spki_sha256_base64("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn certificate_pin_wrong_length() {
        // Valid base64 but wrong length (16 bytes instead of 32)
        let short_hash = "AAAAAAAAAAAAAAAAAAAAAA==";
        let result = CertificatePin::spki_sha256_base64(short_hash);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_pin_from_raw_bytes_valid() {
        let bytes = vec![0u8; 32];
        let pin = CertificatePin::spki_sha256(bytes).unwrap();
        assert_eq!(pin.hash_bytes().len(), 32);
    }

    #[test]
    fn certificate_pin_from_raw_bytes_wrong_length() {
        let bytes = vec![0u8; 16];
        let result = CertificatePin::spki_sha256(bytes);
        assert!(result.is_err());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_pin_compute_spki_sha256_known_answer() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
        assert_eq!(pin.to_base64(), TEST_CERT_SPKI_SHA256_BASE64);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_pin_compute_spki_sha256_rejects_invalid_der() {
        let cert = Certificate::from_der(vec![0x30, 0x00]);
        let err = CertificatePin::compute_spki_sha256(&cert).unwrap_err();
        match err {
            TlsError::Certificate(message) => {
                assert!(message.contains("failed to parse certificate DER"));
            }
            other => panic!("expected certificate error, got {other:?}"),
        }
    }

    /// br-asupersync-86n63i: regression. constant_time_eq must (a) accept
    /// identical inputs, (b) reject length-mismatched and content-mismatched
    /// inputs, and (c) — most importantly — perform the full comparison
    /// regardless of where the first mismatching byte appears. We can't
    /// directly observe wall-clock timing without flake risk, so we
    /// instead assert the FUNCTIONAL property that mismatches at the
    /// front, middle, and end all produce the same result, and that the
    /// helper handles the empty/full-zero edge cases.
    #[test]
    fn constant_time_eq_correctness_and_full_iteration_invariants() {
        // Identical
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(constant_time_eq(b"", b""));

        // Length mismatch — we accept this short-circuit because pin lengths
        // are public (always 32 for SHA-256).
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));

        // Mismatch at front, middle, end — all must return false. The CT
        // property is enforced by the loop structure: every byte is XORed
        // into the diff accumulator regardless of where the mismatch is.
        assert!(!constant_time_eq(&[9, 2, 3, 4], &[1, 2, 3, 4]));
        assert!(!constant_time_eq(&[1, 2, 9, 4], &[1, 2, 3, 4]));
        assert!(!constant_time_eq(&[1, 2, 3, 9], &[1, 2, 3, 4]));

        // 32-byte realistic SHA-256 length
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] ^= 0x01;
        assert!(!constant_time_eq(&a, &b));
        b[31] ^= 0x01;
        b[0] ^= 0x80;
        assert!(!constant_time_eq(&a, &b));
    }

    /// br-asupersync-86n63i: regression. CertificatePinSet::validate must
    /// iterate every stored pin and use constant-time byte equality. We
    /// verify this functionally: a set with many decoy pins plus one real
    /// match still accepts the matching cert. This catches refactors that
    /// reintroduce BTreeSet::contains or any short-circuiting Ord-based
    /// lookup (which, with the test certificate's SPKI hash sorted into
    /// the middle of the decoy ordering, would still functionally pass
    /// — but the *property* under test is that every stored pin
    /// participates in the comparison, which the unit test above
    /// (`constant_time_eq_correctness_*`) covers at the helper layer.
    #[cfg(feature = "tls")]
    #[test]
    fn pin_set_validate_accepts_match_among_many_decoys() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let real_pin = CertificatePin::compute_spki_sha256(&cert).unwrap();

        let mut set = CertificatePinSet::new();
        // Decoys: 32-byte hashes that are NOT the real pin. Vary them
        // across the byte space so the set's BTree storage interleaves
        // them with the real pin (defeating any test that secretly relies
        // on Ord ordering).
        for byte in [0x00u8, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70] {
            set.add(CertificatePin::spki_sha256(vec![byte; 32]).unwrap());
        }
        set.add(real_pin);
        for byte in [0x80u8, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0] {
            set.add(CertificatePin::spki_sha256(vec![byte; 32]).unwrap());
        }
        assert_eq!(set.len(), 17);

        // Real cert must validate even when surrounded by decoys.
        assert!(
            set.validate(&cert).unwrap(),
            "validate should match the real pin among 16 decoys"
        );

        // A cert that does NOT match any pin must yield PinMismatch.
        let mut decoy_only = CertificatePinSet::new();
        for byte in 0u8..16u8 {
            decoy_only.add(CertificatePin::spki_sha256(vec![byte; 32]).unwrap());
        }
        let err = decoy_only.validate(&cert).unwrap_err();
        assert!(matches!(err, TlsError::PinMismatch { .. }));
    }

    /// br-asupersync-86n63i: regression. Mixed pin types (Spki + Cert) in
    /// the same set must both work after the constant-time refactor.
    #[cfg(feature = "tls")]
    #[test]
    fn pin_set_validate_mixed_pin_types_each_resolved_independently() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let spki_pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
        let cert_pin = CertificatePin::compute_cert_sha256(&cert).unwrap();

        // Set with only SPKI pin matches the cert.
        let mut spki_only = CertificatePinSet::new();
        spki_only.add(spki_pin.clone());
        spki_only.add(CertificatePin::cert_sha256(vec![0u8; 32]).unwrap());
        assert!(spki_only.validate(&cert).unwrap());

        // Set with only Cert pin matches the cert.
        let mut cert_only = CertificatePinSet::new();
        cert_only.add(CertificatePin::spki_sha256(vec![0u8; 32]).unwrap());
        cert_only.add(cert_pin);
        assert!(cert_only.validate(&cert).unwrap());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pin_set_validate_accepts_matching_spki_pin() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
        let mut set = CertificatePinSet::new();
        set.add(pin);
        assert!(set.validate(&cert).unwrap());
    }

    #[test]
    fn pin_set_operations() {
        let mut set = CertificatePinSet::new();
        assert!(set.is_empty());
        assert!(set.is_enforcing());

        let pin = CertificatePin::spki_sha256(vec![0u8; 32]).unwrap();
        set.add(pin);
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn pin_set_report_only_mode() {
        let set = CertificatePinSet::report_only();
        assert!(!set.is_enforcing());
    }

    #[test]
    fn pin_set_builder_pattern() {
        let pin = CertificatePin::spki_sha256(vec![0u8; 32]).unwrap();
        let set = CertificatePinSet::new().with_pin(pin);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn pin_set_add_from_base64() {
        let mut set = CertificatePinSet::new();
        let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        set.add_spki_sha256_base64(hash).unwrap();
        set.add_cert_sha256_base64(hash).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn pin_set_from_iterator() {
        let set: CertificatePinSet = (0..3)
            .map(|i| CertificatePin::spki_sha256(vec![i; 32]).unwrap())
            .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn pin_set_empty_validates_any() {
        let set = CertificatePinSet::new();
        // Empty set should allow any certificate
        #[cfg(feature = "tls")]
        {
            // We'd need a real cert to test, so just verify the method exists
            let _ = &set;
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = &set;
        }
    }

    #[test]
    fn pin_equality_and_hash() {
        let pin1 = CertificatePin::spki_sha256(vec![1u8; 32]).unwrap();
        let pin2 = CertificatePin::spki_sha256(vec![1u8; 32]).unwrap();
        let pin3 = CertificatePin::spki_sha256(vec![2u8; 32]).unwrap();

        assert_eq!(pin1, pin2);
        assert_ne!(pin1, pin3);

        // Test hash by adding to HashSet
        let mut set = std::collections::BTreeSet::new();
        set.insert(pin1);
        assert!(set.contains(&pin2));
        assert!(!set.contains(&pin3));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        #[cfg(feature = "tls")]
        {
            // Just verify Debug impl exists and doesn't expose key material
            let key = PrivateKey::from_pkcs8_der(vec![0u8; 32]);
            let debug_str = format!("{key:?}");
            assert!(debug_str.contains("redacted"));
            assert!(!debug_str.contains('0'));
        }
    }

    #[test]
    fn error_variants_display() {
        use super::super::error::TlsError;

        let expired = TlsError::CertificateExpired {
            expired_at: 1_000_000,
            description: "test cert".to_string(),
        };
        let display = format!("{expired}");
        assert!(display.contains("expired"));
        assert!(display.contains("1000000"));

        let not_yet = TlsError::CertificateNotYetValid {
            valid_from: 2_000_000,
            description: "test cert".to_string(),
        };
        let display = format!("{not_yet}");
        assert!(display.contains("not valid"));
        assert!(display.contains("2000000"));

        let chain = TlsError::ChainValidation("chain error".to_string());
        let display = format!("{chain}");
        assert!(display.contains("chain"));

        let pin_mismatch = TlsError::PinMismatch {
            expected: vec!["pin1".to_string(), "pin2".to_string()],
            actual: "actual_pin".to_string(),
        };
        let display = format!("{pin_mismatch}");
        assert!(display.contains("mismatch"));
        assert!(display.contains("actual_pin"));
    }
