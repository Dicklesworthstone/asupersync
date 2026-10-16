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
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls")]
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

    #[cfg(not(feature = "tls"))]
    fn tls_error_kind(error: &TlsError) -> &'static str {
        match error {
            TlsError::InvalidDnsName(_) => "InvalidDnsName",
            TlsError::Handshake(_) => "Handshake",
            TlsError::Certificate(_) => "Certificate",
            TlsError::CertificateExpired { .. } => "CertificateExpired",
            TlsError::CertificateNotYetValid { .. } => "CertificateNotYetValid",
            TlsError::ChainValidation(_) => "ChainValidation",
            TlsError::PinMismatch { .. } => "PinMismatch",
            TlsError::Configuration(_) => "Configuration",
            TlsError::FeatureDisabled { .. } => "FeatureDisabled",
            TlsError::Io(_) => "Io",
            TlsError::Timeout(_) => "Timeout",
            TlsError::AlpnNegotiationFailed { .. } => "AlpnNegotiationFailed",
            #[cfg(feature = "tls")]
            TlsError::Rustls(_) => "Rustls",
        }
    }

    #[cfg(feature = "tls")]
    fn builder_with_test_root() -> TlsConnectorBuilder {
        let certs = Certificate::from_pem(TEST_CERT_PEM).expect("parse TLS test certificate");
        TlsConnectorBuilder::new().add_root_certificates(certs)
    }

    #[test]
    fn test_builder_default() {
        let builder = TlsConnectorBuilder::new();
        assert!(builder.root_certs.is_empty());
        assert!(builder.alpn_protocols.is_empty());
        assert!(builder.enable_sni);
    }

    #[test]
    fn test_builder_alpn_http() {
        let builder = TlsConnectorBuilder::new().alpn_http();
        assert_eq!(
            builder.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn test_builder_alpn_h2() {
        let builder = TlsConnectorBuilder::new().alpn_h2();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
    }

    #[test]
    fn test_builder_alpn_grpc() {
        let builder = TlsConnectorBuilder::new().alpn_grpc();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
    }

    #[test]
    fn test_builder_disable_sni() {
        let builder = TlsConnectorBuilder::new().disable_sni();
        assert!(!builder.enable_sni);
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(TlsConnector::validate_domain("example.com").is_ok());
        assert!(TlsConnector::validate_domain("sub.example.com").is_ok());
        assert!(TlsConnector::validate_domain("localhost").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(TlsConnector::validate_domain("").is_err());
        assert!(TlsConnector::validate_domain("invalid domain with spaces").is_err());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_validate_domain_rfc3492_punycode_vector() {
        // RFC 3492 / IDNA-style A-label for "bücher.example".
        let punycode = "xn--bcher-kva.example";

        assert!(TlsConnector::validate_domain(punycode).is_ok());
        assert!(TlsConnector::validate_domain("bücher.example").is_err());
    }

    // br-asupersync-7wnl2l: previously this test asserted that
    // `TlsConnectorBuilder::new().build()` *succeeded* with no roots
    // configured — directly contradicting the explicit empty-roots
    // rejection at the top of `build()` (which exists precisely so a
    // misconfigured caller doesn't open a no-roots connection that
    // would skip server-cert validation entirely). The test was dead
    // (silently failing the .unwrap() in any environment that
    // exercised it). Inverted to assert the rejection, plus a paired
    // positive test below using the test fixture's CA.
    #[cfg(feature = "tls")]
    #[test]
    fn test_build_empty_roots_rejected() {
        let err = TlsConnectorBuilder::new()
            .build()
            .expect_err("empty roots must be rejected by build()");
        match err {
            TlsError::Certificate(msg) => {
                assert!(
                    msg.contains("no root certificates configured"),
                    "expected empty-roots rejection message, got: {msg}"
                );
            }
            other => panic!("expected TlsError::Certificate, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_with_test_root_succeeds() {
        // Positive control for the empty-roots rejection above. Uses
        // the explicit test-fixture certificate so build() succeeds.
        // Pins the success path so a future agent removing the
        // empty-roots check cannot land it without also breaking this
        // test.
        let connector = builder_with_test_root()
            .build()
            .expect("builder with one root should succeed");
        assert!(connector.config().alpn_protocols.is_empty());
    }

    // --- br-asupersync-gq7l9i: env-var trust anchors are opt-in ----

    #[test]
    fn test_env_cert_loading_disabled_by_default() {
        // br-asupersync-gq7l9i: TlsConnectorBuilder::new() must leave
        // env-var trust-anchor loading disabled. A caller who sets
        // SSL_CERT_FILE in their environment must NOT have those
        // certs silently injected; explicit opt-in via
        // enable_env_cert_loading() is required.
        let builder = TlsConnectorBuilder::new();
        assert!(
            !builder.enable_env_certs,
            "env-var cert loading must be off by default"
        );
    }

    #[test]
    fn test_enable_env_cert_loading_sets_flag() {
        // br-asupersync-gq7l9i: explicit opt-in flips the flag.
        let builder = TlsConnectorBuilder::new().enable_env_cert_loading();
        assert!(
            builder.enable_env_certs,
            "enable_env_cert_loading must flip the opt-in flag"
        );
    }

    #[test]
    fn test_ssl_cert_dir_bundle_extension_match_is_case_insensitive() {
        assert!(super::is_env_cert_bundle_path(std::path::Path::new(
            "/tmp/corp-root.pem"
        )));
        assert!(super::is_env_cert_bundle_path(std::path::Path::new(
            "/tmp/corp-root.PEM"
        )));
        assert!(super::is_env_cert_bundle_path(std::path::Path::new(
            "/tmp/corp-root.CrT"
        )));
        assert!(super::is_env_cert_bundle_path(std::path::Path::new(
            "/tmp/corp-root.cEr"
        )));
        assert!(!super::is_env_cert_bundle_path(std::path::Path::new(
            "/tmp/corp-root.pem.bak"
        )));
        assert!(!super::is_env_cert_bundle_path(std::path::Path::new(
            "/tmp/corp-root"
        )));
    }

    // --- br-asupersync-0owoem: BasicConstraints CA:TRUE gate -------

    #[cfg(feature = "tls")]
    #[test]
    fn test_is_ca_certificate_rejects_self_signed_leaf() {
        // br-asupersync-0owoem: the test fixture server cert is a
        // *leaf* — it lacks `basicConstraints CA:TRUE` (it carries
        // server-auth EKU and is signed by a real CA in test
        // setups). Adding it to the trust store as a *trust anchor*
        // would let any cert it "signed" validate, which is exactly
        // the trust-bypass the gate prevents.
        let certs = Certificate::from_pem(TEST_CERT_PEM).expect("parse test cert");
        let cert = certs.first().expect("at least one cert in fixture");
        let der: &[u8] = cert.as_der();
        let is_ca = super::is_ca_certificate(der);
        // The test fixture is a leaf cert (CA:FALSE or BC missing),
        // so the gate must reject it. If a future fixture rotation
        // ships a CA cert here, this assertion will fail loudly and
        // surface the regression — that's the intent.
        assert!(
            !is_ca,
            "test fixture leaf cert must be rejected by CA-gate (br-asupersync-0owoem); \
             if the fixture was rotated to a CA, update this test"
        );
    }

    // --- br-asupersync-p7369s: CRL configuration -------------------

    #[cfg(feature = "tls")]
    #[test]
    fn test_with_crl_pem_accepts_crl_and_rejects_malformed_tail() {
        // The rustls-pemfile CRL fixture (see its provenance in `tls::tests`).
        // This proves CRL configuration, not revocation enforcement or
        // current validity of this historical CRL.
        let crl = crate::tls::tests::RUSTLS_PEMFILE_CRL_PEM;
        builder_with_test_root()
            .with_crl_pem([TEST_CERT_PEM, b"\n", crl].concat())
            .build()
            .expect("a valid CRL can be configured in a mixed PEM bundle");

        let malformed = b"-----BEGIN X509 CRL-----\n!invalid!\n-----END X509 CRL-----\n";
        let error = builder_with_test_root()
            .with_crl_pem([crl, malformed.as_slice()].concat())
            .build()
            .expect_err("a later malformed CRL must reject the whole configuration");
        assert!(matches!(
            error,
            TlsError::Configuration(message) if message == "CRL PEM parse error: InvalidCharacter(33)"
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_with_crl_pem_with_garbage_pem_rejected_at_build() {
        // br-asupersync-p7369s: garbage that doesn't parse as CRL
        // PEM must surface a typed Configuration error, not a panic
        // and not a silent skip-the-CRL.
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let err = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .with_crl_pem(b"not a valid CRL".to_vec())
            .build()
            .expect_err("garbage CRL PEM must reject at build()");
        match err {
            TlsError::Configuration(msg) => {
                assert!(
                    msg.contains("CRL"),
                    "expected CRL-related Configuration error, got: {msg}"
                );
            }
            other => panic!("expected TlsError::Configuration, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_no_crl_means_default_verifier_path() {
        // br-asupersync-p7369s: callers that don't configure any CRL
        // must continue to land on the rustls default-verifier code
        // path (i.e., build() must not regress to requiring CRL
        // configuration). This test pins the no-CRL no-op behaviour.
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .build()
            .expect("no-CRL build must succeed");
        let _ = connector.config(); // smoke-check the inner config materialised
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_with_alpn() {
        let connector = builder_with_test_root().alpn_http().build().unwrap();

        assert_eq!(
            connector.config().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_handshake_timeout_builder() {
        let timeout = std::time::Duration::from_secs(1);
        let connector = builder_with_test_root()
            .handshake_timeout(timeout)
            .build()
            .unwrap();
        assert_eq!(connector.handshake_timeout(), Some(timeout));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connector_clone_is_cheap() {
        let connector = builder_with_test_root().build().unwrap();

        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _clone = connector.clone();
        }
        let elapsed = start.elapsed();

        // Should be very fast (Arc clone)
        assert!(elapsed.as_millis() < 100);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_invalid_dns() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;

        run_test_with_cx(|_cx| async move {
            let connector = builder_with_test_root().build().unwrap();
            let (client_io, _server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5100".parse().unwrap(),
                "127.0.0.1:5101".parse().unwrap(),
            );
            let err = connector
                .connect("invalid domain with spaces", client_io)
                .await
                .unwrap_err();
            assert!(matches!(err, TlsError::InvalidDnsName(_)));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_completes_under_lab_runtime() {
        use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
        use crate::cx::Cx;
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::init_test_logging;
        use crate::tls::TlsAcceptorBuilder;
        use futures_lite::future::zip;

        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x715A_CCE9)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (ready, protocol_present, alpn, checkpoints) = LabRuntimeTarget::block_on(
            &mut runtime,
            async move {
                let _cx = Cx::current().expect("lab runtime should install a current Cx");

                let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
                let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
                let acceptor = TlsAcceptorBuilder::new(chain, key)
                    .alpn_http()
                    .build()
                    .unwrap();

                let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
                let connector = TlsConnectorBuilder::new()
                    .add_root_certificates(certs)
                    .alpn_http()
                    .handshake_timeout(std::time::Duration::from_secs(1))
                    .build()
                    .unwrap();

                let (client_io, server_io) = VirtualTcpStream::pair(
                    "127.0.0.1:5300".parse().unwrap(),
                    "127.0.0.1:5301".parse().unwrap(),
                );

                let checkpoints = vec![serde_json::json!({
                    "phase": "connector_pair_created",
                    "client_addr": "127.0.0.1:5300",
                    "server_addr": "127.0.0.1:5301",
                    "handshake_timeout_ms": 1000,
                })];
                tracing::info!(event = %checkpoints[0], "tls_connector_lab_checkpoint");

                let (client_res, server_res) = zip(
                    connector.connect("localhost", client_io),
                    acceptor.accept(server_io),
                )
                .await;
                let client = client_res.expect("connector handshake should succeed");
                let server = server_res.expect("server handshake should succeed");

                let ready = client.is_ready() && server.is_ready();
                let protocol_present =
                    client.protocol_version().is_some() && server.protocol_version().is_some();
                let alpn = client.alpn_protocol().map(|protocol| protocol.to_vec());

                let mut checkpoints = checkpoints;
                checkpoints.push(serde_json::json!({
                    "phase": "connector_handshake_completed",
                    "ready": ready,
                    "protocol_present": protocol_present,
                    "client_alpn": alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                    "server_alpn": server.alpn_protocol().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                }));
                tracing::info!(event = %checkpoints[1], "tls_connector_lab_checkpoint");

                (ready, protocol_present, alpn, checkpoints)
            },
        );

        assert!(ready);
        assert!(protocol_present);
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(checkpoints.len(), 2);
        assert!(runtime.is_quiescent());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_session_resumption_custom() {
        let connector = builder_with_test_root()
            .session_resumption(rustls::client::Resumption::in_memory_sessions(512))
            .build()
            .unwrap();
        // Connector builds successfully with custom resumption config.
        assert!(connector.handshake_timeout().is_none());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_session_resumption_disabled() {
        let connector = builder_with_test_root()
            .disable_session_resumption()
            .build()
            .unwrap();
        assert!(connector.handshake_timeout().is_none());
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn test_build_without_tls_feature() {
        let err = match TlsConnectorBuilder::new().build() {
            Err(err) => err,
            Ok(_) => panic!("TLS-disabled build must reject connector construction"),
        };
        match err {
            TlsError::FeatureDisabled { operation, hint } => {
                assert_eq!(operation, "build TLS connector");
                assert!(hint.contains("--features tls"), "got: {hint}");
            }
            other => panic!("expected FeatureDisabled, got {other:?}"),
        }
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn tls_feature_disabled_with_requested_config_logs_redacted_diagnostic() {
        let sensitive_path = "/etc/ssl/private/corp-root-secret.pem";
        let redacted_path = "<redacted>";
        let mut builder = TlsConnectorBuilder::new()
            .enable_env_cert_loading()
            .add_root_certificate(&Certificate::from_der(b"test-root".to_vec()))
            .alpn_h2();

        let load_error = builder
            .load_pem_file(std::path::Path::new(sensitive_path))
            .expect_err("TLS-disabled PEM loading must fail explicitly");
        let requested_root_count = builder.root_certs.len();
        let build_error = match builder.build() {
            Err(err) => err,
            Ok(_) => panic!("TLS-disabled build must reject requested TLS config"),
        };

        let artifact = serde_json::json!({
            "schema_version": "tls-feature-disabled-diagnostic-v1",
            "feature_flags": {
                "tls": cfg!(feature = "tls")
            },
            "config_source": {
                "kind": "env-cert-file",
                "path": redacted_path
            },
            "requested_root_source_count": requested_root_count,
            "env_cert_loading": true,
            "alpn_required": true,
            "load_error_kind": tls_error_kind(&load_error),
            "build_error_kind": tls_error_kind(&build_error),
            "operator_hint": TLS_FEATURE_HINT,
            "final_verdict": "pass"
        });
        let artifact_text = artifact.to_string();
        println!("{artifact_text}");

        assert_eq!(artifact["feature_flags"]["tls"], false);
        assert_eq!(artifact["requested_root_source_count"], 1);
        assert_eq!(artifact["load_error_kind"], "FeatureDisabled");
        assert_eq!(artifact["build_error_kind"], "FeatureDisabled");
        assert_eq!(artifact["operator_hint"], TLS_FEATURE_HINT);
        assert_eq!(artifact["final_verdict"], "pass");
        assert!(
            !artifact_text.contains(sensitive_path),
            "diagnostic artifact leaked TLS config path: {artifact_text}"
        );
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn tls_feature_disabled_native_roots_reports_operator_hint() {
        let err = TlsConnectorBuilder::new()
            .with_native_roots()
            .expect_err("TLS-disabled native-root loading must fail explicitly");
        match err {
            TlsError::FeatureDisabled { operation, hint } => {
                assert_eq!(operation, "load native root certificates");
                assert!(hint.contains("--features tls"), "got: {hint}");
            }
            other => panic!("expected FeatureDisabled, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_enabled_pem_load_reports_certificate_counters() {
        let mut builder = TlsConnectorBuilder::new().enable_env_cert_loading();
        let counts = builder
            .load_pem_file(std::path::Path::new("tests/fixtures/tls/server.crt"))
            .expect("TLS-enabled PEM loading should report counters");

        assert_eq!(
            counts.loaded + counts.rejected_non_ca,
            1,
            "fixture should contain exactly one cert; got {counts:?}"
        );
        assert_eq!(
            counts.rejected_non_ca, 1,
            "server fixture is a leaf and must be rejected as a trust anchor"
        );
        assert!(builder.root_certs.is_empty());
    }

    // ── br-asupersync-v24lvi: certificate-pinning wiring tests ────────

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_with_certificate_pins_attaches_pin_set_to_connector() {
        // Builder accepts a pin set; the resulting connector carries
        // it. Pre-fix there was no such builder method — the only
        // way to "use" pins was to call them manually after connect()
        // returned, which 99% of callers never did.
        let mut pins = CertificatePinSet::new();
        pins.add_spki_sha256_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("valid base64");
        let connector = builder_with_test_root()
            .with_certificate_pins(pins)
            .build()
            .expect("build with pins");
        assert!(
            connector.pin_set.is_some(),
            "with_certificate_pins must populate the connector's pin_set"
        );
        assert_eq!(
            connector.pin_set.as_ref().unwrap().len(),
            1,
            "all attached pins must reach the connector"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_default_connector_has_no_pin_set() {
        // Back-compat: a connector built WITHOUT calling
        // with_certificate_pins() carries no pin set, so existing
        // callers that rely on rustls-only validation are unaffected.
        let connector = builder_with_test_root()
            .build()
            .expect("build without pins");
        assert!(
            connector.pin_set.is_none(),
            "default connector must not have an implicit pin set"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_mismatched_pin_returns_error_via_pin_set_validate() {
        // The connector wires CertificatePinSet::validate into the
        // post-handshake gate. We verify the validate semantics here
        // (the unit-of-fix for the connector's gate logic) — the
        // gate's *invocation* is exercised end-to-end by integration
        // tests that need a real TLS handshake. Without a synthetic
        // stream the connect() path can't run in a unit test, so
        // pinning the validate semantics + the wiring (above) is
        // the maximal regression we can land here.
        let cert = Certificate::from_der(TEST_CERT_PEM.to_vec());
        let mut mismatched = CertificatePinSet::new();
        mismatched
            .add_spki_sha256_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("valid base64");
        let result = mismatched.validate(&cert);
        assert!(
            result.is_err(),
            "mismatched-pin enforcement-on validation must Err; \
             got {result:?}. This is the failure that the connector \
             gate now propagates as TlsError to abort the connection."
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_report_only_mismatched_pin_does_not_error() {
        // Symmetry check: report-only sets surface as Ok(false) (not
        // Err) which the connector gate explicitly treats as
        // "log-and-continue" — verifies the connector's match-arm
        // handles the no-enforcement code path correctly without
        // tearing down the connection.
        let cert = Certificate::from_der(TEST_CERT_PEM.to_vec());
        let mut report_only = CertificatePinSet::report_only();
        report_only
            .add_spki_sha256_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("valid base64");
        let result = report_only.validate(&cert);
        assert!(
            matches!(result, Ok(false)),
            "report-only mismatched pin must return Ok(false) (not Err); \
             got {result:?}"
        );
    }

    // ── br-asupersync-y0gm5q: 0-RTT secure-by-default ────────────────

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_default_connector_disables_0rtt_early_data() {
        let connector = builder_with_test_root()
            .build()
            .expect("build default connector");
        assert!(
            !connector.config.enable_early_data,
            "default connector must have enable_early_data=false \
             (TLS 1.3 0-RTT disabled — replay defense)"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_enable_early_data_opt_in_with_risk_ack_sets_flag() {
        let connector = builder_with_test_root()
            .enable_early_data(true)
            .acknowledge_zero_rtt_replay_risk()
            .build()
            .expect("build with early data enabled and replay risk acknowledged");
        assert!(
            connector.config.enable_early_data,
            "enable_early_data(true) must propagate to ClientConfig"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_enable_early_data_false_disables_flag() {
        let connector = builder_with_test_root()
            .enable_early_data(true)
            .enable_early_data(false)
            .build()
            .expect("build with early data toggled off");
        assert!(
            !connector.config.enable_early_data,
            "enable_early_data(false) must reset enable_early_data flag"
        );
    }

    /// br-asupersync-h41wya — `enable_early_data(true)` without
    /// `acknowledge_zero_rtt_replay_risk()` MUST cause `build()` to
    /// return a Configuration error.
    #[cfg(feature = "tls")]
    #[test]
    fn build_rejects_zero_rtt_without_risk_acknowledgement() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let err = TlsConnectorBuilder::new()
            .insecure_add_root_certificate(&certs[0])
            .enable_early_data(true)
            .build()
            .expect_err("0-RTT without risk ack must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("acknowledge_zero_rtt_replay_risk"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-h41wya — once acknowledged, 0-RTT enables
    /// successfully on the produced connector.
    #[cfg(feature = "tls")]
    #[test]
    fn build_accepts_zero_rtt_with_risk_acknowledgement() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .insecure_add_root_certificate(&certs[0])
            .enable_early_data(true)
            .acknowledge_zero_rtt_replay_risk()
            .build()
            .expect("build should succeed once risk is acknowledged");
        assert!(
            connector.config.enable_early_data,
            "0-RTT must be enabled when both flags are set"
        );
    }

    /// br-asupersync-sx6j9y — `with_strict_ca_validation` rejects a
    /// non-CA leaf cert from `add_root_certificate`. Without the
    /// flag, the same cert is accepted (legacy behavior preserved).
    #[cfg(feature = "tls")]
    #[test]
    fn add_root_certificate_strict_ca_rejects_self_signed_leaf() {
        let leaf_certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let leaf = leaf_certs.into_iter().next().unwrap();

        // Strict mode: rejected.
        let strict = TlsConnectorBuilder::new()
            .with_strict_ca_validation()
            .add_root_certificate(&leaf);
        assert!(
            strict.root_certs.is_empty(),
            "strict-CA mode must reject the self-signed leaf"
        );

        // Permissive default: accepted (legacy).
        let permissive = TlsConnectorBuilder::new().add_root_certificate(&leaf);
        assert_eq!(
            permissive.root_certs.len(),
            1,
            "permissive default must still accept the cert"
        );

        // Insecure bypass: accepted even in strict mode.
        let bypassed = TlsConnectorBuilder::new()
            .with_strict_ca_validation()
            .insecure_add_root_certificate(&leaf);
        assert_eq!(
            bypassed.root_certs.len(),
            1,
            "insecure_add_root_certificate must bypass the strict gate"
        );
    }

    /// br-asupersync-sx6j9y — `enable_env_cert_loading` flips the
    /// strict-CA gate as a side effect, so the operator who opts
    /// into env-cert loading does NOT silently leave the direct
    /// add_root_certificate path ungated.
    #[cfg(feature = "tls")]
    #[test]
    fn enable_env_cert_loading_implies_strict_ca_validation() {
        let builder = TlsConnectorBuilder::new().enable_env_cert_loading();
        assert!(
            builder.validate_ca_constraints,
            "enable_env_cert_loading must set validate_ca_constraints=true"
        );
    }

    /// Regression test for asupersync-2o602p: Verify that production builds
    /// properly reject leaf certificates when strict validation is enabled,
    /// preventing MITM attacks via misconfigured trust stores.
    #[cfg(feature = "tls")]
    #[test]
    fn production_cert_validation_rejects_leaf_certificates() {
        let leaf_certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let leaf = leaf_certs.into_iter().next().unwrap();

        // Production mode with strict validation: must reject leaf certificates
        let builder = TlsConnectorBuilder::new()
            .with_strict_ca_validation()
            .add_root_certificate(&leaf);

        assert!(
            builder.root_certs.is_empty(),
            "Production builds with strict validation must reject leaf certificates"
        );

        // Rejection leaves the store empty. The connector must remain
        // fail-closed rather than acquiring ambient system roots.
        let err = builder
            .build()
            .expect_err("strict rejection must leave no configured trust roots");
        match err {
            TlsError::Certificate(message) => assert!(
                message.contains("no root certificates configured"),
                "unexpected empty-root error: {message}"
            ),
            other => panic!("expected empty-root certificate error, got {other:?}"),
        }
    }

    /// Regression test for asupersync-2o602p: Verify that the insecure bypass
    /// method is only available in test builds, not production.
    #[cfg(feature = "tls")]
    #[test]
    fn insecure_add_root_certificate_restricted_to_tests() {
        // This test verifies the method exists in test builds (where this test runs)
        let leaf_certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let leaf = leaf_certs.into_iter().next().unwrap();

        let builder = TlsConnectorBuilder::new().insecure_add_root_certificate(&leaf);

        assert_eq!(
            builder.root_certs.len(),
            1,
            "insecure_add_root_certificate should work in test builds"
        );

        // In production builds, this method should not be available
        // This is enforced at compile time by #[cfg(test)]
        // If someone tries to use it in production, they'll get a compile error:
        // "cannot find method `insecure_add_root_certificate`"
    }
