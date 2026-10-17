    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn test_tcptls_config_default() {
        let config = TcpTlsConfig::default();
        assert_eq!(config.tls_config.min_tls_version, TlsVersion::Tls12);
        assert_eq!(config.connection_config.no_delay, true);
        assert!(config.fallback_config.enable_warnings);
    }

    #[test]
    fn test_tcptls_connection_lifecycle() {
        block_on(async {
            let mut adapter = TcpTlsAdapter::new(TcpTlsConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));

            // Connect
            let connection_id = adapter
                .connect(object_id, "server.example.com:443")
                .await
                .unwrap();
            assert_eq!(adapter.stats.active_connections, 1);

            // Send frame
            let data = b"ATP frame over TCP/TLS";
            adapter.send_frame(&connection_id, data).await.unwrap();

            // Receive frame
            let inbound = b"ATP response over TCP/TLS".to_vec();
            adapter
                .queue_inbound_frame(&connection_id, inbound.clone())
                .unwrap();
            let received = adapter.receive_frame(&connection_id).await.unwrap();
            assert_eq!(received, inbound);

            // Close connection
            adapter.close_connection(&connection_id).await.unwrap();
            assert_eq!(adapter.stats.active_connections, 0);
        });
    }

    #[test]
    fn test_tcptls_negotiation() {
        block_on(async {
            let adapter = TcpTlsAdapter::new(TcpTlsConfig::default());
            let trace_id = TraceId::from_parts(1, 1);

            let negotiation = adapter.negotiate(trace_id).await.unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::TcpTlsFallback);

            // TCP/TLS should have significant performance caveats
            assert!(!negotiation.performance_caveats.is_empty());
            let has_hol_blocking = negotiation
                .performance_caveats
                .iter()
                .any(|c| matches!(c, PerformanceCaveat::HeadOfLineBlocking));
            assert!(has_hol_blocking);
        });
    }

    #[test]
    fn tcptls_rejects_unwired_insecure_cert_validation_modes() {
        for mode in [
            TlsCertValidation::SkipHostname,
            TlsCertValidation::AcceptSelfSigned,
            TlsCertValidation::Disabled,
        ] {
            let mut config = TcpTlsConfig::default();
            config.tls_config.cert_validation = mode;
            let mut adapter = TcpTlsAdapter::new(config);
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([2; 32]));

            let connect_err = block_on(adapter.connect(object_id, "server.example.com:443"))
                .expect_err("unwired weak certificate-validation mode must fail closed");
            assert_eq!(connect_err.kind(), ErrorKind::ConfigError);
            let message = connect_err
                .message()
                .expect("fail-closed config error should explain the unwired TLS verifier path");
            assert!(
                message.contains("cert_validation") && message.contains(&format!("{mode:?}")),
                "unexpected connect error message for {mode:?}: {message}"
            );

            let negotiation_err = block_on(adapter.negotiate(TraceId::from_parts(2, 2)))
                .expect_err("negotiation must not advertise unwired weak cert validation");
            assert_eq!(negotiation_err.kind(), ErrorKind::ConfigError);
            let message = negotiation_err
                .message()
                .expect("negotiation config error should explain the unwired TLS verifier path");
            assert!(
                message.contains("real TLS verifier"),
                "unexpected negotiation error message for {mode:?}: {message}"
            );
        }
    }

    #[test]
    fn test_hol_blocking_detection() {
        block_on(async {
            let mut config = TcpTlsConfig::default();
            config
                .fallback_config
                .performance_thresholds
                .hol_blocking_threshold = Duration::from_millis(1);
            let mut adapter = TcpTlsAdapter::new(config);
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let connection_id = adapter
                .connect(object_id, "server.example.com:443")
                .await
                .unwrap();

            // Send large frame that should trigger HOL blocking warning
            let large_data = vec![0xAA; 128 * 1024]; // 128KB frame
            adapter
                .send_frame(&connection_id, &large_data)
                .await
                .unwrap();

            // Check that HOL blocking was detected
            let connection = adapter.connections.get(&connection_id).unwrap();
            assert!(connection.stats.hol_blocking_events > 0);
            assert!(!adapter.warnings().is_empty());
            assert!(adapter.stats.hol_blocking_warnings > 0);
        });
    }

    #[test]
    fn test_empty_receive_reports_channel_empty() {
        block_on(async {
            let mut adapter = TcpTlsAdapter::new(TcpTlsConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let connection_id = adapter
                .connect(object_id, "server.example.com:443")
                .await
                .unwrap();

            let result = adapter.receive_frame(&connection_id).await;

            assert!(matches!(
                result,
                Err(err) if err.kind() == ErrorKind::ChannelEmpty
            ));
        });
    }
