    use super::*;
    use crate::atp::object::{ContentId, ObjectId};
    use futures_lite::future::block_on;
    use std::collections::HashMap;

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(label.as_bytes()))
    }

    fn adapter_specific_config(max_concurrent: usize) -> AdapterSpecificConfig {
        AdapterSpecificConfig {
            connection_timeout: Duration::from_secs(10),
            max_concurrent,
            feature_flags: HashMap::new(),
            performance_config: PerformanceConfig {
                buffer_sizes: BufferSizes {
                    send_buffer: 64 * 1024,
                    recv_buffer: 64 * 1024,
                    max_frame_size: 16 * 1024,
                },
                retry_policy: RetryPolicy {
                    max_attempts: 3,
                    base_delay: Duration::from_millis(100),
                    max_delay: Duration::from_secs(5),
                    backoff_factor: 2.0,
                },
                keep_alive: KeepAliveConfig {
                    interval: Duration::from_secs(30),
                    timeout: Duration::from_secs(60),
                    enabled: true,
                },
            },
        }
    }

    #[test]
    fn test_adapter_parity_matrix() {
        let manager = AdapterManager::new(AdapterConfig::default());

        // Native QUIC should have full support
        let native_parity = manager.get_adapter_parity(AdapterType::NativeQuic).unwrap();
        assert_eq!(native_parity.object_support, FeatureSupport::Full);
        assert_eq!(native_parity.stream_support, FeatureSupport::Full);

        // TCP fallback should have limited datagram support
        let tcp_parity = manager
            .get_adapter_parity(AdapterType::TcpTlsFallback)
            .unwrap();
        assert_eq!(tcp_parity.datagram_support, FeatureSupport::Unsupported);
        assert_eq!(tcp_parity.stream_support, FeatureSupport::Downgraded);
    }

    #[test]
    fn test_feature_requirements() {
        let manager = AdapterManager::new(AdapterConfig::default());
        let tcp_parity = manager
            .get_adapter_parity(AdapterType::TcpTlsFallback)
            .unwrap();

        // Object verification should be supported
        assert!(
            manager.check_feature_requirement(tcp_parity, &RequiredFeature::ObjectVerification)
        );

        // Stream protocol should be supported (even if downgraded)
        assert!(manager.check_feature_requirement(tcp_parity, &RequiredFeature::StreamProtocol));
    }

    #[test]
    fn test_adapter_negotiation() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let requirements = vec![RequiredFeature::ObjectVerification];
            let trace_id = TraceId::from_parts(1, 1);

            let negotiation = manager
                .negotiate_adapter(&requirements, trace_id)
                .await
                .unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::NativeQuic);
        });
    }

    #[test]
    fn adapter_negotiation_skips_unmet_feature_requirements() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            manager.config.preferred_adapters =
                vec![AdapterType::NativeQuic, AdapterType::WebTransport];
            manager
                .parity_matrix
                .get_mut(&AdapterType::NativeQuic)
                .expect("native parity")
                .object_support = FeatureSupport::Unsupported;

            let negotiation = manager
                .negotiate_adapter(
                    &[RequiredFeature::ObjectVerification],
                    TraceId::from_parts(1, 1),
                )
                .await
                .expect("compatible fallback should be selected");

            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
            assert!(
                negotiation.downgrade_reasons.is_empty(),
                "selected adapter should satisfy the requested features"
            );
        });
    }

    #[test]
    fn adapter_config_required_features_are_enforced() {
        block_on(async {
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::NativeQuic, AdapterType::WebTransport],
                required_features: vec![RequiredFeature::ObjectVerification],
                ..Default::default()
            };
            let mut manager = AdapterManager::new(config);
            manager
                .parity_matrix
                .get_mut(&AdapterType::NativeQuic)
                .expect("native parity")
                .object_support = FeatureSupport::Unsupported;

            let negotiation = manager
                .negotiate_adapter(&[], TraceId::from_parts(1, 1))
                .await
                .expect("configured requirement should force compatible fallback");

            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
        });
    }

    #[test]
    fn negotiation_does_not_count_as_started_session() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let negotiation = manager
                .negotiate_adapter(&[], TraceId::from_parts(1, 1))
                .await
                .expect("negotiation should succeed");

            assert_eq!(
                manager
                    .metrics()
                    .sessions_by_adapter
                    .get(&negotiation.selected_adapter),
                None
            );
        });
    }

    #[test]
    fn start_session_generates_unique_ids_and_preserves_sessions() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let negotiation = manager
                .negotiate_adapter(&[], TraceId::from_parts(1, 1))
                .await
                .expect("negotiation should succeed");
            let object_id = test_object_id("session-id-collision-regression");

            let first = manager
                .start_session(negotiation.clone(), object_id.clone())
                .await
                .expect("first session should start");
            let second = manager
                .start_session(negotiation.clone(), object_id)
                .await
                .expect("second session should start without replacing the first");

            assert_ne!(first, second);
            assert!(manager.active_sessions.contains_key(&first));
            assert!(manager.active_sessions.contains_key(&second));
            assert_eq!(manager.active_sessions.len(), 2);
            assert_eq!(
                manager
                    .metrics()
                    .sessions_by_adapter
                    .get(&negotiation.selected_adapter),
                Some(&2)
            );
        });
    }

    #[test]
    fn start_session_enforces_adapter_concurrency_limit() {
        block_on(async {
            let mut adapter_configs = HashMap::new();
            adapter_configs.insert(AdapterType::NativeQuic, adapter_specific_config(1));
            let config = AdapterConfig {
                adapter_configs,
                ..Default::default()
            };
            let mut manager = AdapterManager::new(config);
            let negotiation = manager
                .negotiate_adapter(&[], TraceId::from_parts(1, 1))
                .await
                .expect("negotiation should succeed");

            manager
                .start_session(
                    negotiation.clone(),
                    test_object_id("session-capacity-first"),
                )
                .await
                .expect("first session should fit configured capacity");
            let err = manager
                .start_session(negotiation, test_object_id("session-capacity-second"))
                .await
                .expect_err("second session should exceed configured capacity");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            assert_eq!(manager.active_sessions.len(), 1);
        });
    }

    #[test]
    fn caveat_reporting_flags_filter_reported_caveats() {
        block_on(async {
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::TcpTlsFallback],
                caveat_reporting: CaveatReporting {
                    report_performance: false,
                    report_hol_blocking: false,
                    report_diagnostic_limits: false,
                    include_timing: false,
                },
                ..Default::default()
            };
            let mut manager = AdapterManager::new(config);

            let negotiation = manager
                .negotiate_adapter(&[], TraceId::from_parts(1, 1))
                .await
                .expect("TCP fallback should still negotiate");

            assert!(negotiation.performance_caveats.is_empty());
        });
    }

    #[test]
    fn test_adapter_display() {
        assert_eq!(format!("{}", AdapterType::NativeQuic), "native-quic");
        assert_eq!(format!("{}", AdapterType::WebTransport), "webtransport");
        assert_eq!(
            format!("{}", AdapterType::MasqueConnectUdp),
            "masque-connect-udp"
        );
        assert_eq!(format!("{}", AdapterType::TcpTlsFallback), "tcp-tls-443");
    }

    #[test]
    fn test_feature_support_display() {
        assert_eq!(format!("{}", FeatureSupport::Full), "full");
        assert_eq!(format!("{}", FeatureSupport::Partial), "partial");
        assert_eq!(format!("{}", FeatureSupport::Downgraded), "downgraded");
        assert_eq!(format!("{}", FeatureSupport::Unsupported), "unsupported");
    }
