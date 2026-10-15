//! Integration tests for ATP adapter system.
//!
//! Tests adapter negotiation, downgrade policies, performance caveats,
//! and end-to-end compatibility across different transport types.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::atp::object::{ContentId, ObjectId};
    use crate::types::TraceId;
    use futures_lite::future::block_on;
    use std::collections::HashMap;
    use std::time::Duration;

    fn trace_id(ts_ms: u64, random: u128) -> TraceId {
        TraceId::from_parts(ts_ms, random)
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(label.as_bytes()))
    }

    /// Test adapter preference ordering and fallback behavior.
    #[test]
    fn test_adapter_preference_ordering() {
        block_on(async {
            let config = AdapterConfig {
                preferred_adapters: vec![
                    AdapterType::NativeQuic,
                    AdapterType::WebTransport,
                    AdapterType::MasqueConnectUdp,
                    AdapterType::TcpTlsFallback,
                ],
                downgrade_policy: DowngradePolicy::AllowDowngrade,
                required_features: vec![RequiredFeature::ObjectVerification],
                ..Default::default()
            };

            let mut manager = AdapterManager::new(config);
            let trace_id = trace_id(1, 1);

            let negotiation = manager
                .negotiate_adapter(&[RequiredFeature::ObjectVerification], trace_id)
                .await
                .unwrap();

            // Should select the first preferred adapter (NativeQuic)
            assert_eq!(negotiation.selected_adapter, AdapterType::NativeQuic);
            assert!(negotiation.downgrade_reasons.is_empty());
        });
    }

    /// Test strict downgrade policy preventing fallbacks.
    #[test]
    fn test_strict_downgrade_policy() {
        block_on(async {
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::NativeQuic],
                downgrade_policy: DowngradePolicy::Strict,
                required_features: vec![RequiredFeature::ObjectVerification],
                ..Default::default()
            };

            let mut manager = AdapterManager::new(config);
            let trace_id = trace_id(1, 1);

            // This should succeed since we're simulating ideal conditions
            let result = manager
                .negotiate_adapter(&[RequiredFeature::ObjectVerification], trace_id)
                .await;

            assert!(result.is_ok());
        });
    }

    /// Test feature requirement enforcement.
    #[test]
    fn test_feature_requirement_enforcement() {
        block_on(async {
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::TcpTlsFallback],
                downgrade_policy: DowngradePolicy::AllowDowngrade,
                required_features: vec![RequiredFeature::ObjectVerification],
                ..Default::default()
            };

            let mut manager = AdapterManager::new(config);
            let trace_id = trace_id(1, 1);

            // Test that TCP fallback meets object verification requirements
            let negotiation = manager
                .negotiate_adapter(&[RequiredFeature::ObjectVerification], trace_id)
                .await
                .unwrap();

            assert_eq!(negotiation.selected_adapter, AdapterType::TcpTlsFallback);

            // Verify performance caveats are reported for TCP fallback
            assert!(!negotiation.performance_caveats.is_empty());
            assert!(
                negotiation
                    .performance_caveats
                    .iter()
                    .any(|caveat| { matches!(caveat, PerformanceCaveat::HeadOfLineBlocking) })
            );
        });
    }

    /// Test performance caveat reporting for different adapters.
    #[test]
    fn test_performance_caveat_reporting() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let trace_id = trace_id(1, 1);

            // Test WebTransport caveats
            let config_wt = AdapterConfig {
                preferred_adapters: vec![AdapterType::WebTransport],
                ..Default::default()
            };
            manager.config = config_wt;

            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
            assert!(
                negotiation
                    .performance_caveats
                    .iter()
                    .any(|caveat| { matches!(caveat, PerformanceCaveat::NestedTransportOverhead) })
            );

            // Test TCP fallback caveats
            let config_tcp = AdapterConfig {
                preferred_adapters: vec![AdapterType::TcpTlsFallback],
                ..Default::default()
            };
            manager.config = config_tcp;

            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::TcpTlsFallback);

            // Verify all expected TCP caveats are present
            let has_hol_blocking = negotiation
                .performance_caveats
                .iter()
                .any(|caveat| matches!(caveat, PerformanceCaveat::HeadOfLineBlocking));
            let has_no_mux = negotiation
                .performance_caveats
                .iter()
                .any(|caveat| matches!(caveat, PerformanceCaveat::NoMultiplexing));
            let has_latency = negotiation
                .performance_caveats
                .iter()
                .any(|caveat| matches!(caveat, PerformanceCaveat::IncreasedLatency(_)));

            assert!(has_hol_blocking);
            assert!(has_no_mux);
            assert!(has_latency);
        });
    }

    /// Test adapter feature parity matrix accuracy.
    #[test]
    fn test_feature_parity_matrix() {
        let manager = AdapterManager::new(AdapterConfig::default());

        // Native QUIC should have full support for all features
        let native_parity = manager.get_adapter_parity(AdapterType::NativeQuic).unwrap();
        assert_eq!(native_parity.object_support, FeatureSupport::Full);
        assert_eq!(native_parity.stream_support, FeatureSupport::Full);
        assert_eq!(native_parity.proof_support, FeatureSupport::Full);
        assert_eq!(native_parity.datagram_support, FeatureSupport::Full);

        // WebTransport should have good support with some limitations
        let wt_parity = manager
            .get_adapter_parity(AdapterType::WebTransport)
            .unwrap();
        assert_eq!(wt_parity.object_support, FeatureSupport::Full);
        assert_eq!(wt_parity.stream_support, FeatureSupport::Full);
        assert_eq!(wt_parity.proof_support, FeatureSupport::Partial); // Browser limitations
        assert_eq!(wt_parity.datagram_support, FeatureSupport::Full);

        // MASQUE should have proxy-related limitations
        let masque_parity = manager
            .get_adapter_parity(AdapterType::MasqueConnectUdp)
            .unwrap();
        assert_eq!(masque_parity.object_support, FeatureSupport::Full);
        assert_eq!(masque_parity.stream_support, FeatureSupport::Downgraded); // UDP simulation
        assert_eq!(masque_parity.datagram_support, FeatureSupport::Full);

        // TCP fallback should have significant limitations
        let tcp_parity = manager
            .get_adapter_parity(AdapterType::TcpTlsFallback)
            .unwrap();
        assert_eq!(tcp_parity.object_support, FeatureSupport::Full);
        assert_eq!(tcp_parity.stream_support, FeatureSupport::Downgraded); // HOL blocking
        assert_eq!(tcp_parity.datagram_support, FeatureSupport::Unsupported); // No datagrams
    }

    /// Test adapter session management.
    #[test]
    fn test_adapter_session_management() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let trace_id = trace_id(1, 1);
            let object_id = test_object_id("adapter-session-management");

            // Negotiate adapter
            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();

            // Start session
            let session_id = manager
                .start_session(negotiation.clone(), object_id)
                .await
                .unwrap();

            // Verify session exists
            assert!(manager.active_sessions.contains_key(&session_id));

            // Verify metrics updated
            assert!(
                manager
                    .metrics()
                    .sessions_by_adapter
                    .contains_key(&negotiation.selected_adapter)
            );
        });
    }

    /// Test adapter metadata generation.
    #[test]
    fn test_adapter_metadata_generation() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let trace_id = trace_id(42, 123);

            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();

            // Verify metadata structure
            assert_eq!(negotiation.adapter_metadata.version, "1.0.0");
            assert!(
                negotiation
                    .adapter_metadata
                    .security_params
                    .tls_version
                    .is_some()
            );
            assert!(negotiation.adapter_metadata.replay_pointer.is_some());
            assert_eq!(
                negotiation
                    .adapter_metadata
                    .replay_pointer
                    .as_ref()
                    .unwrap(),
                &format!("trace-{}", trace_id.as_u128())
            );
        });
    }

    /// Test caveat reporting configuration.
    #[test]
    fn test_caveat_reporting_configuration() {
        block_on(async {
            let config = AdapterConfig {
                caveat_reporting: CaveatReporting {
                    report_performance: true,
                    report_hol_blocking: true,
                    report_diagnostic_limits: true,
                    include_timing: true,
                },
                preferred_adapters: vec![AdapterType::TcpTlsFallback],
                ..Default::default()
            };

            let mut manager = AdapterManager::new(config);
            let trace_id = trace_id(1, 1);

            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();

            // With full caveat reporting enabled, TCP fallback should report all issues
            assert!(!negotiation.performance_caveats.is_empty());
            assert!(negotiation.performance_caveats.len() >= 4); // HOL, NoMux, Latency, Throughput
        });
    }

    /// Test downgrade policy configurations.
    #[test]
    fn test_downgrade_policy_variations() {
        block_on(async {
            let trace_id = trace_id(1, 1);

            // Test AllowSpecific policy
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::NativeQuic],
                downgrade_policy: DowngradePolicy::AllowSpecific(vec![
                    AdapterType::WebTransport,
                    AdapterType::TcpTlsFallback,
                ]),
                ..Default::default()
            };

            let mut manager = AdapterManager::new(config);
            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();

            // Should succeed with first preference
            assert_eq!(negotiation.selected_adapter, AdapterType::NativeQuic);

            // Test FallbackOnly policy
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::NativeQuic],
                downgrade_policy: DowngradePolicy::FallbackOnly(AdapterType::TcpTlsFallback),
                ..Default::default()
            };

            manager.config = config;
            let negotiation = manager.negotiate_adapter(&[], trace_id).await.unwrap();

            // Should succeed with preferred adapter in this simulation
            assert!(matches!(
                negotiation.selected_adapter,
                AdapterType::NativeQuic | AdapterType::TcpTlsFallback
            ));
        });
    }

    /// Test adapter-specific configuration handling.
    #[test]
    fn test_adapter_specific_configurations() {
        let mut adapter_configs = HashMap::new();
        adapter_configs.insert(
            AdapterType::WebTransport,
            AdapterSpecificConfig {
                connection_timeout: Duration::from_secs(10),
                max_concurrent: 100,
                feature_flags: {
                    let mut flags = HashMap::new();
                    flags.insert("enable_datagrams".to_string(), true);
                    flags.insert("enable_reliability".to_string(), true);
                    flags
                },
                performance_config: PerformanceConfig {
                    buffer_sizes: BufferSizes {
                        send_buffer: 65536,
                        recv_buffer: 65536,
                        max_frame_size: 16384,
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
            },
        );

        let config = AdapterConfig {
            preferred_adapters: vec![AdapterType::WebTransport],
            adapter_configs,
            ..Default::default()
        };

        let manager = AdapterManager::new(config);

        // Verify configuration is accessible
        assert!(
            manager
                .config
                .adapter_configs
                .contains_key(&AdapterType::WebTransport)
        );
        let wt_config = manager
            .config
            .adapter_configs
            .get(&AdapterType::WebTransport)
            .unwrap();
        assert_eq!(wt_config.connection_timeout, Duration::from_secs(10));
        assert_eq!(wt_config.max_concurrent, 100);
        assert!(
            wt_config
                .feature_flags
                .get("enable_datagrams")
                .unwrap_or(&false)
        );
    }

    /// Test end-to-end adapter workflow with different scenarios.
    #[test]
    fn test_end_to_end_adapter_workflow() {
        block_on(async {
            // Scenario 1: Ideal conditions - should select native QUIC
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let trace_id = trace_id(1, 1);

            let negotiation = manager
                .negotiate_adapter(
                    &[
                        RequiredFeature::ObjectVerification,
                        RequiredFeature::StreamProtocol,
                    ],
                    trace_id,
                )
                .await
                .unwrap();

            assert_eq!(negotiation.selected_adapter, AdapterType::NativeQuic);

            // Start session and verify it works
            let object_id = test_object_id("end-to-end-adapter-workflow");
            let session_id = manager.start_session(negotiation, object_id).await.unwrap();
            assert!(!session_id.is_empty());

            // Scenario 2: Browser environment - prefer WebTransport
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::WebTransport, AdapterType::TcpTlsFallback],
                required_features: vec![RequiredFeature::ObjectVerification],
                ..Default::default()
            };

            let mut browser_manager = AdapterManager::new(config);
            let negotiation = browser_manager
                .negotiate_adapter(&[RequiredFeature::ObjectVerification], trace_id)
                .await
                .unwrap();

            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
            assert!(
                negotiation
                    .performance_caveats
                    .iter()
                    .any(|caveat| { matches!(caveat, PerformanceCaveat::NestedTransportOverhead) })
            );

            // Scenario 3: Highly restrictive environment - TCP only
            let config = AdapterConfig {
                preferred_adapters: vec![AdapterType::TcpTlsFallback],
                downgrade_policy: DowngradePolicy::Strict,
                required_features: vec![RequiredFeature::ObjectVerification],
                ..Default::default()
            };

            let mut restrictive_manager = AdapterManager::new(config);
            let negotiation = restrictive_manager
                .negotiate_adapter(&[RequiredFeature::ObjectVerification], trace_id)
                .await
                .unwrap();

            assert_eq!(negotiation.selected_adapter, AdapterType::TcpTlsFallback);
            assert!(negotiation.performance_caveats.len() >= 3); // Multiple TCP limitations
        });
    }

    /// Test display implementations for human-readable output.
    #[test]
    fn test_display_implementations() {
        assert_eq!(format!("{}", AdapterType::NativeQuic), "native-quic");
        assert_eq!(format!("{}", AdapterType::WebTransport), "webtransport");
        assert_eq!(
            format!("{}", AdapterType::MasqueConnectUdp),
            "masque-connect-udp"
        );
        assert_eq!(format!("{}", AdapterType::TcpTlsFallback), "tcp-tls-443");

        assert_eq!(format!("{}", FeatureSupport::Full), "full");
        assert_eq!(format!("{}", FeatureSupport::Partial), "partial");
        assert_eq!(format!("{}", FeatureSupport::Downgraded), "downgraded");
        assert_eq!(format!("{}", FeatureSupport::Unsupported), "unsupported");
    }

    /// Test serialization roundtrip for configuration persistence.
    #[test]
    fn test_serialization_roundtrip() {
        let config = AdapterConfig {
            preferred_adapters: vec![AdapterType::NativeQuic, AdapterType::WebTransport],
            downgrade_policy: DowngradePolicy::AllowDowngrade,
            required_features: vec![
                RequiredFeature::ObjectVerification,
                RequiredFeature::StreamProtocol,
            ],
            ..Default::default()
        };

        // Serialize to JSON
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("native-quic"));
        assert!(json.contains("webtransport"));

        // Deserialize back
        let deserialized: AdapterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.preferred_adapters.len(), 2);
        assert_eq!(deserialized.preferred_adapters[0], AdapterType::NativeQuic);
        assert_eq!(
            deserialized.preferred_adapters[1],
            AdapterType::WebTransport
        );
    }
}
