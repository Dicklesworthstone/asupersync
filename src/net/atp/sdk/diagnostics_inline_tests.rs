    use super::*;
    use crate::net::atp::sdk::{AtpSdk, SessionConfig};
    use futures_lite::future::block_on;

    #[test]
    fn path_diagnosis_basic() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let target_peer = PeerId::from_label("target_peer");
            let diagnosis = sdk.path_diagnose(&cx, target_peer).await.unwrap();

            assert_eq!(diagnosis.peer_id, target_peer);
            assert!(!diagnosis.path_candidates.is_empty());
            assert!(diagnosis.timestamp_nanos > 0);
        });

        crate::test_complete!("path_diagnosis_basic");
    }

    #[test]
    fn path_quality_scoring() {
        let good_quality = PathQuality {
            rtt_ms: 20.0,
            packet_loss_percent: 0.1,
            bandwidth_bps: 100_000_000,
            jitter_ms: 1.0,
            reliability_score: 0.95,
        };

        let poor_quality = PathQuality {
            rtt_ms: 300.0,
            packet_loss_percent: 10.0,
            bandwidth_bps: 1_000_000,
            jitter_ms: 50.0,
            reliability_score: 0.5,
        };

        assert!(good_quality.overall_score() > poor_quality.overall_score());
        assert!(good_quality.is_acceptable());
        assert!(!poor_quality.is_acceptable());
    }

    #[test]
    fn nat_traversal_assessment() {
        let nat_result = NatTraversalResult {
            local_nat_type: NatType::FullCone,
            remote_nat_type: Some(NatType::Symmetric),
            hole_punching_feasible: false,
            success_probability: 0.2,
            recommended_strategies: vec![NatStrategy::TurnRelay],
        };

        assert_eq!(nat_result.local_nat_type, NatType::FullCone);
        assert!(!nat_result.hole_punching_feasible);
        assert!(nat_result.success_probability < 0.5);
    }

    #[test]
    fn diagnostic_warning_severity() {
        let info = DiagnosticWarning {
            severity: WarningSeverity::Info,
            category: WarningCategory::Performance,
            message: "Suboptimal path selected".to_string(),
            suggested_action: Some("Try alternative path".to_string()),
        };

        let critical = DiagnosticWarning {
            severity: WarningSeverity::Critical,
            category: WarningCategory::Connectivity,
            message: "No paths available".to_string(),
            suggested_action: Some("Check network configuration".to_string()),
        };

        assert!(critical.severity > info.severity);
    }

    #[test]
    fn transfer_strategy_defaults() {
        let strategy = TransferStrategy::default();

        assert_eq!(strategy.primary_method, TransferMethod::DirectP2P);
        assert!(strategy.fallback_methods.contains(&TransferMethod::Relay));
        assert!(strategy.enable_compression);
        assert_eq!(strategy.parallel_streams, 1);
    }

    #[test]
    fn path_monitoring() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            use crate::net::atp::protocol::{
                CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope,
                SessionContextKind,
            };

            let config = SessionConfig::default();
            let local_peer = config.local_peer;
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                crate::net::atp::sdk::SessionOptions::direct(peer).with_grants(vec![
                    CapabilityGrant::new(
                        CapabilityGrantId::from_label("path-monitoring"),
                        peer,
                        local_peer,
                        [CapabilityAction::Read, CapabilityAction::Write],
                        CapabilityScope::for_context(SessionContextKind::Direct),
                    ),
                ]);
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let monitor = session.start_path_monitoring(&cx, 100).await.unwrap();
            assert!(monitor.last_diagnosis().is_none());
        });

        crate::test_complete!("path_monitoring");
    }
