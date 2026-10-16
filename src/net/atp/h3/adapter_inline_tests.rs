    use super::*;

    #[test]
    fn test_adapter_creation() {
        let config = AdapterConfig::default();
        let adapter = AtpH3Adapter::new(config);

        assert_eq!(adapter.sessions.len(), 0);
        assert!(adapter.feature_support().supported.len() > 0);
        assert!(adapter.feature_support().unsupported.len() > 0);
    }

    #[test]
    fn test_feature_support_query() {
        let adapter = AtpH3Adapter::new(AdapterConfig::default());

        assert!(adapter.is_feature_supported("ATP frame codec"));
        assert!(!adapter.is_feature_supported("Raw UDP socket"));
        assert!(!adapter.is_feature_supported("QUIC migration"));
    }

    #[test]
    fn test_negotiation_report_is_stable_and_adapter_scoped() {
        let adapter = AtpH3Adapter::new(AdapterConfig::default());
        let report = adapter.negotiation_report();

        assert_eq!(report.adapter_kind, H3_WEBTRANSPORT_ADAPTER_KIND);
        assert_eq!(report.foundation_kind, NATIVE_ATP_FOUNDATION_KIND);
        assert!(report.adapter_after_native);
        assert!(!report.replacement_for_native_quic);
        assert_eq!(report, adapter.negotiation_report());
        assert!(
            report
                .downgrades
                .iter()
                .any(|downgrade| downgrade.reason_code == "raw_udp_unavailable")
        );
    }

    #[test]
    fn test_session_management() {
        let mut adapter = AtpH3Adapter::new(AdapterConfig::default());

        // Create session
        let session_id = "test-session-1".to_string();
        assert!(adapter.create_session(session_id.clone()).is_ok());
        assert_eq!(adapter.sessions.len(), 1);

        // Get session
        assert!(adapter.get_session(&session_id).is_some());

        // Close session
        assert!(adapter.close_session(&session_id).is_ok());
        assert_eq!(adapter.sessions.len(), 0);
    }

    #[test]
    fn test_create_session_returns_inserted_session() {
        let mut adapter = AtpH3Adapter::new(AdapterConfig::default());
        let session_id = "test-session-entry".to_string();

        let session = adapter.create_session(session_id.clone()).unwrap();

        assert_eq!(session.session_id(), session_id);
        assert!(adapter.get_session("test-session-entry").is_some());
    }

    #[test]
    fn test_duplicate_session_id_is_rejected() {
        let mut adapter = AtpH3Adapter::new(AdapterConfig::default());
        let session_id = "test-session-duplicate".to_string();

        assert!(adapter.create_session(session_id.clone()).is_ok());

        let err = adapter
            .create_session(session_id)
            .expect_err("duplicate session id should fail");
        assert!(err.to_string().contains("already exists"));
        assert_eq!(adapter.stats().active_sessions, 1);
    }
