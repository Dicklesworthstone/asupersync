    use super::*;
    use serde_json::json;

    #[test]
    fn test_bundle_creation() {
        let config = AtpLoggerConfig::default();
        let bundle = create_bundle("Test error", json!({"test": true}), &config);

        assert_eq!(bundle.schema_version, ATP_FAILURE_BUNDLE_SCHEMA_VERSION);
        assert!(!bundle.metadata.bundle_id.is_empty());
        assert_eq!(bundle.metadata.atp_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(bundle.additional_data["test"], true);
        assert!(bundle.qlog_data.is_some());
        assert!(bundle.path_log.is_some());
        assert!(bundle.repair_log.is_some());
        assert!(bundle.journal_digest.is_some());
        assert!(bundle.proof_bundle.is_some());
        assert!(bundle.replay_command.contains(&bundle.metadata.bundle_id));
        assert_eq!(bundle.trace_data.error_chain[0].message, "Test error");
    }

    #[test]
    fn test_bundle_serialization() {
        let config = AtpLoggerConfig::default();
        let bundle = create_bundle("Test error", json!({}), &config);

        let serialized = serde_json::to_string(&bundle).unwrap(); // ubs:ignore - test oracle
        let deserialized: FailureBundle = serde_json::from_str(&serialized).unwrap(); // ubs:ignore - test oracle

        assert_eq!(bundle.metadata.bundle_id, deserialized.metadata.bundle_id);
    }

    #[test]
    fn test_bundle_redacts_sensitive_context() {
        let config = AtpLoggerConfig::default();
        let bundle = create_bundle(
            "Bearer abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz leaked",
            json!({
                "capability_secret": "cap://super-secret-capability",
                "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "path": "/home/alice/.ssh/id_ed25519"
            }),
            &config,
        );

        let serialized = serde_json::to_string(&bundle).unwrap(); // ubs:ignore - test oracle
        assert!(!serialized.contains("super-secret"));
        assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(!serialized.contains("/home/alice"));
        assert!(serialized.contains("[REDACTED_CAPABILITY]"));
        assert!(serialized.contains("[REDACTED_CONTENT_HASH]"));
    }
