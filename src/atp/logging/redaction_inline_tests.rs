    use super::*;
    use serde_json::json;

    #[test]
    fn test_private_key_redaction() {
        let rule = RedactionRule {
            field_pattern: "private_key".to_string(),
            redaction_type: RedactionType::PrivateKey,
            replacement: "[REDACTED_KEY]".to_string(),
        };

        let mut event = AtpEvent {
            schema_version: super::super::ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: "2026-05-20T12:00:00Z".to_string(),
            level: super::super::Level::Info,
            subsystem: super::super::AtpSubsystem::Security,
            event_type: "key_generated".to_string(),
            data: json!({
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ..."
            }),
            context: super::super::EventContext {
                session_id: "session123".to_string(),
                transfer_id: None,
                connection_id: None,
                peer_id: None,
                test_case_id: None,
                trace_id: "trace123".to_string(),
                span_id: "span123".to_string(),
            },
            redacted_fields: Vec::new(),
        };

        apply_redaction(&mut event, &[rule]);

        assert_eq!(event.data["private_key"], "[REDACTED_KEY]");
        assert!(
            event
                .redacted_fields
                .contains(&"data.private_key".to_string())
        );
    }

    #[test]
    fn test_path_redaction() {
        let rule = RedactionRule {
            field_pattern: "file_path".to_string(),
            redaction_type: RedactionType::SensitivePath,
            replacement: "[REDACTED_PATH]".to_string(),
        };

        let mut event = AtpEvent {
            schema_version: super::super::ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: "2026-05-20T12:00:00Z".to_string(),
            level: super::super::Level::Info,
            subsystem: super::super::AtpSubsystem::Disk,
            event_type: "file_read_started".to_string(),
            data: json!({
                "file_path": "/home/user/.ssh/id_rsa"
            }),
            context: super::super::EventContext {
                session_id: "session123".to_string(),
                transfer_id: None,
                connection_id: None,
                peer_id: None,
                test_case_id: None,
                trace_id: "trace123".to_string(),
                span_id: "span123".to_string(),
            },
            redacted_fields: Vec::new(),
        };

        apply_redaction(&mut event, &[rule]);

        assert_eq!(event.data["file_path"], "[REDACTED_PATH]");
    }

    #[test]
    fn path_rule_does_not_redact_path_id_metadata() {
        let mut value = json!({
            "file_path": "/home/user/project.log",
            "path_id": "direct-1",
            "path": "/home/user/.ssh/id_ed25519"
        });

        let redacted =
            redact_json_value(&mut value, &super::super::default_redaction_rules(), "data");

        assert_eq!(value["file_path"], "[REDACTED_PATH]");
        assert_eq!(value["path_id"], "direct-1");
        assert_eq!(value["path"], "[REDACTED_PATH]");
        assert_eq!(
            redacted,
            vec!["data.file_path".to_string(), "data.path".to_string()]
        );
    }

    #[test]
    fn sensitive_path_content_masks_username_and_key_basename() {
        let mut value = json!({
            "message": "failed to read /home/alice/.ssh/id_ed25519 during transfer"
        });

        let redacted =
            redact_json_value(&mut value, &super::super::default_redaction_rules(), "data");
        let message = value["message"].as_str().expect("message stays string");

        assert!(message.contains("/home/[USER]/[SENSITIVE_DIR]/[SENSITIVE_FILE]"));
        assert!(!message.contains("alice"));
        assert!(!message.contains(".ssh"));
        assert!(!message.contains("id_ed25519"));
        assert_eq!(redacted, vec!["data.message".to_string()]);
    }

    #[test]
    fn wildcard_custom_field_pattern_matches_nested_token_field() {
        let rules = [RedactionRule {
            field_pattern: "user.*token".to_string(),
            redaction_type: RedactionType::AuthToken,
            replacement: "[REDACTED_TOKEN]".to_string(),
        }];
        let mut value = json!({
            "user": {
                "access_token": "plain-value-that-must-not-leak"
            },
            "other": "safe"
        });

        let redacted = redact_json_value(&mut value, &rules, "data");

        assert_eq!(value["user"]["access_token"], "[REDACTED_TOKEN]");
        assert_eq!(value["other"], "safe");
        assert_eq!(redacted, vec!["data.user.access_token".to_string()]);
    }

    #[test]
    fn unsupported_custom_field_pattern_fails_closed() {
        let rules = [RedactionRule {
            field_pattern: "secret[0-9]".to_string(),
            redaction_type: RedactionType::AuthToken,
            replacement: "[REDACTED_CUSTOM]".to_string(),
        }];
        let mut value = json!({
            "public_note": "not a token"
        });

        let redacted = redact_json_value(&mut value, &rules, "data");

        assert_eq!(value["public_note"], "[REDACTED_CUSTOM]");
        assert_eq!(redacted, vec!["data.public_note".to_string()]);
    }
