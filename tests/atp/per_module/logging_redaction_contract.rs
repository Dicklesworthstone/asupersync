//! ATP per-module structured logging redaction contract tests.

use asupersync::atp::logging::{
    ATP_LOG_EVENT_SCHEMA_VERSION, AtpEvent, AtpLogger, AtpSubsystem, EventContext,
};
use asupersync::observability::LogLevel;
use serde_json::json;

fn context() -> EventContext {
    EventContext {
        session_id: "session-1".to_string(),
        transfer_id: Some("transfer-1".to_string()),
        connection_id: Some("conn-1".to_string()),
        peer_id: Some("peer-secret-identity".to_string()),
        test_case_id: Some("ATP-NR3".to_string()),
        trace_id: "trace-1".to_string(),
        span_id: "span-1".to_string(),
    }
}

fn assert_no_sensitive_fragments(rendered: &str) {
    for fragment in [
        "very-secret",
        "secret-token",
        "keep-this-token-private",
        "0123456789abcdef",
        "fedcba9876543210",
        "/Users/alice",
        "/home/alice",
        "peer-secret-identity",
    ] {
        assert!(
            !rendered.contains(fragment),
            "rendered ATP log leaked sensitive fragment {fragment:?}: {rendered}",
        );
    }
}

#[test]
fn every_atp_subsystem_redacts_shared_sensitive_fields() {
    let logger = AtpLogger::new();
    let expected_redacted_fields = vec![
        "context.peer_id",
        "data.auth_token",
        "data.capability_secret",
        "data.content_hash",
        "data.path",
        "data.peer_id",
    ];

    for subsystem in AtpSubsystem::all() {
        let event_type = logger
            .schema_event_types(subsystem)
            .and_then(|event_types| event_types.first())
            .unwrap_or_else(|| panic!("{} should have a schema event", subsystem.as_str()))
            .clone();
        let event = AtpEvent {
            schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: "2026-05-20T00:00:00Z".to_string(),
            level: LogLevel::Info,
            subsystem: subsystem.clone(),
            event_type,
            data: json!({
                "auth_token": "authorization: bearer keep-this-token-private",
                "capability_secret": "cap://very-secret-transfer-capability-token",
                "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "path": "/Users/alice/.ssh/id_ed25519",
                "peer_id": "peer-secret-identity",
                "safe_marker": format!("safe-{}", subsystem.as_str()),
            }),
            context: context(),
            redacted_fields: Vec::new(),
        };

        let rendered = logger
            .render_event(&event)
            .unwrap_or_else(|err| panic!("{} event should render: {err}", subsystem.as_str()));
        assert_no_sensitive_fragments(&rendered);

        let parsed: AtpEvent =
            serde_json::from_str(&rendered).expect("rendered event should stay schema-valid JSON");
        assert_eq!(parsed.subsystem, *subsystem);
        assert_eq!(parsed.schema_version, ATP_LOG_EVENT_SCHEMA_VERSION);
        assert_eq!(parsed.redacted_fields, expected_redacted_fields);
        let expected_safe_marker = format!("safe-{}", subsystem.as_str());
        assert_eq!(
            parsed.data["safe_marker"].as_str(),
            Some(expected_safe_marker.as_str()),
            "safe metadata should survive redaction for {}",
            subsystem.as_str()
        );
        logger.validate_event(&parsed).unwrap_or_else(|err| {
            panic!(
                "rendered {} event should validate: {err}",
                subsystem.as_str()
            )
        });
    }
}

#[test]
fn logging_redaction_is_idempotent_for_nested_sensitive_fields() {
    let logger = AtpLogger::new();
    let mut event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-20T00:00:00Z".to_string(),
        level: LogLevel::Info,
        subsystem: AtpSubsystem::Security,
        event_type: "audit_event".to_string(),
        data: json!({
            "auth_token": "token=secret-token-value",
            "content_hash": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "nested": [
                {"capability_secret": "cap://very-secret-transfer-capability-token"},
                {"path": "/home/alice/.gnupg/private.key"},
                {"safe_marker": "keep-me"}
            ],
            "peer_id": "peer-secret-identity"
        }),
        context: context(),
        redacted_fields: Vec::new(),
    };

    let once = logger
        .log_event(&mut event)
        .expect("first redaction should render");
    let snapshot_after_once = serde_json::to_value(&event).expect("event should serialize");

    let twice = logger
        .log_event(&mut event)
        .expect("second redaction should render");
    let snapshot_after_twice =
        serde_json::to_value(&event).expect("event should serialize after second redaction");

    assert_eq!(once, twice, "rendered log should be stable after redaction");
    assert_eq!(
        snapshot_after_once, snapshot_after_twice,
        "redaction should be an idempotent transform"
    );
    assert_eq!(event.data["nested"][2]["safe_marker"], "keep-me");
    assert_eq!(
        event.redacted_fields,
        vec![
            "context.peer_id",
            "data.auth_token",
            "data.content_hash",
            "data.nested[0].capability_secret",
            "data.nested[1].path",
            "data.peer_id",
        ]
    );
    assert_no_sensitive_fragments(&twice);
}
