use super::*;
use serde_json::json;
use std::time::{Duration, UNIX_EPOCH};

fn context() -> EventContext {
    EventContext {
        session_id: "session-1".to_string(),
        transfer_id: Some("transfer-1".to_string()),
        connection_id: Some("conn-1".to_string()),
        peer_id: Some("peer-secret-identity".to_string()),
        test_case_id: Some("ATP-N6".to_string()),
        trace_id: "trace-1".to_string(),
        span_id: "span-1".to_string(),
    }
}

fn render_event_or_fail(logger: &AtpLogger, event: &AtpEvent) -> String {
    match logger.render_event(event) {
        Ok(rendered) => rendered,
        Err(err) => {
            assert!(false, "event must render: {err:?}");
            String::new()
        }
    }
}

#[test]
fn all_subsystems_and_test_lanes_have_schema_entries() {
    let logger = AtpLogger::new();
    let mut problems = Vec::new();

    for subsystem in AtpSubsystem::all() {
        match logger.schema_event_types(subsystem) {
            Some(event_types) if !event_types.is_empty() => {}
            Some(_) => problems.push(format!(
                "schema for {} must not be empty",
                subsystem.as_str()
            )),
            None => problems.push(format!("missing schema for {}", subsystem.as_str())),
        }
    }

    assert!(problems.is_empty(), "{}", problems.join("; "));
}

#[test]
fn json_diagnostic_output_is_stable_and_redacted() {
    let logger = AtpLogger::new();
    let event = AtpEvent {
        timestamp: "2026-05-20T00:00:00Z".to_string(),
        level: Level::Info,
        subsystem: AtpSubsystem::Security,
        event_type: "capability_issued".to_string(),
        data: json!({
            "capability_secret": "cap://very-secret-transfer-capability-token",
            "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "path": "/home/alice/.ssh/id_ed25519"
        }),
        context: context(),
        redacted_fields: Vec::new(),
    };

    let rendered = render_event_or_fail(&logger, &event);

    assert_eq!(
        rendered,
        "{\"timestamp\":\"2026-05-20T00:00:00Z\",\"level\":\"info\",\"subsystem\":\"Security\",\"event_type\":\"capability_issued\",\"data\":{\"capability_secret\":\"[REDACTED_CAPABILITY]\",\"content_hash\":\"[REDACTED_CONTENT_HASH]\",\"path\":\"[REDACTED_PATH]\"},\"context\":{\"session_id\":\"session-1\",\"transfer_id\":\"transfer-1\",\"connection_id\":\"conn-1\",\"peer_id\":\"[REDACTED_PEER_ID]\",\"test_case_id\":\"ATP-N6\",\"trace_id\":\"trace-1\",\"span_id\":\"span-1\"},\"redacted_fields\":[\"context.peer_id\",\"data.capability_secret\",\"data.content_hash\",\"data.path\"]}"
    );
    assert!(!rendered.contains("very-secret"));
    assert!(!rendered.contains("/home/alice"));
}

#[test]
fn human_diagnostic_output_is_stable() {
    let logger = AtpLogger::with_config(AtpLoggerConfig {
        format: LogFormat::Human,
        ..AtpLoggerConfig::default()
    });
    let event = AtpEvent {
        timestamp: "2026-05-20T00:00:00Z".to_string(),
        level: Level::Warn,
        subsystem: AtpSubsystem::Path,
        event_type: "path_selected".to_string(),
        data: json!({"path_id": "direct-1"}),
        context: EventContext::deterministic("session-1", "trace-1"),
        redacted_fields: Vec::new(),
    };

    let rendered = render_event_or_fail(&logger, &event);

    assert_eq!(
        rendered,
        "2026-05-20T00:00:00Z [WARN] path.path_selected trace=trace-1 span=root data={\"path_id\":\"direct-1\"} redacted="
    );
}

#[test]
fn unknown_event_type_is_rejected() {
    let logger = AtpLogger::new();
    let event = AtpEvent {
        timestamp: "2026-05-20T00:00:00Z".to_string(),
        level: Level::Info,
        subsystem: AtpSubsystem::Transfer,
        event_type: "not_in_contract".to_string(),
        data: json!({}),
        context: EventContext::deterministic("session-1", "trace-1"),
        redacted_fields: Vec::new(),
    };

    assert!(matches!(
        logger.render_event(&event),
        Err(AtpLogError::UnknownEventType { .. })
    ));
}

#[test]
fn timestamp_renderer_emits_real_rfc3339_utc_seconds() {
    assert_eq!(
        format_system_time_rfc3339(UNIX_EPOCH),
        "1970-01-01T00:00:00Z"
    );
    assert_eq!(
        format_system_time_rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_400)),
        "2000-02-29T00:00:00Z"
    );
    assert_eq!(
        format_system_time_rfc3339(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        "2023-11-14T22:13:20Z"
    );
}

mod external_macro_call_site {
    pub fn invoke_atp_log_macro_without_timestamp_in_scope() {
        let context = crate::atp::logging::EventContext::deterministic("session-1", "trace-1");
        crate::atp_log!(
            crate::atp::logging::AtpSubsystem::UnitTest,
            "test_started",
            crate::observability::LogLevel::Info,
            serde_json::json!({"case": "macro_path"}),
            context
        );
    }
}

#[test]
fn atp_log_macro_uses_crate_qualified_timestamp_path() {
    external_macro_call_site::invoke_atp_log_macro_without_timestamp_in_scope();
}
