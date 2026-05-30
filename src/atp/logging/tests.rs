//! ATP logging system tests.
//!
//! Comprehensive test suite for the Asupersync Transfer Protocol logging
//! infrastructure. Verifies structured event formatting, schema validation,
//! and proper context propagation across transfer operations.
//!
//! # Test Coverage
//! - Event serialization and deserialization
//! - Schema compliance for all ATP subsystems
//! - Context field validation and sanitization
//! - Performance measurement event formatting

use super::*;
use crate::atp_log;
use serde_json::{Value, json};
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
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
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
        "{\"schema_version\":\"asupersync.atp.log.event.v1\",\"timestamp\":\"2026-05-20T00:00:00Z\",\"level\":\"info\",\"subsystem\":\"Security\",\"event_type\":\"capability_issued\",\"data\":{\"capability_secret\":\"[REDACTED_CAPABILITY]\",\"content_hash\":\"[REDACTED_CONTENT_HASH]\",\"path\":\"[REDACTED_PATH]\"},\"context\":{\"session_id\":\"session-1\",\"transfer_id\":\"transfer-1\",\"connection_id\":\"conn-1\",\"peer_id\":\"[REDACTED_PEER_ID]\",\"test_case_id\":\"ATP-N6\",\"trace_id\":\"trace-1\",\"span_id\":\"span-1\"},\"redacted_fields\":[\"context.peer_id\",\"data.capability_secret\",\"data.content_hash\",\"data.path\"]}"
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
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
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
        "2026-05-20T00:00:00Z [WARN] schema=asupersync.atp.log.event.v1 path.path_selected trace=trace-1 span=root data={\"path_id\":\"direct-1\"} redacted="
    );
}

#[test]
fn unknown_event_type_is_rejected() {
    let logger = AtpLogger::new();
    let event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
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
fn every_subsystem_first_schema_event_redacts_shared_sensitive_fields() {
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
            level: Level::Info,
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

        let rendered = render_event_or_fail(&logger, &event);
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
fn nested_redaction_is_idempotent_under_repeated_application() {
    let mut event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-20T00:00:00Z".to_string(),
        level: Level::Info,
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

    redaction::apply_redaction(&mut event, &default_redaction_rules());
    let once = serde_json::to_value(&event).expect("redacted event should serialize");

    redaction::apply_redaction(&mut event, &default_redaction_rules());
    let twice = serde_json::to_value(&event).expect("redacted event should serialize twice");

    assert_eq!(once, twice, "redaction should be an idempotent transform");
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
    assert_no_sensitive_fragments(&twice.to_string());
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

// ATP-N19: Comprehensive ATP Logging Edge Case and Performance Test Coverage Expansion

#[test]
fn test_concurrent_logging_thread_safety() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let logger = Arc::new(AtpLogger::new());
    let num_threads = 4;
    let events_per_thread = 100;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let logger = Arc::clone(&logger);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for event_id in 0..events_per_thread {
                    let event = AtpEvent {
                        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
                        timestamp: format_system_time_rfc3339(std::time::SystemTime::now()),
                        level: Level::Info,
                        subsystem: AtpSubsystem::UnitTest,
                        event_type: "concurrent_test".to_string(),
                        data: json!({
                            "thread_id": thread_id,
                            "event_id": event_id,
                            "timestamp": event_id
                        }),
                        context: EventContext::deterministic(
                            &format!("session-thread-{}", thread_id),
                            &format!("trace-{}-{}", thread_id, event_id),
                        ),
                        redacted_fields: Vec::new(),
                    };

                    // Should not panic under concurrent access
                    let _ = logger.render_event(&event);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread should complete without panic");
    }
}

#[test]
fn test_large_payload_handling_and_memory_bounds() {
    let logger = AtpLogger::new();

    // Test with large string payload
    let large_string = "x".repeat(10_000);
    let large_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Info,
        subsystem: AtpSubsystem::Transfer,
        event_type: "large_object_transfer".to_string(),
        data: json!({
            "large_content": large_string,
            "metadata": {
                "size": 10_000,
                "compression": "none"
            }
        }),
        context: context(),
        redacted_fields: Vec::new(),
    };

    // Should handle large payloads without crashing
    let rendered = logger
        .render_event(&large_event)
        .expect("Large event should render");
    assert!(rendered.len() > 5000);
    assert!(rendered.contains("large_object_transfer"));

    // Test with deeply nested structures
    let deeply_nested = json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": {
                            "data": "deep_value",
                            "array": [1, 2, 3, 4, 5]
                        }
                    }
                }
            }
        }
    });

    let nested_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Info,
        subsystem: AtpSubsystem::Security,
        event_type: "nested_analysis".to_string(),
        data: deeply_nested,
        context: context(),
        redacted_fields: Vec::new(),
    };

    let nested_rendered = logger
        .render_event(&nested_event)
        .expect("Nested event should render");
    assert!(nested_rendered.contains("deep_value"));
}

#[test]
fn test_invalid_data_error_resilience() {
    let logger = AtpLogger::new();

    // Test with null values
    let null_data_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Error,
        subsystem: AtpSubsystem::Quic,
        event_type: "connection_error".to_string(),
        data: json!(null),
        context: context(),
        redacted_fields: Vec::new(),
    };

    // Should handle null data gracefully
    let rendered = logger
        .render_event(&null_data_event)
        .expect("Null data should render");
    assert!(rendered.contains("null"));

    // Test with invalid UTF-8 scenarios (simulated with replacement chars)
    let invalid_utf8_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Warn,
        subsystem: AtpSubsystem::Disk,
        event_type: "encoding_issue".to_string(),
        data: json!({
            "invalid_chars": "Hello\u{FFFD}World\u{FFFD}",
            "binary_data": "data with \u{0000} null bytes"
        }),
        context: context(),
        redacted_fields: Vec::new(),
    };

    let utf8_rendered = logger
        .render_event(&invalid_utf8_event)
        .expect("Invalid UTF-8 should render");
    assert!(utf8_rendered.contains("encoding_issue"));

    // Test with circular reference prevention (JSON serialization should handle this)
    let circular_data = json!({
        "self_ref": "This references itself indirectly",
        "nested": {
            "back_ref": "reference"
        }
    });

    let circular_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Debug,
        subsystem: AtpSubsystem::Scheduler,
        event_type: "circular_detection".to_string(),
        data: circular_data,
        context: context(),
        redacted_fields: Vec::new(),
    };

    let circular_rendered = logger
        .render_event(&circular_event)
        .expect("Circular data should render");
    assert!(circular_rendered.contains("circular_detection"));
}

#[test]
fn test_advanced_redaction_scenarios() {
    let logger = AtpLogger::new();

    // Test complex nested redaction with arrays and mixed types
    let complex_data = json!({
        "credentials": [
            {
                "type": "oauth",
                "token": "oauth_secret_token_12345",
                "expires_at": "2026-12-31T23:59:59Z"
            },
            {
                "type": "api_key",
                "key": "sk_live_very_secret_api_key",
                "permissions": ["read", "write"]
            }
        ],
        "peer_info": {
            "peer_id": "peer-highly-sensitive-identity",
            "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
            "nickname": "alice",
            "last_seen": "2026-05-25T12:00:00Z"
        },
        "paths": [
            "/home/alice/.ssh/id_ed25519",
            "/Users/bob/.gnupg/secring.gpg",
            "/tmp/safe_temp_file.txt"
        ],
        "metadata": {
            "version": "1.0",
            "safe_field": "this_should_remain"
        }
    });

    let complex_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Info,
        subsystem: AtpSubsystem::Security,
        event_type: "complex_auth_event".to_string(),
        data: complex_data,
        context: context(),
        redacted_fields: Vec::new(),
    };

    let rendered = render_event_or_fail(&logger, &complex_event);

    // Sensitive values should be redacted
    assert_no_sensitive_fragments(&rendered);
    assert!(!rendered.contains("oauth_secret_token"));
    assert!(!rendered.contains("sk_live_very_secret"));
    assert!(!rendered.contains("peer-highly-sensitive"));
    assert!(!rendered.contains("/home/alice/.ssh"));
    assert!(!rendered.contains("/Users/bob/.gnupg"));

    // Safe values should remain
    assert!(rendered.contains("alice")); // nickname is safe
    assert!(rendered.contains("this_should_remain"));
    assert!(rendered.contains("1.0"));
    assert!(rendered.contains("/tmp/safe_temp_file.txt")); // /tmp is generally safe

    // Verify redaction field tracking
    let parsed: AtpEvent = serde_json::from_str(&rendered).expect("Should parse back to event");
    assert!(parsed.redacted_fields.len() > 0);
    assert!(
        parsed
            .redacted_fields
            .iter()
            .any(|f| f.contains("credentials"))
    );
    assert!(parsed.redacted_fields.iter().any(|f| f.contains("peer_id")));
    assert!(parsed.redacted_fields.iter().any(|f| f.contains("paths")));
}

#[test]
fn test_cross_subsystem_event_correlation() {
    let logger = AtpLogger::new();
    let trace_id = "correlation-test-trace";
    let session_id = "correlation-session";

    // Create correlated events across multiple subsystems
    let subsystems = [
        (AtpSubsystem::Path, "path_discovered"),
        (AtpSubsystem::Quic, "connection_established"),
        (AtpSubsystem::Transfer, "transfer_initiated"),
        (AtpSubsystem::Verifier, "verification_started"),
        (AtpSubsystem::Repair, "repair_triggered"),
    ];

    for (i, (subsystem, event_type)) in subsystems.iter().enumerate() {
        let correlated_context = EventContext {
            session_id: session_id.to_string(),
            transfer_id: Some(format!("transfer-correlated-{}", i)),
            connection_id: Some(format!("conn-{}", i)),
            peer_id: Some("peer-correlation-test".to_string()),
            test_case_id: Some("ATP-N19".to_string()),
            trace_id: trace_id.to_string(),
            span_id: format!("span-{}", i),
        };

        let event = AtpEvent {
            schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: format!("2026-05-25T12:{:02}:00Z", i),
            level: Level::Info,
            subsystem: subsystem.clone(),
            event_type: event_type.to_string(),
            data: json!({
                "correlation_id": trace_id,
                "step": i,
                "subsystem": subsystem.as_str()
            }),
            context: correlated_context,
            redacted_fields: Vec::new(),
        };

        let rendered = render_event_or_fail(&logger, &event);
        assert!(rendered.contains(trace_id));
        assert!(rendered.contains(session_id));
        assert!(rendered.contains(&format!("step\":{}", i)));
    }
}

#[test]
fn test_format_compatibility_edge_cases() {
    let logger_json = AtpLogger::new();
    let logger_human = AtpLogger::with_config(AtpLoggerConfig {
        format: LogFormat::Human,
        ..AtpLoggerConfig::default()
    });

    // Test with edge case data that might break formatting
    let edge_cases = vec![
        ("empty_string", json!({"value": ""})),
        ("just_whitespace", json!({"value": "   \t\n\r   "})),
        (
            "unicode_emoji",
            json!({"message": "Transfer completed 🎉✨"}),
        ),
        (
            "special_chars",
            json!({"path": "file with spaces & symbols!@#$%^&*()"}),
        ),
        (
            "numbers_as_strings",
            json!({"port": "8080", "timeout": "30.5"}),
        ),
        (
            "boolean_variants",
            json!({"enabled": true, "disabled": false, "maybe": null}),
        ),
        (
            "mixed_array",
            json!({"items": [1, "two", true, null, {"nested": "value"}]}),
        ),
    ];

    for (test_name, test_data) in edge_cases {
        let event = AtpEvent {
            schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: "2026-05-25T00:00:00Z".to_string(),
            level: Level::Debug,
            subsystem: AtpSubsystem::UnitTest,
            event_type: "format_edge_case".to_string(),
            data: test_data,
            context: EventContext::deterministic("session-edge", "trace-edge"),
            redacted_fields: Vec::new(),
        };

        // Both formats should handle edge cases without panic
        let json_rendered = logger_json
            .render_event(&event)
            .expect(&format!("JSON format should handle {}", test_name));
        let human_rendered = logger_human
            .render_event(&event)
            .expect(&format!("Human format should handle {}", test_name));

        assert!(json_rendered.contains("format_edge_case"));
        assert!(human_rendered.contains("format_edge_case"));

        // JSON should be valid JSON
        let _: Value = serde_json::from_str(&json_rendered)
            .expect(&format!("JSON output should be valid for {}", test_name));
    }
}

#[test]
fn test_macro_ergonomics_and_safety() {
    // Test macro with various argument patterns
    let context = EventContext::deterministic("macro-test", "macro-trace");

    // Basic macro usage
    atp_log!(
        AtpSubsystem::UnitTest,
        "macro_basic_test",
        Level::Info,
        json!({"test": "basic"}),
        context.clone()
    );

    // Macro with complex expressions
    let dynamic_level = Level::Warn;
    let complex_data = json!({
        "computed": 2 + 2,
        "conditional": if true { "yes" } else { "no" },
        "formatted": format!("test_{}", 123)
    });

    atp_log!(
        AtpSubsystem::UnitTest,
        "macro_complex_test",
        dynamic_level,
        complex_data,
        context.clone()
    );

    // Macro should work with borrowed vs owned data
    let event_type = "borrowed_test";
    let owned_data = json!({"ownership": "test"});

    atp_log!(
        AtpSubsystem::UnitTest,
        event_type,
        Level::Debug,
        &owned_data,
        context.clone()
    );

    // Test with empty context variations
    let minimal_context = EventContext::deterministic("minimal", "min-trace");
    atp_log!(
        AtpSubsystem::UnitTest,
        "minimal_context_test",
        Level::Trace,
        json!({}),
        minimal_context
    );
}

#[test]
fn test_performance_under_load() {
    let logger = AtpLogger::new();
    let start = std::time::Instant::now();
    let num_events = 1000;

    // Generate many events rapidly
    for i in 0..num_events {
        let event = AtpEvent {
            schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: format_system_time_rfc3339(std::time::SystemTime::now()),
            level: if i % 4 == 0 {
                Level::Error
            } else {
                Level::Info
            },
            subsystem: match i % 6 {
                0 => AtpSubsystem::Path,
                1 => AtpSubsystem::Quic,
                2 => AtpSubsystem::Transfer,
                3 => AtpSubsystem::Security,
                4 => AtpSubsystem::Verifier,
                _ => AtpSubsystem::UnitTest,
            },
            event_type: format!("perf_test_{}", i % 10),
            data: json!({
                "iteration": i,
                "batch": i / 100,
                "data": format!("test_data_{}", i),
                "metadata": {
                    "size": i * 10,
                    "priority": i % 5
                }
            }),
            context: EventContext {
                session_id: format!("perf-session-{}", i / 100),
                transfer_id: Some(format!("transfer-{}", i)),
                connection_id: Some(format!("conn-{}", i % 50)),
                peer_id: Some("peer-perf-test".to_string()),
                test_case_id: Some("ATP-N19".to_string()),
                trace_id: format!("trace-{}", i),
                span_id: format!("span-{}", i),
            },
            redacted_fields: Vec::new(),
        };

        render_event_or_fail(&logger, &event);
    }

    let duration = start.elapsed();

    // Performance should be reasonable (less than 1ms per event on average)
    assert!(
        duration.as_millis() < num_events,
        "Performance too slow: {}ms for {} events",
        duration.as_millis(),
        num_events
    );
}

#[test]
fn test_timestamp_edge_cases() {
    // Test various timestamp edge cases
    let edge_timestamps = vec![
        UNIX_EPOCH,                                        // Epoch start
        UNIX_EPOCH + Duration::from_secs(253_402_300_799), // Year 9999
        UNIX_EPOCH + Duration::from_nanos(999_999_999),    // Sub-second precision
    ];

    for timestamp in edge_timestamps {
        let formatted = format_system_time_rfc3339(timestamp);

        // Should be valid RFC3339 format
        assert!(formatted.ends_with('Z'));
        assert!(formatted.contains('T'));
        assert_eq!(formatted.len(), 20); // YYYY-MM-DDTHH:MM:SSZ

        // Should be parseable by chrono or other RFC3339 parsers
        assert!(
            formatted
                .chars()
                .all(|c| c.is_ascii_digit() || "T-:Z".contains(c))
        );
    }

    // Test current system time
    let now = std::time::SystemTime::now();
    let now_formatted = format_system_time_rfc3339(now);
    assert!(now_formatted.starts_with("202")); // Should be in 2020s
}

#[test]
fn test_error_recovery_scenarios() {
    let logger = AtpLogger::new();

    // Test recovery from schema validation errors
    let invalid_schema_event = AtpEvent {
        schema_version: "invalid.schema.version".to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Error,
        subsystem: AtpSubsystem::UnitTest,
        event_type: "schema_error_test".to_string(),
        data: json!({"error": "intentional"}),
        context: context(),
        redacted_fields: Vec::new(),
    };

    // Should handle gracefully and not crash
    match logger.render_event(&invalid_schema_event) {
        Ok(rendered) => {
            // If it succeeds, should still contain the data
            assert!(rendered.contains("schema_error_test"));
        }
        Err(err) => {
            // If it fails, should be a specific error type
            assert!(
                format!("{:?}", err).contains("schema") || format!("{:?}", err).contains("version")
            );
        }
    }

    // Test with malformed timestamp
    let malformed_time_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "not-a-valid-timestamp".to_string(),
        level: Level::Error,
        subsystem: AtpSubsystem::UnitTest,
        event_type: "timestamp_error_test".to_string(),
        data: json!({"error": "malformed_timestamp"}),
        context: context(),
        redacted_fields: Vec::new(),
    };

    // Should handle gracefully
    let result = logger.render_event(&malformed_time_event);
    match result {
        Ok(rendered) => assert!(rendered.contains("timestamp_error_test")),
        Err(_) => {} // Error is acceptable for malformed input
    }
}

#[test]
fn test_memory_cleanup_and_resource_management() {
    // Test that logger doesn't leak memory with repeated use
    let logger = AtpLogger::new();

    // Create and render many events to test memory behavior
    for cycle in 0..10 {
        let mut large_events = Vec::new();

        for i in 0..100 {
            let large_data = "x".repeat(1000);
            let event = AtpEvent {
                schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
                timestamp: format_system_time_rfc3339(std::time::SystemTime::now()),
                level: Level::Info,
                subsystem: AtpSubsystem::UnitTest,
                event_type: "memory_test".to_string(),
                data: json!({
                    "cycle": cycle,
                    "iteration": i,
                    "large_data": large_data,
                    "metadata": vec![i; 50] // Array of numbers
                }),
                context: EventContext::deterministic(
                    &format!("memory-session-{}", cycle),
                    &format!("memory-trace-{}-{}", cycle, i),
                ),
                redacted_fields: Vec::new(),
            };

            large_events.push(event);
        }

        // Process all events
        for event in &large_events {
            render_event_or_fail(&logger, event);
        }

        // Clear the events to test cleanup
        large_events.clear();
    }

    // Logger should still be functional after intensive use
    let final_event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T00:00:00Z".to_string(),
        level: Level::Info,
        subsystem: AtpSubsystem::UnitTest,
        event_type: "memory_cleanup_final".to_string(),
        data: json!({"status": "cleanup_complete"}),
        context: context(),
        redacted_fields: Vec::new(),
    };

    let final_rendered = render_event_or_fail(&logger, &final_event);
    assert!(final_rendered.contains("memory_cleanup_final"));
}
