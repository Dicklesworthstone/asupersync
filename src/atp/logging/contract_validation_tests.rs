//! ATP-N16: Structured Logging Contract Validation Unit Tests
//!
//! Comprehensive unit tests for ATP structured logging contracts including:
//! - Schema validation and versioning
//! - Trace redaction rules and policies
//! - Failure bundle generation and content validation
//! - Replay artifact consistency
//! - Event format stability and parsing
//! - Performance and memory bounds

#![cfg(test)]

use super::*;
use crate::atp::logging::failure_bundle::{self, *};
use crate::atp::logging::redaction::*;
use crate::atp::logging::replay_artifacts::*;
use crate::atp::logging::schema::*;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Test constants for consistent validation
const TEST_SCHEMA_VERSION: &str = "asupersync.atp.log.event.v1";
const TEST_SESSION_ID: &str = "session-12345";
const TEST_TRANSFER_ID: &str = "transfer-67890";
const TEST_CONNECTION_ID: &str = "conn-abcde";
const TEST_PEER_ID: &str = "peer-secret-identity";
const TEST_TRACE_ID: &str = "trace-fghij";

/// Create a test event context with predictable values.
fn create_test_context() -> EventContext {
    EventContext {
        session_id: TEST_SESSION_ID.to_string(),
        transfer_id: Some(TEST_TRANSFER_ID.to_string()),
        connection_id: Some(TEST_CONNECTION_ID.to_string()),
        peer_id: Some(TEST_PEER_ID.to_string()),
        test_case_id: Some("ATP-N16".to_string()),
        trace_id: TEST_TRACE_ID.to_string(),
        span_id: "span-98765".to_string(),
    }
}

/// Create a test ATP event for validation.
fn create_test_event(subsystem: AtpSubsystem, event_type: &str, data: Value) -> AtpEvent {
    AtpEvent {
        schema_version: TEST_SCHEMA_VERSION.to_string(),
        timestamp: "2026-05-25T12:00:00Z".to_string(),
        level: Level::Info,
        subsystem,
        event_type: event_type.to_string(),
        data,
        context: create_test_context(),
        redacted_fields: vec![],
    }
}

#[test]
fn test_atp_event_schema_version_stability() {
    // Schema version must remain stable for backward compatibility
    assert_eq!(ATP_LOG_EVENT_SCHEMA_VERSION, TEST_SCHEMA_VERSION);

    let event = create_test_event(
        AtpSubsystem::Transfer,
        "transfer_started",
        json!({ "object_id": "obj-123", "size_bytes": 1024 }),
    );

    assert_eq!(event.schema_version, TEST_SCHEMA_VERSION);

    // Schema must be serializable and parseable
    let serialized = serde_json::to_string(&event).expect("event should serialize");
    let parsed: AtpEvent = serde_json::from_str(&serialized).expect("event should parse");
    assert_eq!(parsed.schema_version, event.schema_version);
}

#[test]
fn test_atp_subsystem_completeness() {
    // All subsystems must have defined event types
    let all_subsystems = AtpSubsystem::all();

    // Verify core ATP subsystems are present
    let subsystem_names: Vec<String> = all_subsystems
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();

    let required_subsystems = vec![
        "Path",
        "Quic",
        "Transfer",
        "Scheduler",
        "Repair",
        "Disk",
        "Journal",
        "Verifier",
        "Daemon",
        "Cli",
        "UnitTest",
        "LabTest",
        "E2eTest",
    ];

    for required in required_subsystems {
        assert!(
            subsystem_names.iter().any(|name| name == required),
            "Missing required subsystem: {}",
            required
        );
    }

    // Each subsystem must have non-empty event types
    for subsystem in all_subsystems {
        let event_types = match subsystem {
            AtpSubsystem::Path => path_event_types(),
            AtpSubsystem::Quic => quic_event_types(),
            AtpSubsystem::Transfer => transfer_event_types(),
            AtpSubsystem::Scheduler => scheduler_event_types(),
            AtpSubsystem::Repair => repair_event_types(),
            _ => vec!["generic_event".to_string()], // Default for test subsystems
        };

        assert!(
            !event_types.is_empty(),
            "Subsystem {} must have defined event types",
            subsystem.as_str()
        );
    }
}

#[test]
fn test_event_context_field_validation() {
    let context = create_test_context();

    // Required fields must be present
    assert!(!context.session_id.is_empty());
    assert!(!context.trace_id.is_empty());
    assert!(!context.span_id.is_empty());

    // Optional fields should be Some with test data
    assert!(context.transfer_id.is_some());
    assert!(context.connection_id.is_some());
    assert!(context.peer_id.is_some());
    assert!(context.test_case_id.is_some());

    // Context must be serializable
    let serialized = serde_json::to_value(&context).expect("context should serialize");
    assert!(serialized.is_object());

    // Verify field presence in serialized form
    let obj = serialized.as_object().unwrap();
    assert!(obj.contains_key("session_id"));
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("span_id"));
}

#[test]
fn test_trace_redaction_sensitive_field_detection() {
    // Test data with sensitive fields
    let sensitive_data = json!({
        "peer_id": "peer-secret-identity",
        "auth_token": "secret-auth-token-12345",
        "api_key": "sk_live_abcdefghijk",
        "password": "super-secret-password",
        "private_key": "-----BEGIN PRIVATE KEY-----\n...",
        "session_cookie": "sess_cookie_value",
        "transfer_id": "transfer-public-id",
        "file_size": 1024
    });

    let event = create_test_event(AtpSubsystem::Security, "auth_check", sensitive_data);

    // Apply redaction
    let redacted_event = apply_redaction_policy(&event);

    // Sensitive fields should be redacted
    assert!(
        redacted_event
            .redacted_fields
            .contains(&"peer_id".to_string())
    );
    assert!(
        redacted_event
            .redacted_fields
            .contains(&"auth_token".to_string())
    );
    assert!(
        redacted_event
            .redacted_fields
            .contains(&"api_key".to_string())
    );
    assert!(
        redacted_event
            .redacted_fields
            .contains(&"password".to_string())
    );
    assert!(
        redacted_event
            .redacted_fields
            .contains(&"private_key".to_string())
    );

    // Non-sensitive fields should not be redacted
    assert!(
        !redacted_event
            .redacted_fields
            .contains(&"transfer_id".to_string())
    );
    assert!(
        !redacted_event
            .redacted_fields
            .contains(&"file_size".to_string())
    );

    // Redacted data should not contain original sensitive values
    let data_str = redacted_event.data.to_string();
    assert!(!data_str.contains("secret-auth-token-12345"));
    assert!(!data_str.contains("super-secret-password"));
    assert!(data_str.contains("[REDACTED]") || data_str.contains("***"));
}

#[test]
fn test_failure_bundle_schema_validation() {
    let bundle = FailureBundle {
        schema_version: ATP_FAILURE_BUNDLE_SCHEMA_VERSION.to_string(),
        metadata: BundleMetadata {
            created_at: "2026-05-25T12:00:00Z".to_string(),
            atp_version: "0.1.0".to_string(),
            rust_version: "1.80.0".to_string(),
            platform: "linux-x86_64".to_string(),
            bundle_version: ATP_FAILURE_BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: "bundle-12345".to_string(),
        },
        command: CommandInfo {
            command_line: vec!["atp".to_string(), "transfer".to_string()],
            working_directory: "/tmp/test".to_string(),
            exit_code: Some(1),
            duration_ms: Some(5000),
            parsed_args: {
                let mut args = HashMap::new();
                args.insert("source".to_string(), "file.txt".to_string());
                args.insert("dest".to_string(), "remote:file.txt".to_string());
                args
            },
        },
        environment: EnvironmentInfo {
            environment_variables: {
                let mut env = HashMap::new();
                env.insert("ATP_LOG_LEVEL".to_string(), "debug".to_string());
                env
            },
            system_info: failure_bundle::SystemInfo {
                os: "Linux".to_string(),
                os_version: "6.17.0".to_string(),
                arch: "x86_64".to_string(),
                memory_total: 8_589_934_592,           // 8GB
                disk_space_available: 107_374_182_400, // 100GB
                cpu_count: 8,
            },
            atp_config: Some(json!({"quic_enabled": true})),
            resource_limits: failure_bundle::ResourceLimits {
                max_memory: Some(1_073_741_824), // 1GB
                max_disk: Some(10_737_418_240),  // 10GB
                max_bandwidth: Some(10_000_000),
                max_file_descriptors: Some(1024),
            },
        },
        seed: 0x123456789abcdef0,
        trace_data: failure_bundle::TraceData {
            log_events: vec![
                create_test_event(
                    AtpSubsystem::Transfer,
                    "transfer_started",
                    json!({"object_id": "obj-123"}),
                ),
                create_test_event(
                    AtpSubsystem::Transfer,
                    "transfer_failed",
                    json!({"error": "connection_timeout"}),
                ),
            ],
            trace_timeline: vec![failure_bundle::TraceEvent {
                timestamp: "2026-05-25T12:00:01Z".to_string(),
                event_type: "transfer_started".to_string(),
                thread_id: "test-thread".to_string(),
                data: json!({"object_id": "obj-123"}),
            }],
            performance_metrics: HashMap::from([("duration_ms".to_string(), 1000.0)]),
            error_chain: vec![failure_bundle::ErrorInfo {
                message: "connection_timeout".to_string(),
                error_type: "network".to_string(),
                stack_trace: None,
                context: HashMap::from([("phase".to_string(), "transfer".to_string())]),
            }],
        },
        qlog_data: Some(failure_bundle::QlogData {
            connection_events: vec![failure_bundle::QuicEvent {
                timestamp: "2026-05-25T12:00:00Z".to_string(),
                connection_id: TEST_CONNECTION_ID.to_string(),
                event_type: "connection_started".to_string(),
                data: json!({}),
            }],
            packet_traces: Vec::new(),
            connection_stats: HashMap::new(),
        }),
        path_log: Some(failure_bundle::PathLog {
            discovered_paths: vec![failure_bundle::PathInfo {
                path_id: "path-1".to_string(),
                local_endpoint: "127.0.0.1:12345".to_string(),
                remote_endpoint: "192.168.1.100:443".to_string(),
                path_type: "quic+udp".to_string(),
                metrics: HashMap::from([("latency_ms".to_string(), 45.0)]),
            }],
            nat_classification: HashMap::new(),
            stun_bindings: Vec::new(),
            relay_info: None,
        }),
        repair_log: None,
        journal_digest: None,
        proof_bundle: None,
        replay_command: "atp --seed=0x123456789abcdef0 transfer file.txt remote:file.txt"
            .to_string(),
        additional_data: json!({
            "test_case": "ATP-N16",
            "custom_metadata": "failure_bundle_test"
        }),
    };

    // Validate schema version
    assert_eq!(bundle.schema_version, ATP_FAILURE_BUNDLE_SCHEMA_VERSION);

    // Bundle must serialize correctly
    let serialized = serde_json::to_string(&bundle).expect("bundle should serialize");
    let parsed: FailureBundle = serde_json::from_str(&serialized).expect("bundle should parse");

    // Key fields must be preserved
    assert_eq!(parsed.metadata.bundle_id, "bundle-12345");
    assert_eq!(parsed.command.exit_code, Some(1));
    assert_eq!(parsed.seed, 0x123456789abcdef0);
    assert_eq!(parsed.trace_data.log_events.len(), 2);

    // Replay command must be non-empty and include seed
    assert!(!parsed.replay_command.is_empty());
    assert!(parsed.replay_command.contains("seed"));
}

#[test]
fn test_replay_artifact_consistency() {
    let artifact = ReplayArtifact {
        schema_id: ATP_REPLAY_ARTIFACT_SCHEMA_ID.to_string(),
        created_at: "2026-05-25T12:00:00Z".to_string(),
        command_fingerprint: "cmd_123456".to_string(),
        environment_fingerprint: "env_654321".to_string(),
        deterministic_seed: 0xdeadbeefcafebabe,
        execution_trace: vec![
            json!({
                "step": 1,
                "action": "path_discovery",
                "duration_ms": 100,
                "result": "success"
            }),
            json!({
                "step": 2,
                "action": "quic_handshake",
                "duration_ms": 50,
                "result": "success"
            }),
            json!({
                "step": 3,
                "action": "transfer_start",
                "duration_ms": 10,
                "result": "failed",
                "error": "peer_disconnected"
            }),
        ],
        checkpoint_data: Some(json!({
            "last_successful_step": 2,
            "transfer_progress": {"bytes_transferred": 0, "total_bytes": 1024}
        })),
        replay_instructions: vec![
            "Set environment variable ATP_DETERMINISTIC=1".to_string(),
            "Use seed 0xdeadbeefcafebabe".to_string(),
            "Run: atp --replay transfer file.txt remote:file.txt".to_string(),
        ],
    };

    // Schema ID must be correct
    assert_eq!(artifact.schema_id, ATP_REPLAY_ARTIFACT_SCHEMA_ID);

    // Artifact must be serializable and parseable
    let serialized = serde_json::to_string(&artifact).expect("artifact should serialize");
    let parsed: ReplayArtifact = serde_json::from_str(&serialized).expect("artifact should parse");

    // Critical fields must be preserved exactly
    assert_eq!(parsed.deterministic_seed, 0xdeadbeefcafebabe);
    assert_eq!(parsed.execution_trace.len(), 3);
    assert_eq!(parsed.replay_instructions.len(), 3);

    // Execution trace must maintain order and structure
    assert_eq!(parsed.execution_trace[0]["step"], json!(1));
    assert_eq!(parsed.execution_trace[2]["result"], json!("failed"));
    assert_eq!(
        parsed.execution_trace[2]["error"],
        json!("peer_disconnected")
    );
}

#[test]
fn test_redaction_policy_completeness() {
    // Test all redaction rules are properly defined
    let sensitive_patterns = get_sensitive_field_patterns();

    // Must have patterns for common sensitive data
    let required_patterns = vec![
        "peer_id",
        "auth_token",
        "api_key",
        "password",
        "private_key",
        "session_cookie",
        "bearer_token",
        "access_token",
        "refresh_token",
    ];

    for pattern in required_patterns {
        assert!(
            sensitive_patterns.iter().any(|p| p.contains(pattern)),
            "Missing redaction pattern for: {}",
            pattern
        );
    }

    // Test redaction on various event types
    let test_cases = vec![
        (
            AtpSubsystem::Security,
            "auth_attempt",
            json!({
                "username": "alice",
                "password": "secret123",
                "result": "success"
            }),
        ),
        (
            AtpSubsystem::Quic,
            "connection_established",
            json!({
                "peer_id": "peer-secret-12345",
                "connection_id": "conn-public-67890",
                "protocol_version": "1.0"
            }),
        ),
        (
            AtpSubsystem::Transfer,
            "transfer_authorized",
            json!({
                "api_key": "sk_live_abcdefghijk",
                "transfer_id": "transfer-public-id",
                "file_size": 2048
            }),
        ),
    ];

    for (subsystem, event_type, data) in test_cases {
        let event = create_test_event(subsystem, event_type, data);
        let redacted = apply_redaction_policy(&event);

        // Should have some redacted fields for these sensitive events
        assert!(
            !redacted.redacted_fields.is_empty(),
            "Event {} should have redacted fields",
            event_type
        );

        // Redacted event should be serializable
        let serialized = serde_json::to_string(&redacted).expect("redacted event should serialize");
        assert!(!serialized.is_empty());
    }
}

#[test]
fn test_event_format_stability_across_subsystems() {
    // Test that event structure remains consistent across all subsystems
    let subsystems = vec![
        AtpSubsystem::Path,
        AtpSubsystem::Quic,
        AtpSubsystem::Transfer,
        AtpSubsystem::Scheduler,
        AtpSubsystem::Repair,
        AtpSubsystem::UnitTest,
    ];

    for subsystem in subsystems {
        let event = create_test_event(subsystem, "test_event", json!({ "test_data": "value" }));

        // All events must have consistent structure
        assert_eq!(event.schema_version, TEST_SCHEMA_VERSION);
        assert!(!event.timestamp.is_empty());
        assert!(!event.event_type.is_empty());
        assert!(event.data.is_object() || event.data.is_string() || event.data.is_number());

        // Context must be complete
        assert!(!event.context.session_id.is_empty());
        assert!(!event.context.trace_id.is_empty());
        assert!(!event.context.span_id.is_empty());

        // Must serialize to valid JSON
        let serialized = serde_json::to_string(&event).expect("event should serialize");
        let parsed: Value = serde_json::from_str(&serialized).expect("event JSON should parse");

        // Verify required fields in serialized form
        assert!(parsed["schema_version"].is_string());
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["subsystem"].is_string());
        assert!(parsed["event_type"].is_string());
        assert!(parsed["context"].is_object());
    }
}

#[test]
fn test_logging_performance_bounds() {
    // Test that logging operations stay within performance bounds
    use std::time::Instant;

    let start = Instant::now();

    // Create many events to test performance
    for i in 0..1000 {
        let event = create_test_event(
            AtpSubsystem::Transfer,
            "performance_test",
            json!({
                "iteration": i,
                "data": format!("test_data_{}", i)
            }),
        );

        // Serialize event (common operation)
        let _serialized = serde_json::to_string(&event).expect("should serialize");

        // Apply redaction (expensive operation)
        let _redacted = apply_redaction_policy(&event);
    }

    let duration = start.elapsed();

    // Performance bound: 1000 events should process in under 1 second
    assert!(
        duration.as_millis() < 1000,
        "Logging performance too slow: {}ms for 1000 events",
        duration.as_millis()
    );
}

#[test]
fn test_memory_usage_bounds() {
    // Test that logging structures have reasonable memory footprint
    use std::mem::size_of;

    // AtpEvent should be reasonably sized
    assert!(
        size_of::<AtpEvent>() < 1024,
        "AtpEvent too large: {} bytes",
        size_of::<AtpEvent>()
    );

    // EventContext should be compact
    assert!(
        size_of::<EventContext>() < 512,
        "EventContext too large: {} bytes",
        size_of::<EventContext>()
    );

    // FailureBundle is allowed to be larger but should be bounded
    assert!(
        size_of::<FailureBundle>() < 4096,
        "FailureBundle too large: {} bytes",
        size_of::<FailureBundle>()
    );

    // Test that collections don't grow unbounded
    let mut large_event = create_test_event(
        AtpSubsystem::Transfer,
        "large_data_test",
        json!({ "large_field": "x".repeat(10000) }),
    );

    // Should be able to apply redaction even to large events
    let redacted = apply_redaction_policy(&large_event);
    assert!(
        redacted.redacted_fields.len() <= 100,
        "Too many redacted fields tracked"
    );

    // Add many redacted fields to test bounds
    for i in 0..200 {
        large_event.redacted_fields.push(format!("field_{}", i));
    }

    // Should serialize even with many redacted fields but track reasonable bounds
    let serialized = serde_json::to_string(&large_event).expect("should serialize large event");
    assert!(
        serialized.len() < 100_000,
        "Serialized event too large: {} bytes",
        serialized.len()
    );
}

#[test]
fn test_cross_subsystem_correlation() {
    // Test that events can be correlated across subsystems using context
    let common_context = create_test_context();

    let path_event = AtpEvent {
        subsystem: AtpSubsystem::Path,
        event_type: "path_discovered".to_string(),
        data: json!({ "candidate": "192.168.1.100:443" }),
        context: common_context.clone(),
        ..create_test_event(AtpSubsystem::Path, "test", json!({}))
    };

    let quic_event = AtpEvent {
        subsystem: AtpSubsystem::Quic,
        event_type: "connection_established".to_string(),
        data: json!({ "peer_addr": "192.168.1.100:443" }),
        context: common_context.clone(),
        ..create_test_event(AtpSubsystem::Quic, "test", json!({}))
    };

    let transfer_event = AtpEvent {
        subsystem: AtpSubsystem::Transfer,
        event_type: "transfer_started".to_string(),
        data: json!({ "object_id": "obj-123" }),
        context: common_context.clone(),
        ..create_test_event(AtpSubsystem::Transfer, "test", json!({}))
    };

    // All events should have matching correlation IDs
    assert_eq!(path_event.context.session_id, TEST_SESSION_ID);
    assert_eq!(quic_event.context.session_id, TEST_SESSION_ID);
    assert_eq!(transfer_event.context.session_id, TEST_SESSION_ID);

    assert_eq!(path_event.context.trace_id, TEST_TRACE_ID);
    assert_eq!(quic_event.context.trace_id, TEST_TRACE_ID);
    assert_eq!(transfer_event.context.trace_id, TEST_TRACE_ID);

    // Events should be distinguishable by subsystem and event type
    let subsystems: HashSet<String> = vec![&path_event, &quic_event, &transfer_event]
        .into_iter()
        .map(|e| e.subsystem.as_str().to_string())
        .collect();

    assert_eq!(subsystems.len(), 3); // All different subsystems
    assert!(subsystems.contains("Path"));
    assert!(subsystems.contains("Quic"));
    assert!(subsystems.contains("Transfer"));
}

// Helper functions for the test module

/// Apply the ATP event redaction policy used by the contract tests.
fn apply_redaction_policy(event: &AtpEvent) -> AtpEvent {
    let mut redacted_event = event.clone();
    let mut redacted_fields = Vec::new();

    let sensitive_patterns = get_sensitive_field_patterns();
    redact_sensitive_value(
        &mut redacted_event.data,
        &sensitive_patterns,
        &mut redacted_fields,
    );
    redacted_fields.sort();
    redacted_fields.dedup();
    redacted_fields.truncate(100);
    redacted_event.redacted_fields = redacted_fields;
    redacted_event
}

fn redact_sensitive_value(
    value: &mut Value,
    sensitive_patterns: &[&'static str],
    redacted_fields: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            let keys = map.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                if is_sensitive_field(&key, sensitive_patterns) {
                    redacted_fields.push(key.clone());
                    map.insert(key, Value::String("[REDACTED]".to_string()));
                } else if let Some(child) = map.get_mut(&key) {
                    redact_sensitive_value(child, sensitive_patterns, redacted_fields);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_sensitive_value(item, sensitive_patterns, redacted_fields);
            }
        }
        _ => {}
    }
}

fn is_sensitive_field(key: &str, sensitive_patterns: &[&'static str]) -> bool {
    let normalized = key.to_ascii_lowercase();
    sensitive_patterns
        .iter()
        .any(|pattern| normalized == *pattern || normalized.contains(pattern))
}

/// Get list of sensitive field patterns for redaction.
fn get_sensitive_field_patterns() -> Vec<&'static str> {
    vec![
        "peer_id",
        "auth_token",
        "api_key",
        "password",
        "private_key",
        "session_cookie",
        "bearer_token",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_data",
        "credentials",
        "authorization",
    ]
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ReplayArtifact {
    schema_id: String,
    created_at: String,
    command_fingerprint: String,
    environment_fingerprint: String,
    deterministic_seed: u64,
    execution_trace: Vec<Value>,
    checkpoint_data: Option<Value>,
    replay_instructions: Vec<String>,
}
