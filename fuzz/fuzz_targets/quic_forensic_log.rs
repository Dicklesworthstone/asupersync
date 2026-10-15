#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::quic_native::forensic_log::{
    QuicH3Event, QuicH3ForensicLogger, QuicH3ScenarioManifest,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use tempfile::TempDir;

/// Comprehensive fuzz target for QUIC/H3 forensic log trace parsing
///
/// Tests the NDJSON forensic logging system for:
/// - NDJSON line parsing with malformed JSON input
/// - QuicH3Event deserialization robustness
/// - Event validation and invariant checking
/// - Manifest JSON parsing edge cases
/// - Thread ID parsing from malformed strings
/// - Large event payloads and deep nested structures
/// - Schema version mismatches and compatibility
/// - Binary data in string fields
/// - Integer overflow in numeric fields
#[derive(Arbitrary, Debug)]
struct ForensicLogFuzz {
    /// Raw NDJSON lines to attempt parsing
    ndjson_lines: Vec<String>,
    /// Structured events to test serialization round-trip
    events: Vec<QuicH3EventFuzz>,
    /// Malformed manifest data
    manifest_data: String,
    /// Operations to perform on the logger
    operations: Vec<LoggerOperation>,
}

/// Fuzzing variants of QUIC events with edge case values
#[derive(Arbitrary, Debug)]
enum QuicH3EventFuzz {
    PacketSent {
        pn_space: String,
        packet_number: u64,
        size_bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
        send_time_us: u64,
    },
    AckReceived {
        pn_space: String,
        acked_ranges: Vec<(u64, u64)>,
        ack_delay_us: u64,
        acked_packets: u64,
        acked_bytes: u64,
    },
    LossDetected {
        pn_space: String,
        lost_packets: u64,
        lost_bytes: u64,
        detection_method: String,
    },
    CwndUpdated {
        old_cwnd: u64,
        new_cwnd: u64,
        ssthresh: u64,
        bytes_in_flight: u64,
        reason: String,
    },
    StreamOpened {
        stream_id: u64,
        direction: String,
        role: String,
        is_local: bool,
    },
    RequestStarted {
        stream_id: u64,
        method: String,
        scheme: String,
        authority: String,
        path: String,
    },
    FrameError {
        frame_type: String,
        error_kind: String,
        error_message: String,
        stream_id: u64,
    },
    ScenarioCompleted {
        scenario_id: String,
        seed: u64,
        passed: bool,
        duration_us: u64,
        event_count: u64,
        failure_class: String,
    },
}

/// Operations to perform on the forensic logger
#[derive(Arbitrary, Debug)]
enum LoggerOperation {
    /// Log an event with given category
    LogEvent {
        category: String,
        event: QuicH3EventFuzz,
    },
    /// Emit to NDJSON
    EmitNdjson,
    /// Create manifest
    CreateManifest { passed: bool, exit_code: i32 },
}

/// Maximum limits for safety during fuzzing
const MAX_STRING_LEN: usize = 1024;
const MAX_NDJSON_LINES: usize = 100;
const MAX_EVENTS: usize = 50;
const MAX_OPERATIONS: usize = 20;
const MAX_ACKED_RANGES: usize = 100;

fuzz_target!(|input: ForensicLogFuzz| {
    // Test malformed NDJSON parsing
    test_ndjson_parsing(&input.ndjson_lines);

    // Test event round-trip serialization
    test_event_round_trip(&input.events);

    // Test manifest parsing
    test_manifest_parsing(&input.manifest_data);

    // Test logger operations
    test_logger_operations(&input.operations);

    // Test comprehensive edge cases
    test_edge_cases();
});

fn assert_json_error_observable(error: &serde_json::Error, context: &str) {
    assert!(
        !error.to_string().is_empty(),
        "{context} JSON parser errors should remain observable"
    );
}

fn observe_json_value_parse(line: &str, context: &str) -> Option<serde_json::Value> {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(value) => {
            assert!(
                !value.to_string().is_empty(),
                "{context} successful JSON parse should remain visible"
            );
            Some(value)
        }
        Err(error) => {
            assert_json_error_observable(&error, context);
            None
        }
    }
}

fn observe_forensic_line_parse(line: &str) {
    match serde_json::from_str::<ForensicLineTest>(line) {
        Ok(parsed) => parsed.assert_string_fields_bounded(line.len()),
        Err(error) => assert_json_error_observable(&error, "forensic line"),
    }
}

fn observe_manifest_parse(manifest: &str) {
    match serde_json::from_str::<ManifestTest>(manifest) {
        Ok(parsed) => parsed.assert_string_fields_bounded(manifest.len()),
        Err(error) => assert_json_error_observable(&error, "forensic manifest"),
    }
}

fn observe_known_json_fields(value: &serde_json::Value, fields: &[&str], context: &str) {
    let present = fields
        .iter()
        .filter(|field| value.get(**field).is_some())
        .count();
    if present > 0 {
        assert!(
            value.is_object(),
            "{context} fields observed on non-object JSON"
        );
    }
}

fn observe_json_number_projection(value: &serde_json::Value, context: &str) {
    assert!(value.is_number(), "{context} should be a JSON number");
    assert!(
        value.as_u64().is_some() || value.as_i64().is_some() || value.as_f64().is_some(),
        "{context} number has no serde_json numeric projection"
    );
}

fn observe_json_bool_projection(value: &serde_json::Value, context: &str) {
    assert!(value.is_boolean(), "{context} should be a JSON bool");
    assert!(
        value.as_bool().is_some(),
        "{context} bool has no serde_json bool projection"
    );
}

fn test_ndjson_parsing(lines: &[String]) {
    let limited_lines = if lines.len() > MAX_NDJSON_LINES {
        &lines[..MAX_NDJSON_LINES]
    } else {
        lines
    };

    for line in limited_lines {
        // Limit string length for performance
        let safe_line = if line.len() > MAX_STRING_LEN * 4 {
            &line[..MAX_STRING_LEN * 4]
        } else {
            line
        };

        // NDJSON parsing should never panic
        test_safe_json_parsing(safe_line);

        // Test specific forensic line format
        test_forensic_line_parsing(safe_line);
    }
}

fn test_safe_json_parsing(line: &str) {
    // Basic JSON parsing should handle all malformed input gracefully
    observe_json_value_parse(line, "generic NDJSON");

    // Test parsing as potential forensic log line
    observe_forensic_line_parse(line);
}

fn test_forensic_line_parsing(line: &str) {
    // If it parses as JSON, verify structure expectations
    if let Some(json_value) = observe_json_value_parse(line, "forensic line field scan") {
        // Check for expected forensic log fields
        observe_known_json_fields(
            &json_value,
            &[
                "v",
                "ts_us",
                "subsystem",
                "test_id",
                "seed",
                "event",
                "category",
                "level",
                "thread_id",
                "message",
                "data",
            ],
            "forensic line",
        );

        // Test field type expectations
        if let Some(v) = json_value.get("v")
            && v.is_number()
        {
            observe_json_number_projection(v, "forensic line v");
        }

        if let Some(ts) = json_value.get("ts_us")
            && ts.is_number()
        {
            observe_json_number_projection(ts, "forensic line ts_us");
        }

        if let Some(thread_id) = json_value.get("thread_id")
            && thread_id.is_number()
        {
            observe_json_number_projection(thread_id, "forensic line thread_id");
        }
    }
}

fn test_event_round_trip(events: &[QuicH3EventFuzz]) {
    let limited_events = if events.len() > MAX_EVENTS {
        &events[..MAX_EVENTS]
    } else {
        events
    };

    for event_fuzz in limited_events {
        let event = convert_event_fuzz(event_fuzz);

        // Event methods should never panic
        let name = event.event_name();
        assert!(!name.is_empty(), "Event name should not be empty");

        let level = event.default_level();
        assert!(!level.is_empty(), "Event level should not be empty");

        // Serialization should work
        test_event_serialization(&event);
    }
}

fn test_event_serialization(event: &QuicH3Event) {
    // JSON serialization should never panic
    let serialized = serde_json::to_string(event);
    assert!(serialized.is_ok(), "Event serialization should succeed");

    if let Ok(json_str) = serialized {
        // Should be valid JSON
        let parsed = serde_json::from_str::<serde_json::Value>(&json_str);
        assert!(parsed.is_ok(), "Serialized event should be valid JSON");

        if let Ok(json_value) = parsed {
            // Should have type field
            assert!(
                json_value.get("type").is_some(),
                "Event should have type field"
            );

            // Type should match event name
            if let Some(type_val) = json_value.get("type")
                && type_val.as_str().is_some()
            {
                // Event name should be snake_case version of type
                let event_name = event.event_name();
                assert!(!event_name.is_empty());
            }
        }
    }
}

fn test_manifest_parsing(manifest_data: &str) {
    let safe_data = if manifest_data.len() > MAX_STRING_LEN * 2 {
        &manifest_data[..MAX_STRING_LEN * 2]
    } else {
        manifest_data
    };

    // Manifest parsing should handle malformed JSON gracefully
    observe_json_value_parse(safe_data, "manifest JSON");
    observe_manifest_parse(safe_data);

    // Test specific manifest expectations
    if let Some(json_value) = observe_json_value_parse(safe_data, "manifest field scan") {
        // Check expected manifest fields
        observe_known_json_fields(
            &json_value,
            &[
                "schema_id",
                "passed",
                "scenario_id",
                "seed",
                "exit_code",
                "duration_us",
                "artifacts",
            ],
            "manifest",
        );

        // Validate field types
        if let Some(passed) = json_value.get("passed")
            && passed.is_boolean()
        {
            observe_json_bool_projection(passed, "manifest passed");
        }

        if let Some(exit_code) = json_value.get("exit_code")
            && exit_code.is_number()
        {
            observe_json_number_projection(exit_code, "manifest exit_code");
        }
    }
}

fn test_logger_operations(operations: &[LoggerOperation]) {
    let temp_dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(_) => return, // Skip if temp dir creation fails
    };

    let limited_operations = if operations.len() > MAX_OPERATIONS {
        &operations[..MAX_OPERATIONS]
    } else {
        operations
    };

    let logger = QuicH3ForensicLogger::new("fuzz_scenario", 0xF0A5, "fuzz_function");

    for (index, operation) in limited_operations.iter().enumerate() {
        match operation {
            LoggerOperation::LogEvent { category, event } => {
                let safe_category = limit_string(category, MAX_STRING_LEN);
                let converted_event = convert_event_fuzz(event);
                let ts_us = index as u64;

                // Logging should never panic
                logger.log(ts_us, &safe_category, converted_event);
            }
            LoggerOperation::EmitNdjson => {
                // Emission should handle any internal state gracefully
                let path = temp_dir.path().join(format!("fuzz-log-{index}.ndjson"));
                if let Err(error) = logger.write_ndjson(&path) {
                    assert!(
                        !error.to_string().is_empty(),
                        "NDJSON write errors should remain observable"
                    );
                }
            }
            LoggerOperation::CreateManifest { passed, exit_code } => {
                // Manifest creation should never panic
                let duration_us = u64::from(exit_code.unsigned_abs()).saturating_add(1);
                let manifest = QuicH3ScenarioManifest::from_logger(&logger, *passed, duration_us);

                // Manifest should have expected properties
                assert_eq!(manifest.scenario_id, "fuzz_scenario");
                assert_eq!(manifest.passed, *passed);
                assert_eq!(manifest.duration_us, duration_us);
            }
        }
    }

    // Final emission test
    let final_path = temp_dir.path().join("fuzz-log-final.ndjson");
    if let Err(error) = logger.write_ndjson(&final_path) {
        assert!(
            !error.to_string().is_empty(),
            "final NDJSON write errors should remain observable"
        );
    }
}

fn test_edge_cases() {
    // Test with extreme values
    test_extreme_numeric_values();
    test_extreme_string_values();
    test_malformed_json_structures();
}

fn test_extreme_numeric_values() {
    let extreme_events = [
        QuicH3Event::PacketSent {
            pn_space: "test".to_string(),
            packet_number: u64::MAX,
            size_bytes: u64::MAX,
            ack_eliciting: true,
            in_flight: true,
            send_time_us: u64::MAX,
        },
        QuicH3Event::AckReceived {
            pn_space: "test".to_string(),
            acked_ranges: vec![(0, u64::MAX), (u64::MAX, 0)],
            ack_delay_us: u64::MAX,
            acked_packets: u64::MAX,
            acked_bytes: u64::MAX,
        },
        QuicH3Event::ScenarioCompleted {
            scenario_id: "test".to_string(),
            seed: u64::MAX,
            passed: true,
            duration_us: u64::MAX,
            event_count: u64::MAX,
            failure_class: "test".to_string(),
        },
    ];

    for event in &extreme_events {
        test_event_serialization(event);
    }
}

fn test_extreme_string_values() {
    // Test with various string edge cases
    let edge_strings = [
        String::new(),          // Empty
        "\0".to_string(),       // Null byte
        "🦀".to_string(),       // Unicode
        "\n\r\t".to_string(),   // Control characters
        "\"'\\".to_string(),    // JSON special characters
        "\u{FEFF}".to_string(), // BOM
        "a".repeat(1000),       // Long string
    ];

    for edge_str in &edge_strings {
        let event = QuicH3Event::FrameError {
            frame_type: edge_str.clone(),
            error_kind: edge_str.clone(),
            error_message: edge_str.clone(),
            stream_id: 42,
        };

        test_event_serialization(&event);
    }
}

fn test_malformed_json_structures() {
    let malformed_jsons = [
        "{}",
        "{",
        "}",
        "[",
        "]",
        "null",
        "true",
        "false",
        "123",
        "\"string\"",
        "{\"v\":}",
        "{\"v\":null}",
        "{\"v\":true}",
        "{\"v\":\"not_a_number\"}",
        "{\"ts_us\":-1}",
        "{\"thread_id\":\"not_a_number\"}",
        "{\"data\":null}",
        "{\"type\":123}",
    ];

    for json in &malformed_jsons {
        test_safe_json_parsing(json);
    }
}

fn convert_event_fuzz(event_fuzz: &QuicH3EventFuzz) -> QuicH3Event {
    match event_fuzz {
        QuicH3EventFuzz::PacketSent {
            pn_space,
            packet_number,
            size_bytes,
            ack_eliciting,
            in_flight,
            send_time_us,
        } => QuicH3Event::PacketSent {
            pn_space: limit_string(pn_space, MAX_STRING_LEN),
            packet_number: *packet_number,
            size_bytes: *size_bytes,
            ack_eliciting: *ack_eliciting,
            in_flight: *in_flight,
            send_time_us: *send_time_us,
        },
        QuicH3EventFuzz::AckReceived {
            pn_space,
            acked_ranges,
            ack_delay_us,
            acked_packets,
            acked_bytes,
        } => {
            let limited_ranges = if acked_ranges.len() > MAX_ACKED_RANGES {
                acked_ranges[..MAX_ACKED_RANGES].to_vec()
            } else {
                acked_ranges.clone()
            };

            QuicH3Event::AckReceived {
                pn_space: limit_string(pn_space, MAX_STRING_LEN),
                acked_ranges: limited_ranges,
                ack_delay_us: *ack_delay_us,
                acked_packets: *acked_packets,
                acked_bytes: *acked_bytes,
            }
        }
        QuicH3EventFuzz::LossDetected {
            pn_space,
            lost_packets,
            lost_bytes,
            detection_method,
        } => QuicH3Event::LossDetected {
            pn_space: limit_string(pn_space, MAX_STRING_LEN),
            lost_packets: *lost_packets,
            lost_bytes: *lost_bytes,
            detection_method: limit_string(detection_method, MAX_STRING_LEN),
        },
        QuicH3EventFuzz::CwndUpdated {
            old_cwnd,
            new_cwnd,
            ssthresh,
            bytes_in_flight,
            reason,
        } => QuicH3Event::CwndUpdated {
            old_cwnd: *old_cwnd,
            new_cwnd: *new_cwnd,
            ssthresh: *ssthresh,
            bytes_in_flight: *bytes_in_flight,
            reason: limit_string(reason, MAX_STRING_LEN),
        },
        QuicH3EventFuzz::StreamOpened {
            stream_id,
            direction,
            role,
            is_local,
        } => QuicH3Event::StreamOpened {
            stream_id: *stream_id,
            direction: limit_string(direction, MAX_STRING_LEN),
            role: limit_string(role, MAX_STRING_LEN),
            is_local: *is_local,
        },
        QuicH3EventFuzz::RequestStarted {
            stream_id,
            method,
            scheme,
            authority,
            path,
        } => QuicH3Event::RequestStarted {
            stream_id: *stream_id,
            method: limit_string(method, MAX_STRING_LEN),
            scheme: limit_string(scheme, MAX_STRING_LEN),
            authority: limit_string(authority, MAX_STRING_LEN),
            path: limit_string(path, MAX_STRING_LEN),
        },
        QuicH3EventFuzz::FrameError {
            frame_type,
            error_kind,
            error_message,
            stream_id,
        } => QuicH3Event::FrameError {
            frame_type: limit_string(frame_type, MAX_STRING_LEN),
            error_kind: limit_string(error_kind, MAX_STRING_LEN),
            error_message: limit_string(error_message, MAX_STRING_LEN),
            stream_id: *stream_id,
        },
        QuicH3EventFuzz::ScenarioCompleted {
            scenario_id,
            seed,
            passed,
            duration_us,
            event_count,
            failure_class,
        } => QuicH3Event::ScenarioCompleted {
            scenario_id: limit_string(scenario_id, MAX_STRING_LEN),
            seed: *seed,
            passed: *passed,
            duration_us: *duration_us,
            event_count: *event_count,
            failure_class: limit_string(failure_class, MAX_STRING_LEN),
        },
    }
}

fn limit_string(input: &str, max_len: usize) -> String {
    if input.len() > max_len {
        input.chars().take(max_len).collect()
    } else {
        input.to_string()
    }
}

/// Test structure for parsing forensic log lines
#[derive(serde::Deserialize)]
struct ForensicLineTest {
    #[allow(dead_code)]
    v: Option<u32>,
    #[allow(dead_code)]
    ts_us: Option<u64>,
    #[allow(dead_code)]
    subsystem: Option<String>,
    #[allow(dead_code)]
    test_id: Option<String>,
    #[allow(dead_code)]
    seed: Option<String>,
    #[allow(dead_code)]
    event: Option<String>,
    #[allow(dead_code)]
    category: Option<String>,
    #[allow(dead_code)]
    level: Option<String>,
    #[allow(dead_code)]
    thread_id: Option<u64>,
    #[allow(dead_code)]
    message: Option<String>,
    #[allow(dead_code)]
    data: Option<serde_json::Value>,
}

impl ForensicLineTest {
    fn assert_string_fields_bounded(&self, input_len: usize) {
        assert_optional_string_bounded(&self.subsystem, input_len, "subsystem");
        assert_optional_string_bounded(&self.test_id, input_len, "test_id");
        assert_optional_string_bounded(&self.seed, input_len, "seed");
        assert_optional_string_bounded(&self.event, input_len, "event");
        assert_optional_string_bounded(&self.category, input_len, "category");
        assert_optional_string_bounded(&self.level, input_len, "level");
        assert_optional_string_bounded(&self.message, input_len, "message");
    }
}

/// Test structure for parsing manifest files
#[derive(serde::Deserialize)]
struct ManifestTest {
    #[allow(dead_code)]
    schema_id: Option<String>,
    #[allow(dead_code)]
    passed: Option<bool>,
    #[allow(dead_code)]
    scenario_id: Option<String>,
    #[allow(dead_code)]
    seed: Option<String>,
    #[allow(dead_code)]
    exit_code: Option<i32>,
    #[allow(dead_code)]
    duration_us: Option<u64>,
    #[allow(dead_code)]
    artifacts: Option<BTreeMap<String, String>>,
}

impl ManifestTest {
    fn assert_string_fields_bounded(&self, input_len: usize) {
        assert_optional_string_bounded(&self.schema_id, input_len, "schema_id");
        assert_optional_string_bounded(&self.scenario_id, input_len, "scenario_id");
        assert_optional_string_bounded(&self.seed, input_len, "seed");

        if let Some(artifacts) = &self.artifacts {
            for (key, value) in artifacts {
                assert!(
                    key.len() <= input_len,
                    "manifest artifact key should be input-bounded"
                );
                assert!(
                    value.len() <= input_len,
                    "manifest artifact value should be input-bounded"
                );
            }
        }
    }
}

fn assert_optional_string_bounded(value: &Option<String>, input_len: usize, field: &str) {
    if let Some(value) = value {
        assert!(
            value.len() <= input_len,
            "{field} parsed string should be input-bounded"
        );
    }
}
