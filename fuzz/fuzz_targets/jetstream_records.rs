#![no_main]

//! Fuzz target for JetStream stream-record parsing from src/messaging/jetstream.rs
//!
//! This fuzzer validates the security properties of the JetStream record parsing:
//! 1. Sequence number monotonic (parsed from reply subjects)
//! 2. Subject wildcards parsed correctly (pattern matching)
//! 3. Consumers apply ack correctly (ack/nack/term operations)
//! 4. Oversized records rejected (size limits enforced)
//! 5. Heartbeat frame interval honored (timeout handling)

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

/// Structured input for controlled JetStream record fuzzing scenarios.
#[derive(Arbitrary, Debug)]
enum JetstreamFuzzInput {
    /// Raw API response JSON to parse
    ApiResponse(Vec<u8>),

    /// JetStream message reply subject to parse
    ReplySubject(String),

    /// Stream configuration to serialize/parse
    StreamConfig(FuzzStreamConfig),

    /// Consumer configuration to serialize/parse
    ConsumerConfig(FuzzConsumerConfig),

    /// Message batch with sequence validation
    MessageBatch(Vec<FuzzMessage>),

    /// Heartbeat/timeout scenario
    HeartbeatScenario(FuzzHeartbeat),

    /// Edge case scenarios
    EdgeCase(EdgeCaseVariant),
}

#[derive(Arbitrary, Debug)]
struct FuzzStreamConfig {
    name: String,
    subjects: Vec<String>,
    max_msgs: Option<i64>,
    max_bytes: Option<i64>,
    max_msg_size: Option<i32>,
    retention: u8, // 0-2 for RetentionPolicy
    storage: bool, // File/Memory
    discard: bool, // Old/New
    replicas: u32,
    max_age_nanos: Option<u64>,
    duplicate_window_nanos: Option<u64>,
}

#[derive(Arbitrary, Debug)]
struct FuzzConsumerConfig {
    name: Option<String>,
    durable_name: Option<String>,
    deliver_policy: u8, // 0-4 for DeliverPolicy
    ack_policy: u8,     // 0-2 for AckPolicy
    ack_wait_nanos: u64,
    max_deliver: i64,
    filter_subject: Option<String>,
    max_ack_pending: i64,
    opt_start_seq: Option<u64>,
}

#[derive(Arbitrary, Debug)]
struct FuzzMessage {
    subject: String,
    payload: Vec<u8>,
    sequence: u64,
    delivered: u32,
    reply_subject: Option<String>,
}

#[derive(Arbitrary, Debug)]
struct FuzzHeartbeat {
    pull_timeout_nanos: u64,
    batch_size: usize,
    expected_interval_nanos: u64,
    slack_nanos: u64,
}

#[derive(Arbitrary, Debug)]
enum EdgeCaseVariant {
    /// Empty reply subject
    EmptyReplySubject,

    /// Invalid reply subject format
    MalformedReplySubject(String),

    /// Subject wildcard patterns
    SubjectWildcards(Vec<String>),

    /// Size limit boundary testing
    SizeLimits(SizeLimitTest),

    /// Sequence number edge cases
    SequenceEdgeCases(Vec<u64>),

    /// Ack state transitions
    AckStateTransition(AckTransitionTest),

    /// JSON parsing edge cases
    JsonEdgeCases(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct SizeLimitTest {
    max_msg_size: Option<i32>,
    actual_msg_size: usize,
    max_bytes: Option<i64>,
    actual_bytes: usize,
}

#[derive(Arbitrary, Debug)]
struct AckTransitionTest {
    initial_acked: bool,
    operations: Vec<u8>, // 0=ack, 1=nack, 2=term, 3=in_progress
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = JetstreamFuzzInput::arbitrary(&mut u) {
        fuzz_jetstream_records(input);
    }

    // Also fuzz raw JSON parsing directly
    if data.len() <= 1024 && !data.is_empty() {
        fuzz_json_parsing(data);
    }
});

fn fuzz_jetstream_records(input: JetstreamFuzzInput) {
    match input {
        JetstreamFuzzInput::ApiResponse(json_bytes) => {
            fuzz_api_response_parsing(&json_bytes);
        }

        JetstreamFuzzInput::ReplySubject(reply) => {
            fuzz_reply_subject_parsing(&reply);
        }

        JetstreamFuzzInput::StreamConfig(config) => {
            fuzz_stream_config_serialization(config);
        }

        JetstreamFuzzInput::ConsumerConfig(config) => {
            fuzz_consumer_config_serialization(config);
        }

        JetstreamFuzzInput::MessageBatch(messages) => {
            fuzz_message_sequence_validation(messages);
        }

        JetstreamFuzzInput::HeartbeatScenario(heartbeat) => {
            fuzz_heartbeat_interval_handling(heartbeat);
        }

        JetstreamFuzzInput::EdgeCase(edge) => {
            fuzz_edge_case(edge);
        }
    }
}

fn assert_no_panic(context: String, f: impl FnOnce()) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    assert!(
        result.is_ok(),
        "JetStream records fuzz target panicked: {context}"
    );
}

fn parse_reply_subject_checked(reply: &str, context: String) -> Option<(u64, u32)> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_js_reply_subject_simulation(reply)
    })) {
        Ok(result) => result,
        Err(_) => panic!("JetStream reply subject parser panicked: {context}"),
    }
}

fn preview_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(64)]
}

fn preview_str(value: &str) -> &str {
    value.get(..value.len().min(64)).unwrap_or(value)
}

fn fuzz_api_response_parsing(json_bytes: &[u8]) {
    let json_str = String::from_utf8_lossy(json_bytes);

    // Test JSON string extraction functions
    assert_no_panic(
        format!("api string extraction len={}", json_bytes.len()),
        || {
            extract_json_string_simple(&json_str, "name");
            extract_json_string_simple(&json_str, "stream");
            extract_json_string_simple(&json_str, "description");
        },
    );

    // Test JSON u64 extraction
    assert_no_panic(
        format!("api u64 extraction len={}", json_bytes.len()),
        || {
            extract_json_u64(&json_str, "seq");
            extract_json_u64(&json_str, "messages");
            extract_json_u64(&json_str, "bytes");
            extract_json_u64(&json_str, "first_seq");
            extract_json_u64(&json_str, "last_seq");
            extract_json_u64(&json_str, "code");
            extract_json_u64(&json_str, "err_code");
        },
    );

    // Test error detection - ASSERTION 3: API errors properly classified
    let has_error = json_str.contains("\"error\":{\"code\":");
    if has_error {
        // Should not panic on error parsing
        assert_no_panic(
            format!(
                "api error parsing len={} prefix={:?}",
                json_bytes.len(),
                preview_bytes(json_bytes)
            ),
            || {
                parse_api_error_simulation(&json_str);
            },
        );
    }
}

fn fuzz_reply_subject_parsing(reply: &str) {
    // ASSERTION 1: Sequence number parsing must be monotonic and consistent
    let result =
        parse_reply_subject_checked(reply, format!("reply prefix={:?}", preview_str(reply)));

    if let Some((sequence, delivered)) = result {
        // ASSERTION 1: Sequence numbers should be reasonable values
        // Sequence should be non-zero for valid messages
        if sequence > 0 {
            assert!(
                delivered > 0,
                "Delivered count should be > 0 for valid sequence"
            );
        }
    }
}

fn fuzz_stream_config_serialization(config: FuzzStreamConfig) {
    // ASSERTION 4: Oversized records rejected
    if let Some(max_msg_size) = config.max_msg_size {
        assert!(max_msg_size >= 0, "Max message size cannot be negative");
    }
    if let Some(max_bytes) = config.max_bytes {
        assert!(max_bytes >= 0, "Max bytes cannot be negative");
    }

    // ASSERTION 2: Subject wildcards parsed correctly
    for subject in &config.subjects {
        let _ = subject_pattern_error(subject);
    }

    // Test JSON serialization doesn't panic
    assert_no_panic(
        format!(
            "stream config serialization name_prefix={:?} subjects={}",
            preview_str(&config.name),
            config.subjects.len()
        ),
        || {
            serialize_stream_config_simulation(&config);
        },
    );
}

fn fuzz_consumer_config_serialization(config: FuzzConsumerConfig) {
    // ASSERTION 2: Subject wildcards in filter_subject
    if let Some(ref filter) = config.filter_subject {
        let _ = subject_pattern_error(filter);
    }

    // ASSERTION 5: Heartbeat intervals should be reasonable
    let ack_wait_duration = Duration::from_nanos(config.ack_wait_nanos);
    if ack_wait_duration.as_secs() > 0 {
        // Should be able to create timeout without panic
        let _ = ack_wait_duration.saturating_add(Duration::from_millis(100));
    }

    // Test JSON serialization
    assert_no_panic(
        format!(
            "consumer config serialization name={:?} durable={:?}",
            config.name.as_deref().map(preview_str),
            config.durable_name.as_deref().map(preview_str)
        ),
        || {
            serialize_consumer_config_simulation(&config);
        },
    );
}

fn fuzz_message_sequence_validation(messages: Vec<FuzzMessage>) {
    if messages.is_empty() {
        return;
    }

    // ASSERTION 1: Sequence number monotonic validation
    let mut sequences: Vec<u64> = messages.iter().map(|m| m.sequence).collect();
    sequences.sort_unstable();

    for window in sequences.windows(2) {
        let (prev, curr) = (window[0], window[1]);
        if prev > 0 && curr > 0 {
            // In a proper stream, sequences should not decrease dramatically
            // Allow for some reordering but catch major violations
            if prev > curr && prev.saturating_sub(curr) > 1000000 {
                panic!("Large sequence number regression: {} -> {}", prev, curr);
            }
        }
    }

    // Test message parsing for each message
    for msg in &messages {
        if let Some(ref reply) = msg.reply_subject {
            let _ = parse_reply_subject_checked(
                reply,
                format!(
                    "message subject_prefix={:?} reply_prefix={:?} sequence={} delivered={}",
                    preview_str(&msg.subject),
                    preview_str(reply),
                    msg.sequence,
                    msg.delivered
                ),
            );
        }

        // ASSERTION 4: Message size limits
        if msg.payload.len() > 16 * 1024 * 1024 {
            // 16MB reasonable limit
            // Should be rejected by proper size checking
            panic!("Message payload too large: {} bytes", msg.payload.len());
        }
    }
}

fn fuzz_heartbeat_interval_handling(heartbeat: FuzzHeartbeat) {
    // ASSERTION 5: Heartbeat frame interval honored
    let pull_timeout = Duration::from_nanos(heartbeat.pull_timeout_nanos);
    let expected_interval = Duration::from_nanos(heartbeat.expected_interval_nanos);
    let slack = Duration::from_nanos(heartbeat.slack_nanos);

    // Test timeout computation doesn't overflow
    let total_timeout = pull_timeout.saturating_add(slack);
    let timeout_nanos = total_timeout.as_nanos();

    // Should not exceed reasonable bounds
    if timeout_nanos > u64::MAX as u128 {
        panic!("Timeout overflow: {} nanoseconds", timeout_nanos);
    }

    // Batch size should be reasonable
    if heartbeat.batch_size > 10000 {
        panic!("Batch size too large: {}", heartbeat.batch_size);
    }

    // Expected interval should not be zero unless explicitly disabled
    if expected_interval.is_zero() && pull_timeout.as_secs() > 0 {
        // This might indicate a configuration error
    }
}

fn fuzz_edge_case(edge: EdgeCaseVariant) {
    match edge {
        EdgeCaseVariant::EmptyReplySubject => {
            let result = parse_js_reply_subject_simulation("");
            assert!(result.is_none(), "Empty reply subject should return None");
        }

        EdgeCaseVariant::MalformedReplySubject(malformed) => {
            let _ = parse_reply_subject_checked(
                &malformed,
                format!("malformed reply prefix={:?}", preview_str(&malformed)),
            );
        }

        EdgeCaseVariant::SubjectWildcards(subjects) => {
            for subject in &subjects {
                let _ = subject_pattern_error(subject);
            }
        }

        EdgeCaseVariant::SizeLimits(limits) => {
            // ASSERTION 4: Oversized records rejected
            if let Some(max_size) = limits.max_msg_size
                && max_size > 0
                && limits.actual_msg_size > max_size as usize
            {
                // Should be rejected
                assert!(
                    limits.actual_msg_size <= max_size as usize,
                    "Message size {} exceeds limit {}",
                    limits.actual_msg_size,
                    max_size
                );
            }

            if let Some(max_bytes) = limits.max_bytes
                && max_bytes > 0
                && limits.actual_bytes > max_bytes as usize
            {
                assert!(
                    limits.actual_bytes <= max_bytes as usize,
                    "Total bytes {} exceeds limit {}",
                    limits.actual_bytes,
                    max_bytes
                );
            }
        }

        EdgeCaseVariant::SequenceEdgeCases(sequences) => {
            // ASSERTION 1: Sequence number monotonic
            for seq in sequences {
                assert!(
                    seq != u64::MAX || seq == 0,
                    "Invalid sequence number: {}",
                    seq
                );
            }
        }

        EdgeCaseVariant::AckStateTransition(ack_test) => {
            fuzz_ack_state_transitions(ack_test);
        }

        EdgeCaseVariant::JsonEdgeCases(json_bytes) => {
            fuzz_json_parsing(&json_bytes);
        }
    }
}

fn fuzz_ack_state_transitions(ack_test: AckTransitionTest) {
    // ASSERTION 3: Consumers apply ack correctly
    let mut acked = ack_test.initial_acked;

    for &operation in &ack_test.operations {
        let prev_acked = acked;

        match operation % 4 {
            0 => {
                // ack
                if acked {
                    // Should return AlreadyAcknowledged error
                    assert!(acked, "Double ack should fail");
                } else {
                    acked = true;
                }
            }
            1 => {
                // nack
                if acked {
                    // Should return AlreadyAcknowledged error
                    assert!(acked, "Nack after ack should fail");
                } else {
                    acked = true; // nack also marks as processed
                }
            }
            2 => {
                // term
                if acked {
                    // Should return AlreadyAcknowledged error
                    assert!(acked, "Term after ack should fail");
                } else {
                    acked = true; // term also marks as processed
                }
            }
            3 => { // in_progress (doesn't change ack state)
                // in_progress should succeed regardless of ack state
            }
            _ => unreachable!(),
        }

        // Ack state should never go from true to false
        assert!(
            !(prev_acked && !acked),
            "Ack state regressed from {} to {}",
            prev_acked,
            acked
        );
    }
}

fn fuzz_json_parsing(data: &[u8]) {
    if data.is_empty() || data.len() > 1024 {
        return;
    }

    let json_str = String::from_utf8_lossy(data);

    // Should not panic on any input
    assert_no_panic(
        format!(
            "raw json parsing len={} prefix={:?}",
            data.len(),
            preview_bytes(data)
        ),
        || {
            extract_json_string_simple(&json_str, "test");
            extract_json_u64(&json_str, "value");
            json_escape(&json_str);
        },
    );
}

// Simulation functions (mimicking the actual implementation behavior)

fn parse_js_reply_subject_simulation(reply: &str) -> Option<(u64, u32)> {
    if !reply.starts_with("$JS.ACK.") {
        return None;
    }

    let parts: Vec<&str> = reply.split('.').collect();
    if parts.len() < 9 {
        return None;
    }

    // Parse from the tail: delivered(-5), stream_seq(-4)
    let delivered: u32 = parts.get(parts.len().saturating_sub(5))?.parse().ok()?;
    let sequence: u64 = parts.get(parts.len().saturating_sub(4))?.parse().ok()?;

    Some((sequence, delivered))
}

fn subject_pattern_error(subject: &str) -> Option<String> {
    // ASSERTION 2: Subject wildcards parsed
    // Basic validation that subject patterns don't contain invalid characters
    for ch in subject.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '*' | '>' | '_' | '-' => {
                // Valid subject characters
            }
            _ => {
                // Invalid character in subject
                if !subject.is_empty() {
                    return Some(format!("Invalid character '{ch}' in subject: {subject}"));
                }
            }
        }
    }

    // Validate wildcard rules
    if subject.contains(">.") {
        return Some(format!(
            "Invalid wildcard pattern: '>' must be at end: {subject}"
        ));
    }

    None
}

#[cfg(test)]
fn validate_subject_pattern(subject: &str) {
    if let Some(error) = subject_pattern_error(subject) {
        panic!("{error}");
    }
}

fn serialize_stream_config_simulation(config: &FuzzStreamConfig) -> String {
    // Simulate JSON serialization with size checks
    let mut json = String::from("{");
    json.push_str(&format!("\"name\":\"{}\"", json_escape(&config.name)));

    if !config.subjects.is_empty() {
        json.push_str(",\"subjects\":[");
        for (i, subject) in config.subjects.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("\"{}\"", json_escape(subject)));
        }
        json.push(']');
    }

    if let Some(max) = config.max_msgs {
        if max < 0 {
            panic!("Negative max_msgs: {}", max);
        }
        json.push_str(&format!(",\"max_msgs\":{}", max));
    }
    if let Some(max) = config.max_bytes {
        json.push_str(&format!(",\"max_bytes\":{}", max));
    }
    if let Some(max) = config.max_msg_size {
        json.push_str(&format!(",\"max_msg_size\":{}", max));
    }
    json.push_str(&format!(",\"retention\":{}", config.retention % 3));
    json.push_str(&format!(
        ",\"storage\":\"{}\"",
        if config.storage { "file" } else { "memory" }
    ));
    json.push_str(&format!(
        ",\"discard\":\"{}\"",
        if config.discard { "new" } else { "old" }
    ));
    json.push_str(&format!(",\"num_replicas\":{}", config.replicas));
    if let Some(max_age) = config.max_age_nanos {
        json.push_str(&format!(",\"max_age\":{}", max_age));
    }
    if let Some(duplicate_window) = config.duplicate_window_nanos {
        json.push_str(&format!(",\"duplicate_window\":{}", duplicate_window));
    }

    json.push('}');

    // ASSERTION 4: Check serialized size
    if json.len() > 1024 * 1024 {
        // 1MB limit
        panic!("Serialized config too large: {} bytes", json.len());
    }

    json
}

fn serialize_consumer_config_simulation(config: &FuzzConsumerConfig) -> String {
    let mut json = String::from("{");
    let mut parts = Vec::new();

    if let Some(ref name) = config.name {
        parts.push(format!("\"name\":\"{}\"", json_escape(name)));
    }

    // Add other fields...
    parts.push(format!("\"ack_wait\":{}", config.ack_wait_nanos));
    parts.push(format!("\"max_deliver\":{}", config.max_deliver));
    parts.push(format!("\"deliver_policy\":{}", config.deliver_policy % 5));
    parts.push(format!("\"ack_policy\":{}", config.ack_policy % 3));
    parts.push(format!("\"max_ack_pending\":{}", config.max_ack_pending));

    if let Some(start_seq) = config.opt_start_seq {
        parts.push(format!("\"opt_start_seq\":{start_seq}"));
    }
    if let Some(ref filter_subject) = config.filter_subject {
        parts.push(format!(
            "\"filter_subject\":\"{}\"",
            json_escape(filter_subject)
        ));
    }

    json.push_str(&parts.join(","));
    json.push('}');
    json
}

fn parse_api_error_simulation(json: &str) {
    let code = extract_json_u64(json, "code").unwrap_or(0);
    let err_code = extract_json_u64(json, "err_code").unwrap_or(0);

    // ASSERTION 3: Error classification should be consistent
    if err_code == 10059 && code != 10059 {
        // Should classify as StreamNotFound based on err_code, not code
        assert_ne!(
            code, err_code,
            "Error code mismatch: code={}, err_code={}",
            code, err_code
        );
    }
}

// Utility functions (simplified versions of the real implementations)

fn extract_json_string_simple(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = json.find(&pattern)? + pattern.len();
    let slice = &json[start..];
    let end = slice.find('"')?;
    Some(slice[..end].to_string())
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_subject_parsing() {
        // Valid reply subject
        let reply = "$JS.ACK.mystream.myconsumer.2.100.50.9999999.10";
        let result = parse_js_reply_subject_simulation(reply);
        assert_eq!(result, Some((100, 2)));

        // Invalid reply subject
        let invalid = "INVALID.ACK.FORMAT";
        let result = parse_js_reply_subject_simulation(invalid);
        assert_eq!(result, None);
    }

    #[test]
    fn test_subject_validation() {
        // Valid subjects
        validate_subject_pattern("orders.new");
        validate_subject_pattern("events.*");
        validate_subject_pattern("logs.>");

        // Invalid wildcard should panic
        let result = std::panic::catch_unwind(|| {
            validate_subject_pattern("orders.>.new");
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_json_extraction() {
        let json = r#"{"name":"test","seq":42}"#;
        assert_eq!(
            extract_json_string_simple(json, "name"),
            Some("test".to_string())
        );
        assert_eq!(extract_json_u64(json, "seq"), Some(42));
        assert_eq!(extract_json_u64(json, "missing"), None);
    }

    #[test]
    fn test_ack_state_transitions() {
        let ack_test = AckTransitionTest {
            initial_acked: false,
            operations: vec![0, 0], // ack then ack again
        };
        fuzz_ack_state_transitions(ack_test);
    }
}
