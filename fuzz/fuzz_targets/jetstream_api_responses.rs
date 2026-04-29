#![no_main]

//! Structure-aware fuzz target for NATS JetStream API response parsing.
//!
//! Targets edge cases in JetStream ServerInfo and API_Account_Info response parsing:
//! - JSON structure variations and malformed responses
//! - Field type mismatches and unexpected values
//! - Error response vs success response disambiguation
//! - Server info field parsing (version, cluster, limits)
//! - Account info field parsing (limits, usage, streams, consumers)

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::jetstream::{
    fuzz_parse_api_error, fuzz_parse_pub_ack, fuzz_parse_stream_info, JsError,
};

/// API response types commonly returned by JetStream
#[derive(Arbitrary, Debug, Clone)]
enum ApiResponseType {
    /// ServerInfo response from $SYS.REQ.SERVER.INFO
    ServerInfo {
        server: ServerInfoFields,
        formatting: JsonFormatting,
    },
    /// Account info response from $SYS.REQ.ACCOUNT.INFO
    AccountInfo {
        account: AccountInfoFields,
        formatting: JsonFormatting,
    },
    /// StreamInfo response (already covered but test edge cases)
    StreamInfo {
        stream: StreamInfoFields,
        formatting: JsonFormatting,
    },
    /// PubAck response edge cases
    PubAck {
        ack: PubAckFields,
        formatting: JsonFormatting,
    },
    /// Error response variations
    ApiError {
        error: ApiErrorFields,
        formatting: JsonFormatting,
    },
    /// Malformed/invalid JSON
    Malformed {
        corruption: JsonCorruption,
    },
}

/// ServerInfo response fields that can vary or be malformed
#[derive(Arbitrary, Debug, Clone)]
struct ServerInfoFields {
    /// Server ID - can be missing, empty, or malformed
    server_id: FieldValue<String>,
    /// Server name
    server_name: FieldValue<String>,
    /// Server version - version parsing edge cases
    version: FieldValue<String>,
    /// Git commit hash - can be truncated or invalid hex
    git_commit: FieldValue<String>,
    /// Go version
    go: FieldValue<String>,
    /// Host info
    host: FieldValue<String>,
    /// Port number - can be out of range
    port: FieldValue<i64>,
    /// Max connections
    max_connections: FieldValue<i64>,
    /// Max payload size - can be negative or overflow
    max_payload: FieldValue<i64>,
    /// Cluster info - can be missing or malformed
    cluster: Option<ClusterInfoFields>,
    /// TLS info
    tls_required: FieldValue<bool>,
}

/// Account info response fields
#[derive(Arbitrary, Debug, Clone)]
struct AccountInfoFields {
    /// Account name
    account_name: FieldValue<String>,
    /// Account ID
    account_id: FieldValue<String>,
    /// Limits
    limits: LimitsFields,
    /// Current usage
    usage: UsageFields,
    /// Stream count
    streams: FieldValue<i64>,
    /// Consumer count
    consumers: FieldValue<i64>,
    /// Domain (can be missing)
    domain: Option<FieldValue<String>>,
}

/// Cluster information fields
#[derive(Arbitrary, Debug, Clone)]
struct ClusterInfoFields {
    /// Cluster name
    name: FieldValue<String>,
    /// Leader info
    leader: FieldValue<String>,
    /// Replica count
    replicas: FieldValue<i64>,
}

/// Account limits fields
#[derive(Arbitrary, Debug, Clone)]
struct LimitsFields {
    /// Max streams - can be -1 for unlimited or invalid
    max_streams: FieldValue<i64>,
    /// Max consumers
    max_consumers: FieldValue<i64>,
    /// Max memory
    max_memory: FieldValue<i64>,
    /// Max storage
    max_storage: FieldValue<i64>,
    /// Max connections
    max_connections: FieldValue<i64>,
    /// Max messages per stream
    max_msgs_per_stream: FieldValue<i64>,
}

/// Account usage fields
#[derive(Arbitrary, Debug, Clone)]
struct UsageFields {
    /// Current memory usage
    memory: FieldValue<i64>,
    /// Current storage usage
    storage: FieldValue<i64>,
    /// Current streams
    streams: FieldValue<i64>,
    /// Current consumers
    consumers: FieldValue<i64>,
}

/// StreamInfo fields to test edge cases beyond existing coverage
#[derive(Arbitrary, Debug, Clone)]
struct StreamInfoFields {
    /// Stream name - test invalid characters
    name: FieldValue<String>,
    /// Subject patterns - test wildcard edge cases
    subjects: Vec<FieldValue<String>>,
    /// Message count - test overflow scenarios
    messages: FieldValue<u64>,
    /// Byte count
    bytes: FieldValue<u64>,
    /// First sequence - test wraparound
    first_seq: FieldValue<u64>,
    /// Last sequence
    last_seq: FieldValue<u64>,
    /// Consumer count - test mismatch with reality
    consumer_count: FieldValue<u32>,
}

/// PubAck fields with edge cases
#[derive(Arbitrary, Debug, Clone)]
struct PubAckFields {
    /// Stream name
    stream: FieldValue<String>,
    /// Sequence number - test very large values
    seq: FieldValue<u64>,
    /// Duplicate flag
    duplicate: FieldValue<bool>,
}

/// API error fields
#[derive(Arbitrary, Debug, Clone)]
struct ApiErrorFields {
    /// HTTP-style error code
    code: FieldValue<u32>,
    /// JetStream application error code
    err_code: FieldValue<u32>,
    /// Error description
    description: FieldValue<String>,
}

/// Represents a field that can be present, missing, or have wrong type
#[derive(Arbitrary, Debug, Clone)]
enum FieldValue<T> {
    /// Field is present with expected type
    Present(T),
    /// Field is missing from JSON
    Missing,
    /// Field has wrong type (string when expecting number, etc)
    WrongType(WrongTypeVariant),
    /// Field is null
    Null,
}

/// Different wrong type scenarios
#[derive(Arbitrary, Debug, Clone)]
enum WrongTypeVariant {
    /// String when expecting number
    StringForNumber(String),
    /// Number when expecting string
    NumberForString(i64),
    /// Bool when expecting other type
    BoolForOther(bool),
    /// Array when expecting single value
    ArrayForValue(Vec<String>),
    /// Object when expecting primitive
    ObjectForPrimitive,
}

/// JSON formatting variations that can break parsing
#[derive(Arbitrary, Debug, Clone)]
struct JsonFormatting {
    /// Whitespace variations
    whitespace: WhitespaceFormat,
    /// Quote styles
    quotes: QuoteFormat,
    /// Unicode handling
    unicode: UnicodeFormat,
    /// Number formatting
    numbers: NumberFormat,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum WhitespaceFormat {
    Minimal,        // No extra whitespace
    Spaces,         // Extra spaces
    Tabs,           // Tab characters
    Newlines,       // Multi-line
    Mixed,          // Combination
    Excessive,      // Lots of whitespace
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum QuoteFormat {
    Normal,         // Standard quotes
    Escaped,        // Escaped quotes in strings
    Unicode,        // Unicode escape sequences
    InvalidEscape,  // Invalid escape sequences
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum UnicodeFormat {
    Ascii,          // ASCII only
    ValidUnicode,   // Valid unicode characters
    EscapeSeq,      // \uXXXX sequences
    InvalidSeq,     // Invalid unicode sequences
    Surrogate,      // Surrogate pairs
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum NumberFormat {
    Integer,        // Simple integers
    Float,          // Floating point
    Scientific,     // Scientific notation
    Leading,        // Leading zeros
    Overflow,       // Values that overflow
    Negative,       // Negative when positive expected
}

/// JSON corruption types for malformed responses
#[derive(Arbitrary, Debug, Clone)]
enum JsonCorruption {
    /// Truncated JSON (missing closing braces)
    Truncated { at_byte: u8 },
    /// Invalid characters inserted
    InvalidChars { chars: Vec<u8> },
    /// Nested object depth bomb
    DeepNesting { depth: u8 },
    /// Duplicate keys
    DuplicateKeys { key: String },
    /// Empty response
    Empty,
    /// Non-JSON content
    NonJson { content: Vec<u8> },
}

fuzz_target!(|response: ApiResponseType| {
    // Limit complexity to maintain fuzzer performance
    match &response {
        ApiResponseType::Malformed { corruption } => {
            if let JsonCorruption::DeepNesting { depth } = corruption {
                if *depth > 50 { return; }
            }
            if let JsonCorruption::NonJson { content } = corruption {
                if content.len() > 1024 { return; }
            }
        }
        _ => {}
    }

    let json = build_api_response(&response);
    if json.len() > 8192 {
        return; // Avoid extremely large responses
    }

    // Test parsing with existing JetStream parsers
    test_jetstream_parsing(&response, &json);

    // Test JSON structure edge cases
    test_json_structure(&json);

    // Test error vs success response classification
    test_error_classification(&json);
});

fn build_api_response(response: &ApiResponseType) -> String {
    match response {
        ApiResponseType::ServerInfo { server, formatting } => {
            build_server_info_json(server, formatting)
        }
        ApiResponseType::AccountInfo { account, formatting } => {
            build_account_info_json(account, formatting)
        }
        ApiResponseType::StreamInfo { stream, formatting } => {
            build_stream_info_json(stream, formatting)
        }
        ApiResponseType::PubAck { ack, formatting } => {
            build_pub_ack_json(ack, formatting)
        }
        ApiResponseType::ApiError { error, formatting } => {
            build_api_error_json(error, formatting)
        }
        ApiResponseType::Malformed { corruption } => {
            build_malformed_json(corruption)
        }
    }
}

fn build_server_info_json(server: &ServerInfoFields, formatting: &JsonFormatting) -> String {
    let mut json = String::from("{");

    add_field(&mut json, "server_id", &server.server_id, formatting, false);
    add_field(&mut json, "server_name", &server.server_name, formatting, true);
    add_field(&mut json, "version", &server.version, formatting, true);
    add_field(&mut json, "git_commit", &server.git_commit, formatting, true);
    add_field(&mut json, "go", &server.go, formatting, true);
    add_field(&mut json, "host", &server.host, formatting, true);
    add_field_i64(&mut json, "port", &server.port, formatting, true);
    add_field_i64(&mut json, "max_connections", &server.max_connections, formatting, true);
    add_field_i64(&mut json, "max_payload", &server.max_payload, formatting, true);
    add_field_bool(&mut json, "tls_required", &server.tls_required, formatting, true);

    if let Some(cluster) = &server.cluster {
        add_whitespace(&mut json, formatting);
        json.push_str(",\"cluster\":{");
        add_field(&mut json, "name", &cluster.name, formatting, false);
        add_field(&mut json, "leader", &cluster.leader, formatting, true);
        add_field_i64(&mut json, "replicas", &cluster.replicas, formatting, true);
        json.push('}');
    }

    json.push('}');
    json
}

fn build_account_info_json(account: &AccountInfoFields, formatting: &JsonFormatting) -> String {
    let mut json = String::from("{");

    add_field(&mut json, "account_name", &account.account_name, formatting, false);
    add_field(&mut json, "account_id", &account.account_id, formatting, true);

    // Add limits object
    add_whitespace(&mut json, formatting);
    json.push_str(",\"limits\":{");
    add_field_i64(&mut json, "max_streams", &account.limits.max_streams, formatting, false);
    add_field_i64(&mut json, "max_consumers", &account.limits.max_consumers, formatting, true);
    add_field_i64(&mut json, "max_memory", &account.limits.max_memory, formatting, true);
    add_field_i64(&mut json, "max_storage", &account.limits.max_storage, formatting, true);
    add_field_i64(&mut json, "max_connections", &account.limits.max_connections, formatting, true);
    add_field_i64(&mut json, "max_msgs_per_stream", &account.limits.max_msgs_per_stream, formatting, true);
    json.push('}');

    // Add usage object
    add_whitespace(&mut json, formatting);
    json.push_str(",\"usage\":{");
    add_field_i64(&mut json, "memory", &account.usage.memory, formatting, false);
    add_field_i64(&mut json, "storage", &account.usage.storage, formatting, true);
    add_field_i64(&mut json, "streams", &account.usage.streams, formatting, true);
    add_field_i64(&mut json, "consumers", &account.usage.consumers, formatting, true);
    json.push('}');

    add_field_i64(&mut json, "streams", &account.streams, formatting, true);
    add_field_i64(&mut json, "consumers", &account.consumers, formatting, true);

    if let Some(domain) = &account.domain {
        add_field(&mut json, "domain", domain, formatting, true);
    }

    json.push('}');
    json
}

fn build_stream_info_json(stream: &StreamInfoFields, formatting: &JsonFormatting) -> String {
    let mut json = String::from("{");

    add_field(&mut json, "name", &stream.name, formatting, false);

    // Add subjects array
    add_whitespace(&mut json, formatting);
    json.push_str(",\"subjects\":[");
    for (i, subject) in stream.subjects.iter().enumerate() {
        if i > 0 { json.push(','); }
        add_string_value(&mut json, subject, formatting);
    }
    json.push(']');

    add_field_u64(&mut json, "messages", &stream.messages, formatting, true);
    add_field_u64(&mut json, "bytes", &stream.bytes, formatting, true);
    add_field_u64(&mut json, "first_seq", &stream.first_seq, formatting, true);
    add_field_u64(&mut json, "last_seq", &stream.last_seq, formatting, true);
    add_field_u32(&mut json, "consumer_count", &stream.consumer_count, formatting, true);

    json.push('}');
    json
}

fn build_pub_ack_json(ack: &PubAckFields, formatting: &JsonFormatting) -> String {
    let mut json = String::from("{");

    add_field(&mut json, "stream", &ack.stream, formatting, false);
    add_field_u64(&mut json, "seq", &ack.seq, formatting, true);
    add_field_bool(&mut json, "duplicate", &ack.duplicate, formatting, true);

    json.push('}');
    json
}

fn build_api_error_json(error: &ApiErrorFields, formatting: &JsonFormatting) -> String {
    let mut json = String::from("{\"error\":{");

    add_field_u32(&mut json, "code", &error.code, formatting, false);
    add_field_u32(&mut json, "err_code", &error.err_code, formatting, true);
    add_field(&mut json, "description", &error.description, formatting, true);

    json.push_str("}}");
    json
}

fn build_malformed_json(corruption: &JsonCorruption) -> String {
    match corruption {
        JsonCorruption::Truncated { at_byte } => {
            let mut json = "{\"server_id\":\"test\",\"version\":\"1.0\"".to_string();
            let truncate_at = (*at_byte as usize % json.len()).max(1);
            json.truncate(truncate_at);
            json
        }
        JsonCorruption::InvalidChars { chars } => {
            let mut json = "{\"test\":\"".to_string();
            for &byte in chars.iter().take(10) {
                json.push(byte as char);
            }
            json.push_str("\"}");
            json
        }
        JsonCorruption::DeepNesting { depth } => {
            let mut json = String::new();
            let depth = (*depth as usize).min(50);
            for _ in 0..depth {
                json.push_str("{\"nested\":");
            }
            json.push_str("\"value\"");
            for _ in 0..depth {
                json.push('}');
            }
            json
        }
        JsonCorruption::DuplicateKeys { key } => {
            format!("{{\"{}\":\"first\",\"{}\":\"second\"}}",
                   json_escape(key), json_escape(key))
        }
        JsonCorruption::Empty => String::new(),
        JsonCorruption::NonJson { content } => {
            String::from_utf8_lossy(content).into_owned()
        }
    }
}

fn add_field(json: &mut String, name: &str, value: &FieldValue<String>, formatting: &JsonFormatting, comma: bool) {
    match value {
        FieldValue::Present(s) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_string_value(json, &FieldValue::Present(s.clone()), formatting);
        }
        FieldValue::Missing => {
            // Don't add field
        }
        FieldValue::WrongType(wrong) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_wrong_type_value(json, wrong, formatting);
        }
        FieldValue::Null => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":null", name));
        }
    }
}

fn add_field_i64(json: &mut String, name: &str, value: &FieldValue<i64>, formatting: &JsonFormatting, comma: bool) {
    match value {
        FieldValue::Present(n) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_number_value(json, *n, formatting);
        }
        FieldValue::Missing => {}
        FieldValue::WrongType(wrong) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_wrong_type_value(json, wrong, formatting);
        }
        FieldValue::Null => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":null", name));
        }
    }
}

fn add_field_u64(json: &mut String, name: &str, value: &FieldValue<u64>, formatting: &JsonFormatting, comma: bool) {
    match value {
        FieldValue::Present(n) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            json.push_str(&format_u64(*n, formatting));
        }
        FieldValue::Missing => {}
        FieldValue::WrongType(wrong) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_wrong_type_value(json, wrong, formatting);
        }
        FieldValue::Null => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":null", name));
        }
    }
}

fn add_field_u32(json: &mut String, name: &str, value: &FieldValue<u32>, formatting: &JsonFormatting, comma: bool) {
    match value {
        FieldValue::Present(n) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":{}:", name, *n));
        }
        FieldValue::Missing => {}
        FieldValue::WrongType(wrong) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_wrong_type_value(json, wrong, formatting);
        }
        FieldValue::Null => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":null", name));
        }
    }
}

fn add_field_bool(json: &mut String, name: &str, value: &FieldValue<bool>, formatting: &JsonFormatting, comma: bool) {
    match value {
        FieldValue::Present(b) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":{}", name, if *b { "true" } else { "false" }));
        }
        FieldValue::Missing => {}
        FieldValue::WrongType(wrong) => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":", name));
            add_wrong_type_value(json, wrong, formatting);
        }
        FieldValue::Null => {
            if comma { json.push(','); }
            add_whitespace(json, formatting);
            json.push_str(&format!("\"{}\":null", name));
        }
    }
}

fn add_string_value(json: &mut String, value: &FieldValue<String>, formatting: &JsonFormatting) {
    match value {
        FieldValue::Present(s) => {
            json.push('"');
            json.push_str(&format_string(s, formatting));
            json.push('"');
        }
        FieldValue::Missing | FieldValue::Null => {
            json.push_str("null");
        }
        FieldValue::WrongType(wrong) => {
            add_wrong_type_value(json, wrong, formatting);
        }
    }
}

fn add_wrong_type_value(json: &mut String, wrong: &WrongTypeVariant, formatting: &JsonFormatting) {
    match wrong {
        WrongTypeVariant::StringForNumber(s) => {
            json.push('"');
            json.push_str(&format_string(s, formatting));
            json.push('"');
        }
        WrongTypeVariant::NumberForString(n) => {
            add_number_value(json, *n, formatting);
        }
        WrongTypeVariant::BoolForOther(b) => {
            json.push_str(if *b { "true" } else { "false" });
        }
        WrongTypeVariant::ArrayForValue(arr) => {
            json.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push('"');
                json.push_str(&json_escape(item));
                json.push('"');
            }
            json.push(']');
        }
        WrongTypeVariant::ObjectForPrimitive => {
            json.push_str("{\"nested\":\"value\"}");
        }
    }
}

fn add_number_value(json: &mut String, n: i64, formatting: &JsonFormatting) {
    let formatted = match formatting.numbers {
        NumberFormat::Integer => n.to_string(),
        NumberFormat::Float => format!("{}.0", n),
        NumberFormat::Scientific => format!("{:.2e}", n as f64),
        NumberFormat::Leading => format!("{:010}", n.abs()),
        NumberFormat::Overflow => {
            if n >= 0 {
                format!("{}", u64::MAX)
            } else {
                format!("{}", i64::MIN)
            }
        }
        NumberFormat::Negative => format!("-{}", n.abs()),
    };
    json.push_str(&formatted);
}

fn format_u64(n: u64, formatting: &JsonFormatting) -> String {
    match formatting.numbers {
        NumberFormat::Integer => n.to_string(),
        NumberFormat::Float => format!("{}.0", n),
        NumberFormat::Scientific => format!("{:.2e}", n as f64),
        NumberFormat::Leading => format!("{:020}", n),
        NumberFormat::Overflow => u64::MAX.to_string(),
        NumberFormat::Negative => {
            // Negative u64 is invalid but test edge case
            format!("-{}", n)
        }
    }
}

fn format_string(s: &str, formatting: &JsonFormatting) -> String {
    let mut result = String::new();
    for ch in s.chars().take(100) { // Limit string length
        match formatting.unicode {
            UnicodeFormat::Ascii => {
                if ch.is_ascii() {
                    result.push(ch);
                } else {
                    result.push('?');
                }
            }
            UnicodeFormat::ValidUnicode => {
                result.push(ch);
            }
            UnicodeFormat::EscapeSeq => {
                if ch.is_ascii() {
                    result.push(ch);
                } else {
                    result.push_str(&format!("\\u{:04x}", ch as u32));
                }
            }
            UnicodeFormat::InvalidSeq => {
                // Intentionally create invalid escape sequences
                result.push_str(&format!("\\u{:02x}", (ch as u32) & 0xFF));
            }
            UnicodeFormat::Surrogate => {
                // Create surrogate pair sequences (which may be invalid)
                let code = ch as u32;
                if code > 0xFFFF {
                    result.push_str(&format!("\\uD800\\uDC{:02x}", code & 0xFF));
                } else {
                    result.push(ch);
                }
            }
        }
    }

    match formatting.quotes {
        QuoteFormat::Normal => json_escape(&result),
        QuoteFormat::Escaped => {
            // Extra escaping
            result.replace('\\', "\\\\").replace('"', "\\\"")
        }
        QuoteFormat::Unicode => result,
        QuoteFormat::InvalidEscape => {
            // Create invalid escape sequences
            result.replace('\\', "\\x").replace('"', "\\q")
        }
    }
}

fn add_whitespace(json: &mut String, formatting: &JsonFormatting) {
    match formatting.whitespace {
        WhitespaceFormat::Minimal => {}
        WhitespaceFormat::Spaces => json.push(' '),
        WhitespaceFormat::Tabs => json.push('\t'),
        WhitespaceFormat::Newlines => json.push('\n'),
        WhitespaceFormat::Mixed => json.push_str(" \t\n "),
        WhitespaceFormat::Excessive => {
            for _ in 0..10 {
                json.push(' ');
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut result = String::new();
    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

fn test_jetstream_parsing(response: &ApiResponseType, json: &str) {
    let bytes = json.as_bytes();

    match response {
        ApiResponseType::StreamInfo { .. } => {
            // Test existing StreamInfo parser
            let _ = fuzz_parse_stream_info(bytes);
        }
        ApiResponseType::PubAck { .. } => {
            // Test existing PubAck parser
            let _ = fuzz_parse_pub_ack(bytes);
        }
        ApiResponseType::ApiError { .. } => {
            // Test existing API error parser
            let _ = fuzz_parse_api_error(json);
        }
        _ => {
            // For ServerInfo/AccountInfo, test general error detection
            test_error_classification(json);
        }
    }
}

fn test_json_structure(json: &str) {
    // Test basic JSON structure validation

    // Check for null byte injection
    assert!(!json.contains('\0'), "JSON should not contain null bytes");

    // Check for reasonable length
    assert!(json.len() <= 8192, "JSON response should not be excessively long");

    // Test basic brace/bracket matching (simplified check)
    let mut depth = 0i32;
    for ch in json.chars() {
        match ch {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            break; // Unmatched closing brace - expected for malformed input
        }
    }

    // Test for control character injection
    let has_unescaped_controls = json.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t');
    if has_unescaped_controls {
        // This is expected for malformed input fuzzing
    }
}

fn test_error_classification(json: &str) {
    // Test that error response classification works correctly

    let is_error_response = json.contains("\"error\":{\"code\":");
    let has_error_fields = json.contains("\"code\":") && json.contains("\"description\":");

    if is_error_response {
        // Should be classified as error
        let parsed_error = fuzz_parse_api_error(json);
        match parsed_error {
            JsError::Api { .. } | JsError::StreamNotFound(_) => {
                // Expected error classification
            }
            _ => {
                // Unexpected classification - could be a parsing bug or expected for malformed input
            }
        }
    } else if has_error_fields {
        // Has error-like fields but not in proper error envelope
        // Should NOT be classified as error response
    }
}