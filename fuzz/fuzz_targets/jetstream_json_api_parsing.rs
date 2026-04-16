#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target for JetStream JSON API parsing robustness.
///
/// This target tests the robustness of JetStream message and response parsing:
/// - `parse_stream_info()`: Parses stream configuration and state JSON
/// - `parse_pub_ack()`: Parses publish acknowledgment responses
/// - `parse_api_error()`: Parses API error responses
/// - `extract_json_string_simple()`: Simple JSON field extraction
/// - `extract_json_u64()`: JSON number field extraction
/// - `parse_js_message()`: Parses JetStream message metadata from subjects
///
/// The fuzzer generates malformed, edge case, and malicious JSON payloads
/// to verify parsers are robust against untrusted server responses.
use asupersync::messaging::jetstream::{
    parse_stream_info, parse_pub_ack, parse_api_error,
    extract_json_string_simple, extract_json_u64, parse_js_message,
    StreamInfo, PubAck, ApiError, JsMessage
};
use std::str;

/// Test parse_stream_info with various JSON inputs.
fn test_stream_info_parsing(json_data: &str) {
    // Should not crash on any input
    let _result = parse_stream_info(json_data);

    // Test with whitespace variations
    let trimmed = json_data.trim();
    let _result = parse_stream_info(trimmed);

    // Test with extra whitespace
    let padded = format!("  {}  ", json_data);
    let _result = parse_stream_info(&padded);
}

/// Test parse_pub_ack with various JSON inputs.
fn test_pub_ack_parsing(json_data: &str) {
    // Should not crash on any input
    let _result = parse_pub_ack(json_data);

    // Test with byte prefix/suffix
    let with_prefix = format!("PREFIX{}", json_data);
    let _result = parse_pub_ack(&with_prefix);

    let with_suffix = format!("{}SUFFIX", json_data);
    let _result = parse_pub_ack(&with_suffix);
}

/// Test parse_api_error with various JSON inputs.
fn test_api_error_parsing(json_data: &str) {
    // Should not crash on any input
    let _result = parse_api_error(json_data);

    // Test case variations
    let lowercase = json_data.to_lowercase();
    let _result = parse_api_error(&lowercase);

    let uppercase = json_data.to_uppercase();
    let _result = parse_api_error(&uppercase);
}

/// Test extract_json_string_simple with various field names and JSON.
fn test_json_string_extraction(json_data: &str) {
    let test_fields = ["name", "stream", "subject", "error", "description",
                       "consumer", "durable_name", "deliver_subject", "config"];

    for field in &test_fields {
        let _result = extract_json_string_simple(json_data, field);

        // Test with quoted field names
        let quoted_field = format!("\"{}\"", field);
        let _result = extract_json_string_simple(json_data, &quoted_field);

        // Test case sensitivity
        let upper_field = field.to_uppercase();
        let _result = extract_json_string_simple(json_data, &upper_field);
    }
}

/// Test extract_json_u64 with various field names and JSON.
fn test_json_u64_extraction(json_data: &str) {
    let test_fields = ["seq", "stream_seq", "consumer_seq", "delivered",
                       "ack_floor", "num_pending", "num_redelivered", "code"];

    for field in &test_fields {
        let _result = extract_json_u64(json_data, field);

        // Test with edge values
        let zero_json = format!("{{\"{}\":0}}", field);
        let _result = extract_json_u64(&zero_json, field);

        let max_json = format!("{{\"{}\":{}}}", field, u64::MAX);
        let _result = extract_json_u64(&max_json, field);
    }
}

/// Test parse_js_message with various subject patterns.
fn test_js_message_parsing(subject: &str) {
    // Should not crash on any input
    let _result = parse_js_message(subject);

    // Test with URL-like subjects
    let url_subject = format!("$JS.API.{}", subject);
    let _result = parse_js_message(&url_subject);

    // Test with dots and special chars
    let dotted = subject.replace(" ", ".");
    let _result = parse_js_message(&dotted);
}

/// Generate malformed JSON based on input data.
fn test_malformed_json(base_data: &[u8]) {
    if let Ok(base_str) = str::from_utf8(base_data) {
        let malformed_payloads = vec![
            // Basic JSON variations
            base_str.to_string(),
            format!("{{{}}}", base_str),
            format!("[\"{}\"]", base_str),
            format!("\"{}\"", base_str),

            // Incomplete JSON
            format!("{{\"field\":\"{}", base_str),      // Missing closing quote/brace
            format!("{{\"{}\":", base_str),             // Missing value
            format!("{{\"{}\":{}}}", base_str, base_str), // Non-quoted value

            // Nested structures
            format!("{{\"config\":{{\"name\":\"{}\"}}}}", base_str),
            format!("{{\"stream_info\":{{\"{}\":{}}}}}", base_str, "null"),

            // Array structures
            format!("{{\"subjects\":[\"{}\",\"{}\"]}}", base_str, base_str),
            format!("{{\"messages\":[{{\"data\":\"{}\"}}]}}", base_str),

            // Large numbers
            format!("{{\"seq\":{}}}", base_str),
            format!("{{\"size\":{}}}", u64::MAX),
            format!("{{\"count\":{}}}", i64::MIN),

            // Special float values
            format!("{{\"rate\":{}}}", "NaN"),
            format!("{{\"timeout\":{}}}", "Infinity"),
            format!("{{\"delay\":{}}}", "-Infinity"),

            // Unicode and escapes
            format!("{{\"subject\":\"{}\\u0000\"}}", base_str),
            format!("{{\"data\":\"{}\\uFFFF\"}}", base_str),
            format!("{{\"name\":\"{}\u{1F4A9}\"}}", base_str),   // emoji

            // Control characters
            format!("{{\"{}\x00\":\"value\"}}", base_str),      // null in key
            format!("{{\"key\":\"{}\x1F\"}}", base_str),        // control char
            format!("{{\"bom\":\"{}\u{FEFF}\"}}", base_str),     // BOM

            // Malformed escapes
            format!("{{\"field\":\"{}\\x\"}}", base_str),       // bad escape
            format!("{{\"field\":\"{}\\u123\"}}", base_str),    // incomplete unicode
            format!("{{\"field\":\"{}\\uZZZZ\"}}", base_str),   // invalid unicode

            // Duplicate keys
            format!("{{\"key\":\"{}\",\"key\":\"{}\"}}", base_str, base_str),

            // Type confusion
            format!("{{\"seq\":\"{}\"}}",  base_str),           // string for number
            format!("{{\"messages\":\"{}\"}}",  base_str),     // string for array
            format!("{{\"config\":\"{}\"}}",  base_str),       // string for object

            // Very long values
            base_str.repeat(1000),
            format!("{{\"data\":\"{}\"}}", base_str.repeat(500)),

            // Deep nesting
            (0..100).fold(format!("{{\"data\":\"{}\"}}", base_str), |acc, _| {
                format!("{{\"nested\":{}}}", acc)
            }),
        ];

        for payload in &malformed_payloads {
            test_stream_info_parsing(payload);
            test_pub_ack_parsing(payload);
            test_api_error_parsing(payload);
            test_json_string_extraction(payload);
            test_json_u64_extraction(payload);
        }
    }
}

/// Test edge cases with specific problematic JSON patterns.
fn test_json_edge_cases() {
    let edge_case_payloads = vec![
        // Empty and whitespace
        "",
        "{}",
        "[]",
        "null",
        "   ",
        "\t\n\r",

        // Minimal valid stream info
        r#"{"config":{"name":"test"}}"#,
        r#"{"state":{"messages":0}}"#,

        // Minimal valid pub ack
        r#"{"stream":"test","seq":1}"#,
        r#"{"error":{"code":400,"description":"bad request"}}"#,

        // API errors
        r#"{"error_code":404,"description":"not found"}"#,
        r#"{"type":"error","code":500}"#,

        // Boundary numbers
        r#"{"seq":0}"#,
        r#"{"seq":18446744073709551615}"#,    // u64::MAX
        r#"{"delivered":-1}"#,               // negative
        r#"{"size":1.7976931348623157e+308}"#, // f64 max
        r#"{"rate":4.9406564584124654e-324}"#, // f64 min positive

        // Complex nested structures
        r#"{"config":{"name":"stream","subjects":["a","b","c"],"retention":"limits","max_msgs":1000}}"#,
        r#"{"state":{"messages":100,"bytes":1024,"first_seq":1,"last_seq":100,"consumer_count":2}}"#,
        r#"{"cluster":{"name":"cluster","leader":"node1","replicas":[{"name":"node2","current":true}]}}"#,

        // Real-world-ish payloads
        r#"{"type":"io.nats.jetstream.api.v1.stream_info_response","config":{"name":"EVENTS","subjects":["events.*"],"retention":"limits","max_consumers":-1,"max_msgs":-1,"max_bytes":-1,"max_age":0,"max_msgs_per_subject":-1,"max_msg_size":-1,"storage":"file","num_replicas":1,"discard":"old"},"state":{"messages":0,"bytes":0,"first_seq":0,"last_seq":0,"consumer_count":0}}"#,
        r#"{"type":"io.nats.jetstream.api.v1.pub_ack","stream":"ORDERS","seq":1234567}"#,
        r#"{"error":{"code":404,"err_code":10059,"description":"stream not found"}}"#,

        // Malicious attempts
        "x".repeat(100000),                  // very long
        "{}".repeat(50000),                  // many objects
        "[".repeat(10000) + &"]".repeat(10000), // deep arrays
        format!("{{\"overflow\":{}}}", "9".repeat(1000)),  // huge number
        "{\"a\":".repeat(1000) + "null" + &"}".repeat(1000), // deep nesting

        // Encoding edge cases
        r#"{"utf8":"Hello 世界"}"#,
        r#"{"emoji":"🚀📡🌟"}"#,
        r#"{"control":"\u0000\u001F\u007F"}"#,
        r#"{"highcode":"\uFFFF\uFFFE\uD800\uDFFF"}"#,
    ];

    for payload in &edge_case_payloads {
        test_stream_info_parsing(payload);
        test_pub_ack_parsing(payload);
        test_api_error_parsing(payload);
        test_json_string_extraction(payload);
        test_json_u64_extraction(payload);
    }

    // Test subject parsing edge cases
    let subject_edge_cases = vec![
        "",
        ".",
        "..",
        "...",
        "$JS.API",
        "$JS.API.",
        "$JS.API.STREAM.INFO",
        "$JS.API.CONSUMER.DURABLE.ORDERS.STATUS",
        "events.order.created.tenant123",
        "very.long.subject.with.many.dots.and.segments.that.might.overflow.buffers",
        "subject_with_underscores_and_numbers_123",
        "UPPERCASE.SUBJECT",
        "mixed.Case.Subject.With.123.Numbers",
        "special!@#$%^&*()chars",
        "unicode.测试.🌟",
        "\x00\x1F\x7F",      // control chars
        " leading.space",
        "trailing.space ",
        "  multiple   spaces  ",
        "\t\nwhitespace\r",
    ];

    for subject in &subject_edge_cases {
        test_js_message_parsing(subject);
    }
}

/// Test protocol compliance with real-world patterns.
fn test_protocol_patterns() {
    // Test various JetStream API patterns
    let api_patterns = vec![
        // Stream operations
        ("$JS.API.STREAM.CREATE.EVENTS", r#"{"name":"EVENTS","subjects":["events.*"]}"#),
        ("$JS.API.STREAM.DELETE.EVENTS", r#"{"}"#),
        ("$JS.API.STREAM.INFO.EVENTS", r#"{}"#),
        ("$JS.API.STREAM.LIST", r#"{"offset":0,"limit":256}"#),
        ("$JS.API.STREAM.PURGE.EVENTS", r#"{"filter":"events.old.*"}"#),

        // Consumer operations
        ("$JS.API.CONSUMER.CREATE.EVENTS.PROCESSOR", r#"{"durable_name":"processor","deliver_subject":"process.>"}"#),
        ("$JS.API.CONSUMER.DELETE.EVENTS.PROCESSOR", r#"{}"#),
        ("$JS.API.CONSUMER.INFO.EVENTS.PROCESSOR", r#"{}"#),

        // Message operations
        ("$JS.API.DIRECT.GET.EVENTS", r#"{"seq":123}"#),
        ("$JS.API.STREAM.MSG.DELETE.EVENTS", r#"{"seq":456,"no_erase":false}"#),
    ];

    for (subject, payload) in &api_patterns {
        test_js_message_parsing(subject);
        test_stream_info_parsing(payload);
        test_pub_ack_parsing(payload);
        test_api_error_parsing(payload);
        test_json_string_extraction(payload);
        test_json_u64_extraction(payload);
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 100_000 {
        return;
    }

    // Test 1: Parse as JSON API response
    if let Ok(json_str) = str::from_utf8(data) {
        test_stream_info_parsing(json_str);
        test_pub_ack_parsing(json_str);
        test_api_error_parsing(json_str);
        test_json_string_extraction(json_str);
        test_json_u64_extraction(json_str);
    }

    // Test 2: Parse as subject string
    if let Ok(subject_str) = str::from_utf8(data) {
        test_js_message_parsing(subject_str);
    }

    // Test 3: Generate malformed JSON based on input
    test_malformed_json(data);

    // Test 4: Always test known edge cases
    test_json_edge_cases();

    // Test 5: Test protocol compliance patterns
    test_protocol_patterns();

    // Test 6: Chunked parsing (test partial JSON)
    if data.len() > 1 {
        for chunk_size in [1, 4, 16, 64, 256] {
            if chunk_size < data.len() {
                let partial = &data[..chunk_size];

                if let Ok(partial_str) = str::from_utf8(partial) {
                    test_stream_info_parsing(partial_str);
                    test_pub_ack_parsing(partial_str);
                    test_api_error_parsing(partial_str);
                    test_js_message_parsing(partial_str);
                }
            }
        }
    }

    // Test 7: Concatenation tests (test JSON arrays/sequences)
    if let Ok(base_str) = str::from_utf8(data) {
        if !base_str.is_empty() && base_str.len() < 1000 {
            // Test JSON array format
            let array_json = format!("[{},{}]", base_str, base_str);
            test_stream_info_parsing(&array_json);
            test_pub_ack_parsing(&array_json);

            // Test concatenated objects
            let concat_json = format!("{}{}", base_str, base_str);
            test_api_error_parsing(&concat_json);

            // Test newline-delimited JSON (NDJSON)
            let ndjson = format!("{}\n{}\n{}", base_str, base_str, base_str);
            test_json_string_extraction(&ndjson);
            test_json_u64_extraction(&ndjson);
        }
    }

    // Test 8: Binary data interpretation
    if data.len() <= 1000 {
        // Test with lossy UTF-8 conversion
        let lossy_string = String::from_utf8_lossy(data);
        test_stream_info_parsing(&lossy_string);
        test_js_message_parsing(&lossy_string);

        // Test Latin-1 interpretation
        let latin1_string: String = data.iter().map(|&b| b as char).collect();
        test_json_string_extraction(&latin1_string);
    }

    // Test 9: Stress test with extreme field values
    if !data.is_empty() {
        let first_byte = data[0];

        // Test numeric field extremes
        let numeric_tests = [
            format!("{{\"seq\":{}}}", first_byte),
            format!("{{\"delivered\":{}}}", first_byte as u64),
            format!("{{\"size\":{}}}", (first_byte as u64) * 1_000_000),
            format!("{{\"rate\":{}.{}}}", first_byte / 10, first_byte % 10),
            format!("{{\"timeout\":{}}}", if first_byte == 0 { 1 } else { first_byte }),
        ];

        for test_json in &numeric_tests {
            test_json_u64_extraction(test_json);
            test_pub_ack_parsing(test_json);
        }

        // Test string field extremes
        let string_tests = [
            format!("{{\"name\":\"{}\"}}", first_byte as char),
            format!("{{\"subject\":\"test.{}.events\"}}", first_byte),
            format!("{{\"error\":\"code {}\"}}", first_byte),
            format!("{{\"description\":\"{}\"}}", (0..first_byte).map(|_| 'x').collect::<String>()),
        ];

        for test_json in &string_tests {
            test_json_string_extraction(test_json);
            test_api_error_parsing(test_json);
        }
    }

    // Test 10: Mixed encoding interpretation
    if data.len() >= 2 {
        // Test as potential JSON with BOM
        let with_bom = [0xEF, 0xBB, 0xBF].iter().chain(data.iter()).copied().collect::<Vec<_>>();
        if let Ok(bom_string) = String::from_utf8(with_bom) {
            test_stream_info_parsing(&bom_string);
        }

        // Test as potential UTF-16
        if data.len() % 2 == 0 {
            let utf16_units: Vec<u16> = data.chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            if let Ok(utf16_string) = String::from_utf16(&utf16_units) {
                test_js_message_parsing(&utf16_string);
            }
        }
    }
});