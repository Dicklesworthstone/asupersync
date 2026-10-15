#![no_main]

use asupersync::messaging::jetstream::{
    FuzzJsAckMetadata, JsError, fuzz_parse_api_error, fuzz_parse_js_message, fuzz_parse_pub_ack,
    fuzz_parse_stream_info,
};
use asupersync::messaging::nats::Message;
use libfuzzer_sys::fuzz_target;
use std::str;

const MAX_INPUT_LEN: usize = 100_000;

fn parse_reply_subject(reply_subject: &str, payload: &[u8]) -> Option<FuzzJsAckMetadata> {
    fuzz_parse_js_message(Message {
        subject: "fuzz.jetstream.payload".to_string(),
        sid: 1,
        reply_to: Some(reply_subject.to_string()),
        headers: None,
        payload: payload.to_vec(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckSubjectObservation {
    Accepted,
    Rejected,
}

fn observe_reply_subject_parse(reply_subject: &str, payload: &[u8]) -> AckSubjectObservation {
    match parse_reply_subject(reply_subject, payload) {
        Some(metadata) => {
            assert_eq!(
                metadata.subject, "fuzz.jetstream.payload",
                "ACK metadata should preserve the source message subject",
            );
            assert_eq!(
                metadata.payload_len,
                payload.len(),
                "ACK metadata should preserve the source payload length",
            );
            AckSubjectObservation::Accepted
        }
        None => AckSubjectObservation::Rejected,
    }
}

fn assert_visible_js_error(err: &JsError) {
    assert!(
        !err.to_string().is_empty(),
        "JetStream parser errors should remain observable"
    );
}

fn assert_js_parse_error(err: &JsError, expected_message: &str, expected_display: &str) {
    assert!(
        matches!(err, JsError::ParseError(message) if message == expected_message),
        "expected ParseError({expected_message:?}), got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        expected_display,
        "JetStream parse error display drifted"
    );
}

fn assert_js_api_error(err: &JsError, expected_code: u32, expected_description: &str) {
    assert!(
        matches!(
            err,
            JsError::Api { code, description }
                if *code == expected_code && description == expected_description
        ),
        "expected API error {expected_code}:{expected_description:?}, got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!("JetStream API error {expected_code}: {expected_description}"),
        "JetStream API error display drifted"
    );
}

fn assert_js_stream_not_found(err: &JsError, expected_description: &str) {
    assert!(
        matches!(err, JsError::StreamNotFound(description) if description == expected_description),
        "expected StreamNotFound({expected_description:?}), got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!("JetStream stream not found: {expected_description}"),
        "JetStream stream-not-found display drifted"
    );
}

fn observe_stream_info_parse(bytes: &[u8]) {
    match fuzz_parse_stream_info(bytes) {
        Ok(info) => {
            assert!(
                info.config.name.len() <= bytes.len(),
                "parsed StreamInfo name should be input-bounded"
            );
        }
        Err(err) => assert_visible_js_error(&err),
    }
}

fn observe_pub_ack_parse(bytes: &[u8]) {
    match fuzz_parse_pub_ack(bytes) {
        Ok(ack) => {
            assert!(
                ack.stream.len() <= bytes.len(),
                "parsed PubAck stream should be input-bounded"
            );
        }
        Err(err) => assert_visible_js_error(&err),
    }
}

fn observe_api_error_parse(json_data: &str) {
    let err = fuzz_parse_api_error(json_data);
    assert_visible_js_error(&err);
}

fn observe_jetstream_api_parsers(json_data: &str) {
    let payload = json_data.as_bytes();
    observe_stream_info_parse(payload);
    observe_pub_ack_parse(payload);
    observe_api_error_parse(json_data);
}

fn assert_known_json_parser_outputs() {
    let stream_info = fuzz_parse_stream_info(
        br#"{"config":{"name":"EVENTS"},"state":{"messages":7,"bytes":42,"first_seq":1,"last_seq":7,"consumer_count":2}}"#,
    )
    .expect("valid stream info response should parse");
    assert_eq!(stream_info.config.name, "EVENTS");
    assert_eq!(stream_info.state.messages, 7);
    assert_eq!(stream_info.state.bytes, 42);
    assert_eq!(stream_info.state.first_seq, 1);
    assert_eq!(stream_info.state.last_seq, 7);
    assert_eq!(stream_info.state.consumer_count, 2);

    let pub_ack = fuzz_parse_pub_ack(br#"{"stream":"ORDERS","seq":123,"duplicate":true}"#)
        .expect("valid pub ack response should parse");
    assert_eq!(pub_ack.stream, "ORDERS");
    assert_eq!(pub_ack.seq, 123);
    assert!(pub_ack.duplicate);

    let api_error = fuzz_parse_api_error(
        r#"{"error":{"code":404,"err_code":10059,"description":"stream not found"}}"#,
    );
    assert!(matches!(
        api_error,
        JsError::StreamNotFound(description) if description == "stream not found"
    ));

    let missing_stream_name = match fuzz_parse_stream_info(br#"{}"#) {
        Ok(_) => panic!("stream info without a name should fail"),
        Err(err) => err,
    };
    assert_js_parse_error(
        &missing_stream_name,
        "missing stream name",
        "JetStream parse error: missing stream name",
    );

    let missing_pub_ack_stream = match fuzz_parse_pub_ack(br#"{}"#) {
        Ok(_) => panic!("PubAck without a stream should fail"),
        Err(err) => err,
    };
    assert_js_parse_error(
        &missing_pub_ack_stream,
        "missing stream in PubAck",
        "JetStream parse error: missing stream in PubAck",
    );

    let missing_pub_ack_seq = match fuzz_parse_pub_ack(br#"{"stream":"ORDERS"}"#) {
        Ok(_) => panic!("PubAck without a sequence should fail"),
        Err(err) => err,
    };
    assert_js_parse_error(
        &missing_pub_ack_seq,
        "missing seq in PubAck",
        "JetStream parse error: missing seq in PubAck",
    );

    let stream_info_api_error =
        match fuzz_parse_stream_info(br#"{"error":{"code":400,"description":"bad request"}}"#) {
            Ok(_) => panic!("stream info API error response should fail"),
            Err(err) => err,
        };
    assert_js_api_error(&stream_info_api_error, 400, "bad request");

    let pub_ack_stream_not_found = match fuzz_parse_pub_ack(
        br#"{"error":{"code":404,"err_code":10059,"description":"stream not found"}}"#,
    ) {
        Ok(_) => panic!("PubAck stream-not-found API response should fail"),
        Err(err) => err,
    };
    assert_js_stream_not_found(&pub_ack_stream_not_found, "stream not found");
}

fn assert_known_ack_subject_outputs(payload: &[u8]) {
    let valid_cases = [
        ("$JS.ACK.stream.consumer.1.100.50.1234567890.5", 1, 100),
        (
            "$JS.ACK.stream.with.dots.consumer.with.dots.3.42.21.9999999.0",
            3,
            42,
        ),
        ("$JS.ACK...4.2.3.4.5", 4, 2),
    ];

    for (reply_subject, delivered, sequence) in valid_cases {
        let parsed = parse_reply_subject(reply_subject, payload)
            .expect("valid JetStream ACK reply subject should parse");
        assert_eq!(parsed.delivered, delivered);
        assert_eq!(parsed.sequence, sequence);
        assert_eq!(parsed.payload_len, payload.len());
    }

    let invalid_cases = [
        "",
        "$JS.ACK",
        "$JS.ACK.stream.consumer.1.100.50.1234567890",
        "$JS.ACK.stream.consumer.not-delivered.100.50.1234567890.5",
        "$JS.ACK.stream.consumer.1.not-sequence.50.1234567890.5",
        "$JS.NAK.stream.consumer.1.100.50.1234567890.5",
    ];

    for reply_subject in invalid_cases {
        assert!(parse_reply_subject(reply_subject, payload).is_none());
    }
}

fn observe_ack_subject_variants(subject_data: &str, payload: &[u8]) {
    let reply_subjects = [
        "$JS.ACK.stream.consumer.1.100.50.1234567890.5".to_string(),
        format!("$JS.ACK.{subject_data}.consumer.1.100.50.1234567890.5"),
        format!("$JS.ACK.stream.{subject_data}.2.101.51.1234567891.6"),
        "$JS.ACK.stream.with.dots.consumer.with.dots.3.42.21.9999999.0".to_string(),
        format!("$JS.ACK.{subject_data}"),
        format!("$JS.{subject_data}"),
        subject_data.to_string(),
    ];

    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for reply_subject in &reply_subjects {
        match observe_reply_subject_parse(reply_subject, payload) {
            AckSubjectObservation::Accepted => accepted += 1,
            AckSubjectObservation::Rejected => rejected += 1,
        }
    }

    assert_eq!(
        accepted + rejected,
        reply_subjects.len(),
        "every generated ACK subject variant should be classified",
    );
    assert!(
        accepted > 0,
        "fixed ACK subject variants should keep at least one successful parse",
    );
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
            format!("{{\"field\":\"{}", base_str), // Missing closing quote/brace
            format!("{{\"{}\":", base_str),        // Missing value
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
            "{\"rate\":NaN}".to_string(),
            "{\"timeout\":Infinity}".to_string(),
            "{\"delay\":-Infinity}".to_string(),
            // Unicode and escapes
            format!("{{\"subject\":\"{}\\u0000\"}}", base_str),
            format!("{{\"data\":\"{}\\uFFFF\"}}", base_str),
            format!("{{\"name\":\"{}\u{1F4A9}\"}}", base_str), // emoji
            // Control characters
            format!("{{\"{}\x00\":\"value\"}}", base_str), // null in key
            format!("{{\"key\":\"{}\x1F\"}}", base_str),   // control char
            format!("{{\"bom\":\"{}\u{FEFF}\"}}", base_str), // BOM
            // Malformed escapes
            format!("{{\"field\":\"{}\\x\"}}", base_str), // bad escape
            format!("{{\"field\":\"{}\\u123\"}}", base_str), // incomplete unicode
            format!("{{\"field\":\"{}\\uZZZZ\"}}", base_str), // invalid unicode
            // Duplicate keys
            format!("{{\"key\":\"{}\",\"key\":\"{}\"}}", base_str, base_str),
            // Type confusion
            format!("{{\"seq\":\"{}\"}}", base_str), // string for number
            format!("{{\"messages\":\"{}\"}}", base_str), // string for array
            format!("{{\"config\":\"{}\"}}", base_str), // string for object
            // Very long values
            base_str.repeat(1000),
            format!("{{\"data\":\"{}\"}}", base_str.repeat(500)),
            // Deep nesting
            (0..100).fold(format!("{{\"data\":\"{}\"}}", base_str), |acc, _| {
                format!("{{\"nested\":{}}}", acc)
            }),
        ];

        for payload in &malformed_payloads {
            observe_jetstream_api_parsers(payload);
        }
    }
}

/// Test edge cases with specific problematic JSON patterns.
fn test_json_edge_cases() {
    assert_known_json_parser_outputs();

    let edge_case_payloads = [
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
        r#"{"seq":18446744073709551615}"#,     // u64::MAX
        r#"{"delivered":-1}"#,                 // negative
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
        r#"{"utf8":"Hello 世界"}"#,
        r#"{"emoji":"🚀📡🌟"}"#,
        r#"{"control":"\u0000\u001F\u007F"}"#,
        r#"{"highcode":"\uFFFF\uFFFE\uD800\uDFFF"}"#,
    ];

    for payload in edge_case_payloads {
        observe_jetstream_api_parsers(payload);
    }

    let generated_edge_case_payloads = [
        "x".repeat(100_000),
        "{}".repeat(50_000),
        "[".repeat(10_000) + &"]".repeat(10_000),
        format!("{{\"overflow\":{}}}", "9".repeat(1_000)),
        "{\"a\":".repeat(1_000) + "null" + &"}".repeat(1_000),
    ];

    for payload in &generated_edge_case_payloads {
        observe_jetstream_api_parsers(payload);
    }

    // Test subject parsing edge cases
    let subject_edge_cases = [
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
        "\x00\x1F\x7F", // control chars
        " leading.space",
        "trailing.space ",
        "  multiple   spaces  ",
        "\t\nwhitespace\r",
    ];

    for subject in subject_edge_cases {
        observe_ack_subject_variants(subject, subject.as_bytes());
    }
}

/// Test protocol compliance with real-world patterns.
fn test_protocol_patterns() {
    // Test various JetStream API patterns
    let api_patterns = [
        // Stream operations
        (
            "$JS.API.STREAM.CREATE.EVENTS",
            r#"{"name":"EVENTS","subjects":["events.*"]}"#,
        ),
        ("$JS.API.STREAM.DELETE.EVENTS", r#"{"}"#),
        ("$JS.API.STREAM.INFO.EVENTS", r#"{}"#),
        ("$JS.API.STREAM.LIST", r#"{"offset":0,"limit":256}"#),
        (
            "$JS.API.STREAM.PURGE.EVENTS",
            r#"{"filter":"events.old.*"}"#,
        ),
        // Durable subscription operations
        (
            "$JS.API.CONSUMER.CREATE.EVENTS.PROCESSOR",
            r#"{"durable_name":"processor","deliver_subject":"process.>"}"#,
        ),
        ("$JS.API.CONSUMER.DELETE.EVENTS.PROCESSOR", r#"{}"#),
        ("$JS.API.CONSUMER.INFO.EVENTS.PROCESSOR", r#"{}"#),
        // Message operations
        ("$JS.API.DIRECT.GET.EVENTS", r#"{"seq":123}"#),
        (
            "$JS.API.STREAM.MSG.DELETE.EVENTS",
            r#"{"seq":456,"no_erase":false}"#,
        ),
    ];

    for (subject, payload) in api_patterns {
        observe_ack_subject_variants(subject, payload.as_bytes());
        observe_jetstream_api_parsers(payload);
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    assert_known_ack_subject_outputs(data);

    // Test 1: Parse as JSON API response
    if let Ok(json_str) = str::from_utf8(data) {
        observe_jetstream_api_parsers(json_str);
    }

    // Test 2: Parse as subject string
    if let Ok(subject_str) = str::from_utf8(data) {
        observe_ack_subject_variants(subject_str, data);
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
                    observe_jetstream_api_parsers(partial_str);
                    observe_ack_subject_variants(partial_str, partial);
                }
            }
        }
    }

    // Test 7: Concatenation tests (test JSON arrays/sequences)
    if let Ok(base_str) = str::from_utf8(data)
        && !base_str.is_empty()
        && base_str.len() < 1000
    {
        // Test JSON array format
        let array_json = format!("[{},{}]", base_str, base_str);
        observe_jetstream_api_parsers(&array_json);

        // Test concatenated objects
        let concat_json = format!("{}{}", base_str, base_str);
        observe_jetstream_api_parsers(&concat_json);

        // Test newline-delimited JSON (NDJSON)
        let ndjson = format!("{}\n{}\n{}", base_str, base_str, base_str);
        observe_jetstream_api_parsers(&ndjson);
    }

    // Test 8: Binary data interpretation
    if data.len() <= 1000 {
        // Test with lossy UTF-8 conversion
        let lossy_string = String::from_utf8_lossy(data);
        observe_jetstream_api_parsers(&lossy_string);
        observe_ack_subject_variants(&lossy_string, data);

        // Test Latin-1 interpretation
        let latin1_string: String = data.iter().map(|&b| b as char).collect();
        observe_jetstream_api_parsers(&latin1_string);
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
            format!(
                "{{\"timeout\":{}}}",
                if first_byte == 0 { 1 } else { first_byte }
            ),
        ];

        for test_json in &numeric_tests {
            observe_jetstream_api_parsers(test_json);
        }

        // Test string field extremes
        let string_tests = [
            format!("{{\"name\":\"{}\"}}", first_byte as char),
            format!("{{\"subject\":\"test.{}.events\"}}", first_byte),
            format!("{{\"error\":\"code {}\"}}", first_byte),
            format!(
                "{{\"description\":\"{}\"}}",
                (0..first_byte).map(|_| 'x').collect::<String>()
            ),
        ];

        for test_json in &string_tests {
            observe_jetstream_api_parsers(test_json);
        }
    }

    // Test 10: Mixed encoding interpretation
    if data.len() >= 2 {
        // Test as potential JSON with BOM
        let with_bom = [0xEF, 0xBB, 0xBF]
            .iter()
            .chain(data.iter())
            .copied()
            .collect::<Vec<_>>();
        if let Ok(bom_string) = String::from_utf8(with_bom) {
            observe_jetstream_api_parsers(&bom_string);
        }

        // Test as potential UTF-16
        if data.len().is_multiple_of(2) {
            let utf16_units: Vec<u16> = data
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            if let Ok(utf16_string) = String::from_utf16(&utf16_units) {
                observe_ack_subject_variants(&utf16_string, data);
            }
        }
    }
});
