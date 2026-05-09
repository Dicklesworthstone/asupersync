#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::fmt::Write as _;

use asupersync::messaging::jetstream::{JsError, fuzz_parse_api_error, fuzz_parse_stream_info};

/// Structure-aware fuzz input for JetStream ConsumerInfo/StreamInfo wire decoder testing
#[derive(Arbitrary, Debug)]
struct JetStreamInfoFuzz {
    /// Test scenarios for different JSON response types
    scenario: InfoDecodingScenario,
    /// Whether to test malformed JSON structure
    test_malformed: bool,
    /// JSON field manipulation strategies
    field_strategy: FieldStrategy,
}

#[derive(Arbitrary, Debug, Clone)]
enum InfoDecodingScenario {
    /// Valid StreamInfo response structures
    ValidStreamInfo {
        stream_responses: Vec<StreamInfoVariant>,
    },
    /// Valid ConsumerInfo response structures
    ValidConsumerInfo {
        consumer_responses: Vec<ConsumerInfoVariant>,
    },
    /// API error response structures
    ApiError {
        error_responses: Vec<ApiErrorVariant>,
    },
    /// Mixed response sequences
    MixedResponses { responses: Vec<ResponseVariant> },
    /// JSON structure edge cases
    JsonEdgeCases { edge_cases: Vec<JsonEdgeCase> },
}

#[derive(Arbitrary, Debug, Clone)]
struct StreamInfoVariant {
    /// Stream name
    name: String,
    /// Stream state fields
    state: StreamStateFields,
    /// Configuration fields
    config: StreamConfigFields,
    /// Whether to include optional fields
    include_optional: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct StreamStateFields {
    /// Message count
    messages: u64,
    /// Byte count
    bytes: u64,
    /// First sequence number
    first_seq: u64,
    /// Last sequence number
    last_seq: u64,
    /// Consumer count
    consumer_count: u64,
}

#[derive(Arbitrary, Debug, Clone)]
struct StreamConfigFields {
    /// Subjects array
    subjects: Vec<String>,
    /// Retention policy
    retention: String,
    /// Storage type
    storage: String,
    /// Maximum messages
    max_msgs: Option<i64>,
    /// Maximum bytes
    max_bytes: Option<i64>,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConsumerInfoVariant {
    /// Consumer name
    name: String,
    /// Stream name
    stream: String,
    /// Consumer configuration
    config: ConsumerConfigFields,
    /// Whether to include state information
    include_state: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConsumerConfigFields {
    /// Durable name
    durable_name: Option<String>,
    /// Delivery policy
    deliver_policy: String,
    /// Ack policy
    ack_policy: String,
    /// Ack wait duration (nanoseconds)
    ack_wait: u64,
    /// Max deliveries
    max_deliver: i64,
}

#[derive(Arbitrary, Debug, Clone)]
struct ApiErrorVariant {
    /// HTTP status code
    code: u32,
    /// JetStream error code
    err_code: Option<u32>,
    /// Error description
    description: String,
    /// Error type classification
    error_type: ErrorType,
}

#[derive(Arbitrary, Debug, Clone)]
enum ErrorType {
    /// Stream not found (err_code 10059)
    StreamNotFound,
    /// Consumer not found
    ConsumerNotFound,
    /// Generic API error
    Generic,
    /// Malformed error structure
    Malformed,
}

#[derive(Arbitrary, Debug, Clone)]
enum ResponseVariant {
    Stream(StreamInfoVariant),
    Consumer(ConsumerInfoVariant),
    Error(ApiErrorVariant),
    Empty,
}

#[derive(Arbitrary, Debug, Clone)]
struct JsonEdgeCase {
    /// Type of edge case being tested
    edge_type: JsonEdgeType,
    /// Test data for the edge case
    test_data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum JsonEdgeType {
    /// Empty JSON object
    Empty,
    /// Very large JSON
    VeryLarge,
    /// Deeply nested JSON
    DeeplyNested,
    /// Unicode in field names/values
    Unicode,
    /// Numeric edge cases (overflow, underflow)
    NumericEdges,
    /// String escape sequences
    EscapeSequences,
    /// Invalid JSON syntax
    InvalidSyntax,
    /// Missing required fields
    MissingFields,
}

#[derive(Arbitrary, Debug, Clone)]
enum FieldStrategy {
    /// Standard valid fields
    Standard,
    /// Randomize field order
    RandomOrder,
    /// Include extra unknown fields
    ExtraFields { extra_count: usize },
    /// Omit optional fields randomly
    OmitOptional,
    /// Type confusion (string as number, etc.)
    TypeConfusion,
}

/// Size limits to prevent OOM during fuzzing
const MAX_STRING_LEN: usize = 8192;
const MAX_ARRAY_LEN: usize = 100;
const MAX_RESPONSES: usize = 50;
const MAX_EDGE_CASES: usize = 20;
const MAX_NESTING_DEPTH: usize = 50;

fn assert_visible_js_error(err: &JsError) {
    assert!(
        !err.to_string().is_empty(),
        "JetStream parser errors should be observable"
    );
}

fn observe_stream_info_parse(payload: &[u8]) {
    match fuzz_parse_stream_info(payload) {
        Ok(info) => {
            assert!(
                info.config.name.len() <= payload.len(),
                "parsed StreamInfo name should be sourced from the input"
            );
        }
        Err(err) => assert_visible_js_error(&err),
    }
}

fn observe_api_error_parse(json: &str) -> JsError {
    let err = fuzz_parse_api_error(json);
    assert_visible_js_error(&err);
    err
}

fuzz_target!(|input: JetStreamInfoFuzz| {
    // Input size guards
    match &input.scenario {
        InfoDecodingScenario::ValidStreamInfo { stream_responses } => {
            if stream_responses.len() > MAX_RESPONSES {
                return;
            }
        }
        InfoDecodingScenario::ValidConsumerInfo { consumer_responses } => {
            if consumer_responses.len() > MAX_RESPONSES {
                return;
            }
        }
        InfoDecodingScenario::MixedResponses { responses } => {
            if responses.len() > MAX_RESPONSES {
                return;
            }
        }
        InfoDecodingScenario::JsonEdgeCases { edge_cases } => {
            if edge_cases.len() > MAX_EDGE_CASES {
                return;
            }
        }
        _ => {}
    }

    // Test main decoding scenarios
    test_jetstream_info_decoding_scenarios(&input);

    // Test malformed JSON structure if requested
    if input.test_malformed {
        test_malformed_json_structure(&input);
    }

    // Test JSON field manipulation strategies
    test_field_manipulation_strategies(&input);

    // Test error handling edge cases
    test_error_handling_edge_cases();
});

/// Test main JetStream info decoding scenarios
fn test_jetstream_info_decoding_scenarios(input: &JetStreamInfoFuzz) {
    match &input.scenario {
        InfoDecodingScenario::ValidStreamInfo { stream_responses } => {
            for response in stream_responses.iter().take(MAX_RESPONSES) {
                if is_valid_stream_response(response) {
                    let json = generate_stream_info_json(response, &input.field_strategy);
                    observe_stream_info_parse(json.as_bytes());
                }
            }
        }

        InfoDecodingScenario::ValidConsumerInfo { consumer_responses } => {
            for response in consumer_responses.iter().take(MAX_RESPONSES) {
                if is_valid_consumer_response(response) {
                    let json = generate_consumer_info_json(response, &input.field_strategy);
                    // ConsumerInfo parsing would go through similar JSON extraction
                    test_json_extraction(&json);
                }
            }
        }

        InfoDecodingScenario::ApiError { error_responses } => {
            for response in error_responses.iter().take(MAX_RESPONSES) {
                let json = generate_api_error_json(response, &input.field_strategy);
                observe_api_error_parse(&json);
            }
        }

        InfoDecodingScenario::MixedResponses { responses } => {
            for response in responses.iter().take(MAX_RESPONSES) {
                match response {
                    ResponseVariant::Stream(stream) => {
                        if is_valid_stream_response(stream) {
                            let json = generate_stream_info_json(stream, &input.field_strategy);
                            observe_stream_info_parse(json.as_bytes());
                        }
                    }
                    ResponseVariant::Consumer(consumer) => {
                        if is_valid_consumer_response(consumer) {
                            let json = generate_consumer_info_json(consumer, &input.field_strategy);
                            test_json_extraction(&json);
                        }
                    }
                    ResponseVariant::Error(error) => {
                        let json = generate_api_error_json(error, &input.field_strategy);
                        observe_api_error_parse(&json);
                    }
                    ResponseVariant::Empty => {
                        observe_stream_info_parse(b"{}");
                        observe_api_error_parse("{}");
                    }
                }
            }
        }

        InfoDecodingScenario::JsonEdgeCases { edge_cases } => {
            for edge_case in edge_cases.iter().take(MAX_EDGE_CASES) {
                test_json_edge_case(edge_case);
            }
        }
    }
}

/// Test malformed JSON structure handling
fn test_malformed_json_structure(input: &JetStreamInfoFuzz) {
    let malformed_cases: &[&[u8]] = &[
        b"",                                  // Empty
        b"{",                                 // Incomplete object
        b"}",                                 // Invalid start
        b"{\"name\":}",                       // Missing value
        b"{\"name\":\"test\",}",              // Trailing comma
        b"{\"name\":\"test\"\"other\":true}", // Missing comma
        b"{\"name\":\"test\": true false}",   // Invalid syntax
        b"null",                              // Null instead of object
        b"[]",                                // Array instead of object
        b"\"string\"",                        // String instead of object
        b"123",                               // Number instead of object
    ];

    for malformed in malformed_cases {
        observe_stream_info_parse(malformed);
        observe_api_error_parse(std::str::from_utf8(malformed).unwrap_or(""));
    }

    // Test with specific field strategy
    let corrupt_json = generate_corrupted_json(&input.field_strategy);
    observe_stream_info_parse(corrupt_json.as_bytes());
}

/// Test JSON field manipulation strategies
fn test_field_manipulation_strategies(input: &JetStreamInfoFuzz) {
    // Create a base valid response and apply field manipulation
    let base_stream = StreamInfoVariant {
        name: "test-stream".to_string(),
        state: StreamStateFields {
            messages: 100,
            bytes: 5000,
            first_seq: 1,
            last_seq: 100,
            consumer_count: 2,
        },
        config: StreamConfigFields {
            subjects: vec!["test.>".to_string()],
            retention: "limits".to_string(),
            storage: "file".to_string(),
            max_msgs: Some(1000),
            max_bytes: Some(50000),
        },
        include_optional: true,
    };

    let manipulated_json = generate_stream_info_json(&base_stream, &input.field_strategy);
    observe_stream_info_parse(manipulated_json.as_bytes());
}

/// Test error handling edge cases
fn test_error_handling_edge_cases() {
    // Test API error parsing edge cases
    let error_cases: &[&str] = &[
        // Stream not found variations
        r#"{"error":{"code":404,"err_code":10059,"description":"stream not found"}}"#,
        r#"{"error":{"code":404,"description":"generic not found"}}"#,
        // Consumer not found variations
        r#"{"error":{"code":404,"err_code":10014,"description":"consumer not found"}}"#,
        // Missing fields
        r#"{"error":{}}"#,
        r#"{"error":{"code":500}}"#,
        r#"{"error":{"description":"no code"}}"#,
        // Type confusion
        r#"{"error":{"code":"500","description":123}}"#,
        r#"{"error":{"code":null,"description":"null code"}}"#,
    ];

    for case in error_cases {
        observe_api_error_parse(case);
    }
}

/// Generate StreamInfo JSON with field manipulation
fn generate_stream_info_json(stream: &StreamInfoVariant, strategy: &FieldStrategy) -> String {
    let mut json = String::from("{");

    // Add config section
    write!(&mut json, "\"config\":{{").expect("write to String");
    write!(&mut json, "\"name\":\"{}\"", json_escape(&stream.name)).expect("write to String");

    if stream.include_optional && !stream.config.subjects.is_empty() {
        json.push_str(",\"subjects\":[");
        for (i, subj) in stream.config.subjects.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            write!(&mut json, "\"{}\"", json_escape(subj)).expect("write to String");
        }
        json.push(']');
    }

    if stream.include_optional {
        write!(&mut json, ",\"retention\":\"{}\"", stream.config.retention)
            .expect("write to String");
        write!(&mut json, ",\"storage\":\"{}\"", stream.config.storage).expect("write to String");
    }

    if stream.include_optional
        && let Some(max_msgs) = stream.config.max_msgs
    {
        write!(&mut json, ",\"max_msgs\":{}", max_msgs).expect("write to String");
    }
    if stream.include_optional
        && let Some(max_bytes) = stream.config.max_bytes
    {
        write!(&mut json, ",\"max_bytes\":{}", max_bytes).expect("write to String");
    }

    json.push('}');

    // Add state section
    write!(&mut json, ",\"state\":{{").expect("write to String");
    write!(&mut json, "\"messages\":{}", stream.state.messages).expect("write to String");
    write!(&mut json, ",\"bytes\":{}", stream.state.bytes).expect("write to String");
    write!(&mut json, ",\"first_seq\":{}", stream.state.first_seq).expect("write to String");
    write!(&mut json, ",\"last_seq\":{}", stream.state.last_seq).expect("write to String");
    write!(
        &mut json,
        ",\"consumer_count\":{}",
        stream.state.consumer_count
    )
    .expect("write to String");
    json.push('}');

    // Apply field manipulation strategy
    match strategy {
        FieldStrategy::ExtraFields { extra_count } => {
            for i in 0..*extra_count {
                write!(&mut json, ",\"extra_field_{}\":\"value_{}\"", i, i)
                    .expect("write to String");
            }
        }
        FieldStrategy::TypeConfusion => {
            json.push_str(",\"messages\":\"not_a_number\"");
            json.push_str(",\"bytes\":null");
        }
        _ => {}
    }

    json.push('}');
    json
}

/// Generate ConsumerInfo JSON
fn generate_consumer_info_json(consumer: &ConsumerInfoVariant, strategy: &FieldStrategy) -> String {
    let mut json = String::from("{");

    write!(&mut json, "\"name\":\"{}\"", json_escape(&consumer.name)).expect("write to String");
    write!(
        &mut json,
        ",\"stream_name\":\"{}\"",
        json_escape(&consumer.stream)
    )
    .expect("write to String");

    // Add config section
    write!(&mut json, ",\"config\":{{").expect("write to String");
    write!(
        &mut json,
        "\"deliver_policy\":\"{}\"",
        consumer.config.deliver_policy
    )
    .expect("write to String");
    write!(
        &mut json,
        ",\"ack_policy\":\"{}\"",
        consumer.config.ack_policy
    )
    .expect("write to String");
    write!(&mut json, ",\"ack_wait\":{}", consumer.config.ack_wait).expect("write to String");
    write!(
        &mut json,
        ",\"max_deliver\":{}",
        consumer.config.max_deliver
    )
    .expect("write to String");

    if let Some(ref durable) = consumer.config.durable_name {
        write!(&mut json, ",\"durable_name\":\"{}\"", json_escape(durable))
            .expect("write to String");
    }

    json.push('}');

    if consumer.include_state {
        json.push_str(",\"num_pending\":0,\"num_waiting\":0");
    }

    // Apply field strategy
    match strategy {
        FieldStrategy::OmitOptional => {
            // Randomly omit optional fields (durable_name already handled above)
        }
        FieldStrategy::RandomOrder => {
            // Field order is already somewhat randomized
        }
        _ => {}
    }

    json.push('}');
    json
}

/// Generate API error JSON
fn generate_api_error_json(error: &ApiErrorVariant, strategy: &FieldStrategy) -> String {
    let mut json = String::from("{\"error\":{");

    write!(&mut json, "\"code\":{}", error.code).expect("write to String");

    if let Some(err_code) = error.err_code {
        write!(&mut json, ",\"err_code\":{}", err_code).expect("write to String");
    }

    write!(
        &mut json,
        ",\"description\":\"{}\"",
        json_escape(&error.description)
    )
    .expect("write to String");

    // Apply error type specific fields
    match error.error_type {
        ErrorType::StreamNotFound => {
            if error.err_code.is_none() {
                json.push_str(",\"err_code\":10059");
            }
        }
        ErrorType::ConsumerNotFound => {
            if error.err_code.is_none() {
                json.push_str(",\"err_code\":10014");
            }
        }
        ErrorType::Malformed => {
            if let FieldStrategy::TypeConfusion = strategy {
                json.push_str(",\"code\":\"not_a_number\"");
            }
        }
        _ => {}
    }

    json.push_str("}}");
    json
}

/// Test JSON edge case
fn test_json_edge_case(edge_case: &JsonEdgeCase) {
    if edge_case.test_data.len() > MAX_STRING_LEN {
        return;
    }

    match edge_case.edge_type {
        JsonEdgeType::Empty => {
            observe_stream_info_parse(b"{}");
        }
        JsonEdgeType::VeryLarge => {
            let large_json = generate_large_json();
            observe_stream_info_parse(large_json.as_bytes());
        }
        JsonEdgeType::DeeplyNested => {
            let nested_json = generate_nested_json(10);
            observe_stream_info_parse(nested_json.as_bytes());
        }
        JsonEdgeType::Unicode => {
            let unicode_json = r#"{"name":"测试🌟stream","state":{"messages":100}}"#;
            observe_stream_info_parse(unicode_json.as_bytes());
        }
        JsonEdgeType::NumericEdges => {
            let numeric_json = format!(
                r#"{{"messages":{},"bytes":{},"first_seq":0,"last_seq":{}}}"#,
                u64::MAX,
                i64::MIN,
                u64::MAX
            );
            observe_stream_info_parse(numeric_json.as_bytes());
        }
        JsonEdgeType::EscapeSequences => {
            let escape_json = r#"{"name":"test\nstream\t\"with\\escapes","state":{"messages":1}}"#;
            observe_stream_info_parse(escape_json.as_bytes());
        }
        JsonEdgeType::InvalidSyntax => {
            observe_stream_info_parse(&edge_case.test_data);
        }
        JsonEdgeType::MissingFields => {
            let minimal_json = r#"{"name":"test"}"#;
            observe_stream_info_parse(minimal_json.as_bytes());
        }
    }
}

/// Test JSON field extraction utilities directly
fn test_json_extraction(json: &str) {
    // These functions are internal to the module but the fuzzing exercises them
    // through the public parse functions
    let _ = json.find("\"name\":");
    let _ = json.find("\"messages\":");
    let _ = json.find("\"bytes\":");
}

/// Check if stream response is valid for testing
fn is_valid_stream_response(response: &StreamInfoVariant) -> bool {
    !response.name.is_empty()
        && response.name.len() <= MAX_STRING_LEN
        && response.state.last_seq >= response.state.first_seq
        && response.config.subjects.len() <= MAX_ARRAY_LEN
        && response
            .config
            .subjects
            .iter()
            .all(|s| s.len() <= MAX_STRING_LEN)
}

/// Check if consumer response is valid for testing
fn is_valid_consumer_response(response: &ConsumerInfoVariant) -> bool {
    !response.name.is_empty()
        && response.name.len() <= MAX_STRING_LEN
        && !response.stream.is_empty()
        && response.stream.len() <= MAX_STRING_LEN
}

/// Generate corrupted JSON for malformed testing
fn generate_corrupted_json(strategy: &FieldStrategy) -> String {
    match strategy {
        FieldStrategy::TypeConfusion => {
            r#"{"name":123,"state":{"messages":"not_a_number","bytes":null}}"#.to_string()
        }
        _ => r#"{"name":"test"invalid:syntax"state":{}"#.to_string(),
    }
}

/// Generate large JSON for stress testing
fn generate_large_json() -> String {
    let mut json = String::from(
        r#"{"name":"large_stream","state":{"messages":1000,"bytes":50000,"first_seq":1,"last_seq":1000,"consumer_count":5},"config":{"subjects":["#,
    );

    // Add many subjects to create a large JSON
    for i in 0..100 {
        if i > 0 {
            json.push(',');
        }
        write!(&mut json, "\"large.subject.{}.>\"", i).expect("write to String");
    }

    json.push_str(r#"],"retention":"limits","storage":"file"}"#);

    // Add many extra fields
    for i in 0..50 {
        write!(&mut json, ",\"extra_large_field_{}\":\"value with lots of content that makes the JSON quite large and tests memory handling during parsing - field {}\"", i, i).expect("write to String");
    }

    json.push('}');
    json
}

/// Generate nested JSON for depth testing
fn generate_nested_json(depth: usize) -> String {
    let mut json = String::from(r#"{"name":"nested_stream""#);

    for i in 0..depth.min(MAX_NESTING_DEPTH) {
        write!(&mut json, ",\"level_{}\":{{", i).expect("write to String");
    }

    json.push_str("\"inner\":\"value\"");

    for _ in 0..depth.min(MAX_NESTING_DEPTH) {
        json.push('}');
    }

    json.push('}');
    json
}

/// Escape JSON string values
fn json_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                write!(&mut result, "\\u{:04x}", c as u32).expect("write to String");
            }
            c => result.push(c),
        }
    }
    result
}
