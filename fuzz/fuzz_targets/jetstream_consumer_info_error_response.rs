#![no_main]

use std::fmt::Write as _;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::jetstream::{JsError, fuzz_parse_api_error};

/// Structure-aware fuzz input for JetStream ConsumerInfo API error-response parsing
#[derive(Arbitrary, Debug)]
struct ConsumerInfoErrorFuzz {
    /// Error response scenarios specific to ConsumerInfo operations
    scenario: ConsumerInfoErrorScenario,
    /// JSON structure manipulation strategies
    structure_strategy: StructureStrategy,
    /// Error field variations
    error_field_variations: Vec<ErrorFieldVariation>,
}

#[derive(Arbitrary, Debug, Clone)]
enum ConsumerInfoErrorScenario {
    /// Consumer not found errors (10014)
    ConsumerNotFound {
        consumer_names: Vec<String>,
        stream_names: Vec<String>,
    },
    /// Stream not found errors (10059) when accessing consumer
    StreamNotFoundForConsumer { stream_names: Vec<String> },
    /// Invalid consumer configuration errors (10012)
    InvalidConsumerConfig { config_errors: Vec<String> },
    /// Consumer name already in use errors (10013)
    ConsumerNameInUse { existing_names: Vec<String> },
    /// Bad request errors for ConsumerInfo operations (10003)
    BadRequest { request_errors: Vec<String> },
    /// Authentication/authorization errors (10040)
    AuthErrors { auth_messages: Vec<String> },
    /// Mixed error scenarios with multiple error types
    MixedErrorTypes { errors: Vec<SpecificError> },
    /// Malformed error responses
    MalformedErrors {
        malformed_variants: Vec<MalformedErrorVariant>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct SpecificError {
    /// HTTP-style code (400, 404, 500, etc.)
    http_code: u32,
    /// JetStream error code (10014, 10059, etc.)
    err_code: Option<u32>,
    /// Error description
    description: String,
    /// Additional error context
    context: Option<String>,
}

#[derive(Arbitrary, Debug, Clone)]
enum MalformedErrorVariant {
    /// Missing required error fields
    MissingFields {
        include_code: bool,
        include_err_code: bool,
        include_description: bool,
    },
    /// Invalid JSON structure
    InvalidJson { corruption_type: JsonCorruption },
    /// Type confusion in error fields
    TypeConfusion {
        code_as_string: bool,
        err_code_as_string: bool,
        description_as_number: bool,
    },
    /// Edge case values
    EdgeCaseValues {
        use_negative_codes: bool,
        use_zero_codes: bool,
        use_max_values: bool,
        use_empty_description: bool,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum JsonCorruption {
    /// Truncated JSON
    Truncated { at_position: usize },
    /// Invalid escape sequences
    InvalidEscapes,
    /// Nested structure corruption
    NestedCorruption,
    /// Unicode corruption
    UnicodeCorruption,
    /// Oversized values
    OversizedValues,
}

#[derive(Arbitrary, Debug, Clone)]
enum StructureStrategy {
    /// Standard JetStream error format
    Standard,
    /// Nested error objects
    Nested { depth: u8 },
    /// Array of errors
    ErrorArray,
    /// Additional metadata fields
    ExtendedMetadata,
    /// Legacy error formats
    LegacyFormats,
}

#[derive(Arbitrary, Debug, Clone)]
struct ErrorFieldVariation {
    /// Field name variation
    field_name: String,
    /// Field value variation
    field_value: FieldValue,
}

#[derive(Arbitrary, Debug, Clone)]
enum FieldValue {
    String(String),
    Number(i64),
    Boolean(bool),
    Null,
    Object(String), // JSON object as string
    Array(Vec<String>),
}

// ConsumerInfo-specific JetStream error codes based on NATS documentation
const CONSUMER_NOT_FOUND: u32 = 10014;
const STREAM_NOT_FOUND: u32 = 10059;
const INVALID_CONSUMER_CONFIG: u32 = 10012;
const CONSUMER_NAME_ALREADY_IN_USE: u32 = 10013;
const BAD_REQUEST: u32 = 10003;
const AUTH_REQUIRED: u32 = 10040;
const AUTH_TIMEOUT: u32 = 10041;
const AUTH_REVOKED: u32 = 10042;

fn observe_api_error_parse(json: &str) -> JsError {
    let err = fuzz_parse_api_error(json);
    assert!(
        !err.to_string().is_empty(),
        "JetStream API error parser output should be observable"
    );
    err
}

fuzz_target!(|input: ConsumerInfoErrorFuzz| {
    // Limit array sizes to prevent excessive resource usage
    const MAX_NAMES: usize = 100;
    const MAX_ERRORS: usize = 50;
    const MAX_VARIATIONS: usize = 20;

    // Validate input sizes
    match &input.scenario {
        ConsumerInfoErrorScenario::ConsumerNotFound {
            consumer_names,
            stream_names,
        } => {
            if consumer_names.len() > MAX_NAMES || stream_names.len() > MAX_NAMES {
                return;
            }
        }
        ConsumerInfoErrorScenario::StreamNotFoundForConsumer { stream_names } => {
            if stream_names.len() > MAX_NAMES {
                return;
            }
        }
        ConsumerInfoErrorScenario::MixedErrorTypes { errors } => {
            if errors.len() > MAX_ERRORS {
                return;
            }
        }
        _ => {}
    }

    if input.error_field_variations.len() > MAX_VARIATIONS {
        return;
    }

    // Test main error parsing scenarios
    test_consumer_info_error_scenarios(&input);

    // Test API error parsing robustness
    test_api_error_parsing_robustness(&input);

    // Test error classification consistency
    test_error_classification_consistency(&input);

    // Test malformed error handling
    test_malformed_error_handling(&input);
});

fn test_consumer_info_error_scenarios(input: &ConsumerInfoErrorFuzz) {
    match &input.scenario {
        ConsumerInfoErrorScenario::ConsumerNotFound {
            consumer_names,
            stream_names,
        } => {
            for consumer in consumer_names.iter().take(10) {
                for stream in stream_names.iter().take(10) {
                    let json = build_consumer_not_found_error(consumer, stream);
                    test_error_parsing_invariants(&json);
                }
            }
        }

        ConsumerInfoErrorScenario::StreamNotFoundForConsumer { stream_names } => {
            for stream in stream_names.iter().take(10) {
                let json = build_stream_not_found_error(stream);
                test_error_parsing_invariants(&json);
            }
        }

        ConsumerInfoErrorScenario::InvalidConsumerConfig { config_errors } => {
            for error_msg in config_errors.iter().take(10) {
                let json = build_invalid_config_error(error_msg);
                test_error_parsing_invariants(&json);
            }
        }

        ConsumerInfoErrorScenario::ConsumerNameInUse { existing_names } => {
            for name in existing_names.iter().take(10) {
                let json = build_name_in_use_error(name);
                test_error_parsing_invariants(&json);
            }
        }

        ConsumerInfoErrorScenario::BadRequest { request_errors } => {
            for error_msg in request_errors.iter().take(10) {
                let json = build_bad_request_error(error_msg);
                test_error_parsing_invariants(&json);
            }
        }

        ConsumerInfoErrorScenario::AuthErrors { auth_messages } => {
            for msg in auth_messages.iter().take(10) {
                let json = build_auth_error(msg);
                test_error_parsing_invariants(&json);
            }
        }

        ConsumerInfoErrorScenario::MixedErrorTypes { errors } => {
            for error in errors.iter().take(10) {
                let json = build_custom_error(error);
                test_error_parsing_invariants(&json);
            }
        }

        ConsumerInfoErrorScenario::MalformedErrors { malformed_variants } => {
            for variant in malformed_variants.iter().take(10) {
                let json = build_malformed_error(variant, &input.structure_strategy);
                test_error_parsing_robustness(&json);
            }
        }
    }
}

fn test_error_parsing_invariants(json: &str) {
    // The parser should never panic on any error JSON
    let result = observe_api_error_parse(json);

    // All valid error JSONs should produce some kind of error
    match result {
        JsError::Api { code, description } => {
            // Valid API error - check basic invariants
            assert!(
                !description.is_empty() || code > 0,
                "Error should have code or description"
            );
        }
        JsError::StreamNotFound(_) => {
            // Should only be returned for err_code 10059
            assert!(
                json.contains("10059"),
                "StreamNotFound should only occur for err_code 10059"
            );
        }
        JsError::ConsumerNotFound { stream, consumer } => {
            // Check that consumer not found errors have proper structure
            assert!(
                !stream.is_empty() || !consumer.is_empty(),
                "ConsumerNotFound should have stream or consumer info"
            );
        }
        _ => {
            // Other error types are also valid
        }
    }
}

fn test_error_parsing_robustness(json: &str) {
    // Parser should handle malformed JSON gracefully without panicking
    observe_api_error_parse(json);
}

fn test_api_error_parsing_robustness(input: &ConsumerInfoErrorFuzz) {
    let baseline = build_bad_request_error("consumer info probe");
    test_error_parsing_robustness(&baseline);

    let auth_timeout = format!(
        r#"{{"error":{{"code":401,"err_code":{},"description":"authentication timeout"}}}}"#,
        AUTH_TIMEOUT
    );
    test_error_parsing_robustness(&auth_timeout);

    let auth_revoked = format!(
        r#"{{"error":{{"code":403,"err_code":{},"description":"authentication revoked"}}}}"#,
        AUTH_REVOKED
    );
    test_error_parsing_robustness(&auth_revoked);

    for variation in input.error_field_variations.iter().take(20) {
        let json = build_field_variation_error(variation);
        test_error_parsing_robustness(&json);
    }

    let structural_probe = match &input.structure_strategy {
        StructureStrategy::Standard => {
            r#"{"error":{"code":400,"err_code":10003,"description":"standard"}}"#.to_string()
        }
        StructureStrategy::Nested { depth } => {
            let depth = (*depth).min(8);
            let mut json = r#"{"error":{"code":400,"description":"nested""#.to_string();
            for level in 0..depth {
                let _ = write!(&mut json, r#","level{}":{{"#, level);
            }
            for _ in 0..depth {
                json.push('}');
            }
            json.push_str("}}");
            json
        }
        StructureStrategy::ErrorArray => {
            r#"{"errors":[{"code":404,"err_code":10014,"description":"consumer not found"}]}"#
                .to_string()
        }
        StructureStrategy::ExtendedMetadata => {
            r#"{"error":{"code":400,"err_code":10003,"description":"bad request"},"metadata":{"operation":"consumer_info"}}"#
                .to_string()
        }
        StructureStrategy::LegacyFormats => r#"{"code":404,"message":"legacy not found"}"#.to_string(),
    };
    test_error_parsing_robustness(&structural_probe);
}

fn test_error_classification_consistency(input: &ConsumerInfoErrorFuzz) {
    // Test that the same error JSON produces consistent results
    if let ConsumerInfoErrorScenario::ConsumerNotFound {
        consumer_names,
        stream_names,
    } = &input.scenario
        && let (Some(consumer), Some(stream)) = (consumer_names.first(), stream_names.first())
    {
        let json = build_consumer_not_found_error(consumer, stream);

        let result1 = observe_api_error_parse(&json);
        let result2 = observe_api_error_parse(&json);

        // Results should be consistent (same error type)
        assert_eq!(
            std::mem::discriminant(&result1),
            std::mem::discriminant(&result2),
            "Same JSON should produce same error type"
        );
    }
}

fn test_malformed_error_handling(_input: &ConsumerInfoErrorFuzz) {
    // Test with various malformed JSON structures
    let malformed_jsons = vec![
        r#"{"error":{"#,                                             // Truncated
        r#"{"error":{"code":"not_a_number","description":"test"}}"#, // Type error
        r#"{"error":null}"#,                                         // Null error
        r#"{"error":[]}"#,                                           // Array instead of object
        r#"{}"#,                                                     // Missing error field
        "",                                                          // Empty string
        r#"not json at all"#,                                        // Invalid JSON
    ];

    for malformed in malformed_jsons {
        observe_api_error_parse(malformed);
    }
}

// Helper functions to build specific error JSON formats

fn build_consumer_not_found_error(consumer: &str, stream: &str) -> String {
    format!(
        r#"{{"error":{{"code":404,"err_code":{},"description":"consumer '{}' not found in stream '{}'"}}}}"#,
        CONSUMER_NOT_FOUND, consumer, stream
    )
}

fn build_stream_not_found_error(stream: &str) -> String {
    format!(
        r#"{{"error":{{"code":404,"err_code":{},"description":"stream '{}' not found"}}}}"#,
        STREAM_NOT_FOUND, stream
    )
}

fn build_invalid_config_error(msg: &str) -> String {
    format!(
        r#"{{"error":{{"code":400,"err_code":{},"description":"invalid consumer configuration: {}"}}}}"#,
        INVALID_CONSUMER_CONFIG, msg
    )
}

fn build_name_in_use_error(name: &str) -> String {
    format!(
        r#"{{"error":{{"code":400,"err_code":{},"description":"consumer name '{}' already in use"}}}}"#,
        CONSUMER_NAME_ALREADY_IN_USE, name
    )
}

fn build_bad_request_error(msg: &str) -> String {
    format!(
        r#"{{"error":{{"code":400,"err_code":{},"description":"bad request: {}"}}}}"#,
        BAD_REQUEST, msg
    )
}

fn build_auth_error(msg: &str) -> String {
    format!(
        r#"{{"error":{{"code":401,"err_code":{},"description":"authentication required: {}"}}}}"#,
        AUTH_REQUIRED, msg
    )
}

fn build_custom_error(error: &SpecificError) -> String {
    let context = error
        .context
        .as_ref()
        .map(|context| format!(r#","context":"{}""#, context))
        .unwrap_or_default();

    match error.err_code {
        Some(err_code) => format!(
            r#"{{"error":{{"code":{},"err_code":{},"description":"{}"{}}}}}"#,
            error.http_code, err_code, error.description, context
        ),
        None => format!(
            r#"{{"error":{{"code":{},"description":"{}"{}}}}}"#,
            error.http_code, error.description, context
        ),
    }
}

fn build_field_variation_error(variation: &ErrorFieldVariation) -> String {
    format!(
        r#"{{"error":{{"code":400,"description":"field variation","{}":{}}}}}"#,
        variation.field_name,
        render_field_value(&variation.field_value)
    )
}

fn render_field_value(value: &FieldValue) -> String {
    match value {
        FieldValue::String(value) => format!(r#""{}""#, value),
        FieldValue::Number(value) => value.to_string(),
        FieldValue::Boolean(value) => value.to_string(),
        FieldValue::Null => "null".to_string(),
        FieldValue::Object(value) => value.to_string(),
        FieldValue::Array(values) => {
            let mut rendered = String::from("[");
            for (index, value) in values.iter().take(8).enumerate() {
                if index > 0 {
                    rendered.push(',');
                }
                rendered.push('"');
                rendered.push_str(value);
                rendered.push('"');
            }
            rendered.push(']');
            rendered
        }
    }
}

fn build_malformed_error(variant: &MalformedErrorVariant, _strategy: &StructureStrategy) -> String {
    match variant {
        MalformedErrorVariant::MissingFields {
            include_code,
            include_err_code,
            include_description,
        } => {
            let mut parts = vec![];
            if *include_code {
                parts.push(r#""code":404"#);
            }
            if *include_err_code {
                parts.push(r#""err_code":10014"#);
            }
            if *include_description {
                parts.push(r#""description":"test error""#);
            }
            format!(r#"{{"error":{{{}}}}}"#, parts.join(","))
        }

        MalformedErrorVariant::TypeConfusion {
            code_as_string,
            err_code_as_string,
            description_as_number,
        } => {
            let code = if *code_as_string {
                r#""code":"404""#
            } else {
                r#""code":404"#
            };
            let err_code = if *err_code_as_string {
                r#""err_code":"10014""#
            } else {
                r#""err_code":10014"#
            };
            let description = if *description_as_number {
                r#""description":12345"#
            } else {
                r#""description":"test""#
            };
            format!(r#"{{"error":{{{},{},{}}}}}"#, code, err_code, description)
        }

        MalformedErrorVariant::EdgeCaseValues {
            use_negative_codes,
            use_zero_codes,
            use_max_values,
            use_empty_description,
        } => {
            let code = if *use_negative_codes {
                -404
            } else if *use_zero_codes {
                0
            } else if *use_max_values {
                i64::from(u32::MAX)
            } else {
                404
            };

            let description = if *use_empty_description { "" } else { "test" };

            format!(
                r#"{{"error":{{"code":{},"description":"{}"}}}}"#,
                code, description
            )
        }

        MalformedErrorVariant::InvalidJson { corruption_type } => match corruption_type {
            JsonCorruption::Truncated { at_position } => {
                let full = r#"{"error":{"code":404,"description":"test"}}"#;
                let pos = (*at_position).min(full.len());
                match full.get(..pos) {
                    Some(prefix) => prefix.to_string(),
                    None => String::new(),
                }
            }
            JsonCorruption::InvalidEscapes => {
                r#"{"error":{"code":404,"description":"test\invalid"}}"#.to_string()
            }
            JsonCorruption::NestedCorruption => {
                r#"{"error":{"code":404,"nested":{"invalid"}}}"#.to_string()
            }
            JsonCorruption::UnicodeCorruption => {
                r#"{"error":{"code":404,"description":"test\uXXXX"}}"#.to_string()
            }
            JsonCorruption::OversizedValues => {
                format!(
                    r#"{{"error":{{"code":404,"description":"{}"}}}}"#,
                    "x".repeat(10000)
                )
            }
        },
    }
}
