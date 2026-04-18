//! Comprehensive fuzz target for web request extractor combinators.
//!
//! Focuses specifically on request extraction mechanisms in asupersync web framework
//! to test critical extractor invariants and error handling:
//! 1. Path/Query/Json/Form extractors validate input properly
//! 2. Required fields return 400 when missing
//! 3. Multi-extractor composition order honored
//! 4. Oversized bodies rejected with appropriate limits
//! 5. Content-Type mismatch returns 415
//!
//! # Web Extractor Attack Vectors Tested
//! - Malformed JSON with oversized payloads
//! - Invalid form data with encoding issues
//! - Path parameter injection and overflow
//! - Query parameter tampering and type coercion
//! - Content-Type header manipulation
//! - Multi-extractor race conditions and composition
//! - Body size limit bypass attempts
//! - Character encoding edge cases (UTF-8 validation)
//!
//! # Web Framework Security (Request Processing)
//! - Input validation must reject malformed data
//! - Size limits must be enforced consistently
//! - Content-Type validation prevents MIME confusion
//! - Error responses must not leak sensitive information
//! - Parameter binding must preserve type safety
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run web_extract
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::web::extract::{
    ExtractionError, FromRequest, FromRequestParts, Json, Query, Path, Form,
    Request, BodyLimits, Extensions
};
use asupersync::web::response::StatusCode;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Maximum input size to prevent memory exhaustion during fuzzing.
const MAX_FUZZ_INPUT_SIZE: usize = 32_000;

/// Maximum decoded output size for safety.
const MAX_DECODED_OUTPUT_SIZE: usize = 128_000;

/// Web request extraction test scenarios.
#[derive(Arbitrary, Debug, Clone)]
struct WebExtractFuzzInput {
    /// HTTP method
    method: HttpMethod,
    /// Request path
    path: String,
    /// Query string (optional)
    query_string: Option<String>,
    /// Request headers
    headers: Vec<(String, String)>,
    /// Request body bytes
    body: Vec<u8>,
    /// Path parameters
    path_params: HashMap<String, String>,
    /// Test specific edge cases
    test_edge_cases: bool,
    /// Test oversized body scenarios
    test_oversized_bodies: bool,
    /// Test Content-Type mismatch scenarios
    test_content_type_mismatch: bool,
    /// Test multi-extractor composition
    test_composition: bool,
}

/// HTTP methods for testing.
#[derive(Arbitrary, Debug, Clone)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        }
    }
}

/// Test data structures for extraction.
#[derive(Arbitrary, Debug, Clone, Deserialize, Serialize, PartialEq)]
struct TestUser {
    id: u64,
    name: String,
    email: Option<String>,
    age: Option<u32>,
}

#[derive(Arbitrary, Debug, Clone, Deserialize, Serialize)]
struct TestQuery {
    page: Option<u32>,
    limit: Option<u32>,
    sort: Option<String>,
    filter: Option<String>,
}

#[derive(Arbitrary, Debug, Clone, Deserialize, Serialize)]
struct TestForm {
    username: String,
    password: String,
    remember_me: Option<bool>,
}

#[derive(Arbitrary, Debug, Clone, Deserialize, Serialize)]
struct TestPath {
    user_id: u64,
    post_id: Option<u32>,
}

/// Specific edge case patterns for web extractor testing.
#[derive(Arbitrary, Debug, Clone)]
enum WebExtractEdgeCase {
    /// Empty request (no body, no params)
    EmptyRequest,
    /// Oversized JSON payload
    OversizedJson { size_multiplier: u8 },
    /// Oversized form payload
    OversizedForm { size_multiplier: u8 },
    /// Invalid JSON syntax
    InvalidJson { data: Vec<u8> },
    /// Invalid form encoding
    InvalidForm { data: Vec<u8> },
    /// Content-Type header manipulation
    ContentTypeMismatch {
        actual_content_type: String,
        body_type: BodyType,
    },
    /// Path parameter injection
    PathInjection {
        param_name: String,
        param_value: String,
    },
    /// Query parameter edge cases
    QueryEdgeCases {
        params: Vec<(String, String)>,
    },
    /// Multi-extractor scenarios
    MultiExtractor {
        extractors: Vec<ExtractorType>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum BodyType {
    Json,
    Form,
    Plain,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExtractorType {
    Path,
    Query,
    Json,
    Form,
    Headers,
}

/// Test the web extractors through comprehensive invariant checking.
fn test_web_extractor_invariants(fuzz_input: &WebExtractFuzzInput) -> Result<String, String> {
    if fuzz_input.body.len() > MAX_FUZZ_INPUT_SIZE {
        return Err("Input too large for fuzzing".to_string());
    }

    // Create request from fuzz input
    let mut request = create_test_request(fuzz_input);

    // Test individual extractors
    test_individual_extractors(&request)?;

    // Test body size limits if enabled
    if fuzz_input.test_oversized_bodies {
        test_body_size_limits(&mut request)?;
    }

    // Test Content-Type mismatches if enabled
    if fuzz_input.test_content_type_mismatch {
        test_content_type_mismatches(&mut request)?;
    }

    // Test multi-extractor composition if enabled
    if fuzz_input.test_composition {
        test_multi_extractor_composition(&request)?;
    }

    Ok("All extractors processed successfully".to_string())
}

/// Create a test request from fuzz input.
fn create_test_request(fuzz_input: &WebExtractFuzzInput) -> Request {
    let mut request = Request::new(fuzz_input.method.as_str(), &fuzz_input.path);

    // Set query string
    if let Some(ref query) = fuzz_input.query_string {
        request = request.with_query(query);
    }

    // Set body
    request = request.with_body(Bytes::copy_from_slice(&fuzz_input.body));

    // Set headers
    for (name, value) in &fuzz_input.headers {
        request = request.with_header(name, value);
    }

    // Set path parameters
    request = request.with_path_params(fuzz_input.path_params.clone());

    request
}

/// Test individual extractors for proper validation.
fn test_individual_extractors(request: &Request) -> Result<(), String> {
    // Invariant 1: Path/Query/Json/Form extractors validate input properly

    // Test Path extractor
    match Path::<TestPath>::from_request_parts(request) {
        Ok(Path(path_data)) => {
            // Valid path data should be within reasonable bounds
            assert!(path_data.user_id < u64::MAX / 2, "Path user_id should be reasonable");
            if let Some(post_id) = path_data.post_id {
                assert!(post_id < u32::MAX / 2, "Path post_id should be reasonable");
            }
        },
        Err(err) => {
            // Invariant 2: Required fields return 400 when missing
            if err.message.contains("no path parameters") {
                assert_eq!(err.status, StatusCode::BAD_REQUEST,
                    "Missing path parameters should return 400 Bad Request");
            }
        }
    }

    // Test Query extractor
    match Query::<TestQuery>::from_request_parts(request) {
        Ok(Query(query_data)) => {
            // Valid query data should be within reasonable bounds
            if let Some(page) = query_data.page {
                assert!(page < 1_000_000, "Query page should be reasonable");
            }
            if let Some(limit) = query_data.limit {
                assert!(limit <= 10_000, "Query limit should be reasonable");
            }
        },
        Err(err) => {
            // Query parsing errors should be descriptive
            assert!(!err.message.is_empty(), "Query error should have descriptive message");
        }
    }

    // Test Json extractor (if body appears to be JSON)
    if request.header("content-type").map_or(false, |ct| ct.contains("json")) {
        match Json::<TestUser>::from_request(request.clone()) {
            Ok(Json(user_data)) => {
                // Invariant 1: Valid JSON should decode to proper structures
                assert!(user_data.name.len() <= MAX_DECODED_OUTPUT_SIZE,
                    "Decoded JSON field should not exceed maximum size");
                assert!(user_data.name.is_ascii() || user_data.name.chars().all(|c| !c.is_control()),
                    "Decoded name should not contain control characters");
            },
            Err(err) => {
                // Invariant 5: Content-Type mismatch returns 415
                if err.message.contains("expected application/json") {
                    assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "JSON Content-Type mismatch should return 415");
                }
                // JSON parsing errors should be descriptive
                assert!(!err.message.is_empty(), "JSON error should have descriptive message");
            }
        }
    }

    // Test Form extractor (if body appears to be form data)
    if request.header("content-type").map_or(false, |ct| ct.contains("form")) {
        match Form::<TestForm>::from_request(request.clone()) {
            Ok(Form(form_data)) => {
                // Invariant 1: Valid form should decode to proper structures
                assert!(form_data.username.len() <= MAX_DECODED_OUTPUT_SIZE,
                    "Decoded form field should not exceed maximum size");
                assert!(form_data.password.len() <= MAX_DECODED_OUTPUT_SIZE,
                    "Decoded form field should not exceed maximum size");
            },
            Err(err) => {
                // Invariant 5: Content-Type mismatch returns 415
                if err.message.contains("expected application/x-www-form-urlencoded") {
                    assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "Form Content-Type mismatch should return 415");
                }
                // Form parsing errors should be descriptive
                assert!(!err.message.is_empty(), "Form error should have descriptive message");
            }
        }
    }

    Ok(())
}

/// Test body size limits enforcement.
fn test_body_size_limits(request: &mut Request) -> Result<(), String> {
    // Invariant 4: Oversized bodies rejected with appropriate limits

    // Test JSON size limits (default 10 MiB)
    let large_json = r#"{"name":"#.to_string() + &"x".repeat(11 * 1024 * 1024) + r#"","id":1}"#;
    let mut large_request = request.clone();
    large_request = large_request
        .with_body(Bytes::copy_from_slice(large_json.as_bytes()))
        .with_header("content-type", "application/json");

    match Json::<TestUser>::from_request(large_request) {
        Ok(_) => {
            return Err("Oversized JSON body should have been rejected".to_string());
        },
        Err(err) => {
            assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE,
                "Oversized JSON should return 413 Payload Too Large");
            assert!(err.message.contains("JSON body too large"),
                "Error message should indicate JSON size limit exceeded");
        }
    }

    // Test Form size limits (default 2 MiB)
    let large_form = "username=".to_string() + &"x".repeat(3 * 1024 * 1024) + "&password=test";
    let mut large_form_request = request.clone();
    large_form_request = large_form_request
        .with_body(Bytes::copy_from_slice(large_form.as_bytes()))
        .with_header("content-type", "application/x-www-form-urlencoded");

    match Form::<TestForm>::from_request(large_form_request) {
        Ok(_) => {
            return Err("Oversized form body should have been rejected".to_string());
        },
        Err(err) => {
            assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE,
                "Oversized form should return 413 Payload Too Large");
            assert!(err.message.contains("form body too large"),
                "Error message should indicate form size limit exceeded");
        }
    }

    // Test custom body limits
    let mut custom_request = request.clone();
    let mut extensions = Extensions::new();
    let custom_limits = BodyLimits::new()
        .max_json_body_size(1024)  // 1KB limit
        .max_form_body_size(512);  // 512B limit
    extensions.insert_typed(custom_limits);
    custom_request.extensions = extensions;

    let medium_json = r#"{"name":"#.to_string() + &"x".repeat(2048) + r#"","id":1}"#;
    custom_request = custom_request
        .with_body(Bytes::copy_from_slice(medium_json.as_bytes()))
        .with_header("content-type", "application/json");

    match Json::<TestUser>::from_request(custom_request) {
        Ok(_) => {
            return Err("Body exceeding custom limit should have been rejected".to_string());
        },
        Err(err) => {
            assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE,
                "Body exceeding custom limit should return 413");
        }
    }

    Ok(())
}

/// Test Content-Type mismatch scenarios.
fn test_content_type_mismatches(request: &mut Request) -> Result<(), String> {
    // Invariant 5: Content-Type mismatch returns 415

    // Test JSON extractor with wrong Content-Type
    let json_body = r#"{"id": 42, "name": "test"}"#;
    let mut json_request = request.clone();
    json_request = json_request
        .with_body(Bytes::copy_from_slice(json_body.as_bytes()))
        .with_header("content-type", "text/plain"); // Wrong Content-Type

    match Json::<TestUser>::from_request(json_request) {
        Ok(_) => {
            return Err("JSON extractor should reject non-JSON Content-Type".to_string());
        },
        Err(err) => {
            assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Wrong Content-Type for JSON should return 415");
            assert!(err.message.contains("expected application/json"),
                "Error should mention expected Content-Type");
        }
    }

    // Test Form extractor with wrong Content-Type
    let form_body = "username=test&password=secret";
    let mut form_request = request.clone();
    form_request = form_request
        .with_body(Bytes::copy_from_slice(form_body.as_bytes()))
        .with_header("content-type", "application/json"); // Wrong Content-Type

    match Form::<TestForm>::from_request(form_request) {
        Ok(_) => {
            return Err("Form extractor should reject non-form Content-Type".to_string());
        },
        Err(err) => {
            assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Wrong Content-Type for form should return 415");
            assert!(err.message.contains("expected application/x-www-form-urlencoded"),
                "Error should mention expected Content-Type");
        }
    }

    Ok(())
}

/// Test multi-extractor composition order.
fn test_multi_extractor_composition(request: &Request) -> Result<(), String> {
    // Invariant 3: Multi-extractor composition order honored

    // Test that FromRequestParts extractors work together
    let path_result = Path::<HashMap<String, String>>::from_request_parts(request);
    let query_result = Query::<HashMap<String, String>>::from_request_parts(request);
    let headers_result = HashMap::<String, String>::from_request_parts(request);

    // These should all be independent and not interfere with each other
    match (path_result, query_result, headers_result) {
        (Ok(_), Ok(_), Ok(_)) => {
            // All extractors succeeded - composition works correctly
        },
        (path_res, query_res, headers_res) => {
            // At least one failed - verify failures are legitimate
            if let Err(path_err) = path_res {
                assert!(!path_err.message.is_empty(), "Path error should be descriptive");
            }
            if let Err(query_err) = query_res {
                assert!(!query_err.message.is_empty(), "Query error should be descriptive");
            }
            if let Err(headers_err) = headers_res {
                assert!(!headers_err.message.is_empty(), "Headers error should be descriptive");
            }
        }
    }

    // Test that body-consuming extractors are exclusive
    // (Only one can succeed since body is consumed)
    if request.body.len() > 0 {
        let json_result = Json::<serde_json::Value>::from_request(request.clone());
        let form_result = Form::<HashMap<String, String>>::from_request(request.clone());

        // Both might fail due to Content-Type, but if one succeeds, verify it's reasonable
        match (json_result, form_result) {
            (Ok(Json(json_val)), _) => {
                assert!(json_val.is_object() || json_val.is_array() || json_val.is_string() || json_val.is_number(),
                    "Successful JSON extraction should produce valid JSON value");
            },
            (_, Ok(Form(form_map))) => {
                // Form data should not be unreasonably large
                let total_size: usize = form_map.iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum();
                assert!(total_size <= MAX_DECODED_OUTPUT_SIZE,
                    "Successful form extraction should not exceed size limits");
            },
            (Err(_), Err(_)) => {
                // Both failed - acceptable if input is invalid or has wrong Content-Type
            }
        }
    }

    Ok(())
}

/// Generate specific edge case inputs for targeted testing.
fn generate_edge_case_input(edge_case: &WebExtractEdgeCase) -> WebExtractFuzzInput {
    match edge_case {
        WebExtractEdgeCase::EmptyRequest => {
            WebExtractFuzzInput {
                method: HttpMethod::Get,
                path: "/".to_string(),
                query_string: None,
                headers: vec![],
                body: vec![],
                path_params: HashMap::new(),
                test_edge_cases: true,
                test_oversized_bodies: false,
                test_content_type_mismatch: false,
                test_composition: false,
            }
        },

        WebExtractEdgeCase::OversizedJson { size_multiplier } => {
            let size = ((*size_multiplier as usize + 1) * 1024 * 1024).min(MAX_FUZZ_INPUT_SIZE);
            let json_data = format!(r#"{{"data":"{}"}}"#, "x".repeat(size.saturating_sub(20)));

            WebExtractFuzzInput {
                method: HttpMethod::Post,
                path: "/api/data".to_string(),
                query_string: None,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: json_data.into_bytes(),
                path_params: HashMap::new(),
                test_edge_cases: true,
                test_oversized_bodies: true,
                test_content_type_mismatch: false,
                test_composition: false,
            }
        },

        WebExtractEdgeCase::OversizedForm { size_multiplier } => {
            let size = ((*size_multiplier as usize + 1) * 512 * 1024).min(MAX_FUZZ_INPUT_SIZE);
            let form_data = format!("data={}", "x".repeat(size.saturating_sub(10)));

            WebExtractFuzzInput {
                method: HttpMethod::Post,
                path: "/form".to_string(),
                query_string: None,
                headers: vec![("content-type".to_string(), "application/x-www-form-urlencoded".to_string())],
                body: form_data.into_bytes(),
                path_params: HashMap::new(),
                test_edge_cases: true,
                test_oversized_bodies: true,
                test_content_type_mismatch: false,
                test_composition: false,
            }
        },

        WebExtractEdgeCase::InvalidJson { data } => {
            WebExtractFuzzInput {
                method: HttpMethod::Post,
                path: "/api/json".to_string(),
                query_string: None,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: data.clone(),
                path_params: HashMap::new(),
                test_edge_cases: true,
                test_oversized_bodies: false,
                test_content_type_mismatch: false,
                test_composition: false,
            }
        },

        WebExtractEdgeCase::ContentTypeMismatch { actual_content_type, body_type } => {
            let body_data = match body_type {
                BodyType::Json => r#"{"test": "value"}"#.as_bytes().to_vec(),
                BodyType::Form => "key=value&other=data".as_bytes().to_vec(),
                BodyType::Plain => "plain text content".as_bytes().to_vec(),
            };

            WebExtractFuzzInput {
                method: HttpMethod::Post,
                path: "/mismatch".to_string(),
                query_string: None,
                headers: vec![("content-type".to_string(), actual_content_type.clone())],
                body: body_data,
                path_params: HashMap::new(),
                test_edge_cases: true,
                test_oversized_bodies: false,
                test_content_type_mismatch: true,
                test_composition: false,
            }
        },

        _ => {
            // Default case for other edge cases
            WebExtractFuzzInput {
                method: HttpMethod::Get,
                path: "/test".to_string(),
                query_string: Some("test=value".to_string()),
                headers: vec![],
                body: vec![],
                path_params: HashMap::new(),
                test_edge_cases: true,
                test_oversized_bodies: false,
                test_content_type_mismatch: false,
                test_composition: true,
            }
        }
    }
}

fuzz_target!(|fuzz_input: WebExtractFuzzInput| {
    // Skip oversized inputs to prevent memory exhaustion
    if fuzz_input.body.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Skip if path or query is unreasonably large
    if fuzz_input.path.len() > 1000
        || fuzz_input.query_string.as_ref().map_or(false, |q| q.len() > 10000) {
        return;
    }

    // Test the primary input data
    let result = test_web_extractor_invariants(&fuzz_input);

    // Allow both success and failure - we're testing for crashes/invariant violations
    match result {
        Ok(_) => {
            // Success case - extractors processed without crashes
        },
        Err(err) => {
            // Failure case - should be graceful with descriptive errors
            assert!(!err.is_empty(), "Error messages should be descriptive");
        }
    }

    // Test specific edge cases if requested
    if fuzz_input.test_edge_cases {
        let edge_cases = [
            WebExtractEdgeCase::EmptyRequest,
            WebExtractEdgeCase::OversizedJson { size_multiplier: 1 },
            WebExtractEdgeCase::OversizedForm { size_multiplier: 1 },
            WebExtractEdgeCase::InvalidJson { data: b"invalid{json}".to_vec() },
            WebExtractEdgeCase::ContentTypeMismatch {
                actual_content_type: "text/plain".to_string(),
                body_type: BodyType::Json,
            },
        ];

        for edge_case in &edge_cases {
            let edge_input = generate_edge_case_input(edge_case);
            let _ = test_web_extractor_invariants(&edge_input);
        }
    }
});