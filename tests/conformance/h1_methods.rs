//! HTTP/1.1 method-token conformance tests against the live H1 codec.
//!
//! These tests pin RFC 9110 method token grammar, case sensitivity, standard
//! method recognition, extension-method preservation, and request-line
//! rejection behavior using the production method parser and request decoder.

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::http::h1::types::{Method, Request};

const BEAD_ID: &str = "asupersync-nax796";
const SUITE_ID: &str = "h1_methods";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodSemantics {
    SafeIdempotent,
    UnsafeIdempotent,
    UnsafeNonIdempotent,
}

impl MethodSemantics {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SafeIdempotent => "safe_idempotent",
            Self::UnsafeIdempotent => "unsafe_idempotent",
            Self::UnsafeNonIdempotent => "unsafe_non_idempotent",
        }
    }
}

fn semantics_for(method: &Method) -> MethodSemantics {
    match method {
        Method::Get | Method::Head | Method::Options | Method::Trace => {
            MethodSemantics::SafeIdempotent
        }
        Method::Put | Method::Delete => MethodSemantics::UnsafeIdempotent,
        Method::Post | Method::Connect | Method::Patch | Method::Extension(_) => {
            MethodSemantics::UnsafeNonIdempotent
        }
    }
}

#[derive(Debug)]
struct MethodCaseResult {
    scenario_id: &'static str,
    method: String,
    body_shape: &'static str,
    expected_status: &'static str,
    actual_status: String,
    expected_connection_state: &'static str,
    actual_connection_state: String,
    verdict: &'static str,
    first_failure: String,
}

impl MethodCaseResult {
    fn pass(
        scenario_id: &'static str,
        method: impl Into<String>,
        body_shape: &'static str,
        expected_status: &'static str,
        expected_connection_state: &'static str,
    ) -> Self {
        Self {
            scenario_id,
            method: method.into(),
            body_shape,
            expected_status,
            actual_status: expected_status.to_string(),
            expected_connection_state,
            actual_connection_state: expected_connection_state.to_string(),
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn fail(
        scenario_id: &'static str,
        method: impl Into<String>,
        body_shape: &'static str,
        expected_status: &'static str,
        actual_status: impl Into<String>,
        expected_connection_state: &'static str,
        actual_connection_state: impl Into<String>,
        first_failure: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            method: method.into(),
            body_shape,
            expected_status,
            actual_status: actual_status.into(),
            expected_connection_state,
            actual_connection_state: actual_connection_state.into(),
            verdict: "fail",
            first_failure: first_failure.into(),
        }
    }

    fn emit(&self) {
        println!(
            "bead_id={} suite_id={} scenario_id={} protocol_version=HTTP/1.1 method={} headers=n/a body_shape={} connection_reused=n/a cookie_case=n/a expected_status={} actual_status={} expected_connection_state={} actual_connection_state={} verdict={} first_failure={}",
            BEAD_ID,
            SUITE_ID,
            self.scenario_id,
            self.method,
            self.body_shape,
            self.expected_status,
            self.actual_status,
            self.expected_connection_state,
            self.actual_connection_state,
            self.verdict,
            self.first_failure
        );
    }

    fn assert_pass(self) {
        self.emit();
        assert_eq!(
            self.verdict, "pass",
            "HTTP/1 method conformance failed: {self:?}"
        );
    }
}

fn decode_request(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(raw);
    codec.decode(&mut src)
}

#[test]
fn standard_method_tokens_parse_exactly_with_rfc_semantics() {
    let cases = [
        ("GET", MethodSemantics::SafeIdempotent),
        ("HEAD", MethodSemantics::SafeIdempotent),
        ("OPTIONS", MethodSemantics::SafeIdempotent),
        ("TRACE", MethodSemantics::SafeIdempotent),
        ("PUT", MethodSemantics::UnsafeIdempotent),
        ("DELETE", MethodSemantics::UnsafeIdempotent),
        ("POST", MethodSemantics::UnsafeNonIdempotent),
        ("CONNECT", MethodSemantics::UnsafeNonIdempotent),
        ("PATCH", MethodSemantics::UnsafeNonIdempotent),
    ];

    for (wire, expected_semantics) in cases {
        match Method::from_bytes(wire.as_bytes()) {
            Some(method)
                if method.as_str() == wire && semantics_for(&method) == expected_semantics =>
            {
                MethodCaseResult::pass(
                    "H1_METHOD_STANDARD_PARSE",
                    wire,
                    expected_semantics.as_str(),
                    "parsed",
                    "complete",
                )
                .assert_pass();
            }
            other => MethodCaseResult::fail(
                "H1_METHOD_STANDARD_PARSE",
                wire,
                expected_semantics.as_str(),
                "parsed",
                format!("{other:?}"),
                "complete",
                "method_mismatch",
                "standard method did not parse to the expected case-sensitive variant",
            )
            .assert_pass(),
        }
    }
}

#[test]
fn extension_method_tokens_preserve_case_sensitive_wire_form() {
    let cases = [
        "PURGE",
        "M-SEARCH",
        "get",
        "Custom_Method",
        "FOO!#$%&'*+-.^_`|~09AZaz",
    ];

    for wire in cases {
        match Method::from_bytes(wire.as_bytes()) {
            Some(Method::Extension(name)) if name == wire => MethodCaseResult::pass(
                "H1_METHOD_EXTENSION_PARSE",
                wire,
                "extension_token",
                "parsed",
                "complete",
            )
            .assert_pass(),
            other => MethodCaseResult::fail(
                "H1_METHOD_EXTENSION_PARSE",
                wire,
                "extension_token",
                "parsed",
                format!("{other:?}"),
                "complete",
                "extension_mismatch",
                "extension method token was not preserved exactly",
            )
            .assert_pass(),
        }
    }
}

#[test]
fn invalid_method_tokens_are_rejected_by_method_parser() {
    let cases: &[(&str, &[u8])] = &[
        ("empty", b""),
        ("space", b"GE T"),
        ("slash", b"GET/POST"),
        ("tab", b"GET\t"),
        ("cr", b"GET\r"),
        ("lf", b"GET\n"),
        ("non_utf8", b"\xff"),
    ];

    for (label, bytes) in cases {
        match Method::from_bytes(bytes) {
            None => MethodCaseResult::pass(
                "H1_METHOD_INVALID_TOKEN_REJECT",
                *label,
                "invalid_token",
                "BadMethod",
                "error",
            )
            .assert_pass(),
            other => MethodCaseResult::fail(
                "H1_METHOD_INVALID_TOKEN_REJECT",
                *label,
                "invalid_token",
                "BadMethod",
                format!("{other:?}"),
                "error",
                "parsed",
                "invalid method token parsed successfully",
            )
            .assert_pass(),
        }
    }
}

#[test]
fn request_decoder_accepts_standard_and_extension_methods() {
    let cases = [
        (
            "POST",
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n".as_slice(),
            Method::Post,
        ),
        (
            "PURGE",
            b"PURGE /cache HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            Method::Extension("PURGE".to_string()),
        ),
    ];

    for (wire, raw, expected) in cases {
        match decode_request(raw) {
            Ok(Some(request)) if request.method == expected => MethodCaseResult::pass(
                "H1_METHOD_DECODER_ACCEPT",
                wire,
                "request_line",
                "decoded",
                "complete",
            )
            .assert_pass(),
            other => MethodCaseResult::fail(
                "H1_METHOD_DECODER_ACCEPT",
                wire,
                "request_line",
                "decoded",
                format!("{other:?}"),
                "complete",
                "decode_mismatch",
                "request decoder did not preserve the expected method",
            )
            .assert_pass(),
        }
    }
}

#[test]
fn request_decoder_rejects_invalid_method_tokens() {
    let cases = [
        ("slash", b"GET/POST / HTTP/1.1\r\n\r\n".as_slice()),
        ("tab", b"GET\t / HTTP/1.1\r\n\r\n".as_slice()),
        ("non_utf8", b"\xff / HTTP/1.1\r\n\r\n".as_slice()),
    ];

    for (label, raw) in cases {
        match decode_request(raw) {
            Err(HttpError::BadMethod) => MethodCaseResult::pass(
                "H1_METHOD_DECODER_REJECT",
                label,
                "invalid_request_line",
                "BadMethod",
                "error",
            )
            .assert_pass(),
            other => MethodCaseResult::fail(
                "H1_METHOD_DECODER_REJECT",
                label,
                "invalid_request_line",
                "BadMethod",
                format!("{other:?}"),
                "error",
                "not_bad_method",
                "request decoder did not reject invalid method with BadMethod",
            )
            .assert_pass(),
        }
    }
}

#[rustfmt::skip]
#[cfg(any())]
mod stale_h1_methods_suite {
    #![allow(warnings)]
    #![allow(clippy::all)]
//! HTTP/1.1 Method Conformance Tests per RFC 9110 Section 9.1
//!
//! This module provides comprehensive conformance testing for HTTP/1.1 method
//! semantics, parsing, and classification per RFC 9110 Section 9.1. These tests
//! validate method safety and idempotency properties, token grammar compliance,
//! and proper handling of both standard and extension methods.
//!
//! # RFC 9110 Section 9.1 Requirements Tested
//!
//! 1. **Method Token Grammar**: All methods must follow token grammar rules
//! 2. **Safe Methods**: GET, HEAD, OPTIONS, TRACE are safe (read-only semantics)
//! 3. **Idempotent Methods**: GET, HEAD, OPTIONS, TRACE, PUT, DELETE are idempotent
//! 4. **Unsafe Methods**: POST, CONNECT are neither safe nor idempotent
//! 5. **Extension Methods**: Custom methods parsed according to token grammar
//!
//! # Metamorphic Relations
//!
//! These tests use metamorphic testing to verify that method classification
//! and parsing maintain consistency across different input transformations:
//!
//! - **MR1**: Method safety/idempotency flags are correctly classified
//! - **MR2**: Safe+idempotent methods (GET/HEAD/OPTIONS/TRACE) preserve read-only semantics
//! - **MR3**: Idempotent-only methods (PUT/DELETE) allow state modification but are repeatable
//! - **MR4**: Unsafe methods (POST/CONNECT) have no semantic guarantees
//! - **MR5**: Extension methods follow token grammar and parse consistently

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

use asupersync::http::h1::types::Method;

/// Classification of HTTP method semantic properties per RFC 9110
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MethodProperties {
    /// Method has safe semantics (read-only, no side effects)
    pub is_safe: bool,
    /// Method is idempotent (repeated calls have same effect)
    pub is_idempotent: bool,
    /// Method allows request body
    pub allows_body: bool,
    /// Method allows response body
    pub allows_response_body: bool,
}

#[allow(dead_code)]

impl MethodProperties {
    /// Get the standard properties for a method per RFC 9110
    #[must_use]
    #[allow(dead_code)]
    pub fn for_method(method: &Method) -> Self {
        match method {
            // Safe and idempotent methods (RFC 9110 Section 9.2.1 and 9.2.2)
            Method::Get => Self {
                is_safe: true,
                is_idempotent: true,
                allows_body: false,
                allows_response_body: true,
            },
            Method::Head => Self {
                is_safe: true,
                is_idempotent: true,
                allows_body: false,
                allows_response_body: false, // HEAD returns headers only
            },
            Method::Options => Self {
                is_safe: true,
                is_idempotent: true,
                allows_body: false,
                allows_response_body: true,
            },
            Method::Trace => Self {
                is_safe: true,
                is_idempotent: true,
                allows_body: false,
                allows_response_body: true,
            },

            // Idempotent but not safe methods
            Method::Put => Self {
                is_safe: false,
                is_idempotent: true,
                allows_body: true,
                allows_response_body: true,
            },
            Method::Delete => Self {
                is_safe: false,
                is_idempotent: true,
                allows_body: false,
                allows_response_body: true,
            },

            // Neither safe nor idempotent methods
            Method::Post => Self {
                is_safe: false,
                is_idempotent: false,
                allows_body: true,
                allows_response_body: true,
            },
            Method::Connect => Self {
                is_safe: false,
                is_idempotent: false,
                allows_body: false,
                allows_response_body: false, // CONNECT establishes tunnel
            },

            // PATCH is not idempotent (RFC 5789)
            Method::Patch => Self {
                is_safe: false,
                is_idempotent: false,
                allows_body: true,
                allows_response_body: true,
            },

            // Extension methods: conservative defaults
            Method::Extension(_) => Self {
                is_safe: false,
                is_idempotent: false,
                allows_body: true,
                allows_response_body: true,
            },
        }
    }

    /// Check if this method is safe (read-only semantics)
    #[must_use]
    pub const fn is_safe(self) -> bool {
        self.is_safe
    }

    /// Check if this method is idempotent (repeatable)
    #[must_use]
    pub const fn is_idempotent(self) -> bool {
        self.is_idempotent
    }
}

/// Test result for method conformance verification
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MethodTestResult {
    pub test_id: String,
    pub description: String,
    pub passed: bool,
    pub error_message: Option<String>,
    pub method_parsed: bool,
}

#[allow(dead_code)]

impl MethodTestResult {
    #[allow(dead_code)]
    fn pass(test_id: &str, description: &str, method_parsed: bool) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            passed: true,
            error_message: None,
            method_parsed,
        }
    }

    #[allow(dead_code)]

    fn fail(test_id: &str, description: &str, error: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            passed: false,
            error_message: Some(error.to_string()),
            method_parsed: false,
        }
    }
}

/// Validate that a string follows HTTP token grammar per RFC 9110 Section 5.6.2
#[allow(dead_code)]
fn is_valid_http_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            matches!(
                b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
                | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            )
        })
}

/// Generate arbitrary valid HTTP method tokens
#[allow(dead_code)]
fn arb_valid_method_token() -> impl Strategy<Value = String> {
    prop::string::string_regex("[!#$%&'*+\\-.^_`|~0-9A-Za-z]+")
        .unwrap()
        .prop_filter("non-empty and valid token", |s| {
            !s.is_empty() && is_valid_http_token(s)
        })
}

/// Generate arbitrary invalid method strings (for negative testing)
#[allow(dead_code)]
fn arb_invalid_method_token() -> impl Strategy<Value = String> {
    prop_oneof![
        // Empty string
        Just(String::new()),
        // Contains invalid characters
        prop::string::string_regex(".*[ ()<>@,;:\\\"/\\[\\]?={}]+.*").unwrap(),
        // Contains control characters
        prop::string::string_regex(".*[\x00-\x1F\x7F]+.*").unwrap(),
    ]
}

// =============================================================================
// MR1: Safe/Idempotent Method Flags Correct
// =============================================================================

proptest! {
    /// MR1: Method properties are correctly classified per RFC 9110
    #[test]
    #[allow(dead_code)]
    fn mr1_method_properties_classified_correctly(
        method_name in prop_oneof![
            Just("GET".to_string()),
            Just("HEAD".to_string()),
            Just("POST".to_string()),
            Just("PUT".to_string()),
            Just("DELETE".to_string()),
            Just("CONNECT".to_string()),
            Just("OPTIONS".to_string()),
            Just("TRACE".to_string()),
            Just("PATCH".to_string()),
        ]
    ) {
        let method = Method::from_bytes(method_name.as_bytes())
            .expect("Standard method should parse");

        let props = MethodProperties::for_method(&method);

        // Verify RFC 9110 classifications
        match &method {
            Method::Get | Method::Head | Method::Options | Method::Trace => {
                prop_assert!(props.is_safe, "Method {} should be safe", method_name);
                prop_assert!(props.is_idempotent, "Method {} should be idempotent", method_name);
            }
            Method::Put | Method::Delete => {
                prop_assert!(!props.is_safe, "Method {} should not be safe", method_name);
                prop_assert!(props.is_idempotent, "Method {} should be idempotent", method_name);
            }
            Method::Post | Method::Connect | Method::Patch => {
                prop_assert!(!props.is_safe, "Method {} should not be safe", method_name);
                prop_assert!(!props.is_idempotent, "Method {} should not be idempotent", method_name);
            }
            Method::Extension(_) => {
                // Extension methods default to unsafe and non-idempotent
                prop_assert!(!props.is_safe, "Extension method should default to unsafe");
                prop_assert!(!props.is_idempotent, "Extension method should default to non-idempotent");
            }
        }
    }
}

// =============================================================================
// MR2: GET/HEAD/OPTIONS/TRACE Safe+Idempotent
// =============================================================================

proptest! {
    /// MR2: Safe methods maintain read-only semantics and idempotency
    #[test]
    #[allow(dead_code)]
    fn mr2_safe_methods_are_safe_and_idempotent(
        safe_method_name in prop_oneof![
            Just("GET"),
            Just("HEAD"),
            Just("OPTIONS"),
            Just("TRACE"),
        ]
    ) {
        let method = Method::from_bytes(safe_method_name.as_bytes())
            .expect("Safe method should parse");

        let props = MethodProperties::for_method(&method);

        // Safe methods MUST be both safe and idempotent
        prop_assert!(props.is_safe, "Method {} must be safe", safe_method_name);
        prop_assert!(props.is_idempotent, "Method {} must be idempotent", safe_method_name);

        // Safe methods should not modify state
        prop_assert!(
            matches!(method, Method::Get | Method::Head | Method::Options | Method::Trace),
            "Method {} must be a recognized safe method", safe_method_name
        );

        // Verify consistency: safe implies read-only semantics
        match method {
            Method::Head => {
                prop_assert!(!props.allows_response_body, "HEAD must not allow response body");
            }
            Method::Get | Method::Options | Method::Trace => {
                prop_assert!(props.allows_response_body, "Safe method {} should allow response body", safe_method_name);
            }
            _ => unreachable!(),
        }
    }
}

// =============================================================================
// MR3: PUT/DELETE Idempotent but Not Safe
// =============================================================================

proptest! {
    /// MR3: PUT and DELETE are idempotent but not safe (allow state modification)
    #[test]
    #[allow(dead_code)]
    fn mr3_put_delete_idempotent_not_safe(
        idempotent_method_name in prop_oneof![
            Just("PUT"),
            Just("DELETE"),
        ]
    ) {
        let method = Method::from_bytes(idempotent_method_name.as_bytes())
            .expect("Idempotent method should parse");

        let props = MethodProperties::for_method(&method);

        // PUT and DELETE MUST be idempotent but not safe
        prop_assert!(!props.is_safe, "Method {} must not be safe", idempotent_method_name);
        prop_assert!(props.is_idempotent, "Method {} must be idempotent", idempotent_method_name);

        // Verify specific semantics
        match method {
            Method::Put => {
                prop_assert!(props.allows_body, "PUT must allow request body");
                prop_assert!(props.allows_response_body, "PUT must allow response body");
            }
            Method::Delete => {
                prop_assert!(!props.allows_body, "DELETE typically does not allow request body");
                prop_assert!(props.allows_response_body, "DELETE must allow response body");
            }
            _ => unreachable!(),
        }
    }
}

// =============================================================================
// MR4: POST/CONNECT Not Safe nor Idempotent
// =============================================================================

proptest! {
    /// MR4: POST and CONNECT have no safety or idempotency guarantees
    #[test]
    #[allow(dead_code)]
    fn mr4_post_connect_unsafe_and_non_idempotent(
        unsafe_method_name in prop_oneof![
            Just("POST"),
            Just("CONNECT"),
            Just("PATCH"), // PATCH is also unsafe and non-idempotent
        ]
    ) {
        let method = Method::from_bytes(unsafe_method_name.as_bytes())
            .expect("Unsafe method should parse");

        let props = MethodProperties::for_method(&method);

        // These methods MUST be neither safe nor idempotent
        prop_assert!(!props.is_safe, "Method {} must not be safe", unsafe_method_name);
        prop_assert!(!props.is_idempotent, "Method {} must not be idempotent", unsafe_method_name);

        // Verify specific semantics
        match method {
            Method::Post => {
                prop_assert!(props.allows_body, "POST must allow request body");
                prop_assert!(props.allows_response_body, "POST must allow response body");
            }
            Method::Connect => {
                prop_assert!(!props.allows_body, "CONNECT typically does not allow request body");
                prop_assert!(!props.allows_response_body, "CONNECT establishes tunnel, no response body");
            }
            Method::Patch => {
                prop_assert!(props.allows_body, "PATCH must allow request body");
                prop_assert!(props.allows_response_body, "PATCH must allow response body");
            }
            _ => unreachable!(),
        }
    }
}

// =============================================================================
// MR5: Custom Methods Parsed Per Token Grammar
// =============================================================================

proptest! {
    /// MR5: Extension methods follow token grammar and parse consistently
    #[test]
    #[allow(dead_code)]
    fn mr5_extension_methods_follow_token_grammar(
        valid_token in arb_valid_method_token(),
    ) {
        // Valid tokens should parse as extension methods
        let method = Method::from_bytes(valid_token.as_bytes());

        match method {
            Some(Method::Extension(ext_name)) => {
                prop_assert_eq!(&ext_name, &valid_token, "Extension method name should match input");
                prop_assert!(is_valid_http_token(&ext_name), "Extension method should be valid token");

                // Extension methods have conservative defaults
                let props = MethodProperties::for_method(&method.unwrap());
                prop_assert!(!props.is_safe, "Extension methods default to unsafe");
                prop_assert!(!props.is_idempotent, "Extension methods default to non-idempotent");
            }
            Some(standard_method) => {
                // If it parsed as a standard method, verify it's actually standard
                prop_assert!(
                    matches!(standard_method,
                        Method::Get | Method::Head | Method::Post | Method::Put |
                        Method::Delete | Method::Connect | Method::Options | Method::Trace | Method::Patch
                    ),
                    "Standard method recognition should be consistent"
                );
            }
            None => {
                // Should only fail for invalid tokens
                prop_assert!(!is_valid_http_token(&valid_token),
                    "Valid token {} should parse successfully", valid_token);
            }
        }
    }
}

proptest! {
    /// MR5b: Invalid method strings are rejected per token grammar
    #[test]
    #[allow(dead_code)]
    fn mr5b_invalid_methods_rejected(
        invalid_token in arb_invalid_method_token(),
    ) {
        let method = Method::from_bytes(invalid_token.as_bytes());

        if !is_valid_http_token(&invalid_token) {
            prop_assert!(method.is_none(),
                "Invalid token '{}' should not parse as method", invalid_token);
        } else {
            // If it's actually valid, it should parse
            prop_assert!(method.is_some(),
                "Valid token '{}' should parse successfully", invalid_token);
        }
    }
}

// =============================================================================
// Integration Tests Combining All MRs
// =============================================================================

proptest! {
    /// Integration test: Method parsing and classification consistency
    #[test]
    #[allow(dead_code)]
    fn integration_method_parsing_classification_consistency(
        method_bytes in prop_oneof![
            // Standard methods
            Just(b"GET".to_vec()),
            Just(b"HEAD".to_vec()),
            Just(b"POST".to_vec()),
            Just(b"PUT".to_vec()),
            Just(b"DELETE".to_vec()),
            Just(b"CONNECT".to_vec()),
            Just(b"OPTIONS".to_vec()),
            Just(b"TRACE".to_vec()),
            Just(b"PATCH".to_vec()),
            // Valid extension methods
            arb_valid_method_token().prop_map(|s| s.into_bytes()),
            // Invalid methods (should be rejected)
            arb_invalid_method_token().prop_map(|s| s.into_bytes()),
        ]
    ) {
        let method_result = Method::from_bytes(&method_bytes);
        let method_string = String::from_utf8_lossy(&method_bytes);

        match method_result {
            Some(method) => {
                // If method parsed, verify its properties are consistent
                let props = MethodProperties::for_method(&method);

                // Round-trip consistency: method.as_str() should match original for standard methods
                match &method {
                    Method::Extension(name) => {
                        prop_assert_eq!(name, &method_string, "Extension method round-trip consistency");
                        prop_assert!(is_valid_http_token(name), "Extension method must be valid token");
                    }
                    standard => {
                        let standard_name = standard.as_str();
                        prop_assert_eq!(standard_name, method_string, "Standard method round-trip consistency");
                    }
                }

                // Properties consistency
                match method {
                    Method::Get | Method::Head | Method::Options | Method::Trace => {
                        prop_assert!(props.is_safe && props.is_idempotent,
                            "Safe methods must be safe and idempotent");
                    }
                    Method::Put | Method::Delete => {
                        prop_assert!(!props.is_safe && props.is_idempotent,
                            "PUT/DELETE must be idempotent but not safe");
                    }
                    Method::Post | Method::Connect | Method::Patch => {
                        prop_assert!(!props.is_safe && !props.is_idempotent,
                            "POST/CONNECT/PATCH must be neither safe nor idempotent");
                    }
                    Method::Extension(_) => {
                        prop_assert!(!props.is_safe && !props.is_idempotent,
                            "Extension methods default to unsafe and non-idempotent");
                    }
                }
            }
            None => {
                // If method didn't parse, it should be an invalid token
                prop_assert!(!is_valid_http_token(&method_string),
                    "Failed to parse method '{}' should be invalid token", method_string);
            }
        }
    }
}

// =============================================================================
// Unit Tests for Specific Conformance Requirements
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_standard_method_properties() {
        // Test all standard methods have correct properties
        let test_cases = vec![
            ("GET", true, true),
            ("HEAD", true, true),
            ("OPTIONS", true, true),
            ("TRACE", true, true),
            ("PUT", false, true),
            ("DELETE", false, true),
            ("POST", false, false),
            ("CONNECT", false, false),
            ("PATCH", false, false),
        ];

        for (method_name, expected_safe, expected_idempotent) in test_cases {
            let method = Method::from_bytes(method_name.as_bytes())
                .unwrap_or_else(|| panic!("Method {method_name} should parse"));
            let props = MethodProperties::for_method(&method);

            assert_eq!(
                props.is_safe, expected_safe,
                "Method {} safety classification incorrect", method_name
            );
            assert_eq!(
                props.is_idempotent, expected_idempotent,
                "Method {} idempotency classification incorrect", method_name
            );
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_token_grammar_validation() {
        // Valid tokens
        let valid_tokens = vec![
            "CUSTOM",
            "PATCH",
            "BREW", // RFC 2324 HTCPCP
            "PROPFIND", // WebDAV
            "GET-METADATA",
            "X-CUSTOM-METHOD",
            "test123",
        ];

        for token in valid_tokens {
            assert!(is_valid_http_token(token), "Token '{}' should be valid", token);
            let method = Method::from_bytes(token.as_bytes());
            assert!(method.is_some(), "Valid token '{}' should parse", token);
        }

        // Invalid tokens
        let invalid_tokens = vec![
            "",           // Empty
            "GET POST",   // Space
            "GET\r\n",    // CRLF
            "GET()",      // Parentheses
            "GET<>",      // Angle brackets
            "GET@",       // At sign
            "GET,",       // Comma
            "GET;",       // Semicolon
            "GET:",       // Colon
            "GET\\",      // Backslash
            "GET\"",      // Quote
            "GET/",       // Slash
            "GET[]",      // Brackets
            "GET?",       // Question mark
            "GET=",       // Equals
            "GET{}",      // Braces
            "GET\x00",    // Null
            "GET\x1F",    // Control character
        ];

        for token in invalid_tokens {
            assert!(!is_valid_http_token(token), "Token '{}' should be invalid", token);
            let method = Method::from_bytes(token.as_bytes());
            assert!(method.is_none(), "Invalid token '{}' should not parse", token);
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_method_round_trip_consistency() {
        let methods = vec![
            Method::Get,
            Method::Head,
            Method::Post,
            Method::Put,
            Method::Delete,
            Method::Connect,
            Method::Options,
            Method::Trace,
            Method::Patch,
            Method::Extension("CUSTOM".to_string()),
        ];

        for method in methods {
            let method_str = method.as_str();
            let parsed = Method::from_bytes(method_str.as_bytes())
                .unwrap_or_else(|| panic!("Method {method_str} should round-trip"));

            match (&method, &parsed) {
                (Method::Extension(a), Method::Extension(b)) => {
                    assert_eq!(a, b, "Extension method should round-trip exactly");
                }
                _ => {
                    assert_eq!(method, parsed, "Standard method should round-trip exactly");
                }
            }
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_method_case_sensitivity() {
        // Methods are case-sensitive per RFC 9110
        let case_variants = vec![
            ("GET", Some("GET")),
            ("get", None), // Should not parse
            ("Get", None), // Should not parse
            ("HEAD", Some("HEAD")),
            ("head", None),
            ("POST", Some("POST")),
            ("post", None),
        ];

        for (input, expected) in case_variants {
            let method = Method::from_bytes(input.as_bytes());
            match expected {
                Some(expected_str) => {
                    let parsed =
                        method.unwrap_or_else(|| panic!("Method {input} should parse"));
                    assert_eq!(parsed.as_str(), expected_str);
                }
                None => {
                    assert!(method.is_none(), "Method {} should not parse", input);
                }
            }
        }
    }
}

}
