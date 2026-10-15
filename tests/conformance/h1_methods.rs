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
