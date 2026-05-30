//! HTTP/1.1 body framing conformance tests against the live H1 codec.
//!
//! These tests pin RFC 9112 body-length precedence and no-body response
//! behavior using the production request decoder and response encoder. The
//! older metamorphic draft is preserved below as disabled archaeology until it
//! can be refactored into smaller live suites.

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder};
use asupersync::http::h1::Request;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::http::h1::types::Response;

const BEAD_ID: &str = "asupersync-nax796";
const SUITE_ID: &str = "h1_body_framing";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedConnectionState {
    Complete,
    Incomplete,
    Error,
    NoBody,
}

impl ExpectedConnectionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Error => "error",
            Self::NoBody => "no_body",
        }
    }
}

#[derive(Debug)]
struct FramingCaseResult {
    scenario_id: &'static str,
    method: &'static str,
    headers: &'static str,
    body_shape: &'static str,
    expected_status: &'static str,
    actual_status: String,
    expected_connection_state: ExpectedConnectionState,
    actual_connection_state: String,
    verdict: &'static str,
    first_failure: String,
}

impl FramingCaseResult {
    fn pass(
        scenario_id: &'static str,
        method: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        expected_status: &'static str,
        expected_connection_state: ExpectedConnectionState,
    ) -> Self {
        Self {
            scenario_id,
            method,
            headers,
            body_shape,
            expected_status,
            actual_status: expected_status.to_string(),
            expected_connection_state,
            actual_connection_state: expected_connection_state.as_str().to_string(),
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn fail(
        scenario_id: &'static str,
        method: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        expected_status: &'static str,
        actual_status: impl Into<String>,
        expected_connection_state: ExpectedConnectionState,
        actual_connection_state: impl Into<String>,
        first_failure: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            method,
            headers,
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
            "bead_id={} suite_id={} scenario_id={} protocol_version=HTTP/1.1 method={} headers={} body_shape={} connection_reused=n/a cookie_case=n/a expected_status={} actual_status={} expected_connection_state={} actual_connection_state={} verdict={} first_failure={}",
            BEAD_ID,
            SUITE_ID,
            self.scenario_id,
            self.method,
            self.headers,
            self.body_shape,
            self.expected_status,
            self.actual_status,
            self.expected_connection_state.as_str(),
            self.actual_connection_state,
            self.verdict,
            self.first_failure
        );
    }

    fn assert_pass(self) {
        self.emit();
        assert_eq!(
            self.verdict, "pass",
            "HTTP/1 body framing conformance failed: {self:?}"
        );
    }
}

fn decode_request(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(raw);
    codec.decode(&mut src)
}

fn decode_request_with_remainder(raw: &[u8]) -> Result<(Option<Request>, Vec<u8>), HttpError> {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(raw);
    let decoded = codec.decode(&mut src)?;
    Ok((decoded, src.to_vec()))
}

fn encode_response(response: Response) -> Result<Vec<u8>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut dst = BytesMut::new();
    codec.encode(response, &mut dst)?;
    Ok(dst.to_vec())
}

#[test]
fn transfer_encoding_and_content_length_are_rejected() {
    let scenario = "H1_BODY_TE_CL_REJECTS";
    let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    match decode_request(raw) {
        Err(HttpError::AmbiguousBodyLength) => FramingCaseResult::pass(
            scenario,
            "POST",
            "transfer-encoding+content-length",
            "chunked_body",
            "AmbiguousBodyLength",
            ExpectedConnectionState::Error,
        )
        .assert_pass(),
        other => FramingCaseResult::fail(
            scenario,
            "POST",
            "transfer-encoding+content-length",
            "chunked_body",
            "AmbiguousBodyLength",
            format!("{other:?}"),
            ExpectedConnectionState::Error,
            "not_rejected",
            "TE+CL request was not rejected as ambiguous body length",
        )
        .assert_pass(),
    }
}

#[test]
fn content_length_exact_body_is_decoded() {
    let scenario = "H1_BODY_CONTENT_LENGTH_EXACT";
    let raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";

    match decode_request(raw) {
        Ok(Some(request)) if request.body == b"hello" => FramingCaseResult::pass(
            scenario,
            "POST",
            "content-length",
            "exact_length",
            "decoded",
            ExpectedConnectionState::Complete,
        )
        .assert_pass(),
        other => FramingCaseResult::fail(
            scenario,
            "POST",
            "content-length",
            "exact_length",
            "decoded",
            format!("{other:?}"),
            ExpectedConnectionState::Complete,
            "wrong_body",
            "Content-Length body did not decode to exact bytes",
        )
        .assert_pass(),
    }
}

#[test]
fn content_length_short_body_is_incomplete() {
    let scenario = "H1_BODY_CONTENT_LENGTH_INCOMPLETE";
    let raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nhello";

    match decode_request(raw) {
        Ok(None) => FramingCaseResult::pass(
            scenario,
            "POST",
            "content-length",
            "short_body",
            "incomplete",
            ExpectedConnectionState::Incomplete,
        )
        .assert_pass(),
        other => FramingCaseResult::fail(
            scenario,
            "POST",
            "content-length",
            "short_body",
            "incomplete",
            format!("{other:?}"),
            ExpectedConnectionState::Incomplete,
            "not_incomplete",
            "short Content-Length body should wait for more bytes",
        )
        .assert_pass(),
    }
}

#[test]
fn absent_body_headers_decode_empty_request_body() {
    let scenario = "H1_BODY_ABSENT_HEADERS_EMPTY";
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nnext-bytes";

    match decode_request_with_remainder(raw) {
        Ok((Some(request), remainder)) if request.body.is_empty() && remainder == b"next-bytes" => {
            FramingCaseResult::pass(
                scenario,
                "GET",
                "none",
                "implicit_empty",
                "decoded",
                ExpectedConnectionState::Complete,
            )
            .assert_pass();
        }
        other => FramingCaseResult::fail(
            scenario,
            "GET",
            "none",
            "implicit_empty",
            "decoded",
            format!("{other:?}"),
            ExpectedConnectionState::Complete,
            "body_or_remainder_mismatch",
            "request without body headers must decode an empty body and leave following bytes",
        )
        .assert_pass(),
    }
}

#[test]
fn transfer_encoding_chunked_must_be_only_supported_coding() {
    let scenario = "H1_BODY_TRANSFER_ENCODING_ORDER";
    let valid = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let invalid_order =
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
    let unsupported_stack =
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";

    let valid_ok = matches!(decode_request(valid), Ok(Some(request)) if request.body == b"hello");
    let invalid_order_rejected = matches!(
        decode_request(invalid_order),
        Err(HttpError::BadTransferEncoding)
    );
    let unsupported_stack_rejected = matches!(
        decode_request(unsupported_stack),
        Err(HttpError::BadTransferEncoding)
    );

    if valid_ok && invalid_order_rejected && unsupported_stack_rejected {
        FramingCaseResult::pass(
            scenario,
            "POST",
            "transfer-encoding",
            "chunked_only",
            "decoded_or_rejected",
            ExpectedConnectionState::Complete,
        )
        .assert_pass();
    } else {
        FramingCaseResult::fail(
            scenario,
            "POST",
            "transfer-encoding",
            "chunked_only",
            "decoded_or_rejected",
            format!(
                "valid_ok={valid_ok} invalid_order_rejected={invalid_order_rejected} unsupported_stack_rejected={unsupported_stack_rejected}"
            ),
            ExpectedConnectionState::Complete,
            "transfer_encoding_contract_mismatch",
            "chunked-only request was not accepted or unsupported transfer coding stack was not rejected",
        )
        .assert_pass();
    }
}

#[test]
fn response_status_without_body_suppresses_payload() {
    let scenario = "H1_BODY_NO_BODY_RESPONSE_SUPPRESSES_PAYLOAD";
    let response = Response::new(204, "No Content", b"must-not-appear".to_vec());

    match encode_response(response) {
        Ok(encoded)
            if !encoded
                .windows(b"must-not-appear".len())
                .any(|w| w == b"must-not-appear") =>
        {
            FramingCaseResult::pass(
                scenario,
                "RESPONSE",
                "status=204",
                "forbidden_payload",
                "encoded_without_body",
                ExpectedConnectionState::NoBody,
            )
            .assert_pass();
        }
        other => FramingCaseResult::fail(
            scenario,
            "RESPONSE",
            "status=204",
            "forbidden_payload",
            "encoded_without_body",
            format!("{other:?}"),
            ExpectedConnectionState::NoBody,
            "payload_encoded",
            "204 response must not encode a payload body",
        )
        .assert_pass(),
    }
}

#[test]
fn response_transfer_encoding_and_content_length_are_rejected() {
    let scenario = "H1_BODY_RESPONSE_TE_CL_REJECTS";
    let response = Response::new(200, "OK", b"test".to_vec())
        .with_header("Transfer-Encoding", "chunked")
        .with_header("Content-Length", "4");

    match encode_response(response) {
        Err(HttpError::AmbiguousBodyLength) => FramingCaseResult::pass(
            scenario,
            "RESPONSE",
            "transfer-encoding+content-length",
            "fixed_body",
            "AmbiguousBodyLength",
            ExpectedConnectionState::Error,
        )
        .assert_pass(),
        other => FramingCaseResult::fail(
            scenario,
            "RESPONSE",
            "transfer-encoding+content-length",
            "fixed_body",
            "AmbiguousBodyLength",
            format!("{other:?}"),
            ExpectedConnectionState::Error,
            "not_rejected",
            "response TE+CL was not rejected as ambiguous body length",
        )
        .assert_pass(),
    }
}
