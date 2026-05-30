//! HTTP content-encoding conformance tests against public compression helpers.
//!
//! These tests pin RFC 9110 content-coding token parsing, header extraction,
//! Accept-Encoding negotiation, and identity round-trip behavior without
//! relying on optional compression features.

use asupersync::http::compress::{
    ContentEncoding, Decompressor, IdentityDecompressor, accept_encoding_from_headers,
    content_encoding_from_headers, make_compressor, negotiate_encoding,
};

const BEAD_ID: &str = "asupersync-nax796";
const SUITE_ID: &str = "h1_content_encoding";

#[derive(Debug)]
struct EncodingCaseResult {
    scenario_id: &'static str,
    headers: &'static str,
    body_shape: &'static str,
    expected_status: &'static str,
    actual_status: String,
    verdict: &'static str,
    first_failure: String,
}

impl EncodingCaseResult {
    fn pass(
        scenario_id: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        expected_status: &'static str,
    ) -> Self {
        Self {
            scenario_id,
            headers,
            body_shape,
            expected_status,
            actual_status: expected_status.to_string(),
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn fail(
        scenario_id: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        expected_status: &'static str,
        actual_status: impl Into<String>,
        first_failure: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            headers,
            body_shape,
            expected_status,
            actual_status: actual_status.into(),
            verdict: "fail",
            first_failure: first_failure.into(),
        }
    }

    fn emit(&self) {
        println!(
            "bead_id={} suite_id={} scenario_id={} protocol_version=HTTP/1.1 method=RESPONSE headers={} body_shape={} connection_reused=n/a cookie_case=n/a expected_status={} actual_status={} expected_connection_state=n/a actual_connection_state=n/a verdict={} first_failure={}",
            BEAD_ID,
            SUITE_ID,
            self.scenario_id,
            self.headers,
            self.body_shape,
            self.expected_status,
            self.actual_status,
            self.verdict,
            self.first_failure
        );
    }

    fn assert_pass(self) {
        self.emit();
        assert_eq!(
            self.verdict, "pass",
            "HTTP content-encoding conformance failed: {self:?}"
        );
    }
}

#[test]
fn content_encoding_tokens_parse_case_insensitive_and_canonicalize() {
    let cases = [
        ("gzip", ContentEncoding::Gzip, "gzip"),
        ("x-gzip", ContentEncoding::Gzip, "gzip"),
        ("GZIP", ContentEncoding::Gzip, "gzip"),
        ("deflate", ContentEncoding::Deflate, "deflate"),
        ("br", ContentEncoding::Brotli, "br"),
        ("identity", ContentEncoding::Identity, "identity"),
    ];

    for (wire, expected, canonical) in cases {
        match ContentEncoding::from_token(wire) {
            Some(actual) if actual == expected && actual.as_token() == canonical => {
                EncodingCaseResult::pass(
                    "H1_CONTENT_ENCODING_TOKEN_PARSE",
                    "Content-Encoding",
                    canonical,
                    "parsed",
                )
                .assert_pass();
            }
            other => EncodingCaseResult::fail(
                "H1_CONTENT_ENCODING_TOKEN_PARSE",
                "Content-Encoding",
                canonical,
                "parsed",
                format!("{other:?}"),
                "content-coding token did not parse to the expected canonical encoding",
            )
            .assert_pass(),
        }
    }
}

#[test]
fn header_extractors_are_case_insensitive_and_reject_unknown_codings() {
    let content_headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("content-encoding".to_string(), "Br".to_string()),
    ];
    let accept_headers = vec![
        (
            "ACCEPT-ENCODING".to_string(),
            "gzip;q=1, br;q=0.8".to_string(),
        ),
        ("Content-Type".to_string(), "text/plain".to_string()),
    ];
    let unknown_headers = vec![("Content-Encoding".to_string(), "zstd".to_string())];

    let content = content_encoding_from_headers(&content_headers);
    let accept = accept_encoding_from_headers(&accept_headers);
    let unknown = content_encoding_from_headers(&unknown_headers);

    if content == Some(ContentEncoding::Brotli)
        && accept == Some("gzip;q=1, br;q=0.8")
        && unknown.is_none()
    {
        EncodingCaseResult::pass(
            "H1_CONTENT_ENCODING_HEADER_EXTRACT",
            "content-encoding+accept-encoding",
            "header_lookup",
            "extracted",
        )
        .assert_pass();
    } else {
        EncodingCaseResult::fail(
            "H1_CONTENT_ENCODING_HEADER_EXTRACT",
            "content-encoding+accept-encoding",
            "header_lookup",
            "extracted",
            format!("content={content:?} accept={accept:?} unknown={unknown:?}"),
            "header extraction was not case-insensitive or unknown content-coding was accepted",
        )
        .assert_pass();
    }
}

#[test]
fn accept_encoding_negotiation_honors_quality_identity_and_wildcards() {
    let supported = [
        ContentEncoding::Brotli,
        ContentEncoding::Gzip,
        ContentEncoding::Deflate,
        ContentEncoding::Identity,
    ];
    let cases = [
        (
            "absent_header_prefers_identity",
            None,
            Some(ContentEncoding::Identity),
        ),
        (
            "empty_header_identity_only",
            Some(""),
            Some(ContentEncoding::Identity),
        ),
        (
            "explicit_br_quality_wins",
            Some("br;q=1.0, gzip;q=0.8, identity;q=0.1"),
            Some(ContentEncoding::Brotli),
        ),
        (
            "identity_default_beats_low_wildcard",
            Some("*;q=0.5"),
            Some(ContentEncoding::Identity),
        ),
        (
            "identity_explicit_reject_allows_gzip",
            Some("identity;q=0, gzip;q=1.0"),
            Some(ContentEncoding::Gzip),
        ),
        (
            "wildcard_zero_rejects_implicit_identity",
            Some("*;q=0"),
            None,
        ),
    ];

    for (label, accept, expected) in cases {
        let actual = negotiate_encoding(accept, &supported);
        if actual == expected {
            EncodingCaseResult::pass(
                "H1_CONTENT_ENCODING_NEGOTIATE",
                label,
                "accept_encoding",
                "negotiated",
            )
            .assert_pass();
        } else {
            EncodingCaseResult::fail(
                "H1_CONTENT_ENCODING_NEGOTIATE",
                label,
                "accept_encoding",
                "negotiated",
                format!("{actual:?}"),
                format!("expected {expected:?} for Accept-Encoding {accept:?}"),
            )
            .assert_pass();
        }
    }
}

#[test]
fn unknown_accept_encoding_tokens_do_not_win_negotiation() {
    let supported_without_identity = [ContentEncoding::Gzip, ContentEncoding::Deflate];
    let supported_with_identity = [ContentEncoding::Gzip, ContentEncoding::Identity];

    let unknown_only = negotiate_encoding(Some("zstd;q=1.0"), &supported_without_identity);
    let unknown_with_gzip =
        negotiate_encoding(Some("zstd;q=1.0, gzip;q=1.0"), &supported_without_identity);
    let unknown_with_identity_default =
        negotiate_encoding(Some("zstd;q=1.0, gzip;q=0.5"), &supported_with_identity);

    if unknown_only.is_none()
        && unknown_with_gzip == Some(ContentEncoding::Gzip)
        && unknown_with_identity_default == Some(ContentEncoding::Identity)
    {
        EncodingCaseResult::pass(
            "H1_CONTENT_ENCODING_UNKNOWN_REJECT",
            "Accept-Encoding",
            "unknown_tokens",
            "ignored",
        )
        .assert_pass();
    } else {
        EncodingCaseResult::fail(
            "H1_CONTENT_ENCODING_UNKNOWN_REJECT",
            "Accept-Encoding",
            "unknown_tokens",
            "ignored",
            format!(
                "unknown_only={unknown_only:?} unknown_with_gzip={unknown_with_gzip:?} unknown_with_identity_default={unknown_with_identity_default:?}"
            ),
            "unknown content-coding won negotiation or identity default was not preserved",
        )
        .assert_pass();
    }
}

#[test]
fn identity_compressor_round_trips_bytes_without_feature_gate() {
    let input = b"identity content-coding must be a byte-for-byte pass-through";
    let Some(mut compressor) = make_compressor(ContentEncoding::Identity) else {
        EncodingCaseResult::fail(
            "H1_CONTENT_ENCODING_IDENTITY_ROUND_TRIP",
            "Content-Encoding=identity",
            "identity_payload",
            "round_trip",
            "compressor_unavailable",
            "identity compressor must always be available",
        )
        .assert_pass();
        return;
    };

    let mut compressed = Vec::new();
    let compress_result = compressor
        .compress(input, &mut compressed)
        .and_then(|()| compressor.finish(&mut compressed));
    let mut decompressed = Vec::new();
    let mut decompressor = IdentityDecompressor::new(None);
    let decompress_result = decompressor
        .decompress(&compressed, &mut decompressed)
        .and_then(|()| decompressor.finish(&mut decompressed));

    if compress_result.is_ok() && decompress_result.is_ok() && decompressed == input {
        EncodingCaseResult::pass(
            "H1_CONTENT_ENCODING_IDENTITY_ROUND_TRIP",
            "Content-Encoding=identity",
            "identity_payload",
            "round_trip",
        )
        .assert_pass();
    } else {
        EncodingCaseResult::fail(
            "H1_CONTENT_ENCODING_IDENTITY_ROUND_TRIP",
            "Content-Encoding=identity",
            "identity_payload",
            "round_trip",
            format!(
                "compress={compress_result:?} decompress={decompress_result:?} output_len={}",
                decompressed.len()
            ),
            "identity compression/decompression did not preserve the input bytes",
        )
        .assert_pass();
    }
}
