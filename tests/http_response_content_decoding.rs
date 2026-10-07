//! Client-facing content decoding is explicit, bounded, and transactional.

use asupersync::http::compress::DecompressionLimit;
use asupersync::http::{Method, Response};

fn assert_unchanged(actual: &Response, before: &Response) {
    assert_eq!(actual.version, before.version);
    assert_eq!(actual.status, before.status);
    assert_eq!(actual.reason, before.reason);
    assert_eq!(actual.headers, before.headers);
    assert_eq!(actual.body, before.body);
    assert_eq!(actual.trailers, before.trailers);
}

#[cfg(feature = "compression")]
fn encode(input: &[u8], coding: asupersync::http::compress::ContentEncoding) -> Vec<u8> {
    let mut encoder = asupersync::http::compress::make_compressor(coding).unwrap();
    let mut wire = Vec::new();
    encoder.compress(input, &mut wire).unwrap();
    encoder.finish(&mut wire).unwrap();
    wire
}

#[test]
fn unencoded_and_identity_bodies_are_bounded_without_mutation() {
    for encoding in [None, Some("identity")] {
        let mut response = Response::new(200, "OK", b"payload".to_vec());
        if let Some(encoding) = encoding {
            response = response.with_header("Content-Encoding", encoding);
        }
        let before = response.clone();
        response
            .decode_content(&Method::Get, DecompressionLimit::new(7))
            .unwrap();
        assert_unchanged(&response, &before);
        assert!(response
            .decode_content(&Method::Get, DecompressionLimit::new(6))
            .is_err());
        assert_unchanged(&response, &before);
    }
}

#[test]
fn bodyless_responses_preserve_representation_headers() {
    for (method, status) in [
        (Method::Head, 200),
        (Method::Connect, 200),
        (Method::Connect, 201),
        (Method::Get, 100),
        (Method::Get, 204),
        (Method::Get, 205),
        (Method::Get, 304),
    ] {
        let mut response = Response::new(status, "", Vec::new())
            .with_header("Content-Encoding", "gzip")
            .with_header("Content-Length", "1234");
        let before = response.clone();
        response
            .decode_content(&method, DecompressionLimit::new(0))
            .unwrap();
        assert_unchanged(&response, &before);
    }
}

#[test]
fn invalid_unknown_and_excessive_codings_leave_response_unchanged() {
    for coding in [
        "",
        " , \t , ",
        "future-coding",
        "gzip, future-coding",
        "gzip;q=1",
        "gzip\r\n",
        "identity,identity,identity,identity,identity,identity,identity,identity,identity",
    ] {
        let mut response = Response::new(200, "OK", b"wire".to_vec())
            .with_header("Content-Encoding", coding)
            .with_header("Content-Length", "4");
        let before = response.clone();
        assert!(response
            .decode_content(&Method::Get, DecompressionLimit::new(1024))
            .is_err(), "accepted coding {coding:?}");
        assert_unchanged(&response, &before);
    }
}

#[test]
fn empty_list_members_do_not_count_as_extra_coding_layers() {
    let mut response = Response::new(200, "OK", b"x".to_vec())
        .with_header("Content-Encoding", " , identity, ,\t");
    let before = response.clone();
    response
        .decode_content(&Method::Get, DecompressionLimit::new(1))
        .unwrap();
    assert_unchanged(&response, &before);
}

#[test]
fn encoded_partial_responses_are_not_reinterpreted() {
    for status in [200, 206] {
        let mut response = Response::new(status, "", b"partial".to_vec())
            .with_header("Content-Encoding", "deflate");
        if status == 200 {
            response = response.with_header("Content-Range", "bytes 0-6/100");
        }
        let before = response.clone();
        let error = response
            .decode_content(&Method::Get, DecompressionLimit::new(1024))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_unchanged(&response, &before);
    }
}

#[cfg(not(feature = "compression"))]
#[test]
fn unavailable_codecs_are_explicit_errors_in_default_builds() {
    for coding in ["gzip", "deflate", "br"] {
        let mut response = Response::new(200, "OK", b"wire".to_vec())
            .with_header("Content-Encoding", coding);
        let before = response.clone();
        let error = response
            .decode_content(&Method::Get, DecompressionLimit::new(1024))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_unchanged(&response, &before);
    }
}

#[cfg(feature = "compression")]
#[test]
fn every_supported_codec_reaches_the_json_response_api() {
    use asupersync::http::compress::ContentEncoding;
    let plain = br#"{"answer":42,"ready":true}"#;
    for coding in [ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Brotli] {
        let wire = encode(plain, coding);
        let mut response = Response::new(200, "OK", wire.clone())
            .with_header("Content-Encoding", coding.as_token())
            .with_header("Content-Length", wire.len().to_string())
            .with_header("Content-Type", "application/json")
            .with_header("ETag", "origin-validator");
        response
            .decode_content(&Method::Get, DecompressionLimit::new(plain.len()))
            .unwrap();
        assert_eq!(response.body, plain);
        let value: serde_json::Value = response.json().unwrap();
        assert_eq!(value["answer"], 42);
        assert_eq!(value["ready"], true);
        assert!(!response.headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("content-encoding")
                || name.eq_ignore_ascii_case("content-length")
        }));
        assert!(response.headers.iter().any(|(name, value)| {
            name == "ETag" && value == "origin-validator"
        }));
        let before = response.clone();
        response
            .decode_content(&Method::Get, DecompressionLimit::new(plain.len()))
            .unwrap();
        assert_unchanged(&response, &before);
    }
}

#[cfg(feature = "compression")]
#[test]
fn repeated_headers_and_coding_lists_decode_in_reverse_order() {
    use asupersync::http::compress::ContentEncoding;
    let plain = b"first gzip, then deflate";
    let inner = encode(plain, ContentEncoding::Gzip);
    let wire = encode(&inner, ContentEncoding::Deflate);
    for repeated in [false, true] {
        let mut response = Response::new(200, "OK", wire.clone());
        response = if repeated {
            response
                .with_header("CONTENT-ENCODING", "x-gzip")
                .with_header("content-encoding", "DEFLATE")
        } else {
            response.with_header("Content-Encoding", " gzip, identity, deflate ")
        };
        response
            .decode_content(&Method::Get, DecompressionLimit::new(1024))
            .unwrap();
        assert_eq!(response.body, plain);
    }
}

#[cfg(feature = "compression")]
#[test]
fn inner_layer_failure_does_not_publish_successfully_decoded_outer_layer() {
    use asupersync::http::compress::ContentEncoding;
    let mut inner = encode(b"protected payload", ContentEncoding::Deflate);
    *inner.last_mut().unwrap() ^= 1;
    let wire = encode(&inner, ContentEncoding::Gzip);
    let mut response = Response::new(200, "OK", wire)
        .with_header("Content-Encoding", "deflate, gzip")
        .with_header("Digest", "original-digest");
    let before = response.clone();
    assert!(response
        .decode_content(&Method::Get, DecompressionLimit::new(1024))
        .is_err());
    assert_unchanged(&response, &before);
}

#[cfg(feature = "compression")]
#[test]
fn intermediate_and_final_expansions_both_obey_the_limit() {
    use asupersync::http::compress::ContentEncoding;
    for (plain, limit) in [(vec![b'a'; 4096], 128), (vec![b'a'], 1)] {
        let inner = encode(&plain, ContentEncoding::Gzip);
        let wire = encode(&inner, ContentEncoding::Deflate);
        let mut response = Response::new(200, "OK", wire)
            .with_header("Content-Encoding", "gzip, deflate");
        let before = response.clone();
        assert!(response
            .decode_content(&Method::Get, DecompressionLimit::new(limit))
            .is_err());
        assert_unchanged(&response, &before);
    }
}

#[cfg(feature = "compression")]
#[test]
fn decoding_removes_stale_payload_digests_in_headers_and_trailers() {
    use asupersync::http::compress::ContentEncoding;
    let wire = encode(b"payload", ContentEncoding::Deflate);
    let mut response = Response::new(200, "OK", wire)
        .with_header("Content-Encoding", "deflate")
        .with_header("content-encoding", "identity")
        .with_header("Content-MD5", "old")
        .with_header("Content-Digest", "old")
        .with_header("Repr-Digest", "old")
        .with_trailer("Digest", "old")
        .with_trailer("Content-Digest", "old")
        .with_trailer("X-Trace-ID", "keep");
    response
        .decode_content(&Method::Get, DecompressionLimit::new(1024))
        .unwrap();
    assert!(response.headers.is_empty());
    assert_eq!(response.trailers, vec![("X-Trace-ID".to_string(), "keep".to_string())]);
}

#[cfg(feature = "compression")]
#[test]
fn truncated_content_cannot_become_a_successful_response() {
    use asupersync::http::compress::ContentEncoding;
    let wire = encode(b"payload", ContentEncoding::Deflate);
    for len in 0..wire.len() {
        let mut response = Response::new(200, "OK", wire[..len].to_vec())
            .with_header("Content-Encoding", "deflate");
        let before = response.clone();
        assert!(response
            .decode_content(&Method::Get, DecompressionLimit::new(1024))
            .is_err());
        assert_unchanged(&response, &before);
    }
}
