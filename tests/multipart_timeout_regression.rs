//! Regression tests for multipart parse-time limits.
//!
//! Bead: br-asupersync-iosl6f
//!
//! These tests exercise request and idle timeout checks in the synchronous
//! multipart parser. Slow upload protection must still be enforced by the
//! streaming request-body layer before a complete `Request` reaches this
//! extractor.

#![cfg(test)]

use asupersync::bytes::Bytes;
use asupersync::web::extract::FromRequest;
use asupersync::web::extract::Request;
use asupersync::web::multipart::{Multipart, MultipartLimits};
use asupersync::web::response::StatusCode;

/// Create a large multipart request that would normally parse successfully
/// but should timeout with aggressive timeout limits.
fn create_large_multipart_request() -> Request {
    // Create a multipart body with multiple parts that would take time to parse
    let boundary = "test-boundary-12345";
    let mut body = Vec::new();

    // Create multiple parts with reasonable data
    for i in 0..100 {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!(
            "Content-Disposition: form-data; name=\"field{i}\"\r\nContent-Type: text/plain\r\n\r\n"
        ).as_bytes());
        body.extend_from_slice(format!("Data for field {i} ").repeat(100).as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut req = Request::new("POST", "/upload");
    req.headers.insert(
        "content-type".to_string(),
        format!("multipart/form-data; boundary={boundary}"),
    );
    req.body = Bytes::from(body);
    req
}

#[test]
fn multipart_parsing_respects_request_timeout() {
    let mut req = create_large_multipart_request();

    // Configure very aggressive request timeout that should trigger
    // even for a valid multipart request due to parsing complexity
    let limits = MultipartLimits::new()
        .request_timeout_secs(0) // Zero timeout should trigger immediately
        .idle_timeout_secs(60);

    req.extensions.insert_typed(limits);

    let result = Multipart::from_request(req);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.status, StatusCode::REQUEST_TIMEOUT);
    assert!(err.message.contains("timed out"));
}

#[test]
fn multipart_parsing_respects_idle_timeout() {
    let mut req = create_large_multipart_request();

    // Configure aggressive idle timeout
    let limits = MultipartLimits::new()
        .request_timeout_secs(60)
        .idle_timeout_secs(0); // Zero idle timeout should trigger

    req.extensions.insert_typed(limits);

    let result = Multipart::from_request(req);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.status, StatusCode::REQUEST_TIMEOUT);
    assert!(err.message.contains("idle"));
}

#[test]
fn multipart_parsing_succeeds_with_generous_timeouts() {
    let mut req = create_large_multipart_request();

    // Use generous timeouts that should allow normal parsing
    let limits = MultipartLimits::new()
        .request_timeout_secs(60)
        .idle_timeout_secs(30);

    req.extensions.insert_typed(limits);

    let result = Multipart::from_request(req);
    assert!(result.is_ok());

    let multipart = result.unwrap();
    assert_eq!(multipart.len(), 100); // Should successfully parse all 100 fields
}

#[test]
fn multipart_default_timeouts_allow_normal_requests() {
    let req = create_large_multipart_request();

    // Use default timeout limits (no custom limits configured)
    let result = Multipart::from_request(req);
    assert!(result.is_ok());

    let multipart = result.unwrap();
    assert_eq!(multipart.len(), 100);
}

/// The parser-level budget should not reject a reasonable complete request.
/// Slow upload attacks must be rejected before body buffering.
#[test]
fn parser_timeout_limits_allow_reasonable_complete_request() {
    let mut req = create_large_multipart_request();

    // Production-like parser settings should allow legitimate uploads after
    // the request-body layer has already accepted and buffered the body.
    let limits = MultipartLimits::new()
        .request_timeout_secs(30) // 30 seconds max for parser work
        .idle_timeout_secs(5) // 5 seconds max idle between parser steps
        .max_total_size(16 * 1024 * 1024) // 16MB max
        .max_parts(1024) // 1024 parts max
        .max_part_headers(8 * 1024) // 8KB headers per part
        .max_part_body_size(8 * 1024 * 1024); // 8MB per part

    req.extensions.insert_typed(limits);

    let result = Multipart::from_request(req);
    assert!(result.is_ok());
}
