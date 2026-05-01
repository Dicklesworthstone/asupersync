//! Regression tests for static file Range request handling.

use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::response::StatusCode;
use asupersync::web::static_files::StaticFiles;
use std::fs;
use tempfile::TempDir;

const TEST_CONTENT: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn setup_test_dir() -> TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("test.txt"), TEST_CONTENT).expect("write test file");

    dir
}

#[test]
fn test_single_range_request() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=0-9");

    let resp = handler.call(req);

    assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.body.as_ref(), b"0123456789");
    assert_eq!(resp.header_value("content-range"), Some("bytes 0-9/62"));
    assert_eq!(resp.header_value("content-length"), Some("10"));
    assert_eq!(resp.header_value("accept-ranges"), Some("bytes"));
}

#[test]
fn test_multi_range_request() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=0-4, 10-14");

    let resp = handler.call(req);

    assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
    let content_type = resp.header_value("content-type").unwrap_or("");
    assert!(
        content_type.starts_with("multipart/byteranges; boundary="),
        "unexpected content-type: {content_type}"
    );
    assert_eq!(resp.header_value("accept-ranges"), Some("bytes"));

    let body = std::str::from_utf8(resp.body.as_ref()).expect("multipart body is utf8");
    assert!(body.contains("Content-Range: bytes 0-4/62"));
    assert!(body.contains("Content-Range: bytes 10-14/62"));
    assert!(body.contains("\r\n\r\n01234\r\n"));
    assert!(body.contains("\r\n\r\nabcde\r\n"));
}

#[test]
fn test_range_forms_are_respected() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();

    let test_cases = [
        ("bytes=0-10", b"0123456789a".as_slice()),
        ("bytes=-10", b"QRSTUVWXYZ".as_slice()),
        (
            "bytes=10-",
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice(),
        ),
        ("bytes=-999", TEST_CONTENT),
    ];

    for (range_header, expected) in test_cases {
        let req = Request::new("GET", "/test.txt").with_header("range", range_header);
        let resp = handler.call(req);

        assert_eq!(
            resp.status,
            StatusCode::PARTIAL_CONTENT,
            "range {range_header} should return partial content"
        );
        assert_eq!(
            resp.body.as_ref(),
            expected,
            "range {range_header} returned wrong body"
        );
        assert_eq!(
            resp.header_value("accept-ranges"),
            Some("bytes"),
            "range {range_header} must advertise byte range support"
        );
    }
}

#[test]
fn mixed_multi_range_request_returns_multipart_body() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=0-4, -5");

    let resp = handler.call(req);

    assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
    let body = std::str::from_utf8(resp.body.as_ref()).expect("multipart body is utf8");
    assert!(
        body.contains("Content-Range: bytes 0-4/62"),
        "first range missing from multipart body"
    );
    assert!(
        body.contains("Content-Range: bytes 57-61/62"),
        "suffix range missing from multipart body"
    );
    assert!(body.contains("\r\n\r\n01234\r\n"));
    assert!(body.contains("\r\n\r\nVWXYZ\r\n"));
}

#[test]
fn if_none_match_wildcard_takes_precedence_over_range() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt")
        .with_header("range", "bytes=0-9")
        .with_header("if-none-match", "*");

    let resp = handler.call(req);

    assert_eq!(resp.status, StatusCode::NOT_MODIFIED);
    assert!(resp.body.is_empty());
    assert_eq!(resp.header_value("accept-ranges"), Some("bytes"));
    assert!(resp.header_value("etag").is_some());
}

#[test]
fn head_range_preserves_partial_headers_without_body() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("HEAD", "/test.txt").with_header("range", "bytes=0-9");

    let resp = handler.call(req);

    assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
    assert!(resp.body.is_empty());
    assert_eq!(resp.header_value("content-range"), Some("bytes 0-9/62"));
    assert_eq!(resp.header_value("content-length"), Some("10"));
}

#[test]
fn test_invalid_range_syntax_returns_416() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=abc-def");

    let resp = handler.call(req);

    assert_eq!(resp.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(resp.header_value("content-range"), Some("bytes */62"));
    assert_eq!(resp.header_value("accept-ranges"), Some("bytes"));
}

#[test]
fn test_unsatisfiable_range_should_return_416() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=100-200");

    let resp = handler.call(req);

    assert_eq!(
        resp.status,
        StatusCode::RANGE_NOT_SATISFIABLE,
        "unsatisfiable range should return 416"
    );
    assert_eq!(resp.header_value("content-range"), Some("bytes */62"));
    assert_eq!(resp.header_value("accept-ranges"), Some("bytes"));
}

#[test]
fn test_content_range_header_present() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();

    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=0-9");

    let resp = handler.call(req);

    assert_eq!(
        resp.header_value("content-range"),
        Some("bytes 0-9/62"),
        "Content-Range header must be present for single range requests"
    );
}

#[test]
fn test_accept_ranges_header_present() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();

    let req = Request::new("GET", "/test.txt");
    let resp = handler.call(req);

    assert_eq!(
        resp.header_value("accept-ranges"),
        Some("bytes"),
        "regular static responses should advertise byte range support"
    );
}

#[test]
fn verify_multipart_byteranges_format() {
    let dir = setup_test_dir();
    let handler = StaticFiles::new(dir.path()).handler();
    let req = Request::new("GET", "/test.txt").with_header("range", "bytes=0-4, 10-14");

    let resp = handler.call(req);
    let body = std::str::from_utf8(resp.body.as_ref()).expect("multipart body is utf8");

    assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
    assert!(
        body.starts_with("--asupersync_range_boundary\r\n"),
        "multipart body should start with the configured boundary"
    );
    assert!(
        body.ends_with("--asupersync_range_boundary--\r\n"),
        "multipart body should end with the closing boundary"
    );
    assert!(
        body.contains("Content-Type: text/plain; charset=utf-8\r\n"),
        "each part should include the original content type"
    );
    assert!(
        body.contains("Content-Range: bytes 0-4/62\r\n\r\n01234\r\n"),
        "first range part should include its Content-Range and bytes"
    );
    assert!(
        body.contains("Content-Range: bytes 10-14/62\r\n\r\nabcde\r\n"),
        "second range part should include its Content-Range and bytes"
    );
}
