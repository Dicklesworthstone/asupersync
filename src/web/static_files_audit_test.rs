//! Audit test for static files ETag generation behavior.
//!
//! AUDIT FINDING: SOUND - static files correctly generate strong ETags based on
//! SHA256 content hash, per RFC 9110 §8.8.3. This test pins the behavior.

#![cfg(test)]

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

trait SyncHandlerExt {
    fn call_sync(&self, req: crate::web::extract::Request) -> crate::web::response::Response;
}

impl SyncHandlerExt for crate::web::static_files::StaticFilesHandler {
    fn call_sync(&self, req: crate::web::extract::Request) -> crate::web::response::Response {
        futures_lite::future::block_on(crate::web::handler::Handler::call(
            self,
            &crate::Cx::for_testing(),
            req,
        ))
    }
}

/// AUDIT: Verify ETag generation produces strong ETags (content-based, no W/ prefix)
/// per RFC 9110 §8.8.3. Strong ETags must be content-derived, not metadata-derived.
#[test]
fn audit_etag_generation_strong_content_based() {
    let content1 = b"Hello, world!";
    let content2 = b"Hello, World!"; // Different case
    let content3 = b"Hello, world!"; // Identical to content1

    let etag1 = crate::web::static_files::generate_etag_test_access(content1);
    let etag2 = crate::web::static_files::generate_etag_test_access(content2);
    let etag3 = crate::web::static_files::generate_etag_test_access(content3);

    // AUDIT: Strong ETags must not have W/ prefix
    assert!(
        !etag1.starts_with("W/"),
        "Strong ETag must not have W/ prefix"
    );
    assert!(
        !etag2.starts_with("W/"),
        "Strong ETag must not have W/ prefix"
    );

    // AUDIT: Strong ETags must be quoted
    assert!(
        etag1.starts_with('"') && etag1.ends_with('"'),
        "Strong ETag must be quoted"
    );
    assert!(
        etag2.starts_with('"') && etag2.ends_with('"'),
        "Strong ETag must be quoted"
    );

    // AUDIT: Different content must produce different strong ETags
    assert_ne!(
        etag1, etag2,
        "Different content must produce different strong ETags"
    );

    // AUDIT: Identical content must produce identical strong ETags (deterministic)
    assert_eq!(
        etag1, etag3,
        "Identical content must produce identical strong ETags"
    );

    // AUDIT: Verify it's actually SHA256-based (content determinism)
    let expected_hash = {
        let digest = Sha256::digest(content1);
        let mut etag = String::with_capacity(2 + digest.len() * 2);
        etag.push('"');
        for &byte in &digest {
            let _ = write!(etag, "{byte:02x}");
        }
        etag.push('"');
        etag
    };
    assert_eq!(etag1, expected_hash, "ETag must be SHA256 of content");

    // AUDIT: Same-length different content produces different ETags
    // This is critical - weak implementations might use length + mtime
    let same_len_diff = b"Hello, earth!"; // Same length as content1
    let etag_same_len = crate::web::static_files::generate_etag_test_access(same_len_diff);
    assert_ne!(
        etag1, etag_same_len,
        "Same-length different content must produce different ETags"
    );
}

/// AUDIT: Verify ETag matching handles weak client ETags correctly per RFC 9110
#[test]
fn audit_etag_matching_handles_weak_client_etags() {
    let server_etag = r#""abc123def456""#; // Strong server ETag
    let client_weak_etag = r#"W/"abc123def456""#; // Weak client ETag
    let client_strong_etag = r#""abc123def456""#; // Strong client ETag
    let client_different_etag = r#""different123""#; // Different ETag

    // AUDIT: Server strong ETag should match client weak ETag for same content
    assert!(
        crate::web::static_files::etag_matches_test_access(client_weak_etag, server_etag),
        "Server strong ETag must match client weak ETag for same content"
    );

    // AUDIT: Server strong ETag should match client strong ETag for same content
    assert!(
        crate::web::static_files::etag_matches_test_access(client_strong_etag, server_etag),
        "Server strong ETag must match client strong ETag for same content"
    );

    // AUDIT: Different content should not match
    assert!(
        !crate::web::static_files::etag_matches_test_access(client_different_etag, server_etag),
        "Different ETags must not match"
    );

    // AUDIT: Wildcard should always match
    assert!(
        crate::web::static_files::etag_matches_test_access("*", server_etag),
        "Wildcard ETag must always match"
    );
}

/// AUDIT: Verify that file serving includes proper ETag headers
#[test]
fn audit_file_serving_includes_etag_headers() {
    use std::fs;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.txt");
    let file_content = "Test content for ETag";
    fs::write(&file_path, file_content).unwrap();

    let static_files = crate::web::static_files::StaticFiles::new(dir.path());
    let response = static_files
        .handler()
        .call_sync(crate::web::extract::Request::new("GET", "/test.txt"));

    // AUDIT: Response must include ETag header
    assert!(
        response.headers.contains_key("etag"),
        "Static file response must include ETag header"
    );

    // AUDIT: ETag must be strong (no W/ prefix)
    let etag = response.headers.get("etag").unwrap();
    assert!(
        !etag.starts_with("W/"),
        "Static file ETag must be strong (no W/ prefix)"
    );

    // AUDIT: ETag must be quoted
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "Static file ETag must be quoted"
    );

    // AUDIT: Must include Cache-Control for caching
    assert!(
        response.headers.contains_key("cache-control"),
        "Static file response must include Cache-Control header"
    );
}

/// AUDIT: Verify conditional requests (If-None-Match) work correctly with strong ETags
#[test]
fn audit_conditional_requests_with_strong_etags() {
    use std::fs;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.txt");
    let file_content = "Test content for conditional requests";
    fs::write(&file_path, file_content).unwrap();

    let static_files = crate::web::static_files::StaticFiles::new(dir.path());
    let handler = static_files.handler();

    // First request to get ETag
    let response1 = handler.call_sync(crate::web::extract::Request::new("GET", "/test.txt"));
    assert_eq!(response1.status, crate::web::response::StatusCode::OK);
    let etag = response1.headers.get("etag").unwrap().clone();

    // AUDIT: Conditional request with matching ETag should return 304
    let response2 = handler.call_sync(
        crate::web::extract::Request::new("GET", "/test.txt").with_header("If-None-Match", etag),
    );
    assert_eq!(
        response2.status,
        crate::web::response::StatusCode::NOT_MODIFIED,
        "Matching ETag must return 304 Not Modified"
    );
    assert!(
        response2.body.is_empty(),
        "304 response must have empty body"
    );
    assert!(
        response2.headers.contains_key("etag"),
        "304 response must still include ETag header"
    );

    // AUDIT: Conditional request with non-matching ETag should return full content
    let different_etag = r#""different-etag-value""#;
    let response3 = handler.call_sync(
        crate::web::extract::Request::new("GET", "/test.txt")
            .with_header("If-None-Match", different_etag),
    );
    assert_eq!(
        response3.status,
        crate::web::response::StatusCode::OK,
        "Non-matching ETag must return 200 OK with full content"
    );
    assert!(!response3.body.is_empty(), "200 response must include body");
}
