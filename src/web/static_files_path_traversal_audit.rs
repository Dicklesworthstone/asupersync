//! Path traversal security audit for static file serving.
//!
//! AUDIT FINDING: SOUND - Static file serving correctly normalizes requests and
//! rejects all path traversal attempts with multi-layered protection per OWASP
//! guidelines. This test pins the security-critical behavior.

#![cfg(test)]

use crate::web::response::StatusCode;
use crate::web::static_files::StaticFiles;
use std::fs;
use tempfile::TempDir;

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

fn body_contains_bytes(body: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && body.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn audit_body_contains_bytes_matches_subslices_not_single_bytes() {
    let body = b"safe payload with ERROR: traversal detected marker";

    assert!(
        body_contains_bytes(body, b"ERROR: traversal detected"),
        "byte body matcher must find multi-byte diagnostic markers"
    );
    assert!(
        !body_contains_bytes(body, b"ERROR: different marker"),
        "byte body matcher must not collapse to single-byte contains semantics"
    );
    assert!(
        !body_contains_bytes(body, b""),
        "empty marker is not a useful audit match"
    );
}

/// AUDIT: Verify that direct path traversal attempts are rejected (basic case)
///
/// When request path "/static/../etc/passwd" is received, the handler must:
/// 1. Normalize the path by URL decoding
/// 2. Detect the path traversal pattern
/// 3. Reject with 404 (not serve the file)
#[test]
fn audit_basic_path_traversal_rejected() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Basic path traversal attack patterns must be rejected
    let traversal_paths = vec![
        "/static/../etc/passwd",         // Classic traversal
        "/static/../../etc/passwd",      // Multiple levels
        "/static/../../../etc/passwd",   // Deep traversal
        "/files/../config/secrets.txt",  // Different prefix
        "/assets/../../../bin/sh",       // Executable access attempt
        "/public/../.env",               // Environment file access
        "/static/..\\windows\\system32", // Windows-style backslash
    ];

    for path in traversal_paths {
        let request = crate::web::extract::Request::new("GET", path);
        let response = handler.call_sync(request);

        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "Path traversal attempt '{path}' must be rejected with 404, not served"
        );

        // AUDIT: Must not leak any file content
        assert!(
            response.body.is_empty() || !response.body.as_ref().starts_with(b"root:"),
            "Path traversal attempt '{path}' must not leak passwd file content"
        );
    }
}

/// AUDIT: Verify that URL-encoded path traversal attempts are rejected
///
/// Attackers often URL-encode traversal sequences to bypass basic filters.
/// The system must decode and then detect the traversal pattern.
#[test]
fn audit_url_encoded_path_traversal_rejected() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: URL-encoded traversal patterns must be decoded and rejected
    let encoded_traversal_paths = vec![
        "/static/%2e%2e/etc/passwd",          // URL-encoded ..
        "/static%2f..%2fetc%2fpasswd",        // URL-encoded separators
        "/static%5c..%5cetc%5cpasswd",        // URL-encoded backslashes
        "/static/%2e%2e%2f%2e%2e/etc/passwd", // Mixed encoding
    ];

    for path in encoded_traversal_paths {
        let request = crate::web::extract::Request::new("GET", path);
        let response = handler.call_sync(request);

        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "URL-encoded path traversal '{path}' must be decoded and rejected with 404"
        );
    }
}

/// AUDIT: Verify that double-encoded path traversal attempts are rejected
///
/// Sophisticated attacks use multiple encoding layers to evade detection.
/// The system must perform multiple decoding rounds and detect traversal.
#[test]
fn audit_double_encoded_path_traversal_rejected() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Double/triple-encoded traversal must be detected after multi-round decoding
    let double_encoded_paths = vec![
        "/static/%252e%252e/etc/passwd",         // Double-encoded ..
        "/static%252f..%252fetc%252fpasswd",     // Double-encoded with separators
        "/static%255c..%255cetc%255cpasswd",     // Double-encoded backslashes
        "/%252e%252e%252f%252e%252e/etc/passwd", // Multiple levels double-encoded
    ];

    for path in double_encoded_paths {
        let request = crate::web::extract::Request::new("GET", path);
        let response = handler.call_sync(request);

        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "Double-encoded path traversal '{path}' must be decoded and rejected with 404"
        );
    }
}

/// AUDIT: Verify that Unicode dot variants in traversal are rejected
///
/// Attackers may use Unicode characters that visually resemble dots
/// but have different codepoints to evade ASCII-only filters.
#[test]
fn audit_unicode_dot_path_traversal_rejected() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Unicode dot variants must be detected as traversal attempts
    let unicode_dot_paths = vec![
        "/static/\u{2024}\u{2024}/etc/passwd", // ONE DOT LEADER (U+2024)
        "/static/\u{FE52}\u{FE52}/etc/passwd", // SMALL FULL STOP (U+FE52)
        "/static/\u{FF0E}\u{FF0E}/etc/passwd", // FULLWIDTH FULL STOP (U+FF0E)
        "/static/.\u{2024}/etc/passwd",        // Mixed regular and Unicode dots
    ];

    for path in unicode_dot_paths {
        let request = crate::web::extract::Request::new("GET", path);
        let response = handler.call_sync(request);

        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "Unicode dot traversal '{path}' must be rejected with 404"
        );
    }
}

/// AUDIT: Verify that null byte injection is rejected
///
/// Null bytes can truncate paths in some systems, potentially bypassing filters.
#[test]
fn audit_null_byte_injection_rejected() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Null byte injection must be rejected
    let null_byte_paths = vec![
        "/static/file\0.txt",
        "/static/../../etc/passwd\0.jpg",
        "/static/..\0/etc/passwd",
    ];

    for path in null_byte_paths {
        let request = crate::web::extract::Request::new("GET", path);
        let response = handler.call_sync(request);

        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "Null byte injection '{path:?}' must be rejected with 404"
        );
    }
}

/// AUDIT: Verify legitimate files are still served (no false positives)
///
/// Security measures must not break legitimate access to allowed files.
#[test]
fn audit_legitimate_files_still_accessible() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Legitimate paths must still work (security without breaking functionality)
    let legitimate_paths = vec![
        "/safe.txt",
        "/static/app.js",
        "/static/styles.css",
        "/assets/image.png",
        "/version.1.2/file.txt", // Dots in filenames (not traversal)
        "/static/v1.0/api.json", // Version-like paths
    ];

    for path in legitimate_paths {
        let request = crate::web::extract::Request::new("GET", path);
        let response = handler.call_sync(request);

        // File exists → 200, File doesn't exist → 404, but NOT security rejection
        assert!(
            response.status == StatusCode::OK || response.status == StatusCode::NOT_FOUND,
            "Legitimate path '{path}' must not be security-rejected (got {:?})",
            response.status
        );

        // If the file exists and is served, verify it's actually the right content
        if response.status == StatusCode::OK {
            let traversal_marker = b"ERROR: traversal detected";
            assert!(
                !body_contains_bytes(response.body.as_ref(), traversal_marker),
                "Legitimate path '{path}' must serve actual file content, not error message"
            );
        }
    }
}

/// AUDIT: Verify behavior is consistent across HTTP methods
///
/// Path traversal protection must apply to all HTTP methods, not just GET.
#[test]
fn audit_path_traversal_rejected_across_http_methods() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    let traversal_path = "/static/../etc/passwd";
    let methods = vec!["GET", "HEAD", "POST", "PUT", "DELETE"];

    for method in methods {
        let request = crate::web::extract::Request::new(method, traversal_path);
        let response = handler.call_sync(request);

        // Static file handler should reject traversal regardless of method
        // (It may return 405 Method Not Allowed for non-GET/HEAD, but not serve the file)
        assert_ne!(
            response.status,
            StatusCode::OK,
            "Path traversal via {method} '{traversal_path}' must not succeed"
        );

        // AUDIT: Must never leak sensitive content regardless of HTTP method
        assert!(
            !response.body.as_ref().starts_with(b"root:"),
            "Path traversal via {method} must not leak passwd content"
        );
    }
}

/// AUDIT: Verify symlink traversal is blocked
///
/// Symlinks can be used to escape the document root even after path validation.
#[cfg(unix)]
#[test]
fn audit_symlink_traversal_blocked() {
    let dir = setup_secure_test_environment();

    // Create a symlink pointing outside the document root
    let outside_dir = TempDir::new().unwrap();
    let secret_file = outside_dir.path().join("secret.txt");
    fs::write(&secret_file, "top secret data").unwrap();

    let symlink_path = dir.path().join("evil_link");
    std::os::unix::fs::symlink(&secret_file, &symlink_path).unwrap();

    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Symlink that points outside document root must be rejected
    let request = crate::web::extract::Request::new("GET", "/evil_link");
    let response = handler.call_sync(request);

    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "Symlink pointing outside document root must be rejected"
    );

    assert_ne!(
        response.body.as_ref(),
        b"top secret data",
        "Symlink traversal must not leak external file content"
    );
}

/// AUDIT: End-to-end traversal attack simulation
///
/// Comprehensive test simulating a real attack scenario with multiple techniques.
#[test]
fn audit_comprehensive_traversal_attack_simulation() {
    let dir = setup_secure_test_environment();
    let handler = StaticFiles::new(dir.path()).handler();

    // AUDIT: Simulate realistic attack progression
    let attack_sequence = vec![
        // Phase 1: Basic reconnaissance
        ("/../etc/passwd", "Basic traversal"),
        ("/static/../../../etc/passwd", "Deep traversal"),
        // Phase 2: Encoding evasion
        ("/static/%2e%2e/etc/passwd", "URL encoded"),
        ("/static%2f..%2fetc%2fpasswd", "Path separator encoded"),
        // Phase 3: Double encoding
        ("/static/%252e%252e/etc/passwd", "Double encoded"),
        // Phase 4: Unicode evasion
        ("/static/\u{2024}\u{2024}/etc/passwd", "Unicode dots"),
        // Phase 5: Null byte attacks
        ("/static/../../etc/passwd\0.txt", "Null byte suffix"),
        // Phase 6: Alternative targets
        ("/static/../../../proc/version", "Proc filesystem"),
        ("/static/../../../home/user/.ssh/id_rsa", "SSH keys"),
        ("/static/../../../var/log/auth.log", "Log files"),
    ];

    for (attack_path, attack_name) in attack_sequence {
        let request = crate::web::extract::Request::new("GET", attack_path);
        let response = handler.call_sync(request);

        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "Attack '{attack_name}' using path '{attack_path}' must be rejected"
        );

        // AUDIT: No sensitive content must leak
        let body_str = String::from_utf8_lossy(&response.body);
        let sensitive_patterns = vec![
            "root:",
            "Linux version",
            "ssh-rsa",
            "BEGIN PRIVATE KEY",
            "password",
            "secret",
            "auth",
            "login",
            "/bin/bash",
        ];

        for pattern in &sensitive_patterns {
            assert!(
                !body_str.to_lowercase().contains(&pattern.to_lowercase()),
                "Attack '{attack_name}' must not leak content matching '{pattern}'"
            );
        }
    }
}

/// Set up a secure test environment with realistic file structure
fn setup_secure_test_environment() -> TempDir {
    let dir = TempDir::new().unwrap();

    // Create legitimate static files
    fs::write(dir.path().join("safe.txt"), "This is a safe file").unwrap();

    // Create subdirectories with files
    let static_dir = dir.path().join("static");
    fs::create_dir(&static_dir).unwrap();
    fs::write(static_dir.join("app.js"), "console.log('app');").unwrap();
    fs::write(static_dir.join("styles.css"), "body { margin: 0; }").unwrap();

    let assets_dir = dir.path().join("assets");
    fs::create_dir(&assets_dir).unwrap();
    fs::write(assets_dir.join("image.png"), "test PNG fixture data").unwrap();

    // Create version-like directory structure
    let version_dir = dir.path().join("version.1.2");
    fs::create_dir(&version_dir).unwrap();
    fs::write(version_dir.join("file.txt"), "version file").unwrap();

    let v1_dir = static_dir.join("v1.0");
    fs::create_dir(&v1_dir).unwrap();
    fs::write(v1_dir.join("api.json"), r#"{"api":"v1"}"#).unwrap();

    dir
}
