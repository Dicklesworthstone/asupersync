#![allow(clippy::all)]
//! Regression tests for HTTP/1.1 request-line parsing
//!
//! This module contains regression tests generated from fuzz target discoveries
//! and validates core request-line parsing functionality including method/path/version
//! extraction, CRLF handling, length limits, and invalid byte rejection.

#[cfg(test)]
mod request_line_regression_tests {
    use crate::bytes::BytesMut;
    use crate::codec::Decoder;
    use crate::http::h1::{Http1Codec, HttpError};

    /// Test basic request-line parsing for standard methods
    #[test]
    fn request_line_standard_methods() {
        let test_cases = vec![
            "GET /index.html HTTP/1.1\r\n\r\n",
            "POST /api/users HTTP/1.1\r\n\r\n",
            "PUT /resource HTTP/1.0\r\n\r\n",
            "DELETE /item/123 HTTP/1.1\r\n\r\n",
            "HEAD /status HTTP/1.1\r\n\r\n",
            "OPTIONS * HTTP/1.1\r\n\r\n",
        ];

        for (i, request) in test_cases.iter().enumerate() {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(*request);

            let result = codec.decode(&mut buf);
            assert!(
                result.is_ok(),
                "Failed to parse standard request {}: {:?}",
                i,
                request
            );
        }
    }

    /// Test extension method handling
    #[test]
    fn request_line_extension_methods() {
        let test_cases = vec![
            "PATCH /resource HTTP/1.1\r\n\r\n",
            "CUSTOMMETHOD /api HTTP/1.1\r\n\r\n",
            "MYVERB /endpoint HTTP/1.1\r\n\r\n",
        ];

        for request in test_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            let result = codec.decode(&mut buf);
            assert!(
                result.is_ok(),
                "Failed to parse extension method: {}",
                request
            );
        }
    }

    /// Test whitespace handling robustness
    #[test]
    fn request_line_whitespace_handling() {
        let test_cases = vec![
            // Multiple spaces between components
            "GET    /path    HTTP/1.1\r\n\r\n",
            "POST   /api   HTTP/1.0\r\n\r\n",
            // Tab characters (should be rejected per HTTP spec)
            "GET\t/path\tHTTP/1.1\r\n\r\n",
        ];

        for (i, request) in test_cases.iter().enumerate() {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(*request);

            let result = codec.decode(&mut buf);
            if i < 2 {
                // Multiple spaces should be handled by slow path
                assert!(
                    result.is_ok(),
                    "Failed to parse request with extra spaces: {}",
                    request
                );
            } else {
                // Tab characters should be rejected
                assert!(
                    result.is_err(),
                    "Tab characters should be rejected: {}",
                    request
                );
            }
        }
    }

    /// Test HTTP version validation
    #[test]
    fn request_line_version_validation() {
        let valid_cases = vec!["GET /test HTTP/1.0\r\n\r\n", "GET /test HTTP/1.1\r\n\r\n"];

        let invalid_cases = vec![
            "GET /test HTTP/2.0\r\n\r\n",
            "GET /test http/1.1\r\n\r\n", // lowercase
            "GET /test HTTP/1.2\r\n\r\n",
            "GET /test HTTP\r\n\r\n",       // missing version
            "GET /test HTTP/1.1.0\r\n\r\n", // too detailed
        ];

        for request in valid_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            let result = codec.decode(&mut buf);
            assert!(
                result.is_ok(),
                "Valid version should be accepted: {}",
                request
            );
        }

        for request in invalid_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            let result = codec.decode(&mut buf);
            assert!(
                result.is_err(),
                "Invalid version should be rejected: {}",
                request
            );
        }
    }

    /// Test request-line length limits (MAX_REQUEST_LINE = 8192)
    #[test]
    fn request_line_length_limits() {
        let mut codec = Http1Codec::new();

        // Create a request line just under the limit
        let long_path = "a".repeat(8000);
        let request_ok = format!("GET /{} HTTP/1.1\r\n\r\n", long_path);
        let mut buf_ok = BytesMut::from(request_ok.as_str());

        let result = codec.decode(&mut buf_ok);
        assert!(
            result.is_ok(),
            "Request under length limit should be accepted"
        );

        // Create a request line over the limit
        let very_long_path = "a".repeat(9000);
        let request_too_long = format!("GET /{} HTTP/1.1\r\n\r\n", very_long_path);
        let mut buf_too_long = BytesMut::from(request_too_long.as_str());

        let result = codec.decode(&mut buf_too_long);
        match result {
            Err(HttpError::RequestLineTooLong) => {
                // Expected behavior
            }
            _ => panic!("Request over length limit should return RequestLineTooLong error"),
        }
    }

    /// Test CRLF handling and line ending tolerance
    #[test]
    fn request_line_crlf_handling() {
        let test_cases = vec![
            // Standard CRLF
            ("GET /test HTTP/1.1\r\n\r\n", true),
            // LF only (should be handled)
            ("GET /test HTTP/1.1\n\n", true),
            // CR only (invalid)
            ("GET /test HTTP/1.1\r\r", false),
            // Mixed line endings
            ("GET /test HTTP/1.1\r\nHost: example.com\n\r\n", true),
        ];

        for (request, should_succeed) in test_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            let result = codec.decode(&mut buf);
            if should_succeed {
                assert!(
                    result.is_ok(),
                    "Request should parse successfully: {:?}",
                    request
                );
            } else {
                assert!(
                    result.is_err(),
                    "Request should fail to parse: {:?}",
                    request
                );
            }
        }
    }

    /// Test invalid byte rejection
    #[test]
    fn request_line_invalid_bytes() {
        let invalid_cases = vec![
            // Null byte in method
            "G\x00ET /test HTTP/1.1\r\n\r\n",
            // Control character in path
            "GET /test\x01 HTTP/1.1\r\n\r\n",
            // DEL character in version
            "GET /test HTTP/1.1\x7F\r\n\r\n",
            // Non-ASCII in method
            "GÈT /test HTTP/1.1\r\n\r\n",
        ];

        for request in invalid_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            let result = codec.decode(&mut buf);
            assert!(
                result.is_err(),
                "Invalid bytes should be rejected: {:?}",
                request.escape_debug()
            );
        }
    }

    /// Test percent-encoding in paths (should be handled at a higher level)
    #[test]
    fn request_line_percent_encoding() {
        let test_cases = vec![
            "GET /path%20with%20spaces HTTP/1.1\r\n\r\n",
            "GET /encoded%2Fslash HTTP/1.1\r\n\r\n",
            "GET /%3Fquery%3Dvalue HTTP/1.1\r\n\r\n",
        ];

        for request in test_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            // The codec should parse percent-encoded paths as-is
            // (decoding happens at higher layers)
            let result = codec.decode(&mut buf);
            assert!(
                result.is_ok(),
                "Percent-encoded path should parse: {}",
                request
            );
        }
    }

    /// Test malformed request lines
    #[test]
    fn request_line_malformed() {
        let malformed_cases = vec![
            // Missing components
            "GET\r\n\r\n",
            "GET /test\r\n\r\n",
            "/test HTTP/1.1\r\n\r\n",
            // Too many components
            "GET /test HTTP/1.1 EXTRA\r\n\r\n",
            // Empty components
            " /test HTTP/1.1\r\n\r\n",
            "GET  HTTP/1.1\r\n\r\n",
            "GET /test \r\n\r\n",
        ];

        for request in malformed_cases {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(request);

            let result = codec.decode(&mut buf);
            assert!(
                result.is_err(),
                "Malformed request should be rejected: {:?}",
                request
            );
        }
    }

    /// Test edge case: request line exactly at limit boundary
    #[test]
    fn request_line_exact_boundary() {
        // Create request line exactly 8192 bytes (MAX_REQUEST_LINE)
        let method = "GET ";
        let version = " HTTP/1.1";
        let path_len = 8192 - method.len() - version.len();
        let path = format!("/{}", "a".repeat(path_len - 1));

        let request_line = format!("{}{}{}\r\n\r\n", method, path, version);
        assert_eq!(request_line.find("\r\n").unwrap(), 8192);

        let mut codec = Http1Codec::new();
        let mut buf = BytesMut::from(request_line.as_str());

        let result = codec.decode(&mut buf);
        assert!(
            result.is_ok(),
            "Request line exactly at limit should be accepted"
        );
    }
}
