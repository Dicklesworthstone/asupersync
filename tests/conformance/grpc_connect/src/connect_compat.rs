#![allow(warnings)]
#![allow(clippy::all)]
//! Connect protocol compatibility layer
//!
//! This module provides Connect protocol specific testing and compatibility
//! verification against the Connect specification.

use anyhow::Result;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Connect protocol constants
pub mod constants {
    pub const CONNECT_PROTOCOL_VERSION: &str = "1";
    pub const CONNECT_CONTENT_TYPE: &str = "application/connect+proto";
    pub const CONNECT_CONTENT_TYPE_JSON: &str = "application/connect+json";
    pub const CONNECT_STREAMING_CONTENT_TYPE: &str = "application/connect+proto";
    pub const CONNECT_USER_AGENT: &str = "connect-conformance/1.0.0";
    pub const CONNECT_PROTOCOL_HEADER: &str = "connect-protocol-version";
    pub const CONNECT_TIMEOUT_HEADER: &str = "connect-timeout-ms";
    pub const CONNECT_ENCODING_HEADER: &str = "connect-accept-encoding";
}

/// Connect protocol specific test configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectTestConfig {
    pub use_json_encoding: bool,
    pub use_streaming: bool,
    pub timeout_ms: Option<u64>,
    pub compression: Option<ConnectCompression>,
    pub user_agent: String,
}

impl Default for ConnectTestConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            use_json_encoding: false,
            use_streaming: false,
            timeout_ms: None,
            compression: None,
            user_agent: constants::CONNECT_USER_AGENT.to_string(),
        }
    }
}

/// Connect compression options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConnectCompression {
    Gzip,
    Deflate,
    Brotli,
}

#[allow(dead_code)]

impl ConnectCompression {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectCompression::Gzip => "gzip",
            ConnectCompression::Deflate => "deflate",
            ConnectCompression::Brotli => "br",
        }
    }
}

/// Connect request builder
#[allow(dead_code)]
pub struct ConnectRequestBuilder {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    config: ConnectTestConfig,
}

#[allow(dead_code)]

impl ConnectRequestBuilder {
    #[allow(dead_code)]
    pub fn new(service: &str, method: &str) -> Self {
        let uri = format!("/{}/{}", service, method).parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_str(&constants::CONNECT_USER_AGENT).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(constants::CONNECT_PROTOCOL_HEADER),
            HeaderValue::from_str(constants::CONNECT_PROTOCOL_VERSION).unwrap(),
        );

        Self {
            method: Method::POST,
            uri,
            headers,
            body: Bytes::new(),
            config: ConnectTestConfig::default(),
        }
    }

    #[allow(dead_code)]

    pub fn with_config(mut self, config: ConnectTestConfig) -> Self {
        self.config = config;

        // Set content type based on encoding preference
        let content_type = if config.use_json_encoding {
            constants::CONNECT_CONTENT_TYPE_JSON
        } else if config.use_streaming {
            constants::CONNECT_STREAMING_CONTENT_TYPE
        } else {
            constants::CONNECT_CONTENT_TYPE
        };

        self.headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_str(content_type).unwrap(),
        );

        // Set timeout if specified
        if let Some(timeout_ms) = config.timeout_ms {
            self.headers.insert(
                HeaderName::from_static(constants::CONNECT_TIMEOUT_HEADER),
                HeaderValue::from_str(&timeout_ms.to_string()).unwrap(),
            );
        }

        // Set compression
        if let Some(compression) = config.compression {
            self.headers.insert(
                HeaderName::from_static(constants::CONNECT_ENCODING_HEADER),
                HeaderValue::from_str(compression.as_str()).unwrap(),
            );
        }

        // Update user agent
        self.headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_str(&config.user_agent).unwrap(),
        );

        self
    }

    #[allow(dead_code)]

    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }

    #[allow(dead_code)]

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(
            HeaderName::from_str(name).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        self
    }

    #[allow(dead_code)]

    pub fn build(self) -> ConnectRequest {
        ConnectRequest {
            method: self.method,
            uri: self.uri,
            headers: self.headers,
            body: self.body,
        }
    }
}

/// Connect protocol request
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Connect protocol response
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectResponse {
    pub status_code: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
}

/// Connect error format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConnectError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<ConnectErrorDetail>>,
}

/// Connect error detail
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConnectErrorDetail {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub value: serde_json::Value,
}

/// Connect protocol validator
#[allow(dead_code)]
pub struct ConnectProtocolValidator;

#[allow(dead_code)]

impl ConnectProtocolValidator {
    /// Validate that a request conforms to Connect protocol
    #[allow(dead_code)]
    pub fn validate_request(request: &ConnectRequest) -> Result<ValidationResult> {
        let mut issues = Vec::new();

        // Check HTTP method
        if request.method != Method::POST {
            issues.push(format!("Expected POST method, got {}", request.method));
        }

        // Check Content-Type header
        let content_type = request.headers.get("content-type");
        match content_type {
            Some(ct) => {
                let ct_str = ct.to_str().unwrap_or("");
                if !ct_str.starts_with("application/connect+") {
                    issues.push(format!("Invalid Content-Type: {}", ct_str));
                }
            }
            None => issues.push("Missing Content-Type header".to_string()),
        }

        // Check Connect protocol version
        let protocol_version = request.headers.get(constants::CONNECT_PROTOCOL_HEADER);
        match protocol_version {
            Some(version) => {
                if version != constants::CONNECT_PROTOCOL_VERSION {
                    issues.push(format!(
                        "Unsupported protocol version: {:?}",
                        version
                    ));
                }
            }
            None => issues.push("Missing Connect protocol version header".to_string()),
        }

        // Check URI format (should be /{service}/{method})
        let path = request.uri.path();
        let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if path_segments.len() != 2 {
            issues.push(format!(
                "Invalid URI path format: {} (expected /service/method)",
                path
            ));
        }

        Ok(ValidationResult {
            is_valid: issues.is_empty(),
            issues,
        })
    }

    /// Validate that a response conforms to Connect protocol
    #[allow(dead_code)]
    pub fn validate_response(response: &ConnectResponse) -> Result<ValidationResult> {
        let mut issues = Vec::new();

        // Check status code ranges
        match response.status_code {
            200 => {
                // Success response - validate success headers
                if let Some(content_type) = response.headers.get("content-type") {
                    let ct_str = content_type.to_str().unwrap_or("");
                    if !ct_str.starts_with("application/connect+") {
                        issues.push(format!("Invalid success Content-Type: {}", ct_str));
                    }
                }
            }
            400..=499 | 500..=599 => {
                // Error response - validate error format
                if let Some(content_type) = response.headers.get("content-type") {
                    let ct_str = content_type.to_str().unwrap_or("");
                    if !ct_str.starts_with("application/") {
                        issues.push(format!("Invalid error Content-Type: {}", ct_str));
                    }
                }

                // Try to parse error body
                if !response.body.is_empty() {
                    match serde_json::from_slice::<ConnectError>(&response.body) {
                        Ok(_) => {}, // Valid error format
                        Err(e) => issues.push(format!("Invalid error body format: {}", e)),
                    }
                }
            }
            _ => {
                issues.push(format!("Unexpected status code: {}", response.status_code));
            }
        }

        Ok(ValidationResult {
            is_valid: issues.is_empty(),
            issues,
        })
    }

    /// Map gRPC status codes to Connect error codes
    #[allow(dead_code)]
    pub fn grpc_to_connect_status(grpc_code: i32) -> &'static str {
        match grpc_code {
            0 => "ok",
            1 => "cancelled",
            2 => "unknown",
            3 => "invalid_argument",
            4 => "deadline_exceeded",
            5 => "not_found",
            6 => "already_exists",
            7 => "permission_denied",
            8 => "resource_exhausted",
            9 => "failed_precondition",
            10 => "aborted",
            11 => "out_of_range",
            12 => "unimplemented",
            13 => "internal",
            14 => "unavailable",
            15 => "data_loss",
            16 => "unauthenticated",
            _ => "unknown",
        }
    }

    /// Map HTTP status codes to gRPC status codes per Connect spec
    #[allow(dead_code)]
    pub fn http_to_grpc_status(http_status: u16) -> i32 {
        match http_status {
            200 => 0,  // OK
            400 => 3,  // INVALID_ARGUMENT
            401 => 16, // UNAUTHENTICATED
            403 => 7,  // PERMISSION_DENIED
            404 => 5,  // NOT_FOUND
            408 => 4,  // DEADLINE_EXCEEDED
            409 => 6,  // ALREADY_EXISTS
            412 => 9,  // FAILED_PRECONDITION
            413 => 11, // OUT_OF_RANGE
            429 => 8,  // RESOURCE_EXHAUSTED
            501 => 12, // UNIMPLEMENTED
            502 | 503 | 504 => 14, // UNAVAILABLE
            _ => 13, // INTERNAL
        }
    }
}

/// Validation result
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub issues: Vec<String>,
}

/// Connect-specific conformance tests
#[allow(dead_code)]
pub struct ConnectConformanceTests;

#[allow(dead_code)]

impl ConnectConformanceTests {
    /// Test Connect protocol header requirements
    pub async fn test_protocol_headers() -> Result<ValidationResult> {
        // This would test that our server correctly handles Connect protocol headers
        let mut issues = Vec::new();

        // TODO: Implement actual Connect protocol header tests
        issues.push("Connect protocol header tests not yet implemented".to_string());

        Ok(ValidationResult {
            is_valid: false,
            issues,
        })
    }

    /// Test Connect error format compliance
    pub async fn test_error_format() -> Result<ValidationResult> {
        // This would test that errors are returned in Connect format
        let mut issues = Vec::new();

        // TODO: Implement Connect error format tests
        issues.push("Connect error format tests not yet implemented".to_string());

        Ok(ValidationResult {
            is_valid: false,
            issues,
        })
    }

    /// Test Connect streaming protocol
    pub async fn test_streaming_protocol() -> Result<ValidationResult> {
        // This would test Connect streaming protocol specifics
        let mut issues = Vec::new();

        // TODO: Implement Connect streaming tests
        issues.push("Connect streaming tests not yet implemented".to_string());

        Ok(ValidationResult {
            is_valid: false,
            issues,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_connect_request_builder() {
        let request = ConnectRequestBuilder::new("test.Service", "TestMethod")
            .with_config(ConnectTestConfig::default())
            .with_body(Bytes::from("test body"))
            .build();

        assert_eq!(request.method, Method::POST);
        assert_eq!(request.uri.path(), "/test.Service/TestMethod");
        assert!(request.headers.contains_key("user-agent"));
        assert!(request.headers.contains_key(constants::CONNECT_PROTOCOL_HEADER));
    }

    #[test]
    #[allow(dead_code)]
    fn test_grpc_to_connect_status() {
        assert_eq!(ConnectProtocolValidator::grpc_to_connect_status(0), "ok");
        assert_eq!(ConnectProtocolValidator::grpc_to_connect_status(1), "cancelled");
        assert_eq!(ConnectProtocolValidator::grpc_to_connect_status(3), "invalid_argument");
        assert_eq!(ConnectProtocolValidator::grpc_to_connect_status(12), "unimplemented");
        assert_eq!(ConnectProtocolValidator::grpc_to_connect_status(999), "unknown");
    }

    #[test]
    #[allow(dead_code)]
    fn test_http_to_grpc_status() {
        assert_eq!(ConnectProtocolValidator::http_to_grpc_status(200), 0);
        assert_eq!(ConnectProtocolValidator::http_to_grpc_status(400), 3);
        assert_eq!(ConnectProtocolValidator::http_to_grpc_status(404), 5);
        assert_eq!(ConnectProtocolValidator::http_to_grpc_status(500), 13);
    }

    #[test]
    #[allow(dead_code)]
    fn test_connect_request_validation() {
        let request = ConnectRequestBuilder::new("test.Service", "TestMethod")
            .with_config(ConnectTestConfig::default())
            .build();

        let result = ConnectProtocolValidator::validate_request(&request).unwrap();
        assert!(result.is_valid, "Validation issues: {:?}", result.issues);
    }
}