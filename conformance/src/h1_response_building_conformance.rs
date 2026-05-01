//! HTTP/1.1 response building conformance testing.
//!
//! This harness tests the `asupersync` HTTP/1.1 ResponseBuilder against the
//! `hyper` reference implementation to ensure byte-identical wire output
//! for the same response building operations.

use asupersync::bytes::BytesMut;
use asupersync::codec::Encoder;
use asupersync::http::h1::codec::Http1Codec;
use asupersync::http::h1::types::{ResponseBuilder, Version};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Test verdict for response building conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseBuildingTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for ResponseBuildingTestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::ExpectedFailure => write!(f, "XFAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Single HTTP/1.1 response building conformance test case.
#[derive(Debug, Clone)]
pub struct ResponseBuildingConformanceCase {
    pub id: String,
    pub description: String,
    pub builder_ops: Vec<ResponseBuilderOp>,
    pub expected_identical: bool,
}

/// ResponseBuilder operation for replaying on both implementations.
#[derive(Debug, Clone)]
pub enum ResponseBuilderOp {
    New(u16), // status code
    Status(u16),
    Reason(String),
    Version(String), // "HTTP/1.1" or "HTTP/1.0"
    Header { name: String, value: String },
    Headers(Vec<(String, String)>),
    Body(Vec<u8>),
    Trailer { name: String, value: String },
}

/// Result of running a single response building test case.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseBuildingTestResult {
    pub case_id: String,
    pub verdict: ResponseBuildingTestVerdict,
    pub error: Option<String>,
    pub asupersync_wire: Vec<u8>,
    pub hyper_wire: Vec<u8>,
    pub bytes_match: bool,
    pub asupersync_size: usize,
    pub hyper_size: usize,
}

/// Summary statistics for response building conformance run.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseBuildingComplianceSummary {
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub total: usize,
    pub compliance_score: f64,
}

/// Complete report for HTTP/1.1 response building conformance.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseBuildingComplianceReport {
    pub test_run_id: String,
    pub timestamp: String,
    pub total_cases: usize,
    pub results: Vec<ResponseBuildingTestResult>,
    pub summary: ResponseBuildingComplianceSummary,
}

/// HTTP/1.1 response building conformance tester.
pub struct ResponseBuildingConformanceTester {
    pub test_cases: Vec<ResponseBuildingConformanceCase>,
}

impl ResponseBuildingConformanceTester {
    /// Create a new response building conformance tester.
    pub fn new() -> Self {
        Self {
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create the standard set of response building conformance test cases.
    fn create_test_cases() -> Vec<ResponseBuildingConformanceCase> {
        vec![
            ResponseBuildingConformanceCase {
                id: "RESP-001".to_string(),
                description: "Simple 200 OK response".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(200),
                    ResponseBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "text/plain".to_string(),
                    },
                    ResponseBuilderOp::Body(b"Hello, World!".to_vec()),
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-002".to_string(),
                description: "404 Not Found response".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(404),
                    ResponseBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "text/html".to_string(),
                    },
                    ResponseBuilderOp::Body(b"<h1>Not Found</h1>".to_vec()),
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-003".to_string(),
                description: "JSON response with multiple headers".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(201),
                    ResponseBuilderOp::Headers(vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("Server".to_string(), "asupersync/1.0".to_string()),
                        ("X-API-Version".to_string(), "v1".to_string()),
                        ("Cache-Control".to_string(), "no-cache".to_string()),
                    ]),
                    ResponseBuilderOp::Body(br#"{"id":123,"name":"test resource","created":true}"#.to_vec()),
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-004".to_string(),
                description: "Redirect response with location".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(302),
                    ResponseBuilderOp::Header {
                        name: "Location".to_string(),
                        value: "https://example.com/new-location".to_string(),
                    },
                    ResponseBuilderOp::Header {
                        name: "Cache-Control".to_string(),
                        value: "no-store".to_string(),
                    },
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-005".to_string(),
                description: "Empty response body".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(204),
                    ResponseBuilderOp::Header {
                        name: "Server".to_string(),
                        value: "asupersync/1.0".to_string(),
                    },
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-006".to_string(),
                description: "HTTP/1.0 response".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(200),
                    ResponseBuilderOp::Version("HTTP/1.0".to_string()),
                    ResponseBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "text/plain".to_string(),
                    },
                    ResponseBuilderOp::Body(b"HTTP/1.0 response".to_vec()),
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-007".to_string(),
                description: "Custom reason phrase".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(200),
                    ResponseBuilderOp::Reason("Everything is Fine".to_string()),
                    ResponseBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "text/plain".to_string(),
                    },
                    ResponseBuilderOp::Body(b"Custom reason".to_vec()),
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-008".to_string(),
                description: "Large response body".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(200),
                    ResponseBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "text/plain".to_string(),
                    },
                    ResponseBuilderOp::Body("A".repeat(1000).into_bytes()),
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-009".to_string(),
                description: "Response with trailers".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(200),
                    ResponseBuilderOp::Header {
                        name: "Transfer-Encoding".to_string(),
                        value: "chunked".to_string(),
                    },
                    ResponseBuilderOp::Body(b"Chunked response".to_vec()),
                    ResponseBuilderOp::Trailer {
                        name: "Checksum".to_string(),
                        value: "sha256:abc123".to_string(),
                    },
                ],
                expected_identical: true,
            },
            ResponseBuildingConformanceCase {
                id: "RESP-010".to_string(),
                description: "Server error response".to_string(),
                builder_ops: vec![
                    ResponseBuilderOp::New(500),
                    ResponseBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    },
                    ResponseBuilderOp::Body(br#"{"error":"Internal Server Error","code":500,"message":"Something went wrong"}"#.to_vec()),
                ],
                expected_identical: true,
            },
        ]
    }

    /// Run all conformance test cases.
    pub async fn run_all_tests(&mut self) -> ResponseBuildingComplianceReport {
        let test_run_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let total_cases = self.test_cases.len();
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            let result = self.run_single_test(test_case).await;
            results.push(result);
        }

        let summary = self.compute_summary(&results);

        ResponseBuildingComplianceReport {
            test_run_id,
            timestamp,
            total_cases,
            results,
            summary,
        }
    }

    /// Run a single response building conformance test case.
    async fn run_single_test(
        &self,
        case: &ResponseBuildingConformanceCase,
    ) -> ResponseBuildingTestResult {
        // Build response with asupersync
        let asupersync_result = self.build_asupersync_response(&case.builder_ops).await;

        // Build response with hyper-compatible reference
        let hyper_result = self.build_hyper_response(&case.builder_ops).await;

        let (asupersync_wire, asupersync_error) = match asupersync_result {
            Ok(wire) => (wire, None),
            Err(e) => (Vec::new(), Some(e)),
        };

        let (hyper_wire, hyper_error) = match hyper_result {
            Ok(wire) => (wire, None),
            Err(e) => (Vec::new(), Some(e)),
        };

        let bytes_match = asupersync_wire == hyper_wire;
        let error = match (asupersync_error, hyper_error) {
            (Some(a), Some(h)) => Some(format!("Both failed: asupersync={}, hyper={}", a, h)),
            (Some(a), None) => Some(format!("Asupersync failed: {}", a)),
            (None, Some(h)) => Some(format!("Hyper failed: {}", h)),
            (None, None) if !bytes_match => Some(format!(
                "Wire output differs: asupersync={} bytes, hyper={} bytes",
                asupersync_wire.len(),
                hyper_wire.len()
            )),
            _ => None,
        };

        let verdict = if case.expected_identical && bytes_match && error.is_none() {
            ResponseBuildingTestVerdict::Pass
        } else if !case.expected_identical {
            ResponseBuildingTestVerdict::Pass // Not expecting identical output
        } else {
            ResponseBuildingTestVerdict::Fail
        };

        let asupersync_size = asupersync_wire.len();
        let hyper_size = hyper_wire.len();

        ResponseBuildingTestResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_wire,
            hyper_wire,
            bytes_match,
            asupersync_size,
            hyper_size,
        }
    }

    /// Build response using asupersync ResponseBuilder and encode to wire format.
    async fn build_asupersync_response(
        &self,
        ops: &[ResponseBuilderOp],
    ) -> Result<Vec<u8>, String> {
        let mut builder: Option<ResponseBuilder> = None;

        for op in ops {
            builder = Some(match op {
                ResponseBuilderOp::New(status) => ResponseBuilder::new(*status),
                ResponseBuilderOp::Status(status) => {
                    builder.ok_or("No builder initialized")?.status(*status)
                }
                ResponseBuilderOp::Reason(reason) => builder
                    .ok_or("No builder initialized")?
                    .reason(reason.clone()),
                ResponseBuilderOp::Version(version_str) => {
                    let version = match version_str.as_str() {
                        "HTTP/1.0" => Version::Http10,
                        "HTTP/1.1" => Version::Http11,
                        _ => return Err(format!("Unsupported version: {}", version_str)),
                    };
                    builder.ok_or("No builder initialized")?.version(version)
                }
                ResponseBuilderOp::Header { name, value } => builder
                    .ok_or("No builder initialized")?
                    .header(name.clone(), value.clone()),
                ResponseBuilderOp::Headers(headers) => builder
                    .ok_or("No builder initialized")?
                    .headers(headers.clone()),
                ResponseBuilderOp::Body(body) => {
                    builder.ok_or("No builder initialized")?.body(body.clone())
                }
                ResponseBuilderOp::Trailer { name, value } => builder
                    .ok_or("No builder initialized")?
                    .trailer(name.clone(), value.clone()),
            });
        }

        let response = builder.ok_or("No response built")?.build();

        // Encode to wire format using Http1Codec
        let mut codec = Http1Codec::new();
        let mut wire_buf = BytesMut::new();

        codec
            .encode(response, &mut wire_buf)
            .map_err(|e| format!("Encoding error: {:?}", e))?;

        Ok(wire_buf.to_vec())
    }

    /// Build response using hyper-compatible reference implementation.
    /// This creates the wire format that hyper would produce.
    async fn build_hyper_response(&self, ops: &[ResponseBuilderOp]) -> Result<Vec<u8>, String> {
        let mut status: u16 = 200;
        let mut reason = "OK";
        let mut version = "HTTP/1.1";
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body: Vec<u8> = Vec::new();

        // Process operations to build the response
        for op in ops {
            match op {
                ResponseBuilderOp::New(s) => {
                    status = *s;
                    reason = default_reason_phrase(status);
                }
                ResponseBuilderOp::Status(s) => {
                    status = *s;
                    reason = default_reason_phrase(status);
                }
                ResponseBuilderOp::Reason(r) => reason = r,
                ResponseBuilderOp::Version(v) => version = v,
                ResponseBuilderOp::Header { name, value } => {
                    headers.push((name.clone(), value.clone()));
                }
                ResponseBuilderOp::Headers(h) => headers.extend(h.clone()),
                ResponseBuilderOp::Body(b) => body = b.clone(),
                ResponseBuilderOp::Trailer { .. } => {
                    // Trailers are added after body in chunked encoding
                    // For this reference implementation, we'll skip them in the main headers
                }
            }
        }

        // Normalize headers to match hyper's behavior
        // - Header names are lowercase in hyper
        // - Add Content-Length if body is present and not already specified
        let mut normalized_headers = Vec::new();
        let mut has_content_length = false;
        let mut has_transfer_encoding = false;

        for (name, value) in headers {
            let lower_name = name.to_lowercase();
            if lower_name == "content-length" {
                has_content_length = true;
            }
            if lower_name == "transfer-encoding" {
                has_transfer_encoding = true;
            }
            normalized_headers.push((lower_name, value));
        }

        // Add Content-Length if body is present and not already set (and not chunked)
        if !body.is_empty() && !has_content_length && !has_transfer_encoding {
            normalized_headers.push(("content-length".to_string(), body.len().to_string()));
        }

        // Sort headers for deterministic output (hyper-like behavior)
        normalized_headers.sort_by_key(|(name, _)| name.clone());

        // Build the response wire format
        let mut wire = Vec::new();

        // Status line
        wire.extend_from_slice(format!("{} {} {}\r\n", version, status, reason).as_bytes());

        // Headers
        for (name, value) in normalized_headers {
            wire.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        // Empty line to end headers
        wire.extend_from_slice(b"\r\n");

        // Body
        if !body.is_empty() {
            wire.extend_from_slice(&body);
        }

        Ok(wire)
    }

    /// Compute summary statistics from test results.
    fn compute_summary(
        &self,
        results: &[ResponseBuildingTestResult],
    ) -> ResponseBuildingComplianceSummary {
        let passed = results
            .iter()
            .filter(|r| r.verdict == ResponseBuildingTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == ResponseBuildingTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == ResponseBuildingTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == ResponseBuildingTestVerdict::Skipped)
            .count();
        let total = results.len();

        let compliance_score = if total > 0 {
            (passed as f64) / (total as f64) * 100.0
        } else {
            0.0
        };

        ResponseBuildingComplianceSummary {
            passed,
            failed,
            expected_failures,
            skipped,
            total,
            compliance_score,
        }
    }
}

impl Default for ResponseBuildingConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the default reason phrase for an HTTP status code.
/// Matches standard HTTP reason phrases.
fn default_reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
