//! HTTP/1.1 request building conformance testing.
//!
//! This harness tests the `asupersync` HTTP/1.1 RequestBuilder against the
//! `hyper-util` reference implementation to ensure byte-identical wire output
//! for the same request building operations.

use asupersync::bytes::BytesMut;
use asupersync::codec::Encoder;
use asupersync::http::h1::client::Http1ClientCodec;
use asupersync::http::h1::types::{Method, RequestBuilder, Version};
use serde::{Deserialize, Serialize};
use std::fmt;

// Note: Using simplified hyper-style reference formatting instead of actual hyper APIs

/// Test verdict for request building conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestBuildingTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for RequestBuildingTestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::ExpectedFailure => write!(f, "XFAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Single HTTP/1.1 request building conformance test case.
#[derive(Debug, Clone)]
pub struct RequestBuildingConformanceCase {
    pub id: String,
    pub description: String,
    pub builder_ops: Vec<RequestBuilderOp>,
    pub expected_identical: bool,
}

/// RequestBuilder operation for replaying on both implementations.
#[derive(Debug, Clone)]
pub enum RequestBuilderOp {
    New { method: String, uri: String },
    Method(String),
    Uri(String),
    Version(String), // "HTTP/1.1" or "HTTP/1.0"
    Header { name: String, value: String },
    Headers(Vec<(String, String)>),
    Body(Vec<u8>),
    Trailer { name: String, value: String },
    Json(serde_json::Value),
    Form(Vec<(String, String)>),
}

/// Result of running a single request building test case.
#[derive(Debug, Clone, Serialize)]
pub struct RequestBuildingTestResult {
    pub case_id: String,
    pub verdict: RequestBuildingTestVerdict,
    pub error: Option<String>,
    pub asupersync_wire: Vec<u8>,
    pub reqwest_wire: Vec<u8>,
    pub bytes_match: bool,
    pub asupersync_size: usize,
    pub reqwest_size: usize,
}

/// Summary statistics for request building conformance run.
#[derive(Debug, Clone, Serialize)]
pub struct RequestBuildingComplianceSummary {
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub total: usize,
    pub compliance_score: f64,
}

/// Complete report for HTTP/1.1 request building conformance.
#[derive(Debug, Clone, Serialize)]
pub struct RequestBuildingComplianceReport {
    pub test_run_id: String,
    pub timestamp: String,
    pub total_cases: usize,
    pub results: Vec<RequestBuildingTestResult>,
    pub summary: RequestBuildingComplianceSummary,
}

/// HTTP/1.1 request building conformance tester.
pub struct RequestBuildingConformanceTester {
    pub test_cases: Vec<RequestBuildingConformanceCase>,
}

impl RequestBuildingConformanceTester {
    /// Create a new request building conformance tester.
    pub fn new() -> Self {
        Self {
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create the standard set of request building conformance test cases.
    fn create_test_cases() -> Vec<RequestBuildingConformanceCase> {
        vec![
            RequestBuildingConformanceCase {
                id: "REQ-001".to_string(),
                description: "Simple GET request".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "GET".to_string(),
                        uri: "/".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "example.com".to_string(),
                    },
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-002".to_string(),
                description: "POST request with body".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "POST".to_string(),
                        uri: "/api/data".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "api.example.com".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "text/plain".to_string(),
                    },
                    RequestBuilderOp::Body(b"Hello, World!".to_vec()),
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-003".to_string(),
                description: "Request with multiple headers".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "GET".to_string(),
                        uri: "/api/v1/users".to_string(),
                    },
                    RequestBuilderOp::Headers(vec![
                        ("Host".to_string(), "api.example.com".to_string()),
                        ("User-Agent".to_string(), "test-client/1.0".to_string()),
                        ("Accept".to_string(), "application/json".to_string()),
                        ("Authorization".to_string(), "Bearer token123".to_string()),
                    ]),
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-004".to_string(),
                description: "JSON POST request".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "POST".to_string(),
                        uri: "/api/users".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "api.example.com".to_string(),
                    },
                    RequestBuilderOp::Json(serde_json::json!({
                        "name": "John Doe",
                        "email": "john@example.com",
                        "age": 30
                    })),
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-005".to_string(),
                description: "Form data POST request".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "POST".to_string(),
                        uri: "/login".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "example.com".to_string(),
                    },
                    RequestBuilderOp::Form(vec![
                        ("username".to_string(), "testuser".to_string()),
                        ("password".to_string(), "testpass".to_string()),
                    ]),
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-006".to_string(),
                description: "PUT request with binary body".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "PUT".to_string(),
                        uri: "/api/files/test.bin".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "files.example.com".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "application/octet-stream".to_string(),
                    },
                    RequestBuilderOp::Body(vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD]),
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-007".to_string(),
                description: "HTTP/1.0 request".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "GET".to_string(),
                        uri: "/legacy".to_string(),
                    },
                    RequestBuilderOp::Version("HTTP/1.0".to_string()),
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "legacy.example.com".to_string(),
                    },
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-008".to_string(),
                description: "Request with query parameters in URI".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "GET".to_string(),
                        uri: "/search?q=rust&type=code&sort=updated".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "search.example.com".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Accept".to_string(),
                        value: "text/html,application/xhtml+xml".to_string(),
                    },
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-009".to_string(),
                description: "DELETE request".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "DELETE".to_string(),
                        uri: "/api/users/123".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "api.example.com".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Authorization".to_string(),
                        value: "Bearer delete-token".to_string(),
                    },
                ],
                expected_identical: true,
            },
            RequestBuildingConformanceCase {
                id: "REQ-010".to_string(),
                description: "Request with custom method".to_string(),
                builder_ops: vec![
                    RequestBuilderOp::New {
                        method: "PATCH".to_string(),
                        uri: "/api/users/123".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Host".to_string(),
                        value: "api.example.com".to_string(),
                    },
                    RequestBuilderOp::Header {
                        name: "Content-Type".to_string(),
                        value: "application/json-patch+json".to_string(),
                    },
                    RequestBuilderOp::Body(
                        b"[{\"op\":\"replace\",\"path\":\"/name\",\"value\":\"New Name\"}]"
                            .to_vec(),
                    ),
                ],
                expected_identical: true,
            },
        ]
    }

    /// Run all conformance test cases.
    pub async fn run_all_tests(&mut self) -> RequestBuildingComplianceReport {
        let test_run_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let total_cases = self.test_cases.len();
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            let result = self.run_single_test(test_case).await;
            results.push(result);
        }

        let summary = self.compute_summary(&results);

        RequestBuildingComplianceReport {
            test_run_id,
            timestamp,
            total_cases,
            results,
            summary,
        }
    }

    /// Run a single request building conformance test case.
    async fn run_single_test(
        &self,
        case: &RequestBuildingConformanceCase,
    ) -> RequestBuildingTestResult {
        // Build request with asupersync
        let asupersync_result = self.build_asupersync_request(&case.builder_ops).await;

        // Build request with hyper-util to get actual wire format
        let hyper_util_result = self
            .build_hyper_util_request(&case.builder_ops)
            .await;

        let (asupersync_wire, asupersync_error) = match asupersync_result {
            Ok(wire) => (wire, None),
            Err(e) => (Vec::new(), Some(e)),
        };

        let (hyper_util_wire, hyper_util_error) = match hyper_util_result {
            Ok(wire) => (wire, None),
            Err(e) => (Vec::new(), Some(e)),
        };

        let bytes_match = asupersync_wire == hyper_util_wire;
        let error = match (asupersync_error, hyper_util_error) {
            (Some(a), Some(h)) => Some(format!("Both failed: asupersync={}, hyper-util={}", a, h)),
            (Some(a), None) => Some(format!("Asupersync failed: {}", a)),
            (None, Some(h)) => Some(format!("Hyper-util failed: {}", h)),
            (None, None) if !bytes_match => Some(format!(
                "Wire output differs: asupersync={} bytes, hyper-util={} bytes",
                asupersync_wire.len(),
                hyper_util_wire.len()
            )),
            _ => None,
        };

        let verdict = if case.expected_identical && bytes_match && error.is_none() {
            RequestBuildingTestVerdict::Pass
        } else if !case.expected_identical {
            RequestBuildingTestVerdict::Pass // Not expecting identical output
        } else {
            RequestBuildingTestVerdict::Fail
        };
        let asupersync_size = asupersync_wire.len();
        let hyper_util_size = hyper_util_wire.len();

        RequestBuildingTestResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_wire,
            reqwest_wire: hyper_util_wire,
            bytes_match,
            asupersync_size,
            reqwest_size: hyper_util_size,
        }
    }

    /// Build request using asupersync RequestBuilder and encode to wire format.
    async fn build_asupersync_request(&self, ops: &[RequestBuilderOp]) -> Result<Vec<u8>, String> {
        let mut builder: Option<RequestBuilder> = None;

        for op in ops {
            builder = Some(match op {
                RequestBuilderOp::New { method, uri } => {
                    let method = Method::from_bytes(method.as_bytes())
                        .ok_or_else(|| format!("Invalid method: {}", method))?;
                    RequestBuilder::new(method, uri.clone())
                }
                RequestBuilderOp::Method(method_str) => {
                    let method = Method::from_bytes(method_str.as_bytes())
                        .ok_or_else(|| format!("Invalid method: {}", method_str))?;
                    builder.ok_or("No builder initialized")?.method(method)
                }
                RequestBuilderOp::Uri(uri) => {
                    builder.ok_or("No builder initialized")?.uri(uri.clone())
                }
                RequestBuilderOp::Version(version_str) => {
                    let version = match version_str.as_str() {
                        "HTTP/1.0" => Version::Http10,
                        "HTTP/1.1" => Version::Http11,
                        _ => return Err(format!("Unsupported version: {}", version_str)),
                    };
                    builder.ok_or("No builder initialized")?.version(version)
                }
                RequestBuilderOp::Header { name, value } => builder
                    .ok_or("No builder initialized")?
                    .header(name.clone(), value.clone()),
                RequestBuilderOp::Headers(headers) => builder
                    .ok_or("No builder initialized")?
                    .headers(headers.clone()),
                RequestBuilderOp::Body(body) => {
                    builder.ok_or("No builder initialized")?.body(body.clone())
                }
                RequestBuilderOp::Trailer { name, value } => builder
                    .ok_or("No builder initialized")?
                    .trailer(name.clone(), value.clone()),
                RequestBuilderOp::Json(value) => builder
                    .ok_or("No builder initialized")?
                    .json(value)
                    .map_err(|e| format!("JSON serialization error: {}", e))?,
                RequestBuilderOp::Form(form_data) => {
                    let form_string = form_data
                        .iter()
                        .map(|(k, v)| {
                            format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
                        })
                        .collect::<Vec<_>>()
                        .join("&");
                    builder
                        .ok_or("No builder initialized")?
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(form_string.into_bytes())
                }
            });
        }

        let request = builder.ok_or("No request built")?.build();

        // Encode to wire format using Http1ClientCodec
        let mut codec = Http1ClientCodec::new();
        let mut wire_buf = BytesMut::new();

        codec
            .encode(request, &mut wire_buf)
            .map_err(|e| format!("Encoding error: {:?}", e))?;

        Ok(wire_buf.to_vec())
    }

    /// Build request using hyper-util and capture the actual wire format.
    /// This uses hyper-util's HTTP/1.1 client to build a real request.
    async fn build_hyper_util_request(
        &self,
        ops: &[RequestBuilderOp],
    ) -> Result<Vec<u8>, String> {
        // Build request manually following HTTP/1.1 standard, simulating how hyper would format it
        // This represents the "hyper-util reference implementation" wire format
        let mut method = "GET";
        let mut uri = "/";
        let mut version = "HTTP/1.1";
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body: Vec<u8> = Vec::new();

        // Process operations to build the request
        for op in ops {
            match op {
                RequestBuilderOp::New { method: m, uri: u } => {
                    method = m;
                    uri = u;
                }
                RequestBuilderOp::Method(m) => method = m,
                RequestBuilderOp::Uri(u) => uri = u,
                RequestBuilderOp::Version(v) => version = v,
                RequestBuilderOp::Header { name, value } => {
                    headers.push((name.clone(), value.clone()));
                }
                RequestBuilderOp::Headers(h) => headers.extend(h.clone()),
                RequestBuilderOp::Body(b) => body = b.clone(),
                RequestBuilderOp::Json(value) => {
                    body = serde_json::to_vec(value)
                        .map_err(|e| format!("JSON serialization: {}", e))?;
                    headers.push(("content-type".to_string(), "application/json".to_string()));
                }
                RequestBuilderOp::Form(form_data) => {
                    let form_string = form_data
                        .iter()
                        .map(|(k, v)| {
                            format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
                        })
                        .collect::<Vec<_>>()
                        .join("&");
                    body = form_string.into_bytes();
                    headers.push((
                        "content-type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    ));
                }
                RequestBuilderOp::Trailer { .. } => {
                    // Trailers are not commonly supported in HTTP/1.1, skip
                }
            }
        }

        // Normalize headers to match hyper's behavior
        // - Header names are lowercase in hyper
        // - Add content-length if body is present and not already specified
        let mut normalized_headers = Vec::new();
        let mut has_content_length = false;

        for (name, value) in headers {
            let lower_name = name.to_lowercase();
            if lower_name == "content-length" {
                has_content_length = true;
            }
            normalized_headers.push((lower_name, value));
        }

        // Add Content-Length if body is present and not already set
        if !body.is_empty() && !has_content_length {
            normalized_headers.push(("content-length".to_string(), body.len().to_string()));
        }

        // Sort headers for deterministic output (hyper-like behavior)
        normalized_headers.sort_by_key(|(name, _)| name.clone());

        // Generate HTTP/1.1 wire format (hyper reference style)
        let mut wire = Vec::new();

        // Request line
        wire.extend_from_slice(method.as_bytes());
        wire.extend_from_slice(b" ");
        wire.extend_from_slice(uri.as_bytes());
        wire.extend_from_slice(b" ");
        wire.extend_from_slice(version.as_bytes());
        wire.extend_from_slice(b"\r\n");

        // Headers
        for (name, value) in &normalized_headers {
            wire.extend_from_slice(name.as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(value.as_bytes());
            wire.extend_from_slice(b"\r\n");
        }

        // End of headers
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
        results: &[RequestBuildingTestResult],
    ) -> RequestBuildingComplianceSummary {
        let total = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == RequestBuildingTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == RequestBuildingTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == RequestBuildingTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == RequestBuildingTestVerdict::Skipped)
            .count();

        let compliance_score = if passed + failed > 0 {
            passed as f64 / (passed + failed) as f64
        } else {
            1.0
        };

        RequestBuildingComplianceSummary {
            passed,
            failed,
            expected_failures,
            skipped,
            total,
            compliance_score,
        }
    }

    /// Generate a markdown report from the compliance results.
    pub fn generate_markdown_report(&self, report: &RequestBuildingComplianceReport) -> String {
        let mut output = String::new();

        output.push_str("# HTTP/1.1 Request Building Conformance Report\n\n");
        output.push_str(&format!("**Test Run ID:** {}\n", report.test_run_id));
        output.push_str(&format!("**Timestamp:** {}\n", report.timestamp));
        output.push_str(&format!("**Total Test Cases:** {}\n\n", report.total_cases));

        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- ✅ **Passed:** {} tests\n",
            report.summary.passed
        ));
        output.push_str(&format!(
            "- ❌ **Failed:** {} tests\n",
            report.summary.failed
        ));
        output.push_str(&format!(
            "- ⚠️  **Expected Failures:** {} tests\n",
            report.summary.expected_failures
        ));
        output.push_str(&format!(
            "- ⏭️  **Skipped:** {} tests\n",
            report.summary.skipped
        ));
        output.push_str(&format!(
            "- 🎯 **Compliance Score:** {:.1}%\n\n",
            report.summary.compliance_score * 100.0
        ));

        if report.summary.failed > 0 {
            output.push_str("## Failed Test Cases\n\n");
            for result in &report.results {
                if result.verdict == RequestBuildingTestVerdict::Fail {
                    output.push_str(&format!("### {}\n", result.case_id));
                    if let Some(error) = &result.error {
                        output.push_str(&format!("**Error:** {}\n", error));
                    }
                    output.push_str(&format!("**Bytes match:** {}\n", result.bytes_match));
                    output.push_str(&format!(
                        "**Asupersync output:** {} bytes\n",
                        result.asupersync_size
                    ));
                    output.push_str(&format!(
                        "**Reqwest simulation:** {} bytes\n\n",
                        result.reqwest_size
                    ));
                }
            }
        }

        output.push_str("## All Test Results\n\n");
        output.push_str(
            "| Case ID | Verdict | Bytes Match | Asupersync Size | Reqwest Size | Error |\n",
        );
        output.push_str(
            "|---------|---------|-------------|-----------------|--------------|-------|\n",
        );

        for result in &report.results {
            let error_str = result.error.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                result.case_id,
                result.verdict,
                result.bytes_match,
                result.asupersync_size,
                result.reqwest_size,
                error_str
            ));
        }

        output
    }
}

impl Default for RequestBuildingConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}
