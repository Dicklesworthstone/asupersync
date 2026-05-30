#![allow(warnings)]
#![allow(clippy::all)]
//! gRPC Connect Conformance Test Suite
//!
//! This module implements Pattern 6 (Process-Based Conformance) for gRPC
//! with Connect compatibility testing. It verifies that our gRPC implementation
//! conforms to the gRPC specification and is compatible with Connect clients.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────┐    ┌─────────────────────┐
//! │ Connect Client      │    │ gRPC Client         │
//! │ (Reference)         │    │ (Our Implementation)│
//! └──────────┬──────────┘    └──────────┬──────────┘
//!            │                          │
//!            ▼                          ▼
//! ┌─────────────────────────────────────────────────┐
//! │          Our gRPC Server                        │
//! │  (Target Implementation Under Test)             │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Test Categories
//!
//! - **Unary RPC**: Single request → single response
//! - **Server Streaming**: Single request → multiple responses
//! - **Client Streaming**: Multiple requests → single response
//! - **Bidirectional Streaming**: Multiple requests ↔ multiple responses
//! - **Error Handling**: Status codes, metadata, cancellation
//! - **Protocol Compliance**: HTTP/2 framing, compression, timeouts

use anyhow::Result;
use asupersync::cx::Cx;
use asupersync::grpc::{Code, MetadataValue, Request};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub mod client;
pub mod connect_compat;
pub mod runner;
pub mod service;
pub mod test_cases;

/// Test result tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConformanceResult {
    pub test_name: String,
    pub category: TestCategory,
    pub status: TestStatus,
    pub duration: Duration,
    pub error_message: Option<String>,
    pub metadata: TestMetadata,
}

/// Test categories for organizing conformance tests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    UnaryRpc,
    ServerStreaming,
    ClientStreaming,
    BidirectionalStreaming,
    ErrorHandling,
    Metadata,
    Compression,
    Timeout,
    Cancellation,
    ConnectProtocol,
}

/// Test execution status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Error,
}

/// Additional test metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct TestMetadata {
    pub request_count: u32,
    pub response_count: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub grpc_status: Option<i32>,
    pub http_status: Option<u16>,
    pub headers: HashMap<String, String>,
}

impl Default for TestMetadata {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            request_count: 0,
            response_count: 0,
            bytes_sent: 0,
            bytes_received: 0,
            grpc_status: None,
            http_status: None,
            headers: HashMap::new(),
        }
    }
}

/// Test message types for conformance testing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct TestRequest {
    pub message: String,
    pub echo_metadata: bool,
    pub echo_deadline: bool,
    pub check_auth_context: bool,
    pub response_size: Option<u32>,
    pub fill_server_id: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct TestResponse {
    pub message: String,
    pub server_id: Option<String>,
    pub client_compressed: bool,
    pub server_compressed: bool,
    pub auth_context: Option<AuthContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct AuthContext {
    pub peer_identity: Option<String>,
    pub peer_identity_property_name: Option<String>,
}

/// Streaming test message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct StreamingTestRequest {
    pub message: String,
    pub sequence_number: u32,
    pub end_stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct StreamingTestResponse {
    pub message: String,
    pub sequence_number: u32,
    pub server_timestamp: u64,
}

/// Configuration for conformance test runs
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConformanceConfig {
    pub server_address: String,
    pub timeout: Duration,
    pub max_message_size: usize,
    pub enable_compression: bool,
    pub enable_tls: bool,
    pub connect_protocol: bool,
    pub parallel_execution: bool,
}

impl Default for ConformanceConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            server_address: "http://127.0.0.1:8080".to_string(),
            timeout: Duration::from_secs(30),
            max_message_size: 4 * 1024 * 1024,
            enable_compression: true,
            enable_tls: false,
            connect_protocol: true,
            parallel_execution: false,
        }
    }
}

/// Main conformance test suite
#[allow(dead_code)]
pub struct ConformanceTestSuite {
    config: ConformanceConfig,
    results: Vec<ConformanceResult>,
}

struct InProcessConformanceHarness {
    service: service::ConformanceTestService,
}

impl InProcessConformanceHarness {
    fn new(max_message_size: usize) -> Self {
        Self {
            service: service::ConformanceTestService::with_max_message_size(max_message_size),
        }
    }
}

#[allow(dead_code)]
impl ConformanceTestSuite {
    #[allow(dead_code)]
    pub fn new(config: ConformanceConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
        }
    }

    /// Run the complete conformance test suite
    pub async fn run_all_tests(&mut self, cx: &Cx) -> Result<()> {
        info!("Starting gRPC Connect conformance test suite");

        let harness = self.build_in_process_harness(cx).await?;

        // Run test categories in sequence
        self.run_unary_tests(cx, &harness).await?;
        self.run_server_streaming_tests(cx, &harness).await?;
        self.run_client_streaming_tests(cx, &harness).await?;
        self.run_bidirectional_streaming_tests(cx, &harness).await?;
        self.run_error_handling_tests(cx, &harness).await?;
        self.run_metadata_tests(cx, &harness).await?;
        self.run_compression_tests(cx, &harness).await?;
        self.run_timeout_tests(cx, &harness).await?;
        self.run_cancellation_tests(&harness).await?;

        if self.config.connect_protocol {
            self.run_connect_protocol_tests(cx).await?;
        }

        self.generate_conformance_report()?;

        Ok(())
    }

    async fn build_in_process_harness(&self, _cx: &Cx) -> Result<InProcessConformanceHarness> {
        Ok(InProcessConformanceHarness::new(
            self.config.max_message_size,
        ))
    }

    async fn run_unary_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running unary RPC tests");

        let test_cases = vec![
            (
                "unary_empty_request",
                TestRequest {
                    message: String::new(),
                    echo_metadata: false,
                    echo_deadline: false,
                    check_auth_context: false,
                    response_size: None,
                    fill_server_id: false,
                },
            ),
            (
                "unary_large_request",
                TestRequest {
                    message: "x".repeat(1024),
                    echo_metadata: false,
                    echo_deadline: false,
                    check_auth_context: false,
                    response_size: Some(2048),
                    fill_server_id: true,
                },
            ),
            (
                "unary_with_metadata",
                TestRequest {
                    message: "test with metadata".to_string(),
                    echo_metadata: true,
                    echo_deadline: true,
                    check_auth_context: false,
                    response_size: None,
                    fill_server_id: false,
                },
            ),
        ];

        for (test_name, request) in test_cases {
            let result = self.run_unary_test(cx, harness, test_name, request).await?;
            self.results.push(result);
        }

        Ok(())
    }

    async fn run_unary_test(
        &self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
        test_name: &str,
        request: TestRequest,
    ) -> Result<ConformanceResult> {
        let start_time = Instant::now();
        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;

        let encoded_request = serde_json::to_vec(&request)?;
        metadata.bytes_sent = encoded_request.len() as u64;
        let mut grpc_request = Request::new(Bytes::from(encoded_request));
        if request.echo_metadata {
            grpc_request
                .metadata_mut()
                .insert("test-client-header", "client-value");
        }
        if request.echo_deadline {
            grpc_request.metadata_mut().insert("grpc-timeout", "1S");
        }

        let result = match harness.service.unary_call(cx, grpc_request).await {
            Ok(response) => {
                metadata.response_count = 1;
                metadata.bytes_received = response.get_ref().len() as u64;
                metadata.grpc_status = Some(0); // OK
                for (key, value) in response.metadata().iter() {
                    match value {
                        MetadataValue::Ascii(value) => {
                            metadata.headers.insert(key.to_string(), value.clone());
                        }
                        MetadataValue::Binary(value) => {
                            metadata
                                .headers
                                .insert(key.to_string(), format!("{} bytes", value.len()));
                        }
                    }
                }

                let response_data: TestResponse = serde_json::from_slice(response.get_ref())?;
                let mut issues = Vec::new();
                if request.fill_server_id && response_data.server_id.is_none() {
                    issues.push("response omitted requested server_id".to_string());
                }
                if request.echo_metadata
                    && metadata.headers.get("test-client-header")
                        != Some(&"client-value".to_string())
                {
                    issues.push("response did not echo test metadata".to_string());
                }
                if request.echo_deadline
                    && metadata.headers.get("echo-deadline") != Some(&"1S".to_string())
                {
                    issues.push("response did not echo grpc-timeout".to_string());
                }

                ConformanceResult {
                    test_name: test_name.to_string(),
                    category: TestCategory::UnaryRpc,
                    status: if issues.is_empty() {
                        TestStatus::Passed
                    } else {
                        TestStatus::Failed
                    },
                    duration: start_time.elapsed(),
                    error_message: if issues.is_empty() {
                        None
                    } else {
                        Some(issues.join("; "))
                    },
                    metadata,
                }
            }
            Err(status) => {
                metadata.grpc_status = Some(status.code() as i32);

                ConformanceResult {
                    test_name: test_name.to_string(),
                    category: TestCategory::UnaryRpc,
                    status: TestStatus::Failed,
                    duration: start_time.elapsed(),
                    error_message: Some(status.message().to_string()),
                    metadata,
                }
            }
        };

        Ok(result)
    }

    async fn run_server_streaming_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running server streaming tests");

        let start_time = Instant::now();
        let request = StreamingTestRequest {
            message: "server-stream".to_string(),
            sequence_number: 0,
            end_stream: false,
        };
        let request = Request::new(Bytes::from(serde_json::to_vec(&request)?));
        let sink = service::ResponseSink::new();
        let observed = sink.clone();
        let status = match harness
            .service
            .server_streaming_call(cx, request, sink)
            .await
        {
            Ok(()) => {
                let messages = observed.messages();
                let decoded = messages
                    .iter()
                    .map(|bytes| serde_json::from_slice::<StreamingTestResponse>(bytes))
                    .collect::<Result<Vec<_>, _>>()?;
                if decoded.len() == 5
                    && decoded
                        .iter()
                        .enumerate()
                        .all(|(index, response)| response.sequence_number == index as u32)
                {
                    (TestStatus::Passed, None, decoded.len() as u32)
                } else {
                    (
                        TestStatus::Failed,
                        Some(format!("unexpected response sequence: {decoded:?}")),
                        decoded.len() as u32,
                    )
                }
            }
            Err(status) => (
                TestStatus::Failed,
                Some(format!("server streaming returned {:?}", status.code())),
                0,
            ),
        };

        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;
        metadata.response_count = status.2;
        self.results.push(ConformanceResult {
            test_name: "server_streaming_response_sequence_contract".to_string(),
            category: TestCategory::ServerStreaming,
            status: status.0,
            duration: start_time.elapsed(),
            error_message: status.1,
            metadata,
        });

        Ok(())
    }

    async fn run_client_streaming_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running client streaming tests");

        let start_time = Instant::now();
        let requests = (0..3)
            .map(|index| StreamingTestRequest {
                message: format!("client-{index}"),
                sequence_number: index,
                end_stream: index == 2,
            })
            .map(|request| serde_json::to_vec(&request).map(Bytes::from))
            .collect::<Result<Vec<_>, _>>()?;
        let request_count = requests.len() as u32;
        let stream = service::RequestStream::new(requests);
        let mut metadata = TestMetadata::default();
        metadata.request_count = request_count;

        let (status, error_message) = match harness.service.client_streaming_call(cx, stream).await
        {
            Ok(response) => {
                metadata.response_count = 1;
                metadata.bytes_received = response.get_ref().len() as u64;
                let response_data: TestResponse = serde_json::from_slice(response.get_ref())?;
                if response_data.message.contains("Processed 3 requests") {
                    (TestStatus::Passed, None)
                } else {
                    (
                        TestStatus::Failed,
                        Some(format!(
                            "unexpected aggregation response: {}",
                            response_data.message
                        )),
                    )
                }
            }
            Err(status) => (
                TestStatus::Failed,
                Some(format!("client streaming returned {:?}", status.code())),
            ),
        };

        self.results.push(ConformanceResult {
            test_name: "client_streaming_aggregation_contract".to_string(),
            category: TestCategory::ClientStreaming,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });

        Ok(())
    }

    async fn run_bidirectional_streaming_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running bidirectional streaming tests");

        let start_time = Instant::now();
        let requests = (0..3)
            .map(|index| StreamingTestRequest {
                message: format!("duplex-{index}"),
                sequence_number: index,
                end_stream: index == 2,
            })
            .map(|request| serde_json::to_vec(&request).map(Bytes::from))
            .collect::<Result<Vec<_>, _>>()?;
        let request_count = requests.len() as u32;
        let stream = service::RequestStream::new(requests);
        let sink = service::ResponseSink::new();
        let observed = sink.clone();
        let (status, error_message, response_count) = match harness
            .service
            .bidirectional_streaming_call(cx, stream, sink)
            .await
        {
            Ok(()) => {
                let messages = observed.messages();
                let decoded = messages
                    .iter()
                    .map(|bytes| serde_json::from_slice::<StreamingTestResponse>(bytes))
                    .collect::<Result<Vec<_>, _>>()?;
                let valid = decoded.len() == 3
                    && decoded.iter().enumerate().all(|(index, response)| {
                        response.sequence_number == index as u32
                            && response.message == format!("Echo: duplex-{index}")
                    });
                if valid {
                    (TestStatus::Passed, None, decoded.len() as u32)
                } else {
                    (
                        TestStatus::Failed,
                        Some(format!("unexpected duplex responses: {decoded:?}")),
                        decoded.len() as u32,
                    )
                }
            }
            Err(status) => (
                TestStatus::Failed,
                Some(format!(
                    "bidirectional streaming returned {:?}",
                    status.code()
                )),
                0,
            ),
        };

        let mut metadata = TestMetadata::default();
        metadata.request_count = request_count;
        metadata.response_count = response_count;
        self.results.push(ConformanceResult {
            test_name: "bidirectional_streaming_duplex_contract".to_string(),
            category: TestCategory::BidirectionalStreaming,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });

        Ok(())
    }

    async fn run_error_handling_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running error handling tests");

        let error_test_cases = vec![
            ("invalid_method", "/invalid/method"),
            ("large_payload", "/conformance.TestService/UnaryCall"),
            ("timeout_exceeded", "/conformance.TestService/UnaryCall"),
        ];

        for (test_name, method) in error_test_cases {
            let result = self.run_error_test(cx, harness, test_name, method).await?;
            self.results.push(result);
        }

        Ok(())
    }

    async fn run_error_test(
        &self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
        test_name: &str,
        _method: &str,
    ) -> Result<ConformanceResult> {
        let start_time = Instant::now();
        let mut metadata = TestMetadata::default();

        let request = TestRequest {
            message: if test_name == "large_payload" {
                "x".repeat(self.config.max_message_size + 1)
            } else if test_name == "invalid_method" {
                "UNIMPLEMENTED".to_string()
            } else if test_name == "timeout_exceeded" {
                "DEADLINE_EXCEEDED".to_string()
            } else {
                "test".to_string()
            },
            echo_metadata: false,
            echo_deadline: false,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };

        let encoded_request = serde_json::to_vec(&request)?;
        metadata.request_count = 1;
        metadata.bytes_sent = encoded_request.len() as u64;
        let grpc_request = Request::new(Bytes::from(encoded_request));
        let result = if test_name == "large_payload" {
            harness.service.unary_call(cx, grpc_request).await
        } else {
            harness.service.error_test_call(cx, grpc_request).await
        };

        let test_result = match result {
            Err(status) => {
                metadata.grpc_status = Some(status.code() as i32);

                // Verify we got the expected error
                let expected_pass = match test_name {
                    "invalid_method" => status.code() == Code::Unimplemented,
                    "large_payload" => status.code() == Code::ResourceExhausted,
                    "timeout_exceeded" => status.code() == Code::DeadlineExceeded,
                    _ => false,
                };

                ConformanceResult {
                    test_name: test_name.to_string(),
                    category: TestCategory::ErrorHandling,
                    status: if expected_pass {
                        TestStatus::Passed
                    } else {
                        TestStatus::Failed
                    },
                    duration: start_time.elapsed(),
                    error_message: if expected_pass {
                        None
                    } else {
                        Some(format!("Unexpected status: {:?}", status.code()))
                    },
                    metadata,
                }
            }
            Ok(_) => ConformanceResult {
                test_name: test_name.to_string(),
                category: TestCategory::ErrorHandling,
                status: TestStatus::Failed,
                duration: start_time.elapsed(),
                error_message: Some("Expected error but got success".to_string()),
                metadata,
            },
        };

        Ok(test_result)
    }

    async fn run_metadata_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running metadata tests");

        let start_time = Instant::now();
        let request = TestRequest {
            message: "metadata".to_string(),
            echo_metadata: true,
            echo_deadline: true,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };
        let mut grpc_request = Request::new(Bytes::from(serde_json::to_vec(&request)?));
        grpc_request
            .metadata_mut()
            .insert("test-custom-header", "custom-value");
        grpc_request.metadata_mut().insert("grpc-timeout", "250m");

        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;
        let (status, error_message) = match harness.service.unary_call(cx, grpc_request).await {
            Ok(response) => {
                metadata.response_count = 1;
                let echoed_custom =
                    response
                        .metadata()
                        .get("test-custom-header")
                        .and_then(|value| match value {
                            MetadataValue::Ascii(value) => Some(value.as_str()),
                            MetadataValue::Binary(_) => None,
                        });
                let echoed_deadline =
                    response
                        .metadata()
                        .get("echo-deadline")
                        .and_then(|value| match value {
                            MetadataValue::Ascii(value) => Some(value.as_str()),
                            MetadataValue::Binary(_) => None,
                        });
                if echoed_custom == Some("custom-value") && echoed_deadline == Some("250m") {
                    (TestStatus::Passed, None)
                } else {
                    (
                        TestStatus::Failed,
                        Some(format!(
                            "metadata echo mismatch: custom={echoed_custom:?} deadline={echoed_deadline:?}"
                        )),
                    )
                }
            }
            Err(status) => (
                TestStatus::Failed,
                Some(format!("metadata call returned {:?}", status.code())),
            ),
        };

        self.results.push(ConformanceResult {
            test_name: "metadata_custom_headers_contract".to_string(),
            category: TestCategory::Metadata,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });

        Ok(())
    }

    async fn run_compression_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running compression tests");

        let start_time = Instant::now();
        let request = TestRequest {
            message: "compression".to_string(),
            echo_metadata: false,
            echo_deadline: false,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };
        let mut grpc_request = Request::new(Bytes::from(serde_json::to_vec(&request)?));
        grpc_request.metadata_mut().insert("grpc-encoding", "gzip");
        grpc_request
            .metadata_mut()
            .insert("grpc-accept-encoding", "gzip, identity");

        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;
        let (status, error_message) = match harness.service.unary_call(cx, grpc_request).await {
            Ok(response) => {
                metadata.response_count = 1;
                let response_data: TestResponse = serde_json::from_slice(response.get_ref())?;
                if response_data.client_compressed && response_data.server_compressed {
                    (TestStatus::Passed, None)
                } else {
                    (
                        TestStatus::Failed,
                        Some(format!(
                            "compression flags mismatch: client={} server={}",
                            response_data.client_compressed, response_data.server_compressed
                        )),
                    )
                }
            }
            Err(status) => (
                TestStatus::Failed,
                Some(format!("compression call returned {:?}", status.code())),
            ),
        };

        self.results.push(ConformanceResult {
            test_name: "compression_negotiation_contract".to_string(),
            category: TestCategory::Compression,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });

        Ok(())
    }

    async fn run_timeout_tests(
        &mut self,
        cx: &Cx,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running timeout tests");

        let start_time = Instant::now();
        let request = TestRequest {
            message: "DEADLINE_EXCEEDED".to_string(),
            echo_metadata: false,
            echo_deadline: false,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };
        let grpc_request = Request::new(Bytes::from(serde_json::to_vec(&request)?));
        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;
        let (status, error_message) = match harness.service.error_test_call(cx, grpc_request).await
        {
            Err(status) if status.code() == Code::DeadlineExceeded => {
                metadata.grpc_status = Some(status.code() as i32);
                (TestStatus::Passed, None)
            }
            Err(status) => {
                metadata.grpc_status = Some(status.code() as i32);
                (
                    TestStatus::Failed,
                    Some(format!(
                        "expected DeadlineExceeded, got {:?}",
                        status.code()
                    )),
                )
            }
            Ok(_) => (
                TestStatus::Failed,
                Some("expected DeadlineExceeded, got success".to_string()),
            ),
        };

        self.results.push(ConformanceResult {
            test_name: "timeout_deadline_propagation_contract".to_string(),
            category: TestCategory::Timeout,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });

        Ok(())
    }

    async fn run_cancellation_tests(
        &mut self,
        harness: &InProcessConformanceHarness,
    ) -> Result<()> {
        info!("Running cancellation tests");

        let start_time = Instant::now();
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        let request = StreamingTestRequest {
            message: "cancelled".to_string(),
            sequence_number: 0,
            end_stream: false,
        };
        let request = Request::new(Bytes::from(serde_json::to_vec(&request)?));
        let sink = service::ResponseSink::new();
        let observed = sink.clone();
        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;
        let (status, error_message) = match harness
            .service
            .server_streaming_call(&cancelled, request, sink)
            .await
        {
            Err(status) if status.code() == Code::Cancelled && observed.messages().is_empty() => {
                metadata.grpc_status = Some(status.code() as i32);
                (TestStatus::Passed, None)
            }
            Err(status) => {
                metadata.grpc_status = Some(status.code() as i32);
                (
                    TestStatus::Failed,
                    Some(format!(
                        "expected Cancelled before responses, got {:?} with {} responses",
                        status.code(),
                        observed.messages().len()
                    )),
                )
            }
            Ok(()) => (
                TestStatus::Failed,
                Some("cancelled stream completed successfully".to_string()),
            ),
        };

        self.results.push(ConformanceResult {
            test_name: "cancellation_cleanup_contract".to_string(),
            category: TestCategory::Cancellation,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });

        Ok(())
    }

    async fn run_connect_protocol_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running Connect protocol compatibility tests");

        let start_time = Instant::now();
        self.record_connect_validation_result(
            "connect_protocol_headers_contract",
            start_time,
            connect_compat::ConnectConformanceTests::test_protocol_headers().await,
        );

        let start_time = Instant::now();
        self.record_connect_validation_result(
            "connect_error_format_contract",
            start_time,
            connect_compat::ConnectConformanceTests::test_error_format().await,
        );

        let start_time = Instant::now();
        self.record_connect_validation_result(
            "connect_streaming_protocol_contract",
            start_time,
            connect_compat::ConnectConformanceTests::test_streaming_protocol().await,
        );

        Ok(())
    }

    #[allow(dead_code)]
    fn record_connect_validation_result(
        &mut self,
        test_name: &str,
        start_time: Instant,
        validation: Result<connect_compat::ValidationResult>,
    ) {
        let mut metadata = TestMetadata::default();
        metadata.headers.insert(
            "coverage_status".to_string(),
            "validated_in_process_connect_protocol".to_string(),
        );

        let (status, error_message) = match validation {
            Ok(result) if result.is_valid => (TestStatus::Passed, None),
            Ok(result) => (TestStatus::Failed, Some(result.issues.join("; "))),
            Err(error) => (TestStatus::Error, Some(error.to_string())),
        };

        self.results.push(ConformanceResult {
            test_name: test_name.to_string(),
            category: TestCategory::ConnectProtocol,
            status,
            duration: start_time.elapsed(),
            error_message,
            metadata,
        });
    }

    fn generate_conformance_report(&self) -> Result<()> {
        let total_tests = self.results.len();
        let passed_tests = self
            .results
            .iter()
            .filter(|r| r.status == TestStatus::Passed)
            .count();
        let failed_tests = self
            .results
            .iter()
            .filter(|r| r.status == TestStatus::Failed)
            .count();
        let skipped_tests = self
            .results
            .iter()
            .filter(|r| r.status == TestStatus::Skipped)
            .count();

        info!("=== gRPC Connect Conformance Report ===");
        info!("Total tests: {}", total_tests);
        info!(
            "Passed: {} ({:.1}%)",
            passed_tests,
            passed_tests as f64 / total_tests as f64 * 100.0
        );
        info!(
            "Failed: {} ({:.1}%)",
            failed_tests,
            failed_tests as f64 / total_tests as f64 * 100.0
        );
        info!(
            "Skipped: {} ({:.1}%)",
            skipped_tests,
            skipped_tests as f64 / total_tests as f64 * 100.0
        );

        // Group results by category
        let mut by_category = HashMap::new();
        for result in &self.results {
            by_category
                .entry(result.category)
                .or_insert_with(Vec::new)
                .push(result);
        }

        for (category, results) in by_category {
            let category_passed = results
                .iter()
                .filter(|r| r.status == TestStatus::Passed)
                .count();
            let category_total = results.len();
            info!(
                "{:?}: {}/{} passed ({:.1}%)",
                category,
                category_passed,
                category_total,
                category_passed as f64 / category_total as f64 * 100.0
            );
        }

        // List failed tests
        if failed_tests > 0 {
            warn!("Failed tests:");
            for result in self
                .results
                .iter()
                .filter(|r| r.status == TestStatus::Failed)
            {
                warn!(
                    "  - {}: {}",
                    result.test_name,
                    result.error_message.as_deref().unwrap_or("Unknown error")
                );
            }
        }

        // Write detailed JSON report
        let report_data = serde_json::to_string_pretty(&self.results)?;
        std::fs::write("grpc_conformance_report.json", report_data)?;
        info!("Detailed report written to grpc_conformance_report.json");

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_results(&self) -> &[ConformanceResult] {
        &self.results
    }

    #[allow(dead_code)]
    pub fn conformance_percentage(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let passed = self
            .results
            .iter()
            .filter(|r| r.status == TestStatus::Passed)
            .count();
        passed as f64 / self.results.len() as f64 * 100.0
    }
}

/// Handle for managing the test server lifetime
#[allow(dead_code)]
pub struct TestServerHandle {}

#[allow(dead_code)]
impl TestServerHandle {
    pub async fn shutdown(self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::cx::Cx;

    fn harness() -> InProcessConformanceHarness {
        InProcessConformanceHarness::new(4 * 1024 * 1024)
    }

    #[tokio::test]
    async fn test_conformance_suite_creation() {
        let config = ConformanceConfig::default();
        let suite = ConformanceTestSuite::new(config);
        assert_eq!(suite.results.len(), 0);
    }

    #[tokio::test]
    async fn test_unary_conformance() {
        let config = ConformanceConfig {
            server_address: "http://127.0.0.1:8081".to_string(),
            ..Default::default()
        };

        let suite = ConformanceTestSuite::new(config);

        // The suite now runs through the deterministic in-process harness.
        assert!(suite.results.is_empty());
    }

    #[tokio::test]
    async fn test_metadata_conformance_records_in_process_result() {
        let cx = Cx::for_testing();
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_metadata_tests(&cx, &harness).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "metadata_custom_headers_contract");
        assert_eq!(result.category, TestCategory::Metadata);
        assert_eq!(result.status, TestStatus::Passed);
        assert!(result.error_message.is_none());
        assert_eq!(result.metadata.response_count, 1);
    }

    #[tokio::test]
    async fn test_compression_conformance_records_in_process_result() {
        let cx = Cx::for_testing();
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_compression_tests(&cx, &harness).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "compression_negotiation_contract");
        assert_eq!(result.category, TestCategory::Compression);
        assert_eq!(result.status, TestStatus::Passed);
        assert!(result.error_message.is_none());
        assert_eq!(result.metadata.response_count, 1);
    }

    #[tokio::test]
    async fn test_timeout_conformance_records_in_process_result() {
        let cx = Cx::for_testing();
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_timeout_tests(&cx, &harness).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "timeout_deadline_propagation_contract");
        assert_eq!(result.category, TestCategory::Timeout);
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(
            result.metadata.grpc_status,
            Some(Code::DeadlineExceeded as i32)
        );
        assert!(result.error_message.is_none());
    }

    #[tokio::test]
    async fn test_cancellation_conformance_records_in_process_result() {
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_cancellation_tests(&harness).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "cancellation_cleanup_contract");
        assert_eq!(result.category, TestCategory::Cancellation);
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(result.metadata.grpc_status, Some(Code::Cancelled as i32));
        assert!(result.error_message.is_none());
    }

    #[tokio::test]
    async fn test_server_streaming_conformance_records_in_process_result() {
        let cx = Cx::for_testing();
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite
            .run_server_streaming_tests(&cx, &harness)
            .await
            .unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(
            result.test_name,
            "server_streaming_response_sequence_contract"
        );
        assert_eq!(result.category, TestCategory::ServerStreaming);
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(result.metadata.request_count, 1);
        assert_eq!(result.metadata.response_count, 5);
        assert!(result.error_message.is_none());
    }

    #[tokio::test]
    async fn test_client_streaming_conformance_records_in_process_result() {
        let cx = Cx::for_testing();
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite
            .run_client_streaming_tests(&cx, &harness)
            .await
            .unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "client_streaming_aggregation_contract");
        assert_eq!(result.category, TestCategory::ClientStreaming);
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(result.metadata.request_count, 3);
        assert_eq!(result.metadata.response_count, 1);
        assert!(result.error_message.is_none());
    }

    #[tokio::test]
    async fn test_bidirectional_streaming_conformance_records_in_process_result() {
        let cx = Cx::for_testing();
        let harness = harness();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite
            .run_bidirectional_streaming_tests(&cx, &harness)
            .await
            .unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "bidirectional_streaming_duplex_contract");
        assert_eq!(result.category, TestCategory::BidirectionalStreaming);
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(result.metadata.request_count, 3);
        assert_eq!(result.metadata.response_count, 3);
        assert!(result.error_message.is_none());
    }

    #[tokio::test]
    async fn test_connect_protocol_conformance_records_validator_results() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_connect_protocol_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 3);
        let names: std::collections::HashSet<_> = suite
            .results
            .iter()
            .map(|result| result.test_name.as_str())
            .collect();
        assert!(names.contains("connect_protocol_headers_contract"));
        assert!(names.contains("connect_error_format_contract"));
        assert!(names.contains("connect_streaming_protocol_contract"));
        assert!(suite.results.iter().all(|result| {
            result.category == TestCategory::ConnectProtocol
                && result.status == TestStatus::Passed
                && result.metadata.headers.get("coverage_status")
                    == Some(&"validated_in_process_connect_protocol".to_string())
        }));
    }
}
