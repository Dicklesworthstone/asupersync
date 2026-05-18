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

use anyhow::{Context, Result};
use asupersync::cx::Cx;
use asupersync::grpc::{
    Channel, Code, GrpcClient, Request, Response, Server, ServerBuilder, Status,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
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

        // Start our test server
        let server_handle = self.start_test_server(cx).await?;

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run test categories in sequence
        self.run_unary_tests(cx).await?;
        self.run_server_streaming_tests(cx).await?;
        self.run_client_streaming_tests(cx).await?;
        self.run_bidirectional_streaming_tests(cx).await?;
        self.run_error_handling_tests(cx).await?;
        self.run_metadata_tests(cx).await?;
        self.run_compression_tests(cx).await?;
        self.run_timeout_tests(cx).await?;
        self.run_cancellation_tests(cx).await?;

        if self.config.connect_protocol {
            self.run_connect_protocol_tests(cx).await?;
        }

        // Stop test server
        server_handle.shutdown().await?;

        self.generate_conformance_report()?;

        Ok(())
    }

    async fn start_test_server(&self, _cx: &Cx) -> Result<TestServerHandle> {
        let service = service::create_conformance_test_service();

        let server = ServerBuilder::new()
            .max_recv_message_size(self.config.max_message_size)
            .max_send_message_size(self.config.max_message_size)
            .default_timeout(self.config.timeout)
            .add_service(service)
            .build();

        server
            .serve(&self.config.server_address)
            .await
            .context("Failed to start test server")?;

        Ok(TestServerHandle {})
    }

    async fn run_unary_tests(&mut self, cx: &Cx) -> Result<()> {
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
            let result = self.run_unary_test(cx, test_name, request).await?;
            self.results.push(result);
        }

        Ok(())
    }

    async fn run_unary_test(
        &self,
        _cx: &Cx,
        test_name: &str,
        request: TestRequest,
    ) -> Result<ConformanceResult> {
        let start_time = Instant::now();
        let mut metadata = TestMetadata::default();
        metadata.request_count = 1;

        let channel = Channel::connect(&self.config.server_address).await?;
        let mut client = GrpcClient::new(channel);

        let result = match client
            .unary::<Vec<u8>, Vec<u8>>(
                "/conformance.TestService/UnaryCall",
                Request::new(serde_json::to_vec(&request)?),
            )
            .await
        {
            Ok(response) => {
                metadata.response_count = 1;
                metadata.bytes_sent = serde_json::to_vec(&request)?.len() as u64;
                metadata.bytes_received = response.get_ref().len() as u64;
                metadata.grpc_status = Some(0); // OK

                ConformanceResult {
                    test_name: test_name.to_string(),
                    category: TestCategory::UnaryRpc,
                    status: TestStatus::Passed,
                    duration: start_time.elapsed(),
                    error_message: None,
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

    async fn run_server_streaming_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running server streaming tests");

        self.record_skipped_category_result(
            "server_streaming_response_sequence_contract",
            TestCategory::ServerStreaming,
            "requires_connect_reference_client_server_streaming_fixture",
            "server-streaming conformance execution requires a Connect reference-client streaming fixture",
        );

        Ok(())
    }

    async fn run_client_streaming_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running client streaming tests");

        self.record_skipped_category_result(
            "client_streaming_aggregation_contract",
            TestCategory::ClientStreaming,
            "requires_connect_reference_client_client_streaming_fixture",
            "client-streaming conformance execution requires a Connect reference-client streaming fixture",
        );

        Ok(())
    }

    async fn run_bidirectional_streaming_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running bidirectional streaming tests");

        self.record_skipped_category_result(
            "bidirectional_streaming_duplex_contract",
            TestCategory::BidirectionalStreaming,
            "requires_connect_reference_client_bidirectional_streaming_fixture",
            "bidirectional-streaming conformance execution requires a Connect reference-client streaming fixture",
        );

        Ok(())
    }

    async fn run_error_handling_tests(&mut self, cx: &Cx) -> Result<()> {
        info!("Running error handling tests");

        let error_test_cases = vec![
            ("invalid_method", "/invalid/method"),
            ("large_payload", "/conformance.TestService/UnaryCall"),
            ("timeout_exceeded", "/conformance.TestService/UnaryCall"),
        ];

        for (test_name, method) in error_test_cases {
            let result = self.run_error_test(cx, test_name, method).await?;
            self.results.push(result);
        }

        Ok(())
    }

    async fn run_error_test(
        &self,
        _cx: &Cx,
        test_name: &str,
        method: &str,
    ) -> Result<ConformanceResult> {
        let start_time = Instant::now();
        let mut metadata = TestMetadata::default();

        let channel = Channel::connect(&self.config.server_address).await?;
        let mut client = GrpcClient::new(channel);

        let request = TestRequest {
            message: if test_name == "large_payload" {
                "x".repeat(self.config.max_message_size + 1)
            } else {
                "test".to_string()
            },
            echo_metadata: false,
            echo_deadline: false,
            check_auth_context: false,
            response_size: None,
            fill_server_id: false,
        };

        let result = client
            .unary::<Vec<u8>, Vec<u8>>(method, Request::new(serde_json::to_vec(&request)?))
            .await;

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

    fn record_skipped_category_result(
        &mut self,
        test_name: &str,
        category: TestCategory,
        coverage_status: &str,
        error_message: &str,
    ) {
        let start_time = Instant::now();
        let mut metadata = TestMetadata::default();
        metadata
            .headers
            .insert("coverage_status".to_string(), coverage_status.to_string());

        self.results.push(ConformanceResult {
            test_name: test_name.to_string(),
            category,
            status: TestStatus::Skipped,
            duration: start_time.elapsed(),
            error_message: Some(error_message.to_string()),
            metadata,
        });
    }

    async fn run_metadata_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running metadata tests");

        self.record_skipped_category_result(
            "metadata_custom_headers_contract",
            TestCategory::Metadata,
            "requires_connect_reference_client_metadata_fixture",
            "metadata conformance execution requires a Connect reference-client header fixture",
        );

        Ok(())
    }

    async fn run_compression_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running compression tests");

        self.record_skipped_category_result(
            "compression_negotiation_contract",
            TestCategory::Compression,
            "requires_connect_reference_client_compression_fixture",
            "compression conformance execution requires a Connect reference-client compression negotiation fixture",
        );

        Ok(())
    }

    async fn run_timeout_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running timeout tests");

        self.record_skipped_category_result(
            "timeout_deadline_propagation_contract",
            TestCategory::Timeout,
            "requires_connect_reference_client_timeout_fixture",
            "timeout conformance execution requires a Connect reference-client deadline propagation fixture",
        );

        Ok(())
    }

    async fn run_cancellation_tests(&mut self, _cx: &Cx) -> Result<()> {
        info!("Running cancellation tests");

        self.record_skipped_category_result(
            "cancellation_cleanup_contract",
            TestCategory::Cancellation,
            "requires_connect_reference_client_cancellation_fixture",
            "cancellation conformance execution requires a Connect reference-client cancellation fixture",
        );

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

        // This would normally run against a real server.
        // For testing, verify the suite starts empty.
        assert!(suite.results.is_empty());
    }

    #[tokio::test]
    async fn test_metadata_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_metadata_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "metadata_custom_headers_contract");
        assert_eq!(result.category, TestCategory::Metadata);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_metadata_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("Connect reference-client header fixture")));
    }

    #[tokio::test]
    async fn test_compression_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_compression_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "compression_negotiation_contract");
        assert_eq!(result.category, TestCategory::Compression);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_compression_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("compression negotiation fixture")));
    }

    #[tokio::test]
    async fn test_timeout_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_timeout_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "timeout_deadline_propagation_contract");
        assert_eq!(result.category, TestCategory::Timeout);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_timeout_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("deadline propagation fixture")));
    }

    #[tokio::test]
    async fn test_cancellation_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_cancellation_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "cancellation_cleanup_contract");
        assert_eq!(result.category, TestCategory::Cancellation);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_cancellation_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("cancellation fixture")));
    }

    #[tokio::test]
    async fn test_server_streaming_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_server_streaming_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(
            result.test_name,
            "server_streaming_response_sequence_contract"
        );
        assert_eq!(result.category, TestCategory::ServerStreaming);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_server_streaming_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("server-streaming conformance")));
    }

    #[tokio::test]
    async fn test_client_streaming_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_client_streaming_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "client_streaming_aggregation_contract");
        assert_eq!(result.category, TestCategory::ClientStreaming);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_client_streaming_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("client-streaming conformance")));
    }

    #[tokio::test]
    async fn test_bidirectional_streaming_conformance_records_fixture_gap() {
        let cx = Cx::for_testing();
        let mut suite = ConformanceTestSuite::new(ConformanceConfig::default());

        suite.run_bidirectional_streaming_tests(&cx).await.unwrap();

        assert_eq!(suite.results.len(), 1);
        let result = &suite.results[0];
        assert_eq!(result.test_name, "bidirectional_streaming_duplex_contract");
        assert_eq!(result.category, TestCategory::BidirectionalStreaming);
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(
            result.metadata.headers.get("coverage_status"),
            Some(&"requires_connect_reference_client_bidirectional_streaming_fixture".to_string())
        );
        assert!(result
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("bidirectional-streaming conformance")));
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
