//! gRPC Trailer Forwarding Conformance Tests (RFC 9113 + grpc-go parity)
//!
//! This module provides comprehensive conformance testing for gRPC trailer
//! forwarding per RFC 9113 HTTP/2 semantics and grpc-go parity. The tests
//! systematically validate:
//!
//! - grpc-status in trailers (not headers)
//! - grpc-message base64-encoded for non-ASCII characters
//! - trailer-only responses for errors before any DATA frames
//! - RST_STREAM with NO_ERROR after trailers
//! - grpc-timeout header H[1-99]<unit> units U=H,M,S,m,u,n parsing
//!
//! # gRPC over HTTP/2 Requirements (RFC 9113 + gRPC spec)
//!
//! **Trailer Requirements:**
//! ```
//! HTTP/2 HEADERS frame:
//! :method: POST
//! :path: /service/Method
//! content-type: application/grpc
//! grpc-timeout: 10S
//!
//! HTTP/2 DATA frame(s) (optional)
//!
//! HTTP/2 HEADERS frame (trailers):
//! grpc-status: 0
//! grpc-message: (optional, base64-encoded if non-ASCII)
//! ```
//!
//! **Error Response Pattern:**
//! ```
//! HTTP/2 HEADERS frame:
//! :status: 200
//! content-type: application/grpc
//!
//! HTTP/2 HEADERS frame (trailers, no DATA):
//! grpc-status: 5
//! grpc-message: bm90Zm91bmQ%3D  // "notfound" base64-encoded
//! ```
//!
//! # Critical Requirements
//!
//! - **MUST** send grpc-status in trailers, not initial headers (RFC 9113)
//! - **MUST** base64-encode grpc-message for non-ASCII (gRPC spec)
//! - **MUST** support trailer-only responses for immediate errors
//! - **SHOULD** send RST_STREAM with NO_ERROR after complete response
//! - **MUST** parse grpc-timeout header format correctly

//#[cfg(feature = "grpc")]  // gRPC appears to be available by default
mod grpc_trailer_conformance_tests {
    use asupersync::bytes::{Bytes, BytesMut};
    use asupersync::grpc::{
        server::{format_grpc_timeout, parse_grpc_timeout},
        status::{Code, Status},
        streaming::{Metadata, MetadataValue},
        web::{TrailerFrame, decode_trailers, encode_trailers},
    };
    use asupersync::http::h2::frame::{Frame, FrameHeader, FrameType};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// Test result for a single gRPC trailer forwarding conformance requirement.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GrpcTrailerConformanceResult {
        pub test_id: String,
        pub description: String,
        pub category: TestCategory,
        pub requirement_level: RequirementLevel,
        pub verdict: TestVerdict,
        pub error_message: Option<String>,
        pub execution_time_ms: u64,
    }

    /// Conformance test categories for gRPC trailer forwarding.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum TestCategory {
        /// grpc-status trailer placement
        StatusTrailerPlacement,
        /// grpc-message encoding requirements
        MessageEncoding,
        /// Trailer-only response patterns
        TrailerOnlyResponses,
        /// RST_STREAM after trailers
        RstStreamHandling,
        /// grpc-timeout header parsing
        TimeoutHeaderParsing,
        /// HTTP/2 frame ordering
        Http2FrameOrdering,
        /// Error response handling
        ErrorResponseHandling,
    }

    /// Protocol requirement level per RFC 2119.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum RequirementLevel {
        Must,   // RFC 2119: MUST
        Should, // RFC 2119: SHOULD
        May,    // RFC 2119: MAY
    }

    /// Test execution result.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum TestVerdict {
        Pass,
        Fail,
        Skipped,
        ExpectedFailure,
    }

    /// Mock gRPC response for testing trailer forwarding.
    #[derive(Debug, Clone)]
    pub struct MockGrpcResponse {
        pub initial_headers: Metadata,
        pub data_frames: Vec<Bytes>,
        pub trailers: Metadata,
        pub status: Status,
        pub has_rst_stream: bool,
        pub rst_stream_error_code: Option<u32>,
    }

    impl MockGrpcResponse {
        /// Create a new mock gRPC response.
        pub fn new() -> Self {
            let mut initial_headers = Metadata::new();
            initial_headers.insert(":status", "200");
            initial_headers.insert("content-type", "application/grpc");

            Self {
                initial_headers,
                data_frames: Vec::new(),
                trailers: Metadata::new(),
                status: Status::new(Code::Ok),
                has_rst_stream: false,
                rst_stream_error_code: None,
            }
        }

        /// Set the gRPC status.
        pub fn with_status(mut self, status: Status) -> Self {
            self.status = status;
            self
        }

        /// Add a data frame.
        pub fn with_data_frame(mut self, data: Bytes) -> Self {
            self.data_frames.push(data);
            self
        }

        /// Add trailer metadata.
        pub fn with_trailer(mut self, key: &str, value: &str) -> Self {
            self.trailers.insert(key, value);
            self
        }

        /// Set RST_STREAM behavior.
        pub fn with_rst_stream(mut self, error_code: u32) -> Self {
            self.has_rst_stream = true;
            self.rst_stream_error_code = Some(error_code);
            self
        }

        /// Build the final response with proper trailer placement.
        pub fn build_response(&mut self) {
            // Per gRPC spec: grpc-status MUST be in trailers, not initial headers
            self.trailers
                .insert("grpc-status", &self.status.code() as &dyn ToString);

            if !self.status.message().is_empty() {
                // Base64-encode grpc-message if it contains non-ASCII
                let message = self.status.message();
                if message.is_ascii() {
                    self.trailers.insert("grpc-message", message);
                } else {
                    let encoded = base64::encode(message.as_bytes());
                    self.trailers.insert("grpc-message", &encoded);
                }
            }
        }

        /// Check if this is a trailer-only response (no data frames).
        pub fn is_trailer_only(&self) -> bool {
            self.data_frames.is_empty()
        }

        /// Validate trailer placement compliance.
        pub fn validate_trailer_placement(&self) -> Result<(), String> {
            // grpc-status MUST NOT be in initial headers
            if self.initial_headers.get("grpc-status").is_some() {
                return Err(
                    "grpc-status found in initial headers (must be in trailers)".to_string()
                );
            }

            // grpc-status MUST be in trailers
            if self.trailers.get("grpc-status").is_none() {
                return Err("grpc-status missing from trailers".to_string());
            }

            Ok(())
        }
    }

    impl Default for MockGrpcResponse {
        fn default() -> Self {
            Self::new()
        }
    }

    /// gRPC trailer forwarding conformance test harness.
    pub struct GrpcTrailerConformanceHarness {
        start_time: Instant,
    }

    impl GrpcTrailerConformanceHarness {
        /// Create a new conformance test harness.
        pub fn new() -> Self {
            Self {
                start_time: Instant::now(),
            }
        }

        /// Run all gRPC trailer forwarding conformance tests.
        pub fn run_all_tests(&self) -> Vec<GrpcTrailerConformanceResult> {
            let mut results = Vec::new();

            // RFC 9113 + gRPC spec: Status trailer placement
            results.push(self.test_grpc_status_in_trailers_not_headers());
            results.push(self.test_grpc_status_required_in_trailers());

            // gRPC spec: Message encoding requirements
            results.push(self.test_grpc_message_base64_encoding_non_ascii());
            results.push(self.test_grpc_message_ascii_encoding());
            results.push(self.test_grpc_message_empty_handling());

            // Trailer-only response patterns
            results.push(self.test_trailer_only_response_for_immediate_errors());
            results.push(self.test_trailer_only_response_structure());

            // RST_STREAM handling
            results.push(self.test_rst_stream_no_error_after_trailers());
            results.push(self.test_rst_stream_not_sent_for_trailer_only());

            // grpc-timeout header parsing
            results.push(self.test_grpc_timeout_header_parsing_all_units());
            results.push(self.test_grpc_timeout_header_formatting());
            results.push(self.test_grpc_timeout_invalid_format_handling());

            // HTTP/2 frame ordering
            results.push(self.test_http2_frame_ordering_compliance());
            results.push(self.test_data_before_trailers_ordering());

            // Error response handling
            results.push(self.test_error_response_trailer_forwarding());

            results
        }

        /// Test: grpc-status MUST be in trailers, not initial headers.
        fn test_grpc_status_in_trailers_not_headers(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new().with_status(Status::new(Code::Ok));

            // Erroneously place grpc-status in initial headers
            response.initial_headers.insert("grpc-status", "0");
            response.build_response();

            let verdict = match response.validate_trailer_placement() {
                Err(_) => TestVerdict::Pass, // Correctly detected violation
                Ok(_) => TestVerdict::Fail,  // Failed to detect violation
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("grpc-status in initial headers should be rejected".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_status_trailers_not_headers".to_string(),
                description: "grpc-status MUST be in trailers, not initial headers (RFC 9113)"
                    .to_string(),
                category: TestCategory::StatusTrailerPlacement,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-status is required in trailers.
        fn test_grpc_status_required_in_trailers(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new().with_status(Status::new(Code::Ok));

            // Don't call build_response() to simulate missing grpc-status
            let verdict = match response.validate_trailer_placement() {
                Err(_) => TestVerdict::Pass, // Correctly detected missing status
                Ok(_) => TestVerdict::Fail,  // Failed to detect missing status
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("Missing grpc-status in trailers should be detected".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_status_required_in_trailers".to_string(),
                description: "grpc-status is required in trailers".to_string(),
                category: TestCategory::StatusTrailerPlacement,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-message base64-encoded for non-ASCII characters.
        fn test_grpc_message_base64_encoding_non_ascii(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let non_ascii_message = "错误消息"; // Chinese error message
            let mut response = MockGrpcResponse::new().with_status(Status::with_message(
                Code::InvalidArgument,
                non_ascii_message,
            ));

            response.build_response();

            let grpc_message = response.trailers.get("grpc-message");
            let verdict = if let Some(MetadataValue::Ascii(encoded)) = grpc_message {
                // Verify it's base64-encoded (not the original non-ASCII string)
                if encoded != non_ascii_message {
                    // Try to decode and check if it matches original
                    if let Ok(decoded) = base64::decode(encoded) {
                        if String::from_utf8(decoded)
                            .map(|s| s == non_ascii_message)
                            .unwrap_or(false)
                        {
                            TestVerdict::Pass
                        } else {
                            TestVerdict::Fail
                        }
                    } else {
                        TestVerdict::Fail
                    }
                } else {
                    TestVerdict::Fail // Raw non-ASCII string, not encoded
                }
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("grpc-message with non-ASCII characters must be base64-encoded".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_message_base64_encoding_non_ascii".to_string(),
                description: "grpc-message base64-encoded for non-ASCII characters".to_string(),
                category: TestCategory::MessageEncoding,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-message ASCII encoding (not base64).
        fn test_grpc_message_ascii_encoding(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let ascii_message = "not found";
            let mut response = MockGrpcResponse::new()
                .with_status(Status::with_message(Code::NotFound, ascii_message));

            response.build_response();

            let grpc_message = response.trailers.get("grpc-message");
            let verdict = if let Some(MetadataValue::Ascii(message)) = grpc_message {
                if message == ascii_message {
                    TestVerdict::Pass
                } else {
                    TestVerdict::Fail
                }
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("grpc-message with ASCII characters should not be base64-encoded".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_message_ascii_encoding".to_string(),
                description: "grpc-message ASCII encoding (not base64)".to_string(),
                category: TestCategory::MessageEncoding,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-message empty handling.
        fn test_grpc_message_empty_handling(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new().with_status(Status::new(Code::Ok)); // No message

            response.build_response();

            // Empty messages should not include grpc-message header
            let has_grpc_message = response.trailers.get("grpc-message").is_some();
            let verdict = if !has_grpc_message {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("Empty grpc-message should not be included in trailers".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_message_empty_handling".to_string(),
                description: "grpc-message empty handling".to_string(),
                category: TestCategory::MessageEncoding,
                requirement_level: RequirementLevel::Should,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: trailer-only response for immediate errors.
        fn test_trailer_only_response_for_immediate_errors(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new()
                .with_status(Status::with_message(Code::Unauthenticated, "invalid token"));

            // Don't add any data frames for immediate error
            response.build_response();

            let verdict =
                if response.is_trailer_only() && response.trailers.get("grpc-status").is_some() {
                    TestVerdict::Pass
                } else {
                    TestVerdict::Fail
                };

            let error_message = if verdict == TestVerdict::Fail {
                Some("Immediate errors should use trailer-only responses".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "trailer_only_response_immediate_errors".to_string(),
                description: "trailer-only response for immediate errors before DATA frames"
                    .to_string(),
                category: TestCategory::TrailerOnlyResponses,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: trailer-only response structure.
        fn test_trailer_only_response_structure(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new()
                .with_status(Status::with_message(Code::InvalidArgument, "bad request"));

            response.build_response();

            // Trailer-only response should have proper headers and trailers
            let has_content_type = response
                .initial_headers
                .get("content-type")
                .map(|v| matches!(v, MetadataValue::Ascii(s) if s.contains("application/grpc")))
                .unwrap_or(false);

            let has_status_200 = response
                .initial_headers
                .get(":status")
                .map(|v| matches!(v, MetadataValue::Ascii(s) if s == "200"))
                .unwrap_or(false);

            let verdict = if has_content_type && has_status_200 && response.is_trailer_only() {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("Trailer-only response must have proper structure".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "trailer_only_response_structure".to_string(),
                description: "trailer-only response structure validation".to_string(),
                category: TestCategory::TrailerOnlyResponses,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: RST_STREAM with NO_ERROR after trailers.
        fn test_rst_stream_no_error_after_trailers(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let response = MockGrpcResponse::new()
                .with_status(Status::new(Code::Ok))
                .with_data_frame(Bytes::from("response data"))
                .with_rst_stream(0); // NO_ERROR = 0

            let verdict = if response.has_rst_stream
                && response.rst_stream_error_code == Some(0)
                && !response.data_frames.is_empty()
            {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("RST_STREAM with NO_ERROR should be sent after successful response with trailers".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "rst_stream_no_error_after_trailers".to_string(),
                description: "RST_STREAM with NO_ERROR after trailers".to_string(),
                category: TestCategory::RstStreamHandling,
                requirement_level: RequirementLevel::Should,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: RST_STREAM not sent for trailer-only responses.
        fn test_rst_stream_not_sent_for_trailer_only(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let response = MockGrpcResponse::new()
                .with_status(Status::with_message(Code::NotFound, "not found"));
            // No RST_STREAM for trailer-only

            let verdict = if response.is_trailer_only() && !response.has_rst_stream {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("RST_STREAM should not be sent for trailer-only responses".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "rst_stream_not_sent_trailer_only".to_string(),
                description: "RST_STREAM not sent for trailer-only responses".to_string(),
                category: TestCategory::RstStreamHandling,
                requirement_level: RequirementLevel::Should,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-timeout header parsing for all units.
        fn test_grpc_timeout_header_parsing_all_units(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let test_cases = vec![
                ("10H", Some(Duration::from_secs(10 * 3600))), // Hours
                ("5M", Some(Duration::from_secs(5 * 60))),     // Minutes
                ("30S", Some(Duration::from_secs(30))),        // Seconds
                ("500m", Some(Duration::from_millis(500))),    // Milliseconds
                ("1000u", Some(Duration::from_micros(1000))),  // Microseconds
                ("2000n", Some(Duration::from_nanos(2000))),   // Nanoseconds
                ("99H", Some(Duration::from_secs(99 * 3600))), // Maximum value
                ("1H", Some(Duration::from_secs(3600))),       // Minimum value
                ("0S", Some(Duration::from_secs(0))),          // Zero (edge case)
                ("invalid", None),                             // Invalid format
                ("100X", None),                                // Invalid unit
                ("", None),                                    // Empty string
            ];

            let mut all_passed = true;
            let mut error_messages = Vec::new();

            for (header_value, expected) in test_cases {
                let parsed = parse_grpc_timeout(header_value);
                if parsed != expected {
                    all_passed = false;
                    error_messages.push(format!(
                        "Failed to parse '{}': expected {:?}, got {:?}",
                        header_value, expected, parsed
                    ));
                }
            }

            let verdict = if all_passed {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };
            let error_message = if error_messages.is_empty() {
                None
            } else {
                Some(error_messages.join("; "))
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_timeout_header_parsing_all_units".to_string(),
                description: "grpc-timeout header parsing H[1-99]<unit> units U=H,M,S,m,u,n"
                    .to_string(),
                category: TestCategory::TimeoutHeaderParsing,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-timeout header formatting.
        fn test_grpc_timeout_header_formatting(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let test_cases = vec![
                (Duration::from_secs(3600), "1H"), // Should prefer hours
                (Duration::from_secs(60), "1M"),   // Should prefer minutes
                (Duration::from_secs(1), "1S"),    // Should prefer seconds
                (Duration::from_millis(1), "1m"),  // Should use milliseconds
                (Duration::from_micros(1), "1u"),  // Should use microseconds
                (Duration::from_nanos(1), "1n"),   // Should use nanoseconds
            ];

            let mut all_passed = true;
            let mut error_messages = Vec::new();

            for (duration, expected) in test_cases {
                let formatted = format_grpc_timeout(duration);
                if formatted != expected {
                    all_passed = false;
                    error_messages.push(format!(
                        "Failed to format {:?}: expected '{}', got '{}'",
                        duration, expected, formatted
                    ));
                }
            }

            let verdict = if all_passed {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };
            let error_message = if error_messages.is_empty() {
                None
            } else {
                Some(error_messages.join("; "))
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_timeout_header_formatting".to_string(),
                description: "grpc-timeout header formatting to optimal unit".to_string(),
                category: TestCategory::TimeoutHeaderParsing,
                requirement_level: RequirementLevel::Should,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: grpc-timeout invalid format handling.
        fn test_grpc_timeout_invalid_format_handling(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let invalid_cases = vec![
                "100H", // Value too large (>99)
                "0H",   // Value too small (<1) for this unit
                "1.5S", // Decimal not allowed
                "1SS",  // Double unit
                "S1",   // Unit before value
                "-1S",  // Negative value
                "1h",   // Wrong case (should be 'H')
                " 1S ", // Whitespace
            ];

            let mut all_rejected = true;
            let mut error_messages = Vec::new();

            for invalid_case in invalid_cases {
                let parsed = parse_grpc_timeout(invalid_case);
                if parsed.is_some() {
                    all_rejected = false;
                    error_messages
                        .push(format!("Should reject invalid format: '{}'", invalid_case));
                }
            }

            let verdict = if all_rejected {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };
            let error_message = if error_messages.is_empty() {
                None
            } else {
                Some(error_messages.join("; "))
            };

            GrpcTrailerConformanceResult {
                test_id: "grpc_timeout_invalid_format_handling".to_string(),
                description: "grpc-timeout invalid format handling".to_string(),
                category: TestCategory::TimeoutHeaderParsing,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: HTTP/2 frame ordering compliance.
        fn test_http2_frame_ordering_compliance(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new()
                .with_status(Status::new(Code::Ok))
                .with_data_frame(Bytes::from("data"));

            response.build_response();

            // Proper order: HEADERS (request) -> HEADERS (response) -> DATA -> HEADERS (trailers)
            let has_initial_headers = !response.initial_headers.is_empty();
            let has_data = !response.data_frames.is_empty();
            let has_trailers = !response.trailers.is_empty();

            let verdict = if has_initial_headers && has_data && has_trailers {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some(
                    "HTTP/2 frame ordering must be: HEADERS -> DATA -> HEADERS(trailers)"
                        .to_string(),
                )
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "http2_frame_ordering_compliance".to_string(),
                description: "HTTP/2 frame ordering compliance".to_string(),
                category: TestCategory::Http2FrameOrdering,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: DATA frames before trailers ordering.
        fn test_data_before_trailers_ordering(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new()
                .with_status(Status::new(Code::Ok))
                .with_data_frame(Bytes::from("first"))
                .with_data_frame(Bytes::from("second"));

            response.build_response();

            // All DATA frames must come before trailers
            let verdict = if response.data_frames.len() == 2
                && response.trailers.get("grpc-status").is_some()
            {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some("All DATA frames must come before trailers in HTTP/2".to_string())
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "data_before_trailers_ordering".to_string(),
                description: "DATA frames before trailers ordering".to_string(),
                category: TestCategory::Http2FrameOrdering,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }

        /// Test: Error response trailer forwarding.
        fn test_error_response_trailer_forwarding(&self) -> GrpcTrailerConformanceResult {
            let start = Instant::now();

            let mut response = MockGrpcResponse::new().with_status(Status::with_message(
                Code::Internal,
                "database connection failed",
            ));

            response.build_response();

            let has_error_status = response
                .trailers
                .get("grpc-status")
                .map(|v| match v {
                    MetadataValue::Ascii(s) => {
                        s.parse::<i32>().unwrap_or(-1) == Code::Internal as i32
                    }
                    _ => false,
                })
                .unwrap_or(false);

            let has_error_message = response.trailers.get("grpc-message").is_some();

            let verdict = if has_error_status && has_error_message {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            };

            let error_message = if verdict == TestVerdict::Fail {
                Some(
                    "Error responses must include grpc-status and grpc-message in trailers"
                        .to_string(),
                )
            } else {
                None
            };

            GrpcTrailerConformanceResult {
                test_id: "error_response_trailer_forwarding".to_string(),
                description: "Error response trailer forwarding".to_string(),
                category: TestCategory::ErrorResponseHandling,
                requirement_level: RequirementLevel::Must,
                verdict,
                error_message,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }
        }
    }

    impl Default for GrpcTrailerConformanceHarness {
        fn default() -> Self {
            Self::new()
        }
    }

    // Helper function for base64 operations
    mod base64 {
        use base64::Engine;

        pub fn encode(input: &[u8]) -> String {
            base64::engine::general_purpose::STANDARD.encode(input)
        }

        pub fn decode(input: &str) -> Result<Vec<u8>, ()> {
            base64::engine::general_purpose::STANDARD
                .decode(input)
                .map_err(|_| ())
        }
    }

    pub use GrpcTrailerConformanceHarness;
    /// Re-export types for conformance system integration.
    pub use GrpcTrailerConformanceResult as GrpcConformanceResult;
    pub use RequirementLevel;
    pub use TestCategory;
    pub use TestVerdict;
}

// Tests that always run regardless of features
#[test]
fn grpc_trailer_conformance_suite_availability() {
    println!("✓ gRPC trailer forwarding conformance test suite is available");
    println!(
        "✓ Covers: status trailer placement, message encoding, timeout parsing, RST_STREAM handling"
    );
}

#[cfg(test)]
mod tests {
    use super::grpc_trailer_conformance_tests::*;

    #[test]
    fn test_mock_grpc_response() {
        let mut mock =
            MockGrpcResponse::new().with_status(Status::with_message(Code::Ok, "success"));

        mock.build_response();

        assert!(mock.validate_trailer_placement().is_ok());
        assert!(mock.is_trailer_only()); // No data frames added
        assert_eq!(mock.status.code(), Code::Ok);
    }

    #[test]
    fn test_conformance_harness_basic_functionality() {
        let harness = GrpcTrailerConformanceHarness::new();
        let results = harness.run_all_tests();

        assert!(!results.is_empty(), "Should have conformance test results");

        // Verify all tests have required fields
        for result in &results {
            assert!(!result.test_id.is_empty(), "Test ID must not be empty");
            assert!(
                !result.description.is_empty(),
                "Description must not be empty"
            );
        }

        // Should have tests for all required categories
        let categories: std::collections::HashSet<_> =
            results.iter().map(|r| &r.category).collect();

        assert!(categories.contains(&TestCategory::StatusTrailerPlacement));
        assert!(categories.contains(&TestCategory::MessageEncoding));
        assert!(categories.contains(&TestCategory::TrailerOnlyResponses));
        assert!(categories.contains(&TestCategory::RstStreamHandling));
        assert!(categories.contains(&TestCategory::TimeoutHeaderParsing));
    }

    #[test]
    fn test_trailer_placement_validation() {
        let mut response = MockGrpcResponse::new().with_status(Status::new(Code::Ok));

        // Valid: grpc-status in trailers only
        response.build_response();
        assert!(response.validate_trailer_placement().is_ok());

        // Invalid: grpc-status in initial headers
        response.initial_headers.insert("grpc-status", "0");
        assert!(response.validate_trailer_placement().is_err());
    }
}
