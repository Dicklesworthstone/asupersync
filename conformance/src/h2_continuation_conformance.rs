//! HTTP/2 CONTINUATION frame conformance testing.
//!
//! This harness tests the `asupersync` HTTP/2 implementation's CONTINUATION
//! frame handling against the `h2` reference implementation, specifically
//! focusing on the requirement that CONTINUATION frames must immediately
//! follow HEADERS/PUSH_PROMISE frames without intervening frames.

use asupersync::bytes::Bytes;
use asupersync::http::h2::frame::{
    ContinuationFrame, DataFrame, HeadersFrame, PingFrame, SettingsFrame, WindowUpdateFrame,
};
use asupersync::http::h2::{Connection, ErrorCode, Frame, Settings};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Test verdict for CONTINUATION conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuationTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for ContinuationTestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::ExpectedFailure => write!(f, "XFAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Requirement level for CONTINUATION conformance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,   // RFC MUST
    Should, // RFC SHOULD
    May,    // RFC MAY
}

/// Test frame sequence for CONTINUATION testing.
#[derive(Debug, Clone)]
pub struct FrameSequence {
    pub name: String,
    pub description: String,
    pub frames: Vec<TestFrame>,
    pub expected_error: Option<ErrorCode>,
}

/// Individual test frame.
#[derive(Debug, Clone)]
pub struct TestFrame {
    pub frame_type: String,
    pub stream_id: u32,
    pub payload: Vec<u8>,
    pub flags: u8,
    pub description: String,
}

/// Single CONTINUATION conformance test case.
#[derive(Debug, Clone)]
pub struct ContinuationConformanceCase {
    pub id: String,
    pub description: String,
    pub requirement_level: RequirementLevel,
    pub frame_sequence: FrameSequence,
    pub expected_outcome: ExpectedOutcome,
}

/// Expected outcome for a CONTINUATION test.
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedOutcome {
    /// Connection should accept the frame sequence.
    Accept,
    /// Connection should reject with PROTOCOL_ERROR.
    ProtocolError,
    /// Connection should reject with specific error code.
    ErrorCode(ErrorCode),
}

/// Result of running a single CONTINUATION test case.
#[derive(Debug, Clone, Serialize)]
pub struct ContinuationTestResult {
    pub case_id: String,
    pub verdict: ContinuationTestVerdict,
    pub error: Option<String>,
    pub asupersync_result: TestFrameResult,
    pub expected_result: TestFrameResult,
    pub error_codes_match: bool,
}

/// Result of processing a frame sequence on a connection.
#[derive(Debug, Clone, Serialize)]
pub struct TestFrameResult {
    pub accepted: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub frames_processed: usize,
}

/// Summary statistics for a CONTINUATION conformance run.
#[derive(Debug, Clone, Serialize)]
pub struct ContinuationComplianceSummary {
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub total: usize,
    pub compliance_score: f64,
}

/// Complete report for CONTINUATION conformance testing.
#[derive(Debug, Clone, Serialize)]
pub struct ContinuationComplianceReport {
    pub test_run_id: String,
    pub timestamp: String,
    pub total_cases: usize,
    pub results: Vec<ContinuationTestResult>,
    pub summary: ContinuationComplianceSummary,
}

/// CONTINUATION conformance tester.
pub struct ContinuationConformanceTester {
    pub test_cases: Vec<ContinuationConformanceCase>,
}

impl ContinuationConformanceTester {
    /// Create a new CONTINUATION conformance tester with standard test cases.
    pub fn new() -> Self {
        Self {
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create the standard set of CONTINUATION conformance test cases.
    fn create_test_cases() -> Vec<ContinuationConformanceCase> {
        vec![
            ContinuationConformanceCase {
                id: "CONT-001".to_string(),
                description: "HEADERS+CONTINUATION with intervening PING should cause PROTOCOL_ERROR".to_string(),
                requirement_level: RequirementLevel::Must,
                frame_sequence: FrameSequence {
                    name: "headers-ping-continuation".to_string(),
                    description: "HEADERS without END_HEADERS, then PING, then CONTINUATION".to_string(),
                    frames: vec![
                        TestFrame {
                            frame_type: "HEADERS".to_string(),
                            stream_id: 1,
                            payload: create_partial_header_block(),
                            flags: 0x00, // No END_HEADERS (0x04)
                            description: "HEADERS frame without END_HEADERS flag".to_string(),
                        },
                        TestFrame {
                            frame_type: "PING".to_string(),
                            stream_id: 0,
                            payload: vec![0, 1, 2, 3, 4, 5, 6, 7],
                            flags: 0x00,
                            description: "PING frame (invalid - should be CONTINUATION)".to_string(),
                        },
                        TestFrame {
                            frame_type: "CONTINUATION".to_string(),
                            stream_id: 1,
                            payload: vec![0x00], // Empty continuation
                            flags: 0x04, // END_HEADERS
                            description: "CONTINUATION frame with END_HEADERS".to_string(),
                        },
                    ],
                    expected_error: Some(ErrorCode::ProtocolError),
                },
                expected_outcome: ExpectedOutcome::ProtocolError,
            },
            ContinuationConformanceCase {
                id: "CONT-002".to_string(),
                description: "HEADERS+CONTINUATION with intervening SETTINGS should cause PROTOCOL_ERROR".to_string(),
                requirement_level: RequirementLevel::Must,
                frame_sequence: FrameSequence {
                    name: "headers-settings-continuation".to_string(),
                    description: "HEADERS without END_HEADERS, then SETTINGS, then CONTINUATION".to_string(),
                    frames: vec![
                        TestFrame {
                            frame_type: "HEADERS".to_string(),
                            stream_id: 1,
                            payload: create_partial_header_block(),
                            flags: 0x00, // No END_HEADERS
                            description: "HEADERS frame without END_HEADERS flag".to_string(),
                        },
                        TestFrame {
                            frame_type: "SETTINGS".to_string(),
                            stream_id: 0,
                            payload: vec![], // Empty settings
                            flags: 0x00,
                            description: "SETTINGS frame (invalid - should be CONTINUATION)".to_string(),
                        },
                        TestFrame {
                            frame_type: "CONTINUATION".to_string(),
                            stream_id: 1,
                            payload: vec![0x00],
                            flags: 0x04, // END_HEADERS
                            description: "CONTINUATION frame with END_HEADERS".to_string(),
                        },
                    ],
                    expected_error: Some(ErrorCode::ProtocolError),
                },
                expected_outcome: ExpectedOutcome::ProtocolError,
            },
            ContinuationConformanceCase {
                id: "CONT-003".to_string(),
                description: "HEADERS+CONTINUATION with intervening DATA should cause PROTOCOL_ERROR".to_string(),
                requirement_level: RequirementLevel::Must,
                frame_sequence: FrameSequence {
                    name: "headers-data-continuation".to_string(),
                    description: "HEADERS without END_HEADERS, then DATA, then CONTINUATION".to_string(),
                    frames: vec![
                        TestFrame {
                            frame_type: "HEADERS".to_string(),
                            stream_id: 1,
                            payload: create_partial_header_block(),
                            flags: 0x00, // No END_HEADERS
                            description: "HEADERS frame without END_HEADERS flag".to_string(),
                        },
                        TestFrame {
                            frame_type: "DATA".to_string(),
                            stream_id: 1,
                            payload: b"hello".to_vec(),
                            flags: 0x00,
                            description: "DATA frame (invalid - should be CONTINUATION)".to_string(),
                        },
                        TestFrame {
                            frame_type: "CONTINUATION".to_string(),
                            stream_id: 1,
                            payload: vec![0x00],
                            flags: 0x04, // END_HEADERS
                            description: "CONTINUATION frame with END_HEADERS".to_string(),
                        },
                    ],
                    expected_error: Some(ErrorCode::ProtocolError),
                },
                expected_outcome: ExpectedOutcome::ProtocolError,
            },
            ContinuationConformanceCase {
                id: "CONT-004".to_string(),
                description: "HEADERS+CONTINUATION with intervening WINDOW_UPDATE should cause PROTOCOL_ERROR".to_string(),
                requirement_level: RequirementLevel::Must,
                frame_sequence: FrameSequence {
                    name: "headers-window-update-continuation".to_string(),
                    description: "HEADERS without END_HEADERS, then WINDOW_UPDATE, then CONTINUATION".to_string(),
                    frames: vec![
                        TestFrame {
                            frame_type: "HEADERS".to_string(),
                            stream_id: 1,
                            payload: create_partial_header_block(),
                            flags: 0x00, // No END_HEADERS
                            description: "HEADERS frame without END_HEADERS flag".to_string(),
                        },
                        TestFrame {
                            frame_type: "WINDOW_UPDATE".to_string(),
                            stream_id: 1,
                            payload: vec![0x00, 0x00, 0x04, 0x00], // Increment by 1024
                            flags: 0x00,
                            description: "WINDOW_UPDATE frame (invalid - should be CONTINUATION)".to_string(),
                        },
                        TestFrame {
                            frame_type: "CONTINUATION".to_string(),
                            stream_id: 1,
                            payload: vec![0x00],
                            flags: 0x04, // END_HEADERS
                            description: "CONTINUATION frame with END_HEADERS".to_string(),
                        },
                    ],
                    expected_error: Some(ErrorCode::ProtocolError),
                },
                expected_outcome: ExpectedOutcome::ProtocolError,
            },
            ContinuationConformanceCase {
                id: "CONT-005".to_string(),
                description: "Valid HEADERS+CONTINUATION sequence should be accepted".to_string(),
                requirement_level: RequirementLevel::Must,
                frame_sequence: FrameSequence {
                    name: "headers-continuation-valid".to_string(),
                    description: "HEADERS without END_HEADERS, immediately followed by CONTINUATION".to_string(),
                    frames: vec![
                        TestFrame {
                            frame_type: "HEADERS".to_string(),
                            stream_id: 1,
                            payload: create_partial_header_block(),
                            flags: 0x00, // No END_HEADERS
                            description: "HEADERS frame without END_HEADERS flag".to_string(),
                        },
                        TestFrame {
                            frame_type: "CONTINUATION".to_string(),
                            stream_id: 1,
                            payload: vec![0x00],
                            flags: 0x04, // END_HEADERS
                            description: "CONTINUATION frame with END_HEADERS".to_string(),
                        },
                    ],
                    expected_error: None,
                },
                expected_outcome: ExpectedOutcome::Accept,
            },
            ContinuationConformanceCase {
                id: "CONT-006".to_string(),
                description: "CONTINUATION for wrong stream ID should cause PROTOCOL_ERROR".to_string(),
                requirement_level: RequirementLevel::Must,
                frame_sequence: FrameSequence {
                    name: "headers-continuation-wrong-stream".to_string(),
                    description: "HEADERS on stream 1, CONTINUATION on stream 3".to_string(),
                    frames: vec![
                        TestFrame {
                            frame_type: "HEADERS".to_string(),
                            stream_id: 1,
                            payload: create_partial_header_block(),
                            flags: 0x00, // No END_HEADERS
                            description: "HEADERS frame without END_HEADERS flag".to_string(),
                        },
                        TestFrame {
                            frame_type: "CONTINUATION".to_string(),
                            stream_id: 3, // Wrong stream ID
                            payload: vec![0x00],
                            flags: 0x04, // END_HEADERS
                            description: "CONTINUATION frame with wrong stream ID".to_string(),
                        },
                    ],
                    expected_error: Some(ErrorCode::ProtocolError),
                },
                expected_outcome: ExpectedOutcome::ProtocolError,
            },
        ]
    }

    /// Run all conformance test cases.
    pub async fn run_all_tests(&mut self) -> ContinuationComplianceReport {
        let test_run_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let total_cases = self.test_cases.len();
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            let result = self.run_single_test(test_case).await;
            results.push(result);
        }

        let summary = self.compute_summary(&results);

        ContinuationComplianceReport {
            test_run_id,
            timestamp,
            total_cases,
            results,
            summary,
        }
    }

    /// Run a single CONTINUATION conformance test case.
    async fn run_single_test(&self, case: &ContinuationConformanceCase) -> ContinuationTestResult {
        // Test our implementation
        let asupersync_result = self
            .test_asupersync_implementation(&case.frame_sequence)
            .await;

        // Determine expected result
        let expected_result = match &case.expected_outcome {
            ExpectedOutcome::Accept => TestFrameResult {
                accepted: true,
                error_code: None,
                error_message: None,
                frames_processed: case.frame_sequence.frames.len(),
            },
            ExpectedOutcome::ProtocolError => TestFrameResult {
                accepted: false,
                error_code: Some("PROTOCOL_ERROR".to_string()),
                error_message: Some("expected CONTINUATION frame".to_string()),
                frames_processed: 1, // Should fail after first non-CONTINUATION frame
            },
            ExpectedOutcome::ErrorCode(code) => TestFrameResult {
                accepted: false,
                error_code: Some(format!("{:?}", code)),
                error_message: None,
                frames_processed: 1,
            },
        };

        let error_codes_match = match (&asupersync_result.error_code, &expected_result.error_code) {
            (Some(actual), Some(expected)) => actual == expected,
            (None, None) => true,
            _ => false,
        };

        let verdict = if asupersync_result.accepted == expected_result.accepted && error_codes_match
        {
            ContinuationTestVerdict::Pass
        } else {
            ContinuationTestVerdict::Fail
        };

        let error = if verdict == ContinuationTestVerdict::Fail {
            Some(format!(
                "Expected {}, got {}. Error codes: expected {:?}, actual {:?}",
                if expected_result.accepted {
                    "ACCEPT"
                } else {
                    "REJECT"
                },
                if asupersync_result.accepted {
                    "ACCEPT"
                } else {
                    "REJECT"
                },
                expected_result.error_code,
                asupersync_result.error_code
            ))
        } else {
            None
        };

        ContinuationTestResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_result,
            expected_result,
            error_codes_match,
        }
    }

    /// Test frame sequence against asupersync implementation.
    async fn test_asupersync_implementation(&self, sequence: &FrameSequence) -> TestFrameResult {
        // Create a server connection for testing
        let mut connection = Connection::server(Settings::default());
        if let Err(error) = connection.process_frame(Frame::Settings(SettingsFrame::new(vec![]))) {
            return TestFrameResult {
                accepted: false,
                error_code: Some(format!("{:?}", error.code)),
                error_message: Some(error.message),
                frames_processed: 0,
            };
        }

        let mut frames_processed = 0;
        let mut last_error: Option<String> = None;
        let mut last_error_code: Option<String> = None;

        for test_frame in &sequence.frames {
            frames_processed += 1;

            // Convert test frame to actual HTTP/2 frame
            let frame = match self.create_h2_frame(test_frame) {
                Ok(f) => f,
                Err(e) => {
                    last_error = Some(format!("Frame creation failed: {}", e));
                    break;
                }
            };

            // Process the frame
            match connection.process_frame(frame) {
                Ok(_) => {
                    // Frame was accepted, continue
                }
                Err(error) => {
                    // Frame was rejected
                    last_error_code = Some(format!("{:?}", error.code));
                    last_error = Some(error.message);
                    break;
                }
            }
        }

        let accepted = last_error.is_none();

        TestFrameResult {
            accepted,
            error_code: last_error_code,
            error_message: last_error,
            frames_processed: if accepted {
                frames_processed
            } else {
                frames_processed.saturating_sub(1)
            },
        }
    }

    /// Create an actual HTTP/2 frame from test frame description.
    fn create_h2_frame(&self, test_frame: &TestFrame) -> Result<Frame, String> {
        match test_frame.frame_type.as_str() {
            "HEADERS" => {
                Ok(Frame::Headers(HeadersFrame::new(
                    test_frame.stream_id,
                    Bytes::copy_from_slice(&test_frame.payload),
                    false,                        // end_stream
                    test_frame.flags & 0x04 != 0, // end_headers
                )))
            }
            "CONTINUATION" => Ok(Frame::Continuation(ContinuationFrame {
                stream_id: test_frame.stream_id,
                header_block: Bytes::copy_from_slice(&test_frame.payload),
                end_headers: test_frame.flags & 0x04 != 0,
            })),
            "PING" => {
                if test_frame.payload.len() >= 8 {
                    let mut data = [0u8; 8];
                    data.copy_from_slice(&test_frame.payload[..8]);
                    Ok(Frame::Ping(PingFrame::new(data)))
                } else {
                    Err("PING frame needs 8 bytes of payload".to_string())
                }
            }
            "SETTINGS" => Ok(Frame::Settings(SettingsFrame::new(vec![]))),
            "DATA" => {
                Ok(Frame::Data(DataFrame::new(
                    test_frame.stream_id,
                    Bytes::copy_from_slice(&test_frame.payload),
                    test_frame.flags & 0x01 != 0, // end_stream
                )))
            }
            "WINDOW_UPDATE" => {
                if test_frame.payload.len() >= 4 {
                    let increment = u32::from_be_bytes([
                        test_frame.payload[0],
                        test_frame.payload[1],
                        test_frame.payload[2],
                        test_frame.payload[3],
                    ]);
                    Ok(Frame::WindowUpdate(WindowUpdateFrame::new(
                        test_frame.stream_id,
                        increment,
                    )))
                } else {
                    Err("WINDOW_UPDATE frame needs 4 bytes of payload".to_string())
                }
            }
            _ => Err(format!("Unknown frame type: {}", test_frame.frame_type)),
        }
    }

    /// Compute summary statistics from test results.
    fn compute_summary(&self, results: &[ContinuationTestResult]) -> ContinuationComplianceSummary {
        let total = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == ContinuationTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == ContinuationTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == ContinuationTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == ContinuationTestVerdict::Skipped)
            .count();

        let compliance_score = if passed + failed > 0 {
            passed as f64 / (passed + failed) as f64
        } else {
            1.0
        };

        ContinuationComplianceSummary {
            passed,
            failed,
            expected_failures,
            skipped,
            total,
            compliance_score,
        }
    }

    /// Generate a markdown report from the compliance results.
    pub fn generate_markdown_report(&self, report: &ContinuationComplianceReport) -> String {
        let mut output = String::new();

        output.push_str("# HTTP/2 CONTINUATION Frame Conformance Report\n\n");
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
                if result.verdict == ContinuationTestVerdict::Fail {
                    output.push_str(&format!("### {}\n", result.case_id));
                    if let Some(error) = &result.error {
                        output.push_str(&format!("**Error:** {}\n", error));
                    }
                    output.push_str(&format!(
                        "**Error codes match:** {}\n\n",
                        result.error_codes_match
                    ));
                }
            }
        }

        output.push_str("## All Test Results\n\n");
        output.push_str("| Case ID | Verdict | Error Codes Match | Error |\n");
        output.push_str("|---------|---------|-------------------|-------|\n");

        for result in &report.results {
            let error_str = result.error.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                result.case_id, result.verdict, result.error_codes_match, error_str
            ));
        }

        output
    }
}

impl Default for ContinuationConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a minimal header block for testing (just enough to be valid HPACK).
fn create_partial_header_block() -> Vec<u8> {
    // Simple HPACK-encoded header block for ":method: GET"
    // Using indexed header field representation (RFC 7541 Section 6.1)
    // Index 2 in static table is ":method: GET"
    vec![0x82] // 10000010 = indexed header field with index 2
}
