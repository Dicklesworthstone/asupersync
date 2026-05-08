//! HTTP/2 RST_STREAM Error Code Propagation Conformance Test Harness
//!
//! Intended differential test surface for asupersync and the h2 crate reference implementation.
//! Until a real h2 reference adapter is wired, this harness fails closed instead of reporting
//! mocked differential success for RST_STREAM error propagation behavior.
//!
//! ## Test Coverage
//!
//! - All standard HTTP/2 error codes (NO_ERROR through INADEQUATE_SECURITY)
//! - RST_STREAM sequences on different stream states (idle, open, half-closed, closed)
//! - Multiple RST_STREAM frames on the same stream (idempotency)
//! - RST_STREAM on non-existent streams
//! - RST_STREAM timing relative to HEADERS, DATA, and END_STREAM
//! - Error code propagation to client application layer
//! - Stream cleanup and resource deallocation consistency
//!
//! ## Conformance Validation
//!
//! For each test scenario:
//! 1. asupersync: Process RST_STREAM sequence and observe client status
//! 2. h2 reference: Process identical sequence and observe client status, or fail closed if
//!    the live reference seam is unavailable
//! 3. Compare: Client-observed error codes, stream states, and cleanup behavior
//! 4. Assert: Identical behavior across both implementations per RFC 9113
//!
//! ## Expected Behavior Per RFC 9113
//!
//! - RST_STREAM immediately terminates a stream and removes it from flow control
//! - The error code MUST be propagated to the client application
//! - Subsequent frames on reset streams are ignored (no additional errors)
//! - RST_STREAM on closed streams is silently ignored
//! - Error codes preserve semantic meaning across implementations

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::Connection as AsupersyncConnection;
use asupersync::http::h2::error::ErrorCode as AsupersyncErrorCode;
use asupersync::http::h2::frame::{
    DataFrame as AsupersyncDataFrame, HeadersFrame as AsupersyncHeadersFrame,
    RstStreamFrame as AsupersyncRstStreamFrame, Setting as AsupersyncSetting,
    SettingsFrame as AsupersyncSettingsFrame,
};
use asupersync::http::h2::settings::Settings as AsupersyncSettings;
use asupersync::http::h2::{Frame as AsupersyncFrame, H2Error as AsupersyncH2Error};

use serde::{Deserialize, Serialize};
use std::fmt;

const H2_REFERENCE_UNSUPPORTED: &str = "h2 reference adapter unavailable: no live h2 crate seam is wired for RST_STREAM state observation; refusing mocked differential success";

/// Test result from a single RST_STREAM conformance test
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RstStreamTestResult {
    pub test_name: String,
    pub asupersync_result: ClientObservedStatus,
    pub h2_result: ClientObservedStatus,
    pub conformance_status: ConformanceStatus,
    pub error_details: Option<String>,
}

/// Client-observed status after RST_STREAM processing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientObservedStatus {
    pub stream_id: u32,
    pub error_code: Option<u32>,
    pub stream_state: StreamState,
    pub additional_frames_ignored: bool,
    pub cleanup_completed: bool,
    pub connection_state: ConnectionStateInfo,
}

/// Simplified stream state representation for conformance testing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    Reset,
    NonExistent,
}

/// Connection state information relevant to conformance testing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionStateInfo {
    pub state: String,
    pub streams_count: usize,
    pub goaway_sent: bool,
}

/// Conformance test result status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConformanceStatus {
    Pass,
    Fail,
    Skipped,
    Inconclusive,
}

/// Test scenario specification
#[derive(Debug, Clone)]
pub struct RstStreamTestCase {
    pub name: String,
    pub description: String,
    pub stream_id: u32,
    pub initial_stream_state: StreamState,
    pub rst_error_code: AsupersyncErrorCode,
    pub setup_frames: Vec<TestFrame>,
    pub rst_sequence: Vec<RstStreamAction>,
    pub post_rst_frames: Vec<TestFrame>,
    pub expected_behavior: ExpectedBehavior,
}

/// Simplified frame representation for test setup
#[derive(Debug, Clone)]
pub enum TestFrame {
    Headers {
        stream_id: u32,
        end_stream: bool,
        headers: Vec<(String, String)>,
    },
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    Settings {
        settings: Vec<(u16, u32)>,
    },
}

/// RST_STREAM action in a test sequence
#[derive(Debug, Clone)]
pub struct RstStreamAction {
    pub stream_id: u32,
    pub error_code: AsupersyncErrorCode,
    pub delay_ms: Option<u64>, // For timing-sensitive tests
}

/// Expected behavior specification
#[derive(Debug, Clone)]
pub struct ExpectedBehavior {
    pub error_code_propagated: bool,
    pub stream_immediately_reset: bool,
    pub subsequent_frames_ignored: bool,
    pub connection_remains_open: bool,
    pub cleanup_resources: bool,
}

/// Main conformance test runner
pub struct RstStreamConformanceTester {
    test_cases: Vec<RstStreamTestCase>,
    verbose: bool,
}

impl RstStreamConformanceTester {
    /// Create a new conformance tester with default test cases
    pub fn new() -> Self {
        Self {
            test_cases: Self::generate_test_cases(),
            verbose: false,
        }
    }

    /// Create a new conformance tester with verbose output
    pub fn with_verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Run all conformance tests and return aggregated results
    pub fn run_all_tests(&mut self) -> ConformanceReport {
        let mut results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;

        for test_case in &self.test_cases.clone() {
            if self.verbose {
                println!("Running test: {}", test_case.name);
            }

            let result = self.run_single_test(test_case);

            match result.conformance_status {
                ConformanceStatus::Pass => passed += 1,
                ConformanceStatus::Fail => failed += 1,
                ConformanceStatus::Skipped => skipped += 1,
                ConformanceStatus::Inconclusive => failed += 1, // Count as failed for safety
            }

            if self.verbose && result.conformance_status != ConformanceStatus::Pass {
                println!("  ❌ {}: {:?}", test_case.name, result.conformance_status);
                if let Some(details) = &result.error_details {
                    println!("     Details: {}", details);
                }
            } else if self.verbose {
                println!("  ✅ {}", test_case.name);
            }

            results.push(result);
        }

        ConformanceReport {
            total_tests: self.test_cases.len(),
            passed,
            failed,
            skipped,
            results,
        }
    }

    /// Run a single conformance test
    fn run_single_test(&self, test_case: &RstStreamTestCase) -> RstStreamTestResult {
        // Run test on asupersync implementation
        let asupersync_result = match self.run_asupersync_test(test_case) {
            Ok(result) => result,
            Err(e) => {
                return RstStreamTestResult {
                    test_name: test_case.name.clone(),
                    asupersync_result: ClientObservedStatus::default(),
                    h2_result: ClientObservedStatus::default(),
                    conformance_status: ConformanceStatus::Fail,
                    error_details: Some(format!("Asupersync test failed: {}", e)),
                };
            }
        };

        // Run test on h2 reference implementation
        let h2_result = match self.run_h2_reference_test(test_case) {
            Ok(result) => result,
            Err(e) => {
                return RstStreamTestResult {
                    test_name: test_case.name.clone(),
                    asupersync_result,
                    h2_result: ClientObservedStatus::default(),
                    conformance_status: ConformanceStatus::Fail,
                    error_details: Some(format!("h2 reference test failed: {}", e)),
                };
            }
        };

        // Compare results for conformance
        let (conformance_status, error_details) =
            self.compare_results(&asupersync_result, &h2_result);

        RstStreamTestResult {
            test_name: test_case.name.clone(),
            asupersync_result,
            h2_result,
            conformance_status,
            error_details,
        }
    }

    /// Run test case on asupersync implementation
    fn run_asupersync_test(
        &self,
        test_case: &RstStreamTestCase,
    ) -> Result<ClientObservedStatus, AsupersyncH2Error> {
        let mut connection = AsupersyncConnection::server(AsupersyncSettings::default());

        // Initialize connection
        self.initialize_asupersync_connection(&mut connection)?;

        // Setup initial frames
        for frame in &test_case.setup_frames {
            self.send_asupersync_frame(&mut connection, frame)?;
        }

        // Record initial state
        let initial_stream_exists =
            self.asupersync_stream_exists(&mut connection, test_case.stream_id);

        // Execute RST_STREAM sequence
        let mut error_code_observed = None;
        for rst_action in &test_case.rst_sequence {
            let rst_frame =
                AsupersyncRstStreamFrame::new(rst_action.stream_id, rst_action.error_code.clone());

            if let Err(e) = connection.process_frame(AsupersyncFrame::RstStream(rst_frame)) {
                // Error during RST processing - record the error
                error_code_observed = Some(e.code as u32);
            }
        }

        // Test post-RST frame handling
        let mut additional_frames_ignored = true;
        for frame in &test_case.post_rst_frames {
            if let Ok(_) = self.send_asupersync_frame(&mut connection, frame) {
                additional_frames_ignored = false; // Frame was processed, not ignored
            }
        }

        // Determine final stream state
        let stream_state = if !initial_stream_exists {
            StreamState::NonExistent
        } else if self.asupersync_stream_exists(&mut connection, test_case.stream_id) {
            StreamState::Reset // Stream still exists but is reset
        } else {
            StreamState::Closed // Stream was cleaned up
        };

        let connection_state_info = ConnectionStateInfo {
            state: format!("{:?}", connection.state()),
            streams_count: 0,   // Would need access to internal stream count
            goaway_sent: false, // Would need to check outgoing frames
        };
        let cleanup_completed = stream_state == StreamState::Closed;

        Ok(ClientObservedStatus {
            stream_id: test_case.stream_id,
            error_code: error_code_observed,
            stream_state,
            additional_frames_ignored,
            cleanup_completed,
            connection_state: connection_state_info,
        })
    }

    /// Run test case on h2 reference implementation.
    fn run_h2_reference_test(
        &self,
        test_case: &RstStreamTestCase,
    ) -> Result<ClientObservedStatus, Box<dyn std::error::Error>> {
        let message = format!(
            "{}; test_case={}; stream_id={}",
            H2_REFERENCE_UNSUPPORTED, test_case.name, test_case.stream_id
        );
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, message).into())
    }

    /// Compare asupersync and h2 results for conformance
    fn compare_results(
        &self,
        asupersync: &ClientObservedStatus,
        h2: &ClientObservedStatus,
    ) -> (ConformanceStatus, Option<String>) {
        let mut differences = Vec::new();

        // Compare error codes
        if asupersync.error_code != h2.error_code {
            differences.push(format!(
                "Error code mismatch: asupersync={:?}, h2={:?}",
                asupersync.error_code, h2.error_code
            ));
        }

        // Compare stream states
        if asupersync.stream_state != h2.stream_state {
            differences.push(format!(
                "Stream state mismatch: asupersync={:?}, h2={:?}",
                asupersync.stream_state, h2.stream_state
            ));
        }

        // Compare frame ignoring behavior
        if asupersync.additional_frames_ignored != h2.additional_frames_ignored {
            differences.push(format!(
                "Frame ignoring behavior mismatch: asupersync={}, h2={}",
                asupersync.additional_frames_ignored, h2.additional_frames_ignored
            ));
        }

        // Compare cleanup behavior
        if asupersync.cleanup_completed != h2.cleanup_completed {
            differences.push(format!(
                "Cleanup behavior mismatch: asupersync={}, h2={}",
                asupersync.cleanup_completed, h2.cleanup_completed
            ));
        }

        if differences.is_empty() {
            (ConformanceStatus::Pass, None)
        } else {
            (ConformanceStatus::Fail, Some(differences.join("; ")))
        }
    }

    /// Helper functions for asupersync implementation testing
    fn initialize_asupersync_connection(
        &self,
        connection: &mut AsupersyncConnection,
    ) -> Result<(), AsupersyncH2Error> {
        let settings_frame = AsupersyncSettingsFrame::new(vec![
            AsupersyncSetting::MaxConcurrentStreams(100),
            AsupersyncSetting::InitialWindowSize(65536),
            AsupersyncSetting::MaxFrameSize(16384),
        ]);
        let _ = connection.process_frame(AsupersyncFrame::Settings(settings_frame))?;
        Ok(())
    }

    fn send_asupersync_frame(
        &self,
        connection: &mut AsupersyncConnection,
        frame: &TestFrame,
    ) -> Result<(), AsupersyncH2Error> {
        match frame {
            TestFrame::Headers {
                stream_id,
                end_stream,
                headers: _,
            } => {
                let headers_frame = AsupersyncHeadersFrame::new(
                    *stream_id,
                    Bytes::from("dummy headers"),
                    *end_stream,
                    true, // end_headers
                );
                let _ = connection.process_frame(AsupersyncFrame::Headers(headers_frame))?;
            }
            TestFrame::Data {
                stream_id,
                data,
                end_stream,
            } => {
                let data_frame =
                    AsupersyncDataFrame::new(*stream_id, Bytes::copy_from_slice(data), *end_stream);
                let _ = connection.process_frame(AsupersyncFrame::Data(data_frame))?;
            }
            TestFrame::Settings { settings } => {
                let mut setting_list = Vec::new();
                for (id, value) in settings {
                    let setting = match id {
                        1 => AsupersyncSetting::HeaderTableSize(*value),
                        2 => AsupersyncSetting::EnablePush(*value != 0),
                        3 => AsupersyncSetting::MaxConcurrentStreams(*value),
                        4 => AsupersyncSetting::InitialWindowSize(*value),
                        5 => AsupersyncSetting::MaxFrameSize(*value),
                        6 => AsupersyncSetting::MaxHeaderListSize(*value),
                        _ => continue,
                    };
                    setting_list.push(setting);
                }
                let settings_frame = AsupersyncSettingsFrame::new(setting_list);
                let _ = connection.process_frame(AsupersyncFrame::Settings(settings_frame))?;
            }
        }
        Ok(())
    }

    fn asupersync_stream_exists(
        &self,
        connection: &mut AsupersyncConnection,
        stream_id: u32,
    ) -> bool {
        // Check if stream exists (simplified - would need access to internal stream store)
        connection.stream(stream_id).is_some()
    }

    /// Generate comprehensive test cases for RST_STREAM error code propagation
    fn generate_test_cases() -> Vec<RstStreamTestCase> {
        let mut test_cases = Vec::new();

        // Test all error codes on open stream
        let error_codes = [
            (AsupersyncErrorCode::NoError, "NO_ERROR"),
            (AsupersyncErrorCode::ProtocolError, "PROTOCOL_ERROR"),
            (AsupersyncErrorCode::InternalError, "INTERNAL_ERROR"),
            (AsupersyncErrorCode::FlowControlError, "FLOW_CONTROL_ERROR"),
            (AsupersyncErrorCode::SettingsTimeout, "SETTINGS_TIMEOUT"),
            (AsupersyncErrorCode::StreamClosed, "STREAM_CLOSED"),
            (AsupersyncErrorCode::FrameSizeError, "FRAME_SIZE_ERROR"),
            (AsupersyncErrorCode::RefusedStream, "REFUSED_STREAM"),
            (AsupersyncErrorCode::Cancel, "CANCEL"),
            (AsupersyncErrorCode::CompressionError, "COMPRESSION_ERROR"),
            (AsupersyncErrorCode::ConnectError, "CONNECT_ERROR"),
            (AsupersyncErrorCode::EnhanceYourCalm, "ENHANCE_YOUR_CALM"),
            (
                AsupersyncErrorCode::InadequateSecurity,
                "INADEQUATE_SECURITY",
            ),
        ];

        for (error_code, error_name) in &error_codes {
            test_cases.push(RstStreamTestCase {
                name: format!("rst_stream_{}_on_open_stream", error_name.to_lowercase()),
                description: format!("RST_STREAM with {} on an open stream", error_name),
                stream_id: 1,
                initial_stream_state: StreamState::Open,
                rst_error_code: error_code.clone(),
                setup_frames: vec![TestFrame::Headers {
                    stream_id: 1,
                    end_stream: false,
                    headers: vec![("method".to_string(), "GET".to_string())],
                }],
                rst_sequence: vec![RstStreamAction {
                    stream_id: 1,
                    error_code: error_code.clone(),
                    delay_ms: None,
                }],
                post_rst_frames: vec![TestFrame::Data {
                    stream_id: 1,
                    data: b"should be ignored".to_vec(),
                    end_stream: true,
                }],
                expected_behavior: ExpectedBehavior {
                    error_code_propagated: true,
                    stream_immediately_reset: true,
                    subsequent_frames_ignored: true,
                    connection_remains_open: true,
                    cleanup_resources: true,
                },
            });
        }

        // Test RST_STREAM on non-existent stream
        test_cases.push(RstStreamTestCase {
            name: "rst_stream_nonexistent_stream".to_string(),
            description: "RST_STREAM on a non-existent stream".to_string(),
            stream_id: 999,
            initial_stream_state: StreamState::NonExistent,
            rst_error_code: AsupersyncErrorCode::Cancel,
            setup_frames: vec![], // No setup - stream doesn't exist
            rst_sequence: vec![RstStreamAction {
                stream_id: 999,
                error_code: AsupersyncErrorCode::Cancel,
                delay_ms: None,
            }],
            post_rst_frames: vec![],
            expected_behavior: ExpectedBehavior {
                error_code_propagated: false, // No stream to propagate to
                stream_immediately_reset: false,
                subsequent_frames_ignored: true,
                connection_remains_open: true,
                cleanup_resources: false, // Nothing to clean up
            },
        });

        // Test multiple RST_STREAM on same stream (idempotency)
        test_cases.push(RstStreamTestCase {
            name: "multiple_rst_stream_same_stream".to_string(),
            description: "Multiple RST_STREAM frames on the same stream".to_string(),
            stream_id: 3,
            initial_stream_state: StreamState::Open,
            rst_error_code: AsupersyncErrorCode::Cancel,
            setup_frames: vec![TestFrame::Headers {
                stream_id: 3,
                end_stream: false,
                headers: vec![("method".to_string(), "POST".to_string())],
            }],
            rst_sequence: vec![
                RstStreamAction {
                    stream_id: 3,
                    error_code: AsupersyncErrorCode::Cancel,
                    delay_ms: None,
                },
                RstStreamAction {
                    stream_id: 3,
                    error_code: AsupersyncErrorCode::InternalError,
                    delay_ms: None,
                },
            ],
            post_rst_frames: vec![],
            expected_behavior: ExpectedBehavior {
                error_code_propagated: true,
                stream_immediately_reset: true,
                subsequent_frames_ignored: true,
                connection_remains_open: true,
                cleanup_resources: true,
            },
        });

        // Test RST_STREAM on half-closed stream
        test_cases.push(RstStreamTestCase {
            name: "rst_stream_half_closed_stream".to_string(),
            description: "RST_STREAM on a half-closed (local) stream".to_string(),
            stream_id: 5,
            initial_stream_state: StreamState::HalfClosedLocal,
            rst_error_code: AsupersyncErrorCode::StreamClosed,
            setup_frames: vec![TestFrame::Headers {
                stream_id: 5,
                end_stream: true, // Half-close the stream
                headers: vec![("method".to_string(), "GET".to_string())],
            }],
            rst_sequence: vec![RstStreamAction {
                stream_id: 5,
                error_code: AsupersyncErrorCode::StreamClosed,
                delay_ms: None,
            }],
            post_rst_frames: vec![],
            expected_behavior: ExpectedBehavior {
                error_code_propagated: true,
                stream_immediately_reset: true,
                subsequent_frames_ignored: true,
                connection_remains_open: true,
                cleanup_resources: true,
            },
        });

        test_cases
    }
}

impl Default for ClientObservedStatus {
    fn default() -> Self {
        Self {
            stream_id: 0,
            error_code: None,
            stream_state: StreamState::NonExistent,
            additional_frames_ignored: false,
            cleanup_completed: false,
            connection_state: ConnectionStateInfo {
                state: "Unknown".to_string(),
                streams_count: 0,
                goaway_sent: false,
            },
        }
    }
}

/// Aggregated conformance test report
#[derive(Debug, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<RstStreamTestResult>,
}

impl fmt::Display for ConformanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "HTTP/2 RST_STREAM Error Code Propagation Conformance Test Results"
        )?;
        writeln!(
            f,
            "=============================================================="
        )?;
        writeln!(f)?;
        writeln!(f, "Total tests:  {}", self.total_tests)?;
        writeln!(
            f,
            "Passed:       {} ({:.1}%)",
            self.passed,
            (self.passed as f64 / self.total_tests as f64) * 100.0
        )?;
        writeln!(
            f,
            "Failed:       {} ({:.1}%)",
            self.failed,
            (self.failed as f64 / self.total_tests as f64) * 100.0
        )?;
        writeln!(
            f,
            "Skipped:      {} ({:.1}%)",
            self.skipped,
            (self.skipped as f64 / self.total_tests as f64) * 100.0
        )?;
        writeln!(f)?;

        if self.failed == 0 && self.skipped == 0 {
            writeln!(
                f,
                "LIVE H2 REFERENCE PASSED - RST_STREAM behavior matched observed h2 output"
            )?;
        } else {
            writeln!(f, "❌ CONFORMANCE ISSUES DETECTED")?;
            writeln!(f)?;
            writeln!(f, "Failed tests:")?;
            for result in &self.results {
                if result.conformance_status == ConformanceStatus::Fail {
                    writeln!(
                        f,
                        "  - {}: {}",
                        result.test_name,
                        result
                            .error_details
                            .as_ref()
                            .unwrap_or(&"Unknown error".to_string())
                    )?;
                }
            }
        }

        Ok(())
    }
}

/// CLI runner for the conformance test harness
pub fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut verbose = false;
    let mut output_format = "summary";

    for arg in &args[1..] {
        match arg.as_str() {
            "--verbose" | "-v" => verbose = true,
            "--format=json" => output_format = "json",
            "--format=markdown" => output_format = "markdown",
            "--format=summary" => output_format = "summary",
            _ => {
                eprintln!(
                    "Usage: {} [--verbose] [--format=json|markdown|summary]",
                    args[0]
                );
                std::process::exit(1);
            }
        }
    }

    let mut tester = RstStreamConformanceTester::new();
    if verbose {
        tester = tester.with_verbose();
    }

    let report = tester.run_all_tests();

    match output_format {
        "json" => {
            let json = serde_json::to_string_pretty(&report).expect("Failed to serialize JSON");
            println!("{}", json);
        }
        "markdown" => {
            println!("# HTTP/2 RST_STREAM Error Code Propagation Conformance Report\n");
            println!("## Summary\n");
            println!("- **Total tests:** {}", report.total_tests);
            println!(
                "- **Passed:** {} ({:.1}%)",
                report.passed,
                (report.passed as f64 / report.total_tests as f64) * 100.0
            );
            println!(
                "- **Failed:** {} ({:.1}%)",
                report.failed,
                (report.failed as f64 / report.total_tests as f64) * 100.0
            );
            println!(
                "- **Skipped:** {} ({:.1}%)\n",
                report.skipped,
                (report.skipped as f64 / report.total_tests as f64) * 100.0
            );

            if report.failed > 0 {
                println!("## Failed Tests\n");
                for result in &report.results {
                    if result.conformance_status == ConformanceStatus::Fail {
                        println!("### {}\n", result.test_name);
                        if let Some(details) = &result.error_details {
                            println!("**Error:** {}\n", details);
                        }
                        println!("**asupersync result:** {:?}\n", result.asupersync_result);
                        println!("**h2 result:** {:?}\n", result.h2_result);
                    }
                }
            } else {
                println!("## Live H2 Reference Passed\n");
                println!(
                    "RST_STREAM behavior matched observed h2 output for every checked scenario."
                );
            }
        }
        "summary" | _ => {
            println!("{}", report);
        }
    }

    // Exit with error code if any tests failed
    if report.failed > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conformance_tester_creation() {
        let tester = RstStreamConformanceTester::new();
        assert!(!tester.test_cases.is_empty(), "Should generate test cases");
    }

    #[test]
    fn test_error_code_mapping() {
        // Test that we handle all RFC 9113 error codes
        let error_codes = [
            AsupersyncErrorCode::NoError,
            AsupersyncErrorCode::ProtocolError,
            AsupersyncErrorCode::InternalError,
            AsupersyncErrorCode::FlowControlError,
            AsupersyncErrorCode::SettingsTimeout,
            AsupersyncErrorCode::StreamClosed,
            AsupersyncErrorCode::FrameSizeError,
            AsupersyncErrorCode::RefusedStream,
            AsupersyncErrorCode::Cancel,
            AsupersyncErrorCode::CompressionError,
            AsupersyncErrorCode::ConnectError,
            AsupersyncErrorCode::EnhanceYourCalm,
            AsupersyncErrorCode::InadequateSecurity,
        ];

        // Ensure all error codes are covered in test generation
        let tester = RstStreamConformanceTester::new();
        for error_code in &error_codes {
            let has_test = tester
                .test_cases
                .iter()
                .any(|tc| tc.rst_error_code == *error_code);
            assert!(has_test, "Missing test for error code: {:?}", error_code);
        }
    }

    #[test]
    fn test_client_observed_status_default() {
        let status = ClientObservedStatus::default();
        assert_eq!(status.stream_id, 0);
        assert_eq!(status.error_code, None);
        assert_eq!(status.stream_state, StreamState::NonExistent);
    }

    #[test]
    fn test_conformance_report_display() {
        let report = ConformanceReport {
            total_tests: 10,
            passed: 8,
            failed: 2,
            skipped: 0,
            results: vec![],
        };

        let output = format!("{}", report);
        assert!(output.contains("Total tests:  10"));
        assert!(output.contains("Passed:       8"));
        assert!(output.contains("Failed:       2"));
    }

    #[test]
    fn test_h2_reference_adapter_fails_closed_without_live_seam() {
        let tester = RstStreamConformanceTester::new();
        let test_case = tester
            .test_cases
            .first()
            .expect("default scenarios should include RST_STREAM cases");

        let err = tester
            .run_h2_reference_test(test_case)
            .expect_err("missing h2 reference seam must not fabricate a pass")
            .to_string();

        assert!(err.contains("h2 reference adapter unavailable"));
        assert!(err.contains("no live h2 crate seam is wired"));
        assert!(err.contains(&test_case.name));
    }

    #[test]
    fn test_report_fails_closed_until_h2_reference_is_live() {
        let mut tester = RstStreamConformanceTester::new();
        let report = tester.run_all_tests();

        assert_eq!(report.passed, 0);
        assert_eq!(report.failed, report.total_tests);
        assert_eq!(report.skipped, 0);
        assert!(report.results.iter().all(|result| {
            result.conformance_status == ConformanceStatus::Fail
                && result
                    .error_details
                    .as_deref()
                    .is_some_and(|details| details.contains(H2_REFERENCE_UNSUPPORTED))
        }));
    }

    #[test]
    fn test_test_case_generation_completeness() {
        let test_cases = RstStreamConformanceTester::generate_test_cases();

        // Should have tests for all error codes plus edge cases
        assert!(
            test_cases.len() >= 13,
            "Should have at least 13 test cases (one per error code)"
        );

        // Should have non-existent stream test
        assert!(test_cases.iter().any(|tc| tc.name.contains("nonexistent")));

        // Should have multiple RST_STREAM test
        assert!(test_cases.iter().any(|tc| tc.name.contains("multiple")));

        // Should have half-closed stream test
        assert!(test_cases.iter().any(|tc| tc.name.contains("half_closed")));
    }

    #[test]
    fn test_report_wording_does_not_claim_mocked_h2_success() {
        let report = ConformanceReport {
            total_tests: 1,
            passed: 1,
            failed: 0,
            skipped: 0,
            results: vec![RstStreamTestResult {
                test_name: "synthetic".to_string(),
                asupersync_result: ClientObservedStatus::default(),
                h2_result: ClientObservedStatus::default(),
                conformance_status: ConformanceStatus::Pass,
                error_details: None,
            }],
        };
        let rendered = report.to_string();

        assert!(rendered.contains("LIVE H2 REFERENCE PASSED"));
        assert!(!rendered.contains("ALL TESTS PASSED"));
        assert!(!rendered.contains("asupersync and h2 produce identical"));
    }
}
