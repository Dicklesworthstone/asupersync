//! HTTP/2 GOAWAY frame conformance testing.
//!
//! This harness exercises the asupersync HTTP/2 connection's GOAWAY frame
//! handling against RFC-backed expected states. The h2 reference side is not
//! wired yet, so matching the local expected state is reported as XFAIL instead
//! of a vendor-parity pass.

use asupersync::bytes::Bytes;
use asupersync::http::h2::{
    Connection, Header, Settings,
    connection::ReceivedFrame,
    error::ErrorCode,
    frame::{Frame, GoAwayFrame, SettingsFrame},
};
use serde::{Deserialize, Serialize};
use std::fmt;

const H2_REFERENCE_UNIMPLEMENTED: &str = "h2 reference comparison not yet implemented";

/// Test verdict for individual conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoAwayTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for GoAwayTestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::ExpectedFailure => write!(f, "XFAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Requirement level for conformance testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,   // RFC MUST
    Should, // RFC SHOULD
    May,    // RFC MAY
}

/// Connection state after GOAWAY processing for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoAwayConnectionState {
    /// Whether GOAWAY has been received
    pub goaway_received: bool,
    /// Whether GOAWAY has been sent
    pub goaway_sent: bool,
    /// Connection state (handshaking, open, closing, closed)
    pub connection_state: String,
    /// Effective last stream ID from received GOAWAY
    pub received_goaway_last_stream_id: Option<u32>,
    /// Last stream ID from sent GOAWAY
    pub sent_goaway_last_stream_id: Option<u32>,
    /// List of streams that should be reset due to GOAWAY
    pub reset_streams: Vec<u32>,
}

/// Serializable GOAWAY frame for test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableGoAwayFrame {
    pub last_stream_id: u32,
    pub error_code: String, // Serialized error code name
    pub debug_data: Vec<u8>,
}

impl From<GoAwayFrame> for SerializableGoAwayFrame {
    fn from(frame: GoAwayFrame) -> Self {
        Self {
            last_stream_id: frame.last_stream_id,
            error_code: format!("{:?}", frame.error_code),
            debug_data: frame.debug_data.to_vec(),
        }
    }
}

impl From<SerializableGoAwayFrame> for GoAwayFrame {
    fn from(frame: SerializableGoAwayFrame) -> Self {
        let error_code = match frame.error_code.as_str() {
            "NoError" => ErrorCode::NoError,
            "ProtocolError" => ErrorCode::ProtocolError,
            "InternalError" => ErrorCode::InternalError,
            "FlowControlError" => ErrorCode::FlowControlError,
            "SettingsTimeout" => ErrorCode::SettingsTimeout,
            "StreamClosed" => ErrorCode::StreamClosed,
            "FrameSizeError" => ErrorCode::FrameSizeError,
            "RefusedStream" => ErrorCode::RefusedStream,
            "Cancel" => ErrorCode::Cancel,
            "CompressionError" => ErrorCode::CompressionError,
            "ConnectError" => ErrorCode::ConnectError,
            "EnhanceYourCalm" => ErrorCode::EnhanceYourCalm,
            "InadequateSecurity" => ErrorCode::InadequateSecurity,
            "Http11Required" => ErrorCode::Http11Required,
            _ => ErrorCode::InternalError, // Default fallback
        };

        Self {
            last_stream_id: frame.last_stream_id,
            error_code,
            debug_data: Bytes::from(frame.debug_data),
        }
    }
}

/// Single conformance test case for GOAWAY frame handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoAwayConformanceCase {
    pub id: String,
    pub description: String,
    pub requirement_level: RequirementLevel,
    /// Sequence of GOAWAY frames to apply
    pub goaway_sequence: Vec<SerializableGoAwayFrame>,
    /// Stream IDs that exist before GOAWAY processing
    pub existing_streams: Vec<u32>,
    /// Expected final connection state
    pub expected_connection_state: GoAwayConnectionState,
}

/// Result of a single conformance test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoAwayConformanceResult {
    pub case_id: String,
    pub verdict: GoAwayTestVerdict,
    pub error: Option<String>,
    /// Asupersync's final connection state
    pub asupersync_state: Option<GoAwayConnectionState>,
    /// H2 reference's final connection state
    pub h2_state: Option<GoAwayConnectionState>,
    /// Differences detected between implementations
    pub differences: Vec<String>,
}

/// Summary statistics for the conformance run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoAwayComplianceSummary {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub compliance_score: f64, // (passed + expected_failures) / total
}

/// Complete conformance test report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoAwayComplianceReport {
    pub test_run_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_cases: usize,
    pub results: Vec<GoAwayConformanceResult>,
    pub summary: GoAwayComplianceSummary,
}

impl GoAwayComplianceReport {
    /// Create a new report with generated ID and timestamp.
    fn new(results: Vec<GoAwayConformanceResult>) -> Self {
        let total_cases = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == GoAwayTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == GoAwayTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == GoAwayTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == GoAwayTestVerdict::Skipped)
            .count();

        let compliance_score = if total_cases > 0 {
            (passed + expected_failures) as f64 / total_cases as f64
        } else {
            1.0
        };

        let summary = GoAwayComplianceSummary {
            total_cases,
            passed,
            failed,
            expected_failures,
            skipped,
            compliance_score,
        };

        Self {
            test_run_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            total_cases,
            results,
            summary,
        }
    }
}

/// Main conformance tester for HTTP/2 GOAWAY frames.
#[derive(Debug)]
pub struct GoAwayConformanceTester {
    pub test_cases: Vec<GoAwayConformanceCase>,
}

impl GoAwayConformanceTester {
    /// Create a new tester with predefined conformance cases.
    pub fn new() -> Self {
        Self {
            test_cases: create_goaway_test_cases(),
        }
    }

    /// Run all conformance tests and return a report.
    pub async fn run_all_tests(&self) -> GoAwayComplianceReport {
        let mut results = Vec::new();

        for case in &self.test_cases {
            let result = self.run_single_test(case).await;
            results.push(result);
        }

        GoAwayComplianceReport::new(results)
    }

    /// Run a single conformance test case.
    async fn run_single_test(&self, case: &GoAwayConformanceCase) -> GoAwayConformanceResult {
        // Test asupersync implementation
        let asupersync_result = self.test_asupersync_goaway(case).await;

        // Test h2 reference implementation. If the external reference is not
        // wired, keep this as a live conformance check against the RFC-backed
        // expected state instead of reporting a fake comparison.
        let h2_result = self.test_h2_goaway(case).await;

        // Compare results
        let (verdict, error, differences) = match (&asupersync_result, &h2_result) {
            (Ok(asupersync_state), Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => {
                let differences = self
                    .compare_connection_states(asupersync_state, &case.expected_connection_state);
                if differences.is_empty() {
                    (
                        GoAwayTestVerdict::ExpectedFailure,
                        Some(format!(
                            "{h2_err}; live asupersync matched the RFC-expected state but vendor parity remains unexercised"
                        )),
                        differences,
                    )
                } else {
                    (
                        GoAwayTestVerdict::Fail,
                        Some(format!(
                            "Live asupersync GOAWAY state differed from expected RFC behavior while {h2_err}"
                        )),
                        differences,
                    )
                }
            }
            (Err(asupersync_err), Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => (
                GoAwayTestVerdict::Fail,
                Some(format!(
                    "Live asupersync GOAWAY processing failed while {h2_err}: {asupersync_err}"
                )),
                vec![format!("asupersync_error: {asupersync_err}")],
            ),
            (Ok(asupersync_state), Ok(h2_state)) => {
                let differences = self.compare_connection_states(asupersync_state, h2_state);
                if differences.is_empty() {
                    (GoAwayTestVerdict::Pass, None, differences)
                } else {
                    (
                        GoAwayTestVerdict::Fail,
                        Some(format!(
                            "Connection state differences: {}",
                            differences.join(", ")
                        )),
                        differences,
                    )
                }
            }
            (_, Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => {
                (GoAwayTestVerdict::Skipped, Some(h2_err.clone()), Vec::new())
            }
            (Err(asupersync_err), Err(h2_err)) => {
                // Both failed - check if they failed the same way
                if asupersync_err == h2_err {
                    (GoAwayTestVerdict::Pass, None, Vec::new())
                } else {
                    (
                        GoAwayTestVerdict::Fail,
                        Some(format!(
                            "Different error behaviors: asupersync={}, h2={}",
                            asupersync_err, h2_err
                        )),
                        vec![format!(
                            "Error divergence: {} vs {}",
                            asupersync_err, h2_err
                        )],
                    )
                }
            }
            (Ok(_), Err(h2_err)) => (
                GoAwayTestVerdict::Fail,
                Some(format!("asupersync succeeded, h2 failed: {}", h2_err)),
                vec!["Implementation success divergence".to_string()],
            ),
            (Err(asupersync_err), Ok(_)) => (
                GoAwayTestVerdict::Fail,
                Some(format!(
                    "asupersync failed, h2 succeeded: {}",
                    asupersync_err
                )),
                vec!["Implementation success divergence".to_string()],
            ),
        };

        GoAwayConformanceResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_state: asupersync_result.as_ref().ok().cloned(),
            h2_state: h2_result.as_ref().ok().cloned(),
            differences,
        }
    }

    /// Test asupersync GOAWAY handling.
    async fn test_asupersync_goaway(
        &self,
        case: &GoAwayConformanceCase,
    ) -> Result<GoAwayConnectionState, String> {
        let settings = Settings::default();
        let mut connection = Connection::client(settings);
        accept_peer_settings(&mut connection)?;

        // Simulate existing streams
        for &stream_id in &case.existing_streams {
            if let Err(e) = create_local_stream(&mut connection, stream_id) {
                return Err(format!("Failed to create stream {}: {}", stream_id, e));
            }
        }

        // Apply GOAWAY sequence
        let mut last_received_goaway = None;
        for serializable_frame in &case.goaway_sequence {
            let goaway_frame: GoAwayFrame = serializable_frame.clone().into();
            match process_live_goaway_frame(&mut connection, &goaway_frame) {
                Ok(last_stream_id) => last_received_goaway = Some(last_stream_id),
                Err(e) => return Err(format!("Failed to process GOAWAY frame: {}", e)),
            }
        }

        // Extract connection state
        let connection_state = extract_asupersync_goaway_state(
            &connection,
            &case.existing_streams,
            last_received_goaway,
        );
        Ok(connection_state)
    }

    /// Test h2 reference GOAWAY handling.
    async fn test_h2_goaway(
        &self,
        _case: &GoAwayConformanceCase,
    ) -> Result<GoAwayConnectionState, String> {
        Err(H2_REFERENCE_UNIMPLEMENTED.to_string())
    }

    /// Compare connection states between implementations.
    fn compare_connection_states(
        &self,
        asupersync: &GoAwayConnectionState,
        h2: &GoAwayConnectionState,
    ) -> Vec<String> {
        let mut differences = Vec::new();

        if asupersync.goaway_received != h2.goaway_received {
            differences.push(format!(
                "goaway_received differs: asupersync={}, h2={}",
                asupersync.goaway_received, h2.goaway_received
            ));
        }

        if asupersync.goaway_sent != h2.goaway_sent {
            differences.push(format!(
                "goaway_sent differs: asupersync={}, h2={}",
                asupersync.goaway_sent, h2.goaway_sent
            ));
        }

        if asupersync.connection_state != h2.connection_state {
            differences.push(format!(
                "connection_state differs: asupersync={}, h2={}",
                asupersync.connection_state, h2.connection_state
            ));
        }

        if asupersync.received_goaway_last_stream_id != h2.received_goaway_last_stream_id {
            differences.push(format!(
                "received_goaway_last_stream_id differs: asupersync={:?}, h2={:?}",
                asupersync.received_goaway_last_stream_id, h2.received_goaway_last_stream_id
            ));
        }

        if asupersync.sent_goaway_last_stream_id != h2.sent_goaway_last_stream_id {
            differences.push(format!(
                "sent_goaway_last_stream_id differs: asupersync={:?}, h2={:?}",
                asupersync.sent_goaway_last_stream_id, h2.sent_goaway_last_stream_id
            ));
        }

        // Compare reset streams (order-independent)
        let mut asupersync_reset = asupersync.reset_streams.clone();
        let mut h2_reset = h2.reset_streams.clone();
        asupersync_reset.sort_unstable();
        h2_reset.sort_unstable();

        if asupersync_reset != h2_reset {
            differences.push(format!(
                "reset_streams differs: asupersync={:?}, h2={:?}",
                asupersync_reset, h2_reset
            ));
        }

        differences
    }

    /// Generate a markdown report.
    pub fn generate_markdown_report(&self, report: &GoAwayComplianceReport) -> String {
        let mut output = String::new();
        output.push_str("# HTTP/2 GOAWAY Frame Conformance Report\n\n");

        output.push_str(&format!("**Test Run ID:** {}\n", report.test_run_id));
        output.push_str(&format!("**Timestamp:** {}\n", report.timestamp));
        output.push_str(&format!("**Total Test Cases:** {}\n\n", report.total_cases));

        output.push_str("## Summary\n\n");
        output.push_str(&format!("- **Passed:** {}\n", report.summary.passed));
        output.push_str(&format!("- **Failed:** {}\n", report.summary.failed));
        output.push_str(&format!(
            "- **Expected Failures:** {}\n",
            report.summary.expected_failures
        ));
        output.push_str(&format!("- **Skipped:** {}\n", report.summary.skipped));
        output.push_str(&format!(
            "- **Compliance Score:** {:.1}%\n\n",
            report.summary.compliance_score * 100.0
        ));

        if report.summary.failed > 0 {
            output.push_str("## Failures\n\n");
            for result in &report.results {
                if result.verdict == GoAwayTestVerdict::Fail {
                    output.push_str(&format!("### {}\n", result.case_id));
                    if let Some(error) = &result.error {
                        output.push_str(&format!("**Error:** {}\n", error));
                    }
                    if !result.differences.is_empty() {
                        output.push_str("**Differences:**\n");
                        for diff in &result.differences {
                            output.push_str(&format!("- {}\n", diff));
                        }
                    }
                    output.push('\n');
                }
            }
        }

        output.push_str("## All Results\n\n");
        output.push_str("| Case ID | Verdict | Description |\n");
        output.push_str("|---------|---------|-------------|\n");
        for result in &report.results {
            output.push_str(&format!(
                "| {} | {} | Case {} |\n",
                result.case_id, result.verdict, result.case_id
            ));
        }

        output
    }
}

impl Default for GoAwayConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}

fn accept_peer_settings(connection: &mut Connection) -> Result<(), String> {
    let received = connection
        .process_frame(Frame::Settings(SettingsFrame::new(vec![])))
        .map_err(|err| err.to_string())?;
    if received.is_some() {
        return Err("SETTINGS handshake produced an application frame".to_string());
    }

    match connection.next_frame() {
        Some(Frame::Settings(settings)) if settings.ack => Ok(()),
        other => Err(format!(
            "SETTINGS handshake should queue exactly one ACK, got {other:?}"
        )),
    }
}

fn create_local_stream(connection: &mut Connection, expected_stream_id: u32) -> Result<(), String> {
    let headers = vec![
        Header::new(":method", "GET"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.test"),
        Header::new(":path", format!("/stream/{expected_stream_id}")),
    ];
    let stream_id = connection
        .open_stream(headers, false)
        .map_err(|err| err.to_string())?;
    if stream_id != expected_stream_id {
        return Err(format!(
            "expected stream {expected_stream_id}, opened stream {stream_id}"
        ));
    }

    match connection.next_frame() {
        Some(Frame::Headers(headers)) if headers.stream_id == expected_stream_id => Ok(()),
        other => Err(format!(
            "expected queued HEADERS for stream {expected_stream_id}, got {other:?}"
        )),
    }
}

/// Process a GOAWAY frame through the production connection state machine.
fn process_live_goaway_frame(
    connection: &mut Connection,
    goaway_frame: &GoAwayFrame,
) -> Result<u32, String> {
    match connection
        .process_frame(Frame::GoAway(goaway_frame.clone()))
        .map_err(|err| err.to_string())?
    {
        Some(ReceivedFrame::GoAway { last_stream_id, .. }) => Ok(last_stream_id),
        other => Err(format!("GOAWAY produced unexpected frame: {other:?}")),
    }
}

/// Extract GOAWAY-related connection state from asupersync connection.
fn extract_asupersync_goaway_state(
    connection: &Connection,
    existing_streams: &[u32],
    received_goaway_last_stream_id: Option<u32>,
) -> GoAwayConnectionState {
    let reset_streams = existing_streams
        .iter()
        .copied()
        .filter(|stream_id| {
            connection
                .stream(*stream_id)
                .and_then(|stream| stream.error_code())
                .is_some()
        })
        .collect();

    GoAwayConnectionState {
        goaway_received: connection.goaway_received(),
        goaway_sent: false,
        connection_state: format!("{:?}", connection.state()),
        received_goaway_last_stream_id,
        sent_goaway_last_stream_id: None,
        reset_streams,
    }
}

/// Create predefined test cases for GOAWAY frame conformance.
fn create_goaway_test_cases() -> Vec<GoAwayConformanceCase> {
    vec![
        // Test Case 1: Basic GOAWAY processing
        GoAwayConformanceCase {
            id: "goaway-001".to_string(),
            description: "Basic GOAWAY frame sets connection to closing state".to_string(),
            requirement_level: RequirementLevel::Must,
            goaway_sequence: vec![SerializableGoAwayFrame {
                last_stream_id: 3,
                error_code: "NoError".to_string(),
                debug_data: vec![],
            }],
            existing_streams: vec![1, 3],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(3),
                sent_goaway_last_stream_id: None,
                reset_streams: vec![],
            },
        },
        // Test Case 2: GOAWAY with stream reset
        GoAwayConformanceCase {
            id: "goaway-002".to_string(),
            description: "GOAWAY resets streams beyond last_stream_id".to_string(),
            requirement_level: RequirementLevel::Must,
            goaway_sequence: vec![SerializableGoAwayFrame {
                last_stream_id: 3,
                error_code: "NoError".to_string(),
                debug_data: vec![],
            }],
            existing_streams: vec![1, 3, 5, 7],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(3),
                sent_goaway_last_stream_id: None,
                reset_streams: vec![5, 7], // Streams > last_stream_id should be reset
            },
        },
        // Test Case 3: Multiple GOAWAY frames with decreasing last_stream_id
        GoAwayConformanceCase {
            id: "goaway-003".to_string(),
            description: "Multiple GOAWAY frames - effective last_stream_id is minimum".to_string(),
            requirement_level: RequirementLevel::Must,
            goaway_sequence: vec![
                SerializableGoAwayFrame {
                    last_stream_id: 7,
                    error_code: "NoError".to_string(),
                    debug_data: vec![],
                },
                SerializableGoAwayFrame {
                    last_stream_id: 3,
                    error_code: "NoError".to_string(),
                    debug_data: vec![],
                },
            ],
            existing_streams: vec![1, 3, 5, 7, 9],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(3), // Minimum of 7 and 3
                sent_goaway_last_stream_id: None,
                reset_streams: vec![5, 7, 9],
            },
        },
        // Test Case 4: GOAWAY with error code
        GoAwayConformanceCase {
            id: "goaway-004".to_string(),
            description: "GOAWAY with protocol error".to_string(),
            requirement_level: RequirementLevel::Must,
            goaway_sequence: vec![SerializableGoAwayFrame {
                last_stream_id: 1,
                error_code: "ProtocolError".to_string(),
                debug_data: b"Protocol violation detected".to_vec(),
            }],
            existing_streams: vec![1, 3, 5],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(1),
                sent_goaway_last_stream_id: None,
                reset_streams: vec![3, 5],
            },
        },
        // Test Case 5: GOAWAY with zero last_stream_id
        GoAwayConformanceCase {
            id: "goaway-005".to_string(),
            description: "GOAWAY with zero last_stream_id rejects all streams".to_string(),
            requirement_level: RequirementLevel::Must,
            goaway_sequence: vec![SerializableGoAwayFrame {
                last_stream_id: 0,
                error_code: "EnhanceYourCalm".to_string(),
                debug_data: vec![],
            }],
            existing_streams: vec![1, 3, 5, 7],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(0),
                sent_goaway_last_stream_id: None,
                reset_streams: vec![1, 3, 5, 7], // All streams should be reset
            },
        },
        // Test Case 6: GOAWAY with maximum stream ID
        GoAwayConformanceCase {
            id: "goaway-006".to_string(),
            description: "GOAWAY with max stream ID allows all existing streams".to_string(),
            requirement_level: RequirementLevel::Should,
            goaway_sequence: vec![SerializableGoAwayFrame {
                last_stream_id: 0x7FFF_FFFF, // Max valid stream ID (no R bit)
                error_code: "NoError".to_string(),
                debug_data: vec![],
            }],
            existing_streams: vec![1, 3, 5, 7, 9],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(0x7FFF_FFFF),
                sent_goaway_last_stream_id: None,
                reset_streams: vec![], // No streams should be reset
            },
        },
        // Test Case 7: GOAWAY with increasing last_stream_id sequence
        GoAwayConformanceCase {
            id: "goaway-007".to_string(),
            description: "Multiple GOAWAY frames with increasing last_stream_id - first wins"
                .to_string(),
            requirement_level: RequirementLevel::Must,
            goaway_sequence: vec![
                SerializableGoAwayFrame {
                    last_stream_id: 3,
                    error_code: "NoError".to_string(),
                    debug_data: vec![],
                },
                SerializableGoAwayFrame {
                    last_stream_id: 7, // Higher than previous, should be ignored per RFC
                    error_code: "NoError".to_string(),
                    debug_data: vec![],
                },
            ],
            existing_streams: vec![1, 3, 5, 7],
            expected_connection_state: GoAwayConnectionState {
                goaway_received: true,
                goaway_sent: false,
                connection_state: "Closing".to_string(),
                received_goaway_last_stream_id: Some(3), // First GOAWAY wins
                sent_goaway_last_stream_id: None,
                reset_streams: vec![5, 7],
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn h2_reference_unavailable_fails_closed_after_live_goaway_assertions() {
        let tester = GoAwayConformanceTester::new();
        let report = tester.run_all_tests().await;

        assert_eq!(report.total_cases, 7);
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.expected_failures, 7);
        assert_eq!(report.summary.skipped, 0);
        assert!(
            report
                .results
                .iter()
                .all(|result| result.verdict == GoAwayTestVerdict::ExpectedFailure),
            "unwired h2 reference must not produce PASS verdicts"
        );
        assert!(
            report.results.iter().all(|result| result
                .error
                .as_deref()
                .is_some_and(|error| error.contains(H2_REFERENCE_UNIMPLEMENTED)
                    && error.contains("vendor parity remains unexercised"))),
            "each xfail must name the missing vendor reference"
        );
        assert!(
            report
                .results
                .iter()
                .all(|result| result.h2_state.is_none()),
            "h2 reference is intentionally not wired for this harness"
        );
        assert!(
            report
                .results
                .iter()
                .all(|result| result.asupersync_state.is_some()),
            "every case must exercise the live asupersync connection"
        );
    }

    #[test]
    fn received_goaway_resets_local_streams_above_last_stream_id() {
        let mut connection = Connection::client(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        create_local_stream(&mut connection, 1).expect("stream 1");
        create_local_stream(&mut connection, 3).expect("stream 3");

        let goaway = GoAwayFrame::new(1, ErrorCode::NoError);
        let last_stream_id =
            process_live_goaway_frame(&mut connection, &goaway).expect("GOAWAY should process");
        assert_eq!(last_stream_id, 1);
        assert!(connection.stream(1).unwrap().error_code().is_none());
        assert_eq!(
            connection.stream(3).unwrap().error_code(),
            Some(ErrorCode::RefusedStream)
        );
    }

    #[test]
    fn local_goaway_queues_frame_with_debug_data_and_closes_connection() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        connection.goaway(
            ErrorCode::EnhanceYourCalm,
            Bytes::from_static(b"too many requests"),
        );

        let frame = connection
            .next_frame()
            .expect("local GOAWAY should be queued");
        match frame {
            Frame::GoAway(goaway) => {
                assert_eq!(goaway.last_stream_id, 0);
                assert_eq!(goaway.error_code, ErrorCode::EnhanceYourCalm);
                assert_eq!(goaway.debug_data, Bytes::from_static(b"too many requests"));
            }
            other => panic!("expected GOAWAY frame, got {other:?}"),
        }
        assert_eq!(format!("{:?}", connection.state()), "Closing");
    }

    #[test]
    fn open_stream_after_received_goaway_is_refused() {
        let mut connection = Connection::client(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        create_local_stream(&mut connection, 1).expect("stream 1");

        let goaway = GoAwayFrame::new(1, ErrorCode::NoError);
        process_live_goaway_frame(&mut connection, &goaway).expect("GOAWAY should process");

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.test"),
            Header::new(":path", "/after-goaway"),
        ];
        let error = connection
            .open_stream(headers, false)
            .expect_err("new local streams after GOAWAY must be refused");
        assert_eq!(error.code, ErrorCode::ProtocolError);
    }
}
