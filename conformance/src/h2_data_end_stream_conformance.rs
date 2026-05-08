//! HTTP/2 DATA frame END_STREAM conformance testing.
//!
//! This harness exercises the asupersync HTTP/2 connection's DATA frame
//! END_STREAM handling against RFC-backed expected states. The h2 reference
//! side is not wired yet, so matching the local expected state is reported as
//! XFAIL instead of a vendor-parity pass.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    Connection, Header, HpackEncoder, Settings,
    connection::ReceivedFrame,
    frame::{DataFrame, Frame, HeadersFrame, SettingsFrame},
};
use serde::{Deserialize, Serialize};
use std::fmt;

const H2_REFERENCE_UNIMPLEMENTED: &str = "h2 reference comparison not yet implemented";

/// Test verdict for individual conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataEndStreamTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for DataEndStreamTestVerdict {
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

/// Stream state after DATA END_STREAM processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEndStreamState {
    pub stream_id: u32,
    /// Stream state: Open, HalfClosedLocal, HalfClosedRemote, Closed
    pub state: String,
    /// Whether the stream can receive more data
    pub can_recv: bool,
    /// Whether the stream can send more data
    pub can_send: bool,
    /// Error code if stream was reset
    pub error_code: Option<String>,
}

/// Connection state after DATA END_STREAM processing for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataEndStreamConnectionState {
    /// Connection state (should remain stable)
    pub connection_state: String,
    /// Stream states indexed by stream ID
    pub stream_states: Vec<StreamEndStreamState>,
    /// Whether any errors occurred during processing
    pub has_errors: bool,
    /// List of error messages for failed operations
    pub error_messages: Vec<String>,
}

/// Serializable DATA frame for test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableDataFrame {
    pub stream_id: u32,
    pub data: Vec<u8>,
    pub end_stream: bool,
}

impl From<DataFrame> for SerializableDataFrame {
    fn from(frame: DataFrame) -> Self {
        Self {
            stream_id: frame.stream_id,
            data: frame.data.to_vec(),
            end_stream: frame.end_stream,
        }
    }
}

impl From<SerializableDataFrame> for DataFrame {
    fn from(frame: SerializableDataFrame) -> Self {
        Self {
            stream_id: frame.stream_id,
            data: Bytes::from(frame.data),
            end_stream: frame.end_stream,
        }
    }
}

/// Single conformance test case for DATA frame END_STREAM handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEndStreamConformanceCase {
    pub id: String,
    pub description: String,
    pub requirement_level: RequirementLevel,
    /// Initial stream setup (HEADERS frames to establish streams)
    pub initial_streams: Vec<u32>,
    /// Sequence of DATA frames to apply
    pub data_sequence: Vec<SerializableDataFrame>,
    /// Expected final connection state
    pub expected_connection_state: DataEndStreamConnectionState,
}

/// Result of a single conformance test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEndStreamConformanceResult {
    pub case_id: String,
    pub verdict: DataEndStreamTestVerdict,
    pub error: Option<String>,
    /// Asupersync's final connection state
    pub asupersync_state: Option<DataEndStreamConnectionState>,
    /// H2 reference's final connection state
    pub h2_state: Option<DataEndStreamConnectionState>,
    /// Differences detected between implementations
    pub differences: Vec<String>,
}

/// Summary statistics for the conformance run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEndStreamComplianceSummary {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub compliance_score: f64, // passed / total
}

/// Complete conformance test report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEndStreamComplianceReport {
    pub test_run_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_cases: usize,
    pub results: Vec<DataEndStreamConformanceResult>,
    pub summary: DataEndStreamComplianceSummary,
}

impl DataEndStreamComplianceReport {
    /// Create a new report with generated ID and timestamp.
    fn new(results: Vec<DataEndStreamConformanceResult>) -> Self {
        let total_cases = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == DataEndStreamTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == DataEndStreamTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == DataEndStreamTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == DataEndStreamTestVerdict::Skipped)
            .count();

        let compliance_score = if total_cases > 0 {
            passed as f64 / total_cases as f64
        } else {
            1.0
        };

        let summary = DataEndStreamComplianceSummary {
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

/// Main conformance tester for HTTP/2 DATA frame END_STREAM handling.
#[derive(Debug)]
pub struct DataEndStreamConformanceTester {
    pub test_cases: Vec<DataEndStreamConformanceCase>,
}

impl DataEndStreamConformanceTester {
    /// Create a new tester with predefined conformance cases.
    pub fn new() -> Self {
        Self {
            test_cases: create_data_end_stream_test_cases(),
        }
    }

    /// Run all conformance tests and return a report.
    pub async fn run_all_tests(&self) -> DataEndStreamComplianceReport {
        let mut results = Vec::new();

        for case in &self.test_cases {
            let result = self.run_single_test(case).await;
            results.push(result);
        }

        DataEndStreamComplianceReport::new(results)
    }

    /// Run a single conformance test case.
    async fn run_single_test(
        &self,
        case: &DataEndStreamConformanceCase,
    ) -> DataEndStreamConformanceResult {
        // Test asupersync implementation
        let asupersync_result = self.test_asupersync_data_end_stream(case).await;

        // Test h2 reference implementation. If the external reference is not
        // wired, keep this as a live conformance check against the RFC-backed
        // expected state instead of reporting a fake comparison.
        let h2_result = self.test_h2_data_end_stream(case).await;

        // Compare results
        let (verdict, error, differences) = match (&asupersync_result, &h2_result) {
            (Ok(asupersync_state), Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => {
                let differences = self
                    .compare_connection_states(asupersync_state, &case.expected_connection_state);
                if differences.is_empty() {
                    (
                        DataEndStreamTestVerdict::ExpectedFailure,
                        Some(format!(
                            "{h2_err}; live asupersync matched the RFC-expected state but vendor parity remains unexercised"
                        )),
                        differences,
                    )
                } else {
                    (
                        DataEndStreamTestVerdict::Fail,
                        Some(format!(
                            "Live asupersync DATA END_STREAM state differed from expected RFC behavior while {h2_err}"
                        )),
                        differences,
                    )
                }
            }
            (Err(asupersync_err), Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => (
                DataEndStreamTestVerdict::Fail,
                Some(format!(
                    "Live asupersync DATA END_STREAM processing failed while {h2_err}: {asupersync_err}"
                )),
                vec![format!("asupersync_error: {asupersync_err}")],
            ),
            (Ok(asupersync_state), Ok(h2_state)) => {
                let differences = self.compare_connection_states(asupersync_state, h2_state);
                if differences.is_empty() {
                    (DataEndStreamTestVerdict::Pass, None, differences)
                } else {
                    (
                        DataEndStreamTestVerdict::Fail,
                        Some(format!(
                            "Connection state differences: {}",
                            differences.join(", ")
                        )),
                        differences,
                    )
                }
            }
            (_, Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => (
                DataEndStreamTestVerdict::Skipped,
                Some(h2_err.clone()),
                Vec::new(),
            ),
            (Err(asupersync_err), Err(h2_err)) => {
                // Both failed - check if they failed the same way
                if asupersync_err == h2_err {
                    (DataEndStreamTestVerdict::Pass, None, Vec::new())
                } else {
                    (
                        DataEndStreamTestVerdict::Fail,
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
                DataEndStreamTestVerdict::Fail,
                Some(format!("asupersync succeeded, h2 failed: {}", h2_err)),
                vec!["Implementation success divergence".to_string()],
            ),
            (Err(asupersync_err), Ok(_)) => (
                DataEndStreamTestVerdict::Fail,
                Some(format!(
                    "asupersync failed, h2 succeeded: {}",
                    asupersync_err
                )),
                vec!["Implementation success divergence".to_string()],
            ),
        };

        DataEndStreamConformanceResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_state: asupersync_result.as_ref().ok().cloned(),
            h2_state: h2_result.as_ref().ok().cloned(),
            differences,
        }
    }

    /// Test asupersync DATA END_STREAM handling.
    async fn test_asupersync_data_end_stream(
        &self,
        case: &DataEndStreamConformanceCase,
    ) -> Result<DataEndStreamConnectionState, String> {
        let settings = Settings::default();
        let mut connection = Connection::server(settings);
        let mut error_messages = Vec::new();
        accept_peer_settings(&mut connection)?;

        // Initialize streams
        for &stream_id in &case.initial_streams {
            if let Err(e) = initialize_remote_stream(&mut connection, stream_id) {
                return Err(format!("Failed to initialize stream {}: {}", stream_id, e));
            }
        }

        // Apply DATA sequence
        for serializable_frame in &case.data_sequence {
            let data_frame: DataFrame = serializable_frame.clone().into();
            match process_live_data_frame(&mut connection, &data_frame) {
                Ok(_) => {}
                Err(e) => {
                    error_messages.push(format!(
                        "DATA frame error on stream {}: {}",
                        data_frame.stream_id, e
                    ));
                }
            }
        }

        // Extract connection state
        let connection_state = extract_asupersync_data_end_stream_state(
            &connection,
            &case.initial_streams,
            error_messages,
        );
        Ok(connection_state)
    }

    /// Test h2 reference DATA END_STREAM handling.
    async fn test_h2_data_end_stream(
        &self,
        _case: &DataEndStreamConformanceCase,
    ) -> Result<DataEndStreamConnectionState, String> {
        Err(H2_REFERENCE_UNIMPLEMENTED.to_string())
    }

    /// Compare connection states between implementations.
    fn compare_connection_states(
        &self,
        asupersync: &DataEndStreamConnectionState,
        h2: &DataEndStreamConnectionState,
    ) -> Vec<String> {
        let mut differences = Vec::new();

        if asupersync.connection_state != h2.connection_state {
            differences.push(format!(
                "connection_state differs: asupersync={}, h2={}",
                asupersync.connection_state, h2.connection_state
            ));
        }

        if asupersync.has_errors != h2.has_errors {
            differences.push(format!(
                "has_errors differs: asupersync={}, h2={}",
                asupersync.has_errors, h2.has_errors
            ));
        }

        // Compare stream states
        if asupersync.stream_states.len() != h2.stream_states.len() {
            differences.push(format!(
                "stream_states count differs: asupersync={}, h2={}",
                asupersync.stream_states.len(),
                h2.stream_states.len()
            ));
        } else {
            for (asupersync_stream, h2_stream) in
                asupersync.stream_states.iter().zip(&h2.stream_states)
            {
                if asupersync_stream.stream_id != h2_stream.stream_id {
                    differences.push(format!(
                        "stream_id mismatch: asupersync={}, h2={}",
                        asupersync_stream.stream_id, h2_stream.stream_id
                    ));
                }
                if asupersync_stream.state != h2_stream.state {
                    differences.push(format!(
                        "stream {} state differs: asupersync={}, h2={}",
                        asupersync_stream.stream_id, asupersync_stream.state, h2_stream.state
                    ));
                }
                if asupersync_stream.can_recv != h2_stream.can_recv {
                    differences.push(format!(
                        "stream {} can_recv differs: asupersync={}, h2={}",
                        asupersync_stream.stream_id, asupersync_stream.can_recv, h2_stream.can_recv
                    ));
                }
                if asupersync_stream.can_send != h2_stream.can_send {
                    differences.push(format!(
                        "stream {} can_send differs: asupersync={}, h2={}",
                        asupersync_stream.stream_id, asupersync_stream.can_send, h2_stream.can_send
                    ));
                }
            }
        }

        // Compare error messages (order-independent)
        if asupersync.error_messages.len() != h2.error_messages.len() {
            differences.push(format!(
                "error_messages count differs: asupersync={}, h2={}",
                asupersync.error_messages.len(),
                h2.error_messages.len()
            ));
        } else {
            let mut asupersync_errors = asupersync.error_messages.clone();
            let mut h2_errors = h2.error_messages.clone();
            asupersync_errors.sort();
            h2_errors.sort();

            if asupersync_errors != h2_errors {
                differences.push("error_messages content differs".to_string());
            }
        }

        differences
    }

    /// Generate a markdown report.
    pub fn generate_markdown_report(&self, report: &DataEndStreamComplianceReport) -> String {
        let mut output = String::new();
        output.push_str("# HTTP/2 DATA Frame END_STREAM Conformance Report\n\n");

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
                if result.verdict == DataEndStreamTestVerdict::Fail {
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
                "| {} | {} | {} |\n",
                result.case_id,
                result.verdict,
                // Get description from case if available
                format!("Case {}", result.case_id)
            ));
        }

        output
    }
}

impl Default for DataEndStreamConformanceTester {
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

fn request_header_block(stream_id: u32) -> Bytes {
    let headers = [
        Header::new(":method", "GET"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.test"),
        Header::new(":path", format!("/stream/{stream_id}")),
    ];
    let mut encoder = HpackEncoder::new();
    let mut block = BytesMut::new();
    encoder.encode(&headers, &mut block);
    block.freeze()
}

/// Open a peer-initiated stream through the production HEADERS path.
fn initialize_remote_stream(connection: &mut Connection, stream_id: u32) -> Result<(), String> {
    let headers = HeadersFrame::new(stream_id, request_header_block(stream_id), false, true);
    match connection
        .process_frame(Frame::Headers(headers))
        .map_err(|err| err.to_string())?
    {
        Some(ReceivedFrame::Headers {
            stream_id: received_stream_id,
            end_stream,
            ..
        }) if received_stream_id == stream_id && !end_stream => Ok(()),
        other => Err(format!(
            "HEADERS stream initialization produced unexpected frame: {other:?}"
        )),
    }
}

/// Process a DATA frame through the production connection state machine.
fn process_live_data_frame(
    connection: &mut Connection,
    data_frame: &DataFrame,
) -> Result<(), String> {
    match connection.process_frame(Frame::Data(data_frame.clone())) {
        Ok(Some(ReceivedFrame::Data {
            stream_id,
            end_stream,
            ..
        })) if stream_id == data_frame.stream_id && end_stream == data_frame.end_stream => Ok(()),
        Ok(None) => Ok(()),
        Ok(other) => Err(format!("unexpected DATA result frame: {other:?}")),
        Err(err) => Err(format!("{:?}", err.code)),
    }
}

/// Extract DATA END_STREAM-related connection state from asupersync connection.
fn extract_asupersync_data_end_stream_state(
    connection: &Connection,
    stream_ids: &[u32],
    error_messages: Vec<String>,
) -> DataEndStreamConnectionState {
    let stream_states = stream_ids
        .iter()
        .filter_map(|&stream_id| {
            let stream = connection.stream(stream_id)?;
            let state = stream.state();
            Some(StreamEndStreamState {
                stream_id,
                state: format!("{state:?}"),
                can_recv: state.can_recv(),
                can_send: state.can_send(),
                error_code: stream.error_code().map(|code| format!("{code:?}")),
            })
        })
        .collect();

    DataEndStreamConnectionState {
        connection_state: format!("{:?}", connection.state()),
        stream_states,
        has_errors: !error_messages.is_empty(),
        error_messages,
    }
}

/// Create predefined test cases for DATA frame END_STREAM conformance.
fn create_data_end_stream_test_cases() -> Vec<DataEndStreamConformanceCase> {
    vec![
        // Test Case 1: Basic DATA with END_STREAM
        DataEndStreamConformanceCase {
            id: "data-end-stream-001".to_string(),
            description: "Basic DATA frame with END_STREAM closes stream correctly".to_string(),
            requirement_level: RequirementLevel::Must,
            initial_streams: vec![1],
            data_sequence: vec![SerializableDataFrame {
                stream_id: 1,
                data: b"Hello, World!".to_vec(),
                end_stream: true,
            }],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![StreamEndStreamState {
                    stream_id: 1,
                    state: "HalfClosedRemote".to_string(),
                    can_recv: false,
                    can_send: true,
                    error_code: None,
                }],
                has_errors: false,
                error_messages: Vec::new(),
            },
        },
        // Test Case 2: DATA after END_STREAM should be rejected
        DataEndStreamConformanceCase {
            id: "data-end-stream-002".to_string(),
            description: "DATA frame after END_STREAM is rejected with StreamClosed error"
                .to_string(),
            requirement_level: RequirementLevel::Must,
            initial_streams: vec![1],
            data_sequence: vec![
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"First message".to_vec(),
                    end_stream: true,
                },
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"Should be rejected".to_vec(),
                    end_stream: false,
                },
            ],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![StreamEndStreamState {
                    stream_id: 1,
                    state: "HalfClosedRemote".to_string(),
                    can_recv: false,
                    can_send: true,
                    error_code: None,
                }],
                has_errors: true,
                error_messages: vec!["DATA frame error on stream 1: StreamClosed".to_string()],
            },
        },
        // Test Case 3: Multiple DATA frames, last with END_STREAM
        DataEndStreamConformanceCase {
            id: "data-end-stream-003".to_string(),
            description: "Multiple DATA frames, only last has END_STREAM".to_string(),
            requirement_level: RequirementLevel::Must,
            initial_streams: vec![1],
            data_sequence: vec![
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"Chunk 1".to_vec(),
                    end_stream: false,
                },
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"Chunk 2".to_vec(),
                    end_stream: false,
                },
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"Final chunk".to_vec(),
                    end_stream: true,
                },
            ],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![StreamEndStreamState {
                    stream_id: 1,
                    state: "HalfClosedRemote".to_string(),
                    can_recv: false,
                    can_send: true,
                    error_code: None,
                }],
                has_errors: false,
                error_messages: Vec::new(),
            },
        },
        // Test Case 4: Empty DATA with END_STREAM
        DataEndStreamConformanceCase {
            id: "data-end-stream-004".to_string(),
            description: "Empty DATA frame with END_STREAM closes stream".to_string(),
            requirement_level: RequirementLevel::Must,
            initial_streams: vec![1],
            data_sequence: vec![SerializableDataFrame {
                stream_id: 1,
                data: Vec::new(), // Empty payload
                end_stream: true,
            }],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![StreamEndStreamState {
                    stream_id: 1,
                    state: "HalfClosedRemote".to_string(),
                    can_recv: false,
                    can_send: true,
                    error_code: None,
                }],
                has_errors: false,
                error_messages: Vec::new(),
            },
        },
        // Test Case 5: Multiple streams with END_STREAM
        DataEndStreamConformanceCase {
            id: "data-end-stream-005".to_string(),
            description: "Multiple streams each closed with END_STREAM".to_string(),
            requirement_level: RequirementLevel::Should,
            initial_streams: vec![1, 3, 5],
            data_sequence: vec![
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"Stream 1 data".to_vec(),
                    end_stream: true,
                },
                SerializableDataFrame {
                    stream_id: 3,
                    data: b"Stream 3 data".to_vec(),
                    end_stream: true,
                },
                SerializableDataFrame {
                    stream_id: 5,
                    data: b"Stream 5 data".to_vec(),
                    end_stream: true,
                },
            ],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![
                    StreamEndStreamState {
                        stream_id: 1,
                        state: "HalfClosedRemote".to_string(),
                        can_recv: false,
                        can_send: true,
                        error_code: None,
                    },
                    StreamEndStreamState {
                        stream_id: 3,
                        state: "HalfClosedRemote".to_string(),
                        can_recv: false,
                        can_send: true,
                        error_code: None,
                    },
                    StreamEndStreamState {
                        stream_id: 5,
                        state: "HalfClosedRemote".to_string(),
                        can_recv: false,
                        can_send: true,
                        error_code: None,
                    },
                ],
                has_errors: false,
                error_messages: Vec::new(),
            },
        },
        // Test Case 6: Large DATA with END_STREAM
        DataEndStreamConformanceCase {
            id: "data-end-stream-006".to_string(),
            description: "Large DATA frame with END_STREAM handles correctly".to_string(),
            requirement_level: RequirementLevel::Should,
            initial_streams: vec![1],
            data_sequence: vec![SerializableDataFrame {
                stream_id: 1,
                data: vec![0u8; 8192], // 8KB payload
                end_stream: true,
            }],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![StreamEndStreamState {
                    stream_id: 1,
                    state: "HalfClosedRemote".to_string(),
                    can_recv: false,
                    can_send: true,
                    error_code: None,
                }],
                has_errors: false,
                error_messages: Vec::new(),
            },
        },
        // Test Case 7: Attempt to send multiple END_STREAM frames
        DataEndStreamConformanceCase {
            id: "data-end-stream-007".to_string(),
            description: "Multiple END_STREAM frames on same stream should be rejected".to_string(),
            requirement_level: RequirementLevel::Must,
            initial_streams: vec![1],
            data_sequence: vec![
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"First end".to_vec(),
                    end_stream: true,
                },
                SerializableDataFrame {
                    stream_id: 1,
                    data: b"Second end".to_vec(),
                    end_stream: true, // Second END_STREAM should be rejected
                },
            ],
            expected_connection_state: DataEndStreamConnectionState {
                connection_state: "Open".to_string(),
                stream_states: vec![StreamEndStreamState {
                    stream_id: 1,
                    state: "HalfClosedRemote".to_string(),
                    can_recv: false,
                    can_send: true,
                    error_code: None,
                }],
                has_errors: true,
                error_messages: vec!["DATA frame error on stream 1: StreamClosed".to_string()],
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::http::h2::ErrorCode;

    #[tokio::test]
    async fn h2_reference_unavailable_still_runs_live_data_assertions() {
        let tester = DataEndStreamConformanceTester::new();
        let report = tester.run_all_tests().await;

        assert_eq!(report.total_cases, 7);
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.expected_failures, 7);
        assert_eq!(report.summary.skipped, 0);
        assert_eq!(report.summary.compliance_score, 0.0);
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

    #[tokio::test]
    async fn h2_reference_gap_is_reported_as_expected_failure_not_pass() {
        let tester = DataEndStreamConformanceTester::new();
        let report = tester.run_all_tests().await;

        assert!(
            report
                .results
                .iter()
                .all(|result| result.verdict == DataEndStreamTestVerdict::ExpectedFailure),
            "unwired h2 vendor parity must not be reported as full pass: {:?}",
            report.results
        );
        assert!(
            report.results.iter().all(|result| result
                .error
                .as_deref()
                .is_some_and(|error| error.contains(H2_REFERENCE_UNIMPLEMENTED)
                    && error.contains("vendor parity remains unexercised"))),
            "each expected failure should explain the missing h2 reference parity"
        );
    }

    #[test]
    fn data_end_stream_moves_stream_half_closed_remote() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        initialize_remote_stream(&mut connection, 1).expect("open stream");

        let data = DataFrame::new(1, Bytes::from_static(b"done"), true);
        process_live_data_frame(&mut connection, &data).expect("DATA should process");

        let stream = connection.stream(1).expect("stream exists");
        assert_eq!(format!("{:?}", stream.state()), "HalfClosedRemote");
        assert!(!stream.state().can_recv());
        assert!(stream.state().can_send());
    }

    #[test]
    fn data_after_end_stream_reports_stream_closed() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        initialize_remote_stream(&mut connection, 1).expect("open stream");

        let first = DataFrame::new(1, Bytes::from_static(b"done"), true);
        process_live_data_frame(&mut connection, &first).expect("first DATA should process");

        let second = DataFrame::new(1, Bytes::from_static(b"again"), false);
        let error = process_live_data_frame(&mut connection, &second)
            .expect_err("DATA after END_STREAM must fail");
        assert_eq!(error, "StreamClosed");
    }

    #[test]
    fn data_frame_updates_connection_and_stream_receive_windows() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        initialize_remote_stream(&mut connection, 1).expect("open stream");

        let connection_window_before = connection.recv_window();
        let stream_window_before = connection.stream(1).unwrap().recv_window();
        let data = DataFrame::new(1, Bytes::from_static(b"windowed"), false);
        process_live_data_frame(&mut connection, &data).expect("DATA should process");

        assert_eq!(connection.recv_window(), connection_window_before - 8);
        assert_eq!(
            connection.stream(1).unwrap().recv_window(),
            stream_window_before - 8
        );
        assert_eq!(
            format!("{:?}", connection.stream(1).unwrap().state()),
            "Open"
        );
    }

    #[test]
    fn headers_after_data_end_stream_reports_stream_closed() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");
        initialize_remote_stream(&mut connection, 1).expect("open stream");

        let data = DataFrame::new(1, Bytes::from_static(b"done"), true);
        process_live_data_frame(&mut connection, &data).expect("DATA should close remote side");

        let trailers = HeadersFrame::new(1, Bytes::new(), true, true);
        let error = connection
            .process_frame(Frame::Headers(trailers))
            .expect_err("HEADERS after END_STREAM must fail");
        assert_eq!(error.code, ErrorCode::StreamClosed);
        assert_eq!(error.stream_id, Some(1));
    }
}
