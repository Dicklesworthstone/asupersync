//! HTTP/2 PING frame conformance testing.
//!
//! This harness exercises the asupersync HTTP/2 connection's PING frame
//! handling against the h2 reference implementation to ensure identical
//! RTT computation and response behavior per RFC 7540.

use asupersync::http::h2::{
    Connection, Settings,
    frame::{Frame, PingFrame, SettingsFrame},
};
#[cfg(test)]
use asupersync::{
    bytes::Bytes,
    http::h2::frame::{FrameHeader, FrameType, parse_frame},
};
use serde::{Deserialize, Serialize};
use std::fmt;

const H2_REFERENCE_UNIMPLEMENTED: &str = "h2 reference comparison not yet implemented";

/// Test verdict for individual conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for PingTestVerdict {
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

/// PING operation timing for RTT calculation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingTiming {
    /// When the PING was sent
    pub sent_at_ms: u64,
    /// When the PING_ACK was received
    pub ack_received_at_ms: Option<u64>,
    /// Computed RTT in milliseconds
    pub rtt_ms: Option<u64>,
}

/// Connection state after PING processing for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingConnectionState {
    /// Connection state (should remain stable - no spurious GOAWAY)
    pub connection_state: String,
    /// Number of pending operations (PING ACKs to send)
    pub pending_ping_acks: usize,
    /// RTT measurements collected
    pub ping_timings: Vec<PingTiming>,
    /// Whether any spurious errors occurred
    pub has_errors: bool,
}

/// Serializable PING frame for test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePingFrame {
    pub opaque_data: [u8; 8],
    pub ack: bool,
    /// Simulated timestamp for RTT calculation (milliseconds)
    pub timestamp_ms: u64,
}

impl From<PingFrame> for SerializablePingFrame {
    fn from(frame: PingFrame) -> Self {
        Self {
            opaque_data: frame.opaque_data,
            ack: frame.ack,
            timestamp_ms: 0, // Will be set during test execution
        }
    }
}

impl From<SerializablePingFrame> for PingFrame {
    fn from(frame: SerializablePingFrame) -> Self {
        Self {
            opaque_data: frame.opaque_data,
            ack: frame.ack,
        }
    }
}

/// Single conformance test case for PING frame handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingConformanceCase {
    pub id: String,
    pub description: String,
    pub requirement_level: RequirementLevel,
    /// Sequence of PING frames to apply (includes PING and PING_ACK)
    pub ping_sequence: Vec<SerializablePingFrame>,
    /// Expected final connection state
    pub expected_connection_state: PingConnectionState,
    /// Expected RTT behavior (within tolerance)
    pub expected_rtt_behavior: String,
}

/// Result of a single conformance test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingConformanceResult {
    pub case_id: String,
    pub verdict: PingTestVerdict,
    pub error: Option<String>,
    /// Asupersync's final connection state
    pub asupersync_state: Option<PingConnectionState>,
    /// H2 reference's final connection state
    pub h2_state: Option<PingConnectionState>,
    /// Differences detected between implementations
    pub differences: Vec<String>,
}

/// Summary statistics for the conformance run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingComplianceSummary {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub compliance_score: f64, // passed / total
}

/// Complete conformance test report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingComplianceReport {
    pub test_run_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_cases: usize,
    pub results: Vec<PingConformanceResult>,
    pub summary: PingComplianceSummary,
}

impl PingComplianceReport {
    /// Create a new report with generated ID and timestamp.
    fn new(results: Vec<PingConformanceResult>) -> Self {
        let total_cases = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == PingTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == PingTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == PingTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == PingTestVerdict::Skipped)
            .count();

        let compliance_score = if total_cases > 0 {
            passed as f64 / total_cases as f64
        } else {
            1.0
        };

        let summary = PingComplianceSummary {
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

/// Main conformance tester for HTTP/2 PING frames.
#[derive(Debug)]
pub struct PingConformanceTester {
    pub test_cases: Vec<PingConformanceCase>,
}

impl PingConformanceTester {
    /// Create a new tester with predefined conformance cases.
    pub fn new() -> Self {
        Self {
            test_cases: create_ping_test_cases(),
        }
    }

    /// Run all conformance tests and return a report.
    pub async fn run_all_tests(&self) -> PingComplianceReport {
        let mut results = Vec::new();

        for case in &self.test_cases {
            let result = self.run_single_test(case).await;
            results.push(result);
        }

        PingComplianceReport::new(results)
    }

    /// Run a single conformance test case.
    async fn run_single_test(&self, case: &PingConformanceCase) -> PingConformanceResult {
        // Test asupersync implementation
        let asupersync_result = self.test_asupersync_ping(case).await;

        // Test h2 reference implementation. If the external reference is not wired,
        // keep this as a live conformance check against the RFC-backed expected
        // state in the test case instead of reporting a fake comparison.
        let h2_result = self.test_h2_ping(case).await;

        // Compare results
        let (verdict, error, differences) = match (&asupersync_result, &h2_result) {
            (Ok(asupersync_state), Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => {
                let differences = self
                    .compare_connection_states(asupersync_state, &case.expected_connection_state);
                if differences.is_empty() {
                    (
                        PingTestVerdict::ExpectedFailure,
                        Some(format!(
                            "{h2_err}; live asupersync matched the RFC-expected state but vendor parity remains unexercised"
                        )),
                        differences,
                    )
                } else {
                    (
                        PingTestVerdict::Fail,
                        Some(format!(
                            "Live asupersync state differed from expected RFC behavior while {h2_err}"
                        )),
                        differences,
                    )
                }
            }
            (Err(asupersync_err), Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => (
                PingTestVerdict::Fail,
                Some(format!(
                    "Live asupersync PING processing failed while {h2_err}: {asupersync_err}"
                )),
                vec![format!("asupersync_error: {asupersync_err}")],
            ),
            (_, Err(h2_err)) if h2_err == H2_REFERENCE_UNIMPLEMENTED => (
                PingTestVerdict::Skipped,
                Some(H2_REFERENCE_UNIMPLEMENTED.to_string()),
                Vec::new(),
            ),
            (Ok(asupersync_state), Ok(h2_state)) => {
                let differences = self.compare_connection_states(asupersync_state, h2_state);
                if differences.is_empty() {
                    (PingTestVerdict::Pass, None, differences)
                } else {
                    (
                        PingTestVerdict::Fail,
                        Some(format!(
                            "Connection state differences: {}",
                            differences.join(", ")
                        )),
                        differences,
                    )
                }
            }
            (Err(asupersync_err), Err(h2_err)) => {
                // Both failed - check if they failed the same way
                if asupersync_err == h2_err {
                    (PingTestVerdict::Pass, None, Vec::new())
                } else {
                    (
                        PingTestVerdict::Fail,
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
                PingTestVerdict::Fail,
                Some(format!("asupersync succeeded, h2 failed: {}", h2_err)),
                vec!["Implementation success divergence".to_string()],
            ),
            (Err(asupersync_err), Ok(_)) => (
                PingTestVerdict::Fail,
                Some(format!(
                    "asupersync failed, h2 succeeded: {}",
                    asupersync_err
                )),
                vec!["Implementation success divergence".to_string()],
            ),
        };

        PingConformanceResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_state: asupersync_result.as_ref().ok().cloned(),
            h2_state: h2_result.as_ref().ok().cloned(),
            differences,
        }
    }

    /// Test asupersync PING handling.
    async fn test_asupersync_ping(
        &self,
        case: &PingConformanceCase,
    ) -> Result<PingConnectionState, String> {
        let settings = Settings::default();
        let mut connection = Connection::server(settings);
        let mut ping_timings = Vec::new();
        let mut outstanding_ping_timings: Vec<([u8; 8], usize)> = Vec::new();
        accept_peer_settings(&mut connection)?;

        // Apply PING sequence with timing
        for serializable_frame in &case.ping_sequence {
            let ping_frame: PingFrame = serializable_frame.clone().into();

            if !ping_frame.ack {
                // This is a PING request - track timing
                let timing = PingTiming {
                    sent_at_ms: serializable_frame.timestamp_ms,
                    ack_received_at_ms: None,
                    rtt_ms: None,
                };
                ping_timings.push(timing);
                outstanding_ping_timings.push((ping_frame.opaque_data, ping_timings.len() - 1));
            } else {
                // This is a PING ACK - update timing
                if let Some(position) =
                    outstanding_ping_timings
                        .iter()
                        .position(|(opaque_data, index)| {
                            *opaque_data == ping_frame.opaque_data
                                && ping_timings[*index].ack_received_at_ms.is_none()
                        })
                {
                    let (_, timing_index) = outstanding_ping_timings.remove(position);
                    let timing = &mut ping_timings[timing_index];
                    timing.ack_received_at_ms = Some(serializable_frame.timestamp_ms);
                    timing.rtt_ms = Some(
                        serializable_frame
                            .timestamp_ms
                            .saturating_sub(timing.sent_at_ms),
                    );
                }
            }

            // Process the PING frame
            if let Err(e) = process_live_ping_frame(&mut connection, &ping_frame) {
                return Err(format!("Failed to process PING frame: {}", e));
            }
        }

        // Extract connection state
        let connection_state = extract_asupersync_ping_state(&mut connection, ping_timings)?;
        Ok(connection_state)
    }

    /// Test h2 reference PING handling.
    async fn test_h2_ping(
        &self,
        _case: &PingConformanceCase,
    ) -> Result<PingConnectionState, String> {
        Err(H2_REFERENCE_UNIMPLEMENTED.to_string())
    }

    /// Compare connection states between implementations.
    fn compare_connection_states(
        &self,
        asupersync: &PingConnectionState,
        h2: &PingConnectionState,
    ) -> Vec<String> {
        let mut differences = Vec::new();

        if asupersync.connection_state != h2.connection_state {
            differences.push(format!(
                "connection_state differs: asupersync={}, h2={}",
                asupersync.connection_state, h2.connection_state
            ));
        }

        if asupersync.pending_ping_acks != h2.pending_ping_acks {
            differences.push(format!(
                "pending_ping_acks differs: asupersync={}, h2={}",
                asupersync.pending_ping_acks, h2.pending_ping_acks
            ));
        }

        if asupersync.has_errors != h2.has_errors {
            differences.push(format!(
                "has_errors differs: asupersync={}, h2={}",
                asupersync.has_errors, h2.has_errors
            ));
        }

        // Compare ping timings length
        if asupersync.ping_timings.len() != h2.ping_timings.len() {
            differences.push(format!(
                "ping_timings count differs: asupersync={}, h2={}",
                asupersync.ping_timings.len(),
                h2.ping_timings.len()
            ));
        } else {
            // Compare RTT values (within tolerance)
            for (i, (asupersync_timing, h2_timing)) in asupersync
                .ping_timings
                .iter()
                .zip(&h2.ping_timings)
                .enumerate()
            {
                if let (Some(asupersync_rtt), Some(h2_rtt)) =
                    (asupersync_timing.rtt_ms, h2_timing.rtt_ms)
                {
                    let diff = asupersync_rtt.abs_diff(h2_rtt);
                    if diff > 5 {
                        // 5ms tolerance
                        differences.push(format!(
                            "ping_timing[{}] RTT differs by {}ms: asupersync={}ms, h2={}ms",
                            i, diff, asupersync_rtt, h2_rtt
                        ));
                    }
                } else if asupersync_timing.rtt_ms != h2_timing.rtt_ms {
                    differences.push(format!(
                        "ping_timing[{}] RTT availability differs: asupersync={:?}ms, h2={:?}ms",
                        i, asupersync_timing.rtt_ms, h2_timing.rtt_ms
                    ));
                }
            }
        }

        differences
    }

    /// Generate a markdown report.
    pub fn generate_markdown_report(&self, report: &PingComplianceReport) -> String {
        let mut output = String::new();
        output.push_str("# HTTP/2 PING Frame Conformance Report\n\n");

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
                if result.verdict == PingTestVerdict::Fail {
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

impl Default for PingConformanceTester {
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

/// Process a PING frame through the production connection state machine.
fn process_live_ping_frame(
    connection: &mut Connection,
    ping_frame: &PingFrame,
) -> Result<(), String> {
    let received = connection
        .process_frame(Frame::Ping(ping_frame.clone()))
        .map_err(|err| err.to_string())?;
    if received.is_some() {
        return Err(format!(
            "PING produced unexpected application frame: {received:?}"
        ));
    }
    Ok(())
}

/// Extract PING-related connection state from asupersync connection.
fn extract_asupersync_ping_state(
    connection: &mut Connection,
    ping_timings: Vec<PingTiming>,
) -> Result<PingConnectionState, String> {
    let mut pending_ping_acks = 0;
    while connection.has_pending_frames() {
        match connection.next_frame() {
            Some(Frame::Ping(ping)) if ping.ack => pending_ping_acks += 1,
            Some(frame) => {
                return Err(format!(
                    "unexpected pending frame after PING processing: {frame:?}"
                ));
            }
            None => break,
        }
    }

    Ok(PingConnectionState {
        connection_state: format!("{:?}", connection.state()),
        pending_ping_acks,
        ping_timings,
        has_errors: false,
    })
}

/// Create predefined test cases for PING frame conformance.
fn create_ping_test_cases() -> Vec<PingConformanceCase> {
    vec![
        // Test Case 1: Basic PING/PING_ACK exchange
        PingConformanceCase {
            id: "ping-001".to_string(),
            description: "Basic PING frame generates PING_ACK response".to_string(),
            requirement_level: RequirementLevel::Must,
            ping_sequence: vec![
                SerializablePingFrame {
                    opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
                    ack: false,
                    timestamp_ms: 0,
                },
                SerializablePingFrame {
                    opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
                    ack: true,
                    timestamp_ms: 50, // 50ms later
                },
            ],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(),
                pending_ping_acks: 1,
                ping_timings: vec![PingTiming {
                    sent_at_ms: 0,
                    ack_received_at_ms: Some(50),
                    rtt_ms: Some(50),
                }],
                has_errors: false,
            },
            expected_rtt_behavior: "RTT calculated from PING/ACK timing".to_string(),
        },
        // Test Case 2: PING with zero payload
        PingConformanceCase {
            id: "ping-002".to_string(),
            description: "PING with zero payload works correctly".to_string(),
            requirement_level: RequirementLevel::Must,
            ping_sequence: vec![
                SerializablePingFrame {
                    opaque_data: [0, 0, 0, 0, 0, 0, 0, 0],
                    ack: false,
                    timestamp_ms: 0,
                },
                SerializablePingFrame {
                    opaque_data: [0, 0, 0, 0, 0, 0, 0, 0],
                    ack: true,
                    timestamp_ms: 25,
                },
            ],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(),
                pending_ping_acks: 1,
                ping_timings: vec![PingTiming {
                    sent_at_ms: 0,
                    ack_received_at_ms: Some(25),
                    rtt_ms: Some(25),
                }],
                has_errors: false,
            },
            expected_rtt_behavior: "RTT calculated correctly with zero payload".to_string(),
        },
        // Test Case 3: PING with maximum payload
        PingConformanceCase {
            id: "ping-003".to_string(),
            description: "PING with maximum payload (0xFF bytes)".to_string(),
            requirement_level: RequirementLevel::Must,
            ping_sequence: vec![
                SerializablePingFrame {
                    opaque_data: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    ack: false,
                    timestamp_ms: 100,
                },
                SerializablePingFrame {
                    opaque_data: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    ack: true,
                    timestamp_ms: 175,
                },
            ],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(),
                pending_ping_acks: 1,
                ping_timings: vec![PingTiming {
                    sent_at_ms: 100,
                    ack_received_at_ms: Some(175),
                    rtt_ms: Some(75),
                }],
                has_errors: false,
            },
            expected_rtt_behavior: "RTT calculated correctly with max payload".to_string(),
        },
        // Test Case 4: Multiple PING exchanges
        PingConformanceCase {
            id: "ping-004".to_string(),
            description: "Multiple PING/PING_ACK exchanges track RTT correctly".to_string(),
            requirement_level: RequirementLevel::Should,
            ping_sequence: vec![
                // First PING
                SerializablePingFrame {
                    opaque_data: [1, 0, 0, 0, 0, 0, 0, 0],
                    ack: false,
                    timestamp_ms: 0,
                },
                SerializablePingFrame {
                    opaque_data: [1, 0, 0, 0, 0, 0, 0, 0],
                    ack: true,
                    timestamp_ms: 30,
                },
                // Second PING
                SerializablePingFrame {
                    opaque_data: [2, 0, 0, 0, 0, 0, 0, 0],
                    ack: false,
                    timestamp_ms: 100,
                },
                SerializablePingFrame {
                    opaque_data: [2, 0, 0, 0, 0, 0, 0, 0],
                    ack: true,
                    timestamp_ms: 140,
                },
            ],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(),
                pending_ping_acks: 2,
                ping_timings: vec![
                    PingTiming {
                        sent_at_ms: 0,
                        ack_received_at_ms: Some(30),
                        rtt_ms: Some(30),
                    },
                    PingTiming {
                        sent_at_ms: 100,
                        ack_received_at_ms: Some(140),
                        rtt_ms: Some(40),
                    },
                ],
                has_errors: false,
            },
            expected_rtt_behavior: "Multiple RTT measurements maintained".to_string(),
        },
        // Test Case 5: PING without ACK (pending state)
        PingConformanceCase {
            id: "ping-005".to_string(),
            description: "PING without matching ACK remains pending".to_string(),
            requirement_level: RequirementLevel::Must,
            ping_sequence: vec![
                SerializablePingFrame {
                    opaque_data: [9, 8, 7, 6, 5, 4, 3, 2],
                    ack: false,
                    timestamp_ms: 0,
                },
                // No corresponding PING_ACK
            ],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(),
                pending_ping_acks: 1, // Should be pending
                ping_timings: vec![PingTiming {
                    sent_at_ms: 0,
                    ack_received_at_ms: None,
                    rtt_ms: None,
                }],
                has_errors: false,
            },
            expected_rtt_behavior: "Pending PING tracked without RTT".to_string(),
        },
        // Test Case 6: PING ACK only (no corresponding PING)
        PingConformanceCase {
            id: "ping-006".to_string(),
            description: "Received PING_ACK without PING should not cause errors".to_string(),
            requirement_level: RequirementLevel::Should,
            ping_sequence: vec![SerializablePingFrame {
                opaque_data: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
                ack: true, // ACK without corresponding PING
                timestamp_ms: 50,
            }],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(),
                pending_ping_acks: 0,
                ping_timings: Vec::new(),
                has_errors: false, // Should not cause connection errors
            },
            expected_rtt_behavior: "Orphan PING_ACK ignored gracefully".to_string(),
        },
        // Test Case 7: High-frequency PING stress test
        PingConformanceCase {
            id: "ping-007".to_string(),
            description: "High-frequency PING exchanges maintain stability".to_string(),
            requirement_level: RequirementLevel::May,
            ping_sequence: vec![
                // Rapid succession of PINGs
                SerializablePingFrame {
                    opaque_data: [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
                    ack: false,
                    timestamp_ms: 0,
                },
                SerializablePingFrame {
                    opaque_data: [0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02],
                    ack: false,
                    timestamp_ms: 5,
                },
                SerializablePingFrame {
                    opaque_data: [0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03],
                    ack: false,
                    timestamp_ms: 10,
                },
                // Corresponding ACKs
                SerializablePingFrame {
                    opaque_data: [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
                    ack: true,
                    timestamp_ms: 15,
                },
                SerializablePingFrame {
                    opaque_data: [0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02],
                    ack: true,
                    timestamp_ms: 20,
                },
                SerializablePingFrame {
                    opaque_data: [0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03],
                    ack: true,
                    timestamp_ms: 25,
                },
            ],
            expected_connection_state: PingConnectionState {
                connection_state: "Open".to_string(), // No spurious GOAWAY
                pending_ping_acks: 3,
                ping_timings: vec![
                    PingTiming {
                        sent_at_ms: 0,
                        ack_received_at_ms: Some(15),
                        rtt_ms: Some(15),
                    },
                    PingTiming {
                        sent_at_ms: 5,
                        ack_received_at_ms: Some(20),
                        rtt_ms: Some(15),
                    },
                    PingTiming {
                        sent_at_ms: 10,
                        ack_received_at_ms: Some(25),
                        rtt_ms: Some(15),
                    },
                ],
                has_errors: false,
            },
            expected_rtt_behavior: "High-frequency PING does not destabilize connection"
                .to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ack_ping_queues_one_ack_with_same_opaque_data() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");

        let ping = PingFrame::new(*b"pingpong");
        process_live_ping_frame(&mut connection, &ping).expect("PING should process");

        match connection.next_frame() {
            Some(Frame::Ping(ack)) => {
                assert!(ack.ack);
                assert_eq!(ack.opaque_data, *b"pingpong");
            }
            other => panic!("expected PING ACK, got {other:?}"),
        }
        assert!(!connection.has_pending_frames());
    }

    #[test]
    fn ping_ack_does_not_queue_another_ack() {
        let mut connection = Connection::server(Settings::default());
        accept_peer_settings(&mut connection).expect("SETTINGS handshake");

        let ping_ack = PingFrame::ack(*b"ack-only");
        process_live_ping_frame(&mut connection, &ping_ack).expect("PING ACK should process");

        assert!(
            !connection.has_pending_frames(),
            "incoming PING ACK must not be ACKed again"
        );
    }

    #[test]
    fn invalid_ping_payload_length_is_rejected_by_parser() {
        let short_header = FrameHeader {
            length: 7,
            frame_type: FrameType::Ping as u8,
            flags: 0,
            stream_id: 0,
        };
        assert!(
            parse_frame(&short_header, Bytes::from_static(b"1234567")).is_err(),
            "PING payloads shorter than 8 bytes must be rejected"
        );

        let long_header = FrameHeader {
            length: 9,
            frame_type: FrameType::Ping as u8,
            flags: 0,
            stream_id: 0,
        };
        assert!(
            parse_frame(&long_header, Bytes::from_static(b"123456789")).is_err(),
            "PING payloads longer than 8 bytes must be rejected"
        );
    }

    #[tokio::test]
    async fn h2_reference_unavailable_still_runs_live_ping_assertions() {
        let tester = PingConformanceTester::new();
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
        let tester = PingConformanceTester::new();
        let report = tester.run_all_tests().await;

        assert!(
            report
                .results
                .iter()
                .all(|result| result.verdict == PingTestVerdict::ExpectedFailure),
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
}
