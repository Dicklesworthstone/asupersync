//! HTTP/2 PING with ACK frames RTT measurement conformance test
//!
//! This module exercises asupersync's HTTP/2 PING frame timing model.
//!
//! A live h2 crate PING frame observation seam is not wired yet. The reference
//! side therefore fails closed instead of reporting model-only timing as
//! differential conformance evidence.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const H2_PING_REFERENCE_UNSUPPORTED: &str =
    "h2 PING frame RTT reference observation is not wired; refusing model-only conformance";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingTestCase {
    pub id: String,
    pub description: String,
    pub ping_payload: [u8; 8],
    pub timing_scenario: TimingScenario,
    pub expected_behavior: ExpectedBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimingScenario {
    /// Single PING -> PING+ACK sequence with fixed timing
    SinglePing {
        ping_time: Duration,
        ack_delay: Duration,
    },
    /// Multiple PINGs in flight with different payloads
    MultiplePings {
        ping_intervals: Vec<Duration>,
        ack_delays: Vec<Duration>,
    },
    /// PING with payload that should not be modified in ACK
    PayloadPreservation {
        payload: [u8; 8],
        round_trip_time: Duration,
    },
    /// Rapid PING/PONG sequence stress test
    RapidSequence { count: u32, interval: Duration },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpectedBehavior {
    /// RTT should match within tolerance
    RttWithinTolerance {
        expected_rtt: Duration,
        tolerance: Duration,
    },
    /// Payload should be preserved exactly
    PayloadPreserved,
    /// All PINGs should receive ACKs
    AllPingsAcked,
    /// RTT measurements should be monotonic for increasing delays
    RttMonotonic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceResults {
    pub test_id: String,
    pub test_description: String,
    pub asupersync_result: TestResult,
    pub h2_result: TestResult,
    pub comparison: ComparisonResult,
    pub conformant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub success: bool,
    pub rtt_measurements: Vec<Duration>,
    pub ping_payloads_sent: Vec<[u8; 8]>,
    pub ack_payloads_received: Vec<[u8; 8]>,
    pub error: Option<String>,
    pub timing_analysis: TimingAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    pub min_rtt: Option<Duration>,
    pub max_rtt: Option<Duration>,
    pub avg_rtt: Option<Duration>,
    pub rtt_variance: Option<Duration>,
    pub payload_corruption_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub rtt_difference: Option<Duration>,
    pub payload_match: bool,
    pub timing_correlation: f64,
    pub divergence_points: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub timestamp: String,
    pub total_tests: usize,
    pub passing_tests: usize,
    pub conformant_implementations: bool,
    pub test_results: Vec<ConformanceResults>,
    pub summary: TestSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub rtt_accuracy_score: f64,
    pub payload_preservation_score: f64,
    pub timing_consistency_score: f64,
    pub overall_conformance_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Markdown,
    Summary,
}

/// Generate comprehensive test cases for PING RTT measurement
pub fn generate_ping_test_cases() -> Vec<PingTestCase> {
    vec![
        PingTestCase {
            id: "ping_basic_rtt".to_string(),
            description: "Basic PING->PING+ACK RTT measurement".to_string(),
            ping_payload: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            timing_scenario: TimingScenario::SinglePing {
                ping_time: Duration::from_millis(0),
                ack_delay: Duration::from_millis(50),
            },
            expected_behavior: ExpectedBehavior::RttWithinTolerance {
                expected_rtt: Duration::from_millis(50),
                tolerance: Duration::from_millis(5),
            },
        },
        PingTestCase {
            id: "ping_payload_preservation".to_string(),
            description: "PING payload must be preserved in ACK".to_string(),
            ping_payload: [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
            timing_scenario: TimingScenario::PayloadPreservation {
                payload: [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
                round_trip_time: Duration::from_millis(25),
            },
            expected_behavior: ExpectedBehavior::PayloadPreserved,
        },
        PingTestCase {
            id: "ping_multiple_in_flight".to_string(),
            description: "Multiple PINGs in flight with different payloads".to_string(),
            ping_payload: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            timing_scenario: TimingScenario::MultiplePings {
                ping_intervals: vec![
                    Duration::from_millis(0),
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                ],
                ack_delays: vec![
                    Duration::from_millis(30),
                    Duration::from_millis(35),
                    Duration::from_millis(40),
                ],
            },
            expected_behavior: ExpectedBehavior::AllPingsAcked,
        },
        PingTestCase {
            id: "ping_rapid_sequence".to_string(),
            description: "Rapid PING/PONG sequence stress test".to_string(),
            ping_payload: [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            timing_scenario: TimingScenario::RapidSequence {
                count: 10,
                interval: Duration::from_millis(5),
            },
            expected_behavior: ExpectedBehavior::AllPingsAcked,
        },
        PingTestCase {
            id: "ping_rtt_monotonic".to_string(),
            description: "RTT measurements should be monotonic for increasing delays".to_string(),
            ping_payload: [0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a],
            timing_scenario: TimingScenario::MultiplePings {
                ping_intervals: vec![
                    Duration::from_millis(0),
                    Duration::from_millis(100),
                    Duration::from_millis(200),
                ],
                ack_delays: vec![
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                    Duration::from_millis(30),
                ],
            },
            expected_behavior: ExpectedBehavior::RttMonotonic,
        },
        PingTestCase {
            id: "ping_zero_payload".to_string(),
            description: "PING with zero payload".to_string(),
            ping_payload: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            timing_scenario: TimingScenario::SinglePing {
                ping_time: Duration::from_millis(0),
                ack_delay: Duration::from_millis(15),
            },
            expected_behavior: ExpectedBehavior::PayloadPreserved,
        },
        PingTestCase {
            id: "ping_max_payload".to_string(),
            description: "PING with maximum payload values".to_string(),
            ping_payload: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            timing_scenario: TimingScenario::SinglePing {
                ping_time: Duration::from_millis(0),
                ack_delay: Duration::from_millis(100),
            },
            expected_behavior: ExpectedBehavior::PayloadPreserved,
        },
        PingTestCase {
            id: "ping_pattern_payload".to_string(),
            description: "PING with alternating bit pattern".to_string(),
            ping_payload: [0xaa, 0x55, 0xaa, 0x55, 0x33, 0xcc, 0x33, 0xcc],
            timing_scenario: TimingScenario::PayloadPreservation {
                payload: [0xaa, 0x55, 0xaa, 0x55, 0x33, 0xcc, 0x33, 0xcc],
                round_trip_time: Duration::from_millis(75),
            },
            expected_behavior: ExpectedBehavior::PayloadPreserved,
        },
    ]
}

/// Run asupersync PING RTT test
async fn run_asupersync_ping_test(test_case: &PingTestCase) -> TestResult {
    match run_asupersync_ping_test_impl(test_case).await {
        Ok(result) => result,
        Err(e) => TestResult {
            success: false,
            rtt_measurements: Vec::new(),
            ping_payloads_sent: Vec::new(),
            ack_payloads_received: Vec::new(),
            error: Some(format!("Asupersync test failed: {}", e)),
            timing_analysis: TimingAnalysis {
                min_rtt: None,
                max_rtt: None,
                avg_rtt: None,
                rtt_variance: None,
                payload_corruption_detected: false,
            },
        },
    }
}

async fn run_asupersync_ping_test_impl(
    test_case: &PingTestCase,
) -> Result<TestResult, Box<dyn std::error::Error>> {
    let mut rtt_measurements = Vec::new();
    let mut ping_payloads_sent = Vec::new();
    let mut ack_payloads_received = Vec::new();

    match &test_case.timing_scenario {
        TimingScenario::SinglePing { ack_delay, .. } => {
            // Simulate single PING->ACK with controlled timing
            let start_time = Instant::now();
            ping_payloads_sent.push(test_case.ping_payload);

            // Simulate network delay
            tokio::time::sleep(*ack_delay).await;

            let end_time = Instant::now();
            let measured_rtt = end_time.duration_since(start_time);
            rtt_measurements.push(measured_rtt);
            ack_payloads_received.push(test_case.ping_payload); // Payload preserved
        }
        TimingScenario::MultiplePings {
            ping_intervals,
            ack_delays,
        } => {
            for (i, ack_delay) in ack_delays.iter().enumerate() {
                if i < ping_intervals.len() {
                    let mut payload = test_case.ping_payload;
                    payload[7] = i as u8; // Vary payload slightly

                    let start_time = Instant::now();
                    ping_payloads_sent.push(payload);

                    tokio::time::sleep(*ack_delay).await;

                    let end_time = Instant::now();
                    let measured_rtt = end_time.duration_since(start_time);
                    rtt_measurements.push(measured_rtt);
                    ack_payloads_received.push(payload);
                }
            }
        }
        TimingScenario::PayloadPreservation {
            payload,
            round_trip_time,
        } => {
            let start_time = Instant::now();
            ping_payloads_sent.push(*payload);

            tokio::time::sleep(*round_trip_time).await;

            let end_time = Instant::now();
            let measured_rtt = end_time.duration_since(start_time);
            rtt_measurements.push(measured_rtt);
            ack_payloads_received.push(*payload);
        }
        TimingScenario::RapidSequence { count, interval } => {
            for i in 0..*count {
                let mut payload = test_case.ping_payload;
                // Include sequence number in payload
                payload[6] = (i >> 8) as u8;
                payload[7] = (i & 0xff) as u8;

                let start_time = Instant::now();
                ping_payloads_sent.push(payload);

                tokio::time::sleep(*interval).await;

                let end_time = Instant::now();
                let measured_rtt = end_time.duration_since(start_time);
                rtt_measurements.push(measured_rtt);
                ack_payloads_received.push(payload);
            }
        }
    }

    let timing_analysis = analyze_timing(
        &rtt_measurements,
        &ping_payloads_sent,
        &ack_payloads_received,
    );

    Ok(TestResult {
        success: true,
        rtt_measurements,
        ping_payloads_sent,
        ack_payloads_received,
        error: None,
        timing_analysis,
    })
}

/// Run h2 reference implementation PING RTT test
async fn run_h2_ping_test(test_case: &PingTestCase) -> TestResult {
    TestResult {
        success: false,
        rtt_measurements: Vec::new(),
        ping_payloads_sent: Vec::new(),
        ack_payloads_received: Vec::new(),
        error: Some(format!(
            "{H2_PING_REFERENCE_UNSUPPORTED}; test_id={}",
            test_case.id
        )),
        timing_analysis: TimingAnalysis {
            min_rtt: None,
            max_rtt: None,
            avg_rtt: None,
            rtt_variance: None,
            payload_corruption_detected: false,
        },
    }
}

fn analyze_timing(
    rtt_measurements: &[Duration],
    ping_payloads: &[[u8; 8]],
    ack_payloads: &[[u8; 8]],
) -> TimingAnalysis {
    let min_rtt = rtt_measurements.iter().min().copied();
    let max_rtt = rtt_measurements.iter().max().copied();

    let avg_rtt = if !rtt_measurements.is_empty() {
        let sum: Duration = rtt_measurements.iter().sum();
        Some(sum / rtt_measurements.len() as u32)
    } else {
        None
    };

    let rtt_variance = if rtt_measurements.len() > 1 && avg_rtt.is_some() {
        let avg = avg_rtt.unwrap();
        let variance_sum: u128 = rtt_measurements
            .iter()
            .map(|&rtt| {
                let diff = if rtt > avg { rtt - avg } else { avg - rtt };
                diff.as_nanos() * diff.as_nanos()
            })
            .sum();
        let variance_ns = variance_sum / (rtt_measurements.len() as u128);
        Some(Duration::from_nanos((variance_ns as f64).sqrt() as u64))
    } else {
        None
    };

    let payload_corruption_detected = ping_payloads != ack_payloads;

    TimingAnalysis {
        min_rtt,
        max_rtt,
        avg_rtt,
        rtt_variance,
        payload_corruption_detected,
    }
}

fn compare_results(
    _test_case: &PingTestCase,
    asupersync_result: &TestResult,
    h2_result: &TestResult,
) -> ComparisonResult {
    let rtt_difference = if let (Some(asupersync_avg), Some(h2_avg)) = (
        asupersync_result.timing_analysis.avg_rtt,
        h2_result.timing_analysis.avg_rtt,
    ) {
        Some(if asupersync_avg > h2_avg {
            asupersync_avg - h2_avg
        } else {
            h2_avg - asupersync_avg
        })
    } else {
        None
    };

    let payload_match = asupersync_result.ping_payloads_sent == h2_result.ping_payloads_sent
        && asupersync_result.ack_payloads_received == h2_result.ack_payloads_received;

    let timing_correlation = calculate_timing_correlation(
        &asupersync_result.rtt_measurements,
        &h2_result.rtt_measurements,
    );

    let mut divergence_points = Vec::new();

    if let Some(error) = &asupersync_result.error {
        divergence_points.push(format!("asupersync side failed: {error}"));
    }

    if let Some(error) = &h2_result.error {
        divergence_points.push(format!("h2 reference unavailable: {error}"));
    }

    if !payload_match {
        divergence_points.push("Payload handling differs between implementations".to_string());
    }

    if let Some(rtt_diff) = rtt_difference {
        if rtt_diff > Duration::from_millis(10) {
            divergence_points.push(format!("RTT difference exceeds threshold: {:?}", rtt_diff));
        }
    }

    if timing_correlation < 0.9 {
        divergence_points.push(format!(
            "Timing correlation too low: {:.3}",
            timing_correlation
        ));
    }

    ComparisonResult {
        rtt_difference,
        payload_match,
        timing_correlation,
        divergence_points,
    }
}

fn calculate_timing_correlation(rtts1: &[Duration], rtts2: &[Duration]) -> f64 {
    if rtts1.len() != rtts2.len() || rtts1.is_empty() {
        return 0.0;
    }

    let n = rtts1.len() as f64;
    let sum1: f64 = rtts1.iter().map(|d| d.as_nanos() as f64).sum();
    let sum2: f64 = rtts2.iter().map(|d| d.as_nanos() as f64).sum();
    let sum1_sq: f64 = rtts1.iter().map(|d| (d.as_nanos() as f64).powi(2)).sum();
    let sum2_sq: f64 = rtts2.iter().map(|d| (d.as_nanos() as f64).powi(2)).sum();
    let sum_product: f64 = rtts1
        .iter()
        .zip(rtts2.iter())
        .map(|(d1, d2)| (d1.as_nanos() as f64) * (d2.as_nanos() as f64))
        .sum();

    let numerator = n * sum_product - sum1 * sum2;
    let denominator = ((n * sum1_sq - sum1.powi(2)) * (n * sum2_sq - sum2.powi(2))).sqrt();

    if denominator == 0.0 {
        1.0
    } else {
        numerator / denominator
    }
}

/// Run a single conformance test case
pub async fn run_single_conformance_test(test_case: &PingTestCase) -> ConformanceResults {
    let asupersync_result = run_asupersync_ping_test(test_case).await;
    let h2_result = run_h2_ping_test(test_case).await;

    let comparison = compare_results(test_case, &asupersync_result, &h2_result);

    let conformant = asupersync_result.success
        && h2_result.success
        && comparison.payload_match
        && comparison.divergence_points.is_empty();

    ConformanceResults {
        test_id: test_case.id.clone(),
        test_description: test_case.description.clone(),
        asupersync_result,
        h2_result,
        comparison,
        conformant,
    }
}

/// Run basic conformance test suite
pub fn run_basic_conformance_tests() -> ConformanceReport {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        let test_cases = generate_ping_test_cases();
        let basic_cases = &test_cases[0..4]; // First 4 tests for basic suite

        let mut test_results = Vec::new();

        for test_case in basic_cases {
            println!("Running test: {}", test_case.id);
            let result = run_single_conformance_test(test_case).await;
            test_results.push(result);
        }

        let passing_tests = test_results.iter().filter(|r| r.conformant).count();
        let conformant_implementations = passing_tests == test_results.len();

        let summary = calculate_test_summary(&test_results);

        ConformanceReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            total_tests: test_results.len(),
            passing_tests,
            conformant_implementations,
            test_results,
            summary,
        }
    })
}

/// Run comprehensive conformance test suite
pub fn run_all_conformance_tests() -> ConformanceReport {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        let test_cases = generate_ping_test_cases();

        let mut test_results = Vec::new();

        for test_case in &test_cases {
            println!("Running test: {}", test_case.id);
            let result = run_single_conformance_test(test_case).await;
            test_results.push(result);
        }

        let passing_tests = test_results.iter().filter(|r| r.conformant).count();
        let conformant_implementations = passing_tests == test_results.len();

        let summary = calculate_test_summary(&test_results);

        ConformanceReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            total_tests: test_results.len(),
            passing_tests,
            conformant_implementations,
            test_results,
            summary,
        }
    })
}

fn calculate_test_summary(test_results: &[ConformanceResults]) -> TestSummary {
    let total = test_results.len() as f64;

    if total == 0.0 {
        return TestSummary {
            rtt_accuracy_score: 0.0,
            payload_preservation_score: 0.0,
            timing_consistency_score: 0.0,
            overall_conformance_score: 0.0,
        };
    }

    let rtt_accurate = test_results
        .iter()
        .filter(|r| {
            r.asupersync_result.success
                && r.h2_result.success
                && r.comparison
                    .rtt_difference
                    .is_some_and(|d| d < Duration::from_millis(10))
        })
        .count() as f64;

    let payload_preserved = test_results
        .iter()
        .filter(|r| {
            r.asupersync_result.success && r.h2_result.success && r.comparison.payload_match
        })
        .count() as f64;

    let timing_consistent = test_results
        .iter()
        .filter(|r| {
            r.asupersync_result.success
                && r.h2_result.success
                && r.comparison.timing_correlation > 0.9
        })
        .count() as f64;

    let overall_conformant = test_results.iter().filter(|r| r.conformant).count() as f64;

    TestSummary {
        rtt_accuracy_score: rtt_accurate / total,
        payload_preservation_score: payload_preserved / total,
        timing_consistency_score: timing_consistent / total,
        overall_conformance_score: overall_conformant / total,
    }
}

/// Format results as summary text
pub fn format_results_as_summary(results: &ConformanceReport) -> String {
    let mut output = String::new();

    output.push_str("H2 PING RTT Measurement Conformance Test Results\n");
    output.push_str("================================================\n\n");

    output.push_str(&format!("Timestamp: {}\n", results.timestamp));
    output.push_str(&format!("Total Tests: {}\n", results.total_tests));
    output.push_str(&format!("Passing: {}\n", results.passing_tests));
    output.push_str(&format!(
        "Conformant: {}\n\n",
        if results.conformant_implementations {
            "YES"
        } else {
            "NO"
        }
    ));
    output.push_str(&format!(
        "Reference Status: {}\n\n",
        H2_PING_REFERENCE_UNSUPPORTED
    ));

    output.push_str("Test Summary:\n");
    output.push_str(&format!(
        "  RTT Accuracy Score: {:.1}%\n",
        results.summary.rtt_accuracy_score * 100.0
    ));
    output.push_str(&format!(
        "  Payload Preservation Score: {:.1}%\n",
        results.summary.payload_preservation_score * 100.0
    ));
    output.push_str(&format!(
        "  Timing Consistency Score: {:.1}%\n",
        results.summary.timing_consistency_score * 100.0
    ));
    output.push_str(&format!(
        "  Overall Conformance Score: {:.1}%\n\n",
        results.summary.overall_conformance_score * 100.0
    ));

    for (i, result) in results.test_results.iter().enumerate() {
        output.push_str(&format!(
            "{}. {} [{}]\n",
            i + 1,
            result.test_description,
            if result.conformant { "PASS" } else { "FAIL" }
        ));

        if !result.conformant && !result.comparison.divergence_points.is_empty() {
            output.push_str("   Divergences:\n");
            for divergence in &result.comparison.divergence_points {
                output.push_str(&format!("   - {}\n", divergence));
            }
        }
    }

    output
}

/// Format results as markdown report
pub fn format_results_as_markdown(results: &ConformanceReport) -> String {
    let mut output = String::new();

    output.push_str("# H2 PING RTT Measurement Conformance Test Results\n\n");

    output.push_str(&format!("**Timestamp:** {}\n", results.timestamp));
    output.push_str(&format!("**Total Tests:** {}\n", results.total_tests));
    output.push_str(&format!("**Passing:** {}\n", results.passing_tests));
    output.push_str(&format!(
        "**Conformant:** {}\n\n",
        if results.conformant_implementations {
            "✅ YES"
        } else {
            "❌ NO"
        }
    ));
    output.push_str(&format!(
        "**Reference Status:** `{}`\n\n",
        H2_PING_REFERENCE_UNSUPPORTED
    ));

    output.push_str("## Test Summary\n\n");
    output.push_str("| Metric | Score |\n");
    output.push_str("|--------|-------|\n");
    output.push_str(&format!(
        "| RTT Accuracy | {:.1}% |\n",
        results.summary.rtt_accuracy_score * 100.0
    ));
    output.push_str(&format!(
        "| Payload Preservation | {:.1}% |\n",
        results.summary.payload_preservation_score * 100.0
    ));
    output.push_str(&format!(
        "| Timing Consistency | {:.1}% |\n",
        results.summary.timing_consistency_score * 100.0
    ));
    output.push_str(&format!(
        "| Overall Conformance | {:.1}% |\n\n",
        results.summary.overall_conformance_score * 100.0
    ));

    output.push_str("## Individual Test Results\n\n");

    for (i, result) in results.test_results.iter().enumerate() {
        let status = if result.conformant {
            "✅ PASS"
        } else {
            "❌ FAIL"
        };
        output.push_str(&format!(
            "### {}. {} {}\n\n",
            i + 1,
            result.test_description,
            status
        ));

        if !result.conformant && !result.comparison.divergence_points.is_empty() {
            output.push_str("**Divergences:**\n");
            for divergence in &result.comparison.divergence_points {
                output.push_str(&format!("- {}\n", divergence));
            }
            output.push('\n');
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_reference_fails_closed_instead_of_returning_modeled_timing() {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let test_case = generate_ping_test_cases()
            .into_iter()
            .next()
            .expect("at least one ping case");

        let result = runtime.block_on(run_h2_ping_test(&test_case));

        assert!(!result.success);
        assert!(result.rtt_measurements.is_empty());
        assert!(result.ping_payloads_sent.is_empty());
        assert!(result.ack_payloads_received.is_empty());
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains(H2_PING_REFERENCE_UNSUPPORTED))
        );
    }

    #[test]
    fn conformance_result_records_unsupported_h2_reference() {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let test_case = generate_ping_test_cases()
            .into_iter()
            .next()
            .expect("at least one ping case");

        let result = runtime.block_on(run_single_conformance_test(&test_case));

        assert!(!result.conformant);
        assert!(
            result
                .comparison
                .divergence_points
                .iter()
                .any(|point| point.contains("h2 reference unavailable"))
        );
    }

    #[test]
    fn formatted_summary_exposes_fail_closed_reference_status() {
        let report = ConformanceReport {
            timestamp: "2026-05-08T00:00:00Z".to_string(),
            total_tests: 0,
            passing_tests: 0,
            conformant_implementations: false,
            test_results: Vec::new(),
            summary: TestSummary {
                rtt_accuracy_score: 0.0,
                payload_preservation_score: 0.0,
                timing_consistency_score: 0.0,
                overall_conformance_score: 0.0,
            },
        };

        let summary = format_results_as_summary(&report);
        assert!(summary.contains(H2_PING_REFERENCE_UNSUPPORTED));
    }
}
