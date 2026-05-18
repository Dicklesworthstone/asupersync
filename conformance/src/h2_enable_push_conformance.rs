//! HTTP/2 SETTINGS_ENABLE_PUSH=0 enforcement conformance testing.
//!
//! This harness tests the production asupersync HTTP/2 SETTINGS_ENABLE_PUSH
//! and PUSH_PROMISE seams. It intentionally does not synthesize h2 reference
//! behavior when no live h2 peer is wired into this crate.

use asupersync::bytes::{BufMut, BytesMut};
use asupersync::http::h2::connection::{Connection, ReceivedFrame};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    Frame, FrameHeader, FrameType, PushPromiseFrame, Setting, SettingsFrame, parse_frame,
};
use asupersync::http::h2::hpack::{Encoder, Header};
use asupersync::http::h2::settings::Settings;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Test verdict for enable push conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnablePushTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for EnablePushTestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::ExpectedFailure => write!(f, "XFAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Single HTTP/2 ENABLE_PUSH conformance test case.
#[derive(Debug, Clone)]
pub struct EnablePushConformanceCase {
    pub id: String,
    pub description: String,
    pub enable_push_setting: bool,
    pub requests: Vec<TestRequest>,
    pub expected_push_promise_count: usize,
}

/// HTTP/2 request for testing push promise behavior.
#[derive(Debug, Clone)]
pub struct TestRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Resources that the server might try to push
    pub pushable_resources: Vec<String>,
}

/// Result of running a single enable push test case.
#[derive(Debug, Clone, Serialize)]
pub struct EnablePushTestResult {
    pub case_id: String,
    pub verdict: EnablePushTestVerdict,
    pub error: Option<String>,
    pub asupersync_push_promise_count: usize,
    pub h2_push_promise_count: usize,
    pub push_promises_match: bool,
    pub reference_comparison_available: bool,
    pub reference_status: String,
    pub support_class: String,
    pub evidence: Vec<String>,
    pub test_duration_ms: u64,
}

#[derive(Debug, Clone)]
struct LiveEnablePushOutcome {
    accepted_push_promises: usize,
    evidence: Vec<String>,
    support_class: String,
}

/// Summary statistics for enable push conformance run.
#[derive(Debug, Clone, Serialize)]
pub struct EnablePushComplianceSummary {
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub total: usize,
    pub compliance_score: f64,
}

/// Complete report for HTTP/2 ENABLE_PUSH conformance.
#[derive(Debug, Clone, Serialize)]
pub struct EnablePushComplianceReport {
    pub test_run_id: String,
    pub timestamp: String,
    pub total_cases: usize,
    pub results: Vec<EnablePushTestResult>,
    pub summary: EnablePushComplianceSummary,
}

/// HTTP/2 ENABLE_PUSH conformance tester.
pub struct EnablePushConformanceTester {
    pub test_cases: Vec<EnablePushConformanceCase>,
}

impl Default for EnablePushConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}

impl EnablePushConformanceTester {
    /// Create a new enable push conformance tester.
    pub fn new() -> Self {
        Self {
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create the standard set of enable push conformance test cases.
    fn create_test_cases() -> Vec<EnablePushConformanceCase> {
        vec![
            EnablePushConformanceCase {
                id: "PUSH-001".to_string(),
                description: "SETTINGS_ENABLE_PUSH=0 disables server push".to_string(),
                enable_push_setting: false,
                requests: vec![TestRequest {
                    method: "GET".to_string(),
                    path: "/index.html".to_string(),
                    headers: vec![
                        ("Accept".to_string(), "text/html".to_string()),
                        ("User-Agent".to_string(), "test-agent/1.0".to_string()),
                    ],
                    pushable_resources: vec![
                        "/style.css".to_string(),
                        "/script.js".to_string(),
                        "/image.png".to_string(),
                    ],
                }],
                expected_push_promise_count: 0,
            },
            EnablePushConformanceCase {
                id: "PUSH-002".to_string(),
                description: "SETTINGS_ENABLE_PUSH=1 permits valid PUSH_PROMISE".to_string(),
                enable_push_setting: true,
                requests: vec![TestRequest {
                    method: "GET".to_string(),
                    path: "/index.html".to_string(),
                    headers: vec![("Accept".to_string(), "text/html".to_string())],
                    pushable_resources: vec!["/style.css".to_string(), "/script.js".to_string()],
                }],
                expected_push_promise_count: 2,
            },
            EnablePushConformanceCase {
                id: "PUSH-003".to_string(),
                description: "Multiple requests with ENABLE_PUSH=0".to_string(),
                enable_push_setting: false,
                requests: vec![
                    TestRequest {
                        method: "GET".to_string(),
                        path: "/page1.html".to_string(),
                        headers: vec![("Accept".to_string(), "text/html".to_string())],
                        pushable_resources: vec!["/css1.css".to_string()],
                    },
                    TestRequest {
                        method: "GET".to_string(),
                        path: "/page2.html".to_string(),
                        headers: vec![("Accept".to_string(), "text/html".to_string())],
                        pushable_resources: vec!["/css2.css".to_string()],
                    },
                ],
                expected_push_promise_count: 0,
            },
            EnablePushConformanceCase {
                id: "PUSH-004".to_string(),
                description: "POST request with ENABLE_PUSH=0".to_string(),
                enable_push_setting: false,
                requests: vec![TestRequest {
                    method: "POST".to_string(),
                    path: "/api/data".to_string(),
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("Content-Length".to_string(), "13".to_string()),
                    ],
                    pushable_resources: vec!["/response.json".to_string()],
                }],
                expected_push_promise_count: 0,
            },
            EnablePushConformanceCase {
                id: "PUSH-005".to_string(),
                description: "Enabled client accepts multiple valid PUSH_PROMISE frames"
                    .to_string(),
                enable_push_setting: true, // Default for servers is true
                requests: vec![TestRequest {
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: vec![("Accept".to_string(), "*/*".to_string())],
                    pushable_resources: vec![
                        "/favicon.ico".to_string(),
                        "/manifest.json".to_string(),
                    ],
                }],
                expected_push_promise_count: 2,
            },
        ]
    }

    /// Run all conformance test cases.
    pub async fn run_all_tests(&mut self) -> EnablePushComplianceReport {
        let test_run_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let total_cases = self.test_cases.len();
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            let result = self.run_single_test(test_case).await;
            results.push(result);
        }

        let summary = self.compute_summary(&results);

        EnablePushComplianceReport {
            test_run_id,
            timestamp,
            total_cases,
            results,
            summary,
        }
    }

    /// Run a single conformance test case.
    async fn run_single_test(&self, test_case: &EnablePushConformanceCase) -> EnablePushTestResult {
        let start_time = std::time::Instant::now();

        // Run test with asupersync implementation
        let asupersync_result = self.test_with_asupersync(test_case).await;

        let duration = start_time.elapsed();

        match asupersync_result {
            Ok(outcome) => {
                let expected = test_case.expected_push_promise_count;
                let verdict = if outcome.accepted_push_promises == expected {
                    EnablePushTestVerdict::Pass
                } else {
                    EnablePushTestVerdict::Fail
                };
                EnablePushTestResult {
                    case_id: test_case.id.clone(),
                    verdict,
                    error: (outcome.accepted_push_promises != expected).then(|| {
                        format!(
                            "expected {expected} accepted PUSH_PROMISE frame(s), got {}",
                            outcome.accepted_push_promises
                        )
                    }),
                    asupersync_push_promise_count: outcome.accepted_push_promises,
                    h2_push_promise_count: 0,
                    push_promises_match: false,
                    reference_comparison_available: false,
                    reference_status: reference_unavailable_status().to_string(),
                    support_class: outcome.support_class,
                    evidence: outcome.evidence,
                    test_duration_ms: duration.as_millis() as u64,
                }
            }
            Err(e) => EnablePushTestResult {
                case_id: test_case.id.clone(),
                verdict: EnablePushTestVerdict::Fail,
                error: Some(e),
                asupersync_push_promise_count: 0,
                h2_push_promise_count: 0,
                push_promises_match: false,
                reference_comparison_available: false,
                reference_status: reference_unavailable_status().to_string(),
                support_class: "failed".to_string(),
                evidence: Vec::new(),
                test_duration_ms: duration.as_millis() as u64,
            },
        }
    }

    /// Test push promise behavior with asupersync implementation.
    async fn test_with_asupersync(
        &self,
        test_case: &EnablePushConformanceCase,
    ) -> Result<LiveEnablePushOutcome, String> {
        let mut evidence = Vec::new();
        assert_settings_parser_accepts_enable_push(test_case.enable_push_setting, &mut evidence)?;
        assert_server_applies_client_enable_push(test_case.enable_push_setting, &mut evidence)?;
        assert_client_rejects_server_enable_push(test_case.enable_push_setting, &mut evidence)?;

        let mut accepted_push_promises = 0;
        let mut local_settings = Settings::client();
        local_settings.enable_push = test_case.enable_push_setting;
        let mut client = Connection::client(local_settings);
        client
            .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .map_err(|err| format!("server initial SETTINGS rejected: {err}"))?;

        let mut next_promised_stream_id = 2;
        for request in &test_case.requests {
            let parent_stream_id = client
                .open_stream(request_headers(request), false)
                .map_err(|err| {
                    format!("failed to open request stream for {}: {err}", request.path)
                })?;

            for resource in &request.pushable_resources {
                let frame = push_promise_frame(parent_stream_id, next_promised_stream_id, resource);
                next_promised_stream_id += 2;
                let parsed = encode_then_parse(Frame::PushPromise(frame))
                    .map_err(|err| format!("PUSH_PROMISE parser rejected {resource}: {err}"))?;
                match client.process_frame(parsed) {
                    Ok(Some(ReceivedFrame::PushPromise {
                        stream_id,
                        promised_stream_id,
                        headers,
                    })) if test_case.enable_push_setting => {
                        if stream_id != parent_stream_id {
                            return Err(format!(
                                "PUSH_PROMISE associated stream mismatch: expected {parent_stream_id}, got {stream_id}"
                            ));
                        }
                        if !headers.iter().any(|header| {
                            header.name == ":path" && header.value == resource.as_str()
                        }) {
                            return Err(format!(
                                "PUSH_PROMISE for stream {promised_stream_id} did not decode :path {resource}"
                            ));
                        }
                        accepted_push_promises += 1;
                    }
                    Err(err)
                        if !test_case.enable_push_setting
                            && err.code == ErrorCode::ProtocolError
                            && err.message.contains("push not enabled") =>
                    {
                        evidence.push(format!(
                            "rejected PUSH_PROMISE for {resource} with push disabled"
                        ));
                    }
                    Ok(other) => {
                        return Err(format!(
                            "unexpected PUSH_PROMISE result for {resource}: {other:?}"
                        ));
                    }
                    Err(err) => {
                        return Err(format!(
                            "unexpected PUSH_PROMISE rejection for {resource}: {err}"
                        ));
                    }
                }
            }
        }

        let support_class = if test_case.enable_push_setting {
            "live-push-promise-accepted"
        } else {
            "live-push-disabled-fail-closed"
        };
        evidence.push(format!(
            "accepted {accepted_push_promises} PUSH_PROMISE frame(s) through Connection::process_frame"
        ));

        Ok(LiveEnablePushOutcome {
            accepted_push_promises,
            evidence,
            support_class: support_class.to_string(),
        })
    }

    /// Compute summary statistics from test results.
    fn compute_summary(&self, results: &[EnablePushTestResult]) -> EnablePushComplianceSummary {
        let passed = results
            .iter()
            .filter(|r| r.verdict == EnablePushTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == EnablePushTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == EnablePushTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == EnablePushTestVerdict::Skipped)
            .count();
        let total = results.len();

        let compliance_score = if total > 0 {
            (passed + expected_failures) as f64 / total as f64
        } else {
            0.0
        };

        EnablePushComplianceSummary {
            passed,
            failed,
            expected_failures,
            skipped,
            total,
            compliance_score,
        }
    }

    /// Generate a markdown report.
    pub fn generate_markdown_report(&self, report: &EnablePushComplianceReport) -> String {
        let mut md = String::new();

        md.push_str("# HTTP/2 SETTINGS_ENABLE_PUSH=0 Conformance Report\n\n");

        md.push_str(&format!("**Test Run ID:** {}\n", report.test_run_id));
        md.push_str(&format!("**Timestamp:** {}\n", report.timestamp));
        md.push_str(&format!("**Total Test Cases:** {}\n\n", report.total_cases));

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- ✅ **Passed:** {}\n", report.summary.passed));
        md.push_str(&format!("- ❌ **Failed:** {}\n", report.summary.failed));
        md.push_str(&format!(
            "- ⚠️ **Expected Failures:** {}\n",
            report.summary.expected_failures
        ));
        md.push_str(&format!("- ⏭️ **Skipped:** {}\n", report.summary.skipped));
        md.push_str(&format!(
            "- 🎯 **Compliance Score:** {:.1}%\n\n",
            report.summary.compliance_score * 100.0
        ));

        md.push_str("## Test Results\n\n");
        md.push_str(
            "| Test ID | Description | Verdict | Support | Asupersync PUSH | Reference |\n",
        );
        md.push_str(
            "|---------|-------------|---------|---------|-----------------|-----------|\n",
        );

        for result in &report.results {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                result.case_id,
                self.test_cases
                    .iter()
                    .find(|case| case.id == result.case_id)
                    .map(|case| case.description.as_str())
                    .unwrap_or("Unknown"),
                result.verdict,
                result.support_class,
                result.asupersync_push_promise_count,
                result.reference_status
            ));
        }

        md.push_str("\n## Failed Tests\n\n");
        let failed_tests: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.verdict == EnablePushTestVerdict::Fail)
            .collect();

        if failed_tests.is_empty() {
            md.push_str("No tests failed.\n\n");
        } else {
            for result in failed_tests {
                md.push_str(&format!("### {}\n\n", result.case_id));
                if let Some(error) = &result.error {
                    md.push_str(&format!("**Error:** {}\n\n", error));
                }
                md.push_str(&format!(
                    "**PUSH_PROMISE Count:** asupersync={}\n\n",
                    result.asupersync_push_promise_count
                ));
            }
        }

        md.push_str("---\n");
        md.push_str(&format!(
            "*Generated by asupersync conformance tester at {}*\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        md
    }
}

fn reference_unavailable_status() -> &'static str {
    "unavailable: no live h2 peer wired; no simulated reference parity"
}

fn assert_settings_parser_accepts_enable_push(
    enable_push: bool,
    evidence: &mut Vec<String>,
) -> Result<(), String> {
    let parsed = parse_raw_enable_push_setting(u32::from(enable_push))
        .map_err(|err| format!("SETTINGS_ENABLE_PUSH parser rejected {enable_push}: {err}"))?;
    match parsed {
        Frame::Settings(frame) if frame.settings == vec![Setting::EnablePush(enable_push)] => {
            evidence.push(format!(
                "parsed SETTINGS_ENABLE_PUSH={} through FrameHeader::parse/parse_frame",
                u32::from(enable_push)
            ));
            Ok(())
        }
        other => Err(format!("unexpected parsed ENABLE_PUSH frame: {other:?}")),
    }
}

fn assert_server_applies_client_enable_push(
    enable_push: bool,
    evidence: &mut Vec<String>,
) -> Result<(), String> {
    let mut server = Connection::server(Settings::server());
    let frame = Frame::Settings(SettingsFrame::new(vec![Setting::EnablePush(enable_push)]));
    server.process_frame(frame).map_err(|err| {
        format!("server rejected client SETTINGS_ENABLE_PUSH={enable_push}: {err}")
    })?;
    if server.remote_settings().enable_push != enable_push {
        return Err(format!(
            "server remote_settings.enable_push = {}, expected {enable_push}",
            server.remote_settings().enable_push
        ));
    }
    match server.next_frame() {
        Some(Frame::Settings(settings)) if settings.ack => {
            evidence.push(format!(
                "server applied client SETTINGS_ENABLE_PUSH={} and queued ACK",
                u32::from(enable_push)
            ));
            Ok(())
        }
        other => Err(format!(
            "server did not queue SETTINGS ACK after ENABLE_PUSH: {other:?}"
        )),
    }
}

fn assert_client_rejects_server_enable_push(
    enable_push: bool,
    evidence: &mut Vec<String>,
) -> Result<(), String> {
    let mut client = Connection::client(Settings::client());
    let frame = Frame::Settings(SettingsFrame::new(vec![Setting::EnablePush(enable_push)]));
    let err = client
        .process_frame(frame)
        .expect_err("client must reject server-sent SETTINGS_ENABLE_PUSH");
    if err.code != ErrorCode::ProtocolError || !err.message.contains("server MUST NOT send") {
        return Err(format!(
            "client rejected server SETTINGS_ENABLE_PUSH with wrong error: {err}"
        ));
    }
    evidence.push(format!(
        "client rejected server SETTINGS_ENABLE_PUSH={} as PROTOCOL_ERROR",
        u32::from(enable_push)
    ));
    Ok(())
}

fn parse_raw_enable_push_setting(value: u32) -> Result<Frame, H2Error> {
    let mut payload = BytesMut::with_capacity(6);
    payload.put_u16(0x2);
    payload.put_u32(value);
    let header = FrameHeader {
        length: 6,
        frame_type: FrameType::Settings as u8,
        flags: 0,
        stream_id: 0,
    };
    parse_frame(&header, payload.freeze())
}

fn encode_then_parse(frame: Frame) -> Result<Frame, H2Error> {
    let mut bytes = BytesMut::new();
    frame.encode(&mut bytes)?;
    let header = FrameHeader::parse(&mut bytes)?;
    parse_frame(&header, bytes.freeze())
}

fn request_headers(request: &TestRequest) -> Vec<Header> {
    let mut headers = vec![
        Header::new(":method", request.method.to_ascii_uppercase()),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.test"),
        Header::new(":path", request.path.clone()),
    ];
    for (name, value) in &request.headers {
        headers.push(Header::new(name.to_ascii_lowercase(), value.clone()));
    }
    headers
}

fn push_promise_frame(
    stream_id: u32,
    promised_stream_id: u32,
    resource_path: &str,
) -> PushPromiseFrame {
    let mut encoder = Encoder::new();
    let mut encoded = BytesMut::new();
    let headers = [
        Header::new(":method", "GET"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.test"),
        Header::new(":path", resource_path),
    ];
    encoder.encode(&headers, &mut encoded);
    PushPromiseFrame {
        stream_id,
        promised_stream_id,
        header_block: encoded.freeze(),
        end_headers: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_push_uses_live_connection_rejection() {
        let tester = EnablePushConformanceTester::new();
        let result = tester.run_single_test(&tester.test_cases[0]).await;

        assert_eq!(result.verdict, EnablePushTestVerdict::Pass);
        assert_eq!(result.asupersync_push_promise_count, 0);
        assert!(!result.reference_comparison_available);
        assert_eq!(result.reference_status, reference_unavailable_status());
        assert_eq!(result.support_class, "live-push-disabled-fail-closed");
        assert!(
            result
                .evidence
                .iter()
                .any(|line| line.contains("push disabled"))
        );
    }

    #[tokio::test]
    async fn enabled_push_accepts_real_push_promise_frames() {
        let tester = EnablePushConformanceTester::new();
        let result = tester.run_single_test(&tester.test_cases[1]).await;

        assert_eq!(result.verdict, EnablePushTestVerdict::Pass);
        assert_eq!(result.asupersync_push_promise_count, 2);
        assert_eq!(result.support_class, "live-push-promise-accepted");
        assert!(
            result
                .evidence
                .iter()
                .any(|line| line.contains("FrameHeader::parse/parse_frame"))
        );
    }

    #[test]
    fn invalid_enable_push_value_is_parser_error() {
        let err = parse_raw_enable_push_setting(2)
            .expect_err("SETTINGS_ENABLE_PUSH values above 1 must fail parsing");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("SETTINGS_ENABLE_PUSH must be 0 or 1"));
    }

    #[test]
    fn role_rules_use_connection_state_machine() {
        let mut evidence = Vec::new();
        assert_server_applies_client_enable_push(false, &mut evidence).unwrap();
        assert_client_rejects_server_enable_push(false, &mut evidence).unwrap();
        assert!(evidence.iter().any(|line| line.contains("queued ACK")));
        assert!(evidence.iter().any(|line| line.contains("PROTOCOL_ERROR")));
    }

    #[tokio::test]
    async fn full_report_has_no_fake_reference_passes() {
        let mut tester = EnablePushConformanceTester::new();
        let report = tester.run_all_tests().await;

        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.passed, report.total_cases);
        assert!(
            report
                .results
                .iter()
                .all(|result| !result.reference_comparison_available)
        );
        assert!(
            report
                .results
                .iter()
                .all(|result| result.reference_status == reference_unavailable_status())
        );
    }
}
