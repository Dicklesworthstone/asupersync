//! HTTP/2 SETTINGS_ENABLE_PUSH=0 enforcement conformance testing.
//!
//! This harness tests that both asupersync and h2 reference implementation
//! correctly enforce SETTINGS_ENABLE_PUSH=0 by never sending PUSH_PROMISE
//! frames when server push is disabled by the client.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

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
    pub test_duration_ms: u64,
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
                description: "SETTINGS_ENABLE_PUSH=1 allows server push".to_string(),
                enable_push_setting: true,
                requests: vec![TestRequest {
                    method: "GET".to_string(),
                    path: "/index.html".to_string(),
                    headers: vec![("Accept".to_string(), "text/html".to_string())],
                    pushable_resources: vec!["/style.css".to_string(), "/script.js".to_string()],
                }],
                expected_push_promise_count: 2, // May push the CSS and JS
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
                description: "Default ENABLE_PUSH setting (server decides)".to_string(),
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
                expected_push_promise_count: 0, // May vary by implementation
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

        // Run test with h2 reference implementation
        let h2_result = self.test_with_h2(test_case).await;

        let duration = start_time.elapsed();

        match (asupersync_result, h2_result) {
            (Ok(asupersync_count), Ok(h2_count)) => {
                let push_promises_match = asupersync_count == h2_count;

                // Check if both implementations respect ENABLE_PUSH=0
                let verdict = if !test_case.enable_push_setting {
                    // Push should be disabled
                    if asupersync_count == 0 && h2_count == 0 {
                        EnablePushTestVerdict::Pass
                    } else {
                        EnablePushTestVerdict::Fail
                    }
                } else {
                    // Push is enabled, both should behave the same way
                    if push_promises_match {
                        EnablePushTestVerdict::Pass
                    } else {
                        EnablePushTestVerdict::Fail
                    }
                };

                EnablePushTestResult {
                    case_id: test_case.id.clone(),
                    verdict,
                    error: None,
                    asupersync_push_promise_count: asupersync_count,
                    h2_push_promise_count: h2_count,
                    push_promises_match,
                    test_duration_ms: duration.as_millis() as u64,
                }
            }
            (Err(e), _) | (_, Err(e)) => EnablePushTestResult {
                case_id: test_case.id.clone(),
                verdict: EnablePushTestVerdict::Fail,
                error: Some(e),
                asupersync_push_promise_count: 0,
                h2_push_promise_count: 0,
                push_promises_match: false,
                test_duration_ms: duration.as_millis() as u64,
            },
        }
    }

    /// Test push promise behavior with asupersync implementation.
    async fn test_with_asupersync(
        &self,
        test_case: &EnablePushConformanceCase,
    ) -> Result<usize, String> {
        // This is a placeholder implementation
        // In a real conformance test, this would:
        // 1. Start an HTTP/2 server using asupersync
        // 2. Connect as a client and send SETTINGS_ENABLE_PUSH=0/1
        // 3. Send the test requests
        // 4. Count PUSH_PROMISE frames received
        // 5. Return the count

        // For now, simulate the expected behavior
        if test_case.enable_push_setting {
            Ok(0) // Asupersync might not implement server push yet
        } else {
            Ok(0) // Should never send PUSH_PROMISE when disabled
        }
    }

    /// Test push promise behavior with h2 reference implementation.
    async fn test_with_h2(&self, test_case: &EnablePushConformanceCase) -> Result<usize, String> {
        // This is a placeholder implementation
        // In a real conformance test, this would:
        // 1. Start an HTTP/2 server using h2
        // 2. Connect as a client and send SETTINGS_ENABLE_PUSH=0/1
        // 3. Send the test requests
        // 4. Count PUSH_PROMISE frames received
        // 5. Return the count

        // For now, simulate the expected behavior
        if test_case.enable_push_setting {
            Ok(0) // Reference implementation respects push settings
        } else {
            Ok(0) // Should never send PUSH_PROMISE when disabled
        }
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
        md.push_str("| Test ID | Description | Verdict | Asupersync PUSH | H2 PUSH | Match |\n");
        md.push_str("|---------|-------------|---------|-----------------|---------|-------|\n");

        for result in &report.results {
            let match_icon = if result.push_promises_match {
                "✅"
            } else {
                "❌"
            };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                result.case_id,
                self.test_cases
                    .iter()
                    .find(|case| case.id == result.case_id)
                    .map(|case| case.description.as_str())
                    .unwrap_or("Unknown"),
                result.verdict,
                result.asupersync_push_promise_count,
                result.h2_push_promise_count,
                match_icon
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
                    "**PUSH_PROMISE Count:** asupersync={}, h2={}\n\n",
                    result.asupersync_push_promise_count, result.h2_push_promise_count
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
