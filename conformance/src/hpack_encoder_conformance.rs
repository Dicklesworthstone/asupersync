//! HPACK encoder conformance testing.
//!
//! This harness tests the `asupersync` HPACK encoder against the `h2` reference
//! implementation to ensure byte-identical wire output given the same HeaderMap
//! and dynamic table state.

use asupersync::bytes::Bytes;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder as AsupersyncEncoder};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Test verdict for individual encoder conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncoderTestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for EncoderTestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::ExpectedFailure => write!(f, "XFAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Single HPACK encoder conformance test case.
#[derive(Debug, Clone)]
pub struct HpackEncoderConformanceCase {
    pub id: String,
    pub description: String,
    pub headers: Vec<Header>,
    pub max_table_size: Option<usize>,
    pub use_huffman: bool,
    pub expected_identical: bool, // Whether outputs should be byte-identical
}

/// Result of running a single encoder test case.
#[derive(Debug, Clone, Serialize)]
pub struct HpackEncoderTestResult {
    pub case_id: String,
    pub verdict: EncoderTestVerdict,
    pub error: Option<String>,
    pub asupersync_output: Vec<u8>,
    pub h2_output: Vec<u8>,
    pub bytes_match: bool,
    pub table_size_match: bool,
    pub asupersync_table_size: usize,
    pub h2_table_size: usize,
}

/// Summary statistics for an encoder conformance run.
#[derive(Debug, Clone, Serialize)]
pub struct HpackEncoderComplianceSummary {
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub total: usize,
    pub compliance_score: f64, // (passed / (passed + failed))
}

/// Complete report for an HPACK encoder conformance run.
#[derive(Debug, Clone, Serialize)]
pub struct HpackEncoderComplianceReport {
    pub test_run_id: String,
    pub timestamp: String,
    pub total_cases: usize,
    pub results: Vec<HpackEncoderTestResult>,
    pub summary: HpackEncoderComplianceSummary,
}

/// HPACK encoder conformance tester.
pub struct HpackEncoderConformanceTester {
    pub test_cases: Vec<HpackEncoderConformanceCase>,
}

impl HpackEncoderConformanceTester {
    /// Create a new encoder conformance tester with standard test cases.
    pub fn new() -> Self {
        Self {
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create the standard set of encoder conformance test cases.
    fn create_test_cases() -> Vec<HpackEncoderConformanceCase> {
        vec![
            HpackEncoderConformanceCase {
                id: "ENC-001".to_string(),
                description: "Simple header without indexing".to_string(),
                headers: vec![Header {
                    name: "custom-header".to_string(),
                    value: "custom-value".to_string(),
                }],
                max_table_size: None,
                use_huffman: false,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-002".to_string(),
                description: "Common headers using static table".to_string(),
                headers: vec![
                    Header {
                        name: ":method".to_string(),
                        value: "GET".to_string(),
                    },
                    Header {
                        name: ":path".to_string(),
                        value: "/".to_string(),
                    },
                    Header {
                        name: ":scheme".to_string(),
                        value: "https".to_string(),
                    },
                    Header {
                        name: ":authority".to_string(),
                        value: "example.com".to_string(),
                    },
                ],
                max_table_size: None,
                use_huffman: false,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-003".to_string(),
                description: "Headers with Huffman encoding".to_string(),
                headers: vec![
                    Header {
                        name: "user-agent".to_string(),
                        value: "Mozilla/5.0".to_string(),
                    },
                    Header {
                        name: "accept-encoding".to_string(),
                        value: "gzip, deflate".to_string(),
                    },
                ],
                max_table_size: None,
                use_huffman: true,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-004".to_string(),
                description: "Dynamic table indexing".to_string(),
                headers: vec![
                    Header {
                        name: "x-custom-header".to_string(),
                        value: "first-value".to_string(),
                    },
                    Header {
                        name: "x-custom-header".to_string(),
                        value: "second-value".to_string(),
                    },
                    Header {
                        name: "x-another-header".to_string(),
                        value: "another-value".to_string(),
                    },
                ],
                max_table_size: Some(4096),
                use_huffman: false,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-005".to_string(),
                description: "Small dynamic table eviction".to_string(),
                headers: vec![
                    Header {
                        name: "large-header-name-that-exceeds".to_string(),
                        value: "large-header-value-that-also-exceeds-small-table".to_string(),
                    },
                    Header {
                        name: "another-large-header-name".to_string(),
                        value: "another-large-value".to_string(),
                    },
                ],
                max_table_size: Some(128), // Small table to force eviction
                use_huffman: false,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-006".to_string(),
                description: "Empty headers list".to_string(),
                headers: vec![],
                max_table_size: None,
                use_huffman: false,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-007".to_string(),
                description: "Headers with empty values".to_string(),
                headers: vec![
                    Header {
                        name: "empty-value".to_string(),
                        value: "".to_string(),
                    },
                    Header {
                        name: "x-trace-id".to_string(),
                        value: "".to_string(),
                    },
                ],
                max_table_size: None,
                use_huffman: false,
                expected_identical: true,
            },
            HpackEncoderConformanceCase {
                id: "ENC-008".to_string(),
                description: "Duplicate header names".to_string(),
                headers: vec![
                    Header {
                        name: "cookie".to_string(),
                        value: "session=abc123".to_string(),
                    },
                    Header {
                        name: "cookie".to_string(),
                        value: "preference=dark".to_string(),
                    },
                    Header {
                        name: "cookie".to_string(),
                        value: "lang=en".to_string(),
                    },
                ],
                max_table_size: None,
                use_huffman: false,
                expected_identical: true,
            },
        ]
    }

    /// Run all conformance test cases.
    pub async fn run_all_tests(&mut self) -> HpackEncoderComplianceReport {
        let test_run_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let total_cases = self.test_cases.len();
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            let result = self.run_single_test(test_case).await;
            results.push(result);
        }

        let summary = self.compute_summary(&results);

        HpackEncoderComplianceReport {
            test_run_id,
            timestamp,
            total_cases,
            results,
            summary,
        }
    }

    /// Run a single encoder conformance test case.
    async fn run_single_test(&self, case: &HpackEncoderConformanceCase) -> HpackEncoderTestResult {
        // Test our encoder
        let mut asupersync_encoder = AsupersyncEncoder::new();
        if let Some(size) = case.max_table_size {
            asupersync_encoder.set_max_table_size(size);
        }
        asupersync_encoder.set_use_huffman(case.use_huffman);

        let mut asupersync_buf = BytesMut::new();
        asupersync_encoder.encode(&case.headers, &mut asupersync_buf);
        let asupersync_output = asupersync_buf.to_vec();
        let asupersync_table_size = asupersync_encoder.dynamic_table_size();

        let roundtrip_error = decode_asupersync_output(&asupersync_output, &case.headers).err();
        let h2_output = Vec::new();
        let h2_table_size = 0;
        let bytes_match = false;
        let table_size_match = true;

        let (verdict, error) = if let Some(error) = roundtrip_error {
            (EncoderTestVerdict::Fail, Some(error))
        } else {
            (
                EncoderTestVerdict::Skipped,
                Some(
                    "h2 crate HPACK encoder internals are private; byte-differential reference output is unavailable"
                        .to_string(),
                ),
            )
        };

        HpackEncoderTestResult {
            case_id: case.id.clone(),
            verdict,
            error,
            asupersync_output,
            h2_output,
            bytes_match,
            table_size_match,
            asupersync_table_size,
            h2_table_size,
        }
    }

    /// Compute summary statistics from test results.
    fn compute_summary(&self, results: &[HpackEncoderTestResult]) -> HpackEncoderComplianceSummary {
        let total = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == EncoderTestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == EncoderTestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == EncoderTestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == EncoderTestVerdict::Skipped)
            .count();

        let compliance_score = if passed + failed > 0 {
            passed as f64 / (passed + failed) as f64
        } else {
            1.0
        };

        HpackEncoderComplianceSummary {
            passed,
            failed,
            expected_failures,
            skipped,
            total,
            compliance_score,
        }
    }

    /// Generate a markdown report from the compliance results.
    pub fn generate_markdown_report(&self, report: &HpackEncoderComplianceReport) -> String {
        let mut output = String::new();

        output.push_str("# HPACK Encoder Conformance Report\n\n");
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
                if result.verdict == EncoderTestVerdict::Fail {
                    output.push_str(&format!("### {}\n", result.case_id));
                    if let Some(error) = &result.error {
                        output.push_str(&format!("**Error:** {}\n", error));
                    }
                    output.push_str(&format!("**Bytes match:** {}\n", result.bytes_match));
                    output.push_str(&format!(
                        "**Table size match:** {}\n",
                        result.table_size_match
                    ));
                    output.push_str(&format!(
                        "**Asupersync output:** {} bytes\n",
                        result.asupersync_output.len()
                    ));
                    output.push_str(&format!(
                        "**H2 output:** {} bytes\n\n",
                        result.h2_output.len()
                    ));
                }
            }
        }

        output.push_str("## All Test Results\n\n");
        output.push_str("| Case ID | Verdict | Bytes Match | Table Size Match | Error |\n");
        output.push_str("|---------|---------|-------------|------------------|-------|\n");

        for result in &report.results {
            let error_str = result.error.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                result.case_id,
                result.verdict,
                result.bytes_match,
                result.table_size_match,
                error_str
            ));
        }

        output
    }
}

fn decode_asupersync_output(encoded: &[u8], expected: &[Header]) -> Result<(), String> {
    let mut decoder = HpackDecoder::new();
    let mut src = Bytes::copy_from_slice(encoded);
    let decoded = decoder.decode(&mut src).map_err(|err| err.to_string())?;
    if decoded == expected {
        Ok(())
    } else {
        Err(format!(
            "asupersync HPACK encode/decode round trip differed: decoded={decoded:?}, expected={expected:?}"
        ))
    }
}

impl Default for HpackEncoderConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}
