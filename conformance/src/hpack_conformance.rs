//! HPACK decoder conformance testing.
//!
//! This harness exercises the real `asupersync` HPACK decoder against explicit
//! wire vectors and expected outcomes. Header ordering and duplicate fields are
//! part of the contract and must not be collapsed away during comparison.

use asupersync::bytes::Bytes;
use asupersync::http::h2::HpackDecoder;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Test verdict for individual conformance cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    Pass,
    Fail,
    ExpectedFailure, // Known divergence
    Skipped,
}

impl fmt::Display for TestVerdict {
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

/// Single conformance test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpackConformanceCase {
    pub id: String,
    pub description: String,
    pub requirement_level: RequirementLevel,
    pub wire_bytes: Vec<u8>,
    pub expected_outcome: ExpectedOutcome,
}

/// Expected decoder outcome for a single HPACK block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedOutcome {
    Success { headers: Vec<(String, String)> },
    CompressionError,
}

/// Result of a single conformance test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceResult {
    pub case_id: String,
    pub verdict: TestVerdict,
    pub error: Option<String>,
    pub decoded_headers: Option<Vec<(String, String)>>,
    pub expected_headers: Option<Vec<(String, String)>>,
}

/// Summary statistics for the conformance run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub compliance_score: f64, // (passed + expected_failures) / total
}

/// Complete conformance test report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub test_run_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_cases: usize,
    pub results: Vec<ConformanceResult>,
    pub summary: ComplianceSummary,
}

impl ComplianceReport {
    /// Create a new report with generated ID and timestamp.
    fn new(results: Vec<ConformanceResult>) -> Self {
        let total_cases = results.len();
        let passed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::ExpectedFailure)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Skipped)
            .count();

        let compliance_score = if total_cases > 0 {
            (passed + expected_failures) as f64 / total_cases as f64
        } else {
            0.0
        };

        let summary = ComplianceSummary {
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

/// HPACK conformance tester.
pub struct HpackConformanceTester {
    pub test_cases: Vec<HpackConformanceCase>,
}

impl HpackConformanceTester {
    /// Create a new HPACK conformance tester with default test cases.
    pub fn new() -> Self {
        let test_cases = create_hpack_test_cases();
        Self { test_cases }
    }

    /// Run all conformance tests.
    pub async fn run_all_tests(&self) -> ComplianceReport {
        let mut results = Vec::with_capacity(self.test_cases.len());

        for case in &self.test_cases {
            let result = self.run_single_test(case).await;
            results.push(result);
        }

        ComplianceReport::new(results)
    }

    /// Run a single conformance test case.
    async fn run_single_test(&self, case: &HpackConformanceCase) -> ConformanceResult {
        let decoded = decode_asupersync_headers(&case.wire_bytes);

        match (&case.expected_outcome, decoded) {
            (
                ExpectedOutcome::Success {
                    headers: expected_headers,
                },
                Ok(decoded_headers),
            ) => {
                if decoded_headers == *expected_headers {
                    ConformanceResult {
                        case_id: case.id.clone(),
                        verdict: TestVerdict::Pass,
                        error: None,
                        decoded_headers: Some(decoded_headers),
                        expected_headers: Some(expected_headers.clone()),
                    }
                } else {
                    ConformanceResult {
                        case_id: case.id.clone(),
                        verdict: TestVerdict::Fail,
                        error: Some(format!(
                            "decoded headers differ: decoded={decoded_headers:?}, expected={expected_headers:?}"
                        )),
                        decoded_headers: Some(decoded_headers),
                        expected_headers: Some(expected_headers.clone()),
                    }
                }
            }
            (
                ExpectedOutcome::Success {
                    headers: expected_headers,
                },
                Err(error),
            ) => ConformanceResult {
                case_id: case.id.clone(),
                verdict: TestVerdict::Fail,
                error: Some(format!("decoder rejected a valid header block: {error}")),
                decoded_headers: None,
                expected_headers: Some(expected_headers.clone()),
            },
            (ExpectedOutcome::CompressionError, Err(error)) => ConformanceResult {
                case_id: case.id.clone(),
                verdict: TestVerdict::Pass,
                error: Some(format!("decoder rejected invalid block: {error}")),
                decoded_headers: None,
                expected_headers: None,
            },
            (ExpectedOutcome::CompressionError, Ok(decoded_headers)) => ConformanceResult {
                case_id: case.id.clone(),
                verdict: TestVerdict::Fail,
                error: Some(format!(
                    "decoder accepted a malformed header block: {decoded_headers:?}"
                )),
                decoded_headers: Some(decoded_headers),
                expected_headers: None,
            },
        }
    }

    /// Generate markdown compliance report.
    pub fn generate_markdown_report(&self, report: &ComplianceReport) -> String {
        let mut output = String::new();

        output.push_str("# HPACK Decoder Conformance Report\n\n");
        output.push_str(&format!("**Test Run ID:** {}\n", report.test_run_id));
        output.push_str(&format!(
            "**Timestamp:** {}\n",
            report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push_str(&format!("**Total Cases:** {}\n\n", report.total_cases));

        output.push_str("## Summary\n\n");
        output.push_str(&format!("- ✅ **Passed:** {}\n", report.summary.passed));
        output.push_str(&format!("- ❌ **Failed:** {}\n", report.summary.failed));
        output.push_str(&format!(
            "- ⚠️ **Expected Failures:** {}\n",
            report.summary.expected_failures
        ));
        output.push_str(&format!("- ⏭️ **Skipped:** {}\n", report.summary.skipped));
        output.push_str(&format!(
            "- 📊 **Compliance Score:** {:.1}%\n\n",
            report.summary.compliance_score * 100.0
        ));

        if report.summary.failed > 0 {
            output.push_str("## Failures\n\n");
            for result in &report.results {
                if result.verdict == TestVerdict::Fail {
                    output.push_str(&format!("### {}\n", result.case_id));
                    if let Some(ref error) = result.error {
                        output.push_str(&format!("**Error:** {}\n\n", error));
                    }
                }
            }
        }

        output.push_str("## Test Details\n\n");
        output.push_str("| Case ID | Verdict | Error |\n");
        output.push_str("|---------|---------|-------|\n");

        for result in &report.results {
            let verdict_emoji = match result.verdict {
                TestVerdict::Pass => "✅",
                TestVerdict::Fail => "❌",
                TestVerdict::ExpectedFailure => "⚠️",
                TestVerdict::Skipped => "⏭️",
            };
            let error_summary = result.error.as_deref().unwrap_or("");
            output.push_str(&format!(
                "| {} | {} {} | {} |\n",
                result.case_id, verdict_emoji, result.verdict, error_summary
            ));
        }

        output
    }
}

impl Default for HpackConformanceTester {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_asupersync_headers(wire_bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut decoder = HpackDecoder::new();
    let mut src = Bytes::copy_from_slice(wire_bytes);
    decoder
        .decode(&mut src)
        .map(|headers| {
            headers
                .into_iter()
                .map(|header| (header.name, header.value))
                .collect()
        })
        .map_err(|error| error.to_string())
}

/// Create the default set of HPACK test cases.
fn create_hpack_test_cases() -> Vec<HpackConformanceCase> {
    vec![
        // Test case 1: Empty header block
        HpackConformanceCase {
            id: "HPACK-001".to_string(),
            description: "Empty header block".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![],
            expected_outcome: ExpectedOutcome::Success { headers: vec![] },
        },
        // Test case 2: Single indexed header (method: GET)
        HpackConformanceCase {
            id: "HPACK-002".to_string(),
            description: "Single indexed header - method: GET".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![0x82], // Index 2 in static table = :method: GET
            expected_outcome: ExpectedOutcome::Success {
                headers: vec![(":method".to_string(), "GET".to_string())],
            },
        },
        // Test case 3: Multiple indexed headers
        HpackConformanceCase {
            id: "HPACK-003".to_string(),
            description: "Multiple indexed headers".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![0x82, 0x86, 0x84], // :method GET, :scheme http, :path /
            expected_outcome: ExpectedOutcome::Success {
                headers: vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "http".to_string()),
                    (":path".to_string(), "/".to_string()),
                ],
            },
        },
        // Test case 4: Literal with incremental indexing
        HpackConformanceCase {
            id: "HPACK-004".to_string(),
            description: "Literal header with incremental indexing".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![
                0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
                0x79, // Name: "custom-key"
                0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65,
                0x72, // Value: "custom-header"
            ],
            expected_outcome: ExpectedOutcome::Success {
                headers: vec![("custom-key".to_string(), "custom-header".to_string())],
            },
        },
        // Test case 5: Literal without indexing
        HpackConformanceCase {
            id: "HPACK-005".to_string(),
            description: "Literal header without indexing".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![
                0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, // Name: "hello"
                0x05, 0x77, 0x6f, 0x72, 0x6c, 0x64, // Value: "world"
            ],
            expected_outcome: ExpectedOutcome::Success {
                headers: vec![("hello".to_string(), "world".to_string())],
            },
        },
        // Test case 6: Dynamic table size update
        HpackConformanceCase {
            id: "HPACK-006".to_string(),
            description: "Dynamic table size update".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![0x20], // Size update to 0
            expected_outcome: ExpectedOutcome::Success { headers: vec![] },
        },
        // Test case 7: Huffman encoded string
        HpackConformanceCase {
            id: "HPACK-007".to_string(),
            description: "Huffman encoded string".to_string(),
            requirement_level: RequirementLevel::Should,
            wire_bytes: vec![
                0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d,
                0x7f, // Huffman encoded "custom-key"
                0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4,
                0xbf, // Huffman encoded "custom-value"
            ],
            expected_outcome: ExpectedOutcome::Success {
                headers: vec![("custom-key".to_string(), "custom-value".to_string())],
            },
        },
        // Test case 8: Invalid encoding (should fail consistently)
        HpackConformanceCase {
            id: "HPACK-008".to_string(),
            description: "Invalid HPACK encoding".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![0xFF, 0xFF, 0xFF], // Invalid pattern
            expected_outcome: ExpectedOutcome::CompressionError,
        },
        // Test case 9: Large indexed header reference (out of bounds)
        HpackConformanceCase {
            id: "HPACK-009".to_string(),
            description: "Out of bounds indexed header".to_string(),
            requirement_level: RequirementLevel::Must,
            wire_bytes: vec![0xFF, 0x7F], // Index way beyond static table
            expected_outcome: ExpectedOutcome::CompressionError,
        },
        // Test case 10: Complex multi-header block
        HpackConformanceCase {
            id: "HPACK-010".to_string(),
            description: "Complex multi-header block".to_string(),
            requirement_level: RequirementLevel::Should,
            wire_bytes: vec![
                0x82, // :method GET
                0x86, // :scheme http
                0x84, // :path /
                0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
                0x63, 0x6f, 0x6d, // :authority www.example.com
            ],
            expected_outcome: ExpectedOutcome::Success {
                headers: vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "http".to_string()),
                    (":path".to_string(), "/".to_string()),
                    (":authority".to_string(), "www.example.com".to_string()),
                ],
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hpack_conformance_empty() {
        let tester = HpackConformanceTester::new();
        let report = tester.run_all_tests().await;

        assert!(report.total_cases > 0);
        assert_eq!(report.results.len(), report.total_cases);
    }

    #[test]
    fn test_header_block_match_requires_exact_order() {
        let a = vec![
            (":method".to_string(), "GET".to_string()),
            ("set-cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
        ];
        let b = vec![
            ("set-cookie".to_string(), "a=1".to_string()),
            (":method".to_string(), "GET".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
        ];

        assert_ne!(a, b);
    }

    #[test]
    fn test_real_decoder_preserves_pseudo_header_names() {
        let decoded = decode_asupersync_headers(&[0x82]).expect("decode static pseudo-header");

        assert_eq!(decoded, vec![(":method".to_string(), "GET".to_string())]);
    }
}
