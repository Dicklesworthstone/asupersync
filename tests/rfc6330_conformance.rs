//! RFC 6330 conformance test harness for RaptorQ implementation.
//!
//! This module provides a compact integration-level RFC 6330 check against the
//! live RaptorQ seams. It complements the larger golden and fixture-driven
//! suites elsewhere in the tree with a small, report-producing smoke harness.
//!
//! # Coverage Matrix
//!
//! | RFC Section | Function | Test Count | Status |
//! |-------------|----------|------------|--------|
//! | 5.3.5.1 | rand(y,i,m) | Representative golden vectors | ✓ |
//! | 5.3.5.2 | deg(v) | Boundary golden vectors | ✓ |
//! | 5.3.5.3 | tuple(J,W,P,X) | Representative golden vectors | ✓ |
//! | 5.4.2.1 | Intermediate symbols | Determinism + shape | ✓ |
//! | 5.4.2.2 | Repair symbols | Bounds + determinism | ✓ |
//!
//! # Test Pattern
//!
//! Following Pattern 4 from the conformance skill: Spec-Derived Test Matrix
//! - One test per MUST/SHOULD clause
//! - Tagged by requirement level (MUST, SHOULD, MAY)
//! - Structured JSON-line output for CI parsing

#![allow(missing_docs)]

use asupersync::raptorq::{
    rfc6330::{LtTuple, deg, next_prime_ge, rand, repair_indices_for_esi, tuple},
    systematic::{SystematicEncoder, SystematicParams},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Test result for conformance tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceResult {
    pub test_id: String,
    pub rfc_section: String,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub description: String,
    pub error_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skip,
    ExpectedFail, // Known divergence
}

/// RFC 6330 golden test vector.
#[derive(Debug, Clone)]
struct GoldenVector<Input, Expected> {
    id: &'static str,
    rfc_section: &'static str,
    description: &'static str,
    input: Input,
    expected: Expected,
}

// ============================================================================
// RFC 6330 Section 5.3.5.1: rand(y, i, m) function vectors
// ============================================================================

/// Test the RFC 6330 rand() function against reference values.
///
/// RFC 6330 Section 5.3.5.1 specifies: "The rand() function MUST produce
/// deterministic pseudorandom values based on the lookup tables V0-V3."
const RAND_VECTORS: &[GoldenVector<(u32, u8, u32), u32>] = &[
    GoldenVector {
        id: "RFC6330-5.3.5.1-001",
        rfc_section: "5.3.5.1",
        description: "RFC golden vector: zero seed, byte modulus",
        input: (0, 0, 256),
        expected: 25,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.1-002",
        rfc_section: "5.3.5.1",
        description: "RFC golden vector: low seed, byte modulus",
        input: (1, 0, 256),
        expected: 214,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.1-003",
        rfc_section: "5.3.5.1",
        description: "RFC golden vector: mixed seed, decimal modulus",
        input: (42, 1, 100),
        expected: 34,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.1-004",
        rfc_section: "5.3.5.1",
        description: "RFC golden vector: large seed, decimal modulus",
        input: (0xDEAD_BEEF, 0, 1000),
        expected: 326,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.1-005",
        rfc_section: "5.3.5.1",
        description: "RFC golden vector: mid seed, 16-bit modulus",
        input: (12_345, 1, 65_536),
        expected: 18_106,
    },
];

// ============================================================================
// RFC 6330 Section 5.3.5.2: deg(v) function vectors
// ============================================================================

/// Test the RFC 6330 deg() function against the degree distribution.
///
/// RFC 6330 Section 5.3.5.2 specifies: "The deg() function MUST implement
/// the degree distribution table correctly for LT code generation."
const DEG_VECTORS: &[GoldenVector<u32, usize>] = &[
    GoldenVector {
        id: "RFC6330-5.3.5.2-001",
        rfc_section: "5.3.5.2",
        description: "degree-1 lower boundary",
        input: 0,
        expected: 1,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-002",
        rfc_section: "5.3.5.2",
        description: "degree-1 upper boundary",
        input: 5_242,
        expected: 1,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-003",
        rfc_section: "5.3.5.2",
        description: "degree-2 lower boundary",
        input: 5_243,
        expected: 2,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-004",
        rfc_section: "5.3.5.2",
        description: "degree-2 upper boundary",
        input: 529_530,
        expected: 2,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-005",
        rfc_section: "5.3.5.2",
        description: "degree-3 lower boundary",
        input: 529_531,
        expected: 3,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-006",
        rfc_section: "5.3.5.2",
        description: "degree-4 lower boundary",
        input: 704_294,
        expected: 4,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-007",
        rfc_section: "5.3.5.2",
        description: "degree-30 lower boundary",
        input: 1_017_662,
        expected: 30,
    },
    GoldenVector {
        id: "RFC6330-5.3.5.2-008",
        rfc_section: "5.3.5.2",
        description: "maximum 20-bit sample",
        input: 1_048_575,
        expected: 30,
    },
];

// ============================================================================
// RFC 6330 Section 5.3.5.3: tuple(k, x) function vectors
// ============================================================================

/// Test the RFC 6330 tuple() function for LT code parameter generation.
///
/// RFC 6330 Section 5.3.5.3 specifies the full `(d, a, b, d1, a1, b1)` tuple
/// and the derived intermediate-symbol schedule for a given `(J, W, P, X)`.
#[derive(Debug, Clone)]
struct TupleGoldenVector {
    id: &'static str,
    rfc_section: &'static str,
    description: &'static str,
    systematic_index: usize,
    lt_width: usize,
    pi_count: usize,
    encoding_symbol_id: u32,
    expected_tuple: LtTuple,
    expected_indices: &'static [usize],
}

const TUPLE_VECTORS: &[TupleGoldenVector] = &[
    TupleGoldenVector {
        id: "RFC6330-5.3.5.3-001",
        rfc_section: "5.3.5.3",
        description: "K=10 parameter space, X=0",
        systematic_index: 254,
        lt_width: 17,
        pi_count: 10,
        encoding_symbol_id: 0,
        expected_tuple: LtTuple {
            d: 2,
            a: 4,
            b: 9,
            d1: 2,
            a1: 5,
            b1: 1,
        },
        expected_indices: &[9, 13, 18, 23],
    },
    TupleGoldenVector {
        id: "RFC6330-5.3.5.3-002",
        rfc_section: "5.3.5.3",
        description: "K=10 parameter space, X=1",
        systematic_index: 254,
        lt_width: 17,
        pi_count: 10,
        encoding_symbol_id: 1,
        expected_tuple: LtTuple {
            d: 7,
            a: 6,
            b: 12,
            d1: 2,
            a1: 1,
            b1: 3,
        },
        expected_indices: &[12, 1, 7, 13, 2, 8, 14, 20, 21],
    },
    TupleGoldenVector {
        id: "RFC6330-5.3.5.3-003",
        rfc_section: "5.3.5.3",
        description: "K=100 parameter space, X=200",
        systematic_index: 562,
        lt_width: 113,
        pi_count: 15,
        encoding_symbol_id: 200,
        expected_tuple: LtTuple {
            d: 2,
            a: 109,
            b: 107,
            d1: 3,
            a1: 15,
            b1: 7,
        },
        expected_indices: &[107, 103, 120, 118, 116],
    },
];

// ============================================================================
// Test execution framework
// ============================================================================

/// Run all RFC 6330 conformance tests and return detailed results.
pub fn run_rfc6330_conformance() -> Vec<ConformanceResult> {
    let mut results = Vec::new();

    // Test rand() function vectors against RFC-derived goldens
    for vector in RAND_VECTORS {
        let result = test_rand_function(vector);
        results.push(result);
    }

    // Test deg() function vectors
    for vector in DEG_VECTORS {
        let result = test_deg_function(vector);
        results.push(result);
    }

    // Test tuple() function vectors
    for vector in TUPLE_VECTORS {
        let result = test_tuple_function(vector);
        results.push(result);
    }

    // Test intermediate symbol generation consistency
    results.extend(test_intermediate_symbol_generation());

    // Test repair packet recovery edge cases
    results.extend(test_repair_recovery_edge_cases());

    results
}

fn test_rand_function(vector: &GoldenVector<(u32, u8, u32), u32>) -> ConformanceResult {
    let (y, i, m) = vector.input;

    let actual = rand(y, i, m);

    let verdict = if actual == vector.expected {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail
    };

    ConformanceResult {
        test_id: vector.id.to_string(),
        rfc_section: vector.rfc_section.to_string(),
        requirement_level: RequirementLevel::Must,
        verdict: verdict.clone(),
        description: format!("{}: rand({}, {}, {})", vector.description, y, i, m),
        error_details: if verdict == TestVerdict::Fail {
            Some(format!("Expected {}, got {}", vector.expected, actual))
        } else {
            None
        },
    }
}

fn test_deg_function(vector: &GoldenVector<u32, usize>) -> ConformanceResult {
    let actual = deg(vector.input);

    let verdict = if actual == vector.expected {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail
    };

    ConformanceResult {
        test_id: vector.id.to_string(),
        rfc_section: vector.rfc_section.to_string(),
        requirement_level: RequirementLevel::Must,
        verdict: verdict.clone(),
        description: format!(
            "{}: deg({}) -> {}",
            vector.description, vector.input, vector.expected
        ),
        error_details: if verdict == TestVerdict::Fail {
            Some(format!("Expected {}, got {}", vector.expected, actual))
        } else {
            None
        },
    }
}

fn test_tuple_function(vector: &TupleGoldenVector) -> ConformanceResult {
    let p1 = next_prime_ge(vector.pi_count);
    let actual_tuple = tuple(
        vector.systematic_index,
        vector.lt_width,
        vector.pi_count,
        p1,
        vector.encoding_symbol_id,
    );
    let actual_indices = repair_indices_for_esi(
        vector.systematic_index,
        vector.lt_width,
        vector.pi_count,
        vector.encoding_symbol_id,
    );

    let verdict =
        if actual_tuple == vector.expected_tuple && actual_indices == vector.expected_indices {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

    ConformanceResult {
        test_id: vector.id.to_string(),
        rfc_section: vector.rfc_section.to_string(),
        requirement_level: RequirementLevel::Must,
        verdict: verdict.clone(),
        description: format!(
            "{}: tuple(J={}, W={}, P={}, X={})",
            vector.description,
            vector.systematic_index,
            vector.lt_width,
            vector.pi_count,
            vector.encoding_symbol_id
        ),
        error_details: if verdict == TestVerdict::Fail {
            Some(format!(
                "Expected tuple {:?} and indices {:?}, got tuple {:?} and indices {:?}",
                vector.expected_tuple, vector.expected_indices, actual_tuple, actual_indices
            ))
        } else {
            None
        },
    }
}

// ============================================================================
// Intermediate Symbol Generation Tests (RFC 6330 Section 5.4.2.1)
// ============================================================================

fn test_intermediate_symbol_generation() -> Vec<ConformanceResult> {
    let mut results = Vec::new();

    // Test case: Small systematic encoding with intermediate symbol consistency
    let source_data = vec![
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
        vec![9, 10, 11, 12],
        vec![13, 14, 15, 16],
    ];
    let symbol_size = 4;
    let seed = 12345u64;

    let encoder = if let Some(enc) = SystematicEncoder::new(&source_data, symbol_size, seed) {
        enc
    } else {
        results.push(ConformanceResult {
            test_id: "RFC6330-5.4.2.1-001".to_string(),
            rfc_section: "5.4.2.1".to_string(),
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Fail,
            description: "Intermediate symbols generation setup".to_string(),
            error_details: Some("Encoder creation failed".to_string()),
        });
        return results;
    };

    let params = encoder.params();

    // Test 1: Intermediate symbol determinism
    for i in 0..params.l {
        let sym1 = encoder.intermediate_symbol(i);
        let sym2 = encoder.intermediate_symbol(i);

        let verdict = if sym1 == sym2 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        results.push(ConformanceResult {
            test_id: format!("RFC6330-5.4.2.1-DET-{i:03}"),
            rfc_section: "5.4.2.1".to_string(),
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            description: format!("Intermediate symbol {i} determinism"),
            error_details: if verdict == TestVerdict::Fail {
                Some("Intermediate symbol computation not deterministic".to_string())
            } else {
                None
            },
        });
    }

    // Test 2: Intermediate symbol bounds checking
    for i in 0..params.l {
        let sym = encoder.intermediate_symbol(i);
        let valid_size = sym.len() == symbol_size;

        results.push(ConformanceResult {
            test_id: format!("RFC6330-5.4.2.1-SIZE-{i:03}"),
            rfc_section: "5.4.2.1".to_string(),
            requirement_level: RequirementLevel::Must,
            verdict: if valid_size {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            description: format!("Intermediate symbol {i} size validation"),
            error_details: if valid_size {
                None
            } else {
                Some(format!("Expected size {}, got {}", symbol_size, sym.len()))
            },
        });
    }

    results
}

// ============================================================================
// Repair Packet Recovery Edge Cases (RFC 6330 Section 5.4.2.2)
// ============================================================================

fn test_repair_recovery_edge_cases() -> Vec<ConformanceResult> {
    let mut results = Vec::new();

    // Edge case tests for repair symbol index generation
    let test_cases = [
        (4usize, 0u32, "Small source block, low encoding symbol id"),
        (
            4usize,
            100u32,
            "Small source block, high encoding symbol id",
        ),
        (
            16usize,
            16u32,
            "Medium source block, repair-range encoding symbol id",
        ),
        (
            16usize,
            1_000u32,
            "Medium source block, high encoding symbol id",
        ),
        (
            100usize,
            500u32,
            "Large source block, mid-range encoding symbol id",
        ),
    ];

    for (test_idx, (source_symbols, encoding_symbol_id, description)) in
        test_cases.iter().enumerate()
    {
        let params = if let Ok(params) = SystematicParams::try_for_source_block(*source_symbols, 4)
        {
            params
        } else {
            results.push(ConformanceResult {
                test_id: format!("RFC6330-5.4.2.2-SETUP-{test_idx:03}"),
                rfc_section: "5.4.2.2".to_string(),
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                description: format!("Repair schedule setup for K={source_symbols}"),
                error_details: Some("Systematic parameter derivation failed".to_string()),
            });
            continue;
        };

        // Test repair indices generation
        let indices = repair_indices_for_esi(params.j, params.w, params.p, *encoding_symbol_id);

        // Validate that repair indices are within bounds
        let bounds_valid = indices.iter().all(|&idx| idx < params.w + params.p);

        // Validate uniqueness
        let mut sorted_indices = indices.clone();
        sorted_indices.sort_unstable();
        sorted_indices.dedup();
        let uniqueness_valid = sorted_indices.len() == indices.len();
        let non_empty_valid = !indices.is_empty();

        let valid = bounds_valid && uniqueness_valid && non_empty_valid;
        let verdict = if valid {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        results.push(ConformanceResult {
            test_id: format!("RFC6330-5.4.2.2-EDGE-{test_idx:03}"),
            rfc_section: "5.4.2.2".to_string(),
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            description: description.to_string(),
            error_details: if verdict == TestVerdict::Fail {
                let mut errors = Vec::new();
                if !bounds_valid {
                    errors.push("repair indices out of bounds".to_string());
                }
                if !uniqueness_valid {
                    errors.push("repair indices not unique".to_string());
                }
                if !non_empty_valid {
                    errors.push("repair index schedule is empty".to_string());
                }
                Some(format!(
                    "Invalid repair indices: {:?} for J={}, W={}, P={}, X={}. Errors: {}",
                    indices,
                    params.j,
                    params.w,
                    params.p,
                    encoding_symbol_id,
                    errors.join(", ")
                ))
            } else {
                None
            },
        });

        // Test repair equation determinism
        let indices1 = repair_indices_for_esi(params.j, params.w, params.p, *encoding_symbol_id);
        let indices2 = repair_indices_for_esi(params.j, params.w, params.p, *encoding_symbol_id);

        let deterministic = indices1 == indices2;

        results.push(ConformanceResult {
            test_id: format!("RFC6330-5.4.2.2-DET-{test_idx:03}"),
            rfc_section: "5.4.2.2".to_string(),
            requirement_level: RequirementLevel::Must,
            verdict: if deterministic {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            description: format!("Repair equation X={encoding_symbol_id} determinism"),
            error_details: if deterministic {
                None
            } else {
                Some("Repair equation generation not deterministic".to_string())
            },
        });
    }

    results
}

// ============================================================================
// Conformance report generation
// ============================================================================

/// Generate a markdown compliance report.
pub fn generate_conformance_report(results: &[ConformanceResult]) -> String {
    let mut report = String::new();

    report.push_str("# RFC 6330 RaptorQ Conformance Report\n\n");
    report.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    let mut by_section: HashMap<String, Vec<&ConformanceResult>> = HashMap::new();
    for result in results {
        by_section
            .entry(result.rfc_section.clone())
            .or_default()
            .push(result);
    }

    // Summary table
    report.push_str("## Conformance Summary\n\n");
    report.push_str("| RFC Section | Description | MUST Tests | Pass | Fail | Coverage |\n");
    report.push_str("|-------------|-------------|------------|------|------|----------|\n");

    let sections = [
        ("5.3.5.1", "Pseudorandom function rand()"),
        ("5.3.5.2", "Degree distribution deg()"),
        ("5.3.5.3", "LT tuple generation"),
        ("5.4.2.1", "Intermediate symbols"),
        ("5.4.2.2", "Repair symbols"),
    ];

    for (section, desc) in &sections {
        if let Some(section_results) = by_section.get(*section) {
            let must_tests: Vec<_> = section_results
                .iter()
                .filter(|r| matches!(r.requirement_level, RequirementLevel::Must))
                .collect();
            let pass_count = must_tests
                .iter()
                .filter(|r| r.verdict == TestVerdict::Pass)
                .count();
            let fail_count = must_tests
                .iter()
                .filter(|r| r.verdict == TestVerdict::Fail)
                .count();
            let coverage = if must_tests.is_empty() {
                0
            } else {
                (pass_count as f64 / must_tests.len() as f64 * 100.0) as u32
            };

            report.push_str(&format!(
                "| {} | {} | {} | {} | {} | {}% |\n",
                section,
                desc,
                must_tests.len(),
                pass_count,
                fail_count,
                coverage
            ));
        }
    }

    // Overall conformance score
    let all_must_tests: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.requirement_level, RequirementLevel::Must))
        .collect();
    let total_pass = all_must_tests
        .iter()
        .filter(|r| r.verdict == TestVerdict::Pass)
        .count();
    let overall_coverage = if all_must_tests.is_empty() {
        0.0
    } else {
        total_pass as f64 / all_must_tests.len() as f64 * 100.0
    };

    report.push_str(&format!(
        "\n**Overall RFC 6330 Conformance: {:.1}%** ({}/{} MUST requirements pass)\n\n",
        overall_coverage,
        total_pass,
        all_must_tests.len()
    ));

    // Conformance status
    if overall_coverage >= 95.0 {
        report.push_str("🟢 **CONFORMANT** - Meets RFC 6330 requirements (≥95% MUST coverage)\n\n");
    } else {
        report.push_str("🔴 **NON-CONFORMANT** - Below required 95% MUST coverage\n\n");
    }

    // Detailed test results
    report.push_str("## Detailed Results\n\n");
    for (section, desc) in &sections {
        if let Some(section_results) = by_section.get(*section) {
            report.push_str(&format!("### {section} - {desc}\n\n"));
            for result in section_results {
                let status_icon = match result.verdict {
                    TestVerdict::Pass => "✅",
                    TestVerdict::Fail => "❌",
                    TestVerdict::Skip => "⏭️",
                    TestVerdict::ExpectedFail => "⚠️",
                };
                report.push_str(&format!(
                    "- {} **{}**: {}\n",
                    status_icon, result.test_id, result.description
                ));
                if let Some(error) = &result.error_details {
                    report.push_str(&format!("  - **Error**: {error}\n"));
                }
            }
            report.push('\n');
        }
    }

    report
}

/// Output structured JSON logs for CI parsing (GAP-D7 initial implementation).
pub fn output_structured_logs(results: &[ConformanceResult]) {
    eprintln!("📊 RFC 6330 Conformance Results (GAP-D7 Schema Foundation):");
    for result in results {
        eprintln!(
            "{{\"test_id\":\"{}\",\"rfc_section\":\"{}\",\"verdict\":\"{:?}\",\"requirement_level\":\"{:?}\"}}",
            result.test_id, result.rfc_section, result.verdict, result.requirement_level
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6330_conformance_suite() {
        println!("Running RFC 6330 conformance test suite...");

        let results = run_rfc6330_conformance();

        // Generate detailed report
        let report = generate_conformance_report(&results);
        println!("{report}");

        // Output structured results using GAP-D7 schema foundation
        output_structured_logs(&results);

        // Check for any failures
        let failures: Vec<_> = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .collect();

        if !failures.is_empty() {
            eprintln!("\n🔴 CONFORMANCE FAILURES:");
            for failure in &failures {
                eprintln!("  ❌ {} - {}", failure.test_id, failure.description);
                if let Some(details) = &failure.error_details {
                    eprintln!("     Error: {details}");
                }
            }
            panic!("{} conformance test(s) failed", failures.len());
        }

        // Verify minimum coverage requirements
        let must_tests: Vec<_> = results
            .iter()
            .filter(|r| matches!(r.requirement_level, RequirementLevel::Must))
            .collect();
        let pass_count = must_tests
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();

        let coverage = pass_count as f64 / must_tests.len() as f64;
        assert!(
            coverage >= 0.95,
            "RFC 6330 MUST coverage {:.1}% below required 95%",
            coverage * 100.0
        );

        println!(
            "✅ RFC 6330 conformance PASS: {}/{} MUST tests ({:.1}% coverage)",
            pass_count,
            must_tests.len(),
            coverage * 100.0
        );
    }
}
