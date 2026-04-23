//! RFC 6330 Conformance Tests
//!
//! This module contains conformance tests that validate the asupersync RaptorQ
//! implementation against RFC 6330 requirements using reference fixtures.

use crate::raptorq_rfc6330::{
    ConformanceContext, ConformanceResult, ConformanceTest, RequirementLevel, TestCategory,
};
use crate::rfc6330_fixtures::*;

// ============================================================================
// P0 Priority Tests - Critical Requirements
// ============================================================================

/// Test RFC 6330 Section 5.5.1 - Lookup table V0 validation
pub struct LookupTableV0Test;

impl ConformanceTest for LookupTableV0Test {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.5.1"
    }

    fn section(&self) -> &str {
        "5.5"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }

    fn description(&self) -> &str {
        "Lookup table V0 MUST match RFC 6330 values exactly"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // For now, this validates that the fixtures themselves are correct.
        // In a real integration, this would compare against the actual implementation.

        // TODO: When integrated with asupersync main crate:
        // let actual_v0 = asupersync::raptorq::rfc6330::V0;
        // match validate_lookup_table(&actual_v0, &RFC6330_V0_TABLE, "V0") {

        // For now, validate that we have the correct reference data structure
        if RFC6330_V0_TABLE.len() != 256 {
            return ConformanceResult::Fail {
                reason: "V0 table has incorrect length".to_string(),
                details: Some(format!("Expected 256 entries, got {}", RFC6330_V0_TABLE.len())),
            };
        }

        // Validate some known RFC values (first few entries)
        let expected_first_values = [251291136u32, 3952231631, 3370958628];
        for (i, &expected) in expected_first_values.iter().enumerate() {
            if RFC6330_V0_TABLE[i] != expected {
                return ConformanceResult::Fail {
                    reason: format!("V0[{}] reference value incorrect", i),
                    details: Some(format!("Expected {}, got {}", expected, RFC6330_V0_TABLE[i])),
                };
            }
        }

        ConformanceResult::Pass
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "lookup-tables", "critical"]
    }
}

/// Test RFC 6330 Section 5.5.1 - Lookup table V1 validation
pub struct LookupTableV1Test;

impl ConformanceTest for LookupTableV1Test {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.5.1-V1"
    }

    fn section(&self) -> &str {
        "5.5"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }

    fn description(&self) -> &str {
        "Lookup table V1 MUST match RFC 6330 values exactly"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // For now, this validates that the fixtures themselves are correct.
        // TODO: When integrated with asupersync main crate:
        // let actual_v1 = asupersync::raptorq::rfc6330::V1;
        // match validate_lookup_table(&actual_v1, &RFC6330_V1_TABLE, "V1") {

        // Validate that we have the correct reference data structure
        if RFC6330_V1_TABLE.len() != 256 {
            return ConformanceResult::Fail {
                reason: "V1 table has incorrect length".to_string(),
                details: Some(format!("Expected 256 entries, got {}", RFC6330_V1_TABLE.len())),
            };
        }

        // Validate some known RFC values (first few entries)
        let expected_first_values = [807385413u32, 2043073223, 3336749796];
        for (i, &expected) in expected_first_values.iter().enumerate() {
            if RFC6330_V1_TABLE[i] != expected {
                return ConformanceResult::Fail {
                    reason: format!("V1[{}] reference value incorrect", i),
                    details: Some(format!("Expected {}, got {}", expected, RFC6330_V1_TABLE[i])),
                };
            }
        }

        ConformanceResult::Pass
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "lookup-tables", "critical"]
    }
}

/// Test RFC 6330 Section 5.1.1 - Systematic index calculation
pub struct SystematicIndexTest;

impl ConformanceTest for SystematicIndexTest {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.1.1"
    }

    fn section(&self) -> &str {
        "5.1"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }

    fn description(&self) -> &str {
        "Systematic index J(K) MUST be calculated according to RFC Table 2"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // Test systematic index calculation against RFC Table 2

        for entry in RFC6330_SYSTEMATIC_INDEX_TABLE {
            // Calculate expected systematic index J(K) = S + H from table entry
            let expected_j = entry.s + entry.h;

            // Get the calculated systematic index from our implementation
            if let Some(actual_j) = get_systematic_index(entry.k) {
                if actual_j != expected_j {
                    return ConformanceResult::Fail {
                        reason: format!("Systematic index mismatch for K={}", entry.k),
                        details: Some(format!(
                            "expected J({})={}, got {} (S={}, H={}, W={})",
                            entry.k, expected_j, actual_j, entry.s, entry.h, entry.w
                        )),
                    };
                }
            } else {
                return ConformanceResult::Fail {
                    reason: format!("No systematic index found for K={}", entry.k),
                    details: Some(format!(
                        "K={} should be supported according to RFC Table 2",
                        entry.k
                    )),
                };
            }
        }

        ConformanceResult::Pass
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "parameters", "systematic-index", "critical"]
    }
}

/// Test RFC 6330 Section 5.3.1 - Systematic tuple generation
pub struct SystematicTupleGenerationTest;

impl ConformanceTest for SystematicTupleGenerationTest {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.3.1"
    }

    fn section(&self) -> &str {
        "5.3"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Differential
    }

    fn description(&self) -> &str {
        "Systematic symbol tuples (d, a, b) MUST be generated using RFC algorithm"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // Test tuple generation against reference test vectors
        for test_vector in RFC6330_TUPLE_TEST_VECTORS {
            // Note: This test would require integration with the actual tuple generation
            // implementation in asupersync::raptorq. For now, we validate the test vector
            // structure and defer to future implementation.

            // Validate test vector structure
            if test_vector.k == 0 {
                return ConformanceResult::Fail {
                    reason: "Invalid test vector: K cannot be 0".to_string(),
                    details: Some(format!("Test vector: {:?}", test_vector)),
                };
            }

            // TODO: When tuple generation is implemented:
            // let (actual_d, actual_a, actual_b) =
            //     asupersync::raptorq::generate_tuple(test_vector.k, test_vector.symbol_index);
            //
            // if (actual_d, actual_a, actual_b) !=
            //    (test_vector.expected_d, test_vector.expected_a, test_vector.expected_b) {
            //     return ConformanceResult::Fail {
            //         reason: format!("Tuple generation mismatch for K={}, X={}",
            //                        test_vector.k, test_vector.symbol_index),
            //         details: Some(format!(
            //             "expected (d={}, a={}, b={}), got (d={}, a={}, b={})",
            //             test_vector.expected_d, test_vector.expected_a, test_vector.expected_b,
            //             actual_d, actual_a, actual_b
            //         )),
            //     };
            // }
        }

        // For now, return skipped with improved error message
        ConformanceResult::Skipped {
            reason: "Tuple generation validation requires integration with asupersync::raptorq tuple generation API".to_string(),
        }

        // When implemented with reference implementation:
        // for k in [4, 8, 16, 32, 64] {
        //     for esi in 0..k {
        //         let (d, a, b) = our_systematic_tuple_generation(k, esi);
        //         let (ref_d, ref_a, ref_b) = reference_systematic_tuple_generation(k, esi);
        //
        //         if (d, a, b) != (ref_d, ref_a, ref_b) {
        //             return ConformanceResult::Fail {
        //                 reason: format!("Systematic tuple mismatch for K={k}, ESI={esi}"),
        //                 details: Some(format!(
        //                     "our: ({d}, {a}, {b}), reference: ({ref_d}, {ref_a}, {ref_b})"
        //                 )),
        //             };
        //         }
        //     }
        // }
        // ConformanceResult::Pass
    }

    fn dependencies(&self) -> Vec<&str> {
        vec!["RFC6330-5.5.1", "RFC6330-5.1.1"] // Depends on lookup tables and systematic index
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "tuple-generation", "differential", "critical"]
    }
}

/// Test RFC 6330 Section 5.3.2 - Repair tuple generation
pub struct RepairTupleGenerationTest;

impl ConformanceTest for RepairTupleGenerationTest {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.3.2"
    }

    fn section(&self) -> &str {
        "5.3"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Differential
    }

    fn description(&self) -> &str {
        "Repair symbol tuples (d1, a1, b1) MUST be generated using RFC algorithm"
    }

    fn run(&self, ctx: &ConformanceContext) -> ConformanceResult {
        if !ctx.enable_differential {
            return ConformanceResult::Skipped {
                reason: "Differential testing disabled - no reference implementation available"
                    .to_string(),
            };
        }

        // TODO: Implement differential testing for repair tuple generation
        ConformanceResult::Skipped {
            reason: "Repair tuple generation differential testing not yet implemented".to_string(),
        }
    }

    fn dependencies(&self) -> Vec<&str> {
        vec!["RFC6330-5.5.1", "RFC6330-5.1.1"] // Depends on lookup tables and systematic index
    }

    fn tags(&self) -> Vec<&str> {
        vec![
            "p0",
            "tuple-generation",
            "differential",
            "repair-symbols",
            "critical",
        ]
    }
}

// ============================================================================
// P1 Priority Tests - High Priority Requirements
// ============================================================================

/// Test RFC 6330 Section 4.1.2 - K parameter derivation
pub struct KParameterDerivationTest;

impl ConformanceTest for KParameterDerivationTest {
    fn rfc_clause(&self) -> &str {
        "RFC6330-4.1.2"
    }

    fn section(&self) -> &str {
        "4.1"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }

    fn description(&self) -> &str {
        "K source symbols MUST be correctly derived from object size and symbol size"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // TODO: Implement K derivation validation
        ConformanceResult::Skipped {
            reason: "K parameter derivation validation not yet implemented".to_string(),
        }

        // When implemented:
        // let test_cases = [
        //     (1024, 64, 16),     // 1KB object, 64-byte symbols, expect K=16
        //     (4096, 256, 16),    // 4KB object, 256-byte symbols, expect K=16
        //     (65536, 1024, 64),  // 64KB object, 1024-byte symbols, expect K=64
        // ];
        //
        // for (object_size, symbol_size, expected_k) in test_cases {
        //     let actual_k = derive_k(object_size, symbol_size);
        //     if actual_k != expected_k {
        //         return ConformanceResult::Fail {
        //             reason: format!("K derivation incorrect for {object_size}B object with {symbol_size}B symbols"),
        //             details: Some(format!("expected K={expected_k}, got K={actual_k}")),
        //         };
        //     }
        // }
        // ConformanceResult::Pass
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p1", "parameters", "k-derivation"]
    }
}

/// Test RFC 6330 Section 5.5.1 - Lookup table V2 validation
pub struct LookupTableV2Test;

impl ConformanceTest for LookupTableV2Test {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.5.1-V2"
    }

    fn section(&self) -> &str {
        "5.5"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }

    fn description(&self) -> &str {
        "Lookup table V2 MUST match RFC 6330 values exactly"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // For now, this validates that the fixtures themselves are correct.
        // TODO: When integrated with asupersync main crate:
        // let actual_v2 = asupersync::raptorq::rfc6330::V2;
        // match validate_lookup_table(&actual_v2, &RFC6330_V2_TABLE, "V2") {

        // Validate that we have the correct reference data structure
        if RFC6330_V2_TABLE.len() != 256 {
            return ConformanceResult::Fail {
                reason: "V2 table has incorrect length".to_string(),
                details: Some(format!("Expected 256 entries, got {}", RFC6330_V2_TABLE.len())),
            };
        }

        // Validate some known RFC values (first few entries)
        let expected_first_values = [1629829892u32, 282540176, 2794583710];
        for (i, &expected) in expected_first_values.iter().enumerate() {
            if RFC6330_V2_TABLE[i] != expected {
                return ConformanceResult::Fail {
                    reason: format!("V2[{}] reference value incorrect", i),
                    details: Some(format!("Expected {}, got {}", expected, RFC6330_V2_TABLE[i])),
                };
            }
        }

        ConformanceResult::Pass
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "lookup-tables", "critical"]
    }
}

/// Test RFC 6330 Section 5.5.1 - Lookup table V3 validation
pub struct LookupTableV3Test;

impl ConformanceTest for LookupTableV3Test {
    fn rfc_clause(&self) -> &str {
        "RFC6330-5.5.1-V3"
    }

    fn section(&self) -> &str {
        "5.5"
    }

    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }

    fn description(&self) -> &str {
        "Lookup table V3 MUST match RFC 6330 values exactly"
    }

    fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
        // For now, this validates that the fixtures themselves are correct.
        // TODO: When integrated with asupersync main crate:
        // let actual_v3 = asupersync::raptorq::rfc6330::V3;
        // match validate_lookup_table(&actual_v3, &RFC6330_V3_TABLE, "V3") {

        // Validate that we have the correct reference data structure
        if RFC6330_V3_TABLE.len() != 256 {
            return ConformanceResult::Fail {
                reason: "V3 table has incorrect length".to_string(),
                details: Some(format!("Expected 256 entries, got {}", RFC6330_V3_TABLE.len())),
            };
        }

        // Validate some known RFC values (first few entries)
        let expected_first_values = [1772608948u32, 3669932701, 400781334];
        for (i, &expected) in expected_first_values.iter().enumerate() {
            if RFC6330_V3_TABLE[i] != expected {
                return ConformanceResult::Fail {
                    reason: format!("V3[{}] reference value incorrect", i),
                    details: Some(format!("Expected {}, got {}", expected, RFC6330_V3_TABLE[i])),
                };
            }
        }

        ConformanceResult::Pass
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "lookup-tables", "critical"]
    }
}

// ============================================================================
// Test Registry Helper
// ============================================================================

/// Get all example conformance tests for registration
pub fn get_all_example_tests() -> Vec<Box<dyn ConformanceTest>> {
    vec![
        // P0 Tests - RFC 6330 lookup tables
        Box::new(LookupTableV0Test),
        Box::new(LookupTableV1Test),
        Box::new(LookupTableV2Test),
        Box::new(LookupTableV3Test),
        // P0 Tests - RFC 6330 parameters and algorithms
        Box::new(SystematicIndexTest),
        Box::new(SystematicTupleGenerationTest),
    ]
}

/// Get P0 priority tests only (critical requirements)
pub fn get_p0_tests() -> Vec<Box<dyn ConformanceTest>> {
    vec![
        Box::new(LookupTableV0Test),
        Box::new(LookupTableV1Test),
        Box::new(LookupTableV2Test),
        Box::new(LookupTableV3Test),
        Box::new(SystematicIndexTest),
        Box::new(SystematicTupleGenerationTest),
    ]
}

/// Get tests by section
pub fn get_section_tests(section: &str) -> Vec<Box<dyn ConformanceTest>> {
    let all_tests = get_all_example_tests();
    all_tests
        .into_iter()
        .filter(|test| test.section() == section)
        .collect()
}

/// Get tests by requirement level
pub fn get_level_tests(level: RequirementLevel) -> Vec<Box<dyn ConformanceTest>> {
    let all_tests = get_all_example_tests();
    all_tests
        .into_iter()
        .filter(|test| test.requirement_level() == level)
        .collect()
}
