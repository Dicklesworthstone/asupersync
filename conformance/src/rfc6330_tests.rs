//! RFC 6330 Conformance Tests
//!
//! This module contains conformance tests that validate the asupersync RaptorQ
//! implementation against RFC 6330 requirements using reference fixtures.

use crate::raptorq_rfc6330::{
    ConformanceContext, ConformanceResult, ConformanceRunner, ConformanceTest, RequirementLevel,
    TestCategory,
};
use crate::rfc6330_fixtures::*;
use asupersync::raptorq::{
    rfc6330::{self, LtTuple},
    systematic::SystematicParams,
};

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
        lookup_table_result(&rfc6330::V0, &RFC6330_V0_TABLE, "V0")
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
        lookup_table_result(&rfc6330::V1, &RFC6330_V1_TABLE, "V1")
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
        for entry in RFC6330_SYSTEMATIC_INDEX_TABLE.iter() {
            let params =
                match SystematicParams::try_for_source_block(usize::from(entry.k_prime), 1024) {
                    Ok(params) => params,
                    Err(err) => {
                        return ConformanceResult::Fail {
                            reason: format!(
                                "Systematic parameter lookup failed for K'={}",
                                entry.k_prime
                            ),
                            details: Some(format!("{err:?}")),
                        };
                    }
                };

            let actual = (params.k_prime, params.j, params.s, params.h, params.w);
            let expected = (
                usize::from(entry.k_prime),
                usize::from(entry.systematic_index),
                usize::from(entry.s),
                usize::from(entry.h),
                usize::try_from(entry.w).expect("RFC6330 W fixture fits usize"),
            );
            if actual != expected {
                return ConformanceResult::Fail {
                    reason: format!("Systematic parameters mismatch for K'={}", entry.k_prime),
                    details: Some(format!(
                        "expected (K', J, S, H, W)={expected:?}, got {actual:?}"
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
        for test_vector in RFC6330_TUPLE_TEST_VECTORS {
            let params =
                match SystematicParams::try_for_source_block(usize::from(test_vector.k), 1024) {
                    Ok(params) => params,
                    Err(err) => {
                        return ConformanceResult::Fail {
                            reason: format!(
                                "Systematic parameter lookup failed for K={}",
                                test_vector.k
                            ),
                            details: Some(format!("{err:?}")),
                        };
                    }
                };
            let p1 = rfc6330::next_prime_ge(params.p);
            let actual =
                rfc6330::try_tuple(params.j, params.w, params.p, p1, test_vector.symbol_index);
            let expected = LtTuple {
                d: usize::try_from(test_vector.expected_d).expect("tuple d fixture fits usize"),
                a: usize::try_from(test_vector.expected_a).expect("tuple a fixture fits usize"),
                b: usize::try_from(test_vector.expected_b).expect("tuple b fixture fits usize"),
                d1: usize::try_from(test_vector.expected_d1).expect("tuple d1 fixture fits usize"),
                a1: usize::try_from(test_vector.expected_a1).expect("tuple a1 fixture fits usize"),
                b1: usize::try_from(test_vector.expected_b1).expect("tuple b1 fixture fits usize"),
            };

            match actual {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return ConformanceResult::Fail {
                        reason: format!(
                            "Tuple generation mismatch for K={}, X={}",
                            test_vector.k, test_vector.symbol_index
                        ),
                        details: Some(format!(
                            "expected {expected:?}, got {actual:?} (J={}, W={}, P={}, P1={p1})",
                            params.j, params.w, params.p
                        )),
                    };
                }
                None => {
                    return ConformanceResult::Fail {
                        reason: format!(
                            "Tuple generation rejected RFC fixture for K={}, X={}",
                            test_vector.k, test_vector.symbol_index
                        ),
                        details: Some(format!(
                            "live tuple seam rejected valid inputs J={}, W={}, P={}, P1={p1}",
                            params.j, params.w, params.p
                        )),
                    };
                }
            }
        }

        ConformanceResult::Pass
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
        lookup_table_result(&rfc6330::V2, &RFC6330_V2_TABLE, "V2")
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
        lookup_table_result(&rfc6330::V3, &RFC6330_V3_TABLE, "V3")
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p0", "lookup-tables", "critical"]
    }
}

// ============================================================================
// Test Registry Helper
// ============================================================================

fn lookup_table_result(
    actual: &[u32; 256],
    expected: &[u32; 256],
    name: &str,
) -> ConformanceResult {
    match validate_lookup_table(actual, expected, name) {
        Ok(()) => ConformanceResult::Pass,
        Err(err) => ConformanceResult::Fail {
            reason: format!("{name} lookup table diverges from RFC 6330 fixture"),
            details: Some(err),
        },
    }
}

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

/// Register every RFC 6330 conformance test exposed by this module.
pub fn register_all_tests(runner: &mut ConformanceRunner) {
    runner.register_test(LookupTableV0Test);
    runner.register_test(LookupTableV1Test);
    runner.register_test(LookupTableV2Test);
    runner.register_test(LookupTableV3Test);
    runner.register_test(SystematicIndexTest);
    runner.register_test(SystematicTupleGenerationTest);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6330_registry_exposes_real_tests() {
        let registry = get_all_example_tests();
        assert_eq!(registry.len(), 6);
        assert!(registry.iter().all(|test| !test.rfc_clause().is_empty()));
        assert!(registry.iter().all(|test| !test.description().is_empty()));
    }

    #[test]
    fn rfc6330_register_all_tests_matches_registry() {
        let mut runner = ConformanceRunner::new();
        register_all_tests(&mut runner);

        let registry = get_all_example_tests();
        let registry_names: Vec<_> = registry.iter().map(|test| test.name()).collect();

        assert_eq!(runner.test_count(), registry.len());
        assert_eq!(runner.test_names(), registry_names);
        assert_eq!(runner.test_count_by_level(RequirementLevel::Must), 6);
    }

    #[test]
    fn rfc6330_registry_filters_select_expected_subsets() {
        assert_eq!(get_section_tests("5.5").len(), 4);
        assert_eq!(get_section_tests("5.1").len(), 1);
        assert_eq!(get_section_tests("5.3").len(), 1);
        assert_eq!(get_level_tests(RequirementLevel::Must).len(), 6);
        assert!(get_level_tests(RequirementLevel::Should).is_empty());
        assert_eq!(get_p0_tests().len(), 6);
    }

    #[test]
    fn rfc6330_registered_tests_pass_against_runtime() {
        let ctx = ConformanceContext::default();

        for test in get_all_example_tests() {
            let result = test.run(&ctx);
            assert_eq!(
                result,
                ConformanceResult::Pass,
                "{} returned {}",
                test.name(),
                result.description()
            );
        }
    }
}
