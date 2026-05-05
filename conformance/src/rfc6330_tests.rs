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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/rfc6330.rs::V0")
    }

    fn fixture_reference(&self) -> Option<&str> {
        Some("RFC6330_V0_TABLE")
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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/rfc6330.rs::V1")
    }

    fn fixture_reference(&self) -> Option<&str> {
        Some("RFC6330_V1_TABLE")
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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/systematic.rs::SystematicParams::try_for_source_block")
    }

    fn fixture_reference(&self) -> Option<&str> {
        Some("RFC6330_SYSTEMATIC_INDEX_TABLE")
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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/rfc6330.rs::try_tuple")
    }

    fn fixture_reference(&self) -> Option<&str> {
        Some("RFC6330_TUPLE_TEST_VECTORS")
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
            return ConformanceResult::Blocked {
                reason: "Repair tuple generation needs a live oracle or reference fixture path; differential fixtures are disabled".to_string(),
                blocker_id: "asupersync-kokw3m".to_string(),
            };
        }

        ConformanceResult::Blocked {
            reason:
                "Repair tuple generation differential testing is not wired to a live oracle yet"
                    .to_string(),
            blocker_id: "asupersync-kokw3m".to_string(),
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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/decoder.rs::InactivationDecoder::repair_equation_rfc6330")
    }

    fn blocker_id(&self) -> Option<&str> {
        Some("asupersync-kokw3m")
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
        ConformanceResult::Blocked {
            reason: "K parameter derivation validation is not wired to a live SourceBlockEncoder assertion yet".to_string(),
            blocker_id: "asupersync-kokw3m".to_string(),
        }
    }

    fn tags(&self) -> Vec<&str> {
        vec!["p1", "parameters", "k-derivation"]
    }

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/encoder.rs::SourceBlockEncoder")
    }

    fn blocker_id(&self) -> Option<&str> {
        Some("asupersync-kokw3m")
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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/rfc6330.rs::V2")
    }

    fn fixture_reference(&self) -> Option<&str> {
        Some("RFC6330_V2_TABLE")
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

    fn production_seam_path(&self) -> Option<&str> {
        Some("src/raptorq/rfc6330.rs::V3")
    }

    fn fixture_reference(&self) -> Option<&str> {
        Some("RFC6330_V3_TABLE")
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
        Box::new(RepairTupleGenerationTest),
        // P1 Tests - explicitly tracked gaps that must not masquerade as live conformance
        Box::new(KParameterDerivationTest),
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
    runner.register_test(RepairTupleGenerationTest);
    runner.register_test(KParameterDerivationTest);
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
        Box::new(RepairTupleGenerationTest),
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
        assert_eq!(registry.len(), 8);
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
        assert_eq!(runner.test_count_by_level(RequirementLevel::Must), 8);
    }

    #[test]
    fn rfc6330_registry_filters_select_expected_subsets() {
        assert_eq!(get_section_tests("5.5").len(), 4);
        assert_eq!(get_section_tests("5.1").len(), 1);
        assert_eq!(get_section_tests("5.3").len(), 2);
        assert_eq!(get_section_tests("4.1").len(), 1);
        assert_eq!(get_level_tests(RequirementLevel::Must).len(), 8);
        assert!(get_level_tests(RequirementLevel::Should).is_empty());
        assert_eq!(get_p0_tests().len(), 7);
    }

    #[test]
    fn rfc6330_registered_live_tests_pass_and_degraded_gaps_are_blocked() {
        let ctx = ConformanceContext::default();
        let mut live_checked = 0;
        let mut blocked = 0;

        for test in get_all_example_tests() {
            let result = test.run(&ctx);
            match test.rfc_clause() {
                "RFC6330-5.3.2" | "RFC6330-4.1.2" => {
                    assert!(
                        matches!(result, ConformanceResult::Blocked { .. }),
                        "{} must be explicit blocked evidence, got {}",
                        test.name(),
                        result.description()
                    );
                    assert_eq!(test.blocker_id(), Some("asupersync-kokw3m"));
                    assert!(test.production_seam_path().is_some());
                    blocked += 1;
                }
                _ => {
                    assert_eq!(
                        result,
                        ConformanceResult::Pass,
                        "{} returned {}",
                        test.name(),
                        result.description()
                    );
                    assert!(test.production_seam_path().is_some());
                    live_checked += 1;
                }
            }
        }

        assert_eq!(live_checked, 6);
        assert_eq!(blocked, 2);
    }
}
