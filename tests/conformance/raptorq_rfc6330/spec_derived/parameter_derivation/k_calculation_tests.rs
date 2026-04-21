//! Tests for K derivation from object size and symbol size (RFC 6330 Section 5.1).

use crate::{
    Rfc6330ConformanceCase, Rfc6330ConformanceSuite, RequirementLevel,
    ConformanceContext, ConformanceResult,
};
use std::time::Instant;

/// Register K calculation conformance tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.1.1",
        section: "5.1",
        level: RequirementLevel::Must,
        description: "K MUST be calculated as ceil(object_size / symbol_size)",
        test_fn: test_k_calculation_basic,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.1.2",
        section: "5.1",
        level: RequirementLevel::Must,
        description: "K MUST be within supported range [1, 8192]",
        test_fn: test_k_range_validation,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.1.3",
        section: "5.1",
        level: RequirementLevel::Must,
        description: "Source block subdivision MUST handle objects larger than max K",
        test_fn: test_source_block_subdivision,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.1.4",
        section: "5.1",
        level: RequirementLevel::Should,
        description: "Symbol padding SHOULD be applied for partial final symbols",
        test_fn: test_symbol_padding,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.1.5",
        section: "5.1",
        level: RequirementLevel::Must,
        description: "K calculation MUST be deterministic for given inputs",
        test_fn: test_k_calculation_deterministic,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.1.6",
        section: "5.1",
        level: RequirementLevel::Must,
        description: "Edge case: single-byte objects MUST result in K=1",
        test_fn: test_k_calculation_edge_cases,
    });
}

/// Test basic K calculation according to RFC 6330 formula.
#[allow(dead_code)]
fn test_k_calculation_basic(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test cases: (object_size, symbol_size, expected_k)
    let test_cases = vec![
        (1000, 100, 10),     // Exact division
        (1000, 300, 4),      // Requires ceiling
        (1, 1, 1),           // Minimum case
        (1000, 1, 1000),     // Many small symbols
        (8192, 1, 8192),     // Maximum K
    ];

    for (object_size, symbol_size, expected_k) in test_cases {
        let calculated_k = calculate_k_rfc6330(object_size, symbol_size);

        if calculated_k != expected_k {
            return ConformanceResult::fail(format!(
                "K calculation mismatch: object_size={}, symbol_size={}, expected={}, got={}",
                object_size, symbol_size, expected_k, calculated_k
            ));
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("test_cases_validated", test_cases.len() as f64)
        .with_detail("All basic K calculation test cases passed")
}

/// Test K range validation according to RFC 6330 limits.
#[allow(dead_code)]
fn test_k_range_validation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test minimum valid K
    let min_k = calculate_k_rfc6330(1, 1);
    if min_k != 1 {
        return ConformanceResult::fail(format!("Minimum K should be 1, got {}", min_k));
    }

    // Test maximum valid K
    let max_k = calculate_k_rfc6330(8192, 1);
    if max_k != 8192 {
        return ConformanceResult::fail(format!("Maximum K should be 8192, got {}", max_k));
    }

    // Test K > maximum should trigger error handling
    // Note: In practice, this would be handled by source block subdivision
    let oversized_result = validate_k_in_range(8193);
    if oversized_result {
        return ConformanceResult::fail("K=8193 should not be valid");
    }

    // Test K = 0 should be invalid
    let zero_result = validate_k_in_range(0);
    if zero_result {
        return ConformanceResult::fail("K=0 should not be valid");
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("range_validations", 4.0)
        .with_detail("K range validation passed for min/max boundaries")
}

/// Test source block subdivision for large objects.
#[allow(dead_code)]
fn test_source_block_subdivision(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test object larger than maximum source block
    let large_object_size = 100000;  // 100KB
    let symbol_size = 10;            // 10 bytes per symbol

    let subdivision = calculate_source_block_subdivision(large_object_size, symbol_size);

    // Each source block should have K <= 8192
    for (block_index, k_value) in subdivision.iter().enumerate() {
        if *k_value > 8192 {
            return ConformanceResult::fail(format!(
                "Source block {} has K={} which exceeds maximum of 8192",
                block_index, k_value
            ));
        }
        if *k_value < 1 {
            return ConformanceResult::fail(format!(
                "Source block {} has K={} which is below minimum of 1",
                block_index, k_value
            ));
        }
    }

    // Total symbols across all blocks should cover the object
    let total_symbols: usize = subdivision.iter().sum();
    let expected_total_symbols = (large_object_size + symbol_size - 1) / symbol_size; // Ceiling division

    if total_symbols != expected_total_symbols {
        return ConformanceResult::fail(format!(
            "Total symbols mismatch: expected {}, got {}",
            expected_total_symbols, total_symbols
        ));
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("source_blocks_created", subdivision.len() as f64)
        .with_metric("total_symbols", total_symbols as f64)
        .with_detail(format!("Successfully subdivided into {} source blocks", subdivision.len()))
}

/// Test symbol padding behavior for partial symbols.
#[allow(dead_code)]
fn test_symbol_padding(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test case where object doesn't align perfectly with symbol boundaries
    let object_size = 1050;  // 1050 bytes
    let symbol_size = 100;   // 100 bytes per symbol

    let k = calculate_k_rfc6330(object_size, symbol_size);
    let expected_k = 11; // ceil(1050/100) = 11

    if k != expected_k {
        return ConformanceResult::fail(format!(
            "K calculation with padding: expected {}, got {}",
            expected_k, k
        ));
    }

    // Calculate padding needed for the final symbol
    let total_data_size = k * symbol_size;
    let padding_bytes = total_data_size - object_size;
    let expected_padding = 50; // 11*100 - 1050 = 50 bytes

    if padding_bytes != expected_padding {
        return ConformanceResult::fail(format!(
            "Padding calculation: expected {} bytes, got {}",
            expected_padding, padding_bytes
        ));
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("padding_bytes", padding_bytes as f64)
        .with_metric("padding_percentage", (padding_bytes as f64 / symbol_size as f64) * 100.0)
        .with_detail(format!("Symbol padding correctly calculated: {} bytes", padding_bytes))
}

/// Test that K calculation is deterministic.
#[allow(dead_code)]
fn test_k_calculation_deterministic(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    let test_cases = ctx.config.test_object_sizes.iter()
        .flat_map(|&obj_size|
            ctx.config.test_symbol_sizes.iter()
                .map(move |&sym_size| (obj_size, sym_size))
        )
        .collect::<Vec<_>>();

    for (object_size, symbol_size) in test_cases {
        let k1 = calculate_k_rfc6330(object_size, symbol_size);
        let k2 = calculate_k_rfc6330(object_size, symbol_size);

        if k1 != k2 {
            return ConformanceResult::fail(format!(
                "K calculation not deterministic: obj={}, sym={}, got {} and {}",
                object_size, symbol_size, k1, k2
            ));
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("deterministic_tests", test_cases.len() as f64)
        .with_detail("All K calculations were deterministic across repeated calls")
}

/// Test edge cases for K calculation.
#[allow(dead_code)]
fn test_k_calculation_edge_cases(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut edge_cases_tested = 0;

    // Single byte object with single byte symbols
    let k = calculate_k_rfc6330(1, 1);
    if k != 1 {
        return ConformanceResult::fail(format!("Single byte object: expected K=1, got {}", k));
    }
    edge_cases_tested += 1;

    // Object size equals symbol size
    let k = calculate_k_rfc6330(256, 256);
    if k != 1 {
        return ConformanceResult::fail(format!("Equal sizes: expected K=1, got {}", k));
    }
    edge_cases_tested += 1;

    // Object size is one less than symbol size
    let k = calculate_k_rfc6330(255, 256);
    if k != 1 {
        return ConformanceResult::fail(format!("Object < symbol: expected K=1, got {}", k));
    }
    edge_cases_tested += 1;

    // Large symbol size, small object
    let k = calculate_k_rfc6330(10, 1000);
    if k != 1 {
        return ConformanceResult::fail(format!("Small object/large symbol: expected K=1, got {}", k));
    }
    edge_cases_tested += 1;

    // Maximum supported K
    let k = calculate_k_rfc6330(8192, 1);
    if k != 8192 {
        return ConformanceResult::fail(format!("Maximum K: expected 8192, got {}", k));
    }
    edge_cases_tested += 1;

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("edge_cases_tested", edge_cases_tested as f64)
        .with_detail("All edge cases for K calculation passed")
}

/// Calculate K according to RFC 6330 Section 5.1.
#[allow(dead_code)]
fn calculate_k_rfc6330(object_size: usize, symbol_size: usize) -> usize {
    if symbol_size == 0 {
        return 0; // Invalid input
    }

    // K = ceil(object_size / symbol_size)
    (object_size + symbol_size - 1) / symbol_size
}

/// Validate that K is within the supported range.
#[allow(dead_code)]
fn validate_k_in_range(k: usize) -> bool {
    k >= 1 && k <= 8192
}

/// Calculate source block subdivision for large objects.
#[allow(dead_code)]
fn calculate_source_block_subdivision(object_size: usize, symbol_size: usize) -> Vec<usize> {
    const MAX_K: usize = 8192;

    let total_symbols = calculate_k_rfc6330(object_size, symbol_size);
    let mut subdivision = Vec::new();

    let mut remaining_symbols = total_symbols;
    while remaining_symbols > 0 {
        let block_k = remaining_symbols.min(MAX_K);
        subdivision.push(block_k);
        remaining_symbols -= block_k;
    }

    subdivision
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConformanceConfig, ConformanceContext};

    #[allow(dead_code)]

    fn create_test_context() -> ConformanceContext {
        ConformanceContext {
            config: ConformanceConfig::default(),
            timeout: std::time::Duration::from_secs(10),
            verbose: false,
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_k_calculation_formula() {
        assert_eq!(calculate_k_rfc6330(1000, 100), 10);
        assert_eq!(calculate_k_rfc6330(1000, 300), 4);
        assert_eq!(calculate_k_rfc6330(1, 1), 1);
        assert_eq!(calculate_k_rfc6330(8192, 1), 8192);
    }

    #[test]
    #[allow(dead_code)]
    fn test_k_range_validation_fn() {
        assert!(validate_k_in_range(1));
        assert!(validate_k_in_range(8192));
        assert!(!validate_k_in_range(0));
        assert!(!validate_k_in_range(8193));
    }

    #[test]
    #[allow(dead_code)]
    fn test_source_block_subdivision_fn() {
        let subdivision = calculate_source_block_subdivision(100000, 10);
        assert!(subdivision.iter().all(|&k| k <= 8192));
        assert!(subdivision.iter().all(|&k| k >= 1));

        let total: usize = subdivision.iter().sum();
        let expected = calculate_k_rfc6330(100000, 10);
        assert_eq!(total, expected);
    }

    #[test]
    #[allow(dead_code)]
    fn test_k_calculation_conformance() {
        let ctx = create_test_context();
        let result = test_k_calculation_basic(&ctx);
        assert!(result.passed);
    }

    #[test]
    #[allow(dead_code)]
    fn test_k_range_validation_conformance() {
        let ctx = create_test_context();
        let result = test_k_range_validation(&ctx);
        assert!(result.passed);
    }
}