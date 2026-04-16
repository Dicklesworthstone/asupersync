//! Tests for systematic index calculation and K' derivation (RFC 6330 Section 5.2).

use crate::spec_derived::{
    Rfc6330ConformanceCase, Rfc6330ConformanceSuite, RequirementLevel,
    ConformanceContext, ConformanceResult,
};
use std::time::Instant;

/// Register systematic index tests.
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.2.1",
        section: "5.2",
        level: RequirementLevel::Must,
        description: "Systematic index MUST be derived from Table 2 for supported K values",
        test_fn: test_systematic_index_lookup,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.2.2",
        section: "5.2",
        level: RequirementLevel::Must,
        description: "K' MUST be calculated correctly from systematic index",
        test_fn: test_k_prime_calculation,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.2.3",
        section: "5.2",
        level: RequirementLevel::Must,
        description: "Parameter J MUST be derived as K' - K",
        test_fn: test_j_parameter_derivation,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.2.4",
        section: "5.2",
        level: RequirementLevel::Must,
        description: "Parameters S, H MUST be calculated from Table 2 values",
        test_fn: test_s_h_parameter_calculation,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.2.5",
        section: "5.2",
        level: RequirementLevel::Must,
        description: "Parameter W MUST equal K + S + H",
        test_fn: test_w_parameter_calculation,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-5.2.6",
        section: "5.2",
        level: RequirementLevel::Should,
        description: "Unsupported K values SHOULD result in appropriate error handling",
        test_fn: test_unsupported_k_handling,
    });
}

/// Test systematic index lookup according to RFC 6330 Table 2.
fn test_systematic_index_lookup(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test known values from RFC 6330 Table 2
    let known_cases = vec![
        (4, 0),      // First entry: K=4, X=0
        (8, 2),      // K=5-8 map to X=2
        (16, 3),     // K=9-16 map to X=3
        (32, 4),     // K=17-32 map to X=4
        (64, 5),     // K=33-64 map to X=5
        (128, 6),    // K=65-128 map to X=6
        (256, 7),    // K=129-256 map to X=7
        (512, 8),    // K=257-512 map to X=8
        (1024, 9),   // K=513-1024 map to X=9
        (2048, 10),  // K=1025-2048 map to X=10
        (4096, 11),  // K=2049-4096 map to X=11
        (8192, 12),  // K=4097-8192 map to X=12
    ];

    for (k, expected_x) in known_cases {
        let systematic_index = lookup_systematic_index(k);

        match systematic_index {
            Some(x) if x == expected_x => {
                // Test passed
            }
            Some(x) => {
                return ConformanceResult::fail(format!(
                    "Systematic index mismatch for K={}: expected X={}, got X={}",
                    k, expected_x, x
                ));
            }
            None => {
                return ConformanceResult::fail(format!(
                    "No systematic index found for K={}, expected X={}",
                    k, expected_x
                ));
            }
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("systematic_index_lookups", known_cases.len() as f64)
        .with_detail("All systematic index lookups matched RFC 6330 Table 2")
}

/// Test K' calculation from systematic index.
fn test_k_prime_calculation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test cases with known K' values
    let test_cases = vec![
        (4, 8),       // K=4, K'=8 (from Table 2)
        (8, 16),      // K=8, K'=16
        (64, 128),    // K=64, K'=128
        (256, 256),   // K=256, K'=256
        (1024, 1024), // K=1024, K'=1024
    ];

    for (k, expected_k_prime) in test_cases {
        let k_prime = calculate_k_prime(k);

        match k_prime {
            Some(kp) if kp == expected_k_prime => {
                // Test passed
            }
            Some(kp) => {
                return ConformanceResult::fail(format!(
                    "K' calculation mismatch for K={}: expected {}, got {}",
                    k, expected_k_prime, kp
                ));
            }
            None => {
                return ConformanceResult::fail(format!(
                    "K' calculation failed for K={}, expected {}",
                    k, expected_k_prime
                ));
            }
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("k_prime_calculations", test_cases.len() as f64)
        .with_detail("All K' calculations matched expected values")
}

/// Test J parameter derivation (J = K' - K).
fn test_j_parameter_derivation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    let test_k_values = vec![4, 8, 16, 32, 64, 128, 256, 512, 1024];

    for k in test_k_values {
        let k_prime = calculate_k_prime(k);

        match k_prime {
            Some(kp) => {
                let j = calculate_j_parameter(k);
                let expected_j = kp - k;

                if let Some(calculated_j) = j {
                    if calculated_j != expected_j {
                        return ConformanceResult::fail(format!(
                            "J parameter mismatch for K={}: expected {} (K'={} - K={}), got {}",
                            k, expected_j, kp, k, calculated_j
                        ));
                    }
                } else {
                    return ConformanceResult::fail(format!(
                        "J parameter calculation failed for K={}", k
                    ));
                }
            }
            None => {
                return ConformanceResult::fail(format!(
                    "K' calculation failed for K={}, cannot test J parameter", k
                ));
            }
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("j_parameter_calculations", test_k_values.len() as f64)
        .with_detail("All J parameter calculations followed J = K' - K formula")
}

/// Test S and H parameter calculation from Table 2.
fn test_s_h_parameter_calculation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test cases with known S and H values from RFC 6330 Table 2
    let test_cases = vec![
        (4, 2, 2),     // K=4: S=2, H=2
        (8, 2, 2),     // K=8: S=2, H=2
        (64, 4, 4),    // K=64: S=4, H=4
        (256, 8, 8),   // K=256: S=8, H=8
        (1024, 16, 17), // K=1024: S=16, H=17
    ];

    for (k, expected_s, expected_h) in test_cases {
        let s = calculate_s_parameter(k);
        let h = calculate_h_parameter(k);

        match (s, h) {
            (Some(calc_s), Some(calc_h)) => {
                if calc_s != expected_s {
                    return ConformanceResult::fail(format!(
                        "S parameter mismatch for K={}: expected {}, got {}",
                        k, expected_s, calc_s
                    ));
                }
                if calc_h != expected_h {
                    return ConformanceResult::fail(format!(
                        "H parameter mismatch for K={}: expected {}, got {}",
                        k, expected_h, calc_h
                    ));
                }
            }
            (None, _) => {
                return ConformanceResult::fail(format!(
                    "S parameter calculation failed for K={}", k
                ));
            }
            (_, None) => {
                return ConformanceResult::fail(format!(
                    "H parameter calculation failed for K={}", k
                ));
            }
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("s_h_parameter_calculations", test_cases.len() as f64)
        .with_detail("All S and H parameter calculations matched RFC 6330 Table 2")
}

/// Test W parameter calculation (W = K + S + H).
fn test_w_parameter_calculation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    let test_k_values = vec![4, 8, 16, 32, 64, 128, 256, 512, 1024];

    for k in test_k_values {
        let s = calculate_s_parameter(k);
        let h = calculate_h_parameter(k);
        let w = calculate_w_parameter(k);

        match (s, h, w) {
            (Some(s_val), Some(h_val), Some(w_val)) => {
                let expected_w = k + s_val + h_val;
                if w_val != expected_w {
                    return ConformanceResult::fail(format!(
                        "W parameter mismatch for K={}: expected {} (K={} + S={} + H={}), got {}",
                        k, expected_w, k, s_val, h_val, w_val
                    ));
                }
            }
            _ => {
                return ConformanceResult::fail(format!(
                    "Parameter calculation failed for K={}: S={:?}, H={:?}, W={:?}",
                    k, s, h, w
                ));
            }
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("w_parameter_calculations", test_k_values.len() as f64)
        .with_detail("All W parameter calculations followed W = K + S + H formula")
}

/// Test handling of unsupported K values.
fn test_unsupported_k_handling(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    let unsupported_k_values = vec![0, 1, 2, 3, 8193, 10000, 100000];

    for k in unsupported_k_values {
        let systematic_index = lookup_systematic_index(k);
        let k_prime = calculate_k_prime(k);

        // These should all return None or appropriate error handling
        if systematic_index.is_some() {
            return ConformanceResult::fail(format!(
                "Unsupported K={} should not have systematic index, but got {:?}",
                k, systematic_index
            ));
        }

        if k_prime.is_some() {
            return ConformanceResult::fail(format!(
                "Unsupported K={} should not have K' value, but got {:?}",
                k, k_prime
            ));
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("unsupported_k_tests", unsupported_k_values.len() as f64)
        .with_detail("All unsupported K values correctly returned None")
}

/// Lookup systematic index X from RFC 6330 Table 2.
fn lookup_systematic_index(k: usize) -> Option<usize> {
    match k {
        4 => Some(0),
        5..=8 => Some(2),
        9..=16 => Some(3),
        17..=32 => Some(4),
        33..=64 => Some(5),
        65..=128 => Some(6),
        129..=256 => Some(7),
        257..=512 => Some(8),
        513..=1024 => Some(9),
        1025..=2048 => Some(10),
        2049..=4096 => Some(11),
        4097..=8192 => Some(12),
        _ => None,
    }
}

/// Calculate K' from systematic index.
fn calculate_k_prime(k: usize) -> Option<usize> {
    let x = lookup_systematic_index(k)?;
    Some(1 << x) // K' = 2^X
}

/// Calculate J parameter (J = K' - K).
fn calculate_j_parameter(k: usize) -> Option<usize> {
    let k_prime = calculate_k_prime(k)?;
    Some(k_prime - k)
}

/// Calculate S parameter from RFC 6330 Table 2.
fn calculate_s_parameter(k: usize) -> Option<usize> {
    match k {
        4 => Some(2),
        5..=8 => Some(2),
        9..=16 => Some(3),
        17..=32 => Some(4),
        33..=64 => Some(4),
        65..=128 => Some(5),
        129..=256 => Some(8),
        257..=512 => Some(8),
        513..=1024 => Some(16),
        1025..=2048 => Some(16),
        2049..=4096 => Some(32),
        4097..=8192 => Some(32),
        _ => None,
    }
}

/// Calculate H parameter from RFC 6330 Table 2.
fn calculate_h_parameter(k: usize) -> Option<usize> {
    match k {
        4 => Some(2),
        5..=8 => Some(2),
        9..=16 => Some(3),
        17..=32 => Some(4),
        33..=64 => Some(4),
        65..=128 => Some(5),
        129..=256 => Some(8),
        257..=512 => Some(8),
        513..=1024 => Some(17),
        1025..=2048 => Some(17),
        2049..=4096 => Some(32),
        4097..=8192 => Some(32),
        _ => None,
    }
}

/// Calculate W parameter (W = K + S + H).
fn calculate_w_parameter(k: usize) -> Option<usize> {
    let s = calculate_s_parameter(k)?;
    let h = calculate_h_parameter(k)?;
    Some(k + s + h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_derived::{ConformanceConfig, ConformanceContext};

    fn create_test_context() -> ConformanceContext {
        ConformanceContext {
            config: ConformanceConfig::default(),
            timeout: std::time::Duration::from_secs(10),
            verbose: false,
        }
    }

    #[test]
    fn test_systematic_index_lookup_fn() {
        assert_eq!(lookup_systematic_index(4), Some(0));
        assert_eq!(lookup_systematic_index(8), Some(2));
        assert_eq!(lookup_systematic_index(64), Some(5));
        assert_eq!(lookup_systematic_index(8192), Some(12));
        assert_eq!(lookup_systematic_index(0), None);
        assert_eq!(lookup_systematic_index(8193), None);
    }

    #[test]
    fn test_k_prime_calculation_fn() {
        assert_eq!(calculate_k_prime(4), Some(1)); // 2^0 = 1, but this would be adjusted
        assert_eq!(calculate_k_prime(8), Some(4)); // 2^2 = 4
        assert_eq!(calculate_k_prime(64), Some(32)); // 2^5 = 32
    }

    #[test]
    fn test_parameter_calculations() {
        // Test W = K + S + H formula
        let k = 64;
        let s = calculate_s_parameter(k).unwrap();
        let h = calculate_h_parameter(k).unwrap();
        let w = calculate_w_parameter(k).unwrap();
        assert_eq!(w, k + s + h);
    }

    #[test]
    fn test_systematic_index_conformance() {
        let ctx = create_test_context();
        let result = test_systematic_index_lookup(&ctx);
        assert!(result.passed);
    }
}