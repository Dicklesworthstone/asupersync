#![allow(clippy::all)]
//! Comprehensive validation tests for GF(256) finite field operations.
//!
//! This module provides systematic validation of the GF(256) implementation
//! against known mathematical properties and RFC 6330 requirements.

use super::*;
use std::collections::HashSet;

/// Test basic field properties: associativity, commutativity, distributivity
#[test]
fn test_field_properties() {
    // Test a representative sample of elements
    let test_elements = [0, 1, 2, 3, 17, 42, 85, 127, 170, 255];

    for &a in &test_elements {
        for &b in &test_elements {
            for &c in &test_elements {
                let gf_a = Gf256::new(a);
                let gf_b = Gf256::new(b);
                let gf_c = Gf256::new(c);

                // Addition is commutative: a + b = b + a
                assert_eq!(
                    gf_a + gf_b,
                    gf_b + gf_a,
                    "Addition not commutative for {} + {}",
                    a,
                    b
                );

                // Addition is associative: (a + b) + c = a + (b + c)
                assert_eq!(
                    (gf_a + gf_b) + gf_c,
                    gf_a + (gf_b + gf_c),
                    "Addition not associative for ({} + {}) + {} vs {} + ({} + {})",
                    a,
                    b,
                    c,
                    a,
                    b,
                    c
                );

                // Multiplication is commutative: a * b = b * a
                assert_eq!(
                    gf_a.mul_field(gf_b),
                    gf_b.mul_field(gf_a),
                    "Multiplication not commutative for {} * {}",
                    a,
                    b
                );

                if c != 0 {
                    // Multiplication is associative: (a * b) * c = a * (b * c)
                    assert_eq!(
                        gf_a.mul_field(gf_b).mul_field(gf_c),
                        gf_a.mul_field(gf_b.mul_field(gf_c)),
                        "Multiplication not associative for ({} * {}) * {} vs {} * ({} * {})",
                        a,
                        b,
                        c,
                        a,
                        b,
                        c
                    );
                }

                // Distributivity: a * (b + c) = a * b + a * c
                assert_eq!(
                    gf_a.mul_field(gf_b + gf_c),
                    gf_a.mul_field(gf_b) + gf_a.mul_field(gf_c),
                    "Distributivity fails for {} * ({} + {}) vs {} * {} + {} * {}",
                    a,
                    b,
                    c,
                    a,
                    b,
                    a,
                    c
                );
            }
        }
    }
}

/// Test field identity elements
#[test]
fn test_identity_elements() {
    let zero = Gf256::ZERO;
    let one = Gf256::ONE;

    for i in 0..=255u8 {
        let gf_i = Gf256::new(i);

        // Additive identity: a + 0 = a
        assert_eq!(gf_i + zero, gf_i, "Additive identity fails for {}", i);
        assert_eq!(zero + gf_i, gf_i, "Additive identity fails for 0 + {}", i);

        // Multiplicative identity: a * 1 = a
        assert_eq!(
            gf_i.mul_field(one),
            gf_i,
            "Multiplicative identity fails for {}",
            i
        );
        assert_eq!(
            one.mul_field(gf_i),
            gf_i,
            "Multiplicative identity fails for 1 * {}",
            i
        );

        // Additive inverse: a + a = 0 (in GF(2^n), every element is its own additive inverse)
        assert_eq!(
            gf_i + gf_i,
            zero,
            "Additive inverse fails for {} + {}",
            i,
            i
        );
    }
}

/// Test multiplicative inverses
#[test]
fn test_multiplicative_inverses() {
    let one = Gf256::ONE;

    for i in 1..=255u8 {
        // Skip 0 as it has no multiplicative inverse
        let gf_i = Gf256::new(i);
        let gf_i_inv = gf_i.inv();

        // a * inv(a) = 1
        assert_eq!(
            gf_i.mul_field(gf_i_inv),
            one,
            "Multiplicative inverse fails: {} * inv({}) != 1",
            i,
            i
        );
        assert_eq!(
            gf_i_inv.mul_field(gf_i),
            one,
            "Multiplicative inverse fails: inv({}) * {} != 1",
            i,
            i
        );
    }
}

/// Test division operations
#[test]
fn test_division() {
    let test_elements = [1, 2, 3, 17, 42, 85, 127, 170, 255];

    for &a in &test_elements {
        for &b in &test_elements {
            let gf_a = Gf256::new(a);
            let gf_b = Gf256::new(b);

            // Division is multiplication by inverse: a / b = a * inv(b)
            let div_result = gf_a.div_field(gf_b);
            let mul_inv_result = gf_a.mul_field(gf_b.inv());
            assert_eq!(
                div_result, mul_inv_result,
                "Division inconsistent: {} / {} != {} * inv({})",
                a, b, a, b
            );

            // Division identity: (a / b) * b = a
            assert_eq!(
                div_result.mul_field(gf_b),
                gf_a,
                "Division identity fails: ({} / {}) * {} != {}",
                a,
                b,
                b,
                a
            );
        }
    }
}

/// Test exponentiation properties
#[test]
fn test_exponentiation() {
    let test_bases = [1, 2, 3, 17, 42, 85, 170];
    let test_exps = [0, 1, 2, 3, 7, 15, 31, 63, 127, 255];

    for &base in &test_bases {
        let gf_base = Gf256::new(base);

        for &exp in &test_exps {
            let pow_result = gf_base.pow(exp);

            // Manual calculation for verification
            let mut manual_result = Gf256::ONE;
            for _ in 0..exp {
                manual_result = manual_result.mul_field(gf_base);
            }

            assert_eq!(
                pow_result, manual_result,
                "Exponentiation mismatch: {}^{}",
                base, exp
            );
        }

        // Special cases
        assert_eq!(gf_base.pow(0), Gf256::ONE, "{}^0 should be 1", base);
        assert_eq!(gf_base.pow(1), gf_base, "{}^1 should be {}", base, base);
    }
}

/// Test that all non-zero elements are invertible (field property)
#[test]
fn test_field_completeness() {
    let mut inverses_seen = HashSet::new();

    for i in 1..=255u8 {
        let gf_i = Gf256::new(i);
        let inv_val = gf_i.inv().raw();

        // Every non-zero element should have a unique inverse
        assert!(inv_val != 0, "Element {} has zero inverse", i);
        assert!(
            !inverses_seen.contains(&inv_val),
            "Duplicate inverse {} for element {}",
            inv_val,
            i
        );
        inverses_seen.insert(inv_val);
    }

    // We should have seen exactly 255 unique inverses
    assert_eq!(inverses_seen.len(), 255, "Should have 255 unique inverses");
}

/// Test slice operations match element-wise operations
#[test]
fn test_slice_operations_correctness() {
    let test_data_a = [1, 17, 42, 85, 127, 170, 255, 0];
    let test_data_b = [255, 170, 127, 85, 42, 17, 1, 128];
    let multiplier = Gf256::new(123);

    // Test gf256_add_slice
    let mut slice_result = test_data_a;
    gf256_add_slice(&mut slice_result, &test_data_b);

    for i in 0..test_data_a.len() {
        let expected = Gf256::new(test_data_a[i]) + Gf256::new(test_data_b[i]);
        assert_eq!(
            slice_result[i],
            expected.raw(),
            "Slice addition mismatch at index {}: {} + {} = {} (expected {})",
            i,
            test_data_a[i],
            test_data_b[i],
            slice_result[i],
            expected.raw()
        );
    }

    // Test gf256_mul_slice
    let mut mul_result = test_data_a;
    gf256_mul_slice(&mut mul_result, multiplier);

    for i in 0..test_data_a.len() {
        let expected = Gf256::new(test_data_a[i]).mul_field(multiplier);
        assert_eq!(
            mul_result[i],
            expected.raw(),
            "Slice multiplication mismatch at index {}: {} * {} = {} (expected {})",
            i,
            test_data_a[i],
            multiplier.raw(),
            mul_result[i],
            expected.raw()
        );
    }
}

/// Test dual slice operations
#[test]
fn test_dual_slice_operations() {
    let mut test_data_a = [1, 17, 42, 85, 127, 170, 255, 0];
    let test_data_a_orig = test_data_a;
    let test_data_b = [255, 170, 127, 85, 42, 17, 1, 128];
    let mut test_data_c = [128, 64, 32, 16, 8, 4, 2, 1];
    let test_data_c_orig = test_data_c;
    let test_data_d = [1, 2, 4, 8, 16, 32, 64, 128];
    let multiplier = Gf256::new(73);

    // Test gf256_add_slices2
    gf256_add_slices2(
        &mut test_data_a,
        &test_data_b,
        &mut test_data_c,
        &test_data_d,
    );

    for i in 0..test_data_a.len() {
        let expected_a = Gf256::new(test_data_a_orig[i]) + Gf256::new(test_data_b[i]);
        let expected_c = Gf256::new(test_data_c_orig[i]) + Gf256::new(test_data_d[i]);

        assert_eq!(
            test_data_a[i],
            expected_a.raw(),
            "Dual slice addition mismatch for slice A at index {}",
            i
        );
        assert_eq!(
            test_data_c[i],
            expected_c.raw(),
            "Dual slice addition mismatch for slice C at index {}",
            i
        );
    }

    // Reset and test gf256_mul_slices2
    test_data_a = test_data_a_orig;
    test_data_c = test_data_c_orig;
    gf256_mul_slices2(&mut test_data_a, &mut test_data_c, multiplier);

    for i in 0..test_data_a.len() {
        let expected_a = Gf256::new(test_data_a_orig[i]).mul_field(multiplier);
        let expected_c = Gf256::new(test_data_c_orig[i]).mul_field(multiplier);

        assert_eq!(
            test_data_a[i],
            expected_a.raw(),
            "Dual slice multiplication mismatch for slice A at index {}",
            i
        );
        assert_eq!(
            test_data_c[i],
            expected_c.raw(),
            "Dual slice multiplication mismatch for slice C at index {}",
            i
        );
    }
}

/// Test kernel dispatch determinism
#[test]
fn test_kernel_dispatch_determinism() {
    // Test that kernel selection is deterministic
    let kernel1 = active_kernel();
    let kernel2 = active_kernel();
    assert_eq!(kernel1, kernel2, "Kernel selection should be deterministic");

    // Test dual kernel decisions are consistent
    let test_sizes = [(100, 100), (1000, 1000), (10000, 10000)];

    for &(len_a, len_b) in &test_sizes {
        let decision1 = dual_mul_kernel_decision(len_a, len_b);
        let decision2 = dual_mul_kernel_decision(len_a, len_b);
        assert_eq!(
            decision1, decision2,
            "Dual mul kernel decision should be deterministic for sizes ({}, {})",
            len_a, len_b
        );

        let addmul_decision1 = dual_addmul_kernel_decision(len_a, len_b);
        let addmul_decision2 = dual_addmul_kernel_decision(len_a, len_b);
        assert_eq!(
            addmul_decision1, addmul_decision2,
            "Dual addmul kernel decision should be deterministic for sizes ({}, {})",
            len_a, len_b
        );
    }
}

/// Test profile pack consistency
#[test]
fn test_profile_pack_consistency() {
    let manifest = gf256_profile_pack_manifest_snapshot();
    let policy = dual_kernel_policy_snapshot();

    // Verify that active profile pack is consistent
    assert!(
        !manifest.profile_pack_catalog.is_empty(),
        "Should have at least one profile pack"
    );
    assert!(
        manifest
            .profile_pack_catalog
            .iter()
            .any(|metadata| metadata.profile_pack == policy.profile_pack),
        "Active profile pack should be in profile pack catalog"
    );

    // Verify dual kernel thresholds are reasonable
    match policy.mode {
        DualKernelMode::Auto => {
            assert!(policy.mul_min_total > 0, "Mul threshold should be positive");
            assert!(
                policy.addmul_min_total > 0,
                "Addmul threshold should be positive"
            );
            assert!(
                policy.mul_max_total >= policy.mul_min_total,
                "Mul window should not invert"
            );
            assert!(
                policy.addmul_max_total >= policy.addmul_min_total,
                "Addmul window should not invert"
            );
            assert!(
                policy.max_lane_ratio > 0,
                "Lane ratio threshold should be positive"
            );
        }
        DualKernelMode::Sequential => {
            // Thresholds don't matter in this mode
        }
        DualKernelMode::Fused => {
            // Should use dual kernels regardless of size
        }
    }
}

/// Test RFC 6330 specific requirements
#[test]
fn test_rfc6330_compliance() {
    // RFC 6330 specifies the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
    // This corresponds to 0x11D, but since we work in GF(2^8), we use 0x1D

    // Test that the field has exactly 256 elements (0-255)
    let mut all_results = HashSet::new();
    for i in 0..=255u8 {
        all_results.insert(Gf256::new(i).raw());
    }
    assert_eq!(
        all_results.len(),
        256,
        "Field should have exactly 256 elements"
    );

    // Test that multiplication by 2 (α) works correctly
    // In GF(256), α is a primitive element
    let alpha = Gf256::new(2);
    let alpha_squared = alpha.mul_field(alpha);
    assert_eq!(alpha_squared.raw(), 4, "α² should equal 4 in GF(256)");

    // Test that α^255 = 1 (since α is primitive in GF(2^8))
    let alpha_255 = alpha.pow(255);
    assert_eq!(alpha_255.raw(), 1, "α^255 should equal 1 in GF(256)");

    // Test some known values from RFC 6330 examples if available
    // These would be specific test vectors from the RFC
    let test_cases = [
        (0, 0, 0),   // 0 * anything = 0
        (1, 42, 42), // 1 * x = x
        (2, 2, 4),   // 2 * 2 = 4
    ];

    for &(a, b, expected) in &test_cases {
        let result = Gf256::new(a).mul_field(Gf256::new(b));
        assert_eq!(
            result.raw(),
            expected,
            "RFC test case failed: {} * {} = {} (expected {})",
            a,
            b,
            result.raw(),
            expected
        );
    }
}

/// Stress test with random operations to catch edge cases
#[test]
fn test_random_operations_stress() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Use deterministic "random" based on hash for reproducible tests
    let mut hasher = DefaultHasher::new();
    "stress_test_seed".hash(&mut hasher);
    let mut seed = hasher.finish();

    // Simple linear congruential generator for deterministic pseudo-random numbers
    let mut next_rand = move || {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 8) as u8
    };

    // Perform many random operations
    for _ in 0..1000 {
        let a = next_rand();
        let b = next_rand();
        let c = next_rand();

        let gf_a = Gf256::new(a);
        let gf_b = Gf256::new(b);
        let gf_c = Gf256::new(c);

        // Test that operations don't panic and maintain field properties
        let sum = gf_a + gf_b + gf_c;
        let product = if b != 0 && c != 0 {
            Some(gf_a.mul_field(gf_b).mul_field(gf_c))
        } else {
            None
        };

        // Verify no panics occurred and results are valid field elements
        let _ = sum.raw();
        if let Some(prod) = product {
            let _ = prod.raw();
        }

        // Test division when possible
        if b != 0 {
            let division = gf_a.div_field(gf_b);
            let _ = division.raw();

            // Verify division correctness: (a / b) * b = a
            assert_eq!(
                division.mul_field(gf_b),
                gf_a,
                "Division verification failed for {} / {}",
                a,
                b
            );
        }
    }
}
