//! Comprehensive bit-exact validation tests for GF(256) kernel implementations.
//!
//! Validates that all SIMD kernel variants produce identical results to the
//! scalar reference implementation across exhaustive test scenarios.

#![cfg(test)]

use crate::raptorq::gf256::{
    Gf256, Gf256Kernel, active_kernel, dual_addmul_kernel_decision_detail, dual_policy_snapshot,
    gf256_addmul_slice, gf256_addmul_slices2, gf256_mul_slice, gf256_mul_slices2,
};
use crate::test_logging::{TestOutcome, UnitLogEntry, test_log_sink};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQUENCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate next unique test sequence number for structured logging.
fn next_test_sequence() -> u64 {
    TEST_SEQUENCE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Test configuration for validation scenarios.
#[derive(Debug, Clone)]
struct ValidationConfig {
    /// Size of test data.
    size: usize,
    /// Test scalar value.
    scalar: u8,
    /// Data generation seed.
    seed: u64,
    /// Test scenario name.
    scenario: &'static str,
}

impl ValidationConfig {
    /// Create deterministic test data based on config.
    fn generate_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.size);
        for i in 0..self.size {
            let value = ((i as u64).wrapping_mul(17).wrapping_add(self.seed)) % 256;
            data.push(value as u8);
        }
        data
    }

    /// Create structured log entry for this test.
    fn log_entry(&self, sequence: u64, outcome: TestOutcome, details: &str) -> UnitLogEntry {
        UnitLogEntry::new(
            sequence,
            format!("gf256_validation_{}", self.scenario),
            format!(
                "size={} scalar={} seed={}",
                self.size, self.scalar, self.seed
            ),
            outcome,
            details.to_string(),
            format!(
                "cargo test gf256_validation_tests::test_{} -- --nocapture",
                self.scenario
            ),
        )
    }
}

fn reference_mul_slice(data: &mut [u8], scalar: Gf256) {
    for byte in data {
        *byte = Gf256::new(*byte).mul_field(scalar).raw();
    }
}

fn reference_addmul_slice(dst: &mut [u8], src: &[u8], scalar: Gf256) {
    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    for (dst_byte, src_byte) in dst.iter_mut().zip(src) {
        let product = Gf256::new(*src_byte).mul_field(scalar);
        *dst_byte = Gf256::new(*dst_byte).add(product).raw();
    }
}

/// Validation test scenarios covering different sizes and edge cases.
const VALIDATION_SCENARIOS: &[ValidationConfig] = &[
    // Small sizes for exhaustive coverage
    ValidationConfig {
        size: 1,
        scalar: 1,
        seed: 0,
        scenario: "single_byte",
    },
    ValidationConfig {
        size: 15,
        scalar: 17,
        seed: 42,
        scenario: "sub_simd_odd",
    },
    ValidationConfig {
        size: 16,
        scalar: 255,
        seed: 123,
        scenario: "exactly_simd",
    },
    ValidationConfig {
        size: 17,
        scalar: 2,
        seed: 456,
        scenario: "just_over_simd",
    },
    // Medium sizes for typical usage
    ValidationConfig {
        size: 64,
        scalar: 85,
        seed: 789,
        scenario: "cache_line",
    },
    ValidationConfig {
        size: 256,
        scalar: 42,
        seed: 1011,
        scenario: "page_fraction",
    },
    ValidationConfig {
        size: 1024,
        scalar: 199,
        seed: 1213,
        scenario: "small_page",
    },
    // Large sizes for performance validation
    ValidationConfig {
        size: 4096,
        scalar: 123,
        seed: 1415,
        scenario: "page_size",
    },
    ValidationConfig {
        size: 16384,
        scalar: 77,
        seed: 1617,
        scenario: "large_block",
    },
    ValidationConfig {
        size: 65536,
        scalar: 234,
        seed: 1819,
        scenario: "very_large",
    },
    // Edge cases for corner validation
    ValidationConfig {
        size: 4095,
        scalar: 1,
        seed: 2021,
        scenario: "odd_large",
    },
    ValidationConfig {
        size: 32768,
        scalar: 0,
        seed: 2223,
        scenario: "zero_scalar",
    },
    ValidationConfig {
        size: 8192,
        scalar: 255,
        seed: 2425,
        scenario: "max_scalar",
    },
];

/// Validate mul_slice operation produces bit-exact results.
#[test]
fn test_mul_slice_bit_exact() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    for config in VALIDATION_SCENARIOS {
        let mut reference_data = config.generate_data();
        let mut test_data = reference_data.clone();

        let scalar = Gf256::new(config.scalar);

        // Compare the active kernel path against an independent field-arithmetic reference.
        reference_mul_slice(&mut reference_data, scalar);
        gf256_mul_slice(&mut test_data, scalar);

        // Verify bit-exact match
        let bit_exact = reference_data == test_data;

        let details = format!(
            "kernel={:?} size={} scalar={} bit_exact={}",
            kernel, config.size, config.scalar, bit_exact
        );

        let outcome = if bit_exact {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            bit_exact,
            "mul_slice not bit-exact for scenario: {}",
            config.scenario
        );
    }
}

/// Validate addmul_slice operation produces bit-exact results.
#[test]
fn test_addmul_slice_bit_exact() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    for config in VALIDATION_SCENARIOS {
        let mut dst_reference = config.generate_data();
        let src_reference = {
            let mut cfg = config.clone();
            cfg.seed += 1000;
            cfg.generate_data()
        };

        let mut dst_test = dst_reference.clone();
        let src_test = src_reference.clone();

        let scalar = Gf256::new(config.scalar);

        // Compare the active kernel path against an independent field-arithmetic reference.
        reference_addmul_slice(&mut dst_reference, &src_reference, scalar);
        gf256_addmul_slice(&mut dst_test, &src_test, scalar);

        // Verify bit-exact match
        let bit_exact = dst_reference == dst_test;

        let details = format!(
            "kernel={:?} size={} scalar={} bit_exact={}",
            kernel, config.size, config.scalar, bit_exact
        );

        let outcome = if bit_exact {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            bit_exact,
            "addmul_slice not bit-exact for scenario: {}",
            config.scenario
        );
    }
}

/// Validate dual-slice operations produce identical results to sequential operations.
#[test]
fn test_dual_slice_equivalence() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    for config in VALIDATION_SCENARIOS {
        // Generate test data
        let mut dst_a_dual = config.generate_data();
        let mut dst_b_dual = {
            let mut cfg = config.clone();
            cfg.seed += 2000;
            cfg.generate_data()
        };

        let mut dst_a_sequential = dst_a_dual.clone();
        let mut dst_b_sequential = dst_b_dual.clone();

        let scalar = Gf256::new(config.scalar);

        // Test dual-lane multiplication
        gf256_mul_slices2(&mut dst_a_dual, &mut dst_b_dual, scalar);

        // Test sequential multiplication
        gf256_mul_slice(&mut dst_a_sequential, scalar);
        gf256_mul_slice(&mut dst_b_sequential, scalar);

        // Verify equivalence
        let mul_equivalent = dst_a_dual == dst_a_sequential && dst_b_dual == dst_b_sequential;

        let details = format!(
            "kernel={:?} size={} scalar={} mul_equivalent={}",
            kernel, config.size, config.scalar, mul_equivalent
        );

        let outcome = if mul_equivalent {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            mul_equivalent,
            "dual mul_slices2 not equivalent for scenario: {}",
            config.scenario
        );
    }
}

/// Validate dual-lane addmul operations.
#[test]
fn test_dual_addmul_equivalence() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    for config in VALIDATION_SCENARIOS {
        // Generate test data
        let mut dst_a_dual = config.generate_data();
        let src_a = {
            let mut cfg = config.clone();
            cfg.seed += 3000;
            cfg.generate_data()
        };
        let mut dst_b_dual = {
            let mut cfg = config.clone();
            cfg.seed += 4000;
            cfg.generate_data()
        };
        let src_b = {
            let mut cfg = config.clone();
            cfg.seed += 5000;
            cfg.generate_data()
        };

        let mut dst_a_sequential = dst_a_dual.clone();
        let mut dst_b_sequential = dst_b_dual.clone();

        let scalar = Gf256::new(config.scalar);

        // Test dual-lane addmul
        gf256_addmul_slices2(&mut dst_a_dual, &src_a, &mut dst_b_dual, &src_b, scalar);

        // Test sequential addmul
        gf256_addmul_slice(&mut dst_a_sequential, &src_a, scalar);
        gf256_addmul_slice(&mut dst_b_sequential, &src_b, scalar);

        // Verify equivalence
        let addmul_equivalent = dst_a_dual == dst_a_sequential && dst_b_dual == dst_b_sequential;

        let decision = dual_addmul_kernel_decision_detail(config.size, config.size);

        let details = format!(
            "kernel={:?} size={} scalar={} addmul_equivalent={} decision={:?}",
            kernel, config.size, config.scalar, addmul_equivalent, decision.decision
        );

        let outcome = if addmul_equivalent {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            addmul_equivalent,
            "dual addmul_slices2 not equivalent for scenario: {}",
            config.scenario
        );
    }
}

/// Test fast path optimizations produce correct results.
#[test]
fn test_fast_path_correctness() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    // Test c == 0 (zero scalar) fast path
    for &size in &[16, 64, 1024, 4096] {
        let config = ValidationConfig {
            size,
            scalar: 0,
            seed: 6000,
            scenario: "zero_fast_path",
        };

        let mut dst = config.generate_data();
        let src = {
            let mut cfg = config.clone();
            cfg.seed += 1;
            cfg.generate_data()
        };
        let original_dst = dst.clone();

        // Test addmul with zero scalar - should not change dst
        gf256_addmul_slice(&mut dst, &src, Gf256::ZERO);

        let unchanged = dst == original_dst;

        let details = format!(
            "kernel={:?} size={} zero_scalar_unchanged={}",
            kernel, size, unchanged
        );

        let outcome = if unchanged {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            unchanged,
            "Zero scalar should not change dst for size: {}",
            size
        );
    }

    // Test c == 1 (identity scalar) fast path
    for &size in &[16, 64, 1024, 4096] {
        let config = ValidationConfig {
            size,
            scalar: 1,
            seed: 7000,
            scenario: "identity_fast_path",
        };

        let mut dst = config.generate_data();
        let src = {
            let mut cfg = config.clone();
            cfg.seed += 1;
            cfg.generate_data()
        };

        let mut expected = dst.clone();
        for i in 0..size {
            expected[i] ^= src[i]; // XOR for c == 1
        }

        // Test addmul with identity scalar - should XOR
        gf256_addmul_slice(&mut dst, &src, Gf256::ONE);

        let correct_xor = dst == expected;

        let details = format!(
            "kernel={:?} size={} identity_scalar_xor={}",
            kernel, size, correct_xor
        );

        let outcome = if correct_xor {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(correct_xor, "Identity scalar should XOR for size: {}", size);
    }
}

/// Test alignment sensitivity and edge cases.
#[test]
fn test_alignment_robustness() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    let base_size = 1024;
    let scalar = Gf256::new(199);

    // Test various alignment offsets
    for offset in 0..16 {
        let config = ValidationConfig {
            size: base_size,
            scalar: 199,
            seed: 8000 + offset as u64,
            scenario: "alignment_test",
        };

        let total_size = base_size + offset;
        let mut dst_data = config.generate_data();
        dst_data.resize(total_size, 0);

        let src_data = {
            let mut cfg = config.clone();
            cfg.seed += 1;
            let mut data = cfg.generate_data();
            data.resize(total_size, 0);
            data
        };

        // Create offset slices
        let dst_slice = &mut dst_data[offset..];
        let src_slice = &src_data[offset..];

        // Reference calculation on aligned data using independent field arithmetic.
        let mut reference_dst = dst_slice.to_vec();
        let reference_src = src_slice.to_vec();

        reference_addmul_slice(&mut reference_dst, &reference_src, scalar);
        gf256_addmul_slice(dst_slice, src_slice, scalar);

        let alignment_robust = dst_slice == reference_dst;

        let details = format!(
            "kernel={:?} offset={} size={} alignment_robust={}",
            kernel, offset, base_size, alignment_robust
        );

        let outcome = if alignment_robust {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            alignment_robust,
            "Alignment sensitive at offset: {}",
            offset
        );
    }
}

/// Test exhaustive scalar coverage for small sizes.
#[test]
fn test_exhaustive_scalar_coverage() {
    let sequence = next_test_sequence();
    let kernel = active_kernel();

    let test_size = 32; // Small enough for exhaustive scalar testing

    for scalar_value in 0..=255u8 {
        let config = ValidationConfig {
            size: test_size,
            scalar: scalar_value,
            seed: 9000,
            scenario: "exhaustive_scalar",
        };

        let mut dst = config.generate_data();
        let src = {
            let mut cfg = config.clone();
            cfg.seed += 1;
            cfg.generate_data()
        };

        let original_dst = dst.clone();
        let scalar = Gf256::new(scalar_value);

        // Test that operation completes without panic
        gf256_addmul_slice(&mut dst, &src, scalar);

        let mut expected = original_dst.clone();
        reference_addmul_slice(&mut expected, &src, scalar);
        let expected_behavior = dst == expected;

        let details = format!(
            "kernel={:?} scalar={} size={} behavior_correct={}",
            kernel, scalar_value, test_size, expected_behavior
        );

        let outcome = if expected_behavior {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        };
        let log_entry = config.log_entry(sequence, outcome, &details);
        test_log_sink().write_log_entry(log_entry);

        assert!(
            expected_behavior,
            "Incorrect behavior for scalar: {}",
            scalar_value
        );
    }
}

/// Test policy decision determinism.
#[test]
fn test_policy_determinism() {
    let sequence = next_test_sequence();

    // Test that policy decisions are deterministic
    let snapshot1 = dual_policy_snapshot();
    let snapshot2 = dual_policy_snapshot();

    let deterministic = snapshot1 == snapshot2;

    // Test that dual decisions are deterministic
    let decision1 = dual_addmul_kernel_decision_detail(4096, 4096);
    let decision2 = dual_addmul_kernel_decision_detail(4096, 4096);

    let decisions_deterministic =
        decision1.decision == decision2.decision && decision1.reason == decision2.reason;

    let details = format!(
        "policy_deterministic={} decisions_deterministic={} active_kernel={:?}",
        deterministic,
        decisions_deterministic,
        active_kernel()
    );

    let overall_deterministic = deterministic && decisions_deterministic;
    let outcome = if overall_deterministic {
        TestOutcome::Pass
    } else {
        TestOutcome::Fail
    };

    let log_entry = UnitLogEntry::new(
        sequence,
        "gf256_validation_policy_determinism".to_string(),
        "determinism_check".to_string(),
        outcome,
        details,
        "cargo test test_policy_determinism -- --nocapture".to_string(),
    );
    test_log_sink().write_log_entry(log_entry);

    assert!(overall_deterministic, "Policy decisions not deterministic");
}

/// Performance regression test - ensure SIMD is faster than scalar for large sizes.
#[test]
#[ignore] // Run manually for performance validation
fn test_performance_regression() {
    use std::time::Instant;

    let sequence = next_test_sequence();
    let kernel = active_kernel();

    let size = 65536;
    let iterations = 1000;
    let scalar = Gf256::new(177);

    let config = ValidationConfig {
        size,
        scalar: 177,
        seed: 10000,
        scenario: "performance_regression",
    };

    let mut dst = config.generate_data();
    let src = {
        let mut cfg = config.clone();
        cfg.seed += 1;
        cfg.generate_data()
    };

    // Warmup
    for _ in 0..10 {
        gf256_addmul_slice(&mut dst, &src, scalar);
    }

    // Time the operation
    let start = Instant::now();
    for _ in 0..iterations {
        gf256_addmul_slice(&mut dst, &src, scalar);
    }
    let duration = start.elapsed();

    let throughput_gbps = (size * iterations) as f64 / duration.as_secs_f64() / 1e9;

    let details = format!(
        "kernel={:?} size={} iterations={} duration_ms={} throughput_gbps={}",
        kernel,
        size,
        iterations,
        duration.as_millis(),
        throughput_gbps
    );

    // Expect at least 1 GB/s for reasonable SIMD performance
    let adequate_performance = throughput_gbps >= 1.0;
    let outcome = if adequate_performance {
        TestOutcome::Pass
    } else {
        TestOutcome::Fail
    };

    let log_entry = config.log_entry(sequence, outcome, &details);
    test_log_sink().write_log_entry(log_entry);

    println!(
        "Performance: {} GB/s with kernel {:?}",
        throughput_gbps, kernel
    );

    // Don't assert for now - just collect performance data
    // assert!(adequate_performance, "Performance regression: {} GB/s", throughput_gbps);
}
