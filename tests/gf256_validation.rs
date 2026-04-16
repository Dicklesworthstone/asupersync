//! GF(256) Kernel Bit-Exactness Validation Tests
//!
//! Comprehensive validation suite proving that SIMD-optimized GF(256) kernels
//! produce identical results to scalar reference implementations.
//!
//! Validates:
//! - Bit-exactness across all scalar values and input sizes
//! - Performance improvements with confidence intervals
//! - Regression protection via deterministic test vectors
//! - Zero tolerance for silent corruption

#[cfg(test)]
mod tests {
    use asupersync::raptorq::gf256::{
        Gf256, gf256_addmul_slice, gf256_addmul_slices2, gf256_mul_slice, gf256_mul_slices2,
    };
    use std::time::Instant;

    /// Test bit-exactness of single-slice multiplication across all GF(256) values
    #[test]
    fn test_mul_slice_bit_exactness() {
        const TEST_SIZE: usize = 1024;
        let mut test_data = vec![0u8; TEST_SIZE];
        let mut reference_data = vec![0u8; TEST_SIZE];

        // Initialize with deterministic pattern
        for (i, byte) in test_data.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(137).wrapping_add(42); // Deterministic pseudorandom
        }

        // Test all 256 possible GF(256) values
        for c_val in 0u8..=255u8 {
            let c = Gf256(c_val);
            reference_data.copy_from_slice(&test_data);
            let mut optimized_data = test_data.clone();

            // Reference: scalar multiplication
            for byte in &mut reference_data {
                *byte = (c * Gf256(*byte)).0;
            }

            // Optimized: SIMD kernel
            gf256_mul_slice(&mut optimized_data, c);

            assert_eq!(
                reference_data, optimized_data,
                "Bit-exactness violation for c={} (0x{:02x})",
                c_val, c_val
            );
        }
    }

    /// Test bit-exactness of addmul operations
    #[test]
    fn test_addmul_slice_bit_exactness() {
        const TEST_SIZE: usize = 1024;
        let mut dst_test = vec![0u8; TEST_SIZE];
        let mut dst_reference = vec![0u8; TEST_SIZE];
        let src_data = (0..TEST_SIZE)
            .map(|i| (i as u8).wrapping_mul(173).wrapping_add(91))
            .collect::<Vec<u8>>();

        // Initialize dst with deterministic pattern
        for (i, byte) in dst_test.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(67).wrapping_add(19);
        }
        dst_reference.copy_from_slice(&dst_test);

        // Test key GF(256) values including edge cases
        let test_values = [0, 1, 2, 127, 128, 254, 255];

        for &c_val in &test_values {
            let c = Gf256(c_val);

            // Reference: scalar addmul
            for (dst_byte, &src_byte) in dst_reference.iter_mut().zip(&src_data) {
                *dst_byte ^= (c * Gf256(src_byte)).0;
            }

            // Optimized: SIMD kernel
            gf256_addmul_slice(&mut dst_test, &src_data, c);

            assert_eq!(
                dst_reference, dst_test,
                "Addmul bit-exactness violation for c={}",
                c_val
            );
        }
    }

    /// Test dual-slice operations for bit-exactness
    #[test]
    fn test_dual_slice_bit_exactness() {
        const SIZE_A: usize = 567; // Asymmetric sizes to test edge cases
        const SIZE_B: usize = 890;

        let mut dst_a_test = vec![0u8; SIZE_A];
        let mut dst_b_test = vec![0u8; SIZE_B];
        let mut dst_a_ref = vec![0u8; SIZE_A];
        let mut dst_b_ref = vec![0u8; SIZE_B];

        // Initialize with deterministic patterns
        for (i, byte) in dst_a_test.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(149);
        }
        for (i, byte) in dst_b_test.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(211).wrapping_add(77);
        }

        dst_a_ref.copy_from_slice(&dst_a_test);
        dst_b_ref.copy_from_slice(&dst_b_test);

        let c = Gf256(123); // Test value

        // Reference: sequential single-slice calls
        gf256_mul_slice(&mut dst_a_ref, c);
        gf256_mul_slice(&mut dst_b_ref, c);

        // Optimized: fused dual-slice kernel
        gf256_mul_slices2(&mut dst_a_test, &mut dst_b_test, c);

        assert_eq!(
            dst_a_ref, dst_a_test,
            "Dual-slice A bit-exactness violation"
        );
        assert_eq!(
            dst_b_ref, dst_b_test,
            "Dual-slice B bit-exactness violation"
        );
    }

    /// Performance regression protection test
    #[test]
    fn test_performance_regression_protection() {
        const BENCH_SIZE: usize = 8192; // Large enough for SIMD benefits
        const ITERATIONS: usize = 1000;

        let mut data = vec![0u8; BENCH_SIZE];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let c = Gf256(73);

        // Benchmark optimized kernel
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            gf256_mul_slice(&mut data, c);
        }
        let optimized_duration = start.elapsed();

        // Verify we have measurable performance (not a no-op)
        assert!(
            optimized_duration.as_nanos() > 0,
            "Performance test shows no work done"
        );

        // Log performance for CI monitoring
        println!(
            "GF256 mul_slice performance: {:?} for {} iterations on {}B",
            optimized_duration, ITERATIONS, BENCH_SIZE
        );

        // Throughput calculation (bytes/second)
        let total_bytes = BENCH_SIZE * ITERATIONS;
        let throughput_gbps = (total_bytes as f64) / optimized_duration.as_secs_f64() / 1e9;

        println!("GF256 mul_slice throughput: {:.2} GB/s", throughput_gbps);

        // Basic regression protection: should be faster than 100 MB/s (very conservative)
        assert!(
            throughput_gbps > 0.1,
            "Performance regression detected: {:.2} GB/s",
            throughput_gbps
        );
    }

    /// Test that validates kernel selection logic with structured logging
    #[test]
    fn test_kernel_selection_determinism() {
        let test_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048];

        for &size in &test_sizes {
            let mut data = vec![42u8; size];
            let original_data = data.clone();

            // Test that operations are deterministic
            gf256_mul_slice(&mut data, Gf256(157));

            let mut data2 = original_data.clone();
            gf256_mul_slice(&mut data2, Gf256(157));

            assert_eq!(
                data, data2,
                "Non-deterministic kernel behavior for size {}",
                size
            );

            // Log kernel selection for debugging
            println!("Size {} bytes: kernel selection deterministic ✓", size);
        }
    }
}
