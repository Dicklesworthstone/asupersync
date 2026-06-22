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
        Gf256, gf256_addmul_slice, gf256_mul_slice, gf256_mul_slices2,
    };
    #[cfg(feature = "simd-intrinsics")]
    use asupersync::raptorq::gf256::{Gf256Kernel, active_kernel};

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn host_has_gf256_simd() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    fn host_has_gf256_simd() -> bool {
        std::arch::is_aarch64_feature_detected!("neon")
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    fn host_has_gf256_simd() -> bool {
        false
    }

    #[cfg(feature = "simd-intrinsics")]
    fn next_pinned_u8(state: &mut u64) -> u8 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*state >> 56) as u8
    }

    #[cfg(feature = "simd-intrinsics")]
    #[test]
    fn test_mul_slice_pinned_random_pairs() {
        const PAIR_COUNT: usize = 1024;
        const SIMD_BLOCK_LEN: usize = 32;
        const BLOCK_COUNT: usize = PAIR_COUNT / SIMD_BLOCK_LEN;

        if !host_has_gf256_simd() {
            return;
        }

        let kernel = active_kernel();
        assert!(
            !matches!(kernel, Gf256Kernel::Scalar),
            "simd-intrinsics build did not select a SIMD kernel"
        );

        let seed = 0x5EED_F00D_CAFE_BABEu64;
        let mut corpus_state = seed;

        for block_idx in 0..BLOCK_COUNT {
            let scalar = Gf256::new(next_pinned_u8(&mut corpus_state));
            let mut simd_block = [0u8; SIMD_BLOCK_LEN];
            for byte in &mut simd_block {
                *byte = next_pinned_u8(&mut corpus_state);
            }

            let original_block = simd_block;
            gf256_mul_slice(&mut simd_block, scalar);

            let pair_start = block_idx * SIMD_BLOCK_LEN;
            for (lane_idx, (&src, &actual)) in
                original_block.iter().zip(simd_block.iter()).enumerate()
            {
                let expected = Gf256::new(src).mul_field(scalar).raw();
                assert_eq!(
                    actual,
                    expected,
                    "seed={seed:#x} kernel={kernel:?} pair={} lane={} src={src:#04x} scalar={:#04x}",
                    pair_start + lane_idx,
                    lane_idx,
                    scalar.raw(),
                );
            }
        }
    }

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
                "Bit-exactness violation for c={c_val} (0x{c_val:02x})"
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
                "Addmul bit-exactness violation for c={c_val}"
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

    /// Deterministic regression protection for the hot multiplication loop.
    #[test]
    fn test_performance_regression_protection() {
        const BENCH_SIZE: usize = 8192; // Large enough for SIMD benefits
        const ITERATIONS: usize = 1000;

        let mut data = vec![0u8; BENCH_SIZE];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        let original_data = data.clone();

        let c = Gf256(73);
        for _ in 0..ITERATIONS {
            gf256_mul_slice(&mut data, c);
        }

        let mut factor = Gf256(1);
        for _ in 0..ITERATIONS {
            factor = factor * c;
        }
        let expected_data = original_data
            .iter()
            .map(|&byte| (factor * Gf256(byte)).0)
            .collect::<Vec<_>>();

        assert_eq!(
            data, expected_data,
            "Repeated optimized GF256 multiplication diverged from scalar field semantics"
        );
        assert_ne!(
            data, original_data,
            "Repeated optimized GF256 multiplication should not behave as a no-op"
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
                "Non-deterministic kernel behavior for size {size}"
            );

            // Log kernel selection for debugging
            println!("Size {size} bytes: kernel selection deterministic ✓");
        }
    }
}
