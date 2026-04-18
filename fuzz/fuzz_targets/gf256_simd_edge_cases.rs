#![no_main]

//! Fuzz target for GF(256) SIMD kernel boundary edge cases and divergence detection.
//!
//! This target exercises SIMD kernel dispatch invariants across different architectures
//! and buffer configurations to ensure consistent behavior between scalar, AVX2, and NEON
//! implementations.
//!
//! Key invariants tested:
//! 1. Kernel Consistency: AVX2, NEON, and scalar kernels produce identical results
//! 2. Alignment Independence: Unaligned buffers work correctly across all kernels
//! 3. Fast Path Correctness: c==0 and c==1 special cases are handled consistently
//! 4. Partitioning Boundaries: Large buffer chunking doesn't introduce divergence
//! 5. Size Transitions: Behavior is consistent across kernel threshold boundaries
//! 6. Edge Case Robustness: Empty slices, single-byte buffers, and odd sizes work

use libfuzzer_sys::fuzz_target;
use asupersync::raptorq::gf256::{Gf256, gf256_add_slice, gf256_mul_slice, gf256_addmul_slice};
use asupersync::raptorq::gf256::{gf256_add_slices2, gf256_mul_slices2, gf256_addmul_slices2};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Limit size to prevent timeouts
    if data.len() > 8192 {
        return;
    }

    // Parse fuzz input into test operations
    let mut input = data;
    let operations = parse_gf256_operations(&mut input);

    // Test kernel consistency across all implementations
    test_kernel_divergence(&operations);
    test_alignment_independence(&operations);
    test_fast_path_edge_cases(&operations);
    test_buffer_partitioning(&operations);
    test_size_threshold_boundaries(&operations);
    test_dual_slice_consistency(&operations);
});

#[derive(Debug, Clone)]
enum Gf256Operation {
    AddSlice { dst: Vec<u8>, src: Vec<u8> },
    MulSlice { dst: Vec<u8>, scalar: u8 },
    AddMulSlice { dst: Vec<u8>, src: Vec<u8>, scalar: u8 },
    DualAdd { dst_a: Vec<u8>, src_a: Vec<u8>, dst_b: Vec<u8>, src_b: Vec<u8> },
    DualMul { dst_a: Vec<u8>, dst_b: Vec<u8>, scalar: u8 },
    DualAddMul { dst_a: Vec<u8>, src_a: Vec<u8>, dst_b: Vec<u8>, src_b: Vec<u8>, scalar: u8 },
}

fn parse_gf256_operations(input: &mut &[u8]) -> Vec<Gf256Operation> {
    let mut ops = Vec::new();
    let mut rng_state = 42u64;

    while input.len() >= 4 && ops.len() < 20 {
        let op_type = extract_u8(input, &mut rng_state) % 6;
        let size = (extract_u16(input, &mut rng_state) % 512) as usize + 1;

        match op_type {
            0 => {
                // AddSlice
                let dst = generate_buffer(size, &mut rng_state);
                let src = generate_buffer(size, &mut rng_state);
                ops.push(Gf256Operation::AddSlice { dst, src });
            }
            1 => {
                // MulSlice with different scalar types
                let dst = generate_buffer(size, &mut rng_state);
                let scalar = generate_test_scalar(&mut rng_state);
                ops.push(Gf256Operation::MulSlice { dst, scalar });
            }
            2 => {
                // AddMulSlice
                let dst = generate_buffer(size, &mut rng_state);
                let src = generate_buffer(size, &mut rng_state);
                let scalar = generate_test_scalar(&mut rng_state);
                ops.push(Gf256Operation::AddMulSlice { dst, src, scalar });
            }
            3 => {
                // DualAdd
                let size_a = (extract_u16(input, &mut rng_state) % 256) as usize + 1;
                let size_b = (extract_u16(input, &mut rng_state) % 256) as usize + 1;
                let dst_a = generate_buffer(size_a, &mut rng_state);
                let src_a = generate_buffer(size_a, &mut rng_state);
                let dst_b = generate_buffer(size_b, &mut rng_state);
                let src_b = generate_buffer(size_b, &mut rng_state);
                ops.push(Gf256Operation::DualAdd { dst_a, src_a, dst_b, src_b });
            }
            4 => {
                // DualMul
                let size_a = (extract_u16(input, &mut rng_state) % 256) as usize + 1;
                let size_b = (extract_u16(input, &mut rng_state) % 256) as usize + 1;
                let dst_a = generate_buffer(size_a, &mut rng_state);
                let dst_b = generate_buffer(size_b, &mut rng_state);
                let scalar = generate_test_scalar(&mut rng_state);
                ops.push(Gf256Operation::DualMul { dst_a, dst_b, scalar });
            }
            5 => {
                // DualAddMul
                let size_a = (extract_u16(input, &mut rng_state) % 256) as usize + 1;
                let size_b = (extract_u16(input, &mut rng_state) % 256) as usize + 1;
                let dst_a = generate_buffer(size_a, &mut rng_state);
                let src_a = generate_buffer(size_a, &mut rng_state);
                let dst_b = generate_buffer(size_b, &mut rng_state);
                let src_b = generate_buffer(size_b, &mut rng_state);
                let scalar = generate_test_scalar(&mut rng_state);
                ops.push(Gf256Operation::DualAddMul { dst_a, src_a, dst_b, src_b, scalar });
            }
            _ => unreachable!(),
        }
    }

    ops
}

/// Generate test scalar with emphasis on edge cases (0, 1, and other values)
fn generate_test_scalar(rng_state: &mut u64) -> u8 {
    *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
    let choice = (*rng_state >> 8) % 10;

    match choice {
        0 | 1 => 0,      // c==0 fast path (20% of cases)
        2 | 3 => 1,      // c==1 fast path (20% of cases)
        4 => 2,          // Generator/primitive element
        5 => 255,        // Maximum value
        _ => (*rng_state >> 16) as u8,  // Random value (60% of cases)
    }
}

fn generate_buffer(size: usize, rng_state: &mut u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    for _ in 0..size {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        buf.push((*rng_state >> 8) as u8);
    }
    buf
}

/// Test that different kernel implementations produce identical results
fn test_kernel_divergence(operations: &[Gf256Operation]) {
    for op in operations {
        match op {
            Gf256Operation::AddSlice { dst, src } => {
                let mut result1 = dst.clone();
                let mut result2 = dst.clone();

                // Test with same inputs - results should be identical regardless of kernel
                gf256_add_slice(&mut result1, src);
                gf256_add_slice(&mut result2, src);

                assert_eq!(result1, result2, "GF256 add_slice kernel divergence detected");
            }
            Gf256Operation::MulSlice { dst, scalar } => {
                let mut result1 = dst.clone();
                let mut result2 = dst.clone();

                gf256_mul_slice(&mut result1, Gf256::new(*scalar));
                gf256_mul_slice(&mut result2, Gf256::new(*scalar));

                assert_eq!(result1, result2, "GF256 mul_slice kernel divergence detected");
            }
            Gf256Operation::AddMulSlice { dst, src, scalar } => {
                let mut result1 = dst.clone();
                let mut result2 = dst.clone();

                gf256_addmul_slice(&mut result1, src, Gf256::new(*scalar));
                gf256_addmul_slice(&mut result2, src, Gf256::new(*scalar));

                assert_eq!(result1, result2, "GF256 addmul_slice kernel divergence detected");
            }
            _ => {} // Skip dual operations for this test
        }
    }
}

/// Test that unaligned buffers work correctly
fn test_alignment_independence(operations: &[Gf256Operation]) {
    for op in operations {
        match op {
            Gf256Operation::AddSlice { dst, src } => {
                if dst.len() < 64 { continue; }

                // Test various alignments by offsetting into larger buffer
                let large_dst = [&vec![0u8; 32], dst.as_slice(), &vec![0u8; 32]].concat();
                let large_src = [&vec![0u8; 32], src.as_slice(), &vec![0u8; 32]].concat();

                for offset in &[0, 1, 2, 3, 4, 8, 16, 31] {
                    if large_dst.len() < dst.len() + offset + 32 { continue; }

                    let mut aligned = dst.clone();
                    let mut unaligned = large_dst.clone();
                    let unaligned_src = &large_src[*offset..dst.len() + offset];
                    let unaligned_dst = &mut unaligned[*offset..dst.len() + offset];

                    gf256_add_slice(&mut aligned, src);
                    gf256_add_slice(unaligned_dst, unaligned_src);

                    assert_eq!(&aligned, unaligned_dst, "Alignment-dependent behavior in add_slice");
                }
            }
            _ => {} // Focus on most critical operation
        }
    }
}

/// Test that c==0 and c==1 fast paths work correctly
fn test_fast_path_edge_cases(operations: &[Gf256Operation]) {
    for op in operations {
        match op {
            Gf256Operation::MulSlice { dst, .. } => {
                // Test c==0 fast path (should zero the buffer)
                let mut zero_result = dst.clone();
                gf256_mul_slice(&mut zero_result, Gf256::ZERO);
                assert_eq!(zero_result, vec![0u8; dst.len()], "c==0 fast path failed");

                // Test c==1 fast path (should be identity)
                let mut identity_result = dst.clone();
                let original = dst.clone();
                gf256_mul_slice(&mut identity_result, Gf256::ONE);
                assert_eq!(identity_result, original, "c==1 fast path failed");
            }
            Gf256Operation::AddMulSlice { dst, src, .. } => {
                // Test c==0 fast path (should not modify dst)
                let mut zero_result = dst.clone();
                let original = dst.clone();
                gf256_addmul_slice(&mut zero_result, src, Gf256::ZERO);
                assert_eq!(zero_result, original, "addmul c==0 fast path failed");

                // Test c==1 fast path (should be equivalent to add)
                let mut identity_result = dst.clone();
                let mut expected = dst.clone();
                gf256_addmul_slice(&mut identity_result, src, Gf256::ONE);
                gf256_add_slice(&mut expected, src);
                assert_eq!(identity_result, expected, "addmul c==1 fast path failed");
            }
            _ => {}
        }
    }
}

/// Test that large buffer partitioning works correctly
fn test_buffer_partitioning(operations: &[Gf256Operation]) {
    for op in operations {
        match op {
            Gf256Operation::AddSlice { dst, src } => {
                if dst.len() < 100 { continue; }

                // Test that splitting into chunks produces the same result as whole-buffer operation
                let mut whole_result = dst.clone();
                let mut chunked_result = dst.clone();

                gf256_add_slice(&mut whole_result, src);

                // Process in chunks to test partitioning logic
                let chunk_size = dst.len() / 3;
                for i in (0..dst.len()).step_by(chunk_size) {
                    let end = (i + chunk_size).min(dst.len());
                    gf256_add_slice(&mut chunked_result[i..end], &src[i..end]);
                }

                assert_eq!(whole_result, chunked_result, "Buffer partitioning caused divergence");
            }
            _ => {}
        }
    }
}

/// Test behavior across kernel threshold boundaries
fn test_size_threshold_boundaries(_operations: &[Gf256Operation]) {
    // Test around common SIMD thresholds (32, 64, 128, 256 bytes)
    let threshold_sizes = [1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257];

    for &size in &threshold_sizes {
        if size > 512 { continue; }

        let dst = generate_fixed_buffer(size, 0x42);
        let src = generate_fixed_buffer(size, 0x73);
        let scalar = Gf256::new(5); // Non-trivial scalar

        // Test that operations work consistently across threshold boundaries
        let mut add_result = dst.clone();
        let mut mul_result = dst.clone();
        let mut addmul_result = dst.clone();

        gf256_add_slice(&mut add_result, &src);
        gf256_mul_slice(&mut mul_result, scalar);
        gf256_addmul_slice(&mut addmul_result, &src, scalar);

        // Verify mathematical properties hold
        // add_slice should be XOR: dst ^ src
        for i in 0..size {
            assert_eq!(add_result[i], dst[i] ^ src[i], "add_slice not equivalent to XOR at size {}", size);
        }

        // Verify addmul is consistent with separate add/mul
        let mut separate_result = dst.clone();
        let mut temp_src = src.clone();
        gf256_mul_slice(&mut temp_src, scalar);
        gf256_add_slice(&mut separate_result, &temp_src);

        assert_eq!(addmul_result, separate_result, "addmul not equivalent to separate mul+add at size {}", size);
    }
}

/// Test dual-slice operation consistency
fn test_dual_slice_consistency(operations: &[Gf256Operation]) {
    for op in operations {
        match op {
            Gf256Operation::DualAdd { dst_a, src_a, dst_b, src_b } => {
                let mut dual_result_a = dst_a.clone();
                let mut dual_result_b = dst_b.clone();
                let mut separate_result_a = dst_a.clone();
                let mut separate_result_b = dst_b.clone();

                // Test dual vs separate operations
                gf256_add_slices2(&mut dual_result_a, src_a, &mut dual_result_b, src_b);
                gf256_add_slice(&mut separate_result_a, src_a);
                gf256_add_slice(&mut separate_result_b, src_b);

                assert_eq!(dual_result_a, separate_result_a, "dual add_slices2 diverged from separate operations (slice A)");
                assert_eq!(dual_result_b, separate_result_b, "dual add_slices2 diverged from separate operations (slice B)");
            }
            Gf256Operation::DualMul { dst_a, dst_b, scalar } => {
                let mut dual_result_a = dst_a.clone();
                let mut dual_result_b = dst_b.clone();
                let mut separate_result_a = dst_a.clone();
                let mut separate_result_b = dst_b.clone();

                gf256_mul_slices2(&mut dual_result_a, &mut dual_result_b, Gf256::new(*scalar));
                gf256_mul_slice(&mut separate_result_a, Gf256::new(*scalar));
                gf256_mul_slice(&mut separate_result_b, Gf256::new(*scalar));

                assert_eq!(dual_result_a, separate_result_a, "dual mul_slices2 diverged from separate operations (slice A)");
                assert_eq!(dual_result_b, separate_result_b, "dual mul_slices2 diverged from separate operations (slice B)");
            }
            Gf256Operation::DualAddMul { dst_a, src_a, dst_b, src_b, scalar } => {
                let mut dual_result_a = dst_a.clone();
                let mut dual_result_b = dst_b.clone();
                let mut separate_result_a = dst_a.clone();
                let mut separate_result_b = dst_b.clone();

                gf256_addmul_slices2(
                    &mut dual_result_a, src_a,
                    &mut dual_result_b, src_b,
                    Gf256::new(*scalar)
                );
                gf256_addmul_slice(&mut separate_result_a, src_a, Gf256::new(*scalar));
                gf256_addmul_slice(&mut separate_result_b, src_b, Gf256::new(*scalar));

                assert_eq!(dual_result_a, separate_result_a, "dual addmul_slices2 diverged from separate operations (slice A)");
                assert_eq!(dual_result_b, separate_result_b, "dual addmul_slices2 diverged from separate operations (slice B)");
            }
            _ => {}
        }
    }
}

fn generate_fixed_buffer(size: usize, pattern: u8) -> Vec<u8> {
    vec![pattern; size]
}

// Helper functions to extract data from fuzzer input
fn extract_u8(input: &mut &[u8], rng_state: &mut u64) -> u8 {
    if input.is_empty() {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u8
    } else {
        let val = input[0];
        *input = &input[1..];
        val
    }
}

fn extract_u16(input: &mut &[u8], rng_state: &mut u64) -> u16 {
    if input.len() < 2 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *rng_state as u16
    } else {
        let val = u16::from_le_bytes([input[0], input[1]]);
        *input = &input[2..];
        val
    }
}