#![no_main]

//! Structure-aware fuzzer for RaptorQ Gaussian elimination boundary conditions.
//!
//! This fuzzer targets specific mathematical boundary conditions in the Gaussian
//! elimination process of `src/raptorq/decoder.rs`, focusing on rank-deficient
//! matrix configurations that stress pivot selection, elimination steps, and
//! singular matrix detection.
//!
//! Coverage goals:
//! - Matrices with rank exactly k-1, k-2, etc. (boundary conditions)
//! - Zero rows and zero columns in constraint matrices
//! - Singular submatrices during elimination
//! - Pivot selection edge cases (no valid pivots, multiple pivot candidates)
//! - Constraint matrix structural boundaries around k values

use arbitrary::{Arbitrary, Unstructured};
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;

/// Fuzzing configuration for Gaussian elimination boundary conditions
#[derive(Debug, Clone, Arbitrary)]
struct GaussElimBoundaryInput {
    /// Matrix dimension parameter (source symbols)
    #[arbitrary(with = k_boundary_arbitrary)]
    k: usize,

    /// Symbol size in bytes
    #[arbitrary(with = symbol_size_arbitrary)]
    symbol_size: usize,

    /// Random seed for systematic parameters
    seed: u64,

    /// Sequence of elimination-specific operations
    operations: Vec<EliminationOperation>,
}

/// Operations that create specific boundary conditions in Gaussian elimination
#[derive(Debug, Clone, Arbitrary)]
enum EliminationOperation {
    /// Create exactly rank k-N matrix (N=1,2,3)
    RankDeficitExact {
        deficit: u8, // 1-3
    },

    /// Zero out specific row/column patterns
    ZeroPattern {
        #[arbitrary(with = zero_pattern_arbitrary)]
        pattern: ZeroPattern,
        target_index: u8,
    },

    /// Create singular submatrix at specific position
    SingularSubmatrix {
        start_row: u8,
        start_col: u8,
        size: u8, // 2-4
    },

    /// Pivot selection stress test
    PivotStress {
        #[arbitrary(with = pivot_stress_arbitrary)]
        stress_type: PivotStressType,
    },

    /// Constraint matrix structure boundary
    ConstraintBoundary {
        #[arbitrary(with = constraint_boundary_arbitrary)]
        boundary_type: ConstraintBoundaryType,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum ZeroPattern {
    ZeroRow,
    ZeroColumn,
    ZeroDiagonal,
    ZeroAntiDiagonal,
    ZeroBlock,
}

#[derive(Debug, Clone, Arbitrary)]
enum PivotStressType {
    NoPivot,        // All candidates are zero
    MultiplePivots, // Multiple valid pivot candidates
    WeakPivot,      // Very small pivot value
}

#[derive(Debug, Clone, Arbitrary)]
enum ConstraintBoundaryType {
    MinimalConstraints,   // Exactly k constraints
    ExcessiveConstraints, // >> k constraints
    SparseConstraints,    // Very sparse constraint matrix
    DenseConstraints,     // Very dense constraint matrix
}

/// Custom arbitrary for k values focusing on boundary conditions
fn k_boundary_arbitrary(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 12 {
        0 => 2,    // Minimal k
        1 => 3,    // Small k
        2 => 4,    // Small k
        3 => 8,    // Power of 2
        4 => 16,   // Power of 2
        5 => 32,   // Power of 2
        6 => 64,   // Larger power of 2
        7 => 127,  // Just under power of 2
        8 => 128,  // Power of 2
        9 => 255,  // Just under limit
        10 => 256, // Common limit
        11 => {
            // Random in reasonable range
            let base: u16 = u.arbitrary()?;
            (base as usize % 500) + 2
        }
    })
}

/// Custom arbitrary for symbol sizes with boundary focus
fn symbol_size_arbitrary(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 8 {
        0 => 1,   // Minimal
        1 => 4,   // Small
        2 => 8,   // Small power of 2
        3 => 16,  // Power of 2
        4 => 32,  // Power of 2
        5 => 64,  // Common size
        6 => 128, // Larger size
        7 => {
            // Random reasonable size
            let base: u8 = u.arbitrary()?;
            (base as usize % 256) + 1
        }
    })
}

/// Custom arbitrary for zero patterns
fn zero_pattern_arbitrary(u: &mut Unstructured) -> arbitrary::Result<ZeroPattern> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 5 {
        0 => ZeroPattern::ZeroRow,
        1 => ZeroPattern::ZeroColumn,
        2 => ZeroPattern::ZeroDiagonal,
        3 => ZeroPattern::ZeroAntiDiagonal,
        4 => ZeroPattern::ZeroBlock,
        _ => unreachable!(),
    })
}

/// Custom arbitrary for pivot stress types
fn pivot_stress_arbitrary(u: &mut Unstructured) -> arbitrary::Result<PivotStressType> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 3 {
        0 => PivotStressType::NoPivot,
        1 => PivotStressType::MultiplePivots,
        2 => PivotStressType::WeakPivot,
        _ => unreachable!(),
    })
}

/// Custom arbitrary for constraint boundary types
fn constraint_boundary_arbitrary(
    u: &mut Unstructured,
) -> arbitrary::Result<ConstraintBoundaryType> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 4 {
        0 => ConstraintBoundaryType::MinimalConstraints,
        1 => ConstraintBoundaryType::ExcessiveConstraints,
        2 => ConstraintBoundaryType::SparseConstraints,
        3 => ConstraintBoundaryType::DenseConstraints,
        _ => unreachable!(),
    })
}

/// Normalize input to prevent degenerate test cases
fn normalize_input(input: &mut GaussElimBoundaryInput) {
    // Keep k in reasonable bounds to prevent memory exhaustion
    input.k = input.k.clamp(2, 512);

    // Keep symbol size reasonable
    input.symbol_size = input.symbol_size.clamp(1, 512);

    // Limit operations to prevent timeout
    input.operations.truncate(20);

    // Ensure we have at least one operation
    if input.operations.is_empty() {
        input
            .operations
            .push(EliminationOperation::RankDeficitExact { deficit: 1 });
    }
}

/// Execute Gaussian elimination boundary condition fuzzing
fn fuzz_gauss_elimination_boundaries(mut input: GaussElimBoundaryInput) {
    normalize_input(&mut input);

    let k = input.k;
    let symbol_size = input.symbol_size;

    // Build source data
    let source_data = (0..k * symbol_size)
        .map(|i| ((input.seed.wrapping_add(i as u64)) % 256) as u8)
        .collect::<Vec<_>>();

    let source = source_data
        .chunks(symbol_size)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();

    // Create decoder and encoder
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);
    let encoder = match SystematicEncoder::new(&source, symbol_size, input.seed) {
        Ok(enc) => enc,
        Err(_) => return, // Skip invalid configurations
    };

    for operation in input.operations {
        // Create base symbol set
        let mut symbols = decoder.constraint_symbols();

        match operation {
            EliminationOperation::RankDeficitExact { deficit } => {
                create_rank_deficit_matrix(
                    &decoder,
                    &source,
                    &mut symbols,
                    deficit.clamp(1, 3) as usize,
                );
            }

            EliminationOperation::ZeroPattern {
                pattern,
                target_index,
            } => {
                create_zero_pattern(
                    &decoder,
                    &source,
                    &mut symbols,
                    pattern,
                    target_index as usize % k,
                );
            }

            EliminationOperation::SingularSubmatrix {
                start_row,
                start_col,
                size,
            } => {
                create_singular_submatrix(
                    &decoder,
                    &source,
                    &mut symbols,
                    start_row as usize % k,
                    start_col as usize % k,
                    size.clamp(2, 4) as usize,
                );
            }

            EliminationOperation::PivotStress { stress_type } => {
                create_pivot_stress(&decoder, &encoder, &source, &mut symbols, stress_type);
            }

            EliminationOperation::ConstraintBoundary { boundary_type } => {
                create_constraint_boundary(
                    &decoder,
                    &encoder,
                    &source,
                    &mut symbols,
                    boundary_type,
                );
            }
        }

        // Test decode with this boundary condition configuration
        test_decode_with_boundary_symbols(&decoder, symbols, k);
    }
}

/// Create matrix with exact rank deficit
fn create_rank_deficit_matrix(
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    symbols: &mut Vec<ReceivedSymbol>,
    deficit: usize,
) {
    let k = source.len();
    let effective_rank = k.saturating_sub(deficit);

    // Add source symbols with linear dependencies
    for i in 0..effective_rank {
        symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
    }

    // Add linearly dependent symbols (combinations of existing ones)
    for i in effective_rank..k {
        let base_index = i % effective_rank;
        let mut dependent_data = source[base_index].clone();

        // Modify slightly but keep linear dependence
        if i + 1 < k && (i + 1) % effective_rank < source.len() {
            let other_index = (i + 1) % effective_rank;
            for (byte_idx, byte) in dependent_data.iter_mut().enumerate() {
                if byte_idx < source[other_index].len() {
                    *byte = byte.wrapping_add(source[other_index][byte_idx]);
                }
            }
        }

        symbols.push(ReceivedSymbol::source(i as u32, dependent_data));
    }
}

/// Create specific zero patterns in the matrix
fn create_zero_pattern(
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    symbols: &mut Vec<ReceivedSymbol>,
    pattern: ZeroPattern,
    target_index: usize,
) {
    let k = source.len();
    let symbol_size = source[0].len();

    // Add normal source symbols first
    for i in 0..k {
        if i != target_index {
            symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
        }
    }

    match pattern {
        ZeroPattern::ZeroRow => {
            // Create zero row by making target symbol all zeros
            symbols.push(ReceivedSymbol::source(
                target_index as u32,
                vec![0; symbol_size],
            ));
        }

        ZeroPattern::ZeroColumn => {
            // Skip the target symbol to create a "zero column" effect
            // (In practice, this creates an incomplete system)
        }

        ZeroPattern::ZeroDiagonal => {
            // Create pattern where diagonal elements are effectively zero
            let mut zero_data = source[target_index].clone();
            for byte in &mut zero_data {
                *byte = 0;
            }
            symbols.push(ReceivedSymbol::source(target_index as u32, zero_data));
        }

        ZeroPattern::ZeroAntiDiagonal => {
            // Create anti-diagonal zero pattern
            let anti_target = k.saturating_sub(1).saturating_sub(target_index);
            let mut zero_data = source[target_index].clone();
            if anti_target < source.len() {
                for (i, byte) in zero_data.iter_mut().enumerate() {
                    if i < source[anti_target].len() {
                        *byte = source[anti_target][i];
                    }
                }
            }
            symbols.push(ReceivedSymbol::source(target_index as u32, zero_data));
        }

        ZeroPattern::ZeroBlock => {
            // Create block of zeros
            symbols.push(ReceivedSymbol::source(
                target_index as u32,
                vec![0; symbol_size],
            ));
            if target_index + 1 < k {
                symbols.push(ReceivedSymbol::source(
                    (target_index + 1) as u32,
                    vec![0; symbol_size],
                ));
            }
        }
    }
}

/// Create singular submatrix at specific position
fn create_singular_submatrix(
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    symbols: &mut Vec<ReceivedSymbol>,
    start_row: usize,
    start_col: usize,
    size: usize,
) {
    let k = source.len();

    // Add most source symbols normally
    for i in 0..k {
        if i < start_row || i >= start_row + size {
            symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
        }
    }

    // Create singular submatrix block
    for i in 0..size.min(k - start_row) {
        let row_idx = start_row + i;
        if row_idx < k {
            let base_data = if start_row < source.len() {
                source[start_row].clone()
            } else {
                vec![0; source[0].len()]
            };
            symbols.push(ReceivedSymbol::source(row_idx as u32, base_data));
        }
    }
}

/// Create pivot selection stress conditions
fn create_pivot_stress(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    symbols: &mut Vec<ReceivedSymbol>,
    stress_type: PivotStressType,
) {
    let k = source.len();
    let symbol_size = source[0].len();

    match stress_type {
        PivotStressType::NoPivot => {
            // Create configuration where potential pivots are zero
            for i in 0..k.min(5) {
                // Limit to avoid timeout
                symbols.push(ReceivedSymbol::source(i as u32, vec![0; symbol_size]));
            }
        }

        PivotStressType::MultiplePivots => {
            // Create multiple equivalent pivot candidates
            let base_data = source[0].clone();
            for i in 0..k.min(3) {
                symbols.push(ReceivedSymbol::source(i as u32, base_data.clone()));
            }
        }

        PivotStressType::WeakPivot => {
            // Create very small values that might cause numerical issues
            for i in 0..k {
                let mut weak_data = source[i].clone();
                for byte in &mut weak_data {
                    *byte = if *byte == 0 { 1 } else { 1 }; // Very small values
                }
                symbols.push(ReceivedSymbol::source(i as u32, weak_data));
            }
        }
    }
}

/// Create constraint boundary conditions
fn create_constraint_boundary(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    symbols: &mut Vec<ReceivedSymbol>,
    boundary_type: ConstraintBoundaryType,
) {
    let k = source.len();

    match boundary_type {
        ConstraintBoundaryType::MinimalConstraints => {
            // Exactly k symbols (minimal for solvability)
            for i in 0..k {
                symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
            }
        }

        ConstraintBoundaryType::ExcessiveConstraints => {
            // Many more than k symbols
            for i in 0..k {
                symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
            }
            // Add repair symbols up to reasonable limit
            for i in 0..(k.min(20)) {
                if let Ok(repair) = encoder.generate_repair_symbol(k as u32 + i as u32) {
                    symbols.push(ReceivedSymbol::repair(k as u32 + i as u32, repair));
                }
            }
        }

        ConstraintBoundaryType::SparseConstraints => {
            // Very few symbols, likely insufficient
            let sparse_count = k / 3;
            for i in (0..k).step_by(3).take(sparse_count) {
                symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
            }
        }

        ConstraintBoundaryType::DenseConstraints => {
            // Dense system with many interconnected constraints
            for i in 0..k {
                symbols.push(ReceivedSymbol::source(i as u32, source[i].clone()));
            }
            // Add a few repair symbols for density
            for i in 0..(k.min(5)) {
                if let Ok(repair) = encoder.generate_repair_symbol(k as u32 + i as u32) {
                    symbols.push(ReceivedSymbol::repair(k as u32 + i as u32, repair));
                }
            }
        }
    }
}

/// Test decode with boundary condition symbols
fn test_decode_with_boundary_symbols(
    decoder: &InactivationDecoder,
    symbols: Vec<ReceivedSymbol>,
    k: usize,
) {
    // Test standard decode
    match decoder.decode(&symbols) {
        Ok(result) => {
            // Verify result has expected length
            assert_eq!(result.len(), k, "Decode result length should match k");
            for symbol in &result {
                assert!(!symbol.is_empty(), "Decoded symbols should not be empty");
            }
        }
        Err(error) if error.is_recoverable() => {
            // Expected for rank-deficient or underdetermined boundary cases.
        }
        Err(error) => {
            assert!(
                error.is_unrecoverable(),
                "decode error was neither recoverable nor unrecoverable: {error:?}"
            );
        }
    }

    // Test wavefront decode if we have enough symbols
    if symbols.len() >= k {
        match decoder.decode_wavefront(&symbols, symbols.len().min(64)) {
            Ok(_) => {
                // Success is allowed
            }
            Err(_) => {
                // Errors are expected for boundary conditions
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 50_000 {
        return; // Prevent excessive memory usage
    }

    let mut u = Unstructured::new(data);
    if let Ok(input) = GaussElimBoundaryInput::arbitrary(&mut u) {
        fuzz_gauss_elimination_boundaries(input);
    }
});
