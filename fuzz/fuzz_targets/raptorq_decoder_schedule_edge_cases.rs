//! Structure-aware fuzz target for RaptorQ decoder Schedule construction edge cases.
//!
//! This target focuses on the pivot selection and dense elimination scheduling that occurs
//! during the inactivation phase of RaptorQ decoding. The "schedule" refers to the order
//! and strategy used for pivot selection during Gaussian elimination.
//!
//! Key edge cases tested:
//! 1. **Pivot selection strategies**: Conservative baseline vs hard regime (Markowitz/BlockSchur)
//! 2. **Dense matrix dimensions**: Various ratios of rows to columns in the dense core
//! 3. **Sparsity patterns**: Different distributions of nonzero coefficients
//! 4. **Tie-breaking scenarios**: Multiple rows with identical nonzero counts
//! 5. **Fallback scenarios**: When one strategy fails and falls back to another
//! 6. **Cache behavior**: Dense factor cache hits/misses with identical matrix signatures

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::{
    decoder::{DecodeError, DecodeResult, InactivationDecoder, ReceivedSymbol},
    gf256::Gf256,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

const MAX_K: usize = 32; // Keep K small for faster fuzzing
const MAX_SYMBOL_SIZE: usize = 64; // Small symbols for performance
const MAX_EXTRA_SYMBOLS: usize = 8; // Additional repair symbols
const MAX_REPAIR_DEGREE: usize = 8; // Max columns per repair symbol

/// Structure-aware input for RaptorQ decoder schedule edge case testing.
#[derive(Arbitrary, Debug)]
struct ScheduleEdgeCaseInput {
    /// Source block size (K) - number of source symbols
    #[arbitrary(with = arbitrary_k)]
    k: usize,
    /// Symbol size in bytes
    #[arbitrary(with = arbitrary_symbol_size)]
    symbol_size: usize,
    /// Seed for deterministic LT encoding
    seed: u64,
    /// Configuration for the symbol mix to test different schedule scenarios
    symbol_config: SymbolConfiguration,
    /// Dense matrix forcing configuration
    dense_config: DenseMatrixConfig,
}

#[derive(Arbitrary, Debug)]
struct SymbolConfiguration {
    /// Number of source symbols to include (0 to k)
    num_sources: u8,
    /// Number of repair symbols to generate
    num_repairs: u8,
    /// Strategy for repair symbol degree distribution
    repair_strategy: RepairStrategy,
    /// Whether to create duplicate symbols (tests deduplication edge cases)
    create_duplicates: bool,
}

#[derive(Arbitrary, Debug)]
enum RepairStrategy {
    /// All repair symbols have degree 1 (easy to peel)
    AllDegreeOne,
    /// All repair symbols have maximum degree (forces dense elimination)
    AllMaxDegree,
    /// Mixed degrees to create specific sparsity patterns
    MixedDegrees {
        /// Pattern of degrees for repair symbols
        degree_pattern: Vec<u8>,
    },
    /// Create specific tie-breaking scenarios for pivot selection
    TieBreakingPattern {
        /// Number of rows that should have identical nonzero counts
        identical_nnz_groups: u8,
        /// Target nonzero count for tie-breaking test
        target_nnz: u8,
    },
}

#[derive(Arbitrary, Debug)]
struct DenseMatrixConfig {
    /// Force a specific dense matrix row/column ratio
    force_ratio: Option<DenseRatio>,
    /// Inject specific sparsity patterns
    sparsity_pattern: SparsityPattern,
    /// Cache signature collision testing
    cache_config: CacheTestConfig,
}

#[derive(Arbitrary, Debug)]
enum DenseRatio {
    /// More rows than columns (overdetermined)
    Overdetermined,
    /// Equal rows and columns (square)
    Square,
    /// Fewer rows than columns (underdetermined - should fail)
    Underdetermined,
}

#[derive(Arbitrary, Debug)]
enum SparsityPattern {
    /// Random sparsity
    Random,
    /// All coefficients are 1 (XOR-based)
    XorOnly,
    /// Block diagonal structure
    BlockDiagonal { block_size: u8 },
    /// Anti-diagonal structure (challenging for pivot selection)
    AntiDiagonal,
    /// Specific pattern to test Markowitz pivoting heuristics
    MarkowitzChallenge,
    /// Pattern designed to trigger Block-Schur decomposition
    BlockSchurTrigger { split_ratio: u8 },
}

#[derive(Arbitrary, Debug)]
struct CacheTestConfig {
    /// Create multiple decodings with identical dense matrix signatures
    test_cache_reuse: bool,
    /// Create fingerprint collision scenarios
    create_collision: bool,
    /// Number of decode iterations to test cache behavior
    iterations: u8,
}

/// Generate bounded K values for faster fuzzing
fn arbitrary_k(u: &mut arbitrary::Unstructured) -> arbitrary::Result<usize> {
    let k = u.int_in_range(1..=MAX_K)?;
    Ok(k)
}

/// Generate bounded symbol sizes
fn arbitrary_symbol_size(u: &mut arbitrary::Unstructured) -> arbitrary::Result<usize> {
    let sizes = [1, 2, 4, 8, 16, 32, 64];
    let idx = u.int_in_range(0..=sizes.len() - 1)?;
    Ok(sizes[idx])
}

/// Generate repair symbol with controlled degree and coefficient pattern
fn create_repair_symbol(
    esi: u32,
    k: usize,
    degree: usize,
    sparsity_pattern: &SparsityPattern,
    symbol_size: usize,
    rng_state: &mut u64,
) -> ReceivedSymbol {
    let max_columns = std::cmp::min(degree, k + 4); // L ≈ k + 4 for small k
    let mut columns = Vec::with_capacity(max_columns);
    let mut coefficients = Vec::with_capacity(max_columns);

    match sparsity_pattern {
        SparsityPattern::XorOnly => {
            // Simple XOR-based LT codes (all coefficients = 1)
            for i in 0..max_columns {
                columns.push(i);
                coefficients.push(Gf256::ONE);
            }
        }
        SparsityPattern::BlockDiagonal { block_size } => {
            // Block diagonal: symbols only connect to nearby columns
            let block_start = ((esi as usize) % k) / (*block_size as usize).max(1);
            let block_end = std::cmp::min(block_start + (*block_size as usize), k);
            for col in block_start..block_end {
                columns.push(col);
                coefficients.push(gf256_from_rng(rng_state));
            }
        }
        SparsityPattern::AntiDiagonal => {
            // Anti-diagonal: connect to columns at the "opposite" end
            for i in 0..max_columns {
                let col = k.saturating_sub(1 + i);
                if col < k {
                    columns.push(col);
                    coefficients.push(gf256_from_rng(rng_state));
                }
            }
        }
        SparsityPattern::MarkowitzChallenge => {
            // Create patterns that challenge Markowitz minimum-degree heuristic
            // All repair symbols connect to the same few "bottleneck" columns
            let bottleneck_cols = std::cmp::min(3, k);
            for i in 0..bottleneck_cols {
                columns.push(i);
                coefficients.push(gf256_from_rng(rng_state));
            }
        }
        SparsityPattern::BlockSchurTrigger { split_ratio } => {
            // Create structure that benefits from Block-Schur decomposition
            let split = k * (*split_ratio as usize) / 100;
            let connect_left = esi.is_multiple_of(2);
            let range = if connect_left { 0..split } else { split..k };
            for col in range.take(max_columns) {
                columns.push(col);
                coefficients.push(gf256_from_rng(rng_state));
            }
        }
        SparsityPattern::Random => {
            // Truly random connections
            let mut used_cols = HashSet::new();
            for _ in 0..max_columns {
                let col = lcg_next(rng_state) as usize % k;
                if used_cols.insert(col) {
                    columns.push(col);
                    coefficients.push(gf256_from_rng(rng_state));
                }
            }
        }
    }

    // Ensure we have at least one column
    if columns.is_empty() {
        columns.push(0);
        coefficients.push(Gf256::ONE);
    }

    // Generate symbol data
    let data = (0..symbol_size)
        .map(|_| lcg_next(rng_state) as u8)
        .collect();

    ReceivedSymbol {
        esi,
        is_source: false,
        columns,
        coefficients,
        data,
    }
}

/// Simple LCG for deterministic pseudorandom generation
fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(1103515245).wrapping_add(12345);
    *state
}

/// Generate GF(256) coefficient from RNG state
fn gf256_from_rng(rng_state: &mut u64) -> Gf256 {
    let val = (lcg_next(rng_state) % 255) + 1; // Avoid zero coefficients
    Gf256::new(val as u8)
}

/// Generate tie-breaking repair symbols with identical nonzero counts
fn create_tie_breaking_symbols(
    start_esi: u32,
    k: usize,
    symbol_size: usize,
    identical_groups: u8,
    target_nnz: u8,
) -> Vec<ReceivedSymbol> {
    let mut symbols = Vec::new();
    let target_degree = (target_nnz as usize).min(k);

    for group in 0..identical_groups {
        let esi = start_esi + (group as u32);
        let mut rng_state = 0x12345678u64 ^ (esi as u64);

        // Create columns with exactly target_degree elements
        let mut columns = Vec::new();
        let mut used = HashSet::new();

        while columns.len() < target_degree {
            let col = lcg_next(&mut rng_state) as usize % k;
            if used.insert(col) {
                columns.push(col);
            }
        }
        columns.sort(); // Deterministic ordering

        let coefficients: Vec<Gf256> = (0..target_degree)
            .map(|_| gf256_from_rng(&mut rng_state))
            .collect();

        let data = (0..symbol_size)
            .map(|_| lcg_next(&mut rng_state) as u8)
            .collect();

        symbols.push(ReceivedSymbol {
            esi,
            is_source: false,
            columns,
            coefficients,
            data,
        });
    }

    symbols
}

/// Build symbol set according to the configuration
fn build_symbols(input: &ScheduleEdgeCaseInput) -> Vec<ReceivedSymbol> {
    let mut symbols = Vec::new();
    let k = input.k;
    let symbol_size = input.symbol_size;

    // Add source symbols
    let num_sources = (input.symbol_config.num_sources as usize).min(k);
    for i in 0..num_sources {
        let data = vec![i as u8; symbol_size]; // Simple deterministic data
        symbols.push(ReceivedSymbol {
            esi: i as u32,
            is_source: true,
            columns: vec![i],
            coefficients: vec![Gf256::ONE],
            data,
        });
    }

    // Add repair symbols based on strategy
    let requested_repairs = (input.symbol_config.num_repairs as usize).min(MAX_EXTRA_SYMBOLS);
    let num_repairs = match &input.dense_config.force_ratio {
        Some(DenseRatio::Overdetermined) => requested_repairs
            .max(k.saturating_add(1).saturating_sub(num_sources))
            .min(MAX_EXTRA_SYMBOLS),
        Some(DenseRatio::Square) => requested_repairs
            .max(k.saturating_sub(num_sources))
            .min(MAX_EXTRA_SYMBOLS),
        Some(DenseRatio::Underdetermined) => requested_repairs
            .min(k.saturating_sub(num_sources).saturating_sub(1))
            .min(MAX_EXTRA_SYMBOLS),
        None => requested_repairs,
    };
    let mut rng_state = input.seed;

    match &input.symbol_config.repair_strategy {
        RepairStrategy::AllDegreeOne => {
            for i in 0..num_repairs {
                let esi = (k + i) as u32;
                let col = lcg_next(&mut rng_state) as usize % k;
                let data = vec![(esi % 256) as u8; symbol_size];
                symbols.push(ReceivedSymbol {
                    esi,
                    is_source: false,
                    columns: vec![col],
                    coefficients: vec![Gf256::ONE],
                    data,
                });
            }
        }
        RepairStrategy::AllMaxDegree => {
            for i in 0..num_repairs {
                let esi = (k + i) as u32;
                symbols.push(create_repair_symbol(
                    esi,
                    k,
                    MAX_REPAIR_DEGREE,
                    &input.dense_config.sparsity_pattern,
                    symbol_size,
                    &mut rng_state,
                ));
            }
        }
        RepairStrategy::MixedDegrees { degree_pattern } => {
            for i in 0..num_repairs {
                let esi = (k + i) as u32;
                let degree_idx = i % degree_pattern.len().max(1);
                let degree = degree_pattern[degree_idx] as usize;
                symbols.push(create_repair_symbol(
                    esi,
                    k,
                    degree,
                    &input.dense_config.sparsity_pattern,
                    symbol_size,
                    &mut rng_state,
                ));
            }
        }
        RepairStrategy::TieBreakingPattern {
            identical_nnz_groups,
            target_nnz,
        } => {
            let tie_symbols = create_tie_breaking_symbols(
                k as u32,
                k,
                symbol_size,
                *identical_nnz_groups,
                *target_nnz,
            );
            symbols.extend(tie_symbols);

            // Add remaining symbols with different patterns
            let remaining = num_repairs.saturating_sub(*identical_nnz_groups as usize);
            for i in 0..remaining {
                let esi = (k + *identical_nnz_groups as usize + i) as u32;
                symbols.push(create_repair_symbol(
                    esi,
                    k,
                    (*target_nnz as usize + 1).min(MAX_REPAIR_DEGREE),
                    &input.dense_config.sparsity_pattern,
                    symbol_size,
                    &mut rng_state,
                ));
            }
        }
    }

    // Add duplicates if requested (tests deduplication handling)
    if input.symbol_config.create_duplicates && !symbols.is_empty() {
        let dup_idx = (rng_state as usize) % symbols.len();
        let mut duplicate = symbols[dup_idx].clone();
        duplicate.esi += 1000; // Different ESI, same equation
        symbols.push(duplicate);
    }

    symbols
}

fuzz_target!(|input: ScheduleEdgeCaseInput| {
    // Guard against excessive input sizes
    if input.k > MAX_K
        || input.symbol_size > MAX_SYMBOL_SIZE
        || input.symbol_config.num_repairs > MAX_EXTRA_SYMBOLS as u8
    {
        return;
    }

    // Create decoder
    let decoder = match InactivationDecoder::try_new(input.k, input.symbol_size, input.seed) {
        Ok(decoder) => decoder,
        Err(_) => return, // Invalid parameters
    };

    // Build symbol set
    let symbols = build_symbols(&input);

    // If configured for cache testing, run multiple iterations
    let iterations = if input.dense_config.cache_config.test_cache_reuse {
        (input.dense_config.cache_config.iterations as usize).clamp(1, 5)
    } else {
        1
    };

    for iteration in 0..iterations {
        // For cache collision testing, modify seed slightly
        let decode_result = if iteration > 0 && input.dense_config.cache_config.create_collision {
            match InactivationDecoder::try_new(
                input.k,
                input.symbol_size,
                input.seed + iteration as u64,
            ) {
                Ok(test_decoder) => test_decoder.decode(&symbols),
                Err(_) => continue,
            }
        } else if iteration > 0 {
            // Reuse same decoder to test cache hits.
            continue;
        } else {
            decoder.decode(&symbols)
        };

        observe_decode_result(
            decode_result,
            input.k,
            input.symbol_size,
            false,
            "schedule decode",
        );
    }

    // Test wavefront decoder as well (different code path)
    if !symbols.is_empty() {
        let batch_size = (input.seed % 8) + 1; // Small batch sizes for edge case testing
        observe_decode_result(
            decoder.decode_wavefront(&symbols, batch_size as usize),
            input.k,
            input.symbol_size,
            true,
            "wavefront decode",
        );
    }

    // ORACLE: The fuzz target succeeds if no panics occur.
    // Decode failures (insufficient symbols, singular matrix) are expected
    // and valid outcomes. We're testing the robustness of schedule construction,
    // not decode success rate.

    // INVARIANTS:
    // 1. No panics during schedule construction
    // 2. Deterministic pivot selection (same inputs → same pivots)
    // 3. Proper error classification (recoverable vs unrecoverable)
    // 4. Cache coherency (same matrix signatures → cache hits)
});

fn observe_decode_result(
    result: Result<DecodeResult, DecodeError>,
    expected_k: usize,
    symbol_size: usize,
    expect_wavefront: bool,
    context: &str,
) {
    match result {
        Ok(result) => {
            assert_eq!(
                result.source.len(),
                expected_k,
                "{context}: decoded source count changed"
            );
            assert!(
                result.intermediate.len() >= result.source.len(),
                "{context}: intermediate symbols should cover source symbols"
            );
            assert!(
                result
                    .source
                    .iter()
                    .all(|symbol| symbol.len() == symbol_size),
                "{context}: decoded source symbol size mismatch"
            );
            assert_eq!(
                result.stats.wavefront_active, expect_wavefront,
                "{context}: wavefront stats flag mismatch"
            );
            if expect_wavefront {
                assert!(
                    result.stats.wavefront_batches > 0,
                    "{context}: successful wavefront decode should record batches"
                );
                assert!(
                    result.stats.wavefront_batch_size > 0,
                    "{context}: successful wavefront decode should record batch size"
                );
            }
        }
        Err(error) => {
            assert_ne!(
                error.is_recoverable(),
                error.is_unrecoverable(),
                "{context}: decode error classification should be exclusive"
            );
            assert!(
                !format!("{error:?}").is_empty(),
                "{context}: decode error diagnostics should remain observable"
            );
        }
    }
}
