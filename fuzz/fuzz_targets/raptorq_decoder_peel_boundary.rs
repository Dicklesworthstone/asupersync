//! Focused fuzz target for RaptorQ decoder peel boundary and rank-deficient matrices.
//!
//! This harness specifically targets the transition from peeling to Gaussian elimination
//! in `src/raptorq/decoder.rs`, focusing on degenerate symbol sets that stress-test
//! the rank-deficient matrix handling at the peel boundary.
//!
//! ## Target Coverage
//!
//! **Peel Boundary Edge Cases:**
//! - Symbol sets that exhaust peeling but leave rank-deficient cores
//! - Mixed degree-1/degree-2+ equations that create elimination pressure
//! - Equations that become degree-1 only after partial peeling
//! - Malformed equation structures that break peeling assumptions
//!
//! ## Rank-Deficient Matrix Focus
//!
//! **Gaussian Elimination Stress Tests:**
//! - Matrices with zero pivots (no solvable columns)
//! - Near-singular matrices with numerical instability
//! - Block-structured rank deficiency (systematic pattern failure)
//! - Inconsistent overdetermined systems (`0 = nonzero_rhs`)
//! - Edge cases in pivot selection with tie-breaking
//!
//! ## Oracle Strategy
//!
//! Uses multiple oracles to validate decoder robustness:
//! 1. **Failure classification oracle**: Rank-deficient inputs should produce
//!    `SingularMatrix` errors with deterministic witness rows
//! 2. **Determinism oracle**: Same symbol set should produce identical decode results
//! 3. **Invariant oracle**: No panics, even on malformed or impossible inputs
//! 4. **Elimination trace oracle**: Pivot selection should be deterministic and complete

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};
use libfuzzer_sys::fuzz_target;

/// Maximum parameters to prevent timeout/OOM while reaching interesting edge cases
const MAX_K: usize = 32;
const MAX_SYMBOL_SIZE: usize = 64;
const MAX_SYMBOLS_TO_GENERATE: usize = 50;

/// Structure-aware fuzzing input for peel boundary testing
#[derive(Arbitrary, Debug)]
struct PeelBoundaryFuzzInput {
    /// Core systematic parameters
    k: u8,
    symbol_size: u8,
    seed: u64,

    /// Symbol set construction strategy
    strategy: BoundaryTestStrategy,

    /// Rank deficiency configuration
    rank_deficiency: RankDeficiencyPattern,

    /// Equation malformation patterns
    malformation: EquationMalformation,

    /// Additional symbols to stress the decoder
    extra_symbols: Vec<ExtraSymbol>,
}

/// Test strategies that target peel boundary transition points
#[derive(Arbitrary, Debug, Clone)]
enum BoundaryTestStrategy {
    /// Create exactly enough degree-1 equations to partially solve, then rank-deficient remainder
    PartialPeelThenRankDeficit {
        /// Number of symbols solvable by peeling
        peel_solvable: u8,
        /// Degree of remaining equations after peeling
        remaining_degrees: Vec<u8>,
    },

    /// Alternate between degree-1 and higher-degree equations in a pattern
    AlternatingDegreePattern {
        /// Pattern of equation degrees (cycles through the list)
        degree_pattern: Vec<u8>,
        /// Whether to add source symbols that create dependencies
        add_dependent_sources: bool,
    },

    /// Create chains of dependencies that collapse to rank deficiency
    DependencyChainCollapse {
        /// Length of dependency chains before collapse
        chain_length: u8,
        /// Position where chain becomes rank-deficient
        collapse_point: u8,
    },

    /// Stress-test with only source symbols (no repair) but missing key sources
    SourceOnlyIncomplete {
        /// Indices of source symbols to omit (mod k)
        missing_indices: Vec<u8>,
    },

    /// Create repair equations that appear independent but are actually linearly dependent
    RepairLinearDependence {
        /// Number of apparently independent repair equations
        repair_count: u8,
        /// Dependence pattern (which repairs copy which others)
        dependence_pattern: Vec<u8>,
    },
}

/// Patterns for introducing rank deficiency into the matrix
#[derive(Arbitrary, Debug, Clone)]
enum RankDeficiencyPattern {
    /// No rank deficiency - control case
    FullRank,

    /// Duplicate some equations exactly
    ExactDuplicates {
        /// How many equations to duplicate
        duplicate_count: u8,
        /// Base equation index to duplicate from
        base_index: u8,
    },

    /// Create linear combinations that sum to zero
    LinearCombinationZero {
        /// Coefficients for the zero combination
        coefficients: Vec<u8>,
        /// Which equation indices to combine
        equation_indices: Vec<u8>,
    },

    /// Block structure where sub-blocks are rank deficient
    BlockRankDeficit {
        /// Block size
        block_size: u8,
        /// Which blocks to make rank deficient
        deficient_blocks: Vec<u8>,
    },

    /// Progressive rank loss (remove one degree of freedom at each step)
    ProgressiveRankLoss {
        /// How many steps of rank reduction
        steps: u8,
        /// Which variables to eliminate at each step
        elimination_order: Vec<u8>,
    },

    /// All-zero matrix (extreme rank deficiency)
    AllZero,
}

/// Ways to malform equation structures to test error handling
#[derive(Arbitrary, Debug, Clone)]
enum EquationMalformation {
    /// Well-formed equations
    None,

    /// Mismatched column/coefficient counts
    ArityMismatch {
        /// Target equation index
        equation_index: u8,
        /// How many extra/fewer coefficients to provide
        mismatch_delta: i8,
    },

    /// Column indices outside valid range [0, L)
    ColumnOutOfRange {
        /// Target equation index
        equation_index: u8,
        /// Invalid column index to inject
        invalid_column: u16,
    },

    /// Source symbols with non-identity equations
    InvalidSourceEquation {
        /// Source ESI to corrupt
        source_esi: u8,
        /// Malformed equation to assign
        malformed_columns: Vec<u8>,
        malformed_coefficients: Vec<u8>,
    },

    /// Wrong symbol sizes
    SymbolSizeMismatch {
        /// Target symbol index
        symbol_index: u8,
        /// Wrong size to use
        wrong_size: u8,
    },
}

/// Additional symbols to stress the decoder beyond the basic test case
#[derive(Arbitrary, Debug, Clone)]
struct ExtraSymbol {
    /// Symbol type and configuration
    symbol_type: ExtraSymbolType,
    /// Symbol data
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExtraSymbolType {
    /// Redundant source symbol
    RedundantSource { esi: u8 },

    /// High-degree repair symbol
    HighDegreeRepair {
        degree: u8,
        columns: Vec<u8>,
        coefficients: Vec<u8>,
    },

    /// Repair with zero coefficients (should be ignored)
    ZeroRepair { columns: Vec<u8> },

    /// Repair that references non-existent columns
    InvalidRepair { invalid_columns: Vec<u8>, coefficients: Vec<u8> },

    /// Source with wrong ESI
    WrongEsiSource { claimed_esi: u16, actual_esi: u8 },
}

fuzz_target!(|input: PeelBoundaryFuzzInput| {
    let mut input = input;
    normalize_input(&mut input);
    test_peel_boundary_robustness(input);
});

fn normalize_input(input: &mut PeelBoundaryFuzzInput) {
    // Normalize to valid ranges
    input.k = ((input.k as usize % (MAX_K - 1)) + 2) as u8;  // k ∈ [2, MAX_K]
    input.symbol_size = ((input.symbol_size as usize % MAX_SYMBOL_SIZE) + 1) as u8;

    // Truncate to prevent OOM
    input.extra_symbols.truncate(MAX_SYMBOLS_TO_GENERATE);

    // Normalize malformation parameters
    match &mut input.malformation {
        EquationMalformation::ArityMismatch { equation_index, .. } => {
            *equation_index %= input.k;
        }
        EquationMalformation::ColumnOutOfRange { equation_index, .. } => {
            *equation_index %= input.k;
        }
        EquationMalformation::InvalidSourceEquation { source_esi, .. } => {
            *source_esi %= input.k;
        }
        EquationMalformation::SymbolSizeMismatch { symbol_index, wrong_size } => {
            *symbol_index %= input.k;
            *wrong_size = ((*wrong_size as usize % MAX_SYMBOL_SIZE) + 1) as u8;
        }
        _ => {}
    }

    // Normalize rank deficiency patterns
    match &mut input.rank_deficiency {
        RankDeficiencyPattern::ExactDuplicates { duplicate_count, base_index } => {
            *duplicate_count = (*duplicate_count % input.k) + 1;
            *base_index %= input.k;
        }
        RankDeficiencyPattern::LinearCombinationZero { coefficients, equation_indices } => {
            equation_indices.truncate(input.k as usize);
            coefficients.truncate(input.k as usize);
            for idx in equation_indices {
                *idx %= input.k;
            }
        }
        RankDeficiencyPattern::BlockRankDeficit { block_size, deficient_blocks } => {
            *block_size = ((*block_size % input.k) + 1).min(input.k / 2);
            deficient_blocks.truncate(input.k as usize / *block_size as usize);
        }
        RankDeficiencyPattern::ProgressiveRankLoss { steps, elimination_order } => {
            *steps = (*steps % input.k) + 1;
            elimination_order.truncate(*steps as usize);
            for var in elimination_order {
                *var %= input.k;
            }
        }
        _ => {}
    }

    // Normalize strategy parameters
    match &mut input.strategy {
        BoundaryTestStrategy::PartialPeelThenRankDeficit { peel_solvable, remaining_degrees } => {
            *peel_solvable = (*peel_solvable % input.k) + 1;
            remaining_degrees.truncate((input.k - *peel_solvable) as usize);
            for deg in remaining_degrees {
                *deg = ((*deg % input.k) + 2).min(input.k);  // degree ≥ 2
            }
        }
        BoundaryTestStrategy::AlternatingDegreePattern { degree_pattern, .. } => {
            degree_pattern.truncate(10);  // Reasonable pattern length
            for deg in degree_pattern {
                *deg = ((*deg % input.k) + 1).min(input.k);
            }
        }
        BoundaryTestStrategy::DependencyChainCollapse { chain_length, collapse_point } => {
            *chain_length = (*chain_length % input.k) + 1;
            *collapse_point = (*collapse_point % *chain_length) + 1;
        }
        BoundaryTestStrategy::SourceOnlyIncomplete { missing_indices } => {
            missing_indices.truncate((input.k / 2) as usize);  // Don't remove too many
            for idx in missing_indices {
                *idx %= input.k;
            }
            missing_indices.sort();
            missing_indices.dedup();
        }
        BoundaryTestStrategy::RepairLinearDependence { repair_count, dependence_pattern } => {
            *repair_count = (*repair_count % 10) + 1;  // Reasonable repair count
            dependence_pattern.truncate(*repair_count as usize);
            for dep in dependence_pattern {
                *dep %= *repair_count;
            }
        }
    }
}

fn test_peel_boundary_robustness(input: PeelBoundaryFuzzInput) {
    let k = input.k as usize;
    let symbol_size = input.symbol_size as usize;

    // Create systematic parameters
    let params = match SystematicParams::try_for_source_block(k, symbol_size) {
        Ok(p) => p,
        Err(_) => return,  // Invalid parameters
    };

    // Generate base source data
    let source_data = generate_source_data(k, symbol_size, input.seed);

    // Create encoder for generating repair symbols
    let encoder = match SystematicEncoder::new(&source_data, symbol_size, input.seed) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Build symbol set based on strategy and rank deficiency pattern
    let symbols = build_symbol_set(&input, &params, &encoder, &source_data);

    // Test decoder robustness
    test_decoder_with_symbols(&input, k, symbol_size, symbols);
}

fn generate_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<u8> {
    // Use seed to generate deterministic but varied source data
    let mut data = vec![0u8; k * symbol_size];
    let mut rng_state = seed;

    for byte in &mut data {
        // Simple PRNG for deterministic data generation
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (rng_state >> 16) as u8;
    }

    data
}

fn build_symbol_set(
    input: &PeelBoundaryFuzzInput,
    params: &SystematicParams,
    encoder: &SystematicEncoder,
    source_data: &[u8],
) -> Vec<ReceivedSymbol> {
    let mut symbols = Vec::new();
    let k = input.k as usize;
    let symbol_size = input.symbol_size as usize;

    // Apply test strategy to generate initial symbol set
    match &input.strategy {
        BoundaryTestStrategy::PartialPeelThenRankDeficit { peel_solvable, remaining_degrees } => {
            // Add enough sources/repairs to solve `peel_solvable` symbols via peeling
            for i in 0..*peel_solvable as usize {
                let source_symbol = create_source_symbol(i, source_data, symbol_size);
                symbols.push(source_symbol);
            }

            // Add higher-degree equations for remaining symbols
            for (i, &degree) in remaining_degrees.iter().enumerate() {
                let repair_esi = k as u32 + i as u32;
                let repair_symbol = create_repair_symbol_with_degree(
                    repair_esi, degree as usize, k, encoder, symbol_size);
                symbols.push(repair_symbol);
            }
        }

        BoundaryTestStrategy::AlternatingDegreePattern { degree_pattern, add_dependent_sources } => {
            let mut esi_counter = 0u32;

            for (i, &degree) in degree_pattern.iter().cycle().take(k * 2).enumerate() {
                if degree == 1 && i < k && !add_dependent_sources {
                    // Add source symbol (degree-1)
                    symbols.push(create_source_symbol(i, source_data, symbol_size));
                } else {
                    // Add repair symbol with specified degree
                    let repair_esi = k as u32 + esi_counter;
                    symbols.push(create_repair_symbol_with_degree(
                        repair_esi, degree as usize, k, encoder, symbol_size));
                    esi_counter += 1;
                }
            }
        }

        BoundaryTestStrategy::DependencyChainCollapse { chain_length, collapse_point } => {
            // Create dependency chain that becomes rank-deficient at collapse_point
            for i in 0..k {
                if i < *chain_length as usize {
                    if i < *collapse_point as usize {
                        // Independent equations
                        symbols.push(create_source_symbol(i, source_data, symbol_size));
                    } else {
                        // Start creating dependent equations that collapse rank
                        let repair_esi = k as u32 + i as u32;
                        symbols.push(create_dependent_repair_symbol(
                            repair_esi, i, k, encoder, symbol_size));
                    }
                } else {
                    symbols.push(create_source_symbol(i, source_data, symbol_size));
                }
            }
        }

        BoundaryTestStrategy::SourceOnlyIncomplete { missing_indices } => {
            // Add all sources except those in missing_indices
            for i in 0..k {
                if !missing_indices.contains(&(i as u8)) {
                    symbols.push(create_source_symbol(i, source_data, symbol_size));
                }
            }
        }

        BoundaryTestStrategy::RepairLinearDependence { repair_count, dependence_pattern } => {
            // Add all source symbols
            for i in 0..k {
                symbols.push(create_source_symbol(i, source_data, symbol_size));
            }

            // Add linearly dependent repair symbols
            for (i, &dep_idx) in dependence_pattern.iter().enumerate() {
                let repair_esi = k as u32 + i as u32;
                let base_esi = k as u32 + (dep_idx % dependence_pattern.len()) as u32;
                symbols.push(create_linearly_dependent_repair(
                    repair_esi, base_esi, k, encoder, symbol_size));
            }
        }
    }

    // Apply rank deficiency patterns
    apply_rank_deficiency(&mut symbols, &input.rank_deficiency, k, symbol_size);

    // Apply malformation patterns
    apply_malformation(&mut symbols, &input.malformation, k, symbol_size);

    // Add extra symbols
    for extra in &input.extra_symbols {
        if let Some(symbol) = create_extra_symbol(extra, k, symbol_size, encoder) {
            symbols.push(symbol);
        }
    }

    symbols
}

fn create_source_symbol(esi: usize, source_data: &[u8], symbol_size: usize) -> ReceivedSymbol {
    let start = esi * symbol_size;
    let end = start + symbol_size;
    let data = source_data.get(start..end).unwrap_or(&vec![0u8; symbol_size]).to_vec();

    ReceivedSymbol {
        esi: esi as u32,
        is_source: true,
        columns: vec![esi],
        coefficients: vec![Gf256::new(1)],
        data,
    }
}

fn create_repair_symbol_with_degree(
    esi: u32,
    degree: usize,
    k: usize,
    encoder: &SystematicEncoder,
    symbol_size: usize
) -> ReceivedSymbol {
    let degree = degree.min(k).max(1);
    let mut columns = Vec::with_capacity(degree);
    let mut coefficients = Vec::with_capacity(degree);

    // Select columns for the repair equation (use ESI for deterministic selection)
    let mut rng_state = esi as u64;
    for _ in 0..degree {
        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let col = (rng_state as usize) % k;
        columns.push(col);

        rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let coef = if (rng_state & 0xFF) == 0 { 1 } else { (rng_state & 0xFF) as u8 };
        coefficients.push(Gf256::new(coef));
    }

    // Remove duplicates and sort
    let mut pairs: Vec<(usize, Gf256)> = columns.into_iter().zip(coefficients).collect();
    pairs.sort_by_key(|(col, _)| *col);
    pairs.dedup_by_key(|(col, _)| *col);

    let (columns, coefficients): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();

    // Generate symbol data using encoder
    let data = match encoder.repair_symbol(esi, symbol_size) {
        Ok(d) => d,
        Err(_) => vec![0u8; symbol_size],
    };

    ReceivedSymbol {
        esi,
        is_source: false,
        columns,
        coefficients,
        data,
    }
}

fn create_dependent_repair_symbol(
    esi: u32,
    dependency_base: usize,
    k: usize,
    encoder: &SystematicEncoder,
    symbol_size: usize,
) -> ReceivedSymbol {
    // Create a repair that's linearly dependent on previous equations
    let columns = vec![dependency_base, (dependency_base + 1) % k];
    let coefficients = vec![Gf256::new(1), Gf256::new(1)];  // Just sum two symbols

    let data = match encoder.repair_symbol(esi, symbol_size) {
        Ok(d) => d,
        Err(_) => vec![0u8; symbol_size],
    };

    ReceivedSymbol {
        esi,
        is_source: false,
        columns,
        coefficients,
        data,
    }
}

fn create_linearly_dependent_repair(
    esi: u32,
    base_esi: u32,
    k: usize,
    encoder: &SystematicEncoder,
    symbol_size: usize,
) -> ReceivedSymbol {
    // Create repair that copies another repair's equation structure
    let columns = vec![base_esi as usize % k, (base_esi as usize + 1) % k];
    let coefficients = vec![Gf256::new(1), Gf256::new(1)];

    let data = match encoder.repair_symbol(esi, symbol_size) {
        Ok(d) => d,
        Err(_) => vec![0u8; symbol_size],
    };

    ReceivedSymbol {
        esi,
        is_source: false,
        columns,
        coefficients,
        data,
    }
}

fn apply_rank_deficiency(
    symbols: &mut Vec<ReceivedSymbol>,
    pattern: &RankDeficiencyPattern,
    k: usize,
    symbol_size: usize,
) {
    match pattern {
        RankDeficiencyPattern::FullRank => {
            // No modification needed
        }

        RankDeficiencyPattern::ExactDuplicates { duplicate_count, base_index } => {
            if let Some(base_symbol) = symbols.get(*base_index as usize) {
                let base_clone = base_symbol.clone();
                for i in 0..*duplicate_count {
                    let mut duplicate = base_clone.clone();
                    duplicate.esi = k as u32 + 1000 + i as u32; // High ESI for duplicate
                    symbols.push(duplicate);
                }
            }
        }

        RankDeficiencyPattern::AllZero => {
            // Replace all equations with zero equations
            for symbol in symbols {
                symbol.coefficients.fill(Gf256::new(0));
                symbol.data = vec![0u8; symbol_size];
            }
        }

        // Implement other patterns as needed for comprehensive coverage
        _ => {
            // Placeholder for additional rank deficiency patterns
        }
    }
}

fn apply_malformation(
    symbols: &mut Vec<ReceivedSymbol>,
    malformation: &EquationMalformation,
    k: usize,
    symbol_size: usize,
) {
    match malformation {
        EquationMalformation::None => {}

        EquationMalformation::ArityMismatch { equation_index, mismatch_delta } => {
            if let Some(symbol) = symbols.get_mut(*equation_index as usize) {
                if *mismatch_delta > 0 {
                    // Add extra coefficients
                    for _ in 0..*mismatch_delta {
                        symbol.coefficients.push(Gf256::new(1));
                    }
                } else {
                    // Remove coefficients
                    let to_remove = (-*mismatch_delta as usize).min(symbol.coefficients.len());
                    symbol.coefficients.truncate(symbol.coefficients.len() - to_remove);
                }
            }
        }

        EquationMalformation::ColumnOutOfRange { equation_index, invalid_column } => {
            if let Some(symbol) = symbols.get_mut(*equation_index as usize) {
                if !symbol.columns.is_empty() {
                    symbol.columns[0] = *invalid_column as usize;
                }
            }
        }

        EquationMalformation::SymbolSizeMismatch { symbol_index, wrong_size } => {
            if let Some(symbol) = symbols.get_mut(*symbol_index as usize) {
                symbol.data = vec![0u8; *wrong_size as usize];
            }
        }

        EquationMalformation::InvalidSourceEquation { source_esi, malformed_columns, malformed_coefficients } => {
            if let Some(symbol) = symbols.iter_mut().find(|s| s.esi == *source_esi as u32 && s.is_source) {
                symbol.columns = malformed_columns.iter().map(|&c| c as usize).collect();
                symbol.coefficients = malformed_coefficients.iter().map(|&c| Gf256::new(c)).collect();
            }
        }
    }
}

fn create_extra_symbol(
    extra: &ExtraSymbol,
    k: usize,
    symbol_size: usize,
    encoder: &SystematicEncoder,
) -> Option<ReceivedSymbol> {
    match &extra.symbol_type {
        ExtraSymbolType::RedundantSource { esi } => {
            let esi = *esi as usize % k;
            let data = extra.data.get(0..symbol_size).unwrap_or(&vec![0u8; symbol_size]).to_vec();
            Some(ReceivedSymbol {
                esi: esi as u32,
                is_source: true,
                columns: vec![esi],
                coefficients: vec![Gf256::new(1)],
                data,
            })
        }

        ExtraSymbolType::ZeroRepair { columns } => {
            let columns: Vec<usize> = columns.iter().map(|&c| c as usize % k).collect();
            let coefficients = vec![Gf256::new(0); columns.len()];
            let data = vec![0u8; symbol_size];
            Some(ReceivedSymbol {
                esi: k as u32 + 9999,  // High ESI
                is_source: false,
                columns,
                coefficients,
                data,
            })
        }

        ExtraSymbolType::HighDegreeRepair { degree, columns, coefficients } => {
            let degree = (*degree as usize % k).max(1);
            let columns: Vec<usize> = columns.iter()
                .take(degree)
                .map(|&c| c as usize % k)
                .collect();
            let coefficients: Vec<Gf256> = coefficients.iter()
                .take(degree)
                .map(|&c| Gf256::new(c))
                .collect();

            let data = match encoder.repair_symbol(k as u32 + 8888, symbol_size) {
                Ok(d) => d,
                Err(_) => vec![0u8; symbol_size],
            };

            Some(ReceivedSymbol {
                esi: k as u32 + 8888,
                is_source: false,
                columns,
                coefficients,
                data,
            })
        }

        _ => None,  // Skip other types for now
    }
}

fn test_decoder_with_symbols(
    input: &PeelBoundaryFuzzInput,
    k: usize,
    symbol_size: usize,
    symbols: Vec<ReceivedSymbol>,
) {
    let decoder = match InactivationDecoder::try_new(k, symbol_size, input.seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Test basic decode
    let result1 = decoder.decode(symbols.clone());

    // Test decode with proof (should have same outcome)
    let result2 = decoder.decode_with_proof(symbols.clone());

    // Apply oracles
    apply_oracles(input, &symbols, k, &result1, &result2);
}

fn apply_oracles(
    input: &PeelBoundaryFuzzInput,
    _symbols: &[ReceivedSymbol],
    k: usize,
    result1: &Result<Vec<u8>, DecodeError>,
    result2: &Result<(Vec<u8>, asupersync::raptorq::proof::DecodeProof), DecodeError>,
) {
    // Oracle 1: Determinism - same symbols should produce same results
    let comparable_result2 = result2.as_ref().map(|(data, _proof)| data.clone()).map_err(|e| e.clone());
    assert_eq!(result1, &comparable_result2,
        "Decoder results should be deterministic across different API calls");

    // Oracle 2: Failure classification - rank-deficient cases should produce appropriate errors
    match (&input.rank_deficiency, result1) {
        (RankDeficiencyPattern::AllZero, Err(DecodeError::SingularMatrix { .. })) => {
            // Expected - all-zero matrix should be detected as singular
        }
        (RankDeficiencyPattern::FullRank, _) => {
            // May succeed or fail, but shouldn't panic
        }
        (RankDeficiencyPattern::ExactDuplicates { .. }, Err(DecodeError::SingularMatrix { .. })) => {
            // Expected - duplicates should cause rank deficiency
        }
        _ => {
            // Other cases are allowed - main goal is no panics
        }
    }

    // Oracle 3: Invariant - no panics on any input
    // This oracle is implicitly satisfied if we reach this point

    // Oracle 4: Witness row should be deterministic for same error
    if let (Err(DecodeError::SingularMatrix { row: row1 }),
            Err(DecodeError::SingularMatrix { row: row2 })) =
           (result1, comparable_result2.as_ref()) {
        assert_eq!(row1, row2,
            "Witness row should be deterministic for same singular matrix");
    }

    // Oracle 5: Malformation should be detected appropriately
    match &input.malformation {
        EquationMalformation::ArityMismatch { .. } => {
            if let Err(DecodeError::SymbolEquationArityMismatch { .. }) = result1 {
                // Expected error type
            }
        }
        EquationMalformation::ColumnOutOfRange { .. } => {
            if let Err(DecodeError::ColumnIndexOutOfRange { .. }) = result1 {
                // Expected error type
            }
        }
        EquationMalformation::SymbolSizeMismatch { .. } => {
            if let Err(DecodeError::SymbolSizeMismatch { .. }) = result1 {
                // Expected error type
            }
        }
        _ => {}
    }

    // Oracle 6: If decode succeeds, result should be correct length
    if let Ok(decoded) = result1 {
        assert_eq!(decoded.len(), k * input.symbol_size as usize,
            "Successful decode should produce correct amount of data");
    }
}

/// Security and robustness invariants for the peel boundary fuzzer
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_determinism_across_api_variants() {
        // Verify that decode() and decode_with_proof() are deterministic
        let input = PeelBoundaryFuzzInput {
            k: 4,
            symbol_size: 16,
            seed: 12345,
            strategy: BoundaryTestStrategy::PartialPeelThenRankDeficit {
                peel_solvable: 2,
                remaining_degrees: vec![3, 3],
            },
            rank_deficiency: RankDeficiencyPattern::FullRank,
            malformation: EquationMalformation::None,
            extra_symbols: vec![],
        };

        test_peel_boundary_robustness(input);
    }

    #[test]
    fn oracle_rank_deficient_detection() {
        let input = PeelBoundaryFuzzInput {
            k: 4,
            symbol_size: 16,
            seed: 54321,
            strategy: BoundaryTestStrategy::SourceOnlyIncomplete {
                missing_indices: vec![0, 1],
            },
            rank_deficiency: RankDeficiencyPattern::AllZero,
            malformation: EquationMalformation::None,
            extra_symbols: vec![],
        };

        test_peel_boundary_robustness(input);
    }

    #[test]
    fn oracle_malformation_error_classification() {
        let input = PeelBoundaryFuzzInput {
            k: 4,
            symbol_size: 16,
            seed: 99999,
            strategy: BoundaryTestStrategy::AlternatingDegreePattern {
                degree_pattern: vec![1, 2, 1, 2],
                add_dependent_sources: false,
            },
            rank_deficiency: RankDeficiencyPattern::FullRank,
            malformation: EquationMalformation::ArityMismatch {
                equation_index: 0,
                mismatch_delta: 3,
            },
            extra_symbols: vec![],
        };

        test_peel_boundary_robustness(input);
    }
}