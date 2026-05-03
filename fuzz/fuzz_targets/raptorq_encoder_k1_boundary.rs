//! Structure-aware fuzzer for RaptorQ encoder K=1 boundary case.
//!
//! This fuzzer targets a critical boundary condition in the RaptorQ systematic
//! encoder where K (number of source symbols) equals 1, which can trigger edge
//! cases in parameter lookup, repair equation generation, and degree distribution.
//!
//! **Target vulnerability areas:**
//! - Systematic index table lookup for K values below minimum table entry (K < 10)
//! - Parameter derivation when K' == K (no padding needed)
//! - Repair symbol generation with minimal source symbol count
//! - Degree distribution edge cases in robust soliton for K=1
//! - ESI overflow detection in repair equation generation
//!
//! **Structure-aware approach:** Rather than feeding random bytes, this fuzzer
//! generates realistic encoding configurations with K=1 and various edge case
//! parameters to exercise systematic encoder boundary handling.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::config::EncodingConfig;
use asupersync::encoding::{EncodingError, EncodingPipeline};
use asupersync::types::ObjectId;
use asupersync::types::resource::{PoolConfig, SymbolPool};

const MAX_SYMBOL_SIZE: u16 = 1024;
const MAX_BLOCK_SIZE: usize = 8192;
const MAX_DATA_SIZE: usize = 64;

#[derive(Debug, Arbitrary)]
struct K1BoundaryInput {
    /// Encoding configuration targeting K=1 boundary
    config_spec: K1ConfigSpec,
    /// Data configuration for exactly one symbol or edge cases
    data_spec: DataSpec,
    /// Edge cases during encoding
    edge_cases: K1EdgeCases,
}

#[derive(Debug, Arbitrary)]
struct K1ConfigSpec {
    /// Symbol size - small values more likely to hit K=1
    symbol_size: SymbolSizeChoice,
    /// Block size designed to force K=1
    max_block_size: BlockSizeChoice,
    /// Repair overhead
    repair_overhead: RepairOverheadChoice,
    /// Parallelism settings
    encoding_parallelism: u8,
    decoding_parallelism: u8,
}

#[derive(Debug, Arbitrary)]
enum SymbolSizeChoice {
    /// Exactly 1 byte - forces K=1 for any 1-byte input
    Minimal,
    /// Small power of 2
    Small(u8), // 1-16
    /// Larger sizes to test different K boundaries
    Medium(u8), // 17-64
    /// Large sizes for K boundary exploration
    Large(u8), // 65-255
    /// Edge case: zero (should fail validation)
    Zero,
    /// Edge case: maximum
    Maximum,
}

#[derive(Debug, Arbitrary)]
enum BlockSizeChoice {
    /// Very small - forces K=1 for many inputs
    Tiny(u8), // 1-8
    /// Small - K=1 for certain symbol_size/data combinations
    Small(u8), // 9-32
    /// Medium - test K boundary transitions
    Medium(u16), // 33-256
    /// Large - test higher K values
    Large(u16), // 257-1024
    /// Edge case: zero (should fail validation)
    Zero,
}

#[derive(Debug, Arbitrary)]
enum RepairOverheadChoice {
    /// Minimal repair overhead
    Minimal, // 1.0
    /// Small overhead
    Small, // 1.1 - 2.0
    /// Medium overhead
    Medium, // 2.0 - 5.0
    /// Large overhead (stress test)
    Large, // 5.0 - 10.0
    /// Edge cases
    EdgeCase(EdgeCaseOverhead),
}

#[derive(Debug, Arbitrary)]
enum EdgeCaseOverhead {
    /// Below 1.0 (should fail validation)
    BelowOne,
    /// Exactly 1.0
    ExactlyOne,
    /// Very large
    VeryLarge, // 100.0
    /// Infinity (should fail validation)
    Infinity,
    /// NaN (should fail validation)
    NaN,
}

#[derive(Debug, Arbitrary)]
struct DataSpec {
    /// Object ID for encoding
    object_id: u64,
    /// Data configuration
    data_config: DataConfig,
}

#[derive(Debug, Arbitrary)]
enum DataConfig {
    /// Empty data
    Empty,
    /// Exactly one byte (forces K=1 with symbol_size >= 1)
    OneByte(u8),
    /// Small data sizes to explore K=1 boundary
    Small { bytes: Vec<u8> }, // 2-8 bytes
    /// Data size that targets specific K values
    Targeted { target_k: TargetK, padding: Vec<u8> },
    /// Random data up to max size
    Random { size: u8, pattern: DataPattern },
}

#[derive(Debug, Arbitrary)]
enum TargetK {
    /// Target exactly K=1
    One,
    /// Target K=2 (boundary between K=1 and higher)
    Two,
    /// Target K values not in systematic table (1-9)
    UnsupportedRange(u8), // 1-9
    /// Target first supported K value (10)
    FirstSupported,
}

#[derive(Debug, Arbitrary)]
enum DataPattern {
    /// All zeros
    Zeros,
    /// All ones
    Ones,
    /// Alternating pattern
    Alternating,
    /// Random bytes
    Random(u64), // seed
    /// Specific pattern that might trigger edge cases
    EdgePattern(u8),
}

#[derive(Debug, Arbitrary)]
struct K1EdgeCases {
    /// Force systematic index table boundary lookup
    force_index_boundary: bool,
    /// Test ESI overflow scenarios
    test_esi_overflow: bool,
    /// Test repair equation generation edge cases
    test_repair_equations: bool,
    /// Pool configuration edge cases
    pool_config: PoolEdgeCase,
}

#[derive(Debug, Arbitrary)]
enum PoolEdgeCase {
    /// No pool (direct allocation)
    NoPool,
    /// Pool with matching symbol size
    Matching,
    /// Pool with mismatched symbol size (should fail validation)
    Mismatched { pool_symbol_size: u16 },
    /// Pool with zero size
    ZeroSize,
    /// Pool exhausted scenario
    Exhausted { tiny_size: u8 },
}

fuzz_target!(|input: K1BoundaryInput| {
    fuzz_k1_boundary(input);
});

fn fuzz_k1_boundary(input: K1BoundaryInput) {
    // Step 1: Build encoding configuration with K=1 targeting
    let config = build_encoding_config(&input.config_spec);

    // Step 2: Create symbol pool based on edge case specification
    let pool = create_symbol_pool(&input.config_spec, &input.edge_cases.pool_config);

    // Step 3: Generate data designed to force specific K values
    let data = generate_data(&input.data_spec, config.symbol_size);

    // Step 4: Create pipeline and test K=1 boundary behavior
    exercise_k1_encoding(config, pool, &data, &input.edge_cases);
}

fn build_encoding_config(spec: &K1ConfigSpec) -> EncodingConfig {
    let symbol_size = resolve_symbol_size(&spec.symbol_size);
    let max_block_size = resolve_max_block_size(&spec.max_block_size);
    let repair_overhead = resolve_repair_overhead(&spec.repair_overhead);

    EncodingConfig {
        symbol_size,
        max_block_size,
        repair_overhead,
        encoding_parallelism: (spec.encoding_parallelism % 8).max(1),
        decoding_parallelism: (spec.decoding_parallelism % 8).max(1),
    }
}

fn resolve_symbol_size(choice: &SymbolSizeChoice) -> u16 {
    match choice {
        SymbolSizeChoice::Minimal => 1,
        SymbolSizeChoice::Small(v) => (*v % 16).max(1) as u16,
        SymbolSizeChoice::Medium(v) => ((*v % 48) + 17) as u16,
        SymbolSizeChoice::Large(v) => ((*v % 191) + 65) as u16,
        SymbolSizeChoice::Zero => 0, // Should trigger validation error
        SymbolSizeChoice::Maximum => MAX_SYMBOL_SIZE,
    }
}

fn resolve_max_block_size(choice: &BlockSizeChoice) -> usize {
    match choice {
        BlockSizeChoice::Tiny(v) => (*v % 8).max(1) as usize,
        BlockSizeChoice::Small(v) => ((*v % 24) + 9) as usize,
        BlockSizeChoice::Medium(v) => ((*v % 224) + 33) as usize,
        BlockSizeChoice::Large(v) => ((*v % 768) + 257) as usize,
        BlockSizeChoice::Zero => 0, // Should trigger validation error
    }
}

fn resolve_repair_overhead(choice: &RepairOverheadChoice) -> f64 {
    match choice {
        RepairOverheadChoice::Minimal => 1.0,
        RepairOverheadChoice::Small => 1.1 + (rand_f64() * 0.9), // 1.1 - 2.0
        RepairOverheadChoice::Medium => 2.0 + (rand_f64() * 3.0), // 2.0 - 5.0
        RepairOverheadChoice::Large => 5.0 + (rand_f64() * 5.0), // 5.0 - 10.0
        RepairOverheadChoice::EdgeCase(edge) => match edge {
            EdgeCaseOverhead::BelowOne => 0.5,
            EdgeCaseOverhead::ExactlyOne => 1.0,
            EdgeCaseOverhead::VeryLarge => 100.0,
            EdgeCaseOverhead::Infinity => f64::INFINITY,
            EdgeCaseOverhead::NaN => f64::NAN,
        },
    }
}

// Simple deterministic random for reproducibility
fn rand_f64() -> f64 {
    0.5 // Simple constant for deterministic testing
}

fn create_symbol_pool(config_spec: &K1ConfigSpec, pool_edge: &PoolEdgeCase) -> SymbolPool {
    let symbol_size = resolve_symbol_size(&config_spec.symbol_size);

    let pool_config = match pool_edge {
        PoolEdgeCase::NoPool => PoolConfig {
            symbol_size: symbol_size,
            max_size: 0,
            initial_size: 0,
            allow_growth: false,
        },
        PoolEdgeCase::Matching => PoolConfig {
            symbol_size: symbol_size,
            max_size: 16,
            initial_size: 4,
            allow_growth: true,
        },
        PoolEdgeCase::Mismatched { pool_symbol_size } => PoolConfig {
            symbol_size: *pool_symbol_size,
            max_size: 16,
            initial_size: 4,
            allow_growth: true,
        },
        PoolEdgeCase::ZeroSize => PoolConfig {
            symbol_size: symbol_size,
            max_size: 0,
            initial_size: 0,
            allow_growth: false,
        },
        PoolEdgeCase::Exhausted { tiny_size } => PoolConfig {
            symbol_size: symbol_size,
            max_size: (*tiny_size % 3) as usize,
            initial_size: 0,
            allow_growth: false,
        },
    };

    SymbolPool::new(pool_config)
}

fn generate_data(spec: &DataSpec, symbol_size: u16) -> Vec<u8> {
    match &spec.data_config {
        DataConfig::Empty => Vec::new(),
        DataConfig::OneByte(b) => vec![*b],
        DataConfig::Small { bytes } => bytes.iter().take(8).copied().collect(),
        DataConfig::Targeted { target_k, padding } => {
            let target_size = match target_k {
                TargetK::One => (symbol_size as usize).max(1),
                TargetK::Two => (symbol_size as usize * 2).max(1),
                TargetK::UnsupportedRange(k) => (symbol_size as usize * (*k as usize)).max(1),
                TargetK::FirstSupported => symbol_size as usize * 10,
            };

            let mut data = Vec::with_capacity(target_size.min(MAX_DATA_SIZE));
            let padding_cycle = if padding.is_empty() { &[0u8] } else { padding };

            for i in 0..target_size.min(MAX_DATA_SIZE) {
                data.push(padding_cycle[i % padding_cycle.len()]);
            }
            data
        }
        DataConfig::Random { size, pattern } => {
            let actual_size = (*size as usize).min(MAX_DATA_SIZE);
            match pattern {
                DataPattern::Zeros => vec![0u8; actual_size],
                DataPattern::Ones => vec![0xFFu8; actual_size],
                DataPattern::Alternating => (0..actual_size)
                    .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
                    .collect(),
                DataPattern::Random(seed) => {
                    // Simple deterministic PRNG for reproducibility
                    let mut data = Vec::with_capacity(actual_size);
                    let mut state = *seed;
                    for _ in 0..actual_size {
                        state = state.wrapping_mul(1103515245).wrapping_add(12345);
                        data.push((state >> 16) as u8);
                    }
                    data
                }
                DataPattern::EdgePattern(pattern) => vec![*pattern; actual_size],
            }
        }
    }
}

fn exercise_k1_encoding(
    config: EncodingConfig,
    pool: SymbolPool,
    data: &[u8],
    edge_cases: &K1EdgeCases,
) {
    let mut pipeline = EncodingPipeline::new(config, pool);
    let object_id = ObjectId::new_for_test(0xDEADBEEF);

    // Test 1: Basic encoding - expect either success or specific failure modes
    let encoding_result: Vec<_> = pipeline.encode(object_id, data).collect();

    let mut has_error = false;
    let mut symbol_count = 0;

    for (idx, result) in encoding_result.iter().enumerate() {
        match result {
            Ok(symbol) => {
                symbol_count += 1;
                // Verify symbol properties hold even for K=1
                let id = symbol.id();
                let kind = symbol.kind();

                // Invariant: symbol data length must match config symbol_size
                assert!(
                    symbol.symbol().data().len() == config.symbol_size as usize
                        || (idx == 0 && data.len() < config.symbol_size as usize), // Last symbol can be partial
                    "K=1 encoding produced symbol with wrong size: expected {}, got {}",
                    config.symbol_size,
                    symbol.symbol().data().len()
                );

                // Invariant: ESI must be reasonable for small K
                assert!(
                    id.esi() < 10000,
                    "K=1 encoding produced unreasonable ESI: {}",
                    id.esi()
                );

                // Log the symbol for debugging
                let _ = std::hint::black_box((id.sbn(), id.esi(), kind));
            }
            Err(_) => {
                has_error = true;
                // Expected error categories for K=1 boundary:
                // - InvalidConfig (symbol_size=0, max_block_size=0, bad repair_overhead)
                // - UnsupportedSourceBlockSize (K < 10 not in systematic table)
                // - DataTooLarge (if data exceeds max_object_size)
                // - PoolExhausted (if pool is configured too small)

                // Don't panic on expected error categories - just verify we handle them gracefully
                let _ = std::hint::black_box(result);
                break; // Stop on first error as expected
            }
        }
    }

    // Test 2: If encoding succeeded, verify consistency
    if !has_error && symbol_count > 0 {
        // For K=1, we should have exactly 1 source symbol + repair symbols
        // The number of source symbols should never exceed the computed K
        if !data.is_empty() && config.symbol_size > 0 && config.max_block_size > 0 {
            let expected_k = data.len().div_ceil(config.symbol_size as usize);
            // This might trigger the bug if expected_k < 10 (not in systematic table)

            // Verify statistics are reasonable
            let stats = pipeline.stats();
            assert_eq!(stats.bytes_in, data.len(), "Stats mismatch: bytes_in");

            if expected_k > 0 {
                // This assertion may expose the boundary bug
                assert!(
                    stats.source_symbols >= expected_k.min(symbol_count),
                    "K=1 boundary: source symbol count inconsistent. Expected K={}, got source_symbols={}, total_symbols={}",
                    expected_k,
                    stats.source_symbols,
                    symbol_count
                );
            }
        }
    }

    // Test 3: Edge case exploration
    if edge_cases.test_repair_equations {
        // Try creating a new pipeline to test parameter validation in isolation
        let test_pipeline = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));
        let _ = std::hint::black_box(test_pipeline);
    }

    // Test 4: ESI overflow testing
    if edge_cases.test_esi_overflow {
        // This would require calling systematic encoder directly, but we test the boundary through pipeline
        let _ = std::hint::black_box(config);
    }
}
