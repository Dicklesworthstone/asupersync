#![allow(clippy::all)]
//! Golden artifact tests for RaptorQ encoded blocks.
//!
//! These tests verify that RaptorQ encoding produces consistent, deterministic
//! outputs for known inputs. Changes to encoding behavior will cause golden
//! mismatches, ensuring backwards compatibility and correctness.
//!
//! To update goldens after intentional changes:
//!   UPDATE_GOLDENS=1 cargo test --test raptorq_encoded_block_golden
//!   Review diffs and commit changes with justification

use insta::assert_json_snapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use asupersync::config::EncodingConfig;
use asupersync::encoding::EncodingPipeline;
use asupersync::types::Symbol;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::symbol::{ObjectId, SymbolKind};
use asupersync::util::DetRng;

/// Golden artifact representation of an encoded symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct EncodedSymbolGolden {
    /// Object identifier.
    object_id: u128,
    /// Source block number.
    source_block_number: u8,
    /// Encoding symbol identifier.
    encoding_symbol_id: u32,
    /// Symbol kind (Source or Repair).
    kind: String,
    /// Symbol payload (as byte array for deterministic comparison).
    payload_bytes: Vec<u8>,
    /// Symbol size in bytes.
    size: usize,
}

impl From<&Symbol> for EncodedSymbolGolden {
    fn from(symbol: &Symbol) -> Self {
        let symbol_id = symbol.id();
        Self {
            object_id: symbol_id.object_id().as_u128(),
            source_block_number: symbol_id.sbn(),
            encoding_symbol_id: symbol_id.esi(),
            kind: match symbol.kind() {
                SymbolKind::Source => "Source".to_string(),
                SymbolKind::Repair => "Repair".to_string(),
            },
            payload_bytes: symbol.data().to_vec(),
            size: symbol.data().len(),
        }
    }
}

/// Golden artifact for a complete encoded block set.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncodedBlockGolden {
    /// Description of this test case.
    description: String,
    /// Input data (as byte array).
    input_bytes: Vec<u8>,
    /// Encoding configuration used.
    config: EncodingConfigGolden,
    /// All encoded symbols (source + repair).
    symbols: Vec<EncodedSymbolGolden>,
    /// Statistics.
    stats: EncodingStatsGolden,
}

/// Golden representation of encoding configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncodingConfigGolden {
    symbol_size: u16,
    max_block_size: usize,
    repair_overhead: f64,
    encoding_parallelism: usize,
    decoding_parallelism: usize,
    deterministic_seed: u64,
}

/// Golden representation of encoding statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncodingStatsGolden {
    source_symbols: usize,
    repair_symbols: usize,
    total_symbols: usize,
}

/// Creates a deterministic object ID for testing.
fn create_test_object_id(seed: u64) -> ObjectId {
    let mut rng = DetRng::new(seed);
    ObjectId::new_random(&mut rng)
}

/// Creates test encoding configuration.
fn create_test_encoding_config(symbol_size: u16, repair_overhead: f64) -> EncodingConfig {
    EncodingConfig {
        symbol_size,
        max_block_size: 8192, // Small for testing
        repair_overhead,
        encoding_parallelism: 1, // Single-threaded for deterministic tests
        decoding_parallelism: 1,
    }
}

/// Encodes data and collects all symbols into a golden artifact.
fn encode_to_golden(
    input: &[u8],
    config: EncodingConfig,
    seed: u64,
    description: &str,
) -> EncodedBlockGolden {
    let object_id = create_test_object_id(seed);

    let pool = SymbolPool::new(PoolConfig {
        symbol_size: config.symbol_size,
        initial_size: 64,
        max_size: 1024,
        allow_growth: true,
        growth_increment: 32,
    });

    let mut encoder = EncodingPipeline::new(config.clone(), pool);
    let symbol_iter = encoder.encode(object_id, input);

    let mut symbols = Vec::new();
    for encoded_result in symbol_iter {
        let encoded_sym = encoded_result.expect("encoding should succeed");
        let symbol = encoded_sym.into_symbol();
        symbols.push(EncodedSymbolGolden::from(&symbol));
    }

    let stats = encoder.stats();

    EncodedBlockGolden {
        description: description.to_string(),
        input_bytes: input.to_vec(),
        config: EncodingConfigGolden {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: config.repair_overhead,
            encoding_parallelism: config.encoding_parallelism,
            decoding_parallelism: config.decoding_parallelism,
            deterministic_seed: seed,
        },
        symbols,
        stats: EncodingStatsGolden {
            source_symbols: stats.source_symbols,
            repair_symbols: stats.repair_symbols,
            total_symbols: stats.source_symbols + stats.repair_symbols,
        },
    }
}

#[test]
fn test_encode_small_block_no_repair() {
    // Test encoding a small block that fits in a single source symbol with no repair overhead
    let input = b"Hello, RaptorQ!";
    let config = create_test_encoding_config(1280, 0.0); // No repair symbols
    let seed = 42;

    let golden = encode_to_golden(
        input,
        config,
        seed,
        "Small single-symbol block with no repair",
    );

    assert_json_snapshot!("encode_small_block_no_repair", golden);
}

#[test]
fn test_encode_small_block_with_repair() {
    // Test encoding a small block with repair overhead
    let input = b"Hello, RaptorQ with repair symbols!";
    let config = create_test_encoding_config(1280, 0.25); // 25% repair overhead
    let seed = 123;

    let golden = encode_to_golden(input, config, seed, "Small block with 25% repair overhead");

    assert_json_snapshot!("encode_small_block_with_repair", golden);
}

#[test]
fn test_encode_multi_symbol_block() {
    // Test encoding data that spans multiple source symbols
    let input = vec![0xAB; 3000]; // 3KB of test data
    let config = create_test_encoding_config(1000, 0.1); // 10% repair overhead, 1KB symbols
    let seed = 456;

    let golden = encode_to_golden(
        &input,
        config,
        seed,
        "Multi-symbol block (3KB data, 1KB symbols) with 10% repair",
    );

    assert_json_snapshot!("encode_multi_symbol_block", golden);
}

#[test]
fn test_encode_boundary_conditions() {
    // Test encoding at symbol size boundary
    let config = create_test_encoding_config(64, 0.5); // Small symbols, high repair overhead
    let seed = 789;

    // Exactly one symbol size
    let input_exact = vec![0x55; 64];
    let golden_exact = encode_to_golden(
        &input_exact,
        config.clone(),
        seed,
        "Exactly one symbol size with 50% repair overhead",
    );

    assert_json_snapshot!("encode_boundary_exact", golden_exact);

    // One byte over symbol size
    let input_over = vec![0x55; 65];
    let golden_over = encode_to_golden(
        &input_over,
        config,
        seed + 1,
        "One byte over symbol size with 50% repair overhead",
    );

    assert_json_snapshot!("encode_boundary_over", golden_over);
}

#[test]
fn test_encode_empty_data() {
    // Test edge case of empty input
    let input = b"";
    let config = create_test_encoding_config(1280, 0.2);
    let seed = 999;

    let golden = encode_to_golden(input, config, seed, "Empty input data");

    assert_json_snapshot!("encode_empty_data", golden);
}

#[test]
fn test_encode_deterministic_reproducibility() {
    // Test that encoding is deterministic - same input/config/seed produces identical output
    let input = b"Deterministic test data for RaptorQ encoding";
    let config = create_test_encoding_config(512, 0.15);
    let seed = 2023;

    let golden1 = encode_to_golden(input, config.clone(), seed, "First encoding");
    let golden2 = encode_to_golden(input, config, seed, "Second encoding");

    // Both should be identical
    assert_eq!(golden1.symbols, golden2.symbols);
    assert_eq!(golden1.stats.source_symbols, golden2.stats.source_symbols);
    assert_eq!(golden1.stats.repair_symbols, golden2.stats.repair_symbols);

    assert_json_snapshot!("encode_deterministic", golden1);
}

#[test]
fn test_encode_varying_sizes() {
    // Test a series of different input sizes to ensure symbol boundaries are handled correctly
    let config = create_test_encoding_config(256, 0.0); // Small symbols, no repair for simplicity
    let base_seed = 1000;

    let test_sizes = [1, 50, 100, 255, 256, 257, 500, 512, 1000];
    let mut goldens = BTreeMap::new();

    for (i, &size) in test_sizes.iter().enumerate() {
        let input = vec![(i as u8).wrapping_add(0x10); size]; // Different pattern per size
        let golden = encode_to_golden(
            &input,
            config.clone(),
            base_seed + i as u64,
            &format!("Size {size} bytes"),
        );
        goldens.insert(size, golden);
    }

    assert_json_snapshot!("encode_varying_sizes", goldens);
}

#[test]
fn test_encode_systematic_properties() {
    // Test that systematic encoding preserves source symbols
    let input = b"Systematic encoding test - source symbols should be preserved";
    let config = create_test_encoding_config(32, 1.0); // 100% repair overhead for clear source/repair split
    let seed = 1337;

    let golden = encode_to_golden(
        input,
        config,
        seed,
        "Systematic encoding with 100% repair overhead",
    );

    // Verify we have both source and repair symbols
    let source_count = golden.symbols.iter().filter(|s| s.kind == "Source").count();
    let repair_count = golden.symbols.iter().filter(|s| s.kind == "Repair").count();

    assert!(source_count > 0, "Should have source symbols");
    assert!(repair_count > 0, "Should have repair symbols");
    assert_eq!(golden.stats.source_symbols, source_count);
    assert_eq!(golden.stats.repair_symbols, repair_count);

    assert_json_snapshot!("encode_systematic", golden);
}
