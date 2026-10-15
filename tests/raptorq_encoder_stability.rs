//! RaptorQ encoder stability tests with golden snapshots.
//!
//! These tests capture canonical encoder output for fixed seeds and detect
//! non-determinism or unintended changes in RaptorQ encoder behavior.
//!
//! Pattern: Exact Golden (insta snapshots) - encoder output should be
//! deterministic for given (source_data, symbol_size, seed) inputs.

use asupersync::raptorq::systematic::SystematicEncoder;
use insta::assert_debug_snapshot;
use serde::Serialize;
use std::collections::BTreeMap;

/// Canonical test configuration for encoder stability testing.
#[derive(Debug, Clone, Serialize)]
struct EncoderTestCase {
    k: usize,
    symbol_size: usize,
    seed: u64,
    repair_count: usize,
}

/// Captured encoder output for golden comparison.
#[derive(Debug, Serialize)]
struct EncoderOutput {
    config: EncoderTestCase,
    source_symbols_hash: String,
    repair_symbols: Vec<RepairSymbolData>,
    params_summary: BTreeMap<String, usize>,
}

/// Individual repair symbol data for golden comparison.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct RepairSymbolData {
    esi: u32,
    symbol_data_hex: String,
    symbol_length: usize,
}

impl EncoderTestCase {
    const fn new(k: usize, symbol_size: usize, seed: u64, repair_count: usize) -> Self {
        Self {
            k,
            symbol_size,
            seed,
            repair_count,
        }
    }
}

/// Generate deterministic source symbols for testing.
/// Uses fixed pattern based on K and symbol_size to ensure reproducibility.
fn generate_deterministic_source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..symbol_size)
                .map(|j| {
                    // Deterministic pattern: combines symbol index and byte position
                    ((i * 37 + j * 13 + 7) % 256) as u8
                })
                .collect()
        })
        .collect()
}

/// Capture encoder output as structured data for golden comparison.
fn capture_encoder_output(test_case: &EncoderTestCase) -> EncoderOutput {
    let source_symbols = generate_deterministic_source_symbols(test_case.k, test_case.symbol_size);

    // Create encoder with fixed seed for deterministic output
    let encoder = SystematicEncoder::new(&source_symbols, test_case.symbol_size, test_case.seed)
        .expect("encoder creation should succeed");

    // Hash source symbols for verification
    let source_hash = {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        source_symbols.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };

    // Capture repair symbols
    let mut repair_symbols = Vec::new();
    for i in 0..test_case.repair_count {
        let esi = (test_case.k + i) as u32;
        let symbol_data = encoder.repair_symbol(esi);

        repair_symbols.push(RepairSymbolData {
            esi,
            symbol_data_hex: hex::encode(&symbol_data),
            symbol_length: symbol_data.len(),
        });
    }

    // Capture key encoder parameters for stability tracking
    let params = encoder.params();
    let mut params_summary = BTreeMap::new();
    params_summary.insert("k".to_string(), params.k);
    params_summary.insert("k_prime".to_string(), params.k_prime);
    params_summary.insert("l".to_string(), params.l);
    params_summary.insert("s".to_string(), params.s);
    params_summary.insert("h".to_string(), params.h);
    params_summary.insert("w".to_string(), params.w);

    EncoderOutput {
        config: test_case.clone(),
        source_symbols_hash: source_hash,
        repair_symbols,
        params_summary,
    }
}

#[test]
fn test_encoder_stability_k10() {
    let test_case = EncoderTestCase::new(10, 64, 0x12345678, 5);
    let output = capture_encoder_output(&test_case);

    // Golden snapshot for K=10 case
    assert_debug_snapshot!("encoder_k10_seed12345678", output);
}

#[test]
fn test_encoder_stability_k100() {
    let test_case = EncoderTestCase::new(100, 128, 0xDEADBEEF, 10);
    let output = capture_encoder_output(&test_case);

    // Golden snapshot for K=100 case
    assert_debug_snapshot!("encoder_k100_seed_deadbeef", output);
}

#[test]
fn test_encoder_stability_k1000() {
    let test_case = EncoderTestCase::new(1000, 256, 0xCAFEBABE, 15);
    let output = capture_encoder_output(&test_case);

    // Golden snapshot for K=1000 case
    assert_debug_snapshot!("encoder_k1000_seed_cafebabe", output);
}

#[test]
fn test_encoder_determinism_multiple_runs() {
    // Verify encoder produces identical output across multiple runs
    let test_case = EncoderTestCase::new(50, 64, 0x42424242, 8);

    let output1 = capture_encoder_output(&test_case);
    let output2 = capture_encoder_output(&test_case);
    let output3 = capture_encoder_output(&test_case);

    // All outputs should be identical for determinism
    assert_eq!(output1.source_symbols_hash, output2.source_symbols_hash);
    assert_eq!(output1.repair_symbols, output2.repair_symbols);
    assert_eq!(output1.repair_symbols, output3.repair_symbols);

    // Capture one as golden for regression detection
    assert_debug_snapshot!("encoder_determinism_k50_seed42424242", output1);
}

#[test]
fn test_encoder_seed_independence() {
    // The seed is recorded for provenance but RFC tuple generation is currently
    // deterministic for a given source block and symbol size.
    let base_config = EncoderTestCase::new(25, 64, 0, 5);
    let config_seed1 = EncoderTestCase::new(25, 64, 1, 5);
    let config_seed2 = EncoderTestCase::new(25, 64, 0xFFFFFFFF, 5);

    let output_base = capture_encoder_output(&base_config);
    let output_seed1 = capture_encoder_output(&config_seed1);
    let output_seed2 = capture_encoder_output(&config_seed2);

    // Source symbols should be same (same K, symbol_size)
    assert_eq!(
        output_base.source_symbols_hash,
        output_seed1.source_symbols_hash
    );
    assert_eq!(
        output_base.source_symbols_hash,
        output_seed2.source_symbols_hash
    );

    assert_eq!(output_base.repair_symbols, output_seed1.repair_symbols);
    assert_eq!(output_base.repair_symbols, output_seed2.repair_symbols);
    assert_eq!(output_seed1.repair_symbols, output_seed2.repair_symbols);

    // Capture all as goldens to detect regressions
    assert_debug_snapshot!("encoder_seed_0", output_base);
    assert_debug_snapshot!("encoder_seed_1", output_seed1);
    assert_debug_snapshot!("encoder_seed_ffffffff", output_seed2);
}

#[test]
fn test_encoder_parameter_stability() {
    // Verify RFC 6330 parameter derivation remains stable
    let test_cases = [
        (10, 64),
        (100, 128),
        (1000, 256),
        (256, 1316), // Common RaptorQ symbol size
        (1024, 1316),
    ];

    let mut all_params = BTreeMap::new();

    for (k, symbol_size) in test_cases {
        let test_case = EncoderTestCase::new(k, symbol_size, 0, 1);
        let output = capture_encoder_output(&test_case);

        all_params.insert(format!("k{}_s{}", k, symbol_size), output.params_summary);
    }

    // Golden snapshot for parameter stability across configurations
    assert_debug_snapshot!("encoder_rfc6330_parameters", all_params);
}

#[test]
fn test_encoder_symbol_size_consistency() {
    // Verify repair symbols always match expected symbol_size
    let test_cases = [
        (10, 32, 0x11111111, 3),
        (20, 64, 0x22222222, 3),
        (50, 128, 0x33333333, 3),
        (100, 256, 0x44444444, 3),
    ];

    for (k, symbol_size, seed, repair_count) in test_cases {
        let test_case = EncoderTestCase::new(k, symbol_size, seed, repair_count);
        let output = capture_encoder_output(&test_case);

        // Every repair symbol should have exactly symbol_size bytes
        for repair in &output.repair_symbols {
            assert_eq!(
                repair.symbol_length, symbol_size,
                "Repair symbol ESI {} has wrong length: {} != {}",
                repair.esi, repair.symbol_length, symbol_size
            );

            // Verify hex encoding length consistency
            assert_eq!(
                repair.symbol_data_hex.len(),
                symbol_size * 2,
                "Hex encoding length mismatch for ESI {}: {} != {}",
                repair.esi,
                repair.symbol_data_hex.len(),
                symbol_size * 2
            );
        }
    }

    // Capture final test case as golden
    let final_test = EncoderTestCase::new(100, 256, 0x44444444, 3);
    let final_output = capture_encoder_output(&final_test);
    assert_debug_snapshot!("encoder_symbol_size_consistency", final_output);
}
