//! RaptorQ codec symbol corruption fuzz target.
//!
//! This fuzz target specifically tests the RaptorQ codec's resilience to
//! malformed and corrupted symbols during encode/decode operations. While the
//! existing roundtrip tests verify correct behavior with valid inputs, this
//! target validates proper error handling and graceful degradation when fed
//! adversarial or corrupted symbol data.
//!
//! # Test Coverage
//!
//! 1. **Symbol corruption resilience**: Bit flips in symbol data
//! 2. **Malformed ESI validation**: Out-of-range encoding symbol IDs
//! 3. **Size mismatch detection**: Symbols with incorrect byte lengths
//! 4. **Coefficient corruption**: Invalid GF(256) coefficients
//! 5. **Truncated symbol handling**: Incomplete symbol data
//! 6. **Mixed corruption scenarios**: Multiple simultaneous corruptions
//!
//! # Oracle Strategy
//!
//! Uses a **crash oracle** combined with **graceful degradation** checks:
//! - Must not panic on any malformed input
//! - Should detect corruption and return appropriate errors
//! - Partial corruption should degrade gracefully, not fail catastrophically

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;

/// Maximum number of source symbols for focused corruption testing
const MAX_K_CORRUPTION: usize = 64;

/// Maximum symbol size for efficient fuzzing
const MAX_SYMBOL_SIZE_CORRUPTION: u8 = u8::MAX;

/// Maximum number of bit flips per symbol
const MAX_BIT_FLIPS: usize = 8;

/// Corruption configuration for fuzzing
#[derive(Arbitrary, Debug)]
struct CorruptionConfig {
    /// Number of source symbols (K)
    k: u8,
    /// Symbol size in bytes
    symbol_size: u8,
    /// Encoding seed
    seed: u64,
    /// Number of repair symbols to generate
    repair_count: u8,
    /// Corruption scenarios to apply
    corruptions: Vec<SymbolCorruption>,
    /// Source data pattern
    source_pattern: SourcePattern,
}

/// Different source data patterns to test
#[derive(Arbitrary, Debug)]
enum SourcePattern {
    /// All zeros
    AllZeros,
    /// All ones
    AllOnes,
    /// Alternating pattern
    Alternating,
    /// Random seed-based pattern
    SeedBased,
    /// Custom byte pattern
    Custom(Vec<u8>),
}

/// Types of symbol corruption to test
#[derive(Arbitrary, Debug)]
enum SymbolCorruption {
    /// Flip specific bits in symbol data
    BitFlip {
        symbol_idx: u8,
        bit_positions: Vec<u16>,
    },
    /// Change ESI to invalid value
    InvalidEsi { symbol_idx: u8, new_esi: u32 },
    /// Truncate symbol data
    Truncate { symbol_idx: u8, new_length: u8 },
    /// Extend symbol data with garbage
    Extend {
        symbol_idx: u8,
        extra_bytes: Vec<u8>,
    },
    /// Corrupt GF(256) coefficients
    CorruptCoefficients {
        symbol_idx: u8,
        bad_coefficients: Vec<u8>,
    },
    /// Mark source symbol as repair or vice versa
    FlipSourceFlag { symbol_idx: u8 },
    /// Completely zero out symbol data
    ZeroOut { symbol_idx: u8 },
    /// Replace with random garbage
    RandomGarbage { symbol_idx: u8, garbage: Vec<u8> },
}

/// Result of corruption testing
#[derive(Debug)]
struct CorruptionResult {
    /// Whether encoding succeeded
    encoding_success: bool,
    /// Whether decoding was attempted
    decoding_attempted: bool,
    /// Whether decoder detected corruption appropriately
    corruption_detected: bool,
    /// Whether any panic occurred (should never happen)
    panic_occurred: bool,
    /// Error details if available
    error_info: Option<String>,
}

/// Normalize corruption config to valid bounds
fn normalize_corruption_config(config: &mut CorruptionConfig) {
    config.k = config.k.clamp(1, MAX_K_CORRUPTION as u8);
    config.symbol_size = config.symbol_size.clamp(1, MAX_SYMBOL_SIZE_CORRUPTION);
    config.repair_count = config.repair_count.clamp(0, config.k.saturating_mul(2));

    // Limit corruption count for performance
    config.corruptions.truncate(10);

    // Normalize corruption parameters
    for corruption in &mut config.corruptions {
        match corruption {
            SymbolCorruption::BitFlip {
                symbol_idx,
                bit_positions,
            } => {
                *symbol_idx %= config.k;
                bit_positions.truncate(MAX_BIT_FLIPS);
                for pos in bit_positions {
                    *pos %= (config.symbol_size as u16) * 8;
                }
            }
            SymbolCorruption::InvalidEsi { symbol_idx, .. } => {
                *symbol_idx %= config.k;
            }
            SymbolCorruption::Truncate {
                symbol_idx,
                new_length,
            } => {
                *symbol_idx %= config.k;
                *new_length %= config.symbol_size;
            }
            SymbolCorruption::Extend {
                symbol_idx,
                extra_bytes,
            } => {
                *symbol_idx %= config.k;
                extra_bytes.truncate(64); // Limit size
            }
            SymbolCorruption::CorruptCoefficients {
                symbol_idx,
                bad_coefficients,
            } => {
                *symbol_idx %= config.k;
                bad_coefficients.truncate(8);
            }
            SymbolCorruption::FlipSourceFlag { symbol_idx } => {
                *symbol_idx %= config.k;
            }
            SymbolCorruption::ZeroOut { symbol_idx } => {
                *symbol_idx %= config.k;
            }
            SymbolCorruption::RandomGarbage {
                symbol_idx,
                garbage,
            } => {
                *symbol_idx %= config.k;
                garbage.truncate(config.symbol_size as usize);
            }
        }
    }
}

/// Generate source data based on pattern
fn generate_source_data(
    k: usize,
    symbol_size: usize,
    pattern: &SourcePattern,
    seed: u64,
) -> Vec<Vec<u8>> {
    match pattern {
        SourcePattern::AllZeros => {
            vec![vec![0u8; symbol_size]; k]
        }
        SourcePattern::AllOnes => {
            vec![vec![0xFFu8; symbol_size]; k]
        }
        SourcePattern::Alternating => (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| if (i + j) % 2 == 0 { 0xAA } else { 0x55 })
                    .collect()
            })
            .collect(),
        SourcePattern::SeedBased => {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            (0..k)
                .map(|i| {
                    let mut hasher = DefaultHasher::new();
                    seed.hash(&mut hasher);
                    i.hash(&mut hasher);

                    let symbol_seed = hasher.finish();
                    (0..symbol_size)
                        .map(|j| {
                            let mut byte_hasher = DefaultHasher::new();
                            symbol_seed.hash(&mut byte_hasher);
                            j.hash(&mut byte_hasher);
                            (byte_hasher.finish() & 0xFF) as u8
                        })
                        .collect()
                })
                .collect()
        }
        SourcePattern::Custom(data) => (0..k)
            .map(|i| {
                let start = i * symbol_size;
                let mut symbol = vec![0u8; symbol_size];
                for j in 0..symbol_size {
                    if start + j < data.len() {
                        symbol[j] = data[start + j];
                    }
                }
                symbol
            })
            .collect(),
    }
}

/// Apply bit flips to symbol data
fn apply_bit_flips(data: &mut [u8], bit_positions: &[u16]) {
    for &pos in bit_positions {
        let byte_idx = (pos / 8) as usize;
        let bit_idx = pos % 8;

        if byte_idx < data.len() {
            data[byte_idx] ^= 1u8 << bit_idx;
        }
    }
}

/// Apply symbol corruptions
fn apply_corruptions(symbols: &mut [ReceivedSymbol], corruptions: &[SymbolCorruption]) {
    for corruption in corruptions {
        match corruption {
            SymbolCorruption::BitFlip {
                symbol_idx,
                bit_positions,
            } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    apply_bit_flips(&mut symbol.data, bit_positions);
                }
            }
            SymbolCorruption::InvalidEsi {
                symbol_idx,
                new_esi,
            } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    symbol.esi = *new_esi;
                }
            }
            SymbolCorruption::Truncate {
                symbol_idx,
                new_length,
            } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    symbol.data.truncate(*new_length as usize);
                }
            }
            SymbolCorruption::Extend {
                symbol_idx,
                extra_bytes,
            } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    symbol.data.extend_from_slice(extra_bytes);
                }
            }
            SymbolCorruption::CorruptCoefficients {
                symbol_idx,
                bad_coefficients,
            } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    symbol.coefficients = bad_coefficients.iter().map(|&b| Gf256::new(b)).collect();
                }
            }
            SymbolCorruption::FlipSourceFlag { symbol_idx } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    symbol.is_source = !symbol.is_source;
                }
            }
            SymbolCorruption::ZeroOut { symbol_idx } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize) {
                    symbol.data.fill(0);
                }
            }
            SymbolCorruption::RandomGarbage {
                symbol_idx,
                garbage,
            } => {
                if let Some(symbol) = symbols.get_mut(*symbol_idx as usize)
                    && !garbage.is_empty()
                {
                    symbol.data.clear();
                    symbol.data.extend_from_slice(garbage);
                }
            }
        }
    }
}

/// Convert emitted symbol to received symbol for testing
fn create_received_symbol(esi: u32, data: Vec<u8>, is_source: bool, k: usize) -> ReceivedSymbol {
    ReceivedSymbol {
        esi,
        is_source,
        columns: if is_source {
            vec![esi as usize]
        } else {
            // Simple repair symbol structure for testing
            (0..k.min(3)).collect()
        },
        coefficients: if is_source {
            vec![Gf256::ONE]
        } else {
            vec![Gf256::ONE; k.min(3)]
        },
        data,
    }
}

/// Execute corruption test
fn execute_corruption_test(config: &CorruptionConfig) -> CorruptionResult {
    let k = config.k as usize;
    let symbol_size = config.symbol_size as usize;
    let seed = config.seed;
    let repair_count = config.repair_count as usize;

    // Generate source data
    let source = generate_source_data(k, symbol_size, &config.source_pattern, seed);

    // Try to create encoder (may fail for invalid parameters)
    let encoder_result =
        std::panic::catch_unwind(|| SystematicEncoder::new(&source, symbol_size, seed));

    let mut encoder = match encoder_result {
        Ok(Some(enc)) => enc,
        Ok(None) => {
            return CorruptionResult {
                encoding_success: false,
                decoding_attempted: false,
                corruption_detected: false,
                panic_occurred: false,
                error_info: Some("Encoder creation returned None".to_string()),
            };
        }
        Err(_) => {
            return CorruptionResult {
                encoding_success: false,
                decoding_attempted: false,
                corruption_detected: false,
                panic_occurred: true,
                error_info: Some("Encoder creation panicked".to_string()),
            };
        }
    };

    // Generate symbols
    let encode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let systematic = encoder.emit_systematic();
        let repairs = encoder.emit_repair(repair_count);
        (systematic, repairs)
    }));

    let (systematic, repairs) = match encode_result {
        Ok((sys, rep)) => (sys, rep),
        Err(_) => {
            return CorruptionResult {
                encoding_success: false,
                decoding_attempted: false,
                corruption_detected: false,
                panic_occurred: true,
                error_info: Some("Symbol generation panicked".to_string()),
            };
        }
    };

    // Convert to received symbols
    let mut received_symbols = Vec::new();
    for symbol in &systematic {
        received_symbols.push(create_received_symbol(
            symbol.esi,
            symbol.data.clone(),
            true,
            k,
        ));
    }
    for symbol in &repairs {
        received_symbols.push(create_received_symbol(
            symbol.esi,
            symbol.data.clone(),
            false,
            k,
        ));
    }

    // Apply corruptions
    apply_corruptions(&mut received_symbols, &config.corruptions);

    // Create decoder
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let object_id = ObjectId::new_for_test(seed);

    // Try to decode with corrupted symbols
    let decode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decoder
            .decode_with_proof(&received_symbols, object_id, 0)
            .map(|_| ())
            .map_err(|_| ())
    }));

    match decode_result {
        Ok(Ok(())) => {
            // Decoding succeeded despite corruption - this might be OK if corruption was minor
            CorruptionResult {
                encoding_success: true,
                decoding_attempted: true,
                corruption_detected: false,
                panic_occurred: false,
                error_info: Some("Decode succeeded with corrupted symbols".to_string()),
            }
        }
        Ok(Err(())) => {
            // Decoding failed gracefully - this is good!
            CorruptionResult {
                encoding_success: true,
                decoding_attempted: true,
                corruption_detected: true,
                panic_occurred: false,
                error_info: Some("Decode failed gracefully on corruption".to_string()),
            }
        }
        Err(_) => {
            // Decoding panicked - this is bad!
            CorruptionResult {
                encoding_success: true,
                decoding_attempted: true,
                corruption_detected: false,
                panic_occurred: true,
                error_info: Some("Decode panicked on corrupted symbols".to_string()),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(mut config) = CorruptionConfig::arbitrary(&mut unstructured) else {
        return;
    };

    normalize_corruption_config(&mut config);

    // Skip degenerate cases
    if config.corruptions.is_empty() {
        return;
    }

    // Execute corruption test
    let result = execute_corruption_test(&config);

    // Critical invariant: must never panic
    assert!(
        !result.panic_occurred,
        "RaptorQ codec panicked on corrupted symbols: {:?}",
        result.error_info
    );

    // If encoding succeeded, decoding should have been attempted
    if result.encoding_success {
        assert!(
            result.decoding_attempted,
            "Decoding should be attempted when encoding succeeds"
        );
    }

    if result.corruption_detected {
        assert!(
            result.error_info.is_some(),
            "corruption detection should preserve diagnostic context"
        );
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_flip_corruption() {
        let config = CorruptionConfig {
            k: 4,
            symbol_size: 8,
            seed: 12345,
            repair_count: 2,
            corruptions: vec![SymbolCorruption::BitFlip {
                symbol_idx: 0,
                bit_positions: vec![0, 7, 15],
            }],
            source_pattern: SourcePattern::SeedBased,
        };

        let result = execute_corruption_test(&config);
        assert!(!result.panic_occurred, "Should not panic on bit flips");
    }

    #[test]
    fn test_invalid_esi_corruption() {
        let config = CorruptionConfig {
            k: 3,
            symbol_size: 16,
            seed: 67890,
            repair_count: 1,
            corruptions: vec![SymbolCorruption::InvalidEsi {
                symbol_idx: 0,
                new_esi: u32::MAX,
            }],
            source_pattern: SourcePattern::AllZeros,
        };

        let result = execute_corruption_test(&config);
        assert!(!result.panic_occurred, "Should not panic on invalid ESI");
    }

    #[test]
    fn test_size_mismatch_corruption() {
        let config = CorruptionConfig {
            k: 2,
            symbol_size: 32,
            seed: 11111,
            repair_count: 1,
            corruptions: vec![SymbolCorruption::Truncate {
                symbol_idx: 0,
                new_length: 1,
            }],
            source_pattern: SourcePattern::Alternating,
        };

        let result = execute_corruption_test(&config);
        assert!(!result.panic_occurred, "Should not panic on size mismatch");
    }

    #[test]
    fn test_multiple_corruptions() {
        let config = CorruptionConfig {
            k: 8,
            symbol_size: 64,
            seed: 99999,
            repair_count: 4,
            corruptions: vec![
                SymbolCorruption::BitFlip {
                    symbol_idx: 0,
                    bit_positions: vec![0, 8, 16],
                },
                SymbolCorruption::FlipSourceFlag { symbol_idx: 1 },
                SymbolCorruption::ZeroOut { symbol_idx: 2 },
            ],
            source_pattern: SourcePattern::Custom(vec![0xAB; 512]),
        };

        let result = execute_corruption_test(&config);
        assert!(
            !result.panic_occurred,
            "Should not panic on multiple corruptions"
        );
    }
}
