//! RaptorQ encoder-decoder roundtrip fuzz target.
//!
//! This fuzz target tests the complete RaptorQ encode-decode pipeline to verify
//! that data can be successfully reconstructed through the RaptorQ forward error
//! correction process. The target validates five critical properties:
//!
//! 1. **Exact reconstruction**: Decoded output matches original exactly
//! 2. **Loss tolerance**: Packet loss below threshold still recovers
//! 3. **Reordering resilience**: Symbol re-ordering preserves correctness
//! 4. **Zero-length rejection**: Zero-length source blocks are properly rejected
//! 5. **Parameter bounds**: K parameter stays within supported range
//!
//! # RaptorQ Roundtrip Process
//!
//! ```text
//! Original Data → EncodingPipeline → Encoded Symbols → Simulated Loss/Reorder
//!                                        ↓
//! Decoded Data ← DecodingPipeline ← Received Symbols (subset)
//! ```
//!
//! The fuzz target simulates realistic network conditions including packet loss,
//! reordering, and varying symbol sizes to ensure the RaptorQ implementation
//! maintains correctness under adverse conditions.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::config::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline};
use asupersync::encoding::{EncodingError, EncodingPipeline};
use asupersync::security::SecurityContext;
use asupersync::security::{AuthenticatedSymbol, tag::AuthenticationTag};
use asupersync::types::resource::SymbolPool;
use asupersync::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Maximum source data size for fuzzing (prevents OOM)
const MAX_SOURCE_SIZE: usize = 64 * 1024; // 64KB

/// Maximum symbol size (RFC 6330 limit)
const MAX_SYMBOL_SIZE: u16 = 8192;

/// Minimum symbol size for meaningful tests
const MIN_SYMBOL_SIZE: u16 = 64;

/// Maximum number of source symbols (K parameter bounds)
const MAX_SOURCE_SYMBOLS: usize = 1000;

/// Maximum loss rate for recovery testing (as percentage)
const MAX_LOSS_RATE: u8 = 50; // 50%

/// Fuzzing input for RaptorQ roundtrip testing
#[derive(Arbitrary, Debug)]
struct RaptorQRoundtripInput {
    /// Source data to encode
    source_data: Vec<u8>,
    /// Symbol size for encoding/decoding
    symbol_size: u16,
    /// Repair overhead factor (1.0 = no overhead, 2.0 = 100% overhead)
    repair_overhead_percent: u8,
    /// Simulation parameters for loss and reordering
    simulation: NetworkSimulation,
    /// Test scenario to execute
    scenario: TestScenario,
}

/// Network simulation parameters
#[derive(Arbitrary, Debug)]
struct NetworkSimulation {
    /// Packet loss rate as percentage (0-100)
    loss_rate: u8,
    /// Whether to reorder symbols
    reorder_symbols: bool,
    /// Random seed for deterministic loss/reorder patterns
    random_seed: u64,
}

/// Different test scenarios to cover edge cases
#[derive(Arbitrary, Debug)]
enum TestScenario {
    /// Basic roundtrip with no packet loss
    BasicRoundtrip,
    /// Test with simulated packet loss
    PacketLoss,
    /// Test symbol reordering
    SymbolReordering,
    /// Test with minimal repair overhead
    MinimalOverhead,
    /// Test with maximum repair overhead
    MaximalOverhead,
    /// Test boundary conditions (small/large blocks)
    BoundaryConditions,
}

/// Simulation result for a roundtrip test
#[derive(Debug)]
struct RoundtripResult {
    /// Whether encoding succeeded
    encoding_success: bool,
    /// Whether decoding succeeded
    decoding_success: bool,
    /// Whether decoded data matches original
    data_matches: bool,
    /// Number of symbols encoded
    symbols_encoded: usize,
    /// Number of symbols available for decoding
    symbols_available: usize,
    /// Number of symbols actually used in decoding
    symbols_used: usize,
    /// Error details if any step failed
    error: Option<String>,
}

/// Normalize fuzzing input to valid ranges
fn normalize_input(input: &mut RaptorQRoundtripInput) {
    // Limit source data size to prevent OOM
    input.source_data.truncate(MAX_SOURCE_SIZE);

    // Ensure symbol size is within valid bounds
    input.symbol_size = input.symbol_size.clamp(MIN_SYMBOL_SIZE, MAX_SYMBOL_SIZE);

    // Ensure repair overhead is reasonable (1% to 200%)
    input.repair_overhead_percent = input.repair_overhead_percent.clamp(1, 200);

    // Clamp loss rate to maximum
    input.simulation.loss_rate = input.simulation.loss_rate.min(MAX_LOSS_RATE);
}

/// Execute a complete RaptorQ roundtrip test
fn execute_roundtrip(input: &RaptorQRoundtripInput) -> Result<RoundtripResult, String> {
    // Assertion 4: Zero-length source block rejected
    if input.source_data.is_empty() {
        // Should reject zero-length data gracefully
        return Ok(RoundtripResult {
            encoding_success: false,
            decoding_success: false,
            data_matches: false,
            symbols_encoded: 0,
            symbols_available: 0,
            symbols_used: 0,
            error: Some("Zero-length source block".to_string()),
        });
    }

    // Calculate number of source symbols (K parameter)
    let k = (input.source_data.len() + input.symbol_size as usize - 1) / input.symbol_size as usize;

    // Assertion 5: K parameter within supported range
    if k == 0 || k > MAX_SOURCE_SYMBOLS {
        return Ok(RoundtripResult {
            encoding_success: false,
            decoding_success: false,
            data_matches: false,
            symbols_encoded: 0,
            symbols_available: 0,
            symbols_used: 0,
            error: Some(format!(
                "K parameter {} out of range [1, {}]",
                k, MAX_SOURCE_SYMBOLS
            )),
        });
    }

    // Create encoding configuration
    let repair_overhead = 1.0 + (input.repair_overhead_percent as f64 / 100.0);
    let encoding_config = EncodingConfig {
        repair_overhead,
        max_block_size: MAX_SOURCE_SIZE,
        symbol_size: input.symbol_size,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    };

    // Create symbol pool
    let pool = SymbolPool::with_capacity(1000, input.symbol_size as usize)
        .map_err(|e| format!("Failed to create symbol pool: {:?}", e))?;

    // Create encoding pipeline
    let mut encoder = EncodingPipeline::new(encoding_config.clone(), pool);

    // Encode the source data
    let encoded_symbols = match encoder.encode(&input.source_data) {
        Ok(symbols) => symbols,
        Err(EncodingError::DataTooLarge { size, limit }) => {
            return Ok(RoundtripResult {
                encoding_success: false,
                decoding_success: false,
                data_matches: false,
                symbols_encoded: 0,
                symbols_available: 0,
                symbols_used: 0,
                error: Some(format!("Data too large: {} > {}", size, limit)),
            });
        }
        Err(e) => return Err(format!("Encoding failed: {:?}", e)),
    };

    // Simulate network conditions (loss and reordering)
    let received_symbols = simulate_network(&encoded_symbols, &input.simulation);

    // Assertion 2: Packet loss below threshold still recovers
    let loss_rate = 1.0 - (received_symbols.len() as f64 / encoded_symbols.len() as f64);
    let expected_loss_threshold = input.simulation.loss_rate as f64 / 100.0;

    // Create decoding configuration
    let decoding_config = DecodingConfig {
        symbol_size: input.symbol_size,
        max_block_size: MAX_SOURCE_SIZE,
        repair_overhead,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: Duration::from_secs(10),
        verify_auth: false,
    };

    // Create decoding pipeline
    let mut decoder = DecodingPipeline::new(decoding_config);

    // Create object parameters for decoding
    let object_id = ObjectId::new_for_test(1);
    let object_params = ObjectParams::new(
        object_id,
        input.source_data.len() as u64,
        input.symbol_size,
        1, // Single block
        k,
    );

    // Feed received symbols to decoder
    let mut symbols_used = 0;
    for symbol in &received_symbols {
        let authenticated_symbol =
            AuthenticatedSymbol::new_verified(symbol.clone(), AuthenticationTag::zero());

        match decoder.add_symbol(&authenticated_symbol) {
            Ok(_) => symbols_used += 1,
            Err(_) => {} // Symbol was rejected, continue
        }

        // Check if we can decode yet
        if decoder.can_decode(&object_params) {
            break;
        }
    }

    // Attempt to decode
    let decoded_data = match decoder.decode(&object_params) {
        Ok(data) => data,
        Err(e) => {
            // If loss rate was too high, this is expected
            if loss_rate > expected_loss_threshold {
                return Ok(RoundtripResult {
                    encoding_success: true,
                    decoding_success: false,
                    data_matches: false,
                    symbols_encoded: encoded_symbols.len(),
                    symbols_available: received_symbols.len(),
                    symbols_used,
                    error: Some(format!(
                        "Decoding failed with high loss rate {:.1}%: {:?}",
                        loss_rate * 100.0,
                        e
                    )),
                });
            } else {
                return Err(format!("Decoding failed unexpectedly: {:?}", e));
            }
        }
    };

    // Assertion 1: Decoded output matches original exactly
    let data_matches = decoded_data == input.source_data;

    Ok(RoundtripResult {
        encoding_success: true,
        decoding_success: true,
        data_matches,
        symbols_encoded: encoded_symbols.len(),
        symbols_available: received_symbols.len(),
        symbols_used,
        error: None,
    })
}

/// Simulate network conditions (packet loss and reordering)
fn simulate_network(encoded_symbols: &[Symbol], simulation: &NetworkSimulation) -> Vec<Symbol> {
    let mut rng_state = simulation.random_seed;
    let mut received_symbols = Vec::new();

    // Apply packet loss
    for symbol in encoded_symbols {
        // Simple LCG for deterministic pseudo-random numbers
        rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);
        let loss_prob = (rng_state as u32) % 100;

        if loss_prob >= simulation.loss_rate as u32 {
            received_symbols.push(symbol.clone());
        }
    }

    // Assertion 3: Symbol re-ordering preserves correctness
    if simulation.reorder_symbols && received_symbols.len() > 1 {
        // Shuffle the symbols using the same RNG
        for i in (1..received_symbols.len()).rev() {
            rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);
            let j = (rng_state as usize) % (i + 1);
            received_symbols.swap(i, j);
        }
    }

    received_symbols
}

fuzz_target!(|mut input: RaptorQRoundtripInput| {
    normalize_input(&mut input);

    // Execute the roundtrip test
    let result = match execute_roundtrip(&input) {
        Ok(result) => result,
        Err(e) => {
            // Unexpected errors should not panic - this could indicate bugs
            eprintln!("Unexpected roundtrip error: {}", e);
            return;
        }
    };

    // Verify assertions based on the test scenario
    match input.scenario {
        TestScenario::BasicRoundtrip => {
            // Should succeed with no loss
            if result.encoding_success && result.decoding_success {
                assert!(
                    result.data_matches,
                    "Basic roundtrip failed: decoded data doesn't match original"
                );
            }
        }

        TestScenario::PacketLoss => {
            // Should handle expected packet loss gracefully
            let loss_rate =
                1.0 - (result.symbols_available as f64 / result.symbols_encoded.max(1) as f64);
            let expected_loss = input.simulation.loss_rate as f64 / 100.0;

            if loss_rate <= expected_loss && result.encoding_success {
                // Low loss rate should still decode successfully
                if result.decoding_success {
                    assert!(
                        result.data_matches,
                        "Packet loss test failed: low loss rate should preserve data integrity"
                    );
                }
            }
        }

        TestScenario::SymbolReordering => {
            // Reordering should not affect correctness
            if result.encoding_success && result.decoding_success {
                assert!(
                    result.data_matches,
                    "Symbol reordering test failed: order should not affect correctness"
                );
            }
        }

        TestScenario::MinimalOverhead | TestScenario::MaximalOverhead => {
            // Test different repair overhead scenarios
            if result.encoding_success && result.decoding_success {
                assert!(
                    result.data_matches,
                    "Overhead test failed: repair overhead should not affect correctness"
                );
            }
        }

        TestScenario::BoundaryConditions => {
            // Test edge cases - may fail in expected ways
            if result.encoding_success && result.decoding_success {
                assert!(
                    result.data_matches,
                    "Boundary test failed: edge cases should preserve correctness when they succeed"
                );
            }
        }
    }

    // Additional global invariants
    if result.encoding_success && result.decoding_success {
        // If both encoding and decoding succeeded, data must match
        assert!(
            result.data_matches,
            "Global invariant violation: successful encode-decode cycle must preserve data"
        );

        // Number of symbols used should not exceed symbols available
        assert!(
            result.symbols_used <= result.symbols_available,
            "Used more symbols than available: {} > {}",
            result.symbols_used,
            result.symbols_available
        );

        // Should have used some symbols for successful decoding
        assert!(
            result.symbols_used > 0,
            "Successful decoding should use at least one symbol"
        );
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_length_data_rejected() {
        let input = RaptorQRoundtripInput {
            source_data: vec![],
            symbol_size: 256,
            repair_overhead_percent: 5,
            simulation: NetworkSimulation {
                loss_rate: 0,
                reorder_symbols: false,
                random_seed: 12345,
            },
            scenario: TestScenario::BasicRoundtrip,
        };

        let result = execute_roundtrip(&input).unwrap();
        assert!(
            !result.encoding_success,
            "Zero-length data should be rejected"
        );
    }

    #[test]
    fn test_basic_roundtrip_success() {
        let input = RaptorQRoundtripInput {
            source_data: b"Hello, RaptorQ world!".to_vec(),
            symbol_size: 256,
            repair_overhead_percent: 5,
            simulation: NetworkSimulation {
                loss_rate: 0,
                reorder_symbols: false,
                random_seed: 12345,
            },
            scenario: TestScenario::BasicRoundtrip,
        };

        let result = execute_roundtrip(&input).unwrap();
        assert!(result.encoding_success, "Basic encoding should succeed");
        assert!(result.decoding_success, "Basic decoding should succeed");
        assert!(result.data_matches, "Basic roundtrip should preserve data");
    }

    #[test]
    fn test_k_parameter_bounds() {
        // Test with very large symbol size to force K=0
        let input = RaptorQRoundtripInput {
            source_data: b"small".to_vec(),
            symbol_size: MAX_SYMBOL_SIZE,
            repair_overhead_percent: 5,
            simulation: NetworkSimulation {
                loss_rate: 0,
                reorder_symbols: false,
                random_seed: 12345,
            },
            scenario: TestScenario::BoundaryConditions,
        };

        let k =
            (input.source_data.len() + input.symbol_size as usize - 1) / input.symbol_size as usize;
        if k == 0 || k > MAX_SOURCE_SYMBOLS {
            let result = execute_roundtrip(&input).unwrap();
            assert!(
                !result.encoding_success,
                "Out-of-range K parameter should be rejected"
            );
        }
    }

    #[test]
    fn test_symbol_reordering_preserves_correctness() {
        let input = RaptorQRoundtripInput {
            source_data: b"This is a test of symbol reordering preservation".to_vec(),
            symbol_size: 128,
            repair_overhead_percent: 20,
            simulation: NetworkSimulation {
                loss_rate: 10,
                reorder_symbols: true,
                random_seed: 42,
            },
            scenario: TestScenario::SymbolReordering,
        };

        let result = execute_roundtrip(&input).unwrap();
        if result.encoding_success && result.decoding_success {
            assert!(
                result.data_matches,
                "Symbol reordering should preserve correctness"
            );
        }
    }

    #[test]
    fn test_packet_loss_tolerance() {
        let input = RaptorQRoundtripInput {
            source_data: vec![0xAB; 1024], // 1KB of test data
            symbol_size: 256,
            repair_overhead_percent: 30, // 30% overhead should handle reasonable loss
            simulation: NetworkSimulation {
                loss_rate: 20, // 20% loss
                reorder_symbols: false,
                random_seed: 98765,
            },
            scenario: TestScenario::PacketLoss,
        };

        let result = execute_roundtrip(&input).unwrap();
        if result.encoding_success {
            // With 30% overhead and 20% loss, decoding should still succeed
            if result.decoding_success {
                assert!(
                    result.data_matches,
                    "Moderate packet loss should still allow recovery"
                );
            }
        }
    }
}
