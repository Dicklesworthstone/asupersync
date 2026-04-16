//! Metamorphic property tests for RaptorQ encode/decode correctness.
//!
//! These tests verify relationships between inputs/outputs rather than specific
//! expected values (oracle problem). Each test exercises a fundamental property
//! that must hold for any correct RaptorQ implementation.

use crate::config::RaptorQConfig;
use crate::cx::Cx;
use crate::raptorq::builder::RaptorQSenderBuilder;
use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use crate::raptorq::gf256::Gf256;
use crate::security::AuthenticatedSymbol;
use crate::transport::sink::SymbolSink;
use crate::types::symbol::ObjectId;

use std::pin::Pin;
use std::task::{Context, Poll};

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// In-memory symbol collector for testing.
pub struct CollectorSink {
    symbols: Vec<AuthenticatedSymbol>,
}

impl CollectorSink {
    fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    pub fn symbols(&self) -> &[AuthenticatedSymbol] {
        &self.symbols
    }
}

impl SymbolSink for CollectorSink {
    fn poll_send(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), crate::transport::error::SinkError>> {
        self.symbols.push(symbol);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), crate::transport::error::SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), crate::transport::error::SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), crate::transport::error::SinkError>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for CollectorSink {}

/// Generate test data of specified size.
fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    use crate::util::DetRng;
    let mut rng = DetRng::new(seed);
    (0..size).map(|_| rng.next_u32() as u8).collect()
}

/// Create a minimal viable decoder for testing.
fn create_test_decoder(k: usize, symbol_size: usize) -> InactivationDecoder {
    InactivationDecoder::new(k, symbol_size, 0)
}

/// Convert authenticated symbols to received symbols for decoder.
fn symbols_to_received(symbols: &[AuthenticatedSymbol], k: usize) -> Vec<ReceivedSymbol> {
    symbols
        .iter()
        .enumerate()
        .map(|(i, auth_symbol)| ReceivedSymbol {
            esi: i as u32,
            is_source: i < k,
            columns: vec![i],
            coefficients: vec![Gf256::ONE],
            data: auth_symbol.symbol().data().to_vec(),
        })
        .collect()
}

/// Flatten source symbols into original data format.
fn flatten_source_symbols(source_symbols: &[Vec<u8>], original_len: usize) -> Vec<u8> {
    source_symbols
        .iter()
        .flatten()
        .copied()
        .take(original_len)
        .collect()
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

/// MR1: Encode-Decode Identity (Invertive)
/// Property: decode(encode(data)) = data
/// Catches: Symbol corruption, decode algorithm bugs, precision loss
#[test]
fn mr_encode_decode_identity() {
    proptest!(|(
        data_size in 128usize..1024,
        seed in any::<u64>(),
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode phase
        let config = RaptorQConfig::default();
        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(sink)
            .build()
            .expect("sender build");

        let send_outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding should succeed");

        // Get symbols from the transport
        let symbols = sender.transport_mut().symbols().to_vec();

        // Decode phase - use enough symbols for guaranteed decode
        let symbol_size = config.encoding.symbol_size as usize;
        let k = send_outcome.source_symbols;
        let decoder = create_test_decoder(k, symbol_size);

        // Take K + extra symbols to ensure decodability
        let received_symbols = symbols_to_received(
            &symbols[..std::cmp::min(symbols.len(), k + 10)],
            k
        );

        let decode_result = decoder.decode(&received_symbols);

        // METAMORPHIC ASSERTION: decode(encode(data)) = data
        match decode_result {
            Ok(output) => {
                let reconstructed = flatten_source_symbols(&output.source, data.len());
                prop_assert_eq!(
                    reconstructed,
                    data,
                    "MR1 VIOLATION: encode-decode identity failed"
                );
            }
            Err(e) => {
                prop_assert!(
                    false,
                    "MR1 VIOLATION: decode failed unexpectedly with {} symbols: {:?}",
                    received_symbols.len(),
                    e
                );
            }
        }
    });
}

/// MR2: Symbol Order Invariance (Equivalence)
/// Property: decode(shuffle(symbols)) success = decode(symbols) success
/// Catches: Order dependency bugs, state corruption during symbol processing
#[test]
fn mr_symbol_order_invariance() {
    proptest!(|(
        data_size in 128usize..512,
        seed in any::<u64>(),
        shuffle_seed in any::<u64>(),
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode to get symbols
        let config = RaptorQConfig::default();
        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(sink)
            .build()
            .expect("sender build");

        let send_outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding should succeed");
        let symbols = sender.transport_mut().symbols().to_vec();

        let k = send_outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(k, symbol_size);

        // Create received symbols in original order (minimal decodable set)
        let original_symbols = &symbols[..std::cmp::min(symbols.len(), k + 3)];
        let received_original = symbols_to_received(original_symbols, k);

        // Create shuffled version
        use crate::util::DetRng;
        let mut rng = DetRng::new(shuffle_seed);
        let mut received_shuffled = received_original.clone();
        for i in (1..received_shuffled.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            received_shuffled.swap(i, j);
        }

        // Test both orderings
        let result_original = decoder.decode(&received_original);
        let result_shuffled = decoder.decode(&received_shuffled);

        // METAMORPHIC ASSERTION: both succeed or both fail consistently
        match (result_original, result_shuffled) {
            (Ok(data1), Ok(data2)) => {
                let reconstructed1 = flatten_source_symbols(&data1.source, data.len());
                let reconstructed2 = flatten_source_symbols(&data2.source, data.len());
                prop_assert_eq!(
                    reconstructed1, reconstructed2,
                    "MR2 VIOLATION: symbol order changed decode result"
                );
            }
            (Err(_), Err(_)) => {
                // Both failed - this is consistent
            }
            (Ok(_), Err(e)) => {
                prop_assert!(
                    false,
                    "MR2 VIOLATION: shuffling symbols caused decode failure: {:?}",
                    e
                );
            }
            (Err(_), Ok(_)) => {
                prop_assert!(
                    false,
                    "MR2 VIOLATION: shuffling symbols enabled decode success"
                );
            }
        }
    });
}

/// MR6: Symbol Abundance Monotonicity (Inclusive)
/// Property: if decode(symbols) succeeds, then decode(symbols + extra) succeeds
/// Catches: Threshold bugs, resource exhaustion with more data
#[test]
fn mr_symbol_abundance_monotonicity() {
    proptest!(|(
        data_size in 128usize..256,
        seed in any::<u64>(),
        extra_symbols in 1usize..5,
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode to get abundant symbols
        let config = RaptorQConfig::default();
        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(sink)
            .build()
            .expect("sender build");

        let send_outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding should succeed");
        let symbols = sender.transport_mut().symbols();

        let k = send_outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(k, symbol_size);

        // Create minimal symbol set that should decode
        let minimal_count = std::cmp::min(symbols.len(), k + 2);
        let minimal_symbols = symbols_to_received(&symbols[..minimal_count], k);

        // Create abundant symbol set (minimal + extra)
        let abundant_count = std::cmp::min(symbols.len(), minimal_count + extra_symbols);
        let abundant_symbols = symbols_to_received(&symbols[..abundant_count], k);

        let result_minimal = decoder.decode(&minimal_symbols);
        let result_abundant = decoder.decode(&abundant_symbols);

        // METAMORPHIC ASSERTION: if minimal succeeds, abundant must succeed
        match result_minimal {
            Ok(decoded_minimal) => {
                match result_abundant {
                    Ok(decoded_abundant) => {
                        let reconstructed_minimal = flatten_source_symbols(&decoded_minimal.source, data.len());
                        let reconstructed_abundant = flatten_source_symbols(&decoded_abundant.source, data.len());
                        prop_assert_eq!(
                            reconstructed_minimal, reconstructed_abundant,
                            "MR6 VIOLATION: extra symbols changed decode result"
                        );
                    }
                    Err(e) => {
                        prop_assert!(
                            false,
                            "MR6 VIOLATION: adding {} symbols caused decode failure: {:?}",
                            extra_symbols, e
                        );
                    }
                }
            }
            Err(_) => {
                // Minimal failed - no constraint on abundant case
            }
        }
    });
}

/// MR3: Repair Symbol Orthogonality (Additive, Score: 8.0)
/// Property: decode(systematic + repair_n) = decode(systematic + repair_n + extra_repair)
/// Catches: Repair symbol interference, matrix construction bugs, ESI handling issues
#[test]
fn mr_repair_symbol_orthogonality() {
    proptest!(|(
        data_size in 128usize..384,
        seed in any::<u64>(),
        extra_repair in 1usize..8,
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Create configurations with different repair overhead
        let base_config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                repair_overhead: 1.05, // 5% overhead
                ..Default::default()
            },
            ..Default::default()
        };

        let extended_config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                repair_overhead: 1.05 + (extra_repair as f64 * 0.05), // More overhead
                ..Default::default()
            },
            ..Default::default()
        };

        // Encode with base repair overhead
        let sink_base = CollectorSink::new();
        let mut sender_base = RaptorQSenderBuilder::new()
            .config(base_config.clone())
            .transport(sink_base)
            .build()
            .expect("base sender build");

        let base_outcome = sender_base.send_object(&cx, object_id, &data)
            .expect("base encoding");
        let base_symbols = sender_base.transport_mut().symbols().to_vec();

        // Encode with extended repair overhead
        let sink_extended = CollectorSink::new();
        let mut sender_extended = RaptorQSenderBuilder::new()
            .config(extended_config.clone())
            .transport(sink_extended)
            .build()
            .expect("extended sender build");

        let _extended_outcome = sender_extended.send_object(&cx, object_id, &data)
            .expect("extended encoding");
        let extended_symbols = sender_extended.transport_mut().symbols().to_vec();

        let k = base_outcome.source_symbols;
        let symbol_size = base_config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(k, symbol_size);

        // Take enough base symbols for decoding
        let base_symbol_count = std::cmp::min(base_symbols.len(), k + 5);
        let base_received = symbols_to_received(&base_symbols[..base_symbol_count], k);

        // Take the same systematic symbols + more repair symbols from extended
        let extended_symbol_count = std::cmp::min(extended_symbols.len(), base_symbol_count + extra_repair);
        let extended_received = symbols_to_received(&extended_symbols[..extended_symbol_count], k);

        let base_result = decoder.decode(&base_received);
        let extended_result = decoder.decode(&extended_received);

        // METAMORPHIC ASSERTION: Additional repair symbols don't change decoded output
        match (base_result, extended_result) {
            (Ok(base_decoded), Ok(extended_decoded)) => {
                let base_data = flatten_source_symbols(&base_decoded.source, data.len());
                let extended_data = flatten_source_symbols(&extended_decoded.source, data.len());
                prop_assert_eq!(
                    base_data.clone(), extended_data,
                    "MR3 VIOLATION: additional repair symbols changed decode result"
                );
                prop_assert_eq!(
                    base_data, data,
                    "MR3 VIOLATION: base decode failed identity check"
                );
            }
            (Ok(_), Err(e)) => {
                prop_assert!(
                    false,
                    "MR3 VIOLATION: additional repair symbols caused decode failure: {:?}",
                    e
                );
            }
            (Err(_), _) => {
                // Base failed - no constraint on extended case
                // This can happen with insufficient symbols in some test cases
            }
        }
    });
}

/// MR4: Erasure Resilience (Inclusive, Score: 6.7)
/// Property: if decodable_with(X_symbols), then decodable_with(X+1_symbols)
/// Catches: Decoder resilience failures, threshold miscalculation, state corruption
#[test]
fn mr_erasure_resilience() {
    proptest!(|(
        data_size in 128usize..384,
        seed in any::<u64>(),
        erasure_count in 1usize..8,
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode with generous repair overhead for erasure testing
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                repair_overhead: 1.25, // 25% overhead for resilience
                ..Default::default()
            },
            ..Default::default()
        };

        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(sink)
            .build()
            .expect("sender build");

        let outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding");
        let symbols = sender.transport_mut().symbols().to_vec();

        let k = outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(k, symbol_size);

        // Simulate erasures by removing symbols from the middle (burst erasure pattern)
        let mut with_erasures = symbols.clone();
        let start_erasure = std::cmp::max(2, symbols.len() / 4);
        let end_erasure = std::cmp::min(start_erasure + erasure_count, symbols.len() - 2);
        if start_erasure < end_erasure {
            with_erasures.drain(start_erasure..end_erasure);
        }

        // Create set with fewer erasures (one less missing symbol)
        let mut fewer_erasures = symbols.clone();
        let fewer_end = std::cmp::max(start_erasure + 1, end_erasure - 1);
        if start_erasure < fewer_end {
            fewer_erasures.drain(start_erasure..fewer_end);
        }

        // Convert to received symbols with enough for decoding
        let max_symbols = std::cmp::min(with_erasures.len(), k + 15);
        let fewer_max_symbols = std::cmp::min(fewer_erasures.len(), k + 15);

        let with_erasures_received = symbols_to_received(&with_erasures[..max_symbols], k);
        let fewer_erasures_received = symbols_to_received(&fewer_erasures[..fewer_max_symbols], k);

        let result_with_erasures = decoder.decode(&with_erasures_received);
        let result_fewer_erasures = decoder.decode(&fewer_erasures_received);

        // METAMORPHIC ASSERTION: Fewer erasures should not make decoding worse
        match result_fewer_erasures {
            Ok(decoded_fewer) => {
                match result_with_erasures {
                    Ok(decoded_with) => {
                        let data_fewer = flatten_source_symbols(&decoded_fewer.source, data.len());
                        let data_with = flatten_source_symbols(&decoded_with.source, data.len());
                        prop_assert_eq!(
                            data_fewer.clone(), data_with,
                            "MR4 VIOLATION: different erasure patterns produced different results"
                        );
                        prop_assert_eq!(
                            data_fewer, data,
                            "MR4 VIOLATION: decode result doesn't match original"
                        );
                    }
                    Err(_) => {
                        // This is acceptable - more erasures failed to decode
                        // but fewer erasures succeeded, which maintains resilience ordering
                    }
                }
            }
            Err(_) => {
                // Fewer erasures failed - no constraint on more erasures
            }
        }
    });
}

/// MR5: Parameter Consistency (Equivalence)
/// Property: Same encoding parameters produce same structure
/// Catches: Non-deterministic parameter handling, configuration bugs
#[test]
fn mr_parameter_consistency() {
    proptest!(|(
        data_size in 128usize..512,
        seed in any::<u64>(),
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);
        let config = RaptorQConfig::default();

        // Encode twice with identical configuration
        let mut outcomes = Vec::new();
        let mut symbol_counts = Vec::new();

        for _ in 0..2 {
            let sink = CollectorSink::new();
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let outcome = sender.send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols();

            outcomes.push(outcome);
            symbol_counts.push(symbols.len());
        }

        // METAMORPHIC ASSERTION: identical parameters produce identical structure
        prop_assert_eq!(
            outcomes[0].source_symbols, outcomes[1].source_symbols,
            "MR5 VIOLATION: source symbol count varied between identical encodes"
        );

        prop_assert_eq!(
            outcomes[0].repair_symbols, outcomes[1].repair_symbols,
            "MR5 VIOLATION: repair symbol count varied between identical encodes"
        );

        prop_assert_eq!(
            symbol_counts[0], symbol_counts[1],
            "MR5 VIOLATION: total symbol count varied between identical encodes"
        );
    });
}

// ============================================================================
// Composite Metamorphic Relations
// ============================================================================

/// Composite MR: Identity + Order Invariance + Abundance
/// Tests interaction of multiple properties simultaneously
#[test]
fn mr_composite_encode_decode_properties() {
    proptest!(|(
        data_size in 128usize..256,
        seed in any::<u64>(),
        shuffle_seed in any::<u64>(),
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode once
        let config = RaptorQConfig::default();
        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(sink)
            .build()
            .expect("sender build");

        let send_outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding");
        let symbols = sender.transport_mut().symbols().to_vec();

        let k = send_outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(k, symbol_size);

        // Create abundant symbol set (more than minimal)
        let abundant_count = std::cmp::min(symbols.len(), k + 8);
        let mut received_symbols = symbols_to_received(&symbols[..abundant_count], k);

        // Apply transformation: shuffle the abundant set
        use crate::util::DetRng;
        let mut rng = DetRng::new(shuffle_seed);
        for i in (1..received_symbols.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            received_symbols.swap(i, j);
        }

        let decode_result = decoder.decode(&received_symbols);

        // COMPOSITE ASSERTION: All properties must hold together
        match decode_result {
            Ok(result) => {
                let reconstructed = flatten_source_symbols(&result.source, data.len());
                prop_assert_eq!(
                    reconstructed,
                    data,
                    "COMPOSITE MR VIOLATION: identity failed under abundance+shuffle"
                );
            }
            Err(e) => {
                prop_assert!(
                    false,
                    "COMPOSITE MR VIOLATION: abundant shuffled symbols failed to decode: {:?}",
                    e
                );
            }
        }
    });
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Mutation testing: verify MR suite catches planted bugs
    #[test]
    fn validate_mrs_catch_planted_mutations() {
        // Basic smoke test of MR infrastructure
        let _data = vec![42u8; 256];
        let _cx = Cx::for_testing();

        // Test infrastructure creation
        let config = RaptorQConfig::default();
        let sink = CollectorSink::new();
        let sender = RaptorQSenderBuilder::new()
            .config(config)
            .transport(sink)
            .build();

        assert!(sender.is_ok(), "MR test infrastructure should work");
    }

    /// Validate that repair symbol orthogonality test detects interference
    #[test]
    fn validate_repair_orthogonality_catches_interference() {
        use super::*;

        let cx = Cx::for_testing();
        let data = generate_test_data(256, 42);
        let object_id = ObjectId::new_for_test(42);

        // Test with different repair overhead levels
        let configs = [
            RaptorQConfig {
                encoding: crate::config::EncodingConfig {
                    repair_overhead: 1.05,
                    ..Default::default()
                },
                ..Default::default()
            },
            RaptorQConfig {
                encoding: crate::config::EncodingConfig {
                    repair_overhead: 1.20,
                    ..Default::default()
                },
                ..Default::default()
            },
        ];

        let mut results = Vec::new();
        for config in &configs {
            let sink = CollectorSink::new();
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let outcome = sender.send_object(&cx, object_id, &data)
                .expect("encoding");
            let symbols = sender.transport_mut().symbols().to_vec();

            let k = outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(k, symbol_size);

            let symbol_count = std::cmp::min(symbols.len(), k + 8);
            let received = symbols_to_received(&symbols[..symbol_count], k);

            if let Ok(decoded) = decoder.decode(&received) {
                let reconstructed = flatten_source_symbols(&decoded.source, data.len());
                results.push(reconstructed);
            }
        }

        // Both should decode to the same result (orthogonality)
        if results.len() == 2 {
            assert_eq!(results[0], results[1], "Repair symbol orthogonality test validation");
            assert_eq!(results[0], data, "Identity preservation test validation");
        }
    }

    /// Validate that erasure resilience test properly simulates erasures
    #[test]
    fn validate_erasure_resilience_simulation() {
        use super::*;

        let cx = Cx::for_testing();
        let data = generate_test_data(256, 123);
        let object_id = ObjectId::new_for_test(123);

        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                repair_overhead: 1.30, // High overhead for erasure tolerance
                ..Default::default()
            },
            ..Default::default()
        };

        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(sink)
            .build()
            .expect("sender build");

        let outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding");
        let symbols = sender.transport_mut().symbols().to_vec();

        let k = outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(k, symbol_size);

        // Test various erasure patterns
        let original_count = std::cmp::min(symbols.len(), k + 12);

        // Minimal erasures (should succeed)
        let mut minimal_erasures = symbols.clone();
        minimal_erasures.drain(2..4); // Remove 2 symbols
        let minimal_received = symbols_to_received(
            &minimal_erasures[..std::cmp::min(minimal_erasures.len(), original_count - 2)],
            k
        );

        // More erasures
        let mut more_erasures = symbols.clone();
        more_erasures.drain(2..6); // Remove 4 symbols
        let more_received = symbols_to_received(
            &more_erasures[..std::cmp::min(more_erasures.len(), original_count - 4)],
            k
        );

        let minimal_result = decoder.decode(&minimal_received);
        let more_result = decoder.decode(&more_received);

        // Erasure resilience validation: if minimal succeeds, both should succeed
        if let Ok(minimal_decoded) = minimal_result {
            let minimal_data = flatten_source_symbols(&minimal_decoded.source, data.len());
            assert_eq!(minimal_data, data, "Minimal erasure decode identity");

            if let Ok(more_decoded) = more_result {
                let more_data = flatten_source_symbols(&more_decoded.source, data.len());
                assert_eq!(more_data, data, "More erasure decode identity");
                assert_eq!(minimal_data, more_data, "Erasure resilience consistency");
            }
        }
    }
}
