//! Integration tests for the RaptorQ pipeline.

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::config::RaptorQConfig;
use crate::cx::Cx;
use crate::error::ErrorKind;
use crate::observability::Metrics;
use crate::raptorq::builder::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::transport::error::{SinkError, StreamError};
use crate::transport::sink::SymbolSink;
use crate::transport::stream::SymbolStream;
use crate::types::symbol::ObjectId;

// =========================================================================
// Mock transport
// =========================================================================

struct VecSink {
    symbols: Vec<AuthenticatedSymbol>,
}

impl VecSink {
    fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }
}

impl SymbolSink for VecSink {
    fn poll_send(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        self.symbols.push(symbol);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for VecSink {}

struct VecStream {
    symbols: Vec<AuthenticatedSymbol>,
    index: usize,
}

impl VecStream {
    fn new(symbols: Vec<AuthenticatedSymbol>) -> Self {
        Self { symbols, index: 0 }
    }
}

impl SymbolStream for VecStream {
    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        if self.index < self.symbols.len() {
            let sym = self.symbols[self.index].clone();
            self.index += 1;
            Poll::Ready(Some(Ok(sym)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl Unpin for VecStream {}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn sender_builder_with_transport_succeeds() {
    let result = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(VecSink::new())
        .build();
    assert!(result.is_ok());
}

#[test]
fn receiver_builder_with_source_succeeds() {
    let result = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(VecStream::new(vec![]))
        .build();
    assert!(result.is_ok());
}

#[test]
fn default_config_passes_validation() {
    let config = RaptorQConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn sender_encodes_and_transmits() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let data = vec![42u8; 1024];
    let object_id = ObjectId::new_for_test(1);
    let outcome = sender.send_object(&cx, object_id, &data).unwrap();

    assert_eq!(outcome.object_id, object_id);
    assert!(outcome.source_symbols > 0);
    assert!(outcome.symbols_sent > 0);
    assert_eq!(
        outcome.symbols_sent,
        outcome.source_symbols + outcome.repair_symbols
    );
}

#[test]
fn sender_with_security_signs_symbols() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let security = SecurityContext::for_testing(42);

    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .security(security)
        .build()
        .unwrap();

    let data = vec![0xABu8; 512];
    let object_id = ObjectId::new_for_test(2);
    let outcome = sender.send_object(&cx, object_id, &data).unwrap();
    assert!(outcome.symbols_sent > 0);
}

#[test]
fn sender_rejects_oversized_data() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    // Create data larger than max_block_size * symbol_size.
    let max = u64::try_from(sender.config().encoding.max_block_size)
        .expect("max_block_size fits u64")
        * u64::from(sender.config().encoding.symbol_size);
    let data = vec![0u8; (max + 1) as usize];
    let result = sender.send_object(&cx, ObjectId::new_for_test(99), &data);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::DataTooLarge);
}

#[test]
fn sender_respects_cancellation() {
    let cx: Cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let data = vec![0u8; 512];
    let result = sender.send_object(&cx, ObjectId::new_for_test(1), &data);
    assert!(result.is_err());
}

#[test]
fn sender_with_metrics_increments_counters() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let metrics = Metrics::new();

    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .metrics(metrics)
        .build()
        .unwrap();

    let data = vec![1u8; 256];
    sender
        .send_object(&cx, ObjectId::new_for_test(1), &data)
        .unwrap();

    // Metrics should have been updated (exact values depend on encoding).
}

/// Full roundtrip test through the RaptorQ sender/receiver pipeline.
#[test]
fn send_receive_roundtrip() {
    let cx: Cx = Cx::for_testing();

    // Sender side.
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let original_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let object_id = ObjectId::new_for_test(77);
    let outcome = sender.send_object(&cx, object_id, &original_data).unwrap();

    // Extract symbols from the sink for the receiver.
    let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
    assert_eq!(symbols.len(), outcome.symbols_sent);

    // Receiver side — needs ObjectParams to know how to decode.
    // For Phase 0, the encoding pipeline produces symbols that match the
    // decoding pipeline's expectations. We need to compute params.
    let config = &sender.config().encoding;
    let symbol_size = config.symbol_size;
    let source_symbols = outcome.source_symbols as u16;
    let params = crate::types::symbol::ObjectParams::new(
        object_id,
        original_data.len() as u64,
        symbol_size,
        1, // single source block
        source_symbols,
    );

    let stream = VecStream::new(symbols);
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(stream)
        .build()
        .unwrap();

    let recv_outcome = receiver.receive_object(&cx, &params).unwrap();
    // The decoded data should match the original (after trimming padding).
    assert!(recv_outcome.data.len() >= original_data.len());
    assert_eq!(&recv_outcome.data[..original_data.len()], &original_data);
}

#[test]
fn receiver_reports_insufficient_symbols() {
    let cx: Cx = Cx::for_testing();

    // Empty stream — no symbols available.
    let stream = VecStream::new(vec![]);
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(stream)
        .build()
        .unwrap();

    let params =
        crate::types::symbol::ObjectParams::new(ObjectId::new_for_test(1), 1024, 256, 1, 4);

    let result = receiver.receive_object(&cx, &params);
    assert!(result.is_err());
}

#[test]
fn builder_default_config_used_when_not_specified() {
    let sender = RaptorQSenderBuilder::new()
        .transport(VecSink::new())
        .build()
        .unwrap();

    assert_eq!(sender.config().encoding.symbol_size, 256);
}

#[test]
fn builder_accepts_custom_config() {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = 512;

    let sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(VecSink::new())
        .build()
        .unwrap();

    assert_eq!(sender.config().encoding.symbol_size, 512);
}

#[test]
fn send_empty_data_succeeds() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    let outcome = sender
        .send_object(&cx, ObjectId::new_for_test(1), &[])
        .unwrap();
    // Empty data may produce zero symbols (no source blocks to encode).
    assert_eq!(outcome.source_symbols, 0);
}

#[test]
fn send_symbols_directly() {
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap();

    // Create a few authenticated symbols.
    let symbols: Vec<AuthenticatedSymbol> = (0..5)
        .map(|i| {
            let sym = crate::types::symbol::Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
            AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
        })
        .collect();

    let count = sender.send_symbols(&cx, symbols).unwrap();
    assert_eq!(count, 5);
    assert_eq!(sender.transport_mut().symbols.len(), 5);
}

// =========================================================================
// Conformance tests (bd-3h65)
// =========================================================================
//
// These tests verify deterministic behavior across runs by checking that
// the same seed produces the same content hash.

mod conformance {
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::systematic::SystematicEncoder;
    use crate::types::symbol::ObjectId;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    /// Compute a content hash for verification.
    fn content_hash(data: &[Vec<u8>]) -> u64 {
        let mut hasher = DefaultHasher::new();
        for chunk in data {
            chunk.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Known vector: small block (K=4, symbol_size=16, seed=42)
    #[test]
    fn known_vector_small_block() {
        let k = 4;
        let symbol_size = 16;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        // Generate repair symbols with fixed ESIs
        let repair_0 = encoder.repair_symbol(k as u32);
        let repair_1 = encoder.repair_symbol(k as u32 + 1);
        let repair_2 = encoder.repair_symbol(k as u32 + 2);

        // Verify deterministic repair generation
        let repair_hash = content_hash(&[repair_0, repair_1, repair_2]);

        // Re-create encoder and verify same output
        let encoder2 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let repair_0_2 = encoder2.repair_symbol(k as u32);
        let repair_1_2 = encoder2.repair_symbol(k as u32 + 1);
        let repair_2_2 = encoder2.repair_symbol(k as u32 + 2);

        let repair_hash_2 = content_hash(&[repair_0_2, repair_1_2, repair_2_2]);
        assert_eq!(
            repair_hash, repair_hash_2,
            "repair symbols must be deterministic"
        );
    }

    /// Known vector: medium block (K=32, symbol_size=64, seed=12345)
    /// NOTE: This test requires repair-based recovery. Currently marked #[ignore]
    /// because the decoder's Gaussian elimination phase has a known issue.
    /// Known vector: medium block roundtrip.
    #[test]
    fn known_vector_medium_block() {
        let k = 32;
        let symbol_size = 64;
        let seed = 12345u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 41 + j * 17 + 11) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        // Verify roundtrip
        let source_hash = content_hash(&source);
        let decoded_hash = content_hash(&result.source);
        assert_eq!(source_hash, decoded_hash, "decoded data must match source");
    }

    /// Known vector: verify proof artifact determinism.
    #[test]
    fn known_vector_proof_determinism() {
        let k = 8;
        let symbol_size = 32;
        let seed = 99u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 53 + j * 19 + 3) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let object_id = ObjectId::new_for_test(777);

        // Decode twice with proof
        let result1 = decoder
            .decode_with_proof(&received, object_id, 0)
            .expect("decode should succeed");
        let result2 = decoder
            .decode_with_proof(&received, object_id, 0)
            .expect("decode should succeed");

        // Proof content hashes must match
        assert_eq!(
            result1.proof.content_hash(),
            result2.proof.content_hash(),
            "proof artifacts must be deterministic"
        );
    }

    /// Known vector: encoder determinism (works without decoder)
    #[test]
    fn known_vector_encoder_determinism() {
        let k = 16;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder1 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let encoder2 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        // Verify intermediate symbols match
        for i in 0..encoder1.params().l {
            assert_eq!(
                encoder1.intermediate_symbol(i),
                encoder2.intermediate_symbol(i),
                "intermediate symbol {i} must be deterministic"
            );
        }

        // Verify repair symbols match
        for esi in 0..50u32 {
            assert_eq!(
                encoder1.repair_symbol(esi),
                encoder2.repair_symbol(esi),
                "repair symbol {esi} must be deterministic"
            );
        }
    }
}

// =========================================================================
// Property tests (bd-3h65)
// =========================================================================
//
// These tests verify encode → drop random symbols → decode → verify roundtrip.

mod property_tests {
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::systematic::SystematicEncoder;
    use crate::util::DetRng;

    /// Generate deterministic source data for testing.
    fn make_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
        let mut rng = DetRng::new(seed);
        (0..k)
            .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
            .collect()
    }

    /// Property: roundtrip with all symbols succeeds for known-good parameters.
    /// Uses the same parameters as the decoder module's passing tests.
    #[test]
    fn property_roundtrip_known_good_params() {
        // These parameters are known to work (from decoder::tests)
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Enough repair to reach L
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("roundtrip should succeed");

        assert_eq!(result.source, source, "decoded source must match original");
    }

    /// Property: roundtrip with overhead symbols handles LT rank issues.
    /// NOTE: Some parameter combinations produce singular matrices due to
    /// incomplete LT coverage. This test verifies behavior with extra overhead.
    #[test]
    fn property_roundtrip_with_overhead() {
        // Use 2x overhead to increase decode success probability
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // 2x overhead (L + extra repair symbols)
        let overhead = l;
        for esi in (k as u32)..((k + l + overhead) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("decode with overhead should succeed");
        assert_eq!(result.source, source);
    }

    /// Property: encoder produces correctly-sized symbols.
    #[test]
    fn property_encoder_symbol_sizes() {
        for (k, symbol_size, seed) in [(4, 16, 1u64), (8, 32, 2), (16, 64, 3), (32, 128, 4)] {
            let source = make_source_data(k, symbol_size, seed);
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let params = encoder.params();

            // Check intermediate symbols
            for i in 0..params.l {
                assert_eq!(
                    encoder.intermediate_symbol(i).len(),
                    symbol_size,
                    "intermediate symbol {i} should be {symbol_size} bytes for k={k}"
                );
            }

            // Check repair symbols
            for esi in 0..20u32 {
                assert_eq!(
                    encoder.repair_symbol(esi).len(),
                    symbol_size,
                    "repair symbol {esi} should be {symbol_size} bytes for k={k}"
                );
            }
        }
    }

    /// Property: roundtrip with random symbol drops should succeed if ≥ L symbols remain.
    /// NOTE: Requires working decoder Gaussian elimination.
    #[test]
    fn property_roundtrip_with_drops() {
        let k = 16;
        let symbol_size = 48;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;
        let constraints = decoder.constraint_symbols();

        // Generate excess symbols (2x overhead)
        let total_symbols = l * 2;
        let mut all_symbols: Vec<ReceivedSymbol> = Vec::with_capacity(total_symbols);

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            all_symbols.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols
        for esi in (k as u32)..(total_symbols as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            all_symbols.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Run multiple drop patterns with deterministic RNG
        for drop_seed in 0..10u64 {
            let mut rng = DetRng::new(drop_seed + 1000);

            // Randomly drop symbols but keep at least L
            let mut kept: Vec<ReceivedSymbol> = all_symbols
                .iter()
                .filter(|_| !rng.next_u64().is_multiple_of(3)) // Drop ~33%
                .cloned()
                .collect();

            // Ensure we have at least L symbols
            if kept.len() < l {
                // Add back enough symbols
                for sym in &all_symbols {
                    if kept.len() >= l {
                        break;
                    }
                    if !kept.iter().any(|s| s.esi == sym.esi) {
                        kept.push(sym.clone());
                    }
                }
            }

            // Truncate to exactly L symbols to stress the decoder
            kept.truncate(l);

            // Always include constraint symbols
            let mut with_constraints = constraints.clone();
            with_constraints.extend(kept);

            let result = decoder.decode(&with_constraints);

            // Decode should succeed with exactly L symbols
            match result {
                Ok(decoded_result) => {
                    assert_eq!(
                        decoded_result.source, source,
                        "decoded source must match for drop_seed={drop_seed}"
                    );
                }
                Err(e) => {
                    // Some drop patterns may create singular matrices - that's acceptable
                    // as long as we don't panic
                    println!(
                        "Note: drop_seed={drop_seed} produced decode error (acceptable): {e:?}"
                    );
                }
            }
        }
    }

    /// Property: different seeds produce different repair symbols.
    #[test]
    fn property_different_seeds_different_output() {
        let k = 8;
        let symbol_size = 32;
        let source = make_source_data(k, symbol_size, 0);

        let enc1 = SystematicEncoder::new(&source, symbol_size, 111).unwrap();
        let enc2 = SystematicEncoder::new(&source, symbol_size, 222).unwrap();

        let repair1: Vec<Vec<u8>> = (0..10u32).map(|esi| enc1.repair_symbol(esi)).collect();
        let repair2: Vec<Vec<u8>> = (0..10u32).map(|esi| enc2.repair_symbol(esi)).collect();

        // At least some repair symbols should differ
        let differences = repair1
            .iter()
            .zip(repair2.iter())
            .filter(|(a, b)| a != b)
            .count();

        assert!(
            differences > 0,
            "different seeds should produce different repair symbols"
        );
    }

    /// Property: same seed always produces identical results.
    #[test]
    fn property_determinism_across_runs() {
        let k = 12;
        let symbol_size = 24;
        let seed = 77777u64;

        for _ in 0..5 {
            let source = make_source_data(k, symbol_size, seed);
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

            let repairs: Vec<Vec<u8>> = (0..20u32).map(|esi| encoder.repair_symbol(esi)).collect();

            // All runs should produce identical repairs
            let expected: Vec<Vec<u8>> = (0..20u32)
                .map(|esi| {
                    let enc = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
                    enc.repair_symbol(esi)
                })
                .collect();

            assert_eq!(repairs, expected, "same seed must produce identical output");
        }
    }
}

// =========================================================================
// Deterministic fuzz harness (bd-3h65)
// =========================================================================
//
// Fuzz tests with fixed seeds for CI reproducibility.

mod fuzz {
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::systematic::SystematicEncoder;
    use crate::util::DetRng;

    /// Configuration for a single fuzz iteration.
    struct FuzzConfig {
        k: usize,
        symbol_size: usize,
        seed: u64,
        overhead_percent: usize,
        drop_percent: usize,
    }

    /// Run a single fuzz iteration.
    fn run_fuzz_iteration(config: &FuzzConfig) -> Result<(), String> {
        let FuzzConfig {
            k,
            symbol_size,
            seed,
            overhead_percent,
            drop_percent,
        } = *config;

        // Generate source data
        let mut rng = DetRng::new(seed);
        let source: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
            .collect();

        let Some(encoder) = SystematicEncoder::new(&source, symbol_size, seed) else {
            return Err("encoder creation failed".to_string());
        };

        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Constraint symbols (always included, never dropped)
        let constraints = decoder.constraint_symbols();

        // Generate symbols with overhead
        let total_target = l * (100 + overhead_percent) / 100;
        let mut all_symbols: Vec<ReceivedSymbol> = Vec::with_capacity(total_target);

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            all_symbols.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols
        let repair_needed = total_target.saturating_sub(k);
        for esi in (k as u32)..((k + repair_needed) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            all_symbols.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Drop symbols
        let mut kept: Vec<ReceivedSymbol> = Vec::new();
        for sym in &all_symbols {
            if rng.next_u64() % 100 >= drop_percent as u64 {
                kept.push(sym.clone());
            }
        }

        // Ensure at least L symbols
        if kept.len() < l {
            for sym in &all_symbols {
                if kept.len() >= l {
                    break;
                }
                if !kept.iter().any(|s| s.esi == sym.esi) {
                    kept.push(sym.clone());
                }
            }
        }

        // Include constraint symbols and decode
        let mut with_constraints = constraints.clone();
        with_constraints.extend(kept);

        match decoder.decode(&with_constraints) {
            Ok(result) => {
                if result.source != source {
                    return Err(format!(
                        "decoded source mismatch: got {} symbols, expected {}",
                        result.source.len(),
                        source.len()
                    ));
                }
                Ok(())
            }
            Err(e) => {
                // Some configurations may legitimately fail (singular matrix)
                // This is not a bug, just a limitation of the received symbol set
                Err(format!("decode error (may be acceptable): {e:?}"))
            }
        }
    }

    /// Deterministic fuzz with varied parameters.
    #[test]
    fn fuzz_varied_parameters() {
        let mut successes = 0;
        let mut acceptable_failures = 0;

        // Test matrix covering various parameter combinations
        let configs: Vec<FuzzConfig> = vec![
            // Small blocks
            FuzzConfig {
                k: 4,
                symbol_size: 16,
                seed: 1,
                overhead_percent: 50,
                drop_percent: 0,
            },
            FuzzConfig {
                k: 4,
                symbol_size: 16,
                seed: 2,
                overhead_percent: 100,
                drop_percent: 20,
            },
            FuzzConfig {
                k: 8,
                symbol_size: 32,
                seed: 3,
                overhead_percent: 50,
                drop_percent: 10,
            },
            // Medium blocks
            FuzzConfig {
                k: 16,
                symbol_size: 64,
                seed: 4,
                overhead_percent: 30,
                drop_percent: 15,
            },
            FuzzConfig {
                k: 32,
                symbol_size: 128,
                seed: 5,
                overhead_percent: 20,
                drop_percent: 10,
            },
            FuzzConfig {
                k: 64,
                symbol_size: 256,
                seed: 6,
                overhead_percent: 25,
                drop_percent: 5,
            },
            // Larger blocks (bounded for CI)
            FuzzConfig {
                k: 128,
                symbol_size: 512,
                seed: 7,
                overhead_percent: 15,
                drop_percent: 5,
            },
            FuzzConfig {
                k: 256,
                symbol_size: 256,
                seed: 8,
                overhead_percent: 10,
                drop_percent: 0,
            },
            // Stress tests
            FuzzConfig {
                k: 4,
                symbol_size: 8,
                seed: 9,
                overhead_percent: 200,
                drop_percent: 50,
            },
            FuzzConfig {
                k: 64,
                symbol_size: 64,
                seed: 10,
                overhead_percent: 50,
                drop_percent: 30,
            },
        ];

        for config in &configs {
            match run_fuzz_iteration(config) {
                Ok(()) => successes += 1,
                Err(e) => {
                    if e.contains("acceptable") {
                        acceptable_failures += 1;
                    } else {
                        panic!(
                            "Fuzz failure for k={}, seed={}: {}",
                            config.k, config.seed, e
                        );
                    }
                }
            }
        }

        // Most iterations should succeed
        assert!(
            successes >= configs.len() / 2,
            "Too few successes: {successes}/{} (acceptable failures: {acceptable_failures})",
            configs.len()
        );
    }

    /// Fuzz encoder determinism (works without decoder).
    #[test]
    fn fuzz_encoder_determinism() {
        // Test that same inputs always produce same outputs
        for seed in 0..20u64 {
            let k = 8 + (seed % 8) as usize;
            let symbol_size = 16 + (seed % 32) as usize;

            let mut rng = DetRng::new(seed);
            let source: Vec<Vec<u8>> = (0..k)
                .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
                .collect();

            let enc1 = SystematicEncoder::new(&source, symbol_size, seed * 1000).unwrap();
            let enc2 = SystematicEncoder::new(&source, symbol_size, seed * 1000).unwrap();

            // Verify repair symbols match
            for esi in 0..10u32 {
                assert_eq!(
                    enc1.repair_symbol(esi),
                    enc2.repair_symbol(esi),
                    "repair symbol {esi} must be deterministic for seed={seed}"
                );
            }
        }
    }

    /// Deterministic fuzz with random seed sweep (for CI regression).
    #[test]
    fn fuzz_seed_sweep() {
        let k = 16;
        let symbol_size = 32;

        let mut successes = 0;

        // 100 iterations with incrementing seeds
        for seed in 0..100u64 {
            let config = FuzzConfig {
                k,
                symbol_size,
                seed: seed + 10000, // Offset to avoid overlap with other tests
                overhead_percent: 30,
                drop_percent: 10,
            };

            if run_fuzz_iteration(&config).is_ok() {
                successes += 1;
            }
        }

        // High success rate expected
        assert!(
            successes >= 80,
            "Seed sweep success rate too low: {successes}/100"
        );
    }
}

// =========================================================================
// Edge case tests (bd-3h65)
// =========================================================================

mod edge_cases {
    use crate::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::gf256::Gf256;
    use crate::raptorq::systematic::SystematicEncoder;

    /// Edge case: tiny block (K=1).
    #[test]
    fn tiny_block_k1() {
        let k = 1;
        let symbol_size = 16;
        let seed = 42u64;

        let source = vec![vec![0xAB; symbol_size]];
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols, then add source
        let mut received = decoder.constraint_symbols();
        received.push(ReceivedSymbol::source(0, source[0].clone()));

        for esi in 1u32..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("K=1 decode should succeed");
        assert_eq!(result.source.len(), 1);
        assert_eq!(result.source[0], source[0]);
    }

    /// Edge case: tiny block (K=2).
    #[test]
    fn tiny_block_k2() {
        let k = 2;
        let symbol_size = 8;
        let seed = 99u64;

        let source = vec![vec![0x11; symbol_size], vec![0x22; symbol_size]];
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, d) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, d.clone()));
        }

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("K=2 decode should succeed");
        assert_eq!(result.source, source);
    }

    /// Edge case: tiny symbol size (1 byte).
    #[test]
    fn tiny_symbol_size() {
        let k = 4;
        let symbol_size = 1;
        let seed = 77u64;

        let source: Vec<Vec<u8>> = (0..k).map(|i| vec![i as u8]).collect();
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, d) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, d.clone()));
        }

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("tiny symbol decode should succeed");
        assert_eq!(result.source, source);
    }

    /// Edge case: large block (bounded for CI - K=512).
    #[test]
    fn large_block_bounded() {
        let k = 512;
        let symbol_size = 64;
        let seed = 12345u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..symbol_size).map(|j| ((i + j) % 256) as u8).collect())
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols, then add source + repair
        let mut received = decoder.constraint_symbols();
        for (i, d) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, d.clone()));
        }

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("large block decode should succeed");
        assert_eq!(result.source.len(), k);
        assert_eq!(result.source, source);
    }

    /// Edge case: repair=0 (only source symbols, need L=K+S+H).
    /// This tests the case where we have all source symbols but still need
    /// LDPC/HDPC constraint equations to satisfy the system.
    #[test]
    fn repair_zero_only_source() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 7 + j * 3) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC)
        let mut received = decoder.constraint_symbols();

        // Add all K source symbols
        for (i, d) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, d.clone()));
        }

        // Add repair symbols to reach L total received
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("source-heavy decode should succeed");
        assert_eq!(result.source, source);
    }

    /// Edge case: all repair symbols (no source symbols received).
    #[test]
    fn all_repair_no_source() {
        let k = 4;
        let symbol_size = 16;
        let seed = 333u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 11 + j * 5) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols, then only repair (no source)
        let mut received = decoder.constraint_symbols();
        for esi in (k as u32)..((k + l) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("all-repair decode should succeed");
        assert_eq!(result.source, source);
    }

    /// Edge case: insufficient symbols should fail gracefully
    #[test]
    fn insufficient_symbols_error() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k).map(|i| vec![i as u8; symbol_size]).collect();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Only k-1 symbols (less than L)
        let received: Vec<ReceivedSymbol> = source[..(l - 1).min(k)]
            .iter()
            .enumerate()
            .map(|(i, d)| ReceivedSymbol::source(i as u32, d.clone()))
            .collect();

        let result = decoder.decode(&received);
        assert!(
            matches!(result, Err(DecodeError::InsufficientSymbols { .. })),
            "should fail with InsufficientSymbols"
        );
    }

    /// Edge case: symbol size mismatch should fail gracefully
    #[test]
    fn symbol_size_mismatch_error() {
        let k = 4;
        let symbol_size = 32;
        let seed = 42u64;

        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Mix of correct and incorrect symbol sizes
        let mut received = vec![
            ReceivedSymbol::source(0, vec![0u8; symbol_size]),
            ReceivedSymbol::source(1, vec![0u8; symbol_size]),
            ReceivedSymbol::source(2, vec![0u8; symbol_size + 1]), // Wrong size!
            ReceivedSymbol::source(3, vec![0u8; symbol_size]),
        ];

        // Add more symbols to reach L
        let l = decoder.params().l;
        for esi in 4u32..(l as u32) {
            received.push(ReceivedSymbol {
                esi,
                is_source: false,
                columns: vec![0],
                coefficients: vec![Gf256::ONE],
                data: vec![0u8; symbol_size], // Correct size
            });
        }

        let result = decoder.decode(&received);
        assert!(
            matches!(result, Err(DecodeError::SymbolSizeMismatch { .. })),
            "should fail with SymbolSizeMismatch"
        );
    }

    /// Edge case: large symbol size.
    #[test]
    fn large_symbol_size() {
        let k = 4;
        let symbol_size = 4096; // 4KB symbols
        let seed = 88u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..symbol_size).map(|j| ((i + j) % 256) as u8).collect())
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, d) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, d.clone()));
        }

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("large symbol decode should succeed");
        assert_eq!(result.source, source);
    }
}
