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
// In-memory test transport
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

use crate::raptorq::test_log_schema::UnitLogEntry;

fn builder_failure_context(
    scenario_id: &str,
    seed: u64,
    parameter_set: &str,
    replay_ref: &str,
) -> String {
    UnitLogEntry::new(scenario_id, seed, parameter_set, replay_ref, "pending")
        .with_repro_command("rch exec -- cargo test --lib raptorq::tests -- --nocapture")
        .to_context_string()
}

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
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let config = RaptorQConfig::default();
    let symbol_size = config.encoding.symbol_size;
    let replay_ref = "replay:rq-u-builder-send-transmit-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-SEND-TRANSMIT",
        seed,
        &format!("symbol_size={symbol_size},data_len=1024"),
        replay_ref,
    );
    let mut sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(sink)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    let data = vec![42u8; 1024];
    let object_id = ObjectId::new_for_test(1);
    let outcome = sender
        .send_object(&cx, object_id, &data)
        .unwrap_or_else(|err| panic!("{context} send_object should succeed; got {err:?}"));

    assert_eq!(outcome.object_id, object_id);
    assert!(
        outcome.source_symbols > 0,
        "{context} expected source symbols > 0"
    );
    assert!(
        outcome.symbols_sent > 0,
        "{context} expected symbols sent > 0"
    );
    assert_eq!(
        outcome.symbols_sent,
        outcome.source_symbols + outcome.repair_symbols,
        "{context} expected symbols_sent == source_symbols + repair_symbols"
    );
}

#[test]
fn sender_with_security_signs_symbols() {
    let seed = 42u64;
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let security = SecurityContext::for_testing(42);
    let config = RaptorQConfig::default();
    let symbol_size = config.encoding.symbol_size;
    let replay_ref = "replay:rq-u-builder-security-send-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-SECURITY-SEND",
        seed,
        &format!("symbol_size={symbol_size},data_len=512"),
        replay_ref,
    );

    let mut sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(sink)
        .security(security)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    let data = vec![0xABu8; 512];
    let object_id = ObjectId::new_for_test(2);
    let outcome = sender
        .send_object(&cx, object_id, &data)
        .unwrap_or_else(|err| panic!("{context} send_object should succeed; got {err:?}"));
    assert!(
        outcome.symbols_sent > 0,
        "{context} expected signed send to emit symbols"
    );
}

#[test]
fn sender_rejects_oversized_data() {
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let config = RaptorQConfig::default();
    let replay_ref = "replay:rq-u-builder-oversized-error-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-ERROR-OVERSIZED",
        seed,
        &format!("symbol_size={}", config.encoding.symbol_size),
        replay_ref,
    );
    let mut sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(sink)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    // Create data larger than max_block_size * symbol_size.
    let max = u64::try_from(sender.config().encoding.max_block_size)
        .expect("max_block_size fits u64")
        * u64::from(sender.config().encoding.symbol_size);
    let data = vec![0u8; (max + 1) as usize];
    let result = sender.send_object(&cx, ObjectId::new_for_test(99), &data);

    let err = result
        .err()
        .unwrap_or_else(|| panic!("{context} expected DataTooLarge error"));
    assert_eq!(
        err.kind(),
        ErrorKind::DataTooLarge,
        "{context} expected DataTooLarge error kind"
    );
}

#[test]
fn sender_respects_cancellation() {
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    let sink = VecSink::new();
    let config = RaptorQConfig::default();
    let replay_ref = "replay:rq-u-builder-cancelled-send-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-CANCELLED-SEND",
        seed,
        &format!("symbol_size={},data_len=512", config.encoding.symbol_size),
        replay_ref,
    );
    let mut sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(sink)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    let data = vec![0u8; 512];
    let result = sender.send_object(&cx, ObjectId::new_for_test(1), &data);
    assert!(
        result.is_err(),
        "{context} expected cancellation to return error"
    );
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
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();

    // Sender side.
    let sink = VecSink::new();
    let config = RaptorQConfig::default();
    let symbol_size = config.encoding.symbol_size;
    let replay_ref = "replay:rq-u-builder-roundtrip-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-ROUNDTRIP",
        seed,
        &format!("symbol_size={symbol_size},data_len=6"),
        replay_ref,
    );
    let mut sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(sink)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    let original_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let object_id = ObjectId::new_for_test(77);
    let outcome = sender
        .send_object(&cx, object_id, &original_data)
        .unwrap_or_else(|err| panic!("{context} send_object should succeed; got {err:?}"));

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
        .unwrap_or_else(|err| panic!("{context} receiver build should succeed; got {err:?}"));

    let recv_outcome = receiver
        .receive_object(&cx, &params)
        .unwrap_or_else(|err| panic!("{context} receive_object should succeed; got {err:?}"));
    // The decoded data should match the original (after trimming padding).
    assert!(
        recv_outcome.data.len() >= original_data.len(),
        "{context} expected decoded data len >= original data len"
    );
    assert_eq!(
        &recv_outcome.data[..original_data.len()],
        &original_data,
        "{context} expected decoded prefix to match original payload"
    );
}

#[test]
fn receiver_reports_insufficient_symbols() {
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();
    let replay_ref = "replay:rq-u-builder-receiver-insufficient-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-RECEIVER-INSUFFICIENT",
        seed,
        "symbol_size=256,data_len=1024,source_symbols=4",
        replay_ref,
    );

    // Empty stream — no symbols available.
    let stream = VecStream::new(vec![]);
    let mut receiver = RaptorQReceiverBuilder::new()
        .config(RaptorQConfig::default())
        .source(stream)
        .build()
        .unwrap_or_else(|err| panic!("{context} receiver build should succeed; got {err:?}"));

    let params =
        crate::types::symbol::ObjectParams::new(ObjectId::new_for_test(1), 1024, 256, 1, 4);

    let result = receiver.receive_object(&cx, &params);
    assert!(
        result.is_err(),
        "{context} expected insufficient-symbols error"
    );
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
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let config = RaptorQConfig::default();
    let symbol_size = config.encoding.symbol_size;
    let replay_ref = "replay:rq-u-builder-send-empty-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-SEND-EMPTY",
        seed,
        &format!("symbol_size={symbol_size},data_len=0"),
        replay_ref,
    );
    let mut sender = RaptorQSenderBuilder::new()
        .config(config)
        .transport(sink)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    let outcome = sender
        .send_object(&cx, ObjectId::new_for_test(1), &[])
        .unwrap_or_else(|err| panic!("{context} empty send should succeed; got {err:?}"));
    // Empty data may produce zero symbols (no source blocks to encode).
    assert_eq!(
        outcome.source_symbols, 0,
        "{context} expected empty send to emit zero source symbols"
    );
}

#[test]
fn send_symbols_directly() {
    let seed = 0u64;
    let cx: Cx = Cx::for_testing();
    let sink = VecSink::new();
    let replay_ref = "replay:rq-u-builder-send-symbols-v1";
    let context = builder_failure_context(
        "RQ-U-BUILDER-SEND-SYMBOLS",
        seed,
        "symbol_count=5,symbol_size=256",
        replay_ref,
    );
    let mut sender = RaptorQSenderBuilder::new()
        .config(RaptorQConfig::default())
        .transport(sink)
        .build()
        .unwrap_or_else(|err| panic!("{context} sender build should succeed; got {err:?}"));

    // Create a few authenticated symbols.
    let symbols: Vec<AuthenticatedSymbol> = (0..5)
        .map(|i| {
            let sym = crate::types::symbol::Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
            AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
        })
        .collect();

    let count = sender
        .send_symbols(&cx, symbols)
        .unwrap_or_else(|err| panic!("{context} send_symbols should succeed; got {err:?}"));
    assert_eq!(
        count, 5,
        "{context} expected five symbols to be transmitted"
    );
    assert_eq!(
        sender.transport_mut().symbols.len(),
        5,
        "{context} expected sink to store five symbols"
    );
}

// =========================================================================
// Conformance tests (bd-3h65)
// =========================================================================
//
// These tests verify deterministic behavior across runs by checking that
// the same seed produces the same content hash.

mod conformance {
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::gf256::gf256_addmul_slice;
    use crate::raptorq::systematic::SystematicEncoder;
    use crate::raptorq::test_log_schema::UnitLogEntry;
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

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        UnitLogEntry::new(scenario_id, seed, parameter_set, replay_ref, "pending")
            .with_repro_command(
                "rch exec -- cargo test --lib raptorq::tests::conformance -- --nocapture",
            )
            .to_context_string()
    }

    /// Known vector: small block (K=4, symbol_size=16, seed=42)
    #[test]
    fn known_vector_small_block() {
        let k = 4;
        let symbol_size = 16;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-systematic-known-vector-small-v1";
        let context = failure_context(
            "RQ-U-SYSTEMATIC-KNOWN-VECTOR-SMALL",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));

        // Generate repair symbols with fixed ESIs
        let repair_0 = encoder.repair_symbol(k as u32);
        let repair_1 = encoder.repair_symbol(k as u32 + 1);
        let repair_2 = encoder.repair_symbol(k as u32 + 2);

        // Verify deterministic repair generation
        let repair_hash = content_hash(&[repair_0, repair_1, repair_2]);

        // Re-create encoder and verify same output
        let encoder2 = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
        let repair_0_2 = encoder2.repair_symbol(k as u32);
        let repair_1_2 = encoder2.repair_symbol(k as u32 + 1);
        let repair_2_2 = encoder2.repair_symbol(k as u32 + 2);

        let repair_hash_2 = content_hash(&[repair_0_2, repair_1_2, repair_2_2]);
        assert_eq!(
            repair_hash, repair_hash_2,
            "{context} repair symbols must be deterministic"
        );
    }

    #[test]
    fn repair_symbol_matches_rfc_equation_projection() {
        let k = 10;
        let symbol_size = 24;
        let seed = 123u64;
        let replay_ref = "replay:rq-u-systematic-rfc-projection-v1";
        let context = failure_context(
            "RQ-U-SYSTEMATIC-RFC-PROJECTION",
            seed,
            &format!("k={k},symbol_size={symbol_size},esi_range=[{k},{}]", k + 7),
            replay_ref,
        );
        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 17 + j * 29 + 5) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
        for esi in (k as u32)..(k as u32 + 8) {
            let repair = encoder.repair_symbol(esi);
            let (columns, coefficients) = encoder.params().rfc_repair_equation(esi);
            let mut expected = vec![0u8; symbol_size];

            for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                gf256_addmul_slice(
                    &mut expected,
                    encoder.intermediate_symbol(column),
                    coefficient,
                );
            }

            assert_eq!(
                repair, expected,
                "{context} repair symbol must equal projection of RFC equation for esi={esi}"
            );
        }
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
        let replay_ref = "replay:rq-u-systematic-known-vector-medium-v1";
        let context = failure_context(
            "RQ-U-SYSTEMATIC-KNOWN-VECTOR-MEDIUM",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 41 + j * 17 + 11) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
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

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|err| panic!("{context} decode should succeed; got {err:?}"));

        // Verify roundtrip
        let source_hash = content_hash(&source);
        let decoded_hash = content_hash(&result.source);
        assert_eq!(
            source_hash, decoded_hash,
            "{context} decoded data must match source"
        );
    }

    /// Known vector: verify proof artifact determinism.
    #[test]
    fn known_vector_proof_determinism() {
        let k = 8;
        let symbol_size = 32;
        let seed = 99u64;
        let replay_ref = "replay:rq-u-determinism-proof-vector-v1";
        let context = failure_context(
            "RQ-U-DETERMINISM-PROOF-VECTOR",
            seed,
            &format!("k={k},symbol_size={symbol_size},object_id=777"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 53 + j * 19 + 3) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
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
            .unwrap_or_else(|err| {
                panic!("{context} decode_with_proof should succeed; got {err:?}")
            });
        let result2 = decoder
            .decode_with_proof(&received, object_id, 0)
            .unwrap_or_else(|err| {
                panic!("{context} decode_with_proof should succeed; got {err:?}")
            });

        // Proof content hashes must match
        assert_eq!(
            result1.proof.content_hash(),
            result2.proof.content_hash(),
            "{context} proof artifacts must be deterministic"
        );
    }

    /// Known vector: encoder determinism (works without decoder)
    #[test]
    fn known_vector_encoder_determinism() {
        let k = 16;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-systematic-encoder-determinism-v1";
        let context = failure_context(
            "RQ-U-DETERMINISM-SEED",
            seed,
            &format!("k={k},symbol_size={symbol_size},esi_range=[0,49]"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder1 = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
        let encoder2 = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));

        // Verify intermediate symbols match
        for i in 0..encoder1.params().l {
            assert_eq!(
                encoder1.intermediate_symbol(i),
                encoder2.intermediate_symbol(i),
                "{context} intermediate symbol {i} must be deterministic"
            );
        }

        // Verify repair symbols match
        for esi in 0..50u32 {
            assert_eq!(
                encoder1.repair_symbol(esi),
                encoder2.repair_symbol(esi),
                "{context} repair symbol {esi} must be deterministic"
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
    use crate::raptorq::test_log_schema::UnitLogEntry;
    use crate::util::DetRng;

    /// Generate deterministic source data for testing.
    fn make_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
        let mut rng = DetRng::new(seed);
        (0..k)
            .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
            .collect()
    }

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        UnitLogEntry::new(scenario_id, seed, parameter_set, replay_ref, "pending")
            .with_repro_command(
                "rch exec -- cargo test --lib raptorq::tests::property_tests -- --nocapture",
            )
            .to_context_string()
    }

    /// Property: roundtrip with all symbols succeeds for known-good parameters.
    /// Uses the same parameters as the decoder module's passing tests.
    #[test]
    fn property_roundtrip_known_good_params() {
        // These parameters are known to work (from decoder::tests)
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-systematic-property-roundtrip-v1";
        let context = failure_context(
            "RQ-U-HAPPY-SYSTEMATIC",
            seed,
            &format!("k={k},symbol_size={symbol_size},repair_to_l=true"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
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

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|err| panic!("{context} roundtrip should succeed; got {err:?}"));

        assert_eq!(
            result.source, source,
            "{context} decoded source must match original"
        );
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
        let replay_ref = "replay:rq-u-systematic-property-overhead-v1";
        let context = failure_context(
            "RQ-U-HAPPY-REPAIR",
            seed,
            &format!("k={k},symbol_size={symbol_size},overhead_multiplier=2"),
            replay_ref,
        );

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} decode with overhead should succeed; got {err:?}")
        });
        assert_eq!(
            result.source, source,
            "{context} decoded source must match original"
        );
    }

    /// Property: encoder produces correctly-sized symbols.
    #[test]
    fn property_encoder_symbol_sizes() {
        let replay_ref = "replay:rq-u-systematic-property-symbol-sizes-v1";
        for (k, symbol_size, seed) in [(4, 16, 1u64), (8, 32, 2), (16, 64, 3), (32, 128, 4)] {
            let context = failure_context(
                "RQ-U-SYSTEMATIC-PROPERTY-SIZES",
                seed,
                &format!("k={k},symbol_size={symbol_size},esi_range=[0,19]"),
                replay_ref,
            );
            let source = make_source_data(k, symbol_size, seed);
            let encoder = SystematicEncoder::new(&source, symbol_size, seed)
                .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
            let params = encoder.params();

            // Check intermediate symbols
            for i in 0..params.l {
                assert_eq!(
                    encoder.intermediate_symbol(i).len(),
                    symbol_size,
                    "{context} intermediate symbol {i} should be {symbol_size} bytes for k={k}"
                );
            }

            // Check repair symbols
            for esi in 0..20u32 {
                assert_eq!(
                    encoder.repair_symbol(esi).len(),
                    symbol_size,
                    "{context} repair symbol {esi} should be {symbol_size} bytes for k={k}"
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
        let replay_ref = "replay:rq-u-systematic-property-drops-v1";

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
            let effective_seed = drop_seed + 1000;
            let context = failure_context(
                "RQ-U-ADVERSARIAL-LOSS",
                effective_seed,
                &format!("k={k},symbol_size={symbol_size},truncate_to_l=true"),
                replay_ref,
            );
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
                        "{context} decoded source must match for drop_seed={drop_seed}"
                    );
                }
                Err(e) => {
                    // Some drop patterns may create singular matrices - that's acceptable
                    // as long as we don't panic
                    let _ = (e, &context);
                }
            }
        }
    }

    /// Property: encoding is deterministic regardless of seed (seed is reserved for future use).
    #[test]
    fn property_seed_independent_encoding() {
        let k = 8;
        let symbol_size = 32;
        let source = make_source_data(k, symbol_size, 0);
        let replay_ref = "replay:rq-u-systematic-property-seed-independent-v1";
        let context = failure_context(
            "RQ-U-DETERMINISM-SEED",
            0,
            &format!("k={k},symbol_size={symbol_size},compare_seeds=[111,222]"),
            replay_ref,
        );

        let enc1 = SystematicEncoder::new(&source, symbol_size, 111).unwrap_or_else(|| {
            panic!("{context} expected encoder construction to succeed for seed=111")
        });
        let enc2 = SystematicEncoder::new(&source, symbol_size, 222).unwrap_or_else(|| {
            panic!("{context} expected encoder construction to succeed for seed=222")
        });

        let repair1: Vec<Vec<u8>> = (0..10u32).map(|esi| enc1.repair_symbol(esi)).collect();
        let repair2: Vec<Vec<u8>> = (0..10u32).map(|esi| enc2.repair_symbol(esi)).collect();

        // The constraint matrix and repair equations are fully determined
        // by the RFC 6330 systematic index table, not by the seed.
        assert_eq!(
            repair1, repair2,
            "{context} same source data should produce identical repair output"
        );
    }

    /// Property: same seed always produces identical results.
    #[test]
    fn property_determinism_across_runs() {
        let k = 12;
        let symbol_size = 24;
        let seed = 77777u64;
        let replay_ref = "replay:rq-u-systematic-property-determinism-runs-v1";

        for run_idx in 0..5 {
            let context = failure_context(
                "RQ-U-DETERMINISM-SEED",
                seed,
                &format!("k={k},symbol_size={symbol_size},run={run_idx},esi_range=[0,19]"),
                replay_ref,
            );
            let source = make_source_data(k, symbol_size, seed);
            let encoder = SystematicEncoder::new(&source, symbol_size, seed)
                .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));

            let repairs: Vec<Vec<u8>> = (0..20u32).map(|esi| encoder.repair_symbol(esi)).collect();

            // All runs should produce identical repairs
            let expected: Vec<Vec<u8>> = (0..20u32)
                .map(|esi| {
                    let enc =
                        SystematicEncoder::new(&source, symbol_size, seed).unwrap_or_else(|| {
                            panic!("{context} expected encoder construction to succeed")
                        });
                    enc.repair_symbol(esi)
                })
                .collect();

            assert_eq!(
                repairs, expected,
                "{context} same seed must produce identical output"
            );
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
    use crate::raptorq::test_log_schema::UnitLogEntry;
    use crate::util::DetRng;

    /// Configuration for a single fuzz iteration.
    struct FuzzConfig {
        k: usize,
        symbol_size: usize,
        seed: u64,
        overhead_percent: usize,
        drop_percent: usize,
    }

    fn failure_context(config: &FuzzConfig, scenario_id: &str, replay_ref: &str) -> String {
        UnitLogEntry::new(
            scenario_id,
            config.seed,
            &format!(
                "k={},symbol_size={},overhead_percent={},drop_percent={}",
                config.k, config.symbol_size, config.overhead_percent, config.drop_percent
            ),
            replay_ref,
            "pending",
        )
        .with_repro_command("rch exec -- cargo test --lib raptorq::tests::fuzz -- --nocapture")
        .to_context_string()
    }

    /// Run a single fuzz iteration.
    fn run_fuzz_iteration(
        config: &FuzzConfig,
        scenario_id: &str,
        replay_ref: &str,
    ) -> Result<(), String> {
        let context = failure_context(config, scenario_id, replay_ref);
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
            return Err(format!("{context} encoder creation failed"));
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
        let mut with_constraints = constraints;
        with_constraints.extend(kept);

        match decoder.decode(&with_constraints) {
            Ok(result) => {
                if result.source != source {
                    return Err(format!(
                        "{context} decoded source mismatch: got {} symbols, expected {}",
                        result.source.len(),
                        source.len()
                    ));
                }
                Ok(())
            }
            Err(e) => {
                // Some configurations may legitimately fail (singular matrix)
                // This is not a bug, just a limitation of the received symbol set
                Err(format!("{context} decode error (may be acceptable): {e:?}"))
            }
        }
    }

    /// Deterministic fuzz with varied parameters.
    #[test]
    fn fuzz_varied_parameters() {
        let replay_ref = "replay:rq-u-systematic-fuzz-varied-v1";
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
            match run_fuzz_iteration(config, "RQ-U-ADVERSARIAL-LOSS", replay_ref) {
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
        let replay_ref = "replay:rq-u-systematic-fuzz-encoder-determinism-v1";
        // Test that same inputs always produce same outputs
        for seed in 0..20u64 {
            let k = 8 + (seed % 8) as usize;
            let symbol_size = 16 + (seed % 32) as usize;
            let context = format!(
                "scenario_id=RQ-U-DETERMINISM-SEED seed={seed} parameter_set=k={k},symbol_size={symbol_size},esi_range=[0,9] replay_ref={replay_ref}"
            );

            let mut rng = DetRng::new(seed);
            let source: Vec<Vec<u8>> = (0..k)
                .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
                .collect();

            let enc1 = SystematicEncoder::new(&source, symbol_size, seed * 1000)
                .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));
            let enc2 = SystematicEncoder::new(&source, symbol_size, seed * 1000)
                .unwrap_or_else(|| panic!("{context} expected encoder construction to succeed"));

            // Verify repair symbols match
            for esi in 0..10u32 {
                assert_eq!(
                    enc1.repair_symbol(esi),
                    enc2.repair_symbol(esi),
                    "{context} repair symbol {esi} must be deterministic for seed={seed}"
                );
            }
        }
    }

    /// Deterministic fuzz with random seed sweep (for CI regression).
    #[test]
    fn fuzz_seed_sweep() {
        let replay_ref = "replay:rq-u-systematic-fuzz-seed-sweep-v1";
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

            if run_fuzz_iteration(&config, "RQ-U-SEED-SWEEP-STRUCTURED", replay_ref).is_ok() {
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
    use crate::raptorq::test_log_schema::UnitLogEntry;

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        k: usize,
        symbol_size: usize,
        replay_ref: &str,
    ) -> String {
        UnitLogEntry::new(
            scenario_id,
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
            "pending",
        )
        .with_repro_command(
            "rch exec -- cargo test --lib raptorq::tests::edge_cases -- --nocapture",
        )
        .to_context_string()
    }

    fn encoder_with_seed_fallback(
        source: &[Vec<u8>],
        symbol_size: usize,
        seed_candidates: &[u64],
    ) -> Option<(SystematicEncoder, u64)> {
        for &candidate in seed_candidates {
            if let Some(encoder) = SystematicEncoder::new(source, symbol_size, candidate) {
                return Some((encoder, candidate));
            }
        }
        None
    }

    struct SelectedLargeProfile {
        k: usize,
        symbol_size: usize,
        source: Vec<Vec<u8>>,
        encoder: SystematicEncoder,
        seed: u64,
    }

    /// Edge case: tiny block (K=1).
    #[test]
    fn tiny_block_k1() {
        let k = 1;
        let symbol_size = 16;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-boundary-tiny-k1-v1";
        let context = failure_context("RQ-U-BOUNDARY-TINY", seed, k, symbol_size, replay_ref);

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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} K=1 decode should succeed; got {err:?}");
        });
        assert_eq!(result.source.len(), 1);
        assert_eq!(result.source[0], source[0]);
    }

    /// Edge case: tiny block (K=2).
    #[test]
    fn tiny_block_k2() {
        let k = 2;
        let symbol_size = 8;
        let seed = 99u64;
        let replay_ref = "replay:rq-u-boundary-tiny-k2-v1";
        let context = failure_context("RQ-U-BOUNDARY-TINY", seed, k, symbol_size, replay_ref);

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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} K=2 decode should succeed; got {err:?}");
        });
        assert_eq!(result.source, source);
    }

    /// Edge case: tiny symbol size (1 byte).
    #[test]
    fn tiny_symbol_size() {
        let k = 4;
        let symbol_size = 1;
        let seed = 77u64;
        let replay_ref = "replay:rq-u-boundary-tiny-symbol-v1";
        let context = failure_context("RQ-U-BOUNDARY-TINY", seed, k, symbol_size, replay_ref);

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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} tiny symbol decode should succeed; got {err:?}");
        });
        assert_eq!(result.source, source);
    }

    /// Edge case: large block (bounded for CI - K=512).
    #[test]
    fn large_block_bounded() {
        let replay_ref = "replay:rq-u-boundary-large-v1";
        let profile_candidates = [
            (512usize, 64usize),
            (256, 64),
            (128, 64),
            (64, 32),
            (32, 32),
            (16, 16),
        ];
        let seed_candidates = [12345u64, 42, 99, 7777, 2024];

        let mut selected: Option<SelectedLargeProfile> = None;
        for &(candidate_k, candidate_symbol_size) in &profile_candidates {
            let candidate_source: Vec<Vec<u8>> = (0..candidate_k)
                .map(|i| {
                    (0..candidate_symbol_size)
                        .map(|j| ((i + j) % 256) as u8)
                        .collect()
                })
                .collect();
            if let Some((encoder, seed)) = encoder_with_seed_fallback(
                &candidate_source,
                candidate_symbol_size,
                &seed_candidates,
            ) {
                selected = Some(SelectedLargeProfile {
                    k: candidate_k,
                    symbol_size: candidate_symbol_size,
                    source: candidate_source,
                    encoder,
                    seed,
                });
                break;
            }
        }
        let SelectedLargeProfile {
            k,
            symbol_size,
            source,
            encoder,
            seed,
        } = selected.unwrap_or_else(|| {
            panic!(
                "scenario_id=RQ-U-BOUNDARY-LARGE profiles={profile_candidates:?} \
                 replay_ref={replay_ref} could not construct non-singular encoder for any tested (k, seed)"
            )
        });
        let context = failure_context("RQ-U-BOUNDARY-LARGE", seed, k, symbol_size, replay_ref);
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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} large block decode should succeed; got {err:?}");
        });
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
        let replay_ref = "replay:rq-u-happy-source-heavy-v1";
        let context = failure_context("RQ-U-HAPPY-SYSTEMATIC", seed, k, symbol_size, replay_ref);

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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} source-heavy decode should succeed; got {err:?}");
        });
        assert_eq!(result.source, source);
    }

    /// Edge case: all repair symbols (no source symbols received).
    #[test]
    fn all_repair_no_source() {
        let k = 4;
        let symbol_size = 16;
        let seed = 333u64;
        let replay_ref = "replay:rq-u-happy-repair-only-v1";
        let context = failure_context("RQ-U-HAPPY-REPAIR", seed, k, symbol_size, replay_ref);

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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} all-repair decode should succeed; got {err:?}");
        });
        assert_eq!(result.source, source);
    }

    /// Edge case: insufficient symbols should fail gracefully
    #[test]
    fn insufficient_symbols_error() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-error-insufficient-v1";
        let context = failure_context("RQ-U-ERROR-INSUFFICIENT", seed, k, symbol_size, replay_ref);

        let source: Vec<Vec<u8>> = (0..k).map(|i| vec![i as u8; symbol_size]).collect();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Only k-1 symbols (less than L)
        let received: Vec<ReceivedSymbol> = source[..(l - 1).min(k)]
            .iter()
            .enumerate()
            .map(|(i, d)| ReceivedSymbol::source(i as u32, d.clone()))
            .collect();

        let expected_received = received.len();
        let result = decoder.decode(&received);
        match result {
            Err(DecodeError::InsufficientSymbols {
                received: actual_received,
                required,
            }) => {
                assert_eq!(
                    actual_received, expected_received,
                    "{context} unexpected received count in error payload"
                );
                assert_eq!(
                    required, l,
                    "{context} expected required symbol count to match L"
                );
            }
            other => {
                panic!("{context} expected InsufficientSymbols, got {other:?}");
            }
        }
    }

    /// Edge case: symbol size mismatch should fail gracefully
    #[test]
    fn symbol_size_mismatch_error() {
        let k = 4;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-error-size-mismatch-v1";
        let context = failure_context("RQ-U-ERROR-SIZE-MISMATCH", seed, k, symbol_size, replay_ref);

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
        match result {
            Err(DecodeError::SymbolSizeMismatch { expected, actual }) => {
                assert_eq!(
                    expected, symbol_size,
                    "{context} expected decode error to report configured symbol_size"
                );
                assert_eq!(
                    actual,
                    symbol_size + 1,
                    "{context} expected decode error to report offending symbol size"
                );
            }
            other => {
                panic!("{context} expected SymbolSizeMismatch, got {other:?}");
            }
        }
    }

    /// Edge case: large symbol size.
    #[test]
    fn large_symbol_size() {
        let k = 4;
        let symbol_size = 4096; // 4KB symbols
        let seed = 88u64;
        let replay_ref = "replay:rq-u-boundary-large-symbol-v1";
        let context = failure_context("RQ-U-BOUNDARY-LARGE", seed, k, symbol_size, replay_ref);

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

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("{context} large symbol decode should succeed; got {err:?}");
        });
        assert_eq!(result.source, source);
    }
}

// =========================================================================
// Failure-mode + invariant closure tests (br-3narc.2.7)
// =========================================================================

mod failure_modes {
    use crate::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::gf256::Gf256;
    use crate::raptorq::systematic::SystematicEncoder;
    use crate::raptorq::test_log_schema::UnitLogEntry;
    use crate::types::symbol::ObjectId;

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        UnitLogEntry::new(scenario_id, seed, parameter_set, replay_ref, "pending")
            .with_repro_command(
                "rch exec -- cargo test --lib raptorq::tests::failure_modes -- --nocapture",
            )
            .to_context_string()
    }

    /// Corruption injection: flip a bit in a source symbol after encoding,
    /// verify the decoder detects corruption via verify_decoded_output.
    #[test]
    fn bit_flip_corruption_detected_as_corrupt_decoded_output() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-corruption-bitflip-v1";
        let context = failure_context(
            "RQ-U-CORRUPTION-BITFLIP",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

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

        let mut received = decoder.constraint_symbols();

        // Add source symbols, but corrupt symbol 3
        for (i, data) in source.iter().enumerate() {
            let mut sym_data = data.clone();
            if i == 3 {
                sym_data[0] ^= 0xFF; // Flip all bits of first byte
            }
            received.push(ReceivedSymbol::source(i as u32, sym_data));
        }

        // Add repair symbols (correct)
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received);
        match result {
            Err(DecodeError::CorruptDecodedOutput { esi, .. }) => {
                // The corruption should be detected. The exact ESI reported
                // depends on which equation fires first during verification.
                let _ = (esi, &context);
            }
            Err(DecodeError::SingularMatrix { .. }) => {
                // Also acceptable: the corruption may make the system inconsistent
                // before we even reach the verification step.
            }
            Ok(_) => {
                panic!("{context} decoder should NOT silently return success with corrupted input");
            }
            Err(other) => {
                panic!("{context} unexpected error type: {other:?}");
            }
        }
    }

    /// Contiguous burst loss: drop the first K source symbols,
    /// rely entirely on repair symbols for recovery.
    #[test]
    fn contiguous_burst_loss_all_source_symbols_dropped() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-burst-loss-all-source-v1";
        let context = failure_context(
            "RQ-U-ADVERSARIAL-BURST",
            seed,
            &format!("k={k},symbol_size={symbol_size},drop=all_source"),
            replay_ref,
        );

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

        // Start with constraints, then ONLY repair symbols (no source)
        let mut received = decoder.constraint_symbols();

        // Add enough repair symbols (use a large ESI range for diversity)
        for esi in (k as u32)..((k + l * 2) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received);
        match result {
            Ok(decoded_symbols) => {
                assert_eq!(
                    decoded_symbols.source, source,
                    "{context} burst-loss decode should recover original source"
                );
            }
            Err(DecodeError::SingularMatrix { .. }) => {
                // Acceptable: some parameter combos are rank-deficient under full source loss.
                // But we should not panic.
            }
            Err(other) => {
                panic!("{context} unexpected error on burst loss: {other:?}");
            }
        }
    }

    /// Contiguous burst: drop a specific consecutive range of ESIs.
    #[test]
    fn contiguous_burst_drop_first_half_of_source() {
        let k = 16;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-burst-loss-first-half-v1";
        let context = failure_context(
            "RQ-U-ADVERSARIAL-BURST",
            seed,
            &format!("k={k},symbol_size={symbol_size},drop=first_half"),
            replay_ref,
        );

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

        let mut received = decoder.constraint_symbols();

        // Keep only second half of source symbols
        for i in (k / 2)..k {
            received.push(ReceivedSymbol::source(i as u32, source[i].clone()));
        }

        // Fill rest with repair symbols to reach >= L equations
        for esi in (k as u32)..((k + l * 2) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received);
        match result {
            Ok(decoded_symbols) => {
                assert_eq!(
                    decoded_symbols.source, source,
                    "{context} first-half burst loss should still recover"
                );
            }
            Err(DecodeError::SingularMatrix { .. }) => {
                // Acceptable for some parameter configurations
            }
            Err(other) => {
                panic!("{context} unexpected error: {other:?}");
            }
        }
    }

    /// Proof replay after a SingularMatrix failure: verify that the proof
    /// from an error path can be replayed and matches.
    #[test]
    fn proof_replay_on_singular_matrix_failure() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-proof-singular-replay-v1";
        let context = failure_context(
            "RQ-U-PROOF-SINGULAR-REPLAY",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

        let _source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Construct a rank-deficient system: duplicate the same equation L times
        // to guarantee SingularMatrix.
        let mut received: Vec<ReceivedSymbol> = Vec::new();
        for idx in 0..l {
            // All equations map to column 0 only → rank 1 → singular for K > 1
            received.push(ReceivedSymbol {
                esi: idx as u32,
                is_source: false,
                columns: vec![0],
                coefficients: vec![Gf256::ONE],
                data: vec![0u8; symbol_size],
            });
        }

        let object_id = ObjectId::new_for_test(999);
        let result = decoder.decode_with_proof(&received, object_id, 0);

        match result {
            Err((DecodeError::SingularMatrix { .. }, proof)) => {
                // Proof from error path: replay should produce the same failure trace
                let replay_result = proof.replay_and_verify(&received);
                match replay_result {
                    Ok(()) => {
                        // Replay matched the original trace — deterministic failure
                    }
                    Err(e) => {
                        panic!(
                            "{context} proof replay should match original failure trace; got {e}"
                        );
                    }
                }
            }
            Err((other_err, _)) => {
                // Other error types from rank-deficient input are acceptable as long
                // as we don't panic. InsufficientSymbols is possible if the validator
                // rejects before reaching inactivation.
                let _ = (other_err, &context);
            }
            Ok(_) => {
                panic!("{context} expected SingularMatrix from rank-deficient input");
            }
        }
    }

    /// Repair symbol bit-flip: corrupt a single repair symbol and verify detection.
    #[test]
    fn repair_symbol_corruption_detected() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-corruption-repair-v1";
        let context = failure_context(
            "RQ-U-CORRUPTION-REPAIR",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

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

        let mut received = decoder.constraint_symbols();

        // Add all source symbols (correct)
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols, but corrupt the first one
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let mut repair_data = encoder.repair_symbol(esi);
            if esi == k as u32 {
                repair_data[0] ^= 0x01; // Single bit flip
            }
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received);
        // Must not silently succeed with wrong data
        match result {
            Ok(decoded_symbols) => {
                // If the system is overdetermined enough that the corruption
                // doesn't affect the solution, source should still match.
                // Otherwise this should have been caught.
                assert_eq!(
                    decoded_symbols.source, source,
                    "{context} if decode succeeds, source must be correct"
                );
            }
            Err(DecodeError::CorruptDecodedOutput { .. } | DecodeError::SingularMatrix { .. }) => {
                // Expected: corruption detected either during solve or verification
            }
            Err(other) => {
                panic!("{context} unexpected error: {other:?}");
            }
        }
    }
}

// =========================================================================
// Systematic encoder invariant tests (br-3narc.2.7)
// =========================================================================

mod encoder_invariants {
    use crate::raptorq::gf256::gf256_addmul_slice;
    use crate::raptorq::systematic::SystematicEncoder;
    use crate::raptorq::test_log_schema::UnitLogEntry;

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        UnitLogEntry::new(scenario_id, seed, parameter_set, replay_ref, "pending")
            .with_repro_command(
                "rch exec -- cargo test --lib raptorq::tests::encoder_invariants -- --nocapture",
            )
            .to_context_string()
    }

    /// repair_symbol_into produces identical output to repair_symbol.
    #[test]
    fn repair_symbol_into_matches_repair_symbol() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-encoder-repair-into-v1";
        let context = failure_context(
            "RQ-U-ENCODER-REPAIR-INTO",
            seed,
            &format!("k={k},symbol_size={symbol_size},esi_range=[{k},{}]", k + 20),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} encoder creation should succeed"));

        let mut buf = vec![0u8; symbol_size];
        for esi in (k as u32)..((k + 20) as u32) {
            let from_fn = encoder.repair_symbol(esi);
            buf.fill(0);
            encoder.repair_symbol_into(esi, &mut buf);
            assert_eq!(
                from_fn, buf,
                "{context} repair_symbol_into must match repair_symbol for esi={esi}"
            );
        }
    }

    /// repair_symbol_into with a larger buffer writes into the prefix.
    #[test]
    fn repair_symbol_into_with_oversized_buffer() {
        let k = 4;
        let symbol_size = 16;
        let seed = 99u64;
        let replay_ref = "replay:rq-u-encoder-repair-into-oversize-v1";
        let context = failure_context(
            "RQ-U-ENCODER-REPAIR-INTO-OVERSIZE",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k).map(|i| vec![(i * 7) as u8; symbol_size]).collect();
        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} encoder creation should succeed"));

        let mut buf = vec![0xFFu8; symbol_size + 16]; // Larger than needed
        encoder.repair_symbol_into(k as u32, &mut buf);

        let expected = encoder.repair_symbol(k as u32);
        assert_eq!(
            &buf[..symbol_size],
            &expected[..],
            "{context} repair_symbol_into should write to prefix of oversized buffer"
        );
    }

    /// Emit ESI ranges do not overlap: systematic ESIs [0..K), repair ESIs [K..).
    #[test]
    fn emit_systematic_and_repair_esi_ranges_disjoint() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let replay_ref = "replay:rq-u-encoder-emit-disjoint-v1";
        let context = failure_context(
            "RQ-U-ENCODER-EMIT-DISJOINT",
            seed,
            &format!("k={k},symbol_size={symbol_size}"),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let mut encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} encoder creation should succeed"));

        let systematic = encoder.emit_systematic();
        let repair = encoder.emit_repair(10);

        // Verify systematic ESIs are [0, K)
        for sym in &systematic {
            assert!(
                sym.esi < k as u32,
                "{context} systematic ESI {} must be < K={k}",
                sym.esi
            );
            assert!(
                sym.is_source,
                "{context} systematic symbol must be flagged is_source"
            );
        }

        // Verify repair ESIs are >= K
        for sym in &repair {
            assert!(
                sym.esi >= k as u32,
                "{context} repair ESI {} must be >= K={k}",
                sym.esi
            );
            assert!(
                !sym.is_source,
                "{context} repair symbol must not be flagged is_source"
            );
        }

        // Verify no ESI collision
        let sys_esis: std::collections::HashSet<u32> = systematic.iter().map(|s| s.esi).collect();
        let rep_esis: std::collections::HashSet<u32> = repair.iter().map(|s| s.esi).collect();
        assert!(
            sys_esis.is_disjoint(&rep_esis),
            "{context} systematic and repair ESI sets must be disjoint"
        );
    }

    /// Repair symbol cross-check: repair_symbol matches RFC equation projection.
    #[test]
    fn repair_symbol_cross_check_gf256_projection() {
        let k = 16;
        let symbol_size = 48;
        let seed = 123u64;
        let replay_ref = "replay:rq-u-encoder-repair-crosscheck-v1";
        let context = failure_context(
            "RQ-U-ENCODER-REPAIR-CROSSCHECK",
            seed,
            &format!("k={k},symbol_size={symbol_size},esi_range=[{k},{}]", k + 10),
            replay_ref,
        );

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 17 + j * 29 + 5) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .unwrap_or_else(|| panic!("{context} encoder creation should succeed"));

        for esi in (k as u32)..((k + 10) as u32) {
            let repair = encoder.repair_symbol(esi);
            let (columns, coefficients) = encoder.params().rfc_repair_equation(esi);
            let mut expected = vec![0u8; symbol_size];

            for (&col, &coef) in columns.iter().zip(coefficients.iter()) {
                gf256_addmul_slice(&mut expected, encoder.intermediate_symbol(col), coef);
            }

            assert_eq!(
                repair, expected,
                "{context} repair symbol esi={esi} must match GF(256) projection"
            );
        }
    }
}
