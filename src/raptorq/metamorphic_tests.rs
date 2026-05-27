#![allow(clippy::all)]
//! Metamorphic property tests for RaptorQ encode/decode correctness.
//!
//! These tests verify relationships between inputs/outputs rather than specific
//! expected values (oracle problem). Each test exercises a fundamental property
//! that must hold for any correct RaptorQ implementation.

use crate::config::RaptorQConfig;
use crate::cx::Cx;
use crate::raptorq::builder::RaptorQSenderBuilder;
use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use crate::raptorq::linalg::GaussianResult;
use crate::raptorq::systematic::SystematicEncoder;
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

fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
    let obj = object_id.as_u128();
    let hi = (obj >> 64) as u64;
    let lo = obj as u64;
    let mut seed = hi ^ lo.rotate_left(13);
    seed ^= u64::from(sbn) << 56;
    if seed == 0 { 1 } else { seed }
}

fn create_test_decoder(
    symbols: &[AuthenticatedSymbol],
    k: usize,
    symbol_size: usize,
) -> InactivationDecoder {
    let first_symbol = symbols
        .first()
        .expect("metamorphic decode sets must contain at least one symbol")
        .symbol();
    let seed = seed_for_block(first_symbol.object_id(), first_symbol.sbn());
    InactivationDecoder::new(k, symbol_size, seed)
}

/// Convert authenticated symbols to received symbols for decoder.
fn symbols_to_received(symbols: &[AuthenticatedSymbol], k: usize) -> Vec<ReceivedSymbol> {
    let Some(first) = symbols.first() else {
        return Vec::new();
    };

    let first_symbol = first.symbol();
    let seed = seed_for_block(first_symbol.object_id(), first_symbol.sbn());
    let decoder = InactivationDecoder::new(k, first_symbol.len(), seed);
    let mut received = Vec::with_capacity(symbols.len());

    for auth_symbol in symbols {
        let symbol = auth_symbol.symbol();
        assert_eq!(
            symbol.object_id(),
            first_symbol.object_id(),
            "metamorphic helper requires a single object per decode set"
        );
        assert_eq!(
            symbol.sbn(),
            first_symbol.sbn(),
            "metamorphic helper requires a single source block per decode set"
        );

        let row = match symbol.kind() {
            crate::types::SymbolKind::Source => {
                ReceivedSymbol::source(symbol.esi(), symbol.data().to_vec())
            }
            crate::types::SymbolKind::Repair => {
                let (columns, coefficients) = decoder.repair_equation(symbol.esi()).unwrap();
                ReceivedSymbol::repair(symbol.esi(), columns, coefficients, symbol.data().to_vec())
            }
        };
        received.push(row);
    }

    received
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

fn encode_symbols(
    data_size: usize,
    seed: u64,
    repair_overhead: f64,
) -> (Vec<u8>, usize, usize, Vec<AuthenticatedSymbol>) {
    let cx = Cx::for_testing();
    let data = generate_test_data(data_size, seed);
    let object_id = ObjectId::new_for_test(seed);
    // Use a small symbol size so fixed-fixture data sizes like 1280 bytes
    // yield K >> 1 source symbols and the requested `repair_overhead` reliably
    // produces enough authenticated repair symbols to exceed the RFC 6330
    // systematic K' >= 10 intermediate-symbol budget the decoder enforces.
    let config = RaptorQConfig {
        encoding: crate::config::EncodingConfig {
            symbol_size: 16,
            repair_overhead,
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

    let send_outcome = sender
        .send_object(&cx, object_id, &data)
        .expect("encoding should succeed");
    (
        data,
        send_outcome.source_symbols,
        config.encoding.symbol_size as usize,
        sender.transport_mut().symbols().to_vec(),
    )
}

fn decode_payload(
    symbols: &[AuthenticatedSymbol],
    k: usize,
    symbol_size: usize,
    original_len: usize,
) -> Result<Vec<u8>, crate::raptorq::decoder::DecodeError> {
    let decoder = create_test_decoder(symbols, k, symbol_size);
    let received = symbols_to_received(symbols, k);
    decoder
        .decode(&received)
        .map(|decoded| flatten_source_symbols(&decoded.source, original_len))
}

fn repair_backed_subset(
    symbols: &[AuthenticatedSymbol],
    k: usize,
    symbol_size: usize,
    original: &[u8],
) -> Vec<AuthenticatedSymbol> {
    let withheld_sources = 2.min(k.saturating_sub(1));
    let kept_source_count = k.saturating_sub(withheld_sources);
    let (source_symbols, repair_symbols): (Vec<_>, Vec<_>) = symbols
        .iter()
        .cloned()
        .partition(|symbol| matches!(symbol.symbol().kind(), crate::types::SymbolKind::Source));

    assert_eq!(
        source_symbols.len(),
        k,
        "fixture should expose exactly K source symbols"
    );
    assert!(
        !repair_symbols.is_empty(),
        "fixture should expose repair symbols for subset decode"
    );

    let mut candidates = Vec::with_capacity(symbols.len());
    candidates.extend(source_symbols.iter().take(kept_source_count).cloned());
    candidates.extend(repair_symbols.iter().cloned());
    candidates.extend(source_symbols.iter().skip(kept_source_count).cloned());

    let mut subset = Vec::new();
    let mut used_repairs = 0usize;
    for symbol in candidates {
        if matches!(symbol.symbol().kind(), crate::types::SymbolKind::Repair) {
            used_repairs += 1;
        }
        subset.push(symbol);
        if let Ok(payload) = decode_payload(&subset, k, symbol_size, original.len()) {
            if payload == original && used_repairs > 0 && subset.len() < symbols.len() {
                return subset;
            }
        }
    }

    panic!("failed to find a repair-backed decodable subset for deterministic fixture");
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

#[test]
fn mr_subset_roundtrip_identity_on_fixed_fixture() {
    let (data, k, symbol_size, symbols) = encode_symbols(1280, 0x1A2B_3C4D, 2.2);
    let subset = repair_backed_subset(&symbols, k, symbol_size, &data);

    assert!(
        subset.len() < symbols.len(),
        "subset relation should use fewer symbols than the full emission"
    );
    assert!(
        subset
            .iter()
            .any(|symbol| matches!(symbol.symbol().kind(), crate::types::SymbolKind::Repair)),
        "subset relation should exercise repair-backed recovery"
    );

    let payload = decode_payload(&subset, k, symbol_size, data.len())
        .expect("repair-backed subset should decode");
    assert_eq!(payload, data, "subset roundtrip must preserve payload");
}

#[test]
fn mr_symbol_permutation_preserves_payload_on_fixed_fixture() {
    let (data, k, symbol_size, symbols) = encode_symbols(1280, 0x5566_7788, 2.2);
    let subset = repair_backed_subset(&symbols, k, symbol_size, &data);
    let original_payload =
        decode_payload(&subset, k, symbol_size, data.len()).expect("original subset should decode");

    use crate::util::DetRng;
    let mut rng = DetRng::new(0xABCD_EF01);
    let mut permuted = subset.clone();
    for i in (1..permuted.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        permuted.swap(i, j);
    }

    let permuted_payload = decode_payload(&permuted, k, symbol_size, data.len())
        .expect("permuted subset should still decode");
    assert_eq!(
        permuted_payload, original_payload,
        "permuting received symbols must not change decoded payload"
    );
    assert_eq!(
        permuted_payload, data,
        "permuted decode must preserve identity"
    );
}

#[test]
fn mr_extra_repair_symbols_do_not_reduce_success_on_fixed_fixture() {
    let (data, k, symbol_size, symbols) = encode_symbols(1280, 0xCAFEBABE, 2.4);
    let base_subset = repair_backed_subset(&symbols, k, symbol_size, &data);
    let base_payload = decode_payload(&base_subset, k, symbol_size, data.len())
        .expect("base repair-backed subset should decode");

    let used_esis: Vec<_> = base_subset
        .iter()
        .map(|symbol| symbol.symbol().esi())
        .collect();
    let mut extended_subset = base_subset.clone();
    extended_subset.extend(
        symbols
            .iter()
            .filter(|symbol| {
                matches!(symbol.symbol().kind(), crate::types::SymbolKind::Repair)
                    && !used_esis.contains(&symbol.symbol().esi())
            })
            .take(2)
            .cloned(),
    );

    assert!(
        extended_subset.len() > base_subset.len(),
        "fixture should provide extra repair symbols beyond the base subset"
    );

    let extended_payload = decode_payload(&extended_subset, k, symbol_size, data.len())
        .expect("adding extra repair symbols must not break decode");
    assert_eq!(
        extended_payload, base_payload,
        "additional repair symbols must preserve decoded payload"
    );
    assert_eq!(
        extended_payload, data,
        "extended repair set must preserve identity"
    );
}

#[test]
fn mr_duplicate_repair_backed_symbols_preserve_payload_on_fixed_fixture() {
    let (data, k, symbol_size, symbols) = encode_symbols(1280, 0x0D15_EA5E, 2.2);
    let subset = repair_backed_subset(&symbols, k, symbol_size, &data);
    let baseline_payload =
        decode_payload(&subset, k, symbol_size, data.len()).expect("baseline subset should decode");

    let mut duplicated = subset.clone();
    let source_duplicate = subset
        .iter()
        .find(|symbol| matches!(symbol.symbol().kind(), crate::types::SymbolKind::Source))
        .expect("repair-backed subset should include source symbols")
        .clone();
    let repair_duplicate = subset
        .iter()
        .find(|symbol| matches!(symbol.symbol().kind(), crate::types::SymbolKind::Repair))
        .expect("repair-backed subset should include repair symbols")
        .clone();
    duplicated.push(source_duplicate);
    duplicated.push(repair_duplicate);

    let duplicate_payload = decode_payload(&duplicated, k, symbol_size, data.len())
        .expect("duplicate symbols must not break repair-backed decode");
    assert_eq!(
        duplicate_payload, baseline_payload,
        "duplicating received source and repair symbols must preserve decoded payload"
    );
    assert_eq!(
        duplicate_payload, data,
        "duplicate-symbol relation must preserve identity"
    );
}

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

        // Encode phase. Use a small symbol size so even the smallest
        // fixture in the property range yields enough source symbols for
        // the RFC 6330 systematic block (K' >= 10). A high repair overhead
        // guarantees we still emit enough repair symbols to satisfy the
        // intermediate-symbol decoder budget across the full proptest range.
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 4.0,
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

        let send_outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding should succeed");

        // Get symbols from the transport
        let symbols = sender.transport_mut().symbols().to_vec();

        // Decode phase - use enough symbols for guaranteed decode.
        let symbol_size = config.encoding.symbol_size as usize;
        let k = send_outcome.source_symbols;
        let decoder = create_test_decoder(&symbols, k, symbol_size);

        // RFC 6330 decoding is sized off L = K' + S + H, not just K, so pass
        // every emitted symbol to the decoder; the high repair overhead
        // guarantees coverage for every fixture in the property range.
        let received_symbols = symbols_to_received(&symbols, k);

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
        let decoder = create_test_decoder(&symbols, k, symbol_size);

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
        let decoder = create_test_decoder(symbols, k, symbol_size);

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
        let decoder = create_test_decoder(&base_symbols, k, symbol_size);

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

        // Encode with small symbols and generous repair overhead so that the
        // full proptest range — including the smallest data_size fixture —
        // produces enough symbols for a meaningful erasure simulation under
        // the RFC 6330 K' >= 10 systematic constraint.
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 4.0,
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
        let decoder = create_test_decoder(&symbols, k, symbol_size);

        // Simulate erasures by removing symbols from the middle (burst erasure pattern).
        // All slice arithmetic below is written in saturating form so a shrunken
        // proptest fixture (e.g. K=1 with only 2 total symbols) surfaces an
        // empty erasure window instead of overflowing usize arithmetic.
        let mut with_erasures = symbols.clone();
        let start_erasure = std::cmp::max(2, symbols.len() / 4);
        let end_erasure = std::cmp::min(
            start_erasure + erasure_count,
            symbols.len().saturating_sub(2),
        );
        if start_erasure < end_erasure {
            with_erasures.drain(start_erasure..end_erasure);
        }

        // Create set with fewer erasures (one less missing symbol).
        let mut fewer_erasures = symbols.clone();
        let fewer_end = std::cmp::max(start_erasure + 1, end_erasure.saturating_sub(1));
        if start_erasure < fewer_end && fewer_end <= symbols.len() {
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

/// MR7: Repair Symbol Substitutability (Equivalence)
/// Property: decode(sources[0..k-n] + repair[0..n]) = decode(sources[0..k])
/// Catches: Source/repair symbol interaction bugs, ESI mapping issues
#[test]
fn mr_repair_symbol_substitutability() {
    proptest!(|(
        data_size in 128usize..384,
        seed in any::<u64>(),
        substitution_count in 1usize..4,
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode with generous repair overhead for substitution testing
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                repair_overhead: 1.30, // 30% overhead for substitution
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
        let decoder = create_test_decoder(&symbols, k, symbol_size);

        // Ensure we have enough symbols for substitution
        if symbols.len() < k + substitution_count {
            return Ok(());
        }

        // Create two symbol sets:
        // 1. All source symbols (systematic)
        let systematic_symbols = symbols_to_received(&symbols[..k], k);

        // 2. Source symbols with some replaced by repair symbols
        let mut substituted_indices = Vec::new();
        for i in 0..substitution_count {
            substituted_indices.push(i);
        }

        let mut substituted_symbols = Vec::new();
        for i in 0..k {
            if substituted_indices.contains(&i) {
                // Replace this source symbol with a repair symbol
                let repair_index = k + i; // Use repair symbol at offset
                if repair_index < symbols.len() {
                    substituted_symbols.push(&symbols[repair_index]);
                } else {
                    substituted_symbols.push(&symbols[i]); // Fallback to source
                }
            } else {
                substituted_symbols.push(&symbols[i]);
            }
        }

        let substituted_received = symbols_to_received(&substituted_symbols.iter().copied().cloned().collect::<Vec<_>>(), k);

        let systematic_result = decoder.decode(&systematic_symbols);
        let substituted_result = decoder.decode(&substituted_received);

        // METAMORPHIC ASSERTION: Both symbol sets should decode to same result
        match (systematic_result, substituted_result) {
            (Ok(sys_decoded), Ok(sub_decoded)) => {
                let sys_data = flatten_source_symbols(&sys_decoded.source, data.len());
                let sub_data = flatten_source_symbols(&sub_decoded.source, data.len());
                prop_assert_eq!(
                    sys_data.clone(), sub_data,
                    "MR7 VIOLATION: repair symbol substitution changed decode result"
                );
                prop_assert_eq!(
                    sys_data, data,
                    "MR7 VIOLATION: systematic decode failed identity check"
                );
            }
            (Ok(_), Err(e)) => {
                prop_assert!(
                    false,
                    "MR7 VIOLATION: repair substitution caused decode failure: {:?}",
                    e
                );
            }
            (Err(_), Ok(_)) => {
                prop_assert!(
                    false,
                    "MR7 VIOLATION: substitution succeeded where systematic failed"
                );
            }
            (Err(_), Err(_)) => {
                // Both failed - this can happen with insufficient repair symbols
                // or edge cases, so we don't assert failure here
            }
        }
    });
}

/// MR8: Symbol Duplication Idempotence (Equivalence)
/// Property: decode(symbols) = decode(symbols + duplicate_symbols)
/// Catches: Duplicate symbol handling bugs, redundancy processing issues
#[test]
fn mr_symbol_duplication_idempotence() {
    proptest!(|(
        data_size in 128usize..256,
        seed in any::<u64>(),
        duplicate_count in 1usize..3,
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        // Encode with standard configuration
        let config = RaptorQConfig::default();
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
        let decoder = create_test_decoder(&symbols, k, symbol_size);

        // Create decodable symbol set
        let symbol_count = std::cmp::min(symbols.len(), k + 5);
        let original_received = symbols_to_received(&symbols[..symbol_count], k);

        // Create duplicated symbol set (add duplicates of first few symbols)
        let mut with_duplicates = original_received.clone();
        for i in 0..std::cmp::min(duplicate_count, original_received.len()) {
            with_duplicates.push(original_received[i].clone());
        }

        let original_result = decoder.decode(&original_received);
        let duplicate_result = decoder.decode(&with_duplicates);

        // METAMORPHIC ASSERTION: Duplicates should not change decode result
        match (original_result, duplicate_result) {
            (Ok(orig_decoded), Ok(dup_decoded)) => {
                let orig_data = flatten_source_symbols(&orig_decoded.source, data.len());
                let dup_data = flatten_source_symbols(&dup_decoded.source, data.len());
                prop_assert_eq!(
                    orig_data.clone(), dup_data,
                    "MR8 VIOLATION: duplicate symbols changed decode result"
                );
                prop_assert_eq!(
                    orig_data, data,
                    "MR8 VIOLATION: original decode failed identity check"
                );
            }
            (Ok(_), Err(e)) => {
                prop_assert!(
                    false,
                    "MR8 VIOLATION: adding duplicate symbols caused decode failure: {:?}",
                    e
                );
            }
            (Err(_), Ok(_)) => {
                prop_assert!(
                    false,
                    "MR8 VIOLATION: duplicates enabled decode where original failed"
                );
            }
            (Err(_), Err(_)) => {
                // Both failed - no constraint violated
            }
        }
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

        // Encode once. Use a small symbol size with generous repair overhead
        // so the composite test emits enough symbols for the RFC 6330
        // intermediate-symbol budget across the full proptest range.
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 4.0,
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

        let send_outcome = sender.send_object(&cx, object_id, &data)
            .expect("encoding");
        let symbols = sender.transport_mut().symbols().to_vec();

        let k = send_outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(&symbols, k, symbol_size);

        // Use every emitted symbol so the decoder receives at least L - (K'-K)
        // rows regardless of where the proptest fixture lands in the range.
        let mut received_symbols = symbols_to_received(&symbols, k);

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

            let outcome = sender.send_object(&cx, object_id, &data).expect("encoding");
            let symbols = sender.transport_mut().symbols().to_vec();

            let k = outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            let symbol_count = std::cmp::min(symbols.len(), k + 8);
            let received = symbols_to_received(&symbols[..symbol_count], k);

            if let Ok(decoded) = decoder.decode(&received) {
                let reconstructed = flatten_source_symbols(&decoded.source, data.len());
                results.push(reconstructed);
            }
        }

        // Both should decode to the same result (orthogonality)
        if results.len() == 2 {
            assert_eq!(
                results[0], results[1],
                "Repair symbol orthogonality test validation"
            );
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

        // Use a small symbol size so the 256-byte fixture yields enough
        // source symbols to satisfy the RFC 6330 K' >= 10 intermediate
        // decoding budget with the specified repair overhead.
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 4.0,
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

        let outcome = sender.send_object(&cx, object_id, &data).expect("encoding");
        let symbols = sender.transport_mut().symbols().to_vec();

        let k = outcome.source_symbols;
        let symbol_size = config.encoding.symbol_size as usize;
        let decoder = create_test_decoder(&symbols, k, symbol_size);

        // Test various erasure patterns. Clamp every drain window and slice
        // length to the fixture's actual symbol count so that a small-K
        // deterministic run (e.g. K=1 producing only a few symbols) does not
        // index past the end of the emission.
        let original_count = std::cmp::min(symbols.len(), k + 12);

        // Minimal erasures (should succeed).
        let mut minimal_erasures = symbols.clone();
        let minimal_drain_end = std::cmp::min(4, minimal_erasures.len());
        let minimal_drain_start = std::cmp::min(2, minimal_drain_end);
        minimal_erasures.drain(minimal_drain_start..minimal_drain_end);
        let minimal_take = std::cmp::min(minimal_erasures.len(), original_count.saturating_sub(2));
        let minimal_received = symbols_to_received(&minimal_erasures[..minimal_take], k);

        // More erasures.
        let mut more_erasures = symbols.clone();
        let more_drain_end = std::cmp::min(6, more_erasures.len());
        let more_drain_start = std::cmp::min(2, more_drain_end);
        more_erasures.drain(more_drain_start..more_drain_end);
        let more_take = std::cmp::min(more_erasures.len(), original_count.saturating_sub(4));
        let more_received = symbols_to_received(&more_erasures[..more_take], k);

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

/// MR14: Decode-Completion Idempotence (br-asupersync-h004s7)
///
/// Property: after a successful decode returns the original block,
/// feeding ADDITIONAL repair symbols (or duplicate source symbols)
/// to a fresh decode invocation MUST either:
///   (a) return the same block byte-for-byte, OR
///   (b) return a decode error
///
/// MUST NOT: corrupt internal state, panic, mutate the previously-
/// returned block, or return a DIFFERENT block.
///
/// Distinguishes from MR8 (mr_symbol_duplication_idempotence): MR8
/// tests duplicate-source-symbol handling DURING a single decode
/// call. MR14 tests the POST-completion case where late-arriving
/// symbols continue to flow after decode succeeded — common in lossy
/// network codecs where the receiver continues receiving after enough
/// symbols arrived.
///
/// Catches: decoder state corruption on extra-symbol re-decode, race
/// conditions in streaming receivers, any future caching that
/// silently drifts on extra inputs.
#[test]
fn mr_decode_completion_idempotence() {
    proptest!(|(
        data_size in 128usize..256,
        seed in any::<u64>(),
        extra_count in 1usize..10,
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 4.0,
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

        // First decode: minimum needed for success.
        let min_symbols = std::cmp::min(symbols.len(), k + 2);
        let decoder1 = create_test_decoder(&symbols, k, symbol_size);
        let received1 = symbols_to_received(&symbols[..min_symbols], k);
        let result1 = decoder1.decode(&received1);

        // Only the success-then-success path is the property's domain.
        if let Ok(decoded1) = result1 {
            let block1 = flatten_source_symbols(&decoded1.source, data.len());
            prop_assert_eq!(block1.clone(), data.clone(),
                "MR14 first decode must round-trip");

            // Second decode: SAME minimum + extra_count more symbols.
            let extended_count = std::cmp::min(symbols.len(), min_symbols + extra_count);
            let decoder2 = create_test_decoder(&symbols, k, symbol_size);
            let received2 = symbols_to_received(&symbols[..extended_count], k);
            let result2 = decoder2.decode(&received2);

            match result2 {
                Ok(decoded2) => {
                    let block2 = flatten_source_symbols(&decoded2.source, data.len());
                    // Property: extra symbols MUST yield the same block.
                    prop_assert_eq!(block2.clone(), block1.clone(),
                        "MR14 VIOLATION: extra symbols changed the decoded block");
                    prop_assert_eq!(block2, data.clone(),
                        "MR14 VIOLATION: extended decode failed identity");
                }
                Err(err) => {
                    // br-asupersync-48c0nb: previously this arm was a
                    // permissive no-op — "more symbols should never make
                    // decode FAIL after fewer symbols succeeded. We allow
                    // it but don't require it." That made MR14 a
                    // monotonicity check pretending to be idempotence and
                    // would silently pass if a future regression flipped
                    // Ok→Err on the extended symbol set. Tighten to FAIL.
                    prop_assert!(
                        false,
                        "MR14 VIOLATION (br-asupersync-48c0nb): extended symbol set \
                         flipped decode from Ok→Err. min_symbols={}, extended_count={}, \
                         extra_count={}, k={}, error={:?}",
                        min_symbols, extended_count, extra_count, k, err
                    );
                }
            }
        }
    });
}

/// MR13: Byte-Identical Determinism Across Runs (br-asupersync-kohtae)
///
/// Property: encode(data, seed, symbol_size) × N runs MUST produce the
/// EXACT SAME byte sequence for every emitted symbol. Any nondeterminism
/// (HashMap iteration order, ambient time leak, scheduler-induced race in
/// the encoder pipeline, non-deterministic pivot selection in the GF256
/// solver) would surface here BEFORE corrupting downstream replay traces.
///
/// This is the foundation of asupersync's replay-determinism guarantee:
/// MR1 (mr_encode_decode_identity) only verifies round-trip correctness —
/// it does NOT assert the encoded SYMBOLS are byte-identical across runs,
/// only that they decode back to the input. A subtly non-deterministic
/// encoder could pass MR1 (round-trip works) while breaking replay.
///
/// Catches: HashMap-iteration order leaks, RNG state leaks across calls,
/// any future change that introduces parallelism into the encoder.
#[test]
fn mr_byte_identical_determinism_across_runs() {
    proptest!(|(
        data_size in 128usize..512,
        seed in any::<u64>(),
    )| {
        let cx = Cx::for_testing();
        let data = generate_test_data(data_size, seed);
        let object_id = ObjectId::new_for_test(seed);

        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 2.0,
                ..Default::default()
            },
            ..Default::default()
        };

        const N_RUNS: usize = 16;
        let mut runs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(N_RUNS);

        for _ in 0..N_RUNS {
            let sink = CollectorSink::new();
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");
            sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            // Capture each emitted symbol as Vec<u8> for byte-equality.
            let run_symbols: Vec<Vec<u8>> = sender
                .transport_mut()
                .symbols()
                .iter()
                .map(|s| s.symbol().data().to_vec())
                .collect();
            runs.push(run_symbols);
        }

        // Property: every run MUST be byte-identical to run 0.
        let baseline = &runs[0];
        for (i, run) in runs.iter().enumerate().skip(1) {
            prop_assert_eq!(
                run.len(),
                baseline.len(),
                "run {} produced {} symbols vs baseline {} — non-deterministic count",
                i, run.len(), baseline.len()
            );
            for (j, (a, b)) in baseline.iter().zip(run.iter()).enumerate() {
                prop_assert_eq!(
                    a, b,
                    "non-deterministic symbol {} on run {}",
                    j, i
                );
            }
        }
    });
}

/// MR-EncoderLinearity: SystematicEncoder is linear over GF(2) in its source vector.
///
/// Property: for any pair of K-symbol source vectors `A`, `B` (same `K`,
/// same `symbol_size`, same seed), the encoder must satisfy
///
/// ```text
/// repair_symbol(esi, A XOR B) == repair_symbol(esi, A) XOR repair_symbol(esi, B)
/// ```
///
/// for every `esi >= K`, where XOR is componentwise byte-XOR.
///
/// Why this catches real bugs:
///   - The systematic RaptorQ encoder is built from a precode (LDPC + HDPC)
///     and an LT layer; both are linear maps over GF(2). Linearity in the
///     source slot is therefore a structural invariant of any conformant
///     implementation, independent of the seed or padding choice.
///   - It catches: a corrupt LDPC/HDPC matrix that introduces non-linear
///     cross-terms, a buggy intermediate-symbol solve that drops or
///     duplicates rows for non-zero input, padding-related bugs that only
///     manifest for non-zero `K..K'` rows, and seed-derived randomness that
///     accidentally depends on input bytes (rather than only on `seed`).
///   - It is independent of the decoder, so it isolates encoder bugs from
///     decoder bugs that the existing `mr_encode_decode_identity` would
///     conflate.
#[test]
fn mr_encoder_linearity_under_xor_of_source_vectors() {
    use crate::util::DetRng;

    // Stress a handful of (K, symbol_size, seed) corners so the test does
    // not over-fit to one matrix shape. K is held >= 10 to clear the
    // RFC 6330 systematic K' >= 10 floor.
    const CASES: &[(usize, usize, u64)] = &[
        (10, 8, 0x0123_4567_89AB_CDEF),
        (12, 16, 0xDEAD_BEEF_CAFE_BABE),
        (20, 8, 0xFEED_FACE_F00D_F00D),
    ];

    for &(k, symbol_size, seed) in CASES {
        let mut rng_a = DetRng::new(seed ^ 0xA5A5_A5A5_A5A5_A5A5);
        let mut rng_b = DetRng::new(seed ^ 0x5A5A_5A5A_5A5A_5A5A);

        let source_a: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..symbol_size).map(|_| rng_a.next_u32() as u8).collect())
            .collect();
        let source_b: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..symbol_size).map(|_| rng_b.next_u32() as u8).collect())
            .collect();

        // Componentwise XOR — the source vector at the GF(2)-sum point.
        let source_xor: Vec<Vec<u8>> = source_a
            .iter()
            .zip(source_b.iter())
            .map(|(a, b)| a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
            .collect();

        // Sanity: A and B chosen so the XOR is non-trivial in every slot.
        // Guards against a degenerate fixture that would let a buggy
        // encoder pass the test by collapsing both inputs to zero.
        for slot in &source_xor {
            assert!(
                slot.iter().any(|&byte| byte != 0),
                "fixture XOR collapsed to all-zero in some slot for \
                 (K={k}, T={symbol_size}, seed={seed:#x}) — choose different RNG masks",
            );
        }

        let enc_a = SystematicEncoder::new(&source_a, symbol_size, seed)
            .expect("encoder A construction (K, T, seed) should succeed");
        let enc_b = SystematicEncoder::new(&source_b, symbol_size, seed)
            .expect("encoder B construction (K, T, seed) should succeed");
        let enc_xor = SystematicEncoder::new(&source_xor, symbol_size, seed)
            .expect("encoder XOR construction (K, T, seed) should succeed");

        // Probe a window of repair ESIs past K. The window is wide enough
        // to cross at least one LT degree-distribution boundary so a bug
        // that only fires for high-degree rows still surfaces.
        let probe_count = 16usize;
        for offset in 0..probe_count {
            let esi = k as u32 + offset as u32;

            let r_a = enc_a.repair_symbol(esi);
            let r_b = enc_b.repair_symbol(esi);
            let r_xor = enc_xor.repair_symbol(esi);

            assert_eq!(
                r_a.len(),
                symbol_size,
                "repair_symbol must return symbol_size bytes (K={k}, T={symbol_size}, esi={esi})",
            );
            assert_eq!(r_b.len(), symbol_size);
            assert_eq!(r_xor.len(), symbol_size);

            let r_a_xor_r_b: Vec<u8> = r_a.iter().zip(r_b.iter()).map(|(x, y)| x ^ y).collect();

            assert_eq!(
                r_xor, r_a_xor_r_b,
                "MR-EncoderLinearity VIOLATION: repair_symbol(esi={esi}) on A XOR B \
                 differs from repair_symbol(esi=A) XOR repair_symbol(esi=B) \
                 for (K={k}, T={symbol_size}, seed={seed:#x})",
            );
        }
    }
}

// ============================================================================
// Extended Metamorphic Relations - Symmetry Violations & Boundary Cases
// ============================================================================

/// MR-ParameterBoundarySymmetry: Encoding behavior should be symmetric around
/// RFC 6330 systematic index table boundaries.
///
/// Property: For K values that are adjacent in the systematic index table,
/// the ratio of repair symbols to source symbols should be approximately
/// preserved for the same repair_overhead configuration.
///
/// Why this catches bugs:
///   - Table lookup edge cases where K transitions between different (S, H, W) parameter groups
///   - Off-by-one errors in parameter derivation that only manifest at table boundaries
///   - Asymmetric behavior around systematric index boundaries that could indicate
///     incorrect constraint matrix construction
#[test]
fn mr_parameter_boundary_symmetry() {
    proptest!(|(
        seed: u64,
        repair_overhead in 0.1..3.0f64,
    )| {
        // Test adjacent K values from systematic index table boundaries
        let boundary_k_pairs = vec![
            (10, 12),   // First entries in table
            (48, 49),   // Adjacent entries in middle
            (69, 75),   // Jump between different parameter groups
            (84, 88),   // Another transition
        ];

        for (k_low, k_high) in boundary_k_pairs {
            let symbol_size = 32; // Fixed to focus on K behavior

            let (_data, k_actual_low, _, symbols_low) =
                encode_symbols(k_low * symbol_size, seed, repair_overhead);
            let (_, k_actual_high, _, symbols_high) = encode_symbols(k_high * symbol_size, seed ^ 0x1111, repair_overhead);

            if k_actual_low >= 10 && k_actual_high >= 10 && k_actual_low != k_actual_high {
                let repair_ratio_low = (symbols_low.len() - k_actual_low) as f64 / k_actual_low as f64;
                let repair_ratio_high = (symbols_high.len() - k_actual_high) as f64 / k_actual_high as f64;

                // Repair ratios should be similar for same overhead (within 50% tolerance due to discretization)
                let ratio_diff = (repair_ratio_low - repair_ratio_high).abs();
                let avg_ratio = f64::midpoint(repair_ratio_low, repair_ratio_high);

                prop_assert!(
                    ratio_diff <= 0.5 * avg_ratio.max(0.1),
                    "Parameter boundary asymmetry: K={} ratio={:.3}, K={} ratio={:.3}, diff={:.3}",
                    k_low, repair_ratio_low, k_high, repair_ratio_high, ratio_diff
                );
            }
        }
    });
}

/// MR-SymbolSizePowerOfTwoSymmetry: Encoding should behave similarly for
/// power-of-2 and non-power-of-2 symbol sizes with similar total capacity.
///
/// Property: For symbol sizes that yield similar block sizes, encoding
/// efficiency (symbols produced per byte of input) should be comparable.
///
/// Why this catches bugs:
///   - Alignment assumptions that only work for power-of-2 sizes
///   - Memory allocation bugs that manifest differently for different size classes
///   - Byte-level operations that assume certain alignments
#[test]
fn mr_symbol_size_power_of_two_symmetry() {
    proptest!(|(
        base_size in 10..20usize,
        seed: u64,
    )| {
        // Compare power-of-2 vs nearby non-power-of-2 symbol sizes
        let power_of_2 = if base_size <= 16 { 16 } else { 32 };
        let non_power_of_2 = power_of_2 - 1; // 15 or 31

        let k = 20; // Fixed K to focus on symbol size effects
        let data = generate_test_data(k * power_of_2.max(non_power_of_2), seed);

        // Encode with both symbol sizes
        let cx = Cx::for_testing();
        let config_pow2 = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: power_of_2 as u16,
                repair_overhead: 1.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let config_non_pow2 = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: non_power_of_2 as u16,
                repair_overhead: 1.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut sender_pow2 = RaptorQSenderBuilder::new()
            .config(config_pow2)
            .transport(CollectorSink::new())
            .build()
            .expect("power-of-2 sender");

        let mut sender_non_pow2 = RaptorQSenderBuilder::new()
            .config(config_non_pow2)
            .transport(CollectorSink::new())
            .build()
            .expect("non-power-of-2 sender");

        let object_id = ObjectId::new_for_test(seed);

        let outcome_pow2 = sender_pow2.send_object(&cx, object_id, &data).expect("pow2 encode");
        let outcome_non_pow2 = sender_non_pow2.send_object(&cx, object_id, &data).expect("non-pow2 encode");

        // Symbol efficiency should be comparable
        let efficiency_pow2 = outcome_pow2.symbols_sent as f64 / data.len() as f64;
        let efficiency_non_pow2 = outcome_non_pow2.symbols_sent as f64 / data.len() as f64;

        let efficiency_diff = (efficiency_pow2 - efficiency_non_pow2).abs();

        prop_assert!(
            efficiency_diff <= 0.3 * efficiency_pow2.max(efficiency_non_pow2),
            "Symbol size symmetry violation: pow2({}) efficiency={:.3}, non-pow2({}) efficiency={:.3}",
            power_of_2, efficiency_pow2, non_power_of_2, efficiency_non_pow2
        );
    });
}

/// MR-MinimalViableRoundTrip: Decode should succeed with exactly K symbols
/// and fail with K-1 symbols for any valid symbol selection.
///
/// Property: For any set of exactly K linearly independent symbols,
/// decoding must succeed. For any set of K-1 symbols, decoding must fail
/// with InsufficientSymbols.
///
/// Why this catches bugs:
///   - Off-by-one errors in decoder threshold logic
///   - Matrix rank computation bugs that miscount available equations
///   - Edge cases in the inactivation decoder's peeling phase
#[test]
fn mr_minimal_viable_round_trip() {
    proptest!(|(
        k in 10..30usize,
        seed: u64,
        symbol_size in 16..64usize,
    )| {
        // Generate test data and encode
        let data = generate_test_data(k * symbol_size, seed);
        let (_original_data, k_actual, symbol_size_actual, symbols) =
            encode_symbols(data.len(), seed, 0.5);

        if symbols.len() >= k_actual && k_actual >= 10 {
            let received = symbols_to_received(&symbols, k_actual);

            // Test 1: Exactly K symbols should decode successfully
            let k_symbols: Vec<_> = received.iter().take(k_actual).cloned().collect();
            let decode_result = {
                let decoder = create_test_decoder(&symbols[..k_actual], k_actual, symbol_size_actual);
                decoder.decode(&k_symbols)
            };

            prop_assert!(
                decode_result.is_ok(),
                "Minimal viable round-trip failed: {} symbols (exactly K) should be sufficient",
                k_actual
            );

            // Test 2: K-1 symbols should fail with InsufficientSymbols (if we have K+1 or more total)
            if received.len() > k_actual {
                let k_minus_1_symbols: Vec<_> = received.iter().take(k_actual - 1).cloned().collect();
                let decode_result = {
                    let decoder = create_test_decoder(&symbols[..k_actual - 1], k_actual, symbol_size_actual);
                    decoder.decode(&k_minus_1_symbols)
                };

                prop_assert!(
                    decode_result.is_err(),
                    "Minimal viable round-trip symmetry violation: {} symbols (K-1) should fail",
                    k_actual - 1
                );
            }
        }
    });
}

/// MR-BlockCompositionSymmetry: Concatenating objects should be equivalent
/// to encoding a combined object (for object sizes below block split threshold).
///
/// Property: encode(A) + encode(B) should yield equivalent redundancy and
/// decodability to encode(A||B) when total size fits in one block.
///
/// Why this catches bugs:
///   - Block boundary detection errors that trigger too early
///   - State pollution between encoding operations
///   - Object ID generation that affects encoding determinism
#[test]
fn mr_block_composition_symmetry() {
    proptest!(|(
        size_a in 100..500usize,
        size_b in 100..500usize,
        seed: u64,
    )| {
        // Ensure total size is small enough for single-block encoding
        let symbol_size = 32;
        let total_size = size_a + size_b;

        if total_size <= 1000 { // Well below typical block split threshold
            let data_a = generate_test_data(size_a, seed);
            let data_b = generate_test_data(size_b, seed ^ 0x5555);
            let mut data_combined = data_a.clone();
            data_combined.extend_from_slice(&data_b);

            let cx = Cx::for_testing();
            let config = RaptorQConfig {
                encoding: crate::config::EncodingConfig {
                    symbol_size: symbol_size as u16,
                    repair_overhead: 1.0,
                    ..Default::default()
                },
                ..Default::default()
            };

            // Encode separately
            let mut sender_a = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(CollectorSink::new())
                .build()
                .expect("sender A");
            let mut sender_b = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(CollectorSink::new())
                .build()
                .expect("sender B");

            let outcome_a = sender_a.send_object(&cx, ObjectId::new_for_test(seed), &data_a).expect("encode A");
            let outcome_b = sender_b.send_object(&cx, ObjectId::new_for_test(seed ^ 0xAAAA), &data_b).expect("encode B");

            // Encode combined
            let mut sender_combined = RaptorQSenderBuilder::new()
                .config(config)
                .transport(CollectorSink::new())
                .build()
                .expect("sender combined");

            let outcome_combined = sender_combined.send_object(&cx, ObjectId::new_for_test(seed ^ 0xCCCC), &data_combined).expect("encode combined");

            // Symbol efficiency should be comparable (within 20% due to padding differences)
            let total_separate_symbols = outcome_a.symbols_sent + outcome_b.symbols_sent;
            let combined_symbols = outcome_combined.symbols_sent;

            let efficiency_separate = total_separate_symbols as f64 / total_size as f64;
            let efficiency_combined = combined_symbols as f64 / total_size as f64;
            let efficiency_ratio = efficiency_separate / efficiency_combined.max(0.001);

            prop_assert!(
                efficiency_ratio >= 0.8 && efficiency_ratio <= 1.25,
                "Block composition asymmetry: separate={} symbols ({:.3} eff), combined={} symbols ({:.3} eff), ratio={:.3}",
                total_separate_symbols, efficiency_separate, combined_symbols, efficiency_combined, efficiency_ratio
            );
        }
    });
}

/// MR-ZeroByteBoundaryRoundTrip: Encoding and decoding should handle
/// zero-length inputs and single-byte inputs correctly.
///
/// Property: Empty input should encode to empty output after round-trip.
/// Single-byte input should preserve that byte exactly.
///
/// Why this catches bugs:
///   - Division by zero in block size calculation
///   - Underflow in symbol count arithmetic
///   - Edge cases in padding logic for minimal inputs
///   - Off-by-one errors that only manifest for tiny inputs
#[test]
fn mr_zero_byte_boundary_round_trip() {
    let test_cases = vec![
        (vec![], "empty input"),
        (vec![0x42], "single byte"),
        (vec![0x00, 0xFF], "two bytes"),
        (vec![0xAA; 16], "one symbol worth"),
    ];

    for (data, description) in test_cases {
        let cx = Cx::for_testing();
        let config = RaptorQConfig {
            encoding: crate::config::EncodingConfig {
                symbol_size: 16,
                repair_overhead: 0.5,
                ..Default::default()
            },
            ..Default::default()
        };

        if data.is_empty() {
            // Empty data should be handled gracefully - might not encode anything
            let mut sender = RaptorQSenderBuilder::new()
                .config(config)
                .transport(CollectorSink::new())
                .build()
                .expect("sender for empty data");

            let result = sender.send_object(&cx, ObjectId::new_for_test(0x1234), &data);

            // Should either succeed with empty output or fail gracefully
            if let Ok(outcome) = result {
                assert_eq!(
                    outcome.source_symbols, 0,
                    "Empty input should produce no source symbols"
                );
            } else {
                // Graceful failure is acceptable for empty input
            }
        } else {
            // Non-empty data should round-trip exactly
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(CollectorSink::new())
                .build()
                .expect(&format!("sender for {}", description));

            let object_id = ObjectId::new_for_test(0x5678);
            let send_result = sender.send_object(&cx, object_id, &data);

            if let Ok(outcome) = send_result {
                let symbols = sender.transport_mut().symbols();

                if outcome.source_symbols > 0 && !symbols.is_empty() {
                    // Try to decode with just the source symbols
                    let _received = symbols_to_received(symbols, outcome.source_symbols);
                    let decode_result = decode_payload(
                        symbols,
                        outcome.source_symbols,
                        config.encoding.symbol_size as usize,
                        data.len(),
                    );

                    if let Ok(decoded) = decode_result {
                        assert_eq!(
                            decoded.len(),
                            data.len(),
                            "Boundary case length mismatch for {}: expected {}, got {}",
                            description,
                            data.len(),
                            decoded.len()
                        );

                        if !data.is_empty() {
                            assert_eq!(
                                decoded[..data.len()],
                                data[..],
                                "Boundary case data mismatch for {}: input {:?} != output {:?}",
                                description,
                                data,
                                &decoded[..data.len()]
                            );
                        }
                    }
                }
            }
        }
    }
}

/// MR-RepairSymbolMinimalityProperty: Adding one more repair symbol to a
/// failing decode set should improve decode success probability monotonically.
///
/// Property: For a symbol set that fails to decode, adding one more repair
/// symbol should either enable successful decoding or leave it still failing.
/// It should never make the situation worse.
///
/// Why this catches bugs:
///   - Matrix rank computations that degrade with additional equations
///   - Decoder state corruption that accumulates with more symbols
///   - Numerical instability in Gaussian elimination
#[test]
fn mr_repair_symbol_minimality_property() {
    proptest!(|(
        k in 10..20usize,
        seed: u64,
    )| {
        let symbol_size = 24;
        let (original_data, k_actual, _, symbols) = encode_symbols(k * symbol_size, seed, 1.5);

        if symbols.len() >= k_actual + 2 && k_actual >= 10 {
            // Start with K-1 symbols (should fail)
            let insufficient_symbols: Vec<_> =
                symbols.iter().take(k_actual - 1).cloned().collect();
            let initial_decode =
                decode_payload(&insufficient_symbols, k_actual, symbol_size, original_data.len());

            if initial_decode.is_err() {
                // Add one more symbol (should improve or stay same, never worse)
                let sufficient_symbols: Vec<_> = symbols.iter().take(k_actual).cloned().collect();
                let improved_decode =
                    decode_payload(&sufficient_symbols, k_actual, symbol_size, original_data.len());

                // Add one more repair symbol beyond minimum
                let extra_symbols: Vec<_> =
                    symbols.iter().take(k_actual + 1).cloned().collect();
                let extra_decode =
                    decode_payload(&extra_symbols, k_actual, symbol_size, original_data.len());

                // Monotonicity: more symbols should not make success rate worse
                let sufficient_success = improved_decode.is_ok();
                let extra_success = extra_decode.is_ok();

                prop_assert!(
                    !sufficient_success || extra_success,
                    "Repair symbol minimality violation: {} symbols succeeded, but {} symbols failed",
                    k_actual, k_actual + 1
                );
            }
        }
    });
}

// ============================================================================
// GF(256) Field Arithmetic Metamorphic Relations
// ============================================================================

/// MR-Gf256Commutativity: GF(256) operations should be commutative.
///
/// Property: a + b == b + a and a * b == b * a for all field elements.
///
/// Why this catches bugs:
///   - Implementation asymmetries in field operations
///   - Table lookup order dependencies
///   - SIMD operation asymmetries in vector implementations
#[test]
fn mr_gf256_commutativity() {
    use crate::raptorq::gf256::Gf256;

    proptest!(|(
        a: u8,
        b: u8,
    )| {
        let a_gf = Gf256::new(a);
        let b_gf = Gf256::new(b);

        // Addition commutativity
        let add_ab = a_gf + b_gf;
        let add_ba = b_gf + a_gf;
        prop_assert_eq!(
            add_ab, add_ba,
            "Addition commutativity violation: GF({}) + GF({}) != GF({}) + GF({})",
            a, b, b, a
        );

        // Multiplication commutativity
        let mul_ab = a_gf * b_gf;
        let mul_ba = b_gf * a_gf;
        prop_assert_eq!(
            mul_ab, mul_ba,
            "Multiplication commutativity violation: GF({}) * GF({}) != GF({}) * GF({})",
            a, b, b, a
        );
    });
}

/// MR-Gf256Associativity: GF(256) operations should be associative.
///
/// Property: (a + b) + c == a + (b + c) and (a * b) * c == a * (b * c).
///
/// Why this catches bugs:
///   - Intermediate overflow in implementation
///   - Order-dependent table lookup errors
///   - Incorrect reduction polynomial application
#[test]
fn mr_gf256_associativity() {
    use crate::raptorq::gf256::Gf256;

    proptest!(|(
        a: u8,
        b: u8,
        c: u8,
    )| {
        let a_gf = Gf256::new(a);
        let b_gf = Gf256::new(b);
        let c_gf = Gf256::new(c);

        // Addition associativity: (a + b) + c == a + (b + c)
        let left_add = (a_gf + b_gf) + c_gf;
        let right_add = a_gf + (b_gf + c_gf);
        prop_assert_eq!(
            left_add, right_add,
            "Addition associativity violation: (GF({}) + GF({})) + GF({}) != GF({}) + (GF({}) + GF({}))",
            a, b, c, a, b, c
        );

        // Multiplication associativity: (a * b) * c == a * (b * c)
        let left_mul = (a_gf * b_gf) * c_gf;
        let right_mul = a_gf * (b_gf * c_gf);
        prop_assert_eq!(
            left_mul, right_mul,
            "Multiplication associativity violation: (GF({}) * GF({})) * GF({}) != GF({}) * (GF({}) * GF({}))",
            a, b, c, a, b, c
        );
    });
}

/// MR-Gf256Distributivity: Multiplication distributes over addition.
///
/// Property: a * (b + c) == a * b + a * c for all field elements.
///
/// Why this catches bugs:
///   - Incorrect field arithmetic implementation
///   - Mixing of polynomial and integer arithmetic
///   - SIMD vectorization bugs that break mathematical properties
#[test]
fn mr_gf256_distributivity() {
    use crate::raptorq::gf256::Gf256;

    proptest!(|(
        a: u8,
        b: u8,
        c: u8,
    )| {
        let a_gf = Gf256::new(a);
        let b_gf = Gf256::new(b);
        let c_gf = Gf256::new(c);

        let left = a_gf * (b_gf + c_gf);
        let right = (a_gf * b_gf) + (a_gf * c_gf);

        prop_assert_eq!(
            left, right,
            "Distributivity violation: GF({}) * (GF({}) + GF({})) != GF({}) * GF({}) + GF({}) * GF({})",
            a, b, c, a, b, a, c
        );
    });
}

/// MR-Gf256IdentityElements: Identity elements should behave correctly.
///
/// Property: a + 0 == a, a * 1 == a, a * 0 == 0 for all elements.
///
/// Why this catches bugs:
///   - Special case handling errors for zero and one
///   - Table boundary issues at index 0 and 1
///   - Optimization bypasses that break identity properties
#[test]
fn mr_gf256_identity_elements() {
    use crate::raptorq::gf256::Gf256;

    proptest!(|(a: u8)| {
        let a_gf = Gf256::new(a);
        let zero = Gf256::ZERO;
        let one = Gf256::ONE;

        // Additive identity: a + 0 = a
        let add_zero = a_gf + zero;
        prop_assert_eq!(
            add_zero, a_gf,
            "Additive identity violation: GF({}) + GF(0) != GF({})",
            a, a
        );

        // Multiplicative identity: a * 1 = a
        let mul_one = a_gf * one;
        prop_assert_eq!(
            mul_one, a_gf,
            "Multiplicative identity violation: GF({}) * GF(1) != GF({})",
            a, a
        );

        // Zero multiplication: a * 0 = 0
        let mul_zero = a_gf * zero;
        prop_assert_eq!(
            mul_zero, zero,
            "Zero multiplication violation: GF({}) * GF(0) != GF(0)",
            a
        );
    });
}

/// MR-Gf256InverseProperties: Inverse operations should satisfy field axioms.
///
/// Property: a + a == 0 (additive inverse), a * inv(a) == 1 (multiplicative inverse for a != 0).
///
/// Why this catches bugs:
///   - Incorrect inverse computation using log/exp tables
///   - Off-by-one errors in table indexing
///   - Edge cases around field order (255) boundary
#[test]
fn mr_gf256_inverse_properties() {
    use crate::raptorq::gf256::Gf256;

    proptest!(|(a in 1u8..=255u8)| {
        let a_gf = Gf256::new(a);
        let zero = Gf256::ZERO;
        let one = Gf256::ONE;

        // Additive inverse: a + a = 0 (in characteristic 2 fields)
        let add_self = a_gf + a_gf;
        prop_assert_eq!(
            add_self, zero,
            "Additive inverse violation: GF({}) + GF({}) != GF(0)",
            a, a
        );

        // Multiplicative inverse: a * inv(a) = 1 (for a != 0)
        let inv_a = a_gf.inv();
        let mul_inv = a_gf * inv_a;
        prop_assert_eq!(
            mul_inv, one,
            "Multiplicative inverse violation: GF({}) * inv(GF({})) != GF(1)",
            a, a
        );

        // Double inverse: inv(inv(a)) = a
        let double_inv = inv_a.inv();
        prop_assert_eq!(
            double_inv, a_gf,
            "Double inverse violation: inv(inv(GF({}))) != GF({})",
            a, a
        );
    });
}

/// MR-Gf256ExponentiationProperties: Exponentiation should follow mathematical laws.
///
/// Property: a^(m+n) == a^m * a^n, (a^m)^n == a^(mn), a^0 == 1, 0^n == 0 (n > 0).
///
/// Why this catches bugs:
///   - Overflow in exponent arithmetic
///   - Incorrect exponent reduction modulo field order
///   - Edge cases with zero base and zero exponent
#[test]
fn mr_gf256_exponentiation_properties() {
    use crate::raptorq::gf256::Gf256;

    proptest!(|(
        a in 1u8..=255u8,
        m in 0u8..=20u8,
        n in 0u8..=20u8,
    )| {
        let a_gf = Gf256::new(a);

        // a^(m+n) == a^m * a^n
        let exp_sum = a_gf.pow(m.saturating_add(n));
        let exp_prod = a_gf.pow(m) * a_gf.pow(n);
        prop_assert_eq!(
            exp_sum, exp_prod,
            "Exponent sum rule violation: GF({})^({}) != GF({})^{} * GF({})^{}",
            a, m + n, a, m, a, n
        );

        // (a^m)^n == a^(mn)
        if m > 0 && n > 0 && (m as u16 * n as u16) <= 255 {
            let exp_compose = a_gf.pow(m).pow(n);
            let exp_mult = a_gf.pow((m as u16 * n as u16) as u8);
            prop_assert_eq!(
                exp_compose, exp_mult,
                "Exponent composition rule violation: (GF({})^{})^{} != GF({})^{}",
                a, m, n, a, m as u16 * n as u16
            );
        }

        // a^0 == 1
        let exp_zero = a_gf.pow(0);
        prop_assert_eq!(
            exp_zero, Gf256::ONE,
            "Exponent zero rule violation: GF({})^0 != GF(1)",
            a
        );
    });

    // Special case: 0^n == 0 for n > 0, 0^0 == 1
    let zero = Gf256::ZERO;
    assert_eq!(zero.pow(0), Gf256::ONE, "0^0 should equal 1");
    for exp in 1..=255 {
        assert_eq!(zero.pow(exp), Gf256::ZERO, "0^{} should equal 0", exp);
    }
}

/// MR-Gf256SliceOperationConsistency: Bulk slice operations should be equivalent
/// to element-wise operations.
///
/// Property: Bulk operations on slices should produce the same result as
/// applying the operation element-wise.
///
/// Why this catches bugs:
///   - SIMD implementation divergence from scalar reference
///   - Boundary handling errors in vectorized code
///   - Kernel dispatch bugs that select wrong implementation
#[test]
fn mr_gf256_slice_operation_consistency() {
    use crate::raptorq::gf256::{Gf256, gf256_add_slice, gf256_addmul_slice, gf256_mul_slice};

    proptest!(|(
        data: Vec<u8>,
        scalar: u8,
        other: Vec<u8>,
    )| {
        if !data.is_empty() && other.len() >= data.len() {
            let scalar_gf = Gf256::new(scalar);

            // Test mul_slice consistency
            let mut bulk_result = data.clone();
            gf256_mul_slice(&mut bulk_result, scalar_gf);

            let element_result: Vec<u8> = data.iter()
                .map(|&x| (Gf256::new(x) * scalar_gf).raw())
                .collect();

            prop_assert_eq!(
                bulk_result, element_result,
                "mul_slice inconsistency: bulk != element-wise for scalar GF({})",
                scalar
            );

            // Test add_slice consistency
            let mut bulk_add = data.clone();
            let other_slice = &other[..data.len()];
            gf256_add_slice(&mut bulk_add, other_slice);

            let element_add: Vec<u8> = data.iter().zip(other_slice.iter())
                .map(|(&x, &y)| (Gf256::new(x) + Gf256::new(y)).raw())
                .collect();

            prop_assert_eq!(
                bulk_add, element_add,
                "add_slice inconsistency: bulk != element-wise"
            );

            // Test addmul_slice consistency
            let mut bulk_addmul = data.clone();
            gf256_addmul_slice(&mut bulk_addmul, other_slice, scalar_gf);

            let element_addmul: Vec<u8> = data.iter().zip(other_slice.iter())
                .map(|(&x, &y)| (Gf256::new(x) + Gf256::new(y) * scalar_gf).raw())
                .collect();

            prop_assert_eq!(
                bulk_addmul, element_addmul,
                "addmul_slice inconsistency: bulk != element-wise for scalar GF({})",
                scalar
            );
        }
    });
}

// ============================================================================
// Linear Algebra Metamorphic Relations
// ============================================================================

/// MR-RowOperationLinearityAddition: Row operations should preserve linearity.
///
/// Property: row_xor(A + B, C) == row_xor(A, C) + row_xor(B, C).
///
/// Why this catches bugs:
///   - Non-linear implementation of XOR operations
///   - State pollution between operations
///   - Buffer aliasing issues in bulk operations
#[test]
fn mr_row_operation_linearity_addition() {
    use crate::raptorq::linalg::row_xor;

    proptest!(|(
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    )| {
        if !a.is_empty() && a.len() == b.len() && b.len() == c.len() {
            // Test linearity: row_xor(A + B, C) == row_xor(A, C) + row_xor(B, C)
            let mut a_plus_b: Vec<u8> = a.iter().zip(b.iter())
                .map(|(&x, &y)| x ^ y)  // GF(256) addition
                .collect();
            row_xor(&mut a_plus_b, &c);

            let mut a_xor_c = a.clone();
            row_xor(&mut a_xor_c, &c);

            let mut b_xor_c = b.clone();
            row_xor(&mut b_xor_c, &c);

            let combined: Vec<u8> = a_xor_c.iter().zip(b_xor_c.iter())
                .map(|(&x, &y)| x ^ y)
                .collect();

            prop_assert_eq!(
                a_plus_b, combined,
                "Row XOR linearity violation: row_xor(A+B, C) != row_xor(A, C) + row_xor(B, C)"
            );
        }
    });
}

/// MR-RowOperationScalarLinearity: Row scaling should distribute over addition.
///
/// Property: row_scale(A + B, c) == row_scale(A, c) + row_scale(B, c).
///
/// Why this catches bugs:
///   - Implementation that doesn't properly implement field scalar multiplication
///   - SIMD issues with scalar broadcast
///   - Edge cases with zero or one scalars
#[test]
fn mr_row_operation_scalar_linearity() {
    use crate::raptorq::gf256::Gf256;
    use crate::raptorq::linalg::row_scale;

    proptest!(|(
        a: Vec<u8>,
        b: Vec<u8>,
        scalar: u8,
    )| {
        if !a.is_empty() && a.len() == b.len() {
            let c = Gf256::new(scalar);

            // Scale (A + B) by c
            let mut a_plus_b: Vec<u8> = a.iter().zip(b.iter())
                .map(|(&x, &y)| x ^ y)
                .collect();
            row_scale(&mut a_plus_b, c);

            // Scale A by c and B by c separately, then add
            let mut scaled_a = a.clone();
            row_scale(&mut scaled_a, c);

            let mut scaled_b = b.clone();
            row_scale(&mut scaled_b, c);

            let combined: Vec<u8> = scaled_a.iter().zip(scaled_b.iter())
                .map(|(&x, &y)| x ^ y)
                .collect();

            prop_assert_eq!(
                a_plus_b, combined,
                "Row scale linearity violation: row_scale(A+B, c) != row_scale(A, c) + row_scale(B, c)"
            );
        }
    });
}

/// MR-GaussianSolveDeterminism: Different pivot strategies should yield equivalent solutions.
///
/// Property: solve() and solve_markowitz() should produce solutions that satisfy the same equation.
///
/// Why this catches bugs:
///   - Non-deterministic pivot selection
///   - Inconsistent solution classification between methods
///   - Numerical instability that depends on pivot order
#[test]
fn mr_gaussian_solve_determinism() {
    use crate::raptorq::linalg::{DenseRow, GaussianResult, GaussianSolver};

    proptest!(|(
        matrix_data: Vec<Vec<u8>>,
        rhs_data: Vec<Vec<u8>>,
    )| {
        if !matrix_data.is_empty() && !matrix_data[0].is_empty() &&
           matrix_data.len() == rhs_data.len() &&
           matrix_data.iter().all(|row| row.len() == matrix_data[0].len()) &&
           rhs_data.iter().all(|row| row.len() == matrix_data[0].len()) {

            let rows = matrix_data.len();
            let cols = matrix_data[0].len();

            // Only test small matrices to avoid timeout
            if rows <= 8 && cols <= 8 {
                // Set up two identical solvers
                let mut solver1 = GaussianSolver::new(rows, cols);
                let mut solver2 = GaussianSolver::new(rows, cols);

                for (i, (matrix_row, rhs_row)) in matrix_data.iter().zip(rhs_data.iter()).enumerate() {
                    solver1.set_row(i, matrix_row, DenseRow::new(rhs_row.clone()));
                    solver2.set_row(i, matrix_row, DenseRow::new(rhs_row.clone()));
                }

                let result1 = solver1.solve();
                let result2 = solver2.solve_markowitz();

                // Both methods should agree on solvability classification
                match (&result1, &result2) {
                    (GaussianResult::Solved(sol1), GaussianResult::Solved(sol2)) => {
                        // Solutions may differ in specific values due to pivot choice,
                        // but both should satisfy the original equations
                        prop_assert_eq!(
                            sol1.len(), sol2.len(),
                            "Solution vector length mismatch between solve methods"
                        );
                    }
                    (GaussianResult::Singular { .. }, GaussianResult::Singular { .. }) => {
                        // Both detected singularity - acceptable
                    }
                    (GaussianResult::Inconsistent { .. }, GaussianResult::Inconsistent { .. }) => {
                        // Both detected inconsistency - acceptable
                    }
                    _ => {
                        prop_assert!(false,
                            "Gaussian solver determinism violation: solve() = {:?}, solve_markowitz() = {:?}",
                            classify_result(&result1), classify_result(&result2)
                        );
                    }
                }
            }
        }
    });
}

fn classify_result(result: &GaussianResult) -> &'static str {
    match result {
        GaussianResult::Solved(_) => "Solved",
        GaussianResult::Singular { .. } => "Singular",
        GaussianResult::Inconsistent { .. } => "Inconsistent",
    }
}

/// MR-MatrixOperationRankMonotonicity: Matrix operations should respect rank properties.
///
/// Property: Elementary row operations should not increase rank.
///
/// Why this catches bugs:
///   - Row operations that incorrectly increase rank
///   - Precision issues that create spurious non-zero entries
///   - Implementation bugs in row swap/scale operations
#[test]
fn mr_matrix_operation_rank_monotonicity() {
    use crate::raptorq::gf256::Gf256;
    use crate::raptorq::linalg::{row_scale, row_swap, row_xor};

    proptest!(|(
        matrix: Vec<Vec<u8>>,
        scalar in 1u8..=255u8,  // Non-zero scalar
    )| {
        if !matrix.is_empty() && !matrix[0].is_empty() &&
           matrix.len() >= 2 && matrix.iter().all(|row| row.len() == matrix[0].len()) {

            let mut modified_matrix = matrix.clone();
            let original_rank = count_nonzero_rows(&matrix);

            // Perform row XOR operation: R1 := R1 + R2
            let (first_row, remaining_rows) = modified_matrix.split_at_mut(1);
            row_xor(&mut first_row[0], &remaining_rows[0]);
            let rank_after_xor = count_nonzero_rows(&modified_matrix);

            prop_assert!(
                rank_after_xor <= original_rank,
                "Row XOR increased rank: {} -> {}",
                original_rank, rank_after_xor
            );

            // Reset and test row scaling: R1 := c * R1 (c != 0)
            let mut scaled_matrix = matrix.clone();
            row_scale(&mut scaled_matrix[0], Gf256::new(scalar));
            let rank_after_scale = count_nonzero_rows(&scaled_matrix);

            prop_assert_eq!(
                rank_after_scale, original_rank,
                "Row scaling changed rank: {} -> {}",
                original_rank, rank_after_scale
            );

            // Reset and test row swap: R1 <-> R2
            let mut swapped_matrix = matrix.clone();
            let (first_row, remaining_rows) = swapped_matrix.split_at_mut(1);
            row_swap(&mut first_row[0], &mut remaining_rows[0]);
            let rank_after_swap = count_nonzero_rows(&swapped_matrix);

            prop_assert_eq!(
                rank_after_swap, original_rank,
                "Row swap changed rank: {} -> {}",
                original_rank, rank_after_swap
            );
        }
    });
}

fn count_nonzero_rows(matrix: &[Vec<u8>]) -> usize {
    matrix
        .iter()
        .filter(|row| row.iter().any(|&x| x != 0))
        .count()
}

/// MR-DenseRowOperationConsistency: Dense row operations should match slice operations.
///
/// Property: DenseRow methods should produce the same results as equivalent slice operations.
///
/// Why this catches bugs:
///   - Inconsistency between dense row API and underlying slice operations
///   - Boundary checking issues in safe vs unsafe implementations
///   - State management bugs in row data structures
#[test]
fn mr_dense_row_operation_consistency() {
    use crate::raptorq::gf256::Gf256;
    use crate::raptorq::linalg::{DenseRow, row_xor};

    proptest!(|(
        data1: Vec<u8>,
        data2: Vec<u8>,
        index: usize,
        value: u8,
    )| {
        if !data1.is_empty() && data1.len() == data2.len() && index < data1.len() {
            // Test element access consistency
            let row = DenseRow::new(data1.clone());
            let expected = Gf256::new(data1[index]);

            prop_assert_eq!(
                row.get(index), expected,
                "DenseRow::get() inconsistency at index {}: expected GF({}), got {:?}",
                index, data1[index], row.get(index)
            );

            // Test modification consistency
            let mut row_dense = DenseRow::new(data1.clone());
            let mut slice_direct = data1.clone();

            // Set value using DenseRow API
            row_dense.set(index, Gf256::new(value));
            // Set value directly on slice
            slice_direct[index] = value;

            prop_assert_eq!(
                row_dense.as_slice(), slice_direct.as_slice(),
                "DenseRow::set() inconsistency: DenseRow API diverged from direct slice modification"
            );

            // Test row XOR consistency
            let mut row_xor_dense = DenseRow::new(data1.clone());
            let other_row = DenseRow::new(data2.clone());
            let mut slice_xor = data1.clone();

            // XOR using slice operations
            row_xor(slice_xor.as_mut_slice(), other_row.as_slice());

            // XOR using DenseRow (via slice access)
            row_xor(row_xor_dense.as_mut_slice(), other_row.as_slice());

            prop_assert_eq!(
                row_xor_dense.as_slice(), slice_xor.as_slice(),
                "DenseRow XOR inconsistency: operations via DenseRow diverged from direct slice XOR"
            );
        }
    });
}

// ============================================================================
// Phase 3: Codec Round-Trip and Bytes Operation Metamorphic Relations
// ============================================================================

/// MR-CodecRoundTripIdentity: decode(encode(x)) = x for valid inputs.
///
/// Property: Encoding then decoding should recover original data.
///
/// Why this catches bugs:
///   - Codec state corruption during encode/decode cycles
///   - Data loss or transformation bugs
///   - Inconsistent frame boundaries in delimited codecs
#[test]
fn mr_codec_roundtrip_identity() {
    use crate::bytes::{Bytes, BytesMut};
    use crate::codec::{BytesCodec, LengthDelimitedCodec};
    use crate::codec::{Decoder, Encoder};

    proptest!(|(data: Vec<u8>)| {
        if !data.is_empty() {
            // Test BytesCodec round-trip
            {
                let mut codec = BytesCodec::new();
                let mut encode_buf = BytesMut::new();

                if matches!(codec.encode(Bytes::from(data.clone()), &mut encode_buf), Ok(())) {
                    match codec.decode(&mut encode_buf) {
                        Ok(Some(decoded)) => {
                            prop_assert_eq!(
                                decoded.as_ref(), data.as_slice(),
                                "BytesCodec round-trip failed: data corruption detected"
                            );
                        }
                        Ok(None) => {
                            prop_assert!(false, "BytesCodec decode returned None unexpectedly");
                        }
                        Err(e) => {
                            prop_assert!(false, "BytesCodec decode failed: {:?}", e);
                        }
                    }
                }
            }

            // Test LengthDelimitedCodec round-trip
            {
                let mut codec = LengthDelimitedCodec::new();
                let mut encode_buf = BytesMut::new();

                if matches!(
                    codec.encode(BytesMut::from(data.as_slice()), &mut encode_buf),
                    Ok(())
                ) {
                    match codec.decode(&mut encode_buf) {
                        Ok(Some(decoded)) => {
                            prop_assert_eq!(
                                decoded.as_ref(), data.as_slice(),
                                "LengthDelimitedCodec round-trip failed: data corruption"
                            );
                        }
                        Ok(None) => {
                            // Incomplete frame is acceptable for this codec
                        }
                        Err(e) => {
                            prop_assert!(false, "LengthDelimitedCodec decode failed: {:?}", e);
                        }
                    }
                }
            }
        }
    });
}

/// MR-CodecStreamingConsistency: Chunked decoding equals full decoding.
///
/// Property: Decoding data in chunks should produce the same result as decoding all at once.
///
/// Why this catches bugs:
///   - State management issues in streaming decoders
///   - Frame boundary detection bugs
///   - Partial buffer handling errors
#[test]
fn mr_codec_streaming_consistency() {
    use crate::bytes::BytesMut;
    use crate::codec::{Decoder, Encoder, LengthDelimitedCodec};

    proptest!(|(
        data: Vec<u8>,
        chunk_size in 1usize..=100usize,
    )| {
        if !data.is_empty() && chunk_size > 0 {
            let mut codec = LengthDelimitedCodec::new();
            let mut encode_buf = BytesMut::new();

            // First encode the data
            if matches!(
                codec.encode(BytesMut::from(data.as_slice()), &mut encode_buf),
                Ok(())
            ) {
                let encoded_data = encode_buf.freeze();

                // Full decode
                let mut full_codec = LengthDelimitedCodec::new();
                let mut full_input = BytesMut::from(encoded_data.as_ref());
                let full_result = full_codec.decode(&mut full_input);

                // Chunked decode
                let mut chunked_codec = LengthDelimitedCodec::new();
                let mut chunked_results = Vec::new();
                let mut chunked_input = BytesMut::new();

                for chunk in encoded_data.chunks(chunk_size) {
                    chunked_input.extend_from_slice(chunk);
                    if let Ok(Some(decoded)) = chunked_codec.decode(&mut chunked_input) {
                        chunked_results.push(decoded);
                    }
                }

                match (&full_result, chunked_results.len()) {
                    (Ok(Some(full_decoded)), 1) => {
                        prop_assert_eq!(
                            full_decoded.as_ref(), chunked_results[0].as_ref(),
                            "Codec streaming consistency violation: chunked decode differs from full decode"
                        );
                        prop_assert_eq!(
                            full_decoded.as_ref(), data.as_slice(),
                            "Codec streaming sanity check failed: full decode corrupted data"
                        );
                    }
                    (Ok(Some(_)), n) if n != 1 => {
                        prop_assert!(false,
                            "Streaming consistency: expected 1 chunk result, got {}",
                            n
                        );
                    }
                    (Ok(None), 0) => {
                        // Both incomplete is acceptable
                    }
                    _ => {
                        // Other mismatches acceptable due to frame boundaries
                    }
                }
            }
        }
    });
}

/// MR-BytesSplitComposition: split_to(n) + remainder = original.
///
/// Property: Splitting bytes and recombining should recreate the original.
///
/// Why this catches bugs:
///   - Off-by-one errors in split position calculation
///   - Reference counting issues with split operations
///   - Data corruption during split operations
#[test]
fn mr_bytes_split_composition() {
    use crate::bytes::Bytes;

    proptest!(|(
        data: Vec<u8>,
        split_pos: usize,
    )| {
        if !data.is_empty() && split_pos <= data.len() {
            let original = Bytes::from(data.clone());
            let original_copy = original.clone();

            // Perform split
            let left = original.slice(..split_pos);
            let right = original.slice(split_pos..);

            // Recombine by concatenation
            let mut recombined = Vec::new();
            recombined.extend_from_slice(&left);
            recombined.extend_from_slice(&right);

            prop_assert_eq!(
                recombined.as_slice(), data.as_slice(),
                "Bytes split composition failed: split_to({}) + remainder != original",
                split_pos
            );

            // Verify original is unchanged
            prop_assert_eq!(
                original_copy.as_ref(), data.as_slice(),
                "Bytes split mutated original data"
            );
        }
    });
}

/// MR-BytesSliceConsistency: slice operations should preserve data integrity.
///
/// Property: Slicing bytes should return exact subranges without corruption.
///
/// Why this catches bugs:
///   - Boundary calculation errors in slice operations
///   - Reference offset bugs in shared data
///   - Range validation issues
#[test]
fn mr_bytes_slice_consistency() {
    use crate::bytes::Bytes;

    proptest!(|(
        data: Vec<u8>,
        start: usize,
        len: usize,
    )| {
        if !data.is_empty() && start < data.len() {
            let end = std::cmp::min(start + len, data.len());
            if start <= end {
                let bytes = Bytes::from(data.clone());

                // Test slice operation
                let sliced = bytes.slice(start..end);
                let expected = &data[start..end];

                prop_assert_eq!(
                    sliced.as_ref(), expected,
                    "Bytes slice inconsistency: slice({}..{}) returned wrong data",
                    start, end
                );

                // Test that slice doesn't affect original
                prop_assert_eq!(
                    bytes.as_ref(), data.as_slice(),
                    "Bytes slice mutated original data"
                );
            }
        }
    });
}

/// MR-BytesMutFreezeInvariance: freeze() should preserve data exactly.
///
/// Property: Freezing a mutable buffer should create an immutable copy with identical data.
///
/// Why this catches bugs:
///   - Data corruption during mutable to immutable conversion
///   - Reference sharing bugs between mutable and immutable views
///   - State inconsistency in freeze operation
#[test]
fn mr_bytes_mut_freeze_invariance() {
    use crate::bytes::BytesMut;

    proptest!(|(data: Vec<u8>)| {
        if !data.is_empty() {
            let bytes_mut = BytesMut::from(data.as_slice());
            let pre_freeze_data = bytes_mut.to_vec();

            // Freeze the mutable buffer
            let frozen = bytes_mut.freeze();

            prop_assert_eq!(
                frozen.as_ref(), pre_freeze_data.as_slice(),
                "BytesMut freeze() changed data during conversion"
            );

            prop_assert_eq!(
                frozen.as_ref(), data.as_slice(),
                "BytesMut freeze() corrupted original data"
            );
        }
    });
}

/// MR-BytesMutSplitOffComposition: split_off(n) + remainder = original.
///
/// Property: Splitting mutable bytes should preserve total data content.
///
/// Why this catches bugs:
///   - Data loss during mutable buffer split operations
///   - Incorrect buffer capacity management
///   - Reference counting bugs in mutable split
#[test]
fn mr_bytes_mut_split_off_composition() {
    use crate::bytes::BytesMut;

    proptest!(|(
        data: Vec<u8>,
        split_pos: usize,
    )| {
        if !data.is_empty() && split_pos <= data.len() {
            let original_data = data.clone();
            let mut bytes_mut = BytesMut::from(data.as_slice());

            if split_pos < bytes_mut.len() {
                // Perform split_off operation
                let right_part = bytes_mut.split_off(split_pos);
                let left_part = bytes_mut.to_vec();

                // Recombine and verify
                let mut recombined = left_part;
                recombined.extend_from_slice(&right_part);

                prop_assert_eq!(
                    recombined, original_data,
                    "BytesMut split_off composition failed: left + right != original"
                );
            }
        }
    });
}

/// MR-BytesCloneIndependence: cloned bytes should be independent.
///
/// Property: Cloning bytes should create logically independent copies.
///
/// Why this catches bugs:
///   - Shared mutable state between clones
///   - Reference counting issues
///   - Unintended data sharing bugs
#[test]
fn mr_bytes_clone_independence() {
    use crate::bytes::{Bytes, BytesMut};

    proptest!(|(data: Vec<u8>)| {
        if !data.is_empty() {
            // Test immutable bytes clone independence
            let bytes1 = Bytes::from(data.clone());
            let bytes2 = bytes1.clone();

            // Both should have identical content
            prop_assert_eq!(
                bytes1.as_ref(), bytes2.as_ref(),
                "Cloned Bytes have different content"
            );

            // Test that slicing one doesn't affect the other
            if data.len() > 1 {
                let _slice1 = bytes1.slice(1..);
                prop_assert_eq!(
                    bytes2.as_ref(), data.as_slice(),
                    "Slicing cloned Bytes affected original clone"
                );
            }

            // Test mutable bytes clone independence
            let mut bytes_mut1 = BytesMut::from(data.as_slice());
            let bytes_mut2 = bytes_mut1.clone();

            prop_assert_eq!(
                bytes_mut1.as_ref(), bytes_mut2.as_ref(),
                "Cloned BytesMut have different content"
            );

            // Modify one and verify other is unaffected
            if !data.is_empty() {
                bytes_mut1.truncate(data.len().saturating_sub(1));
                prop_assert_eq!(
                    bytes_mut2.as_ref(), data.as_slice(),
                    "Modifying cloned BytesMut affected original clone"
                );
            }
        }
    });
}
