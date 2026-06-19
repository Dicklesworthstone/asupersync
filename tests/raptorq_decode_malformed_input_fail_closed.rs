//! RFC 6330 decoder rejects malformed received symbols fail-closed (bead bd-3uox5).
//!
//! A RaptorQ receiver consumes network-supplied encoding-symbol metadata. A
//! hostile or buggy peer can send structurally malformed symbols: wrong payload
//! size, mismatched equation arity, a column index outside the intermediate
//! domain `[0, L)`, a "source" symbol claiming an ESI outside `[0, K)`, or a
//! source symbol carrying a non-identity equation. Each MUST be rejected with a
//! specific structured `DecodeError` -- never a panic, never silent acceptance
//! (which would let an attacker steer the linear system). This mirrors the
//! fail-closed hardening already applied to `tuple_indices` / `try_tuple` and
//! the `validate_input` guard, and pins it at the integration boundary.
//!
//! Each case starts from an over-determined, fully-decodable symbol set (so the
//! count gate is satisfied) and appends exactly one malformed symbol crafted to
//! trip one specific validation arm.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_malformed_input_fail_closed -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const OBJECT_ID_HIGH: u64 = 0x4D41_4C46_4F52_4D45;
const OBJECT_ID_LOW: u64 = 0x6661_696C_636C_6F73;

const K: usize = 16;
const SYMBOL_SIZE: usize = 40;
const SEED: u64 = 0x00FE_DCBA_9876_5432;
const SBN: u8 = 71;
const REPAIRS: usize = 5;

fn make_source(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| {
            (0..symbol_size)
                .map(|_| (rng.next_u64() & 0xFF) as u8)
                .collect()
        })
        .collect()
}

fn object_id() -> ObjectId {
    ObjectId::new(OBJECT_ID_HIGH, OBJECT_ID_LOW)
}

/// A clean, over-determined received set: constraints, every source symbol, and
/// `REPAIRS` repairs starting at ESI `K`. Decodes successfully on its own.
fn clean_received(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut received = decoder.constraint_symbols();
    for (esi, data) in source.iter().enumerate() {
        received.push(ReceivedSymbol::source(esi as u32, data.clone()));
    }
    for offset in 0..REPAIRS {
        let esi = k as u32 + offset as u32;
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair_equation esi={esi} failed: {err:?}"));
        let data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }
    received
}

/// Decode an otherwise-valid set with one appended malformed symbol and return
/// the error, asserting the decoder neither accepted it nor panicked.
fn reject(malformed: ReceivedSymbol, context: &str) -> DecodeError {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");
    let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);

    let mut received = clean_received(&encoder, &decoder, &source);
    received.push(malformed);

    match decoder.decode_with_proof(&received, object_id(), SBN) {
        Ok(_) => panic!("{context}: malformed symbol was SILENTLY ACCEPTED (decode returned Ok)"),
        Err((err, _proof)) => err,
    }
}

#[test]
fn clean_baseline_decodes() {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");
    let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let received = clean_received(&encoder, &decoder, &source);
    let ok = decoder
        .decode_with_proof(&received, object_id(), SBN)
        .unwrap_or_else(|(err, _)| panic!("clean baseline must decode: {err:?}"));
    assert_eq!(ok.result.source, source);
}

#[test]
fn wrong_payload_size_is_rejected() {
    // Repair symbol whose payload is one byte too long.
    let bogus = ReceivedSymbol::repair(
        K as u32,
        vec![0],
        vec![Gf256(1)],
        vec![0u8; SYMBOL_SIZE + 1],
    );
    match reject(bogus, "wrong-size") {
        DecodeError::SymbolSizeMismatch { expected, actual } => {
            assert_eq!(expected, SYMBOL_SIZE);
            assert_eq!(actual, SYMBOL_SIZE + 1);
        }
        other => panic!("expected SymbolSizeMismatch, got {other:?}"),
    }
}

#[test]
fn equation_arity_mismatch_is_rejected() {
    // Correct payload size, but two columns and only one coefficient.
    let bogus =
        ReceivedSymbol::repair(K as u32, vec![0, 1], vec![Gf256(1)], vec![0u8; SYMBOL_SIZE]);
    match reject(bogus, "arity-mismatch") {
        DecodeError::SymbolEquationArityMismatch {
            columns,
            coefficients,
            ..
        } => {
            assert_eq!(columns, 2);
            assert_eq!(coefficients, 1);
        }
        other => panic!("expected SymbolEquationArityMismatch, got {other:?}"),
    }
}

#[test]
fn column_index_out_of_range_is_rejected() {
    let l = InactivationDecoder::new(K, SYMBOL_SIZE, SEED).params().l;
    // A column index equal to L is one past the valid domain [0, L).
    let bogus = ReceivedSymbol::repair(K as u32, vec![l], vec![Gf256(1)], vec![0u8; SYMBOL_SIZE]);
    match reject(bogus, "column-oob") {
        DecodeError::ColumnIndexOutOfRange {
            column, max_valid, ..
        } => {
            assert_eq!(column, l);
            assert_eq!(max_valid, l);
        }
        other => panic!("expected ColumnIndexOutOfRange, got {other:?}"),
    }
}

#[test]
fn source_esi_out_of_range_is_rejected() {
    // A "source" symbol claiming ESI = K, outside the systematic domain [0, K).
    let bogus = ReceivedSymbol::source(K as u32, vec![0u8; SYMBOL_SIZE]);
    match reject(bogus, "source-esi-oob") {
        DecodeError::SourceEsiOutOfRange { esi, max_valid } => {
            assert_eq!(esi, K as u32);
            assert_eq!(max_valid, K);
        }
        other => panic!("expected SourceEsiOutOfRange, got {other:?}"),
    }
}

#[test]
fn non_identity_source_equation_is_rejected() {
    // A source symbol (ESI < K) carrying a non-empty, non-canonical equation
    // instead of the required identity. Lets a peer smuggle a different equation
    // under a source ESI; must be rejected.
    let bogus = ReceivedSymbol {
        esi: 0,
        is_source: true,
        columns: vec![5],
        coefficients: vec![Gf256(1)],
        data: vec![0u8; SYMBOL_SIZE],
    };
    match reject(bogus, "non-identity-source") {
        DecodeError::InvalidSourceSymbolEquation { esi, .. } => {
            assert_eq!(esi, 0);
        }
        other => panic!("expected InvalidSourceSymbolEquation, got {other:?}"),
    }
}
