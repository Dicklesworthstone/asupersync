//! RFC 6330 under-determined decode must fail loud, never silently (bead bd-3uox5).
//!
//! AC #3 of the conformance program forbids *tolerated silent decode
//! corruption*: when the received set cannot determine the source block, the
//! decoder must return a structured `DecodeError` -- it must never return `Ok`
//! with wrong bytes, and it must never panic. Every other raptorq integration
//! test in the tree exercises only the *success* path (each `unwrap_or_else`s on
//! failure); this harness pins the negative path.
//!
//! Two under-determination modes are covered:
//!
//! 1. **Count-insufficient** — fewer equations than `minimum_received_symbols`.
//!    The decoder rejects before solving with `InsufficientSymbols`, so it is
//!    structurally impossible to return wrong bytes.
//! 2. **Rank-deficient with sufficient count** — enough equations *numerically*
//!    but a missing independent one (duplicate repair rows). The solver must
//!    detect the deficiency and fail (under-determined family), not emit garbage.
//!
//! Inputs use fixed `DetRng` seeds.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_underdetermined_fail_loud -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const OBJECT_ID_HIGH: u64 = 0x0DEC_0DED_FEED_0001;
const OBJECT_ID_LOW: u64 = 0x0BAD_5EED_DEAD_0002;

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

/// Decode and return the structured error, asserting the decoder did NOT
/// silently succeed with wrong bytes.
fn decode_expecting_failure(
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    sbn: u8,
    context: &str,
) -> DecodeError {
    match decoder.decode_with_proof(received, object_id(), sbn) {
        Ok(success) => panic!(
            "{context}: under-determined system must NOT decode, \
             but returned Ok with {} recovered source symbols",
            success.result.source.len()
        ),
        Err((err, _proof)) => err,
    }
}

/// Mode 1 — strictly too few equations: decoder fails with `InsufficientSymbols`
/// before any solving, so wrong output is structurally impossible.
#[test]
fn count_insufficient_decode_fails_with_insufficient_symbols() {
    for &(k, symbol_size, seed, sbn) in &[
        (10usize, 32usize, 0x1234_5678_9ABC_DEF0u64, 3u8),
        (26, 24, 0x0F1E_2D3C_4B5A_6978, 91),
    ] {
        let source = make_source(k, symbol_size, seed);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Constraint rows plus only THREE surviving source symbols -- far below
        // the L-padding minimum, so the count gate must trip.
        let mut received = decoder.constraint_symbols();
        for (esi, data) in source.iter().enumerate().take(3) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
        let provided = received.len();

        let err = decode_expecting_failure(&decoder, &received, sbn, "count-insufficient");
        match err {
            DecodeError::InsufficientSymbols { received, required } => {
                assert_eq!(
                    received, provided,
                    "reported received count must equal the symbols actually supplied"
                );
                assert!(
                    received < required,
                    "InsufficientSymbols must report received ({received}) < required ({required})"
                );
            }
            other => panic!("K={k}: expected InsufficientSymbols, got {other:?}"),
        }
    }
}

/// Mode 2 — sufficient equation *count* but rank-deficient (a missing
/// independent equation, modeled by duplicate repair rows). The solver must
/// surface the deficiency rather than emit garbage. The decoder may report this
/// as a singular matrix or, if it pre-counts distinct equations, as
/// insufficient symbols; either is a loud, structured failure in the
/// under-determined family. The contract under test is that it is never `Ok`.
#[test]
fn rank_deficient_decode_fails_in_underdetermined_family() {
    let k = 10usize;
    let symbol_size = 32usize;
    let seed = 0xCAFE_F00D_1357_9BDFu64;
    let sbn = 17u8;

    let source = make_source(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).expect("encoder");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Drop two source symbols, so two independent equations are missing.
    let dropped = [3usize, 7usize];
    let mut received = decoder.constraint_symbols();
    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    // Re-supply equations only via DUPLICATES of a single repair symbol: this
    // lifts the raw count to/above the minimum while adding at most one
    // independent equation, leaving the system rank-deficient by one.
    let repair_esi = k as u32;
    let (columns, coefficients) = decoder
        .repair_equation(repair_esi)
        .expect("repair_equation must build for a valid repair ESI");
    let repair_data = encoder.repair_symbol(repair_esi);
    for _ in 0..6 {
        received.push(ReceivedSymbol::repair(
            repair_esi,
            columns.clone(),
            coefficients.clone(),
            repair_data.clone(),
        ));
    }

    let err = decode_expecting_failure(&decoder, &received, sbn, "rank-deficient");
    assert!(
        matches!(
            err,
            DecodeError::SingularMatrix { .. } | DecodeError::InsufficientSymbols { .. }
        ),
        "rank-deficient system must fail in the under-determined family, got {err:?}"
    );
}
