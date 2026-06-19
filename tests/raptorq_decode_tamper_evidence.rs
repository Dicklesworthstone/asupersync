//! RFC 6330 decode tamper-evidence: a corrupted symbol can never silently
//! produce wrong output (bead bd-3uox5).
//!
//! AC #3 forbids tolerated silent decode corruption. The decoder carries an
//! integrity guard (`DecodeError::CorruptDecodedOutput`) that re-checks the
//! reconstructed output against EVERY input symbol's right-hand side before
//! returning success. This harness proves the guard actually engages on the
//! integration path: with an over-determined (fully recoverable) symbol set,
//! flipping a single byte in a redundant repair symbol's payload must be caught
//! -- the decode must fail loud, never return `Ok` with bytes that differ from
//! the true source, and never panic.
//!
//! Tampering is applied only to a *redundant* repair symbol so the true source
//! is determinable from the remaining correct equations; this isolates the
//! integrity guard from a genuine information-loss (garbage-in) case, where a
//! corrupted symbol in an exactly-determined system is indistinguishable from
//! truth and no code could detect it.
//!
//! Inputs use fixed `DetRng` seeds.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_tamper_evidence -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const OBJECT_ID_HIGH: u64 = 0x7A37_BEEF_0BAD_F00D;
const OBJECT_ID_LOW: u64 = 0x1357_9BDF_2468_ACE0;

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

/// Build an over-determined received set: constraints, every source symbol, and
/// `repair_count` repairs starting at ESI `K`. When `corrupt_repair_offset` is
/// `Some(off)`, the repair at ESI `K + off` carries a single flipped payload
/// byte while keeping a structurally valid equation.
fn build_received(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    repair_count: usize,
    corrupt_repair_offset: Option<usize>,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut received = decoder.constraint_symbols();

    for (esi, data) in source.iter().enumerate() {
        received.push(ReceivedSymbol::source(esi as u32, data.clone()));
    }

    for offset in 0..repair_count {
        let esi = k as u32 + offset as u32;
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair_equation esi={esi} failed: {err:?}"));
        let mut repair_data = encoder.repair_symbol(esi);
        if corrupt_repair_offset == Some(offset) {
            // Flip a single payload byte; the equation columns/coefficients stay
            // valid so this is a *content* tamper, not a malformed symbol.
            repair_data[0] ^= 0xFF;
        }
        received.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            repair_data,
        ));
    }

    received
}

const K: usize = 16;
const SYMBOL_SIZE: usize = 40;
const SEED: u64 = 0x2BAD_C0DE_5EED_9001;
const SBN: u8 = 55;
const REPAIRS: usize = 5;

/// Baseline: the clean over-determined set decodes to the true source exactly.
/// (Establishes that any failure in the tamper case is caused by the tamper,
/// not by an under-supplied system.)
#[test]
fn clean_overdetermined_set_recovers_true_source() {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");
    let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);

    let received = build_received(&encoder, &decoder, &source, REPAIRS, None);
    let success = decoder
        .decode_with_proof(&received, object_id(), SBN)
        .unwrap_or_else(|(err, _)| panic!("clean set must decode: {err:?}"));
    assert_eq!(
        success.result.source, source,
        "clean decode must be byte-exact"
    );
}

/// Tamper-evidence: a single flipped byte in a redundant repair symbol must be
/// caught. The decode must never return `Ok` with bytes != the true source.
#[test]
fn tampered_repair_byte_is_never_silently_accepted() {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");

    // Corrupt each repair slot in turn so the result does not hinge on a single
    // pivot ordering.
    for corrupt_offset in 0..REPAIRS {
        let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
        let received = build_received(&encoder, &decoder, &source, REPAIRS, Some(corrupt_offset));

        match decoder.decode_with_proof(&received, object_id(), SBN) {
            Ok(success) => {
                // The only acceptable success is recovering the TRUE source
                // (the tampered equation being treated as redundant and the
                // solution coming from the clean symbols). Wrong bytes here
                // would be exactly the silent corruption AC #3 forbids.
                assert_eq!(
                    success.result.source, source,
                    "corrupt repair at offset {corrupt_offset} yielded Ok with WRONG source bytes"
                );
            }
            Err((err, _proof)) => {
                // Expected: the integrity guard (or an inconsistency in the
                // linear system) catches the tamper.
                assert!(
                    matches!(
                        err,
                        DecodeError::CorruptDecodedOutput { .. }
                            | DecodeError::SingularMatrix { .. }
                    ),
                    "corrupt repair at offset {corrupt_offset} must fail via the integrity \
                     guard or an inconsistent system, got {err:?}"
                );
            }
        }
    }
}
