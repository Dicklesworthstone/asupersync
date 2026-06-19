//! RFC 6330 decode metamorphic-invariance relations (bead bd-3uox5).
//!
//! Decode correctness is normally verified against a known plaintext, but two
//! oracle-free metamorphic relations hold for any RaptorQ source block and
//! catch solver bugs even where the "correct" output is taken on faith:
//!
//! 1. **Receive-order invariance** — the recovered source must not depend on
//!    the order in which encoding symbols (source + repair) arrive. A correct
//!    linear solver yields the same solution for any permutation of its
//!    equations.
//! 2. **Redundant-symbol invariance** — handing the decoder *more* repair
//!    symbols than it needs must not change the recovered source.
//!
//! Both relations are checked here against the live `InactivationDecoder`, with
//! a plaintext cross-check as a third anchor. Inputs use fixed `DetRng` seeds.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_metamorphic_invariance -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const OBJECT_ID_HIGH: u64 = 0x1A2B_3C4D_5E6F_7080;
const OBJECT_ID_LOW: u64 = 0x90A1_B2C3_D4E5_F607;

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

/// Build received symbols: decoder constraint rows first, then the surviving
/// source symbols, then `repair_count` repair symbols starting at ESI `K`.
/// Returns the received vector and the number of leading constraint rows.
fn build_received(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    dropped: &[usize],
    repair_count: usize,
) -> (Vec<ReceivedSymbol>, usize) {
    let k = source.len();
    let constraints = decoder.constraint_symbols();
    let constraint_count = constraints.len();
    let mut received = constraints;

    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    for offset in 0..repair_count {
        let esi = k as u32 + offset as u32;
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair_equation esi={esi} failed: {err:?}"));
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            repair_data,
        ));
    }

    (received, constraint_count)
}

/// Build received symbols using a repair window that starts at an arbitrary
/// ESI offset above `K` instead of being anchored at `K`. Used to prove the
/// decoder does not secretly depend on low / K-anchored repair ESIs.
fn build_received_with_repair_window(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    dropped: &[usize],
    repair_start_offset: u32,
    repair_count: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut received = decoder.constraint_symbols();

    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    for offset in 0..repair_count {
        let esi = k as u32 + repair_start_offset + offset as u32;
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair_equation esi={esi} failed: {err:?}"));
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            repair_data,
        ));
    }

    received
}

/// Decode and return the recovered source, panicking on failure.
fn decode(decoder: &InactivationDecoder, received: &[ReceivedSymbol], sbn: u8) -> Vec<Vec<u8>> {
    let object_id = ObjectId::new(OBJECT_ID_HIGH, OBJECT_ID_LOW);
    decoder
        .decode_with_proof(received, object_id, sbn)
        .map_or_else(
            |(err, _proof)| panic!("decode must succeed: {err:?}"),
            |success| success.result.source,
        )
}

const K: usize = 20;
const SYMBOL_SIZE: usize = 32;
const SEED: u64 = 0x5151_2727_9393_BDBD;
const SBN: u8 = 91;
const DROPPED: &[usize] = &[3, 9, 14];

/// Relation 1 — recovered source is invariant under permutation of the order in
/// which encoding symbols (source + repair) are received.
#[test]
fn decode_is_invariant_under_received_symbol_permutation() {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");

    let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let (baseline, constraint_count) =
        build_received(&encoder, &decoder, &source, DROPPED, decoder.params().l);
    let recovered = decode(&decoder, &baseline, SBN);
    assert_eq!(recovered, source, "baseline decode must recover the source");

    // Permute only the encoding-symbol tail (constraint rows stay leading),
    // modeling arbitrary network arrival order.
    let mut reversed = baseline.clone();
    reversed[constraint_count..].reverse();
    let decoder_rev = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    assert_eq!(
        decode(&decoder_rev, &reversed, SBN),
        recovered,
        "reversed receive order must recover identical source"
    );

    // A deterministic rotation is a second, independent permutation.
    let tail_len = baseline.len() - constraint_count;
    let mut rotated = baseline.clone();
    if tail_len > 1 {
        rotated[constraint_count..].rotate_left(tail_len / 2);
    }
    let decoder_rot = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    assert_eq!(
        decode(&decoder_rot, &rotated, SBN),
        recovered,
        "rotated receive order must recover identical source"
    );
}

/// Relation 2 — recovered source is invariant to handing the decoder more
/// repair symbols than strictly required.
#[test]
fn decode_is_invariant_to_redundant_repair_symbols() {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");
    let l = InactivationDecoder::new(K, SYMBOL_SIZE, SEED).params().l;

    let decoder_lean = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let (lean, _) = build_received(&encoder, &decoder_lean, &source, DROPPED, l);
    let lean_recovered = decode(&decoder_lean, &lean, SBN);
    assert_eq!(
        lean_recovered, source,
        "lean decode must recover the source"
    );

    // Generous extra repairs beyond the lean set must not perturb the result.
    let decoder_rich = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let (rich, _) = build_received(&encoder, &decoder_rich, &source, DROPPED, l + 12);
    assert!(rich.len() > lean.len(), "rich set must add symbols");
    assert_eq!(
        decode(&decoder_rich, &rich, SBN),
        lean_recovered,
        "redundant repair symbols must not change the recovered source"
    );
}

/// Relation 3 — recovered source is invariant to *which* repair symbols carry
/// the recovery, not merely how many. Every other decode test in the tree feeds
/// a contiguous repair run anchored at ESI `K`; a decoder that secretly depended
/// on low or `K`-anchored repair ESIs (e.g. a broken `ESI -> ISI` K' padding
/// translation in `repair_isi_for_esi`) would pass all of them yet corrupt
/// higher-ESI repair recovery. Here the same dropped source set is recovered
/// from a repair window anchored at `K` versus one shifted well above `K`; both
/// must reconstruct byte-identical source.
#[test]
fn decode_is_invariant_to_repair_symbol_selection() {
    let source = make_source(K, SYMBOL_SIZE, SEED);
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");
    let l = InactivationDecoder::new(K, SYMBOL_SIZE, SEED).params().l;

    // Window A: repair ESIs [K, K + L).
    let decoder_a = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let window_a = build_received_with_repair_window(&encoder, &decoder_a, &source, DROPPED, 0, l);
    let recovered_a = decode(&decoder_a, &window_a, SBN);
    assert_eq!(
        recovered_a, source,
        "K-anchored repair window must recover the source"
    );

    // Window B: repair ESIs [K + 37, K + 37 + L) — a disjoint, higher-ESI set.
    let shift: u32 = 37;
    let decoder_b = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let window_b =
        build_received_with_repair_window(&encoder, &decoder_b, &source, DROPPED, shift, l);
    let recovered_b = decode(&decoder_b, &window_b, SBN);
    assert_eq!(
        recovered_b, recovered_a,
        "a shifted, disjoint repair window must recover identical source"
    );
}
