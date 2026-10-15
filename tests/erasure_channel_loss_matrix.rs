//! Seeded loss-injection matrix for the erasure-channel symbol-intake layer
//! (`asupersync-raptorq-leverage-3bb2pl.1`, AC1 loss tolerance + AC7 determinism).
//!
//! Exercises the public `channel::erasure` surface end-to-end through a real
//! lossy/duplicating/reordering in-memory transport: a message's `N = K +
//! repair` symbols are framed as [`SymbolFrame`]s, run through a deterministic
//! seeded [`LossModel`], and fed to a [`MessageReassembler`]. The proof at this
//! layer is decode *readiness*: the reassembler reaches the RaptorQ-theoretic
//! `K`-symbol bound exactly when losses stay within the repair budget (the count
//! complement of the loss margin) — across a 5/10/20/40% loss matrix, with
//! duplication, reorder, and a wire round-trip, and reproducibly from the seed.
//!
//! No-claim boundary: this pins the intake readiness bound, not byte-level
//! reconstruction — the actual RaptorQ decode of the collected symbols back into
//! the original message bytes is a sibling slice. Where this asserts "ready", it
//! means "enough distinct symbols to attempt a decode", per `BlockLayout`.
#![allow(missing_docs)]

use asupersync::channel::erasure::{
    EcConfig, LossModel, MessageHeader, MessageReassembler, SymbolAccept, SymbolFrame,
};

const SYMBOL_SIZE: u16 = 8;
const REPAIR: u16 = 4;
const MESSAGE_ID: u64 = 0x00C0_FFEE;

/// A K=8, N=12, repair=4 message header (message of 64 bytes at 8-byte symbols).
fn header() -> MessageHeader {
    let cfg = EcConfig {
        symbol_size: SYMBOL_SIZE,
        repair_overhead: REPAIR,
        max_message_size: 1 << 20,
    };
    let layout = cfg.plan(64).expect("plan");
    assert_eq!(layout.source_symbols, 8, "K");
    assert_eq!(layout.total_symbols, 12, "N");
    assert_eq!(layout.repair_symbols, REPAIR);
    MessageHeader::from_layout(MESSAGE_ID, &layout).expect("header")
}

/// All `N` symbol frames for the message, each with a distinct deterministic
/// payload of `SYMBOL_SIZE` bytes.
fn full_symbol_set(header: &MessageHeader) -> Vec<SymbolFrame> {
    (0..header.total_symbols)
        .map(|esi| {
            let fill = (esi as u8).wrapping_mul(7).wrapping_add(1);
            SymbolFrame::new(MESSAGE_ID, esi, vec![fill; SYMBOL_SIZE as usize])
        })
        .collect()
}

/// Feed a delivered frame sequence into a fresh reassembler.
fn reassemble(header: &MessageHeader, delivered: &[SymbolFrame]) -> MessageReassembler {
    let mut ra = MessageReassembler::new(header);
    for frame in delivered {
        let _ = ra.accept_frame(frame);
    }
    ra
}

/// AC1: across a 5/10/20/40% drop matrix and several seeds, the reassembler is
/// ready exactly when the number of distinct symbols lost stays within the
/// repair budget — the readiness bound tracks `BlockLayout` for every outcome.
#[test]
fn loss_matrix_readiness_tracks_the_repair_margin() {
    let header = header();
    let layout = header.block_layout();
    let frames = full_symbol_set(&header);

    for drop_ppm in [50_000u32, 100_000, 200_000, 400_000] {
        for seed in [1u64, 2, 7, 42, 99, 12_345, 654_321] {
            let model = LossModel::new(seed).with_drop_ppm(drop_ppm);
            let delivered = model.apply(&frames);
            let ra = reassemble(&header, &delivered);

            let lost = header.total_symbols - ra.distinct_received();
            assert_eq!(
                ra.is_ready(),
                lost <= REPAIR,
                "drop_ppm={drop_ppm} seed={seed}: ready iff lost({lost}) <= repair({REPAIR})"
            );
            assert_eq!(
                ra.is_ready(),
                !layout.is_unrecoverable(lost),
                "drop_ppm={drop_ppm} seed={seed}: readiness must agree with BlockLayout"
            );
        }
    }
}

/// Reorder-independence: delivering the same survivor set forward and reversed
/// yields an identical reassembler end-state (the intake is order-free).
#[test]
fn reorder_does_not_change_the_outcome() {
    let header = header();
    let frames = full_symbol_set(&header);

    for seed in [3u64, 17, 250, 99_991] {
        let model = LossModel::new(seed).with_drop_ppm(150_000);
        let delivered = model.apply(&frames);
        let mut reversed = delivered.clone();
        reversed.reverse();

        let forward = reassemble(&header, &delivered);
        let backward = reassemble(&header, &reversed);

        assert_eq!(forward.distinct_received(), backward.distinct_received());
        assert_eq!(forward.is_ready(), backward.is_ready());
        let f: Vec<(u16, Vec<u8>)> = forward.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        let b: Vec<(u16, Vec<u8>)> = backward.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        assert_eq!(
            f, b,
            "seed={seed}: held set must not depend on arrival order"
        );
    }
}

/// Duplication never inflates the distinct count: a drop+dup mix still yields
/// exactly the distinct survivors, and every repeated symbol is flagged.
#[test]
fn duplication_is_deduplicated() {
    let header = header();
    let frames = full_symbol_set(&header);

    for seed in [5u64, 21, 808, 123_457] {
        let model = LossModel::new(seed)
            .with_drop_ppm(100_000)
            .with_duplicate_ppm(500_000);
        let delivered = model.apply(&frames);

        let mut ra = MessageReassembler::new(&header);
        let mut accepted = 0u16;
        let mut duplicates = 0u32;
        for frame in &delivered {
            match ra.accept_frame(frame) {
                SymbolAccept::Accepted => accepted += 1,
                SymbolAccept::Duplicate => duplicates += 1,
                other => panic!("unexpected accept outcome for an in-range frame: {other:?}"),
            }
        }
        assert_eq!(ra.distinct_received(), accepted, "distinct == accepted");
        assert!(ra.distinct_received() <= header.total_symbols);
        // Every delivered frame was either a first-seen accept or a duplicate.
        assert_eq!(
            u32::from(accepted) + duplicates,
            u32::try_from(delivered.len()).expect("fits u32"),
            "seed={seed}: accounting must cover every delivered frame"
        );
        assert_eq!(
            ra.is_ready(),
            ra.distinct_received() >= header.source_symbols
        );
    }
}

/// AC7: the model is reproducible from its seed — the same `(seed, rates)`
/// applied to the same input yields a byte-identical delivered sequence and an
/// identical reassembler end-state, so a failing scenario replays exactly.
#[test]
fn deterministic_replay_for_a_fixed_seed() {
    let header = header();
    let frames = full_symbol_set(&header);
    let model = LossModel::new(2024)
        .with_drop_ppm(175_000)
        .with_duplicate_ppm(60_000);

    let first = model.apply(&frames);
    let second = model.apply(&frames);
    assert_eq!(
        first, second,
        "same model + input must deliver an identical stream"
    );

    let ra1 = reassemble(&header, &first);
    let ra2 = reassemble(&header, &second);
    assert_eq!(ra1.distinct_received(), ra2.distinct_received());
    assert_eq!(ra1.is_ready(), ra2.is_ready());
}

/// The delivered frames survive a wire encode/decode round-trip unchanged, so
/// the byte form composes with the loss model and intake identically to the
/// in-memory frames.
#[test]
fn wire_roundtrip_composes_with_the_model() {
    let header = header();
    let frames = full_symbol_set(&header);
    let model = LossModel::new(77)
        .with_drop_ppm(120_000)
        .with_duplicate_ppm(80_000);
    let delivered = model.apply(&frames);

    let decoded: Vec<SymbolFrame> = delivered
        .iter()
        .map(|frame| {
            let bytes = frame.encode();
            assert_eq!(bytes.len(), frame.encoded_len());
            SymbolFrame::decode(&bytes).expect("decode")
        })
        .collect();
    assert_eq!(decoded, delivered, "wire round-trip must be identity");

    let from_wire = reassemble(&header, &decoded);
    let from_memory = reassemble(&header, &delivered);
    assert_eq!(
        from_wire.distinct_received(),
        from_memory.distinct_received()
    );
    assert_eq!(from_wire.is_ready(), from_memory.is_ready());
}

/// The documented bound at the public surface: exactly `K-1` distinct symbols is
/// not ready; the `K`-th flips readiness on.
#[test]
fn k_minus_one_is_not_ready_k_is() {
    let header = header();
    let frames = full_symbol_set(&header);
    let k = header.source_symbols;

    let mut ra = MessageReassembler::new(&header);
    for frame in frames.iter().take((k - 1) as usize) {
        assert_eq!(ra.accept_frame(frame), SymbolAccept::Accepted);
    }
    assert_eq!(ra.distinct_received(), k - 1);
    assert!(!ra.is_ready(), "K-1 distinct symbols must not be decodable");
    assert_eq!(ra.symbols_until_ready(), 1);

    assert_eq!(
        ra.accept_frame(&frames[(k - 1) as usize]),
        SymbolAccept::Accepted
    );
    assert_eq!(ra.distinct_received(), k);
    assert!(ra.is_ready(), "K distinct symbols must be decodable");
    assert_eq!(ra.symbols_until_ready(), 0);
}
