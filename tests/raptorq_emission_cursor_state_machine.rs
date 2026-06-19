//! RFC 6330 systematic-encoder emission state machine — wire-ordering contract.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC2/AC3. The streaming emission API
//! (`emit_systematic` / `emit_repair` / `next_repair_esi` /
//! `systematic_emitted`) is a small state machine whose job is to guarantee
//! a single legal on-the-wire ESI ordering: all source ESIs (0..K) strictly
//! before any repair ESI (>= K), each ESI emitted at most once, monotonically
//! ascending. Those invariants live only behind `debug_assert!` inside the
//! encoder; `next_repair_esi()` and `systematic_emitted()` had ZERO test
//! coverage, and the cursor/lane-closure transitions were unpinned at the
//! public boundary.
//!
//! This harness pins the full transition table via the public API only:
//!
//!   - INITIAL STATE: next_repair_esi() == K, systematic_emitted() == false.
//!   - SYSTEMATIC IDEMPOTENCE: emit_systematic() yields K source symbols
//!     (ESI 0..K, is_source, degree 1, byte-exact source) the first time and
//!     an empty batch on every later call.
//!   - REPAIR CURSOR CONTINUITY: successive emit_repair(n) calls return
//!     contiguous, non-overlapping, strictly ascending ESI runs starting at K;
//!     next_repair_esi() advances by exactly the number emitted.
//!   - LANE CLOSURE: emit_repair (count > 0) permanently closes the systematic
//!     lane, so a subsequent emit_systematic() is empty — even when repair is
//!     emitted FIRST (source symbols can never follow higher repair ESIs).
//!   - EMPTY-REPAIR NO-CLOSE EDGE CASE: emit_repair(0) emits nothing AND does
//!     NOT close the lane (the `if count != 0` guard), so systematic emission
//!     still works afterward.
//!
//! Repro: `cargo test --test raptorq_emission_cursor_state_machine`

use asupersync::raptorq::systematic::{EmittedSymbol, SystematicEncoder};

const SYMBOL_SIZE: usize = 8;

/// Deterministic, per-symbol-distinct source block of `k` symbols.
fn make_source(k: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..SYMBOL_SIZE)
                .map(|b| ((i * 31 + b * 7 + 3) & 0xFF) as u8)
                .collect()
        })
        .collect()
}

fn new_encoder(k: usize) -> SystematicEncoder {
    let source = make_source(k);
    SystematicEncoder::new(&source, SYMBOL_SIZE, 0xC0FFEE_u64)
        .unwrap_or_else(|| panic!("encoder construction failed for K={k}"))
}

/// Assert a batch is exactly the K source symbols in canonical order.
fn assert_is_full_source(batch: &[EmittedSymbol], source: &[Vec<u8>]) {
    assert_eq!(batch.len(), source.len(), "systematic batch must be K long");
    for (i, sym) in batch.iter().enumerate() {
        assert_eq!(sym.esi, i as u32, "source ESI must equal index");
        assert!(sym.is_source, "source symbol must be flagged is_source");
        assert_eq!(sym.degree, 1, "source symbol degree must be 1");
        assert_eq!(sym.data, source[i], "source symbol must be byte-exact");
    }
}

#[test]
fn initial_cursor_and_flag_state() {
    for &k in &[1usize, 4, 10, 42] {
        let enc = new_encoder(k);
        assert_eq!(
            enc.next_repair_esi(),
            k as u32,
            "next_repair_esi must start at K={k}"
        );
        assert!(
            !enc.systematic_emitted(),
            "systematic_emitted must be false before any emission (K={k})"
        );
    }
}

#[test]
fn systematic_emission_is_idempotent() {
    for &k in &[1usize, 4, 10, 42] {
        let source = make_source(k);
        let mut enc = SystematicEncoder::new(&source, SYMBOL_SIZE, 7).unwrap();

        let first = enc.emit_systematic();
        assert_is_full_source(&first, &source);
        assert!(
            enc.systematic_emitted(),
            "flag must flip true after first systematic emission (K={k})"
        );
        // Cursor untouched by systematic emission.
        assert_eq!(
            enc.next_repair_esi(),
            k as u32,
            "systematic emission must not move the repair cursor (K={k})"
        );

        // Every subsequent call is empty and idempotent.
        for _ in 0..3 {
            assert!(
                enc.emit_systematic().is_empty(),
                "repeated emit_systematic must be empty (K={k})"
            );
        }
    }
}

#[test]
fn repair_cursor_is_contiguous_and_monotone() {
    for &k in &[1usize, 4, 10, 42] {
        let mut enc = new_encoder(k);
        let _ = enc.emit_systematic();

        // Drive several non-uniform repair batches and accumulate ESIs.
        let plan = [3usize, 1, 5, 2, 4];
        let mut all_esis: Vec<u32> = Vec::new();
        let mut expected_next = k as u32;

        for &count in &plan {
            let start = enc.next_repair_esi();
            assert_eq!(
                start, expected_next,
                "cursor desync before emit_repair({count}) (K={k})"
            );
            let batch = enc.emit_repair(count);
            assert_eq!(
                batch.len(),
                count,
                "emit_repair must return `count` symbols (K={k})"
            );
            for (i, sym) in batch.iter().enumerate() {
                assert_eq!(
                    sym.esi,
                    start + i as u32,
                    "repair ESI must be start+i within batch (K={k})"
                );
                assert!(
                    !sym.is_source,
                    "repair symbol must not be is_source (K={k})"
                );
                assert!(sym.esi >= k as u32, "repair ESI must be >= K (K={k})");
                all_esis.push(sym.esi);
            }
            expected_next = start + count as u32;
            assert_eq!(
                enc.next_repair_esi(),
                expected_next,
                "cursor must advance by exactly `count` (K={k})"
            );
        }

        // Global property: strictly ascending, no gaps, no overlaps, begins at K.
        assert_eq!(
            all_esis.first().copied(),
            Some(k as u32),
            "first repair ESI != K"
        );
        for w in all_esis.windows(2) {
            assert_eq!(
                w[1],
                w[0] + 1,
                "repair ESIs must be gap-free and ascending (K={k})"
            );
        }
        let total: usize = plan.iter().sum();
        assert_eq!(
            all_esis.len(),
            total,
            "emitted repair count mismatch (K={k})"
        );
    }
}

#[test]
fn repair_permanently_closes_systematic_lane() {
    for &k in &[1usize, 10, 42] {
        let mut enc = new_encoder(k);
        let _ = enc.emit_systematic();

        // After repair starts, systematic emission is closed forever.
        let repair = enc.emit_repair(2);
        assert_eq!(repair.len(), 2);
        assert!(
            enc.systematic_emitted(),
            "flag stays true after repair (K={k})"
        );
        assert!(
            enc.emit_systematic().is_empty(),
            "systematic lane must stay closed after repair (K={k})"
        );
    }
}

#[test]
fn repair_first_drops_source_from_the_wire() {
    // The dangerous ordering: emit repair BEFORE source. The lane must close
    // so that source symbols (low ESIs) can never follow higher repair ESIs.
    for &k in &[1usize, 10, 42] {
        let mut enc = new_encoder(k);
        assert!(!enc.systematic_emitted());

        let repair = enc.emit_repair(3);
        assert_eq!(repair.len(), 3);
        assert_eq!(
            repair[0].esi, k as u32,
            "repair-first must still start at K (K={k})"
        );
        assert!(
            enc.systematic_emitted(),
            "emit_repair must close the lane even when called first (K={k})"
        );
        assert!(
            enc.emit_systematic().is_empty(),
            "source must be unavailable once repair has been emitted first (K={k})"
        );
        // Cursor continues cleanly from where repair-first left off.
        assert_eq!(enc.next_repair_esi(), k as u32 + 3);
    }
}

#[test]
fn empty_repair_does_not_close_lane() {
    // emit_repair(0) is a no-op: it emits nothing AND must NOT close the
    // systematic lane (the `if count != 0` guard). Source emission must still
    // work afterward.
    for &k in &[1usize, 10, 42] {
        let source = make_source(k);
        let mut enc = SystematicEncoder::new(&source, SYMBOL_SIZE, 99).unwrap();

        let empty = enc.emit_repair(0);
        assert!(empty.is_empty(), "emit_repair(0) must emit nothing (K={k})");
        assert!(
            !enc.systematic_emitted(),
            "emit_repair(0) must NOT close the systematic lane (K={k})"
        );
        assert_eq!(
            enc.next_repair_esi(),
            k as u32,
            "emit_repair(0) must not move the cursor (K={k})"
        );

        // Systematic emission still works and yields the full source block.
        let sys = enc.emit_systematic();
        assert_is_full_source(&sys, &source);
        assert!(
            enc.systematic_emitted(),
            "flag flips after the real systematic pass (K={k})"
        );
    }
}
