//! RaptorQ decode-proof trace recorders — bounded-preview + counter conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC3 (property/metamorphic checks) + AC5
//! (structured forensic logging schema). The decode-proof forensic trace
//! (`src/raptorq/proof.rs`) records peeling/elimination events into bounded
//! preview lists that operators read from structured logs. The recorder
//! methods had ZERO integration coverage:
//!   - `ReceivedSummary::from_received`
//!   - `PeelingTrace::record_solved`
//!   - `EliminationTrace::{set_strategy, record_strategy_transition,
//!      record_inactivation, record_pivot, record_row_op}`
//! so nothing pinned the documented bookkeeping: full counters always advance,
//! preview vectors cap at `MAX_PIVOT_EVENTS` / `MAX_RECEIVED_SYMBOLS` and flip a
//! truncation flag, the received-ESI multiset hash is order-independent, and a
//! same-strategy "transition" is a no-op on the event list.
//!
//! These are pure value types (`Default` + public fields + public mutators), so
//! the harness is oracle-free and needs no decode run: it recomputes the
//! expected bookkeeping directly and asserts structural laws (counter == call
//! count, preview == first `min(N, CAP)` entries, flags iff over cap).
//!
//! Repro: `cargo test --test raptorq_decode_proof_trace_recorders_conformance`

use asupersync::raptorq::proof::{
    EliminationTrace, InactivationStrategy, MAX_PIVOT_EVENTS, MAX_RECEIVED_SYMBOLS, PeelingTrace,
    PivotEvent, ReceivedSummary, StrategyTransition,
};

// ---------------------------------------------------------------------------
// ReceivedSummary::from_received
// ---------------------------------------------------------------------------

#[test]
fn received_summary_counts_partition_total() {
    // total == source + repair, and each counter matches the input multiset.
    let symbols: Vec<(u32, bool)> = vec![
        (0, true),
        (5, false),
        (1, true),
        (9, false),
        (3, false),
        (2, true),
    ];
    let summary = ReceivedSummary::from_received(symbols.iter().copied());
    let expected_source = symbols.iter().filter(|(_, s)| *s).count();
    let expected_repair = symbols.len() - expected_source;
    assert_eq!(summary.total, symbols.len(), "total must equal #symbols");
    assert_eq!(
        summary.source_count, expected_source,
        "source_count mismatch"
    );
    assert_eq!(
        summary.repair_count, expected_repair,
        "repair_count mismatch"
    );
    assert_eq!(
        summary.source_count + summary.repair_count,
        summary.total,
        "source + repair must partition total"
    );
}

#[test]
fn received_summary_esis_sorted_ascending_and_complete_when_small() {
    let symbols: Vec<(u32, bool)> = vec![(9, false), (2, true), (5, false), (0, true), (7, false)];
    let summary = ReceivedSummary::from_received(symbols.iter().copied());
    assert!(!summary.truncated, "small input must not be truncated");
    let mut expected: Vec<u32> = symbols.iter().map(|(esi, _)| *esi).collect();
    expected.sort_unstable();
    assert_eq!(
        summary.esis, expected,
        "esis must be the full ascending set"
    );
    assert!(
        summary.esis.windows(2).all(|w| w[0] <= w[1]),
        "esis must be sorted ascending"
    );
}

#[test]
fn received_summary_truncates_to_smallest_max_received() {
    // Feed strictly more than the cap with ESIs 0..N: the preview must keep the
    // SMALLEST MAX_RECEIVED_SYMBOLS ESIs (the heap evicts the current max).
    let n = MAX_RECEIVED_SYMBOLS + 76;
    let symbols: Vec<(u32, bool)> = (0..n as u32).map(|esi| (esi, esi % 2 == 0)).collect();
    let summary = ReceivedSummary::from_received(symbols.iter().copied());
    assert_eq!(summary.total, n, "total counts every received symbol");
    assert!(summary.truncated, "over-cap input must set truncated");
    assert_eq!(
        summary.esis.len(),
        MAX_RECEIVED_SYMBOLS,
        "preview caps at MAX_RECEIVED_SYMBOLS"
    );
    let expected: Vec<u32> = (0..MAX_RECEIVED_SYMBOLS as u32).collect();
    assert_eq!(
        summary.esis, expected,
        "preview must retain the smallest MAX_RECEIVED_SYMBOLS ESIs, sorted"
    );
}

#[test]
fn received_summary_multiset_hash_is_order_independent() {
    // The multiset hash accumulates per-element digests with commutative
    // wrapping adds, so permuting the input must not change the hash (nor the
    // counts), while the bounded ESI preview is canonically re-sorted.
    let forward: Vec<(u32, bool)> = vec![
        (4, false),
        (1, true),
        (4, false), // duplicate ESI on purpose: it's a multiset
        (8, false),
        (1, true),
        (2, true),
    ];
    let reversed: Vec<(u32, bool)> = forward.iter().rev().copied().collect();
    let a = ReceivedSummary::from_received(forward.iter().copied());
    let b = ReceivedSummary::from_received(reversed.iter().copied());
    assert_eq!(
        a.esi_multiset_hash, b.esi_multiset_hash,
        "multiset hash must be order-independent"
    );
    assert_eq!(a.total, b.total, "total invariant under permutation");
    assert_eq!(a.source_count, b.source_count, "source count invariant");
    assert_eq!(a.esis, b.esis, "canonical sorted preview invariant");
}

#[test]
fn received_summary_distinct_multiset_changes_hash() {
    // A genuinely different multiset (one element flips source->repair) yields a
    // different hash on these fixed deterministic inputs.
    let base: Vec<(u32, bool)> = vec![(1, true), (2, false), (3, true)];
    let mutated: Vec<(u32, bool)> = vec![(1, true), (2, true), (3, true)];
    let a = ReceivedSummary::from_received(base.into_iter());
    let b = ReceivedSummary::from_received(mutated.into_iter());
    assert_ne!(
        a.esi_multiset_hash, b.esi_multiset_hash,
        "distinct multiset must change the hash"
    );
}

// ---------------------------------------------------------------------------
// PeelingTrace::record_solved
// ---------------------------------------------------------------------------

#[test]
fn peeling_record_solved_counter_and_bounded_preview() {
    let n = MAX_PIVOT_EVENTS + 13;
    let mut trace = PeelingTrace::default();
    for col in 0..n {
        trace.record_solved(col);
    }
    assert_eq!(trace.solved, n, "solved counter must advance on every call");
    assert!(
        trace.truncated,
        "over-cap solved preview must set truncated"
    );
    assert_eq!(
        trace.solved_indices.len(),
        MAX_PIVOT_EVENTS,
        "solved preview caps at MAX_PIVOT_EVENTS"
    );
    let expected: Vec<usize> = (0..MAX_PIVOT_EVENTS).collect();
    assert_eq!(
        trace.solved_indices, expected,
        "preview retains the FIRST MAX_PIVOT_EVENTS solved columns in order"
    );
}

#[test]
fn peeling_record_solved_no_truncation_under_cap() {
    let mut trace = PeelingTrace::default();
    let cols = [7usize, 2, 9, 0, 5];
    for &col in &cols {
        trace.record_solved(col);
    }
    assert_eq!(trace.solved, cols.len(), "counter matches call count");
    assert!(!trace.truncated, "under-cap must not truncate");
    assert_eq!(
        trace.solved_indices,
        cols.to_vec(),
        "preview preserves insertion order exactly (no sorting)"
    );
}

// ---------------------------------------------------------------------------
// EliminationTrace mutators
// ---------------------------------------------------------------------------

#[test]
fn elimination_pivot_and_inactivation_counters_and_previews() {
    let n = MAX_PIVOT_EVENTS + 9;
    let mut trace = EliminationTrace::default();
    for i in 0..n {
        trace.record_pivot(i, i * 2);
        trace.record_inactivation(i + 100);
    }
    assert_eq!(trace.pivots, n, "pivot counter advances per call");
    assert_eq!(
        trace.inactivated, n,
        "inactivation counter advances per call"
    );
    assert!(
        trace.pivot_events_truncated,
        "pivot preview truncates over cap"
    );
    assert!(
        trace.inactive_cols_truncated,
        "inactive-cols preview truncates over cap"
    );
    assert_eq!(trace.pivot_events.len(), MAX_PIVOT_EVENTS);
    assert_eq!(trace.inactive_cols.len(), MAX_PIVOT_EVENTS);
    let expected_pivots: Vec<PivotEvent> = (0..MAX_PIVOT_EVENTS)
        .map(|i| PivotEvent { col: i, row: i * 2 })
        .collect();
    assert_eq!(
        trace.pivot_events, expected_pivots,
        "pivot preview keeps the FIRST cap (col,row) events in order"
    );
    let expected_inactive: Vec<usize> = (0..MAX_PIVOT_EVENTS).map(|i| i + 100).collect();
    assert_eq!(
        trace.inactive_cols, expected_inactive,
        "inactive-cols preview keeps the FIRST cap columns in order"
    );
}

#[test]
fn elimination_record_row_op_is_unbounded_pure_counter() {
    let mut trace = EliminationTrace::default();
    let n = MAX_PIVOT_EVENTS * 3 + 1;
    for _ in 0..n {
        trace.record_row_op();
    }
    assert_eq!(
        trace.row_ops, n,
        "row_ops is a plain counter with no preview"
    );
    // row ops never affect pivot/inactivation bookkeeping.
    assert_eq!(trace.pivots, 0);
    assert_eq!(trace.inactivated, 0);
    assert!(!trace.pivot_events_truncated);
}

#[test]
fn elimination_set_strategy_overwrites_field() {
    let mut trace = EliminationTrace::default();
    assert_eq!(
        trace.strategy,
        InactivationStrategy::AllAtOnce,
        "default strategy is AllAtOnce"
    );
    trace.set_strategy(InactivationStrategy::HighSupportFirst);
    assert_eq!(trace.strategy, InactivationStrategy::HighSupportFirst);
    trace.set_strategy(InactivationStrategy::AllAtOnce);
    assert_eq!(
        trace.strategy,
        InactivationStrategy::AllAtOnce,
        "set_strategy is a plain overwrite"
    );
}

#[test]
fn elimination_strategy_transition_records_only_real_changes() {
    use InactivationStrategy::{AllAtOnce, HighSupportFirst};
    let mut trace = EliminationTrace::default();

    // Same-strategy "transition" is a no-op on the event list but still sets
    // the active strategy.
    trace.record_strategy_transition(AllAtOnce, AllAtOnce, "noop");
    assert!(
        trace.strategy_transitions.is_empty(),
        "from == to must not push a transition"
    );
    assert_eq!(trace.strategy, AllAtOnce, "strategy still set to `to`");

    // A genuine change pushes one transition with the exact from/to/reason.
    trace.record_strategy_transition(AllAtOnce, HighSupportFirst, "hard_regime");
    assert_eq!(trace.strategy_transitions.len(), 1);
    assert_eq!(
        trace.strategy_transitions[0],
        StrategyTransition {
            from: AllAtOnce,
            to: HighSupportFirst,
            reason: "hard_regime",
        }
    );
    assert_eq!(trace.strategy, HighSupportFirst, "active strategy updated");
    assert!(!trace.strategy_transitions_truncated);
}

#[test]
fn elimination_strategy_transition_bounded_preview() {
    use InactivationStrategy::{AllAtOnce, HighSupportFirst};
    let mut trace = EliminationTrace::default();
    // Alternate so every call is a real change; exceed the cap.
    let n = MAX_PIVOT_EVENTS + 7;
    for i in 0..n {
        if i % 2 == 0 {
            trace.record_strategy_transition(AllAtOnce, HighSupportFirst, "to_high");
        } else {
            trace.record_strategy_transition(HighSupportFirst, AllAtOnce, "to_all");
        }
    }
    assert_eq!(
        trace.strategy_transitions.len(),
        MAX_PIVOT_EVENTS,
        "transition preview caps at MAX_PIVOT_EVENTS"
    );
    assert!(
        trace.strategy_transitions_truncated,
        "over-cap transitions set the truncation flag"
    );
    // The active strategy mirrors the LAST call's `to`, regardless of how many
    // earlier transitions the bounded preview dropped: even final index ->
    // "to_high" (HighSupportFirst), odd -> "to_all" (AllAtOnce).
    let expected_last = if (n - 1) % 2 == 0 {
        HighSupportFirst
    } else {
        AllAtOnce
    };
    assert_eq!(
        trace.strategy, expected_last,
        "active strategy tracks the latest transition even after preview truncation"
    );
}
