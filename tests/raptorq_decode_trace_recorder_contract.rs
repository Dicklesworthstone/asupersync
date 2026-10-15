//! RaptorQ decode-trace recorders — counter-exactness, cap-truncation, and
//! cross-field independence conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330). The decode solver instruments its peeling and
//! Gaussian-elimination phases through two public forensic recorders in
//! `raptorq::proof`:
//!   - `PeelingTrace::record_solved`
//!   - `EliminationTrace::{set_strategy, record_strategy_transition,
//!     record_inactivation, record_pivot, record_row_op}`
//!
//! Every one of those recorder methods had ZERO integration coverage — the
//! only exercise lived in `#[cfg(test)]` blocks inside `proof.rs` that compile
//! into the (perpetually heavy) lib-unittest binary and so never run as a
//! gate. Yet replay tooling and the DecodeProof artifact depend on the EXACT
//! shape these recorders produce: a precise event count, a bounded event list
//! that truncates at `MAX_PIVOT_EVENTS` while the counter keeps climbing, and a
//! truncation flag that flips exactly at the boundary.
//!
//! This harness pins, oracle-free (recomputing every expectation from the call
//! sequence and the public `MAX_PIVOT_EVENTS` constant):
//!   - each `record_*` counter equals the number of calls EXACTLY, even far
//!     past the cap (the list truncates; the counter does not);
//!   - each bounded list stores the first `MAX_PIVOT_EVENTS` events in call
//!     order and sets its `*_truncated` flag iff the call count exceeds the cap,
//!     with the boundary pinned at exactly the cap and cap+1;
//!   - `record_row_op` is an exact UNBOUNDED counter that touches no list;
//!   - `set_strategy` assigns directly and records no transition;
//!   - `record_strategy_transition` is a no-op for the transition list when
//!     `from == to` (but still advances the strategy) and otherwise appends and
//!     advances, with the final strategy equal to the last `to`;
//!   - the recorders are field-independent: driving one never perturbs the
//!     counters or lists owned by another.
//!
//! Repro: `cargo test --test raptorq_decode_trace_recorder_contract`

use asupersync::raptorq::proof::{
    EliminationTrace, InactivationStrategy, MAX_PIVOT_EVENTS, PeelingTrace, PivotEvent,
    StrategyTransition,
};

/// A distinct, non-trivial column index for the i-th recorded event, so a
/// silent reordering or dedup would be caught.
fn col_at(i: usize) -> usize {
    i.wrapping_mul(7).wrapping_add(3)
}

// ---------------------------------------------------------------------------
// PeelingTrace::record_solved
// ---------------------------------------------------------------------------

#[test]
fn record_solved_counts_exactly_and_truncates_index_list_at_cap() {
    // Sub-cap: the full index list is preserved in order, nothing truncated.
    let mut sub = PeelingTrace::default();
    let sub_n = MAX_PIVOT_EVENTS - 1;
    for i in 0..sub_n {
        sub.record_solved(col_at(i));
    }
    assert_eq!(sub.solved, sub_n, "counter must equal call count below cap");
    assert_eq!(sub.solved_indices.len(), sub_n);
    assert!(!sub.truncated, "must not truncate below the cap");
    let want: Vec<usize> = (0..sub_n).map(col_at).collect();
    assert_eq!(sub.solved_indices, want, "indices preserved in call order");

    // Exactly at the cap: list is full but truncation has NOT yet fired.
    let mut at = PeelingTrace::default();
    for i in 0..MAX_PIVOT_EVENTS {
        at.record_solved(col_at(i));
    }
    assert_eq!(at.solved, MAX_PIVOT_EVENTS);
    assert_eq!(at.solved_indices.len(), MAX_PIVOT_EVENTS);
    assert!(
        !at.truncated,
        "the cap-th event fills the list without truncating"
    );

    // Past the cap: the counter keeps climbing, the list is frozen at the cap,
    // and the truncation flag is set.
    let mut over = PeelingTrace::default();
    let over_n = MAX_PIVOT_EVENTS + 50;
    for i in 0..over_n {
        over.record_solved(col_at(i));
    }
    assert_eq!(over.solved, over_n, "counter is exact past the cap");
    assert_eq!(
        over.solved_indices.len(),
        MAX_PIVOT_EVENTS,
        "list frozen at cap"
    );
    assert!(
        over.truncated,
        "truncation flag set once the cap is exceeded"
    );
    let want_prefix: Vec<usize> = (0..MAX_PIVOT_EVENTS).map(col_at).collect();
    assert_eq!(
        over.solved_indices, want_prefix,
        "stored prefix is the FIRST cap events, in order"
    );
}

// ---------------------------------------------------------------------------
// EliminationTrace::record_inactivation
// ---------------------------------------------------------------------------

#[test]
fn record_inactivation_counts_exactly_and_truncates_at_cap() {
    let mut t = EliminationTrace::default();
    let n = MAX_PIVOT_EVENTS + 17;
    for i in 0..n {
        t.record_inactivation(col_at(i));
    }
    assert_eq!(
        t.inactivated, n,
        "inactivation counter is exact past the cap"
    );
    assert_eq!(
        t.inactive_cols.len(),
        MAX_PIVOT_EVENTS,
        "list frozen at cap"
    );
    assert!(t.inactive_cols_truncated, "truncation flag set");
    let want_prefix: Vec<usize> = (0..MAX_PIVOT_EVENTS).map(col_at).collect();
    assert_eq!(t.inactive_cols, want_prefix, "first cap cols, in order");

    // A fresh trace exactly at the cap does not truncate.
    let mut at = EliminationTrace::default();
    for i in 0..MAX_PIVOT_EVENTS {
        at.record_inactivation(col_at(i));
    }
    assert_eq!(at.inactivated, MAX_PIVOT_EVENTS);
    assert!(!at.inactive_cols_truncated);
}

// ---------------------------------------------------------------------------
// EliminationTrace::record_pivot
// ---------------------------------------------------------------------------

#[test]
fn record_pivot_counts_exactly_and_truncates_preserving_events() {
    let mut t = EliminationTrace::default();
    let n = MAX_PIVOT_EVENTS + 9;
    for i in 0..n {
        // Distinct (col, row) so reorderings are visible.
        t.record_pivot(col_at(i), i.wrapping_mul(2).wrapping_add(1));
    }
    assert_eq!(t.pivots, n, "pivot counter is exact past the cap");
    assert_eq!(
        t.pivot_events.len(),
        MAX_PIVOT_EVENTS,
        "events frozen at cap"
    );
    assert!(t.pivot_events_truncated, "truncation flag set");
    let want: Vec<PivotEvent> = (0..MAX_PIVOT_EVENTS)
        .map(|i| PivotEvent {
            col: col_at(i),
            row: i.wrapping_mul(2).wrapping_add(1),
        })
        .collect();
    assert_eq!(t.pivot_events, want, "first cap pivot events, in order");
}

// ---------------------------------------------------------------------------
// EliminationTrace::record_row_op — exact, unbounded, isolated.
// ---------------------------------------------------------------------------

#[test]
fn record_row_op_is_an_exact_unbounded_counter_touching_nothing_else() {
    let mut t = EliminationTrace::default();
    let n = MAX_PIVOT_EVENTS * 3 + 1; // well past any cap
    for _ in 0..n {
        t.record_row_op();
    }
    assert_eq!(t.row_ops, n, "row_ops is an exact unbounded counter");
    // Nothing else moved: row ops carry no list and never truncate.
    assert_eq!(t, {
        let mut expected = EliminationTrace::default();
        expected.row_ops = n;
        expected
    });
}

// ---------------------------------------------------------------------------
// EliminationTrace::set_strategy / record_strategy_transition
// ---------------------------------------------------------------------------

#[test]
fn set_strategy_assigns_directly_without_recording_a_transition() {
    for strategy in [
        InactivationStrategy::AllAtOnce,
        InactivationStrategy::HighSupportFirst,
        InactivationStrategy::BlockSchurLowRank,
    ] {
        let mut t = EliminationTrace::default();
        t.set_strategy(strategy);
        assert_eq!(t.strategy, strategy, "set_strategy assigns directly");
        assert!(
            t.strategy_transitions.is_empty(),
            "set_strategy records no transition"
        );
        assert!(!t.strategy_transitions_truncated);
    }
}

#[test]
fn record_strategy_transition_is_noop_on_equal_and_advances_on_change() {
    use InactivationStrategy::{AllAtOnce, BlockSchurLowRank, HighSupportFirst};

    // from == to: the strategy is set, but NO transition is recorded.
    let mut eq = EliminationTrace::default();
    eq.set_strategy(HighSupportFirst);
    eq.record_strategy_transition(HighSupportFirst, HighSupportFirst, "self-edge");
    assert_eq!(eq.strategy, HighSupportFirst);
    assert!(
        eq.strategy_transitions.is_empty(),
        "equal from/to must not append a transition"
    );

    // A sequence of genuine changes is recorded in order; strategy tracks last `to`.
    let mut seq = EliminationTrace::default();
    seq.record_strategy_transition(AllAtOnce, HighSupportFirst, "hard-regime");
    seq.record_strategy_transition(HighSupportFirst, BlockSchurLowRank, "low-rank");
    seq.record_strategy_transition(BlockSchurLowRank, AllAtOnce, "fallback");
    assert_eq!(seq.strategy, AllAtOnce, "strategy equals the last `to`");
    let want = vec![
        StrategyTransition {
            from: AllAtOnce,
            to: HighSupportFirst,
            reason: "hard-regime",
        },
        StrategyTransition {
            from: HighSupportFirst,
            to: BlockSchurLowRank,
            reason: "low-rank",
        },
        StrategyTransition {
            from: BlockSchurLowRank,
            to: AllAtOnce,
            reason: "fallback",
        },
    ];
    assert_eq!(
        seq.strategy_transitions, want,
        "transitions captured in order"
    );
    assert!(!seq.strategy_transitions_truncated);
}

#[test]
fn record_strategy_transition_truncates_the_list_at_cap() {
    use InactivationStrategy::{AllAtOnce, HighSupportFirst};

    // Alternate between two distinct strategies so every call is a real change
    // (from != to) and therefore appends until the cap is hit.
    let mut t = EliminationTrace::default();
    let n = MAX_PIVOT_EVENTS + 12;
    for i in 0..n {
        let (from, to) = if i % 2 == 0 {
            (AllAtOnce, HighSupportFirst)
        } else {
            (HighSupportFirst, AllAtOnce)
        };
        t.record_strategy_transition(from, to, "alternating");
    }
    assert_eq!(
        t.strategy_transitions.len(),
        MAX_PIVOT_EVENTS,
        "transition list frozen at cap"
    );
    assert!(t.strategy_transitions_truncated, "truncation flag set");
    // The final strategy still reflects the most recent `to`, regardless of
    // truncation of the recorded list.
    let last_to = if (n - 1) % 2 == 0 {
        HighSupportFirst
    } else {
        AllAtOnce
    };
    assert_eq!(
        t.strategy, last_to,
        "strategy advances even after truncation"
    );
}

// ---------------------------------------------------------------------------
// Cross-recorder independence.
// ---------------------------------------------------------------------------

#[test]
fn recorders_are_field_independent() {
    use InactivationStrategy::{AllAtOnce, HighSupportFirst};

    // Interleave a small, distinct number of each kind of event and assert each
    // counter/list reflects ONLY its own calls — no cross-contamination.
    let mut t = EliminationTrace::default();
    let inactivations = 5usize;
    let pivots = 3usize;
    let row_ops = 11usize;

    for i in 0..inactivations {
        t.record_inactivation(col_at(i));
        t.record_row_op();
    }
    for i in 0..pivots {
        t.record_pivot(col_at(i), i + 1);
        t.record_row_op();
    }
    for _ in 0..(row_ops - inactivations - pivots) {
        t.record_row_op();
    }
    t.record_strategy_transition(AllAtOnce, HighSupportFirst, "switch");

    assert_eq!(t.inactivated, inactivations, "inactivation count isolated");
    assert_eq!(t.inactive_cols.len(), inactivations);
    assert_eq!(t.pivots, pivots, "pivot count isolated");
    assert_eq!(t.pivot_events.len(), pivots);
    assert_eq!(t.row_ops, row_ops, "row_op count isolated");
    assert_eq!(
        t.strategy_transitions.len(),
        1,
        "one real transition recorded"
    );
    assert_eq!(t.strategy, HighSupportFirst);
    // No spurious truncation anywhere below the cap.
    assert!(!t.inactive_cols_truncated);
    assert!(!t.pivot_events_truncated);
    assert!(!t.strategy_transitions_truncated);

    // The peeling recorder lives on a separate struct and is wholly unaffected.
    let mut p = PeelingTrace::default();
    p.record_solved(col_at(99));
    assert_eq!(p.solved, 1);
    assert_eq!(p.solved_indices, vec![col_at(99)]);
}

#[test]
fn cap_constant_is_the_observed_truncation_boundary() {
    // Pin the public cap and prove all four bounded lists honor exactly it.
    assert_eq!(MAX_PIVOT_EVENTS, 256, "documented forensic-event cap");

    let mut peel = PeelingTrace::default();
    let mut elim = EliminationTrace::default();
    for i in 0..=MAX_PIVOT_EVENTS {
        peel.record_solved(col_at(i));
        elim.record_inactivation(col_at(i));
        elim.record_pivot(col_at(i), i);
        let to = if i % 2 == 0 {
            InactivationStrategy::HighSupportFirst
        } else {
            InactivationStrategy::AllAtOnce
        };
        let from = if i % 2 == 0 {
            InactivationStrategy::AllAtOnce
        } else {
            InactivationStrategy::HighSupportFirst
        };
        elim.record_strategy_transition(from, to, "boundary");
    }
    for (len, truncated, label) in [
        (
            peel.solved_indices.len(),
            peel.truncated,
            "peeling.solved_indices",
        ),
        (
            elim.inactive_cols.len(),
            elim.inactive_cols_truncated,
            "elim.inactive_cols",
        ),
        (
            elim.pivot_events.len(),
            elim.pivot_events_truncated,
            "elim.pivot_events",
        ),
        (
            elim.strategy_transitions.len(),
            elim.strategy_transitions_truncated,
            "elim.strategy_transitions",
        ),
    ] {
        assert_eq!(len, MAX_PIVOT_EVENTS, "{label} frozen at cap");
        assert!(truncated, "{label} truncation flag set at cap+1");
    }
}
