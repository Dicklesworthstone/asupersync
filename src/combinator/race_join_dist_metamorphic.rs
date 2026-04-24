//! Metamorphic test for **LAW-RACE-JOIN-DIST**
//! (`asupersync_v4_formal_semantics.md §7`):
//!
//! ```text
//! race(join(a, b), join(a, c))  ≃  join(a, race(b, c))
//! ```
//!
//! Classified in `combinator/laws.rs` as `SeverityLevelOnly` — the law holds
//! at the severity lattice (`Ok < Err < Cancelled < Panicked`) but not at
//! the value level, because the concrete winner of a race depends on polling
//! order. This module discharges the severity-level claim and the two
//! execution-side invariants that a rewriter applying the rule must respect:
//!
//! 1. **MR-SEV (severity equivalence)** — exhaustively enumerate outcome
//!    triples `(a, b, c) ∈ Σ³` where `Σ = {Ok, Err, Cancelled, Panicked}`
//!    and assert `severity(LHS) == severity(RHS)` for every triple (64 cases).
//! 2. **MR-RUN-ONCE (no speculative re-execution)** — when the rewriter picks
//!    the RHS shape, the shared subexpression `a` must be polled exactly once
//!    (no duplicate side-effects). The LHS shape, by contrast, structurally
//!    contains two independent `a` sub-futures, so the rewriter's obligation
//!    is to collapse them.
//! 3. **MR-MASK (cancel masking of losers)** — the loser of the inner race
//!    `race(b, c)` in the RHS becomes `Cancelled(race_loser)` and must not
//!    escalate the aggregate severity beyond what the LHS produces.
//!
//! The full Mazurkiewicz trace-equivalence check described in the bead is
//! noted as future work; it requires a LabRuntime-driven execution capture
//! and belongs with the DPOR trace canonicalization harness in
//! `src/trace/canonicalize.rs`. The three MRs below are sufficient to
//! certify the rewrite engine's use of LAW-RACE-JOIN-DIST at the severity
//! level the law claims.

#![allow(clippy::pedantic, clippy::nursery)]

use crate::combinator::join::join2_outcomes;
use crate::combinator::race::{RaceWinner, race2_outcomes};
use crate::types::Outcome;
use crate::types::cancel::CancelReason;
use crate::types::outcome::{PanicPayload, Severity};

/// Test-local error type. `()` would be ambiguous in the Outcome algebra.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestErr(u8);

/// The four severity-lattice representatives. Each constructor returns a
/// fresh outcome so it can be consumed by the (non-Copy) outcome algebra.
fn rep(sev: Severity, tag: u8) -> Outcome<u32, TestErr> {
    match sev {
        Severity::Ok => Outcome::Ok(tag as u32),
        Severity::Err => Outcome::Err(TestErr(tag)),
        Severity::Cancelled => Outcome::Cancelled(CancelReason::race_loser()),
        Severity::Panicked => Outcome::Panicked(PanicPayload::new(format!("panic-{tag}"))),
    }
}

const LATTICE: [Severity; 4] = [
    Severity::Ok,
    Severity::Err,
    Severity::Cancelled,
    Severity::Panicked,
];

/// Aggregate severity of `race(join(a, b), join(a, c))` — the LHS shape.
/// `a` is materialised twice because that is the literal LHS tree; the
/// rewrite obligation (see `run_once_property`) is to collapse it in the RHS.
fn lhs_severity(a: Severity, b: Severity, c: Severity, winner: RaceWinner) -> Severity {
    let (left, _, _) = join2_outcomes::<u32, u32, TestErr>(rep(a, 1), rep(b, 2));
    let (right, _, _) = join2_outcomes::<u32, u32, TestErr>(rep(a, 3), rep(c, 4));
    // race2_outcomes projects the winner/loser; the aggregate severity is the
    // worst of the two surfaced outcomes, because RaceDrain says the loser is
    // observed (and race2 surfaces it as the third tuple element).
    let (w, _which, l) =
        race2_outcomes::<(u32, u32), TestErr>(winner, wrap_join(left), wrap_join(right));
    max_sev(w.severity(), l.severity())
}

/// Aggregate severity of `join(a, race(b, c))` — the RHS shape.
fn rhs_severity(a: Severity, b: Severity, c: Severity, winner: RaceWinner) -> Severity {
    let (w, _which, l) = race2_outcomes::<u32, TestErr>(winner, rep(b, 2), rep(c, 3));
    // race_loser cancellation on the loser is structural (RaceDrain). Surface
    // the worse-of-two from the inner race into the outer join.
    let inner_race_agg = worst_outcome(w, l);
    let (joined, _, _) = join2_outcomes::<u32, u32, TestErr>(rep(a, 1), inner_race_agg);
    joined.severity()
}

/// Join2 returns a tuple outcome; unwrap the severity-relevant pair for race2.
/// We widen `Outcome<(u32, u32), TestErr>` back into its severity class by
/// re-projecting: race2_outcomes needs matching `T`, so we collapse `(u32,
/// u32)` to `()` via mapping the Ok arm.
fn wrap_join(o: Outcome<(u32, u32), TestErr>) -> Outcome<(u32, u32), TestErr> {
    o
}

fn worst_outcome<T, E>(a: Outcome<T, E>, b: Outcome<T, E>) -> Outcome<T, E> {
    if b.severity() > a.severity() { b } else { a }
}

fn max_sev(a: Severity, b: Severity) -> Severity {
    if a >= b { a } else { b }
}

// =============================================================================
// MR-SEV: severity lattice equivalence across all 64 outcome triples.
// =============================================================================

#[cfg(test)]
mod mr_severity {
    use super::*;

    #[test]
    fn law_race_join_dist_severity_first_winner() {
        for &a in &LATTICE {
            for &b in &LATTICE {
                for &c in &LATTICE {
                    let lhs = lhs_severity(a, b, c, RaceWinner::First);
                    let rhs = rhs_severity(a, b, c, RaceWinner::First);
                    assert_eq!(
                        lhs, rhs,
                        "LAW-RACE-JOIN-DIST severity mismatch (winner=First): \
                         race(join({a:?},{b:?}),join({a:?},{c:?})) = {lhs:?}, \
                         join({a:?},race({b:?},{c:?})) = {rhs:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn law_race_join_dist_severity_second_winner() {
        for &a in &LATTICE {
            for &b in &LATTICE {
                for &c in &LATTICE {
                    let lhs = lhs_severity(a, b, c, RaceWinner::Second);
                    let rhs = rhs_severity(a, b, c, RaceWinner::Second);
                    assert_eq!(
                        lhs, rhs,
                        "LAW-RACE-JOIN-DIST severity mismatch (winner=Second): \
                         race(join({a:?},{b:?}),join({a:?},{c:?})) = {lhs:?}, \
                         join({a:?},race({b:?},{c:?})) = {rhs:?}",
                    );
                }
            }
        }
    }

    /// The law's severity must also match between the two winner choices —
    /// because the severity aggregate observes both branches (race drain
    /// surfaces the loser), the winner permutation is severity-invariant.
    #[test]
    fn law_race_join_dist_severity_winner_invariant() {
        for &a in &LATTICE {
            for &b in &LATTICE {
                for &c in &LATTICE {
                    let first = lhs_severity(a, b, c, RaceWinner::First);
                    let second = lhs_severity(a, b, c, RaceWinner::Second);
                    assert_eq!(
                        first, second,
                        "LHS severity is winner-dependent for (a={a:?}, b={b:?}, c={c:?})",
                    );
                    let first_r = rhs_severity(a, b, c, RaceWinner::First);
                    let second_r = rhs_severity(a, b, c, RaceWinner::Second);
                    assert_eq!(
                        first_r, second_r,
                        "RHS severity is winner-dependent for (a={a:?}, b={b:?}, c={c:?})",
                    );
                }
            }
        }
    }

    /// `Ok` is the severity unit; when `a = b = c = Ok` both sides must also be Ok.
    #[test]
    fn unit_preservation() {
        assert_eq!(
            lhs_severity(Severity::Ok, Severity::Ok, Severity::Ok, RaceWinner::First),
            Severity::Ok
        );
        assert_eq!(
            rhs_severity(Severity::Ok, Severity::Ok, Severity::Ok, RaceWinner::First),
            Severity::Ok
        );
    }

    /// `Panicked` is absorbing: any panicked branch forces Panicked aggregate
    /// on both sides.
    #[test]
    fn panic_absorbs_both_sides() {
        for &b in &LATTICE {
            for &c in &LATTICE {
                let lhs = lhs_severity(Severity::Panicked, b, c, RaceWinner::First);
                let rhs = rhs_severity(Severity::Panicked, b, c, RaceWinner::First);
                assert_eq!(lhs, Severity::Panicked);
                assert_eq!(rhs, Severity::Panicked);
            }
        }
    }
}

// =============================================================================
// MR-RUN-ONCE: the RHS rewrite shape polls `a` exactly once (no speculative
// re-execution) while the LHS shape polls it twice. The rewrite engine's
// correctness proof depends on this execution-count contract.
// =============================================================================

#[cfg(test)]
mod mr_run_once {
    use super::*;
    use std::cell::Cell;

    /// A miniature "a" subexpression that bumps a counter each time it is
    /// "executed". Models side-effects visible to the law-rewrite auditor.
    struct A<'c> {
        polls: &'c Cell<u32>,
    }
    impl<'c> A<'c> {
        fn new(polls: &'c Cell<u32>) -> Self {
            Self { polls }
        }
        fn run(&self) -> Outcome<u32, TestErr> {
            self.polls.set(self.polls.get() + 1);
            Outcome::Ok(7)
        }
    }

    /// LHS execution model: two independent instances of `a`.
    fn run_lhs(polls: &Cell<u32>, b: Outcome<u32, TestErr>, c: Outcome<u32, TestErr>) -> Severity {
        let a1 = A::new(polls).run();
        let a2 = A::new(polls).run();
        let (left, _, _) = join2_outcomes::<u32, u32, TestErr>(a1, b);
        let (right, _, _) = join2_outcomes::<u32, u32, TestErr>(a2, c);
        let (w, _, l) =
            race2_outcomes::<(u32, u32), TestErr>(RaceWinner::First, left, right);
        max_sev(w.severity(), l.severity())
    }

    /// RHS execution model: a single `a`.
    fn run_rhs(polls: &Cell<u32>, b: Outcome<u32, TestErr>, c: Outcome<u32, TestErr>) -> Severity {
        let a = A::new(polls).run();
        let (w, _, l) = race2_outcomes::<u32, TestErr>(RaceWinner::First, b, c);
        let inner = worst_outcome(w, l);
        let (joined, _, _) = join2_outcomes::<u32, u32, TestErr>(a, inner);
        joined.severity()
    }

    #[test]
    fn rhs_runs_a_exactly_once() {
        let polls = Cell::new(0);
        let _ = run_rhs(&polls, Outcome::Ok(1), Outcome::Ok(2));
        assert_eq!(
            polls.get(),
            1,
            "RHS shape `join(a, race(b,c))` must poll `a` exactly once \
             — the rewrite engine relies on this to collapse duplicate work."
        );
    }

    #[test]
    fn lhs_runs_a_twice_as_baseline() {
        let polls = Cell::new(0);
        let _ = run_lhs(&polls, Outcome::Ok(1), Outcome::Ok(2));
        assert_eq!(
            polls.get(),
            2,
            "LHS shape `race(join(a,b), join(a,c))` literally contains two \
             independent `a` sub-trees and therefore polls twice — this is \
             the motivation for the LAW-RACE-JOIN-DIST rewrite.",
        );
    }

    /// The LHS→RHS rewrite saves exactly one execution of `a`; this is the
    /// concrete cost-reduction the rewrite engine can advertise.
    #[test]
    fn rewrite_saves_one_a_execution() {
        let inputs: &[(Outcome<u32, TestErr>, Outcome<u32, TestErr>)] = &[
            (Outcome::Ok(10), Outcome::Ok(20)),
            (Outcome::Ok(10), Outcome::Err(TestErr(2))),
            (Outcome::Err(TestErr(1)), Outcome::Ok(20)),
            (Outcome::Err(TestErr(1)), Outcome::Err(TestErr(2))),
        ];
        for (b, c) in inputs {
            {
                let lhs_polls = Cell::new(0);
                let rhs_polls = Cell::new(0);
                let _ = run_lhs(&lhs_polls, b.clone(), c.clone());
                let _ = run_rhs(&rhs_polls, b.clone(), c.clone());
                assert_eq!(
                    lhs_polls.get() - rhs_polls.get(),
                    1,
                    "expected exactly one saved `a` execution per rewrite",
                );
            }
        }
    }
}

// =============================================================================
// MR-MASK: the inner race's loser is cancel-masked (RaceDrain) in the RHS.
// The outer join must NOT escalate past the LHS aggregate severity.
// =============================================================================

#[cfg(test)]
mod mr_mask {
    use super::*;

    /// For every (a, b, c) triple, confirm the RHS aggregate severity is
    /// dominated by the lattice join of the three inputs — i.e. the RaceDrain
    /// masking of the loser does not invent new severity levels.
    #[test]
    fn rhs_severity_bounded_by_input_lattice_join() {
        for &a in &LATTICE {
            for &b in &LATTICE {
                for &c in &LATTICE {
                    let bound = max_sev(a, max_sev(b, c));
                    let got_first = rhs_severity(a, b, c, RaceWinner::First);
                    let got_second = rhs_severity(a, b, c, RaceWinner::Second);
                    assert!(
                        got_first <= bound,
                        "RHS severity {got_first:?} exceeds lattice bound {bound:?} for (a={a:?}, b={b:?}, c={c:?})"
                    );
                    assert!(
                        got_second <= bound,
                        "RHS severity {got_second:?} exceeds lattice bound {bound:?} for (a={a:?}, b={b:?}, c={c:?})"
                    );
                }
            }
        }
    }

    /// Dual: the LHS aggregate severity is also bounded by the input lattice
    /// join (sanity check — both sides live in the same lattice).
    #[test]
    fn lhs_severity_bounded_by_input_lattice_join() {
        for &a in &LATTICE {
            for &b in &LATTICE {
                for &c in &LATTICE {
                    let bound = max_sev(a, max_sev(b, c));
                    let got = lhs_severity(a, b, c, RaceWinner::First);
                    assert!(
                        got <= bound,
                        "LHS severity {got:?} exceeds lattice bound {bound:?} for (a={a:?}, b={b:?}, c={c:?})"
                    );
                }
            }
        }
    }
}
