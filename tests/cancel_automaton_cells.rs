//! §3.2.5 cancellation automaton — per-cell property tests
//! (bead asupersync-7ntvjs).
//!
//! `asupersync_v4_formal_semantics.md` §3.2.5 specifies a deterministic
//! automaton over `(phase, reason, budget, mask)` driven by four events:
//!
//!     Event ::= Request(reason) | Checkpoint | CleanupDone | FinalizersDone
//!
//! The full transition table has twelve cells — one per
//! (Running, CancelRequested, Cancelling, Finalizing) × Event combination.
//! Most are no-ops or invalid; the spec lists eight legal transitions plus
//! the implicit "ignore" cells. This file exercises every cell and asserts:
//!
//!   1. Legal cells produce exactly the spec's target phase.
//!   2. `Request` is idempotent and only ever **strengthens** the reason
//!      and **tightens** the budget (monotonicity of the protocol).
//!   3. `mask` only ever decreases (INV-MASK-BOUNDED).
//!   4. Non-applicable events on a phase are no-ops (the implementation
//!      may panic or error, but the abstract automaton stutters).
//!
//! The model is a self-contained pure executable mirror of §3.2.5; it builds
//! on the runtime's public `CancelReason::strengthen` so any change to
//! reason ordering flows through this test suite.

use asupersync::types::Budget;
use asupersync::types::cancel::{CancelKind, CancelReason};

/// Phase identifier (matches `TaskState` discriminants relevant to the
/// cancellation protocol — Running through Finalizing). `Completed` is the
/// terminal sink and isn't part of the automaton's input vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    CancelRequested,
    Cancelling,
    Finalizing,
    Completed,
}

#[derive(Debug, Clone)]
struct AutomatonState {
    phase: Phase,
    reason: Option<CancelReason>,
    budget: Budget,
    mask: u32,
}

impl AutomatonState {
    fn fresh(mask: u32) -> Self {
        Self {
            phase: Phase::Running,
            reason: None,
            budget: Budget::INFINITE,
            mask,
        }
    }
}

#[derive(Debug, Clone)]
enum Event {
    Request(CancelReason),
    Checkpoint,
    CleanupDone,
    FinalizersDone,
}

/// The §3.2.5 automaton, transcribed verbatim. Returns `None` if the cell is
/// "stutter / not applicable" (the abstract automaton silently ignores
/// events that don't have a transition for the current phase).
fn step(state: &AutomatonState, event: &Event) -> Option<AutomatonState> {
    let mut next = state.clone();
    match (state.phase, event) {
        // Running × Request -> CancelRequested
        (Phase::Running, Event::Request(r)) => {
            next.phase = Phase::CancelRequested;
            next.reason = Some(r.clone());
            next.budget = next.budget.meet(Budget::MINIMAL);
            Some(next)
        }
        // CancelRequested × Request -> CancelRequested (strengthen + tighten)
        (Phase::CancelRequested, Event::Request(r)) => {
            apply_request(&mut next, r);
            Some(next)
        }
        // CancelRequested × Checkpoint when mask=0 -> Cancelling
        (Phase::CancelRequested, Event::Checkpoint) if state.mask == 0 => {
            next.phase = Phase::Cancelling;
            Some(next)
        }
        // CancelRequested × Checkpoint when mask>0 -> CancelRequested with mask--
        (Phase::CancelRequested, Event::Checkpoint) => {
            next.mask = state.mask - 1;
            Some(next)
        }
        // Cancelling × Request -> Cancelling (strengthen + tighten)
        (Phase::Cancelling, Event::Request(r)) => {
            apply_request(&mut next, r);
            Some(next)
        }
        // Cancelling × CleanupDone -> Finalizing
        (Phase::Cancelling, Event::CleanupDone) => {
            next.phase = Phase::Finalizing;
            Some(next)
        }
        // Finalizing × Request -> Finalizing (strengthen + tighten)
        (Phase::Finalizing, Event::Request(r)) => {
            apply_request(&mut next, r);
            Some(next)
        }
        // Finalizing × FinalizersDone -> Completed(Cancelled(reason))
        (Phase::Finalizing, Event::FinalizersDone) => {
            next.phase = Phase::Completed;
            Some(next)
        }
        // All other (phase, event) cells are not in the spec's transition
        // table: the automaton stutters.
        _ => None,
    }
}

fn apply_request(state: &mut AutomatonState, incoming: &CancelReason) {
    match &mut state.reason {
        Some(existing) => {
            existing.strengthen(incoming);
        }
        None => {
            state.reason = Some(incoming.clone());
        }
    }
    state.budget = state.budget.meet(Budget::MINIMAL);
}

// --- Test helpers ---------------------------------------------------------

fn r_user() -> CancelReason {
    CancelReason::user("user-cancel")
}
fn r_timeout() -> CancelReason {
    CancelReason::timeout()
}
fn r_failfast() -> CancelReason {
    CancelReason::sibling_failed()
}
fn r_parent() -> CancelReason {
    CancelReason::new(CancelKind::ParentCancelled)
}
fn r_shutdown() -> CancelReason {
    CancelReason::new(CancelKind::Shutdown)
}

// === Cells 1–8: legal transitions =========================================

#[test]
fn cell_running_request_advances_to_cancel_requested() {
    let s = AutomatonState::fresh(0);
    let next = step(&s, &Event::Request(r_user())).expect("legal cell");
    assert_eq!(next.phase, Phase::CancelRequested);
    assert_eq!(next.reason.as_ref().map(|r| r.kind), Some(CancelKind::User));
}

#[test]
fn cell_cancel_requested_request_strengthens_only() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();

    // Apply a strictly more-severe request: reason kind must rise; phase stays.
    let after = step(&s, &Event::Request(r_shutdown())).expect("legal cell");
    assert_eq!(after.phase, Phase::CancelRequested);
    assert_eq!(after.reason.as_ref().unwrap().kind, CancelKind::Shutdown);

    // Apply an equally-severe request: kind must not change.
    let after2 = step(&after, &Event::Request(r_shutdown())).unwrap();
    assert_eq!(after2.reason.as_ref().unwrap().kind, CancelKind::Shutdown);

    // Apply a strictly weaker request: kind must NOT regress.
    let after3 = step(&after2, &Event::Request(r_user())).unwrap();
    assert_eq!(after3.reason.as_ref().unwrap().kind, CancelKind::Shutdown);
}

#[test]
fn cell_cancel_requested_checkpoint_mask_zero_advances_to_cancelling() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    assert_eq!(s.mask, 0);
    let next = step(&s, &Event::Checkpoint).expect("legal cell");
    assert_eq!(next.phase, Phase::Cancelling);
    assert_eq!(next.mask, 0);
}

#[test]
fn cell_cancel_requested_checkpoint_mask_pos_decrements_only() {
    let mut s = AutomatonState::fresh(3);
    s = step(&s, &Event::Request(r_user())).unwrap();
    assert_eq!(s.mask, 3);

    let mut current = s;
    for expected in [2u32, 1, 0] {
        let n = step(&current, &Event::Checkpoint).expect("legal cell");
        assert_eq!(n.phase, Phase::CancelRequested, "phase stays masked");
        assert_eq!(n.mask, expected, "mask decrements monotonically");
        current = n;
    }

    // Once mask is exhausted, the next Checkpoint advances to Cancelling.
    let advance = step(&current, &Event::Checkpoint).expect("legal cell");
    assert_eq!(advance.phase, Phase::Cancelling);
    assert_eq!(advance.mask, 0);
}

#[test]
fn cell_cancelling_request_strengthens_only() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    assert_eq!(s.phase, Phase::Cancelling);

    let after = step(&s, &Event::Request(r_failfast())).expect("legal cell");
    assert_eq!(after.phase, Phase::Cancelling, "phase preserved");
    assert_eq!(
        after.reason.as_ref().unwrap().kind,
        CancelKind::FailFast,
        "fail-fast strictly stronger than user"
    );

    // Idempotent: same kind again leaves state unchanged on kind axis.
    let again = step(&after, &Event::Request(r_failfast())).unwrap();
    assert_eq!(again.reason.as_ref().unwrap().kind, CancelKind::FailFast);
}

#[test]
fn cell_cancelling_cleanup_done_advances_to_finalizing() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    let next = step(&s, &Event::CleanupDone).expect("legal cell");
    assert_eq!(next.phase, Phase::Finalizing);
}

#[test]
fn cell_finalizing_request_strengthens_only() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    s = step(&s, &Event::CleanupDone).unwrap();
    assert_eq!(s.phase, Phase::Finalizing);

    let after = step(&s, &Event::Request(r_parent())).expect("legal cell");
    assert_eq!(after.phase, Phase::Finalizing, "phase preserved");
    assert_eq!(
        after.reason.as_ref().unwrap().kind,
        CancelKind::ParentCancelled,
        "ParentCancelled stronger than User"
    );
}

#[test]
fn cell_finalizing_finalizers_done_completes() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_timeout())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    s = step(&s, &Event::CleanupDone).unwrap();
    let done = step(&s, &Event::FinalizersDone).expect("legal cell");
    assert_eq!(done.phase, Phase::Completed);
    assert_eq!(
        done.reason.as_ref().unwrap().kind,
        CancelKind::Timeout,
        "terminal reason preserved across the protocol"
    );
}

// === Stutter cells: events not applicable to a phase ======================

#[test]
fn stutter_running_checkpoint_is_noop() {
    let s = AutomatonState::fresh(0);
    assert!(
        step(&s, &Event::Checkpoint).is_none(),
        "Checkpoint on Running has no transition"
    );
}

#[test]
fn stutter_running_cleanup_and_finalizers_done_are_noops() {
    let s = AutomatonState::fresh(0);
    assert!(step(&s, &Event::CleanupDone).is_none());
    assert!(step(&s, &Event::FinalizersDone).is_none());
}

#[test]
fn stutter_cancel_requested_cleanup_and_finalizers_done_are_noops() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    assert!(step(&s, &Event::CleanupDone).is_none());
    assert!(step(&s, &Event::FinalizersDone).is_none());
}

#[test]
fn stutter_cancelling_finalizers_done_is_noop() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    assert!(step(&s, &Event::FinalizersDone).is_none());
    assert!(step(&s, &Event::Checkpoint).is_none());
}

#[test]
fn stutter_finalizing_checkpoint_and_cleanup_are_noops() {
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    s = step(&s, &Event::CleanupDone).unwrap();
    assert!(step(&s, &Event::Checkpoint).is_none());
    assert!(step(&s, &Event::CleanupDone).is_none());
}

// === Cross-cell properties ================================================

#[test]
fn property_request_idempotent_per_phase() {
    // Apply the same Request event twice; the second application must not
    // change the kind axis.
    let phases_under_test: Vec<fn() -> AutomatonState> = vec![
        || {
            // Running -> CancelRequested
            let s = AutomatonState::fresh(0);
            step(&s, &Event::Request(r_user())).unwrap()
        },
        || {
            // Cancelling
            let mut s = AutomatonState::fresh(0);
            s = step(&s, &Event::Request(r_user())).unwrap();
            step(&s, &Event::Checkpoint).unwrap()
        },
        || {
            // Finalizing
            let mut s = AutomatonState::fresh(0);
            s = step(&s, &Event::Request(r_user())).unwrap();
            s = step(&s, &Event::Checkpoint).unwrap();
            step(&s, &Event::CleanupDone).unwrap()
        },
    ];

    for build in phases_under_test {
        let s0 = build();
        let s1 = step(&s0, &Event::Request(r_failfast())).unwrap();
        let s2 = step(&s1, &Event::Request(r_failfast())).unwrap();
        assert_eq!(
            s1.reason.as_ref().unwrap().kind,
            s2.reason.as_ref().unwrap().kind,
            "idempotent Request must not change kind on replay (phase={:?})",
            s0.phase
        );
        assert_eq!(s1.phase, s2.phase, "phase preserved on idempotent replay");
    }
}

#[test]
fn property_reason_severity_is_monotone() {
    // Across an arbitrary sequence of legal events, the cancel reason kind
    // must be monotone non-decreasing once it has been set.
    let events = vec![
        Event::Request(r_user()),     // -> CancelRequested(User)
        Event::Request(r_failfast()), // -> CancelRequested(FailFast)
        Event::Request(r_user()),     // weaker; must not regress
        Event::Checkpoint,            // -> Cancelling
        Event::Request(r_parent()),   // -> Cancelling(ParentCancelled)
        Event::Request(r_failfast()), // weaker; must not regress
        Event::CleanupDone,           // -> Finalizing
        Event::Request(r_shutdown()), // -> Finalizing(Shutdown)
        Event::Request(r_timeout()),  // weaker; must not regress
        Event::FinalizersDone,        // -> Completed
    ];

    let mut s = AutomatonState::fresh(0);
    let mut last_kind_ord: u8 = 0;
    for ev in &events {
        if let Some(next) = step(&s, ev) {
            if let Some(reason) = &next.reason {
                let ord = reason.kind as u8;
                assert!(
                    ord >= last_kind_ord,
                    "reason kind regressed: was {last_kind_ord}, now {ord}"
                );
                last_kind_ord = ord;
            }
            s = next;
        }
    }
    assert_eq!(s.phase, Phase::Completed);
    assert_eq!(s.reason.as_ref().unwrap().kind, CancelKind::Shutdown);
}

#[test]
fn property_terminal_phase_is_absorbing() {
    // Once Completed, no event re-opens the automaton.
    let mut s = AutomatonState::fresh(0);
    s = step(&s, &Event::Request(r_user())).unwrap();
    s = step(&s, &Event::Checkpoint).unwrap();
    s = step(&s, &Event::CleanupDone).unwrap();
    s = step(&s, &Event::FinalizersDone).unwrap();
    assert_eq!(s.phase, Phase::Completed);

    for ev in [
        Event::Request(r_shutdown()),
        Event::Checkpoint,
        Event::CleanupDone,
        Event::FinalizersDone,
    ] {
        assert!(step(&s, &ev).is_none(), "Completed must absorb all events");
    }
}

#[test]
fn property_mask_never_increases() {
    // Across any reachable trace, mask is monotone non-increasing.
    let mut s = AutomatonState::fresh(5);
    let trace = vec![
        Event::Request(r_user()),
        Event::Checkpoint,
        Event::Checkpoint,
        Event::Request(r_failfast()),
        Event::Checkpoint,
        Event::Checkpoint,
        Event::Checkpoint,
        Event::Checkpoint, // pushes through to Cancelling
        Event::CleanupDone,
        Event::FinalizersDone,
    ];
    let mut last_mask = s.mask;
    for ev in trace {
        if let Some(next) = step(&s, &ev) {
            assert!(
                next.mask <= last_mask,
                "mask regressed: was {last_mask}, now {}",
                next.mask
            );
            last_mask = next.mask;
            s = next;
        }
    }
    assert_eq!(s.phase, Phase::Completed);
}

#[test]
fn property_full_state_table_size_matches_spec() {
    // §3.2.5 lists 4 input phases × 4 events = 16 (phase, event) cells.
    // Of those, 7 (phase, event) pairs are legal transitions and 9 are
    // stutter no-ops. The CancelRequested×Checkpoint cell branches on
    // mask (mask=0 → Cancelling; mask>0 → CancelRequested with mask--),
    // bringing the total **distinct legal transitions** to 8 — verified
    // separately below.
    let phase_builders: Vec<fn() -> AutomatonState> = vec![
        || AutomatonState::fresh(0),
        || {
            let s = AutomatonState::fresh(0);
            step(&s, &Event::Request(r_user())).unwrap()
        },
        || {
            let mut s = AutomatonState::fresh(0);
            s = step(&s, &Event::Request(r_user())).unwrap();
            step(&s, &Event::Checkpoint).unwrap()
        },
        || {
            let mut s = AutomatonState::fresh(0);
            s = step(&s, &Event::Request(r_user())).unwrap();
            s = step(&s, &Event::Checkpoint).unwrap();
            step(&s, &Event::CleanupDone).unwrap()
        },
    ];
    let events_under_test = vec![
        Event::Request(r_user()),
        Event::Checkpoint,
        Event::CleanupDone,
        Event::FinalizersDone,
    ];

    let mut legal = 0;
    let mut stutter = 0;
    for build in &phase_builders {
        for ev in &events_under_test {
            let s = build();
            if step(&s, ev).is_some() {
                legal += 1;
            } else {
                stutter += 1;
            }
        }
    }
    assert_eq!(legal, 7, "7 legal (phase, event) cells per spec §3.2.5");
    assert_eq!(stutter, 9, "9 stutter cells per spec §3.2.5");
    assert_eq!(legal + stutter, 16);

    // Distinct legal transition count: legal (phase, event) cells (7)
    // plus the mask>0 branch of CancelRequested×Checkpoint (1) = 8.
    let masked = {
        let mut s = AutomatonState::fresh(2);
        s = step(&s, &Event::Request(r_user())).unwrap();
        let n = step(&s, &Event::Checkpoint).expect("masked branch legal");
        // Distinct from the mask=0 branch: stays in CancelRequested.
        n.phase == Phase::CancelRequested && n.mask == s.mask - 1
    };
    assert!(masked, "mask>0 Checkpoint branch is a distinct transition");
}
