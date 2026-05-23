//! Metamorphic + conformance harness for `asupersync::trace::independence`.
//!
//! The DPOR (dynamic partial-order reduction) explorer reorders independent
//! trace events to prune the schedule space. Soundness of that pruning rests
//! entirely on the `independent` relation obeying its documented contract:
//!
//! - **Symmetric**: `independent(a, b) == independent(b, a)`.
//! - **Irreflexive**: `!independent(e, e)` — an event never commutes with
//!   itself (same `seq`).
//! - **Conflict-driven**: two distinct events are independent iff their
//!   resource footprints share no conflicting access (read/write or
//!   write/write on the same resource).
//!
//! The relation is deliberately **not** transitive — that is the whole point
//! of a Mazurkiewicz dependency relation — and this harness includes an
//! explicit non-transitivity witness so a future "simplification" that makes
//! it an equivalence relation is caught.
//!
//! `independent` has the oracle problem for an arbitrary event pair (there is
//! no independent reference answer), but it satisfies a dense web of
//! metamorphic relations that this harness pins:
//!
//! - **Spec conformance**: `independent` agrees with the footprint/conflict
//!   definition re-derived from `resource_footprint` + `accesses_conflict`.
//! - **Footprint determinism**: `resource_footprint` is a pure function.
//! - **Self-dependence under `seq` bump**: an event is dependent on a
//!   distinct-`seq` copy of itself iff its footprint contains a write.
//! - **Footprint equivalence**: events with identical footprints are
//!   interchangeable for every independence query.
//! - **Disjoint resources ⇒ independent**.
//! - `accesses_conflict` is symmetric and obeys the read/write truth table.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;

use asupersync::trace::{
    AccessMode, Resource, ResourceAccess, TraceData, TraceEvent, TraceEventKind, accesses_conflict,
    independent, resource_footprint,
};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};

// Note: `ObligationKind` lives in `record`, not `trace`.
use asupersync::record::ObligationKind;

// ---------------------------------------------------------------------------
// Compact id helpers
// ---------------------------------------------------------------------------

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}
fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}
fn oid(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

fn chaos(seq: u64, kind: &str, task: Option<TaskId>) -> TraceEvent {
    TraceEvent::new(
        seq,
        Time::ZERO,
        TraceEventKind::ChaosInjection,
        TraceData::Chaos {
            kind: kind.to_string(),
            task,
            detail: "metamorphic-fixture".to_string(),
        },
    )
}

/// A diverse corpus of trace events, every one with a distinct `seq`.
///
/// Spans every footprint shape in `resource_footprint`: task lifecycle
/// (write Task / read Region), cancel (write Task / write Region), region
/// create/cancel, obligations (write Obligation / read Task / read Region),
/// time advance, timers, I/O, RNG, checkpoints, chaos, and the empty-footprint
/// `UserTrace`.
fn corpus() -> Vec<TraceEvent> {
    let t = Time::ZERO;
    vec![
        // task lifecycle on (t1, r1)
        TraceEvent::spawn(1, t, tid(1), rid(1)),
        TraceEvent::schedule(2, t, tid(1), rid(1)),
        TraceEvent::complete(3, t, tid(1), rid(1)),
        // task lifecycle on (t2, r1) — same region, different task
        TraceEvent::schedule(4, t, tid(2), rid(1)),
        TraceEvent::poll(5, t, tid(2), rid(1)),
        // task lifecycle on (t3, r2)
        TraceEvent::spawn(6, t, tid(3), rid(2)),
        TraceEvent::wake(7, t, tid(3), rid(2)),
        TraceEvent::yield_task(8, t, tid(3), rid(2)),
        // cancel requests (write both task and region)
        TraceEvent::cancel_request(9, t, tid(1), rid(1), CancelReason::user("x")),
        TraceEvent::cancel_request(10, t, tid(4), rid(3), CancelReason::user("y")),
        // region lifecycle
        TraceEvent::region_created(11, t, rid(1), None),
        TraceEvent::region_created(12, t, rid(5), Some(rid(1))),
        TraceEvent::region_cancelled(13, t, rid(1), CancelReason::user("z")),
        TraceEvent::region_cancelled(14, t, rid(2), CancelReason::user("w")),
        // obligations
        TraceEvent::obligation_reserve(15, t, oid(1), tid(1), rid(1), ObligationKind::SendPermit),
        TraceEvent::obligation_commit(16, t, oid(1), tid(1), rid(1), ObligationKind::SendPermit, 5),
        TraceEvent::obligation_reserve(17, t, oid(2), tid(5), rid(4), ObligationKind::Ack),
        // time / timers
        TraceEvent::time_advance(18, t, Time::ZERO, Time::from_nanos(1000)),
        TraceEvent::timer_scheduled(19, t, 42, Time::from_nanos(2000)),
        TraceEvent::timer_fired(20, t, 42),
        TraceEvent::timer_fired(21, t, 99),
        // I/O
        TraceEvent::io_requested(22, t, 100, 0x01),
        TraceEvent::io_ready(23, t, 100, 0x01),
        TraceEvent::io_ready(24, t, 200, 0x02),
        TraceEvent::io_result(25, t, 100, 512),
        // RNG
        TraceEvent::rng_seed(26, t, 0xDEAD),
        TraceEvent::rng_value(27, t, 7),
        // checkpoints (read GlobalState)
        TraceEvent::checkpoint(28, t, 1, 3, 2),
        TraceEvent::checkpoint(29, t, 2, 4, 3),
        // chaos (write GlobalState, optional write Task)
        chaos(30, "delay", None),
        chaos(31, "kill", Some(tid(1))),
        // empty footprint
        TraceEvent::user_trace(32, t, "annotation-a"),
        TraceEvent::user_trace(33, t, "annotation-b"),
    ]
}

// ---------------------------------------------------------------------------
// The independence-relation contract: symmetry + irreflexivity
// ---------------------------------------------------------------------------

#[test]
fn independent_is_symmetric_over_all_pairs() {
    let events = corpus();
    for a in &events {
        for b in &events {
            assert_eq!(
                independent(a, b),
                independent(b, a),
                "independence not symmetric for seq {} ({:?}) vs seq {} ({:?})",
                a.seq,
                a.kind,
                b.seq,
                b.kind
            );
        }
    }
}

#[test]
fn independent_is_irreflexive() {
    // An event never commutes with itself: same `seq` short-circuits to false.
    for e in corpus() {
        assert!(
            !independent(&e, &e),
            "event seq {} ({:?}) reported independent of itself",
            e.seq,
            e.kind
        );
    }
}

#[test]
fn equal_seq_distinct_content_is_still_dependent() {
    // Irreflexivity keys on `seq`, not structural equality: two *different*
    // events that happen to share a `seq` are treated as the same instance.
    let a = TraceEvent::spawn(7, Time::ZERO, tid(1), rid(1));
    let b = TraceEvent::io_ready(7, Time::ZERO, 500, 0x04);
    assert!(!independent(&a, &b), "shared seq must force dependence");
    assert!(!independent(&b, &a));
}

// ---------------------------------------------------------------------------
// Spec conformance: independent ⇔ footprint/conflict definition
// ---------------------------------------------------------------------------

/// The independence relation re-derived directly from the documented spec:
/// distinct `seq`, and either footprint empty or no pair of accesses conflicts.
fn spec_independent(a: &TraceEvent, b: &TraceEvent) -> bool {
    if a.seq == b.seq {
        return false;
    }
    let fa = resource_footprint(a);
    let fb = resource_footprint(b);
    if fa.is_empty() || fb.is_empty() {
        return true;
    }
    for ra in &fa {
        for rb in &fb {
            if accesses_conflict(ra, rb) {
                return false;
            }
        }
    }
    true
}

#[test]
fn independent_conforms_to_footprint_conflict_spec() {
    let events = corpus();
    for a in &events {
        for b in &events {
            assert_eq!(
                independent(a, b),
                spec_independent(a, b),
                "independent() diverged from footprint/conflict spec: \
                 seq {} ({:?}) vs seq {} ({:?})",
                a.seq,
                a.kind,
                b.seq,
                b.kind
            );
        }
    }
}

// ---------------------------------------------------------------------------
// resource_footprint — purity / determinism
// ---------------------------------------------------------------------------

#[test]
fn resource_footprint_is_deterministic() {
    // Constructing the same logical event twice yields the same footprint.
    for e in corpus() {
        let f1 = resource_footprint(&e);
        let f2 = resource_footprint(&e);
        assert_eq!(
            f1, f2,
            "resource_footprint non-deterministic for seq {} ({:?})",
            e.seq, e.kind
        );
    }
}

#[test]
fn footprint_is_independent_of_seq_and_time() {
    // The footprint depends only on (kind, data), never on seq or wall time.
    let a = TraceEvent::spawn(1, Time::ZERO, tid(9), rid(9));
    let b = TraceEvent::spawn(2, Time::from_nanos(123_456), tid(9), rid(9));
    assert_eq!(
        resource_footprint(&a),
        resource_footprint(&b),
        "footprint must not depend on seq or time"
    );
}

// ---------------------------------------------------------------------------
// accesses_conflict — symmetry + truth table
// ---------------------------------------------------------------------------

fn all_accesses() -> Vec<ResourceAccess> {
    let resources = [
        Resource::Task(tid(1)),
        Resource::Task(tid(2)),
        Resource::Region(rid(1)),
        Resource::Obligation(oid(1)),
        Resource::Timer(7),
        Resource::IoToken(9),
        Resource::GlobalClock,
        Resource::GlobalRng,
        Resource::GlobalState,
    ];
    let mut out = Vec::new();
    for r in resources {
        out.push(ResourceAccess::read(r.clone()));
        out.push(ResourceAccess::write(r));
    }
    out
}

#[test]
fn accesses_conflict_is_symmetric() {
    let accesses = all_accesses();
    for a in &accesses {
        for b in &accesses {
            assert_eq!(
                accesses_conflict(a, b),
                accesses_conflict(b, a),
                "accesses_conflict not symmetric: {a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn accesses_conflict_obeys_the_read_write_truth_table() {
    let accesses = all_accesses();
    for a in &accesses {
        for b in &accesses {
            let expect = if a.resource == b.resource {
                // Same resource: conflict unless both are reads.
                !(a.mode == AccessMode::Read && b.mode == AccessMode::Read)
            } else {
                // Distinct resources never conflict.
                false
            };
            assert_eq!(
                accesses_conflict(a, b),
                expect,
                "conflict truth table mismatch: {a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn two_reads_on_the_same_resource_never_conflict() {
    for r in [
        Resource::Task(tid(1)),
        Resource::Region(rid(1)),
        Resource::GlobalState,
    ] {
        let a = ResourceAccess::read(r.clone());
        let b = ResourceAccess::read(r);
        assert!(!accesses_conflict(&a, &b));
    }
}

#[test]
fn a_write_conflicts_with_a_distinct_copy_of_itself() {
    // Reflexive-ish: a write access conflicts with an equal write access
    // (this is what makes a write-bearing event self-dependent under a
    // `seq` bump).
    for r in [
        Resource::Task(tid(1)),
        Resource::GlobalClock,
        Resource::IoToken(3),
    ] {
        let w = ResourceAccess::write(r);
        assert!(accesses_conflict(&w, &w.clone()));
    }
}

// ---------------------------------------------------------------------------
// Empty footprint ⇒ independent of everything (with a distinct seq)
// ---------------------------------------------------------------------------

#[test]
fn empty_footprint_events_are_independent_of_all_distinct_events() {
    let probe = corpus();
    // user_trace has an empty footprint; give it a seq disjoint from corpus.
    let annotation = TraceEvent::user_trace(9999, Time::ZERO, "free-floating");
    assert!(resource_footprint(&annotation).is_empty());

    for e in &probe {
        assert!(
            independent(&annotation, e),
            "empty-footprint event should be independent of seq {} ({:?})",
            e.seq,
            e.kind
        );
        assert!(independent(e, &annotation), "and symmetrically");
    }
}

// ---------------------------------------------------------------------------
// Metamorphic relation: self-dependence under a `seq` bump iff footprint
// contains a write.
// ---------------------------------------------------------------------------

/// Rebuild a corpus event with a fresh `seq` so it is a distinct instance with
/// an identical footprint. (The corpus is regenerated; we just pick index `i`
/// from a corpus built with a shifted seq base.)
fn corpus_with_seq_offset(offset: u64) -> Vec<TraceEvent> {
    corpus()
        .into_iter()
        .map(|e| {
            // Reconstruct via `new` to bump seq while preserving kind+data.
            TraceEvent::new(e.seq + offset, e.time, e.kind, e.data)
        })
        .collect()
}

#[test]
fn event_is_self_dependent_under_seq_bump_iff_footprint_has_a_write() {
    let base = corpus();
    let bumped = corpus_with_seq_offset(10_000);
    assert_eq!(base.len(), bumped.len());

    for (e, e2) in base.iter().zip(bumped.iter()) {
        // e2 is e with a different seq — same footprint, distinct instance.
        assert_ne!(e.seq, e2.seq);
        let footprint = resource_footprint(e);
        let has_write = footprint.iter().any(|a| a.mode == AccessMode::Write);

        let indep = independent(e, e2);
        assert_eq!(
            indep, !has_write,
            "self-vs-bumped independence mismatch for {:?}: footprint={:?}, \
             has_write={has_write}, independent={indep}",
            e.kind, footprint
        );
    }
}

// ---------------------------------------------------------------------------
// Metamorphic relation: footprint-equivalent events are interchangeable.
// ---------------------------------------------------------------------------

#[test]
fn task_lifecycle_events_share_one_footprint_shape() {
    // Spawn/Schedule/Yield/Wake/Poll/Complete on the same (task, region) all
    // produce the footprint [write Task, read Region].
    let lifecycle = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::schedule(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::yield_task(3, Time::ZERO, tid(1), rid(1)),
        TraceEvent::wake(4, Time::ZERO, tid(1), rid(1)),
        TraceEvent::poll(5, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(6, Time::ZERO, tid(1), rid(1)),
    ];
    let reference = resource_footprint(&lifecycle[0]);
    for e in &lifecycle {
        assert_eq!(
            resource_footprint(e),
            reference,
            "{:?} should share the task-lifecycle footprint",
            e.kind
        );
    }
}

#[test]
fn footprint_equivalent_events_are_interchangeable_for_independence() {
    // Build two events with identical footprints but different kinds:
    // spawn and schedule on (t1, r1). For every probe with a distinct seq,
    // the independence verdict must be the same against both.
    let spawn_ev = TraceEvent::spawn(5001, Time::ZERO, tid(1), rid(1));
    let sched_ev = TraceEvent::schedule(5002, Time::ZERO, tid(1), rid(1));
    assert_eq!(
        resource_footprint(&spawn_ev),
        resource_footprint(&sched_ev),
        "precondition: the two events must share a footprint"
    );

    for probe in corpus() {
        // Skip probes whose seq collides with either event (none should).
        assert_ne!(probe.seq, spawn_ev.seq);
        assert_ne!(probe.seq, sched_ev.seq);
        assert_eq!(
            independent(&spawn_ev, &probe),
            independent(&sched_ev, &probe),
            "footprint-equivalent events disagreed against probe seq {} ({:?})",
            probe.seq,
            probe.kind
        );
    }
}

// ---------------------------------------------------------------------------
// Metamorphic relation: disjoint resource sets ⇒ independent.
// ---------------------------------------------------------------------------

fn resource_set(e: &TraceEvent) -> BTreeSet<String> {
    resource_footprint(e)
        .iter()
        .map(|a| format!("{:?}", a.resource))
        .collect()
}

#[test]
fn events_touching_disjoint_resources_are_independent() {
    let events = corpus();
    let mut disjoint_pairs_checked = 0usize;
    for a in &events {
        for b in &events {
            if a.seq >= b.seq {
                continue;
            }
            let ra = resource_set(a);
            let rb = resource_set(b);
            if ra.is_empty() || rb.is_empty() {
                continue;
            }
            if ra.is_disjoint(&rb) {
                disjoint_pairs_checked += 1;
                assert!(
                    independent(a, b),
                    "disjoint-resource events must be independent: \
                     seq {} ({:?}, {ra:?}) vs seq {} ({:?}, {rb:?})",
                    a.seq,
                    a.kind,
                    b.seq,
                    b.kind
                );
            }
        }
    }
    assert!(
        disjoint_pairs_checked > 20,
        "expected the corpus to contain many disjoint-resource pairs, got {disjoint_pairs_checked}"
    );
}

#[test]
fn shared_writable_resource_forces_dependence() {
    // The converse direction on a concrete witness: two events that both write
    // Task(1) (a task-lifecycle event and a chaos-kill targeting that task)
    // must be dependent.
    let lifecycle = TraceEvent::complete(40, Time::ZERO, tid(1), rid(1));
    let kill = chaos(41, "kill", Some(tid(1)));
    // Both footprints contain a write to Task(1).
    let has_task_write = |e: &TraceEvent| {
        resource_footprint(e)
            .iter()
            .any(|a| a.resource == Resource::Task(tid(1)) && a.mode == AccessMode::Write)
    };
    assert!(has_task_write(&lifecycle) && has_task_write(&kill));
    assert!(
        !independent(&lifecycle, &kill),
        "shared Task write ⇒ dependent"
    );
}

// ---------------------------------------------------------------------------
// The relation is NOT transitive — explicit witness.
// ---------------------------------------------------------------------------

#[test]
fn independence_is_not_transitive() {
    // a and c both write Task(1) → dependent.
    // b is a free-floating annotation → independent of both.
    // So a⊥b and b⊥c hold, but a⊥c does NOT — the relation is genuinely a
    // (non-transitive) dependency relation, not an equivalence.
    let a = TraceEvent::spawn(60, Time::ZERO, tid(1), rid(1));
    let b = TraceEvent::user_trace(61, Time::ZERO, "bridge");
    let c = TraceEvent::complete(62, Time::ZERO, tid(1), rid(1));

    assert!(independent(&a, &b), "a ⊥ b expected");
    assert!(independent(&b, &c), "b ⊥ c expected");
    assert!(
        !independent(&a, &c),
        "a ⊥ c must NOT hold — independence is not transitive"
    );
}

// ---------------------------------------------------------------------------
// ResourceAccess constructor sanity (guards the harness's own assumptions).
// ---------------------------------------------------------------------------

#[test]
fn resource_access_constructors_set_the_mode() {
    let r = Resource::Region(rid(3));
    assert_eq!(ResourceAccess::read(r.clone()).mode, AccessMode::Read);
    assert_eq!(ResourceAccess::write(r).mode, AccessMode::Write);
}
