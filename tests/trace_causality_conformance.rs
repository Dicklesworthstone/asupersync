//! Conformance harness for `asupersync::trace::causality`.
//!
//! `CausalOrderVerifier::verify` checks that a recorded trace respects the
//! happens-before partial order, using logical timestamps attached to events.
//! It enforces three documented rules:
//!
//! 1. **Monotonic sequence** — consecutive annotated events must not have
//!    decreasing logical time (`NonMonotonic` otherwise).
//! 2. **Same-task ordering** — successive events on one task must be strictly
//!    `Before` each other (`SameTaskConcurrent` otherwise).
//! 3. **Causal dependency** — a `Wake`/`Schedule` for a task must have a
//!    logical time strictly after that task's `Spawn` (`MissingDependency`
//!    otherwise).
//!
//! Events without a logical timestamp are skipped entirely.
//!
//! This harness pins the contract from both sides: well-formed traces verify
//! clean, and each violation class is provoked with a targeted fixture whose
//! reported metadata (indices, sequence numbers) is checked exactly. It also
//! pins two metamorphic relations:
//!
//! - **Unannotated-skip**: inserting events with no logical time never
//!   changes the verdict — they are invisible to the verifier.
//! - **Task-id renaming**: applying a consistent bijection to task ids leaves
//!   the Ok/Err verdict unchanged (the verifier groups by task, not by the
//!   numeric id value).

#![allow(clippy::needless_range_loop)]

use asupersync::remote::NodeId;
use asupersync::trace::distributed::{LamportClock, LogicalTime, VectorClock};
use asupersync::trace::{
    CausalOrderVerifier, CausalityViolation, CausalityViolationKind, TraceEvent,
};
use asupersync::types::{RegionId, TaskId, Time};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}
fn region() -> RegionId {
    RegionId::new_for_test(0, 0)
}

/// A Lamport `LogicalTime` with exact value `v` (`v >= 1`).
fn lamport(v: u64) -> LogicalTime {
    assert!(v >= 1, "lamport value must be >= 1");
    LogicalTime::Lamport(LamportClock::with_start(v - 1).tick())
}

fn spawn(seq: u64, t: u32, lt: LogicalTime) -> TraceEvent {
    TraceEvent::spawn(seq, Time::ZERO, task(t), region()).with_logical_time(lt)
}
fn schedule(seq: u64, t: u32, lt: LogicalTime) -> TraceEvent {
    TraceEvent::schedule(seq, Time::ZERO, task(t), region()).with_logical_time(lt)
}
fn wake(seq: u64, t: u32, lt: LogicalTime) -> TraceEvent {
    TraceEvent::wake(seq, Time::ZERO, task(t), region()).with_logical_time(lt)
}
fn complete(seq: u64, t: u32, lt: LogicalTime) -> TraceEvent {
    TraceEvent::complete(seq, Time::ZERO, task(t), region()).with_logical_time(lt)
}

fn ok(trace: &[TraceEvent]) -> bool {
    CausalOrderVerifier::verify(trace).is_ok()
}
fn violations(trace: &[TraceEvent]) -> Vec<CausalityViolation> {
    CausalOrderVerifier::verify(trace).unwrap_err()
}
fn has_kind(vs: &[CausalityViolation], kind: CausalityViolationKind) -> bool {
    vs.iter().any(|v| v.kind == kind)
}

// ---------------------------------------------------------------------------
// Well-formed traces verify clean
// ---------------------------------------------------------------------------

#[test]
fn empty_and_single_event_traces_pass() {
    assert!(ok(&[]));
    assert!(ok(&[spawn(0, 1, lamport(1))]));
    assert!(ok(&[TraceEvent::spawn(0, Time::ZERO, task(1), region())]));
}

#[test]
fn a_globally_monotone_well_formed_trace_passes() {
    // For each task: spawn, then schedule, then wake, then complete — all
    // drawn from one ever-increasing global Lamport sequence. This satisfies
    // every rule simultaneously, for any task count.
    for task_count in 1u32..=6 {
        let clock = LamportClock::new();
        let mut trace = Vec::new();
        let mut seq = 0u64;
        // spawns first so every task's Spawn precedes its Wake/Schedule
        for t in 1..=task_count {
            trace.push(spawn(seq, t, LogicalTime::Lamport(clock.tick())));
            seq += 1;
        }
        for t in 1..=task_count {
            trace.push(schedule(seq, t, LogicalTime::Lamport(clock.tick())));
            seq += 1;
        }
        for t in 1..=task_count {
            trace.push(wake(seq, t, LogicalTime::Lamport(clock.tick())));
            seq += 1;
        }
        for t in 1..=task_count {
            trace.push(complete(seq, t, LogicalTime::Lamport(clock.tick())));
            seq += 1;
        }
        assert!(
            ok(&trace),
            "well-formed trace with {task_count} tasks should verify clean: {:?}",
            CausalOrderVerifier::verify(&trace)
        );
    }
}

#[test]
fn verify_is_deterministic() {
    let clock = LamportClock::new();
    let trace = vec![
        spawn(0, 1, LogicalTime::Lamport(clock.tick())),
        spawn(1, 2, LogicalTime::Lamport(clock.tick())),
        schedule(2, 1, LogicalTime::Lamport(clock.tick())),
        wake(3, 2, LogicalTime::Lamport(clock.tick())),
    ];
    let a = CausalOrderVerifier::verify(&trace).is_ok();
    let b = CausalOrderVerifier::verify(&trace).is_ok();
    let c = CausalOrderVerifier::verify(&trace).is_ok();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

// ---------------------------------------------------------------------------
// Violation detection — one targeted fixture per violation class
// ---------------------------------------------------------------------------

#[test]
fn non_monotonic_logical_time_is_detected() {
    // Two events on *different* tasks (so no same-task or dependency rule
    // applies) where the second carries an earlier logical time. Only the
    // monotonic rule can fire — giving a clean, single-violation fixture.
    let trace = vec![spawn(10, 1, lamport(5)), spawn(11, 2, lamport(3))];
    let vs = violations(&trace);
    assert!(
        has_kind(&vs, CausalityViolationKind::NonMonotonic),
        "expected NonMonotonic, got {vs:?}"
    );
    // Isolated fixture: exactly one violation, metadata points at both events.
    assert_eq!(vs.len(), 1, "fixture should produce exactly one violation");
    let v = &vs[0];
    assert_eq!(v.kind, CausalityViolationKind::NonMonotonic);
    assert_eq!(v.earlier_idx, 0);
    assert_eq!(v.later_idx, 1);
    assert_eq!(v.earlier_seq, 10);
    assert_eq!(v.later_seq, 11);
}

#[test]
fn same_task_concurrent_logical_time_is_detected() {
    // Two events on the *same* task with equal logical time. Neither is a
    // Wake/Schedule, so the dependency rule stays quiet and the monotonic
    // rule does not fire on an equal (non-decreasing) pair — isolating the
    // same-task rule.
    let trace = vec![complete(20, 1, lamport(4)), complete(21, 1, lamport(4))];
    let vs = violations(&trace);
    assert!(
        has_kind(&vs, CausalityViolationKind::SameTaskConcurrent),
        "expected SameTaskConcurrent, got {vs:?}"
    );
    let v = vs
        .iter()
        .find(|v| v.kind == CausalityViolationKind::SameTaskConcurrent)
        .unwrap();
    assert_eq!(v.earlier_idx, 0);
    assert_eq!(v.later_idx, 1);
    assert_eq!(v.earlier_seq, 20);
    assert_eq!(v.later_seq, 21);
}

#[test]
fn wake_before_spawn_is_a_missing_dependency() {
    // Spawn carries a later logical time than the Wake that should depend on
    // it — the causal dependency is not reflected.
    let trace = vec![spawn(30, 1, lamport(9)), wake(31, 1, lamport(3))];
    let vs = violations(&trace);
    assert!(
        has_kind(&vs, CausalityViolationKind::MissingDependency),
        "expected MissingDependency, got {vs:?}"
    );
    let v = vs
        .iter()
        .find(|v| v.kind == CausalityViolationKind::MissingDependency)
        .unwrap();
    assert_eq!(v.earlier_idx, 0, "earlier should be the spawn");
    assert_eq!(v.later_idx, 1, "later should be the wake");
    assert_eq!(v.earlier_seq, 30);
    assert_eq!(v.later_seq, 31);
}

#[test]
fn schedule_before_spawn_is_a_missing_dependency() {
    // The dependency rule covers Schedule as well as Wake.
    let trace = vec![spawn(40, 1, lamport(9)), schedule(41, 1, lamport(3))];
    let vs = violations(&trace);
    assert!(
        has_kind(&vs, CausalityViolationKind::MissingDependency),
        "expected MissingDependency for Schedule, got {vs:?}"
    );
}

#[test]
fn spawn_before_wake_with_increasing_time_passes() {
    // Positive control for the dependency rule: a correctly ordered pair.
    let trace = vec![spawn(50, 1, lamport(2)), wake(51, 1, lamport(7))];
    assert!(ok(&trace), "{:?}", CausalOrderVerifier::verify(&trace));
}

// ---------------------------------------------------------------------------
// Metamorphic relation: unannotated events are invisible to the verifier.
// ---------------------------------------------------------------------------

#[test]
fn unannotated_events_are_skipped_entirely() {
    // A trace made only of events without logical time always verifies clean,
    // no matter how "wrong" the ordering would look if it were timed.
    let trace = vec![
        TraceEvent::wake(0, Time::ZERO, task(1), region()),
        TraceEvent::spawn(1, Time::ZERO, task(1), region()),
        TraceEvent::complete(2, Time::ZERO, task(1), region()),
        TraceEvent::schedule(3, Time::ZERO, task(1), region()),
    ];
    assert!(
        ok(&trace),
        "unannotated events must never produce violations"
    );
}

#[test]
fn inserting_unannotated_events_preserves_the_verdict() {
    // Metamorphic: splicing logical-time-free events into a trace must not
    // change Ok/Err — they are skipped by every check.
    let good = vec![
        spawn(0, 1, lamport(1)),
        wake(1, 1, lamport(2)),
        complete(2, 1, lamport(3)),
    ];
    let bad = vec![spawn(0, 1, lamport(9)), wake(1, 1, lamport(2))];

    let filler = || {
        vec![
            TraceEvent::poll(100, Time::ZERO, task(7), region()),
            TraceEvent::user_trace(101, Time::ZERO, "note"),
        ]
    };

    for (base, base_ok) in [(good, true), (bad, false)] {
        // Interleave: filler, then each base event followed by more filler.
        let mut spliced = filler();
        for ev in &base {
            spliced.push(ev.clone());
            spliced.extend(filler());
        }
        assert_eq!(
            ok(&spliced),
            base_ok,
            "unannotated splicing changed the verdict (expected ok={base_ok})"
        );
    }
}

// ---------------------------------------------------------------------------
// Metamorphic relation: consistent task-id renaming preserves the verdict.
// ---------------------------------------------------------------------------

/// Rebuild a trace with every task id `t` mapped through a bijection.
/// The verifier groups events by task, so a consistent relabel must not
/// change which events are compared, hence not the Ok/Err verdict.
fn build_trace(task_ids: &[(u64, &str, u32, u64)]) -> Vec<TraceEvent> {
    // tuple = (seq, kind, task_id, lamport_value)
    task_ids
        .iter()
        .map(|&(seq, kind, t, lv)| {
            let lt = lamport(lv);
            match kind {
                "spawn" => spawn(seq, t, lt),
                "schedule" => schedule(seq, t, lt),
                "wake" => wake(seq, t, lt),
                "complete" => complete(seq, t, lt),
                other => panic!("unknown kind {other}"),
            }
        })
        .collect()
}

#[test]
fn task_id_renaming_preserves_verdict() {
    // A passing spec and a failing spec, each rebuilt under a task-id
    // bijection {1->101, 2->202, 3->303}.
    let passing = &[
        (0u64, "spawn", 1u32, 1u64),
        (1, "spawn", 2, 2),
        (2, "schedule", 1, 3),
        (3, "wake", 2, 4),
    ];
    let failing = &[
        (0u64, "spawn", 1u32, 9u64),
        (1, "wake", 1, 2), // wake before spawn (logically)
    ];
    let rename = |t: u32| t * 101;

    for spec in [passing.as_slice(), failing.as_slice()] {
        let original: Vec<_> = spec.to_vec();
        let renamed: Vec<_> = spec
            .iter()
            .map(|&(seq, kind, t, lv)| (seq, kind, rename(t), lv))
            .collect();
        let verdict_original = ok(&build_trace(&original));
        let verdict_renamed = ok(&build_trace(&renamed));
        assert_eq!(
            verdict_original, verdict_renamed,
            "task-id renaming changed the verdict for spec {spec:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Vector-clock semantics
// ---------------------------------------------------------------------------

#[test]
fn concurrent_vector_clocks_on_distinct_tasks_pass() {
    // Two tasks, each advancing its own node's vector clock once. The clocks
    // are concurrent (incomparable); since the events are on different tasks
    // that is allowed.
    let mut vc_a = VectorClock::new();
    let mut vc_b = VectorClock::new();
    vc_a.increment(&NodeId::new("node-a"));
    vc_b.increment(&NodeId::new("node-b"));

    let trace = vec![
        TraceEvent::spawn(0, Time::ZERO, task(1), region())
            .with_logical_time(LogicalTime::Vector(vc_a)),
        TraceEvent::spawn(1, Time::ZERO, task(2), region())
            .with_logical_time(LogicalTime::Vector(vc_b)),
    ];
    assert!(ok(&trace), "{:?}", CausalOrderVerifier::verify(&trace));
}

#[test]
fn vector_clock_happens_before_on_same_task_passes() {
    let node = NodeId::new("node-a");
    let mut vc = VectorClock::new();
    vc.increment(&node);
    let t1 = LogicalTime::Vector(vc.clone());
    vc.increment(&node);
    let t2 = LogicalTime::Vector(vc);

    let trace = vec![
        TraceEvent::spawn(0, Time::ZERO, task(1), region()).with_logical_time(t1),
        TraceEvent::schedule(1, Time::ZERO, task(1), region()).with_logical_time(t2),
    ];
    assert!(ok(&trace), "{:?}", CausalOrderVerifier::verify(&trace));
}

// ---------------------------------------------------------------------------
// Violation value-type contract
// ---------------------------------------------------------------------------

#[test]
fn violation_display_names_the_kind_and_both_events() {
    let trace = vec![spawn(77, 1, lamport(8)), spawn(88, 2, lamport(2))];
    let vs = violations(&trace);
    let rendered = format!("{}", vs[0]);
    assert!(rendered.contains("NonMonotonic"), "{rendered}");
    assert!(rendered.contains("77"), "earlier seq missing: {rendered}");
    assert!(rendered.contains("88"), "later seq missing: {rendered}");
}

#[test]
fn violation_kind_has_value_semantics() {
    let a = CausalityViolationKind::NonMonotonic;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(
        CausalityViolationKind::NonMonotonic,
        CausalityViolationKind::SameTaskConcurrent
    );
    assert_ne!(
        CausalityViolationKind::SameTaskConcurrent,
        CausalityViolationKind::MissingDependency
    );
    // Debug is non-empty for every variant.
    for k in [
        CausalityViolationKind::NonMonotonic,
        CausalityViolationKind::SameTaskConcurrent,
        CausalityViolationKind::MissingDependency,
    ] {
        assert!(!format!("{k:?}").is_empty());
    }
}

#[test]
fn verify_reports_every_violation_not_just_the_first() {
    // Two independent same-task-concurrent pairs on two different tasks must
    // both be reported — `verify` accumulates rather than short-circuiting.
    let trace = vec![
        complete(0, 1, lamport(4)),
        complete(1, 1, lamport(4)), // task 1: equal times
        complete(2, 2, lamport(4)),
        complete(3, 2, lamport(4)), // task 2: equal times
    ];
    let vs = violations(&trace);
    let same_task = vs
        .iter()
        .filter(|v| v.kind == CausalityViolationKind::SameTaskConcurrent)
        .count();
    assert!(
        same_task >= 2,
        "expected both same-task pairs reported, got {same_task}: {vs:?}"
    );
}
