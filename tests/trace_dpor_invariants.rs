//! Focused invariant test for `asupersync::trace::dpor`.
//!
//! `trace::dpor` is the dynamic partial-order reduction race detector. It has
//! two detectors — the O(n³) immediate-race `detect_races` and the
//! vector-clock `detect_hb_races` — plus `estimated_classes`, `racing_events`,
//! a `SleepSet`, and `trace_coverage_analysis`. This file pins the structural
//! invariants every one of those must satisfy on any trace:
//!
//! - Every reported race runs forward (`earlier < later`) with in-range
//!   indices, and `racing_events` is exactly the sorted, deduplicated set of
//!   race endpoints.
//! - The HB detector never reports a same-task pair (those are ordered, not
//!   raced) and always records distinct `earlier_task` / `later_task`.
//! - `estimated_classes` is at least 1 and exactly 1 for an empty or
//!   race-free trace (fail-closed lower bound).
//! - Both detectors and the coverage analysis are deterministic.
//! - `SleepSet` membership is monotone and insertion is idempotent.
//! - `trace_coverage_analysis` keeps its tallies mutually consistent and
//!   `race_density` within `[0, 1]`.
//!
//! Focused single-module test; small fixed/derived trace corpus, no
//! `proptest` dependency.

use asupersync::trace::{
    BacktrackPoint, Race, SleepSet, TraceEvent, detect_hb_races, detect_races, estimated_classes,
    racing_events, trace_coverage_analysis,
};
use asupersync::types::{CancelReason, RegionId, TaskId, Time};

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}
fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

/// A spread of traces exercising independent, dependent, same-task,
/// cross-task, and region-conflict shapes.
fn corpus() -> Vec<Vec<TraceEvent>> {
    let z = Time::ZERO;
    vec![
        // empty
        vec![],
        // single event
        vec![TraceEvent::spawn(1, z, tid(1), rid(1))],
        // two independent spawns — no races
        vec![
            TraceEvent::spawn(1, z, tid(1), rid(1)),
            TraceEvent::spawn(2, z, tid(2), rid(2)),
        ],
        // same-task sequence — immediate dependent pair
        vec![
            TraceEvent::spawn(1, z, tid(1), rid(1)),
            TraceEvent::poll(2, z, tid(1), rid(1)),
            TraceEvent::complete(3, z, tid(1), rid(1)),
        ],
        // region create + two cross-task spawns sharing the region
        vec![
            TraceEvent::region_created(1, z, rid(1), None),
            TraceEvent::spawn(2, z, tid(1), rid(1)),
            TraceEvent::spawn(3, z, tid(2), rid(1)),
        ],
        // cross-task cancel requests racing on a region write
        vec![
            TraceEvent::cancel_request(1, z, tid(1), rid(1), CancelReason::user("a")),
            TraceEvent::cancel_request(2, z, tid(2), rid(1), CancelReason::user("b")),
        ],
        // mixed: timers (no task) interleaved with task events
        vec![
            TraceEvent::timer_scheduled(1, z, 7, Time::from_nanos(5)),
            TraceEvent::spawn(2, z, tid(1), rid(1)),
            TraceEvent::timer_fired(3, z, 7),
            TraceEvent::complete(4, z, tid(1), rid(1)),
        ],
    ]
}

// ---------------------------------------------------------------------------
// detect_races / racing_events — structural invariants
// ---------------------------------------------------------------------------

#[test]
fn every_race_runs_forward_with_in_range_indices() {
    for trace in corpus() {
        let analysis = detect_races(&trace);
        for race in &analysis.races {
            assert!(race.earlier < race.later, "race not forward: {race:?}");
            assert!(
                race.later < trace.len(),
                "race index out of range: {race:?}"
            );
        }
        // Backtrack points correspond one-to-one with races.
        assert_eq!(
            analysis.backtrack_points.len(),
            analysis.races.len(),
            "backtrack point count != race count"
        );
        for bp in &analysis.backtrack_points {
            assert_eq!(
                bp.divergence_index, bp.race.earlier,
                "backtrack point must diverge at the earlier event"
            );
        }
    }
}

#[test]
fn racing_events_is_exactly_the_sorted_deduped_race_endpoints() {
    for trace in corpus() {
        let analysis = detect_races(&trace);
        let mut expected: Vec<usize> = analysis
            .races
            .iter()
            .flat_map(|r| [r.earlier, r.later])
            .collect();
        expected.sort_unstable();
        expected.dedup();

        let got = racing_events(&trace);
        assert_eq!(got, expected, "racing_events mismatch");
        // Sorted, deduplicated, in range.
        for w in got.windows(2) {
            assert!(w[0] < w[1], "racing_events not strictly sorted");
        }
        for &idx in &got {
            assert!(idx < trace.len(), "racing event index out of range");
        }
    }
}

#[test]
fn detect_races_is_deterministic() {
    for trace in corpus() {
        let a = detect_races(&trace);
        let b = detect_races(&trace);
        assert_eq!(a.races, b.races, "detect_races non-deterministic");
    }
}

// ---------------------------------------------------------------------------
// detect_hb_races — the cross-task contract
// ---------------------------------------------------------------------------

#[test]
fn hb_races_are_cross_task_and_forward() {
    for trace in corpus() {
        let report = detect_hb_races(&trace);
        for dr in &report.races {
            assert!(dr.race.earlier < dr.race.later, "hb race not forward");
            assert!(dr.race.later < trace.len(), "hb race index out of range");
            // The HB detector explicitly skips same-task pairs.
            assert_ne!(
                dr.earlier_task, dr.later_task,
                "hb race must be between distinct tasks"
            );
            assert!(dr.earlier_task.is_some() && dr.later_task.is_some());
        }
        let again = detect_hb_races(&trace);
        assert_eq!(
            report.race_count(),
            again.race_count(),
            "detect_hb_races non-deterministic"
        );
    }
}

#[test]
fn a_pure_same_task_trace_has_no_hb_races() {
    // Every event belongs to one task — the HB detector orders them, so it
    // reports zero races even though the immediate detector sees dependencies.
    let z = Time::ZERO;
    let trace = vec![
        TraceEvent::spawn(1, z, tid(1), rid(1)),
        TraceEvent::poll(2, z, tid(1), rid(1)),
        TraceEvent::complete(3, z, tid(1), rid(1)),
    ];
    assert!(detect_hb_races(&trace).is_race_free());
    // ...while the immediate detector does see the same-task dependencies.
    assert!(detect_races(&trace).race_count() >= 1);
}

// ---------------------------------------------------------------------------
// estimated_classes — fail-closed lower bound
// ---------------------------------------------------------------------------

#[test]
fn estimated_classes_is_at_least_one_and_one_when_race_free() {
    for trace in corpus() {
        let est = estimated_classes(&trace);
        assert!(est >= 1, "estimated_classes must be a positive lower bound");

        // A trace with no schedulable races collapses to a single class.
        let schedulable = !detect_hb_races(&trace).is_race_free();
        if !schedulable && detect_races(&trace).is_race_free() {
            assert_eq!(est, 1, "race-free trace must estimate exactly one class");
        }
    }
    // Empty trace: exactly one class.
    assert_eq!(estimated_classes(&[]), 1);
}

// ---------------------------------------------------------------------------
// trace_coverage_analysis — internal consistency
// ---------------------------------------------------------------------------

#[test]
fn coverage_analysis_tallies_are_mutually_consistent() {
    for trace in corpus() {
        let cov = trace_coverage_analysis(&trace);
        assert_eq!(cov.event_count, trace.len(), "event_count mismatch");
        assert_eq!(
            cov.immediate_race_count,
            detect_races(&trace).race_count(),
            "immediate_race_count mismatch"
        );
        assert_eq!(
            cov.hb_race_count,
            detect_hb_races(&trace).race_count(),
            "hb_race_count mismatch"
        );
        assert_eq!(
            cov.racing_event_count,
            racing_events(&trace).len(),
            "racing_event_count mismatch"
        );
        assert_eq!(cov.estimated_classes, estimated_classes(&trace));
        assert!(
            (0.0..=1.0).contains(&cov.race_density),
            "race_density {} out of [0,1]",
            cov.race_density
        );
        assert!(
            cov.racing_event_count <= cov.event_count,
            "more racing events than events"
        );
        // resource distribution total equals the HB race count.
        assert_eq!(
            cov.resource_distribution.total(),
            cov.hb_race_count,
            "resource distribution total != hb race count"
        );
    }
}

// ---------------------------------------------------------------------------
// SleepSet — monotone membership, idempotent insertion
// ---------------------------------------------------------------------------

#[test]
fn sleep_set_membership_is_monotone_and_insertion_idempotent() {
    let z = Time::ZERO;
    let events = vec![
        TraceEvent::spawn(1, z, tid(1), rid(1)),
        TraceEvent::complete(2, z, tid(1), rid(1)),
    ];
    let bp = BacktrackPoint {
        race: Race {
            earlier: 0,
            later: 1,
        },
        divergence_index: 0,
    };

    let mut sleep = SleepSet::new();
    assert!(sleep.is_empty());
    assert!(
        !sleep.contains(&bp, &events),
        "fresh sleep set contains nothing"
    );

    sleep.insert(&bp, &events);
    assert!(
        sleep.contains(&bp, &events),
        "inserted point must be present"
    );
    assert_eq!(sleep.len(), 1);

    // Idempotent: re-inserting the same point does not grow the set, and
    // membership stays true (monotone — entries are never removed).
    sleep.insert(&bp, &events);
    assert_eq!(sleep.len(), 1, "re-insert must not grow the sleep set");
    assert!(sleep.contains(&bp, &events));
}
