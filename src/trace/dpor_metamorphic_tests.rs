//! Metamorphic tests for DPOR race detection.
//!
//! These tests verify correctness properties of race detection algorithms
//! without requiring oracle knowledge of "correct" race sets for arbitrary inputs.
//! Each test encodes a metamorphic relation that must hold for any correct
//! implementation.

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery)]

use super::dpor::*;
use crate::trace::event::{TraceEvent, TraceEventKind};
use crate::types::{RegionId, TaskId, Time};
use std::collections::HashMap;

// Test data generators
fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

// Generate test trace events for metamorphic testing
fn create_test_traces() -> Vec<Vec<TraceEvent>> {
    vec![
        // Empty trace
        vec![],
        // Single event trace
        vec![TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))],
        // Two independent events
        vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ],
        // Sequential dependent events on same task
        vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ],
        // Region creation with spawns
        vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        ],
        // Complex trace with multiple events
        vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::from_nanos(10), tid(1), rid(1)),
            TraceEvent::region_created(3, Time::from_nanos(20), rid(2), None),
            TraceEvent::spawn(4, Time::from_nanos(30), tid(2), rid(2)),
            TraceEvent::complete(5, Time::from_nanos(40), tid(1), rid(1)),
        ],
        // Timer events (no task context)
        vec![
            TraceEvent::timer_scheduled(1, Time::ZERO, 1, Time::from_nanos(10)),
            TraceEvent::timer_scheduled(2, Time::ZERO, 2, Time::from_nanos(20)),
        ],
    ]
}

/// MR1: Determinism - Same trace input always produces identical race analysis
#[test]
fn mr_determinism() {
    for trace in create_test_traces() {
        let analysis1 = detect_races(&trace);
        let analysis2 = detect_races(&trace);

        assert_eq!(
            analysis1.race_count(),
            analysis2.race_count(),
            "Race count must be deterministic"
        );
        assert_eq!(
            analysis1.races, analysis2.races,
            "Race sets must be identical for same input"
        );

        let hb1 = detect_hb_races(&trace);
        let hb2 = detect_hb_races(&trace);
        assert_eq!(
            hb1.race_count(),
            hb2.race_count(),
            "HB race count must be deterministic"
        );

        let est1 = estimated_classes(&trace);
        let est2 = estimated_classes(&trace);
        assert_eq!(est1, est2, "Estimated classes must be deterministic");
    }
}

/// MR2: Task Permutation Invariance - Systematically renaming tasks preserves race structure
#[test]
fn mr_task_permutation_invariance() {
    for trace in create_test_traces() {
        if trace.is_empty() {
            continue;
        }

        // Extract all task IDs and create a simple permutation (swap first two tasks if possible)
        let mut task_ids: Vec<TaskId> = trace.iter().filter_map(extract_task_id).collect();
        task_ids.sort_unstable();
        task_ids.dedup();

        if task_ids.len() < 2 {
            continue;
        }

        // Create simple permutation mapping (swap first two task IDs)
        let mut perm_map = HashMap::new();
        perm_map.insert(task_ids[0], task_ids[1]);
        perm_map.insert(task_ids[1], task_ids[0]);
        for &task in &task_ids[2..] {
            perm_map.insert(task, task); // Identity mapping for others
        }

        // Apply permutation to create transformed trace
        let permuted_trace: Vec<TraceEvent> = trace
            .iter()
            .map(|event| apply_task_permutation(event, &perm_map))
            .collect();

        let original_analysis = detect_races(&trace);
        let permuted_analysis = detect_races(&permuted_trace);

        // Race structure should be preserved
        assert_eq!(
            original_analysis.race_count(),
            permuted_analysis.race_count(),
            "Task permutation must preserve race count for trace with {} events",
            trace.len()
        );

        let original_classes = estimated_classes(&trace);
        let permuted_classes = estimated_classes(&permuted_trace);
        assert_eq!(
            original_classes, permuted_classes,
            "Task permutation must preserve estimated classes"
        );
    }
}

/// MR3: Sub-trace Consistency - Races in a prefix should be consistent with full trace
#[test]
fn mr_subtrace_consistency() {
    for trace in create_test_traces() {
        if trace.len() <= 1 {
            continue;
        }

        // Test multiple prefix lengths
        for prefix_len in 1..trace.len() {
            let prefix = &trace[..prefix_len];

            let full_analysis = detect_races(&trace);
            let prefix_analysis = detect_races(prefix);

            // All races in prefix should reference events within prefix bounds
            for race in &prefix_analysis.races {
                assert!(
                    race.earlier < prefix_len,
                    "Prefix race earlier index {} must be < prefix length {}",
                    race.earlier,
                    prefix_len
                );
                assert!(
                    race.later < prefix_len,
                    "Prefix race later index {} must be < prefix length {}",
                    race.later,
                    prefix_len
                );
            }

            // Races in prefix should be subset of races in full trace
            // (but with adjusted indices - this is a structural property)
            for prefix_race in &prefix_analysis.races {
                let found_matching = full_analysis.races.iter().any(|full_race| {
                    full_race.earlier == prefix_race.earlier && full_race.later == prefix_race.later
                });
                assert!(
                    found_matching,
                    "Race ({}, {}) found in prefix should exist in full trace",
                    prefix_race.earlier, prefix_race.later
                );
            }
        }
    }
}

/// MR4: HB Subset Consistency - HB races should be subset of immediate races for same trace
#[test]
fn mr_hb_subset_consistency() {
    for trace in create_test_traces() {
        let immediate_analysis = detect_races(&trace);
        let hb_report = detect_hb_races(&trace);

        // HB race count should not exceed immediate race count
        // (This is a structural property - HB is more restrictive)
        assert!(
            hb_report.race_count() <= immediate_analysis.race_count(),
            "HB races ({}) should not exceed immediate races ({}) for trace with {} events",
            hb_report.race_count(),
            immediate_analysis.race_count(),
            trace.len()
        );

        // Coverage analysis should be consistent
        let coverage = trace_coverage_analysis(&trace);
        assert_eq!(
            coverage.immediate_race_count,
            immediate_analysis.race_count()
        );
        assert_eq!(coverage.hb_race_count, hb_report.race_count());
        assert_eq!(coverage.event_count, trace.len());
    }
}

/// MR5: Sleep Set Deduplication - Same semantic race should deduplicate
#[test]
fn mr_sleep_set_deduplication() {
    // Use a specific test case that we know will have races
    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
    ];

    let analysis = detect_races(&events);
    if analysis.races.is_empty() {
        return;
    }

    // Test sleep set with same backtrack point
    let bp = BacktrackPoint {
        race: analysis.races[0].clone(),
        divergence_index: analysis.races[0].earlier,
    };

    let mut sleep = SleepSet::new();
    assert!(
        !sleep.contains(&bp, &events),
        "Fresh sleep set should not contain any backtrack point"
    );

    sleep.insert(&bp, &events);
    assert!(
        sleep.contains(&bp, &events),
        "Sleep set should contain inserted backtrack point"
    );
    assert_eq!(
        sleep.len(),
        1,
        "Sleep set should have exactly one entry after single insert"
    );

    // Insert same backtrack point again - should deduplicate
    sleep.insert(&bp, &events);
    assert_eq!(
        sleep.len(),
        1,
        "Sleep set should deduplicate identical backtrack points"
    );
}

/// MR6: Independent Events - Truly independent events should never race
#[test]
fn mr_independent_events_no_race() {
    // Construct traces with provably independent events
    let independent_traces = vec![
        // Different regions, different tasks
        vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ],
        // Timer events (no task context)
        vec![
            TraceEvent::timer_scheduled(1, Time::ZERO, 1, Time::from_nanos(10)),
            TraceEvent::timer_scheduled(2, Time::ZERO, 2, Time::from_nanos(20)),
        ],
        // Same region but only reads
        vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        ],
    ];

    for trace in independent_traces {
        let _analysis = detect_races(&trace);
        let hb_report = detect_hb_races(&trace);

        // For specific independent cases, verify expected behavior
        match trace.len() {
            2 if trace[0].kind == TraceEventKind::Spawn
                && trace[1].kind == TraceEventKind::Spawn =>
            {
                // Different regions/tasks should be race-free
                let t0_task = extract_task_id(&trace[0]);
                let t1_task = extract_task_id(&trace[1]);
                let t0_region = extract_region_id(&trace[0]);
                let t1_region = extract_region_id(&trace[1]);

                if t0_task != t1_task && t0_region != t1_region {
                    assert!(
                        hb_report.is_race_free(),
                        "Different tasks in different regions should not race"
                    );
                }
            }
            _ => {} // Other patterns checked by general properties
        }
    }
}

/// MR7: Backtrack Consistency - Each race should generate corresponding backtrack point
#[test]
fn mr_backtrack_consistency() {
    for trace in create_test_traces() {
        let analysis = detect_races(&trace);

        // Each race should generate a backtrack point
        assert_eq!(
            analysis.races.len(),
            analysis.backtrack_points.len(),
            "Number of backtrack points should equal number of races"
        );

        // Each backtrack point should reference a valid race
        for (i, bp) in analysis.backtrack_points.iter().enumerate() {
            assert_eq!(
                bp.race, analysis.races[i],
                "Backtrack point {} should reference corresponding race",
                i
            );
            assert_eq!(
                bp.divergence_index, bp.race.earlier,
                "Divergence index should equal earlier event index"
            );
        }
    }
}

/// MR8: Empty/Minimal Trace Properties
#[test]
fn mr_empty_minimal_traces() {
    // Empty trace
    let empty_analysis = detect_races(&[]);
    assert!(
        empty_analysis.is_race_free(),
        "Empty trace should have no races"
    );
    assert_eq!(
        estimated_classes(&[]),
        1,
        "Empty trace should have 1 equivalence class"
    );

    // Single event
    let single = vec![TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
    let single_analysis = detect_races(&single);
    assert!(
        single_analysis.is_race_free(),
        "Single event should have no races"
    );

    // Two independent events
    let independent = vec![
        TraceEvent::timer_scheduled(1, Time::ZERO, 1, Time::from_nanos(10)),
        TraceEvent::timer_scheduled(2, Time::ZERO, 2, Time::from_nanos(20)),
    ];
    let indep_hb = detect_hb_races(&independent);
    assert!(
        indep_hb.is_race_free(),
        "Independent timer events should not race"
    );
}

/// MR9: Time Scaling Invariance - Scaling all timestamps shouldn't affect race structure
#[test]
fn mr_time_scaling_invariance() {
    let scale_factors = [2, 5, 10, 100];

    for trace in create_test_traces() {
        for &scale_factor in &scale_factors {
            let scaled_trace: Vec<TraceEvent> = trace
                .iter()
                .map(|event| scale_event_time(event, scale_factor))
                .collect();

            let original_analysis = detect_races(&trace);
            let scaled_analysis = detect_races(&scaled_trace);

            assert_eq!(
                original_analysis.race_count(),
                scaled_analysis.race_count(),
                "Time scaling by {} should preserve race count",
                scale_factor
            );

            let original_classes = estimated_classes(&trace);
            let scaled_classes = estimated_classes(&scaled_trace);
            assert_eq!(
                original_classes, scaled_classes,
                "Time scaling should preserve estimated classes"
            );
        }
    }
}

// Helper functions for transformations

fn extract_task_id(event: &TraceEvent) -> Option<TaskId> {
    match &event.data {
        crate::trace::event::TraceData::Task { task, .. }
        | crate::trace::event::TraceData::Cancel { task, .. }
        | crate::trace::event::TraceData::Obligation { task, .. }
        | crate::trace::event::TraceData::Futurelock { task, .. }
        | crate::trace::event::TraceData::Worker { task, .. } => Some(*task),
        crate::trace::event::TraceData::Chaos {
            task: Some(task), ..
        } => Some(*task),
        _ => None,
    }
}

fn extract_region_id(event: &TraceEvent) -> Option<RegionId> {
    match &event.data {
        crate::trace::event::TraceData::Task { region, .. }
        | crate::trace::event::TraceData::Cancel { region, .. }
        | crate::trace::event::TraceData::Obligation { region, .. } => Some(*region),
        crate::trace::event::TraceData::Region { region, .. } => Some(*region),
        _ => None,
    }
}

fn apply_task_permutation(event: &TraceEvent, perm_map: &HashMap<TaskId, TaskId>) -> TraceEvent {
    let mut new_event = event.clone();

    match &mut new_event.data {
        crate::trace::event::TraceData::Task { task, .. }
        | crate::trace::event::TraceData::Cancel { task, .. }
        | crate::trace::event::TraceData::Obligation { task, .. }
        | crate::trace::event::TraceData::Futurelock { task, .. }
        | crate::trace::event::TraceData::Worker { task, .. } => {
            if let Some(new_task) = perm_map.get(task) {
                *task = *new_task;
            }
        }
        crate::trace::event::TraceData::Chaos {
            task: Some(task), ..
        } => {
            if let Some(new_task) = perm_map.get(task) {
                *task = *new_task;
            }
        }
        _ => {} // No task ID to permute
    }

    new_event
}

fn scale_event_time(event: &TraceEvent, scale_factor: u64) -> TraceEvent {
    let mut new_event = event.clone();
    new_event.time = Time::from_nanos(event.time.as_nanos().saturating_mul(scale_factor));

    // Also scale embedded timestamps in event data if present
    match &mut new_event.data {
        crate::trace::event::TraceData::Timer {
            deadline: Some(deadline_time),
            ..
        } => {
            *deadline_time =
                Time::from_nanos(deadline_time.as_nanos().saturating_mul(scale_factor));
        }
        _ => {} // No embedded time to scale
    }

    new_event
}

// Composite MR: Determinism + Task Permutation + Sub-trace
// This compound property multiplies the fault detection power
#[test]
fn mr_composite_determinism_permutation_subtrace() {
    for trace in create_test_traces() {
        if trace.len() < 2 {
            continue;
        }

        let prefix_ratios = [0.5, 0.75, 1.0];

        for &prefix_ratio in &prefix_ratios {
            let prefix_len = ((trace.len() as f64 * prefix_ratio) as usize)
                .max(1)
                .min(trace.len());
            let prefix = &trace[..prefix_len];

            // Extract and permute tasks (simple swap strategy)
            let mut task_ids: Vec<TaskId> = trace.iter().filter_map(extract_task_id).collect();
            task_ids.sort_unstable();
            task_ids.dedup();

            if task_ids.len() < 2 {
                continue;
            }

            // Create simple permutation (swap first two tasks)
            let mut perm_map = HashMap::new();
            perm_map.insert(task_ids[0], task_ids[1]);
            perm_map.insert(task_ids[1], task_ids[0]);
            for &task in &task_ids[2..] {
                perm_map.insert(task, task);
            }

            let permuted_prefix: Vec<TraceEvent> = prefix
                .iter()
                .map(|event| apply_task_permutation(event, &perm_map))
                .collect();

            // All three analyses should be deterministic and structurally consistent
            let orig_races = detect_races(prefix).race_count();
            let perm_races = detect_races(&permuted_prefix).race_count();

            assert_eq!(
                orig_races, perm_races,
                "Composite: permuted sub-trace should preserve race count"
            );

            // Repeat analysis should be identical (determinism)
            let repeat_races = detect_races(&permuted_prefix).race_count();
            assert_eq!(
                perm_races, repeat_races,
                "Composite: repeated analysis should be deterministic"
            );
        }
    }
}
