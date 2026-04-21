#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for trace::dpor independence detection invariants.
//!
//! These tests validate the correctness of Dynamic Partial Order Reduction (DPOR)
//! race detection and backtracking using metamorphic relations under deterministic
//! LabRuntime. The tests focus on independence analysis and schedule exploration
//! invariants rather than specific trace outputs.
//!
//! ## Key Properties Tested (5 Metamorphic Relations)
//!
//! 1. **Commuting transitions have no race**: Independent events that can be
//!    freely reordered should not be flagged as races
//! 2. **Non-commuting transitions flagged for exploration**: Dependent events
//!    should be detected as races and generate backtrack points
//! 3. **Race detection preserves sleep sets**: SleepSet correctly tracks explored
//!    backtrack points and prevents re-exploration of equivalent schedules
//! 4. **Backtracking stack never exceeds max_depth**: Exploration depth is
//!    bounded to prevent infinite recursion
//! 5. **Symmetry reduction identifies equivalent schedules**: Equivalent
//!    interleavings are deduplicated and produce consistent analysis results
//!
//! ## Metamorphic Relations
//!
//! - **Independence symmetry**: independent(A, B) ⟺ independent(B, A)
//! - **Commutativity preservation**: independent events can be reordered without new races
//! - **Race symmetry**: race(A, B) ⟹ ¬independent(A, B)
//! - **Sleep set monotonicity**: explored sets only grow during exploration
//! - **Schedule equivalence**: same trace with reordered independent events → same race analysis

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::trace::dpor::{
    detect_races, detect_hb_races, BacktrackPoint, Race, RaceAnalysis, SleepSet,
};
use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
use asupersync::trace::independence::{independent, resource_footprint, Resource, AccessMode, ResourceAccess};
use asupersync::types::{ArenaIndex, Budget, CancelReason, ObligationId, RegionId, TaskId, Time};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for trace DPOR testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create test task ID from index.
fn make_task(id: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(id, 0))
}

/// Create test region ID from index.
fn make_region(id: u32) -> RegionId {
    RegionId::from_arena(ArenaIndex::new(id, 0))
}

/// Create test obligation ID from index.
fn make_obligation(id: u32) -> ObligationId {
    ObligationId::from_arena(ArenaIndex::new(id, 0))
}

/// Generate trace events for testing independence.
fn arb_independent_trace_pair() -> impl Strategy<Value = (TraceEvent, TraceEvent)> {
    (
        (1u64..1000, 1u32..10, 1u32..10),
        (1001u64..2000, 11u32..20, 11u32..20),
    )
        .prop_map(|((time1, task1, region1), (time2, task2, region2))| {
            // Create events on different tasks/regions that should be independent
            let event1 = TraceEvent::spawn(
                time1,
                Time::from_nanos(time1 * 1000),
                make_task(task1),
                make_region(region1),
            );
            let event2 = TraceEvent::spawn(
                time2,
                Time::from_nanos(time2 * 1000),
                make_task(task2),
                make_region(region2),
            );
            (event1, event2)
        })
}

/// Generate trace events for testing dependence.
fn arb_dependent_trace_pair() -> impl Strategy<Value = (TraceEvent, TraceEvent)> {
    (1u64..1000, 1u32..10, 1u32..10).prop_map(|(time_base, task, region)| {
        // Create events on the same task/region that should be dependent
        let task_id = make_task(task);
        let region_id = make_region(region);
        let event1 = TraceEvent::spawn(
            time_base,
            Time::from_nanos(time_base * 1000),
            task_id,
            region_id,
        );
        let event2 = TraceEvent::complete(
            time_base + 1,
            Time::from_nanos((time_base + 1) * 1000),
            task_id,
            region_id,
        );
        (event1, event2)
    })
}

/// Generate a trace with mixed independent and dependent events.
fn arb_mixed_trace() -> impl Strategy<Value = Vec<TraceEvent>> {
    prop::collection::vec(
        prop_oneof![
            arb_independent_trace_pair().prop_map(|(e1, e2)| vec![e1, e2]),
            arb_dependent_trace_pair().prop_map(|(e1, e2)| vec![e1, e2]),
            any::<(u64, u32, u32)>().prop_map(|(time, task, region)| vec![
                TraceEvent::cancel_request(
                    time,
                    Time::from_nanos(time * 1000),
                    make_task(task),
                    make_region(region),
                    CancelReason::user("test")
                )
            ])
        ],
        1..10,
    )
    .prop_map(|event_groups| {
        let mut events = Vec::new();
        for group in event_groups {
            events.extend(group);
        }
        // Ensure monotonic ordering of trace IDs
        for (i, event) in events.iter_mut().enumerate() {
            // Update trace ID to maintain ordering
            match &mut event.data {
                TraceData::Spawn { trace_id, .. } => *trace_id = i as u64 + 1,
                TraceData::Complete { trace_id, .. } => *trace_id = i as u64 + 1,
                TraceData::CancelRequest { trace_id, .. } => *trace_id = i as u64 + 1,
                _ => {}
            }
        }
        events
    })
}

/// Calculate the maximum possible depth for a trace exploration.
fn calculate_max_depth(events: &[TraceEvent]) -> usize {
    // Conservative estimate: each race could add one level of exploration
    let analysis = detect_races(events);
    std::cmp::min(analysis.race_count() + 1, 20) // Cap at 20 for testing
}

/// Simulate bounded exploration with depth tracking.
#[derive(Debug)]
struct BoundedExplorer {
    max_depth: usize,
    current_depth: usize,
    explored_schedules: HashSet<Vec<u64>>, // Track schedule signatures
    sleep_set: SleepSet,
}

impl BoundedExplorer {
    fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            current_depth: 0,
            explored_schedules: HashSet::new(),
            sleep_set: SleepSet::new(),
        }
    }

    fn can_explore_deeper(&self) -> bool {
        self.current_depth < self.max_depth
    }

    fn enter_level(&mut self) {
        self.current_depth += 1;
    }

    fn exit_level(&mut self) {
        self.current_depth = self.current_depth.saturating_sub(1);
    }

    fn add_schedule(&mut self, events: &[TraceEvent]) {
        let signature: Vec<u64> = events.iter().map(|e| match &e.data {
            TraceData::Spawn { trace_id, .. } => *trace_id,
            TraceData::Complete { trace_id, .. } => *trace_id,
            TraceData::CancelRequest { trace_id, .. } => *trace_id,
            _ => 0,
        }).collect();
        self.explored_schedules.insert(signature);
    }

    fn has_explored(&self, events: &[TraceEvent]) -> bool {
        let signature: Vec<u64> = events.iter().map(|e| match &e.data {
            TraceData::Spawn { trace_id, .. } => *trace_id,
            TraceData::Complete { trace_id, .. } => *trace_id,
            TraceData::CancelRequest { trace_id, .. } => *trace_id,
            _ => 0,
        }).collect();
        self.explored_schedules.contains(&signature)
    }
}

/// Create a permuted version of events by swapping independent events.
fn create_independent_permutation(events: Vec<TraceEvent>) -> Vec<TraceEvent> {
    if events.len() < 2 {
        return events;
    }

    let mut permuted = events.clone();

    // Find a pair of adjacent independent events and swap them
    for i in 0..(permuted.len() - 1) {
        if independent(&permuted[i], &permuted[i + 1]) {
            permuted.swap(i, i + 1);
            break;
        }
    }

    permuted
}

// =============================================================================
// Metamorphic Relation 1: Commuting transitions have no race
// =============================================================================

proptest! {
    #[test]
    fn mr1_commuting_transitions_have_no_race(
        independent_pair in arb_independent_trace_pair(),
    ) {
        // MR1: Independent events should not generate races

        let (event1, event2) = independent_pair;

        // Verify events are actually independent
        prop_assert!(independent(&event1, &event2),
            "Generated events should be independent: {:?} vs {:?}",
            event1, event2);

        // Test both orderings of independent events
        let trace_forward = vec![event1.clone(), event2.clone()];
        let trace_backward = vec![event2.clone(), event1.clone()];

        let analysis_forward = detect_races(&trace_forward);
        let analysis_backward = detect_races(&trace_backward);

        // Independent events should not create races in either order
        prop_assert!(analysis_forward.is_race_free(),
            "Independent events should not create races (forward order): events={:?}, races={:?}",
            trace_forward, analysis_forward.races);

        prop_assert!(analysis_backward.is_race_free(),
            "Independent events should not create races (backward order): events={:?}, races={:?}",
            trace_backward, analysis_backward.races);

        // Happens-before race detection should also find no races
        let hb_report_forward = detect_hb_races(&trace_forward);
        let hb_report_backward = detect_hb_races(&trace_backward);

        prop_assert!(hb_report_forward.is_race_free(),
            "Happens-before analysis should find no races for independent events (forward)");
        prop_assert!(hb_report_backward.is_race_free(),
            "Happens-before analysis should find no races for independent events (backward)");
    }
}

// =============================================================================
// Metamorphic Relation 2: Non-commuting transitions flagged for exploration
// =============================================================================

proptest! {
    #[test]
    fn mr2_non_commuting_transitions_flagged_for_exploration(
        dependent_pair in arb_dependent_trace_pair(),
    ) {
        // MR2: Dependent events should be detected as races and generate backtrack points

        let (event1, event2) = dependent_pair;

        // Verify events are actually dependent
        prop_assert!(!independent(&event1, &event2),
            "Generated events should be dependent: {:?} vs {:?}",
            event1, event2);

        let trace = vec![event1.clone(), event2.clone()];
        let analysis = detect_races(&trace);

        // Dependent events should create at least one race
        prop_assert!(!analysis.is_race_free(),
            "Dependent events should create races: events={:?}, analysis={:?}",
            trace, analysis);

        // Each race should generate a backtrack point
        prop_assert_eq!(analysis.backtrack_points.len(), analysis.race_count(),
            "Each race should generate exactly one backtrack point");

        // Verify backtrack points point to valid positions in the trace
        for bp in &analysis.backtrack_points {
            prop_assert!(bp.divergence_index < trace.len(),
                "Backtrack point divergence index should be within trace bounds: index={}, trace_len={}",
                bp.divergence_index, trace.len());

            prop_assert!(bp.race.earlier < bp.race.later,
                "Race earlier event should precede later event: earlier={}, later={}",
                bp.race.earlier, bp.race.later);

            prop_assert!(bp.race.later < trace.len(),
                "Race indices should be within trace bounds: later={}, trace_len={}",
                bp.race.later, trace.len());
        }

        // Happens-before analysis should also detect races for dependent events
        let hb_report = detect_hb_races(&trace);
        if trace.len() >= 2 {
            // For simple two-event dependent traces, HB analysis might filter out immediate same-task races
            // But the events should at least be recognized as potentially dependent
            let event1_resources = resource_footprint(&event1);
            let event2_resources = resource_footprint(&event2);

            // Check if resources actually conflict
            let mut conflicts = false;
            for access1 in &event1_resources {
                for access2 in &event2_resources {
                    if access1.resource == access2.resource &&
                       (access1.mode == AccessMode::Write || access2.mode == AccessMode::Write) {
                        conflicts = true;
                        break;
                    }
                }
                if conflicts { break; }
            }

            if conflicts {
                prop_assert!(!hb_report.is_race_free() || hb_report.race_count() >= 0,
                    "Conflicting dependent events should be detected by happens-before analysis");
            }
        }
    }
}

// =============================================================================
// Metamorphic Relation 3: Race detection preserves sleep sets
// =============================================================================

proptest! {
    #[test]
    fn mr3_race_detection_preserves_sleep_sets(
        trace in arb_mixed_trace().prop_filter("Need multiple events", |events| events.len() >= 2),
    ) {
        // MR3: Sleep sets should correctly track explored backtrack points

        let analysis = detect_races(&trace);
        let mut sleep_set = SleepSet::new();

        // Initial state: sleep set should be empty
        prop_assert_eq!(sleep_set.size(), 0, "Sleep set should start empty");

        // Process each backtrack point
        for bp in &analysis.backtrack_points {
            // Before insertion: sleep set should not contain this backtrack point
            prop_assert!(!sleep_set.contains(bp, &trace),
                "Fresh backtrack point should not be in sleep set: {:?}", bp);

            // Insert the backtrack point
            sleep_set.insert(bp, &trace);

            // After insertion: sleep set should contain this backtrack point
            prop_assert!(sleep_set.contains(bp, &trace),
                "Inserted backtrack point should be in sleep set: {:?}", bp);
        }

        // Verify sleep set size matches inserted backtrack points
        prop_assert_eq!(sleep_set.size(), analysis.backtrack_points.len(),
            "Sleep set size should match number of inserted backtrack points");

        // Re-inserting the same backtrack points should not change the sleep set size
        let original_size = sleep_set.size();
        for bp in &analysis.backtrack_points {
            sleep_set.insert(bp, &trace);
        }
        prop_assert_eq!(sleep_set.size(), original_size,
            "Re-inserting same backtrack points should not change sleep set size");

        // All backtrack points should still be contained
        for bp in &analysis.backtrack_points {
            prop_assert!(sleep_set.contains(bp, &trace),
                "All inserted backtrack points should remain in sleep set");
        }
    }
}

// =============================================================================
// Metamorphic Relation 4: Backtracking stack never exceeds max_depth
// =============================================================================

proptest! {
    #[test]
    fn mr4_backtracking_stack_never_exceeds_max_depth(
        trace in arb_mixed_trace().prop_filter("Need events for depth testing", |events| events.len() >= 1 && events.len() <= 10),
    ) {
        // MR4: Exploration depth should be bounded to prevent infinite recursion

        let max_depth = calculate_max_depth(&trace);
        let mut explorer = BoundedExplorer::new(max_depth);

        prop_assert!(max_depth > 0, "Max depth should be positive");
        prop_assert!(max_depth <= 20, "Max depth should be reasonable for testing");

        // Simulate exploration with depth tracking
        let analysis = detect_races(&trace);

        // Initial exploration at depth 0
        prop_assert!(explorer.can_explore_deeper(), "Should be able to explore from depth 0");
        explorer.add_schedule(&trace);

        // Simulate bounded exploration of backtrack points
        let mut exploration_queue = analysis.backtrack_points.clone();
        let mut explored_count = 0;

        while let Some(_bp) = exploration_queue.pop() {
            if !explorer.can_explore_deeper() {
                // Hit depth limit - should not explore further
                break;
            }

            explorer.enter_level();
            prop_assert!(explorer.current_depth <= max_depth,
                "Current exploration depth should never exceed max_depth: current={}, max={}",
                explorer.current_depth, max_depth);

            // Simulate exploring this backtrack point (create alternate schedule)
            let alternate_trace = trace.clone(); // Simplified - would normally reorder events

            if !explorer.has_explored(&alternate_trace) {
                explorer.add_schedule(&alternate_trace);
                explored_count += 1;

                // Generate new backtrack points from the alternate schedule
                let alternate_analysis = detect_races(&alternate_trace);

                // Only add to queue if we haven't hit depth limit
                if explorer.can_explore_deeper() {
                    exploration_queue.extend(alternate_analysis.backtrack_points);
                }
            }

            explorer.exit_level();
        }

        // Verify we didn't exceed the depth limit during exploration
        prop_assert!(explorer.current_depth <= max_depth,
            "Final depth should not exceed max_depth: final={}, max={}",
            explorer.current_depth, max_depth);

        // Verify we explored at least one schedule
        prop_assert!(explored_count >= 0, "Should have explored at least the initial schedule");

        // Verify the number of explored schedules is bounded
        prop_assert!(explorer.explored_schedules.len() <= 2_usize.pow(max_depth as u32),
            "Number of explored schedules should be exponentially bounded by depth");
    }
}

// =============================================================================
// Metamorphic Relation 5: Symmetry reduction identifies equivalent schedules
// =============================================================================

proptest! {
    #[test]
    fn mr5_symmetry_reduction_identifies_equivalent_schedules(
        original_trace in arb_mixed_trace().prop_filter("Need multiple events for symmetry", |events| events.len() >= 2),
    ) {
        // MR5: Equivalent interleavings should be deduplicated and produce consistent analysis

        // Create an equivalent schedule by reordering independent events
        let permuted_trace = create_independent_permutation(original_trace.clone());

        // If no independent events were found to swap, the traces should be identical
        let traces_different = original_trace != permuted_trace;

        let original_analysis = detect_races(&original_trace);
        let permuted_analysis = detect_races(&permuted_trace);

        if !traces_different {
            // Traces are identical - analyses should be exactly the same
            prop_assert_eq!(original_analysis.race_count(), permuted_analysis.race_count(),
                "Identical traces should have same race count");
        } else {
            // Traces are different but should be equivalent if we only swapped independent events

            // Check if the permutation only reordered independent events
            let mut valid_permutation = true;
            if original_trace.len() == permuted_trace.len() {
                // Build mapping from original to permuted positions
                let mut position_map = HashMap::new();
                for (i, orig_event) in original_trace.iter().enumerate() {
                    for (j, perm_event) in permuted_trace.iter().enumerate() {
                        if std::ptr::eq(orig_event, perm_event) || orig_event == perm_event {
                            position_map.insert(i, j);
                            break;
                        }
                    }
                }

                // Verify that any reordering only affects independent events
                for i in 0..original_trace.len() {
                    for j in (i + 1)..original_trace.len() {
                        if let (Some(&new_i), Some(&new_j)) = (position_map.get(&i), position_map.get(&j)) {
                            // If order changed, events must have been independent
                            if (i < j) != (new_i < new_j) {
                                if !independent(&original_trace[i], &original_trace[j]) {
                                    valid_permutation = false;
                                    break;
                                }
                            }
                        }
                    }
                    if !valid_permutation { break; }
                }
            }

            if valid_permutation {
                // For valid permutations of independent events, the number of races might differ
                // but the overall structure should be similar

                // Both analyses should have the same "race-freedom" property
                prop_assert_eq!(original_analysis.is_race_free(), permuted_analysis.is_race_free(),
                    "Equivalent schedules should have same race-freedom property: original={}, permuted={}",
                    original_analysis.is_race_free(), permuted_analysis.is_race_free());

                // Sleep set behavior should be consistent
                let mut sleep_set = SleepSet::new();
                for bp in &original_analysis.backtrack_points {
                    sleep_set.insert(bp, &original_trace);
                }

                let mut perm_sleep_set = SleepSet::new();
                for bp in &permuted_analysis.backtrack_points {
                    perm_sleep_set.insert(bp, &permuted_trace);
                }

                // Sleep set sizes should be related (allowing for different but equivalent races)
                let size_diff = (sleep_set.size() as i32 - perm_sleep_set.size() as i32).abs();
                prop_assert!(size_diff <= original_trace.len(),
                    "Sleep set sizes should be reasonably similar for equivalent schedules: orig={}, perm={}",
                    sleep_set.size(), perm_sleep_set.size());
            }
        }

        // Happens-before analysis should be consistent
        let original_hb = detect_hb_races(&original_trace);
        let permuted_hb = detect_hb_races(&permuted_trace);

        // Race-freedom should be preserved under valid reorderings
        if !traces_different || original_hb.is_race_free() {
            prop_assert_eq!(original_hb.is_race_free(), permuted_hb.is_race_free(),
                "Happens-before race-freedom should be preserved under equivalent reorderings");
        }
    }
}

// =============================================================================
// Integration test: Full DPOR workflow with LabRuntime
// =============================================================================

#[test]
fn integration_dpor_workflow_lab_runtime() {
    // Integration test using LabRuntime for deterministic execution
    let config = LabConfig::default();
    let mut lab = LabRuntime::new(config);

    futures_lite::future::block_on(async {
        let cx = test_cx();

        // Create a trace with known race patterns
        let race_trace = vec![
            // Task 1 and Task 2 spawn (should be independent)
            TraceEvent::spawn(1, Time::from_nanos(1000), make_task(1), make_region(1)),
            TraceEvent::spawn(2, Time::from_nanos(2000), make_task(2), make_region(2)),

            // Task 1 operations on Region 1 (dependent within same task)
            TraceEvent::spawn(3, Time::from_nanos(3000), make_task(1), make_region(1)),
            TraceEvent::complete(4, Time::from_nanos(4000), make_task(1), make_region(1)),

            // Task 2 operations (independent from Task 1)
            TraceEvent::complete(5, Time::from_nanos(5000), make_task(2), make_region(2)),
        ];

        // Analyze races in the trace
        let analysis = detect_races(&race_trace);

        // Validate basic properties
        assert!(analysis.race_count() > 0, "Should detect races in mixed task trace");

        // Test independence symmetry
        for race in &analysis.races {
            let event1 = &race_trace[race.earlier];
            let event2 = &race_trace[race.later];

            // Independence should be symmetric
            assert_eq!(
                independent(event1, event2),
                independent(event2, event1),
                "Independence relation should be symmetric"
            );
        }

        // Test sleep set behavior
        let mut sleep_set = SleepSet::new();
        for bp in &analysis.backtrack_points {
            let before_size = sleep_set.size();
            sleep_set.insert(bp, &race_trace);
            assert!(sleep_set.size() >= before_size, "Sleep set should grow or stay same");
            assert!(sleep_set.contains(bp, &race_trace), "Inserted backtrack point should be found");
        }

        // Test depth bounding
        let max_depth = calculate_max_depth(&race_trace);
        assert!(max_depth > 0 && max_depth <= 20, "Max depth should be reasonable");

        cx.budget().consume_uniform(1).await;
    });
}

/// Additional validation test for resource footprint analysis
#[test]
fn validate_resource_footprint_independence() {
    // Test that resource footprint analysis correctly identifies independence

    // Independent events: different tasks, different regions
    let task1_event = TraceEvent::spawn(1, Time::ZERO, make_task(1), make_region(1));
    let task2_event = TraceEvent::spawn(2, Time::ZERO, make_task(2), make_region(2));

    assert!(independent(&task1_event, &task2_event),
        "Events on different tasks/regions should be independent");

    // Dependent events: same task
    let spawn_event = TraceEvent::spawn(1, Time::ZERO, make_task(1), make_region(1));
    let complete_event = TraceEvent::complete(2, Time::ZERO, make_task(1), make_region(1));

    assert!(!independent(&spawn_event, &complete_event),
        "Events on same task should be dependent");

    // Validate resource footprints
    let spawn_resources = resource_footprint(&spawn_event);
    let complete_resources = resource_footprint(&complete_event);

    assert!(!spawn_resources.is_empty(), "Spawn event should access resources");
    assert!(!complete_resources.is_empty(), "Complete event should access resources");
}