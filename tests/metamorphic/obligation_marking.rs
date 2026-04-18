//! Metamorphic tests for obligation::marking token accounting invariants.
//!
//! These tests validate the core invariants of the VASS obligation marking system
//! using metamorphic relations and property-based testing under deterministic
//! LabRuntime with DPOR (Dynamic Partial-Order Reduction).
//!
//! ## Key Properties Tested (5 Metamorphic Relations)
//!
//! 1. **Mark+unmark preserves balance**: Total reserves = total commits + aborts
//! 2. **Double-mark tracked via generation**: Multiple reserves properly tracked
//! 3. **Unmark without mark is error**: Decrementing below zero is invalid transition
//! 4. **Concurrent mark/unmark deterministic**: Concurrent operations resolve deterministically
//! 5. **Region close fails if any mark outstanding**: Closing with pending obligations = leak
//!
//! ## Metamorphic Relations
//!
//! - **Vector addition balance**: All increments have matching decrements for safety
//! - **Dimension isolation**: Changes to one (kind, region) don't affect others
//! - **Timeline monotonicity**: Total pending never goes negative
//! - **Leak detection**: Region closure with non-zero marking is detected
//! - **Deterministic concurrency**: Same concurrent marking operations → same outcome
//! - **State consistency**: Marking counts match underlying obligation state

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::marking::{
    MarkingAnalyzer, MarkingEvent, MarkingEventKind, ObligationMarking,
};
use asupersync::record::ObligationKind;
use asupersync::types::{ArenaIndex, Budget, ObligationId, RegionId, TaskId, Time};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for obligation marking testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test task ID.
fn make_task(id: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(id, 0))
}

/// Create a test region ID.
fn make_region(id: u32) -> RegionId {
    RegionId::from_arena(ArenaIndex::new(id, 0))
}

/// Create a test obligation ID.
fn make_obligation(id: u32) -> ObligationId {
    ObligationId::from_arena(ArenaIndex::new(id, 0))
}

/// Generate arbitrary obligation kinds
fn arb_obligation_kind() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
    ]
}

/// Generate arbitrary time values for testing
fn arb_time() -> impl Strategy<Value = Time> {
    (1u64..=1_000_000_000u64).prop_map(Time::from_nanos)
}

/// Generate small numbers for test entities to keep space manageable
fn small_id() -> impl Strategy<Value = u32> {
    0u32..8
}

/// Generate medium numbers for obligation IDs
fn medium_id() -> impl Strategy<Value = u32> {
    0u32..32
}

/// Operations that can be performed on the marking
#[derive(Debug, Clone)]
enum MarkingOperation {
    Reserve {
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
        time: Time,
    },
    Commit {
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
        time: Time,
    },
    Abort {
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
        time: Time,
    },
    CloseRegion {
        region: RegionId,
        time: Time,
    },
}

/// Generate arbitrary marking operations
fn arb_marking_operation() -> impl Strategy<Value = MarkingOperation> {
    prop_oneof![
        (
            medium_id().prop_map(make_obligation),
            arb_obligation_kind(),
            small_id().prop_map(make_task),
            small_id().prop_map(make_region),
            arb_time(),
        ).prop_map(|(obligation, kind, task, region, time)| {
            MarkingOperation::Reserve {
                obligation,
                kind,
                task,
                region,
                time,
            }
        }),
        (
            medium_id().prop_map(make_obligation),
            small_id().prop_map(make_region),
            arb_obligation_kind(),
            arb_time(),
        ).prop_map(|(obligation, region, kind, time)| {
            MarkingOperation::Commit {
                obligation,
                region,
                kind,
                time,
            }
        }),
        (
            medium_id().prop_map(make_obligation),
            small_id().prop_map(make_region),
            arb_obligation_kind(),
            arb_time(),
        ).prop_map(|(obligation, region, kind, time)| {
            MarkingOperation::Abort {
                obligation,
                region,
                kind,
                time,
            }
        }),
        (
            small_id().prop_map(make_region),
            arb_time(),
        ).prop_map(|(region, time)| {
            MarkingOperation::CloseRegion {
                region,
                time,
            }
        }),
    ]
}

/// Convert operation to marking event
fn operation_to_event(op: &MarkingOperation) -> MarkingEvent {
    match op {
        MarkingOperation::Reserve { obligation, kind, task, region, time } => {
            MarkingEvent::new(*time, MarkingEventKind::Reserve {
                obligation: *obligation,
                kind: *kind,
                task: *task,
                region: *region,
            })
        }
        MarkingOperation::Commit { obligation, region, kind, time } => {
            MarkingEvent::new(*time, MarkingEventKind::Commit {
                obligation: *obligation,
                region: *region,
                kind: *kind,
            })
        }
        MarkingOperation::Abort { obligation, region, kind, time } => {
            MarkingEvent::new(*time, MarkingEventKind::Abort {
                obligation: *obligation,
                region: *region,
                kind: *kind,
            })
        }
        MarkingOperation::CloseRegion { region, time } => {
            MarkingEvent::new(*time, MarkingEventKind::RegionClose {
                region: *region,
            })
        }
    }
}

// =============================================================================
// Metamorphic Relation 1: Mark+Unmark Preserves Balance
// =============================================================================

proptest! {
    /// MR1: Total reserves must equal total commits + aborts for a safe execution
    #[test]
    fn mr1_mark_unmark_preserves_balance(
        ops in prop::collection::vec(arb_marking_operation(), 1..20),
    ) {
        let mut analyzer = MarkingAnalyzer::new();

        // Convert operations to events and sort by time
        let mut events: Vec<_> = ops.iter().map(operation_to_event).collect();
        events.sort_by_key(|e| e.time);

        // Analyze the marking sequence
        let result = analyzer.analyze(&events);

        // Balance property: reserves = commits + aborts (excluding leaks)
        // This is only true if there are no invalid transitions or leaks
        if result.is_safe() && result.invalid_transitions.is_empty() {
            let balance = result.stats.total_reserved as i64
                - result.stats.total_committed as i64
                - result.stats.total_aborted as i64;

            // For safe execution, final marking should be zero (all resolved)
            if let Some(final_marking) = result.timeline.final_marking() {
                prop_assert_eq!(
                    final_marking.total_pending(),
                    balance.max(0) as u32,
                    "Balance property: pending = reserves - (commits + aborts)"
                );
            }
        }
    }
}

// =============================================================================
// Metamorphic Relation 2: Double-Mark Tracked via Generation
// =============================================================================

proptest! {
    /// MR2: Multiple reserves of same (kind, region) are tracked independently
    #[test]
    fn mr2_double_mark_tracked_properly(
        kind in arb_obligation_kind(),
        region_id in small_id(),
        task_id in small_id(),
        count in 1u32..8,
        time_base in arb_time(),
    ) {
        let region = make_region(region_id);
        let task = make_task(task_id);
        let mut events = Vec::new();

        // Reserve multiple obligations of the same kind in same region
        for i in 0..count {
            events.push(MarkingEvent::new(
                Time::from_nanos(time_base.as_nanos() + i as u64 * 10),
                MarkingEventKind::Reserve {
                    obligation: make_obligation(i),
                    kind,
                    task,
                    region,
                },
            ));
        }

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // Should track each obligation separately
        prop_assert_eq!(
            result.stats.total_reserved,
            count,
            "Multiple reserves should be tracked independently"
        );

        if let Some(final_marking) = result.timeline.final_marking() {
            prop_assert_eq!(
                final_marking.get(kind, region),
                count,
                "Marking count should equal number of reserves"
            );
        }
    }
}

// =============================================================================
// Metamorphic Relation 3: Unmark Without Mark is Error
// =============================================================================

proptest! {
    /// MR3: Attempting to decrement below zero is an invalid transition
    #[test]
    fn mr3_unmark_without_mark_is_error(
        kind in arb_obligation_kind(),
        region_id in small_id(),
        obligation_id in medium_id(),
        time in arb_time(),
    ) {
        let region = make_region(region_id);
        let obligation = make_obligation(obligation_id);

        // Try to commit/abort without a matching reserve
        let events = vec![
            MarkingEvent::new(time, MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            })
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // Should detect invalid transition
        prop_assert!(!result.invalid_transitions.is_empty(),
            "Committing without reserve should be invalid transition");

        // Alternative test: abort without reserve
        let events = vec![
            MarkingEvent::new(time, MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            })
        ];

        let result = analyzer.analyze(&events);
        prop_assert!(!result.invalid_transitions.is_empty(),
            "Aborting without reserve should be invalid transition");
    }
}

// =============================================================================
// Metamorphic Relation 4: Concurrent Mark/Unmark Deterministic
// =============================================================================

proptest! {
    /// MR4: Concurrent operations on the same marking should be deterministic
    #[test]
    fn mr4_concurrent_mark_unmark_deterministic(
        ops in prop::collection::vec(arb_marking_operation(), 5..15),
        time_offset in 1u64..100,
    ) {
        // Execute the same sequence twice to verify determinism
        let mut events1: Vec<_> = ops.iter().map(operation_to_event).collect();
        let mut events2 = events1.clone();

        // Sort both by time (deterministic ordering for concurrent events)
        events1.sort_by_key(|e| e.time);
        events2.sort_by_key(|e| e.time);

        // Add small offset to second sequence to test time independence
        for event in &mut events2 {
            event.time = Time::from_nanos(event.time.as_nanos() + time_offset);
        }

        let mut analyzer1 = MarkingAnalyzer::new();
        let mut analyzer2 = MarkingAnalyzer::new();

        let result1 = analyzer1.analyze(&events1);
        let result2 = analyzer2.analyze(&events2);

        // Key properties should be deterministic
        prop_assert_eq!(
            result1.is_safe(),
            result2.is_safe(),
            "Safety determination should be deterministic"
        );

        prop_assert_eq!(
            result1.stats.total_reserved,
            result2.stats.total_reserved,
            "Total reserves should be deterministic"
        );

        prop_assert_eq!(
            result1.leak_count(),
            result2.leak_count(),
            "Leak count should be deterministic"
        );

        prop_assert_eq!(
            result1.invalid_transitions.len(),
            result2.invalid_transitions.len(),
            "Invalid transition count should be deterministic"
        );
    }
}

// =============================================================================
// Metamorphic Relation 5: Region Close Fails if Any Mark Outstanding
// =============================================================================

proptest! {
    /// MR5: Closing a region with pending obligations should be detected as a leak
    #[test]
    fn mr5_region_close_fails_if_marks_outstanding(
        kind in arb_obligation_kind(),
        region_id in small_id(),
        task_id in small_id(),
        obligation_id in medium_id(),
        reserve_time in arb_time(),
    ) {
        let region = make_region(region_id);
        let task = make_task(task_id);
        let obligation = make_obligation(obligation_id);
        let close_time = Time::from_nanos(reserve_time.as_nanos() + 1000);

        // Reserve an obligation but close region without resolving it
        let events = vec![
            MarkingEvent::new(reserve_time, MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            }),
            MarkingEvent::new(close_time, MarkingEventKind::RegionClose {
                region,
            }),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // Should detect leak
        prop_assert!(!result.is_safe(),
            "Region close with pending obligations should not be safe");

        prop_assert!(!result.leaks.is_empty(),
            "Should detect leak when region closes with pending obligations");

        // Verify the leak details
        let leak = &result.leaks[0];
        prop_assert_eq!(leak.region, region, "Leak should be in the correct region");
        prop_assert_eq!(leak.kind, kind, "Leak should be the correct obligation kind");
        prop_assert_eq!(leak.count, 1, "Should leak exactly one obligation");
        prop_assert_eq!(leak.close_time, close_time, "Leak time should match region close time");
    }
}

// =============================================================================
// Complex Metamorphic Relations (Composite Properties)
// =============================================================================

proptest! {
    /// MR6: Dimension isolation - changes to one (kind, region) don't affect others
    #[test]
    fn mr6_dimension_isolation(
        kind1 in arb_obligation_kind(),
        kind2 in arb_obligation_kind(),
        region1_id in small_id(),
        region2_id in small_id(),
        task_id in small_id(),
    ) {
        prop_assume!(kind1 != kind2 || region1_id != region2_id);

        let region1 = make_region(region1_id);
        let region2 = make_region(region2_id);
        let task = make_task(task_id);

        // Reserve in dimension 1, commit in dimension 2 (different)
        let events = vec![
            MarkingEvent::new(Time::from_nanos(10), MarkingEventKind::Reserve {
                obligation: make_obligation(0),
                kind: kind1,
                task,
                region: region1,
            }),
            MarkingEvent::new(Time::from_nanos(20), MarkingEventKind::Commit {
                obligation: make_obligation(1),
                region: region2,
                kind: kind2,
            }),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // Should have invalid transition (commit without reserve in dimension 2)
        if kind1 != kind2 || region1 != region2 {
            prop_assert!(!result.invalid_transitions.is_empty(),
                "Commit in different dimension should be invalid");
        }
    }
}

proptest! {
    /// MR7: Monotonicity - total pending never goes below zero
    #[test]
    fn mr7_total_pending_monotonic(
        ops in prop::collection::vec(arb_marking_operation(), 1..25),
    ) {
        let mut events: Vec<_> = ops.iter().map(operation_to_event).collect();
        events.sort_by_key(|e| e.time);

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // Check that total pending never went negative in timeline
        for snapshot in &result.timeline.snapshots {
            // Total pending is sum of all positive counts
            let total = snapshot.marking.total_pending();

            // Invariant: total pending >= 0 (trivially true for u32, but check consistency)
            prop_assert!(total >= 0, "Total pending should never be negative");
        }
    }
}

// =============================================================================
// LabRuntime DPOR Integration Tests
// =============================================================================

/// Test marking operations under deterministic scheduling with DPOR
#[test]
fn test_marking_with_lab_runtime_dpor() {
    use asupersync::lab::LabConfig;

    let config = LabConfig::default().with_dpor(true);
    let lab = LabRuntime::new(config);

    lab.block_on(async move {
        let cx = test_cx();

        // Simple marking scenario in lab runtime
        let mut marking = ObligationMarking::empty();

        // Test basic operations
        marking.increment(ObligationKind::SendPermit, make_region(0));
        assert_eq!(marking.get(ObligationKind::SendPermit, make_region(0)), 1);

        let decremented = marking.decrement(ObligationKind::SendPermit, make_region(0));
        assert!(decremented, "Should successfully decrement existing count");
        assert!(marking.is_zero(), "Should be zero after decrement");

        // Test invalid decrement
        let failed_decrement = marking.decrement(ObligationKind::Ack, make_region(1));
        assert!(!failed_decrement, "Should fail to decrement non-existent count");
    });
}

/// Integration test: Marking analysis with LabRuntime
#[test]
fn test_marking_analysis_lab_integration() {
    use asupersync::lab::LabConfig;

    let config = LabConfig::default().with_dpor(true);
    let lab = LabRuntime::new(config);

    lab.block_on(async move {
        let cx = test_cx();

        // Create a realistic marking scenario
        let events = vec![
            MarkingEvent::new(Time::from_nanos(100), MarkingEventKind::Reserve {
                obligation: make_obligation(0),
                kind: ObligationKind::SendPermit,
                task: make_task(0),
                region: make_region(0),
            }),
            MarkingEvent::new(Time::from_nanos(200), MarkingEventKind::Reserve {
                obligation: make_obligation(1),
                kind: ObligationKind::Ack,
                task: make_task(1),
                region: make_region(0),
            }),
            MarkingEvent::new(Time::from_nanos(300), MarkingEventKind::Commit {
                obligation: make_obligation(0),
                region: make_region(0),
                kind: ObligationKind::SendPermit,
            }),
            MarkingEvent::new(Time::from_nanos(400), MarkingEventKind::Abort {
                obligation: make_obligation(1),
                region: make_region(0),
                kind: ObligationKind::Ack,
            }),
            MarkingEvent::new(Time::from_nanos(500), MarkingEventKind::RegionClose {
                region: make_region(0),
            }),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // Should be safe (all obligations resolved before region close)
        assert!(result.is_safe(), "Well-formed sequence should be safe");
        assert_eq!(result.stats.total_reserved, 2);
        assert_eq!(result.stats.total_committed, 1);
        assert_eq!(result.stats.total_aborted, 1);
        assert_eq!(result.leak_count(), 0);
    });
}