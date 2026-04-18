//! Metamorphic tests for obligation separation logic frame rule invariants.
//!
//! Tests the 5 core metamorphic relations for separation logic frame rules:
//! 1. Frame rule preserves disjoint resources - operations don't affect unrelated obligations
//! 2. Heap merging commutative - combining heap states is order-independent
//! 3. Assertion validity through composition - valid predicates compose to valid states
//! 4. Cancel preserves separation - cancellation maintains separation properties
//! 5. Concurrent modification of disjoint heaps independent - parallel ops on disjoint heaps commute
//!
//! Uses LabRuntime for deterministic property-based testing with separation logic verifier.

use asupersync::lab::runtime::LabRuntime;
use asupersync::obligation::separation_logic::{
    SeparationLogicVerifier, ResourcePredicate, FrameCondition, SeparationProperty,
    OperationFootprint, Excl, Agree, AuthNat,
};
use asupersync::obligation::marking::{MarkingEvent, MarkingEventKind};
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of obligations in test scenarios
const MAX_OBLIGATIONS: usize = 10;

/// Maximum time value for deterministic testing
const MAX_TIME_NS: u64 = 1_000_000;

/// Strategy for generating obligation IDs
fn obligation_id_strategy() -> impl Strategy<Value = ObligationId> {
    (0u32..MAX_OBLIGATIONS as u32, 0u32..10).prop_map(|(gen, slot)| {
        ObligationId::new_for_test(gen, slot)
    })
}

/// Strategy for generating region IDs
fn region_id_strategy() -> impl Strategy<Value = RegionId> {
    (0u32..5, 0u32..10).prop_map(|(gen, slot)| {
        RegionId::new_for_test(gen, slot)
    })
}

/// Strategy for generating task IDs
fn task_id_strategy() -> impl Strategy<Value = TaskId> {
    (0u32..5, 0u32..10).prop_map(|(gen, slot)| {
        TaskId::new_for_test(gen, slot)
    })
}

/// Strategy for generating obligation kinds
fn obligation_kind_strategy() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
    ]
}

/// Strategy for generating time values
fn time_strategy() -> impl Strategy<Value = Time> {
    (0u64..MAX_TIME_NS).prop_map(Time::from_nanos)
}

/// Configuration for a separation logic test scenario
#[derive(Debug, Clone)]
struct SeparationTestScenario {
    obligations: Vec<ObligationConfig>,
    disjoint_regions: Vec<RegionId>,
    event_sequence: Vec<TestEvent>,
}

/// Configuration for individual obligations in test
#[derive(Debug, Clone)]
struct ObligationConfig {
    id: ObligationId,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    reserve_time: Time,
}

/// Test events for building marking event sequences
#[derive(Debug, Clone)]
enum TestEvent {
    Reserve { obligation: ObligationId },
    Commit { obligation: ObligationId },
    Abort { obligation: ObligationId },
    RegionClose { region: RegionId },
}

/// Helper to create marking events from obligation config and test events
struct MarkingEventBuilder;

impl MarkingEventBuilder {
    fn build_events(
        scenario: &SeparationTestScenario,
    ) -> Vec<MarkingEvent> {
        let obligation_map: BTreeMap<ObligationId, &ObligationConfig> =
            scenario.obligations.iter().map(|o| (o.id, o)).collect();

        let mut events = Vec::new();

        for test_event in &scenario.event_sequence {
            match test_event {
                TestEvent::Reserve { obligation } => {
                    if let Some(config) = obligation_map.get(obligation) {
                        events.push(MarkingEvent::new(
                            config.reserve_time,
                            MarkingEventKind::Reserve {
                                obligation: config.id,
                                kind: config.kind,
                                task: config.holder,
                                region: config.region,
                            },
                        ));
                    }
                }
                TestEvent::Commit { obligation } => {
                    if let Some(config) = obligation_map.get(obligation) {
                        events.push(MarkingEvent::new(
                            config.reserve_time + Time::from_nanos(100),
                            MarkingEventKind::Commit {
                                obligation: config.id,
                                region: config.region,
                                kind: config.kind,
                            },
                        ));
                    }
                }
                TestEvent::Abort { obligation } => {
                    if let Some(config) = obligation_map.get(obligation) {
                        events.push(MarkingEvent::new(
                            config.reserve_time + Time::from_nanos(100),
                            MarkingEventKind::Abort {
                                obligation: config.id,
                                region: config.region,
                                kind: config.kind,
                            },
                        ));
                    }
                }
                TestEvent::RegionClose { region } => {
                    events.push(MarkingEvent::new(
                        Time::from_nanos(MAX_TIME_NS - 1000),
                        MarkingEventKind::RegionClose { region: *region },
                    ));
                }
            }
        }

        // Sort events by time to ensure proper ordering
        events.sort_by_key(|e| e.time);
        events
    }
}

/// Strategy for generating separation test scenarios
fn separation_scenario_strategy() -> impl Strategy<Value = SeparationTestScenario> {
    (
        prop::collection::vec(
            (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy(), time_strategy()),
            1..=5
        ),
        prop::collection::vec(region_id_strategy(), 1..=3),
        prop::collection::vec(
            prop_oneof![
                obligation_id_strategy().prop_map(|o| TestEvent::Reserve { obligation: o }),
                obligation_id_strategy().prop_map(|o| TestEvent::Commit { obligation: o }),
                obligation_id_strategy().prop_map(|o| TestEvent::Abort { obligation: o }),
                region_id_strategy().prop_map(|r| TestEvent::RegionClose { region: r }),
            ],
            2..=8
        )
    ).prop_map(|(obligation_configs, regions, events)| {
        let obligations = obligation_configs
            .into_iter()
            .enumerate()
            .map(|(i, (id, kind, holder, region, time))| ObligationConfig {
                id: ObligationId::new_for_test(i as u32, 0),
                kind,
                holder,
                region,
                reserve_time: time,
            })
            .collect();

        SeparationTestScenario {
            obligations,
            disjoint_regions: regions,
            event_sequence: events,
        }
    })
}

/// MR1: Frame rule preserves disjoint resources
#[test]
fn mr_frame_rule_preserves_disjoint_resources() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(scenario in separation_scenario_strategy())| {
        runtime.block_on(&cx, async {
            // Property: Operations on one obligation should not affect unrelated obligations
            // Frame rule: {P * F} op {Q * F} where F represents disjoint resources

            if scenario.obligations.len() < 2 {
                return Ok(());
            }

            let events = MarkingEventBuilder::build_events(&scenario);
            if events.is_empty() {
                return Ok(());
            }

            let mut verifier = SeparationLogicVerifier::new();
            let result = verifier.verify(&events);

            // Check that frame conditions are preserved for disjoint obligations
            for i in 0..scenario.obligations.len() {
                for j in (i + 1)..scenario.obligations.len() {
                    let obl1 = &scenario.obligations[i];
                    let obl2 = &scenario.obligations[j];

                    // If obligations are truly disjoint (different IDs)
                    if obl1.id != obl2.id {
                        // Create resource predicates for both obligations
                        let pred1 = ResourcePredicate::reserved(obl1.id, obl1.kind, obl1.holder, obl1.region);
                        let pred2 = ResourcePredicate::reserved(obl2.id, obl2.kind, obl2.holder, obl2.region);

                        // They should be separable (frame condition preserved)
                        prop_assert!(pred1.is_separable_from(&pred2),
                            "Distinct obligations {:?} and {:?} should be separable (frame preserved)",
                            obl1.id, obl2.id);

                        // Frame condition should mark them as framed from each other
                        let frame1 = FrameCondition::single_obligation(obl1.id, obl1.holder, obl1.region);
                        let frame2 = FrameCondition::single_obligation(obl2.id, obl2.holder, obl2.region);

                        prop_assert!(frame1.is_framed(obl2.id),
                            "Obligation {:?} should be framed from operations on {:?}",
                            obl2.id, obl1.id);

                        prop_assert!(frame2.is_framed(obl1.id),
                            "Obligation {:?} should be framed from operations on {:?}",
                            obl1.id, obl2.id);
                    }
                }
            }

            // Verify no aliasing violations occurred (frame preservation)
            let aliasing_violations = result.violations_for_property(|prop| {
                matches!(prop, SeparationProperty::NoAliasing { .. })
            }).count();

            prop_assert_eq!(aliasing_violations, 0,
                "Frame rule violation: {} aliasing violations detected", aliasing_violations);
        }).await;
    });
}

/// MR2: Heap merging commutative
#[test]
fn mr_heap_merging_commutative() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        obl1 in (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy()),
        obl2 in (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy()),
        time1 in time_strategy(),
        time2 in time_strategy(),
    )| {
        runtime.block_on(&cx, async {
            // Property: Combining heap states should be commutative
            // H1 * H2 = H2 * H1 (separating conjunction is commutative)

            let (id1, kind1, holder1, region1) = obl1;
            let (id2, kind2, holder2, region2) = obl2;

            // Ensure different obligation IDs for valid separation
            if id1 == id2 {
                return Ok(());
            }

            // Create resource predicates for both heap states
            let pred1 = ResourcePredicate::reserved(id1, kind1, holder1, region1);
            let pred2 = ResourcePredicate::reserved(id2, kind2, holder2, region2);

            // Test commutative composition via exclusive resource algebra
            let state1_excl = Excl::Some(ObligationState::Reserved);
            let state2_excl = Excl::Some(ObligationState::Reserved);

            // Test agreement composition for kinds
            let kind1_agree = Agree(kind1);
            let kind2_agree = Agree(kind2);

            // Resource algebra composition should be commutative for disjoint elements
            // Since these are different obligations, Excl composition with Consumed works
            let consumed = Excl::Consumed;

            // Test commutativity: composed_left should equal composed_right
            let composed_left = state1_excl.compose(&consumed);
            let composed_right = consumed.compose(&state1_excl);

            prop_assert_eq!(composed_left, composed_right,
                "Excl resource composition should be commutative");

            // Test AuthNat fragment composition commutativity
            let frag1 = AuthNat::Frag(1);
            let frag2 = AuthNat::Frag(2);

            let auth_left = frag1.compose(&frag2);
            let auth_right = frag2.compose(&frag1);

            prop_assert_eq!(auth_left, auth_right,
                "AuthNat fragment composition should be commutative");

            // Test agreement composition commutativity for same values
            if kind1 == kind2 {
                let agree_left = kind1_agree.compose(&kind2_agree);
                let agree_right = kind2_agree.compose(&kind1_agree);
                prop_assert_eq!(agree_left, agree_right,
                    "Agree composition should be commutative for equal values");
            }

            // Verify separation is symmetric
            let sep_left_right = pred1.is_separable_from(&pred2);
            let sep_right_left = pred2.is_separable_from(&pred1);

            prop_assert_eq!(sep_left_right, sep_right_left,
                "Separation should be symmetric (commutative)");
        }).await;
    });
}

/// MR3: Assertion validity through composition
#[test]
fn mr_assertion_validity_through_composition() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        obligations in prop::collection::vec(
            (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy()),
            1..=4
        ),
    )| {
        runtime.block_on(&cx, async {
            // Property: Composing valid resource predicates should remain valid
            // Valid(P) ∧ Valid(Q) ∧ Separable(P,Q) → Valid(P * Q)

            if obligations.is_empty() {
                return Ok(());
            }

            let mut predicates = Vec::new();
            let mut used_ids = BTreeSet::new();

            // Create valid predicates for distinct obligations
            for (id, kind, holder, region) in obligations {
                if !used_ids.contains(&id) {
                    used_ids.insert(id);
                    predicates.push(ResourcePredicate::reserved(id, kind, holder, region));
                }
            }

            if predicates.len() < 2 {
                return Ok(());
            }

            // Test pairwise separability of all valid predicates
            for i in 0..predicates.len() {
                for j in (i + 1)..predicates.len() {
                    let pred_i = &predicates[i];
                    let pred_j = &predicates[j];

                    // Individual predicates are valid by construction (reserved state)
                    prop_assert!(matches!(pred_i.state, Excl::Some(ObligationState::Reserved)),
                        "Individual predicate {} should be valid", i);

                    prop_assert!(matches!(pred_j.state, Excl::Some(ObligationState::Reserved)),
                        "Individual predicate {} should be valid", j);

                    // Different obligations should be separable
                    prop_assert!(pred_i.is_separable_from(pred_j),
                        "Valid predicates {:?} and {:?} should be separable",
                        pred_i.obligation, pred_j.obligation);

                    // Composition should preserve validity (no resource conflicts)
                    // Test the underlying resource algebra elements
                    let holder_frag_i = &pred_i.holder_pending_frag;
                    let holder_frag_j = &pred_j.holder_pending_frag;

                    if pred_i.holder.0 == pred_j.holder.0 {
                        // Same holder - fragments should compose
                        let composed = holder_frag_i.compose(holder_frag_j);
                        prop_assert!(composed.is_some(),
                            "Holder fragments for same holder should compose validly");
                    }

                    // Agreement elements should compose for equal values
                    if pred_i.kind.0 == pred_j.kind.0 {
                        let kind_composed = pred_i.kind.compose(&pred_j.kind);
                        prop_assert!(kind_composed.is_some(),
                            "Kind agreement should compose for equal kinds");
                    }
                }
            }

            // Test that a sequence of valid operations maintains validity
            let mut events = Vec::new();
            let mut time_offset = 0u64;

            for pred in &predicates {
                events.push(MarkingEvent::new(
                    Time::from_nanos(time_offset),
                    MarkingEventKind::Reserve {
                        obligation: pred.obligation,
                        kind: pred.kind.0,
                        task: pred.holder.0,
                        region: pred.region.0,
                    },
                ));
                time_offset += 100;
            }

            let mut verifier = SeparationLogicVerifier::new();
            let result = verifier.verify(&events);

            // Composing valid predicates should not create violations
            prop_assert!(result.is_sound(),
                "Composition of valid predicates should remain sound, but got {} violations",
                result.violations.len());
        }).await;
    });
}

/// MR4: Cancel preserves separation
#[test]
fn mr_cancel_preserves_separation() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        obligations in prop::collection::vec(
            (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy()),
            2..=4
        ),
        abort_indices in prop::collection::vec(0usize..4, 1..=2),
    )| {
        runtime.block_on(&cx, async {
            // Property: Cancellation (abort) should preserve separation properties
            // If P * Q was separable before cancel, remaining heap should maintain separation

            if obligations.len() < 2 {
                return Ok(());
            }

            let mut distinct_obligations = Vec::new();
            let mut used_ids = BTreeSet::new();

            for (id, kind, holder, region) in obligations {
                if !used_ids.contains(&id) {
                    used_ids.insert(id);
                    distinct_obligations.push((id, kind, holder, region));
                }
            }

            if distinct_obligations.len() < 2 {
                return Ok(());
            }

            // Create initial events (all reserves)
            let mut events = Vec::new();
            for (i, (id, kind, holder, region)) in distinct_obligations.iter().enumerate() {
                events.push(MarkingEvent::new(
                    Time::from_nanos(i as u64 * 100),
                    MarkingEventKind::Reserve {
                        obligation: *id,
                        kind: *kind,
                        task: *holder,
                        region: *region,
                    },
                ));
            }

            // Add abort events for some obligations
            for &abort_idx in &abort_indices {
                if abort_idx < distinct_obligations.len() {
                    let (id, kind, _holder, region) = distinct_obligations[abort_idx];
                    events.push(MarkingEvent::new(
                        Time::from_nanos(1000 + abort_idx as u64 * 100),
                        MarkingEventKind::Abort {
                            obligation: id,
                            region,
                            kind,
                        },
                    ));
                }
            }

            events.sort_by_key(|e| e.time);

            let mut verifier = SeparationLogicVerifier::new();
            let result = verifier.verify(&events);

            // Check that remaining obligations maintain separation
            // No aliasing should occur from cancellation
            let aliasing_violations = result.violations_for_property(|prop| {
                matches!(prop, SeparationProperty::NoAliasing { .. })
            }).count();

            prop_assert_eq!(aliasing_violations, 0,
                "Cancel should not introduce aliasing violations");

            // No use-after-release should occur
            let use_after_release_violations = result.violations_for_property(|prop| {
                matches!(prop, SeparationProperty::NoUseAfterRelease { .. })
            }).count();

            prop_assert_eq!(use_after_release_violations, 0,
                "Cancel should not introduce use-after-release violations");

            // Distinct identity should be preserved among remaining obligations
            let distinct_violations = result.violations_for_property(|prop| {
                matches!(prop, SeparationProperty::DistinctIdentity { .. })
            }).count();

            prop_assert_eq!(distinct_violations, 0,
                "Cancel should preserve distinct identity invariant");

            // Test that remaining obligations are still separable
            let remaining_obligations: Vec<_> = distinct_obligations
                .iter()
                .enumerate()
                .filter(|(i, _)| !abort_indices.contains(i))
                .map(|(_, obl)| obl)
                .collect();

            for i in 0..remaining_obligations.len() {
                for j in (i + 1)..remaining_obligations.len() {
                    let (id1, kind1, holder1, region1) = remaining_obligations[i];
                    let (id2, kind2, holder2, region2) = remaining_obligations[j];

                    let pred1 = ResourcePredicate::reserved(*id1, *kind1, *holder1, *region1);
                    let pred2 = ResourcePredicate::reserved(*id2, *kind2, *holder2, *region2);

                    prop_assert!(pred1.is_separable_from(&pred2),
                        "Remaining obligations {:?} and {:?} should still be separable after cancellation",
                        id1, id2);
                }
            }
        }).await;
    });
}

/// MR5: Concurrent modification of disjoint heaps independent
#[test]
fn mr_concurrent_modification_disjoint_heaps_independent() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        heap1_operations in prop::collection::vec(
            (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy()),
            1..=3
        ),
        heap2_operations in prop::collection::vec(
            (obligation_id_strategy(), obligation_kind_strategy(), task_id_strategy(), region_id_strategy()),
            1..=3
        ),
        interleaving in prop::bool(),
    )| {
        runtime.block_on(&cx, async {
            // Property: Concurrent operations on disjoint heaps should be independent
            // If H1 ⊥ H2 (disjoint), then op1(H1) || op2(H2) = op2(H2) || op1(H1)

            // Ensure heaps are truly disjoint (no shared obligation IDs)
            let heap1_ids: BTreeSet<_> = heap1_operations.iter().map(|(id, _, _, _)| *id).collect();
            let heap2_ids: BTreeSet<_> = heap2_operations.iter().map(|(id, _, _, _)| *id).collect();

            // Skip if heaps share obligation IDs (not disjoint)
            if heap1_ids.intersection(&heap2_ids).next().is_some() {
                return Ok(());
            }

            if heap1_operations.is_empty() || heap2_operations.is_empty() {
                return Ok(());
            }

            // Create two orderings: heap1 first, then heap2 second
            let mut events_order1 = Vec::new();
            let mut events_order2 = Vec::new();

            let mut time_offset = 0u64;

            // Order 1: All heap1 operations, then all heap2 operations
            for (id, kind, holder, region) in &heap1_operations {
                events_order1.push(MarkingEvent::new(
                    Time::from_nanos(time_offset),
                    MarkingEventKind::Reserve {
                        obligation: *id,
                        kind: *kind,
                        task: *holder,
                        region: *region,
                    },
                ));
                time_offset += 100;
            }

            for (id, kind, holder, region) in &heap2_operations {
                events_order1.push(MarkingEvent::new(
                    Time::from_nanos(time_offset),
                    MarkingEventKind::Reserve {
                        obligation: *id,
                        kind: *kind,
                        task: *holder,
                        region: *region,
                    },
                ));
                time_offset += 100;
            }

            // Order 2: All heap2 operations, then all heap1 operations
            time_offset = 0;
            for (id, kind, holder, region) in &heap2_operations {
                events_order2.push(MarkingEvent::new(
                    Time::from_nanos(time_offset),
                    MarkingEventKind::Reserve {
                        obligation: *id,
                        kind: *kind,
                        task: *holder,
                        region: *region,
                    },
                ));
                time_offset += 100;
            }

            for (id, kind, holder, region) in &heap1_operations {
                events_order2.push(MarkingEvent::new(
                    Time::from_nanos(time_offset),
                    MarkingEventKind::Reserve {
                        obligation: *id,
                        kind: *kind,
                        task: *holder,
                        region: *region,
                    },
                ));
                time_offset += 100;
            }

            // Verify both orderings
            let mut verifier1 = SeparationLogicVerifier::new();
            let result1 = verifier1.verify(&events_order1);

            let mut verifier2 = SeparationLogicVerifier::new();
            let result2 = verifier2.verify(&events_order2);

            // Both orderings should have the same soundness
            prop_assert_eq!(result1.is_sound(), result2.is_sound(),
                "Disjoint heap operations should have same soundness regardless of ordering");

            // Both should have same number of violations (should be none for disjoint heaps)
            prop_assert_eq!(result1.violations.len(), result2.violations.len(),
                "Disjoint heap operations should produce same number of violations");

            // Both should verify the same number of events
            prop_assert_eq!(result1.events_checked, result2.events_checked,
                "Both orderings should check same number of events");

            // Test frame conditions are independent
            for heap1_obl in &heap1_operations {
                for heap2_obl in &heap2_operations {
                    let frame1 = FrameCondition::single_obligation(
                        heap1_obl.0, heap1_obl.2, heap1_obl.3
                    );
                    let frame2 = FrameCondition::single_obligation(
                        heap2_obl.0, heap2_obl.2, heap2_obl.3
                    );

                    // Operations should be framed from each other
                    prop_assert!(frame1.is_framed(heap2_obl.0),
                        "Heap1 operations should be framed from heap2 obligation {:?}",
                        heap2_obl.0);

                    prop_assert!(frame2.is_framed(heap1_obl.0),
                        "Heap2 operations should be framed from heap1 obligation {:?}",
                        heap1_obl.0);
                }
            }
        }).await;
    });
}

/// Integration test: Combined separation logic properties
#[test]
fn mr_combined_separation_properties() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(scenario in separation_scenario_strategy())| {
        runtime.block_on(&cx, async {
            // Property: All separation logic metamorphic relations should hold simultaneously

            if scenario.obligations.len() < 2 {
                return Ok(());
            }

            let events = MarkingEventBuilder::build_events(&scenario);
            if events.is_empty() {
                return Ok(());
            }

            let mut verifier = SeparationLogicVerifier::new();
            let result = verifier.verify(&events);

            // Check all separation properties
            for i in 0..scenario.obligations.len() {
                for j in (i + 1)..scenario.obligations.len() {
                    let obl1 = &scenario.obligations[i];
                    let obl2 = &scenario.obligations[j];

                    if obl1.id != obl2.id {
                        // MR1: Frame rule preservation
                        let pred1 = ResourcePredicate::reserved(obl1.id, obl1.kind, obl1.holder, obl1.region);
                        let pred2 = ResourcePredicate::reserved(obl2.id, obl2.kind, obl2.holder, obl2.region);

                        prop_assert!(pred1.is_separable_from(&pred2),
                            "Distinct obligations should maintain separation");

                        // MR2: Heap merging commutativity
                        let sep_left_right = pred1.is_separable_from(&pred2);
                        let sep_right_left = pred2.is_separable_from(&pred1);
                        prop_assert_eq!(sep_left_right, sep_right_left,
                            "Separation should be commutative");

                        // MR3: Assertion validity
                        prop_assert!(matches!(pred1.state, Excl::Some(ObligationState::Reserved)),
                            "Resource predicates should be valid");
                        prop_assert!(matches!(pred2.state, Excl::Some(ObligationState::Reserved)),
                            "Resource predicates should be valid");
                    }
                }
            }

            // MR4 & MR5: No violations should occur for proper separation
            prop_assert!(result.violations_for_property(|prop| {
                matches!(prop, SeparationProperty::NoAliasing { .. })
            }).count() == 0, "No aliasing violations expected");

            prop_assert!(result.violations_for_property(|prop| {
                matches!(prop, SeparationProperty::NoUseAfterRelease { .. })
            }).count() == 0, "No use-after-release violations expected");
        }).await;
    });
}

#[cfg(test)]
mod property_validation {
    use super::*;

    /// Verify test framework setup
    #[test]
    fn test_framework_validation() {
        let runtime = LabRuntime::new(LabConfig::default());
        let cx = runtime.cx();

        runtime.block_on(&cx, async {
            // Test basic resource predicate creation
            let obl_id = ObligationId::new_for_test(0, 0);
            let task_id = TaskId::new_for_test(0, 0);
            let region_id = RegionId::new_for_test(0, 0);

            let pred = ResourcePredicate::reserved(
                obl_id,
                ObligationKind::SendPermit,
                task_id,
                region_id
            );

            assert!(matches!(pred.state, Excl::Some(ObligationState::Reserved)));
            assert_eq!(pred.kind.0, ObligationKind::SendPermit);
            assert_eq!(pred.holder.0, task_id);
            assert_eq!(pred.region.0, region_id);

            // Test separation
            let obl_id2 = ObligationId::new_for_test(1, 0);
            let pred2 = ResourcePredicate::reserved(
                obl_id2,
                ObligationKind::Ack,
                task_id,
                region_id
            );

            assert!(pred.is_separable_from(&pred2));

            // Test verifier basic functionality
            let mut verifier = SeparationLogicVerifier::new();
            let events = vec![
                MarkingEvent::new(Time::ZERO, MarkingEventKind::Reserve {
                    obligation: obl_id,
                    kind: ObligationKind::SendPermit,
                    task: task_id,
                    region: region_id,
                }),
            ];

            let result = verifier.verify(&events);
            assert!(result.is_sound());
            assert_eq!(result.events_checked, 1);
        }).await;
    }
}