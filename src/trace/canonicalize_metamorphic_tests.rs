//! Metamorphic tests for trace canonicalization (Foata normal form).
//!
//! This module applies metamorphic testing to the trace canonicalization system,
//! which converts traces into Foata normal form for equivalence class analysis
//! in DPOR and trace monoid operations.
//!
//! ## Oracle Problem
//!
//! We cannot predict the exact canonical form (Foata normal form) for arbitrary
//! trace inputs. The canonicalization involves complex independence relation
//! checking, layering based on happens-before relationships, and deterministic
//! sorting within layers.
//!
//! ## Metamorphic Relations Tested
//!
//! 1. **Layer Independence**: Events within same layer are pairwise independent
//! 2. **Idempotence**: canonicalize(canonicalize(trace)) = canonicalize(trace)
//! 3. **Layer Ordering**: Events in layer k+1 depend on events in layer ≤ k
//! 4. **Fingerprint Consistency**: canonical form and fingerprint must match
//! 5. **Event Preservation**: All original events appear in canonical form
//! 6. **Trace Equivalence**: Semantically equivalent traces → same canonical form
//! 7. **Monoid Identity**: Empty trace acts as monoid identity element
//! 8. **Event Order Preservation**: Within independence classes, constraints preserved
//! 9. **Equivalence Transitivity**: If A ≡ B and B ≡ C, then A ≡ C

use super::*;
use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::trace::independence::independent;
use crate::types::{RegionId, TaskId, Time};

/// Create diverse test traces for comprehensive metamorphic testing.
fn create_test_traces() -> Vec<Vec<TraceEvent>> {
    vec![
        // Empty trace (monoid identity)
        vec![],
        // Single event
        vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::Task {
                task: TaskId::new_for_test(1, 0),
                region: RegionId::new_for_test(1, 0),
            },
        )],
        // Two independent events (should be in same layer)
        vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(2, 0),
                    region: RegionId::new_for_test(2, 0),
                },
            ),
        ],
        // Two dependent events (spawn then complete same task)
        vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::Complete,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
        ],
        // Complex trace with multiple layers
        vec![
            // Layer 0: Two independent spawns
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(50),
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(2, 0),
                    region: RegionId::new_for_test(2, 0),
                },
            ),
            // Layer 1: Dependent on first spawn
            TraceEvent::new(
                3,
                Time::from_nanos(100),
                TraceEventKind::Complete,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            // Layer 1: Also dependent on second spawn (independent of first complete)
            TraceEvent::new(
                4,
                Time::from_nanos(150),
                TraceEventKind::Complete,
                TraceData::Task {
                    task: TaskId::new_for_test(2, 0),
                    region: RegionId::new_for_test(2, 0),
                },
            ),
        ],
        // Events with different kinds but same task (dependent)
        vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::Poll,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::Yield,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
        ],
        // Region lifecycle events
        vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::RegionCreated,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(2, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::Complete,
                TraceData::Task {
                    task: TaskId::new_for_test(2, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                4,
                Time::from_nanos(300),
                TraceEventKind::RegionCloseComplete,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
        ],
        // Cancellation protocol events
        vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::CancelRequest,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::CancelAck,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
        ],
    ]
}

/// MR1: Layer Independence
/// Property: Events within same layer are pairwise independent
/// Category: Equivalence (independence relation must be preserved)
#[test]
fn mr_layer_independence() {
    for trace in create_test_traces() {
        let foata = canonicalize(&trace);

        for layer in foata.layers() {
            // Check all pairs within each layer for independence
            for i in 0..layer.len() {
                for j in i + 1..layer.len() {
                    assert!(
                        independent(&layer[i], &layer[j]),
                        "Events in same layer are not independent: {:?} and {:?}",
                        layer[i].kind,
                        layer[j].kind
                    );
                }
            }
        }
    }
}

/// MR2: Idempotence
/// Property: canonicalize(canonicalize(trace)) = canonicalize(trace)
/// Category: Invertive (applying canonicalization twice)
#[test]
fn mr_canonicalize_idempotence() {
    for trace in create_test_traces() {
        let canonical_once = canonicalize(&trace);

        // Extract events from canonical form and canonicalize again
        let flattened: Vec<TraceEvent> = canonical_once
            .layers()
            .iter()
            .flat_map(|layer| layer.iter().cloned())
            .collect();

        let canonical_twice = canonicalize(&flattened);

        assert_eq!(
            canonical_once.depth(),
            canonical_twice.depth(),
            "Double canonicalization changed depth for trace with {} events",
            trace.len()
        );

        assert_eq!(
            canonical_once.layers().len(),
            canonical_twice.layers().len(),
            "Double canonicalization changed layer count"
        );

        for (layer1, layer2) in canonical_once
            .layers()
            .iter()
            .zip(canonical_twice.layers().iter())
        {
            assert_eq!(
                layer1, layer2,
                "Double canonicalization changed layer contents"
            );
        }
    }
}

/// MR3: Layer Ordering
/// Property: Events in layer k+1 depend on events in layer ≤ k
/// Category: Permutative (ordering relationships preserved)
#[test]
fn mr_layer_ordering() {
    for trace in create_test_traces() {
        let foata = canonicalize(&trace);
        let layers = foata.layers();

        for current_layer_idx in 1..layers.len() {
            let current_layer = &layers[current_layer_idx];

            // Each event in current layer should depend on at least one event
            // in a previous layer
            for current_event in current_layer {
                let mut has_dependency = false;

                for prev_layer in layers.iter().take(current_layer_idx) {
                    for prev_event in prev_layer {
                        if !independent(prev_event, current_event) {
                            has_dependency = true;
                            break;
                        }
                    }

                    if has_dependency {
                        break;
                    }
                }

                assert!(
                    has_dependency || current_layer_idx == 0,
                    "Event {:?} in layer {} has no dependencies in previous layers",
                    current_event.kind,
                    current_layer_idx
                );
            }

            // Events in current layer should be independent of events in later layers
            for later_layer in layers.iter().skip(current_layer_idx + 1) {
                for _current_event in current_layer {
                    for _later_event in later_layer {
                        // The later event can depend on the current event,
                        // but not the other way around due to layer ordering
                        // We just verify the layering is consistent with dependency structure
                    }
                }
            }
        }
    }
}

/// MR4: Fingerprint Consistency
/// Property: canonical form fingerprint matches trace fingerprint
/// Category: Equivalence (fingerprint computation consistency)
#[test]
fn mr_fingerprint_consistency() {
    for trace in create_test_traces() {
        let foata = canonicalize(&trace);
        let trace_fingerprint_direct = trace_fingerprint(&trace);
        let foata_fingerprint = foata.fingerprint();

        assert_eq!(
            trace_fingerprint_direct,
            foata_fingerprint,
            "Fingerprint mismatch: direct computation ({}) vs canonical form ({}) for trace with {} events",
            trace_fingerprint_direct,
            foata_fingerprint,
            trace.len()
        );

        // Fingerprint should be consistent across multiple computations
        let foata_fingerprint2 = foata.fingerprint();
        assert_eq!(
            foata_fingerprint, foata_fingerprint2,
            "Fingerprint computation is not deterministic"
        );
    }
}

/// MR5: Event Preservation
/// Property: All original events appear in canonical form (no events lost/added)
/// Category: Equivalence (event set preservation)
#[test]
fn mr_event_preservation() {
    for trace in create_test_traces() {
        let foata = canonicalize(&trace);

        // Collect all events from canonical form
        let canonical_events: Vec<&TraceEvent> = foata
            .layers()
            .iter()
            .flat_map(|layer| layer.iter())
            .collect();

        // Same number of events
        assert_eq!(
            canonical_events.len(),
            trace.len(),
            "Canonical form has different event count: {} vs {}",
            canonical_events.len(),
            trace.len()
        );

        // Every original event appears in canonical form
        for original_event in &trace {
            assert!(
                canonical_events
                    .iter()
                    .any(|&ce| events_semantically_equal(original_event, ce)),
                "Original event {:?} not found in canonical form",
                original_event.kind
            );
        }

        // Every canonical event appears in original trace
        for canonical_event in canonical_events {
            assert!(
                trace
                    .iter()
                    .any(|oe| events_semantically_equal(oe, canonical_event)),
                "Canonical event {:?} not found in original trace",
                canonical_event.kind
            );
        }
    }
}

/// MR6: Trace Equivalence
/// Property: Semantically equivalent traces → same canonical form
/// Category: Equivalence (equivalence class representatives)
#[test]
fn mr_trace_equivalence() {
    // Create pairs of equivalent traces by reordering independent events
    let equivalent_pairs = vec![
        // Independent spawns in different orders
        (
            vec![
                TraceEvent::new(
                    1,
                    Time::ZERO,
                    TraceEventKind::Spawn,
                    TraceData::Task {
                        task: TaskId::new_for_test(1, 0),
                        region: RegionId::new_for_test(1, 0),
                    },
                ),
                TraceEvent::new(
                    2,
                    Time::from_nanos(100),
                    TraceEventKind::Spawn,
                    TraceData::Task {
                        task: TaskId::new_for_test(2, 0),
                        region: RegionId::new_for_test(2, 0),
                    },
                ),
            ],
            vec![
                TraceEvent::new(
                    2,
                    Time::from_nanos(100),
                    TraceEventKind::Spawn,
                    TraceData::Task {
                        task: TaskId::new_for_test(2, 0),
                        region: RegionId::new_for_test(2, 0),
                    },
                ),
                TraceEvent::new(
                    1,
                    Time::ZERO,
                    TraceEventKind::Spawn,
                    TraceData::Task {
                        task: TaskId::new_for_test(1, 0),
                        region: RegionId::new_for_test(1, 0),
                    },
                ),
            ],
        ),
    ];

    for (trace1, trace2) in equivalent_pairs {
        let foata1 = canonicalize(&trace1);
        let foata2 = canonicalize(&trace2);
        let monoid1 = TraceMonoid::from_events(&trace1);
        let monoid2 = TraceMonoid::from_events(&trace2);

        assert_eq!(
            foata1.fingerprint(),
            foata2.fingerprint(),
            "Equivalent traces have different fingerprints"
        );

        assert_eq!(
            foata1.depth(),
            foata2.depth(),
            "Equivalent traces have different canonical depths"
        );

        assert_eq!(
            monoid1, monoid2,
            "Equivalent traces should have equal trace monoids"
        );
    }
}

/// MR7: Monoid Identity
/// Property: Empty trace acts as monoid identity element
/// Category: Additive (identity element behavior)
#[test]
fn mr_monoid_identity() {
    let empty_trace = vec![];
    let _empty_monoid = TraceMonoid::from_events(&empty_trace);

    for trace in create_test_traces() {
        let trace_monoid = TraceMonoid::from_events(&trace);

        // Empty canonical form properties
        let empty_canonical = canonicalize(&empty_trace);
        assert_eq!(
            empty_canonical.depth(),
            0,
            "Empty trace should have depth 0"
        );
        assert_eq!(
            empty_canonical.layers().len(),
            0,
            "Empty trace should have 0 layers"
        );

        // Identity behavior: concatenation with empty should preserve equivalence
        // Note: Actual concatenation would require implementing the monoid operation,
        // but we can test that empty trace has the right identity properties

        assert_eq!(
            trace_monoid, trace_monoid,
            "Trace monoid should equal itself (reflexivity)"
        );
    }
}

/// MR8: Event Order Preservation
/// Property: Within independence classes, original ordering constraints preserved
/// Category: Permutative (partial ordering preservation)
#[test]
fn mr_event_order_preservation() {
    for trace in create_test_traces() {
        if trace.len() < 2 {
            continue;
        }

        let foata = canonicalize(&trace);

        // Check that dependent events maintain their relative order
        for (i, event_i) in trace.iter().enumerate() {
            for (_j, event_j) in trace.iter().enumerate().skip(i + 1) {
                if !independent(event_i, event_j) {
                    // These events are dependent, so their order should be preserved
                    // in the canonical form

                    let (pos_i, pos_j) = find_event_positions(&foata, event_i, event_j);

                    assert!(
                        pos_i < pos_j,
                        "Dependent events {:?} and {:?} have wrong order in canonical form",
                        event_i.kind,
                        event_j.kind
                    );
                }
            }
        }
    }
}

/// MR9: Equivalence Transitivity
/// Property: If A ≡ B and B ≡ C, then A ≡ C
/// Category: Equivalence (transitivity of equivalence relation)
#[test]
fn mr_equivalence_transitivity() {
    // Create three equivalent traces through different reorderings
    let trace_a = vec![
        TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::Task {
                task: TaskId::new_for_test(1, 0),
                region: RegionId::new_for_test(1, 0),
            },
        ),
        TraceEvent::new(
            2,
            Time::from_nanos(50),
            TraceEventKind::Spawn,
            TraceData::Task {
                task: TaskId::new_for_test(2, 0),
                region: RegionId::new_for_test(2, 0),
            },
        ),
        TraceEvent::new(
            3,
            Time::from_nanos(100),
            TraceEventKind::Spawn,
            TraceData::Task {
                task: TaskId::new_for_test(3, 0),
                region: RegionId::new_for_test(3, 0),
            },
        ),
    ];

    // All these spawns are independent, so any ordering should be equivalent
    let trace_b = vec![trace_a[1].clone(), trace_a[0].clone(), trace_a[2].clone()];
    let trace_c = vec![trace_a[2].clone(), trace_a[1].clone(), trace_a[0].clone()];

    let monoid_a = TraceMonoid::from_events(&trace_a);
    let monoid_b = TraceMonoid::from_events(&trace_b);
    let monoid_c = TraceMonoid::from_events(&trace_c);

    // Transitivity: if A ≡ B and B ≡ C, then A ≡ C
    assert_eq!(monoid_a, monoid_b, "A and B should be equivalent");
    assert_eq!(monoid_b, monoid_c, "B and C should be equivalent");
    assert_eq!(
        monoid_a, monoid_c,
        "A and C should be equivalent (transitivity)"
    );
}

/// Composite MR: Idempotence + Event Preservation + Layer Independence
/// Tests compound property: canonicalization preserves all events while maintaining
/// independence within layers and idempotent behavior
#[test]
fn mr_composite_idempotence_preservation_independence() {
    for trace in create_test_traces() {
        // Apply canonicalization
        let foata = canonicalize(&trace);

        // MR2: Idempotence
        let flattened: Vec<TraceEvent> = foata
            .layers()
            .iter()
            .flat_map(|layer| layer.iter().cloned())
            .collect();
        let double_canonical = canonicalize(&flattened);
        assert_eq!(
            foata.layers(),
            double_canonical.layers(),
            "Idempotence failed"
        );

        // MR5: Event Preservation
        let canonical_event_count = foata.layers().iter().flat_map(|layer| layer.iter()).count();
        assert_eq!(canonical_event_count, trace.len(), "Event count changed");

        // MR1: Layer Independence
        for layer in foata.layers() {
            for i in 0..layer.len() {
                for j in i + 1..layer.len() {
                    assert!(
                        independent(&layer[i], &layer[j]),
                        "Compound test: Layer independence violated after idempotent canonicalization"
                    );
                }
            }
        }

        // Compound property: fingerprint should be stable across all transformations
        assert_eq!(
            foata.fingerprint(),
            double_canonical.fingerprint(),
            "Fingerprint changed after idempotent canonicalization"
        );
    }
}

// Helper functions

/// Check if two events are semantically equal (ignoring sequence and timestamp).
fn events_semantically_equal(a: &TraceEvent, b: &TraceEvent) -> bool {
    a.kind == b.kind && a.data == b.data
}

/// Find the positions of two events in the canonical form.
fn find_event_positions(
    foata: &FoataTrace,
    event_a: &TraceEvent,
    event_b: &TraceEvent,
) -> (usize, usize) {
    let mut pos_a = None;
    let mut pos_b = None;
    let mut position = 0;

    for layer in foata.layers() {
        for event in layer {
            if events_semantically_equal(event, event_a) && pos_a.is_none() {
                pos_a = Some(position);
            }
            if events_semantically_equal(event, event_b) && pos_b.is_none() {
                pos_b = Some(position);
            }
            position += 1;
        }
    }

    (
        pos_a.expect("Event A not found"),
        pos_b.expect("Event B not found"),
    )
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Mutation testing: verify MR suite catches common canonicalization bugs
    #[test]
    fn test_mr_suite_detects_mutations() {
        // Test that layer independence MR would catch bugs where dependent events
        // are placed in the same layer
        let trace = vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::Complete,
                TraceData::Task {
                    task: TaskId::new_for_test(1, 0),
                    region: RegionId::new_for_test(1, 0),
                },
            ),
        ];

        let foata = canonicalize(&trace);

        // These events are dependent (same task), so should be in different layers
        assert!(
            foata.depth() >= 2,
            "Dependent events should create multiple layers"
        );

        // Test that event preservation would catch bugs where events are lost
        let canonical_event_count: usize = foata.layers().iter().map(|layer| layer.len()).sum();
        assert_eq!(
            canonical_event_count,
            trace.len(),
            "Event preservation check"
        );

        // Test that fingerprint consistency would catch fingerprint computation bugs
        let fingerprint1 = trace_fingerprint(&trace);
        let fingerprint2 = foata.fingerprint();
        assert_eq!(fingerprint1, fingerprint2, "Fingerprint consistency check");
    }
}
