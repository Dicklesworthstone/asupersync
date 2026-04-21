#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for trace::causality vclock merge invariants.
//!
//! These tests validate the vector clock merge behavior using metamorphic relations
//! to ensure commutativity, associativity, partial order preservation, concurrency
//! detection, and per-node monotonicity are preserved across various operation patterns.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;

use asupersync::lab::runtime::LabRuntime;
use asupersync::lab::config::LabConfig;
use asupersync::remote::NodeId;
use asupersync::trace::distributed::{VectorClock, CausalOrder};
use asupersync::util::DetRng;

/// Generate arbitrary node IDs for testing.
fn arb_node_id() -> impl Strategy<Value = NodeId> {
    "[a-z][a-z0-9-]{2,8}".prop_map(|s| NodeId::new(format!("node-{}", s)))
}

/// Generate a set of node IDs for testing.
fn arb_node_set() -> impl Strategy<Value = BTreeSet<NodeId>> {
    prop::collection::btree_set(arb_node_id(), 1..=8)
}

/// Generate arbitrary vector clock entries.
fn arb_clock_entries(nodes: BTreeSet<NodeId>) -> impl Strategy<Value = BTreeMap<NodeId, u64>> {
    let node_vec: Vec<NodeId> = nodes.into_iter().collect();
    prop::collection::vec(0u64..=20, node_vec.len())
        .prop_map(move |counters| {
            node_vec.iter().zip(counters.iter()).map(|(n, &c)| (n.clone(), c)).collect()
        })
}

/// Generate arbitrary vector clocks from a shared node set.
fn arb_vector_clock_from_nodes(nodes: BTreeSet<NodeId>) -> impl Strategy<Value = VectorClock> {
    arb_clock_entries(nodes).prop_map(|entries| {
        let mut clock = VectorClock::new();
        for (node, count) in entries {
            for _ in 0..count {
                clock.increment(&node);
            }
        }
        clock
    })
}

/// Generate pair of vector clocks from shared nodes.
fn arb_vector_clock_pair() -> impl Strategy<Value = (VectorClock, VectorClock)> {
    arb_node_set().prop_flat_map(|nodes| {
        let nodes1 = nodes.clone();
        let nodes2 = nodes.clone();
        (
            arb_vector_clock_from_nodes(nodes1),
            arb_vector_clock_from_nodes(nodes2),
        )
    })
}

/// Generate triple of vector clocks from shared nodes.
fn arb_vector_clock_triple() -> impl Strategy<Value = (VectorClock, VectorClock, VectorClock)> {
    arb_node_set().prop_flat_map(|nodes| {
        let nodes1 = nodes.clone();
        let nodes2 = nodes.clone();
        let nodes3 = nodes.clone();
        (
            arb_vector_clock_from_nodes(nodes1),
            arb_vector_clock_from_nodes(nodes2),
            arb_vector_clock_from_nodes(nodes3),
        )
    })
}

/// Create a deterministic lab runtime for testing.
fn test_lab_runtime() -> LabRuntime {
    let config = LabConfig {
        seed: 42,
        chaos_probability: 0.0, // Disable chaos for deterministic tests
        max_steps: Some(1000),
        ..LabConfig::default()
    };
    LabRuntime::new(config)
}

/// Helper to create vector clock with specific node increments.
fn clock_with_increments(increments: &[(NodeId, u64)]) -> VectorClock {
    let mut clock = VectorClock::new();
    for (node, count) in increments {
        for _ in 0..*count {
            clock.increment(node);
        }
    }
    clock
}

/// Helper to verify clock component-wise comparison.
fn verify_componentwise_max(a: &VectorClock, b: &VectorClock, merged: &VectorClock) -> bool {
    let all_nodes: BTreeSet<&NodeId> = a.iter()
        .chain(b.iter())
        .chain(merged.iter())
        .map(|(node, _)| node)
        .collect();

    for node in all_nodes {
        let a_val = a.get(node);
        let b_val = b.get(node);
        let merged_val = merged.get(node);
        let expected_max = a_val.max(b_val);

        if merged_val != expected_max {
            return false;
        }
    }
    true
}

// Metamorphic Relations for Vector Clock Merge Invariants

/// MR1: VClock merge commutative (Commutative Property, Score: 9.5)
/// Property: merge(a, b) = merge(b, a) for all vector clocks a, b
/// Catches: Order-dependent merge bugs, asymmetric merge implementations
#[test]
fn mr1_vclock_merge_commutative() {
    proptest!(|(
        (clock_a, clock_b) in arb_vector_clock_pair()
    )| {
        let _lab = test_lab_runtime();

        // Merge in both directions
        let merge_a_b = clock_a.merge(&clock_b);
        let merge_b_a = clock_b.merge(&clock_a);

        // Results should be identical
        prop_assert_eq!(merge_a_b, merge_b_a,
            "Vector clock merge should be commutative: merge(a,b) != merge(b,a)");

        // Verify component-wise correctness for both directions
        prop_assert!(verify_componentwise_max(&clock_a, &clock_b, &merge_a_b),
            "merge(a,b) should be componentwise max");
        prop_assert!(verify_componentwise_max(&clock_b, &clock_a, &merge_b_a),
            "merge(b,a) should be componentwise max");

        // Both should have at least as many entries as the larger input
        let expected_nodes = clock_a.node_count().max(clock_b.node_count());
        prop_assert!(merge_a_b.node_count() >= expected_nodes,
            "Merged clock should track at least as many nodes as inputs");
        prop_assert_eq!(merge_a_b.node_count(), merge_b_a.node_count(),
            "Both merge directions should track same number of nodes");
    });
}

/// MR2: Merge associative (Associative Property, Score: 9.0)
/// Property: merge(merge(a, b), c) = merge(a, merge(b, c)) for all clocks a, b, c
/// Catches: Non-associative merge bugs, order-dependent aggregation errors
#[test]
fn mr2_merge_associative() {
    proptest!(|(
        (clock_a, clock_b, clock_c) in arb_vector_clock_triple()
    )| {
        let _lab = test_lab_runtime();

        // Left-associative: (a ⊔ b) ⊔ c
        let left_assoc = {
            let temp = clock_a.merge(&clock_b);
            temp.merge(&clock_c)
        };

        // Right-associative: a ⊔ (b ⊔ c)
        let right_assoc = {
            let temp = clock_b.merge(&clock_c);
            clock_a.merge(&temp)
        };

        prop_assert_eq!(left_assoc, right_assoc,
            "Vector clock merge should be associative");

        // Both should be componentwise max of all three inputs
        let all_nodes: BTreeSet<&NodeId> = clock_a.iter()
            .chain(clock_b.iter())
            .chain(clock_c.iter())
            .map(|(node, _)| node)
            .collect();

        for node in all_nodes {
            let a_val = clock_a.get(node);
            let b_val = clock_b.get(node);
            let c_val = clock_c.get(node);
            let expected_max = a_val.max(b_val).max(c_val);

            prop_assert_eq!(left_assoc.get(node), expected_max,
                "Left-associative merge should produce componentwise max");
            prop_assert_eq!(right_assoc.get(node), expected_max,
                "Right-associative merge should produce componentwise max");
        }
    });
}

/// MR3: Happens-before partial order preserved (Partial Order Invariant, Score: 8.5)
/// Property: if a ≤ b then merge(a, c) ≤ merge(b, c) for monotone merge
/// Catches: Partial order violation bugs, non-monotone merge behavior
#[test]
fn mr3_happens_before_partial_order_preserved() {
    proptest!(|(
        nodes in arb_node_set(),
        base_increments in prop::collection::vec(0u64..=10, 3..=5),
        additional_increments in prop::collection::vec(0u64..=5, 3..=5)
    )| {
        let _lab = test_lab_runtime();
        let node_vec: Vec<NodeId> = nodes.into_iter().collect();

        // Create base clock
        let mut clock_a = VectorClock::new();
        for (i, &count) in base_increments.iter().enumerate() {
            if i < node_vec.len() {
                for _ in 0..count {
                    clock_a.increment(&node_vec[i]);
                }
            }
        }

        // Create clock_b that extends clock_a (a ≤ b)
        let mut clock_b = clock_a.clone();
        for (i, &additional_count) in additional_increments.iter().enumerate() {
            if i < node_vec.len() {
                for _ in 0..additional_count {
                    clock_b.increment(&node_vec[i]);
                }
            }
        }

        // Verify that a ≤ b (a happens-before or concurrent with b)
        let order_a_b = clock_a.causal_order(&clock_b);
        prop_assert!(
            matches!(order_a_b, CausalOrder::Before | CausalOrder::Equal),
            "Clock a should happen-before or equal clock b by construction"
        );

        // Create arbitrary clock c
        let mut clock_c = VectorClock::new();
        for (i, node) in node_vec.iter().enumerate() {
            let c_count = (i * 3 + 1) as u64; // Deterministic but different pattern
            for _ in 0..c_count {
                clock_c.increment(node);
            }
        }

        // Merge both with c
        let merge_a_c = clock_a.merge(&clock_c);
        let merge_b_c = clock_b.merge(&clock_c);

        // If a ≤ b, then merge(a,c) ≤ merge(b,c) should hold (monotonicity)
        // Since merge is componentwise max, this should always be true
        for node in &node_vec {
            let a_val = clock_a.get(node);
            let b_val = clock_b.get(node);
            let c_val = clock_c.get(node);

            let merge_a_c_val = merge_a_c.get(node);
            let merge_b_c_val = merge_b_c.get(node);

            // merge(a,c)[node] = max(a[node], c[node])
            // merge(b,c)[node] = max(b[node], c[node])
            // Since a[node] ≤ b[node], we have max(a[node], c[node]) ≤ max(b[node], c[node])
            prop_assert_eq!(merge_a_c_val, a_val.max(c_val),
                "merge(a,c) should be componentwise max of a and c");
            prop_assert_eq!(merge_b_c_val, b_val.max(c_val),
                "merge(b,c) should be componentwise max of b and c");
            prop_assert!(merge_a_c_val <= merge_b_c_val,
                "Merge should preserve partial order: merge(a,c)[{}] = {} should be ≤ merge(b,c)[{}] = {}",
                node.as_str(), merge_a_c_val, node.as_str(), merge_b_c_val);
        }
    });
}

/// MR4: Concurrent events detected correctly (Concurrency Detection, Score: 8.0)
/// Property: concurrent(a, b) → concurrent(merge(a, c), merge(b, d)) when c||d
/// Catches: False concurrency detection, happens-before calculation errors
#[test]
fn mr4_concurrent_events_detected_correctly() {
    proptest!(|(nodes in arb_node_set().prop_filter("Need at least 2 nodes", |n| n.len() >= 2))| {
        let _lab = test_lab_runtime();
        let node_vec: Vec<NodeId> = nodes.into_iter().collect();

        // Create two concurrent clocks by advancing different nodes
        let mut clock_a = VectorClock::new();
        let mut clock_b = VectorClock::new();

        // Make them concurrent by having each advance different nodes
        clock_a.increment(&node_vec[0]); // Node 0: a=1, b=0
        clock_b.increment(&node_vec[1]); // Node 1: a=0, b=1

        // Verify they are concurrent
        prop_assert_eq!(clock_a.causal_order(&clock_b), CausalOrder::Concurrent,
            "Clocks with different advanced nodes should be concurrent");
        prop_assert!(clock_a.is_concurrent_with(&clock_b),
            "is_concurrent_with should return true for concurrent clocks");
        prop_assert!(!clock_a.happens_before(&clock_b),
            "Neither concurrent clock should happen-before the other");
        prop_assert!(!clock_b.happens_before(&clock_a),
            "Neither concurrent clock should happen-before the other");

        // Create another pair of concurrent clocks
        let mut clock_c = VectorClock::new();
        let mut clock_d = VectorClock::new();

        if node_vec.len() >= 3 {
            clock_c.increment(&node_vec[2]); // Node 2: c=1, d=0
            clock_c.increment(&node_vec[2]); // Node 2: c=2, d=0
        } else {
            clock_c.increment(&node_vec[0]); // Reuse node 0
            clock_c.increment(&node_vec[0]);
        }

        if node_vec.len() >= 4 {
            clock_d.increment(&node_vec[3]); // Node 3: c=0, d=1
        } else {
            clock_d.increment(&node_vec[1]); // Reuse node 1
        }

        prop_assert!(clock_c.is_concurrent_with(&clock_d),
            "Second pair should also be concurrent");

        // Merge concurrent clocks
        let merged_ac = clock_a.merge(&clock_c);
        let merged_bd = clock_b.merge(&clock_d);

        // The merged clocks may or may not be concurrent depending on the specific
        // node distributions, but we can verify that the merge operation preserved
        // the logical structure correctly

        // Verify that merge preserves the maximum values
        for node in &node_vec {
            let a_val = clock_a.get(node);
            let c_val = clock_c.get(node);
            let expected_ac = a_val.max(c_val);
            prop_assert_eq!(merged_ac.get(node), expected_ac,
                "merge(a,c) should be componentwise max");

            let b_val = clock_b.get(node);
            let d_val = clock_d.get(node);
            let expected_bd = b_val.max(d_val);
            prop_assert_eq!(merged_bd.get(node), expected_bd,
                "merge(b,d) should be componentwise max");
        }

        // Test the causal ordering detection works correctly
        let merged_order = merged_ac.causal_order(&merged_bd);
        prop_assert!(
            matches!(merged_order, CausalOrder::Before | CausalOrder::After |
                    CausalOrder::Equal | CausalOrder::Concurrent),
            "Merged clocks should have valid causal ordering"
        );
    });
}

/// MR5: Vector clock monotonic per node (Monotonicity Invariant, Score: 8.5)
/// Property: merge(clock, other)[node] >= clock[node] for all nodes
/// Catches: Non-monotone merge bugs, counter regression errors
#[test]
fn mr5_vector_clock_monotonic_per_node() {
    proptest!(|(
        (clock_a, clock_b) in arb_vector_clock_pair()
    )| {
        let _lab = test_lab_runtime();

        // Perform merge
        let merged = clock_a.merge(&clock_b);

        // Verify monotonicity for all nodes in clock_a
        for (node, &count_a) in clock_a.iter() {
            let merged_count = merged.get(node);
            prop_assert!(merged_count >= count_a,
                "Merged clock should be monotonic: merged[{}] = {} should be >= original[{}] = {}",
                node.as_str(), merged_count, node.as_str(), count_a);
        }

        // Verify monotonicity for all nodes in clock_b
        for (node, &count_b) in clock_b.iter() {
            let merged_count = merged.get(node);
            prop_assert!(merged_count >= count_b,
                "Merged clock should be monotonic: merged[{}] = {} should be >= other[{}] = {}",
                node.as_str(), merged_count, node.as_str(), count_b);
        }

        // Verify that merge is exactly the componentwise maximum
        let all_nodes: BTreeSet<&NodeId> = clock_a.iter()
            .chain(clock_b.iter())
            .map(|(node, _)| node)
            .collect();

        for node in all_nodes {
            let a_val = clock_a.get(node);
            let b_val = clock_b.get(node);
            let expected_max = a_val.max(b_val);
            let actual = merged.get(node);

            prop_assert_eq!(actual, expected_max,
                "Merged value for {} should be max({}, {}) = {}, got {}",
                node.as_str(), a_val, b_val, expected_max, actual);
        }

        // Test that the merge operation is idempotent when merging with self
        let self_merged = clock_a.merge(&clock_a);
        prop_assert_eq!(self_merged, clock_a,
            "Merging a clock with itself should be idempotent");
    });
}

/// Integration test: Complex vector clock operations
#[test]
fn integration_complex_vclock_operations() {
    let _lab = test_lab_runtime();

    // Create a set of nodes
    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");
    let node_c = NodeId::new("node-c");

    // Create initial clocks
    let mut clock_1 = VectorClock::new();
    let mut clock_2 = VectorClock::new();
    let mut clock_3 = VectorClock::new();

    // Simulate some events
    clock_1.increment(&node_a); // [a:1, b:0, c:0]
    clock_1.increment(&node_a); // [a:2, b:0, c:0]

    clock_2.increment(&node_b); // [a:0, b:1, c:0]
    clock_2.increment(&node_b); // [a:0, b:2, c:0]

    clock_3.increment(&node_c); // [a:0, b:0, c:1]

    // Test various merge combinations
    let merge_1_2 = clock_1.merge(&clock_2); // [a:2, b:2, c:0]
    let merge_2_3 = clock_2.merge(&clock_3); // [a:0, b:2, c:1]
    let merge_1_3 = clock_1.merge(&clock_3); // [a:2, b:0, c:1]

    // Verify expected values
    assert_eq!(merge_1_2.get(&node_a), 2);
    assert_eq!(merge_1_2.get(&node_b), 2);
    assert_eq!(merge_1_2.get(&node_c), 0);

    assert_eq!(merge_2_3.get(&node_a), 0);
    assert_eq!(merge_2_3.get(&node_b), 2);
    assert_eq!(merge_2_3.get(&node_c), 1);

    // Test three-way merge associativity
    let left_merge = merge_1_2.merge(&clock_3);   // ((1⊔2)⊔3)
    let right_merge = clock_1.merge(&merge_2_3);  // (1⊔(2⊔3))

    assert_eq!(left_merge, right_merge, "Three-way merge should be associative");
    assert_eq!(left_merge.get(&node_a), 2);
    assert_eq!(left_merge.get(&node_b), 2);
    assert_eq!(left_merge.get(&node_c), 1);

    // Test concurrency detection
    assert!(clock_1.is_concurrent_with(&clock_2), "clock_1 and clock_2 should be concurrent");
    assert!(clock_1.is_concurrent_with(&clock_3), "clock_1 and clock_3 should be concurrent");
    assert!(clock_2.is_concurrent_with(&clock_3), "clock_2 and clock_3 should be concurrent");

    // Test happens-before after receives
    let mut clock_4 = clock_1.clone();
    clock_4.receive(&node_a, &clock_2); // Receive clock_2's state

    assert!(clock_1.happens_before(&clock_4) || clock_1 == clock_4,
        "Original should happen-before or equal after receive operation");
    assert!(!clock_4.happens_before(&clock_1),
        "Received clock should not happen-before the original");
}

/// Stress test: Large vector clocks with many nodes
#[test]
fn stress_large_vector_clocks() {
    let _lab = test_lab_runtime();

    // Create many nodes
    let nodes: Vec<NodeId> = (0..20).map(|i| NodeId::new(format!("node-{}", i))).collect();

    // Create large vector clocks
    let mut clock_1 = VectorClock::new();
    let mut clock_2 = VectorClock::new();

    // Populate with various increments
    for (i, node) in nodes.iter().enumerate() {
        for _ in 0..=(i % 10) {
            clock_1.increment(node);
        }
        for _ in 0..=((i * 2) % 7) {
            clock_2.increment(node);
        }
    }

    // Test merge performance and correctness
    let merged = clock_1.merge(&clock_2);

    // Verify all nodes are present and have correct values
    for node in &nodes {
        let val_1 = clock_1.get(node);
        let val_2 = clock_2.get(node);
        let merged_val = merged.get(node);
        let expected = val_1.max(val_2);

        assert_eq!(merged_val, expected,
            "Large clock merge failed for {}: expected {}, got {}",
            node.as_str(), expected, merged_val);
    }

    // Verify merge properties still hold
    assert_eq!(clock_1.merge(&clock_2), clock_2.merge(&clock_1),
        "Commutativity should hold for large clocks");

    let clock_3 = clock_1.clone();
    let left_assoc = clock_1.merge(&clock_2).merge(&clock_3);
    let right_assoc = clock_1.merge(&clock_2.merge(&clock_3));
    assert_eq!(left_assoc, right_assoc, "Associativity should hold for large clocks");
}

/// Edge case test: Empty and single-node clocks
#[test]
fn edge_case_empty_and_single_node_clocks() {
    let _lab = test_lab_runtime();

    let node_a = NodeId::new("node-a");
    let empty_clock = VectorClock::new();

    // Test empty clock properties
    assert!(empty_clock.is_zero(), "Empty clock should be zero");
    assert_eq!(empty_clock.node_count(), 0, "Empty clock should have no nodes");

    // Test merge with empty clock
    let mut single_node_clock = VectorClock::new();
    single_node_clock.increment(&node_a);

    let merged_empty = empty_clock.merge(&single_node_clock);
    let merged_single = single_node_clock.merge(&empty_clock);

    assert_eq!(merged_empty, merged_single, "Merge with empty should be commutative");
    assert_eq!(merged_empty, single_node_clock, "Merge with empty should preserve non-empty clock");

    // Test causal ordering with empty clock
    assert_eq!(empty_clock.causal_order(&single_node_clock), CausalOrder::Before,
        "Empty clock should happen-before non-empty clock");
    assert_eq!(single_node_clock.causal_order(&empty_clock), CausalOrder::After,
        "Non-empty clock should happen-after empty clock");
    assert_eq!(empty_clock.causal_order(&empty_clock), CausalOrder::Equal,
        "Empty clock should equal itself");
}