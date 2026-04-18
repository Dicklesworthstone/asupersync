#![no_main]

use asupersync::distributed::consistent_hash::HashRing;
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    // Parse input for ring configuration and operations
    let vnodes_per_node = ((data[0] as usize) % 128) + 1; // 1-128 vnodes
    let max_nodes = ((data[1] as usize) % 64) + 1; // 1-64 max nodes
    let operation_count = ((data[2] as usize) % 100) + 1; // 1-100 operations

    let mut ring = HashRing::new(vnodes_per_node);
    let mut expected_nodes = BTreeSet::new();
    let mut operation_idx = 3;

    // Generate a stable set of test keys for consistency checking
    let test_keys: Vec<u64> = (0..100).map(|i| i as u64 * 31 + 17).collect();

    for _op_num in 0..operation_count {
        if operation_idx + 2 >= data.len() {
            break;
        }

        let op_type = data[operation_idx] % 3;
        let node_id_hash = data[operation_idx + 1] as usize;
        let node_name = format!("node-{}", node_id_hash % max_nodes);
        operation_idx += 2;

        // Track ring state before operation
        let node_count_before = ring.node_count();
        let vnode_count_before = ring.vnode_count();

        // Capture key assignments before operation for consistency checking
        let assignments_before: BTreeMap<u64, Option<String>> = test_keys
            .iter()
            .map(|&key| (key, ring.node_for_key(&key).map(str::to_string)))
            .collect();

        let removed_vnodes = match op_type {
            0 => {
                // Add node operation
                let added = ring.add_node(&node_name);
                if added {
                    expected_nodes.insert(node_name.clone());

                    // INVARIANT: Node count should increase by 1
                    assert_eq!(ring.node_count(), node_count_before + 1);

                    // INVARIANT: Virtual node count should increase by vnodes_per_node
                    assert_eq!(ring.vnode_count(), vnode_count_before + vnodes_per_node);
                } else {
                    // Duplicate add - state should be unchanged
                    assert_eq!(ring.node_count(), node_count_before);
                    assert_eq!(ring.vnode_count(), vnode_count_before);
                    assert!(expected_nodes.contains(&node_name));
                }

                // INVARIANT: New node should appear in nodes() iterator
                assert!(ring.nodes().any(|n| n == node_name));
                0 // No nodes removed
            }
            1 => {
                // Remove node operation
                let removed_vnodes = ring.remove_node(&node_name);
                if expected_nodes.contains(&node_name) {
                    expected_nodes.remove(&node_name);

                    // INVARIANT: Should remove exactly vnodes_per_node virtual nodes
                    assert_eq!(removed_vnodes, vnodes_per_node);

                    // INVARIANT: Node count should decrease by 1
                    assert_eq!(ring.node_count(), node_count_before - 1);

                    // INVARIANT: Virtual node count should decrease by vnodes_per_node
                    assert_eq!(ring.vnode_count(), vnode_count_before - vnodes_per_node);

                    // INVARIANT: Removed node should not appear in nodes() iterator
                    assert!(!ring.nodes().any(|n| n == node_name));
                } else {
                    // Remove non-existent node - state should be unchanged
                    assert_eq!(removed_vnodes, 0);
                    assert_eq!(ring.node_count(), node_count_before);
                    assert_eq!(ring.vnode_count(), vnode_count_before);
                }
                removed_vnodes
            }
            2 => {
                // Query operation (no state change)
                for &test_key in &test_keys {
                    let result = ring.node_for_key(&test_key);
                    if ring.is_empty() {
                        assert!(result.is_none());
                    } else {
                        assert!(result.is_some());
                        let assigned_node = result.unwrap();
                        assert!(ring.nodes().any(|n| n == assigned_node));
                    }
                }
                0 // No nodes removed
            }
            _ => unreachable!(),
        };

        // INVARIANT: Ring state consistency after each operation
        verify_ring_invariants(&ring, vnodes_per_node, &expected_nodes);

        // INVARIANT: Key assignments after add should be minimal remap
        if op_type == 0 && ring.node_count() > 1 {
            verify_minimal_remap(&assignments_before, &ring, &test_keys);
        }

        // INVARIANT: Key assignments after remove should only remap removed node's keys
        if op_type == 1 && removed_vnodes > 0 {
            verify_remove_remap(&assignments_before, &ring, &test_keys, &node_name);
        }
    }

    // FINAL INVARIANTS: Ring should be in valid state
    verify_ring_invariants(&ring, vnodes_per_node, &expected_nodes);
    verify_deterministic_lookups(&ring, &test_keys);
});

/// Verifies core ring invariants that must hold after any operation.
fn verify_ring_invariants(
    ring: &HashRing,
    vnodes_per_node: usize,
    expected_nodes: &BTreeSet<String>,
) {
    // Node count consistency
    assert_eq!(ring.node_count(), expected_nodes.len());

    // Virtual node count consistency
    assert_eq!(ring.vnode_count(), ring.node_count() * vnodes_per_node);

    // Empty ring consistency
    assert_eq!(ring.is_empty(), ring.vnode_count() == 0);

    // Node iterator consistency
    let iterator_nodes: BTreeSet<String> = ring.nodes().map(str::to_string).collect();
    assert_eq!(iterator_nodes, *expected_nodes);

    // Node iterator should be sorted
    let nodes_vec: Vec<String> = ring.nodes().map(str::to_string).collect();
    let mut sorted_nodes = nodes_vec.clone();
    sorted_nodes.sort();
    assert_eq!(nodes_vec, sorted_nodes);

    // Virtual node distribution: each node should have exactly vnodes_per_node virtual nodes
    if !ring.is_empty() {
        // This is a bit hacky since we don't have direct access to ring internals,
        // but we can verify by checking that all test keys map to existing nodes
        for node in expected_nodes {
            let count = (0..1000u64)
                .filter_map(|key| ring.node_for_key(&key))
                .filter(|&assigned| assigned == node)
                .count();

            // Each node should get some assignments (not exact due to hash distribution)
            if expected_nodes.len() > 1 {
                assert!(count > 0, "Node {node} got no key assignments");
            }
        }
    }
}

/// Verifies that adding a node causes minimal key remapping.
fn verify_minimal_remap(
    assignments_before: &BTreeMap<u64, Option<String>>,
    ring: &HashRing,
    test_keys: &[u64],
) {
    let assignments_after: BTreeMap<u64, Option<String>> = test_keys
        .iter()
        .map(|&key| (key, ring.node_for_key(&key).map(str::to_string)))
        .collect();

    let changed_count = assignments_before
        .iter()
        .zip(assignments_after.iter())
        .filter(|((k1, v1), (k2, v2))| k1 == k2 && v1 != v2)
        .count();

    let total_assigned_before = assignments_before.values().filter(|v| v.is_some()).count();

    if total_assigned_before > 0 {
        let change_ratio = changed_count as f64 / total_assigned_before as f64;

        // For consistent hashing, adding one node should remap approximately 1/n keys
        // where n is the total number of nodes. We allow generous bounds for fuzzing.
        assert!(
            change_ratio <= 0.8,
            "Too many keys remapped: {change_ratio}"
        );
    }
}

/// Verifies that removing a node only remaps keys that were assigned to that node.
fn verify_remove_remap(
    assignments_before: &BTreeMap<u64, Option<String>>,
    ring: &HashRing,
    test_keys: &[u64],
    removed_node: &str,
) {
    let assignments_after: BTreeMap<u64, Option<String>> = test_keys
        .iter()
        .map(|&key| (key, ring.node_for_key(&key).map(str::to_string)))
        .collect();

    for (&key, before_assignment) in assignments_before {
        let after_assignment = assignments_after.get(&key).unwrap();

        match before_assignment {
            Some(before_node) if before_node == removed_node => {
                // Keys previously assigned to removed node should be reassigned
                if !ring.is_empty() {
                    assert!(after_assignment.is_some());
                    assert_ne!(after_assignment.as_ref().unwrap(), removed_node);
                } else {
                    assert!(after_assignment.is_none());
                }
            }
            Some(before_node) => {
                // Keys assigned to other nodes should remain unchanged
                assert_eq!(after_assignment.as_ref(), Some(before_node));
            }
            None => {
                // Keys that were unassigned should remain unassigned (empty ring case)
                assert_eq!(after_assignment, &None);
            }
        }
    }
}

/// Verifies that key lookups are deterministic and consistent.
fn verify_deterministic_lookups(ring: &HashRing, test_keys: &[u64]) {
    for &key in test_keys {
        let first_lookup = ring.node_for_key(&key);
        let second_lookup = ring.node_for_key(&key);
        assert_eq!(
            first_lookup, second_lookup,
            "Lookup not deterministic for key {key}"
        );

        if let Some(node) = first_lookup {
            assert!(
                ring.nodes().any(|n| n == node),
                "Assigned node {node} not in ring"
            );
        }
    }
}
