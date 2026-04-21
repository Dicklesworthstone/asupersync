#![allow(clippy::all)]
//! Golden snapshots for consistent-hash node-set transitions.

use asupersync::distributed::HashRing;
use insta::assert_json_snapshot;
use serde_json::json;
use std::collections::BTreeMap;

fn assignment_map(ring: &HashRing, keys: &[u64]) -> BTreeMap<u64, String> {
    keys.iter()
        .map(|key| {
            (
                *key,
                ring.node_for_key(key)
                    .expect("ring should assign every fixture key")
                    .to_owned(),
            )
        })
        .collect()
}

fn partition_buckets(assignments: &BTreeMap<u64, String>) -> BTreeMap<String, Vec<u64>> {
    let mut buckets = BTreeMap::<String, Vec<u64>>::new();
    for (&key, node) in assignments {
        buckets.entry(node.clone()).or_default().push(key);
    }
    buckets
}

fn partition_sizes(assignments: &BTreeMap<u64, String>) -> BTreeMap<String, usize> {
    partition_buckets(assignments)
        .into_iter()
        .map(|(node, keys)| (node, keys.len()))
        .collect()
}

fn changed_keys(
    before: &BTreeMap<u64, String>,
    after: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    before
        .iter()
        .filter_map(|(&key, old_node)| {
            let new_node = after.get(&key).expect("after map should cover all keys");
            (old_node != new_node).then(|| (key, format!("{old_node}->{new_node}")))
        })
        .collect()
}

fn changed_key_count(before: &BTreeMap<u64, String>, after: &BTreeMap<u64, String>) -> usize {
    changed_keys(before, after).len()
}

fn ring_snapshot(
    label: &str,
    ring: &HashRing,
    assignments: &BTreeMap<u64, String>,
) -> serde_json::Value {
    json!({
        "label": label,
        "nodes": ring.nodes().map(str::to_owned).collect::<Vec<_>>(),
        "node_count": ring.node_count(),
        "vnode_count": ring.vnode_count(),
        "partitions": partition_buckets(assignments),
        "assignments": assignments,
    })
}

#[test]
fn node_set_partitioning_scrubbed() {
    let keys: Vec<u64> = (0..24).collect();

    let mut baseline = HashRing::new(32);
    for node in ["node-a", "node-b", "node-c"] {
        assert!(baseline.add_node(node), "baseline fixture should be unique");
    }
    let baseline_assignments = assignment_map(&baseline, &keys);

    let mut after_add = baseline.clone();
    assert!(after_add.add_node("node-d"), "added node should be unique");
    let after_add_assignments = assignment_map(&after_add, &keys);

    let mut after_remove = after_add.clone();
    assert_eq!(after_remove.remove_node("node-b"), 32, "remove should drop one node worth of vnodes");
    let after_remove_assignments = assignment_map(&after_remove, &keys);

    let mut after_replace = baseline.clone();
    assert_eq!(after_replace.remove_node("node-c"), 32, "replace should first remove node-c");
    assert!(after_replace.add_node("node-e"), "replacement node should be unique");
    let after_replace_assignments = assignment_map(&after_replace, &keys);

    assert_json_snapshot!(
        "node_set_partitioning_scrubbed",
        json!({
            "baseline": ring_snapshot("baseline", &baseline, &baseline_assignments),
            "after_add": {
                "ring": ring_snapshot("after_add", &after_add, &after_add_assignments),
                "changed_from_baseline": changed_keys(&baseline_assignments, &after_add_assignments),
            },
            "after_remove": {
                "ring": ring_snapshot("after_remove", &after_remove, &after_remove_assignments),
                "changed_from_after_add": changed_keys(&after_add_assignments, &after_remove_assignments),
            },
            "after_replace": {
                "ring": ring_snapshot("after_replace", &after_replace, &after_replace_assignments),
                "changed_from_baseline": changed_keys(&baseline_assignments, &after_replace_assignments),
            },
        })
    );
}

#[test]
fn node_set_partition_summary_scrubbed() {
    let keys: Vec<u64> = (0..24).collect();

    let mut baseline = HashRing::new(32);
    for node in ["node-a", "node-b", "node-c"] {
        assert!(baseline.add_node(node), "baseline fixture should be unique");
    }
    let baseline_assignments = assignment_map(&baseline, &keys);

    let mut after_add = baseline.clone();
    assert!(after_add.add_node("node-d"), "added node should be unique");
    let after_add_assignments = assignment_map(&after_add, &keys);

    let mut after_remove = after_add.clone();
    assert_eq!(
        after_remove.remove_node("node-b"),
        32,
        "remove should drop one node worth of vnodes"
    );
    let after_remove_assignments = assignment_map(&after_remove, &keys);

    let mut after_replace = baseline.clone();
    assert_eq!(
        after_replace.remove_node("node-c"),
        32,
        "replace should first remove node-c"
    );
    assert!(after_replace.add_node("node-e"), "replacement node should be unique");
    let after_replace_assignments = assignment_map(&after_replace, &keys);

    assert_json_snapshot!(
        "node_set_partition_summary_scrubbed",
        json!({
            "baseline": {
                "node_count": baseline.node_count(),
                "vnode_count": baseline.vnode_count(),
                "partition_sizes": partition_sizes(&baseline_assignments),
            },
            "after_add": {
                "node_count": after_add.node_count(),
                "vnode_count": after_add.vnode_count(),
                "partition_sizes": partition_sizes(&after_add_assignments),
                "changed_from_baseline": changed_key_count(&baseline_assignments, &after_add_assignments),
            },
            "after_remove": {
                "node_count": after_remove.node_count(),
                "vnode_count": after_remove.vnode_count(),
                "partition_sizes": partition_sizes(&after_remove_assignments),
                "changed_from_after_add": changed_key_count(&after_add_assignments, &after_remove_assignments),
            },
            "after_replace": {
                "node_count": after_replace.node_count(),
                "vnode_count": after_replace.vnode_count(),
                "partition_sizes": partition_sizes(&after_replace_assignments),
                "changed_from_baseline": changed_key_count(&baseline_assignments, &after_replace_assignments),
            },
        })
    );
}
