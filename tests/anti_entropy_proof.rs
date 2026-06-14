//! Runnable proof for Merkle-range anti-entropy (bead
//! `asupersync-dist-otp-completeness-8y37kz.6`).
//!
//! Validates the pure reconciliation core: deterministic roots for identical
//! content (AC1), incremental update equals rebuild (AC1), correct key-level
//! diffs, and that the diff cost scales with the divergence rather than the
//! keyspace (AC2).
//!
//! Run with: `cargo test --test anti_entropy_proof --features test-internals`.

use asupersync::distributed::{DiffKind, MerkleRangeTree};

fn tree(depth: u8, entries: &[(&str, u64)]) -> MerkleRangeTree {
    let mut t = MerkleRangeTree::new(depth);
    for (k, h) in entries {
        t.insert(k.as_bytes().to_vec(), *h);
    }
    t
}

#[test]
fn identical_content_yields_identical_root() {
    // AC1: deterministic roots across replicas regardless of insert order.
    let a = tree(8, &[("alpha", 1), ("beta", 2), ("gamma", 3)]);
    let b = tree(8, &[("gamma", 3), ("alpha", 1), ("beta", 2)]);
    assert_eq!(a.root(), b.root());
    assert!(a.diff(&b).diffs.is_empty());
}

#[test]
fn incremental_update_equals_rebuild() {
    // AC1: path-recompute on insert/update/remove == a from-scratch build.
    let mut incremental = MerkleRangeTree::new(8);
    incremental.insert(b"k1".to_vec(), 10);
    incremental.insert(b"k2".to_vec(), 20);
    incremental.insert(b"k2".to_vec(), 99); // update
    incremental.remove(b"k3"); // absent — no-op
    let rebuilt = tree(8, &[("k1", 10), ("k2", 99)]);
    assert_eq!(incremental.root(), rebuilt.root());
    assert_eq!(incremental.len(), 2);
}

#[test]
fn diff_finds_exactly_the_divergent_keys() {
    let here = tree(8, &[("a", 1), ("b", 2), ("c", 3), ("d", 4)]);
    let there = tree(8, &[("a", 1), ("b", 999), ("d", 4), ("e", 5)]);
    let report = here.diff(&there);
    assert_eq!(report.diffs.len(), 3);
    assert!(
        report
            .diffs
            .iter()
            .any(|d| d.key == b"b".to_vec() && d.kind == DiffKind::HashDiffers)
    );
    assert!(
        report
            .diffs
            .iter()
            .any(|d| d.key == b"c".to_vec() && d.kind == DiffKind::OnlyHere)
    );
    assert!(
        report
            .diffs
            .iter()
            .any(|d| d.key == b"e".to_vec() && d.kind == DiffKind::OnlyThere)
    );
}

#[test]
fn diff_cost_scales_with_divergence_not_keyspace() {
    // AC2: 2000 identical keys, a few divergent -> few nodes compared.
    let depth = 10u8; // 1024 leaves, 2048 nodes
    let mut here = MerkleRangeTree::new(depth);
    let mut there = MerkleRangeTree::new(depth);
    for i in 0..2000u32 {
        let key = format!("key-{i}").into_bytes();
        here.insert(key.clone(), u64::from(i));
        there.insert(key, u64::from(i));
    }
    there.insert(b"key-100".to_vec(), 999_999); // differing hash
    there.remove(b"key-1500"); // only-here

    let report = here.diff(&there);
    assert_eq!(report.diffs.len(), 2);
    let total_nodes = 2usize << depth;
    assert!(
        report.nodes_compared < total_nodes / 4,
        "compared {} of {total_nodes} nodes — should scale with divergence",
        report.nodes_compared
    );
}

#[test]
fn identical_trees_prune_at_the_root() {
    let a = tree(8, &[("x", 1), ("y", 2)]);
    let b = tree(8, &[("x", 1), ("y", 2)]);
    let report = a.diff(&b);
    assert!(report.diffs.is_empty());
    assert_eq!(report.nodes_compared, 1);
}
