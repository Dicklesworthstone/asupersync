//! Property, metamorphic, and oracle proofs for Merkle-range anti-entropy
//! (bead `asupersync-dist-otp-completeness-8y37kz.6`).
//!
//! `tests/anti_entropy_proof.rs` pins the basic AC1/AC2 shape with a handful of
//! hand-picked cases. This file strengthens those guarantees on the same public
//! `MerkleRangeTree` surface, oracle-free except for a brute-force ground truth:
//!
//! * **Completeness (AC1)** — `diff` equals an independent brute-force diff of the
//!   two key→hash maps over diverse, pseudo-randomly generated content, not just a
//!   few hand-picked keys (every `OnlyHere`/`OnlyThere`/`HashDiffers` accounted,
//!   nothing spurious, nothing dropped).
//! * **Symmetry (metamorphic)** — `a.diff(b)` is the exact mirror of `b.diff(a)`
//!   (`OnlyHere`↔`OnlyThere`, `HashDiffers` fixed) and visits the same node count.
//! * **Incremental == rebuild (AC1, property)** — thousands of randomized
//!   insert/update/remove operations keep the incremental path-recompute root
//!   identical to a from-scratch rebuild, with `len`/`is_empty` tracking a model.
//! * **Reconciliation cost (AC2, tight bound)** — for `k` divergent keys in a
//!   depth-`d` tree, `nodes_compared` stays within the `O(k·d)` constant-factor
//!   bound and far below the full keyspace.
//! * **Edges** — empty/full-divergence and `depth` clamping.
//!
//! Determinism uses an in-file SplitMix64 (fixed seeds, no `rand`, no ambient
//! entropy) so runs are byte-reproducible. Integration test on the public
//! prelude surface; it does not touch `src/distributed/anti_entropy.rs`.
//!
//! Run with: `cargo test --test anti_entropy_merkle_diff_properties`.

use std::collections::BTreeMap;

use asupersync::distributed::{DiffKind, MerkleRangeTree};

/// Deterministic SplitMix64 — fixed-seed, reproducible, no external entropy.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn tree_with(depth: u8, entries: &[(&str, u64)]) -> MerkleRangeTree {
    let mut t = MerkleRangeTree::new(depth);
    for (k, h) in entries {
        t.insert(k.as_bytes().to_vec(), *h);
    }
    t
}

fn build_from(depth: u8, m: &BTreeMap<Vec<u8>, u64>) -> MerkleRangeTree {
    let mut t = MerkleRangeTree::new(depth);
    for (k, h) in m {
        t.insert(k.clone(), *h);
    }
    t
}

/// Independent brute-force diff of two key→hash maps, sorted by key — the oracle
/// that `MerkleRangeTree::diff` must reproduce exactly.
fn brute_force_diff(
    a: &BTreeMap<Vec<u8>, u64>,
    b: &BTreeMap<Vec<u8>, u64>,
) -> Vec<(Vec<u8>, DiffKind)> {
    let mut out: Vec<(Vec<u8>, DiffKind)> = Vec::new();
    for (key, va) in a {
        match b.get(key) {
            None => out.push((key.clone(), DiffKind::OnlyHere)),
            Some(vb) if vb != va => out.push((key.clone(), DiffKind::HashDiffers)),
            Some(_) => {}
        }
    }
    for key in b.keys() {
        if !a.contains_key(key) {
            out.push((key.clone(), DiffKind::OnlyThere));
        }
    }
    out.sort_by(|x, y| x.0.cmp(&y.0));
    out
}

fn merkle_diff_pairs(
    depth: u8,
    a: &BTreeMap<Vec<u8>, u64>,
    b: &BTreeMap<Vec<u8>, u64>,
) -> Vec<(Vec<u8>, DiffKind)> {
    let ta = build_from(depth, a);
    let tb = build_from(depth, b);
    ta.diff(&tb)
        .diffs
        .into_iter()
        .map(|d| (d.key, d.kind))
        .collect()
}

/// Generates a pseudo-random map pair over a shared key space with a small hash
/// space (so identical keys frequently agree or disagree, exercising every
/// `DiffKind`).
fn random_map_pair(
    seed: u64,
    keyspace: u64,
    ops: u32,
) -> (BTreeMap<Vec<u8>, u64>, BTreeMap<Vec<u8>, u64>) {
    let mut rng = SplitMix64::new(seed);
    let mut a = BTreeMap::new();
    let mut b = BTreeMap::new();
    for _ in 0..ops {
        let key = format!("k{:05}", rng.next_u64() % keyspace).into_bytes();
        if rng.next_u64() & 1 == 0 {
            a.insert(key.clone(), rng.next_u64() % 6);
        }
        if rng.next_u64() & 1 == 0 {
            b.insert(key.clone(), rng.next_u64() % 6);
        }
    }
    (a, b)
}

// -- AC1: completeness against a brute-force oracle ---------------------------

#[test]
fn diff_matches_bruteforce_oracle_over_diverse_content() {
    let depth = 10u8;

    // Hand-built corner shapes.
    let disjoint_a: BTreeMap<Vec<u8>, u64> = [(b"a".to_vec(), 1), (b"b".to_vec(), 2)]
        .into_iter()
        .collect();
    let disjoint_b: BTreeMap<Vec<u8>, u64> = [(b"c".to_vec(), 3), (b"d".to_vec(), 4)]
        .into_iter()
        .collect();
    assert_eq!(
        merkle_diff_pairs(depth, &disjoint_a, &disjoint_b),
        brute_force_diff(&disjoint_a, &disjoint_b),
        "fully disjoint key sets",
    );

    let identical: BTreeMap<Vec<u8>, u64> = [(b"x".to_vec(), 7), (b"y".to_vec(), 8)]
        .into_iter()
        .collect();
    assert_eq!(
        merkle_diff_pairs(depth, &identical, &identical),
        brute_force_diff(&identical, &identical),
    );
    assert!(
        merkle_diff_pairs(depth, &identical, &identical).is_empty(),
        "identical content has no divergences",
    );

    // Pseudo-random content across several seeds and shapes.
    for seed in [1u64, 7, 42, 1234, 0xDEAD_BEEF, 0x5151_5151] {
        let (a, b) = random_map_pair(seed, 400, 300);
        let got = merkle_diff_pairs(depth, &a, &b);
        let expected = brute_force_diff(&a, &b);
        assert_eq!(
            got, expected,
            "merkle diff must equal brute-force oracle (seed {seed})",
        );
        // No key appears twice, and every reported key is genuinely divergent.
        let mut seen = std::collections::BTreeSet::new();
        for (key, kind) in &got {
            assert!(seen.insert(key.clone()), "no key reported twice");
            match kind {
                DiffKind::OnlyHere => assert!(a.contains_key(key) && !b.contains_key(key)),
                DiffKind::OnlyThere => assert!(!a.contains_key(key) && b.contains_key(key)),
                DiffKind::HashDiffers => assert_ne!(a.get(key), b.get(key)),
            }
        }
    }
}

// -- metamorphic: diff symmetry ----------------------------------------------

#[test]
fn diff_is_symmetric_under_swapping_replicas() {
    let depth = 10u8;
    let mirror = |k: DiffKind| match k {
        DiffKind::OnlyHere => DiffKind::OnlyThere,
        DiffKind::OnlyThere => DiffKind::OnlyHere,
        DiffKind::HashDiffers => DiffKind::HashDiffers,
    };

    for seed in [3u64, 19, 555, 0xABCD] {
        let (a, b) = random_map_pair(seed, 300, 250);
        let ta = build_from(depth, &a);
        let tb = build_from(depth, &b);

        let ab = ta.diff(&tb);
        let ba = tb.diff(&ta);

        // The descent compares node hashes for equality, which is symmetric, so
        // both directions visit exactly the same nodes.
        assert_eq!(
            ab.nodes_compared, ba.nodes_compared,
            "node-comparison cost is direction-independent (seed {seed})",
        );

        // Mirroring a.diff(b) (swapping OnlyHere<->OnlyThere) yields b.diff(a).
        // Both reports are key-sorted, so element-wise comparison is exact.
        let mirrored: Vec<(Vec<u8>, DiffKind)> = ab
            .diffs
            .iter()
            .map(|d| (d.key.clone(), mirror(d.kind)))
            .collect();
        let reverse: Vec<(Vec<u8>, DiffKind)> =
            ba.diffs.iter().map(|d| (d.key.clone(), d.kind)).collect();
        assert_eq!(
            mirrored, reverse,
            "a.diff(b) must mirror b.diff(a) (seed {seed})"
        );
    }
}

// -- AC1: incremental update equals rebuild (property) -----------------------

#[test]
fn incremental_update_equals_rebuild_over_randomized_operations() {
    let depth = 9u8;
    let mut rng = SplitMix64::new(0x00C0_FFEE);
    let mut tree = MerkleRangeTree::new(depth);
    let mut model: BTreeMap<Vec<u8>, u64> = BTreeMap::new();

    for step in 0..3000u32 {
        let key = format!("key{:02}", rng.next_u64() % 64).into_bytes();
        match rng.next_u64() % 3 {
            // Insert/update is twice as likely as remove, so the tree grows.
            0 | 1 => {
                let hash = rng.next_u64();
                tree.insert(key.clone(), hash);
                model.insert(key, hash);
            }
            _ => {
                tree.remove(&key);
                model.remove(&key);
            }
        }

        if step % 25 == 0 {
            let rebuilt = build_from(depth, &model);
            assert_eq!(
                tree.root(),
                rebuilt.root(),
                "incremental root must equal rebuild at step {step}",
            );
            assert_eq!(tree.len(), model.len(), "len must track the model");
            assert_eq!(tree.is_empty(), model.is_empty());
        }
    }

    // Final cross-check: a fresh rebuild is bit-identical, and the diff between
    // the incrementally-maintained tree and the rebuild is empty (prunes at root).
    let rebuilt = build_from(depth, &model);
    assert_eq!(tree.root(), rebuilt.root());
    assert_eq!(tree.len(), model.len());
    let report = tree.diff(&rebuilt);
    assert!(
        report.diffs.is_empty(),
        "incremental tree equals its rebuild"
    );
    assert_eq!(
        report.nodes_compared, 1,
        "identical roots prune immediately"
    );
}

// -- AC2: reconciliation cost within a constant factor of O(k log n) ----------

#[test]
fn diff_cost_within_constant_factor_of_k_log_n() {
    let depth = 12u8; // 4096 buckets, 8192 implicit nodes
    let mut here = MerkleRangeTree::new(depth);
    let mut there = MerkleRangeTree::new(depth);
    for i in 0..4000u32 {
        let key = format!("key-{i}").into_bytes();
        here.insert(key.clone(), u64::from(i));
        there.insert(key, u64::from(i));
    }

    // Introduce exactly k divergences across distinct keys: two hash changes,
    // one only-there, one only-here.
    let k = 4usize;
    there.insert(b"key-10".to_vec(), 7_000_001);
    there.insert(b"key-1000".to_vec(), 7_000_002);
    there.insert(b"key-7777".to_vec(), 7_000_003); // absent on `here` -> OnlyThere
    there.remove(b"key-3999"); // present on `here` only -> OnlyHere

    let report = here.diff(&there);
    assert_eq!(report.diffs.len(), k, "exactly k divergent keys");

    let depth_us = usize::from(depth);
    let total_nodes = 1usize << (depth + 1); // length of the implicit node array

    // Each divergent key forces at most one root->leaf path; the descent visits
    // those paths and their siblings, bounded by 1 + 2*k*(depth+1).
    let bound = 1 + 2 * k * (depth_us + 1);
    assert!(
        report.nodes_compared <= bound,
        "nodes_compared {} exceeded O(k log n) bound {bound}",
        report.nodes_compared,
    );
    assert!(
        report.nodes_compared < total_nodes / 8,
        "nodes_compared {} must stay far below the full keyspace ({total_nodes} nodes)",
        report.nodes_compared,
    );
}

// -- edges: empty trees, full divergence, depth clamping ----------------------

#[test]
fn empty_and_full_divergence_edges() {
    let depth = 8u8;

    let empty = MerkleRangeTree::new(depth);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let empty2 = MerkleRangeTree::new(depth);
    assert_eq!(
        empty.root(),
        empty2.root(),
        "empty trees of equal depth share a root"
    );
    let same = empty.diff(&empty2);
    assert!(same.diffs.is_empty());
    assert_eq!(same.nodes_compared, 1, "two empty trees prune at the root");

    // Empty vs populated: every populated key is a one-sided divergence.
    let populated = tree_with(depth, &[("a", 1), ("b", 2), ("c", 3)]);
    let only_there = empty.diff(&populated);
    assert_eq!(only_there.diffs.len(), 3);
    assert!(
        only_there
            .diffs
            .iter()
            .all(|d| d.kind == DiffKind::OnlyThere)
    );
    let only_here = populated.diff(&empty);
    assert_eq!(only_here.diffs.len(), 3);
    assert!(only_here.diffs.iter().all(|d| d.kind == DiffKind::OnlyHere));

    // Removing the only key restores the empty root (incremental round-trip).
    let mut t = MerkleRangeTree::new(depth);
    let empty_root = t.root();
    t.insert(b"solo".to_vec(), 42);
    assert_ne!(t.root(), empty_root, "insert changes the root");
    t.remove(b"solo");
    assert_eq!(
        t.root(),
        empty_root,
        "removing the only key restores the empty root"
    );
    assert!(t.is_empty());
}

#[test]
fn depth_is_clamped_to_valid_range() {
    assert_eq!(MerkleRangeTree::new(0).depth(), 1, "depth 0 clamps up to 1");
    assert_eq!(MerkleRangeTree::new(1).depth(), 1);
    assert_eq!(MerkleRangeTree::new(24).depth(), 24);
    assert_eq!(
        MerkleRangeTree::new(200).depth(),
        24,
        "oversized depth clamps to 24"
    );

    // A minimal depth-1 tree (two buckets) still diffs correctly.
    let a = tree_with(1, &[("x", 1)]);
    let b = tree_with(1, &[("x", 2)]);
    let report = a.diff(&b);
    assert_eq!(report.diffs.len(), 1);
    assert_eq!(report.diffs[0].kind, DiffKind::HashDiffers);
}
