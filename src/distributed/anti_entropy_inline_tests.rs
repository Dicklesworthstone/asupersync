    use super::*;

    fn tree_with(depth: u8, entries: &[(&str, u64)]) -> MerkleRangeTree {
        let mut t = MerkleRangeTree::new(depth);
        for (k, h) in entries {
            t.insert(k.as_bytes().to_vec(), *h);
        }
        t
    }

    #[test]
    fn identical_content_yields_identical_root_regardless_of_insert_order() {
        // AC1: deterministic roots across replicas with identical content.
        let a = tree_with(8, &[("alpha", 1), ("beta", 2), ("gamma", 3)]);
        let b = tree_with(8, &[("gamma", 3), ("alpha", 1), ("beta", 2)]);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.diff(&b).diffs, vec![]);
    }

    #[test]
    fn incremental_update_equals_rebuild() {
        // AC1: incremental insert/remove path-recompute == a from-scratch build.
        let mut incremental = MerkleRangeTree::new(8);
        incremental.insert(b"k1".to_vec(), 10);
        incremental.insert(b"k2".to_vec(), 20);
        incremental.insert(b"k3".to_vec(), 30);
        incremental.insert(b"k2".to_vec(), 99); // update
        incremental.remove(b"k3");

        let rebuilt = tree_with(8, &[("k1", 10), ("k2", 99)]);
        assert_eq!(incremental.root(), rebuilt.root());
        assert_eq!(incremental.len(), 2);
    }

    #[test]
    fn diff_finds_exactly_the_divergent_keys() {
        let here = tree_with(8, &[("a", 1), ("b", 2), ("c", 3), ("d", 4)]);
        let there = tree_with(8, &[("a", 1), ("b", 999), ("d", 4), ("e", 5)]);
        let report = here.diff(&there);
        let kinds: Vec<(&[u8], DiffKind)> = report
            .diffs
            .iter()
            .map(|d| (d.key.as_slice(), d.kind))
            .collect();
        assert!(kinds.contains(&(b"b".as_slice(), DiffKind::HashDiffers)));
        assert!(kinds.contains(&(b"c".as_slice(), DiffKind::OnlyHere)));
        assert!(kinds.contains(&(b"e".as_slice(), DiffKind::OnlyThere)));
        assert_eq!(report.diffs.len(), 3);
        // "a" and "d" are identical and must not appear.
        assert!(!kinds.iter().any(|(k, _)| *k == b"a" || *k == b"d"));
    }

    #[test]
    fn diff_cost_scales_with_divergence_not_keyspace() {
        // AC2: many identical keys, a few differing -> few nodes compared.
        let depth = 10u8; // 1024 buckets, 2048 nodes
        let mut here = MerkleRangeTree::new(depth);
        let mut there = MerkleRangeTree::new(depth);
        for i in 0..2000u32 {
            let key = format!("key-{i}").into_bytes();
            here.insert(key.clone(), u64::from(i));
            there.insert(key, u64::from(i));
        }
        // Diverge exactly 3 keys.
        there.insert(b"key-100".to_vec(), 999_999);
        there.insert(b"key-500".to_vec(), 888_888);
        there.remove(b"key-1500");

        let report = here.diff(&there);
        assert_eq!(report.diffs.len(), 3);
        // Identical stores would compare just the root; with 3 divergent keys in
        // at most 3 buckets, far fewer than the full 2*1024 nodes are visited.
        let total_nodes = 2usize * (1usize << depth);
        assert!(
            report.nodes_compared < total_nodes / 4,
            "compared {} of {total_nodes} nodes — should scale with divergence",
            report.nodes_compared
        );
    }

    #[test]
    fn identical_trees_compare_only_the_root() {
        let a = tree_with(8, &[("x", 1), ("y", 2)]);
        let b = tree_with(8, &[("x", 1), ("y", 2)]);
        let report = a.diff(&b);
        assert!(report.diffs.is_empty());
        assert_eq!(
            report.nodes_compared, 1,
            "identical roots prune immediately"
        );
    }
