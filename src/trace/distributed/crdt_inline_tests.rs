    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    /// Helper: verify the three semilattice laws for a CRDT.
    fn assert_semilattice_laws<T: Merge + Clone + PartialEq + std::fmt::Debug>(
        a: &T,
        b: &T,
        c: &T,
    ) {
        // Commutativity: a ⊔ b = b ⊔ a
        let mut ab = a.clone();
        ab.merge(b);
        let mut ba = b.clone();
        ba.merge(a);
        assert_eq!(ab, ba, "commutativity violated");

        // Associativity: (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)
        let mut ab_c = a.clone();
        ab_c.merge(b);
        ab_c.merge(c);
        let mut bc = b.clone();
        bc.merge(c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);
        assert_eq!(ab_c, a_bc, "associativity violated");

        // Idempotence: a ⊔ a = a
        let mut aa = a.clone();
        aa.merge(a);
        assert_eq!(aa, *a, "idempotence violated for a");

        let mut bb = b.clone();
        bb.merge(b);
        assert_eq!(bb, *b, "idempotence violated for b");

        let mut cc = c.clone();
        cc.merge(c);
        assert_eq!(cc, *c, "idempotence violated for c");
    }

    // ── GCounter ─────────────────────────────────────────────────────────

    #[test]
    fn gcounter_increment_and_value() {
        let mut g = GCounter::new();
        g.increment(&node("a"), 3);
        g.increment(&node("b"), 5);
        g.increment(&node("a"), 2);
        assert_eq!(g.value(), 10);
        assert_eq!(g.get(&node("a")), 5);
        assert_eq!(g.get(&node("b")), 5);
    }

    #[test]
    fn gcounter_merge_takes_max() {
        let mut g1 = GCounter::new();
        g1.increment(&node("a"), 3);
        g1.increment(&node("b"), 1);

        let mut g2 = GCounter::new();
        g2.increment(&node("a"), 1);
        g2.increment(&node("b"), 5);

        g1.merge(&g2);
        assert_eq!(g1.get(&node("a")), 3);
        assert_eq!(g1.get(&node("b")), 5);
        assert_eq!(g1.value(), 8);
    }

    #[test]
    fn gcounter_semilattice_laws() {
        let mut a = GCounter::new();
        a.increment(&node("x"), 3);

        let mut b = GCounter::new();
        b.increment(&node("y"), 7);

        let mut c = GCounter::new();
        c.increment(&node("x"), 5);
        c.increment(&node("z"), 2);

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn gcounter_semilattice_laws_overlapping() {
        let mut a = GCounter::new();
        a.increment(&node("n1"), 10);
        a.increment(&node("n2"), 3);

        let mut b = GCounter::new();
        b.increment(&node("n1"), 5);
        b.increment(&node("n2"), 8);
        b.increment(&node("n3"), 1);

        let mut c = GCounter::new();
        c.increment(&node("n2"), 6);
        c.increment(&node("n3"), 4);

        assert_semilattice_laws(&a, &b, &c);
    }

    // ── PNCounter ────────────────────────────────────────────────────────

    #[test]
    fn pncounter_increment_decrement() {
        let mut pn = PNCounter::new();
        pn.increment(&node("a"), 10);
        pn.decrement(&node("b"), 3);
        assert_eq!(pn.value(), 7);
    }

    #[test]
    fn pncounter_negative_value() {
        let mut pn = PNCounter::new();
        pn.decrement(&node("a"), 5);
        assert_eq!(pn.value(), -5);
    }

    #[test]
    fn pncounter_merge() {
        let mut pn1 = PNCounter::new();
        pn1.increment(&node("a"), 10);
        pn1.decrement(&node("b"), 2);

        let mut pn2 = PNCounter::new();
        pn2.increment(&node("a"), 5);
        pn2.decrement(&node("b"), 7);

        pn1.merge(&pn2);
        // positive: max(10,5)=10, negative: max(2,7)=7
        assert_eq!(pn1.value(), 3);
    }

    #[test]
    fn pncounter_semilattice_laws() {
        let mut a = PNCounter::new();
        a.increment(&node("x"), 5);
        a.decrement(&node("y"), 2);

        let mut b = PNCounter::new();
        b.increment(&node("y"), 3);
        b.decrement(&node("x"), 1);

        let mut c = PNCounter::new();
        c.increment(&node("x"), 8);
        c.increment(&node("z"), 1);

        assert_semilattice_laws(&a, &b, &c);
    }

    // ── LWWRegister ──────────────────────────────────────────────────────

    #[test]
    fn lww_set_higher_timestamp_wins() {
        let mut r = LWWRegister::new("old".to_string(), 1, node("a"));
        r.set("new".to_string(), 2, node("a"));
        assert_eq!(r.value(), "new");
    }

    #[test]
    fn lww_set_lower_timestamp_ignored() {
        let mut r = LWWRegister::new("current".to_string(), 5, node("a"));
        r.set("stale".to_string(), 3, node("a"));
        assert_eq!(r.value(), "current");
    }

    #[test]
    fn lww_merge_higher_timestamp_wins() {
        let r1 = LWWRegister::new("v1".to_string(), 3, node("a"));
        let r2 = LWWRegister::new("v2".to_string(), 5, node("b"));

        let mut merged = r1;
        merged.merge(&r2);
        assert_eq!(merged.value(), "v2");
    }

    #[test]
    fn lww_tie_broken_by_node_id() {
        let r1 = LWWRegister::new("from_a".to_string(), 1, node("a"));
        let r2 = LWWRegister::new("from_b".to_string(), 1, node("b"));

        let mut m1 = r1.clone();
        m1.merge(&r2);
        let mut m2 = r2.clone();
        m2.merge(&r1);
        // "b" > "a", so "from_b" wins in both directions.
        assert_eq!(m1.value(), "from_b");
        assert_eq!(m2.value(), "from_b");
    }

    #[test]
    fn lww_semilattice_laws() {
        let a = LWWRegister::new("a".to_string(), 1, node("n1"));
        let b = LWWRegister::new("b".to_string(), 2, node("n2"));
        let c = LWWRegister::new("c".to_string(), 3, node("n3"));
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn lww_semilattice_laws_same_timestamp() {
        let a = LWWRegister::new("a".to_string(), 5, node("n1"));
        let b = LWWRegister::new("b".to_string(), 5, node("n2"));
        let c = LWWRegister::new("c".to_string(), 5, node("n3"));
        assert_semilattice_laws(&a, &b, &c);
    }

    // ── ORSet ────────────────────────────────────────────────────────────

    #[test]
    fn orset_add_remove_contains() {
        let mut s = ORSet::new();
        s.add("x", &node("a"));
        assert!(s.contains(&"x"));
        s.remove(&"x");
        assert!(!s.contains(&"x"));
    }

    #[test]
    fn orset_concurrent_add_survives_remove() {
        let mut s1 = ORSet::new();
        s1.add("x", &node("a"));

        // s2 forks from s1.
        let mut s2 = s1.clone();

        // s1 removes x.
        s1.remove(&"x");
        assert!(!s1.contains(&"x"));

        // s2 concurrently re-adds x.
        s2.add("x", &node("b"));

        // Merge: the concurrent add survives the remove.
        s1.merge(&s2);
        assert!(s1.contains(&"x"));
    }

    #[test]
    fn orset_semilattice_laws() {
        let mut a = ORSet::new();
        a.add("x", &node("n1"));
        a.add("y", &node("n1"));

        let mut b = ORSet::new();
        b.add("y", &node("n2"));
        b.add("z", &node("n2"));

        let mut c = ORSet::new();
        c.add("x", &node("n3"));
        c.add("z", &node("n3"));
        c.add("w", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn orset_len_and_elements() {
        let mut s = ORSet::new();
        assert!(s.is_empty());
        s.add(1, &node("a"));
        s.add(2, &node("a"));
        s.add(1, &node("b")); // duplicate value, different tag
        assert_eq!(s.len(), 2);
        let elems: Vec<_> = s.elements().copied().collect();
        assert_eq!(elems, vec![1, 2]);
    }

    // ── MVRegister ───────────────────────────────────────────────────────

    #[test]
    fn mvregister_single_writer() {
        let mut r = MVRegister::new();
        r.set("v1", &node("a"));
        r.set("v2", &node("a"));
        let vals: Vec<_> = r.values().collect();
        assert_eq!(vals, vec![&"v2"]);
    }

    #[test]
    fn mvregister_concurrent_writes_preserved() {
        let mut r1 = MVRegister::new();
        r1.set("from_a", &node("a"));

        let mut r2 = MVRegister::new();
        r2.set("from_b", &node("b"));

        r1.merge(&r2);
        // Both concurrent values preserved.
        assert_eq!(r1.len(), 2);
        let mut vals: Vec<_> = r1.values().copied().collect();
        vals.sort_unstable();
        assert_eq!(vals, vec!["from_a", "from_b"]);
    }

    #[test]
    fn mvregister_causal_supersedes() {
        let mut r1 = MVRegister::new();
        r1.set("v1", &node("a"));

        // r2 sees r1's state, then overwrites.
        let mut r2 = r1.clone();
        r2.set("v2", &node("b"));

        // Merge: v2 dominates v1 because r2's version vector ≥ r1's.
        r1.merge(&r2);
        let vals: Vec<_> = r1.values().collect();
        assert_eq!(vals, vec![&"v2"]);
    }

    #[test]
    fn mvregister_semilattice_laws() {
        // Three independent concurrent writes.
        let mut a = MVRegister::new();
        a.set("a", &node("n1"));

        let mut b = MVRegister::new();
        b.set("b", &node("n2"));

        let mut c = MVRegister::new();
        c.set("c", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn mvregister_semilattice_laws_with_causal_chain() {
        let mut a = MVRegister::new();
        a.set("a1", &node("n1"));

        let mut b = a.clone();
        b.set("b1", &node("n2"));

        let mut c = b.clone();
        c.set("c1", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    // ── Cross-type integration ───────────────────────────────────────────

    #[test]
    fn gcounter_empty_merge() {
        let a = GCounter::new();
        let b = GCounter::new();
        let c = GCounter::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn pncounter_empty_merge() {
        let a = PNCounter::new();
        let b = PNCounter::new();
        let c = PNCounter::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn orset_empty_merge() {
        let a: ORSet<String> = ORSet::new();
        let b: ORSet<String> = ORSet::new();
        let c: ORSet<String> = ORSet::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn mvregister_empty_merge() {
        let a: MVRegister<String> = MVRegister::new();
        let b: MVRegister<String> = MVRegister::new();
        let c: MVRegister<String> = MVRegister::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    // ── GCounter: multi-node and edge cases ─────────────────────────────

    #[test]
    fn gcounter_five_replicas_semilattice() {
        let nodes: Vec<_> = (0..5).map(|i| node(&format!("n{i}"))).collect();
        let mut a = GCounter::new();
        a.increment(&nodes[0], 10);
        a.increment(&nodes[1], 20);

        let mut b = GCounter::new();
        b.increment(&nodes[1], 15);
        b.increment(&nodes[2], 30);
        b.increment(&nodes[3], 5);

        let mut c = GCounter::new();
        c.increment(&nodes[2], 25);
        c.increment(&nodes[4], 100);

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn gcounter_merge_disjoint_nodes() {
        let mut a = GCounter::new();
        a.increment(&node("x"), 42);
        let mut b = GCounter::new();
        b.increment(&node("y"), 99);

        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.value(), 141);
        assert_eq!(merged.get(&node("x")), 42);
        assert_eq!(merged.get(&node("y")), 99);
    }

    #[test]
    fn gcounter_get_missing_node_returns_zero() {
        let g = GCounter::new();
        assert_eq!(g.get(&node("nonexistent")), 0);
    }

    #[test]
    fn gcounter_merge_chain_converges() {
        // Simulate ring gossip: a→b→c→a
        let mut a = GCounter::new();
        a.increment(&node("a"), 10);
        let mut b = GCounter::new();
        b.increment(&node("b"), 20);
        let mut c = GCounter::new();
        c.increment(&node("c"), 30);

        a.merge(&b);
        b.merge(&c);
        c.merge(&a);
        a.merge(&c);
        b.merge(&a);

        // All should converge to the same state.
        assert_eq!(a.value(), 60);
        assert_eq!(b.value(), 60);
        assert_eq!(c.value(), 60);
    }

    // ── PNCounter: edge cases ───────────────────────────────────────────

    #[test]
    fn pncounter_five_replicas_semilattice() {
        let mut a = PNCounter::new();
        a.increment(&node("n1"), 100);
        a.decrement(&node("n2"), 30);

        let mut b = PNCounter::new();
        b.increment(&node("n2"), 50);
        b.decrement(&node("n3"), 10);

        let mut c = PNCounter::new();
        c.decrement(&node("n1"), 40);
        c.increment(&node("n4"), 25);

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn pncounter_zero_after_symmetric_ops() {
        let mut pn = PNCounter::new();
        pn.increment(&node("a"), 50);
        pn.decrement(&node("b"), 50);
        assert_eq!(pn.value(), 0);
    }

    #[test]
    fn pncounter_merge_chain_converges() {
        let mut a = PNCounter::new();
        a.increment(&node("a"), 10);
        let mut b = PNCounter::new();
        b.decrement(&node("b"), 5);
        let mut c = PNCounter::new();
        c.increment(&node("c"), 3);

        a.merge(&b);
        b.merge(&c);
        c.merge(&a);
        a.merge(&c);
        b.merge(&a);

        assert_eq!(a.value(), 8);
        assert_eq!(b.value(), 8);
        assert_eq!(c.value(), 8);
    }

    // ── LWWRegister: edge cases ─────────────────────────────────────────

    #[test]
    fn lww_five_replicas_semilattice() {
        let a = LWWRegister::new(1, 10, node("n1"));
        let b = LWWRegister::new(2, 20, node("n2"));
        let c = LWWRegister::new(3, 15, node("n3"));
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn lww_set_same_timestamp_different_node_tiebreak() {
        let mut r = LWWRegister::new("first".to_string(), 1, node("a"));
        r.set("second".to_string(), 1, node("b"));
        // "b" > "a" so "second" wins the tie.
        assert_eq!(r.value(), "second");
    }

    #[test]
    fn lww_set_same_timestamp_lower_node_rejected() {
        let mut r = LWWRegister::new("from_b".to_string(), 1, node("b"));
        r.set("from_a".to_string(), 1, node("a"));
        // "a" < "b" so update rejected.
        assert_eq!(r.value(), "from_b");
    }

    #[test]
    fn lww_merge_chain_converges() {
        let mut a = LWWRegister::new("a".to_string(), 1, node("n1"));
        let b = LWWRegister::new("b".to_string(), 3, node("n2"));
        let mut c2 = LWWRegister::new("c".to_string(), 2, node("n3"));

        a.merge(&b);
        c2.merge(&a);
        // Both should have "b" (highest timestamp).
        assert_eq!(a.value(), "b");
        assert_eq!(c2.value(), "b");
    }

    // ── ORSet: extended scenarios ────────────────────────────────────────

    #[test]
    fn orset_five_replicas_semilattice() {
        let mut a = ORSet::new();
        a.add("x", &node("n1"));
        a.add("y", &node("n1"));

        let mut b = ORSet::new();
        b.add("y", &node("n2"));
        b.add("z", &node("n2"));
        b.add("w", &node("n2"));

        let mut c = ORSet::new();
        c.add("x", &node("n3"));
        c.add("w", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn orset_add_remove_add_cycle() {
        let mut s = ORSet::new();
        s.add("item", &node("a"));
        assert!(s.contains(&"item"));
        s.remove(&"item");
        assert!(!s.contains(&"item"));
        s.add("item", &node("a"));
        assert!(s.contains(&"item"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn orset_remove_nonexistent_is_noop() {
        let mut s = ORSet::new();
        s.remove(&"missing");
        assert!(s.is_empty());
    }

    #[test]
    fn orset_concurrent_adds_same_value_both_survive_remove() {
        // Both replicas add "x" concurrently.
        let mut s1 = ORSet::new();
        s1.add("x", &node("a"));
        let mut s2 = ORSet::new();
        s2.add("x", &node("b"));

        // Merge to see both tags.
        s1.merge(&s2);
        assert!(s1.contains(&"x"));

        // Fork: one side removes (clears all known tags), other has a tag.
        let mut fork = s1.clone();
        fork.remove(&"x");
        // After re-merge from a fresh concurrent add, "x" should re-appear.
        let mut s3 = ORSet::new();
        s3.add("x", &node("c"));
        fork.merge(&s3);
        assert!(fork.contains(&"x"));
    }

    #[test]
    fn orset_merge_chain_converges() {
        let mut a = ORSet::new();
        a.add(1, &node("a"));
        let mut b = ORSet::new();
        b.add(2, &node("b"));
        let mut c = ORSet::new();
        c.add(3, &node("c"));

        a.merge(&b);
        b.merge(&c);
        c.merge(&a);
        a.merge(&c);
        b.merge(&a);

        assert_eq!(a.len(), 3);
        assert_eq!(b.len(), 3);
        assert_eq!(c.len(), 3);
    }

    // ── MVRegister: extended scenarios ───────────────────────────────────

    #[test]
    fn mvregister_five_replicas_semilattice() {
        let mut a = MVRegister::new();
        a.set("a", &node("n1"));
        let mut b = MVRegister::new();
        b.set("b", &node("n2"));
        let mut c = MVRegister::new();
        c.set("c", &node("n3"));
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn mvregister_three_concurrent_writes() {
        let mut r1 = MVRegister::new();
        r1.set("a", &node("n1"));
        let mut r2 = MVRegister::new();
        r2.set("b", &node("n2"));
        let mut r3 = MVRegister::new();
        r3.set("c", &node("n3"));

        r1.merge(&r2);
        r1.merge(&r3);
        // All three concurrent values preserved.
        assert_eq!(r1.len(), 3);
    }

    #[test]
    fn mvregister_later_write_supersedes_all() {
        let mut r1 = MVRegister::new();
        r1.set("a", &node("n1"));
        let mut r2 = MVRegister::new();
        r2.set("b", &node("n2"));

        // Merge both concurrent values.
        r1.merge(&r2);
        assert_eq!(r1.len(), 2);

        // A new write from n3 that has seen both should supersede them.
        let mut r3 = r1.clone();
        r3.set("final", &node("n3"));
        r1.merge(&r3);
        let vals: Vec<_> = r1.values().collect();
        assert_eq!(vals, vec![&"final"]);
    }

    #[test]
    fn mvregister_merge_chain_converges() {
        let mut a = MVRegister::new();
        a.set("a", &node("n1"));
        let mut b = MVRegister::new();
        b.set("b", &node("n2"));

        a.merge(&b);
        b.merge(&a);
        assert_eq!(a, b);
    }

    // ── dominates helper ────────────────────────────────────────────────

    #[test]
    fn dominates_strict() {
        let mut a = BTreeMap::new();
        a.insert(node("n1"), 2);
        let mut b = BTreeMap::new();
        b.insert(node("n1"), 1);
        assert!(dominates(&a, &b));
        assert!(!dominates(&b, &a));
    }

    #[test]
    fn dominates_equal_is_false() {
        let mut a = BTreeMap::new();
        a.insert(node("n1"), 3);
        let b = a.clone();
        assert!(!dominates(&a, &b));
    }

    #[test]
    fn dominates_concurrent_is_false() {
        let mut a = BTreeMap::new();
        a.insert(node("n1"), 2);
        a.insert(node("n2"), 0);
        let mut b = BTreeMap::new();
        b.insert(node("n1"), 0);
        b.insert(node("n2"), 2);
        assert!(!dominates(&a, &b));
        assert!(!dominates(&b, &a));
    }

    #[test]
    fn dominates_superset_keys() {
        let mut a = BTreeMap::new();
        a.insert(node("n1"), 1);
        a.insert(node("n2"), 1);
        let mut b = BTreeMap::new();
        b.insert(node("n1"), 1);
        // a has extra key n2 with value > 0, so a dominates b.
        assert!(dominates(&a, &b));
    }
