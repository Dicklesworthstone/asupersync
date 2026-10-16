    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    // -----------------------------------------------------------------------
    // LatticeState semilattice laws
    // -----------------------------------------------------------------------

    #[test]
    fn join_is_commutative() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "commutativity failed for {a:?} ⊔ {b:?}"
                );
            }
        }
    }

    #[test]
    fn join_is_associative() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
                        "associativity failed for ({a:?} ⊔ {b:?}) ⊔ {c:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn join_is_idempotent() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &a in &states {
            assert_eq!(a.join(a), a, "idempotency failed for {a:?}");
        }
    }

    #[test]
    fn unknown_is_bottom() {
        let states = [
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &s in &states {
            assert_eq!(LatticeState::Unknown.join(s), s);
            assert_eq!(s.join(LatticeState::Unknown), s);
        }
    }

    #[test]
    fn conflict_is_top() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
        ];
        for &s in &states {
            assert_eq!(LatticeState::Conflict.join(s), LatticeState::Conflict);
            assert_eq!(s.join(LatticeState::Conflict), LatticeState::Conflict);
        }
    }

    #[test]
    fn committed_aborted_is_conflict() {
        assert_eq!(
            LatticeState::Committed.join(LatticeState::Aborted),
            LatticeState::Conflict
        );
    }

    #[test]
    fn reserved_progresses_to_committed() {
        assert_eq!(
            LatticeState::Reserved.join(LatticeState::Committed),
            LatticeState::Committed
        );
    }

    #[test]
    fn reserved_progresses_to_aborted() {
        assert_eq!(
            LatticeState::Reserved.join(LatticeState::Aborted),
            LatticeState::Aborted
        );
    }

    // -----------------------------------------------------------------------
    // LeaseLatticeState
    // -----------------------------------------------------------------------

    #[test]
    fn lease_join_is_commutative() {
        let states = [
            LeaseLatticeState::Unknown,
            LeaseLatticeState::Active,
            LeaseLatticeState::Released,
            LeaseLatticeState::Expired,
            LeaseLatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                assert_eq!(a.join(b), b.join(a));
            }
        }
    }

    #[test]
    fn lease_join_is_associative() {
        let states = [
            LeaseLatticeState::Unknown,
            LeaseLatticeState::Active,
            LeaseLatticeState::Released,
            LeaseLatticeState::Expired,
            LeaseLatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    assert_eq!(a.join(b).join(c), a.join(b.join(c)));
                }
            }
        }
    }

    #[test]
    fn lease_join_is_idempotent() {
        let states = [
            LeaseLatticeState::Unknown,
            LeaseLatticeState::Active,
            LeaseLatticeState::Released,
            LeaseLatticeState::Expired,
            LeaseLatticeState::Conflict,
        ];
        for &a in &states {
            assert_eq!(a.join(a), a);
        }
    }

    #[test]
    fn lease_released_expired_is_conflict() {
        assert_eq!(
            LeaseLatticeState::Released.join(LeaseLatticeState::Expired),
            LeaseLatticeState::Conflict
        );
    }

    #[test]
    fn lease_active_progresses() {
        assert_eq!(
            LeaseLatticeState::Active.join(LeaseLatticeState::Released),
            LeaseLatticeState::Released
        );
        assert_eq!(
            LeaseLatticeState::Active.join(LeaseLatticeState::Expired),
            LeaseLatticeState::Expired
        );
    }

    // -----------------------------------------------------------------------
    // ObligationLattice
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_lattice_observe_single() {
        let mut lat = ObligationLattice::new();
        let id = oid(1);
        let n = node("A");

        let result = lat.observe(id, n, LatticeState::Reserved);
        assert_eq!(result, LatticeState::Reserved);
        assert_eq!(lat.get(&id), LatticeState::Reserved);
    }

    #[test]
    fn obligation_lattice_observe_progression() {
        let mut lat = ObligationLattice::new();
        let id = oid(1);
        let na = node("A");
        let nb = node("B");

        lat.observe(id, na, LatticeState::Reserved);
        let result = lat.observe(id, nb, LatticeState::Committed);
        assert_eq!(result, LatticeState::Committed);
    }

    #[test]
    fn obligation_lattice_detects_conflict() {
        let mut lat = ObligationLattice::new();
        let id = oid(1);
        let na = node("A");
        let nb = node("B");

        lat.observe(id, na.clone(), LatticeState::Committed);
        let result = lat.observe(id, nb.clone(), LatticeState::Aborted);
        assert_eq!(result, LatticeState::Conflict);
        assert!(lat.has_conflicts());

        let conflicts = lat.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].0, id);
        // Witnesses show who reported what
        let entry = &conflicts[0].1;
        assert_eq!(entry.witnesses.get(&na), Some(&LatticeState::Committed));
        assert_eq!(entry.witnesses.get(&nb), Some(&LatticeState::Aborted));
    }

    #[test]
    fn obligation_lattice_merge_two_replicas() {
        let na = node("A");
        let nb = node("B");
        let id1 = oid(1);
        let id2 = oid(2);

        let mut replica_a = ObligationLattice::new();
        replica_a.observe(id1, na.clone(), LatticeState::Committed);
        replica_a.observe(id2, na, LatticeState::Reserved);

        let mut replica_b = ObligationLattice::new();
        replica_b.observe(id1, nb.clone(), LatticeState::Reserved);
        replica_b.observe(id2, nb, LatticeState::Aborted);

        // Merge B into A
        replica_a.merge(&replica_b);

        // id1: Committed ⊔ Reserved = Committed
        assert_eq!(replica_a.get(&id1), LatticeState::Committed);
        // id2: Reserved ⊔ Aborted = Aborted
        assert_eq!(replica_a.get(&id2), LatticeState::Aborted);
        assert!(!replica_a.has_conflicts());
    }

    #[test]
    fn obligation_lattice_merge_is_commutative() {
        let na = node("A");
        let nb = node("B");
        let id = oid(1);

        let mut a = ObligationLattice::new();
        a.observe(id, na, LatticeState::Committed);

        let mut b = ObligationLattice::new();
        b.observe(id, nb, LatticeState::Reserved);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.get(&id), ba.get(&id));
    }

    #[test]
    fn lattice_state_partial_order() {
        assert!(LatticeState::Unknown < LatticeState::Reserved);
        assert!(LatticeState::Reserved < LatticeState::Committed);
        assert!(LatticeState::Reserved < LatticeState::Aborted);
        assert!(LatticeState::Committed < LatticeState::Conflict);
        assert!(LatticeState::Aborted < LatticeState::Conflict);
        // Committed and Aborted are incomparable
        assert_eq!(
            LatticeState::Committed.partial_cmp(&LatticeState::Aborted),
            None
        );
    }

    #[test]
    fn unknown_obligation_returns_unknown() {
        let lat = ObligationLattice::new();
        assert_eq!(lat.get(&oid(99)), LatticeState::Unknown);
    }

    #[test]
    fn lattice_state_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let s = LatticeState::Committed;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Committed"), "{dbg}");
        let copied: LatticeState = s;
        let cloned = s;
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(LatticeState::Unknown);
        set.insert(LatticeState::Reserved);
        set.insert(LatticeState::Committed);
        set.insert(LatticeState::Aborted);
        set.insert(LatticeState::Conflict);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn lease_lattice_state_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let s = LeaseLatticeState::Active;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"), "{dbg}");
        let copied: LeaseLatticeState = s;
        let cloned = s;
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(LeaseLatticeState::Unknown);
        set.insert(LeaseLatticeState::Active);
        set.insert(LeaseLatticeState::Released);
        set.insert(LeaseLatticeState::Expired);
        set.insert(LeaseLatticeState::Conflict);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn obligation_lattice_debug_clone() {
        let mut lat = ObligationLattice::new();
        lat.observe(oid(1), node("n1"), LatticeState::Reserved);
        let dbg = format!("{lat:?}");
        assert!(dbg.contains("ObligationLattice"), "{dbg}");
        let cloned = lat.clone();
        assert_eq!(cloned.get(&oid(1)), LatticeState::Reserved);
    }
