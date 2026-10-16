    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::obligation::crdt::CrdtObligationLedger;
    use crate::record::ObligationKind;
    use crate::remote::NodeId;
    use crate::trace::distributed::crdt::Merge;
    use crate::types::ObligationId;

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    fn test_config() -> RecoveryConfig {
        RecoveryConfig {
            stale_timeout_ns: 1000,
            max_resolutions_per_tick: 100,
            auto_resolve_conflicts: true,
            auto_abort_violations: true,
        }
    }

    // ── Basic lifecycle ─────────────────────────────────────────────────

    #[test]
    fn governor_starts_idle() {
        let gov = RecoveryGovernor::new(test_config());
        assert_eq!(gov.phase(), RecoveryPhase::Idle);
        assert_eq!(gov.total_ticks(), 0);
    }

    #[test]
    fn clean_ledger_is_quiescent() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));

        let result = gov.tick(&mut ledger, 0);
        assert!(result.is_quiescent);
        assert_eq!(result.action_count(), 0);
    }

    #[test]
    fn pending_obligation_not_stale_yet() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        // First tick at t=0: discovers the obligation, sets first_seen
        let result = gov.tick(&mut ledger, 0);
        assert!(!result.is_quiescent);
        assert_eq!(result.action_count(), 0);
        assert_eq!(result.remaining_pending, 1);

        // Second tick at t=500: not yet stale (timeout=1000)
        let result = gov.tick(&mut ledger, 500);
        assert_eq!(result.action_count(), 0);
    }

    // ── Stale obligation recovery ───────────────────────────────────────

    #[test]
    fn stale_obligation_is_aborted() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        // First tick: discover and set first_seen
        gov.tick(&mut ledger, 0);

        // Second tick after timeout: should abort
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.action_count(), 1);
        assert!(matches!(
            &result.actions[0],
            RecoveryAction::StaleAbort { id, age_ns } if *id == oid(1) && *age_ns >= 1000
        ));
        assert_eq!(ledger.get(&oid(1)), LatticeState::Aborted);
    }

    #[test]
    fn resolved_obligation_not_considered_stale() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        // First tick at t=0
        gov.tick(&mut ledger, 0);

        // Resolve before timeout
        ledger.record_commit(oid(1));

        // Tick after timeout: should not abort (already committed)
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.action_count(), 0);
        assert_eq!(ledger.get(&oid(1)), LatticeState::Committed);
    }

    // ── Conflict resolution ─────────────────────────────────────────────

    #[test]
    fn conflict_auto_resolved_by_abort() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        // Merge creates conflict
        a.merge(&b);
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);

        // Recovery resolves it
        let result = gov.tick(&mut a, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ConflictResolved { .. }))
        );
    }

    #[test]
    fn conflict_repair_survives_stale_merge() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);
        let stale_conflict = a.clone();
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);

        let result = gov.tick(&mut a, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ConflictResolved { .. }))
        );

        a.merge(&stale_conflict);
        let repaired = a.get_entry(&oid(1)).expect("entry should exist");
        assert_eq!(repaired.state, LatticeState::Aborted);
        assert!(repaired.is_linear());
        assert!(!repaired.is_conflict());
    }

    #[test]
    fn conflict_flagged_when_auto_resolve_disabled() {
        let mut config = test_config();
        config.auto_resolve_conflicts = false;
        let mut gov = RecoveryGovernor::new(config);

        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);

        let result = gov.tick(&mut a, 0);
        assert_eq!(result.action_count(), 1);
        assert!(matches!(
            &result.actions[0],
            RecoveryAction::Flagged { id, reason }
                if *id == oid(1) && reason == "conflict: Committed ⊔ Aborted"
        ));
        assert!(result.remaining_conflicts > 0);
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);
    }

    // ── Linearity violation recovery ────────────────────────────────────

    #[test]
    fn linearity_violation_auto_aborted() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit); // double acquire

        let result = gov.tick(&mut ledger, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ViolationAborted { .. }))
        );
    }

    #[test]
    fn linearity_violation_flagged_when_auto_disabled() {
        let mut config = test_config();
        config.auto_abort_violations = false;
        let mut gov = RecoveryGovernor::new(config);

        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        let result = gov.tick(&mut ledger, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::Flagged { .. }))
        );
    }

    // ── Convergence ─────────────────────────────────────────────────────

    #[test]
    fn repeated_ticks_converge_to_quiescence() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));

        // Create a messy state: stale, conflict, violation
        ledger.record_acquire(oid(1), ObligationKind::SendPermit); // will go stale
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        ledger.record_acquire(oid(2), ObligationKind::Ack); // violation

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(3), ObligationKind::Lease);
        b.record_commit(oid(3));
        let mut c = CrdtObligationLedger::new(node("C"));
        c.record_acquire(oid(3), ObligationKind::Lease);
        c.record_abort(oid(3));
        b.merge(&c); // conflict on oid(3)
        ledger.merge(&b);

        // First tick at t=0: resolves conflict and violation, discovers stale
        let r1 = gov.tick(&mut ledger, 0);
        assert!(r1.action_count() > 0);

        // After timeout: stale obligation gets aborted
        let _r2 = gov.tick(&mut ledger, 2000);

        // Should converge: no more pending, conflicts, or violations
        let r3 = gov.tick(&mut ledger, 3000);
        assert!(
            r3.is_quiescent,
            "not quiescent: pending={}, conflicts={}, violations={}",
            r3.remaining_pending, r3.remaining_conflicts, r3.remaining_violations
        );
    }

    #[test]
    fn convergence_is_monotonic() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));

        // Create several pending obligations
        for i in 0..5 {
            ledger.record_acquire(oid(i), ObligationKind::SendPermit);
        }

        // Discover all at t=0
        gov.tick(&mut ledger, 0);

        // After timeout: all should be aborted
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.remaining_pending, 0);

        // Additional tick: no more actions needed
        let result2 = gov.tick(&mut ledger, 3000);
        assert_eq!(result2.action_count(), 0);
        assert!(result2.is_quiescent);
    }

    // ── Budget limiting ─────────────────────────────────────────────────

    #[test]
    fn max_resolutions_per_tick_respected() {
        let mut config = test_config();
        config.max_resolutions_per_tick = 2;
        let mut gov = RecoveryGovernor::new(config);

        let mut ledger = CrdtObligationLedger::new(node("A"));
        for i in 0..5 {
            ledger.record_acquire(oid(i), ObligationKind::SendPermit);
        }

        // Discover all
        gov.tick(&mut ledger, 0);

        // After timeout: limited to 2 resolutions
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.action_count(), 2);
        assert_eq!(result.remaining_pending, 3);

        // Next tick resolves 2 more
        let result2 = gov.tick(&mut ledger, 3000);
        assert_eq!(result2.action_count(), 2);
        assert_eq!(result2.remaining_pending, 1);
    }

    // ── Reset ───────────────────────────────────────────────────────────

    #[test]
    fn reset_clears_state() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        gov.tick(&mut ledger, 0);

        gov.reset();
        assert_eq!(gov.phase(), RecoveryPhase::Idle);
        assert_eq!(gov.total_ticks(), 0);
        assert_eq!(gov.total_actions(), 0);
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn recovery_action_display() {
        let action = RecoveryAction::StaleAbort {
            id: oid(1),
            age_ns: 5000,
        };
        let display = format!("{action}");
        assert!(display.starts_with("[ASUP-E105]"));
        assert!(display.contains("stale-abort"));
        assert!(display.contains("5000"));
    }

    #[test]
    fn recovery_phase_display() {
        assert_eq!(format!("{}", RecoveryPhase::Idle), "Idle");
        assert_eq!(format!("{}", RecoveryPhase::Scanning), "Scanning");
        assert_eq!(format!("{}", RecoveryPhase::Resolving), "Resolving");
    }

    // ── Partition/heal scenario ─────────────────────────────────────────

    #[test]
    fn partition_heal_converges() {
        let mut gov = RecoveryGovernor::new(test_config());

        // Node A acquires and commits
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        // Node B (partitioned) only saw the acquire
        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);

        // Node B runs recovery: oid(1) appears stale on B
        gov.tick(&mut b, 0);
        let _result = gov.tick(&mut b, 2000);
        // B aborts it (stale)
        assert_eq!(b.get(&oid(1)), LatticeState::Aborted);

        // Partition heals: merge A and B
        a.merge(&b);
        // Committed ⊔ Aborted = Conflict
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);

        // Recovery resolves the conflict
        let mut gov2 = RecoveryGovernor::new(test_config());
        let result = gov2.tick(&mut a, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ConflictResolved { .. }))
        );
    }

    #[test]
    fn recovery_config_debug_clone_default() {
        let c = RecoveryConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("RecoveryConfig"));

        let c2 = c;
        assert_eq!(c2.stale_timeout_ns, 30_000_000_000);
        assert_eq!(c2.max_resolutions_per_tick, 50);

        let c3 = RecoveryConfig::default_for_test();
        assert_eq!(c3.stale_timeout_ns, 5_000_000_000);
    }

    #[test]
    fn recovery_phase_debug_clone_copy_eq() {
        let p = RecoveryPhase::Idle;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Idle"));

        let p2 = p;
        assert_eq!(p, p2);

        let p3 = p;
        assert_eq!(p, p3);

        assert_ne!(RecoveryPhase::Idle, RecoveryPhase::Scanning);
    }

    #[test]
    fn recovery_action_debug_clone_eq() {
        let a = RecoveryAction::ConflictResolved { id: oid(42) };
        let dbg = format!("{a:?}");
        assert!(dbg.contains("ConflictResolved"));

        let a2 = a.clone();
        assert_eq!(a, a2);

        let a3 = RecoveryAction::Flagged {
            id: oid(1),
            reason: "test".into(),
        };
        assert_ne!(a, a3);
    }

    #[test]
    fn recovery_tick_result_debug_clone() {
        let r = RecoveryTickResult {
            actions: vec![],
            remaining_pending: 0,
            remaining_conflicts: 0,
            remaining_violations: 0,
            is_quiescent: true,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RecoveryTickResult"));

        let r2 = r;
        assert!(r2.is_quiescent);
        assert!(r2.actions.is_empty());
    }
