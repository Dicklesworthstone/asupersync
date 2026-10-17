    use super::*;
    use crate::types::TaskId;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn r(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn o(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn reserve(
        time_ns: u64,
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            },
        )
    }

    fn commit(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            },
        )
    }

    fn abort(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            },
        )
    }

    fn leak(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Leak {
                obligation,
                region,
                kind,
            },
        )
    }

    fn close(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    // ---- Contract 1: ExhaustiveResolution ----------------------------------

    #[test]
    fn exhaustive_resolution_clean_trace() {
        init_test("exhaustive_resolution_clean_trace");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "clean", true, clean);
        let satisfied = result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(satisfied, "exhaustive_resolution", true, satisfied);
        crate::test_complete!("exhaustive_resolution_clean_trace");
    }

    #[test]
    fn exhaustive_resolution_violated_by_unresolved() {
        init_test("exhaustive_resolution_violated_by_unresolved");
        let events = vec![
            reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
            // No commit or abort — obligation remains Reserved.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(!clean, "not clean", false, clean);
        let violations = result.violations_for(DialecticaContract::ExhaustiveResolution);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "violation count", 1, count);
        crate::test_complete!("exhaustive_resolution_violated_by_unresolved");
    }

    #[test]
    fn exhaustive_resolution_abort_counts_as_resolved() {
        init_test("exhaustive_resolution_abort_counts_as_resolved");
        let events = vec![
            reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
            abort(5, o(0), r(0), ObligationKind::Lease),
            close(10, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "abort resolves", true, clean);
        crate::test_complete!("exhaustive_resolution_abort_counts_as_resolved");
    }

    #[test]
    fn exhaustive_resolution_leak_counts_as_terminal() {
        init_test("exhaustive_resolution_leak_counts_as_terminal");
        // Leak is a terminal state — it satisfies ExhaustiveResolution
        // (even though it represents an error).
        let events = vec![
            reserve(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::IoOp),
            close(10, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let exhaustive_ok = result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(exhaustive_ok, "leak is terminal", true, exhaustive_ok);
        crate::test_complete!("exhaustive_resolution_leak_counts_as_terminal");
    }

    // ---- Contract 2: NoPartialCommit ---------------------------------------

    #[test]
    fn no_partial_commit_double_commit_detected() {
        init_test("no_partial_commit_double_commit_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(20, o(0), r(0), ObligationKind::SendPermit), // Double commit.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "double commit violation", 1, count);
        crate::test_complete!("no_partial_commit_double_commit_detected");
    }

    #[test]
    fn no_partial_commit_commit_after_abort_detected() {
        init_test("no_partial_commit_commit_after_abort_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
            abort(5, o(0), r(0), ObligationKind::Ack),
            commit(10, o(0), r(0), ObligationKind::Ack), // Commit after abort.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "commit-after-abort violation", 1, count);
        crate::test_complete!("no_partial_commit_commit_after_abort_detected");
    }

    #[test]
    fn no_partial_commit_resolve_without_reserve() {
        init_test("no_partial_commit_resolve_without_reserve");
        let events = vec![
            commit(10, o(99), r(0), ObligationKind::Lease), // No reserve for o(99).
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "resolve without reserve", 1, count);
        crate::test_complete!("no_partial_commit_resolve_without_reserve");
    }

    // ---- Contract 3: RegionClosureSafety -----------------------------------

    #[test]
    fn region_closure_safety_clean() {
        init_test("region_closure_safety_clean");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let ok = result
            .contract_status
            .is_satisfied(DialecticaContract::RegionClosureSafety);
        crate::assert_with_log!(ok, "region closure safe", true, ok);
        crate::test_complete!("region_closure_safety_clean");
    }

    #[test]
    fn region_closure_safety_violated_by_pending() {
        init_test("region_closure_safety_violated_by_pending");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)), // Close with o(0) still pending.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::RegionClosureSafety);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "region closure violation", 1, count);
        crate::test_complete!("region_closure_safety_violated_by_pending");
    }

    #[test]
    fn region_closure_safety_multiple_pending() {
        init_test("region_closure_safety_multiple_pending");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Lease, t(0), r(0)),
            close(10, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::RegionClosureSafety);
        let count = violations.len();
        crate::assert_with_log!(count == 2, "two pending obligations", 2, count);
        crate::test_complete!("region_closure_safety_multiple_pending");
    }

    #[test]
    fn region_closure_only_checks_matching_region() {
        init_test("region_closure_only_checks_matching_region");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(1)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)), // Only r(0) closes — r(1) is fine to have pending.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::RegionClosureSafety);
        let count = violations.len();
        crate::assert_with_log!(count == 0, "other region not checked", 0, count);
        // But ExhaustiveResolution will catch the unresolved o(1).
        let exhaust = result.violations_for(DialecticaContract::ExhaustiveResolution);
        let exhaust_count = exhaust.len();
        crate::assert_with_log!(exhaust_count == 1, "unresolved caught", 1, exhaust_count);
        crate::test_complete!("region_closure_only_checks_matching_region");
    }

    // ---- Contract 5: KindUniformStateMachine -------------------------------

    #[test]
    fn kind_uniform_all_kinds_same_lifecycle() {
        init_test("kind_uniform_all_kinds_same_lifecycle");
        // Every kind follows exactly the same reserve → commit lifecycle.
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let idx = i as u32;
            let events = vec![
                reserve(0, o(idx), *kind, t(0), r(0)),
                commit(10, o(idx), r(0), *kind),
                close(20, r(0)),
            ];

            let mut checker = ContractChecker::new();
            let result = checker.check(&events);
            let clean = result.is_clean();
            crate::assert_with_log!(clean, format!("{kind} clean"), true, clean);
        }
        crate::test_complete!("kind_uniform_all_kinds_same_lifecycle");
    }

    #[test]
    fn kind_uniform_mismatch_detected() {
        init_test("kind_uniform_mismatch_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // Resolve with a different kind — violation.
            commit(10, o(0), r(0), ObligationKind::Lease),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::KindUniformStateMachine);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "kind mismatch", 1, count);
        crate::test_complete!("kind_uniform_mismatch_detected");
    }

    // ---- Morphism type tests -----------------------------------------------

    #[test]
    fn morphism_lifecycle_commit() {
        init_test("morphism_lifecycle_commit");
        let mut m = DialecticaMorphism::new(ObligationKind::SendPermit);
        let pending = m.is_pending();
        crate::assert_with_log!(!pending, "not pending before forward", false, pending);

        m.forward();
        let pending = m.is_pending();
        crate::assert_with_log!(pending, "pending after forward", true, pending);

        m.backward(ObligationState::Committed);
        let complete = m.is_complete();
        crate::assert_with_log!(complete, "complete after backward", true, complete);
        let clean = m.is_clean();
        crate::assert_with_log!(clean, "clean (committed)", true, clean);
        crate::test_complete!("morphism_lifecycle_commit");
    }

    #[test]
    fn morphism_lifecycle_abort() {
        init_test("morphism_lifecycle_abort");
        let mut m = DialecticaMorphism::new(ObligationKind::Lease);
        m.forward();
        m.backward(ObligationState::Aborted);
        let complete = m.is_complete();
        crate::assert_with_log!(complete, "complete", true, complete);
        let clean = m.is_clean();
        crate::assert_with_log!(clean, "clean (aborted)", true, clean);
        crate::test_complete!("morphism_lifecycle_abort");
    }

    #[test]
    fn morphism_lifecycle_leaked_not_clean() {
        init_test("morphism_lifecycle_leaked_not_clean");
        let mut m = DialecticaMorphism::new(ObligationKind::IoOp);
        m.forward();
        m.backward(ObligationState::Leaked);
        let complete = m.is_complete();
        crate::assert_with_log!(complete, "complete (leaked)", true, complete);
        let clean = m.is_clean();
        crate::assert_with_log!(!clean, "not clean (leaked)", false, clean);
        crate::test_complete!("morphism_lifecycle_leaked_not_clean");
    }

    #[test]
    #[should_panic(expected = "forward step already taken")]
    fn morphism_double_forward_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::Ack);
        m.forward();
        m.forward(); // Should panic.
    }

    #[test]
    #[should_panic(expected = "cannot resolve without forward step")]
    fn morphism_backward_without_forward_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::Ack);
        m.backward(ObligationState::Committed); // Should panic.
    }

    #[test]
    #[should_panic(expected = "backward step already taken")]
    fn morphism_double_backward_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::SendPermit);
        m.forward();
        m.backward(ObligationState::Committed);
        m.backward(ObligationState::Aborted); // Should panic.
    }

    #[test]
    #[should_panic(expected = "resolution must be terminal")]
    fn morphism_non_terminal_resolution_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::Lease);
        m.forward();
        m.backward(ObligationState::Reserved); // Not terminal — panic.
    }

    // ---- Display tests -----------------------------------------------------

    #[test]
    fn display_morphism() {
        init_test("display_morphism");
        let m = DialecticaMorphism::new(ObligationKind::SendPermit);
        let s = format!("{m}");
        let has_idle = s.contains("idle");
        crate::assert_with_log!(has_idle, "idle display", true, has_idle);

        let mut m2 = DialecticaMorphism::new(ObligationKind::Lease);
        m2.forward();
        let s2 = format!("{m2}");
        let has_pending = s2.contains("pending");
        crate::assert_with_log!(has_pending, "pending display", true, has_pending);

        m2.backward(ObligationState::Committed);
        let s3 = format!("{m2}");
        let has_committed = s3.contains("committed");
        crate::assert_with_log!(has_committed, "committed display", true, has_committed);
        crate::test_complete!("display_morphism");
    }

    #[test]
    fn display_contract() {
        init_test("display_contract");
        let c = DialecticaContract::ExhaustiveResolution;
        let s = format!("{c}");
        let has_name = s.contains("ExhaustiveResolution");
        crate::assert_with_log!(has_name, "contract display", true, has_name);
        crate::test_complete!("display_contract");
    }

    #[test]
    fn display_result() {
        init_test("display_result");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let s = format!("{result}");
        let has_pass = s.contains("PASS");
        crate::assert_with_log!(has_pass, "result has PASS", true, has_pass);
        let has_clean = s.contains("Clean: true");
        crate::assert_with_log!(has_clean, "result shows clean", true, has_clean);
        crate::test_complete!("display_result");
    }

    // ---- Realistic scenarios -----------------------------------------------

    #[test]
    fn realistic_channel_send_with_cancel() {
        init_test("realistic_channel_send_with_cancel");
        // Two tasks, one sends and commits, one gets cancelled and aborts.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::SendPermit), // Task 1 cancelled.
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "cancel handled correctly", true, clean);
        crate::test_complete!("realistic_channel_send_with_cancel");
    }

    #[test]
    fn realistic_nested_regions_with_obligations() {
        init_test("realistic_nested_regions_with_obligations");
        // Parent region r(0) with child region r(1).
        // Each has its own obligation, resolved before respective close.
        let events = vec![
            reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit(10, o(1), r(1), ObligationKind::SendPermit),
            close(15, r(1)),
            commit(20, o(0), r(0), ObligationKind::Lease),
            close(25, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "nested regions clean", true, clean);
        crate::test_complete!("realistic_nested_regions_with_obligations");
    }

    #[test]
    fn realistic_mixed_resolution_types() {
        init_test("realistic_mixed_resolution_types");
        // Four obligations, each resolved differently.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(1), r(0)),
            reserve(3, o(3), ObligationKind::IoOp, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::Ack),
            commit(12, o(2), r(0), ObligationKind::Lease),
            leak(13, o(3), r(0), ObligationKind::IoOp), // IoOp leaked.
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        // ExhaustiveResolution: satisfied (leak is terminal).
        let exhaustive = result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(exhaustive, "exhaustive ok", true, exhaustive);
        // Region closure: satisfied (all resolved before close).
        let closure = result
            .contract_status
            .is_satisfied(DialecticaContract::RegionClosureSafety);
        crate::assert_with_log!(closure, "closure ok", true, closure);
        // All contracts satisfied even with a leak, because leak is terminal.
        let all = result.contract_status.all_satisfied();
        crate::assert_with_log!(all, "all contracts", true, all);
        crate::test_complete!("realistic_mixed_resolution_types");
    }

    #[test]
    fn realistic_all_violations_in_one_trace() {
        init_test("realistic_all_violations_in_one_trace");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // Double commit (NoPartialCommit violation).
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            commit(6, o(0), r(0), ObligationKind::SendPermit),
            // Reserve but don't resolve (ExhaustiveResolution violation).
            reserve(10, o(1), ObligationKind::Ack, t(0), r(0)),
            // Close region with pending o(1) (RegionClosureSafety violation).
            close(20, r(0)),
            // Kind mismatch (KindUniformStateMachine violation).
            reserve(30, o(2), ObligationKind::Lease, t(0), r(1)),
            commit(35, o(2), r(1), ObligationKind::IoOp),
            close(40, r(1)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(!clean, "not clean", false, clean);

        // Check each contract.
        let npc = !result
            .contract_status
            .is_satisfied(DialecticaContract::NoPartialCommit);
        crate::assert_with_log!(npc, "no_partial_commit violated", true, npc);

        let er = !result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(er, "exhaustive_resolution violated", true, er);

        let rcs = !result
            .contract_status
            .is_satisfied(DialecticaContract::RegionClosureSafety);
        crate::assert_with_log!(rcs, "region_closure_safety violated", true, rcs);

        let kus = !result
            .contract_status
            .is_satisfied(DialecticaContract::KindUniformStateMachine);
        crate::assert_with_log!(kus, "kind_uniform violated", true, kus);

        crate::test_complete!("realistic_all_violations_in_one_trace");
    }

    // ---- Checker reuse test ------------------------------------------------

    #[test]
    fn checker_reuse() {
        init_test("checker_reuse");
        let mut checker = ContractChecker::new();

        // First run — violation.
        let events1 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)),
        ];
        let r1 = checker.check(&events1);
        let r1_clean = r1.is_clean();
        crate::assert_with_log!(!r1_clean, "first not clean", false, r1_clean);

        // Second run — clean.
        let events2 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)),
        ];
        let r2 = checker.check(&events2);
        let r2_clean = r2.is_clean();
        crate::assert_with_log!(r2_clean, "second clean", true, r2_clean);

        // First result unaffected.
        let r1_count = r1.violations.len();
        crate::assert_with_log!(
            r1_count >= 1,
            "first still has violations",
            true,
            r1_count >= 1
        );
        crate::test_complete!("checker_reuse");
    }

    #[test]
    fn duplicate_reserve_detected() {
        init_test("duplicate_reserve_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(0), ObligationKind::SendPermit, t(1), r(0)), // DUPLICATE!
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(!clean, "duplicate reserve not clean", false, clean);

        let npc_violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = npc_violations.len();
        crate::assert_with_log!(count >= 1, "duplicate reserve violation", true, count >= 1);
        crate::test_complete!("duplicate_reserve_detected");
    }

    #[test]
    fn dialectica_contract_debug_clone_copy_eq() {
        let c = DialecticaContract::ExhaustiveResolution;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ExhaustiveResolution"));

        let c2 = c;
        assert_eq!(c, c2);

        let c3 = c;
        assert_eq!(c, c3);

        assert_ne!(
            DialecticaContract::ExhaustiveResolution,
            DialecticaContract::NoPartialCommit
        );
    }

    #[test]
    fn contract_checker_debug_default() {
        let cc = ContractChecker::default();
        let dbg = format!("{cc:?}");
        assert!(dbg.contains("ContractChecker"));

        let cc2 = ContractChecker::new();
        let dbg2 = format!("{cc2:?}");
        assert!(dbg2.contains("ContractChecker"));
    }

    #[test]
    fn dialectica_morphism_debug_clone_copy_eq() {
        let m = DialecticaMorphism::new(ObligationKind::SendPermit);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("DialecticaMorphism"));

        let m2 = m;
        assert_eq!(m, m2);

        let m3 = m;
        assert_eq!(m, m3);

        assert!(!m.forward_taken);
        assert!(!m.backward_taken);
    }

    // =========================================================================
    // METAMORPHIC TESTING: Adversarial Permit Constraints
    // =========================================================================

    /// Configuration for metamorphic testing
    #[derive(Debug, Clone)]
    struct DialecticaMetamorphicConfig {
        /// Number of obligations to test
        obligation_count: u32,
        /// Number of regions to use
        region_count: u32,
        /// Time range for events (nanoseconds)
        max_time_ns: u64,
        /// Obligation kinds to test
        obligation_kinds: Vec<ObligationKind>,
    }

    impl Default for DialecticaMetamorphicConfig {
        fn default() -> Self {
            Self {
                obligation_count: 10,
                region_count: 3,
                max_time_ns: 1000,
                obligation_kinds: vec![
                    ObligationKind::SendPermit,
                    ObligationKind::Ack,
                    ObligationKind::Lease,
                    ObligationKind::IoOp,
                ],
            }
        }
    }

    /// Generate deterministic test trace
    fn generate_dialectica_trace(
        config: &DialecticaMetamorphicConfig,
        rng: &mut crate::util::det_rng::DetRng,
    ) -> Vec<MarkingEvent> {
        let mut events = Vec::new();
        let mut next_time = 0u64;

        // Generate obligations with reserve + resolution events
        for i in 0..config.obligation_count {
            let obligation_id = o(i);
            let task_id = t(i % 5); // Reuse task IDs
            let region_id = r(i % config.region_count);
            let kind_idx = (rng.next_u64() as usize) % config.obligation_kinds.len();
            let kind = config.obligation_kinds[kind_idx];

            // Reserve event
            events.push(reserve(next_time, obligation_id, kind, task_id, region_id));
            next_time += (rng.next_u64() % 50) + 1;

            // Resolution event (commit, abort, or leak)
            let resolution_choice = rng.next_u64() % 10;
            if resolution_choice < 6 {
                // 60% commit
                events.push(commit(next_time, obligation_id, region_id, kind));
            } else if resolution_choice < 9 {
                // 30% abort
                events.push(abort(next_time, obligation_id, region_id, kind));
            } else {
                // 10% leak
                events.push(leak(next_time, obligation_id, region_id, kind));
            }
            next_time += (rng.next_u64() % 30) + 1;
        }

        // Close all regions at the end
        for i in 0..config.region_count {
            events.push(close(next_time, r(i)));
            next_time += 10;
        }

        events
    }

    /// Trait extension for deterministic RNG
    trait DetRngExt {
        fn gen_range(&mut self, range: std::ops::Range<u64>) -> u64;
        fn shuffle<T>(&mut self, slice: &mut [T]);
    }

    impl DetRngExt for crate::util::det_rng::DetRng {
        fn gen_range(&mut self, range: std::ops::Range<u64>) -> u64 {
            if range.is_empty() {
                range.start
            } else {
                range.start + (self.next_u64() % (range.end - range.start))
            }
        }

        fn shuffle<T>(&mut self, slice: &mut [T]) {
            for i in (1..slice.len()).rev() {
                let j = self.gen_range(0..i as u64 + 1) as usize;
                slice.swap(i, j);
            }
        }
    }

    // =========================================================================
    // MR1: Temporal Transformation Invariance
    // =========================================================================

    #[test]
    fn metamorphic_temporal_transformation_invariance() {
        init_test("metamorphic_temporal_transformation_invariance");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        let config = DialecticaMetamorphicConfig::default();
        let base_events = generate_dialectica_trace(&config, &mut rng);

        // Test multiple time offsets
        for offset_ns in [0, 100, 1000, 10000, 100000] {
            let shifted_events: Vec<MarkingEvent> = base_events
                .iter()
                .map(|event| {
                    MarkingEvent::new(
                        Time::from_nanos(event.time.as_nanos() + offset_ns),
                        event.kind.clone(),
                    )
                })
                .collect();

            let mut checker1 = ContractChecker::new();
            let mut checker2 = ContractChecker::new();

            let result1 = checker1.check(&base_events);
            let result2 = checker2.check(&shifted_events);

            // Contract satisfaction should be identical regardless of time offset
            assert_eq!(
                result1.contract_status.exhaustive_resolution,
                result2.contract_status.exhaustive_resolution,
                "Temporal shift by {} changed ExhaustiveResolution satisfaction",
                offset_ns
            );
            assert_eq!(
                result1.contract_status.no_partial_commit,
                result2.contract_status.no_partial_commit,
                "Temporal shift by {} changed NoPartialCommit satisfaction",
                offset_ns
            );
            assert_eq!(
                result1.contract_status.region_closure_safety,
                result2.contract_status.region_closure_safety,
                "Temporal shift by {} changed RegionClosureSafety satisfaction",
                offset_ns
            );
            assert_eq!(
                result1.violations.len(),
                result2.violations.len(),
                "Temporal shift by {} changed violation count",
                offset_ns
            );
        }

        crate::test_complete!("metamorphic_temporal_transformation_invariance");
    }

    // =========================================================================
    // MR2: Obligation Kind Invariance
    // =========================================================================

    #[test]
    fn metamorphic_obligation_kind_invariance() {
        init_test("metamorphic_obligation_kind_invariance");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let _rng = crate::util::det_rng::DetRng::new(seed);

        // Test that contract checking is identical across different obligation kinds
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        let base_trace = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            reserve(20, o(1), ObligationKind::SendPermit, t(1), r(1)),
            abort(30, o(1), r(1), ObligationKind::SendPermit),
            close(40, r(0)),
            close(50, r(1)),
        ];

        let mut results = Vec::new();

        // Test same trace structure with different obligation kinds
        for &kind in &kinds {
            let kind_specific_trace: Vec<MarkingEvent> = base_trace
                .iter()
                .map(|event| match &event.kind {
                    MarkingEventKind::Reserve {
                        obligation,
                        task,
                        region,
                        ..
                    } => reserve(event.time.as_nanos(), *obligation, kind, *task, *region),
                    MarkingEventKind::Commit {
                        obligation, region, ..
                    } => commit(event.time.as_nanos(), *obligation, *region, kind),
                    MarkingEventKind::Abort {
                        obligation, region, ..
                    } => abort(event.time.as_nanos(), *obligation, *region, kind),
                    MarkingEventKind::Leak {
                        obligation, region, ..
                    } => leak(event.time.as_nanos(), *obligation, *region, kind),
                    MarkingEventKind::RegionClose { region } => {
                        close(event.time.as_nanos(), *region)
                    }
                    MarkingEventKind::TaskComplete { .. } => event.clone(),
                })
                .collect();

            let mut checker = ContractChecker::new();
            let result = checker.check(&kind_specific_trace);
            results.push(result);
        }

        // All results should be identical (KindUniformStateMachine contract)
        for i in 1..results.len() {
            assert_eq!(
                results[0].is_clean(),
                results[i].is_clean(),
                "Kind {} produced different clean status than kind {}",
                kinds[0],
                kinds[i]
            );
            assert_eq!(
                results[0].violations.len(),
                results[i].violations.len(),
                "Kind {} produced different violation count than kind {}",
                kinds[0],
                kinds[i]
            );
            assert_eq!(
                results[0].contract_status.exhaustive_resolution,
                results[i].contract_status.exhaustive_resolution,
                "Kind {} produced different ExhaustiveResolution status than kind {}",
                kinds[0],
                kinds[i]
            );
        }

        crate::test_complete!("metamorphic_obligation_kind_invariance");
    }

    // =========================================================================
    // MR3: Region Isolation Property
    // =========================================================================

    #[test]
    fn metamorphic_region_isolation() {
        init_test("metamorphic_region_isolation");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let _rng = crate::util::det_rng::DetRng::new(seed);

        // Create a base trace with obligations in region 0
        let region0_trace = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(10, o(1), ObligationKind::Ack, t(1), r(0)),
            commit(20, o(0), r(0), ObligationKind::SendPermit),
            commit(30, o(1), r(0), ObligationKind::Ack),
            close(40, r(0)),
        ];

        // Create additional trace with obligations in region 1
        let region1_trace = vec![
            reserve(5, o(2), ObligationKind::Lease, t(2), r(1)),
            reserve(15, o(3), ObligationKind::IoOp, t(3), r(1)),
            abort(25, o(2), r(1), ObligationKind::Lease),
            leak(35, o(3), r(1), ObligationKind::IoOp),
            close(45, r(1)),
        ];

        // Test original region 0 trace alone
        let mut checker1 = ContractChecker::new();
        let result1 = checker1.check(&region0_trace);

        // Test combined trace (region 0 + region 1)
        let mut combined_trace = region0_trace.clone();
        combined_trace.extend(region1_trace.clone());
        combined_trace.sort_by_key(|event| event.time);

        let mut checker2 = ContractChecker::new();
        let result2 = checker2.check(&combined_trace);

        // The contract satisfaction for region 0 obligations should be unaffected
        // by the presence of region 1 obligations
        assert_eq!(
            result1.is_clean(),
            result2.is_clean(),
            "Region isolation failed: adding region 1 changed overall clean status"
        );

        // Check that violations specific to region 0 obligations are preserved
        let region0_violations1: Vec<_> = result1
            .violations
            .iter()
            .filter(|v| v.region == Some(r(0)))
            .collect();
        let region0_violations2 = result2
            .violations
            .iter()
            .filter(|v| v.region == Some(r(0)))
            .count();

        assert_eq!(
            region0_violations1.len(),
            region0_violations2,
            "Region isolation failed: region 0 violation count changed when region 1 added"
        );

        // Test with various region permutations
        for region_offset in 1..5 {
            let shifted_region1_trace: Vec<MarkingEvent> = region1_trace
                .iter()
                .map(|event| match &event.kind {
                    MarkingEventKind::Reserve {
                        obligation,
                        kind,
                        task,
                        ..
                    } => reserve(
                        event.time.as_nanos(),
                        *obligation,
                        *kind,
                        *task,
                        r(region_offset),
                    ),
                    MarkingEventKind::Commit {
                        obligation, kind, ..
                    } => commit(event.time.as_nanos(), *obligation, r(region_offset), *kind),
                    MarkingEventKind::Abort {
                        obligation, kind, ..
                    } => abort(event.time.as_nanos(), *obligation, r(region_offset), *kind),
                    MarkingEventKind::Leak {
                        obligation, kind, ..
                    } => leak(event.time.as_nanos(), *obligation, r(region_offset), *kind),
                    MarkingEventKind::RegionClose { .. } => {
                        close(event.time.as_nanos(), r(region_offset))
                    }
                    MarkingEventKind::TaskComplete { .. } => event.clone(),
                })
                .collect();

            let mut test_combined = region0_trace.clone();
            test_combined.extend(shifted_region1_trace);
            test_combined.sort_by_key(|event| event.time);

            let mut checker3 = ContractChecker::new();
            let result3 = checker3.check(&test_combined);

            // Region 0 results should remain consistent
            let region0_violations3 = result3
                .violations
                .iter()
                .filter(|v| v.region == Some(r(0)))
                .count();

            assert_eq!(
                region0_violations1.len(),
                region0_violations3,
                "Region isolation failed with region offset {}: region 0 violations changed",
                region_offset
            );
        }

        crate::test_complete!("metamorphic_region_isolation");
    }

    // =========================================================================
    // MR4: Event Reordering Invariance (Commutative Operations)
    // =========================================================================

    #[test]
    fn metamorphic_event_reordering_invariance() {
        init_test("metamorphic_event_reordering_invariance");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        // Create a trace with independent obligations that can be reordered
        let base_trace = vec![
            // Independent obligations in different regions
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(1), r(1)),
            reserve(2, o(2), ObligationKind::Lease, t(2), r(2)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(1), ObligationKind::Ack),
            abort(12, o(2), r(2), ObligationKind::Lease),
            close(20, r(0)),
            close(21, r(1)),
            close(22, r(2)),
        ];

        // Test original order
        let mut checker_original = ContractChecker::new();
        let result_original = checker_original.check(&base_trace);

        // Test multiple random permutations of the trace
        for test_iteration in 0..20 {
            let reordered_trace = base_trace.clone();

            // Only reorder events that are logically independent:
            // - Reserves can be reordered among themselves
            // - Commits/aborts can be reordered among themselves (if for different obligations)
            // - Region closes can be reordered among themselves

            // Separate by event type to safely reorder within each group
            let mut reserves = Vec::new();
            let mut resolutions = Vec::new();
            let mut closes = Vec::new();

            for event in &reordered_trace {
                match &event.kind {
                    MarkingEventKind::Reserve { .. } => reserves.push(event.clone()),
                    MarkingEventKind::Commit { .. }
                    | MarkingEventKind::Abort { .. }
                    | MarkingEventKind::Leak { .. } => resolutions.push(event.clone()),
                    MarkingEventKind::RegionClose { .. } => closes.push(event.clone()),
                    MarkingEventKind::TaskComplete { .. } => closes.push(event.clone()),
                }
            }

            // Shuffle each group independently
            rng.shuffle(&mut reserves);
            rng.shuffle(&mut resolutions);
            rng.shuffle(&mut closes);

            // Reconstruct the trace maintaining logical dependencies
            let mut reconstructed = Vec::new();
            reconstructed.extend(reserves);
            reconstructed.extend(resolutions);
            reconstructed.extend(closes);

            let mut checker_reordered = ContractChecker::new();
            let result_reordered = checker_reordered.check(&reconstructed);

            // Contract satisfaction should be identical under safe reorderings
            assert_eq!(
                result_original.is_clean(),
                result_reordered.is_clean(),
                "Iteration {}: Reordering changed clean status",
                test_iteration
            );
            assert_eq!(
                result_original.contract_status.exhaustive_resolution,
                result_reordered.contract_status.exhaustive_resolution,
                "Iteration {}: Reordering changed ExhaustiveResolution",
                test_iteration
            );
            assert_eq!(
                result_original.contract_status.no_partial_commit,
                result_reordered.contract_status.no_partial_commit,
                "Iteration {}: Reordering changed NoPartialCommit",
                test_iteration
            );
            assert_eq!(
                result_original.violations.len(),
                result_reordered.violations.len(),
                "Iteration {}: Reordering changed violation count",
                test_iteration
            );
        }

        crate::test_complete!("metamorphic_event_reordering_invariance");
    }

    // =========================================================================
    // MR5: Resolution Path Equivalence
    // =========================================================================

    #[test]
    fn metamorphic_resolution_path_equivalence() {
        init_test("metamorphic_resolution_path_equivalence");

        // Test that different valid resolution paths don't affect contract checking
        // of other obligations in the same trace

        let base_obligations = vec![
            (o(0), ObligationKind::SendPermit, t(0), r(0)),
            (o(1), ObligationKind::Ack, t(1), r(1)),
            (o(2), ObligationKind::Lease, t(2), r(2)),
        ];

        // Test different resolution combinations
        let resolution_variants = vec![
            // All commit
            vec!["commit", "commit", "commit"],
            // All abort
            vec!["abort", "abort", "abort"],
            // Mixed 1
            vec!["commit", "abort", "commit"],
            // Mixed 2
            vec!["abort", "commit", "abort"],
            // With leak
            vec!["commit", "leak", "abort"],
        ];

        let mut results = Vec::new();

        for (variant_idx, resolutions) in resolution_variants.iter().enumerate() {
            let mut events = Vec::new();

            // Reserve all obligations
            for (i, &(obligation_id, kind, task_id, region_id)) in
                base_obligations.iter().enumerate()
            {
                events.push(reserve(
                    i as u64 * 10,
                    obligation_id,
                    kind,
                    task_id,
                    region_id,
                ));
            }

            // Apply different resolution patterns
            for (i, (&(obligation_id, kind, _, region_id), &resolution)) in
                base_obligations.iter().zip(resolutions.iter()).enumerate()
            {
                let resolve_time = (base_obligations.len() as u64 * 10) + (i as u64 * 10);
                match resolution {
                    "commit" => events.push(commit(resolve_time, obligation_id, region_id, kind)),
                    "abort" => events.push(abort(resolve_time, obligation_id, region_id, kind)),
                    "leak" => events.push(leak(resolve_time, obligation_id, region_id, kind)),
                    _ => panic!("Unknown resolution type: {}", resolution),
                }
            }

            // Close all regions
            for (i, &(_, _, _, region_id)) in base_obligations.iter().enumerate() {
                let close_time = (base_obligations.len() as u64 * 20) + (i as u64 * 5);
                events.push(close(close_time, region_id));
            }

            let mut checker = ContractChecker::new();
            let result = checker.check(&events);
            results.push((variant_idx, result));
        }

        // All variants should satisfy the same contracts (just with different resolution paths)
        for i in 1..results.len() {
            let (variant1, ref result1) = results[0];
            let (variant2, ref result2) = results[i];

            // ExhaustiveResolution should be satisfied in all cases (all obligations resolved)
            assert_eq!(
                result1.contract_status.exhaustive_resolution,
                result2.contract_status.exhaustive_resolution,
                "Resolution variant {} differs from variant {} on ExhaustiveResolution",
                variant2,
                variant1
            );

            // NoPartialCommit should be satisfied (no double resolutions)
            assert_eq!(
                result1.contract_status.no_partial_commit,
                result2.contract_status.no_partial_commit,
                "Resolution variant {} differs from variant {} on NoPartialCommit",
                variant2,
                variant1
            );

            // RegionClosureSafety should be satisfied (all resolved before close)
            assert_eq!(
                result1.contract_status.region_closure_safety,
                result2.contract_status.region_closure_safety,
                "Resolution variant {} differs from variant {} on RegionClosureSafety",
                variant2,
                variant1
            );
        }

        // All variants should be clean (no violations)
        for (variant_idx, result) in &results {
            assert!(
                result.is_clean(),
                "Resolution variant {} has violations: {:?}",
                variant_idx,
                result.violations
            );
        }

        crate::test_complete!("metamorphic_resolution_path_equivalence");
    }

    // =========================================================================
    // MR6: Adversarial Permit Stress Testing
    // =========================================================================

    #[test]
    fn metamorphic_adversarial_permit_stress() {
        init_test("metamorphic_adversarial_permit_stress");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        // Test contract checking under adversarial conditions:
        // - Large number of obligations
        // - Complex interleavings
        // - Edge case timings
        // - Maximal region usage

        let config = DialecticaMetamorphicConfig {
            obligation_count: 50,
            region_count: 10,
            max_time_ns: 5000,
            obligation_kinds: vec![
                ObligationKind::SendPermit,
                ObligationKind::Ack,
                ObligationKind::Lease,
                ObligationKind::IoOp,
            ],
        };

        // Generate multiple adversarial traces
        let trace_variants = (0..5)
            .map(|_| generate_dialectica_trace(&config, &mut rng))
            .collect::<Vec<_>>();

        for (i, trace) in trace_variants.iter().enumerate() {
            let mut checker = ContractChecker::new();
            let result = checker.check(trace);

            // In adversarial scenarios, we primarily check for consistency:
            // - No panics or crashes during checking
            // - Reasonable violation patterns
            // - Contract logic remains sound

            // The trace generator should produce valid traces, so basic contracts should hold
            assert!(
                result.contract_status.exhaustive_resolution,
                "Adversarial trace {} failed ExhaustiveResolution",
                i
            );
            assert!(
                result.contract_status.no_partial_commit,
                "Adversarial trace {} failed NoPartialCommit",
                i
            );
            assert!(
                result.contract_status.region_closure_safety,
                "Adversarial trace {} failed RegionClosureSafety",
                i
            );

            // Verify that all events were processed
            assert_eq!(
                result.events_checked,
                trace.len(),
                "Adversarial trace {}: events_checked mismatch",
                i
            );

            // Check for contract uniformity across obligation kinds
            for contract in [
                DialecticaContract::ExhaustiveResolution,
                DialecticaContract::NoPartialCommit,
                DialecticaContract::RegionClosureSafety,
                DialecticaContract::CancellationNonCascading,
                DialecticaContract::KindUniformStateMachine,
            ] {
                let violations_for_contract = result.violations_for(contract);
                // Adversarial traces should not introduce contract-specific violations
                // if the generator produces valid sequences
                if !violations_for_contract.is_empty() {
                    println!(
                        "Adversarial trace {} has violations for {:?}: {:?}",
                        i, contract, violations_for_contract
                    );
                }
            }
        }

        crate::test_complete!("metamorphic_adversarial_permit_stress");
    }

    // =========================================================================
    // Composite Metamorphic Relations
    // =========================================================================

    #[test]
    fn metamorphic_composite_invariances() {
        init_test("metamorphic_composite_invariances");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let _rng = crate::util::det_rng::DetRng::new(seed);

        // Test combinations of metamorphic transformations:
        // Temporal shift + Kind substitution + Region isolation

        let base_trace = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(10, o(1), ObligationKind::Ack, t(1), r(1)),
            commit(20, o(0), r(0), ObligationKind::SendPermit),
            abort(30, o(1), r(1), ObligationKind::Ack),
            close(40, r(0)),
            close(50, r(1)),
        ];

        let mut checker_base = ContractChecker::new();
        let result_base = checker_base.check(&base_trace);

        // Apply composite transformation:
        // 1. Shift time by 1000ns
        // 2. Change all obligations to IoOp kind
        // 3. Move second obligation to new region
        let transformed_trace: Vec<MarkingEvent> = base_trace
            .iter()
            .map(|event| {
                let new_time = Time::from_nanos(event.time.as_nanos() + 1000);
                match &event.kind {
                    MarkingEventKind::Reserve {
                        obligation,
                        task,
                        region,
                        ..
                    } => {
                        let new_region = if *obligation == o(1) { r(2) } else { *region };
                        reserve(
                            new_time.as_nanos(),
                            *obligation,
                            ObligationKind::IoOp,
                            *task,
                            new_region,
                        )
                    }
                    MarkingEventKind::Commit {
                        obligation, region, ..
                    } => {
                        let new_region = if *obligation == o(1) { r(2) } else { *region };
                        commit(
                            new_time.as_nanos(),
                            *obligation,
                            new_region,
                            ObligationKind::IoOp,
                        )
                    }
                    MarkingEventKind::Abort {
                        obligation, region, ..
                    } => {
                        let new_region = if *obligation == o(1) { r(2) } else { *region };
                        abort(
                            new_time.as_nanos(),
                            *obligation,
                            new_region,
                            ObligationKind::IoOp,
                        )
                    }
                    MarkingEventKind::Leak {
                        obligation, region, ..
                    } => {
                        let new_region = if *obligation == o(1) { r(2) } else { *region };
                        leak(
                            new_time.as_nanos(),
                            *obligation,
                            new_region,
                            ObligationKind::IoOp,
                        )
                    }
                    MarkingEventKind::RegionClose { region } => {
                        let new_region = if *region == r(1) { r(2) } else { *region };
                        close(new_time.as_nanos(), new_region)
                    }
                    MarkingEventKind::TaskComplete { .. } => {
                        let mut new_event = event.clone();
                        new_event.time = new_time;
                        new_event
                    }
                }
            })
            .collect();

        let mut checker_transformed = ContractChecker::new();
        let result_transformed = checker_transformed.check(&transformed_trace);

        // Composite transformation should preserve contract satisfaction
        assert_eq!(
            result_base.is_clean(),
            result_transformed.is_clean(),
            "Composite transformation changed overall clean status"
        );
        assert_eq!(
            result_base.contract_status.exhaustive_resolution,
            result_transformed.contract_status.exhaustive_resolution,
            "Composite transformation changed ExhaustiveResolution"
        );
        assert_eq!(
            result_base.contract_status.no_partial_commit,
            result_transformed.contract_status.no_partial_commit,
            "Composite transformation changed NoPartialCommit"
        );
        assert_eq!(
            result_base.contract_status.kind_uniform_state_machine,
            result_transformed
                .contract_status
                .kind_uniform_state_machine,
            "Composite transformation changed KindUniformStateMachine"
        );

        crate::test_complete!("metamorphic_composite_invariances");
    }

    // ========================================================================
    // DIALECTICA-DUALITY conformance harness (Pattern 4: spec-derived)
    //
    // The spec is the typing judgment at the top of this module:
    //
    //   reserve : (K, R) → Permit(K, R)          (forward step)
    //   resolve : Permit(K, R) → Terminal(K, R)  (backward step)
    //   Terminal(K, R) = Committed | Aborted | Leaked
    //
    // Each DIALECTICA-DUALITY-N clause mechanically verifies one protocol
    // invariant of the (forward, backward) pair as encoded by
    // DialecticaMorphism, plus the bridging invariants that connect the
    // morphism to the event-trace ContractChecker.
    //
    // Every case emits one stderr JSON-line verdict:
    //   {"id":"DIALECTICA-DUALITY-N","verdict":"PASS|FAIL","level":"MUST"}
    // ========================================================================

    fn emit_duality_verdict(id: &str, pass: bool) {
        eprintln!(
            "{{\"id\":\"{id}\",\"verdict\":\"{}\",\"level\":\"MUST\"}}",
            if pass { "PASS" } else { "FAIL" }
        );
    }

    // DIALECTICA-DUALITY-1: Forward-Backward ordering is total — you cannot
    // take the backward step without first taking the forward step.
    #[test]
    #[should_panic(expected = "cannot resolve without forward step")]
    fn conformance_dialectica_duality_1_backward_requires_forward() {
        // We cannot emit a verdict from a panicking test; the #[should_panic]
        // attribute IS the verdict. If the panic message changes, this fails.
        let mut m = DialecticaMorphism::new(ObligationKind::SendPermit);
        m.backward(ObligationState::Committed);
    }

    // DIALECTICA-DUALITY-2: Forward step is at-most-once (linear).
    #[test]
    #[should_panic(expected = "forward step already taken")]
    fn conformance_dialectica_duality_2_forward_is_linear() {
        let mut m = DialecticaMorphism::new(ObligationKind::Ack);
        m.forward();
        m.forward();
    }

    // DIALECTICA-DUALITY-3: Backward step is at-most-once (linear).
    #[test]
    #[should_panic(expected = "backward step already taken")]
    fn conformance_dialectica_duality_3_backward_is_linear() {
        let mut m = DialecticaMorphism::new(ObligationKind::Lease);
        m.forward();
        m.backward(ObligationState::Committed);
        m.backward(ObligationState::Aborted);
    }

    // DIALECTICA-DUALITY-4: Backward resolution must be terminal.
    // Passing a non-terminal state (Reserved) must panic.
    #[test]
    #[should_panic(expected = "resolution must be terminal")]
    fn conformance_dialectica_duality_4_resolution_must_be_terminal() {
        let mut m = DialecticaMorphism::new(ObligationKind::IoOp);
        m.forward();
        m.backward(ObligationState::Reserved);
    }

    // DIALECTICA-DUALITY-5: is_complete iff (forward ∧ backward).
    #[test]
    fn conformance_dialectica_duality_5_completion_witnesses_both_steps() {
        let mut m = DialecticaMorphism::new(ObligationKind::SendPermit);
        let idle = !m.is_complete();
        m.forward();
        let pending = !m.is_complete();
        m.backward(ObligationState::Committed);
        let done = m.is_complete();
        let pass = idle && pending && done;
        emit_duality_verdict("DIALECTICA-DUALITY-5", pass);
        assert!(pass, "is_complete diverged from (forward ∧ backward)");
    }

    // DIALECTICA-DUALITY-6: is_pending iff (forward ∧ ¬backward).
    #[test]
    fn conformance_dialectica_duality_6_pending_characterization() {
        let mut m = DialecticaMorphism::new(ObligationKind::Ack);
        let idle_not_pending = !m.is_pending();
        m.forward();
        let forward_is_pending = m.is_pending();
        m.backward(ObligationState::Aborted);
        let done_not_pending = !m.is_pending();
        let pass = idle_not_pending && forward_is_pending && done_not_pending;
        emit_duality_verdict("DIALECTICA-DUALITY-6", pass);
        assert!(pass, "is_pending diverged from (forward ∧ ¬backward)");
    }

    // DIALECTICA-DUALITY-7: is_clean iff resolution ∈ {Committed, Aborted}.
    // Leaked is complete-but-not-clean; Reserved is neither.
    #[test]
    fn conformance_dialectica_duality_7_clean_excludes_leak() {
        let mut committed = DialecticaMorphism::new(ObligationKind::SendPermit);
        committed.forward();
        committed.backward(ObligationState::Committed);

        let mut aborted = DialecticaMorphism::new(ObligationKind::Ack);
        aborted.forward();
        aborted.backward(ObligationState::Aborted);

        let mut leaked = DialecticaMorphism::new(ObligationKind::Lease);
        leaked.forward();
        leaked.backward(ObligationState::Leaked);

        let pass = committed.is_clean()
            && aborted.is_clean()
            && leaked.is_complete()
            && !leaked.is_clean();
        emit_duality_verdict("DIALECTICA-DUALITY-7", pass);
        assert!(pass, "is_clean admitted Leaked or rejected Commit/Abort");
    }

    // DIALECTICA-DUALITY-8: Duality distinguishes Commit from Abort in Display.
    #[test]
    fn conformance_dialectica_duality_8_display_distinguishes_resolutions() {
        let mut c = DialecticaMorphism::new(ObligationKind::SendPermit);
        c.forward();
        c.backward(ObligationState::Committed);
        let mut a = DialecticaMorphism::new(ObligationKind::SendPermit);
        a.forward();
        a.backward(ObligationState::Aborted);
        let mut l = DialecticaMorphism::new(ObligationKind::SendPermit);
        l.forward();
        l.backward(ObligationState::Leaked);

        let c_s = format!("{c}");
        let a_s = format!("{a}");
        let l_s = format!("{l}");
        let pass = c_s.contains("committed")
            && a_s.contains("aborted")
            && l_s.contains("LEAKED")
            && c_s != a_s
            && a_s != l_s
            && c_s != l_s;
        emit_duality_verdict("DIALECTICA-DUALITY-8", pass);
        assert!(
            pass,
            "Display collapsed the Commit/Abort/Leak distinction: {c_s} / {a_s} / {l_s}"
        );
    }

    // DIALECTICA-DUALITY-9: Kind-uniformity — all four ObligationKind variants
    // produce structurally identical morphism state machines (same forward+
    // backward behavior, same is_complete / is_pending / is_clean verdicts).
    #[test]
    fn conformance_dialectica_duality_9_kind_uniformity() {
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
            ObligationKind::SemaphorePermit,
        ];
        let mut pass = true;
        for k in kinds {
            let mut m = DialecticaMorphism::new(k);
            if m.is_complete() || m.is_pending() || m.is_clean() {
                pass = false;
            }
            m.forward();
            if m.is_complete() || !m.is_pending() || m.is_clean() {
                pass = false;
            }
            m.backward(ObligationState::Committed);
            if !m.is_complete() || m.is_pending() || !m.is_clean() {
                pass = false;
            }
        }
        emit_duality_verdict("DIALECTICA-DUALITY-9", pass);
        assert!(
            pass,
            "state machine diverged across ObligationKind variants"
        );
    }

    // DIALECTICA-DUALITY-10: State monotonicity — (forward_taken, backward_taken)
    // only advances through (F,F) → (T,F) → (T,T); both bits are sticky.
    #[test]
    fn conformance_dialectica_duality_10_state_monotonicity() {
        let mut m = DialecticaMorphism::new(ObligationKind::Lease);
        let s0 = (m.forward_taken, m.backward_taken);
        m.forward();
        let s1 = (m.forward_taken, m.backward_taken);
        m.backward(ObligationState::Aborted);
        let s2 = (m.forward_taken, m.backward_taken);
        let pass = s0 == (false, false) && s1 == (true, false) && s2 == (true, true);
        emit_duality_verdict("DIALECTICA-DUALITY-10", pass);
        assert!(
            pass,
            "state tuple did not follow (F,F) → (T,F) → (T,T): {s0:?}→{s1:?}→{s2:?}"
        );
    }

    // DIALECTICA-DUALITY-11: Bridging — a reserve+commit trace is clean at the
    // ContractChecker level, mirroring a completed, clean morphism.
    #[test]
    fn conformance_dialectica_duality_11_bridge_clean_trace() {
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];
        let mut checker = ContractChecker::new();
        let res = checker.check(&events);
        let pass = res.is_clean()
            && res
                .contract_status
                .is_satisfied(DialecticaContract::ExhaustiveResolution)
            && res
                .contract_status
                .is_satisfied(DialecticaContract::NoPartialCommit)
            && res
                .contract_status
                .is_satisfied(DialecticaContract::RegionClosureSafety);
        emit_duality_verdict("DIALECTICA-DUALITY-11", pass);
        assert!(pass, "clean reserve+commit trace was flagged by checker");
    }

    // DIALECTICA-DUALITY-12: Bridging — a resolve without a prior reserve is
    // a NoPartialCommit violation, mirroring backward-without-forward being
    // a panic at the morphism level (DIALECTICA-DUALITY-1).
    #[test]
    fn conformance_dialectica_duality_12_bridge_resolve_without_reserve() {
        let events = vec![commit(10, o(99), r(0), ObligationKind::Lease)];
        let mut checker = ContractChecker::new();
        let res = checker.check(&events);
        let viols = res.violations_for(DialecticaContract::NoPartialCommit);
        let pass = !res.is_clean() && viols.len() == 1;
        emit_duality_verdict("DIALECTICA-DUALITY-12", pass);
        assert!(
            pass,
            "unreserved resolve did not surface a single NoPartialCommit violation"
        );
    }

    // TEMPORAL-LOGIC-1: Test temporal logic contracts
    #[test]
    fn temporal_logic_contracts() {
        init_test("temporal_logic_contracts");

        // Test NeverThenAfterClose: reservation after region close should be violation
        let events_never_then = vec![
            close(0, r(0)),                                            // Close region 0
            reserve(10, o(0), ObligationKind::SendPermit, t(0), r(0)), // Should violate
        ];
        let mut checker = ContractChecker::new();
        let result = checker.check(&events_never_then);
        assert!(
            !result.is_clean(),
            "Should detect NeverThenAfterClose violation"
        );
        let violations = result.violations_for(DialecticaContract::NeverThenAfterClose);
        assert_eq!(
            violations.len(),
            1,
            "Should have exactly one NeverThenAfterClose violation"
        );

        // Test AlwaysEventuallyResolved: obligation not resolved within time bound
        let time_bound = Time::from_millis(100);
        let events_slow_resolve = vec![
            reserve(0, o(1), ObligationKind::SendPermit, t(1), r(1)),
            MarkingEvent::new(
                Time::from_millis(200),
                MarkingEventKind::TaskComplete { task: t(1) },
            ),
            // No commit within time bound - should violate at trace end
        ];
        let mut checker_time = ContractChecker::new_with_time_bound(time_bound);
        let result_time = checker_time.check(&events_slow_resolve);
        assert!(
            !result_time.is_clean(),
            "Should detect AlwaysEventuallyResolved violation"
        );
        let time_violations =
            result_time.violations_for(DialecticaContract::AlwaysEventuallyResolved);
        assert_eq!(
            time_violations.len(),
            1,
            "Should have exactly one AlwaysEventuallyResolved violation"
        );

        // Test EventuallyAlwaysQuiescent: system reaches and maintains quiescence
        let events_quiescent = vec![
            reserve(0, o(2), ObligationKind::SendPermit, t(2), r(2)),
            commit(50, o(2), r(2), ObligationKind::SendPermit), // Reach quiescence
            close(100, r(2)),
            // System remains quiescent - should be satisfied
        ];
        let mut checker_quies = ContractChecker::new();
        let result_quies = checker_quies.check(&events_quiescent);
        assert!(
            result_quies
                .contract_status
                .is_satisfied(DialecticaContract::EventuallyAlwaysQuiescent)
        );

        // Test EventuallyAlwaysQuiescent violation: lose quiescence
        let events_lose_quies = vec![
            reserve(0, o(3), ObligationKind::SendPermit, t(3), r(3)),
            commit(50, o(3), r(3), ObligationKind::SendPermit), // Reach quiescence
            reserve(100, o(4), ObligationKind::Ack, t(4), r(3)), // Lose quiescence - should violate
        ];
        let mut checker_lose = ContractChecker::new();
        let result_lose = checker_lose.check(&events_lose_quies);
        let quies_violations =
            result_lose.violations_for(DialecticaContract::EventuallyAlwaysQuiescent);
        assert_eq!(
            quies_violations.len(),
            1,
            "Should have exactly one EventuallyAlwaysQuiescent violation"
        );

        // Test AlwaysImpliesTrackable: this is implicitly satisfied if obligations are tracked
        let events_trackable = vec![
            reserve(0, o(5), ObligationKind::Lease, t(5), r(5)),
            commit(10, o(5), r(5), ObligationKind::Lease),
        ];
        let mut checker_track = ContractChecker::new();
        let result_track = checker_track.check(&events_trackable);
        assert!(
            result_track
                .contract_status
                .is_satisfied(DialecticaContract::AlwaysImpliesTrackable)
        );
    }
