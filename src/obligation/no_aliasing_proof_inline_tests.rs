    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::obligation::marking::{MarkingEvent, MarkingEventKind};
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

    // ========================================================================
    // Lemma 1: Allocation Freshness
    // ========================================================================

    #[test]
    fn lemma1_single_allocation() {
        init_test("lemma1_single_allocation");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "single allocation verified", true, verified);

        let alloc_steps = result.steps_for_lemma(Lemma::AllocationFreshness);
        crate::assert_with_log!(
            alloc_steps >= 1,
            "at least 1 allocation step",
            true,
            alloc_steps >= 1
        );
        crate::test_complete!("lemma1_single_allocation");
    }

    #[test]
    fn lemma1_multiple_fresh_allocations() {
        init_test("lemma1_multiple_fresh_allocations");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            reserve(2, o(2), ObligationKind::SendPermit, t(2), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(0), ObligationKind::SendPermit),
            commit(12, o(2), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "3 fresh allocations verified", true, verified);
        let peak = result.peak_active_permits;
        crate::assert_with_log!(peak == 3, "peak active = 3", 3, peak);
        crate::test_complete!("lemma1_multiple_fresh_allocations");
    }

    #[test]
    fn lemma1_rejects_duplicate_allocation() {
        init_test("lemma1_rejects_duplicate_allocation");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(0), ObligationKind::SendPermit, t(1), r(0)), // DUPLICATE!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "duplicate detected", false, verified);

        let dup_count = result
            .counterexamples_of_kind(ViolationKind::DuplicateAllocation)
            .count();
        crate::assert_with_log!(dup_count == 1, "1 duplicate violation", 1, dup_count);
        crate::test_complete!("lemma1_rejects_duplicate_allocation");
    }

    #[test]
    fn lemma1_rejects_reserve_after_consume() {
        init_test("lemma1_rejects_reserve_after_consume");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            reserve(10, o(0), ObligationKind::SendPermit, t(1), r(0)), // REUSE!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "reuse after consume detected", false, verified);

        let uar_count = result
            .counterexamples_of_kind(ViolationKind::UseAfterRelease)
            .count();
        crate::assert_with_log!(uar_count == 1, "1 use-after-release", 1, uar_count);
        crate::test_complete!("lemma1_rejects_reserve_after_consume");
    }

    // ========================================================================
    // Lemma 2: Transfer Exclusivity
    // ========================================================================

    #[test]
    fn lemma2_valid_transfer() {
        init_test("lemma2_valid_transfer");
        let events = vec![reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0))];

        let mut prover = NoAliasingProver::new();
        // Process the reserve.
        for event in &events {
            prover.process_event(event);
        }

        // Apply transfer: t(0) → t(1).
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(0),
            to: t(1),
            time: Time::from_nanos(5),
        });

        // Verify the holder changed.
        let holder = prover.ghost.holder_of(o(0));
        crate::assert_with_log!(
            holder == Some(t(1)),
            "holder is now t(1)",
            Some(t(1)),
            holder
        );

        // Check no violations.
        let violations = prover.counterexamples.len();
        crate::assert_with_log!(violations == 0, "no violations", 0, violations);

        let transfer_steps = prover
            .steps
            .iter()
            .filter(|s| s.lemma == Lemma::TransferExclusivity)
            .count();
        crate::assert_with_log!(
            transfer_steps >= 1,
            "at least 1 transfer step",
            true,
            transfer_steps >= 1
        );
        crate::test_complete!("lemma2_valid_transfer");
    }

    #[test]
    fn lemma2_chain_transfer() {
        init_test("lemma2_chain_transfer");
        let events = vec![reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0))];

        let mut prover = NoAliasingProver::new();
        for event in &events {
            prover.process_event(event);
        }

        // Chain: t(0) → t(1) → t(2).
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(0),
            to: t(1),
            time: Time::from_nanos(5),
        });
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(1),
            to: t(2),
            time: Time::from_nanos(10),
        });

        let holder = prover.ghost.holder_of(o(0));
        crate::assert_with_log!(
            holder == Some(t(2)),
            "holder is t(2) after chain",
            Some(t(2)),
            holder
        );

        let violations = prover.counterexamples.len();
        crate::assert_with_log!(violations == 0, "no violations", 0, violations);
        crate::test_complete!("lemma2_chain_transfer");
    }

    #[test]
    fn lemma2_rejects_self_transfer() {
        init_test("lemma2_rejects_self_transfer");
        let events = vec![reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0))];

        let mut prover = NoAliasingProver::new();
        for event in &events {
            prover.process_event(event);
        }

        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(0),
            to: t(0),
            time: Time::from_nanos(5),
        });

        let self_transfer_count = prover
            .counterexamples
            .iter()
            .filter(|c| c.violation == ViolationKind::SelfTransfer)
            .count();
        crate::assert_with_log!(
            self_transfer_count == 1,
            "1 self-transfer violation",
            1,
            self_transfer_count
        );
        crate::test_complete!("lemma2_rejects_self_transfer");
    }

    #[test]
    fn lemma2_rejects_transfer_from_wrong_holder() {
        init_test("lemma2_rejects_transfer_from_wrong_holder");
        let events = vec![reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0))];

        let mut prover = NoAliasingProver::new();
        for event in &events {
            prover.process_event(event);
        }

        // Transfer from t(1), but holder is t(0). This is aliasing!
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(1), // WRONG — actual holder is t(0)
            to: t(2),
            time: Time::from_nanos(5),
        });

        let alias_count = prover
            .counterexamples
            .iter()
            .filter(|c| c.violation == ViolationKind::TransferAliasing)
            .count();
        crate::assert_with_log!(alias_count == 1, "1 transfer aliasing", 1, alias_count);
        crate::test_complete!("lemma2_rejects_transfer_from_wrong_holder");
    }

    #[test]
    fn lemma2_rejects_transfer_of_consumed() {
        init_test("lemma2_rejects_transfer_of_consumed");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        for event in &events {
            prover.process_event(event);
        }

        // Transfer after commit.
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(0),
            to: t(1),
            time: Time::from_nanos(10),
        });

        let uar_count = prover
            .counterexamples
            .iter()
            .filter(|c| c.violation == ViolationKind::UseAfterRelease)
            .count();
        crate::assert_with_log!(uar_count == 1, "1 use-after-release", 1, uar_count);
        crate::test_complete!("lemma2_rejects_transfer_of_consumed");
    }

    // ========================================================================
    // Lemma 3: Release Consumption
    // ========================================================================

    #[test]
    fn lemma3_commit_consumes() {
        init_test("lemma3_commit_consumes");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "commit consumption verified", true, verified);

        let release_steps = result.steps_for_lemma(Lemma::ReleaseConsumption);
        crate::assert_with_log!(
            release_steps >= 1,
            "at least 1 release step",
            true,
            release_steps >= 1
        );
        crate::test_complete!("lemma3_commit_consumes");
    }

    #[test]
    fn lemma3_abort_consumes() {
        init_test("lemma3_abort_consumes");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            abort(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "abort consumption verified", true, verified);
        crate::test_complete!("lemma3_abort_consumes");
    }

    #[test]
    fn lemma3_rejects_double_commit() {
        init_test("lemma3_rejects_double_commit");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            commit(10, o(0), r(0), ObligationKind::SendPermit), // DOUBLE!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "double commit rejected", false, verified);

        let uar_count = result
            .counterexamples_of_kind(ViolationKind::UseAfterRelease)
            .count();
        crate::assert_with_log!(uar_count == 1, "1 use-after-release", 1, uar_count);
        crate::test_complete!("lemma3_rejects_double_commit");
    }

    #[test]
    fn lemma3_rejects_commit_without_reserve() {
        init_test("lemma3_rejects_commit_without_reserve");
        let events = vec![commit(10, o(99), r(0), ObligationKind::SendPermit)];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "orphan commit rejected", false, verified);
        crate::test_complete!("lemma3_rejects_commit_without_reserve");
    }

    #[test]
    fn lemma3_rejects_kind_mismatch() {
        init_test("lemma3_rejects_kind_mismatch");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::Lease), // WRONG KIND!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "kind mismatch rejected", false, verified);

        let kd_count = result
            .counterexamples_of_kind(ViolationKind::KindDisagreement)
            .count();
        crate::assert_with_log!(kd_count == 1, "1 kind disagreement", 1, kd_count);
        crate::test_complete!("lemma3_rejects_kind_mismatch");
    }

    #[test]
    fn lemma3_rejects_region_mismatch() {
        init_test("lemma3_rejects_region_mismatch");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(1), ObligationKind::SendPermit), // WRONG REGION!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "region mismatch rejected", false, verified);

        let rd_count = result
            .counterexamples_of_kind(ViolationKind::RegionDisagreement)
            .count();
        crate::assert_with_log!(rd_count == 1, "1 region disagreement", 1, rd_count);
        crate::test_complete!("lemma3_rejects_region_mismatch");
    }

    // ========================================================================
    // Lemma 4: Concurrent Independence
    // ========================================================================

    #[test]
    fn lemma4_independent_permits() {
        init_test("lemma4_independent_permits");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            // Commit o(0) — should not affect o(1).
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            // o(1) should still be active with holder t(1).
            commit(15, o(1), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "independent permits verified", true, verified);

        let frame_checks = result.frame_checks;
        crate::assert_with_log!(
            frame_checks >= 2,
            "at least 2 frame checks",
            true,
            frame_checks >= 2
        );
        crate::test_complete!("lemma4_independent_permits");
    }

    #[test]
    fn lemma4_many_concurrent_permits() {
        init_test("lemma4_many_concurrent_permits");
        let mut events = Vec::new();

        // Create 10 concurrent permits.
        for i in 0..10 {
            events.push(reserve(
                u64::from(i),
                o(i),
                ObligationKind::SendPermit,
                t(i),
                r(0),
            ));
        }

        // Commit them in reverse order (interleaved).
        for i in (0..10).rev() {
            events.push(commit(
                u64::from(10 + i),
                o(i),
                r(0),
                ObligationKind::SendPermit,
            ));
        }

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "10 concurrent permits verified", true, verified);
        let peak = result.peak_active_permits;
        crate::assert_with_log!(peak == 10, "peak = 10", 10, peak);
        crate::test_complete!("lemma4_many_concurrent_permits");
    }

    // ========================================================================
    // Lemma 5: Drop Safety
    // ========================================================================

    #[test]
    fn lemma5_leak_consumes() {
        init_test("lemma5_leak_consumes");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "leak consumed (proof verified)", true, verified);

        let drop_steps = result.steps_for_lemma(Lemma::DropSafety);
        crate::assert_with_log!(
            drop_steps >= 1,
            "at least 1 drop step",
            true,
            drop_steps >= 1
        );
        crate::test_complete!("lemma5_leak_consumes");
    }

    #[test]
    fn lemma5_rejects_double_leak() {
        init_test("lemma5_rejects_double_leak");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::SendPermit),
            leak(10, o(0), r(0), ObligationKind::SendPermit), // DOUBLE LEAK!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "double leak rejected", false, verified);
        crate::test_complete!("lemma5_rejects_double_leak");
    }

    #[test]
    fn lemma5_kind_mismatch_marks_failed_drop_step() {
        init_test("lemma5_kind_mismatch_marks_failed_drop_step");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::Ack), // WRONG KIND!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        crate::assert_with_log!(
            !result.is_verified(),
            "kind mismatch on leak rejected",
            false,
            result.is_verified()
        );

        let has_failed_drop_step = result
            .steps
            .iter()
            .any(|step| step.lemma == Lemma::DropSafety && !step.verified);
        crate::assert_with_log!(
            has_failed_drop_step,
            "drop mismatch produces failed DropSafety step",
            true,
            has_failed_drop_step
        );
        crate::test_complete!("lemma5_kind_mismatch_marks_failed_drop_step");
    }

    #[test]
    fn lemma5_region_mismatch_marks_failed_drop_step() {
        init_test("lemma5_region_mismatch_marks_failed_drop_step");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            leak(5, o(0), r(1), ObligationKind::SendPermit), // WRONG REGION!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        crate::assert_with_log!(
            !result.is_verified(),
            "region mismatch on leak rejected",
            false,
            result.is_verified()
        );

        let has_failed_drop_step = result
            .steps
            .iter()
            .any(|step| step.lemma == Lemma::DropSafety && !step.verified);
        crate::assert_with_log!(
            has_failed_drop_step,
            "region mismatch produces failed DropSafety step",
            true,
            has_failed_drop_step
        );
        crate::test_complete!("lemma5_region_mismatch_marks_failed_drop_step");
    }

    // ========================================================================
    // All-kinds mode
    // ========================================================================

    #[test]
    fn all_kinds_mode_verifies_all() {
        init_test("all_kinds_mode_verifies_all");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(2), r(0)),
            reserve(3, o(3), ObligationKind::IoOp, t(3), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(0), ObligationKind::Ack),
            abort(12, o(2), r(0), ObligationKind::Lease),
            leak(13, o(3), r(0), ObligationKind::IoOp),
        ];

        let mut prover = NoAliasingProver::all_kinds();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "all 4 kinds verified", true, verified);

        let sp_events = result.sendpermit_events;
        crate::assert_with_log!(sp_events == 8, "8 events processed", 8, sp_events);
        crate::test_complete!("all_kinds_mode_verifies_all");
    }

    #[test]
    fn sendpermit_only_mode_skips_others() {
        init_test("sendpermit_only_mode_skips_others");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(1), r(0)), // Skipped
            reserve(2, o(2), ObligationKind::Lease, t(2), r(0)), // Skipped
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(0), ObligationKind::Ack), // Skipped
            abort(12, o(2), r(0), ObligationKind::Lease), // Skipped
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "sendpermit-only verified", true, verified);

        let sp_events = result.sendpermit_events;
        crate::assert_with_log!(sp_events == 2, "only 2 SendPermit events", 2, sp_events);
        crate::test_complete!("sendpermit_only_mode_skips_others");
    }

    // ========================================================================
    // Mutation Tests (known-bad configurations)
    // ========================================================================

    #[test]
    fn mutation_cloned_permit() {
        init_test("mutation_cloned_permit");
        // Simulates a clone bug: two reserves with the same ID by different tasks.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(0), ObligationKind::SendPermit, t(1), r(0)), // Clone!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "cloned permit rejected", false, verified);
        crate::test_complete!("mutation_cloned_permit");
    }

    #[test]
    fn mutation_commit_then_abort_same_permit() {
        init_test("mutation_commit_then_abort_same_permit");
        // Simulates double-resolution: commit then abort the same permit.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            abort(10, o(0), r(0), ObligationKind::SendPermit), // Already consumed!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "double resolution rejected", false, verified);
        crate::test_complete!("mutation_commit_then_abort_same_permit");
    }

    #[test]
    fn mutation_stale_transfer() {
        init_test("mutation_stale_transfer");
        // Simulates a stale reference: transfer after the permit was committed.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        for event in &events {
            prover.process_event(event);
        }

        // Try to transfer a committed permit.
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(0),
            to: t(1),
            time: Time::from_nanos(10),
        });

        let violations = prover.counterexamples.len();
        crate::assert_with_log!(
            violations >= 1,
            "stale transfer rejected",
            true,
            violations >= 1
        );
        crate::test_complete!("mutation_stale_transfer");
    }

    #[test]
    fn mutation_kind_confusion() {
        init_test("mutation_kind_confusion");
        // Simulates kind confusion: reserve as SendPermit, commit as Ack.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::Ack), // WRONG KIND!
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "kind confusion rejected", false, verified);
        crate::test_complete!("mutation_kind_confusion");
    }

    // ========================================================================
    // Realistic Scenarios
    // ========================================================================

    #[test]
    fn realistic_two_phase_send_with_cancel() {
        init_test("realistic_two_phase_send_with_cancel");
        // Scenario: Task t0 reserves a send permit, decides to cancel.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            abort(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "cancel path verified", true, verified);
        crate::test_complete!("realistic_two_phase_send_with_cancel");
    }

    #[test]
    fn realistic_work_stealing_delegation() {
        init_test("realistic_work_stealing_delegation");
        // Scenario: Task t0 creates permit, delegates to t1, t1 commits.
        let events = vec![reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0))];

        let mut prover = NoAliasingProver::new();
        for event in &events {
            prover.process_event(event);
        }

        // Delegate: t0 → t1.
        prover.apply_transfer(&TransferEvent {
            obligation: o(0),
            from: t(0),
            to: t(1),
            time: Time::from_nanos(5),
        });

        // t1 commits.
        let commit_event = commit(10, o(0), r(0), ObligationKind::SendPermit);
        prover.process_event(&commit_event);

        let violations = prover.counterexamples.len();
        crate::assert_with_log!(violations == 0, "delegation verified", 0, violations);
        crate::test_complete!("realistic_work_stealing_delegation");
    }

    #[test]
    fn realistic_multi_region_permits() {
        init_test("realistic_multi_region_permits");
        // Permits in different regions are independent.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(0), r(1)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(1), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "multi-region verified", true, verified);
        crate::test_complete!("realistic_multi_region_permits");
    }

    #[test]
    fn realistic_same_task_multiple_permits() {
        init_test("realistic_same_task_multiple_permits");
        // One task can hold multiple distinct permits.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(0), r(0)),
            reserve(2, o(2), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(0), ObligationKind::SendPermit),
            commit(12, o(2), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoAliasingProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "same task multi-permit verified", true, verified);
        crate::test_complete!("realistic_same_task_multiple_permits");
    }

    // ========================================================================
    // Display / Output
    // ========================================================================

    #[test]
    fn proof_result_display() {
        init_test("proof_result_display");
        let result = ProofResult {
            steps: vec![
                ProofStep {
                    lemma: Lemma::AllocationFreshness,
                    obligation: o(0),
                    time: Time::ZERO,
                    verified: true,
                    description: "reserve".to_string(),
                },
                ProofStep {
                    lemma: Lemma::ReleaseConsumption,
                    obligation: o(0),
                    time: Time::from_nanos(10),
                    verified: true,
                    description: "commit".to_string(),
                },
            ],
            counterexamples: Vec::new(),
            events_processed: 2,
            sendpermit_events: 2,
            peak_active_permits: 1,
            frame_checks: 2,
        };

        let rendered = format!("{result}");
        let expected = r#"SendPermit No-Aliasing Proof
============================
Events processed:      2
SendPermit events:     2
Proof steps:           2
Verified steps:        2
Frame checks:          2
Peak active permits:   1
Verified:              true
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("proof_result_display");
    }

    #[test]
    fn counterexample_display() {
        init_test("counterexample_display");
        let ce = Counterexample {
            violation: ViolationKind::DuplicateAllocation,
            obligation: o(0),
            time: Time::from_nanos(42),
            description: "test counterexample".to_string(),
        };
        assert_eq!(
            format!("{ce}"),
            "[duplicate-allocation] obligation ObligationId(0:0) at t=42ns: test counterexample"
        );
        crate::test_complete!("counterexample_display");
    }

    #[test]
    fn lemma_display() {
        init_test("lemma_display");
        let lemmas = [
            Lemma::AllocationFreshness,
            Lemma::TransferExclusivity,
            Lemma::ReleaseConsumption,
            Lemma::ConcurrentIndependence,
            Lemma::DropSafety,
        ];
        let rendered = lemmas
            .iter()
            .map(|lemma| lemma.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let expected = "Lemma 1 (Allocation Freshness)
Lemma 2 (Transfer Exclusivity)
Lemma 3 (Release Consumption)
Lemma 4 (Concurrent Independence)
Lemma 5 (Drop Safety)";
        assert_eq!(rendered, expected);
        crate::test_complete!("lemma_display");
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn empty_trace() {
        init_test("empty_trace");
        let mut prover = NoAliasingProver::new();
        let result = prover.check(&[]);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "empty trace verified", true, verified);
        let events = result.events_processed;
        crate::assert_with_log!(events == 0, "0 events", 0, events);
        crate::test_complete!("empty_trace");
    }

    #[test]
    fn prover_reuse_resets() {
        init_test("prover_reuse_resets");
        let mut prover = NoAliasingProver::new();

        // First check: violation.
        let events1 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(0), ObligationKind::SendPermit, t(1), r(0)),
        ];
        let r1 = prover.check(&events1);
        let r1_ok = r1.is_verified();
        crate::assert_with_log!(!r1_ok, "first check not verified", false, r1_ok);

        // Second check: clean.
        let events2 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
        ];
        let r2 = prover.check(&events2);
        let r2_ok = r2.is_verified();
        crate::assert_with_log!(r2_ok, "second check verified (reset)", true, r2_ok);
        crate::test_complete!("prover_reuse_resets");
    }

    #[test]
    fn lemma_debug_clone_copy_eq() {
        let a = Lemma::AllocationFreshness;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, Lemma::DropSafety);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("AllocationFreshness"));
    }

    #[test]
    fn violation_kind_debug_clone_copy_eq() {
        let a = ViolationKind::DoubleOwnership;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, ViolationKind::SelfTransfer);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("DoubleOwnership"));
    }
