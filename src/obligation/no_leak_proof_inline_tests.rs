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

    fn reserve_ev(
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

    fn commit_ev(
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

    fn abort_ev(
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

    fn leak_ev(
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

    fn close_ev(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    // ========================================================================
    // Ghost Counter: increment on reserve
    // ========================================================================

    #[test]
    fn counter_increments_on_reserve() {
        init_test("counter_increments_on_reserve");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            commit_ev(11, o(1), r(0), ObligationKind::Ack),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "increments verified", true, verified);
        let peak = result.ghost_counter_peak;
        crate::assert_with_log!(peak == 2, "peak = 2", 2, peak);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 0, "final = 0", 0, final_count);
        crate::test_complete!("counter_increments_on_reserve");
    }

    // ========================================================================
    // Ghost Counter: decrement on resolve
    // ========================================================================

    #[test]
    fn counter_decrements_on_commit() {
        init_test("counter_decrements_on_commit");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "commit decrement verified", true, verified);
        let commit_count = result.paths_exercised.commit_count;
        crate::assert_with_log!(commit_count == 1, "1 commit", 1, commit_count);
        crate::test_complete!("counter_decrements_on_commit");
    }

    #[test]
    fn counter_decrements_on_abort() {
        init_test("counter_decrements_on_abort");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::Lease, t(0), r(0)),
            abort_ev(10, o(0), r(0), ObligationKind::Lease),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "abort decrement verified", true, verified);
        let abort_count = result.paths_exercised.abort_count;
        crate::assert_with_log!(abort_count == 1, "1 abort", 1, abort_count);
        crate::test_complete!("counter_decrements_on_abort");
    }

    #[test]
    fn counter_decrements_on_leak() {
        init_test("counter_decrements_on_leak");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak_ev(10, o(0), r(0), ObligationKind::IoOp),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "leak decrement verified", true, verified);
        let leak_count = result.paths_exercised.leak_count;
        crate::assert_with_log!(leak_count == 1, "1 leak", 1, leak_count);
        crate::test_complete!("counter_decrements_on_leak");
    }

    // ========================================================================
    // All four paths
    // ========================================================================

    #[test]
    fn all_three_paths_exercised() {
        init_test("all_three_paths_exercised");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve_ev(2, o(2), ObligationKind::Lease, t(2), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            abort_ev(11, o(1), r(0), ObligationKind::Ack),
            leak_ev(12, o(2), r(0), ObligationKind::Lease),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "all paths verified", true, verified);
        let paths = result.paths_exercised.paths_covered();
        crate::assert_with_log!(paths == 3, "3 paths", 3, paths);
        crate::test_complete!("all_three_paths_exercised");
    }

    // ========================================================================
    // Region quiescence
    // ========================================================================

    #[test]
    fn region_quiescence_clean() {
        init_test("region_quiescence_clean");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            close_ev(20, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "quiescence verified", true, verified);
        crate::test_complete!("region_quiescence_clean");
    }

    #[test]
    fn region_quiescence_violation() {
        init_test("region_quiescence_violation");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_ev(10, r(0)), // Still pending!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "quiescence violation detected", false, verified);

        let quiescence_count = result
            .counterexamples_of(LivenessProperty::RegionQuiescence)
            .count();
        crate::assert_with_log!(
            quiescence_count >= 1,
            "quiescence counterexample",
            true,
            quiescence_count >= 1
        );
        crate::test_complete!("region_quiescence_violation");
    }

    #[test]
    fn nested_regions_quiescent() {
        init_test("nested_regions_quiescent");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit_ev(10, o(1), r(1), ObligationKind::SendPermit),
            close_ev(15, r(1)),
            commit_ev(20, o(0), r(0), ObligationKind::Lease),
            close_ev(25, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "nested regions quiescent", true, verified);
        crate::test_complete!("nested_regions_quiescent");
    }

    // ========================================================================
    // Task completion
    // ========================================================================

    #[test]
    fn task_completion_clean() {
        init_test("task_completion_clean");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        for event in &events {
            prover.process_event(event);
        }
        prover.notify_task_complete(t(0), Time::from_nanos(20));

        let violations = prover.counterexamples.len();
        crate::assert_with_log!(violations == 0, "task clean", 0, violations);
        crate::test_complete!("task_completion_clean");
    }

    #[test]
    fn task_completion_with_pending() {
        init_test("task_completion_with_pending");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // No resolution before task completion!
        ];

        let mut prover = NoLeakProver::new();
        for event in &events {
            prover.process_event(event);
        }
        prover.notify_task_complete(t(0), Time::from_nanos(10));

        let task_violations = prover
            .counterexamples
            .iter()
            .filter(|c| c.property == LivenessProperty::TaskCompletion)
            .count();
        crate::assert_with_log!(
            task_violations == 1,
            "task completion violation",
            1,
            task_violations
        );
        crate::test_complete!("task_completion_with_pending");
    }

    // ========================================================================
    // Eventual resolution
    // ========================================================================

    #[test]
    fn eventual_resolution_clean() {
        init_test("eventual_resolution_clean");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            abort_ev(11, o(1), r(0), ObligationKind::Ack),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "eventual resolution verified", true, verified);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 0, "final = 0", 0, final_count);
        crate::test_complete!("eventual_resolution_clean");
    }

    #[test]
    fn eventual_resolution_violation() {
        init_test("eventual_resolution_violation");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // Never resolved!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "eventual resolution failed", false, verified);

        let er_count = result
            .counterexamples_of(LivenessProperty::EventualResolution)
            .count();
        crate::assert_with_log!(er_count >= 1, "eventual resolution CE", true, er_count >= 1);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 1, "final = 1", 1, final_count);
        crate::test_complete!("eventual_resolution_violation");
    }

    #[test]
    fn eventual_resolution_multiple_unresolved() {
        init_test("eventual_resolution_multiple_unresolved");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve_ev(2, o(2), ObligationKind::Lease, t(2), r(0)),
            commit_ev(10, o(1), r(0), ObligationKind::Ack), // Only o(1) resolved.
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "2 unresolved detected", false, verified);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 2, "final = 2", 2, final_count);
        crate::test_complete!("eventual_resolution_multiple_unresolved");
    }

    // ========================================================================
    // Use-after-release
    // ========================================================================

    #[test]
    fn rejects_double_resolve() {
        init_test("rejects_double_resolve");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(5, o(0), r(0), ObligationKind::SendPermit),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit), // DOUBLE!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "double resolve rejected", false, verified);
        crate::test_complete!("rejects_double_resolve");
    }

    #[test]
    fn rejects_resolve_without_reserve() {
        init_test("rejects_resolve_without_reserve");
        let events = vec![commit_ev(10, o(99), r(0), ObligationKind::SendPermit)];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "orphan resolve rejected", false, verified);
        crate::test_complete!("rejects_resolve_without_reserve");
    }

    // ========================================================================
    // Mutation tests
    // ========================================================================

    #[test]
    fn mutation_skipped_drop() {
        init_test("mutation_skipped_drop");
        // Simulates mem::forget: obligation reserved but never resolved.
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // No resolution (simulating mem::forget skipping Drop).
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "skipped drop detected", false, verified);
        crate::test_complete!("mutation_skipped_drop");
    }

    #[test]
    fn mutation_region_close_before_resolve() {
        init_test("mutation_region_close_before_resolve");
        // Region closes while obligation is still pending.
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_ev(10, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "premature close detected", false, verified);
        crate::test_complete!("mutation_region_close_before_resolve");
    }

    #[test]
    fn mutation_duplicate_reserve() {
        init_test("mutation_duplicate_reserve");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(5, o(0), ObligationKind::SendPermit, t(1), r(0)), // DUPLICATE!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "duplicate reserve detected", false, verified);
        crate::test_complete!("mutation_duplicate_reserve");
    }

    #[test]
    fn rejects_resolve_kind_mismatch() {
        init_test("rejects_resolve_kind_mismatch");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(5, o(0), r(0), ObligationKind::Lease),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "kind mismatch rejected", false, verified);
        let mismatch_count = result
            .counterexamples_of(LivenessProperty::CounterDecrement)
            .filter(|ce| ce.description.contains("kind mismatch"))
            .count();
        crate::assert_with_log!(mismatch_count == 1, "kind mismatch CE", 1, mismatch_count);
        crate::test_complete!("rejects_resolve_kind_mismatch");
    }

    #[test]
    fn rejects_resolve_region_mismatch() {
        init_test("rejects_resolve_region_mismatch");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(5, o(0), r(1), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "region mismatch rejected", false, verified);
        let mismatch_count = result
            .counterexamples_of(LivenessProperty::CounterDecrement)
            .filter(|ce| ce.description.contains("region mismatch"))
            .count();
        crate::assert_with_log!(mismatch_count == 1, "region mismatch CE", 1, mismatch_count);
        crate::test_complete!("rejects_resolve_region_mismatch");
    }

    #[test]
    fn rejects_reserve_after_region_close() {
        init_test("rejects_reserve_after_region_close");
        let events = vec![
            close_ev(0, r(0)),
            reserve_ev(5, o(0), ObligationKind::SendPermit, t(0), r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "reserve-after-close rejected", false, verified);
        let quiescence_count = result
            .counterexamples_of(LivenessProperty::RegionQuiescence)
            .filter(|ce| ce.description.contains("reserve"))
            .count();
        crate::assert_with_log!(
            quiescence_count == 1,
            "reserve-after-close CE",
            1,
            quiescence_count
        );
        crate::test_complete!("rejects_reserve_after_region_close");
    }

    #[test]
    fn failed_close_does_not_reject_later_resolution() {
        init_test("failed_close_does_not_reject_later_resolution");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_ev(5, r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "failed close still rejected", false, verified);
        let quiescence_count = result
            .counterexamples_of(LivenessProperty::RegionQuiescence)
            .count();
        crate::assert_with_log!(
            quiescence_count == 1,
            "only the failed close should violate quiescence",
            1,
            quiescence_count
        );
        let poisoned_close = result.counterexamples.iter().any(|ce| {
            ce.description.contains("already closed") || ce.description.contains("closed twice")
        });
        crate::assert_with_log!(
            !poisoned_close,
            "failed close should not mark region closed",
            false,
            poisoned_close
        );
        crate::test_complete!("failed_close_does_not_reject_later_resolution");
    }

    #[test]
    fn rejects_double_region_close() {
        init_test("rejects_double_region_close");
        let events = vec![close_ev(0, r(0)), close_ev(10, r(0))];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "double close rejected", false, verified);
        let quiescence_count = result
            .counterexamples_of(LivenessProperty::RegionQuiescence)
            .filter(|ce| ce.description.contains("closed twice"))
            .count();
        crate::assert_with_log!(
            quiescence_count == 1,
            "double-close CE",
            1,
            quiescence_count
        );
        crate::test_complete!("rejects_double_region_close");
    }

    #[test]
    fn failed_close_with_pending_does_not_poison_later_close() {
        init_test("failed_close_with_pending_does_not_poison_later_close");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_ev(10, r(0)),
            commit_ev(20, o(0), r(0), ObligationKind::SendPermit),
            close_ev(30, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "first close still rejected", false, verified);
        let quiescence_count = result
            .counterexamples_of(LivenessProperty::RegionQuiescence)
            .count();
        crate::assert_with_log!(
            quiescence_count == 1,
            "only the first close should violate quiescence",
            1,
            quiescence_count
        );
        let poisoned_close = result.counterexamples.iter().any(|ce| {
            ce.description.contains("already closed") || ce.description.contains("closed twice")
        });
        crate::assert_with_log!(
            !poisoned_close,
            "failed close should not mark region closed",
            false,
            poisoned_close
        );
        crate::test_complete!("failed_close_with_pending_does_not_poison_later_close");
    }

    // ========================================================================
    // Realistic scenarios
    // ========================================================================

    #[test]
    fn realistic_multi_task_multi_region() {
        init_test("realistic_multi_task_multi_region");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve_ev(2, o(2), ObligationKind::Lease, t(2), r(1)),
            reserve_ev(3, o(3), ObligationKind::IoOp, t(3), r(1)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            abort_ev(11, o(1), r(0), ObligationKind::Ack),
            close_ev(15, r(0)),
            commit_ev(20, o(2), r(1), ObligationKind::Lease),
            leak_ev(21, o(3), r(1), ObligationKind::IoOp),
            close_ev(25, r(1)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "multi-task multi-region verified", true, verified);
        let paths = result.paths_exercised.paths_covered();
        crate::assert_with_log!(paths == 3, "all 3 paths covered", 3, paths);
        let total_reserved = result.total_reserved;
        crate::assert_with_log!(total_reserved == 4, "4 reserved", 4, total_reserved);
        crate::test_complete!("realistic_multi_task_multi_region");
    }

    #[test]
    fn realistic_interleaved_operations() {
        init_test("realistic_interleaved_operations");
        // Reserve and resolve in interleaved order.
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit_ev(2, o(0), r(0), ObligationKind::SendPermit),
            reserve_ev(3, o(2), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(4, o(1), r(0), ObligationKind::SendPermit),
            commit_ev(5, o(2), r(0), ObligationKind::SendPermit),
            close_ev(10, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "interleaved verified", true, verified);
        let peak = result.ghost_counter_peak;
        crate::assert_with_log!(peak == 2, "peak = 2", 2, peak);
        crate::test_complete!("realistic_interleaved_operations");
    }

    // ========================================================================
    // Display and edge cases
    // ========================================================================

    #[test]
    fn proof_result_display() {
        init_test("proof_result_display");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let display = format!("{result}");
        let has_title = display.contains("No-Leak");
        crate::assert_with_log!(has_title, "display has title", true, has_title);
        let has_verified = display.contains("Verified:");
        crate::assert_with_log!(has_verified, "display has verified", true, has_verified);
        crate::test_complete!("proof_result_display");
    }

    #[test]
    fn counterexample_display() {
        init_test("counterexample_display");
        let ce = LeakCounterexample {
            property: LivenessProperty::EventualResolution,
            subject: ProofSubject::Obligation(o(0)),
            time: Time::from_nanos(42),
            description: "test".to_string(),
        };
        let s = format!("{ce}");
        let has_property = s.contains("eventual-resolution");
        crate::assert_with_log!(has_property, "has property", true, has_property);
        crate::test_complete!("counterexample_display");
    }

    #[test]
    fn empty_trace() {
        init_test("empty_trace");
        let mut prover = NoLeakProver::new();
        let result = prover.check(&[]);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "empty verified", true, verified);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 0, "final = 0", 0, final_count);
        crate::test_complete!("empty_trace");
    }

    #[test]
    fn prover_reuse_resets() {
        init_test("prover_reuse_resets");
        let mut prover = NoLeakProver::new();

        // First: violation.
        let events1 = vec![reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0))];
        let r1 = prover.check(&events1);
        crate::assert_with_log!(!r1.is_verified(), "first not verified", false, false);

        // Second: clean.
        let events2 = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];
        let r2 = prover.check(&events2);
        crate::assert_with_log!(r2.is_verified(), "second verified (reset)", true, true);
        crate::test_complete!("prover_reuse_resets");
    }

    #[test]
    fn liveness_property_display() {
        init_test("liveness_property_display");
        let props = [
            LivenessProperty::CounterIncrement,
            LivenessProperty::CounterDecrement,
            LivenessProperty::CounterNonNegative,
            LivenessProperty::TaskCompletion,
            LivenessProperty::RegionQuiescence,
            LivenessProperty::EventualResolution,
            LivenessProperty::DropPathCoverage,
        ];
        for prop in &props {
            let s = format!("{prop}");
            let non_empty = !s.is_empty();
            crate::assert_with_log!(non_empty, format!("{prop:?}"), true, non_empty);
        }
        crate::test_complete!("liveness_property_display");
    }

    #[test]
    fn path_coverage_counting() {
        init_test("path_coverage_counting");
        let mut pc = PathCoverage::default();
        let paths = pc.paths_covered();
        crate::assert_with_log!(paths == 0, "0 paths", 0, paths);

        pc.commit_count = 1;
        let paths = pc.paths_covered();
        crate::assert_with_log!(paths == 1, "1 path", 1, paths);

        pc.abort_count = 1;
        pc.leak_count = 1;
        let paths = pc.paths_covered();
        crate::assert_with_log!(paths == 3, "3 paths", 3, paths);
        crate::test_complete!("path_coverage_counting");
    }

    #[test]
    fn resolution_path_display() {
        init_test("resolution_path_display");
        let paths = [
            ResolutionPath::Committed,
            ResolutionPath::Aborted,
            ResolutionPath::Leaked,
        ];
        for path in &paths {
            let s = format!("{path}");
            let non_empty = !s.is_empty();
            crate::assert_with_log!(non_empty, format!("{path:?}"), true, non_empty);
        }
        crate::test_complete!("resolution_path_display");
    }

    #[test]
    fn proof_subject_display() {
        init_test("proof_subject_display");
        let subjects = [
            ProofSubject::Obligation(o(0)),
            ProofSubject::Task(t(0)),
            ProofSubject::Region(r(0)),
        ];
        for subject in &subjects {
            let s = format!("{subject}");
            let non_empty = !s.is_empty();
            crate::assert_with_log!(non_empty, format!("{subject:?}"), true, non_empty);
        }
        crate::test_complete!("proof_subject_display");
    }
