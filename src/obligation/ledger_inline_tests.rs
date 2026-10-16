    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationKind;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(1, 0))
    }

    fn make_region() -> RegionId {
        non_root_region(0)
    }

    fn other_region() -> RegionId {
        non_root_region(1)
    }

    fn non_root_region(index: u32) -> RegionId {
        // The root region (`as_u64() == 0`) cannot own obligations because it
        // never closes to drain them. Ledger tests need ordinary non-root
        // owner regions while preserving stable fixture IDs. (br-asupersync-88h4nd)
        RegionId::from_arena(ArenaIndex::new(index, 1))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LedgerObservation {
        stats: LedgerStats,
        len: usize,
        pending_count: u64,
        pending_for_region: usize,
        pending_for_task: usize,
        pending_ids_for_region: usize,
        region_clean: bool,
        leak_count: usize,
        region_leak_count: usize,
    }

    fn observe_ledger(
        ledger: &ObligationLedger,
        task: TaskId,
        region: RegionId,
    ) -> LedgerObservation {
        LedgerObservation {
            stats: ledger.stats(),
            len: ledger.len(),
            pending_count: ledger.pending_count(),
            pending_for_region: ledger.pending_for_region(region),
            pending_for_task: ledger.pending_for_task(task),
            pending_ids_for_region: ledger.pending_ids_for_region(region).len(),
            region_clean: ledger.is_region_clean(region),
            leak_count: ledger.check_leaks().leaked.len(),
            region_leak_count: ledger.check_region_leaks(region).leaked.len(),
        }
    }

    // ---- Basic lifecycle ---------------------------------------------------

    #[test]
    fn acquire_commit_clean() {
        init_test("acquire_commit_clean");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(10),
        );
        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 1, "pending", 1, pending);

        let duration = ledger.commit(token, Time::from_nanos(25));
        crate::assert_with_log!(duration == 15, "duration", 15, duration);

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 0, "pending after commit", 0, pending);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::assert_with_log!(
            stats.total_acquired == 1,
            "acquired",
            1,
            stats.total_acquired
        );
        crate::assert_with_log!(
            stats.total_committed == 1,
            "committed",
            1,
            stats.total_committed
        );
        crate::test_complete!("acquire_commit_clean");
    }

    #[test]
    fn acquire_abort_clean() {
        init_test("acquire_abort_clean");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(5));
        let duration = ledger.abort(token, Time::from_nanos(10), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 5, "duration", 5, duration);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::test_complete!("acquire_abort_clean");
    }

    // ---- Leak detection ---------------------------------------------------

    #[test]
    fn leak_check_detects_pending() {
        init_test("leak_check_detects_pending");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let _token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        // Intentionally not resolving — simulate a lost token.

        let result = ledger.check_leaks();
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let len = result.leaked.len();
        crate::assert_with_log!(len == 1, "leaked count", 1, len);
        let kind = result.leaked[0].kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "leaked kind",
            ObligationKind::Lease,
            kind
        );
        crate::test_complete!("leak_check_detects_pending");
    }

    #[test]
    fn leak_check_clean_after_resolve() {
        init_test("leak_check_clean_after_resolve");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);

        ledger.commit(t1, Time::from_nanos(1));
        ledger.abort(t2, Time::from_nanos(1), ObligationAbortReason::Explicit);

        let result = ledger.check_leaks();
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::test_complete!("leak_check_clean_after_resolve");
    }

    // ---- Region queries ---------------------------------------------------

    #[test]
    fn pending_for_region() {
        init_test("pending_for_region");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r1 = make_region();
        let r2 = other_region();

        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, r1, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, r1, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, r2, Time::ZERO);

        let r1_pending = ledger.pending_for_region(r1);
        crate::assert_with_log!(r1_pending == 2, "r1 pending", 2, r1_pending);

        let r2_pending = ledger.pending_for_region(r2);
        crate::assert_with_log!(r2_pending == 1, "r2 pending", 1, r2_pending);

        let r1_clean = ledger.is_region_clean(r1);
        crate::assert_with_log!(!r1_clean, "r1 not clean", false, r1_clean);
        crate::test_complete!("pending_for_region");
    }

    #[test]
    fn audit_counts_are_filterable_and_deterministic() {
        init_test("audit_counts_are_filterable_and_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let other_task = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = make_region();
        let other_region = other_region();

        let pending = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(10),
        );
        let pending_id = pending.id();
        let committed = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(20));
        let committed_id = committed.id();
        let aborted = ledger.acquire(
            ObligationKind::Lease,
            other_task,
            other_region,
            Time::from_nanos(30),
        );
        let aborted_id = aborted.id();
        let leaked = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(40));
        let leaked_id = leaked.id();

        ledger.commit(committed, Time::from_nanos(50));
        ledger.abort(aborted, Time::from_nanos(60), ObligationAbortReason::Cancel);
        ledger.mark_leaked(leaked_id, Time::from_nanos(70));

        let region_counts = ledger.counts_for_region(region);
        crate::assert_with_log!(
            region_counts.pending == 1,
            "region pending",
            1usize,
            region_counts.pending
        );
        crate::assert_with_log!(
            region_counts.committed == 1,
            "region committed",
            1usize,
            region_counts.committed
        );
        crate::assert_with_log!(
            region_counts.leaked == 1,
            "region leaked",
            1usize,
            region_counts.leaked
        );
        let region_kind_count = ledger
            .counts_for_region_and_kind(region, ObligationKind::SendPermit)
            .pending;
        crate::assert_with_log!(
            region_kind_count == 1,
            "region kind pending",
            1usize,
            region_kind_count
        );
        let task_total = ledger.counts_for_task(task).total();
        crate::assert_with_log!(task_total == 3, "task total", 3usize, task_total);
        let lease_aborted = ledger.counts_for_kind(ObligationKind::Lease).aborted;
        crate::assert_with_log!(lease_aborted == 1, "kind aborted", 1usize, lease_aborted);
        let aborted_state = ledger.obligation_state(aborted_id);
        crate::assert_with_log!(
            aborted_state == Some(ObligationState::Aborted),
            "obligation state",
            Some(ObligationState::Aborted),
            aborted_state
        );

        let audit = ledger.audit_region(region, Time::from_nanos(100));
        let audit_ids: Vec<_> = audit.iter().map(|record| record.id).collect();
        crate::assert_with_log!(
            audit_ids == vec![pending_id, committed_id, leaked_id],
            "audit ids sorted",
            vec![pending_id, committed_id, leaked_id],
            audit_ids.clone()
        );
        crate::assert_with_log!(audit[0].age_ns == 90, "pending age", 90u64, audit[0].age_ns);
        crate::assert_with_log!(
            audit[2].state == ObligationState::Leaked,
            "leaked audit state",
            ObligationState::Leaked,
            audit[2].state
        );
        let _ = pending;
        crate::test_complete!("audit_counts_are_filterable_and_deterministic");
    }

    #[test]
    fn pending_ids_for_region_returns_sorted() {
        init_test("pending_ids_for_region_returns_sorted");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);

        let ids = ledger.pending_ids_for_region(region);
        crate::assert_with_log!(ids.len() == 2, "ids len", 2, ids.len());
        // BTreeMap ensures deterministic order.
        crate::assert_with_log!(ids[0] == t1.id(), "first id", t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == t2.id(), "second id", t2.id(), ids[1]);

        crate::test_complete!("pending_ids_for_region_returns_sorted");
    }

    // ---- Mark leaked -----------------------------------------------------

    #[test]
    fn mark_leaked_updates_stats() {
        init_test("mark_leaked_updates_stats");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(0));
        let id = token.id();
        // Intentionally not resolving token; mark as leaked below.

        ledger.mark_leaked(id, Time::from_nanos(100));

        let stats = ledger.stats();
        crate::assert_with_log!(!stats.is_clean(), "not clean", false, stats.is_clean());
        crate::assert_with_log!(stats.total_leaked == 1, "leaked", 1, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("mark_leaked_updates_stats");
    }

    #[test]
    fn check_leaks_includes_marked_leaked_obligations() {
        init_test("check_leaks_includes_marked_leaked_obligations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let leaked_id = token.id();
        ledger.mark_leaked(leaked_id, Time::from_nanos(10));

        let result = ledger.check_leaks();
        crate::assert_with_log!(!result.is_clean(), "not clean", false, result.is_clean());
        crate::assert_with_log!(
            result.leaked.len() == 1,
            "leak count",
            1,
            result.leaked.len()
        );
        crate::assert_with_log!(
            result.leaked[0].id == leaked_id,
            "leaked id",
            leaked_id,
            result.leaked[0].id
        );
        crate::test_complete!("check_leaks_includes_marked_leaked_obligations");
    }

    // ---- Task queries ----------------------------------------------------

    #[test]
    fn pending_for_task() {
        init_test("pending_for_task");
        let mut ledger = ObligationLedger::new();
        let t1 = TaskId::from_arena(ArenaIndex::new(0, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region = make_region();

        let _tok1 = ledger.acquire(ObligationKind::SendPermit, t1, region, Time::ZERO);
        let _tok2 = ledger.acquire(ObligationKind::Ack, t1, region, Time::ZERO);
        let _tok3 = ledger.acquire(ObligationKind::Lease, t2, region, Time::ZERO);

        let t1_pending = ledger.pending_for_task(t1);
        crate::assert_with_log!(t1_pending == 2, "t1 pending", 2, t1_pending);

        let t2_pending = ledger.pending_for_task(t2);
        crate::assert_with_log!(t2_pending == 1, "t2 pending", 1, t2_pending);

        crate::test_complete!("pending_for_task");
    }

    // ---- Region leak check -----------------------------------------------

    #[test]
    fn check_region_leaks_scoped() {
        init_test("check_region_leaks_scoped");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r1 = make_region();
        let r2 = other_region();

        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, r1, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, r2, Time::ZERO);
        ledger.commit(t2, Time::from_nanos(1));

        let r1_result = ledger.check_region_leaks(r1);
        crate::assert_with_log!(
            !r1_result.is_clean(),
            "r1 leaks",
            false,
            r1_result.is_clean()
        );

        let r2_result = ledger.check_region_leaks(r2);
        crate::assert_with_log!(r2_result.is_clean(), "r2 clean", true, r2_result.is_clean());

        crate::test_complete!("check_region_leaks_scoped");
    }

    // ---- Empty ledger is clean -------------------------------------------

    #[test]
    fn empty_ledger_is_clean() {
        init_test("empty_ledger_is_clean");
        let ledger = ObligationLedger::new();
        let result = ledger.check_leaks();
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::assert_with_log!(ledger.is_empty(), "empty", true, ledger.is_empty());
        let len = ledger.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("empty_ledger_is_clean");
    }

    // ---- Reset -----------------------------------------------------------

    #[test]
    fn reset_clears_everything() {
        init_test("reset_clears_everything");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        ledger.commit(token, Time::from_nanos(1));

        crate::assert_with_log!(ledger.len() == 1, "len before reset", 1, ledger.len());
        ledger.reset();
        crate::assert_with_log!(
            ledger.is_empty(),
            "empty after reset",
            true,
            ledger.is_empty()
        );
        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_acquired == 0,
            "acquired",
            0,
            stats.total_acquired
        );
        crate::test_complete!("reset_clears_everything");
    }

    #[test]
    fn reset_panics_if_pending_obligation_exists() {
        init_test("reset_panics_if_pending_obligation_exists");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let stale = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let stale_id = stale.id();

        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.reset()));
        crate::assert_with_log!(reset.is_err(), "reset rejected", true, reset.is_err());

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 1, "pending preserved", 1, pending);

        let leaks = ledger.check_leaks();
        crate::assert_with_log!(
            !leaks.is_clean(),
            "leak report still non-clean",
            false,
            leaks.is_clean()
        );
        crate::assert_with_log!(leaks.leaked.len() == 1, "leak count", 1, leaks.leaked.len());
        crate::assert_with_log!(
            leaks.leaked[0].id == stale_id,
            "stale id tracked",
            stale_id,
            leaks.leaked[0].id
        );

        let region_leaks = ledger.check_region_leaks(region);
        crate::assert_with_log!(
            !region_leaks.is_clean(),
            "region leak report still non-clean",
            false,
            region_leaks.is_clean()
        );

        ledger.commit(stale, Time::from_nanos(2));
        crate::test_complete!("reset_panics_if_pending_obligation_exists");
    }

    #[test]
    fn reset_panics_if_leaked_obligation_exists() {
        init_test("reset_panics_if_leaked_obligation_exists");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let leaked = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let leaked_id = leaked.id();
        ledger.mark_leaked(leaked_id, Time::from_nanos(5));

        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.reset()));
        crate::assert_with_log!(reset.is_err(), "reset rejected", true, reset.is_err());

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "pending preserved", 0, stats.pending);
        crate::assert_with_log!(
            stats.total_leaked == 1,
            "leaked preserved",
            1,
            stats.total_leaked
        );
        crate::assert_with_log!(
            !stats.is_clean(),
            "still not clean",
            false,
            stats.is_clean()
        );

        let leaks = ledger.check_leaks();
        crate::assert_with_log!(
            !leaks.is_clean(),
            "leak report still non-clean",
            false,
            leaks.is_clean()
        );
        crate::assert_with_log!(leaks.leaked.len() == 1, "leak count", 1, leaks.leaked.len());
        crate::assert_with_log!(
            leaks.leaked[0].id == leaked_id,
            "leaked id tracked",
            leaked_id,
            leaks.leaked[0].id
        );
        crate::test_complete!("reset_panics_if_leaked_obligation_exists");
    }

    #[test]
    fn reset_reuses_index_with_bumped_generation() {
        init_test("reset_reuses_index_with_bumped_generation");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let old = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let old_id = old.id();
        let old_idx = old_id.arena_index();
        ledger.commit(old, Time::from_nanos(1));

        ledger.reset();

        let fresh = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(2));
        let fresh_idx = fresh.id().arena_index();
        crate::assert_with_log!(
            fresh.id() != old_id,
            "fresh id differs",
            true,
            fresh.id() != old_id
        );
        crate::assert_with_log!(
            fresh_idx.index() == old_idx.index(),
            "index reused after clean reset",
            old_idx.index(),
            fresh_idx.index()
        );
        crate::assert_with_log!(
            fresh_idx.generation() == old_idx.generation().saturating_add(1),
            "generation bumped after clean reset",
            old_idx.generation().saturating_add(1),
            fresh_idx.generation()
        );

        ledger.commit(fresh, Time::from_nanos(3));
        crate::test_complete!("reset_reuses_index_with_bumped_generation");
    }

    #[test]
    fn reset_clears_finalized_region_fence() {
        init_test("reset_clears_finalized_region_fence");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        ledger.commit(token, Time::from_nanos(1));
        ledger.mark_region_finalized(region);
        crate::assert_with_log!(
            ledger.is_region_finalized(region),
            "region finalized before reset",
            true,
            ledger.is_region_finalized(region)
        );

        ledger.reset();

        crate::assert_with_log!(
            !ledger.is_region_finalized(region),
            "reset clears finalized region fence",
            false,
            ledger.is_region_finalized(region)
        );

        let fresh = ledger
            .try_acquire(ObligationKind::Ack, task, region, Time::from_nanos(2))
            .expect("reset must allow fresh acquire for the same region id");
        crate::assert_with_log!(
            ledger.pending_count() == 1,
            "fresh acquire allowed after reset",
            1,
            ledger.pending_count()
        );
        ledger.commit(fresh, Time::from_nanos(3));

        crate::test_complete!("reset_clears_finalized_region_fence");
    }

    #[test]
    fn stale_id_from_previous_generation_cannot_touch_post_reset_obligation() {
        init_test("stale_id_from_previous_generation_cannot_touch_post_reset_obligation");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let stale = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let stale_id = stale.id();
        ledger.abort_by_id(
            stale_id,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );

        ledger.reset();

        let fresh = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(20));
        let fresh_id = fresh.id();
        let fresh_idx = fresh_id.arena_index();
        let stale_idx = stale_id.arena_index();
        crate::assert_with_log!(
            fresh_idx.index() == stale_idx.index(),
            "slot index reused",
            stale_idx.index(),
            fresh_idx.index()
        );
        crate::assert_with_log!(
            fresh_idx.generation() != stale_idx.generation(),
            "generation differs",
            true,
            fresh_idx.generation() != stale_idx.generation()
        );

        let stale_abort = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(
                stale_id,
                Time::from_nanos(30),
                ObligationAbortReason::Cancel,
            )
        }));
        crate::assert_with_log!(
            stale_abort.is_err(),
            "stale id rejected",
            true,
            stale_abort.is_err()
        );

        let fresh_record = ledger.get(fresh_id).expect("fresh obligation exists");
        crate::assert_with_log!(
            fresh_record.is_pending(),
            "fresh obligation remains pending",
            true,
            fresh_record.is_pending()
        );

        ledger.commit(fresh, Time::from_nanos(40));
        crate::test_complete!(
            "stale_id_from_previous_generation_cannot_touch_post_reset_obligation"
        );
    }

    #[test]
    fn metamorphic_reset_advances_generation_monotonically() {
        init_test("metamorphic_reset_advances_generation_monotonically");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let first = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(1),
        );
        let first_idx = first.id().arena_index();
        ledger.commit(first, Time::from_nanos(2));
        ledger.reset();

        let second = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(3),
        );
        let second_idx = second.id().arena_index();
        ledger.commit(second, Time::from_nanos(4));
        ledger.reset();

        let third = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(5),
        );
        let third_idx = third.id().arena_index();
        ledger.commit(third, Time::from_nanos(6));

        crate::assert_with_log!(
            first_idx.index() == second_idx.index(),
            "reset reuses slot after first epoch",
            first_idx.index(),
            second_idx.index()
        );
        crate::assert_with_log!(
            second_idx.index() == third_idx.index(),
            "reset reuses slot after second epoch",
            second_idx.index(),
            third_idx.index()
        );
        crate::assert_with_log!(
            second_idx.generation() == first_idx.generation().saturating_add(1),
            "first reset bumps generation by one",
            first_idx.generation().saturating_add(1),
            second_idx.generation()
        );
        crate::assert_with_log!(
            third_idx.generation() == second_idx.generation().saturating_add(1),
            "second reset bumps generation by one",
            second_idx.generation().saturating_add(1),
            third_idx.generation()
        );

        crate::test_complete!("metamorphic_reset_advances_generation_monotonically");
    }

    #[test]
    fn metamorphic_post_reset_commit_matches_fresh_epoch_observables() {
        init_test("metamorphic_post_reset_commit_matches_fresh_epoch_observables");
        let task = make_task();
        let region = make_region();

        let mut fresh = ObligationLedger::new();
        let fresh_token = fresh.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let fresh_idx = fresh_token.id().arena_index();
        fresh.commit(fresh_token, Time::from_nanos(20));
        let fresh_observation = observe_ledger(&fresh, task, region);

        let mut recycled = ObligationLedger::new();
        let old = recycled.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        recycled.abort(old, Time::from_nanos(2), ObligationAbortReason::Cancel);
        recycled.reset();

        let recycled_token =
            recycled.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let recycled_idx = recycled_token.id().arena_index();
        recycled.commit(recycled_token, Time::from_nanos(20));
        let recycled_observation = observe_ledger(&recycled, task, region);

        crate::assert_with_log!(
            fresh_observation == recycled_observation,
            "post-reset epoch observables match fresh epoch",
            fresh_observation,
            recycled_observation
        );
        crate::assert_with_log!(
            recycled_idx.index() == fresh_idx.index(),
            "post-reset epoch rewinds slot allocation",
            fresh_idx.index(),
            recycled_idx.index()
        );
        crate::assert_with_log!(
            recycled_idx.generation() == fresh_idx.generation().saturating_add(1),
            "post-reset epoch bumps generation",
            fresh_idx.generation().saturating_add(1),
            recycled_idx.generation()
        );

        crate::test_complete!("metamorphic_post_reset_commit_matches_fresh_epoch_observables");
    }

    #[test]
    fn metamorphic_stale_token_after_reset_matches_drop_before_reset_round_trip() {
        init_test("metamorphic_stale_token_after_reset_matches_drop_before_reset_round_trip");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_stale =
            baseline.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        let baseline_stale_id = baseline_stale.id();
        baseline.abort_by_id(
            baseline_stale_id,
            Time::from_nanos(2),
            ObligationAbortReason::Cancel,
        );
        drop(baseline_stale);
        baseline.reset();

        let baseline_fresh =
            baseline.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let baseline_fresh_id = baseline_fresh.id();
        baseline.commit(baseline_fresh, Time::from_nanos(20));
        let baseline_observation = observe_ledger(&baseline, task, region);
        let baseline_resolution = observable_resolution_state(&baseline, baseline_fresh_id);

        let mut commit_replay = ObligationLedger::new();
        let stale_commit =
            commit_replay.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        let stale_commit_id = stale_commit.id();
        commit_replay.abort_by_id(
            stale_commit_id,
            Time::from_nanos(2),
            ObligationAbortReason::Cancel,
        );
        commit_replay.reset();

        let commit_fresh =
            commit_replay.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let commit_fresh_id = commit_fresh.id();
        commit_replay.commit(commit_fresh, Time::from_nanos(20));
        let stale_commit_replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            commit_replay.commit(stale_commit, Time::from_nanos(21))
        }));
        crate::assert_with_log!(
            stale_commit_replay.is_err(),
            "stale commit replay rejected after reset",
            true,
            stale_commit_replay.is_err()
        );
        crate::assert_with_log!(
            observable_resolution_state(&commit_replay, commit_fresh_id) == baseline_resolution,
            "stale commit replay preserves fresh terminal observables",
            baseline_resolution,
            observable_resolution_state(&commit_replay, commit_fresh_id)
        );
        crate::assert_with_log!(
            observe_ledger(&commit_replay, task, region) == baseline_observation,
            "stale commit replay preserves ledger observation",
            baseline_observation,
            observe_ledger(&commit_replay, task, region)
        );

        let mut abort_replay = ObligationLedger::new();
        let stale_abort =
            abort_replay.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        let stale_abort_id = stale_abort.id();
        abort_replay.abort_by_id(
            stale_abort_id,
            Time::from_nanos(2),
            ObligationAbortReason::Cancel,
        );
        abort_replay.reset();

        let abort_fresh =
            abort_replay.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let abort_fresh_id = abort_fresh.id();
        abort_replay.commit(abort_fresh, Time::from_nanos(20));
        let stale_abort_replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            abort_replay.abort(
                stale_abort,
                Time::from_nanos(21),
                ObligationAbortReason::Explicit,
            )
        }));
        crate::assert_with_log!(
            stale_abort_replay.is_err(),
            "stale abort replay rejected after reset",
            true,
            stale_abort_replay.is_err()
        );
        crate::assert_with_log!(
            observable_resolution_state(&abort_replay, abort_fresh_id) == baseline_resolution,
            "stale abort replay preserves fresh terminal observables",
            baseline_resolution,
            observable_resolution_state(&abort_replay, abort_fresh_id)
        );
        crate::assert_with_log!(
            observe_ledger(&abort_replay, task, region) == baseline_observation,
            "stale abort replay preserves ledger observation",
            baseline_observation,
            observe_ledger(&abort_replay, task, region)
        );

        crate::test_complete!(
            "metamorphic_stale_token_after_reset_matches_drop_before_reset_round_trip"
        );
    }

    #[test]
    fn metamorphic_failed_reset_then_commit_matches_commit_then_reset() {
        init_test("metamorphic_failed_reset_then_commit_matches_commit_then_reset");
        let task = make_task();
        let region = make_region();

        let mut raced = ObligationLedger::new();
        let raced_token = raced.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(100),
        );

        let early_reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| raced.reset()));
        crate::assert_with_log!(
            early_reset.is_err(),
            "early reset rejected",
            true,
            early_reset.is_err()
        );

        raced.commit(raced_token, Time::from_nanos(110));
        raced.reset();
        let raced_post_reset =
            raced.acquire(ObligationKind::Ack, task, region, Time::from_nanos(120));
        let raced_idx = raced_post_reset.id().arena_index();
        raced.commit(raced_post_reset, Time::from_nanos(130));
        let raced_observation = observe_ledger(&raced, task, region);

        let mut canonical = ObligationLedger::new();
        let canonical_token = canonical.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(100),
        );
        canonical.commit(canonical_token, Time::from_nanos(110));
        canonical.reset();
        let canonical_post_reset =
            canonical.acquire(ObligationKind::Ack, task, region, Time::from_nanos(120));
        let canonical_idx = canonical_post_reset.id().arena_index();
        canonical.commit(canonical_post_reset, Time::from_nanos(130));
        let canonical_observation = observe_ledger(&canonical, task, region);

        crate::assert_with_log!(
            raced_observation == canonical_observation,
            "failed reset leaves eventual epoch observables unchanged",
            canonical_observation,
            raced_observation
        );
        crate::assert_with_log!(
            raced_idx == canonical_idx,
            "failed reset does not advance generation or slot allocation",
            canonical_idx,
            raced_idx
        );

        crate::test_complete!("metamorphic_failed_reset_then_commit_matches_commit_then_reset");
    }

    // ---- Deterministic iteration -----------------------------------------

    #[test]
    fn iteration_is_deterministic() {
        init_test("iteration_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire multiple obligations.
        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        // Iteration order should be by ID (BTreeMap).
        let ids: Vec<ObligationId> = ledger.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(ids.len() == 3, "len", 3, ids.len());
        // IDs are monotonically increasing since we allocate sequentially.
        crate::assert_with_log!(ids[0] == t1.id(), "first", t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == t2.id(), "second", t2.id(), ids[1]);
        crate::assert_with_log!(ids[2] == t3.id(), "third", t3.id(), ids[2]);
        crate::test_complete!("iteration_is_deterministic");
    }

    // ---- Get by ID -------------------------------------------------------

    #[test]
    fn get_by_id() {
        init_test("get_by_id");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(42));
        let id = token.id();

        let record = ledger.get(id).expect("should exist");
        crate::assert_with_log!(
            record.kind == ObligationKind::IoOp,
            "kind",
            ObligationKind::IoOp,
            record.kind
        );
        crate::assert_with_log!(record.is_pending(), "pending", true, record.is_pending());

        ledger.commit(token, Time::from_nanos(50));
        let record = ledger.get(id).expect("still exists");
        crate::assert_with_log!(!record.is_pending(), "resolved", false, record.is_pending());
        crate::test_complete!("get_by_id");
    }

    // ---- Acquire with description ----------------------------------------

    #[test]
    fn acquire_with_context_captures_description() {
        init_test("acquire_with_context_captures_description");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire_with_context(
            ObligationKind::Lease,
            task,
            region,
            Time::ZERO,
            SourceLocation::unknown(),
            None,
            Some("my lease description".to_string()),
        );
        let id = token.id();

        let record = ledger.get(id).expect("exists");
        crate::assert_with_log!(
            record.description == Some("my lease description".to_string()),
            "description",
            Some("my lease description".to_string()),
            record.description
        );

        ledger.commit(token, Time::from_nanos(1));
        crate::test_complete!("acquire_with_context_captures_description");
    }

    // ---- Multiple kinds in one ledger ------------------------------------

    #[test]
    fn multiple_obligation_kinds() {
        init_test("multiple_obligation_kinds");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t_send = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t_ack = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t_lease = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let t_io = ledger.acquire(ObligationKind::IoOp, task, region, Time::ZERO);

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 4, "pending", 4, pending);

        ledger.commit(t_send, Time::from_nanos(1));
        ledger.abort(t_ack, Time::from_nanos(1), ObligationAbortReason::Cancel);
        ledger.commit(t_lease, Time::from_nanos(1));
        ledger.abort(t_io, Time::from_nanos(1), ObligationAbortReason::Error);

        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_committed == 2,
            "committed",
            2,
            stats.total_committed
        );
        crate::assert_with_log!(stats.total_aborted == 2, "aborted", 2, stats.total_aborted);
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::test_complete!("multiple_obligation_kinds");
    }

    // ---- Cancel drain: abort all pending obligations for a region --------

    #[test]
    fn cancel_drain_aborts_all_region_obligations() {
        init_test("cancel_drain_aborts_all_region_obligations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Simulate: task holds three obligations when cancel is requested.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        let pending = ledger.pending_for_region(region);
        crate::assert_with_log!(pending == 3, "pre-drain pending", 3, pending);

        // Drain: enumerate pending IDs and abort each one.
        let drain_time = Time::from_nanos(100);
        let pending_ids = ledger.pending_ids_for_region(region);
        crate::assert_with_log!(pending_ids.len() == 3, "drain ids", 3, pending_ids.len());

        for id in &pending_ids {
            ledger.abort_by_id(*id, drain_time, ObligationAbortReason::Cancel);
        }

        // Region should now be clean.
        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "region clean after drain", true, is_clean);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "global pending", 0, stats.pending);
        crate::assert_with_log!(
            stats.total_aborted == 3,
            "aborted count",
            3,
            stats.total_aborted
        );
        crate::assert_with_log!(
            stats.total_leaked == 0,
            "leaked count",
            0,
            stats.total_leaked
        );
        crate::assert_with_log!(stats.is_clean(), "ledger clean", true, stats.is_clean());
        crate::test_complete!("cancel_drain_aborts_all_region_obligations");
    }

    // ---- Cancel drain: multi-task region --------------------------------

    #[test]
    fn cancel_drain_multi_task_region() {
        init_test("cancel_drain_multi_task_region");
        let mut ledger = ObligationLedger::new();
        let t1 = TaskId::from_arena(ArenaIndex::new(0, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let t3 = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = make_region();

        // Three tasks in the same region, each with an obligation.
        let tok1 = ledger.acquire(ObligationKind::SendPermit, t1, region, Time::ZERO);
        let tok2 = ledger.acquire(ObligationKind::Ack, t2, region, Time::ZERO);
        let tok3 = ledger.acquire(ObligationKind::Lease, t3, region, Time::ZERO);

        // During drain, abort all obligations in the region.
        let drain_time = Time::from_nanos(50);
        ledger.abort(tok1, drain_time, ObligationAbortReason::Cancel);
        ledger.abort(tok2, drain_time, ObligationAbortReason::Cancel);
        ledger.abort(tok3, drain_time, ObligationAbortReason::Cancel);

        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "region clean", true, is_clean);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 3, "aborted", 3, stats.total_aborted);
        crate::assert_with_log!(stats.is_clean(), "ledger clean", true, stats.is_clean());
        crate::test_complete!("cancel_drain_multi_task_region");
    }

    // ---- Region isolation: drain one region, other unaffected -----------

    #[test]
    fn region_isolation_during_drain() {
        init_test("region_isolation_during_drain");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r_cancel = make_region();
        let r_alive = other_region();

        // Obligations in region being cancelled.
        let tok_cancel = ledger.acquire(ObligationKind::SendPermit, task, r_cancel, Time::ZERO);
        // Obligations in region that is still alive.
        let _tok_alive = ledger.acquire(ObligationKind::Ack, task, r_alive, Time::ZERO);

        // Drain only the cancelled region.
        ledger.abort(
            tok_cancel,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );

        // Cancelled region is clean.
        let cancel_clean = ledger.is_region_clean(r_cancel);
        crate::assert_with_log!(cancel_clean, "cancelled region clean", true, cancel_clean);

        // Alive region still has its obligation.
        let alive_pending = ledger.pending_for_region(r_alive);
        crate::assert_with_log!(alive_pending == 1, "alive region pending", 1, alive_pending);

        // Global ledger still has a pending obligation.
        let global_pending = ledger.pending_count();
        crate::assert_with_log!(global_pending == 1, "global pending", 1, global_pending);
        crate::test_complete!("region_isolation_during_drain");
    }

    // ---- Deterministic drain ordering -----------------------------------

    #[test]
    fn drain_ordering_is_deterministic() {
        init_test("drain_ordering_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire obligations in a known order.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(1));
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(2));

        // IDs should be monotonically increasing (BTreeMap).
        let ids = ledger.pending_ids_for_region(region);
        for window in ids.windows(2) {
            crate::assert_with_log!(window[0] < window[1], "monotonic ids", true, true);
        }

        // Drain in the deterministic order returned by pending_ids_for_region.
        let drain_time = Time::from_nanos(100);
        for id in &ids {
            ledger.abort_by_id(*id, drain_time, ObligationAbortReason::Cancel);
        }

        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "clean after ordered drain", true, is_clean);
        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 3, "aborted", 3, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::test_complete!("drain_ordering_is_deterministic");
    }

    // ---- Quiescence: region clean implies zero pending obligations ------

    #[test]
    fn region_quiescence_after_mixed_resolution() {
        init_test("region_quiescence_after_mixed_resolution");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire four obligations of different kinds.
        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let t4 = ledger.acquire(ObligationKind::IoOp, task, region, Time::ZERO);

        // Resolve them via different paths (commit, abort, cancel-abort).
        ledger.commit(t1, Time::from_nanos(10));
        ledger.abort(t2, Time::from_nanos(20), ObligationAbortReason::Explicit);
        ledger.abort(t3, Time::from_nanos(30), ObligationAbortReason::Cancel);
        ledger.commit(t4, Time::from_nanos(40));

        // Region should be clean regardless of resolution path.
        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "quiescent", true, is_clean);

        let leaks = ledger.check_region_leaks(region);
        crate::assert_with_log!(leaks.is_clean(), "no leaks", true, leaks.is_clean());

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "pending zero", 0, stats.pending);
        crate::assert_with_log!(stats.is_clean(), "stats clean", true, stats.is_clean());
        crate::test_complete!("region_quiescence_after_mixed_resolution");
    }

    // ---- Abort reason preserved -----------------------------------------

    #[test]
    fn abort_reason_preserved_in_record() {
        init_test("abort_reason_preserved_in_record");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();

        ledger.abort(token, Time::from_nanos(10), ObligationAbortReason::Cancel);

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state aborted",
            ObligationState::Aborted,
            record.state
        );
        crate::assert_with_log!(
            record.abort_reason == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            record.abort_reason
        );
        crate::test_complete!("abort_reason_preserved_in_record");
    }

    #[test]
    fn forged_token_metadata_panics_without_mutating_ledger() {
        init_test("forged_token_metadata_panics_without_mutating_ledger");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();
        let forged = ObligationToken {
            id,
            kind: ObligationKind::Ack,
            holder: task,
            region,
        };

        let commit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.commit(forged, Time::from_nanos(10));
        }));
        crate::assert_with_log!(
            commit.is_err(),
            "forged token rejected",
            true,
            commit.is_err()
        );

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Reserved,
            "state unchanged",
            ObligationState::Reserved,
            record.state
        );

        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_committed == 0,
            "committed",
            0,
            stats.total_committed
        );
        crate::assert_with_log!(stats.total_aborted == 0, "aborted", 0, stats.total_aborted);
        crate::assert_with_log!(stats.pending == 1, "pending", 1, stats.pending);
        crate::test_complete!("forged_token_metadata_panics_without_mutating_ledger");
    }

    #[test]
    fn abort_by_id_double_resolve_panics_without_pending_underflow() {
        init_test("abort_by_id_double_resolve_panics_without_pending_underflow");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort_by_id(id, Time::from_nanos(25), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let second_abort = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(id, Time::from_nanos(30), ObligationAbortReason::Cancel);
        }));
        crate::assert_with_log!(
            second_abort.is_err(),
            "double resolve rejected",
            true,
            second_abort.is_err()
        );

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state remains aborted",
            ObligationState::Aborted,
            record.state
        );

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("abort_by_id_double_resolve_panics_without_pending_underflow");
    }

    /// Race-tolerance contract for `try_abort_by_id` covering all four
    /// branches: NotFound, AlreadyResolved (committed and aborted), the
    /// happy reserved-then-aborted path, and the no-op fast-return for
    /// already-finalized regions. Pinned together so a future refactor
    /// that drops one branch can't pass the rest in isolation.
    #[test]
    fn try_abort_by_id_race_branches() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // (a) NotFound: no acquire happened for this ID. Use a fabricated
        // ID by acquiring + dropping (marking the slot used), then synthesise
        // a never-acquired ID via new_for_test in a fresh generation that
        // the ledger never minted.
        let phantom_id = ObligationId::new_for_test(99_999, 7);
        match ledger.try_abort_by_id(
            phantom_id,
            Time::from_nanos(1),
            ObligationAbortReason::Cancel,
        ) {
            Err(LedgerError::NotFound { obligation }) => {
                assert_eq!(obligation, phantom_id);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        assert_eq!(ledger.stats().pending, 0);
        assert_eq!(ledger.stats().total_aborted, 0);

        // (b) Happy path: reserve then race-tolerant abort succeeds.
        let token_b = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_b = token_b.id();
        match ledger.try_abort_by_id(id_b, Time::from_nanos(10), ObligationAbortReason::Cancel) {
            Ok(duration) => assert_eq!(duration, 10),
            other => panic!("expected Ok(10), got {other:?}"),
        }
        assert_eq!(ledger.stats().total_aborted, 1);
        assert_eq!(ledger.stats().pending, 0);

        // (c) AlreadyResolved (Aborted): hitting the just-aborted record
        // again must not panic and must not double-decrement pending.
        let pending_before = ledger.stats().pending;
        let aborted_before = ledger.stats().total_aborted;
        match ledger.try_abort_by_id(id_b, Time::from_nanos(20), ObligationAbortReason::Cancel) {
            Err(LedgerError::AlreadyResolved { obligation, state }) => {
                assert_eq!(obligation, id_b);
                assert_eq!(state, ObligationState::Aborted);
            }
            other => panic!("expected AlreadyResolved(Aborted), got {other:?}"),
        }
        assert_eq!(ledger.stats().pending, pending_before);
        assert_eq!(ledger.stats().total_aborted, aborted_before);

        // (d) AlreadyResolved (Committed): the canonical token-double-
        // fulfillment race — commit happens first, drain calls
        // try_abort_by_id second. Must observe Committed without panicking.
        let token_d = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_d = token_d.id();
        let _ = ledger.commit(token_d, Time::from_nanos(40));
        match ledger.try_abort_by_id(id_d, Time::from_nanos(50), ObligationAbortReason::Cancel) {
            Err(LedgerError::AlreadyResolved { obligation, state }) => {
                assert_eq!(obligation, id_d);
                assert_eq!(state, ObligationState::Committed);
            }
            other => panic!("expected AlreadyResolved(Committed), got {other:?}"),
        }
        // Stats unchanged from the commit alone (one committed, no abort).
        let stats_d = ledger.stats();
        assert_eq!(stats_d.total_committed, 1);
        assert_eq!(stats_d.total_aborted, 1, "from branch (b), unchanged here");
        assert_eq!(stats_d.pending, 0);

        // (e) Region finalized: fallible drain callers observe the fence
        // explicitly instead of silently mutating a closed region.
        // mark_region_finalized is intentionally idempotent so this can run
        // after branch (d).
        let token_e = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_e = token_e.id();
        ledger.mark_region_finalized(region);
        match ledger.try_abort_by_id(id_e, Time::from_nanos(60), ObligationAbortReason::Cancel) {
            Err(LedgerError::RegionFinalized {
                region: err_region,
                obligation,
            }) => {
                assert_eq!(err_region, region);
                assert_eq!(obligation, id_e);
            }
            other => panic!("expected RegionFinalized after finalize, got {other:?}"),
        }
        // The pending count for id_e MUST stay >0 — the fence prevented
        // the abort path from running, so the obligation is still
        // outstanding (and the leak detector will flag it on close, which
        // is the documented contract).
        // We discard the token to satisfy the Drop linearity check; any
        // late-arrival drain would now route through the same fence.
        std::mem::drop(token_e);
        assert!(
            ledger.stats().pending >= 1,
            "fence must NOT decrement pending; got {:?}",
            ledger.stats(),
        );
    }

    #[test]
    fn try_abort_by_id_race_matrix_logs_evidence() {
        init_test("try_abort_by_id_race_matrix_logs_evidence");

        const SCENARIO_ID: &str = "TRY-ABORT-BY-ID-RACE-MATRIX-N3GXII";
        const RCH_COMMAND: &str = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_n3gxii_ledger_final cargo test -p asupersync --lib try_abort_by_id_race_matrix_logs_evidence --features test-internals -- --nocapture";

        fn record_state(ledger: &ObligationLedger, id: ObligationId) -> &'static str {
            ledger
                .get(id)
                .map_or("Missing", |record| match record.state {
                    ObligationState::Reserved => "Reserved",
                    ObligationState::Committed => "Committed",
                    ObligationState::Aborted => "Aborted",
                    ObligationState::Leaked => "Leaked",
                })
        }

        fn abort_result(result: &Result<u64, LedgerError>) -> String {
            match result {
                Ok(duration) => format!("Ok({duration})"),
                Err(LedgerError::NotFound { .. }) => "Err(NotFound)".to_string(),
                Err(LedgerError::AlreadyResolved { state, .. }) => {
                    format!("Err(AlreadyResolved::{state:?})")
                }
                Err(LedgerError::RegionFinalized { .. }) => "Err(RegionFinalized)".to_string(),
                Err(other) => format!("Err({other:?})"),
            }
        }

        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let mut rows = Vec::new();
        let mut double_fulfillment_count = 0usize;

        let missing_id = ObligationId::new_for_test(99_999, 9);
        let missing_result = ledger.try_abort_by_id(
            missing_id,
            Time::from_nanos(1),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            missing_result,
            Err(LedgerError::NotFound { obligation }) if obligation == missing_id
        ));
        rows.push(serde_json::json!({
            "case": "missing_id",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{missing_id:?}"),
            "generation": missing_id.arena_index().generation(),
            "race_participant": "drain_abort_without_record",
            "fulfillment_state_before": "Missing",
            "abort_result": abort_result(&missing_result),
            "fulfillment_state_after": record_state(&ledger, missing_id),
        }));

        let token_success = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_success = token_success.id();
        let before_success = record_state(&ledger, id_success);
        let success_result = ledger.try_abort_by_id(
            id_success,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );
        assert_eq!(success_result, Ok(10));
        rows.push(serde_json::json!({
            "case": "reserved_abort_success",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{id_success:?}"),
            "generation": id_success.arena_index().generation(),
            "race_participant": "drain_abort_wins",
            "fulfillment_state_before": before_success,
            "abort_result": abort_result(&success_result),
            "fulfillment_state_after": record_state(&ledger, id_success),
        }));

        let token_commit = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_commit = token_commit.id();
        let _duration = ledger.commit(token_commit, Time::from_nanos(20));
        let before_commit_race = record_state(&ledger, id_commit);
        let committed_result = ledger.try_abort_by_id(
            id_commit,
            Time::from_nanos(30),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            committed_result,
            Err(LedgerError::AlreadyResolved {
                obligation,
                state: ObligationState::Committed,
            }) if obligation == id_commit
        ));
        double_fulfillment_count += 1;
        rows.push(serde_json::json!({
            "case": "concurrent_fulfillment_commit_wins",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{id_commit:?}"),
            "generation": id_commit.arena_index().generation(),
            "race_participant": "token_commit_then_drain_abort",
            "fulfillment_state_before": before_commit_race,
            "abort_result": abort_result(&committed_result),
            "fulfillment_state_after": record_state(&ledger, id_commit),
        }));

        let token_abort = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_abort = token_abort.id();
        let first_abort = ledger.try_abort_by_id(
            id_abort,
            Time::from_nanos(40),
            ObligationAbortReason::Cancel,
        );
        assert_eq!(first_abort, Ok(40));
        let before_double_abort = record_state(&ledger, id_abort);
        let double_abort_result = ledger.try_abort_by_id(
            id_abort,
            Time::from_nanos(50),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            double_abort_result,
            Err(LedgerError::AlreadyResolved {
                obligation,
                state: ObligationState::Aborted,
            }) if obligation == id_abort
        ));
        double_fulfillment_count += 1;
        rows.push(serde_json::json!({
            "case": "concurrent_abort_double_abort_idempotence",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{id_abort:?}"),
            "generation": id_abort.arena_index().generation(),
            "race_participant": "two_drain_aborts_same_id",
            "fulfillment_state_before": before_double_abort,
            "abort_result": abort_result(&double_abort_result),
            "fulfillment_state_after": record_state(&ledger, id_abort),
        }));

        let token_stale = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id_live = token_stale.id();
        let live_index = id_live.arena_index();
        let stale_id = ObligationId::new_for_test(
            live_index.index(),
            live_index.generation().saturating_add(1),
        );
        let stale_result = ledger.try_abort_by_id(
            stale_id,
            Time::from_nanos(60),
            ObligationAbortReason::Cancel,
        );
        assert!(matches!(
            stale_result,
            Err(LedgerError::NotFound { obligation }) if obligation == stale_id
        ));
        rows.push(serde_json::json!({
            "case": "stale_generation_aba_rejected",
            "task_id": format!("{task:?}"),
            "obligation_id": format!("{stale_id:?}"),
            "generation": stale_id.arena_index().generation(),
            "race_participant": "stale_generation_drain_abort",
            "fulfillment_state_before": "Missing",
            "abort_result": abort_result(&stale_result),
            "fulfillment_state_after": record_state(&ledger, stale_id),
            "live_obligation_state_after": record_state(&ledger, id_live),
        }));
        let live_cleanup = ledger.try_abort_by_id(
            id_live,
            Time::from_nanos(70),
            ObligationAbortReason::Explicit,
        );
        assert_eq!(live_cleanup, Ok(70));

        let stats = ledger.stats();
        let leak_count = ledger.check_leaks().leaked.len();
        assert_eq!(
            stats.pending, 0,
            "race matrix must not leak pending obligations"
        );
        assert_eq!(leak_count, 0, "race matrix leak report must be clean");

        let report = serde_json::json!({
            "scenario_id": SCENARIO_ID,
            "task_id": format!("{task:?}"),
            "region_id": format!("{region:?}"),
            "race_matrix": rows,
            "double_fulfillment_count": double_fulfillment_count,
            "stats": {
                "pending": stats.pending,
                "total_committed": stats.total_committed,
                "total_aborted": stats.total_aborted,
                "total_leaked": stats.total_leaked,
            },
            "leak_count": leak_count,
            "exact_rch_command": RCH_COMMAND,
            "artifact_paths": [],
            "final_race_tolerant_verdict": "pass"
        });

        println!("ASUPERSYNC_TRY_ABORT_BY_ID_RACE_MATRIX_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize try_abort_by_id report")
        );
        println!("ASUPERSYNC_TRY_ABORT_BY_ID_RACE_MATRIX_END");

        crate::test_complete!("try_abort_by_id_race_matrix_logs_evidence");
    }

    #[test]
    fn abort_by_id_supports_cancel_drain_without_leak_accounting() {
        init_test("abort_by_id_supports_cancel_drain_without_leak_accounting");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort_by_id(id, Time::from_nanos(25), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state aborted",
            ObligationState::Aborted,
            record.state
        );
        crate::assert_with_log!(
            record.abort_reason == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            record.abort_reason
        );

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::test_complete!("abort_by_id_supports_cancel_drain_without_leak_accounting");
    }

    fn observable_resolution_state(
        ledger: &ObligationLedger,
        id: ObligationId,
    ) -> (
        ObligationId,
        ObligationKind,
        TaskId,
        RegionId,
        Time,
        ObligationState,
        Option<Time>,
        Option<ObligationAbortReason>,
        LedgerStats,
    ) {
        let record = ledger.get(id).expect("record exists");
        (
            record.id,
            record.kind,
            record.holder,
            record.region,
            record.reserved_at,
            record.state,
            record.resolved_at,
            record.abort_reason,
            ledger.stats(),
        )
    }

    #[test]
    fn metamorphic_commit_then_abort_matches_commit_only_terminal_observables() {
        init_test("metamorphic_commit_then_abort_matches_commit_only_terminal_observables");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_token = baseline.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let baseline_id = baseline_token.id();
        baseline.commit(baseline_token, Time::from_nanos(25));
        let expected = observable_resolution_state(&baseline, baseline_id);
        let expected_observation = observe_ledger(&baseline, task, region);

        let mut transformed = ObligationLedger::new();
        let transformed_token =
            transformed.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let transformed_id = transformed_token.id();
        transformed.commit(transformed_token, Time::from_nanos(25));

        for (idx, rejected) in [
            replay_abort_attempt(
                &mut transformed,
                transformed_id,
                Time::from_nanos(26),
                ObligationAbortReason::Cancel,
            ),
            replay_abort_attempt(
                &mut transformed,
                transformed_id,
                Time::from_nanos(30),
                ObligationAbortReason::Explicit,
            ),
            replay_abort_attempt(
                &mut transformed,
                transformed_id,
                Time::from_nanos(40),
                ObligationAbortReason::Error,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit-then-abort rejected", idx, rejected);
        }

        crate::assert_with_log!(
            observable_resolution_state(&transformed, transformed_id) == expected,
            "commit terminal observables preserved",
            expected,
            observable_resolution_state(&transformed, transformed_id)
        );
        crate::assert_with_log!(
            observe_ledger(&transformed, task, region) == expected_observation,
            "commit ledger observation preserved",
            expected_observation,
            observe_ledger(&transformed, task, region)
        );

        crate::test_complete!(
            "metamorphic_commit_then_abort_matches_commit_only_terminal_observables"
        );
    }

    #[test]
    fn metamorphic_double_commit_matches_single_commit_terminal_observables() {
        init_test("metamorphic_double_commit_matches_single_commit_terminal_observables");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_token = baseline.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let baseline_id = baseline_token.id();
        baseline.commit(baseline_token, Time::from_nanos(15));
        let expected = observable_resolution_state(&baseline, baseline_id);
        let expected_observation = observe_ledger(&baseline, task, region);

        let mut transformed = ObligationLedger::new();
        let transformed_token =
            transformed.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let transformed_id = transformed_token.id();
        transformed.commit(transformed_token, Time::from_nanos(15));

        for (idx, rejected) in [
            replay_commit_attempt(
                &mut transformed,
                transformed_id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(16),
            ),
            replay_commit_attempt(
                &mut transformed,
                transformed_id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(25),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "double-commit rejected", idx, rejected);
        }

        crate::assert_with_log!(
            observable_resolution_state(&transformed, transformed_id) == expected,
            "double-commit terminal observables preserved",
            expected,
            observable_resolution_state(&transformed, transformed_id)
        );
        crate::assert_with_log!(
            observe_ledger(&transformed, task, region) == expected_observation,
            "double-commit ledger observation preserved",
            expected_observation,
            observe_ledger(&transformed, task, region)
        );

        crate::test_complete!(
            "metamorphic_double_commit_matches_single_commit_terminal_observables"
        );
    }

    #[test]
    fn metamorphic_abort_then_commit_matches_abort_only_terminal_observables() {
        init_test("metamorphic_abort_then_commit_matches_abort_only_terminal_observables");
        let task = make_task();
        let region = make_region();

        let mut baseline = ObligationLedger::new();
        let baseline_token = baseline.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let baseline_id = baseline_token.id();
        baseline.abort(
            baseline_token,
            Time::from_nanos(35),
            ObligationAbortReason::Explicit,
        );
        let expected = observable_resolution_state(&baseline, baseline_id);
        let expected_observation = observe_ledger(&baseline, task, region);

        let mut transformed = ObligationLedger::new();
        let transformed_token = transformed.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let transformed_id = transformed_token.id();
        transformed.abort(
            transformed_token,
            Time::from_nanos(35),
            ObligationAbortReason::Explicit,
        );

        let rejected = replay_commit_attempt(
            &mut transformed,
            transformed_id,
            ObligationKind::Ack,
            task,
            region,
            Time::from_nanos(36),
        );
        crate::assert_with_log!(rejected, "abort-then-commit rejected", true, rejected);
        crate::assert_with_log!(
            observable_resolution_state(&transformed, transformed_id) == expected,
            "abort terminal observables preserved",
            expected,
            observable_resolution_state(&transformed, transformed_id)
        );
        crate::assert_with_log!(
            observe_ledger(&transformed, task, region) == expected_observation,
            "abort ledger observation preserved",
            expected_observation,
            observe_ledger(&transformed, task, region)
        );

        crate::test_complete!(
            "metamorphic_abort_then_commit_matches_abort_only_terminal_observables"
        );
    }

    #[test]
    fn metamorphic_independent_commit_reordering_preserves_terminal_observables() {
        init_test("metamorphic_independent_commit_reordering_preserves_terminal_observables");
        let task_a = TaskId::from_arena(ArenaIndex::new(10, 0));
        let task_b = TaskId::from_arena(ArenaIndex::new(11, 0));
        let region_a = RegionId::from_arena(ArenaIndex::new(20, 0));
        let region_b = RegionId::from_arena(ArenaIndex::new(21, 0));

        let mut forward = ObligationLedger::new();
        let forward_first = forward.acquire(
            ObligationKind::SendPermit,
            task_a,
            region_a,
            Time::from_nanos(1),
        );
        let forward_second =
            forward.acquire(ObligationKind::Lease, task_b, region_b, Time::from_nanos(2));
        let first_id = forward_first.id();
        let second_id = forward_second.id();
        forward.commit(forward_first, Time::from_nanos(10));
        forward.commit(forward_second, Time::from_nanos(20));
        let forward_first_state = observable_resolution_state(&forward, first_id);
        let forward_second_state = observable_resolution_state(&forward, second_id);
        let forward_region_a = observe_ledger(&forward, task_a, region_a);
        let forward_region_b = observe_ledger(&forward, task_b, region_b);

        let mut reversed = ObligationLedger::new();
        let reversed_first = reversed.acquire(
            ObligationKind::SendPermit,
            task_a,
            region_a,
            Time::from_nanos(1),
        );
        let reversed_second =
            reversed.acquire(ObligationKind::Lease, task_b, region_b, Time::from_nanos(2));
        let reversed_first_id = reversed_first.id();
        let reversed_second_id = reversed_second.id();
        reversed.commit(reversed_second, Time::from_nanos(20));
        reversed.commit(reversed_first, Time::from_nanos(10));

        crate::assert_with_log!(
            reversed_first_id == first_id,
            "first obligation id stable across reorder",
            first_id,
            reversed_first_id
        );
        crate::assert_with_log!(
            reversed_second_id == second_id,
            "second obligation id stable across reorder",
            second_id,
            reversed_second_id
        );
        crate::assert_with_log!(
            observable_resolution_state(&reversed, reversed_first_id) == forward_first_state,
            "first independent obligation preserved",
            forward_first_state,
            observable_resolution_state(&reversed, reversed_first_id)
        );
        crate::assert_with_log!(
            observable_resolution_state(&reversed, reversed_second_id) == forward_second_state,
            "second independent obligation preserved",
            forward_second_state,
            observable_resolution_state(&reversed, reversed_second_id)
        );
        crate::assert_with_log!(
            observe_ledger(&reversed, task_a, region_a) == forward_region_a,
            "region A observables preserved",
            forward_region_a,
            observe_ledger(&reversed, task_a, region_a)
        );
        crate::assert_with_log!(
            observe_ledger(&reversed, task_b, region_b) == forward_region_b,
            "region B observables preserved",
            forward_region_b,
            observe_ledger(&reversed, task_b, region_b)
        );

        crate::test_complete!(
            "metamorphic_independent_commit_reordering_preserves_terminal_observables"
        );
    }

    #[test]
    fn commit_once_and_replayed_commit_attempts_preserve_observable_state() {
        init_test("commit_once_and_replayed_commit_attempts_preserve_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.commit(token, Time::from_nanos(25));
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(26),
            Time::from_nanos(40),
            Time::from_nanos(100),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.commit(
                    ObligationToken {
                        id,
                        kind: ObligationKind::Lease,
                        holder: task,
                        region,
                    },
                    now,
                );
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "replayed commit rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "observable state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("commit_once_and_replayed_commit_attempts_preserve_observable_state");
    }

    #[test]
    fn abort_once_and_replayed_abort_attempts_preserve_observable_state() {
        init_test("abort_once_and_replayed_abort_attempts_preserve_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort(token, Time::from_nanos(25), ObligationAbortReason::Explicit);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(26),
            Time::from_nanos(40),
            Time::from_nanos(100),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.abort_by_id(id, now, ObligationAbortReason::Cancel);
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "replayed abort rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "observable state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("abort_once_and_replayed_abort_attempts_preserve_observable_state");
    }

    #[test]
    fn abort_after_commit_replay_preserves_committed_observable_state() {
        init_test("abort_after_commit_replay_preserves_committed_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.commit(token, Time::from_nanos(50));
        crate::assert_with_log!(duration == 50, "duration", 50, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(51),
            Time::from_nanos(60),
            Time::from_nanos(75),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.abort_by_id(id, now, ObligationAbortReason::Cancel);
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "abort after commit rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "committed state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("abort_after_commit_replay_preserves_committed_observable_state");
    }

    fn replay_commit_attempt(
        ledger: &mut ObligationLedger,
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.commit(
                ObligationToken {
                    id,
                    kind,
                    holder,
                    region,
                },
                now,
            );
        }))
        .is_err()
    }

    fn replay_abort_attempt(
        ledger: &mut ObligationLedger,
        id: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(id, now, reason);
        }))
        .is_err()
    }

    #[test]
    fn metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables() {
        init_test(
            "metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables",
        );
        let task = make_task();
        let region = make_region();

        let mut commit_then_abort = ObligationLedger::new();
        let token = commit_then_abort.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();
        commit_then_abort.commit(token, Time::from_nanos(10));
        let committed_expected = observable_resolution_state(&commit_then_abort, id);
        for (idx, rejected) in [
            replay_commit_attempt(
                &mut commit_then_abort,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(11),
            ),
            replay_abort_attempt(
                &mut commit_then_abort,
                id,
                Time::from_nanos(12),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut commit_then_abort,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(13),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit-first replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&commit_then_abort, id) == committed_expected,
                "commit-first observable state preserved",
                committed_expected,
                observable_resolution_state(&commit_then_abort, id)
            );
        }

        let mut abort_then_commit = ObligationLedger::new();
        let token = abort_then_commit.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();
        abort_then_commit.commit(token, Time::from_nanos(10));
        for (idx, rejected) in [
            replay_abort_attempt(
                &mut abort_then_commit,
                id,
                Time::from_nanos(11),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut abort_then_commit,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(12),
            ),
            replay_abort_attempt(
                &mut abort_then_commit,
                id,
                Time::from_nanos(13),
                ObligationAbortReason::Explicit,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "abort-first replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&abort_then_commit, id) == committed_expected,
                "abort-first observable state preserved",
                committed_expected,
                observable_resolution_state(&abort_then_commit, id)
            );
        }

        crate::assert_with_log!(
            observable_resolution_state(&commit_then_abort, id)
                == observable_resolution_state(&abort_then_commit, id),
            "committed replay schedules converge",
            observable_resolution_state(&commit_then_abort, id),
            observable_resolution_state(&abort_then_commit, id)
        );

        let mut abort_only_then_commit = ObligationLedger::new();
        let token = abort_only_then_commit.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();
        abort_only_then_commit.abort(token, Time::from_nanos(20), ObligationAbortReason::Explicit);
        let aborted_expected = observable_resolution_state(&abort_only_then_commit, id);
        for (idx, rejected) in [
            replay_abort_attempt(
                &mut abort_only_then_commit,
                id,
                Time::from_nanos(21),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut abort_only_then_commit,
                id,
                ObligationKind::Ack,
                task,
                region,
                Time::from_nanos(22),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "abort terminal replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&abort_only_then_commit, id) == aborted_expected,
                "abort terminal state preserved",
                aborted_expected,
                observable_resolution_state(&abort_only_then_commit, id)
            );
        }

        let mut commit_only_then_abort = ObligationLedger::new();
        let token = commit_only_then_abort.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();
        commit_only_then_abort.abort(token, Time::from_nanos(20), ObligationAbortReason::Explicit);
        for (idx, rejected) in [
            replay_commit_attempt(
                &mut commit_only_then_abort,
                id,
                ObligationKind::Ack,
                task,
                region,
                Time::from_nanos(21),
            ),
            replay_abort_attempt(
                &mut commit_only_then_abort,
                id,
                Time::from_nanos(22),
                ObligationAbortReason::Error,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit terminal replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&commit_only_then_abort, id) == aborted_expected,
                "commit terminal state preserved",
                aborted_expected,
                observable_resolution_state(&commit_only_then_abort, id)
            );
        }

        crate::assert_with_log!(
            observable_resolution_state(&abort_only_then_commit, id)
                == observable_resolution_state(&commit_only_then_abort, id),
            "aborted replay schedules converge",
            observable_resolution_state(&abort_only_then_commit, id),
            observable_resolution_state(&commit_only_then_abort, id)
        );

        crate::test_complete!(
            "metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables"
        );
    }

    // =========================================================================
    // Wave 55 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn ledger_stats_debug_clone_copy_eq_default() {
        let stats = LedgerStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("LedgerStats"), "{dbg}");
        let copied = stats;
        let cloned = stats;
        assert_eq!(copied, cloned);
        assert_eq!(stats.total_acquired, 0);
        assert!(stats.is_clean());
    }

    #[test]
    fn leak_check_result_debug_clone() {
        let result = LeakCheckResult { leaked: vec![] };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("LeakCheckResult"), "{dbg}");
        let cloned = result;
        assert!(cloned.is_clean());
    }

    // =========================================================================
    // Conservation-of-acquired metamorphic relation
    //
    // For any sequence of ledger operations, the invariant
    //
    //     total_acquired == total_committed + total_aborted + total_leaked + pending
    //
    // must hold. This catches off-by-one and miscategorization bugs across
    // acquire / commit / abort / abort_by_id / mark_leaked / reset paths
    // without needing an oracle for the expected pending count after a
    // mixed-operation sequence.
    // =========================================================================

    #[track_caller]
    fn assert_conservation(ledger: &ObligationLedger, step: &str) {
        let s = ledger.stats();
        let rhs = s.total_committed + s.total_aborted + s.total_leaked + s.pending;
        assert_eq!(
            s.total_acquired, rhs,
            "conservation violated after {step}: \
             acquired={} vs committed({})+aborted({})+leaked({})+pending({}) = {}",
            s.total_acquired, s.total_committed, s.total_aborted, s.total_leaked, s.pending, rhs,
        );
    }

    #[test]
    fn metamorphic_conservation_of_acquired_across_mixed_operations() {
        init_test("metamorphic_conservation_of_acquired_across_mixed_operations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        assert_conservation(&ledger, "initial");

        // ---- Pre-reset phase: exercise all token-consuming + by-id paths ----

        let t1 = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(1),
        );
        assert_conservation(&ledger, "acquire t1");

        let t2 = ledger.acquire_with_context(
            ObligationKind::Ack,
            task,
            region,
            Time::from_nanos(2),
            SourceLocation::unknown(),
            None,
            Some("ctx".to_string()),
        );
        assert_conservation(&ledger, "acquire_with_context t2");

        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(3));
        assert_conservation(&ledger, "acquire t3");

        let t3_id = t3.id();
        let pre_reset_acquired = ledger.stats().total_acquired;
        assert_eq!(pre_reset_acquired, 3);

        ledger.commit(t1, Time::from_nanos(10));
        assert_conservation(&ledger, "commit t1");

        ledger.abort(t2, Time::from_nanos(11), ObligationAbortReason::Cancel);
        assert_conservation(&ledger, "abort t2");

        // By-id resolution after original token has been dropped.
        drop(t3);
        ledger.abort_by_id(t3_id, Time::from_nanos(12), ObligationAbortReason::Explicit);
        assert_conservation(&ledger, "abort_by_id t3");

        let pre_reset = ledger.stats();
        assert_eq!(pre_reset.pending, 0);
        assert!(pre_reset.is_clean());
        assert_eq!(
            pre_reset.total_acquired,
            pre_reset.total_committed + pre_reset.total_aborted + pre_reset.total_leaked,
            "fully-resolved ledger satisfies conservation trivially with pending=0",
        );

        // ---- Reset midstream: counters zero, conservation holds trivially ----

        ledger.reset();
        assert_conservation(&ledger, "reset");
        let post_reset = ledger.stats();
        assert_eq!(post_reset, LedgerStats::default());

        // ---- Post-reset phase: re-acquire, include mark_leaked path ----

        let t4 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        assert_conservation(&ledger, "post-reset acquire t4");

        let t5 = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(1));
        assert_conservation(&ledger, "post-reset acquire t5");

        ledger.commit(t4, Time::from_nanos(5));
        assert_conservation(&ledger, "post-reset commit t4");

        let t5_id = t5.id();
        drop(t5);
        ledger.mark_leaked(t5_id, Time::from_nanos(6));
        assert_conservation(&ledger, "mark_leaked t5");

        let final_stats = ledger.stats();
        assert_eq!(final_stats.total_acquired, 2);
        assert_eq!(final_stats.total_committed, 1);
        assert_eq!(final_stats.total_aborted, 0);
        assert_eq!(final_stats.total_leaked, 1);
        assert_eq!(final_stats.pending, 0);
        assert!(
            !final_stats.is_clean(),
            "leaked obligation keeps ledger dirty"
        );
        assert_eq!(ledger.check_leaks().leaked.len(), 1);

        crate::test_complete!("metamorphic_conservation_of_acquired_across_mixed_operations");
    }

    // --- Metamorphic: conservation-of-acquired ------------------------------
    //
    // MR (conservation / flow invariant):
    //   stats.total_acquired
    //     == stats.total_committed
    //      + stats.total_aborted
    //      + stats.total_leaked
    //      + stats.pending
    //
    // Every acquired obligation is in exactly one of four terminal buckets —
    // committed, aborted, leaked, or still pending — so the sum of those
    // four counters must equal the running total of acquisitions at every
    // observable point. reset() zeros all five fields simultaneously, so
    // the equation stays 0 == 0 across the epoch boundary and can be driven
    // to hold again in the new epoch.
    //
    // Bug classes caught:
    //   * miscounted acquire/commit/abort/abort_by_id/mark_leaked paths
    //     (off-by-one, skipped increment, double increment)
    //   * mis-routing between terminal buckets (e.g. mark_leaked bumping
    //     total_aborted instead of total_leaked)
    //   * pending not decremented on a resolution path
    //   * reset() leaving one of the five fields non-zero
    //
    // Independence: orthogonal to region-partition, permutation-invariance,
    // and reset-generation MRs already in this module — those check
    // geometric or temporal relations, this one checks flow conservation.
    #[test]
    fn metamorphic_conservation_acquired_equals_resolved_plus_pending() {
        init_test("metamorphic_conservation_acquired_equals_resolved_plus_pending");
        let task = make_task();
        let region = make_region();

        fn check_conservation(ledger: &ObligationLedger, step: &str) {
            let s = ledger.stats();
            let resolved_plus_pending = s
                .total_committed
                .saturating_add(s.total_aborted)
                .saturating_add(s.total_leaked)
                .saturating_add(s.pending);
            assert_eq!(
                s.total_acquired,
                resolved_plus_pending,
                "conservation violated at {step}: \
                 total_acquired={} vs committed+aborted+leaked+pending={} \
                 (committed={}, aborted={}, leaked={}, pending={})",
                s.total_acquired,
                resolved_plus_pending,
                s.total_committed,
                s.total_aborted,
                s.total_leaked,
                s.pending
            );
        }

        let mut ledger = ObligationLedger::new();
        check_conservation(&ledger, "empty");

        // Phase 1: staggered acquisitions — conservation must hold after each.
        let mut live_tokens: Vec<ObligationToken> = Vec::new();
        for i in 0..6 {
            let kind = match i % 3 {
                0 => ObligationKind::SendPermit,
                1 => ObligationKind::Ack,
                _ => ObligationKind::Lease,
            };
            let tok = ledger.acquire(kind, task, region, Time::from_nanos(10 + i));
            live_tokens.push(tok);
            check_conservation(&ledger, "phase1.acquire");
        }
        assert_eq!(ledger.stats().total_acquired, 6);
        assert_eq!(ledger.stats().pending, 6);

        // Phase 2: mixed terminal resolutions across all four paths —
        // commit via token, abort via token, abort_by_id via id,
        // and mark_leaked via id. Conservation must hold after each.
        let tok_commit = live_tokens.remove(0);
        ledger.commit(tok_commit, Time::from_nanos(100));
        check_conservation(&ledger, "phase2.commit");

        let tok_abort = live_tokens.remove(0);
        ledger.abort(
            tok_abort,
            Time::from_nanos(110),
            ObligationAbortReason::Cancel,
        );
        check_conservation(&ledger, "phase2.abort");

        let tok_abort_by_id = live_tokens.remove(0);
        let id_for_abort_by_id = tok_abort_by_id.id();
        // Drop the token so only the ID path resolves the obligation.
        drop(tok_abort_by_id);
        ledger.abort_by_id(
            id_for_abort_by_id,
            Time::from_nanos(120),
            ObligationAbortReason::Error,
        );
        check_conservation(&ledger, "phase2.abort_by_id");

        let tok_leak = live_tokens.remove(0);
        let id_for_leak = tok_leak.id();
        drop(tok_leak);
        ledger.mark_leaked(id_for_leak, Time::from_nanos(130));
        check_conservation(&ledger, "phase2.mark_leaked");

        // Two obligations remain pending — conservation must still balance.
        assert_eq!(ledger.stats().pending, 2);
        assert_eq!(ledger.stats().total_committed, 1);
        assert_eq!(ledger.stats().total_aborted, 2);
        assert_eq!(ledger.stats().total_leaked, 1);

        let tok_pending_commit = live_tokens.remove(0);
        ledger.commit(tok_pending_commit, Time::from_nanos(140));
        check_conservation(&ledger, "phase2.resolve_pending_commit");

        let tok_pending_abort = live_tokens.remove(0);
        ledger.abort(
            tok_pending_abort,
            Time::from_nanos(150),
            ObligationAbortReason::Explicit,
        );
        check_conservation(&ledger, "phase2.resolve_pending_abort");
        assert!(live_tokens.is_empty());
        assert_eq!(ledger.stats().pending, 0);

        // Phase 3: reset requires a clean ledger, then zeros all five counters
        // simultaneously. The ledger above intentionally exercised the leaked
        // bucket, so keep that ledger as leak-conservation evidence and use a
        // clean fully resolved ledger for the reset contract.
        assert!(!ledger.stats().is_clean());

        let mut reset_ledger = ObligationLedger::new();
        let reset_commit = reset_ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(160),
        );
        let reset_abort =
            reset_ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(170));
        reset_ledger.commit(reset_commit, Time::from_nanos(180));
        reset_ledger.abort(
            reset_abort,
            Time::from_nanos(190),
            ObligationAbortReason::Explicit,
        );
        check_conservation(&reset_ledger, "phase3.clean_pre_reset");
        assert!(reset_ledger.stats().is_clean());

        reset_ledger.reset();
        check_conservation(&reset_ledger, "phase3.reset");
        assert_eq!(reset_ledger.stats().total_acquired, 0);
        assert!(reset_ledger.stats().is_clean());

        // Phase 4: re-acquire after reset and resolve one to confirm the
        // invariant tracks across the epoch boundary (the token held across
        // reset has been invalidated by the generation bump; any attempt to
        // commit it would panic — see metamorphic_post_reset_* tests).
        let post_reset = reset_ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(200),
        );
        check_conservation(&reset_ledger, "phase4.post_reset_acquire");
        reset_ledger.commit(post_reset, Time::from_nanos(210));
        check_conservation(&reset_ledger, "phase4.post_reset_commit");
        assert_eq!(reset_ledger.stats().total_acquired, 1);
        assert_eq!(reset_ledger.stats().total_committed, 1);
        assert_eq!(reset_ledger.stats().pending, 0);

        crate::test_complete!("metamorphic_conservation_acquired_equals_resolved_plus_pending");
    }

    /// br-asupersync-qyf37e: try_commit on a token whose region has
    /// been marked finalized must return Err(LedgerError::RegionFinalized).
    /// This pins the public surface that Drop impls / detached
    /// handlers should use when racing region close.
    #[test]
    fn qyf37e_try_commit_after_region_finalized_returns_err() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );

        // Mark the owning region finalized — the structured-concurrency
        // finalize phase has completed and the obligation should not
        // be allowed to transition.
        ledger.mark_region_finalized(region);
        assert!(ledger.is_region_finalized(region));

        let obligation_id = token.id();
        let err = ledger
            .try_commit(token, Time::from_nanos(100))
            .expect_err("late commit must be rejected after region finalize");

        match err {
            LedgerError::RegionFinalized {
                region: r,
                obligation: o,
            } => {
                assert_eq!(r, region);
                assert_eq!(o, obligation_id);
            }
            other => panic!("expected RegionFinalized, got {other:?}"),
        }

        // The obligation record is still pending (we did not mutate it).
        assert_eq!(ledger.stats().pending, 1);
        assert_eq!(ledger.stats().total_committed, 0);
    }

    /// br-asupersync-qyf37e: same shape for try_abort.
    #[test]
    fn qyf37e_try_abort_after_region_finalized_returns_err() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
        ledger.mark_region_finalized(region);

        let err = ledger
            .try_abort(token, Time::from_nanos(100), ObligationAbortReason::Cancel)
            .expect_err("late abort must be rejected after region finalize");

        match err {
            LedgerError::RegionFinalized { .. } => {}
            other => panic!("expected RegionFinalized, got {other:?}"),
        }
        assert_eq!(ledger.stats().pending, 1);
        assert_eq!(ledger.stats().total_aborted, 0);
    }

    /// br-asupersync-qyf37e: try_commit on a NOT-finalized region
    /// passes through to commit and returns the duration.
    #[test]
    fn qyf37e_try_commit_before_region_finalized_succeeds() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
        let duration = ledger
            .try_commit(token, Time::from_nanos(100))
            .expect("commit before finalize must succeed");
        assert_eq!(duration, 100);
        assert_eq!(ledger.stats().total_committed, 1);
        assert_eq!(ledger.stats().pending, 0);
    }

    // ================================================================
    // br-asupersync-12cqs2 — acquire_with_context fence
    // ================================================================

    /// br-asupersync-12cqs2: try_acquire on a finalized region must
    /// return Err(LedgerError::RegionFinalized) WITHOUT minting a
    /// token, incrementing stats, or otherwise mutating the ledger.
    #[test]
    fn b12cqs2_try_acquire_after_region_finalized_returns_err() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));

        ledger.mark_region_finalized(region);
        assert!(ledger.is_region_finalized(region));

        let stats_before = ledger.stats();
        let err = ledger
            .try_acquire(
                ObligationKind::SendPermit,
                task,
                region,
                Time::from_nanos(0),
            )
            .expect_err("acquire on finalized region must be rejected");

        match err {
            LedgerError::RegionFinalized { region: r, .. } => assert_eq!(r, region),
            other => panic!("expected RegionFinalized, got {other:?}"),
        }

        // No mutation: stats unchanged.
        let stats_after = ledger.stats();
        assert_eq!(stats_after.total_acquired, stats_before.total_acquired);
        assert_eq!(stats_after.pending, stats_before.pending);
    }

    /// br-asupersync-12cqs2: try_acquire on a NOT-finalized region
    /// behaves like the infallible acquire (mints a token).
    #[test]
    fn b12cqs2_try_acquire_before_finalize_succeeds() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));

        let token = ledger
            .try_acquire(ObligationKind::Lease, task, region, Time::from_nanos(0))
            .expect("acquire before finalize must succeed");
        assert_eq!(token.kind(), ObligationKind::Lease);
        assert_eq!(ledger.stats().pending, 1);
    }

    /// br-asupersync-12cqs2: the infallible `acquire` PANICS when
    /// called on a finalized region. This pins the contract that
    /// late-arrival callers MUST use try_acquire instead.
    #[test]
    #[should_panic(expected = "br-asupersync-12cqs2")]
    fn b12cqs2_infallible_acquire_after_finalize_panics() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        ledger.mark_region_finalized(region);
        let _ = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
    }

    // ================================================================
    // br-asupersync-u1gcfp — commit/abort fence (silent bail)
    // ================================================================

    /// br-asupersync-u1gcfp: infallible `commit` on a token whose
    /// region was finalized after token mint MUST bail silently
    /// (return 0, no mutation). This protects Drop impls that call
    /// `ledger.commit` unconditionally from mutating the ledger past
    /// region finalize.
    #[test]
    fn b_u1gcfp_commit_after_finalize_bails_silently() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(0),
        );
        let stats_after_acquire = ledger.stats();
        assert_eq!(stats_after_acquire.pending, 1);

        ledger.mark_region_finalized(region);

        let duration = ledger.commit(token, Time::from_nanos(100));
        assert_eq!(duration, 0, "commit on finalized region must return 0");

        // No mutation: stats are unchanged from the post-acquire snapshot.
        let stats_after_commit = ledger.stats();
        assert_eq!(stats_after_commit.total_committed, 0);
        assert_eq!(stats_after_commit.pending, stats_after_acquire.pending);
    }

    /// br-asupersync-u1gcfp: same fail-closed contract for abort.
    #[test]
    fn b_u1gcfp_abort_after_finalize_bails_silently() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(0));
        ledger.mark_region_finalized(region);

        let duration = ledger.abort(token, Time::from_nanos(50), ObligationAbortReason::Cancel);
        assert_eq!(duration, 0, "abort on finalized region must return 0");

        let stats = ledger.stats();
        assert_eq!(stats.total_aborted, 0);
        assert_eq!(stats.pending, 1);
    }

    /// br-asupersync-u1gcfp: same fail-closed contract for abort_by_id.
    #[test]
    fn b_u1gcfp_abort_by_id_after_finalize_bails_silently() {
        let mut ledger = ObligationLedger::new();
        let region = make_region();
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(0));
        let id = token.id();
        ledger.mark_region_finalized(region);

        let duration = ledger.abort_by_id(id, Time::from_nanos(50), ObligationAbortReason::Cancel);
        assert_eq!(duration, 0, "abort_by_id on finalized region must return 0");

        assert_eq!(ledger.stats().total_aborted, 0);
        assert_eq!(ledger.stats().pending, 1);
    }

    /// A bounded ledger drops its oldest committed and aborted records and
    /// keeps counting every obligation (br-asupersync-rrtgoy).
    #[test]
    fn bounded_ledger_drops_the_oldest_resolved_records() {
        init_test("bounded_ledger_drops_the_oldest_resolved_records");
        let mut ledger = ObligationLedger::with_resolved_retention(4);
        let task = make_task();
        let region = make_region();
        let mut ids = Vec::new();
        for i in 0..10_u64 {
            let token = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(i));
            ids.push(token.id());
            if i % 2 == 0 {
                ledger.commit(token, Time::from_nanos(i));
            } else {
                ledger.abort(token, Time::from_nanos(i), ObligationAbortReason::Cancel);
            }
        }
        assert_eq!(
            ledger.len(),
            4,
            "the retention's worth of resolved records stays"
        );
        assert!(ledger.get(ids[5]).is_none(), "older records are dropped");
        assert_eq!(
            ledger.obligation_state(ids[6]),
            Some(ObligationState::Committed)
        );
        assert_eq!(
            ledger.obligation_state(ids[9]),
            Some(ObligationState::Aborted)
        );
        let stats = ledger.stats();
        assert_eq!(
            (
                stats.total_acquired,
                stats.total_committed,
                stats.total_aborted,
                stats.pending
            ),
            (10, 5, 5, 0)
        );
        assert_eq!(ledger.counts().total(), 4);
        crate::test_complete!("bounded_ledger_drops_the_oldest_resolved_records");
    }

    /// Pending and leaked records stay in a bounded ledger whatever its
    /// retention; a region drain still finds the pending ones.
    #[test]
    fn bounded_ledger_keeps_pending_and_leaked_records() {
        init_test("bounded_ledger_keeps_pending_and_leaked_records");
        let mut ledger = ObligationLedger::with_resolved_retention(0);
        let task = make_task();
        let region = make_region();
        let pending = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let pending_id = pending.id();
        let leaked = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let leaked_id = leaked.id();
        let committed = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let committed_id = committed.id();
        ledger.commit(committed, Time::from_nanos(1));
        ledger.mark_leaked(leaked_id, Time::from_nanos(2));
        assert!(
            ledger.get(committed_id).is_none(),
            "a zero retention drops a commit at once"
        );
        assert_eq!(
            ledger.obligation_state(leaked_id),
            Some(ObligationState::Leaked)
        );
        assert_eq!(
            ledger.obligation_state(pending_id),
            Some(ObligationState::Reserved)
        );
        let drained = ledger.abort_pending_for_region(
            region,
            Time::from_nanos(3),
            ObligationAbortReason::Cancel,
        );
        assert_eq!(drained.aborted, 1, "the drain finds the pending record");
        assert!(ledger.get(pending_id).is_none());
        assert_eq!(ledger.len(), 1, "only the leaked record remains");
        crate::test_complete!("bounded_ledger_keeps_pending_and_leaked_records");
    }

    /// A bounded ledger moves to the next generation when its index space is
    /// exhausted; a ledger from new() still reports IndexOverflow.
    #[test]
    fn bounded_ledger_moves_to_the_next_generation_when_its_index_space_runs_out() {
        init_test("bounded_ledger_moves_to_the_next_generation_when_its_index_space_runs_out");
        let task = make_task();
        let region = make_region();
        let mut bounded = ObligationLedger::with_resolved_retention(8);
        bounded.next_index = u32::MAX;
        let token = bounded.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let idx = token.id().arena_index();
        assert_eq!((idx.index(), idx.generation()), (0, 1));
        bounded.commit(token, Time::from_nanos(1));

        let mut unbounded = ObligationLedger::new();
        unbounded.next_index = u32::MAX;
        assert!(matches!(
            unbounded.try_acquire(ObligationKind::Ack, task, region, Time::ZERO),
            Err(LedgerError::IndexOverflow { generation: 0 })
        ));
        crate::test_complete!(
            "bounded_ledger_moves_to_the_next_generation_when_its_index_space_runs_out"
        );
    }

    /// rrtgoy L1: `try_commit` and `try_abort` returned `Ok(commit(..))` and
    /// `Ok(abort(..))`, so the fallible API panicked where those do: a commit
    /// after a region drain aborted the obligation, a duplicate token, a token
    /// that does not match its record. They return the error now, and the
    /// ledger is left as it was.
    #[test]
    fn try_commit_and_try_abort_return_resolution_errors_instead_of_panicking() {
        init_test("try_commit_and_try_abort_return_resolution_errors_instead_of_panicking");
        let task = make_task();
        let region = make_region();
        let mut ledger = ObligationLedger::new();

        // A drain aborts the obligation while its holder still has the token.
        let drained = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let drained_id = drained.id();
        ledger.abort_by_id(
            drained_id,
            Time::from_nanos(1),
            ObligationAbortReason::Cancel,
        );
        let stats = ledger.stats();
        match ledger.try_commit(drained, Time::from_nanos(2)) {
            Err(LedgerError::NotPending { obligation, state }) => {
                assert_eq!(obligation, drained_id);
                assert_eq!(state, ObligationState::Aborted);
            }
            other => panic!("a commit after the drain must be refused, got {other:?}"),
        }
        assert_eq!(ledger.stats(), stats, "a refused commit changes nothing");

        // A duplicate of a committed token.
        let committed = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let duplicate = ObligationToken {
            id: committed.id(),
            kind: committed.kind,
            holder: committed.holder,
            region: committed.region,
        };
        ledger.commit(committed, Time::from_nanos(3));
        let stats = ledger.stats();
        match ledger.try_abort(
            duplicate,
            Time::from_nanos(4),
            ObligationAbortReason::Cancel,
        ) {
            Err(LedgerError::NotPending { state, .. }) => {
                assert_eq!(state, ObligationState::Committed);
            }
            other => panic!("an abort of a committed obligation must be refused, got {other:?}"),
        }
        assert_eq!(ledger.stats(), stats, "a refused abort changes nothing");

        // A token whose holder does not match its record, and an unknown id.
        let pending = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let pending_id = pending.id();
        let forged = ObligationToken {
            id: pending_id,
            kind: pending.kind,
            holder: TaskId::from_arena(ArenaIndex::new(9, 0)),
            region: pending.region,
        };
        let unknown = ObligationToken {
            id: ObligationId::from_arena(ArenaIndex::new(77, 0)),
            kind: pending.kind,
            holder: pending.holder,
            region: pending.region,
        };
        let stats = ledger.stats();
        assert!(matches!(
            ledger.try_commit(forged, Time::from_nanos(5)),
            Err(LedgerError::TokenMismatch {
                field: "holder",
                ..
            })
        ));
        assert!(matches!(
            ledger.try_abort(unknown, Time::from_nanos(5), ObligationAbortReason::Cancel),
            Err(LedgerError::NotFound { .. })
        ));
        assert_eq!(ledger.stats(), stats, "refused calls change nothing");
        assert_eq!(
            ledger.obligation_state(pending_id),
            Some(ObligationState::Reserved)
        );
        assert!(ledger.try_commit(pending, Time::from_nanos(6)).is_ok());
        assert!(ledger.stats().is_clean());
        crate::test_complete!(
            "try_commit_and_try_abort_return_resolution_errors_instead_of_panicking"
        );
    }
