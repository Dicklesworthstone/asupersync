    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{Budget, Outcome, RegionId, Time};

    #[inline]
    fn make_task_record(owner: RegionId) -> TaskRecord {
        // Use a provisional TaskId (0,0); insert_task canonicalizes it.
        let provisional_id = TaskId::from_arena(ArenaIndex::new(0, 0));
        TaskRecord::new(provisional_id, owner, Budget::INFINITE)
    }

    fn live_phase_sum(table: &TaskTable) -> usize {
        (0..LIVE_PHASE_COUNT)
            .map(|i| table.count_in_phase(TaskPhase::from_u8(i as u8).unwrap()))
            .sum()
    }

    #[test]
    fn shutdown_retires_all_tasks_despite_destructor_and_join_waker_panics() {
        use crate::runtime::task_handle::RetirementBarrier;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Retired(Arc<AtomicUsize>, bool);
        impl Drop for Retired {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                assert!(!self.1, "injected task destructor panic");
            }
        }
        struct Joined(Arc<AtomicUsize>, Arc<AtomicUsize>, bool);
        impl std::task::Wake for Joined {
            fn wake(self: Arc<Self>) {
                assert_eq!(
                    self.0.load(Ordering::SeqCst),
                    2,
                    "all futures retire before publication"
                );
                self.1.fetch_add(1, Ordering::SeqCst);
                assert!(!self.2, "injected join waker panic");
            }
        }
        let retired = Arc::new(AtomicUsize::new(0));
        let joined = Arc::new(AtomicUsize::new(0));
        let mut table = TaskTable::new();
        let mut barriers = Vec::new();
        for hostile in [true, false] {
            let owner = RegionId::testing_default();
            let mut record = make_task_record(owner);
            let barrier = RetirementBarrier::pending();
            let mut inner = crate::types::CxInner::new(owner, record.id, Budget::INFINITE);
            inner.retirement_barrier = Some(Arc::clone(&barrier));
            record.cx_inner = Some(Arc::new(parking_lot::RwLock::new(inner)));
            let task = TaskId::from_arena(table.insert_task(record));
            let guard = Retired(Arc::clone(&retired), hostile);
            table.store_spawned_task(
                task,
                StoredTask::new_with_id(
                    async move {
                        let _guard = guard;
                        std::future::pending::<()>().await;
                        Outcome::Ok(())
                    },
                    task,
                ),
            );
            let waker = std::task::Waker::from(Arc::new(Joined(
                Arc::clone(&retired),
                Arc::clone(&joined),
                hostile,
            )));
            assert!(!barrier.register_and_is_open(&waker));
            barriers.push(barrier);
        }
        drop(table);
        assert_eq!(retired.load(Ordering::SeqCst), 2);
        assert_eq!(joined.load(Ordering::SeqCst), 2);
        assert!(barriers.iter().all(|barrier| barrier.is_open()));
    }

    #[test]
    fn insert_and_get_task() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let record = make_task_record(owner);

        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        let retrieved = table.task(task_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner, owner);
    }

    #[test]
    fn remove_task() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let record = make_task_record(owner);

        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        assert!(table.task(task_id).is_some());
        let removed = table.remove_task(task_id);
        assert!(removed.is_some());
        assert!(table.task(task_id).is_none());
    }

    #[test]
    fn live_task_count() {
        let mut table = TaskTable::new();
        assert_eq!(table.live_task_count(), 0);

        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let idx1 = table.insert_task(make_task_record(owner));
        let _idx2 = table.insert_task(make_task_record(owner));

        assert_eq!(table.live_task_count(), 2);

        table.remove_task(TaskId::from_arena(idx1));
        assert_eq!(table.live_task_count(), 1);
    }

    #[test]
    fn live_task_count_scalar_tracks_phase_bucket_sum() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let idx1 = table.insert_task(make_task_record(owner));
        let idx2 = table.insert_task(make_task_record(owner));
        let task1 = TaskId::from_arena(idx1);
        let task2 = TaskId::from_arena(idx2);
        assert_eq!(table.live_task_count(), live_phase_sum(&table));

        table.update_task(task1, |record| {
            record.start_running();
        });
        assert_eq!(table.live_task_count(), live_phase_sum(&table));

        table.update_task(task1, |record| {
            record.complete(Outcome::Ok(()));
        });
        assert_eq!(table.live_task_count(), live_phase_sum(&table));

        table.remove_task(task2);
        assert_eq!(table.live_task_count(), live_phase_sum(&table));
        assert_eq!(table.live_task_count(), 0);
    }

    #[test]
    fn live_phase_accessors_survive_direct_record_phase_mutation() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let idx = table.insert_task(make_task_record(owner));
        let task = TaskId::from_arena(idx);

        table
            .task_mut(task)
            .expect("task should exist")
            .start_running();

        assert_eq!(table.live_task_count(), 1);
        assert_eq!(table.count_in_phase(TaskPhase::Created), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Running), 1);

        table.remove_task(task);
        assert_eq!(table.live_task_count(), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Created), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Running), 0);
    }

    /// The live count is a counter rather than a scan (br-asupersync-bzict6).
    /// It must still agree with the records on every path that changes them:
    /// each insert path, direct record mutation, `update_task`, removal,
    /// recycling, and reuse of a recycled record.
    #[test]
    fn live_task_count_agrees_with_the_records_on_every_path() {
        fn scanned(table: &TaskTable) -> usize {
            table
                .iter()
                .filter(|(_, record)| !record.phase.load().is_terminal())
                .count()
        }
        fn check(table: &TaskTable, expected: usize, step: &str) {
            assert_eq!(table.live_task_count(), expected, "{step}");
            assert_eq!(scanned(table), expected, "{step}: scan");
        }
        let mut table = TaskTable::with_capacity_and_pool_limit(8, 8);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let a = TaskId::from_arena(table.insert_task(make_task_record(owner)));
        let b = TaskId::from_arena(table.insert_task_with(|_| make_task_record(owner)));
        let c = TaskId::from_arena(table.insert_pooled_task_with(|_, record| record.owner = owner));
        check(&table, 3, "three insert paths");

        let record = table.task_mut(a).expect("a");
        record.start_running();
        check(&table, 3, "running is live");
        table.task_mut(a).expect("a").complete(Outcome::Ok(()));
        check(&table, 2, "direct completion");
        table.update_task(b, |record| {
            record.start_running();
            record.complete(Outcome::Ok(()));
        });
        check(&table, 1, "completion through update_task");

        table.remove_and_recycle_task(c);
        check(&table, 0, "live record removed and recycled");
        let d = TaskId::from_arena(table.insert_pooled_task_with(|_, record| record.owner = owner));
        check(&table, 1, "recycled record reused");
        table.remove_task(a);
        check(&table, 1, "terminal record removed");

        let mut removed = table.remove_task(d).expect("d");
        check(&table, 0, "live record removed");
        removed.start_running();
        drop(removed);
        check(&table, 0, "a removed record no longer counts");
    }

    #[test]
    fn store_and_remove_stored_future() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let idx = table.insert_task(make_task_record(RegionId::from_arena(ArenaIndex::new(
            1, 0,
        ))));
        let task_id = TaskId::from_arena(idx);

        let stored = StoredTask::new(async { Outcome::Ok(()) });
        table.store_spawned_task(task_id, stored);

        assert_eq!(table.stored_future_count(), 1);
        assert!(table.get_stored_future(task_id).is_some());

        let removed = table.remove_stored_future(task_id);
        assert!(removed.is_some());
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(task_id).is_none());
    }

    #[test]
    fn remove_task_cleans_stored_future() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let idx = table.insert_task(make_task_record(RegionId::from_arena(ArenaIndex::new(
            1, 0,
        ))));
        let task_id = TaskId::from_arena(idx);

        table.store_spawned_task(task_id, StoredTask::new(async { Outcome::Ok(()) }));
        assert_eq!(table.stored_future_count(), 1);

        let removed = table.remove_task(task_id);
        assert!(removed.is_some());
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(task_id).is_none());
    }

    #[test]
    fn remove_by_index_cleans_stored_future_even_with_stale_record_id() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        // Model a caller inserting a provisional/stale id.
        let stale = TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            owner,
            Budget::INFINITE,
        );
        let idx = table.insert_task(stale);
        let canonical_id = TaskId::from_arena(idx);

        table.store_spawned_task(canonical_id, StoredTask::new(async { Outcome::Ok(()) }));
        assert_eq!(table.stored_future_count(), 1);

        let removed = table.remove(idx);
        assert!(removed.is_some());
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(canonical_id).is_none());
    }

    #[test]
    fn insert_task_canonicalizes_record_id() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let stale = TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            owner,
            Budget::INFINITE,
        );
        let idx = table.insert_task(stale);

        let canonical_id = TaskId::from_arena(idx);
        let record = table.task(canonical_id).expect("task should exist");
        assert_eq!(record.id, canonical_id);
    }

    #[test]
    fn insert_task_with_canonicalizes_record_id() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let idx = table.insert_task_with(|_idx| {
            // Intentionally stale provisional id to verify table-side canonicalization.
            TaskRecord::new(
                TaskId::from_arena(ArenaIndex::new(0, 0)),
                owner,
                Budget::INFINITE,
            )
        });

        let canonical_id = TaskId::from_arena(idx);
        let record = table.task(canonical_id).expect("task should exist");
        assert_eq!(record.id, canonical_id);
    }

    #[test]
    fn insert_task_with_tracks_deadline_without_cx() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let deadline = crate::types::Time::from_nanos(1_000);
        let budget = Budget::INFINITE.with_deadline(deadline);

        let idx = table.insert_task_with(|_idx| {
            TaskRecord::new(TaskId::from_arena(ArenaIndex::new(0, 0)), owner, budget)
        });

        let canonical_id = TaskId::from_arena(idx);
        let record = table.task(canonical_id).expect("task should exist");
        assert_eq!(record.deadline, Some(deadline));
        assert_eq!(table.tasks_with_deadline_count(), 1);
        assert_eq!(table.deadline_sum_ns(), u128::from(deadline.as_nanos()));
    }

    #[test]
    fn store_spawned_task_ignores_unknown_task_id() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let unknown = TaskId::from_arena(ArenaIndex::new(4242, 0));
        table.store_spawned_task(unknown, StoredTask::new(async { Outcome::Ok(()) }));

        assert_eq!(table.live_task_count(), 0);
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(unknown).is_none());
    }

    #[test]
    fn pooled_insert_clears_stale_metadata_before_reuse() {
        let mut table = TaskTable::with_capacity(256);
        let owner_a = RegionId::from_arena(ArenaIndex::new(1, 0));
        let owner_b = RegionId::from_arena(ArenaIndex::new(2, 0));

        let idx = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner_a,
                Budget::new()
                    .with_poll_quota(7)
                    .with_deadline(Time::from_nanos(99)),
                Time::from_nanos(5),
            );
        });
        let task_id = TaskId::from_arena(idx);

        let cancel_effects = {
            let record = table.task_mut(task_id).expect("pooled task exists");
            let cancel_effects = record.request_cancel(crate::types::CancelReason::timeout());
            record
                .waiters
                .push(TaskId::from_arena(ArenaIndex::new(88, 0)));
            record.cached_waker = Some((std::task::Waker::noop().clone(), 3));
            record.cached_cancel_waker = Some((std::task::Waker::noop().clone(), 4));
            record.pin_to_worker(7);
            record.queue_tag = 9;
            record.heap_index = Some(11);
            record.sched_priority = 5;
            record.sched_generation = 44;
            record.total_polls = 12;
            record.last_polled_step = 77;
            cancel_effects
        };
        let (_newly_cancelled, cancel_wakes) = cancel_effects.into_parts();
        cancel_wakes.dispatch();

        table.remove_and_recycle_task(task_id);
        assert_eq!(table.recycled_task_record_count(), 1);

        let reused_idx = table.insert_pooled_task_with(|_idx, record| {
            record.owner = owner_b;
            record.created_at = Time::from_nanos(123);
            record.polls_remaining = 5;
        });
        let reused_id = TaskId::from_arena(reused_idx);
        let reused = table.task(reused_id).expect("reused pooled task exists");

        assert_eq!(table.recycled_task_record_count(), 0);
        assert_eq!(reused.id, reused_id);
        assert_eq!(reused.owner, owner_b);
        assert!(matches!(
            &reused.state,
            crate::record::task::TaskState::Created
        ));
        assert_eq!(reused.phase(), TaskPhase::Created);
        assert_eq!(reused.deadline, None);
        assert_eq!(reused.waiters.len(), 0);
        assert!(reused.cached_waker.is_none());
        assert!(reused.cached_cancel_waker.is_none());
        assert_eq!(reused.cancel_epoch, 0);
        assert!(!reused.is_local());
        assert!(reused.pinned_worker.is_none());
        assert_eq!(reused.queue_tag, 0);
        assert_eq!(reused.heap_index, None);
        assert_eq!(reused.sched_priority, 0);
        assert_eq!(reused.sched_generation, 0);
        assert_eq!(reused.total_polls, 0);
        assert_eq!(reused.last_polled_step, 0);
    }

    #[test]
    fn pooled_insert_tracks_deadline_without_cx() {
        let mut table = TaskTable::with_capacity(256);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let deadline = Time::from_nanos(1_234);

        let idx = table.insert_pooled_task_with(|_idx, record| {
            record.owner = owner;
            record.deadline = Some(deadline);
            record.polls_remaining = 1;
            record.created_at = Time::from_nanos(7);
        });

        let task_id = TaskId::from_arena(idx);
        let record = table.task(task_id).expect("pooled task exists");
        assert_eq!(record.deadline, Some(deadline));
        assert_eq!(table.tasks_with_deadline_count(), 1);
        assert_eq!(table.deadline_sum_ns(), u128::from(deadline.as_nanos()));
    }

    #[test]
    fn remove_and_recycle_task_double_return_is_noop() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let idx = table.insert_task(make_task_record(owner));
        let task_id = TaskId::from_arena(idx);

        table.remove_and_recycle_task(task_id);
        table.remove_and_recycle_task(task_id);

        assert_eq!(table.recycled_task_record_count(), 1);
        assert!(table.task(task_id).is_none());
        assert_eq!(table.live_task_count(), 0);
    }

    #[test]
    fn insert_pooled_task_with_field_mutation_reuses_recycled_wake_state() {
        // br-asupersync-j1e7zy regression: the production spawn paths in
        // src/cx/scope.rs and src/runtime/state.rs use field-by-field
        // mutation inside `insert_pooled_task_with` so the recycled
        // record's `wake_state` Arc (allocated by `Recyclable::reset`
        // when the prior task was recycled) is reused instead of being
        // dropped+replaced.  Verify that pattern preserves Arc identity
        // across recycle+reinsert.
        use std::sync::Arc;

        let mut table = TaskTable::with_capacity(64);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        // Pool miss: first insert fabricates a fresh record via the
        // miss-path fallback inside `insert_pooled_task_with`.
        let idx1 = table.insert_pooled_task_with(|idx, record| {
            record.id = TaskId::from_arena(idx);
            record.owner = owner;
            record.created_at = Time::from_nanos(1);
            record.deadline = None;
            record.polls_remaining = 1;
        });
        let id1 = TaskId::from_arena(idx1);

        // Recycle: `Recyclable::reset` runs before the record is
        // returned to the pool, allocating a new wake_state Arc on the
        // recycled record.  That Arc is what we want the *next* spawn to
        // reuse.
        table.remove_and_recycle_task(id1);
        assert_eq!(table.recycled_task_record_count(), 1);

        // Pool hit: the field-mutation factory should leave wake_state
        // untouched, so the new record carries the post-reset Arc rather
        // than a freshly-allocated one.  We assert this by checking that
        // strong_count == 1 (only the table holds it) and that no
        // foreign Arc reference can sneak in via the factory path.
        let idx2 = table.insert_pooled_task_with(|idx, record| {
            record.id = TaskId::from_arena(idx);
            record.owner = owner;
            record.created_at = Time::from_nanos(2);
            record.deadline = None;
            record.polls_remaining = 1;
        });
        let id2 = TaskId::from_arena(idx2);

        let stats = table.task_record_pool_stats();
        assert_eq!(stats.hits, 1, "second insert should be a pool hit");
        assert_eq!(stats.misses, 1, "first insert should be the only miss");

        let record = table.task(id2).expect("pooled task is live");
        assert_eq!(
            Arc::strong_count(&record.wake_state),
            1,
            "field-mutation factory must not introduce extra wake_state references",
        );
        assert_eq!(record.id, id2);
        assert_eq!(record.owner, owner);
        assert_eq!(record.created_at, Time::from_nanos(2));
        assert_eq!(record.polls_remaining, 1);
        assert!(
            !record.is_local(),
            "field-mutation factory must not leave stale local pinning",
        );
    }

    #[test]
    fn task_record_pool_saturates_at_capacity_hint_bound() {
        let capacity = 4096usize;
        let expected_pool_cap = (capacity / 4).clamp(64, 512);
        let mut table = TaskTable::with_capacity(capacity);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        for _ in 0..(expected_pool_cap + 128) {
            let idx = table.insert_task(make_task_record(owner));
            table.remove_and_recycle_task(TaskId::from_arena(idx));
        }

        assert_eq!(table.recycled_task_record_count(), expected_pool_cap);
    }

    #[test]
    fn task_record_pool_disabled_mode_forces_heap_fallback() {
        let mut table = TaskTable::with_capacity_and_pool_limit(256, 0);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        assert!(!table.task_record_pool_enabled());
        assert_eq!(table.task_record_pool_capacity(), 0);

        let idx_a = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(3),
                Time::from_nanos(11),
            );
        });
        let first_id = TaskId::from_arena(idx_a);
        table.remove_and_recycle_task(first_id);

        let idx_b = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(5),
                Time::from_nanos(22),
            );
        });
        let second_id = TaskId::from_arena(idx_b);

        assert!(table.task(first_id).is_none());
        assert!(table.task(second_id).is_some());
        assert_eq!(table.recycled_task_record_count(), 0);

        let stats = table.task_record_pool_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.recycled, 0);
        assert_eq!(stats.recycle_drops, 1);
    }

    #[test]
    fn pooled_recycle_rejects_stale_task_id_after_slot_reuse() {
        let mut table = TaskTable::with_capacity_and_pool_limit(1, 1);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let first_idx = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(1),
                Time::from_nanos(7),
            );
        });
        let first_id = TaskId::from_arena(first_idx);
        table.remove_and_recycle_task(first_id);

        let second_idx = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(2),
                Time::from_nanos(8),
            );
        });
        let second_id = TaskId::from_arena(second_idx);

        assert_ne!(first_id, second_id);
        assert!(table.task(first_id).is_none());
        assert!(table.task(second_id).is_some());

        let stats = table.task_record_pool_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.recycled, 1);
        assert_eq!(stats.recycle_drops, 0);
    }

    // === Lock Ordering Conformance Tests ===

    mod conformance_lock_ordering {
        use super::*;
        use crate::observability::metrics::NoOpMetrics;
        use crate::runtime::{ShardGuard, ShardedState};
        use crate::trace::TraceBufferHandle;
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        fn test_config() -> crate::runtime::ShardedConfig {
            crate::runtime::ShardedConfig {
                io_driver: None,
                timer_driver: None,
                logical_clock_mode: crate::trace::distributed::LogicalClockMode::Lamport,
                cancel_attribution: crate::types::CancelAttributionConfig::default(),
                entropy_source: Arc::new(crate::util::entropy::DetEntropy::new(0)),
                blocking_pool: None,
                obligation_leak_response: crate::runtime::config::ObligationLeakResponse::Panic,
                leak_escalation: None,
                observability: None,
            }
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_task_table_operations_preserve_lock_order() {
            // Test 1: Verify task table operations through ShardGuard maintain lock ordering
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = ShardedState::new(trace, metrics, test_config());

            // Test single shard operations (Tasks only)
            {
                let mut guard = ShardGuard::tasks_only(&shards);
                let tasks = guard.tasks.as_mut().unwrap();

                // Basic insert/lookup operations
                let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
                let record = make_task_record(owner);
                let idx = tasks.insert_task(record);
                let task_id = TaskId::from_arena(idx);

                assert!(tasks.task(task_id).is_some());
                let removed = tasks.remove_task(task_id);
                assert!(removed.is_some());
            }

            // Verify lock order is properly tracked during multi-shard operations
            #[cfg(debug_assertions)]
            {
                use crate::runtime::sharded_state::lock_order;

                assert_eq!(
                    lock_order::held_count(),
                    0,
                    "No locks should be held after guard drop"
                );

                // Test proper ordering B→A→C (Regions→Tasks→Obligations)
                let guard = ShardGuard::for_task_completed(&shards);
                assert_eq!(lock_order::held_count(), 3);
                assert_eq!(
                    lock_order::held_labels(),
                    vec!["B:Regions", "A:Tasks", "C:Obligations"]
                );
                drop(guard);
                assert_eq!(lock_order::held_count(), 0);
            }
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_concurrent_task_operations_no_lock_order_violations() {
            // Test 2: Concurrent task table operations should not cause lock order violations
            use std::sync::Barrier;

            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = Arc::new(ShardedState::new(trace, metrics, test_config()));
            let barrier = Arc::new(Barrier::new(4));

            let handles: Vec<_> = (0..4)
                .map(|thread_id| {
                    let shards = Arc::clone(&shards);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();

                        // Each thread performs different operations using proper guards
                        for i in 0..50 {
                            match thread_id % 4 {
                                0 => {
                                    // Tasks-only operations (hotpath polling)
                                    let mut guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_mut().unwrap();
                                    let owner = RegionId::from_arena(ArenaIndex::new(
                                        thread_id as u32 + 1,
                                        0,
                                    ));
                                    let record = make_task_record(owner);
                                    let idx = tasks.insert_task(record);
                                    if i % 10 == 9 {
                                        // Occasionally remove task
                                        let task_id = TaskId::from_arena(idx);
                                        let _ = tasks.remove_task(task_id);
                                    }
                                }
                                1 => {
                                    // Spawn operations (B→A)
                                    let mut guard = ShardGuard::for_spawn(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        let owner = RegionId::from_arena(ArenaIndex::new(
                                            thread_id as u32 + 1,
                                            0,
                                        ));
                                        let record = make_task_record(owner);
                                        let _ = tasks.insert_task(record);
                                    }
                                }
                                2 => {
                                    // Task completion operations (B→A→C)
                                    let mut guard = ShardGuard::for_task_completed(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        let owner = RegionId::from_arena(ArenaIndex::new(
                                            thread_id as u32 + 1,
                                            0,
                                        ));
                                        let record = make_task_record(owner);
                                        let idx = tasks.insert_task(record);
                                        let task_id = TaskId::from_arena(idx);
                                        let _ = tasks.remove_task(task_id);
                                    }
                                }
                                3 => {
                                    // Cancel operations (B→A→C)
                                    let mut guard = ShardGuard::for_cancel(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        // Lookup operations to simulate cancel processing
                                        let task_id =
                                            TaskId::from_arena(ArenaIndex::new(i % 100, 0));
                                        let _ = tasks.task(task_id);
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle
                    .join()
                    .expect("Thread should not panic - no lock order violations");
            }
        }

        #[test]
        fn test_task_table_reallocation_safety() {
            // Test 3: Table growth and shrinking should be safe under concurrent access
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = Arc::new(ShardedState::new(trace, metrics, test_config()));
            let barrier = Arc::new(Barrier::new(3));

            let handles: Vec<_> = (0..3)
                .map(|thread_id| {
                    let shards = Arc::clone(&shards);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();

                        match thread_id {
                            0 => {
                                // Growth thread: rapid task insertions
                                for i in 0..200 {
                                    let mut guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_mut().unwrap();
                                    let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
                                    let record = make_task_record(owner);
                                    let _idx = tasks.insert_task(record);

                                    // Verify table remains consistent during growth
                                    assert!(tasks.live_task_count() > 0);

                                    if i % 50 == 0 {
                                        // Brief pause to allow other threads to interleave
                                        thread::sleep(Duration::from_micros(1));
                                    }
                                }
                            }
                            1 => {
                                // Shrinking thread: task removals
                                thread::sleep(Duration::from_millis(1)); // Let growth start first

                                for i in 0..150 {
                                    let mut guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_mut().unwrap();

                                    // Find a task to remove (iterate through possible indices)
                                    for idx_val in 0..200 {
                                        let task_id =
                                            TaskId::from_arena(ArenaIndex::new(idx_val, 0));
                                        if tasks.remove_task(task_id).is_some() {
                                            break; // Successfully removed one
                                        }
                                    }

                                    if i % 50 == 0 {
                                        thread::sleep(Duration::from_micros(1));
                                    }
                                }
                            }
                            2 => {
                                // Reader thread: continuous lookups during reallocation
                                for i in 0..300 {
                                    let guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_ref().unwrap();

                                    // Try to lookup various task IDs
                                    for idx_val in (i * 10)..((i + 1) * 10) {
                                        let task_id =
                                            TaskId::from_arena(ArenaIndex::new(idx_val % 200, 0));
                                        let _ = tasks.task(task_id); // May or may not exist
                                    }

                                    // Verify table integrity during concurrent access
                                    assert!(
                                        tasks.live_task_count() < 1000,
                                        "Table growth should be reasonable"
                                    );

                                    if i % 30 == 0 {
                                        thread::sleep(Duration::from_micros(1));
                                    }
                                }
                            }
                            _ => unreachable!(),
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle
                    .join()
                    .expect("Reallocation safety test should not panic");
            }

            // Final verification: table should be in a consistent state
            let guard = ShardGuard::tasks_only(&shards);
            let tasks = guard.tasks.as_ref().unwrap();
            let final_count = tasks.live_task_count();

            // We can't predict exact count due to race conditions, but it should be reasonable
            assert!(final_count < 300, "Final task count should be bounded");

            // Verify no stored futures are orphaned
            assert!(
                tasks.stored_future_count() <= tasks.live_task_count(),
                "Stored futures should not exceed live tasks"
            );
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "lock order violation")]
        fn test_lock_order_violation_detection() {
            // Test 4: Verify that incorrect lock ordering is detected and panics
            use crate::runtime::sharded_state::LockShard;
            use crate::runtime::sharded_state::lock_order;

            // Simulate acquiring locks in wrong order (Tasks before Regions)
            // This should panic in debug builds due to lock order violation
            lock_order::before_lock(LockShard::Tasks);
            lock_order::after_lock(LockShard::Tasks);

            // This should panic: trying to acquire Regions after Tasks violates B→A ordering
            lock_order::before_lock(LockShard::Regions);
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_proper_lock_order_sequences() {
            // Test 5: Verify that correct lock ordering sequences work properly
            use crate::runtime::sharded_state::LockShard;
            use crate::runtime::sharded_state::lock_order;

            // Test valid sequence: B→A→C (Regions→Tasks→Obligations)
            lock_order::before_lock(LockShard::Regions);
            lock_order::after_lock(LockShard::Regions);
            lock_order::before_lock(LockShard::Tasks);
            lock_order::after_lock(LockShard::Tasks);
            lock_order::before_lock(LockShard::Obligations);
            lock_order::after_lock(LockShard::Obligations);

            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );

            // Clean up for next test
            lock_order::unlock_n(3);
            assert_eq!(lock_order::held_count(), 0);

            // Test partial sequence: B→C (skip A)
            lock_order::before_lock(LockShard::Regions);
            lock_order::after_lock(LockShard::Regions);
            lock_order::before_lock(LockShard::Obligations);
            lock_order::after_lock(LockShard::Obligations);

            assert_eq!(lock_order::held_count(), 2);
            lock_order::unlock_n(2);
        }

        #[test]
        fn test_task_table_arena_operations_thread_safety() {
            // Test 6: Arena operations should be thread-safe under proper locking
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = Arc::new(ShardedState::new(trace, metrics, test_config()));
            let barrier = Arc::new(Barrier::new(4));

            // Track task IDs created across threads for verification
            let created_tasks = Arc::new(std::sync::Mutex::new(Vec::new()));

            let handles: Vec<_> = (0..4)
                .map(|thread_id| {
                    let shards = Arc::clone(&shards);
                    let barrier = Arc::clone(&barrier);
                    let created_tasks = Arc::clone(&created_tasks);

                    thread::spawn(move || {
                        barrier.wait();

                        let mut local_tasks = Vec::new();

                        // Create tasks
                        for _i in 0..25 {
                            let mut guard = ShardGuard::for_spawn(&shards);
                            let tasks = guard.tasks.as_mut().unwrap();

                            let owner =
                                RegionId::from_arena(ArenaIndex::new(thread_id as u32 + 1, 0));
                            let record = make_task_record(owner);
                            let idx = tasks.insert_task(record);
                            let task_id = TaskId::from_arena(idx);

                            // Verify task was inserted correctly
                            assert!(tasks.task(task_id).is_some());
                            assert_eq!(tasks.task(task_id).unwrap().owner, owner);

                            local_tasks.push(task_id);
                        }

                        // Store in shared list for final verification
                        {
                            let mut global_tasks = created_tasks
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            global_tasks.extend(local_tasks.iter());
                        }

                        // Verify tasks can be looked up
                        for &task_id in &local_tasks {
                            let guard = ShardGuard::tasks_only(&shards);
                            let tasks = guard.tasks.as_ref().unwrap();
                            assert!(tasks.task(task_id).is_some(), "Task should still exist");
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle
                    .join()
                    .expect("Arena operations should be thread-safe");
            }

            // Final verification: all created tasks should be accessible
            let final_guard = ShardGuard::tasks_only(&shards);
            let final_tasks = final_guard.tasks.as_ref().unwrap();

            let created_task_list = created_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                created_task_list.len(),
                100,
                "Should have created 100 tasks total"
            );

            for &task_id in created_task_list.iter() {
                assert!(
                    final_tasks.task(task_id).is_some(),
                    "Task {:?} should be accessible in final state",
                    task_id
                );
            }

            assert_eq!(final_tasks.live_task_count(), 100);
        }
    }

    #[test]
    fn incremental_counters_track_all_mutations() {
        use crate::record::task::{TaskPhase, TaskRecord};
        use crate::types::{Budget, RegionId, TaskId, Time};

        let mut table = TaskTable::new();
        let region = RegionId::new_for_test(1, 1);
        let budget = crate::types::Budget::INFINITE.with_deadline(Time::from_nanos(1000));

        // 1. Initial state
        assert_eq!(table.live_task_count(), 0);
        assert_eq!(table.deadline_sum_ns(), 0);

        // 2. Add task
        let dummy_id = TaskId::new_for_test(1, 1);
        let task1 = TaskRecord::new_with_time(dummy_id, region, budget, Time::ZERO);
        let idx1 = table.insert(task1);
        let id1 = TaskId::from_arena(idx1);

        assert_eq!(table.live_task_count(), 1);
        assert_eq!(table.count_in_phase(TaskPhase::Created), 1);
        assert_eq!(table.deadline_sum_ns(), 1000);

        // 3. Transition phase
        table.update_task(id1, |t| {
            t.start_running();
        });
        assert_eq!(table.count_in_phase(TaskPhase::Created), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Running), 1);
        assert_eq!(table.live_task_count(), 1);

        // 4. Change deadline
        table.update_task(id1, |t| {
            t.deadline = Some(Time::from_nanos(2000));
        });
        assert_eq!(table.deadline_sum_ns(), 2000);

        // 5. Add second task
        let dummy_id2 = TaskId::new_for_test(2, 2);
        let task2 = TaskRecord::new_with_time(dummy_id2, region, Budget::INFINITE, Time::ZERO);
        let idx2 = table.insert(task2);
        assert_eq!(table.live_task_count(), 2);
        assert_eq!(table.deadline_sum_ns(), 2000); // Infinite budget doesn't add to sum

        // ...

        // 7. Remove task
        table.remove(idx2);
        assert_eq!(table.live_task_count(), 1);
    }

    #[test]
    fn removing_completed_task_does_not_double_subtract_deadline() {
        use crate::record::task::TaskRecord;
        use crate::types::{Budget, Outcome, RegionId, TaskId, Time};

        let mut table = TaskTable::new();
        let region = RegionId::new_for_test(1, 1);

        // Two live tasks with deadlines 1000 and 2000.
        let b1 = Budget::INFINITE.with_deadline(Time::from_nanos(1000));
        let b2 = Budget::INFINITE.with_deadline(Time::from_nanos(2000));
        let idx1 = table.insert(TaskRecord::new_with_time(
            TaskId::new_for_test(1, 1),
            region,
            b1,
            Time::ZERO,
        ));
        let _idx2 = table.insert(TaskRecord::new_with_time(
            TaskId::new_for_test(2, 2),
            region,
            b2,
            Time::ZERO,
        ));
        let id1 = TaskId::from_arena(idx1);
        assert_eq!(table.tasks_with_deadline_count(), 2);
        assert_eq!(table.deadline_sum_ns(), 3000);

        // Complete task1: the live→terminal transition removes its deadline
        // from the sum via note_deadline_changed.
        table.update_task(id1, |t| {
            t.complete(Outcome::Ok(()));
        });
        assert_eq!(table.tasks_with_deadline_count(), 1);
        assert_eq!(table.deadline_sum_ns(), 2000);

        // Reaping the completed task must NOT subtract its deadline a second
        // time — task2's deadline is still live. Pre-fix, this drove the count
        // to 0 and the sum to 1000, corrupting the governor's deadline signal.
        table.remove(idx1);
        assert_eq!(
            table.tasks_with_deadline_count(),
            1,
            "task2's live deadline must survive reaping the completed task"
        );
        assert_eq!(table.deadline_sum_ns(), 2000);
    }
