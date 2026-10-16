    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::Outcome;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn retirement_intervals_preserve_live_gaps_and_merge_out_of_order() {
        let mut retired = RetiredLocalStoreKeys::new();
        for key in [8, 4, 6, 2, 7, 3] {
            assert!(retired.insert(key));
        }
        assert_eq!(retired.0, BTreeMap::from([(2, 4), (6, 8)]));
        for key in [0, 1, 5, 9, usize::MAX] {
            assert!(!retired.contains(key), "live key {key} must survive");
        }
        for key in [2, 3, 4, 6, 7, 8] {
            assert!(retired.contains(key));
            assert!(!retired.insert(key), "duplicate retirement {key}");
        }
        assert!(retired.insert(5));
        assert_eq!(retired.0, BTreeMap::from([(2, 8)]));
        assert!(retired.insert(usize::MAX));
        assert!(retired.insert(usize::MAX - 1));
        assert!(!retired.insert(usize::MAX));
        assert!(retired.contains(usize::MAX));
        assert!(!retired.contains(usize::MAX - 2));
        assert_eq!(
            retired.0,
            BTreeMap::from([(2, 8), (usize::MAX - 1, usize::MAX)])
        );
    }

    #[test]
    fn retirement_history_survives_more_than_the_old_key_cap() {
        let mut retired = RetiredLocalStoreKeys::new();
        assert!(retired.insert(2));
        for key in 4..=10_000 {
            assert!(retired.insert(key));
        }
        assert!(retired.contains(2), "the oldest retirement must survive");
        assert!(!retired.contains(1), "an older live runtime must survive");
        assert!(
            !retired.contains(3),
            "a live runtime between ranges survives"
        );
        assert_eq!(retired.0, BTreeMap::from([(2, 2), (4, 10_000)]));
    }

    #[test]
    fn local_store_key_exhaustion_never_wraps_or_reuses_a_key() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let next = AtomicUsize::new(usize::MAX - 1);
        assert_eq!(allocate_local_store_key_from(&next), usize::MAX - 1);
        for _ in 0..2 {
            let exhausted = std::panic::catch_unwind(|| allocate_local_store_key_from(&next));
            assert!(exhausted.is_err(), "exhaustion must fail closed each time");
            assert_eq!(next.load(Ordering::Relaxed), usize::MAX);
        }
    }

    /// asupersync-1fyc8f: keys are process-unique and never reused.
    #[test]
    fn allocated_local_store_keys_are_unique_and_never_zero() {
        init_test("allocated_local_store_keys_are_unique_and_never_zero");
        let first = allocate_local_store_key();
        let second = allocate_local_store_key();
        assert_ne!(first, 0, "zero is the default store");
        assert!(
            second > first,
            "keys grow monotonically: {first} then {second}"
        );
        let from_other_thread = std::thread::spawn(allocate_local_store_key)
            .join()
            .expect("allocator thread");
        assert!(from_other_thread > second, "one process-wide sequence");
    }

    /// asupersync-1fyc8f: a retirement published by any thread drops the
    /// store (and the tasks parked in it) on every thread's next local-store
    /// operation, including threads that currently use the default store.
    #[test]
    fn retired_store_is_purged_on_next_touch_from_any_thread() {
        init_test("retired_store_is_purged_on_next_touch_from_any_thread");
        let key = allocate_local_store_key();
        let task_id = TaskId::new_for_test(42_777, 0);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel::<&'static str>();
        struct DropSignal(std::sync::mpsc::Sender<&'static str>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                let _ = self.0.send("parked task dropped");
            }
        }

        let (stored_tx, stored_rx) = std::sync::mpsc::channel::<usize>();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel::<()>();
        let (after_tx, after_rx) = std::sync::mpsc::channel::<usize>();
        let holder = std::thread::spawn(move || {
            {
                let _key = ScopedLocalStoreKey::new(key);
                let signal = DropSignal(dropped_tx);
                store_local_task(
                    task_id,
                    LocalStoredTask::new(async move {
                        let _signal = signal;
                        std::future::pending::<()>().await;
                        Outcome::Ok(())
                    }),
                );
                stored_tx
                    .send(keyed_local_store_count())
                    .expect("report store count");
            }
            retired_rx.recv().expect("wait for the retirement");
            // Default store selected (no key installed): the touch still
            // observes the retirement.
            let _ = local_task_count();
            after_tx
                .send(keyed_local_store_count())
                .expect("report store count after purge");
        });

        assert_eq!(stored_rx.recv().expect("stored"), 1);
        publish_retired_local_store_key(key);
        retired_tx.send(()).expect("release the holder");
        assert_eq!(after_rx.recv().expect("after"), 0, "retired store purged");
        assert_eq!(
            dropped_rx.recv().expect("drop signal"),
            "parked task dropped",
            "the parked task is dropped with its store"
        );
        holder.join().expect("holder thread");
    }

    /// A task stored under a key that was retired after this thread's last
    /// purge (a concurrent shutdown) is dropped at once; the retired store is
    /// not revived, where no later purge would find it.
    #[test]
    fn storing_under_a_retired_key_drops_the_task_and_revives_no_store() {
        init_test("storing_under_a_retired_key_drops_the_task_and_revives_no_store");
        let key = allocate_local_store_key();
        publish_retired_local_store_key(key);
        let _ = local_task_count();
        let before = keyed_local_store_count();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let flag = DropFlag(std::sync::Arc::clone(&dropped));
        {
            let _key = ScopedLocalStoreKey::new(key);
            store_local_task(
                TaskId::new_for_test(42_778, 0),
                LocalStoredTask::new(async move {
                    let _flag = flag;
                    std::future::pending::<()>().await;
                    Outcome::Ok(())
                }),
            );
        }
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the task stored under a retired key is dropped"
        );
        assert_eq!(keyed_local_store_count(), before, "no store revived");
    }

    #[test]
    fn duplicate_store_replaces_entry_without_panicking() {
        init_test("duplicate_store_replaces_entry_without_panicking");

        let task_id = TaskId::new_for_test(42_424, 0);
        let _ = remove_local_task(task_id);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));

        assert_eq!(local_task_count(), baseline + 1);
        assert!(remove_local_task(task_id).is_some());
        assert_eq!(local_task_count(), baseline);
    }

    /// Invariant: store + remove cycle leaves count unchanged.
    #[test]
    fn store_remove_cycle() {
        init_test("store_remove_cycle");

        let task_id = TaskId::new_for_test(42_425, 0);
        let _ = remove_local_task(task_id);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        crate::assert_with_log!(
            local_task_count() == baseline + 1,
            "count after store",
            baseline + 1,
            local_task_count()
        );

        let removed = remove_local_task(task_id);
        crate::assert_with_log!(removed.is_some(), "removed exists", true, removed.is_some());
        crate::assert_with_log!(
            local_task_count() == baseline,
            "count after remove",
            baseline,
            local_task_count()
        );
        crate::test_complete!("store_remove_cycle");
    }

    /// Invariant: removing a non-existent task returns None.
    #[test]
    fn remove_nonexistent_returns_none() {
        init_test("remove_nonexistent_returns_none");

        let task_id = TaskId::new_for_test(99_999, 0);
        // Ensure it doesn't exist
        let _ = remove_local_task(task_id);

        let result = remove_local_task(task_id);
        crate::assert_with_log!(
            result.is_none(),
            "nonexistent returns None",
            true,
            result.is_none()
        );
        crate::test_complete!("remove_nonexistent_returns_none");
    }

    #[test]
    fn cross_generation_slot_reuse_panics_and_preserves_existing_task() {
        init_test("cross_generation_slot_reuse_panics_and_preserves_existing_task");

        let task_id = TaskId::new_for_test(42_426, 0);
        let reused_slot = TaskId::new_for_test(42_426, 1);
        let _ = remove_local_task(task_id);
        let _ = remove_local_task(reused_slot);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store_local_task(reused_slot, LocalStoredTask::new(async { Outcome::Ok(()) }));
        }));
        let reused_missing = remove_local_task(reused_slot).is_none();
        let original_preserved = remove_local_task(task_id).is_some();

        crate::assert_with_log!(
            panic.is_err(),
            "cross-generation insert panics",
            true,
            panic.is_err()
        );
        crate::assert_with_log!(
            reused_missing,
            "new generation was not inserted",
            true,
            reused_missing
        );
        crate::assert_with_log!(
            original_preserved,
            "original task preserved",
            true,
            original_preserved
        );
        crate::assert_with_log!(
            local_task_count() == baseline,
            "count restored after cleanup",
            baseline,
            local_task_count()
        );
        crate::test_complete!("cross_generation_slot_reuse_panics_and_preserves_existing_task");
    }

    #[test]
    fn metamorphic_local_task_store_is_thread_affine() {
        init_test("metamorphic_local_task_store_is_thread_affine");

        let task_id = TaskId::new_for_test(42_427, 0);
        let _ = remove_local_task(task_id);
        let main_baseline = local_task_count();
        let (stored_tx, stored_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let thread_baseline = local_task_count();
            let thread_missing_before_store = remove_local_task(task_id).is_none();

            store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));

            stored_tx
                .send((
                    thread_baseline,
                    thread_missing_before_store,
                    local_task_count(),
                ))
                .expect("send thread-local store state");

            release_rx.recv().expect("wait for main thread checks");

            let thread_removed = remove_local_task(task_id).is_some();
            (thread_removed, local_task_count(), thread_baseline)
        });

        let (thread_baseline, thread_missing_before_store, thread_after_store_count) =
            stored_rx.recv().expect("receive thread-local store state");

        crate::assert_with_log!(
            thread_missing_before_store,
            "new worker starts without task",
            true,
            thread_missing_before_store
        );
        crate::assert_with_log!(
            thread_after_store_count == thread_baseline + 1,
            "worker-local count increments independently",
            thread_baseline + 1,
            thread_after_store_count
        );

        let main_missing_while_worker_holds_task = remove_local_task(task_id).is_none();
        crate::assert_with_log!(
            main_missing_while_worker_holds_task,
            "worker-owned task invisible on main thread",
            true,
            main_missing_while_worker_holds_task
        );
        crate::assert_with_log!(
            local_task_count() == main_baseline,
            "main thread count unaffected by worker-local store",
            main_baseline,
            local_task_count()
        );

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        crate::assert_with_log!(
            local_task_count() == main_baseline + 1,
            "same task id can be stored independently on main thread",
            main_baseline + 1,
            local_task_count()
        );
        let main_removed = remove_local_task(task_id).is_some();
        crate::assert_with_log!(
            main_removed,
            "main thread removes only its own local task",
            true,
            main_removed
        );
        crate::assert_with_log!(
            local_task_count() == main_baseline,
            "main thread count restored after local cleanup",
            main_baseline,
            local_task_count()
        );

        release_tx
            .send(())
            .expect("allow worker thread to clean up local task");
        let (thread_removed, thread_final_count, thread_join_baseline) =
            handle.join().expect("join worker thread");

        crate::assert_with_log!(
            thread_removed,
            "worker removes its own local task",
            true,
            thread_removed
        );
        crate::assert_with_log!(
            thread_final_count == thread_join_baseline,
            "worker-local count restored after cleanup",
            thread_join_baseline,
            thread_final_count
        );
        crate::assert_with_log!(
            local_task_count() == main_baseline,
            "main thread remains restored after worker cleanup",
            main_baseline,
            local_task_count()
        );
        crate::test_complete!("metamorphic_local_task_store_is_thread_affine");
    }
