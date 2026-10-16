    use super::*;

    fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
        match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => match payload.downcast::<&'static str>() {
                Ok(message) => (*message).to_string(),
                Err(_) => "<non-string panic payload>".to_string(),
            },
        }
    }

    #[test]
    fn test_lock_rank_from_name() {
        assert_eq!(LockRank::from_name("config_cache"), Some(LockRank::Config));
        assert_eq!(LockRank::from_name("CONFIG_CACHE"), Some(LockRank::Config));
        assert_eq!(
            LockRank::from_name("metrics_collector"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("InStRuMeNtAtIoN_State"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("regions_table"),
            Some(LockRank::Regions)
        );
        assert_eq!(LockRank::from_name("TASKS_QUEUE"), Some(LockRank::Tasks));
        assert_eq!(
            LockRank::from_name("ObLiGaTiOnS_Ledger"),
            Some(LockRank::Obligations)
        );
        assert_eq!(LockRank::from_name("unknown_lock"), None);
    }

    #[test]
    fn lock_name_policy_marks_ranked_locks_as_enforced() {
        let policy = classify_lock_name("tasks_queue");

        assert_eq!(
            policy,
            LockNamePolicy::Ranked {
                rank: LockRank::Tasks,
                module: LockModule::Other,
            }
        );
        assert!(policy.is_ranked());
        assert!(!policy.is_denied());
        assert_eq!(policy.rank(), Some(LockRank::Tasks));
        assert_eq!(policy.module(), LockModule::Other);
        assert_eq!(policy.reason(), LOCK_ORDER_REASON_RANKED);
    }

    #[test]
    fn lock_name_policy_documents_allowed_unranked_locks() {
        for (name, reason) in [
            ("unknown", LOCK_ORDER_REASON_DEFAULT_UNRANKED),
            ("runtime_state", LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE),
            (
                "metamorphic.runtime_state",
                LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE,
            ),
            ("test_state", LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE),
            ("atp_transfer_registry", LOCK_ORDER_REASON_ATP_REGISTRY),
            (
                "epoch_gc.last_advance",
                LOCK_ORDER_REASON_EPOCH_GC_RATE_LIMITER,
            ),
            ("service_adapter", LOCK_ORDER_REASON_SERVICE_ADAPTER),
            (
                "atp_memory_object_store",
                LOCK_ORDER_REASON_ATP_OBJECT_STORE,
            ),
            ("transfer_actor", LOCK_ORDER_REASON_ATP_TRANSFER_ACTOR),
            ("atp_transfer_actor", LOCK_ORDER_REASON_ATP_TRANSFER_ACTOR),
            ("test_abandon_read", LOCK_ORDER_REASON_TEST_HELPER),
        ] {
            let policy = classify_lock_name(name);
            assert!(
                matches!(policy, LockNamePolicy::AllowedUnranked { .. }),
                "{name} should be an explicitly allowed unranked lock"
            );
            assert!(!policy.is_ranked());
            assert!(!policy.is_denied());
            assert_eq!(policy.rank(), None);
            assert_eq!(policy.reason(), reason);
        }
    }

    #[test]
    fn lock_name_policy_denies_undocumented_unknown_locks() {
        let policy = classify_lock_name("side_table_without_rank");

        assert_eq!(
            policy,
            LockNamePolicy::DeniedUnknown {
                module: LockModule::Other,
                reason: LOCK_ORDER_REASON_UNKNOWN_RANK,
            }
        );
        assert!(!policy.is_ranked());
        assert!(policy.is_denied());
        assert_eq!(policy.rank(), None);
        assert_eq!(policy.reason(), LOCK_ORDER_REASON_UNKNOWN_RANK);
    }

    #[test]
    fn require_ranked_lock_name_returns_rank_and_module_for_known_locks() {
        assert_eq!(
            require_ranked_lock_name("obligation_tracker"),
            (LockRank::Obligations, LockModule::Obligation)
        );
    }

    #[test]
    fn enforce_lock_name_policy_allows_documented_unranked_locks() {
        let policy = enforce_lock_name_policy("runtime_state");

        assert_eq!(
            policy,
            LockNamePolicy::AllowedUnranked {
                module: LockModule::Runtime,
                reason: LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE,
            }
        );
    }

    #[test]
    fn rank_for_lock_name_preserves_ranked_results() {
        assert_eq!(rank_for_lock_name("regions_table"), Some(LockRank::Regions));
    }

    #[test]
    fn enforce_lock_name_policy_panics_with_stable_reason_for_unknown_lock() {
        let panic = std::panic::catch_unwind(|| {
            let _ = enforce_lock_name_policy("side_table_without_rank");
        })
        .expect_err("undocumented unknown lock should fail closed");
        let message = panic_payload_to_string(panic);

        assert!(
            message.starts_with("[ASUP-E205]"),
            "policy panic should start with ASUP-E205 token: {message}"
        );
        assert!(
            message.contains(LOCK_ORDER_REASON_UNKNOWN_RANK),
            "policy panic should include stable reason: {message}"
        );
    }

    #[test]
    fn require_ranked_lock_name_panics_with_stable_reason_for_unknown_lock() {
        let panic = std::panic::catch_unwind(|| {
            let _ = require_ranked_lock_name("side_table_without_rank");
        })
        .expect_err("undocumented unknown lock should fail closed");
        let message = panic_payload_to_string(panic);

        assert!(
            message.starts_with("[ASUP-E205]"),
            "policy panic should start with ASUP-E205 token: {message}"
        );
        assert!(
            message.contains(LOCK_ORDER_REASON_UNKNOWN_RANK),
            "policy panic should include stable reason: {message}"
        );
    }

    #[test]
    fn test_lock_rank_ordering() {
        assert!(LockRank::Config < LockRank::Instrumentation);
        assert!(LockRank::Instrumentation < LockRank::Regions);
        assert!(LockRank::Regions < LockRank::Tasks);
        assert!(LockRank::Tasks < LockRank::Obligations);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_correct_lock_ordering() {
        // This should not panic - correct ordering
        check_acquire("config_test", LockRank::Config);
        record_acquire("config_test", LockRank::Config);

        check_acquire("regions_test", LockRank::Regions);
        record_acquire("regions_test", LockRank::Regions);

        check_acquire("tasks_test", LockRank::Tasks);
        record_acquire("tasks_test", LockRank::Tasks);

        record_release("tasks_test", LockRank::Tasks);
        record_release("regions_test", LockRank::Regions);
        record_release("config_test", LockRank::Config);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_incorrect_lock_ordering() {
        clear_held_locks(); // Start with clean state
        let panic = std::panic::catch_unwind(|| {
            // This should panic - trying to acquire Config after Tasks
            record_acquire("tasks_test", LockRank::Tasks);
            check_acquire("config_test", LockRank::Config);
        })
        .expect_err("rank-order inversion should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("Lock ordering violation"),
            "rank-order panic should mention ordering violation: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn rank_order_violation_panic_starts_with_asup_e205() {
        clear_held_locks();

        let panic = std::panic::catch_unwind(|| {
            record_acquire("tasks_test", LockRank::Tasks);
            check_acquire("config_test", LockRank::Config);
        })
        .expect_err("rank-order violation should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.starts_with("[ASUP-E205]"),
            "rank-order panic should start with ASUP-E205 token: {message}"
        );
    }

    #[test]
    fn test_module_from_name() {
        for (expected, variants) in [
            (LockModule::Runtime, ["runtime", "RuNtImE", "RUNTIME"]),
            (LockModule::Runtime, ["scheduler", "ScHeDuLeR", "SCHEDULER"]),
            (LockModule::Sync, ["sync", "SyNc", "SYNC"]),
            (LockModule::Sync, ["mutex", "MuTeX", "MUTEX"]),
            (LockModule::Sync, ["rwlock", "RwLoCk", "RWLOCK"]),
            (LockModule::Cx, ["cx", "cX", "CX"]),
            (LockModule::Cx, ["scope", "ScOpE", "SCOPE"]),
            (LockModule::Cx, ["macaroon", "MaCaRoOn", "MACAROON"]),
            (LockModule::Cancel, ["cancel", "CaNcEl", "CANCEL"]),
            (LockModule::Cancel, ["progress", "PrOgReSs", "PROGRESS"]),
            (
                LockModule::Obligation,
                ["obligation", "ObLiGaTiOn", "OBLIGATION"],
            ),
            (LockModule::Channel, ["channel", "ChAnNeL", "CHANNEL"]),
            (LockModule::Channel, ["mpsc", "MpSc", "MPSC"]),
            (LockModule::Channel, ["oneshot", "OnEsHoT", "ONESHOT"]),
            (LockModule::Io, ["io", "Io", "IO"]),
            (LockModule::Io, ["net", "NeT", "NET"]),
            (LockModule::Io, ["tcp", "TcP", "TCP"]),
            (
                LockModule::Other,
                ["widget_state", "WiDgEt_sTaTe", "WIDGET_STATE"],
            ),
        ] {
            for name in variants {
                assert_eq!(
                    LockModule::from_name(name),
                    expected,
                    "module classification must ignore ASCII case for {name}"
                );
            }
        }
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cross_module_correct_patterns() {
        clear_held_locks(); // Start with clean state

        // This should work - Cx before Cancel
        check_acquire_with_module("cx_scope", LockRank::Regions, LockModule::Cx);
        record_acquire_with_module("cx_scope", LockRank::Regions, LockModule::Cx);

        check_acquire_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);
        record_acquire_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);

        // Clean up
        record_release_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);
        record_release_with_module("cx_scope", LockRank::Regions, LockModule::Cx);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cross_module_obligation_cancel_violation() {
        clear_held_locks(); // Start with clean state

        let panic = std::panic::catch_unwind(|| {
            // Hold a Cancel module lock
            record_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);

            // This should panic - acquiring Obligation lock while holding Cancel lock
            check_acquire_with_module(
                "obligation_tracker",
                LockRank::Obligations,
                LockModule::Obligation,
            );
        })
        .expect_err("cancel-before-obligation pattern should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("CROSS-MODULE DEADLOCK PREVENTION"),
            "cross-module panic should mention deadlock prevention: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn cross_module_violation_panic_starts_with_asup_e205() {
        clear_held_locks();

        let panic = std::panic::catch_unwind(|| {
            record_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);
            check_acquire_with_module(
                "obligation_tracker",
                LockRank::Obligations,
                LockModule::Obligation,
            );
        })
        .expect_err("cross-module violation should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.starts_with("[ASUP-E205]"),
            "cross-module panic should start with ASUP-E205 token: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    // The basic rank-order guard fires first here (acquiring a lower-ranked
    // Cancel lock while holding a higher-ranked Cx lock), emitting the
    // "DEADLOCK PREVENTION" message. Matching the shared prefix keeps this
    // robust whether the rank-order or the cross-module rule trips first.
    fn test_cross_module_cx_cancel_violation() {
        clear_held_locks(); // Start with clean state

        let panic = std::panic::catch_unwind(|| {
            // Hold a higher-ranked Cx lock
            record_acquire_with_module("cx_macaroon", LockRank::Obligations, LockModule::Cx);

            // This should panic - acquiring lower-ranked Cancel lock while holding higher-ranked Cx lock
            check_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);
        })
        .expect_err("cx-before-cancel rank inversion should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("DEADLOCK PREVENTION"),
            "cx/cancel panic should mention deadlock prevention: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    // Acquiring a Tasks-rank lock while holding an Obligations-rank lock is
    // a plain rank-order inversion, so the basic guard fires first with the
    // "DEADLOCK PREVENTION" message before the Runtime/Obligation cross-module
    // rule is reached. Match the shared prefix.
    fn test_cross_module_runtime_obligation_violation() {
        clear_held_locks(); // Start with clean state

        let panic = std::panic::catch_unwind(|| {
            // Hold an Obligation lock
            record_acquire_with_module(
                "obligation_ledger",
                LockRank::Obligations,
                LockModule::Obligation,
            );

            // This should panic - acquiring Task lock while holding Obligation lock
            check_acquire_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);
        })
        .expect_err("runtime/obligation rank inversion should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("DEADLOCK PREVENTION"),
            "runtime/obligation panic should mention deadlock prevention: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_detailed_lock_tracking() {
        clear_held_locks(); // Start with clean state

        // Acquire multiple locks
        record_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        record_acquire_with_module("sync_mutex", LockRank::Tasks, LockModule::Sync);

        let held_locks = current_held_locks();
        assert_eq!(held_locks.len(), 2);

        assert!(held_locks.contains_key(&LockRank::Config));
        assert!(held_locks.contains_key(&LockRank::Tasks));

        let config_locks = &held_locks[&LockRank::Config];
        assert_eq!(config_locks.len(), 1);
        assert_eq!(config_locks[0].name, "config_cache");
        assert_eq!(config_locks[0].module, LockModule::Runtime);

        // Clean up
        record_release_with_module("sync_mutex", LockRank::Tasks, LockModule::Sync);
        record_release_with_module("config_cache", LockRank::Config, LockModule::Runtime);

        let held_locks_after = current_held_locks();
        assert_eq!(held_locks_after.len(), 0);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn lock_order_atlas_records_instrumentation_edges_and_violations() {
        clear_held_locks();

        check_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        record_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        check_acquire_with_module(
            "trace_buffer",
            LockRank::Instrumentation,
            LockModule::Runtime,
        );
        record_acquire_with_module(
            "trace_buffer",
            LockRank::Instrumentation,
            LockModule::Runtime,
        );

        let snapshot = lock_order_atlas_snapshot();
        assert_eq!(snapshot.instrumentation_mode, "debug_lock_ordering");
        assert!(snapshot.order_violations.is_empty());
        assert!(snapshot.order_edges_exercised.iter().any(|edge| {
            edge.held_lock_name == "config_cache"
                && edge.held_rank == LockRank::Config
                && edge.held_module == LockModule::Runtime
                && edge.acquired_lock_name == "trace_buffer"
                && edge.acquired_rank == LockRank::Instrumentation
                && edge.acquired_module == LockModule::Runtime
        }));

        clear_held_locks();
        record_acquire_with_module("tasks_queue", LockRank::Tasks, LockModule::Runtime);

        let inversion = std::panic::catch_unwind(|| {
            check_acquire_with_module(
                "trace_buffer",
                LockRank::Instrumentation,
                LockModule::Runtime,
            );
        });
        assert!(inversion.is_err());

        let snapshot = lock_order_atlas_snapshot();
        assert!(snapshot.order_violations.iter().any(|violation| {
            violation.lock_name == "trace_buffer"
                && violation.lock_rank == LockRank::Instrumentation
                && violation.lock_module == LockModule::Runtime
                && violation.held_rank == LockRank::Tasks
                && violation.reason == "rank-order"
        }));

        clear_held_locks();
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn duplicate_lock_name_release_preserves_remaining_acquisition() {
        clear_held_locks();

        record_acquire_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);
        record_acquire_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);

        let held_locks = current_held_locks();
        assert_eq!(held_locks[&LockRank::Tasks].len(), 2);

        record_release_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);

        let held_locks = current_held_locks();
        assert_eq!(held_locks[&LockRank::Tasks].len(), 1);
        assert!(current_held_ranks().contains(&LockRank::Tasks));

        let lower_rank_result =
            std::panic::catch_unwind(|| check_acquire("config_cache", LockRank::Config));
        assert!(
            lower_rank_result.is_err(),
            "remaining same-name task lock must keep its rank active"
        );

        record_release_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);
        assert!(current_held_locks().is_empty());
        assert!(current_held_ranks().is_empty());
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn guard_token_follows_task_context_across_worker_migration() {
        let cx = crate::Cx::for_testing();
        let token = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            clear_held_locks();
            let token = record_guard_acquire("tasks_migrating_guard", Some(LockRank::Tasks));
            assert_eq!(current_held_ranks(), vec![LockRank::Tasks]);
            token
        };

        let worker = std::thread::spawn(move || {
            let _current = crate::Cx::set_current(Some(cx));
            assert_eq!(
                current_held_ranks(),
                vec![LockRank::Tasks],
                "the migrated task must retain its held-rank view"
            );

            let inversion = std::panic::catch_unwind(|| {
                check_acquire("config_after_migration", LockRank::Config);
            });
            assert!(
                inversion.is_err(),
                "migration must not hide a real rank inversion"
            );

            let mut token = token;
            record_guard_release(&mut token);
            assert!(current_held_locks().is_empty());
            assert!(current_held_ranks().is_empty());
            clear_held_locks();
        });
        worker.join().expect("migration worker should complete");
    }

    /// One Cx can be current on two threads at once (a borrowed future polled
    /// under its owner's Cx elsewhere). A ContendedMutex guard never leaves its
    /// thread, so a lock held on one of them is not held on the other.
    /// ThreeLaneWorker::execute stores a polled task back with its Cx still
    /// current; this was a false ASUP-E205 "tasks while holding Obligations"
    /// on a runtime worker.
    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn a_thread_bound_lock_is_not_held_by_another_thread_sharing_the_cx() {
        let cx = crate::Cx::for_testing();
        let obligations = Arc::new(crate::sync::ContendedMutex::new("obligations", ()));
        let tasks = crate::sync::ContendedMutex::new("tasks", ());
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let cx = cx.clone();
            let obligations = Arc::clone(&obligations);
            std::thread::spawn(move || {
                let _current = crate::Cx::set_current(Some(cx));
                let guard = obligations.lock().expect("obligations lock");
                held_tx.send(()).expect("signal held");
                done_rx.recv().expect("await the other thread");
                assert_eq!(
                    current_held_ranks(),
                    vec![LockRank::Obligations],
                    "the holding thread keeps its own view"
                );
                drop(guard);
                assert!(current_held_ranks().is_empty());
            })
        };
        held_rx.recv().expect("holder acquired obligations");
        let acquired = {
            let _current = crate::Cx::set_current(Some(cx));
            let empty = current_held_ranks().is_empty();
            let lock = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(tasks.lock().expect("tasks lock"));
            }));
            (empty, lock.is_ok())
        };
        done_tx.send(()).expect("release the holder");
        holder.join().expect("holder thread");
        assert_eq!(
            acquired,
            (true, true),
            "another thread's lock is not held here, so acquiring tasks is no inversion"
        );

        // A real inversion on one thread still panics, with or without a Cx.
        let _current = crate::Cx::set_current(Some(crate::Cx::for_testing()));
        let guard = obligations.lock().expect("obligations lock");
        let inversion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(tasks.lock().expect("tasks lock"));
        }));
        drop(guard);
        assert!(inversion.is_err(), "tasks after obligations on one thread is an inversion");
        assert!(current_held_ranks().is_empty());
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn exact_guard_token_cannot_erase_another_tasks_same_name_lock() {
        let first_cx = crate::Cx::for_testing();
        let second_cx = crate::Cx::for_testing();

        let first_token = {
            let _current = crate::Cx::set_current(Some(first_cx));
            clear_held_locks();
            record_guard_acquire("tasks_same_name", Some(LockRank::Tasks))
        };

        let _current = crate::Cx::set_current(Some(second_cx));
        clear_held_locks();
        let mut second_token = record_guard_acquire("tasks_same_name", Some(LockRank::Tasks));

        let mut first_token = first_token;
        record_guard_release(&mut first_token);
        let held = current_held_locks();
        assert_eq!(held[&LockRank::Tasks].len(), 1);
        assert_eq!(held[&LockRank::Tasks][0].name, "tasks_same_name");

        record_guard_release(&mut second_token);
        assert!(current_held_locks().is_empty());
        clear_held_locks();
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn shipped_send_guards_release_exact_tracking_after_worker_migration() {
        fn drop_on_matching_task<T: Send>(cx: &crate::Cx, guard: T) {
            let cx = cx.clone();
            std::thread::scope(|scope| {
                scope
                    .spawn(move || {
                        let _current = crate::Cx::set_current(Some(cx));
                        assert_eq!(current_held_ranks(), vec![LockRank::Tasks]);
                        drop(guard);
                        assert!(current_held_locks().is_empty());
                    })
                    .join()
                    .expect("guard migration worker should complete");
            });
        }

        let cx = crate::Cx::for_testing();

        let mutex = std::sync::Arc::new(crate::sync::Mutex::with_name(
            "tasks_owned_mutex_migration",
            1_u8,
        ));
        let mutex_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedMutexGuard::try_lock(std::sync::Arc::clone(&mutex))
                .expect("owned mutex should be immediately available")
        };
        drop_on_matching_task(&cx, mutex_guard);

        let mapped_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedMutexGuard::try_lock(std::sync::Arc::clone(&mutex))
                .expect("owned mutex should remain available")
                .map(|value| value)
        };
        drop_on_matching_task(&cx, mapped_guard);

        let rwlock = crate::sync::RwLock::with_name("tasks_rwlock_migration", 1_u8);
        let read_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            rwlock.try_read().expect("read guard should be available")
        };
        drop_on_matching_task(&cx, read_guard);

        let write_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            rwlock.try_write().expect("write guard should be available")
        };
        drop_on_matching_task(&cx, write_guard);

        let owned_rwlock = std::sync::Arc::new(crate::sync::RwLock::with_name(
            "tasks_owned_rwlock_migration",
            1_u8,
        ));
        let owned_read = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedRwLockReadGuard::try_read(std::sync::Arc::clone(&owned_rwlock))
                .expect("owned read guard should be available")
        };
        drop_on_matching_task(&cx, owned_read);

        let owned_write = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedRwLockWriteGuard::try_write(std::sync::Arc::clone(&owned_rwlock))
                .expect("owned write guard should be available")
        };
        drop_on_matching_task(&cx, owned_write);

        let semaphore = crate::sync::Semaphore::with_name("tasks_semaphore_migration", 1);
        let permit = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            semaphore
                .try_acquire(1)
                .expect("borrowed permit should be available")
        };
        drop_on_matching_task(&cx, permit);

        let owned_semaphore = std::sync::Arc::new(crate::sync::Semaphore::with_name(
            "tasks_owned_semaphore_migration",
            1,
        ));
        let owned_permit = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedSemaphorePermit::try_acquire(
                std::sync::Arc::clone(&owned_semaphore),
                1,
            )
            .expect("owned permit should be available")
        };
        drop_on_matching_task(&cx, owned_permit);

        let _current = crate::Cx::set_current(Some(cx));
        assert!(current_held_locks().is_empty());
        clear_held_locks();
    }
