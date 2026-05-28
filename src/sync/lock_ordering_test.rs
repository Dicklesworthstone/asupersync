//! Tests for lock ordering enforcement.

#[cfg(test)]
mod tests {
    use super::super::contended_mutex::ContendedMutex;
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    use super::super::rwlock::RwLock;
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    use crate::cx::{Cx, cap};
    use std::sync::Arc;
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    use std::thread;

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_correct_lock_ordering() {
        // Test correct ordering: Config -> Instrumentation -> Regions -> Tasks -> Obligations
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let regions_lock = Arc::new(ContendedMutex::new("regions_table", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        // This should not panic - correct ordering
        let _config_guard = config_lock.lock().unwrap(); // ubs:ignore - test oracle
        let _regions_guard = regions_lock.lock().unwrap(); // ubs:ignore - test oracle
        let _tasks_guard = tasks_lock.lock().unwrap(); // ubs:ignore - test oracle

        // Guards are dropped in reverse order automatically via RAII
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "Lock ordering violation")]
    fn test_lock_ordering_violation() {
        // Test incorrect ordering: acquire Tasks before Config (violates hierarchy)
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        // First acquire tasks lock
        let _tasks_guard = tasks_lock.lock().unwrap(); // ubs:ignore - test oracle

        // This should panic - trying to acquire Config after Tasks
        let _config_guard = config_lock.lock().unwrap(); // ubs:ignore - test oracle // This should panic
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_same_rank_locks_allowed() {
        // Multiple locks of the same rank should be allowed
        let tasks_lock1 = Arc::new(ContendedMutex::new("tasks_queue1", 0));
        let tasks_lock2 = Arc::new(ContendedMutex::new("tasks_queue2", 0));

        // This should not panic - same rank is allowed
        let _guard1 = tasks_lock1.lock().unwrap(); // ubs:ignore - test oracle
        let _guard2 = tasks_lock2.lock().unwrap(); // ubs:ignore - test oracle
    }

    #[test]
    fn test_unknown_rank_locks_no_enforcement() {
        // Locks with unknown names should not have ordering enforced
        let unknown_lock1 = Arc::new(ContendedMutex::new("unknown_lock", 0));
        let unknown_lock2 = Arc::new(ContendedMutex::new("another_unknown", 0));
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));

        // This should work regardless of order since unknown locks aren't tracked
        let _unknown1 = unknown_lock1.lock().unwrap(); // ubs:ignore - test oracle
        let _config = config_lock.lock().unwrap(); // ubs:ignore - test oracle
        let _unknown2 = unknown_lock2.lock().unwrap(); // ubs:ignore - test oracle
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_lock_release_and_reacquire() {
        // Test that lock ordering is reset after locks are released
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        // First acquisition: Config -> Tasks (correct order)
        {
            let _config_guard = config_lock.lock().unwrap(); // ubs:ignore - test oracle
            let _tasks_guard = tasks_lock.lock().unwrap(); // ubs:ignore - test oracle
        } // Both guards dropped here

        // Second acquisition: Tasks -> Config should now work (ranks reset)
        {
            let _tasks_guard = tasks_lock.lock().unwrap(); // ubs:ignore - test oracle
            let _config_guard = config_lock.lock().unwrap(); // ubs:ignore - test oracle
        }
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cross_thread_lock_ordering_isolation() {
        // Test that lock ordering is tracked per-thread
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        let config_clone = Arc::clone(&config_lock);
        let tasks_clone = Arc::clone(&tasks_lock);

        // Thread 1: acquire Tasks then Config (should panic in that thread)
        let handle1 = thread::spawn(move || {
            let _tasks_guard = tasks_clone.lock().unwrap(); // ubs:ignore - test oracle
            // This should panic in this thread only
            std::panic::catch_unwind(|| {
                let _config_guard = config_clone.lock().unwrap(); // ubs:ignore - test oracle
            })
        });

        // Thread 2: acquire Config then Tasks (correct order, should work)
        let config_clone2 = Arc::clone(&config_lock);
        let tasks_clone2 = Arc::clone(&tasks_lock);
        let handle2 = thread::spawn(move || {
            let _config_guard = config_clone2.lock().unwrap(); // ubs:ignore - test oracle
            let _tasks_guard = tasks_clone2.lock().unwrap(); // ubs:ignore - test oracle
            "success"
        });

        // Thread 1 should have panicked
        let result1 = handle1.join().unwrap(); // ubs:ignore - test oracle
        assert!(
            result1.is_err(),
            "Thread 1 should have panicked due to lock ordering violation"
        );

        // Thread 2 should have succeeded
        let result2 = handle2.join().unwrap(); // ubs:ignore - test oracle
        assert_eq!(
            result2, "success",
            "Thread 2 should have succeeded with correct ordering"
        );
    }

    #[test]
    fn test_all_lock_ranks() {
        // Test that all lock rank categories are recognized
        use crate::sync::lock_ordering::LockRank;

        assert_eq!(LockRank::from_name("config_cache"), Some(LockRank::Config));
        assert_eq!(
            LockRank::from_name("metrics_collector"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("trace_buffer"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("regions_table"),
            Some(LockRank::Regions)
        );
        assert_eq!(LockRank::from_name("region_state"), Some(LockRank::Regions));
        assert_eq!(LockRank::from_name("tasks_queue"), Some(LockRank::Tasks));
        assert_eq!(
            LockRank::from_name("scheduler_state"),
            Some(LockRank::Tasks)
        );
        assert_eq!(
            LockRank::from_name("obligations_ledger"),
            Some(LockRank::Obligations)
        );
        assert_eq!(
            LockRank::from_name("obligation_tracker"),
            Some(LockRank::Obligations)
        );

        // Case insensitive matching
        assert_eq!(LockRank::from_name("Config_Global"), Some(LockRank::Config));
        assert_eq!(LockRank::from_name("TASKS_QUEUE"), Some(LockRank::Tasks));

        // Unknown names
        assert_eq!(LockRank::from_name("unknown_lock"), None);
        assert_eq!(LockRank::from_name(""), None);
    }

    /// Helper function for RwLock tests
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "Lock ordering violation")]
    fn test_rwlock_owned_futures_respect_lock_ordering() {
        //! Regression test for asupersync-vm1044: RwLock owned futures bypass lock ordering checks.
        //! This test verifies that OwnedRwLockReadGuard and OwnedRwLockWriteGuard properly enforce
        //! the lock ordering hierarchy and don't bypass check_acquire() calls.

        let cx = test_cx();

        // Create locks with different ranks: tasks (40) and config (10)
        let tasks_rwlock = Arc::new(RwLock::with_name("tasks_scheduler", 42));
        let config_rwlock = Arc::new(RwLock::with_name("config_cache", 1));

        // First acquire tasks lock (rank 40)
        let _tasks_read_guard =
            futures_lite::future::block_on(async { tasks_rwlock.read(&cx).await.unwrap() });

        // This should panic - trying to acquire config (rank 10) after tasks (rank 40)
        // violates the E(10) -> D(20) -> B(30) -> A(40) -> C(50) hierarchy
        let _config_read_guard = futures_lite::future::block_on(async {
            config_rwlock.read(&cx).await.unwrap() // Should panic due to ordering violation
        });
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "Lock ordering violation")]
    fn test_rwlock_owned_write_futures_respect_lock_ordering() {
        //! Regression test for asupersync-vm1044: Ensure OwnedWriteFuture also respects lock ordering.

        let cx = test_cx();

        // Create locks with different ranks: obligations (50) and regions (30)
        let obligations_rwlock = Arc::new(RwLock::with_name("obligations_ledger", 0));
        let regions_rwlock = Arc::new(RwLock::with_name("regions_table", 0));

        // First acquire obligations lock (rank 50)
        let _obligations_write_guard =
            futures_lite::future::block_on(async { obligations_rwlock.write(&cx).await.unwrap() });

        // This should panic - trying to acquire regions (rank 30) after obligations (rank 50)
        let _regions_write_guard = futures_lite::future::block_on(async {
            regions_rwlock.write(&cx).await.unwrap() // ubs:ignore - test oracle // Should panic due to ordering violation
        });
    }
}
