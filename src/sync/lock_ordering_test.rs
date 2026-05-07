//! Tests for lock ordering enforcement.

#[cfg(test)]
mod tests {
    use super::super::contended_mutex::ContendedMutex;
    use std::sync::Arc;
    use std::thread;

    #[test]
    #[cfg(debug_assertions)]
    fn test_correct_lock_ordering() {
        // Test correct ordering: Config -> Instrumentation -> Regions -> Tasks -> Obligations
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let regions_lock = Arc::new(ContendedMutex::new("regions_table", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        // This should not panic - correct ordering
        let _config_guard = config_lock.lock().unwrap();
        let _regions_guard = regions_lock.lock().unwrap();
        let _tasks_guard = tasks_lock.lock().unwrap();

        // Guards are dropped in reverse order automatically via RAII
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Lock ordering violation")]
    fn test_lock_ordering_violation() {
        // Test incorrect ordering: acquire Tasks before Config (violates hierarchy)
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        // First acquire tasks lock
        let _tasks_guard = tasks_lock.lock().unwrap();

        // This should panic - trying to acquire Config after Tasks
        let _config_guard = config_lock.lock().unwrap(); // This should panic
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_same_rank_locks_allowed() {
        // Multiple locks of the same rank should be allowed
        let tasks_lock1 = Arc::new(ContendedMutex::new("tasks_queue1", 0));
        let tasks_lock2 = Arc::new(ContendedMutex::new("tasks_queue2", 0));

        // This should not panic - same rank is allowed
        let _guard1 = tasks_lock1.lock().unwrap();
        let _guard2 = tasks_lock2.lock().unwrap();
    }

    #[test]
    fn test_unknown_rank_locks_no_enforcement() {
        // Locks with unknown names should not have ordering enforced
        let unknown_lock1 = Arc::new(ContendedMutex::new("unknown_lock", 0));
        let unknown_lock2 = Arc::new(ContendedMutex::new("another_unknown", 0));
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));

        // This should work regardless of order since unknown locks aren't tracked
        let _unknown1 = unknown_lock1.lock().unwrap();
        let _config = config_lock.lock().unwrap();
        let _unknown2 = unknown_lock2.lock().unwrap();
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_lock_release_and_reacquire() {
        // Test that lock ordering is reset after locks are released
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        // First acquisition: Config -> Tasks (correct order)
        {
            let _config_guard = config_lock.lock().unwrap();
            let _tasks_guard = tasks_lock.lock().unwrap();
        } // Both guards dropped here

        // Second acquisition: Tasks -> Config should now work (ranks reset)
        {
            let _tasks_guard = tasks_lock.lock().unwrap();
            let _config_guard = config_lock.lock().unwrap();
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_cross_thread_lock_ordering_isolation() {
        // Test that lock ordering is tracked per-thread
        let config_lock = Arc::new(ContendedMutex::new("config_cache", 0));
        let tasks_lock = Arc::new(ContendedMutex::new("tasks_queue", 0));

        let config_clone = Arc::clone(&config_lock);
        let tasks_clone = Arc::clone(&tasks_lock);

        // Thread 1: acquire Tasks then Config (should panic in that thread)
        let handle1 = thread::spawn(move || {
            let _tasks_guard = tasks_clone.lock().unwrap();
            // This should panic in this thread only
            std::panic::catch_unwind(|| {
                let _config_guard = config_clone.lock().unwrap();
            })
        });

        // Thread 2: acquire Config then Tasks (correct order, should work)
        let config_clone2 = Arc::clone(&config_lock);
        let tasks_clone2 = Arc::clone(&tasks_lock);
        let handle2 = thread::spawn(move || {
            let _config_guard = config_clone2.lock().unwrap();
            let _tasks_guard = tasks_clone2.lock().unwrap();
            "success"
        });

        // Thread 1 should have panicked
        let result1 = handle1.join().unwrap();
        assert!(
            result1.is_err(),
            "Thread 1 should have panicked due to lock ordering violation"
        );

        // Thread 2 should have succeeded
        let result2 = handle2.join().unwrap();
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
}
