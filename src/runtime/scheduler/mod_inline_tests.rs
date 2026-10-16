    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::RuntimeState;
    use crate::sync::ContendedMutex;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_worker_shutdown() {
        // Create state
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));

        // Create scheduler with 2 workers
        let mut scheduler = WorkStealingScheduler::new(2, &state);

        // Take workers
        let workers = scheduler.take_workers();
        assert_eq!(workers.len(), 2);

        // Spawn threads for workers
        let handles: Vec<_> = workers
            .into_iter()
            .map(|mut worker| {
                std::thread::spawn(move || {
                    worker.run_loop();
                })
            })
            .collect();

        // Let them run briefly (they will park immediately as there is no work)
        std::thread::sleep(Duration::from_millis(10));

        // Signal shutdown
        scheduler.shutdown();

        // Join threads (this will hang if shutdown logic is broken)
        for handle in handles {
            handle.join().unwrap();
        }

        // If we reach here, shutdown worked!
    }

    #[test]
    fn test_zero_worker_count_is_clamped_to_one() {
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let mut scheduler = WorkStealingScheduler::new(0, &state);
        let workers = scheduler.take_workers();
        assert_eq!(
            workers.len(),
            1,
            "scheduler must clamp zero workers to one for forward progress"
        );
    }
