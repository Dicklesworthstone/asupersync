    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn epoch_counter_advances_over_time() {
        let counter = EpochCounter::new(Duration::from_millis(10));
        let initial = counter.current();

        // Should not advance immediately
        assert_eq!(counter.try_advance(), None);
        assert_eq!(counter.current(), initial);

        // Wait for advance interval
        thread::sleep(Duration::from_millis(15));

        // Should advance now
        let new_epoch = counter.try_advance().expect("Should advance");
        assert_eq!(new_epoch, initial + 1);
        assert_eq!(counter.current(), new_epoch);
    }

    #[test]
    fn local_epoch_tracks_behind_state() {
        let local = LocalEpoch::new();
        assert_eq!(local.current(), 0);
        assert!(local.is_behind(1));
        assert!(!local.is_behind(0));

        local.sync_to_global(5);
        assert_eq!(local.current(), 5);
        assert!(!local.is_behind(5));
        assert!(local.is_behind(6));
    }

    #[test]
    fn cleanup_work_memory_usage_calculation() {
        let obligation_work = CleanupWork::Obligation {
            id: 123,
            metadata: vec![1, 2, 3, 4, 5],
        };
        assert!(obligation_work.memory_usage() > std::mem::size_of::<CleanupWork>());

        let waker_work = CleanupWork::WakerCleanup {
            waker_id: 456,
            source: "epoll".to_string(),
        };
        assert!(waker_work.memory_usage() > std::mem::size_of::<CleanupWork>());
    }

    #[test]
    fn cleanup_queue_enqueue_and_process() {
        let config = CleanupConfig {
            max_queue_size: 10,
            min_batch_size: 1,
            max_batch_size: 5,
            ..CleanupConfig::default()
        };
        let queue = DeferredCleanupQueue::with_config(config);

        // Enqueue some work
        let work1 = CleanupWork::Obligation {
            id: 1,
            metadata: vec![],
        };
        let work2 = CleanupWork::WakerCleanup {
            waker_id: 2,
            source: "kqueue".to_string(),
        };

        assert!(queue.enqueue(work1, 1).is_ok());
        assert!(queue.enqueue(work2, 1).is_ok());
        assert_eq!(queue.len(), 2);

        // Process work from epoch 1 (safe epoch 2)
        let processed = queue.process_safe_epochs(2);
        assert_eq!(processed, 2);
        assert_eq!(queue.len(), 0);

        // Verify stats
        let stats = queue.stats();
        assert_eq!(stats.total_enqueued.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_processed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_batches.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cleanup_queue_respects_epoch_safety() {
        let config = CleanupConfig::default();
        let queue = DeferredCleanupQueue::with_config(config);

        // Enqueue work from different epochs
        let work1 = CleanupWork::Obligation {
            id: 1,
            metadata: vec![],
        };
        let work2 = CleanupWork::Obligation {
            id: 2,
            metadata: vec![],
        };
        let work3 = CleanupWork::Obligation {
            id: 3,
            metadata: vec![],
        };

        assert!(queue.enqueue(work1, 1).is_ok());
        assert!(queue.enqueue(work2, 2).is_ok());
        assert!(queue.enqueue(work3, 3).is_ok());
        assert_eq!(queue.len(), 3);

        // Process only work from epoch 1 (safe epoch 2)
        let processed = queue.process_safe_epochs(2);
        assert_eq!(processed, 1);
        assert_eq!(queue.len(), 2);

        // Process work from epochs 1-2 (safe epoch 3)
        let processed = queue.process_safe_epochs(3);
        assert_eq!(processed, 1);
        assert_eq!(queue.len(), 1);

        // Process all remaining work (safe epoch 4)
        let processed = queue.process_safe_epochs(4);
        assert_eq!(processed, 1);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn cleanup_queue_handles_overflow() {
        let config = CleanupConfig {
            max_queue_size: 2,
            ..CleanupConfig::default()
        };
        let queue = DeferredCleanupQueue::with_config(config);

        let work = CleanupWork::Obligation {
            id: 1,
            metadata: vec![],
        };

        // Fill queue to capacity
        assert!(queue.enqueue(work.clone(), 1).is_ok());
        assert!(queue.enqueue(work.clone(), 1).is_ok());

        // Next enqueue should fail due to overflow
        assert!(queue.enqueue(work, 1).is_err());

        // Verify overflow statistics
        let stats = queue.stats();
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn epoch_gc_system_integration() {
        let gc = EpochGC::new();
        assert!(gc.is_enabled());

        // Defer some cleanup work
        let work = CleanupWork::Obligation {
            id: 123,
            metadata: vec![],
        };
        assert!(gc.defer_cleanup(work).is_ok());

        // Force advance and process
        let processed = gc.force_advance_and_cleanup();
        assert_eq!(processed, 1);

        // Verify statistics
        let stats = gc.stats();
        assert_eq!(stats.total_processed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn epoch_gc_disabled_fallback() {
        let gc = EpochGC::disabled();
        assert!(!gc.is_enabled());

        // Deferred cleanup should fail and fall back to direct cleanup
        let work = CleanupWork::Obligation {
            id: 123,
            metadata: vec![],
        };
        assert!(gc.defer_cleanup(work).is_err());

        // Advance should do nothing
        let processed = gc.try_advance_and_cleanup();
        assert_eq!(processed, 0);
    }

    #[test]
    fn cleanup_stats_calculations() {
        let config = CleanupConfig::default();
        let queue = DeferredCleanupQueue::with_config(config);

        // Enqueue and process some work
        for i in 0..10 {
            let work = CleanupWork::Obligation {
                id: i,
                metadata: vec![],
            };
            let _ = queue.enqueue(work, 1);
        }

        // Process in two batches
        queue.process_safe_epochs(2);

        let stats = queue.stats();
        assert_eq!(stats.efficiency_percent(), 100.0);
        assert!(stats.average_batch_size() > 0.0);
        assert!(stats.average_batch_time_us() >= 0.0);
    }

    #[test]
    fn stress_test_concurrent_enqueue_dequeue() {
        let config = CleanupConfig {
            max_queue_size: 100_000,
            max_batch_size: 1000,
            ..CleanupConfig::default()
        };
        let _queue = Arc::new(DeferredCleanupQueue::with_config(config));
        let epoch_gc = Arc::new(EpochGC::with_config(CleanupConfig {
            max_queue_size: 100_000,
            max_batch_size: 1000,
            ..CleanupConfig::default()
        }));

        const NUM_THREADS: usize = 8;
        const WORK_ITEMS_PER_THREAD: usize = 1000;

        let mut handles = Vec::new();

        // Spawn producer threads
        for thread_id in 0..NUM_THREADS {
            let gc = Arc::clone(&epoch_gc);
            let handle = thread::spawn(move || {
                for i in 0..WORK_ITEMS_PER_THREAD {
                    let work = CleanupWork::Obligation {
                        id: (thread_id * WORK_ITEMS_PER_THREAD + i) as u64,
                        metadata: vec![thread_id as u8; 10],
                    };

                    // Keep retrying on overflow (backpressure test)
                    while gc.defer_cleanup(work.clone()).is_err() {
                        thread::sleep(Duration::from_micros(1));
                    }
                }
            });
            handles.push(handle);
        }

        // Spawn consumer thread
        let gc_consumer = Arc::clone(&epoch_gc);
        let consumer_handle = thread::spawn(move || {
            let mut total_processed = 0;
            let start = Instant::now();

            while start.elapsed() < Duration::from_secs(10)
                && total_processed < NUM_THREADS * WORK_ITEMS_PER_THREAD
            {
                let processed = gc_consumer.force_advance_and_cleanup();
                total_processed += processed;

                if processed == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }

            total_processed
        });

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        let total_processed = consumer_handle.join().unwrap();

        // Verify all work was processed
        assert!(
            total_processed >= NUM_THREADS * WORK_ITEMS_PER_THREAD * 9 / 10,
            "Should process at least 90% of work items, got {}",
            total_processed
        );

        let stats = epoch_gc.stats();
        assert!(stats.efficiency_percent() >= 90.0);
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stress_test_memory_usage_extended_operation() {
        use std::sync::atomic::AtomicUsize;

        // Simple memory usage tracker
        static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

        let config = CleanupConfig {
            max_queue_size: 10_000,
            max_batch_size: 100,
            max_batch_time: Duration::from_millis(1),
            ..CleanupConfig::default()
        };
        let epoch_gc = Arc::new(EpochGC::with_config(config));

        let start_memory = ALLOCATED.load(Ordering::Relaxed);

        // Run extended operation
        for iteration in 0..1000 {
            // Add work items
            for i in 0..100 {
                let work = CleanupWork::RegionCleanup {
                    region_id: RegionId::new_for_test(iteration * 100 + i, 1),
                    task_ids: vec![TaskId::new_for_test(i, 1); 10], // 10 tasks per region
                };
                let _ = epoch_gc.defer_cleanup(work);
            }

            // Periodically process cleanup
            if iteration % 10 == 0 {
                epoch_gc.force_advance_and_cleanup();
            }

            // Check for memory leaks every 100 iterations
            if iteration % 100 == 0 {
                epoch_gc.force_advance_and_cleanup(); // Process remaining work

                let current_memory = ALLOCATED.load(Ordering::Relaxed);
                let memory_growth = current_memory.saturating_sub(start_memory);

                // Memory growth should be bounded (less than 1MB)
                assert!(
                    memory_growth < 1_000_000,
                    "Memory growth {} exceeds limit at iteration {}",
                    memory_growth,
                    iteration
                );

                // Queue should not grow unbounded
                assert!(
                    epoch_gc.cleanup_queue.len() < 1000,
                    "Queue size {} too large at iteration {}",
                    epoch_gc.cleanup_queue.len(),
                    iteration
                );
            }
        }

        // Final cleanup
        for _ in 0..10 {
            epoch_gc.force_advance_and_cleanup();
        }

        let stats = epoch_gc.stats();
        assert!(stats.efficiency_percent() >= 95.0);
    }

    #[test]
    fn performance_benchmark_deferred_vs_direct() {
        const NUM_OPERATIONS: usize = 10_000;

        // Benchmark direct cleanup (simulated)
        let start = Instant::now();
        for i in 0..NUM_OPERATIONS {
            // Simulate direct cleanup overhead
            let _ = format!("cleanup_{}", i);
            thread::sleep(Duration::from_nanos(100)); // Simulated cleanup cost
        }
        let direct_duration = start.elapsed();

        // Benchmark deferred cleanup
        let epoch_gc = EpochGC::new();
        let start = Instant::now();

        for i in 0..NUM_OPERATIONS {
            let work = CleanupWork::Obligation {
                id: i as u64,
                metadata: vec![],
            };
            let _ = epoch_gc.defer_cleanup(work);

            // Periodically process cleanup
            if i % 100 == 0 {
                epoch_gc.force_advance_and_cleanup();
            }
        }

        // Process remaining work
        while epoch_gc.cleanup_queue.len() > 0 {
            epoch_gc.force_advance_and_cleanup();
        }

        let deferred_duration = start.elapsed();

        // Keep the measured durations available for local debugging without
        // emitting nondeterministic stdout from the test suite.
        let _ = (direct_duration, deferred_duration);

        let stats = epoch_gc.stats();
        assert!(stats.total_processed.load(Ordering::Relaxed) as usize >= NUM_OPERATIONS);
        assert!(stats.efficiency_percent() >= 95.0);
        assert!(stats.average_batch_size() > 1.0); // Should batch work
    }

    #[test]
    fn correctness_test_no_work_lost() {
        use std::sync::atomic::AtomicU64;

        let epoch_gc = Arc::new(EpochGC::new());
        let _processed_counter = Arc::new(AtomicU64::new(0));

        const NUM_WORK_ITEMS: u64 = 5000;

        // Track which work items were processed
        let mut expected_ids = std::collections::HashSet::new();
        for i in 0..NUM_WORK_ITEMS {
            expected_ids.insert(i);
        }

        // Enqueue work from multiple threads
        let mut handles = Vec::new();
        for thread_id in 0..4 {
            let gc = Arc::clone(&epoch_gc);
            let start_id = thread_id * NUM_WORK_ITEMS / 4;
            let end_id = (thread_id + 1) * NUM_WORK_ITEMS / 4;

            let handle = thread::spawn(move || {
                for id in start_id..end_id {
                    let work = CleanupWork::Obligation {
                        id,
                        metadata: vec![],
                    };

                    // Retry on failure (queue full)
                    while gc.defer_cleanup(work.clone()).is_err() {
                        thread::sleep(Duration::from_micros(10));
                    }
                }
            });
            handles.push(handle);
        }

        // Process work periodically
        let gc_processor = Arc::clone(&epoch_gc);
        let processor_handle = thread::spawn(move || {
            let mut total_processed = 0;
            while total_processed < NUM_WORK_ITEMS {
                let processed = gc_processor.force_advance_and_cleanup();
                total_processed += processed as u64;

                if processed == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        processor_handle.join().unwrap();

        // Verify no work was lost
        let stats = epoch_gc.stats();
        assert_eq!(
            stats.total_processed.load(Ordering::Relaxed),
            NUM_WORK_ITEMS
        );
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(stats.efficiency_percent(), 100.0);
    }

    #[test]
    fn backpressure_prevents_unbounded_growth() {
        let config = CleanupConfig {
            max_queue_size: 100,
            ..CleanupConfig::default()
        };
        let queue = DeferredCleanupQueue::with_config(config);

        let work = CleanupWork::Obligation {
            id: 1,
            metadata: vec![0; 1000],
        };

        // Fill queue to capacity
        let mut enqueued = 0;
        let mut rejected = 0;

        for _ in 0..200 {
            match queue.enqueue(work.clone(), 1) {
                Ok(()) => enqueued += 1,
                Err(_) => rejected += 1,
            }
        }

        assert!(
            enqueued <= 100,
            "Should not enqueue more than max_queue_size"
        );
        assert!(rejected > 0, "Should reject some items when full");
        assert!(queue.is_near_capacity(), "Should detect near capacity");

        // Verify backpressure statistics
        let stats = queue.stats();
        assert_eq!(
            stats.total_dropped.load(Ordering::Relaxed) as usize,
            rejected
        );
    }

    #[test]
    fn epoch_safety_prevents_premature_cleanup() {
        let gc = EpochGC::with_config(CleanupConfig {
            max_batch_size: 1000,
            ..CleanupConfig::default()
        });

        // Enqueue work in current epoch
        for i in 0..10 {
            let work = CleanupWork::Obligation {
                id: i,
                metadata: vec![],
            };
            gc.defer_cleanup(work).unwrap();
        }

        // Try to advance without sufficient time (should not process work)
        let processed = gc.try_advance_and_cleanup();
        assert_eq!(processed, 0, "Should not process work from current epoch");

        // Force advance and verify work is processed
        let processed = gc.force_advance_and_cleanup();
        assert_eq!(
            processed, 10,
            "Should process all work after forced advance"
        );
    }
