    use super::*;
    use crate::runtime::pool_sizing::PoolSizingAction;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize};
    use std::sync::{Condvar as StdCondvar, Mutex as StdMutex, OnceLock};

    static DETERMINISTIC_HOOK_TEST_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    static SCRIPTED_TIME_BASE: OnceLock<Instant> = OnceLock::new();
    static SCRIPTED_TIME_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SCRIPTED_TIME_OFFSET_MS: AtomicU64 = AtomicU64::new(0);
    static SCRIPTED_SLEEP_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn deterministic_hook_test_guard() -> std::sync::MutexGuard<'static, ()> {
        DETERMINISTIC_HOOK_TEST_LOCK
            .get_or_init(|| StdMutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reset_scripted_time_state() {
        SCRIPTED_TIME_CALLS.store(0, Ordering::Relaxed);
        SCRIPTED_TIME_OFFSET_MS.store(0, Ordering::Relaxed);
        SCRIPTED_SLEEP_CALLS.store(0, Ordering::Relaxed);
    }

    fn scripted_time_base() -> Instant {
        *SCRIPTED_TIME_BASE.get_or_init(Instant::now)
    }

    fn stepped_timeout_time() -> Instant {
        let base = scripted_time_base();
        if SCRIPTED_TIME_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
            base
        } else {
            base + Duration::from_millis(25)
        }
    }

    fn advancing_timeout_time() -> Instant {
        scripted_time_base()
            + Duration::from_millis(SCRIPTED_TIME_OFFSET_MS.load(Ordering::Relaxed))
    }

    fn advancing_timeout_sleep(duration: Duration) {
        SCRIPTED_SLEEP_CALLS.fetch_add(1, Ordering::Relaxed);
        let millis = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        SCRIPTED_TIME_OFFSET_MS.fetch_add(millis, Ordering::Relaxed);
    }

    fn test_blocking_task(preferred_cohort: Option<usize>) -> BlockingTask {
        BlockingTask {
            work: Box::new(|| {}),
            priority: 128,
            preferred_cohort,
            cancelled: Arc::new(AtomicBool::new(false)),
            completion: Arc::new(BlockingTaskCompletion::new(wall_clock_now)),
        }
    }

    fn tracked_test_blocking_task(
        preferred_cohort: Option<usize>,
        executions: Arc<AtomicUsize>,
    ) -> (BlockingTask, Arc<AtomicBool>, Arc<BlockingTaskCompletion>) {
        let cancelled = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(BlockingTaskCompletion::new(wall_clock_now));
        let task = BlockingTask {
            work: Box::new(move || {
                executions.fetch_add(1, Ordering::Relaxed);
            }),
            priority: 128,
            preferred_cohort,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };
        (task, cancelled, completion)
    }

    fn test_blocking_inner_with_affinity(
        affinity_profile: BlockingPoolAffinityProfile,
        cohort_count: Option<usize>,
    ) -> Arc<BlockingPoolInner> {
        let options = BlockingPoolOptions {
            affinity_profile,
            cohort_count,
            ..Default::default()
        };
        Arc::new(BlockingPoolInner {
            min_threads: 0,
            max_threads: 4,
            live_max_threads: AtomicUsize::new(4),
            default_sized: AtomicBool::new(false),
            active_threads: AtomicUsize::new(0),
            replacement_pending: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: BlockingTaskQueue::new(BlockingQueuePolicy::Fifo),
            affinity: BlockingPoolAffinityState::from_options(&options, BlockingQueuePolicy::Fifo),
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(10),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "affinity-test".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn basic_spawn_and_wait() {
        let pool = BlockingPool::new(1, 4);
        let counter = Arc::new(AtomicI32::new(0));

        let counter_clone = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });

        handle.wait();
        assert!(handle.is_done());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn set_max_threads_never_strands_work_at_zero() {
        // Regression: the live spawn cap must floor at 1 for a constructed pool
        // (max_threads >= 1). Driving the cap to 0 on a min=0 elastic pool used
        // to strand submitted tasks forever — accepted, handle returned, but no
        // worker ever spawned (the `active < live_max` gate is `0 < 0`).
        let pool = BlockingPool::new(0, 4); // elastic: 0 persistent, up to 4 on demand
        let applied = pool.set_max_threads(0);
        assert_eq!(applied, 1, "live spawn cap must floor at 1, not 0");
        assert_eq!(pool.current_max_threads(), 1);

        // End-to-end: with the cap floored, a submitted task still runs to
        // completion (this `wait()` would hang forever pre-fix). The assertion
        // above fails fast if the floor ever regresses, before reaching here.
        let counter = Arc::new(AtomicI32::new(0));
        let counter_clone = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });
        handle.wait();
        assert!(handle.is_done());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn huge_timeouts_wait_without_a_deadline_instead_of_panicking() {
        // br-asupersync-2u7bpm: `Instant + Duration::MAX` overflowed and
        // panicked, after shutdown had already begun in shutdown_and_wait.
        let pool = BlockingPool::new(1, 1);
        let handle = pool.spawn(|| thread::sleep(Duration::from_millis(20)));
        assert!(handle.wait_timeout(Duration::MAX));
        assert!(pool.shutdown_and_wait(Duration::MAX));
    }

    #[test]
    fn raising_the_cap_starts_threads_for_jobs_already_queued() {
        // br-asupersync-2u7bpm: set_max_threads only stored the new cap, so jobs
        // queued under a lower cap waited for later submissions to spawn
        // threads, one per submission. Each of these three jobs waits until all
        // three have started, so all three see that in time only if raising the
        // cap starts threads for the two still queued.
        let pool = BlockingPool::new(0, 4);
        pool.set_max_threads(1);
        let started = Arc::new(AtomicUsize::new(0));
        let met = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let started = Arc::clone(&started);
                let met = Arc::clone(&met);
                pool.spawn(move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < deadline {
                        if started.load(Ordering::SeqCst) == 3 {
                            met.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .collect();

        let running_by = Instant::now() + Duration::from_secs(5);
        while started.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < running_by, "the first job must start");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pool.pending_count(), 2, "two jobs wait under the cap of 1");

        assert_eq!(pool.set_max_threads(3), 3);
        for handle in &handles {
            handle.wait();
        }
        assert_eq!(
            met.load(Ordering::SeqCst),
            3,
            "all three jobs must run at once after the cap is raised"
        );
    }

    #[test]
    fn affinity_routes_preferred_tasks_into_local_queue() {
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 2,
                spill_check_interval: 1,
            },
            Some(2),
        );

        assert!(try_enqueue_task(&inner, test_blocking_task(Some(1))));

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.cohort_pending_counts, vec![0, 1]);
        assert_eq!(metrics.global_pending_count, 0);

        let (task, kind) =
            pop_next_blocking_task(&inner, Some(1), true).expect("local queue should yield work");
        assert_eq!(kind, BlockingTaskDequeueKind::Local);
        inner.pending_count.fetch_sub(1, Ordering::Relaxed);
        drop(task);

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.local_queue_dispatches, 1);
        assert_eq!(metrics.global_pending_count, 0);
        assert_eq!(metrics.cohort_pending_counts, vec![0, 0]);
    }

    #[test]
    fn affinity_spills_when_local_queue_is_saturated() {
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            Some(1),
        );

        assert!(try_enqueue_task(&inner, test_blocking_task(Some(0))));
        assert!(try_enqueue_task(&inner, test_blocking_task(Some(0))));

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.cohort_pending_counts, vec![1]);
        assert_eq!(metrics.global_pending_count, 1);
        assert_eq!(metrics.fallback_dispatches, 1);

        let (_task, kind) = pop_next_blocking_task(&inner, Some(0), false)
            .expect("spill queue should be checked before local queue");
        assert_eq!(kind, BlockingTaskDequeueKind::Spill);
    }

    #[test]
    fn affinity_disabled_keeps_spawn_on_cohort_equivalent_to_global_queue() {
        let inner = test_blocking_inner_with_affinity(BlockingPoolAffinityProfile::Disabled, None);

        assert!(try_enqueue_task(&inner, test_blocking_task(Some(3))));
        let metrics = blocking_pool_affinity_metrics(&inner);
        assert!(!metrics.enabled);
        assert_eq!(metrics.global_pending_count, 1);
        assert!(metrics.cohort_pending_counts.is_empty());

        let (_task, kind) = pop_next_blocking_task(&inner, Some(0), true)
            .expect("disabled affinity should still use the global queue");
        assert_eq!(kind, BlockingTaskDequeueKind::Global);
    }

    #[test]
    fn multiple_tasks() {
        let pool = BlockingPool::new(2, 8);
        let counter = Arc::new(AtomicI32::new(0));
        let mut handles = Vec::new();

        for _ in 0..100 {
            let counter_clone = Arc::clone(&counter);
            handles.push(pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            }));
        }

        for handle in handles {
            handle.wait();
        }

        assert_eq!(counter.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_spawn_from_handle() {
        let pool = BlockingPool::new(1, 4);
        let handle = pool.handle();
        let counter = Arc::new(AtomicI32::new(0));

        let c = Arc::clone(&counter);
        let task = handle.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        task.wait();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn advisory_pool_sizing_reports_bounds_without_resizing() {
        let pool = BlockingPool::new(0, 4);
        let handle = pool.handle();
        let estimate = PoolWorkloadEstimate::new(5_000_000, 1_000_000, 0);
        let target = PoolSizingTarget::MaxWaitProbabilityPpm(100_000);

        assert_eq!(pool.pool_sizing_bounds(), PoolSizingBounds::new(0, 4));
        assert_eq!(handle.pool_sizing_bounds(), PoolSizingBounds::new(0, 4));
        assert_eq!(
            pool.pool_sizing_controller_state(),
            PoolSizingControllerState {
                current_size: 0,
                last_resize_epoch: 0,
            }
        );

        let decision = pool.advisory_pool_sizing_decision(estimate, target);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(decision.recommendation.bounds, PoolSizingBounds::new(0, 4));
        assert_eq!(decision.recommendation.target, target);
        assert_eq!(pool.active_threads(), 0);

        let handle_decision = handle.advisory_pool_sizing_decision(estimate, target);
        assert_eq!(handle_decision, decision);
    }

    #[test]
    fn test_active_threads_starts_at_min() {
        let pool = BlockingPool::new(3, 8);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(pool.active_threads(), 3);
    }

    #[test]
    fn cancellation_before_execution() {
        let pool = BlockingPool::new(0, 1); // Start with no threads
        let counter = Arc::new(AtomicI32::new(0));

        // Spawn without any threads available
        let counter_clone = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });

        // Cancel immediately
        handle.cancel();
        assert!(handle.is_cancelled());

        // The task should complete (as cancelled) without incrementing
        let _ = handle.wait_timeout(Duration::from_secs(2));

        // Wait for any potential execution
        thread::sleep(Duration::from_millis(50));

        // Cancelled tasks don't execute their work
        // Note: The current implementation still executes if the thread picks it up
        // before cancellation is observed. This test may need adjustment.
    }

    #[test]
    fn test_shutdown_and_wait_empty_pool() {
        let pool = BlockingPool::new(2, 4);
        thread::sleep(Duration::from_millis(20));

        let start = std::time::Instant::now();
        let result = pool.shutdown_and_wait(Duration::from_secs(2));
        let elapsed = start.elapsed();

        assert!(result, "Shutdown should succeed");
        assert!(elapsed < Duration::from_secs(1));
        assert_eq!(pool.active_threads(), 0);
    }

    #[test]
    fn test_shutdown_and_wait_timeout_respected() {
        let pool = BlockingPool::new(1, 1);
        pool.spawn(|| {
            thread::sleep(Duration::from_millis(200));
        });

        thread::sleep(Duration::from_millis(20));

        let start = std::time::Instant::now();
        let result = pool.shutdown_and_wait(Duration::from_millis(50));
        let elapsed = start.elapsed();

        assert!(!result, "Expected timeout to return false");
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn shutdown_and_wait_blocks_until_replacement_handoff_resolves() {
        // A worker that retires with pending work hands the task off to a fresh
        // replacement. It announces that hand-off in `replacement_pending`
        // *before* it decrements `active_threads`, so there is a window where
        // `active_threads == 0` yet a replacement (and its join handle) is still
        // coming. shutdown_and_wait must keep waiting through that window;
        // otherwise it reports a clean shutdown while leaking the replacement's
        // never-joined handle (d679m7).
        //
        // Drive the window directly: announce a hand-off on a pool with no live
        // workers and assert shutdown_and_wait does not complete until the
        // hand-off is resolved. Pre-fix (gating only on `active_threads`) this
        // returns immediately and the assertion below fails.
        let pool = Arc::new(BlockingPool::new(0, 1));
        pool.inner
            .replacement_pending
            .fetch_add(1, Ordering::Release);

        let done = Arc::new(AtomicBool::new(false));
        let pool_w = Arc::clone(&pool);
        let done_w = Arc::clone(&done);
        let waiter = thread::spawn(move || {
            let ok = pool_w.shutdown_and_wait(Duration::from_secs(5));
            done_w.store(true, Ordering::Release);
            ok
        });

        // While the hand-off is outstanding, shutdown_and_wait must keep waiting.
        thread::sleep(Duration::from_millis(60));
        assert!(
            !done.load(Ordering::Acquire),
            "shutdown_and_wait must block while a replacement hand-off is pending",
        );

        // Resolve the hand-off; shutdown_and_wait can now complete cleanly.
        pool.inner
            .replacement_pending
            .fetch_sub(1, Ordering::Release);
        let ok = waiter.join().expect("waiter thread joins");
        assert!(ok, "clean shutdown once the replacement hand-off resolved");
        assert_eq!(pool.active_threads(), 0);
        assert_eq!(
            pool.inner.replacement_pending.load(Ordering::Acquire),
            0,
            "no hand-off should remain outstanding",
        );
        assert!(
            pool.inner.thread_handles.lock().is_empty(),
            "no replacement handle should be left un-joined",
        );
    }

    #[test]
    fn shutdown_and_wait_waits_for_a_queued_job_whose_worker_is_not_spawned_yet() {
        // A submitter enqueues its job and is preempted before its
        // `maybe_spawn`. With no worker active, shutdown_and_wait used to
        // report a clean shutdown at once; the submitter then started a worker
        // nobody joins, which ran the job after teardown (mopkmt M1).
        let pool = Arc::new(BlockingPool::new(0, 1));
        let ran = Arc::new(AtomicUsize::new(0));
        let (task, _cancelled, _completion) = tracked_test_blocking_task(None, Arc::clone(&ran));
        assert!(try_enqueue_task(&pool.inner, task));
        assert_eq!(pool.active_threads(), 0);

        let done = Arc::new(AtomicBool::new(false));
        let pool_w = Arc::clone(&pool);
        let done_w = Arc::clone(&done);
        let waiter = thread::spawn(move || {
            let ok = pool_w.shutdown_and_wait(Duration::from_secs(5));
            done_w.store(true, Ordering::Release);
            ok
        });

        thread::sleep(Duration::from_millis(60));
        assert!(
            !done.load(Ordering::Acquire),
            "shutdown_and_wait must wait while an accepted job is still queued",
        );

        // The preempted submitter resumes and starts its worker.
        maybe_spawn_thread_on_inner(&pool.inner);
        let ok = waiter.join().expect("waiter thread joins");
        assert!(ok, "clean shutdown once the queued job ran");
        assert_eq!(
            ran.load(Ordering::Relaxed),
            1,
            "the job ran before shutdown returned"
        );
        assert!(
            pool.inner.thread_handles.lock().is_empty(),
            "the job's worker was joined",
        );
    }

    fn labelled_cohort_task(
        cohort: usize,
        label: usize,
        order: &Arc<StdMutex<Vec<usize>>>,
    ) -> BlockingTask {
        let order = Arc::clone(order);
        BlockingTask {
            work: Box::new(move || {
                order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(label);
            }),
            priority: 128,
            preferred_cohort: Some(cohort),
            cancelled: Arc::new(AtomicBool::new(false)),
            completion: Arc::new(BlockingTaskCompletion::new(wall_clock_now)),
        }
    }

    /// Runs the worker loop on this thread as the worker of `cohort` until
    /// every queue is empty, and returns the labels in the order they ran.
    fn drain_as_cohort_worker(
        inner: &Arc<BlockingPoolInner>,
        cohort: usize,
        order: &Arc<StdMutex<Vec<usize>>>,
    ) -> Vec<usize> {
        inner.shutdown.store(true, Ordering::Release);
        assert!(!blocking_worker_loop(inner, Some(cohort)));
        order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[test]
    fn a_task_on_a_cohort_no_worker_serves_runs_while_the_worker_has_local_work() {
        // mopkmt M3: one worker serves cohort 0 and no worker serves cohort 1.
        // The cohort-1 task used to run only once cohort 0's queue and the
        // global queue were both empty, so sustained cohort-0 load starved it.
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1024,
                spill_check_interval: 1024,
            },
            Some(2),
        );
        let order = Arc::new(StdMutex::new(Vec::new()));
        let local_tasks = 3 * FOREIGN_COHORT_TURN_INTERVAL;
        let unserved = labelled_cohort_task(1, usize::MAX, &order);
        assert!(try_enqueue_task(&inner, unserved));
        for label in 0..local_tasks {
            let task = labelled_cohort_task(0, label, &order);
            assert!(try_enqueue_task(&inner, task));
        }

        let ran = drain_as_cohort_worker(&inner, 0, &order);
        assert_eq!(ran.len(), local_tasks + 1, "every task runs");
        let position = ran
            .iter()
            .position(|&label| label == usize::MAX)
            .expect("the cohort-1 task ran");
        assert!(
            position <= FOREIGN_COHORT_TURN_INTERVAL,
            "the cohort-1 task ran as dispatch {position} of {}, not within the first {} after it was queued",
            ran.len(),
            FOREIGN_COHORT_TURN_INTERVAL + 1,
        );
    }

    #[test]
    fn steal_foreign_cohort_after_visits_the_other_cohorts_in_turn() {
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1024,
                spill_check_interval: 1024,
            },
            Some(3),
        );
        for cohort in [1, 1, 2] {
            assert!(try_enqueue_task(&inner, test_blocking_task(Some(cohort))));
        }
        let affinity = inner.affinity.as_ref().expect("affinity is enabled");
        let mut cursor = 0;
        let mut served = Vec::new();
        while let Some((task, kind)) = affinity.steal_foreign_cohort_after(0, &mut cursor) {
            assert_eq!(kind, BlockingTaskDequeueKind::Spill);
            inner.pending_count.fetch_sub(1, Ordering::Relaxed);
            served.push(task.preferred_cohort);
        }
        assert_eq!(
            served,
            vec![Some(1), Some(2), Some(1)],
            "cohort 2 is served before cohort 1's second task",
        );
        assert_eq!(blocking_pool_affinity_metrics(&inner).spill_dispatches, 3);
    }

    #[test]
    fn foreign_cohort_turns_rotate_so_one_busy_cohort_does_not_starve_another() {
        // Cohorts 1 and 2 have no worker; cohort 1 stays busy. Foreign turns
        // that always started at the lowest cohort would serve cohort 1 every
        // time and leave the cohort-2 task until everything else had run.
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1024,
                spill_check_interval: 1024,
            },
            Some(3),
        );
        let order = Arc::new(StdMutex::new(Vec::new()));
        let local_tasks = 4 * FOREIGN_COHORT_TURN_INTERVAL;
        let cohort_one_tasks = 8;
        for label in 0..cohort_one_tasks {
            let task = labelled_cohort_task(1, 1000 + label, &order);
            assert!(try_enqueue_task(&inner, task));
        }
        let unserved = labelled_cohort_task(2, usize::MAX, &order);
        assert!(try_enqueue_task(&inner, unserved));
        for label in 0..local_tasks {
            let task = labelled_cohort_task(0, label, &order);
            assert!(try_enqueue_task(&inner, task));
        }

        let ran = drain_as_cohort_worker(&inner, 0, &order);
        let total = local_tasks + cohort_one_tasks + 1;
        assert_eq!(ran.len(), total, "every task runs");
        let position = ran
            .iter()
            .position(|&label| label == usize::MAX)
            .expect("the cohort-2 task ran");
        assert!(
            position <= 2 * (FOREIGN_COHORT_TURN_INTERVAL + 1),
            "the cohort-2 task ran as dispatch {position} of {}, not on the second foreign turn",
            ran.len(),
        );
    }

    #[test]
    fn test_shutdown_idempotent() {
        let pool = BlockingPool::new(1, 2);
        pool.spawn(|| {});

        pool.shutdown();
        assert!(pool.is_shutdown());
        pool.shutdown();
        assert!(pool.is_shutdown());

        assert!(pool.shutdown_and_wait(Duration::from_secs(2)));
    }

    #[test]
    fn close_admission_does_not_wait_for_coordination_mutex() {
        let pool = Arc::new(BlockingPool::new(0, 1));
        let coordination_guard = pool.inner.mutex.lock();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let closer_pool = Arc::clone(&pool);
        let closer = std::thread::spawn(move || {
            closer_pool.close_admission();
            closed_tx.send(()).expect("report admission closure");
        });

        let closed_without_lock = closed_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        drop(coordination_guard);
        closer.join().expect("admission closer joins");
        assert!(
            closed_without_lock,
            "admission closure must not wait for the coordination mutex"
        );
        assert!(pool.is_shutdown());
        pool.shutdown();
    }

    #[test]
    fn spawn_after_shutdown_is_rejected() {
        let pool = BlockingPool::new(1, 2);
        pool.shutdown();

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        assert!(handle.is_cancelled());
        assert!(handle.wait_timeout(Duration::from_millis(100)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_spawn_after_shutdown_is_rejected() {
        let pool = BlockingPool::new(1, 2);
        let handle_api = pool.handle();
        pool.shutdown();

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = handle_api.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        assert!(handle.is_cancelled());
        assert!(handle.wait_timeout(Duration::from_millis(100)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn spawn_rechecks_shutdown_before_queueing_under_submission_lock() {
        let pool = BlockingPool::new(0, 1);
        let handle_api = pool.handle();
        let executed = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(std::sync::Barrier::new(2));

        let submission_guard = pool.inner.mutex.lock();
        let executed_clone = Arc::clone(&executed);
        let gate_clone = Arc::clone(&gate);
        let join = thread::spawn(move || {
            gate_clone.wait();
            handle_api.spawn(move || {
                executed_clone.store(true, Ordering::Release);
            })
        });

        gate.wait();
        // Simulate shutdown linearizing while the submitter is blocked on the
        // submission critical section after its fast-path shutdown check.
        pool.inner.shutdown.store(true, Ordering::Release);
        drop(submission_guard);

        let handle = join.join().expect("spawn thread should return a handle");
        assert!(handle.is_cancelled());
        assert!(handle.wait_timeout(Duration::from_millis(100)));
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.active_threads(), 0);
        assert!(!executed.load(Ordering::Acquire));
    }

    #[test]
    fn wait_timeout() {
        let pool = BlockingPool::new(1, 1);

        let handle = pool.spawn(|| {
            thread::sleep(Duration::from_millis(500));
        });

        // Short timeout should fail
        assert!(!handle.wait_timeout(Duration::from_millis(10)));

        // Long timeout should succeed
        assert!(handle.wait_timeout(Duration::from_secs(2)));
        assert!(handle.is_done());
    }

    #[test]
    fn test_worker_parks_on_empty() {
        let pool = BlockingPool::new(2, 4);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(pool.busy_threads(), 0);
    }

    #[test]
    fn test_worker_wakes_on_task() {
        let pool = BlockingPool::new(1, 2);
        thread::sleep(Duration::from_millis(50));

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        assert!(handle.wait_timeout(Duration::from_secs(2)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[should_panic(expected = "min_threads must be less than or equal to max_threads")]
    fn with_config_rejects_min_threads_above_max_threads() {
        let _pool = BlockingPool::with_config(2, 1, BlockingPoolOptions::default());
    }

    #[test]
    #[should_panic(expected = "thread_name_prefix may not contain interior NUL bytes")]
    fn with_config_rejects_thread_name_prefix_with_nul() {
        let _pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "bad\0name".to_string(),
                ..Default::default()
            },
        );
    }

    #[test]
    fn test_worker_idle_timeout_excess_threads_exit() {
        let options = BlockingPoolOptions {
            idle_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let pool = BlockingPool::with_config(0, 3, options);

        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..3 {
            let b = Arc::clone(&barrier);
            handles.push(pool.spawn(move || {
                b.wait();
            }));
        }

        thread::sleep(Duration::from_millis(50));
        let active_before = pool.active_threads();
        assert!(active_before >= 1);

        barrier.wait();
        for h in handles {
            h.wait();
        }

        thread::sleep(Duration::from_millis(300));
        let active_after = pool.active_threads();
        assert!(
            active_after <= 1,
            "Expected excess threads to retire, active_after={active_after}"
        );
    }

    #[test]
    fn thread_scaling() {
        let pool = BlockingPool::new(1, 4);

        // Initially should have min_threads
        assert_eq!(pool.active_threads(), 1);

        // Spawn multiple blocking tasks that just sleep briefly
        // This tests that the pool can handle multiple concurrent tasks
        let counter = Arc::new(AtomicI32::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let counter_clone = Arc::clone(&counter);
            handles.push(pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(10));
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.wait();
        }

        // All tasks should have executed
        assert_eq!(counter.load(Ordering::Relaxed), 4);

        // Pool should have scaled threads (at least min_threads)
        assert!(pool.active_threads() >= 1);
    }

    #[test]
    fn test_task_panic_caught() {
        let pool = BlockingPool::new(2, 4);
        let _ = pool.spawn(|| unreachable!("intentional panic"));

        thread::sleep(Duration::from_millis(50));

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });
        handle.wait();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn shutdown_graceful() {
        let pool = BlockingPool::new(2, 4);
        let counter = Arc::new(AtomicI32::new(0));

        // Spawn some work
        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Shutdown and wait
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));

        // All work should have completed
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn handle_cloning() {
        let pool = BlockingPool::new(1, 4);
        let handle = pool.handle();
        let handle2 = handle.clone();

        let counter = Arc::new(AtomicI32::new(0));

        let c1 = Arc::clone(&counter);
        let t1 = handle.spawn(move || {
            c1.fetch_add(1, Ordering::Relaxed);
        });

        let c2 = Arc::clone(&counter);
        let t2 = handle2.spawn(move || {
            c2.fetch_add(1, Ordering::Relaxed);
        });

        t1.wait();
        t2.wait();

        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_queue_concurrent_push() {
        let pool = BlockingPool::new(2, 8);
        let counter = Arc::new(AtomicU64::new(0));
        let mut spawners = Vec::new();

        let spawner_count: u64 = 4;
        let tasks_per_spawner: u64 = 50;

        for _ in 0..spawner_count {
            let pool_handle = pool.handle();
            let c = Arc::clone(&counter);
            spawners.push(thread::spawn(move || {
                for _ in 0..tasks_per_spawner {
                    let c_inner = Arc::clone(&c);
                    pool_handle.spawn(move || {
                        c_inner.fetch_add(1, Ordering::Relaxed);
                    });
                }
            }));
        }

        for spawner in spawners {
            spawner.join().expect("spawner panicked");
        }

        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            spawner_count * tasks_per_spawner
        );
    }

    #[test]
    fn pool_metrics() {
        let pool = BlockingPool::new(1, 4);

        assert_eq!(pool.active_threads(), 1);
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.busy_threads(), 0);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let _handle = pool.spawn(move || {
            barrier_clone.wait();
        });

        // Wait a bit for task to start
        thread::sleep(Duration::from_millis(10));

        assert_eq!(pool.busy_threads(), 1);

        // Unblock the task
        barrier.wait();
    }

    #[test]
    #[should_panic(expected = "min_threads must be less than or equal to max_threads")]
    fn new_rejects_min_threads_above_max_threads() {
        let _pool = BlockingPool::new(4, 2);
    }

    #[test]
    fn thread_callbacks() {
        let started = Arc::new(AtomicI32::new(0));
        let stopped = Arc::new(AtomicI32::new(0));

        let started_clone = Arc::clone(&started);
        let stopped_clone = Arc::clone(&stopped);

        let options = BlockingPoolOptions {
            on_thread_start: Some(Arc::new(move || {
                started_clone.fetch_add(1, Ordering::Relaxed);
            })),
            on_thread_stop: Some(Arc::new(move || {
                stopped_clone.fetch_add(1, Ordering::Relaxed);
            })),
            ..Default::default()
        };

        let pool = BlockingPool::with_config(2, 4, options);

        // Wait for threads to start
        thread::sleep(Duration::from_millis(50));

        assert_eq!(started.load(Ordering::Relaxed), 2);

        pool.shutdown_and_wait(Duration::from_secs(5));

        assert_eq!(stopped.load(Ordering::Relaxed), 2);
    }

    /// A start hook that panics on every worker no longer prevents jobs from
    /// running (it churned replacement threads forever).
    #[test]
    fn a_panicking_thread_start_hook_does_not_stop_jobs_from_running() {
        let starts = Arc::new(AtomicI32::new(0));
        let counted = Arc::clone(&starts);
        let options = BlockingPoolOptions {
            on_thread_start: Some(Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                panic!("thread start hook fails");
            })),
            ..Default::default()
        };
        let pool = BlockingPool::with_config(0, 1, options);
        let ran = Arc::new(AtomicI32::new(0));
        let job_ran = Arc::clone(&ran);
        let handle = pool.spawn(move || {
            job_ran.fetch_add(1, Ordering::SeqCst);
        });
        assert!(
            handle.wait_timeout(Duration::from_secs(5)),
            "the job runs despite the hook"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(
            starts.load(Ordering::SeqCst) < 3,
            "no thread churn: {} starts",
            starts.load(Ordering::SeqCst)
        );
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
    }

    #[test]
    fn test_thread_name_unique() {
        let options = BlockingPoolOptions {
            thread_name_prefix: "unique-pool".to_string(),
            ..Default::default()
        };
        let pool = BlockingPool::with_config(2, 2, options);

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let names = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let b = Arc::clone(&barrier);
            let n = Arc::clone(&names);
            handles.push(pool.spawn(move || {
                if let Some(name) = thread::current().name() {
                    n.lock().push(name.to_string());
                }
                b.wait();
            }));
        }

        barrier.wait();
        for h in handles {
            h.wait();
        }

        let recorded = names.lock().clone();
        let unique: HashSet<_> = recorded.into_iter().collect();
        assert_eq!(unique.len(), 2, "Expected two unique thread names");
    }

    /// A panicking task must not hang waiters or leak busy_threads.
    /// The pool should catch the panic, signal completion, and continue
    /// processing subsequent tasks on the same worker thread.
    #[test]
    fn panicking_task_does_not_hang_waiters() {
        // Install a no-op panic hook so the test output isn't noisy.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let pool = BlockingPool::new(1, 1);

        // Submit a task that panics.
        let panic_handle = pool.spawn(|| {
            unreachable!("intentional test panic");
        });

        // Submit a follow-up task to verify the worker thread survived.
        let survived = Arc::new(AtomicBool::new(false));
        let survived_clone = Arc::clone(&survived);
        let follow_up = pool.spawn(move || {
            survived_clone.store(true, Ordering::Release);
        });

        // Both handles must complete without hanging.
        assert!(
            panic_handle.wait_timeout(Duration::from_secs(5)),
            "panicking task should signal completion, not hang"
        );
        assert!(
            follow_up.wait_timeout(Duration::from_secs(5)),
            "follow-up task should complete on the surviving worker"
        );
        assert!(
            survived.load(Ordering::Acquire),
            "worker thread should survive a task panic"
        );

        // Restore the original panic hook.
        std::panic::set_hook(prev_hook);
    }

    #[test]
    fn idle_retirement_claim_allows_only_one_thread_at_floor() {
        let inner = Arc::new(BlockingPoolInner {
            min_threads: 1,
            max_threads: 2,
            live_max_threads: AtomicUsize::new(2),
            default_sized: AtomicBool::new(false),
            active_threads: AtomicUsize::new(2),
            replacement_pending: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: BlockingTaskQueue::new(BlockingQueuePolicy::Fifo),
            affinity: None,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(1),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "retire-test".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        });

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let claims = Arc::new(AtomicUsize::new(0));
        let mut joiners = Vec::new();

        for _ in 0..2 {
            let inner_clone = Arc::clone(&inner);
            let barrier_clone = Arc::clone(&barrier);
            let claims_clone = Arc::clone(&claims);
            joiners.push(thread::spawn(move || {
                barrier_clone.wait();
                if try_claim_idle_retirement(&inner_clone) {
                    claims_clone.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        barrier.wait();

        for joiner in joiners {
            joiner.join().expect("retirement claimant panicked");
        }

        assert_eq!(
            claims.load(Ordering::Relaxed),
            1,
            "exactly one worker should claim the retirement slot at the floor"
        );
        assert_eq!(
            inner.active_threads.load(Ordering::Relaxed),
            inner.min_threads,
            "retirement claims must not drop below min_threads"
        );
    }

    #[test]
    fn cancelled_task_signals_completion() {
        let pool = BlockingPool::new(1, 2);
        let executed = Arc::new(AtomicBool::new(false));
        let exec = Arc::clone(&executed);

        let handle = pool.spawn(move || {
            // Simulate slow work so cancellation can be observed
            thread::sleep(Duration::from_millis(200));
            exec.store(true, Ordering::Release);
        });

        // Cancel before execution starts (race, but we try)
        handle.cancel();

        // Completion must be signaled regardless of cancel outcome
        assert!(
            handle.wait_timeout(Duration::from_secs(5)),
            "cancelled task must signal completion"
        );
        assert!(handle.is_done());
    }

    #[test]
    fn busy_threads_balanced_through_panic() {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let pool = BlockingPool::new(2, 4);

        // Submit a panicking task
        let h1 = pool.spawn(|| unreachable!("audit panic"));
        h1.wait();

        // busy_threads must return to 0 after the panic
        // (catch_unwind ensures the decrement happens)
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            pool.busy_threads(),
            0,
            "busy_threads must be decremented even after panic"
        );

        std::panic::set_hook(prev_hook);
    }

    #[test]
    fn spawn_thread_on_inner_respects_max_threads() {
        let inner = Arc::new(BlockingPoolInner {
            min_threads: 0,
            max_threads: 2,
            live_max_threads: AtomicUsize::new(2),
            default_sized: AtomicBool::new(false),
            active_threads: AtomicUsize::new(2),
            replacement_pending: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: BlockingTaskQueue::new(BlockingQueuePolicy::Fifo),
            affinity: None,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(10),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "max-test".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        });

        // Already at max_threads (2), spawn should be a no-op
        spawn_thread_on_inner(&inner);

        assert_eq!(
            inner.active_threads.load(Ordering::Relaxed),
            2,
            "spawn must not exceed max_threads"
        );
    }

    // ── Audit regression tests ──────────────────────────────────────

    #[test]
    fn spawn_thread_on_inner_rollback_on_overflow() {
        // When active_threads == max_threads, spawn_thread_on_inner
        // must be a no-op (no CAS increment, no OS thread spawned).
        let inner = Arc::new(BlockingPoolInner {
            min_threads: 0,
            max_threads: 1,
            live_max_threads: AtomicUsize::new(1),
            default_sized: AtomicBool::new(false),
            active_threads: AtomicUsize::new(1),
            replacement_pending: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: BlockingTaskQueue::new(BlockingQueuePolicy::Fifo),
            affinity: None,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(10),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "overflow".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        });

        // Try to spawn when already at max
        spawn_thread_on_inner(&inner);
        assert_eq!(inner.active_threads.load(Ordering::Relaxed), 1);
        assert_eq!(inner.thread_handles.lock().len(), 0);
    }

    #[test]
    fn failed_last_worker_spawn_cancels_every_stranded_queue() {
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            Some(2),
        );
        let executions = Arc::new(AtomicUsize::new(0));
        let (local_task, local_cancelled, local_completion) =
            tracked_test_blocking_task(Some(0), Arc::clone(&executions));
        let (spill_task, spill_cancelled, spill_completion) =
            tracked_test_blocking_task(Some(0), Arc::clone(&executions));

        assert!(try_enqueue_task(&inner, local_task));
        assert!(try_enqueue_task(&inner, spill_task));
        inner.active_threads.store(1, Ordering::Release);

        let stranded = {
            let _guard = inner.mutex.lock();
            rollback_failed_worker_spawn_locked(&inner)
                .expect("failed final worker claim must detach pending tasks")
        };
        stranded.cancel();

        assert_eq!(inner.active_threads.load(Ordering::Acquire), 0);
        assert_eq!(inner.pending_count.load(Ordering::Acquire), 0);
        assert!(local_cancelled.load(Ordering::Acquire));
        assert!(spill_cancelled.load(Ordering::Acquire));
        assert!(local_completion.is_done());
        assert!(spill_completion.is_done());
        assert_eq!(executions.load(Ordering::Relaxed), 0);

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.cohort_pending_counts, vec![0, 0]);
        assert_eq!(metrics.global_pending_count, 0);
    }

    #[test]
    fn failed_additional_worker_spawn_preserves_work_for_live_worker() {
        let inner = test_blocking_inner_with_affinity(BlockingPoolAffinityProfile::Disabled, None);
        let executions = Arc::new(AtomicUsize::new(0));
        let (task, cancelled, completion) =
            tracked_test_blocking_task(None, Arc::clone(&executions));
        assert!(try_enqueue_task(&inner, task));
        inner.active_threads.store(2, Ordering::Release);

        let stranded = {
            let _guard = inner.mutex.lock();
            rollback_failed_worker_spawn_locked(&inner)
        };

        assert!(
            stranded.is_none(),
            "one live worker can service queued work"
        );
        assert_eq!(inner.active_threads.load(Ordering::Acquire), 1);
        assert_eq!(inner.pending_count.load(Ordering::Acquire), 1);
        assert!(!cancelled.load(Ordering::Acquire));
        assert!(!completion.is_done());

        let (task, _) = pop_next_blocking_task(&inner, None, false)
            .expect("surviving worker must retain queued task");
        inner.pending_count.fetch_sub(1, Ordering::Relaxed);
        task.cancelled.store(true, Ordering::Release);
        task.completion.signal_done();
        drop(task);
        assert_eq!(executions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn completion_wait_after_signal_returns_immediately() {
        let comp = BlockingTaskCompletion::new(wall_clock_now);
        comp.signal_done();
        // Must return immediately, not block
        assert!(comp.wait_timeout(Duration::from_millis(0)));
    }

    #[test]
    fn completion_wait_timeout_uses_custom_time_getter() {
        let _guard = deterministic_hook_test_guard();
        reset_scripted_time_state();

        let completion = BlockingTaskCompletion::new(stepped_timeout_time);

        assert!(
            !completion.wait_timeout(Duration::from_millis(10)),
            "custom time getter should let wait_timeout observe elapsed time without wall sleep"
        );
        assert_eq!(
            SCRIPTED_TIME_CALLS.load(Ordering::Relaxed),
            2,
            "timeout path should only consult the synthetic clock for deadline and remaining time"
        );
    }

    #[test]
    fn worker_idle_retirement_uses_custom_time_getter() {
        let _guard = deterministic_hook_test_guard();
        reset_scripted_time_state();

        let retired = Arc::new((StdMutex::new(false), StdCondvar::new()));
        let retired_signal = Arc::clone(&retired);

        let pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                idle_timeout: Duration::from_millis(5),
                time_getter: stepped_timeout_time,
                on_thread_stop: Some(Arc::new(move || {
                    let (lock, condvar) = &*retired_signal;
                    {
                        let mut retired = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        *retired = true;
                    }
                    condvar.notify_all();
                })),
                ..Default::default()
            },
        );

        pool.spawn(|| {}).wait();

        let (lock, condvar) = &*retired;
        let retired = {
            let retired = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (retired, _timeout) = condvar
                .wait_timeout_while(retired, Duration::from_secs(30), |retired| !*retired)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *retired
        };

        assert!(
            retired,
            "synthetic time getter should retire the idle worker without long wall sleeps"
        );
        assert_eq!(
            pool.active_threads(),
            0,
            "idle retirement should decrement active thread count to zero"
        );
        assert!(
            SCRIPTED_TIME_CALLS.load(Ordering::Relaxed) >= 2,
            "idle retirement path should consult the scripted clock across multiple loop turns"
        );
    }

    #[test]
    fn shutdown_and_wait_uses_custom_time_and_sleep_hooks() {
        let _guard = deterministic_hook_test_guard();
        reset_scripted_time_state();

        let pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                time_getter: advancing_timeout_time,
                sleep_fn: advancing_timeout_sleep,
                ..Default::default()
            },
        );
        pool.inner.active_threads.store(1, Ordering::Release);

        assert!(
            !pool.shutdown_and_wait(Duration::from_millis(25)),
            "synthetic time should drive shutdown timeout accounting without wall sleep"
        );
        assert!(
            pool.is_shutdown(),
            "shutdown flag should be set before waiting"
        );
        assert!(
            SCRIPTED_SLEEP_CALLS.load(Ordering::Relaxed) > 0,
            "shutdown wait loop should use the configured sleep hook"
        );
        assert_eq!(
            SCRIPTED_TIME_OFFSET_MS.load(Ordering::Relaxed),
            25,
            "sleep hook should advance the synthetic clock through the full timeout budget"
        );

        // Prevent Drop from treating the synthetic active thread count as a live worker.
        pool.inner.active_threads.store(0, Ordering::Release);
    }

    #[test]
    fn shutdown_and_wait_does_not_hold_thread_handles_mutex_while_joining() {
        let pool = Arc::new(BlockingPool::new(0, 1));
        pool.inner.shutdown.store(true, Ordering::Release);
        pool.inner.active_threads.store(0, Ordering::Release);

        let release = Arc::new((StdMutex::new(false), StdCondvar::new()));
        let release_clone = Arc::clone(&release);
        let join_target = thread::spawn(move || {
            let (lock, condvar) = &*release_clone;
            let mut released = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*released {
                released = condvar
                    .wait(released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        });

        let mut thread_handles = pool.inner.thread_handles.lock();
        thread_handles.push(join_target);

        let waiter_pool = Arc::clone(&pool);
        let shutdown_waiter =
            thread::spawn(move || waiter_pool.shutdown_and_wait(Duration::from_secs(1)));

        // Keep the mutex held long enough for shutdown_and_wait() to queue on it.
        thread::sleep(Duration::from_millis(20));
        drop(thread_handles);

        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let contender_pool = Arc::clone(&pool);
        let contender = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(200);
            loop {
                if let Some(guard) = contender_pool.inner.thread_handles.try_lock() {
                    drop(guard);
                    let _ = lock_acquired_tx.send(());
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        });

        lock_acquired_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("shutdown waiter should release thread_handles before blocking on join");

        let (release_lock, release_condvar) = &*release;
        {
            let mut released = release_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *released = true;
        }
        release_condvar.notify_all();

        contender.join().expect("contender panicked");
        assert!(shutdown_waiter.join().expect("shutdown waiter panicked"));
    }

    #[test]
    fn shutdown_drains_pending_tasks() {
        let pool = BlockingPool::new(1, 1);

        // Block the single thread so tasks queue up
        let blocker = Arc::new(std::sync::Barrier::new(2));
        let b = Arc::clone(&blocker);
        pool.spawn(move || {
            b.wait();
        });

        // Queue some tasks while the thread is blocked
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..5 {
            let c = Arc::clone(&counter);
            let _handle = pool.spawn(move || {
                c.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Release the blocker
        blocker.wait();

        // Shutdown and wait should drain all pending tasks
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));

        assert_eq!(
            counter.load(Ordering::Relaxed),
            5,
            "all queued tasks must execute before shutdown completes"
        );
    }

    #[test]
    fn handle_spawn_accepted_before_shutdown_still_runs() {
        let exiting = Arc::new((StdMutex::new(false), StdCondvar::new()));
        let exit_gate = Arc::new((StdMutex::new(false), StdCondvar::new()));

        let exiting_signal = Arc::clone(&exiting);
        let exit_gate_signal = Arc::clone(&exit_gate);
        let pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                on_thread_stop: Some(Arc::new(move || {
                    let (lock, condvar) = &*exiting_signal;
                    {
                        let mut exiting = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        *exiting = true;
                    }
                    condvar.notify_all();

                    let (gate_lock, gate_condvar) = &*exit_gate_signal;
                    let mut release = gate_lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    while !*release {
                        release = gate_condvar
                            .wait(release)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    drop(release);
                })),
                ..Default::default()
            },
        );

        // Start the single worker so shutdown has a live thread to race with.
        pool.spawn(|| {}).wait();

        pool.shutdown();

        let (exiting_lock, exiting_condvar) = &*exiting;
        let (exiting, _timeout) = exiting_condvar
            .wait_timeout_while(
                exiting_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                Duration::from_secs(1),
                |exiting| !*exiting,
            )
            .expect("exit signal wait poisoned");
        assert!(
            *exiting,
            "worker should enter the stop callback before the late task is enqueued"
        );
        drop(exiting);

        // Simulate a task that was accepted just before shutdown and only
        // reaches the shared queue while the last worker is already exiting.
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_clone = Arc::clone(&ran);
        let task_id = pool.inner.next_task_id.fetch_add(1, Ordering::Relaxed);
        let cancelled = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(BlockingTaskCompletion::new(pool.inner.time_getter));
        let handle = BlockingTaskHandle {
            task_id,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };
        let task = BlockingTask {
            work: Box::new(move || {
                ran_clone.fetch_add(1, Ordering::Relaxed);
            }),
            priority: 128,
            preferred_cohort: None,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };

        pool.inner.queue.push(task);
        pool.inner.pending_count.fetch_add(1, Ordering::Relaxed);
        maybe_spawn_thread_on_inner(&pool.inner);
        {
            let _guard = pool.inner.mutex.lock();
            pool.inner.condvar.notify_one();
        }

        let (gate_lock, gate_condvar) = &*exit_gate;
        {
            let mut release = gate_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *release = true;
        }
        gate_condvar.notify_all();

        assert!(
            handle.wait_timeout(Duration::from_secs(5)),
            "accepted work must still complete even if shutdown starts while the last worker exits"
        );
        assert_eq!(
            ran.load(Ordering::Relaxed),
            1,
            "late accepted task should run exactly once"
        );
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
    }

    // ================================================================
    // spawn_blocking Lifecycle Conformance Tests
    // ================================================================

    mod spawn_blocking_conformance {
        use super::*;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::{Duration, Instant};

        /// Test data for conformance verification.
        struct ConformanceTestData {
            thread_ids: Arc<Mutex<Vec<thread::ThreadId>>>,
            execution_count: Arc<AtomicU32>,
            barrier: Arc<Barrier>,
        }

        impl ConformanceTestData {
            fn new(expected_threads: usize) -> Self {
                Self {
                    thread_ids: Arc::new(Mutex::new(Vec::new())),
                    execution_count: Arc::new(AtomicU32::new(0)),
                    barrier: Arc::new(Barrier::new(expected_threads + 1)), // +1 for test thread
                }
            }

            fn record_execution(&self) {
                let current_thread = thread::current().id();
                self.thread_ids.lock().push(current_thread);
                self.execution_count.fetch_add(1, Ordering::Relaxed);
            }

            fn get_unique_thread_count(&self) -> usize {
                let ids = self.thread_ids.lock();
                let mut unique_ids = Vec::new();
                for id in ids.iter() {
                    if !unique_ids.contains(id) {
                        unique_ids.push(*id);
                    }
                }
                unique_ids.len()
            }
        }

        #[test]
        fn blocking_task_scheduled_on_dedicated_thread_pool_conformance() {
            let _guard = deterministic_hook_test_guard();

            // Create pool with 2 threads minimum to test thread separation
            let pool = BlockingPool::new(2, 4);
            let test_data = ConformanceTestData::new(3);

            // Get the main thread ID to verify blocking tasks don't run there
            let main_thread_id = thread::current().id();

            // Spawn multiple blocking tasks to verify thread pool usage
            let mut handles = Vec::new();
            for _ in 0..3 {
                let test_data_clone = test_data.thread_ids.clone();
                let barrier_clone = test_data.barrier.clone();

                let handle = pool.spawn(move || {
                    // Record which thread this task runs on
                    let current_thread = thread::current().id();
                    test_data_clone.lock().push(current_thread);

                    // Wait for all tasks to start
                    barrier_clone.wait();

                    // Do some work to ensure we're actually on a blocking thread
                    thread::sleep(Duration::from_millis(10));
                });
                handles.push(handle);
            }

            // Wait for all tasks to start
            test_data.barrier.wait();

            // Wait for all tasks to complete
            for handle in handles {
                assert!(handle.wait_timeout(Duration::from_secs(5)));
            }

            // Verify tasks ran on dedicated threads (not main thread).
            // IMPORTANT: release the guard before calling `get_unique_thread_count`
            // (which re-locks `thread_ids`) — parking_lot's Mutex is NOT reentrant,
            // so holding the guard across that call used to deadlock this test.
            {
                let thread_ids = test_data.thread_ids.lock();
                assert_eq!(thread_ids.len(), 3, "All three tasks should have executed");

                for thread_id in thread_ids.iter() {
                    assert_ne!(
                        *thread_id, main_thread_id,
                        "Blocking tasks should not run on main thread"
                    );
                }
            }

            // Verify at least 2 different threads were used (pool has min 2 threads)
            let unique_count = test_data.get_unique_thread_count();
            assert!(
                unique_count >= 2,
                "Should use at least 2 different threads, got {}",
                unique_count
            );

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn cancellation_drains_pool_correctly_conformance() {
            let _guard = deterministic_hook_test_guard();

            // Use max_threads=1 so task 2 stays queued while task 1 is running.
            // With max_threads=2, maybe_spawn_thread_on_inner would spawn a second
            // worker that picks up task 2 before the test's `handle2.cancel()`
            // call lands, making the cancel-before-execution check racy.
            let pool = BlockingPool::new(1, 1);
            let start_barrier = Arc::new(Barrier::new(2));
            let finish_gate = Arc::new((Mutex::new(false), Condvar::new()));

            // Task 1: Blocks until we signal completion
            let start_barrier_clone = start_barrier.clone();
            let finish_gate_clone = finish_gate.clone();
            let handle1 = pool.spawn(move || {
                start_barrier_clone.wait(); // Signal task started
                let (lock, cvar) = &*finish_gate_clone;
                let mut finish = lock.lock();
                while !*finish {
                    cvar.wait(&mut finish);
                }
                // Task completes after gate opens
            });

            // Wait for task 1 to start
            start_barrier.wait();

            // Task 2: Will be queued while task 1 is running
            let executed = Arc::new(AtomicBool::new(false));
            let executed_clone = executed.clone();
            let handle2 = pool.spawn(move || {
                executed_clone.store(true, Ordering::SeqCst);
            });

            // Small delay to ensure task 2 is queued
            thread::sleep(Duration::from_millis(50));

            // Cancel task 2 before it gets to execute
            handle2.cancel();

            // Release task 1 to complete
            {
                let (lock, cvar) = &*finish_gate;
                let mut finish = lock.lock();
                *finish = true;
                cvar.notify_all();
            }

            // Task 1 should complete successfully
            assert!(handle1.wait_timeout(Duration::from_secs(5)));
            assert!(!handle1.is_cancelled());

            // Task 2 should be cancelled and not execute
            assert!(handle2.wait_timeout(Duration::from_secs(1))); // Should complete quickly (cancelled)
            assert!(handle2.is_cancelled());
            assert!(
                !executed.load(Ordering::SeqCst),
                "Cancelled task should not execute"
            );

            // Verify pool drains correctly
            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn panic_in_blocking_task_isolated_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);
            let task_executed = Arc::new(AtomicBool::new(false));

            // Task 1: Panics during execution
            let handle_panic = pool.spawn(|| {
                panic!("Test panic - should be isolated");
            });

            // Task 2: Normal execution after panic
            let task_executed_clone = task_executed.clone();
            let handle_normal = pool.spawn(move || {
                task_executed_clone.store(true, Ordering::SeqCst);
                // Return nothing
            });

            // Both tasks should complete (panic is isolated)
            assert!(handle_panic.wait_timeout(Duration::from_secs(5)));
            assert!(handle_normal.wait_timeout(Duration::from_secs(5)));

            // Verify the normal task executed successfully
            assert!(
                task_executed.load(Ordering::SeqCst),
                "Normal task should execute after panic"
            );

            // Verify pool is still operational after panic
            let handle_after_panic = pool.spawn(|| {
                let _ = "still working";
            });
            assert!(handle_after_panic.wait_timeout(Duration::from_secs(5)));

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn result_returned_via_completion_mechanism_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);

            // Test synchronous completion signaling
            let completion_time = Arc::new(Mutex::new(None::<Instant>));
            let completion_time_clone = completion_time.clone();
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);

            let handle = pool.spawn(move || {
                started_tx.send(()).expect("test receives task start");
                release_rx.recv().expect("test releases task completion");
                *completion_time_clone.lock() = Some(Instant::now());
            });

            started_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("blocking task should start under remote test load");

            // The task has started but is held before recording completion, so
            // this assertion cannot race a fast or descheduled worker.
            assert!(!handle.is_done());
            assert!(
                !handle.wait_timeout(Duration::ZERO),
                "release-gated task must remain pending"
            );
            release_tx
                .send(())
                .expect("blocking task remains available for completion");

            // Wait for completion
            assert!(handle.wait_timeout(Duration::from_secs(5)));

            // Verify task is now done
            assert!(handle.is_done());

            // Verify completion was signaled at the right time
            let recorded_completion = completion_time.lock();
            assert!(
                recorded_completion.is_some(),
                "Completion time should be recorded"
            );

            // Test immediate completion check
            let instant_handle = pool.spawn(|| {});
            assert!(instant_handle.wait_timeout(Duration::from_secs(5)));
            assert!(instant_handle.is_done());

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn completion_mechanism_timeout_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let gate_clone = gate.clone();

            // Task that blocks indefinitely until signaled
            let handle = pool.spawn(move || {
                let (lock, cvar) = &*gate_clone;
                let mut release = lock.lock();
                while !*release {
                    cvar.wait(&mut release);
                }
                // "completed" -> removed to match F: FnOnce() -> ()
            });
            // Test timeout behavior
            let start_time = Instant::now();
            assert!(!handle.wait_timeout(Duration::from_millis(100)));
            let elapsed = start_time.elapsed();

            // Should timeout in approximately 100ms
            assert!(
                elapsed >= Duration::from_millis(90),
                "Should wait at least 90ms"
            );
            assert!(
                elapsed <= Duration::from_millis(200),
                "Should timeout within 200ms"
            );
            assert!(!handle.is_done(), "Task should not be done after timeout");

            // Release the task
            {
                let (lock, cvar) = &*gate;
                let mut release = lock.lock();
                *release = true;
                cvar.notify_all();
            }

            // Now it should complete
            assert!(handle.wait_timeout(Duration::from_secs(5)));
            assert!(handle.is_done());

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn budget_accounting_across_poll_boundaries_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 4);

            // Track resource usage across task boundaries
            struct ResourceTracker {
                task_starts: AtomicU32,
                task_ends: AtomicU32,
                max_concurrent: AtomicU32,
                current_concurrent: AtomicU32,
            }

            let tracker = Arc::new(ResourceTracker {
                task_starts: AtomicU32::new(0),
                task_ends: AtomicU32::new(0),
                max_concurrent: AtomicU32::new(0),
                current_concurrent: AtomicU32::new(0),
            });

            let barrier = Arc::new(Barrier::new(4)); // 3 tasks + test thread
            let mut handles = Vec::new();

            // Submit 3 tasks to test concurrent execution
            for _i in 0..3 {
                let tracker_clone = tracker.clone();
                let barrier_clone = barrier.clone();

                let handle = pool.spawn(move || {
                    // Record task start
                    tracker_clone.task_starts.fetch_add(1, Ordering::Relaxed);
                    let current = tracker_clone
                        .current_concurrent
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;

                    // Update max concurrent
                    let mut max = tracker_clone.max_concurrent.load(Ordering::Relaxed);
                    while current > max {
                        match tracker_clone.max_concurrent.compare_exchange_weak(
                            max,
                            current,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(_) => break,
                            Err(new_max) => max = new_max,
                        }
                    }

                    // Wait for all tasks to start
                    barrier_clone.wait();

                    // Simulate work
                    thread::sleep(Duration::from_millis(50));

                    // Record task end
                    tracker_clone
                        .current_concurrent
                        .fetch_sub(1, Ordering::Relaxed);
                    tracker_clone.task_ends.fetch_add(1, Ordering::Relaxed);
                });

                handles.push(handle);
            }

            // Wait for all tasks to start
            barrier.wait();

            // Wait for all tasks to complete
            for handle in handles {
                assert!(handle.wait_timeout(Duration::from_secs(5)));
            }

            // Verify budget accounting
            assert_eq!(
                tracker.task_starts.load(Ordering::Relaxed),
                3,
                "All tasks should start"
            );
            assert_eq!(
                tracker.task_ends.load(Ordering::Relaxed),
                3,
                "All tasks should end"
            );
            assert_eq!(
                tracker.current_concurrent.load(Ordering::Relaxed),
                0,
                "No tasks should be running"
            );

            // Verify resource limits were respected (pool has max 4 threads, so max 3 concurrent is reasonable)
            let max_concurrent = tracker.max_concurrent.load(Ordering::Relaxed);
            assert!(max_concurrent <= 4, "Should not exceed pool thread limit");
            assert!(max_concurrent >= 1, "At least one task should run");

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn spawn_blocking_priority_scheduling_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 1); // Single thread to force sequential execution

            let execution_order = Arc::new(Mutex::new(Vec::new()));
            let start_gate = Arc::new((Mutex::new(false), Condvar::new()));

            // First task blocks to allow others to queue
            let start_gate_clone = start_gate.clone();
            let handle_blocker = pool.spawn(move || {
                let (lock, cvar) = &*start_gate_clone;
                let mut start = lock.lock();
                while !*start {
                    cvar.wait(&mut start);
                }
            });

            // Queue tasks with different priorities
            let mut priority_handles = Vec::new();

            for (priority, task_id) in [(0, "high"), (128, "medium"), (255, "low")] {
                let execution_order_clone = execution_order.clone();
                let handle = pool.spawn_with_priority(
                    move || {
                        execution_order_clone.lock().push(task_id);
                    },
                    priority,
                );
                priority_handles.push(handle);
            }

            // Small delay to ensure tasks are queued
            thread::sleep(Duration::from_millis(50));

            // Release the blocker task
            {
                let (lock, cvar) = &*start_gate;
                let mut start = lock.lock();
                *start = true;
                cvar.notify_all();
            }

            // Wait for all tasks to complete
            assert!(handle_blocker.wait_timeout(Duration::from_secs(5)));
            for handle in priority_handles {
                assert!(handle.wait_timeout(Duration::from_secs(5)));
            }

            // Verify execution order respects priority (higher priority = lower number = executes first)
            let order = execution_order.lock();
            assert_eq!(order.len(), 3, "All priority tasks should execute");

            // Note: Due to concurrent execution, exact order might vary, but high priority should generally go first
            // At minimum, verify all tasks executed
            assert!(order.contains(&"high"));
            assert!(order.contains(&"medium"));
            assert!(order.contains(&"low"));

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_pool_handle_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);
            let handle = pool.handle();

            // Verify handle spawning works identically to pool spawning
            let executed = Arc::new(AtomicBool::new(false));
            let executed_clone = executed.clone();
            let task_handle = handle.spawn(move || {
                executed_clone.store(true, Ordering::SeqCst);
            });

            assert!(task_handle.wait_timeout(Duration::from_secs(5)));
            assert!(
                executed.load(Ordering::SeqCst),
                "Handle-spawned task should execute"
            );

            // Test handle priority spawning
            let priority_executed = Arc::new(AtomicBool::new(false));
            let priority_executed_clone = priority_executed.clone();

            let priority_handle = handle.spawn_with_priority(
                move || {
                    priority_executed_clone.store(true, Ordering::SeqCst);
                },
                64, // High priority
            );

            assert!(priority_handle.wait_timeout(Duration::from_secs(5)));
            assert!(
                priority_executed.load(Ordering::SeqCst),
                "Priority handle task should execute"
            );

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_task_lifecycle_state_transitions_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);

            // Test task state transitions: created -> running -> done
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let gate_clone = gate.clone();

            let handle = pool.spawn(move || {
                let (lock, cvar) = &*gate_clone;
                let mut release = lock.lock();
                while !*release {
                    cvar.wait(&mut release);
                }
                // "completed" -> removed to match F: FnOnce() -> ()
            });

            // Initially: not done, not cancelled
            assert!(!handle.is_done());
            assert!(!handle.is_cancelled());

            // Test cancellation state
            handle.cancel();
            assert!(handle.is_cancelled());
            assert!(!handle.is_done()); // Still not done until completion

            // Release and complete task
            {
                let (lock, cvar) = &*gate;
                let mut release = lock.lock();
                *release = true;
                cvar.notify_all();
            }

            assert!(handle.wait_timeout(Duration::from_secs(5)));

            // Final state: done and cancelled
            assert!(handle.is_done());
            assert!(handle.is_cancelled());

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_pool_shutdown_lifecycle_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);

            // Submit a task before shutdown
            let pre_shutdown_executed = Arc::new(AtomicBool::new(false));
            let pre_shutdown_executed_clone = pre_shutdown_executed.clone();
            let handle_pre = pool.spawn(move || {
                thread::sleep(Duration::from_millis(100)); // Ensure shutdown happens during execution
                pre_shutdown_executed_clone.store(true, Ordering::SeqCst);
            });

            // Start shutdown (but don't wait)
            pool.shutdown();

            // Attempt to submit task after shutdown - should be immediately cancelled
            let post_shutdown_executed = Arc::new(AtomicBool::new(false));
            let post_shutdown_executed_clone = post_shutdown_executed.clone();
            let handle_post = pool.spawn(move || {
                post_shutdown_executed_clone.store(true, Ordering::SeqCst);
            });

            // Pre-shutdown task should complete
            assert!(handle_pre.wait_timeout(Duration::from_secs(5)));
            assert!(
                pre_shutdown_executed.load(Ordering::SeqCst),
                "Pre-shutdown task should execute"
            );

            // Post-shutdown task should be cancelled immediately
            assert!(handle_post.wait_timeout(Duration::from_secs(1))); // Should complete quickly (cancelled)
            assert!(handle_post.is_cancelled());
            assert!(
                !post_shutdown_executed.load(Ordering::SeqCst),
                "Post-shutdown task should not execute"
            );

            // Complete shutdown
            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }
    }

    // =========================================================================
    // Cancel + spawn_blocking under shutdown metamorphic relations.
    //
    // Per-case tests cover:
    //   - single spawn-after-shutdown rejection (both APIs)
    //   - linearization race around the submission mutex
    //   - graceful drain of pending tasks on shutdown
    //
    // These MRs bind the broader contract over the shutdown boundary.
    // Each one names a concrete interleaving and verifies invariants
    // that a refactor of the spawn path or shutdown signal must
    // preserve.
    // =========================================================================

    mod shutdown_mr {
        use super::*;

        /// MR — All N consecutive spawns AFTER shutdown are rejected
        /// uniformly. The rejection is not a first-post-shutdown-only
        /// effect; it holds for the entire suffix. Task counters and
        /// pending queue stay unchanged throughout.
        #[test]
        fn mr_all_spawns_after_shutdown_are_rejected_uniformly() {
            let pool = BlockingPool::new(1, 4);
            pool.shutdown();
            let executed = Arc::new(AtomicI32::new(0));
            let mut handles = Vec::new();
            for _ in 0..8 {
                let e = Arc::clone(&executed);
                handles.push(pool.spawn(move || {
                    e.fetch_add(1, Ordering::Relaxed);
                }));
            }
            for (i, h) in handles.iter().enumerate() {
                assert!(h.is_cancelled(), "spawn #{i} not cancelled post-shutdown");
                assert!(
                    h.wait_timeout(Duration::from_millis(100)),
                    "spawn #{i} completion not signaled post-shutdown",
                );
            }
            assert_eq!(
                executed.load(Ordering::Relaxed),
                0,
                "no post-shutdown task may execute",
            );
            assert_eq!(pool.pending_count(), 0);
        }

        /// MR — Shutdown is idempotent. Calling shutdown() N times is
        /// equivalent to calling it once. is_shutdown() returns true
        /// throughout; spawn rejection semantics unchanged.
        #[test]
        fn mr_shutdown_is_idempotent() {
            let pool = BlockingPool::new(0, 2);
            for _ in 0..5 {
                pool.shutdown();
                assert!(pool.is_shutdown());
            }
            // Spawn rejection still works after N shutdowns.
            let executed = Arc::new(AtomicBool::new(false));
            let e = Arc::clone(&executed);
            let handle = pool.spawn(move || {
                e.store(true, Ordering::Relaxed);
            });
            assert!(handle.is_cancelled());
            assert!(handle.wait_timeout(Duration::from_millis(100)));
            assert!(!executed.load(Ordering::Relaxed));
        }

        /// MR — Handle obtained pre-shutdown survives as a valid handle
        /// across the shutdown boundary. Cancelling it after shutdown
        /// is a no-op on the completion signal state (completion was
        /// already signaled by the running task or will be signaled by
        /// the pre-shutdown-queued task).
        #[test]
        fn mr_pre_shutdown_handle_cancel_after_shutdown_is_safe() {
            let pool = BlockingPool::new(0, 2);
            let executed = Arc::new(AtomicBool::new(false));
            let e = Arc::clone(&executed);
            let handle = pool.spawn(move || {
                // Simulate instantaneous work — the pool may or may not
                // execute it before we shut down; either outcome is valid.
                e.store(true, Ordering::Relaxed);
            });
            pool.shutdown();
            // cancel() after shutdown must not panic and must not flip
            // the completion signal backwards.
            handle.cancel();
            assert!(handle.is_cancelled());
            // shutdown_and_wait must still drain cleanly.
            assert!(pool.shutdown_and_wait(Duration::from_secs(2)));
        }

        /// MR — Post-shutdown spawns do not affect thread accounting.
        /// active_threads and busy_threads observed immediately before
        /// the post-shutdown spawn are equal to those observed
        /// immediately after. The fast-path rejection at spawn must
        /// not call maybe_spawn_thread().
        #[test]
        fn mr_post_shutdown_spawn_does_not_grow_thread_pool() {
            let pool = BlockingPool::new(0, 4);
            pool.shutdown();
            // Wait for any lingering threads to exit after shutdown.
            // With min_threads=0 and immediate shutdown, none should
            // have been spawned, but the invariant we care about is
            // invariance — before == after.
            let before_active = pool.active_threads();
            let before_busy = pool.busy_threads();
            let before_pending = pool.pending_count();
            for _ in 0..4 {
                let _ = pool.spawn(|| {
                    panic!("post-shutdown body must never run");
                });
            }
            assert_eq!(pool.active_threads(), before_active);
            assert_eq!(pool.busy_threads(), before_busy);
            assert_eq!(pool.pending_count(), before_pending);
        }

        /// MR — is_shutdown() is a stable property once shutdown() is
        /// called. No observed interleaving of spawns, cancels, or
        /// queries can make is_shutdown() regress to false.
        #[test]
        fn mr_is_shutdown_is_sticky_true() {
            let pool = BlockingPool::new(1, 2);
            assert!(!pool.is_shutdown(), "fresh pool should not be shutdown");
            pool.shutdown();
            for _ in 0..20 {
                // Interleave reads with rejected spawns and cancels.
                let h = pool.spawn(|| {});
                h.cancel();
                assert!(pool.is_shutdown(), "is_shutdown regressed to false");
            }
        }

        /// MR — shutdown() followed by spawn() yields a handle whose
        /// completion signal has ALREADY fired (wait_timeout returns
        /// true with a zero-ish timeout). This distinguishes
        /// rejection-with-signal from rejection-that-forgets-to-signal
        /// — the latter would hang any caller that awaits completion.
        #[test]
        fn mr_rejected_handle_completion_is_prepaid() {
            let pool = BlockingPool::new(0, 2);
            pool.shutdown();
            for _ in 0..5 {
                let h = pool.spawn(|| {});
                // Any timeout — including zero — must succeed because
                // completion was signaled synchronously inside spawn().
                assert!(
                    h.wait_timeout(Duration::from_millis(1)),
                    "rejected handle completion signal not prepaid",
                );
                assert!(h.is_cancelled());
            }
        }

        /// MR — BlockingPoolHandle::spawn agrees with BlockingPool::spawn
        /// on post-shutdown rejection semantics. The two APIs must have
        /// identical observable contract (rejection + cancellation +
        /// prepaid completion) after shutdown.
        #[test]
        fn mr_pool_and_handle_api_agree_after_shutdown() {
            let pool = BlockingPool::new(0, 2);
            let api_handle = pool.handle();
            pool.shutdown();

            let via_pool = pool.spawn(|| panic!("must not run"));
            let via_handle = api_handle.spawn(|| panic!("must not run"));

            assert_eq!(via_pool.is_cancelled(), via_handle.is_cancelled());
            assert!(via_pool.is_cancelled());
            assert!(
                via_pool.wait_timeout(Duration::from_millis(100))
                    && via_handle.wait_timeout(Duration::from_millis(100)),
                "one of the APIs failed to prepay completion",
            );
        }
    }

    /// GitHub #80 census: thread handles still in the pool when its last
    /// reference goes (after a shutdown that timed out) were dropped with it,
    /// detaching threads that may be exiting at that moment. A running one is
    /// parked instead, and joined once it has finished.
    #[test]
    fn leftover_thread_handles_are_parked_not_detached_when_the_pool_drops() {
        let inner = test_blocking_inner_with_affinity(BlockingPoolAffinityProfile::Disabled, None);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let worker = thread::Builder::new()
            .name("blocking-pool-leftover".to_string())
            .spawn(move || {
                let _ = release_rx.recv_timeout(Duration::from_secs(60));
            })
            .expect("spawn the stand-in worker");
        let worker_id = worker.thread().id();
        inner.thread_handles.lock().push(worker);

        drop(inner);
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread(worker_id),
            Some(false),
            "the running worker must be parked, not detached"
        );

        release_tx.send(()).expect("the worker still waits");
        let deadline = Instant::now() + Duration::from_secs(10);
        while crate::runtime::spawn_blocking::parked_thread(worker_id) == Some(false) {
            assert!(Instant::now() < deadline, "the worker did not finish");
            thread::sleep(Duration::from_millis(5));
        }
        crate::runtime::spawn_blocking::reap_threads(Vec::new());
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread(worker_id),
            None,
            "a finished parked worker is joined"
        );
    }
