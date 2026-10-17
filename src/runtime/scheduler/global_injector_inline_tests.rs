    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Instant;

    thread_local! {
        static READY_PUBLICATION_HOOK: std::cell::RefCell<
            Option<Box<dyn FnMut(&GlobalInjector)>>,
        > = const { std::cell::RefCell::new(None) };
    }

    struct ReadyPublicationHook;

    impl Drop for ReadyPublicationHook {
        fn drop(&mut self) {
            let hook = READY_PUBLICATION_HOOK.with(|slot| slot.borrow_mut().take());
            drop(hook);
        }
    }

    fn on_ready_publication(hook: impl FnMut(&GlobalInjector) + 'static) -> ReadyPublicationHook {
        READY_PUBLICATION_HOOK.with(|slot| {
            assert!(slot.borrow().is_none(), "one publication observer per thread");
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        ReadyPublicationHook
    }

    pub(super) fn observe_ready_combiner_publication(injector: &GlobalInjector) {
        // Observe the first actual enqueue of each batch, while a reserved
        // suffix can still be unpublished. Retire the RefCell borrow before
        // callbacks: a successor may publish reentrantly, but only the outer
        // tenure invokes this hook.
        let hook = READY_PUBLICATION_HOOK
            .try_with(|slot| slot.borrow_mut().take())
            .ok()
            .flatten();
        if let Some(mut hook) = hook {
            hook(injector);
            READY_PUBLICATION_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
        }
    }

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(1, id)
    }

    fn contention_task(producer: usize, offset: usize) -> TaskId {
        TaskId::new_for_test(
            u32::try_from(producer + 10).expect("producer id should fit in u32"),
            u32::try_from(offset).expect("task offset should fit in u32"),
        )
    }

    fn run_ready_combiner_contention_case(
        producers: usize,
        items_per_producer: usize,
    ) -> ReadyCombinerSnapshot {
        let injector = Arc::new(GlobalInjector::new());
        let barrier = Arc::new(Barrier::new(producers));
        let max_enqueue_tail_ns = Arc::new(AtomicU64::new(0));
        let start = Instant::now();

        let handles = (0..producers)
            .map(|producer| {
                let injector = Arc::clone(&injector);
                let barrier = Arc::clone(&barrier);
                let max_enqueue_tail_ns = Arc::clone(&max_enqueue_tail_ns);

                thread::spawn(move || {
                    barrier.wait();
                    for offset in 0..items_per_producer {
                        let enqueue_start = Instant::now();
                        injector.inject_ready(contention_task(producer, offset), 50);
                        let elapsed_ns =
                            u64::try_from(enqueue_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                        max_enqueue_tail_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
                    }
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle
                .join()
                .expect("ready combiner producer should complete");
        }

        let mut seen = HashSet::new();
        while let Some(task) = injector.pop_ready() {
            assert!(
                seen.insert(task.task),
                "ready combiner scenario must not double-enqueue task {:?}",
                task.task
            );
        }

        let total_items = producers * items_per_producer;
        assert_eq!(
            seen.len(),
            total_items,
            "ready combiner scenario must not lose tasks"
        );

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(
            snapshot.direct_injections
                + snapshot.fallback_injections
                + snapshot.combined_injections,
            total_items,
            "direct + fallback + combined publications must account for every injected task"
        );
        assert_eq!(
            snapshot.mode_entries, snapshot.mode_exits,
            "combining mode should not remain active after producers finish"
        );
        assert_eq!(
            snapshot.pending_len, 0,
            "combiner pending buffer should drain completely"
        );
        assert_eq!(snapshot.ready_len, 0, "ready queue should drain completely");
        assert_eq!(
            snapshot.current_in_flight, 0,
            "ready injection in-flight count should converge to zero"
        );
        assert!(snapshot.max_batch <= READY_COMBINER_MAX_BATCH);
        assert!(
            snapshot.flushes <= snapshot.mode_entries * 2,
            "each combiner tenure publishes at most two bounded batches"
        );

        println!(
            "READY_COMBINER_SCENARIO producers={producers} items_per_producer={items_per_producer} total_items={total_items} elapsed_ns={} max_enqueue_tail_ns={} direct_injections={} deferred_injections={} combined_injections={} fallback_injections={} combiner_claim_failures={} mode_entries={} mode_exits={} mode_switches={} flushes={} max_batch={} max_in_flight={}",
            u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX),
            max_enqueue_tail_ns.load(Ordering::Relaxed),
            snapshot.direct_injections,
            snapshot.deferred_injections,
            snapshot.combined_injections,
            snapshot.fallback_injections,
            snapshot.combiner_claim_failures,
            snapshot.mode_entries,
            snapshot.mode_exits,
            snapshot.mode_entries + snapshot.mode_exits,
            snapshot.flushes,
            snapshot.max_batch,
            snapshot.max_in_flight
        );

        snapshot
    }

    #[test]
    fn inject_and_pop_cancel() {
        let injector = GlobalInjector::new();

        injector.inject_cancel(task(1), 100);
        injector.inject_cancel(task(2), 50);

        assert!(!injector.is_empty());
        assert!(injector.has_cancel_work());

        let first = injector.pop_cancel().unwrap();
        assert_eq!(first.task, task(1));

        let second = injector.pop_cancel().unwrap();
        assert_eq!(second.task, task(2));

        assert!(injector.pop_cancel().is_none());
    }

    #[test]
    fn inject_and_pop_timed() {
        let injector = GlobalInjector::new();

        injector.inject_timed(task(1), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        assert!(injector.has_timed_work());

        // EDF order: earliest deadline first
        let first = injector.pop_timed().unwrap();
        assert_eq!(first.task, task(2)); // deadline 50s comes first
        assert_eq!(first.deadline, Time::from_secs(50));

        let second = injector.pop_timed().unwrap();
        assert_eq!(second.task, task(1)); // deadline 100s comes second
        assert_eq!(second.deadline, Time::from_secs(100));
    }

    #[test]
    fn edf_ordering_multiple_tasks() {
        let injector = GlobalInjector::new();

        // Insert in random order
        injector.inject_timed(task(3), Time::from_secs(75));
        injector.inject_timed(task(1), Time::from_secs(25));
        injector.inject_timed(task(4), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        // Should pop in deadline order: 25, 50, 75, 100
        assert_eq!(injector.pop_timed().unwrap().task, task(1));
        assert_eq!(injector.pop_timed().unwrap().task, task(2));
        assert_eq!(injector.pop_timed().unwrap().task, task(3));
        assert_eq!(injector.pop_timed().unwrap().task, task(4));
    }

    #[test]
    fn equal_deadlines_fifo_order() {
        let injector = GlobalInjector::new();

        // Same deadline, should maintain insertion order
        injector.inject_timed(task(1), Time::from_secs(50));
        injector.inject_timed(task(2), Time::from_secs(50));
        injector.inject_timed(task(3), Time::from_secs(50));

        // FIFO among equal deadlines
        assert_eq!(injector.pop_timed().unwrap().task, task(1));
        assert_eq!(injector.pop_timed().unwrap().task, task(2));
        assert_eq!(injector.pop_timed().unwrap().task, task(3));
    }

    #[test]
    fn pop_timed_if_due() {
        let injector = GlobalInjector::new();

        injector.inject_timed(task(1), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        // At t=25, nothing is due
        assert!(injector.pop_timed_if_due(Time::from_secs(25)).is_none());
        assert!(injector.has_timed_work()); // Tasks still in queue

        // At t=50, task 2 is due
        let due = injector.pop_timed_if_due(Time::from_secs(50)).unwrap();
        assert_eq!(due.task, task(2));

        // At t=75, task 1 is still not due
        assert!(injector.pop_timed_if_due(Time::from_secs(75)).is_none());

        // At t=100, task 1 is due
        let due = injector.pop_timed_if_due(Time::from_secs(100)).unwrap();
        assert_eq!(due.task, task(1));
    }

    #[test]
    fn peek_earliest_deadline() {
        let injector = GlobalInjector::new();

        assert!(injector.peek_earliest_deadline().is_none());

        injector.inject_timed(task(1), Time::from_secs(100));
        assert_eq!(
            injector.peek_earliest_deadline(),
            Some(Time::from_secs(100))
        );

        injector.inject_timed(task(2), Time::from_secs(50));
        assert_eq!(injector.peek_earliest_deadline(), Some(Time::from_secs(50)));

        // Peek doesn't remove
        assert_eq!(injector.peek_earliest_deadline(), Some(Time::from_secs(50)));
    }

    #[test]
    fn inject_and_pop_ready() {
        let injector = GlobalInjector::new();

        injector.inject_ready(task(1), 100);

        assert!(injector.has_ready_work());

        let popped = injector.pop_ready().unwrap();
        assert_eq!(popped.task, task(1));
        assert_eq!(popped.priority, 100);
    }

    #[test]
    fn pending_count_accuracy() {
        let injector = GlobalInjector::new();

        assert_eq!(injector.len(), 0);

        injector.inject_cancel(task(1), 100);
        injector.inject_timed(task(2), Time::from_secs(10));
        injector.inject_ready(task(3), 50);

        assert_eq!(injector.len(), 3);

        let _ = injector.pop_cancel();
        assert_eq!(injector.len(), 2);

        let _ = injector.pop_timed();
        let _ = injector.pop_ready();
        assert_eq!(injector.len(), 0);
    }

    #[test]
    fn pop_does_not_underflow_when_counter_lags() {
        let injector = GlobalInjector::new();

        // Simulate queue visibility preceding counter update due to interleaving.
        injector.cancel_queue.push_uncounted(PriorityTask {
            task: task(10),
            priority: 1,
        });

        let popped_cancel = injector.pop_cancel().expect("cancel task should pop");
        assert_eq!(popped_cancel.task, task(10));

        injector.ready_queue.push_uncounted(PriorityTask {
            task: task(11),
            priority: 2,
        });
        assert_eq!(injector.ready_queue.len(), 0);

        let popped_ready = injector.pop_ready().expect("ready task should pop");
        assert_eq!(popped_ready.task, task(11));
        assert_eq!(injector.ready_queue.len(), 0);
    }

    #[test]
    fn readiness_checks_use_ready_counter_to_avoid_false_empty_window() {
        let injector = GlobalInjector::new();

        // Simulate the inject_ready interleaving where the advisory counter is
        // visible before the queue push is visible cross-thread.
        injector.ready_queue.add_count(1);

        assert!(
            !injector.is_empty(),
            "counter-visible ready work must not report empty"
        );
        assert!(
            injector.has_ready_work(),
            "counter-visible ready work must report ready lane activity"
        );
        assert!(
            injector.has_runnable_work(Time::ZERO),
            "counter-visible ready work must report runnable work"
        );

        injector.ready_queue.push_uncounted(PriorityTask {
            task: task(14),
            priority: 9,
        });

        let popped_ready = injector.pop_ready().expect("ready task should pop");
        assert_eq!(popped_ready.task, task(14));
        assert_eq!(injector.ready_queue.len(), 0);
        assert!(injector.is_empty(), "injector returns empty after pop");
    }

    #[test]
    fn timed_pop_does_not_underflow_when_counter_lags() {
        let injector = GlobalInjector::new();

        // Simulate heap visibility preceding counter update due to interleaving.
        // Set timed_count to reflect the heap item (inject_timed now increments
        // counters before pushing, so timed_count >= heap.len() always holds).
        {
            let mut timed = injector.timed_queue.lock();
            timed
                .heap
                .push(TimedTask::new(task(12), Time::from_secs(10), 0));
        }
        injector.timed_count.fetch_add(1, Ordering::Relaxed);

        let popped_timed = injector.pop_timed().expect("timed task should pop");
        assert_eq!(popped_timed.task, task(12));
        assert_eq!(injector.timed_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn timed_pop_if_due_does_not_underflow_when_counter_lags() {
        let injector = GlobalInjector::new();

        // Simulate heap visibility preceding counter update due to interleaving.
        // Set timed_count to reflect the heap item (inject_timed now increments
        // counters before pushing, so timed_count >= heap.len() always holds).
        {
            let mut timed = injector.timed_queue.lock();
            timed
                .heap
                .push(TimedTask::new(task(13), Time::from_secs(10), 0));
        }
        injector.timed_count.fetch_add(1, Ordering::Relaxed);

        // Not due yet: no pop and timed counter unchanged.
        assert!(injector.pop_timed_if_due(Time::from_secs(9)).is_none());
        assert_eq!(injector.timed_count.load(Ordering::Relaxed), 1);

        // Once due, pop must not underflow the lagging counter.
        let popped_timed = injector
            .pop_timed_if_due(Time::from_secs(10))
            .expect("timed task should pop when due");
        assert_eq!(popped_timed.task, task(13));
        assert_eq!(injector.timed_count.load(Ordering::Relaxed), 0);
    }

    // ── has_runnable_work tests (br-3narc.2.1) ──────────────────────────

    #[test]
    fn has_runnable_work_empty_returns_false() {
        let injector = GlobalInjector::new();
        assert!(
            !injector.has_runnable_work(Time::ZERO),
            "empty injector has no runnable work"
        );
    }

    #[test]
    fn has_runnable_work_cancel_always_runnable() {
        let injector = GlobalInjector::new();
        injector.inject_cancel(task(1), 100);
        assert!(
            injector.has_runnable_work(Time::ZERO),
            "cancel work is always runnable regardless of time"
        );
    }

    #[test]
    fn has_runnable_work_ready_always_runnable() {
        let injector = GlobalInjector::new();
        injector.inject_ready(task(1), 50);
        assert!(
            injector.has_runnable_work(Time::ZERO),
            "ready work is always runnable regardless of time"
        );
    }

    #[test]
    fn has_runnable_work_timed_not_due() {
        let injector = GlobalInjector::new();
        injector.inject_timed(task(1), Time::from_secs(100));
        assert!(
            !injector.has_runnable_work(Time::from_secs(50)),
            "timed work with future deadline is not runnable"
        );
    }

    #[test]
    fn has_runnable_work_timed_exactly_due() {
        let injector = GlobalInjector::new();
        injector.inject_timed(task(1), Time::from_secs(100));
        assert!(
            injector.has_runnable_work(Time::from_secs(100)),
            "timed work at exactly its deadline is runnable"
        );
    }

    #[test]
    fn has_runnable_work_timed_past_due() {
        let injector = GlobalInjector::new();
        injector.inject_timed(task(1), Time::from_secs(100));
        assert!(
            injector.has_runnable_work(Time::from_secs(200)),
            "timed work past its deadline is runnable"
        );
    }

    #[test]
    fn has_runnable_work_only_timed_with_mixed_deadlines() {
        let injector = GlobalInjector::new();
        injector.inject_timed(task(1), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        // At t=25, neither is due
        assert!(
            !injector.has_runnable_work(Time::from_secs(25)),
            "no timed work due at t=25"
        );

        // At t=50, task 2 is due
        assert!(
            injector.has_runnable_work(Time::from_secs(50)),
            "earliest timed work (t=50) is due"
        );
    }

    // ── peek_earliest_deadline consistency (br-3narc.2.1) ─────────────

    #[test]
    fn peek_earliest_deadline_updates_after_pop() {
        let injector = GlobalInjector::new();
        injector.inject_timed(task(1), Time::from_secs(50));
        injector.inject_timed(task(2), Time::from_secs(100));

        assert_eq!(injector.peek_earliest_deadline(), Some(Time::from_secs(50)));

        // Pop the earliest
        let _ = injector.pop_timed();
        assert_eq!(
            injector.peek_earliest_deadline(),
            Some(Time::from_secs(100)),
            "peek should reflect next earliest after pop"
        );

        // Pop the last
        let _ = injector.pop_timed();
        assert_eq!(
            injector.peek_earliest_deadline(),
            None,
            "peek should be None after draining all timed work"
        );
    }

    #[test]
    fn peek_earliest_deadline_updates_after_pop_if_due() {
        let injector = GlobalInjector::new();
        injector.inject_timed(task(1), Time::from_secs(50));
        injector.inject_timed(task(2), Time::from_secs(100));

        // Pop via pop_timed_if_due
        let _ = injector.pop_timed_if_due(Time::from_secs(50));
        assert_eq!(
            injector.peek_earliest_deadline(),
            Some(Time::from_secs(100)),
            "peek updated after pop_timed_if_due"
        );
    }

    #[test]
    fn concurrent_decrements_saturate_counters_at_zero() {
        for _ in 0..2_000 {
            let injector = Arc::new(GlobalInjector::new());
            injector.ready_queue.add_count(1);
            let barrier = Arc::new(Barrier::new(3));

            let i1 = Arc::clone(&injector);
            let b1 = Arc::clone(&barrier);
            let h1 = thread::spawn(move || {
                b1.wait();
                i1.ready_queue.decrement_count();
            });

            let i2 = Arc::clone(&injector);
            let b2 = Arc::clone(&barrier);
            let h2 = thread::spawn(move || {
                b2.wait();
                i2.ready_queue.decrement_count();
            });

            barrier.wait();
            h1.join().expect("first decrement thread should complete");
            h2.join().expect("second decrement thread should complete");

            assert_eq!(
                injector.ready_queue.len(),
                0,
                "ready counter must saturate at zero"
            );
        }
    }

    #[test]
    fn ready_combiner_low_contention_preserves_direct_path() {
        let injector = GlobalInjector::new();

        injector.inject_ready(task(31), 90);

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(
            snapshot.direct_injections, 1,
            "single ready injection should stay on the direct fast path"
        );
        assert_eq!(
            snapshot.mode_entries, 0,
            "low-contention ready injection must not enter combining mode"
        );
        assert_eq!(snapshot.ready_len, 1, "direct path should publish one task");

        let popped = injector.pop_ready().expect("direct ready task should pop");
        assert_eq!(popped.task, task(31));
        assert_eq!(popped.priority, 90);
    }

    #[test]
    fn ready_combiner_falls_back_to_direct_queue_when_pending_buffer_is_busy() {
        let injector = GlobalInjector::new();

        injector
            .ready_combiner
            .in_flight
            .store(READY_COMBINER_IN_FLIGHT_THRESHOLD - 1, Ordering::Release);
        injector
            .ready_combiner
            .active
            .store(true, Ordering::Release);
        let pending_guard = injector.ready_combiner.pending.lock();

        injector.inject_ready(task(32), 10);

        drop(pending_guard);
        injector
            .ready_combiner
            .active
            .store(false, Ordering::Release);
        injector
            .ready_combiner
            .in_flight
            .store(0, Ordering::Release);

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(
            snapshot.fallback_injections, 1,
            "busy pending buffer should fall back to the baseline queue path"
        );
        assert_eq!(
            snapshot.combiner_claim_failures, 1,
            "fallback should record the failed active-combiner CAS"
        );

        let popped = injector
            .pop_ready()
            .expect("fallback direct ready task should pop");
        assert_eq!(popped.task, task(32));
        assert!(
            injector.pop_ready().is_none(),
            "fallback path must not double-enqueue"
        );
    }

    #[test]
    fn ready_combiner_handoff_flushes_deferred_batch_without_loss_or_duplicates() {
        let injector = GlobalInjector::new();

        injector
            .ready_combiner
            .active
            .store(true, Ordering::Release);
        {
            let mut pending = injector.ready_combiner.pending.lock();
            pending.push(PriorityTask {
                task: task(42),
                priority: 7,
            });
            pending.push(PriorityTask {
                task: task(43),
                priority: 8,
            });
        }

        injector.flush_ready_combiner_with(PriorityTask {
            task: task(41),
            priority: 6,
        });

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(
            snapshot.combined_injections, 3,
            "combiner should publish the owner task and deferred suffix"
        );
        assert_eq!(snapshot.flushes, 1, "three tasks fit in one combiner flush");
        assert_eq!(
            snapshot.max_batch, 3,
            "max batch should record handoff size"
        );
        assert_eq!(
            snapshot.pending_len, 0,
            "handoff should leave no pending ready tasks"
        );

        let drained = std::iter::from_fn(|| injector.pop_ready()).collect::<Vec<_>>();
        assert_eq!(
            drained.len(),
            3,
            "handoff should publish exactly three tasks"
        );
        assert_eq!(drained[0].task, task(41));
        assert_eq!(drained[1].task, task(42));
        assert_eq!(drained[2].task, task(43));
        assert!(
            injector.pop_ready().is_none(),
            "combiner handoff must not leave duplicate tasks behind"
        );
    }

    #[test]
    fn ready_combiner_contention_scenario_logs_required_producer_counts() {
        let one = run_ready_combiner_contention_case(1, 128);
        assert_eq!(
            one.mode_entries, 0,
            "single-producer run should preserve the low-contention direct path"
        );
        assert_eq!(
            one.direct_injections, 128,
            "single-producer run should account for all tasks as direct injections"
        );

        for producers in [8, 32, 64] {
            let snapshot = run_ready_combiner_contention_case(producers, 128);
            assert!(
                snapshot.max_in_flight >= 1,
                "scenario should report an in-flight pressure metric"
            );
        }
    }

    #[test]
    fn ready_combiner_pending_cap_preserves_fallback_and_cancelled_entry_accounting() {
        let injector = GlobalInjector::new();
        let publications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&publications);
        let _hook = on_ready_publication(move |injector| {
            if observed.fetch_add(1, Ordering::Relaxed) != 0 {
                return;
            }
            for id in 1..=READY_COMBINER_MAX_PENDING + 8 {
                injector.inject_ready_contentious(PriorityTask {
                    task: task(u32::try_from(id).expect("bounded task id")),
                    priority: 90,
                });
            }
            // Cancellation may add a higher-lane copy while the old ready
            // entry is still deferred. Both lane counters must remain exact.
            injector.inject_cancel(task(1), 255);
            let snapshot = injector.ready_combiner_snapshot();
            assert_eq!(snapshot.pending_len, READY_COMBINER_MAX_PENDING);
            assert_eq!(snapshot.deferred_injections, READY_COMBINER_MAX_PENDING);
            assert_eq!(snapshot.fallback_injections, 8);
            assert_eq!(snapshot.ready_len, 9);
        });

        injector.inject_ready_contentious(PriorityTask {
            task: task(0),
            priority: 90,
        });

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(publications.load(Ordering::Relaxed), 2);
        assert_eq!(snapshot.mode_entries, 1);
        assert_eq!(snapshot.mode_exits, 1);
        assert_eq!(snapshot.pending_len, 0);
        assert_eq!(snapshot.combined_injections, READY_COMBINER_MAX_PENDING + 1);
        assert_eq!(snapshot.fallback_injections, 8);
        assert_eq!(snapshot.ready_len, READY_COMBINER_MAX_PENDING + 9);
        assert_eq!(
            injector.pop_cancel().expect("cancel lane progresses").task,
            task(1)
        );
        assert!(injector.pop_cancel().is_none());
        let ready = std::iter::from_fn(|| injector.pop_ready())
            .map(|entry| entry.task)
            .collect::<Vec<_>>();
        let unique = ready.iter().copied().collect::<HashSet<_>>();
        assert_eq!(ready.len(), READY_COMBINER_MAX_PENDING + 9);
        assert_eq!(unique.len(), ready.len());
        assert!(
            unique.contains(&task(1)),
            "cancellation retains its old ready copy"
        );
        assert!(injector.is_empty());
        assert_eq!(injector.ready_count(), 0);
    }

    #[test]
    fn ready_combiner_tenure_ends_despite_continuous_reentrant_arrivals() {
        let injector = GlobalInjector::new();
        let publications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&publications);
        let _hook = on_ready_publication(move |injector| {
            let publication = observed.fetch_add(1, Ordering::Relaxed);
            if injector.ready_combiner.active.load(Ordering::Acquire) {
                // Finite on the old loop too: it publishes 17 batches before
                // returning, so the old code fails the work bound, not a timer.
                if publication < 16 {
                    for offset in 0..READY_COMBINER_MAX_PENDING {
                        injector.inject_ready_contentious(PriorityTask {
                            task: task(
                                u32::try_from(
                                    100 + publication * READY_COMBINER_MAX_PENDING + offset,
                                )
                                .unwrap(),
                            ),
                            priority: 60,
                        });
                    }
                }
            } else {
                // The former owner has released active before its final
                // publication returns. Direct publication and a successor
                // can interleave with its still-reserved suffix.
                injector.inject_ready(task(10_001), 80);
                injector.inject_ready_contentious(PriorityTask {
                    task: task(10_000),
                    priority: 70,
                });
            }
        });

        injector.inject_ready_contentious(PriorityTask {
            task: task(99),
            priority: 50,
        });

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(publications.load(Ordering::Relaxed), 2);
        assert_eq!(
            snapshot.mode_entries, 2,
            "the successor claimed its own tenure"
        );
        assert_eq!(snapshot.mode_exits, 2);
        assert_eq!(snapshot.pending_len, 0);
        assert!(!injector.ready_combiner.active.load(Ordering::Acquire));
        assert_eq!(snapshot.ready_len, READY_COMBINER_MAX_PENDING + 3);
        assert_eq!(snapshot.direct_injections, 1);
        assert_eq!(snapshot.combined_injections + 1, snapshot.ready_len);
        let ready = std::iter::from_fn(|| injector.pop_ready())
            .map(|entry| entry.task)
            .collect::<Vec<_>>();
        assert_eq!(ready.len(), READY_COMBINER_MAX_PENDING + 3);
        assert_eq!(
            ready.iter().copied().collect::<HashSet<_>>().len(),
            ready.len()
        );
        assert!(ready.contains(&task(99)));
        assert!(ready.contains(&task(10_000)));
        assert_eq!(
            &ready[..5],
            &[task(99), task(100), task(10_001), task(10_000), task(101)]
        );
        assert_eq!(injector.ready_count(), 0);
        eprintln!(
            "READY_COMBINER_BOUNDED snapshot={snapshot:?} published={}",
            ready.len()
        );
    }

    #[test]
    fn ready_combiner_native_producers_preserve_control_progress_and_queue_counts() {
        use std::time::Duration;

        const PRODUCERS: usize = 8;
        const PREFIX: usize = 512;
        const ITEMS: usize = 1_024;
        let injector = Arc::new(GlobalInjector::new());
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        thread::scope(|threads| {
            // Dropping the release senders on failure also releases every
            // parked producer; scoped threads always retire before this returns.
            let mut releases = Vec::new();
            for producer in 0..PRODUCERS {
                let injector = Arc::clone(&injector);
                let parked = parked_tx.clone();
                let (release_tx, release_rx) = std::sync::mpsc::channel();
                releases.push(release_tx);
                threads.spawn(move || {
                    for offset in 0..PREFIX {
                        injector.inject_ready(contention_task(producer, offset), 80);
                    }
                    parked.send(producer).expect("publish prefix completion");
                    if release_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                        return;
                    }
                    for offset in PREFIX..ITEMS {
                        injector.inject_ready(contention_task(producer, offset), 80);
                    }
                });
            }
            for _ in 0..PRODUCERS {
                parked_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("every native producer published its prefix");
            }
            assert_eq!(injector.ready_count(), PRODUCERS * PREFIX);
            injector.inject_cancel(contention_task(0, 0), 255);
            injector.inject_timed(contention_task(1, 0), Time::ZERO);
            for release in releases {
                release.send(()).expect("release native producer");
            }
            assert_eq!(
                injector
                    .pop_cancel()
                    .expect("cancel lane progresses with a ready backlog")
                    .task,
                contention_task(0, 0)
            );
            assert_eq!(
                injector
                    .pop_timed_if_due(Time::ZERO)
                    .expect("due timer progresses with a ready backlog")
                    .task,
                contention_task(1, 0)
            );
        });

        let snapshot = injector.ready_combiner_snapshot();
        assert_eq!(snapshot.ready_len, PRODUCERS * ITEMS);
        assert_eq!(snapshot.pending_len, 0);
        assert_eq!(snapshot.current_in_flight, 0);
        assert_eq!(snapshot.mode_entries, snapshot.mode_exits);
        assert!(snapshot.flushes <= snapshot.mode_entries * 2);
        assert!(snapshot.max_batch <= READY_COMBINER_MAX_BATCH);
        assert_eq!(
            snapshot.direct_injections
                + snapshot.fallback_injections
                + snapshot.combined_injections,
            PRODUCERS * ITEMS
        );
        let mut seen = HashSet::new();
        while let Some(entry) = injector.pop_ready() {
            assert!(seen.insert(entry.task), "ready entry was published twice");
        }
        for producer in 0..PRODUCERS {
            for offset in 0..ITEMS {
                assert!(seen.contains(&contention_task(producer, offset)));
            }
        }
        assert_eq!(seen.len(), PRODUCERS * ITEMS);
        assert!(injector.is_empty());
        eprintln!("READY_COMBINER_NATIVE producers={PRODUCERS} items={ITEMS} snapshot={snapshot:?}");
    }

    // =========================================================================
    // Wave 49 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn priority_task_debug_clone_copy() {
        let pt = PriorityTask {
            task: task(1),
            priority: 5,
        };
        let dbg = format!("{pt:?}");
        assert!(dbg.contains("PriorityTask"), "{dbg}");
        let copied = pt;
        let cloned = pt;
        assert_eq!(copied.task, cloned.task);
        assert_eq!(copied.priority, cloned.priority);
    }

    #[test]
    fn timed_task_debug_clone_copy_eq() {
        let tt = TimedTask::new(task(1), Time::from_nanos(1000), 0);
        let dbg = format!("{tt:?}");
        assert!(dbg.contains("TimedTask"), "{dbg}");
        let copied = tt;
        let cloned = tt;
        assert_eq!(copied, cloned);
    }
