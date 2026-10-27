    use super::*;
    use crate::channel::oneshot;
    use crate::cx::Cx;
    use crate::observability::{LogCollector, LogLevel};
    use crate::runtime::{RuntimeBuilder, yield_now};
    use crate::types::{CancelKind, TaskId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn run_in_runtime<F, Fut, T>(f: F) -> T
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("spawned root task has Cx");
            f(cx).await
        }))
    }

    fn is_race_lost_or_stronger<T, E>(outcome: &Outcome<T, E>) -> bool {
        matches!(
            outcome,
            Outcome::Cancelled(reason)
                if reason.is_kind(CancelKind::RaceLost)
                    || reason.kind.severity() > CancelKind::RaceLost.severity()
        )
    }

    fn manual_handle<T>(task_slot: u32) -> (oneshot::Sender<Result<T, JoinError>>, TaskHandle<T>) {
        let (tx, rx) = oneshot::channel::<Result<T, JoinError>>();
        let handle = TaskHandle::new(
            TaskId::new_for_test(task_slot, 0),
            rx,
            std::sync::Weak::new(),
        );
        (tx, handle)
    }

    #[test]
    fn join_to_outcome_maps_value_and_application_error() {
        let ok: Outcome<i32, &'static str> = join_to_outcome(Ok(Ok(7)));
        assert!(matches!(ok, Outcome::Ok(7)));

        let err: Outcome<i32, &'static str> = join_to_outcome(Ok(Err("boom")));
        assert!(matches!(err, Outcome::Err("boom")));
    }

    #[test]
    fn join_to_outcome_maps_poll_after_completion_to_panic() {
        let outcome: Outcome<i32, &'static str> =
            join_to_outcome(Err(JoinError::PolledAfterCompletion));

        match outcome {
            Outcome::Panicked(payload) => {
                assert_eq!(payload.message(), "join handle polled after completion");
            }
            other => panic!("expected panic outcome, got {other:?}"),
        }
    }

    #[test]
    fn join_summary_tracks_completed_and_worst_severity() {
        let mut summary = JoinSummary::default();

        summary.record(&Outcome::<(), ()>::Ok(()));
        summary.record(&Outcome::<(), ()>::Err(()));
        summary.record(&Outcome::<(), ()>::Cancelled(crate::CancelReason::user(
            "cancelled",
        )));

        assert_eq!(summary.completed(), 3);
        assert_eq!(summary.worst(), Severity::Cancelled);
    }

    #[test]
    fn join_set_id_is_deterministic_from_owning_region() {
        let scope =
            Scope::<FailFast>::new(crate::RegionId::new_for_test(7, 1), crate::Budget::INFINITE);
        let set = JoinSet::<(), (), FailFast>::new(&scope);

        assert_eq!(set.set_id, scope.region_id().as_u64());
        assert_eq!(set.next_member_index, 0);
    }

    #[test]
    fn join_set_spawn_trace_records_parent_set_fields() {
        let (entries, set_id, region) = run_in_runtime(|cx| async move {
            let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
            cx.set_log_collector(collector.clone());

            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            let set_id = set.set_id.to_string();
            let region = cx.region_id().to_string();

            set.spawn(&cx, |_| async move { Ok::<u32, ()>(1) })
                .expect("first member spawns");
            set.spawn(&cx, |_| async move { Ok::<u32, ()>(2) })
                .expect("second member spawns");

            let values = set
                .join_all(&cx)
                .await
                .into_iter()
                .map(|outcome| outcome.expect("member ok"))
                .collect::<Vec<_>>();
            assert_eq!(values, vec![1, 2]);

            (collector.peek(), set_id, region)
        });

        let spawn_entries = entries
            .iter()
            .filter(|entry| entry.message() == "join_set.spawn")
            .collect::<Vec<_>>();
        assert_eq!(spawn_entries.len(), 2);

        for (index, entry) in spawn_entries.iter().enumerate() {
            let member_index = index.to_string();
            let active_members = (index + 1).to_string();

            assert_eq!(entry.get_field("join_set_id"), Some(set_id.as_str()));
            assert_eq!(entry.get_field("region"), Some(region.as_str()));
            assert_eq!(entry.get_field("spawn_kind"), Some("send"));
            assert_eq!(entry.get_field("member_index"), Some(member_index.as_str()));
            assert!(entry.get_field("member_task_id").is_some());
            assert_eq!(
                entry.get_field("active_members"),
                Some(active_members.as_str())
            );
        }
    }

    #[test]
    fn join_set_spawn_trace_distinguishes_multiple_sets_in_same_region() {
        let entries = run_in_runtime(|cx| async move {
            let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
            cx.set_log_collector(collector.clone());

            let mut set_a = JoinSet::<u32, (), _>::in_cx(&cx);
            let mut set_b = JoinSet::<u32, (), _>::in_cx(&cx);

            set_a
                .spawn(&cx, |_| async move { Ok::<u32, ()>(10) })
                .expect("set_a member spawns");
            set_b
                .spawn(&cx, |_| async move { Ok::<u32, ()>(20) })
                .expect("set_b member spawns");

            let res_a = set_a.join_next(&cx).await.unwrap().unwrap();
            let res_b = set_b.join_next(&cx).await.unwrap().unwrap();
            assert_eq!(res_a, 10);
            assert_eq!(res_b, 20);

            collector.peek()
        });

        let spawn_entries = entries
            .iter()
            .filter(|entry| entry.message() == "join_set.spawn")
            .collect::<Vec<_>>();
        assert_eq!(spawn_entries.len(), 2);

        // Both sets share the owning region as join_set_id and both have member_index 0,
        // but their distinct member_task_ids uniquely identify which task belonged to which spawn.
        let member_task_id_0 = spawn_entries[0].get_field("member_task_id").unwrap();
        let member_task_id_1 = spawn_entries[1].get_field("member_task_id").unwrap();
        assert_ne!(member_task_id_0, member_task_id_1);
        assert_eq!(spawn_entries[0].get_field("member_index"), Some("0"));
        assert_eq!(spawn_entries[1].get_field("member_index"), Some("0"));
        assert_eq!(
            spawn_entries[0].get_field("join_set_id"),
            spawn_entries[1].get_field("join_set_id")
        );
    }

    #[test]
    fn spawn_all_preserves_member_order_identity_region_and_traces() {
        let entries = run_in_runtime(|cx| async move {
            let collector = LogCollector::new(16).with_min_level(LogLevel::Trace);
            cx.set_log_collector(collector.clone());
            let region = cx.region_id();
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            set.spawn(&cx, |_| async { Ok(10) }).expect("prefix");
            set.spawn_all(
                &cx,
                [20, 30, 40].into_iter().map(move |value| {
                    move |child: Cx| async move {
                        assert_eq!(child.region_id(), region);
                        Ok(value)
                    }
                }),
            )
            .expect("batch");
            set.spawn(&cx, |_| async { Ok(50) }).expect("suffix");
            assert_eq!(set.len(), 5);

            let values = set
                .join_all(&cx)
                .await
                .into_iter()
                .map(|outcome| outcome.expect("member ok"))
                .collect::<Vec<_>>();
            assert_eq!(values, vec![10, 20, 30, 40, 50]);
            collector.peek()
        });

        let spawns = entries
            .iter()
            .filter(|entry| entry.message() == "join_set.spawn")
            .collect::<Vec<_>>();
        assert_eq!(spawns.len(), 5);
        let mut identities = BTreeSet::new();
        for (index, entry) in spawns.iter().enumerate() {
            let expected_index = index.to_string();
            let expected_count = (index + 1).to_string();
            assert_eq!(entry.get_field("member_index"), Some(expected_index.as_str()));
            assert_eq!(entry.get_field("active_members"), Some(expected_count.as_str()));
            assert_eq!(entry.get_field("spawn_kind"), Some("send"));
            identities.insert(entry.get_field("member_task_id").expect("task identity"));
        }
        assert_eq!(identities.len(), 5, "each member has its own identity");
    }

    #[test]
    fn spawn_all_empty_succeeds_without_runtime_wiring() {
        type Factory = fn(Cx) -> std::future::Ready<Result<u32, ()>>;
        let cx = Cx::for_testing();
        let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
        set.spawn_all(&cx, std::iter::empty::<Factory>())
            .expect("an empty batch has no runtime effects");
        assert!(set.is_empty());
        assert_eq!(set.next_member_index, 0);
    }

    #[test]
    fn spawn_all_setup_failure_preserves_existing_members() {
        let cx = Cx::for_testing();
        let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
        let (sender, handle) = manual_handle::<Result<u32, ()>>(31);
        set.insert_member(handle);
        let invoked = Arc::new(AtomicUsize::new(0));
        let factory_invoked = Arc::clone(&invoked);
        let result = set.spawn_all(&cx, [move |_| {
            factory_invoked.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(99))
        }]);

        assert!(matches!(
            result,
            Err(crate::cx::SpawnBatchError::Spawn(SpawnError::RuntimeUnavailable))
        ));
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!(set.len(), 1);
        assert_eq!(set.next_member_index, 1);
        sender.send(&cx, Ok(Ok(7))).expect("existing member completes");
        assert_eq!(set.try_join_next(), Some(Outcome::Ok(7)));
        assert!(set.is_empty());
    }

    #[test]
    fn spawn_all_oversized_batch_publishes_no_partial_members() {
        run_in_runtime(|cx| async move {
            let mut set = JoinSet::<usize, (), _>::in_cx(&cx);
            set.spawn(&cx, |_| async { Ok(7) }).expect("existing member");
            let iterated = Arc::new(AtomicUsize::new(0));
            let invoked = Arc::new(AtomicUsize::new(0));
            let iterator_count = Arc::clone(&iterated);
            let factory_count = Arc::clone(&invoked);
            let factories = std::iter::repeat_with(move || {
                iterator_count.fetch_add(1, Ordering::SeqCst);
                let factory_count = Arc::clone(&factory_count);
                move |_| {
                    factory_count.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(99))
                }
            });
            let result = set.spawn_all(&cx, factories);
            assert!(matches!(
                result,
                Err(crate::cx::SpawnBatchError::TooManyTasks { limit })
                    if limit == crate::cx::MAX_SPAWN_BATCH_SIZE
            ));
            assert_eq!(iterated.load(Ordering::SeqCst), crate::cx::MAX_SPAWN_BATCH_SIZE + 1);
            assert_eq!(invoked.load(Ordering::SeqCst), 0);
            assert_eq!(set.len(), 1);
            assert_eq!(set.next_member_index, 1);
            let outcomes = set.join_all(&cx).await;
            assert_eq!(outcomes, vec![Outcome::Ok(7)]);
        });
    }

    #[test]
    fn spawn_all_pre_admission_cancellation_drains_every_member() {
        let (outcomes, started) = run_in_runtime(|cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let factory_started = Arc::clone(&started);
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            set.spawn_all(&cx, (0..4).map(move |value| {
                let started = Arc::clone(&factory_started);
                move |_| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                }
            }))
            .expect("batch");
            assert_eq!(started.load(Ordering::SeqCst), 0);
            let outcomes = set
                .cancel_all_with_reason(&cx, CancelReason::race_loser())
                .await;
            (outcomes, started.load(Ordering::SeqCst))
        });

        assert_eq!(started, 0, "cancelled provisional tasks never poll user work");
        assert_eq!(outcomes.len(), 4);
        assert!(outcomes.iter().all(is_race_lost_or_stronger));
        let losers = outcomes.iter().collect::<Vec<_>>();
        let witness = crate::combinator::race::verify_losers_drained(&losers)
            .expect("every batched loser drained");
        assert_eq!(witness.losers_checked(), 4);
    }

    #[test]
    fn spawn_all_cancellation_drains_parked_members_after_async_cleanup() {
        let (outcomes, cleaned) = run_in_runtime(|cx| async move {
            let cleaned = Arc::new(AtomicUsize::new(0));
            let mut parked_receivers = Vec::new();
            let mut held_senders = Vec::new();
            let factories = (0..3).map(|value| {
                let (parked_sender, parked_receiver) = oneshot::channel();
                let (held_sender, mut held_receiver) = oneshot::channel::<()>();
                parked_receivers.push(parked_receiver);
                held_senders.push(held_sender);
                let cleaned = Arc::clone(&cleaned);
                move |member_cx: Cx| async move {
                    let mut waiting = Box::pin(held_receiver.recv(&member_cx));
                    std::future::poll_fn(|task_cx| {
                        assert!(waiting.as_mut().poll(task_cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    parked_sender.send_blocking(()).expect("parked witness");
                    assert_eq!(waiting.await, Err(oneshot::RecvError::Cancelled));
                    // Acknowledged cancellation may cross another Pending
                    // while cleanup runs. JoinSet must still classify the
                    // eventual value as cancellation and wait for retirement.
                    yield_now().await;
                    cleaned.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(value)
                }
            });
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            set.spawn_all(&cx, factories).expect("batch");
            for mut receiver in parked_receivers {
                receiver.recv(&cx).await.expect("member reached Pending");
            }
            assert_eq!(cleaned.load(Ordering::SeqCst), 0);
            let outcomes = set
                .cancel_all_with_reason(&cx, CancelReason::race_loser())
                .await;
            let completed_cleanup = cleaned.load(Ordering::SeqCst);
            drop(held_senders);
            (outcomes, completed_cleanup)
        });

        assert_eq!(cleaned, 3, "collection waits for every cleanup future");
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().all(is_race_lost_or_stronger));
    }

    #[test]
    fn join_next_returns_none_for_empty_set() {
        let observed = run_in_runtime(|cx| async move {
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            let next = set.join_next(&cx).await;
            let summary = set.summary();
            (next, summary.completed(), summary.worst())
        });

        assert_eq!(observed.0, None);
        assert_eq!(observed.1, 0);
        assert_eq!(observed.2, Severity::Ok);
    }

    #[test]
    fn try_join_next_returns_none_until_member_is_ready() {
        let scope =
            Scope::<FailFast>::new(crate::RegionId::new_for_test(8, 1), crate::Budget::INFINITE);
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (_tx, handle) = manual_handle::<Result<u32, &'static str>>(1);

        set.insert_member(handle);

        assert!(set.try_join_next().is_none());
        assert_eq!(set.len(), 1);
        assert_eq!(set.summary().completed(), 0);
        assert_eq!(set.summary().worst(), Severity::Ok);
    }

    #[test]
    fn try_join_next_collects_earliest_spawned_ready_member() {
        let cx = Cx::for_testing();
        let scope =
            Scope::<FailFast>::new(crate::RegionId::new_for_test(9, 1), crate::Budget::INFINITE);
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (_pending_tx, pending_handle) = manual_handle::<Result<u32, &'static str>>(1);
        let (ready_tx, ready_handle) = manual_handle::<Result<u32, &'static str>>(2);

        set.insert_member(pending_handle);
        set.insert_member(ready_handle);
        ready_tx
            .send(&cx, Ok(Ok(9)))
            .expect("ready member result sends");

        let outcome = set.try_join_next().expect("ready member collected");

        assert!(matches!(outcome, Outcome::Ok(9)));
        assert_eq!(set.len(), 1);
        assert_eq!(set.summary().completed(), 1);
        assert_eq!(set.summary().worst(), Severity::Ok);
        assert!(set.try_join_next().is_none());
    }

    #[test]
    fn try_join_next_maps_application_error() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(
            crate::RegionId::new_for_test(10, 1),
            crate::Budget::INFINITE,
        );
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (ready_tx, ready_handle) = manual_handle::<Result<u32, &'static str>>(1);

        set.insert_member(ready_handle);
        ready_tx
            .send(&cx, Ok(Err("boom")))
            .expect("ready member error sends");

        let outcome = set.try_join_next().expect("ready member collected");

        assert!(matches!(outcome, Outcome::Err("boom")));
        assert!(set.is_empty());
        assert_eq!(set.summary().completed(), 1);
        assert_eq!(set.summary().worst(), Severity::Err);
    }

    #[test]
    fn join_next_ready_order_is_deterministic_across_replays() {
        fn collect_ready_values(seed_values: &[u32]) -> Vec<u32> {
            let seed_values = seed_values.to_vec();
            run_in_runtime(move |cx| async move {
                let scope = Scope::<FailFast>::new(
                    crate::RegionId::new_for_test(11, 1),
                    crate::Budget::INFINITE,
                );
                let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);

                for (index, value) in seed_values.into_iter().enumerate() {
                    let (ready_tx, ready_handle) =
                        manual_handle::<Result<u32, &'static str>>((index + 1) as u32);
                    set.insert_member(ready_handle);
                    ready_tx
                        .send(&cx, Ok(Ok(value)))
                        .expect("ready member result sends");
                }

                let mut observed = Vec::new();
                while let Some(outcome) = set.join_next(&cx).await {
                    observed.push(outcome.expect("member ok"));
                }
                observed
            })
        }

        let seed_values = [5, 3, 8, 1, 13, 2, 21, 1];

        assert_eq!(collect_ready_values(&seed_values), seed_values);
        assert_eq!(
            collect_ready_values(&seed_values),
            collect_ready_values(&seed_values)
        );
    }

    /// Regression proof for `br-asupersync-tncxj9`: a `join_next` poll that
    /// returns `Pending` must leave every pending member registered for wakeup.
    /// The previous implementation polled a temporary `handle.join(cx)` future
    /// per member and dropped it, which retired the waiter it had just
    /// installed, so member completion woke nothing and the set parked forever.
    #[test]
    fn join_next_pending_poll_registers_wakers_for_every_member() {
        struct CountingWaker {
            counter: Arc<AtomicUsize>,
        }

        impl std::task::Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.counter.fetch_add(1, Ordering::Relaxed);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(
            crate::RegionId::new_for_test(13, 1),
            crate::Budget::INFINITE,
        );
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (_pending_tx, pending_handle) = manual_handle::<Result<u32, &'static str>>(1);
        let (late_tx, late_handle) = manual_handle::<Result<u32, &'static str>>(2);
        set.insert_member(pending_handle);
        set.insert_member(late_handle);

        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(CountingWaker {
            counter: Arc::clone(&wakes),
        }));
        let mut poll_cx = std::task::Context::from_waker(&waker);

        let mut join_next = Box::pin(set.join_next(&cx));
        assert!(
            join_next.as_mut().poll(&mut poll_cx).is_pending(),
            "no member is ready yet, so the first poll must park"
        );
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            0,
            "parking must not owe a wake while every member is still running"
        );

        late_tx
            .send(&cx, Ok(Ok(9)))
            .expect("late member result sends");
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            1,
            "a member completing after the parking poll must wake the set"
        );

        let ready = join_next.as_mut().poll(&mut poll_cx);
        match ready {
            Poll::Ready(Some(Outcome::Ok(9))) => {}
            other => panic!("expected the completed member, got {other:?}"),
        }
        drop(join_next);

        assert_eq!(set.len(), 1, "the still-pending member stays owned");
        assert_eq!(set.summary().completed(), 1);
        assert_eq!(set.summary().worst(), Severity::Ok);
    }

    fn parked_members(
        set: &mut JoinSet<'_, u32, &'static str, FailFast>,
        count: u32,
    ) -> Vec<Option<oneshot::Sender<Result<Result<u32, &'static str>, JoinError>>>> {
        let mut senders = Vec::new();
        for slot in 0..count {
            let (tx, handle) = manual_handle::<Result<u32, &'static str>>(slot + 1);
            set.insert_member(handle);
            senders.push(Some(tx));
        }
        senders
    }

    /// `join_next` polls only members that may have finished: after a parking
    /// poll every pending member waits on its own waker and is no longer a
    /// candidate, and a completion makes exactly that member a candidate. A
    /// set collected in completion order therefore never rescans its other
    /// members (br-asupersync-issue65-criticisms-kpmoy5.1.5).
    #[test]
    fn join_next_polls_only_members_whose_wakeup_fired() {
        const MEMBERS: u32 = 10_000;
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(
            crate::RegionId::new_for_test(14, 1),
            crate::Budget::INFINITE,
        );
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let mut senders = parked_members(&mut set, MEMBERS);
        assert_eq!(
            set.ready.candidates.lock().len(),
            MEMBERS as usize,
            "members never polled are candidates"
        );

        let mut poll_cx = std::task::Context::from_waker(std::task::Waker::noop());
        {
            let mut join_next = Box::pin(set.join_next(&cx));
            assert!(join_next.as_mut().poll(&mut poll_cx).is_pending());
        }
        assert!(
            set.ready.candidates.lock().is_empty(),
            "every parked member waits on its own waker"
        );

        // Complete members in reverse spawn order: each collection must find
        // exactly the one member that finished.
        for slot in (0..MEMBERS).rev() {
            senders[slot as usize]
                .take()
                .expect("unsent member")
                .send(&cx, Ok(Ok(slot)))
                .expect("member result sends");
            assert_eq!(
                set.ready
                    .candidates
                    .lock()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
                vec![u64::from(slot)],
                "only the finished member is a candidate"
            );
            let mut join_next = Box::pin(set.join_next(&cx));
            match join_next.as_mut().poll(&mut poll_cx) {
                Poll::Ready(Some(Outcome::Ok(value))) => assert_eq!(value, slot),
                other => panic!("expected member {slot}, got {other:?}"),
            }
        }
        assert!(set.is_empty());
        assert_eq!(set.summary().completed(), MEMBERS as usize);
    }

    /// Dropping a `join_next` future that parked loses no outcome: the next
    /// call collects every member exactly once, earliest spawned first.
    #[test]
    fn a_dropped_pending_join_next_loses_no_outcome() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(
            crate::RegionId::new_for_test(15, 1),
            crate::Budget::INFINITE,
        );
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let mut senders = parked_members(&mut set, 3);
        let mut poll_cx = std::task::Context::from_waker(std::task::Waker::noop());
        {
            let mut join_next = Box::pin(set.join_next(&cx));
            assert!(join_next.as_mut().poll(&mut poll_cx).is_pending());
        }
        for slot in [2_u32, 0, 1] {
            senders[slot as usize]
                .take()
                .expect("unsent member")
                .send(&cx, Ok(Ok(slot)))
                .expect("member result sends");
        }

        let mut collected = Vec::new();
        loop {
            let mut join_next = Box::pin(set.join_next(&cx));
            match join_next.as_mut().poll(&mut poll_cx) {
                Poll::Ready(Some(outcome)) => collected.push(outcome.expect("member ok")),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("every member has finished"),
            }
        }
        assert_eq!(collected, vec![0, 1, 2]);
        assert_eq!(set.summary().completed(), 3);
    }

    #[test]
    fn join_all_collects_members_in_spawn_order() {
        let (outcomes, next_member_index) = run_in_runtime(|cx| async move {
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            for value in [30_u32, 10, 20] {
                set.spawn(&cx, move |_| async move { Ok::<u32, ()>(value) })
                    .expect("join-set member spawns");
            }

            let next_member_index = set.next_member_index;
            (set.join_all(&cx).await, next_member_index)
        });

        assert_eq!(next_member_index, 3);
        assert_eq!(
            outcomes
                .into_iter()
                .map(|outcome| outcome.expect("member ok"))
                .collect::<Vec<_>>(),
            vec![30, 10, 20]
        );
    }

    #[test]
    fn join_all_drains_ten_thousand_ready_members_in_spawn_order() {
        const MEMBERS: usize = 10_000;

        let outcomes = run_in_runtime(|cx| async move {
            let scope = Scope::<FailFast>::new(
                crate::RegionId::new_for_test(12, 1),
                crate::Budget::INFINITE,
            );
            let mut set = JoinSet::<u64, &'static str, FailFast>::new(&scope);

            for index in 0..MEMBERS {
                let (ready_tx, ready_handle) =
                    manual_handle::<Result<u64, &'static str>>((index + 1) as u32);
                set.insert_member(ready_handle);
                ready_tx
                    .send(&cx, Ok(Ok(index as u64)))
                    .expect("ready member result sends");
            }

            assert_eq!(set.len(), MEMBERS);
            set.join_all(&cx).await
        });

        assert_eq!(outcomes.len(), MEMBERS);

        let mut observed_sum = 0_u64;
        for (expected, outcome) in outcomes.into_iter().enumerate() {
            let value = outcome.expect("member ok");
            assert_eq!(value, expected as u64);
            observed_sum += value;
        }
        assert_eq!(observed_sum, (MEMBERS as u64 - 1) * MEMBERS as u64 / 2);
    }

    fn assert_dropped_join_all_cancels_parked_suffix(local: bool, ready_prefix: usize) {
        const PENDING_MEMBERS: usize = 3;

        struct Retirement(Option<oneshot::Sender<()>>);

        impl Drop for Retirement {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send_blocking(());
                }
            }
        }

        let (observed, prefix_cancelled) = run_in_runtime(move |cx| async move {
            let mut set = JoinSet::<(), (), _>::in_cx(&cx);
            let mut prefix_receipts = Vec::new();
            for _ in 0..ready_prefix {
                let (sender, receiver) = oneshot::channel();
                let factory = move |member_cx: Cx| async move {
                    sender.send_blocking(member_cx).expect("prefix receipt");
                    Ok::<(), ()>(())
                };
                if local {
                    set.spawn_local(&cx, factory).expect("local prefix");
                } else {
                    set.spawn(&cx, factory).expect("send prefix");
                }
                prefix_receipts.push(receiver);
            }
            let mut prefix_contexts = Vec::new();
            for mut receipt in prefix_receipts {
                prefix_contexts.push(receipt.recv(&cx).await.expect("prefix completed"));
            }
            assert!(
                set.members
                    .values()
                    .all(|member| member.handle.is_finished())
            );

            let mut parked_receipts = Vec::new();
            let mut release_senders = Vec::new();
            let mut retirement_receipts = Vec::new();
            for _ in 0..PENDING_MEMBERS {
                let (parked_sender, parked_receiver) = oneshot::channel();
                let (release_sender, mut release_receiver) = oneshot::channel::<()>();
                let (retired_sender, retired_receiver) = oneshot::channel();
                let factory = move |member_cx: Cx| async move {
                    let _retirement = Retirement(Some(retired_sender));
                    let mut waiting = Box::pin(release_receiver.recv(&member_cx));
                    std::future::poll_fn(|task_cx| {
                        assert!(waiting.as_mut().poll(task_cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    parked_sender
                        .send_blocking(member_cx.clone())
                        .expect("parked receipt");
                    let _ = waiting.await;
                    Ok::<(), ()>(())
                };
                if local {
                    set.spawn_local(&cx, factory).expect("local parked member");
                } else {
                    set.spawn(&cx, factory).expect("send parked member");
                }
                parked_receipts.push(parked_receiver);
                release_senders.push(release_sender);
                retirement_receipts.push(retired_receiver);
            }

            let mut member_contexts = Vec::new();
            for mut receipt in parked_receipts {
                member_contexts.push(receipt.recv(&cx).await.expect("member parked"));
            }
            // On this current-thread runtime each receipt is consumed after
            // the sender's poll returns. Every member has a live Pending recv,
            // and each prefix task has returned before the drain is polled.
            assert!(
                member_contexts
                    .iter()
                    .all(|member| !member.is_cancel_requested())
            );
            let mut joining = Box::pin(set.join_all(&cx));
            std::future::poll_fn(|task_cx| {
                assert!(joining.as_mut().poll(task_cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(joining);
            let observed = member_contexts
                .iter()
                .map(Cx::is_cancel_requested)
                .collect::<Vec<_>>();
            let prefix_cancelled = prefix_contexts
                .iter()
                .map(Cx::is_cancel_requested)
                .collect::<Vec<_>>();

            // Release all waits AFTER freezing the oracle. This keeps a run
            // against the old implementation finite without masking its
            // [true, false, false] cancellation-ownership failure.
            for sender in release_senders {
                let _ = sender.send_blocking(());
            }
            for mut receipt in retirement_receipts {
                receipt.recv(&cx).await.expect("member future retired");
            }
            (observed, prefix_cancelled)
        });

        assert_eq!(observed, vec![true; PENDING_MEMBERS]);
        assert_eq!(prefix_cancelled, vec![false; ready_prefix]);
    }

    #[test]
    fn dropped_join_all_cancels_every_parked_send_member() {
        assert_dropped_join_all_cancels_parked_suffix(false, 0);
    }

    #[test]
    fn dropped_join_all_cancels_send_suffix_after_completed_prefix() {
        assert_dropped_join_all_cancels_parked_suffix(false, 2);
    }

    #[test]
    fn dropped_join_all_cancels_every_parked_local_member() {
        assert_dropped_join_all_cancels_parked_suffix(true, 0);
    }

    #[test]
    fn dropped_join_all_cancels_local_suffix_after_completed_prefix() {
        assert_dropped_join_all_cancels_parked_suffix(true, 2);
    }

    #[test]
    fn dropping_finished_members_does_not_rewrite_their_contexts() {
        for local in [false, true] {
            for unpolled_join in [false, true] {
                let cancelled = run_in_runtime(move |cx| async move {
                    let mut set = JoinSet::<(), (), _>::in_cx(&cx);
                    let (sender, mut receiver) = oneshot::channel();
                    let factory = move |member_cx: Cx| async move {
                        sender.send_blocking(member_cx).expect("member context");
                        Ok::<(), ()>(())
                    };
                    if local {
                        set.spawn_local(&cx, factory).expect("local member");
                    } else {
                        set.spawn(&cx, factory).expect("send member");
                    }
                    let member_cx = receiver.recv(&cx).await.expect("finished member");
                    assert!(set.members[&0].handle.is_finished());
                    assert!(!member_cx.is_cancel_requested());
                    if unpolled_join {
                        drop(set.join_all(&cx));
                    } else {
                        drop(set);
                    }
                    member_cx.is_cancel_requested()
                });
                assert!(
                    !cancelled,
                    "terminal Cx changed: local={local}, unpolled_join={unpolled_join}"
                );
            }
        }
    }

    /// A runtime member publishes its result before the scheduler retires its
    /// record and opens its retirement barrier; is_finished() stays false in
    /// between. On a multi-thread runtime the owner can drop the set in that
    /// window. The member has finished, so dropping the set must not request
    /// its cancellation, while a member that has not published still gets one.
    #[test]
    fn dropping_a_member_published_before_retirement_does_not_cancel_it() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(
            crate::RegionId::new_for_test(12, 1),
            crate::Budget::INFINITE,
        );
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let finished_cx = Cx::for_testing();
        let running_cx = Cx::for_testing();
        let (finished_tx, finished_rx) = oneshot::channel();
        let (_running_tx, running_rx) = oneshot::channel();
        set.insert_member(TaskHandle::with_retirement_barrier_for_test(
            TaskId::new_for_test(1, 0),
            finished_rx,
            Arc::downgrade(&finished_cx.inner),
            crate::runtime::task_handle::RetirementBarrier::pending(),
        ));
        set.insert_member(TaskHandle::with_retirement_barrier_for_test(
            TaskId::new_for_test(2, 0),
            running_rx,
            Arc::downgrade(&running_cx.inner),
            crate::runtime::task_handle::RetirementBarrier::pending(),
        ));
        finished_tx
            .send(&cx, Ok(Ok(7)))
            .expect("the finished member publishes its result");
        assert!(
            !set.members[&0].handle.is_finished(),
            "the closed barrier still gates the published result"
        );

        drop(set);

        assert!(
            !finished_cx.is_cancel_requested(),
            "dropping the set cancelled a member that had already published its result"
        );
        assert!(
            running_cx.is_cancel_requested(),
            "dropping the set must still cancel a member that has not finished"
        );
    }

    #[test]
    fn cancel_all_drains_live_members_as_cancelled_outcomes() {
        let (outcomes, summary) = run_in_runtime(|cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let mut set = JoinSet::<u32, crate::error::Error, _>::in_cx(&cx);

            for _ in 0..3 {
                let started = Arc::clone(&started);
                set.spawn(&cx, move |member_cx| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    loop {
                        if let Err(error) = member_cx.checkpoint() {
                            return Err(error);
                        }
                        yield_now().await;
                    }
                })
                .expect("join-set member spawns");
            }

            for _ in 0..16 {
                if started.load(Ordering::SeqCst) == 3 {
                    break;
                }
                yield_now().await;
            }
            assert_eq!(
                started.load(Ordering::SeqCst),
                3,
                "all members must start before cancel_all is tested"
            );

            let outcomes = set.cancel_all(&cx).await;
            let mut summary = JoinSummary::default();
            for outcome in &outcomes {
                summary.record(outcome);
            }
            (outcomes, summary)
        });

        assert_eq!(outcomes.len(), 3);
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, Outcome::Cancelled(_))),
            "cancel_all must drain every live member to a terminal Cancelled outcome: {outcomes:?}"
        );
        assert_eq!(summary.completed(), 3);
        assert_eq!(summary.worst(), Severity::Cancelled);
    }

    #[test]
    fn cancel_all_with_race_loser_reason_satisfies_loser_drain_witness() {
        let outcomes = run_in_runtime(|cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let mut set = JoinSet::<u32, crate::error::Error, _>::in_cx(&cx);

            for _ in 0..2 {
                let started = Arc::clone(&started);
                set.spawn(&cx, move |member_cx| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    loop {
                        if let Err(error) = member_cx.checkpoint() {
                            return Err(error);
                        }
                        yield_now().await;
                    }
                })
                .expect("join-set member spawns");
            }

            for _ in 0..16 {
                if started.load(Ordering::SeqCst) == 2 {
                    break;
                }
                yield_now().await;
            }
            assert_eq!(
                started.load(Ordering::SeqCst),
                2,
                "both members must start before race-loser cancellation"
            );

            set.cancel_all_with_reason(&cx, CancelReason::race_loser())
                .await
        });

        let loser_refs = outcomes.iter().collect::<Vec<_>>();
        let witness = crate::combinator::race::verify_losers_drained(&loser_refs)
            .expect("JoinSet-drained race losers satisfy L-LOSER-DRAINED");

        assert_eq!(witness.losers_checked(), 2);
        assert!(
            outcomes.iter().all(is_race_lost_or_stronger),
            "explicit race-loser cancellation must preserve RaceLost-or-stronger attribution: {outcomes:?}"
        );
    }

    #[test]
    fn immediate_race_loser_cancel_survives_mailbox_admission() {
        let (outcomes, started_before_cancel) = run_in_runtime(|cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let mut set = JoinSet::<u32, crate::error::Error, _>::in_cx(&cx);

            for _ in 0..2 {
                let started = Arc::clone(&started);
                set.spawn(&cx, move |member_cx| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    for _ in 0..64 {
                        if let Err(error) = member_cx.checkpoint() {
                            return Err(error);
                        }
                        yield_now().await;
                    }
                    Ok(1)
                })
                .expect("join-set member spawns");
            }

            // The current-thread runtime cannot admit the mailbox requests
            // until this task yields. This pins cancellation before admission.
            let started_before_cancel = started.load(Ordering::SeqCst);
            let outcomes = set
                .cancel_all_with_reason(&cx, CancelReason::race_loser())
                .await;
            (outcomes, started_before_cancel)
        });

        assert_eq!(
            started_before_cancel, 0,
            "members must still be provisional when cancellation is requested"
        );
        assert!(
            outcomes.iter().all(is_race_lost_or_stronger),
            "pre-admission cancellation must replay as RaceLost or stronger: {outcomes:?}"
        );
        let loser_refs = outcomes.iter().collect::<Vec<_>>();
        let witness = crate::combinator::race::verify_losers_drained(&loser_refs)
            .expect("pre-admission JoinSet losers satisfy L-LOSER-DRAINED");
        assert_eq!(witness.losers_checked(), 2);
    }

    #[test]
    fn immediate_local_race_loser_cancel_survives_mailbox_admission() {
        let (outcomes, started_before_cancel) = run_in_runtime(|cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let mut set = JoinSet::<u32, crate::error::Error, _>::in_cx(&cx);
            let member_started = Arc::clone(&started);
            set.spawn_local(&cx, move |member_cx| async move {
                member_started.fetch_add(1, Ordering::SeqCst);
                for _ in 0..64 {
                    if let Err(error) = member_cx.checkpoint() {
                        return Err(error);
                    }
                    yield_now().await;
                }
                Ok(1)
            })
            .expect("local join-set member spawns");

            let started_before_cancel = started.load(Ordering::SeqCst);
            let outcomes = set
                .cancel_all_with_reason(&cx, CancelReason::race_loser())
                .await;
            (outcomes, started_before_cancel)
        });

        assert_eq!(
            started_before_cancel, 0,
            "local member must still be provisional when cancellation is requested"
        );
        assert!(
            outcomes.iter().all(is_race_lost_or_stronger),
            "local pre-admission cancellation must replay as RaceLost or stronger: {outcomes:?}"
        );
        let loser_refs = outcomes.iter().collect::<Vec<_>>();
        let witness = crate::combinator::race::verify_losers_drained(&loser_refs)
            .expect("pre-admission local JoinSet loser satisfies L-LOSER-DRAINED");
        assert_eq!(witness.losers_checked(), 1);
    }
