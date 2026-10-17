    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::evidence_sink::CollectorSink;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use proptest::prelude::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    fn test_cx() -> crate::cx::Cx {
        crate::cx::Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 1)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn make_controller(
        behavior: PartitionBehavior,
    ) -> (Arc<PartitionController>, Arc<CollectorSink>) {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let ctrl = Arc::new(PartitionController::new(behavior, sink));
        (ctrl, collector)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RouteOutcome {
        Delivered(u32),
        Dropped,
        Disconnected(u32),
    }

    fn route_outcome(
        sender: &PartitionSender<u32>,
        receiver: &mut crate::channel::mpsc::Receiver<u32>,
        cx: &crate::cx::Cx,
        value: u32,
    ) -> RouteOutcome {
        match block_on(sender.send(cx, value)) {
            Ok(()) => match receiver.try_recv() {
                Ok(received) => RouteOutcome::Delivered(received),
                Err(_) => RouteOutcome::Dropped,
            },
            Err(SendError::Disconnected(returned)) => RouteOutcome::Disconnected(returned),
            Err(SendError::Full(returned)) => {
                panic!("unexpected full channel while routing value {returned}") // ubs:ignore
            }
            Err(SendError::Cancelled(returned)) => {
                panic!("unexpected cancellation while routing value {returned}") // ubs:ignore
            }
        }
    }

    struct PartitionTryLockWake {
        controller: Arc<PartitionController>,
        lock_was_available: std::sync::atomic::AtomicBool,
        wake_count: AtomicUsize,
    }

    impl PartitionTryLockWake {
        fn record_wake(&self) {
            let available = self.controller.partitions.try_lock().is_some();
            self.lock_was_available.store(available, Ordering::SeqCst);
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl std::task::Wake for PartitionTryLockWake {
        fn wake(self: Arc<Self>) {
            self.record_wake();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.record_wake();
        }
    }

    #[test]
    fn no_partition_passthrough() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(16, ctrl, a, b);
        let cx = test_cx();

        for i in 0..5 {
            block_on(ptx.send(&cx, i)).expect("send");
        }

        for i in 0..5 {
            assert_eq!(rx.try_recv().unwrap(), i);
        }
    }

    #[test]
    fn partition_drops_messages() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        // Partition A→B.
        ctrl.partition(a, b);
        assert!(ctrl.is_partitioned(a, b));

        // Sends succeed (drop behavior) but messages are lost.
        for i in 0..5 {
            block_on(ptx.send(&cx, i)).expect("send should succeed (drop mode)");
        }
        assert!(rx.try_recv().is_err(), "no messages should be delivered");

        let stats = ctrl.stats();
        assert_eq!(stats.partitions_created, 1);
        assert_eq!(stats.messages_dropped, 5);

        // Evidence logged.
        let entries = collector.entries();
        let drop_entries = entries
            .iter()
            .filter(|e| e.action == "partition_message_dropped")
            .count();
        assert_eq!(drop_entries, 5);
        assert!(
            !entries
                .iter()
                .any(|e| e.action.starts_with("partition_partition_"))
        );
    }

    #[test]
    fn partition_error_mode() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Error);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        ctrl.partition(a, b);
        let result = block_on(ptx.send(&cx, 42));
        assert!(
            matches!(result, Err(SendError::Disconnected(42))),
            "expected Disconnected, got: {result:?}"
        );

        // Error mode rejects sends but does not count them as dropped.
        let stats = ctrl.stats();
        assert_eq!(stats.messages_dropped, 0);

        // Evidence should indicate rejection, not drop.
        let entries = collector.entries();
        assert!(
            entries
                .iter()
                .any(|e| e.action == "partition_message_rejected")
        );
        assert!(
            !entries
                .iter()
                .any(|e| e.action == "partition_message_dropped")
        );
    }

    #[test]
    fn partition_drop_mode_respects_cancellation() {
        let (ctrl, _collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();
        cx.set_cancel_requested(true);

        ctrl.partition(a, b);
        let result = block_on(ptx.send(&cx, 7));
        assert!(matches!(result, Err(SendError::Cancelled(7))));
        assert!(rx.try_recv().is_err());
        assert_eq!(ctrl.stats().messages_dropped, 0);
    }

    #[test]
    fn partition_error_mode_respects_cancellation_precedence() {
        let (ctrl, _collector) = make_controller(PartitionBehavior::Error);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();
        cx.set_cancel_requested(true);

        ctrl.partition(a, b);
        let result = block_on(ptx.send(&cx, 11));
        assert!(matches!(result, Err(SendError::Cancelled(11))));
    }

    #[test]
    fn capacity_parked_send_rechecks_partition_before_commit() {
        for behavior in [PartitionBehavior::Drop, PartitionBehavior::Error] {
            let (ctrl, collector) = make_controller(behavior);
            let a = ActorId::new(1);
            let b = ActorId::new(2);
            let (ptx, mut rx) = partition_channel::<u32>(1, ctrl.clone(), a, b);
            let cx = test_cx();
            ptx.inner().try_send(10).expect("prefill channel");

            let mut send = Box::pin(ptx.send(&cx, 20));
            let waker = std::task::Waker::noop().clone();
            let mut task_cx = Context::from_waker(&waker);
            assert!(matches!(send.as_mut().poll(&mut task_cx), Poll::Pending));

            ctrl.partition(a, b);
            assert_eq!(rx.try_recv(), Ok(10));

            let result = match send.as_mut().poll(&mut task_cx) {
                Poll::Ready(result) => result,
                Poll::Pending => panic!("send remained parked after capacity was released"),
            };
            drop(send);

            match behavior {
                PartitionBehavior::Drop => assert_eq!(result, Ok(())),
                PartitionBehavior::Error => {
                    assert_eq!(result, Err(SendError::Disconnected(20)));
                }
            }
            assert!(
                rx.try_recv().is_err(),
                "blocked value must not be delivered"
            );

            let telemetry = ptx.inner().telemetry_snapshot(91);
            assert_eq!(telemetry.reserved_uncommitted_obligations, 0);
            assert_eq!(telemetry.send_waiter_count, 0);
            assert_eq!(telemetry.cancellation_count, 1);

            let stats = ctrl.stats();
            let entries = collector.entries();
            match behavior {
                PartitionBehavior::Drop => {
                    assert_eq!(stats.messages_dropped, 1);
                    assert_eq!(
                        entries
                            .iter()
                            .filter(|entry| entry.action == "partition_message_dropped")
                            .count(),
                        1
                    );
                }
                PartitionBehavior::Error => {
                    assert_eq!(stats.messages_dropped, 0);
                    assert_eq!(
                        entries
                            .iter()
                            .filter(|entry| entry.action == "partition_message_rejected")
                            .count(),
                        1
                    );
                }
            }

            ctrl.heal(a, b);
            block_on(ptx.send(&cx, 30)).expect("send after heal");
            assert_eq!(rx.try_recv(), Ok(30));
        }
    }

    #[test]
    fn cancellation_wins_while_partition_send_is_capacity_parked() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(1, ctrl.clone(), a, b);
        let cx = test_cx();
        ptx.inner().try_send(10).expect("prefill channel");

        let mut send = Box::pin(ptx.send(&cx, 20));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        assert!(matches!(send.as_mut().poll(&mut task_cx), Poll::Pending));

        ctrl.partition(a, b);
        cx.set_cancel_requested(true);
        let result = match send.as_mut().poll(&mut task_cx) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("cancelled send remained parked"),
        };
        drop(send);

        assert_eq!(result, Err(SendError::Cancelled(20)));
        assert_eq!(rx.try_recv(), Ok(10));
        assert!(rx.try_recv().is_err());
        assert_eq!(ctrl.stats().messages_dropped, 0);
        assert!(!collector.entries().iter().any(|entry| {
            matches!(
                entry.action.as_str(),
                "partition_message_dropped" | "partition_message_rejected"
            )
        }));

        let telemetry = ptx.inner().telemetry_snapshot(92);
        assert_eq!(telemetry.reserved_uncommitted_obligations, 0);
        assert_eq!(telemetry.send_waiter_count, 0);
    }

    #[test]
    fn receiver_drop_while_partition_send_is_parked_preserves_value() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Error);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, rx) = partition_channel::<u32>(1, ctrl.clone(), a, b);
        let cx = test_cx();
        ptx.inner().try_send(10).expect("prefill channel");

        let mut send = Box::pin(ptx.send(&cx, 20));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        assert!(matches!(send.as_mut().poll(&mut task_cx), Poll::Pending));

        drop(rx);
        let result = match send.as_mut().poll(&mut task_cx) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("send remained parked after receiver drop"),
        };
        drop(send);

        assert_eq!(result, Err(SendError::Disconnected(20)));
        assert_eq!(ctrl.stats().messages_dropped, 0);
        assert!(collector.entries().is_empty());
        let telemetry = ptx.inner().telemetry_snapshot(93);
        assert_eq!(telemetry.reserved_uncommitted_obligations, 0);
        assert_eq!(telemetry.send_waiter_count, 0);
    }

    #[test]
    fn partition_commit_wakes_receiver_after_topology_unlock() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(1, ctrl.clone(), a, b);
        let cx = test_cx();

        let probe = Arc::new(PartitionTryLockWake {
            controller: ctrl,
            lock_was_available: std::sync::atomic::AtomicBool::new(false),
            wake_count: AtomicUsize::new(0),
        });
        let waker = std::task::Waker::from(Arc::clone(&probe));
        let mut task_cx = Context::from_waker(&waker);
        let mut recv = Box::pin(rx.recv(&cx));
        assert!(matches!(recv.as_mut().poll(&mut task_cx), Poll::Pending));

        block_on(ptx.send(&cx, 77)).expect("send");
        assert_eq!(probe.wake_count.load(Ordering::SeqCst), 1);
        assert!(probe.lock_was_available.load(Ordering::SeqCst));

        drop(recv);
        assert_eq!(rx.try_recv(), Ok(77));
    }

    #[test]
    fn already_partitioned_send_does_not_wait_for_channel_capacity() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(1, ctrl.clone(), a, b);
        let cx = test_cx();
        ptx.inner().try_send(10).expect("prefill channel");
        ctrl.partition(a, b);

        let mut send = Box::pin(ptx.send(&cx, 20));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        assert!(matches!(
            send.as_mut().poll(&mut task_cx),
            Poll::Ready(Ok(()))
        ));
        drop(send);

        assert_eq!(rx.try_recv(), Ok(10));
        assert!(rx.try_recv().is_err());
        assert_eq!(ctrl.stats().messages_dropped, 1);
    }

    #[test]
    fn heal_restores_delivery() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, mut rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        ctrl.partition(a, b);
        block_on(ptx.send(&cx, 1)).unwrap(); // Dropped.
        assert!(rx.try_recv().is_err());

        ctrl.heal(a, b);
        assert!(!ctrl.is_partitioned(a, b));

        block_on(ptx.send(&cx, 2)).unwrap(); // Delivered.
        assert_eq!(rx.try_recv().unwrap(), 2);

        let stats = ctrl.stats();
        assert_eq!(stats.partitions_healed, 1);
    }

    #[test]
    fn asymmetric_partition() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        // Create channels for both directions.
        let (ptx_ab, mut rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let (ptx_ba, mut rx_a) = partition_channel::<u32>(16, ctrl.clone(), b, a);
        let cx = test_cx();

        // Only partition A→B (asymmetric).
        ctrl.partition(a, b);

        // A→B: dropped.
        block_on(ptx_ab.send(&cx, 1)).unwrap();
        assert!(rx_b.try_recv().is_err());

        // B→A: delivered.
        block_on(ptx_ba.send(&cx, 2)).unwrap();
        assert_eq!(rx_a.try_recv().unwrap(), 2);
    }

    #[test]
    fn symmetric_partition() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx_ab, mut rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let (ptx_ba, mut rx_a) = partition_channel::<u32>(16, ctrl.clone(), b, a);
        let cx = test_cx();

        ctrl.partition_symmetric(a, b);

        // Both directions blocked.
        block_on(ptx_ab.send(&cx, 1)).unwrap();
        block_on(ptx_ba.send(&cx, 2)).unwrap();
        assert!(rx_b.try_recv().is_err());
        assert!(rx_a.try_recv().is_err());

        // Symmetric heal.
        ctrl.heal_symmetric(a, b);
        block_on(ptx_ab.send(&cx, 3)).unwrap();
        block_on(ptx_ba.send(&cx, 4)).unwrap();
        assert_eq!(rx_b.try_recv().unwrap(), 3);
        assert_eq!(rx_a.try_recv().unwrap(), 4);
    }

    #[test]
    fn cascading_partitions() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let c = ActorId::new(3);
        let (tx_a2b, mut rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let (tx_b2c, mut rx_c) = partition_channel::<u32>(16, ctrl.clone(), b, c);
        let (tx_a2c, mut rx_c2) = partition_channel::<u32>(16, ctrl.clone(), a, c);
        let cx = test_cx();

        // Partition A→B and B→C (cascading).
        ctrl.partition(a, b);
        ctrl.partition(b, c);

        // A→B: blocked. A→C: not blocked.
        block_on(tx_a2b.send(&cx, 1)).unwrap();
        block_on(tx_a2c.send(&cx, 2)).unwrap();
        block_on(tx_b2c.send(&cx, 3)).unwrap();

        assert!(rx_b.try_recv().is_err());
        assert!(rx_c.try_recv().is_err());
        assert_eq!(rx_c2.try_recv().unwrap(), 2);
    }

    #[test]
    fn heal_all_clears_all_partitions() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let c = ActorId::new(3);

        ctrl.partition_symmetric(a, b);
        ctrl.partition_symmetric(b, c);
        assert_eq!(ctrl.active_partition_count(), 4); // 2 symmetric = 4 directed.

        ctrl.heal_all();
        assert_eq!(ctrl.active_partition_count(), 0);
        assert_eq!(ctrl.stats().partitions_healed, 4);

        // heal_all should emit heal evidence for every cleared directed edge.
        let entries = collector.entries();
        let heal_entries = entries
            .iter()
            .filter(|e| e.action == "partition_heal")
            .count();
        assert_eq!(heal_entries, 4);
    }

    #[test]
    fn evidence_for_partition_lifecycle() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);

        ctrl.partition(a, b);
        ctrl.heal(a, b);

        let entries = collector.entries();
        assert!(
            entries.iter().any(|e| e.action == "partition_create"),
            "should log partition creation"
        );
        assert!(
            entries.iter().any(|e| e.action == "partition_heal"),
            "should log partition heal"
        );
        assert!(
            !entries
                .iter()
                .any(|e| e.action.starts_with("partition_partition_"))
        );
        for entry in &entries {
            assert_eq!(entry.component, "channel_partition");
            assert!(entry.is_valid());
        }
    }

    #[test]
    fn evidence_timestamps_follow_deterministic_event_sequence() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        ctrl.partition(a, b);
        block_on(ptx.send(&cx, 1)).expect("send");
        ctrl.heal(a, b);

        let timestamps: Vec<u64> = collector
            .entries()
            .iter()
            .map(|entry| entry.ts_unix_ms)
            .collect();
        assert_eq!(timestamps, vec![1, 2, 3]);
    }

    #[test]
    fn idempotent_partition_and_heal() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);

        // Double partition should only count once.
        ctrl.partition(a, b);
        ctrl.partition(a, b);
        assert_eq!(ctrl.stats().partitions_created, 1);

        // Double heal should only count once.
        ctrl.heal(a, b);
        ctrl.heal(a, b);
        assert_eq!(ctrl.stats().partitions_healed, 1);
    }

    // =========================================================================
    // Wave 32: Data-type trait coverage
    // =========================================================================

    #[test]
    fn actor_id_debug_clone_copy_ord_hash() {
        use std::collections::HashSet;
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("ActorId"));
        let cloned = a;
        let copied = a; // Copy
        assert_eq!(cloned, a);
        assert_eq!(copied, a);
        assert_eq!(a, a);
        assert_ne!(a, b);
        assert!(a < b);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(a);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn actor_id_raw_accessor() {
        let a = ActorId::new(42);
        assert_eq!(a.raw(), 42);
    }

    #[test]
    fn partition_stats_debug_clone_default_display() {
        let stats = PartitionStats::default();
        assert_eq!(stats.partitions_created, 0);
        assert_eq!(stats.partitions_healed, 0);
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("PartitionStats"));
        let display = format!("{stats}");
        assert!(display.contains("created: 0"));
        let cloned = stats;
        assert_eq!(cloned.partitions_created, 0);
    }

    #[test]
    fn partition_behavior_debug_clone_copy_eq() {
        let drop_b = PartitionBehavior::Drop;
        let err_b = PartitionBehavior::Error;
        let dbg = format!("{drop_b:?}");
        assert!(dbg.contains("Drop"));
        let cloned = drop_b;
        let copied = drop_b; // Copy
        assert_eq!(cloned, PartitionBehavior::Drop);
        assert_eq!(copied, PartitionBehavior::Drop);
        assert_eq!(drop_b, PartitionBehavior::Drop);
        assert_ne!(drop_b, err_b);
    }

    #[test]
    fn partition_controller_debug() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let dbg = format!("{ctrl:?}");
        assert!(dbg.contains("PartitionController"));
    }

    #[test]
    fn partition_controller_behavior_accessor() {
        let (ctrl, _) = make_controller(PartitionBehavior::Error);
        assert_eq!(ctrl.behavior(), PartitionBehavior::Error);
    }

    #[test]
    fn actor_id_display() {
        let id = ActorId::new(42);
        assert_eq!(format!("{id}"), "actor-42");
    }

    proptest! {
        #[test]
        fn metamorphic_unrelated_partition_churn_preserves_route_outcome(
            a_id in 1u64..1000,
            b_id in 1001u64..2000,
            c_id in 2001u64..3000,
            d_id in 3001u64..4000,
            baseline_value in any::<u32>(),
            churn_value in any::<u32>(),
            blocked_value in any::<u32>(),
            blocked_churn_value in any::<u32>(),
            drop_mode in any::<bool>(),
        ) {
            let behavior = if drop_mode {
                PartitionBehavior::Drop
            } else {
                PartitionBehavior::Error
            };
            let (ctrl, _) = make_controller(behavior);
            let a = ActorId::new(a_id);
            let b = ActorId::new(b_id);
            let c = ActorId::new(c_id);
            let d = ActorId::new(d_id);
            let (ptx, mut rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
            let cx = test_cx();

            let baseline = route_outcome(&ptx, &mut rx, &cx, baseline_value);
            prop_assert_eq!(
                baseline,
                RouteOutcome::Delivered(baseline_value),
                "unpartitioned route should deliver"
            );

            ctrl.partition(c, d);
            ctrl.partition(d, c);
            ctrl.heal(c, d);
            prop_assert!(
                !ctrl.is_partitioned(a, b),
                "unrelated edge churn must not partition the target route"
            );

            let after_unrelated_churn = route_outcome(&ptx, &mut rx, &cx, churn_value);
            prop_assert_eq!(
                after_unrelated_churn,
                RouteOutcome::Delivered(churn_value),
                "disjoint partition churn must not change delivery on the target route"
            );

            ctrl.partition(a, b);
            let blocked = route_outcome(&ptx, &mut rx, &cx, blocked_value);
            match behavior {
                PartitionBehavior::Drop => prop_assert_eq!(blocked, RouteOutcome::Dropped),
                PartitionBehavior::Error => {
                    prop_assert_eq!(blocked, RouteOutcome::Disconnected(blocked_value));
                }
            }

            ctrl.partition(c, d);
            ctrl.heal(d, c);
            ctrl.partition(d, c);
            prop_assert!(
                ctrl.is_partitioned(a, b),
                "unrelated churn must not heal an existing target partition"
            );

            let blocked_after_unrelated_churn =
                route_outcome(&ptx, &mut rx, &cx, blocked_churn_value);
            match behavior {
                PartitionBehavior::Drop => {
                    prop_assert_eq!(
                        blocked_after_unrelated_churn,
                        RouteOutcome::Dropped,
                        "disjoint churn must preserve dropped routing behavior"
                    );
                }
                PartitionBehavior::Error => {
                    prop_assert_eq!(
                        blocked_after_unrelated_churn,
                        RouteOutcome::Disconnected(blocked_churn_value),
                        "disjoint churn must preserve rejected routing behavior"
                    );
                }
            }
        }

        #[test]
        fn metamorphic_partition_sequence_equivalence(
            edges in proptest::collection::vec((1u64..100, 1u64..100), 0..50),
            heals in proptest::collection::vec((1u64..100, 1u64..100), 0..50),
        ) {
            let (ctrl, _) = make_controller(PartitionBehavior::Drop);
            let mut expected_set = std::collections::HashSet::new();

            for &(src, dst) in &edges {
                ctrl.partition(ActorId::new(src), ActorId::new(dst));
                expected_set.insert((src, dst));
            }

            for &(src, dst) in &heals {
                ctrl.heal(ActorId::new(src), ActorId::new(dst));
                expected_set.remove(&(src, dst));
            }

            prop_assert_eq!(
                ctrl.active_partition_count(),
                expected_set.len(),
                "Active partition count must match the hash set size"
            );

            for &(src, dst) in &expected_set {
                prop_assert!(
                    ctrl.is_partitioned(ActorId::new(src), ActorId::new(dst)),
                    "Edge {:?} should be partitioned",
                    (src, dst)
                );
            }

            for &(src, dst) in &edges {
                if !expected_set.contains(&(src, dst)) {
                    prop_assert!(
                        !ctrl.is_partitioned(ActorId::new(src), ActorId::new(dst)),
                        "Edge {:?} should NOT be partitioned",
                        (src, dst)
                    );
                }
            }

            ctrl.heal_all();
            prop_assert_eq!(
                ctrl.active_partition_count(),
                0,
                "heal_all must result in 0 active partitions"
            );

            for &(src, dst) in &edges {
                prop_assert!(
                    !ctrl.is_partitioned(ActorId::new(src), ActorId::new(dst)),
                    "Edge {:?} must be healed after heal_all",
                    (src, dst)
                );
            }
        }
    }
