    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;

    fn register_pending_result(
        node: &mut SimNode,
        task_id: RemoteTaskId,
    ) -> crate::channel::oneshot::Receiver<Result<RemoteOutcome, RemoteError>> {
        let (tx, rx) = crate::channel::oneshot::channel();
        node.pending_results.lock().insert(
            task_id,
            PendingResultEntry {
                tx: Some(tx),
                state: RemoteTaskState::Pending,
            },
        );
        rx
    }

    fn setup_harness() -> (DistributedHarness, NodeId, NodeId) {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions::local(),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");
        (harness, a, b)
    }

    #[test]
    fn spawn_and_complete_across_nodes() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        // A spawns a task on B
        harness.inject_spawn(&a, &b, task_id);

        // Run long enough for the message to arrive, task to execute, and result to return
        harness.run_for(Duration::from_millis(500));

        // B should have received and completed the spawn
        let node_b = harness.node(&b).unwrap();
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }))
        );
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::SpawnAccepted { .. }))
        );
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::TaskCompleted { .. }))
        );
    }

    #[test]
    fn duplicate_spawn_resends_ack() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        let ack_count = harness
            .trace()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    HarnessTraceEvent {
                        kind: HarnessTraceKind::MessageSent { from, to, msg_type },
                        ..
                    } if from == &b && to == &a && msg_type == "SpawnAck"
                )
            })
            .count();
        assert!(ack_count >= 2);

        let node_b = harness.node(&b).unwrap();
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::DuplicateSpawn { .. }))
        );
        assert_eq!(node_b.running_task_count(), 1);
    }

    #[test]
    fn duplicate_spawn_after_completion_resends_result() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(300));

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(20));

        let result_count = harness
            .trace()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    HarnessTraceEvent {
                        kind: HarnessTraceKind::MessageSent { from, to, msg_type },
                        ..
                    } if from == &b && to == &a && msg_type == "ResultDelivery"
                )
            })
            .count();
        assert!(result_count >= 2);
    }

    #[test]
    fn duplicate_spawn_with_fresh_task_id_delivers_result_to_retry_handle() {
        let (mut harness, a, b) = setup_harness();
        let canonical_task_id = RemoteTaskId::from_raw(9001);
        let retry_task_id = RemoteTaskId::from_raw(9002);
        let key = IdempotencyKey::from_raw(0xfeed_beef);

        let mut rx1 =
            register_pending_result(harness.nodes.get_mut(&a).unwrap(), canonical_task_id);
        let mut rx2 = register_pending_result(harness.nodes.get_mut(&a).unwrap(), retry_task_id);

        harness.send_message(
            &a,
            &b,
            &RemoteMessage::SpawnRequest(SpawnRequest {
                remote_task_id: canonical_task_id,
                computation: crate::remote::ComputationName::new("test-computation"),
                input: crate::remote::RemoteInput::new(vec![1, 2, 3]),
                lease: Duration::from_secs(30),
                idempotency_key: key,
                budget: None,
                origin_node: a.clone(),
                origin_region: crate::types::RegionId::new_for_test(0, 0),
                origin_task: crate::types::TaskId::new_for_test(0, 0),
            }),
        );
        harness.run_for(Duration::from_millis(10));

        harness.send_message(
            &a,
            &b,
            &RemoteMessage::SpawnRequest(SpawnRequest {
                remote_task_id: retry_task_id,
                computation: crate::remote::ComputationName::new("test-computation"),
                input: crate::remote::RemoteInput::new(vec![1, 2, 3]),
                lease: Duration::from_secs(30),
                idempotency_key: key,
                budget: None,
                origin_node: a.clone(),
                origin_region: crate::types::RegionId::new_for_test(0, 0),
                origin_task: crate::types::TaskId::new_for_test(0, 0),
            }),
        );
        harness.run_for(Duration::from_millis(200));

        let origin = harness.node(&a).unwrap();
        let pending = origin.pending_results.lock();
        assert_eq!(
            pending.get(&canonical_task_id).map(|entry| entry.state),
            Some(RemoteTaskState::Completed)
        );
        assert_eq!(
            pending.get(&retry_task_id).map(|entry| entry.state),
            Some(RemoteTaskState::Completed)
        );
        drop(pending);

        let outcome1 = rx1.try_recv().expect("canonical result");
        let outcome2 = rx2.try_recv().expect("retry result");
        assert!(matches!(outcome1, Ok(RemoteOutcome::Success(_))));
        assert!(matches!(outcome2, Ok(RemoteOutcome::Success(_))));

        let remote = harness.node(&b).unwrap();
        assert!(
            remote.duplicate_waiters.is_empty(),
            "duplicate waiter aliases must be cleared once the canonical task completes"
        );
        assert!(
            remote.duplicate_aliases.is_empty(),
            "duplicate alias reverse map must be cleared once the canonical task completes"
        );
    }

    #[test]
    fn duplicate_cancel_with_fresh_task_id_cancels_canonical_task() {
        let (mut harness, a, b) = setup_harness();
        let canonical_task_id = RemoteTaskId::from_raw(9101);
        let retry_task_id = RemoteTaskId::from_raw(9102);
        let key = IdempotencyKey::from_raw(0xcafe_feed);

        let mut rx1 =
            register_pending_result(harness.nodes.get_mut(&a).unwrap(), canonical_task_id);
        let mut rx2 = register_pending_result(harness.nodes.get_mut(&a).unwrap(), retry_task_id);

        let make_request = |remote_task_id| SpawnRequest {
            remote_task_id,
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![4, 5, 6]),
            lease: Duration::from_secs(30),
            idempotency_key: key,
            budget: None,
            origin_node: a.clone(),
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        harness.send_message(
            &a,
            &b,
            &RemoteMessage::SpawnRequest(make_request(canonical_task_id)),
        );
        harness.run_for(Duration::from_millis(10));

        harness.send_message(
            &a,
            &b,
            &RemoteMessage::SpawnRequest(make_request(retry_task_id)),
        );
        harness.run_for(Duration::from_millis(10));

        harness.send_message(
            &a,
            &b,
            &RemoteMessage::CancelRequest(CancelRequest {
                remote_task_id: retry_task_id,
                reason: crate::types::CancelReason::user("retry cancel"),
                origin_node: a.clone(),
            }),
        );
        harness.run_for(Duration::from_millis(200));

        let remote = harness.node(&b).unwrap();
        assert!(
            remote.events().iter().any(|event| matches!(
                event,
                NodeEvent::TaskCancelled { task_id } if *task_id == canonical_task_id
            )),
            "duplicate cancel must cancel the canonical running task"
        );

        let outcome1 = rx1.try_recv().expect("canonical cancelled result");
        let outcome2 = rx2.try_recv().expect("retry cancelled result");
        assert!(matches!(outcome1, Ok(RemoteOutcome::Cancelled(_))));
        assert!(matches!(outcome2, Ok(RemoteOutcome::Cancelled(_))));
    }

    #[test]
    fn cancel_propagates() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        // A spawns a task on B
        harness.inject_spawn(&a, &b, task_id);

        // Run briefly so the spawn arrives
        harness.run_for(Duration::from_millis(10));

        // A cancels the task
        harness.inject_cancel(&a, &b, task_id);

        // Run to let cancellation propagate
        harness.run_for(Duration::from_millis(200));

        let node_b = harness.node(&b).unwrap();
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::CancelReceived { .. }))
        );
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::TaskCancelled { .. }))
        );
    }

    #[test]
    fn partition_prevents_delivery() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions::local(),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");

        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        // Partition before spawning
        harness.execute_fault(&HarnessFault::Network(Fault::Partition {
            hosts_a: vec![host_a],
            hosts_b: vec![host_b],
        }));

        let task_id = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(100));

        // B should NOT have received the spawn
        let node_b = harness.node(&b).unwrap();
        assert!(
            !node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }))
        );
    }

    #[test]
    fn node_crash_drops_tasks() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        // Crash node B
        harness.execute_fault(&HarnessFault::CrashNode(b.clone()));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.crashed);
        assert_eq!(node_b.running_task_count(), 0);
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::Crashed))
        );
    }

    #[test]
    fn in_flight_messages_to_crashed_node_do_not_resurface_after_restart() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions {
                latency: crate::lab::network::LatencyModel::Fixed(Duration::from_millis(50)),
                ..crate::lab::network::NetworkConditions::ideal()
            },
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");
        let task_id = RemoteTaskId::next();

        harness.set_fault_script(
            FaultScript::new()
                .at(
                    Duration::from_millis(10),
                    HarnessFault::CrashNode(b.clone()),
                )
                .at(
                    Duration::from_millis(20),
                    HarnessFault::RestartNode(b.clone()),
                ),
        );

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(200));

        let events = harness.node(&b).unwrap().events();
        assert!(events.iter().any(|e| matches!(e, NodeEvent::Crashed)));
        assert!(events.iter().any(|e| matches!(e, NodeEvent::Restarted)));
        assert!(!events.iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id: seen, .. } if *seen == task_id)
        ));
    }

    #[test]
    fn lease_expiry_fails_tasks() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        // Expire leases on B
        harness.execute_fault(&HarnessFault::ExpireLeases(b.clone()));

        // B should have no running tasks
        let node_b = harness.node(&b).unwrap();
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn rejected_spawn_ack_fails_pending_remote_handle() {
        let (mut harness, a, b) = setup_harness();
        let cap = harness.node(&a).unwrap().create_cap();
        let cx = Cx::for_testing().with_remote_cap(cap);
        let assigned_node = b.clone();
        let mut handle = crate::spawn_remote(
            &cx,
            b,
            crate::ComputationName::new("compute"),
            crate::remote::RemoteInput::empty(),
        )
        .expect("spawn");

        assert_eq!(handle.state(), RemoteTaskState::Pending);

        harness
            .nodes
            .get_mut(&a)
            .expect("origin node")
            .handle_spawn_ack(SpawnAck {
                remote_task_id: handle.remote_task_id(),
                status: SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded),
                assigned_node,
            });

        assert_eq!(handle.state(), RemoteTaskState::Failed);
        let err = handle.try_join().expect_err("rejected spawn");
        assert_eq!(
            err,
            RemoteError::SpawnRejected(SpawnRejectReason::CapacityExceeded)
        );
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn late_rejected_spawn_ack_does_not_clobber_running_remote_handle() {
        let (mut harness, a, b) = setup_harness();
        let cap = harness.node(&a).unwrap().create_cap();
        let cx = Cx::for_testing().with_remote_cap(cap);
        let assigned_node = b.clone();
        let mut handle = crate::spawn_remote(
            &cx,
            b,
            crate::ComputationName::new("compute"),
            crate::remote::RemoteInput::empty(),
        )
        .expect("spawn");

        harness.run_for(Duration::from_millis(15));
        assert_eq!(handle.state(), RemoteTaskState::Running);

        harness
            .nodes
            .get_mut(&a)
            .expect("origin node")
            .handle_spawn_ack(SpawnAck {
                remote_task_id: handle.remote_task_id(),
                status: SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded),
                assigned_node,
            });

        assert_eq!(handle.state(), RemoteTaskState::Running);
        assert!(matches!(handle.try_join(), Ok(None)));

        harness.run_for(Duration::from_millis(200));
        let outcome = handle
            .try_join()
            .expect("result available")
            .expect("remote outcome");
        assert!(matches!(outcome, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);
    }

    #[test]
    fn duplicate_terminal_result_does_not_overwrite_completed_state() {
        let (mut harness, a, b) = setup_harness();
        let cap = harness.node(&a).unwrap().create_cap();
        let cx = Cx::for_testing().with_remote_cap(cap);
        let mut handle = crate::spawn_remote(
            &cx,
            b,
            crate::ComputationName::new("compute"),
            crate::remote::RemoteInput::empty(),
        )
        .expect("spawn");

        harness.run_for(Duration::from_millis(200));
        let outcome = handle
            .try_join()
            .expect("result available")
            .expect("remote outcome");
        assert!(matches!(outcome, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        harness
            .nodes
            .get_mut(&a)
            .expect("origin node")
            .handle_result(ResultDelivery {
                remote_task_id: handle.remote_task_id(),
                outcome: RemoteOutcome::Cancelled(crate::types::CancelReason::user(
                    "protocol violation",
                )),
                execution_time: Duration::ZERO,
            });

        assert_eq!(handle.state(), RemoteTaskState::Completed);
        assert!(matches!(
            handle.try_join(),
            Err(RemoteError::PolledAfterCompletion)
        ));
    }

    #[test]
    fn dropped_handle_terminal_delivery_clears_pending_state_after_disconnected_send() {
        let (mut harness, a, b) = setup_harness();
        let cap = harness.node(&a).unwrap().create_cap();
        let cx = Cx::for_testing().with_remote_cap(cap);
        let handle = crate::spawn_remote(
            &cx,
            b,
            crate::ComputationName::new("compute"),
            crate::remote::RemoteInput::empty(),
        )
        .expect("spawn");

        harness.run_for(Duration::from_millis(15));
        let remote_task_id = handle.remote_task_id();
        drop(handle);

        harness
            .nodes
            .get_mut(&a)
            .expect("origin node")
            .handle_result(ResultDelivery {
                remote_task_id,
                outcome: RemoteOutcome::Success(vec![]),
                execution_time: Duration::ZERO,
            });

        assert!(
            harness
                .nodes
                .get(&a)
                .expect("origin node")
                .pending_results
                .lock()
                .get(&remote_task_id)
                .is_none(),
            "terminal delivery into a dropped handle should clear pending bookkeeping"
        );
    }

    #[test]
    fn fault_script_executes_in_order() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions::local(),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");

        let script = FaultScript::new()
            .at(
                Duration::from_millis(50),
                HarnessFault::CrashNode(b.clone()),
            )
            .at(
                Duration::from_millis(150),
                HarnessFault::RestartNode(b.clone()),
            );
        harness.set_fault_script(script);

        let task_id = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, task_id);

        harness.run_for(Duration::from_millis(200));

        let node_b = harness.node(&b).unwrap();
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::Crashed))
        );
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::Restarted))
        );
        // After restart, node is not crashed
        assert!(!node_b.crashed);
    }

    #[test]
    fn deterministic_replay() {
        // Same setup should produce identical event logs.
        fn run_scenario() -> Vec<String> {
            let config = NetworkConfig {
                seed: 42,
                default_conditions: crate::lab::network::NetworkConditions::lan(),
                ..NetworkConfig::default()
            };
            let mut harness = DistributedHarness::new(config);
            let a = harness.add_node("node-a");
            let b = harness.add_node("node-b");

            // Use a fixed task ID for reproducibility
            let task_id = RemoteTaskId::from_raw(1000);
            harness.inject_spawn(&a, &b, task_id);
            harness.run_for(Duration::from_millis(300));

            harness
                .trace()
                .iter()
                .map(|e| format!("{:?}:{:?}", e.time, e.kind))
                .collect()
        }

        let run1 = run_scenario();
        let run2 = run_scenario();
        assert_eq!(run1, run2, "Replay should be deterministic");
    }

    #[test]
    fn harness_drains_network_inboxes_after_delivery() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, task_id);

        // Long enough for spawn, ack, execution, and result exchange.
        harness.run_for(Duration::from_secs(1));

        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;
        assert!(harness.network.inbox(host_a).unwrap().is_empty());
        assert!(harness.network.inbox(host_b).unwrap().is_empty());
    }

    #[test]
    fn idempotent_spawn_dedup() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        // Send same spawn request twice
        harness.inject_spawn(&a, &b, task_id);
        harness.inject_spawn(&a, &b, task_id);

        harness.run_for(Duration::from_millis(50));

        let node_b = harness.node(&b).unwrap();
        let spawn_count = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::SpawnAccepted { .. }))
            .count();
        let dedup_count = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::DuplicateSpawn { .. }))
            .count();

        // First should be accepted, second should be deduped
        assert_eq!(spawn_count, 1);
        assert_eq!(dedup_count, 1);
    }

    #[test]
    fn idempotency_in_flight_retry_after_insertion_ttl_reuses_canonical_execution() {
        let mut node = SimNode::new(NodeId::new("node-b"), HostId::new(1));
        node.dedup = IdempotencyStore::new(Duration::from_secs(1));

        let origin = NodeId::new("node-a");
        let idempotency_key = IdempotencyKey::from_raw(0x1D3A);
        let canonical_task = RemoteTaskId::from_raw(41);
        let retry_task = RemoteTaskId::from_raw(99);
        let make_request = |remote_task_id| SpawnRequest {
            remote_task_id,
            computation: crate::remote::ComputationName::new("long-running-work"),
            input: crate::remote::RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::from_secs(30),
            idempotency_key,
            budget: None,
            origin_node: origin.clone(),
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        node.handle_spawn(make_request(canonical_task), Time::from_secs(1));
        node.outbox.clear();

        // The retry arrives after the old insertion-relative TTL would have
        // elapsed, but before the canonical operation completes.
        node.handle_spawn(make_request(retry_task), Time::from_secs(3));

        assert_eq!(node.running_tasks.len(), 1);
        assert!(node.running_tasks.contains_key(&canonical_task));
        assert!(!node.running_tasks.contains_key(&retry_task));
        assert_eq!(
            node.events()
                .iter()
                .filter(|event| matches!(event, NodeEvent::SpawnAccepted { .. }))
                .count(),
            1
        );
        assert_eq!(
            node.events()
                .iter()
                .filter(|event| matches!(event, NodeEvent::DuplicateSpawn { .. }))
                .count(),
            1
        );

        let (_, ack) = node.outbox.pop_front().expect("duplicate spawn ack");
        assert!(matches!(
            ack,
            RemoteMessage::SpawnAck(SpawnAck {
                remote_task_id,
                status: SpawnAckStatus::Accepted,
                ..
            }) if remote_task_id == retry_task
        ));
        assert!(node.outbox.is_empty());

        let completed = node.tick(Duration::from_millis(100), Time::from_millis(3_100));
        let result_task_ids: Vec<RemoteTaskId> = completed
            .iter()
            .filter_map(|(_, message)| match message {
                RemoteMessage::ResultDelivery(result) => Some(result.remote_task_id),
                _ => None,
            })
            .collect();
        assert_eq!(result_task_ids, vec![canonical_task, retry_task]);
        assert_eq!(
            node.events()
                .iter()
                .filter(|event| matches!(event, NodeEvent::TaskCompleted { .. }))
                .count(),
            1,
            "one canonical operation must produce both correlated results"
        );
    }

    #[test]
    fn duplicate_spawn_reuses_cached_outcome_but_echoes_retry_task_id() {
        let mut node = SimNode::new(NodeId::new("node-b"), HostId::new(1));
        let origin = NodeId::new("node-a");
        let idempotency_key = IdempotencyKey::from_raw(0xD00D);
        let first_task = RemoteTaskId::from_raw(41);
        let retry_task = RemoteTaskId::from_raw(99);

        let make_request = |remote_task_id| SpawnRequest {
            remote_task_id,
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::from_secs(30),
            idempotency_key,
            budget: None,
            origin_node: origin.clone(),
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        node.handle_spawn(make_request(first_task), Time::from_secs(1));
        node.outbox.clear();
        let _ = node.tick(Duration::from_millis(100), Time::from_secs(2));

        node.handle_spawn(make_request(retry_task), Time::from_secs(2));

        let (_, ack) = node.outbox.pop_front().expect("duplicate spawn ack");
        match ack {
            RemoteMessage::SpawnAck(SpawnAck {
                remote_task_id,
                status: SpawnAckStatus::Accepted,
                ..
            }) => assert_eq!(remote_task_id, retry_task),
            other => panic!("unexpected duplicate ack: {other:?}"),
        }

        let (_, delivery) = node.outbox.pop_front().expect("cached result delivery");
        match delivery {
            RemoteMessage::ResultDelivery(ResultDelivery {
                remote_task_id,
                outcome,
                ..
            }) => {
                assert_eq!(remote_task_id, retry_task);
                assert!(outcome.is_success());
            }
            other => panic!("unexpected cached result: {other:?}"), // ubs:ignore - test helper
        }
    }

    #[test]
    fn duplicated_network_packets_reach_node_logic() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions {
                packet_duplicate: 1.0,
                ..crate::lab::network::NetworkConditions::local()
            },
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(50));

        let node_b = harness.node(&b).unwrap();
        let accepted = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::SpawnAccepted { task_id: seen } if *seen == task_id))
            .count();
        let duplicates = node_b
            .events()
            .iter()
            .filter(
                |e| matches!(e, NodeEvent::DuplicateSpawn { task_id: seen } if *seen == task_id),
            )
            .count();

        assert_eq!(accepted, 1);
        assert_eq!(duplicates, 1);
    }

    #[test]
    fn idempotent_spawn_ttl_expiry_allows_fresh_spawn() {
        let (mut harness, a, b) = setup_harness();
        harness.set_tick(Duration::from_secs(1));
        let task_id = RemoteTaskId::from_raw(7_777);

        // First spawn is accepted.
        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_secs(2));

        // Immediate replay before TTL is deduplicated.
        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_secs(2));

        let node_b = harness.node(&b).unwrap();
        let accepted_before = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::SpawnAccepted { .. }))
            .count();
        let dedup_before = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::DuplicateSpawn { .. }))
            .count();
        assert_eq!(accepted_before, 1);
        assert_eq!(dedup_before, 1);

        // Dedup TTL is 5 minutes; after expiry the same key should be treated as new.
        harness.run_for(Duration::from_secs(301));
        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_secs(2));

        let node_b = harness.node(&b).unwrap();
        let accepted_after = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::SpawnAccepted { .. }))
            .count();
        let dedup_after = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::DuplicateSpawn { .. }))
            .count();
        assert_eq!(
            accepted_after, 2,
            "expired dedup entry should allow respawn"
        );
        assert_eq!(dedup_after, 1, "only pre-expiry replay should deduplicate");
    }

    #[test]
    fn new_harness_uses_configured_tick_resolution() {
        let harness = DistributedHarness::new(NetworkConfig {
            tick_resolution: Duration::from_micros(250),
            ..NetworkConfig::default()
        });

        assert_eq!(harness.tick, Duration::from_micros(250));
    }

    #[test]
    fn zero_tick_is_clamped_to_one_nanosecond() {
        let mut harness = DistributedHarness::new(NetworkConfig {
            tick_resolution: Duration::ZERO,
            ..NetworkConfig::default()
        });

        assert_eq!(harness.tick, Duration::from_nanos(1));
        harness.set_tick(Duration::ZERO);
        assert_eq!(harness.tick, Duration::from_nanos(1));
    }

    #[test]
    fn run_for_caps_final_step_to_remaining_duration() {
        let (mut harness, _, _) = setup_harness();
        harness.set_tick(Duration::from_millis(1));

        harness.run_for(Duration::from_micros(250));

        assert_eq!(harness.sim_time(), Duration::from_micros(250));
    }

    #[test]
    fn faults_within_large_tick_execute_at_their_scheduled_time() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions {
                latency: crate::lab::network::LatencyModel::Fixed(Duration::from_millis(500)),
                ..crate::lab::network::NetworkConditions::ideal()
            },
            tick_resolution: Duration::from_secs(1),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");
        let task_id = RemoteTaskId::next();

        harness.set_fault_script(FaultScript::new().at(
            Duration::from_millis(900),
            HarnessFault::CrashNode(b.clone()),
        ));

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_secs(1));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |event| matches!(event, NodeEvent::SpawnReceived { task_id: seen, .. } if *seen == task_id)
        ));

        let fault_times: Vec<_> = harness
            .trace()
            .iter()
            .filter_map(|event| {
                matches!(event.kind, HarnessTraceKind::FaultInjected(_)).then_some(event.time)
            })
            .collect();
        assert_eq!(fault_times, vec![Duration::from_millis(900)]);
    }

    #[test]
    fn same_tick_faults_follow_timestamp_order() {
        let (mut harness, _, b) = setup_harness();
        harness.set_tick(Duration::from_secs(1));
        harness.set_fault_script(
            FaultScript::new()
                .at(
                    Duration::from_millis(900),
                    HarnessFault::RestartNode(b.clone()),
                )
                .at(
                    Duration::from_millis(100),
                    HarnessFault::CrashNode(b.clone()),
                ),
        );

        harness.run_for(Duration::from_secs(1));

        let node_b = harness.node(&b).unwrap();
        let crash_idx = node_b
            .events()
            .iter()
            .position(|event| matches!(event, NodeEvent::Crashed))
            .unwrap();
        let restart_idx = node_b
            .events()
            .iter()
            .position(|event| matches!(event, NodeEvent::Restarted))
            .unwrap();
        assert!(crash_idx < restart_idx);
        assert!(!node_b.crashed);
    }

    #[test]
    fn partition_heal_recovers_delivery() {
        let (mut harness, a, b) = setup_harness();
        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        harness.execute_fault(&HarnessFault::Network(Fault::Partition {
            hosts_a: vec![host_a],
            hosts_b: vec![host_b],
        }));

        let dropped_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, dropped_task);
        harness.run_for(Duration::from_millis(100));

        let node_b = harness.node(&b).unwrap();
        assert!(!node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == dropped_task)
        ));

        harness.execute_fault(&HarnessFault::Network(Fault::Heal {
            hosts_a: vec![host_a],
            hosts_b: vec![host_b],
        }));

        let recovered_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, recovered_task);
        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == recovered_task)
        ));
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == recovered_task)
        ));
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn crash_restart_recovers_new_tasks() {
        let (mut harness, a, b) = setup_harness();
        let initial_task = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, initial_task);
        harness.run_for(Duration::from_millis(10));

        harness.execute_fault(&HarnessFault::CrashNode(b.clone()));
        let node_b = harness.node(&b).unwrap();
        assert!(node_b.crashed);
        assert_eq!(node_b.running_task_count(), 0);

        harness.execute_fault(&HarnessFault::RestartNode(b.clone()));

        let recovered_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, recovered_task);
        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(!node_b.crashed);
        assert!(
            node_b
                .events()
                .iter()
                .any(|e| matches!(e, NodeEvent::Restarted))
        );
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == recovered_task)
        ));
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn message_loss_then_recovery_delivers_new_work() {
        let (mut harness, a, b) = setup_harness();
        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        let mut loss = crate::lab::network::NetworkConditions::local();
        loss.packet_loss = 1.0;
        harness
            .network
            .set_link_conditions(host_a, host_b, loss.clone());
        harness.network.set_link_conditions(host_b, host_a, loss);

        let dropped_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, dropped_task);
        harness.run_for(Duration::from_millis(100));

        let node_b = harness.node(&b).unwrap();
        assert!(!node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == dropped_task)
        ));
        assert!(harness.network_metrics().packets_dropped > 0);

        let recovered = crate::lab::network::NetworkConditions::local();
        harness
            .network
            .set_link_conditions(host_a, host_b, recovered.clone());
        harness
            .network
            .set_link_conditions(host_b, host_a, recovered);

        let recovered_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, recovered_task);
        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == recovered_task)
        ));
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn clock_skew_advances_causal_clock() {
        let (mut harness, a, b) = setup_harness();
        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        let task_id = RemoteTaskId::next();
        let req = SpawnRequest {
            remote_task_id: task_id,
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![]),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::from_raw(u128::from(task_id.raw())),
            budget: None,
            origin_node: a.clone(),
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        let mut skewed = VectorClock::new();
        skewed.set(&a, 100);
        let envelope = MessageEnvelope::new(
            a.clone(),
            LogicalTime::Vector(skewed.clone()),
            RemoteMessage::SpawnRequest(req),
        );
        let encoded = harness.encode_message(&envelope);
        harness.network.send(host_a, host_b, Bytes::from(encoded));

        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id: seen, .. } if *seen == task_id)
        ));
        let clock = node_b.causal_tracker().current_clock();
        assert!(
            clock.get(&a) >= 100,
            "expected skewed clock to merge into receiver"
        );
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn identity_spoofing_protection_rejects_mismatched_origin_node() {
        // Security regression test for asupersync-1f4mlq
        let node_a = NodeId::new("legitimate-node");
        let node_b = NodeId::new("victim-node");

        // Create a runtime that claims to be node_a
        let outbox = Arc::new(Mutex::new(VecDeque::new()));
        let pending = Arc::new(Mutex::new(BTreeMap::new()));
        let runtime = VirtualNetworkRuntime {
            local_node: node_a.clone(),
            outbox: outbox.clone(),
            pending_results: pending,
        };

        // Try to send a message that claims to originate from victim node_b
        let forged_req = SpawnRequest {
            remote_task_id: RemoteTaskId::next(),
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![]),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::from_raw(42),
            budget: None,
            origin_node: node_b.clone(), // SPOOFED IDENTITY
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        let envelope = MessageEnvelope::new(
            node_a.clone(),
            LogicalTime::Vector(VectorClock::new()),
            RemoteMessage::SpawnRequest(forged_req),
        );

        // The send_message should reject this spoofed identity
        let result = runtime.send_message(&NodeId::new("target"), envelope);
        assert!(result.is_err());

        if let Err(RemoteError::TransportError(msg)) = result {
            assert!(msg.contains("Identity spoofing detected"));
            assert!(msg.contains(&format!("{:?}", node_b)));
            assert!(msg.contains(&format!("{:?}", node_a)));
        } else {
            panic!(
                "Expected TransportError with identity spoofing message, got: {:?}",
                result
            );
        }

        // Verify no message was actually sent
        assert!(outbox.lock().is_empty());
    }

    #[test]
    fn legitimate_origin_node_is_allowed() {
        // Test that legitimate messages (matching origin_node) are allowed
        let node_a = NodeId::new("legitimate-node");

        let outbox = Arc::new(Mutex::new(VecDeque::new()));
        let pending = Arc::new(Mutex::new(BTreeMap::new()));
        let runtime = VirtualNetworkRuntime {
            local_node: node_a.clone(),
            outbox: outbox.clone(),
            pending_results: pending,
        };

        // Send a message with matching origin_node
        let legitimate_req = SpawnRequest {
            remote_task_id: RemoteTaskId::next(),
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![]),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::from_raw(43),
            budget: None,
            origin_node: node_a.clone(), // LEGITIMATE IDENTITY
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        let envelope = MessageEnvelope::new(
            node_a.clone(),
            LogicalTime::Vector(VectorClock::new()),
            RemoteMessage::SpawnRequest(legitimate_req),
        );

        let target = NodeId::new("target");
        let result = runtime.send_message(&target, envelope);
        assert!(result.is_ok());

        // Verify message was sent
        let messages = outbox.lock();
        assert_eq!(messages.len(), 1);

        let (dest, message) = &messages[0];
        assert_eq!(dest, &target);

        // Verify the message has the correct origin_node (runtime's local_node)
        if let RemoteMessage::SpawnRequest(req) = message {
            assert_eq!(req.origin_node, node_a);
        } else {
            panic!("Expected SpawnRequest message");
        }
    }
