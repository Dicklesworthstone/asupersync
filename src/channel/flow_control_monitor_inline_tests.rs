    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn potential_deadlocks(monitor: &FlowControlMonitor) -> Vec<&FlowControlViolation> {
        monitor
            .violations()
            .iter()
            .filter_map(|report| {
                matches!(
                    &report.violation,
                    FlowControlViolation::PotentialDeadlock { .. }
                )
                .then_some(&report.violation)
            })
            .collect()
    }

    fn deadlock_tick(monitor: &mut FlowControlMonitor, timestamp: Time) {
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: u64::MAX,
            consumer_task: TaskId::new_for_test(9_999, 0),
            queue_depth: 1,
            timestamp,
        });
    }

    fn record_two_task_cycle(
        monitor: &mut FlowControlMonitor,
        tasks: [TaskId; 2],
        channels: [u64; 2],
        established_edges_at: Time,
        cycle_completed_at: Time,
    ) {
        let [task1, task2] = tasks;
        let [channel1, channel2] = channels;
        for event in [
            FlowControlEvent::BackpressureApplied {
                channel_id: channel1,
                consumer_task: task2,
                queue_depth: 1,
                timestamp: established_edges_at,
            },
            FlowControlEvent::BackpressureApplied {
                channel_id: channel2,
                consumer_task: task1,
                queue_depth: 1,
                timestamp: established_edges_at,
            },
            FlowControlEvent::ProducerBlocked {
                channel_id: channel1,
                task_id: task1,
                reason: FlowControlType::ConsumerBackpressure,
                timestamp: established_edges_at,
            },
            FlowControlEvent::ProducerBlocked {
                channel_id: channel2,
                task_id: task2,
                reason: FlowControlType::ConsumerBackpressure,
                timestamp: cycle_completed_at,
            },
        ] {
            monitor.record_event(event);
        }
    }

    #[test]
    fn test_flow_control_monitor_basic_operations() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        // Test producer blocked event
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::CapacityLimit,
            timestamp: now,
        });

        let stats = monitor.stats();
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.tasks_currently_blocked, 1);
        assert_eq!(stats.channels_under_flow_control, 1);
    }

    #[test]
    fn test_starvation_detection() {
        let mut config = FlowControlConfig::default();
        config.starvation_threshold_s = 1; // 1 second threshold

        let mut monitor = FlowControlMonitor::new(config);
        let start_time = Time::from_nanos(1_000_000_000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        // Task gets blocked
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::ConsumerBackpressure,
            timestamp: start_time,
        });

        // Much later, another event should trigger starvation detection
        let later_time = Time::from_nanos(3_000_000_000); // 2 seconds later
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: TaskId::new_for_test(2, 0),
            queue_depth: 10,
            timestamp: later_time,
        });

        // Should detect starvation
        assert!(!monitor.violations.is_empty());

        let violation = &monitor.violations[0];
        match &violation.violation {
            FlowControlViolation::ProducerStarvation {
                starved_task,
                starvation_duration_s,
                ..
            } => {
                assert_eq!(*starved_task, task_id);
                assert_eq!(*starvation_duration_s, 2);
            }
            _ => panic!("Expected ProducerStarvation violation"),
        }
    }

    #[test]
    fn public_cycle_detects_only_at_threshold() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 2;
        config.starvation_threshold_s = 60;

        let mut monitor = FlowControlMonitor::new(config);
        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);
        let channel1 = 10;
        let channel2 = 20;

        record_two_task_cycle(
            &mut monitor,
            [task1, task2],
            [channel1, channel2],
            Time::from_secs(1),
            Time::from_secs(3),
        );

        assert!(potential_deadlocks(&monitor).is_empty());
        deadlock_tick(&mut monitor, Time::from_secs(4));
        assert!(potential_deadlocks(&monitor).is_empty());
        deadlock_tick(&mut monitor, Time::from_secs(5));

        let deadlocks = potential_deadlocks(&monitor);
        assert_eq!(deadlocks.len(), 1);
        match deadlocks[0] {
            FlowControlViolation::PotentialDeadlock {
                involved_tasks,
                involved_channels,
                detection_time,
                ..
            } => {
                assert_eq!(*detection_time, Time::from_secs(5));
                assert_eq!(involved_tasks.len(), 2);
                assert!(involved_tasks.contains(&task1));
                assert!(involved_tasks.contains(&task2));
                assert_eq!(involved_channels.len(), 2);
                assert!(involved_channels.contains(&channel1));
                assert!(involved_channels.contains(&channel2));
            }
            _ => unreachable!("filtered to potential deadlocks"),
        }
    }

    #[test]
    fn live_cycle_deduplicates_and_rearms_after_release() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        config.starvation_threshold_s = 60;

        let mut monitor = FlowControlMonitor::new(config);
        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);
        let channel1 = 10;
        let channel2 = 20;

        record_two_task_cycle(
            &mut monitor,
            [task1, task2],
            [channel1, channel2],
            Time::from_secs(1),
            Time::from_secs(1),
        );

        deadlock_tick(&mut monitor, Time::from_secs(2));
        assert_eq!(potential_deadlocks(&monitor).len(), 1);
        assert_eq!(monitor.stats().deadlocks_detected, 1);

        // Cancellation records lifecycle state but is not a wait release and
        // does not re-arm or duplicate an already reported live cycle.
        monitor.record_task_cancel(task1, Time::from_secs(3));
        assert_eq!(potential_deadlocks(&monitor).len(), 1);
        deadlock_tick(&mut monitor, Time::from_secs(3));
        deadlock_tick(&mut monitor, Time::from_secs(4));
        assert_eq!(potential_deadlocks(&monitor).len(), 1);
        assert_eq!(monitor.stats().deadlocks_detected, 1);

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id: channel1,
            consumer_task: task2,
            new_queue_depth: 0,
            timestamp: Time::from_secs(5),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: channel1,
            consumer_task: task2,
            queue_depth: 1,
            timestamp: Time::from_secs(7),
        });
        assert_eq!(potential_deadlocks(&monitor).len(), 1);

        deadlock_tick(&mut monitor, Time::from_secs(8));
        let deadlocks = potential_deadlocks(&monitor);
        assert_eq!(deadlocks.len(), 2);
        match deadlocks[1] {
            FlowControlViolation::PotentialDeadlock {
                involved_channels,
                involved_tasks,
                detection_time,
                ..
            } => {
                assert_eq!(*detection_time, Time::from_secs(8));
                assert_eq!(involved_tasks.as_slice(), &[task1, task2]);
                assert_eq!(involved_channels.as_slice(), &[channel1, channel2]);
            }
            _ => unreachable!("filtered to potential deadlocks"),
        }
        assert_eq!(monitor.stats().deadlocks_detected, 2);
    }

    #[test]
    fn overlapping_waits_preserve_continuous_cycle_age() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 3;
        config.starvation_threshold_s = 60;

        let mut monitor = FlowControlMonitor::new(config);
        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);
        let channel1 = 10;
        let channel2 = 20;
        let permit_id = 100;

        record_two_task_cycle(
            &mut monitor,
            [task1, task2],
            [channel1, channel2],
            Time::from_secs(1),
            Time::from_secs(1),
        );
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id: channel1,
            task_id: task1,
            permit_id,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id: channel1,
            task_id: task1,
            reason: FlowControlType::ConsumerBackpressure,
            blocked_duration_ms: 2_000,
            timestamp: Time::from_secs(3),
        });

        assert!(potential_deadlocks(&monitor).is_empty());
        deadlock_tick(&mut monitor, Time::from_secs(4));
        assert_eq!(potential_deadlocks(&monitor).len(), 1);
        assert_eq!(monitor.stats().deadlocks_detected, 1);
    }

    #[test]
    fn multi_owner_channel_checks_all_live_owners() {
        #[derive(Clone, Copy, Debug)]
        enum OwnerRelease {
            None,
            Decoy,
            CycleOwner,
        }

        for release in [
            OwnerRelease::None,
            OwnerRelease::Decoy,
            OwnerRelease::CycleOwner,
        ] {
            let mut config = FlowControlConfig::default();
            config.deadlock_detection_threshold_s = 1;
            config.starvation_threshold_s = 60;

            let mut monitor = FlowControlMonitor::new(config);
            let decoy = TaskId::new_for_test(1, 0);
            let task1 = TaskId::new_for_test(2, 0);
            let task2 = TaskId::new_for_test(3, 0);
            let channel1 = 10;
            let channel2 = 20;

            record_two_task_cycle(
                &mut monitor,
                [task1, task2],
                [channel1, channel2],
                Time::from_secs(1),
                Time::from_secs(1),
            );
            monitor.record_event(FlowControlEvent::BackpressureApplied {
                channel_id: channel1,
                consumer_task: decoy,
                queue_depth: 1,
                timestamp: Time::from_secs(1),
            });

            match release {
                OwnerRelease::None => {}
                OwnerRelease::Decoy => {
                    monitor.record_event(FlowControlEvent::BackpressureReleased {
                        channel_id: channel1,
                        consumer_task: decoy,
                        new_queue_depth: 1,
                        timestamp: Time::from_secs(1),
                    });
                }
                OwnerRelease::CycleOwner => {
                    monitor.record_event(FlowControlEvent::BackpressureReleased {
                        channel_id: channel1,
                        consumer_task: task2,
                        new_queue_depth: 1,
                        timestamp: Time::from_secs(1),
                    });
                }
            }
            deadlock_tick(&mut monitor, Time::from_secs(2));

            let deadlocks = potential_deadlocks(&monitor);
            match release {
                OwnerRelease::None | OwnerRelease::Decoy => {
                    assert_eq!(deadlocks.len(), 1, "release={release:?}");
                    match deadlocks[0] {
                        FlowControlViolation::PotentialDeadlock { involved_tasks, .. } => {
                            assert!(involved_tasks.contains(&task1));
                            assert!(involved_tasks.contains(&task2));
                            assert!(!involved_tasks.contains(&decoy));
                        }
                        _ => unreachable!("filtered to potential deadlocks"),
                    }
                    assert_eq!(monitor.stats().deadlocks_detected, 1);
                }
                OwnerRelease::CycleOwner => {
                    assert!(deadlocks.is_empty(), "release={release:?}");
                    assert_eq!(monitor.stats().deadlocks_detected, 0);
                }
            }
        }
    }

    #[test]
    fn test_indefinite_blocking_detection() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1; // 1 second

        let mut monitor = FlowControlMonitor::new(config);
        let start_time = Time::from_nanos(1_000_000_000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        // Task gets blocked
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::RateLimit,
            timestamp: start_time,
        });

        // Later event triggers indefinite blocking check
        let later_time = Time::from_nanos(3_000_000_000); // 2 seconds later
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 99,
            consumer_task: TaskId::new_for_test(2, 0),
            queue_depth: 5,
            timestamp: later_time,
        });

        // Should detect indefinite blocking
        assert!(!monitor.violations.is_empty());

        let violation = &monitor.violations[0];
        match &violation.violation {
            FlowControlViolation::IndefiniteBlocking {
                blocked_task,
                block_duration_s,
                ..
            } => {
                assert_eq!(*blocked_task, task_id);
                assert_eq!(*block_duration_s, 2);
            }
            _ => panic!("Expected IndefiniteBlocking violation"),
        }
    }

    #[test]
    fn test_producer_unblock_updates_stats() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(1, 0);
        let channel_id = 42;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::CapacityLimit,
            timestamp: Time::from_nanos(500),
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason: FlowControlType::CapacityLimit,
            blocked_duration_ms: 500,
            timestamp: now,
        });

        let stats = monitor.stats();
        assert_eq!(stats.max_block_time_ms, 500);
    }

    #[test]
    fn test_reserve_blocked_creates_task_and_channel_state() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let now = Time::from_nanos(1_000);
        let task_id = TaskId::new_for_test(7, 0);
        let channel_id = 99;
        let permit_id = 1234;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: now,
        });

        let stats = monitor.stats();
        assert_eq!(stats.tasks_currently_blocked, 1);

        let task_state = monitor.task_states.get(&task_id).expect("task state");
        assert!(monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert!(task_state.blocked_channels.contains_key(&channel_id));
        assert_eq!(task_state.first_block_time, Some(now));

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.contains_key(&task_id));
    }

    #[test]
    fn test_reserve_unblocked_clears_blocked_state() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(8, 0);
        let channel_id = 77;
        let permit_id = 4321;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_nanos(1_000),
        });
        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 5,
            timestamp: Time::from_nanos(2_000),
        });

        let stats = monitor.stats();
        assert_eq!(stats.tasks_currently_blocked, 0);

        let task_state = monitor.task_states.get(&task_id).expect("task state");
        assert!(!monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert!(task_state.blocked_channels.is_empty());
        assert!(task_state.first_block_time.is_none());

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.is_empty());
    }

    #[test]
    fn test_commit_without_pending_reserve_reports_atomicity_violation() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(9, 0);
        let channel_id = 55;
        let permit_id = 808;
        let now = Time::from_nanos(10_000);

        monitor.record_event(FlowControlEvent::CommitFlowControlled {
            channel_id,
            task_id,
            permit_id,
            timestamp: now,
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::AtomicityViolation {
                channel_id: violation_channel,
                task_id: violation_task,
                permit_id: violation_permit,
                violation_type,
                ..
            } if *violation_channel == channel_id
                && *violation_task == task_id
                && *violation_permit == permit_id
                && violation_type == "commit_flow_controlled_without_pending_reserve"
        )));
    }

    #[test]
    fn test_commit_with_pending_reserve_clears_state_without_violation() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(12, 0);
        let channel_id = 88;
        let permit_id = 707;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_nanos(10_000),
        });
        monitor.record_event(FlowControlEvent::CommitFlowControlled {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_nanos(20_000),
        });

        assert!(
            !monitor.violations().iter().any(|report| matches!(
                &report.violation,
                FlowControlViolation::AtomicityViolation {
                    channel_id: violation_channel,
                    task_id: violation_task,
                    permit_id: violation_permit,
                    violation_type,
                    ..
                } if *violation_channel == channel_id
                    && *violation_task == task_id
                    && *violation_permit == permit_id
                    && violation_type == "commit_flow_controlled_without_pending_reserve"
            )),
            "valid commit after reserve must not be reported as an atomicity violation"
        );

        let task_state = monitor.task_states.get(&task_id).expect("task state");
        assert!(!monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert!(task_state.blocked_channels.is_empty());
        assert!(task_state.first_block_time.is_none());

        let channel_state = monitor
            .channel_states
            .get(&channel_id)
            .expect("channel state");
        assert!(channel_state.blocked_tasks.is_empty());
    }

    #[test]
    fn test_abort_without_pending_reserve_reports_atomicity_violation() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(10, 0);
        let channel_id = 66;
        let permit_id = 909;
        let now = Time::from_nanos(20_000);

        monitor.record_event(FlowControlEvent::AbortDueToFlowControl {
            channel_id,
            task_id,
            permit_id,
            timeout_reason: "timed out".to_string(),
            timestamp: now,
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::AtomicityViolation {
                channel_id: violation_channel,
                task_id: violation_task,
                permit_id: violation_permit,
                violation_type,
                ..
            } if *violation_channel == channel_id
                && *violation_task == task_id
                && *violation_permit == permit_id
                && violation_type == "abort_without_pending_reserve"
        )));
    }

    #[test]
    fn two_permits_on_one_edge_retain_the_remaining_wait() {
        let mut config = FlowControlConfig::default();
        config.starvation_threshold_s = 3;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(13, 0);
        let channel_id = 101;
        let first_permit = 1_001;
        let second_permit = 1_002;
        let first_time = Time::from_secs(1);
        let second_time = Time::from_secs(2);

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: first_permit,
            timestamp: first_time,
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: second_permit,
            timestamp: second_time,
        });

        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            2
        );
        assert_eq!(
            monitor.channel_states[&channel_id].blocked_tasks[&task_id],
            2
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(first_time)
        );

        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id: first_permit,
            blocked_duration_ms: 10,
            timestamp: Time::from_secs(3),
        });

        assert!(!monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, first_permit)));
        assert!(monitor.has_wait(FlowWaitIdentity::reserve(
            task_id,
            channel_id,
            second_permit
        )));
        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            monitor.channel_states[&channel_id].blocked_tasks[&task_id],
            1
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(second_time)
        );
        assert_eq!(monitor.stats().tasks_currently_blocked, 1);

        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 999,
            consumer_task: TaskId::new_for_test(99, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(4),
        });
        assert!(!monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::ProducerStarvation {
                channel_id: violation_channel,
                starved_task,
                ..
            } if *violation_channel == channel_id && *starved_task == task_id
        )));

        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 999,
            consumer_task: TaskId::new_for_test(99, 0),
            queue_depth: 2,
            timestamp: Time::from_secs(5),
        });
        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::ProducerStarvation {
                channel_id: violation_channel,
                starved_task,
                starvation_duration_s: 3,
                ..
            } if *violation_channel == channel_id && *starved_task == task_id
        )));

        monitor.record_event(FlowControlEvent::CommitFlowControlled {
            channel_id,
            task_id,
            permit_id: second_permit,
            timestamp: Time::from_secs(6),
        });

        assert!(monitor.task_states[&task_id].blocked_channels.is_empty());
        assert!(monitor.channel_states[&channel_id].blocked_tasks.is_empty());
        assert_eq!(monitor.stats().tasks_currently_blocked, 0);
    }

    #[test]
    fn mixed_wait_completions_preserve_the_other_wait_on_same_edge() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(14, 0);
        let channel_id = 102;
        let permit_id = 2_001;
        let reason = FlowControlType::CapacityLimit;
        let reserve_time = Time::from_secs(2);

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: reserve_time,
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason,
            blocked_duration_ms: 7,
            timestamp: Time::from_secs(3),
        });

        assert!(!monitor.has_wait(FlowWaitIdentity::producer(task_id, channel_id, reason)));
        assert!(monitor.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(reserve_time)
        );

        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 5,
            timestamp: Time::from_secs(4),
        });
        assert!(monitor.task_states[&task_id].blocked_channels.is_empty());

        let mut inverse = FlowControlMonitor::with_defaults();
        inverse.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason,
            timestamp: Time::from_secs(1),
        });
        inverse.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: reserve_time,
        });
        inverse.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 5,
            timestamp: Time::from_secs(3),
        });

        assert!(inverse.has_wait(FlowWaitIdentity::producer(task_id, channel_id, reason)));
        assert!(!inverse.has_wait(FlowWaitIdentity::reserve(task_id, channel_id, permit_id)));
        assert_eq!(
            inverse.task_states[&task_id].blocked_channels[&channel_id],
            1
        );

        inverse.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason,
            blocked_duration_ms: 7,
            timestamp: Time::from_secs(4),
        });
        assert!(inverse.task_states[&task_id].blocked_channels.is_empty());
    }

    #[test]
    fn wrong_channel_terminal_events_preserve_the_real_reserve_wait() {
        let task_id = TaskId::new_for_test(15, 0);
        let real_channel = 103;
        let wrong_channel = 104;
        let permit_id = 3_001;

        let terminal_events = [
            (
                FlowControlEvent::ReserveUnblocked {
                    channel_id: wrong_channel,
                    task_id,
                    permit_id,
                    blocked_duration_ms: 1,
                    timestamp: Time::from_secs(2),
                },
                None,
            ),
            (
                FlowControlEvent::CommitFlowControlled {
                    channel_id: wrong_channel,
                    task_id,
                    permit_id,
                    timestamp: Time::from_secs(2),
                },
                Some("commit_flow_controlled_without_pending_reserve"),
            ),
            (
                FlowControlEvent::AbortDueToFlowControl {
                    channel_id: wrong_channel,
                    task_id,
                    permit_id,
                    timeout_reason: "wrong channel".to_string(),
                    timestamp: Time::from_secs(2),
                },
                Some("abort_without_pending_reserve"),
            ),
        ];

        for (terminal_event, expected_atomicity_type) in terminal_events {
            let mut monitor = FlowControlMonitor::with_defaults();
            monitor.record_event(FlowControlEvent::ReserveBlocked {
                channel_id: real_channel,
                task_id,
                permit_id,
                timestamp: Time::from_secs(1),
            });
            monitor.record_event(terminal_event);

            assert!(monitor.has_wait(FlowWaitIdentity::reserve(task_id, real_channel, permit_id)));
            assert_eq!(
                monitor.task_states[&task_id].blocked_channels[&real_channel],
                1
            );
            assert_eq!(
                monitor.channel_states[&real_channel].blocked_tasks[&task_id],
                1
            );
            assert_eq!(monitor.stats().tasks_currently_blocked, 1);
            assert_eq!(monitor.violations().len(), 1);
            let violation = &monitor.violations().back().expect("violation").violation;
            if let Some(expected_type) = expected_atomicity_type {
                assert!(matches!(
                    violation,
                    FlowControlViolation::AtomicityViolation {
                        channel_id: violation_channel,
                        task_id: violation_task,
                        permit_id: violation_permit,
                        violation_type,
                        ..
                    } if *violation_channel == wrong_channel
                        && *violation_task == task_id
                        && *violation_permit == permit_id
                        && violation_type.as_str() == expected_type
                ));
            } else {
                assert!(matches!(
                    violation,
                    FlowControlViolation::FlowControlInconsistency {
                        channel_id: violation_channel,
                        ..
                    } if *violation_channel == wrong_channel
                ));
            }
        }
    }

    #[test]
    fn producer_unblock_requires_the_exact_reason() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(16, 0);
        let channel_id = 105;
        let real_reason = FlowControlType::CreditBased;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: real_reason,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason: FlowControlType::WindowBased,
            blocked_duration_ms: 50,
            timestamp: Time::from_secs(2),
        });

        assert!(monitor.has_wait(FlowWaitIdentity::producer(task_id, channel_id, real_reason)));
        assert_eq!(monitor.total_unblocks, 0);
        assert_eq!(monitor.total_blocked_time_ms, 0);
        assert!(matches!(
            monitor.violations().back().map(|report| &report.violation),
            Some(FlowControlViolation::FlowControlInconsistency { .. })
        ));
    }

    #[test]
    fn duplicate_wait_events_are_idempotent() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let task_id = TaskId::new_for_test(18, 0);
        let channel_id = 107;
        let permit_id = 4_001;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id,
            timestamp: Time::from_secs(1),
        });

        assert_eq!(
            monitor.task_states[&task_id].blocked_channels[&channel_id],
            1
        );
        assert_eq!(
            monitor.channel_states[&channel_id].blocked_tasks[&task_id],
            1
        );
        assert_eq!(
            monitor.task_states[&task_id].first_block_time,
            Some(Time::from_secs(1))
        );

        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 10,
            timestamp: Time::from_secs(3),
        });
        monitor.record_event(FlowControlEvent::ReserveUnblocked {
            channel_id,
            task_id,
            permit_id,
            blocked_duration_ms: 50,
            timestamp: Time::from_secs(4),
        });

        assert_eq!(monitor.total_unblocks, 1);
        assert_eq!(monitor.total_blocked_time_ms, 10);
        assert_eq!(monitor.stats().max_block_time_ms, 10);
        assert!(monitor.task_states[&task_id].blocked_channels.is_empty());
        assert!(monitor.channel_states[&channel_id].blocked_tasks.is_empty());
        assert!(matches!(
            monitor.violations().back().map(|report| &report.violation),
            Some(FlowControlViolation::FlowControlInconsistency { .. })
        ));
    }

    #[test]
    fn cancellation_before_first_block_is_retained() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(17, 0);
        let channel_id = 106;
        let cancel_time = Time::from_secs(1);

        monitor.record_task_cancel(task_id, cancel_time);
        let cancelled_state = monitor.task_states.get(&task_id).expect("cancelled state");
        assert!(cancelled_state.is_cancelled);
        assert_eq!(cancelled_state.cancel_time, Some(cancel_time));

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::ConsumerBackpressure,
            timestamp: Time::from_secs(2),
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::CancellationUnblockFailure {
                channel_id: violation_channel,
                cancelled_task,
                time_since_cancel_s: 1,
                ..
            } if *violation_channel == channel_id && *cancelled_task == task_id
        )));
    }

    #[test]
    fn disabled_monitor_ignores_task_cancellation() {
        let mut config = FlowControlConfig::default();
        config.enable_verification = false;
        let mut monitor = FlowControlMonitor::new(config);

        monitor.record_task_cancel(TaskId::new_for_test(19, 0), Time::from_secs(1));

        assert!(monitor.task_states.is_empty());
    }

    #[test]
    fn test_cancelled_task_still_blocked_reports_unblock_failure() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;

        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(11, 0);
        let channel_id = 77;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::ConsumerBackpressure,
            timestamp: Time::from_nanos(1_000_000_000),
        });
        monitor.record_task_cancel(task_id, Time::from_nanos(2_000_000_000));
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: TaskId::new_for_test(12, 0),
            queue_depth: 4,
            timestamp: Time::from_nanos(4_000_000_000),
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::CancellationUnblockFailure {
                channel_id: violation_channel,
                cancelled_task,
                flow_control_type,
                time_since_cancel_s,
                ..
            } if *violation_channel == channel_id
                && *cancelled_task == task_id
                && *flow_control_type == FlowControlType::ConsumerBackpressure
                && *time_since_cancel_s == 2
        )));
    }

    #[test]
    fn producer_control_refcounts_follow_live_waits() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let channel_id = 201;
        let reason = FlowControlType::RateLimit;
        let first_task = TaskId::new_for_test(21, 0);
        let second_task = TaskId::new_for_test(22, 0);

        for task_id in [first_task, second_task] {
            monitor.record_event(FlowControlEvent::ProducerBlocked {
                channel_id,
                task_id,
                reason,
                timestamp: Time::from_secs(1),
            });
        }

        assert_eq!(
            monitor.channel_states[&channel_id]
                .active_controls
                .get(&reason),
            Some(&2)
        );
        assert_eq!(monitor.stats().channels_under_flow_control, 1);

        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id: first_task,
            reason,
            blocked_duration_ms: 1,
            timestamp: Time::from_secs(2),
        });
        assert_eq!(
            monitor.channel_states[&channel_id]
                .active_controls
                .get(&reason),
            Some(&1)
        );
        assert_eq!(monitor.stats().channels_under_flow_control, 1);

        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id: second_task,
            reason,
            blocked_duration_ms: 1,
            timestamp: Time::from_secs(2),
        });
        assert!(
            monitor.channel_states[&channel_id]
                .active_controls
                .is_empty()
        );
        assert_eq!(monitor.stats().channels_under_flow_control, 0);

        monitor.cleanup_old_state(Time::from_secs(400));
        assert!(!monitor.channel_states.contains_key(&channel_id));
    }

    #[test]
    fn backpressure_control_refcounts_follow_consumer_owners() {
        let mut monitor = FlowControlMonitor::with_defaults();
        let channel_id = 202;
        let first_consumer = TaskId::new_for_test(23, 0);
        let second_consumer = TaskId::new_for_test(24, 0);
        let unknown_consumer = TaskId::new_for_test(25, 0);

        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: first_consumer,
            queue_depth: 2,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: first_consumer,
            queue_depth: 3,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id,
            consumer_task: second_consumer,
            queue_depth: 4,
            timestamp: Time::from_secs(3),
        });

        let state = &monitor.channel_states[&channel_id];
        assert_eq!(
            state
                .active_controls
                .get(&FlowControlType::ConsumerBackpressure),
            Some(&2)
        );
        assert_eq!(state.backpressure_start_time, Some(Time::from_secs(1)));

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id,
            consumer_task: unknown_consumer,
            new_queue_depth: 3,
            timestamp: Time::from_secs(4),
        });
        assert_eq!(
            monitor.channel_states[&channel_id]
                .active_controls
                .get(&FlowControlType::ConsumerBackpressure),
            Some(&2)
        );
        assert!(matches!(
            monitor.violations().back().map(|report| &report.violation),
            Some(FlowControlViolation::FlowControlInconsistency { .. })
        ));

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id,
            consumer_task: first_consumer,
            new_queue_depth: 2,
            timestamp: Time::from_secs(5),
        });
        let state = &monitor.channel_states[&channel_id];
        assert_eq!(
            state
                .active_controls
                .get(&FlowControlType::ConsumerBackpressure),
            Some(&1)
        );
        assert!(state.backpressure_active);
        assert_eq!(state.backpressure_start_time, Some(Time::from_secs(3)));

        monitor.record_event(FlowControlEvent::BackpressureReleased {
            channel_id,
            consumer_task: second_consumer,
            new_queue_depth: 0,
            timestamp: Time::from_secs(6),
        });
        let state = &monitor.channel_states[&channel_id];
        assert!(state.active_controls.is_empty());
        assert!(!state.backpressure_active);
        assert!(state.backpressure_start_time.is_none());
        assert_eq!(monitor.stats().channels_under_flow_control, 0);
    }

    #[test]
    fn reserve_wait_reports_capacity_for_indefinite_and_cancellation() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(26, 0);
        let channel_id = 203;

        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: 5_001,
            timestamp: Time::from_secs(1),
        });
        monitor.record_task_cancel(task_id, Time::from_secs(2));
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 999,
            consumer_task: TaskId::new_for_test(27, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(4),
        });

        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::IndefiniteBlocking {
                channel_id: violation_channel,
                blocked_task,
                flow_control_type: FlowControlType::CapacityLimit,
                block_duration_s: 3,
                ..
            } if *violation_channel == channel_id && *blocked_task == task_id
        )));
        assert!(monitor.violations().iter().any(|report| matches!(
            &report.violation,
            FlowControlViolation::CancellationUnblockFailure {
                channel_id: violation_channel,
                cancelled_task,
                flow_control_type: FlowControlType::CapacityLimit,
                time_since_cancel_s: 2,
                ..
            } if *violation_channel == channel_id && *cancelled_task == task_id
        )));
    }

    #[test]
    fn typed_wait_violations_do_not_cross_attribute_channel_controls() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let channel_id = 204;
        let rate_limited = TaskId::new_for_test(28, 0);
        let capacity_limited = TaskId::new_for_test(29, 0);

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id: rate_limited,
            reason: FlowControlType::RateLimit,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id: capacity_limited,
            reason: FlowControlType::CapacityLimit,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 998,
            consumer_task: TaskId::new_for_test(30, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(3),
        });

        let typed_reports: Vec<_> = monitor
            .violations()
            .iter()
            .filter_map(|report| match report.violation {
                FlowControlViolation::IndefiniteBlocking {
                    channel_id: violation_channel,
                    blocked_task,
                    flow_control_type,
                    ..
                } if violation_channel == channel_id => Some((blocked_task, flow_control_type)),
                _ => None,
            })
            .collect();
        assert_eq!(typed_reports.len(), 2);
        assert!(typed_reports.contains(&(rate_limited, FlowControlType::RateLimit)));
        assert!(typed_reports.contains(&(capacity_limited, FlowControlType::CapacityLimit)));
    }

    #[test]
    fn removed_producer_reason_does_not_label_later_reserve_wait() {
        let mut config = FlowControlConfig::default();
        config.deadlock_detection_threshold_s = 1;
        let mut monitor = FlowControlMonitor::new(config);
        let task_id = TaskId::new_for_test(31, 0);
        let channel_id = 205;

        monitor.record_event(FlowControlEvent::ProducerBlocked {
            channel_id,
            task_id,
            reason: FlowControlType::RateLimit,
            timestamp: Time::from_secs(1),
        });
        monitor.record_event(FlowControlEvent::ProducerUnblocked {
            channel_id,
            task_id,
            reason: FlowControlType::RateLimit,
            blocked_duration_ms: 1,
            timestamp: Time::from_secs(2),
        });
        monitor.record_event(FlowControlEvent::ReserveBlocked {
            channel_id,
            task_id,
            permit_id: 5_002,
            timestamp: Time::from_secs(3),
        });
        monitor.record_event(FlowControlEvent::BackpressureApplied {
            channel_id: 997,
            consumer_task: TaskId::new_for_test(32, 0),
            queue_depth: 1,
            timestamp: Time::from_secs(5),
        });

        let reported_types: Vec<_> = monitor
            .violations()
            .iter()
            .filter_map(|report| match report.violation {
                FlowControlViolation::IndefiniteBlocking {
                    channel_id: violation_channel,
                    blocked_task,
                    flow_control_type,
                    ..
                } if violation_channel == channel_id && blocked_task == task_id => {
                    Some(flow_control_type)
                }
                _ => None,
            })
            .collect();
        assert_eq!(reported_types, vec![FlowControlType::CapacityLimit]);
    }
