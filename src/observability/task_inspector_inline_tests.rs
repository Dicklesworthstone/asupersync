    use super::*;
    use crate::Budget;
    use crate::time::{TimerDriverHandle, VirtualClock};

    fn inspector_lab_fixture() -> (InspectorSnapshot, InspectorSnapshot) {
        let mut lab = crate::LabRuntime::with_seed(41);
        let root = lab.state.create_root_region(Budget::INFINITE);
        let child = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .unwrap();
        let grandchild = lab
            .state
            .create_child_region(child, Budget::INFINITE)
            .unwrap();
        let budget = Budget {
            deadline: Some(Time::from_secs(30)),
            poll_quota: 64,
            cost_quota: Some(512),
            priority: 17,
        };
        let mut task_ids = Vec::new();
        let mut handles = Vec::new();
        for region in [root, root, child, grandchild, grandchild] {
            let (task, handle) = lab
                .state
                .create_task(region, budget, std::future::pending::<()>())
                .unwrap();
            task_ids.push(task);
            handles.push(handle);
        }
        let task = lab.state.task_mut(task_ids[0]).unwrap();
        task.waiters.push(task_ids[1]);
        let cx = task.cx.as_ref().unwrap().clone();
        lab.advance_time_to(Time::from_secs(2));
        cx.checkpoint_with("private-checkpoint-canary").unwrap();

        let pending = lab
            .state
            .create_obligation(
                ObligationKind::IoOp,
                task_ids[0],
                root,
                Some("private-obligation-canary".to_string()),
            )
            .unwrap();
        let committed = lab
            .state
            .create_obligation(ObligationKind::Lease, task_ids[3], grandchild, None)
            .unwrap();
        lab.state.commit_obligation(committed).unwrap();
        let completed = lab.state.task_mut(task_ids[4]).unwrap();
        completed.state = TaskState::Running;
        completed.phase.store(TaskPhase::Running);
        assert!(
            completed.complete(Outcome::Panicked(crate::types::PanicPayload::new(
                "private-panic-canary",
            )))
        );
        lab.advance_time_to(Time::from_secs(5));

        let full = InspectorSnapshot::from_state(&lab.state, InspectorProfile::Full);
        let shareable = InspectorSnapshot::from_state(&lab.state, InspectorProfile::Shareable);
        // Reading a snapshot neither resolves a held obligation nor consumes its record.
        assert_eq!(lab.state.commit_obligation(pending).unwrap(), 3_000_000_000);
        (full, shareable)
    }

    #[test]
    fn runtime_snapshot_lab_topology_budgets_obligations_and_join_edge() {
        let (snapshot, _) = inspector_lab_fixture();
        assert_eq!(snapshot.schema_version, INSPECTOR_SNAPSHOT_SCHEMA_V1);
        assert_eq!(snapshot.generated_at, Time::from_secs(5));
        assert_eq!(snapshot.counters.tasks, 5);
        assert_eq!(snapshot.counters.active_tasks, 4);
        assert_eq!(snapshot.counters.regions, 3);
        assert_eq!(snapshot.counters.retained_obligations, 2);
        assert_eq!(snapshot.counters.reserved_obligations, 1);
        assert_eq!(snapshot.counters.committed_obligations, 1);
        assert_eq!(snapshot.counters.aborted_obligations, 0);
        assert_eq!(snapshot.counters.leaked_obligations, 0);
        assert_eq!(snapshot.counters.join_wait_edges, 1);

        let root = &snapshot.regions[0];
        let child = &snapshot.regions[1];
        let grandchild = &snapshot.regions[2];
        assert_eq!(root.parent, None);
        assert_eq!(root.children, vec![child.id]);
        assert_eq!(child.parent, Some(root.id));
        assert_eq!(child.children, vec![grandchild.id]);
        assert_eq!(grandchild.parent, Some(child.id));
        assert_eq!(root.pending_obligations, 1);
        assert_eq!(root.pending_spawns, 0);
        assert_eq!(root.budget, InspectorBudget::from(Budget::INFINITE));

        let holder = &snapshot.tasks[0];
        let waiter = &snapshot.tasks[1];
        assert_eq!(root.tasks, vec![holder.details.id, waiter.details.id]);
        assert_eq!(holder.details.region_id, root.id);
        assert_eq!(holder.details.obligations, vec![snapshot.obligations[0].id]);
        assert_eq!(holder.details.waiters, vec![waiter.details.id]);
        assert_eq!(snapshot.obligations[0].holder, holder.details.id);
        assert_eq!(snapshot.obligations[0].region, root.id);
        assert_eq!(snapshot.obligations[0].age_nanos, 3_000_000_000);
        assert_eq!(snapshot.obligations[1].state, ObligationState::Committed);
        assert_eq!(
            snapshot.obligations[1].resolved_at,
            Some(Time::from_secs(2))
        );
        assert_eq!(snapshot.wait_edges[0].waiter, waiter.details.id);
        assert_eq!(snapshot.wait_edges[0].awaited_task, holder.details.id);
        assert_eq!(holder.last_checkpoint, Some(Time::from_secs(2)));
        assert_eq!(holder.checkpoint_count, Some(1));
        assert_eq!(
            holder.details.time_since_last_poll_nanos,
            Some(3_000_000_000)
        );
        assert_eq!(holder.checkpoint_trail.len(), 1);
        assert_eq!(
            waiter.budget,
            Some(InspectorBudget {
                deadline: Some(Time::from_secs(30)),
                poll_quota: 64,
                cost_quota: Some(512),
                priority: 17,
            })
        );
        assert!(!snapshot.coverage.record_tables_locked);
        assert!(snapshot.coverage.dynamic_metadata_sampled_separately);
        assert!(snapshot.coverage.retained_obligations_only);
        assert!(snapshot.coverage.join_wait_edges_only);
        assert!(!snapshot.coverage.scheduler_statistics);
        assert!(!snapshot.coverage.controller_cards);
    }

    #[test]
    fn runtime_snapshot_same_seed_json_is_deterministic_and_shareable() {
        let (full, shareable) = inspector_lab_fixture();
        let (_, replay) = inspector_lab_fixture();
        let full_json = serde_json::to_string(&full).unwrap();
        let shareable_json = serde_json::to_string(&shareable).unwrap();
        assert_eq!(shareable_json, serde_json::to_string(&replay).unwrap());
        assert_eq!(
            serde_json::from_str::<InspectorSnapshot>(&shareable_json).unwrap(),
            shareable
        );
        assert_eq!(full.counters, shareable.counters);
        assert_eq!(full.regions, shareable.regions);
        assert_eq!(full.wait_edges, shareable.wait_edges);
        for canary in ["private-checkpoint-canary", "private-obligation-canary"] {
            assert!(full_json.contains(canary));
            assert!(!shareable_json.contains(canary));
        }
        assert!(!full_json.contains("private-panic-canary"));
        assert!(!shareable_json.contains("private-panic-canary"));
        assert!(full.obligations.iter().all(|ob| ob.acquired_at.is_some()));
        assert!(
            shareable
                .obligations
                .iter()
                .all(|ob| { ob.description.is_none() && ob.acquired_at.is_none() })
        );
        assert!(!shareable_json.contains("task_inspector_inline_tests.rs"));
        assert_eq!(
            shareable.tasks[0].checkpoint_trail[0].at,
            Time::from_secs(2)
        );
        assert_eq!(shareable.tasks[0].checkpoint_trail[0].message, None);
        let wire: serde_json::Value = serde_json::from_str(&shareable_json).unwrap();
        assert_eq!(wire["schema_version"], INSPECTOR_SNAPSHOT_SCHEMA_V1);
        assert!(wire["tasks"][0]["budget"]["poll_quota"].is_number());
        assert!(wire["obligations"][0]["acquired_at"].is_null());
        assert!(wire["coverage"]["scheduler_statistics"].is_boolean());
    }

    #[test]
    fn runtime_snapshot_export_scrubbing_matches_shareable_capture() {
        let (full, shareable) = inspector_lab_fixture();
        let scrubbed = full.into_shareable();
        assert_eq!(scrubbed, shareable);
        assert_eq!(scrubbed.clone().into_shareable(), scrubbed);

        // A callback's declared profile must not bypass export scrubbing.
        let (mut mislabeled, _) = inspector_lab_fixture();
        mislabeled.profile = InspectorProfile::Shareable;
        assert_eq!(mislabeled.into_shareable(), shareable);
    }

    #[test]
    fn runtime_snapshot_ignores_display_filter_and_omits_unclocked_checkpoint_times() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state.create_task(root, Budget::INFINITE, async {}).unwrap();
        let cx = state.task(task_id).unwrap().cx.as_ref().unwrap();
        cx.checkpoint_with("wall-clock-checkpoint").unwrap();
        let obligation_id = state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .unwrap();
        let inspector = TaskInspector::with_config(
            Arc::new(state),
            None,
            TaskInspectorConfig::default().with_show_obligations(false),
        );
        assert!(
            inspector
                .inspect_task(task_id)
                .unwrap()
                .obligations
                .is_empty()
        );
        let snapshot = inspector.runtime_snapshot(InspectorProfile::Full);
        assert_eq!(snapshot.tasks[0].details.obligations, vec![obligation_id]);
        assert_eq!(snapshot.counters.reserved_obligations, 1);
        assert_eq!(snapshot.tasks[0].checkpoint_count, Some(1));
        assert_eq!(snapshot.tasks[0].last_checkpoint, None);
        assert!(snapshot.tasks[0].checkpoint_trail.is_empty());
    }

    #[test]
    fn test_task_state_info_name() {
        assert_eq!(TaskStateInfo::Created.name(), "Created");
        assert_eq!(TaskStateInfo::Running.name(), "Running");
        assert_eq!(
            TaskStateInfo::CancelRequested {
                reason: "test".to_string()
            }
            .name(),
            "CancelRequested"
        );
        assert_eq!(
            TaskStateInfo::Cancelling {
                reason: "test".to_string()
            }
            .name(),
            "Cancelling"
        );
        assert_eq!(
            TaskStateInfo::Finalizing {
                reason: "test".to_string()
            }
            .name(),
            "Finalizing"
        );
        assert_eq!(
            TaskStateInfo::Completed {
                outcome: "Ok".to_string()
            }
            .name(),
            "Completed"
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = TaskInspectorConfig::default();
        assert_eq!(config.stuck_task_threshold, Duration::from_secs(30));
        assert!(config.show_obligations);
        assert!(config.highlight_stuck_tasks);
    }

    #[test]
    fn test_config_builder() {
        let config = TaskInspectorConfig::default()
            .with_stuck_threshold(Duration::from_secs(60))
            .with_show_obligations(false)
            .with_highlight_stuck_tasks(false);

        assert_eq!(config.stuck_task_threshold, Duration::from_secs(60));
        assert!(!config.show_obligations);
        assert!(!config.highlight_stuck_tasks);
    }

    #[test]
    fn test_summary_default() {
        let summary = TaskSummary::default();
        assert_eq!(summary.total_tasks, 0);
        assert_eq!(summary.created, 0);
        assert_eq!(summary.running, 0);
        assert_eq!(summary.cancelling, 0);
        assert_eq!(summary.completed, 0);
        assert_eq!(summary.stuck_count, 0);
        assert!(summary.by_region.is_empty());
    }

    #[test]
    fn test_task_details_is_terminal() {
        let created_details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Created,
            phase: TaskPhase::Created,
            poll_count: 0,
            polls_remaining: 100,
            created_at: Time::ZERO,
            age: Duration::ZERO,
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        assert!(!created_details.is_terminal());

        let completed_details = TaskDetails {
            state: TaskStateInfo::Completed {
                outcome: "Ok".to_string(),
            },
            ..created_details
        };
        assert!(completed_details.is_terminal());
    }

    #[test]
    fn test_task_details_is_running() {
        let running_details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 5,
            polls_remaining: 95,
            created_at: Time::ZERO,
            age: Duration::from_secs(1),
            time_since_last_poll: None,
            wake_pending: true,
            obligations: vec![],
            waiters: vec![],
        };
        assert!(running_details.is_running());
        assert!(!running_details.is_terminal());
        assert!(!running_details.is_cancelling());
    }

    #[test]
    fn test_task_details_is_cancelling() {
        let cancel_requested = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::CancelRequested {
                reason: "Timeout".to_string(),
            },
            phase: TaskPhase::CancelRequested,
            poll_count: 10,
            polls_remaining: 50,
            created_at: Time::ZERO,
            age: Duration::from_secs(5),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        assert!(cancel_requested.is_cancelling());

        let cancelling = TaskDetails {
            state: TaskStateInfo::Cancelling {
                reason: "Timeout".to_string(),
            },
            phase: TaskPhase::Cancelling,
            ..cancel_requested.clone()
        };
        assert!(cancelling.is_cancelling());

        let finalizing = TaskDetails {
            state: TaskStateInfo::Finalizing {
                reason: "Timeout".to_string(),
            },
            phase: TaskPhase::Finalizing,
            ..cancel_requested
        };
        assert!(finalizing.is_cancelling());
    }

    // Pure data-type tests (wave 18 – CyanBarn)

    #[test]
    fn config_debug_clone() {
        let cfg = TaskInspectorConfig::default();
        let cfg2 = cfg;
        assert!(format!("{cfg2:?}").contains("TaskInspectorConfig"));
    }

    #[test]
    fn task_state_info_debug_clone() {
        let s = TaskStateInfo::Running;
        let s2 = s;
        assert!(format!("{s2:?}").contains("Running"));
    }

    #[test]
    fn task_state_info_all_variants_debug() {
        let variants: Vec<TaskStateInfo> = vec![
            TaskStateInfo::Created,
            TaskStateInfo::Running,
            TaskStateInfo::CancelRequested {
                reason: "timeout".into(),
            },
            TaskStateInfo::Cancelling {
                reason: "timeout".into(),
            },
            TaskStateInfo::Finalizing {
                reason: "timeout".into(),
            },
            TaskStateInfo::Completed {
                outcome: "Ok".into(),
            },
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
            assert!(!v.name().is_empty());
        }
    }

    #[test]
    fn task_details_debug_clone() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Created,
            phase: TaskPhase::Created,
            poll_count: 0,
            polls_remaining: 100,
            created_at: Time::ZERO,
            age: Duration::ZERO,
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        let details2 = details;
        assert!(format!("{details2:?}").contains("TaskDetails"));
    }

    #[test]
    fn task_summary_debug_clone_default() {
        let summary = TaskSummary::default();
        let summary2 = summary;
        assert_eq!(summary2.total_tasks, 0);
        assert!(format!("{summary2:?}").contains("TaskSummary"));
    }

    #[test]
    fn task_summary_with_data() {
        let mut summary = TaskSummary {
            total_tasks: 10,
            running: 5,
            completed: 3,
            cancelling: 2,
            stuck_count: 1,
            ..TaskSummary::default()
        };
        summary.by_region.insert(RegionId::testing_default(), 10);
        assert_eq!(summary.by_region.len(), 1);
    }

    #[test]
    fn task_details_with_obligations_and_waiters() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 42,
            polls_remaining: 58,
            created_at: Time::ZERO,
            age: Duration::from_secs(10),
            time_since_last_poll: Some(Duration::from_millis(100)),
            wake_pending: true,
            obligations: vec![ObligationId::new_for_test(1, 0)],
            waiters: vec![TaskId::new_for_test(2, 0)],
        };
        assert!(details.is_running());
        assert!(!details.is_terminal());
        assert!(!details.obligations.is_empty());
        assert!(!details.waiters.is_empty());
    }

    #[test]
    fn task_details_stuck_heuristic_ignores_old_polled_task_without_idle_metadata() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 3,
            polls_remaining: 97,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };

        assert!(!details.is_potentially_stuck(Duration::from_secs(30)));
    }

    #[test]
    fn task_details_stuck_heuristic_uses_idle_metadata_when_available() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 3,
            polls_remaining: 97,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: Some(Duration::from_secs(45)),
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };

        assert!(details.is_potentially_stuck(Duration::from_secs(30)));
    }

    #[test]
    fn wire_snapshot_round_trip_and_schema() {
        let summary = TaskSummaryWire {
            total_tasks: 2,
            created: 0,
            running: 1,
            cancelling: 1,
            completed: 0,
            stuck_count: 0,
            by_region: vec![TaskRegionCountWire {
                region_id: RegionId::new_for_test(1, 0),
                task_count: 2,
            }],
        };
        let first = TaskDetailsWire {
            id: TaskId::new_for_test(1, 0),
            region_id: RegionId::new_for_test(1, 0),
            state: TaskStateInfo::Running,
            phase: "Running".to_string(),
            poll_count: 4,
            polls_remaining: 10,
            created_at: Time::from_nanos(100),
            age_nanos: 200,
            time_since_last_poll_nanos: Some(30),
            wake_pending: true,
            obligations: vec![ObligationId::new_for_test(2, 0)],
            waiters: vec![TaskId::new_for_test(3, 0)],
        };
        let second = TaskDetailsWire {
            id: TaskId::new_for_test(5, 0),
            region_id: RegionId::new_for_test(1, 0),
            state: TaskStateInfo::CancelRequested {
                reason: "Timeout".to_string(),
            },
            phase: "CancelRequested".to_string(),
            poll_count: 2,
            polls_remaining: 3,
            created_at: Time::from_nanos(80),
            age_nanos: 220,
            time_since_last_poll_nanos: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };

        let snapshot =
            TaskConsoleWireSnapshot::new(Time::from_nanos(999), summary, vec![second, first]);
        assert!(snapshot.has_expected_schema());
        assert_eq!(snapshot.schema_version, TASK_CONSOLE_WIRE_SCHEMA_V1);
        assert_eq!(snapshot.tasks[0].id, TaskId::new_for_test(1, 0));
        assert_eq!(snapshot.tasks[1].id, TaskId::new_for_test(5, 0));

        let encoded = snapshot.to_json().expect("wire snapshot must encode");
        let decoded =
            TaskConsoleWireSnapshot::from_json(&encoded).expect("wire snapshot must decode");
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn details_wire_normalizes_collections_and_phase_name() {
        let details = TaskDetails {
            id: TaskId::new_for_test(10, 0),
            region_id: RegionId::new_for_test(1, 0),
            state: TaskStateInfo::Finalizing {
                reason: "Shutdown".to_string(),
            },
            phase: TaskPhase::Finalizing,
            poll_count: 7,
            polls_remaining: 9,
            created_at: Time::from_nanos(10),
            age: Duration::from_nanos(99),
            time_since_last_poll: Some(Duration::from_nanos(7)),
            wake_pending: false,
            obligations: vec![
                ObligationId::new_for_test(3, 0),
                ObligationId::new_for_test(1, 0),
            ],
            waiters: vec![TaskId::new_for_test(8, 0), TaskId::new_for_test(2, 0)],
        };

        let wire = TaskDetailsWire::from(details);
        assert_eq!(wire.phase, "Finalizing");
        assert_eq!(wire.age_nanos, 99);
        assert_eq!(wire.time_since_last_poll_nanos, Some(7));
        assert_eq!(wire.obligations[0], ObligationId::new_for_test(1, 0));
        assert_eq!(wire.obligations[1], ObligationId::new_for_test(3, 0));
        assert_eq!(wire.waiters[0], TaskId::new_for_test(2, 0));
        assert_eq!(wire.waiters[1], TaskId::new_for_test(8, 0));
    }

    fn scrub_task_inspector_snapshot(
        snapshot: &str,
        regions: &[(RegionId, &str)],
        tasks: &[(TaskId, &str)],
        obligations: &[(ObligationId, &str)],
    ) -> String {
        let mut scrubbed = snapshot.to_string();
        for (region_id, label) in regions {
            scrubbed = scrubbed.replace(&format!("{region_id:?}"), label);
            scrubbed = scrubbed.replace(
                &serde_json::to_string_pretty(region_id).expect("region id should encode"),
                &format!("\"{label}\""),
            );
        }
        for (task_id, label) in tasks {
            scrubbed = scrubbed.replace(&format!("{task_id:?}"), label);
            scrubbed = scrubbed.replace(
                &serde_json::to_string_pretty(task_id).expect("task id should encode"),
                &format!("\"{label}\""),
            );
        }
        for (obligation_id, label) in obligations {
            scrubbed = scrubbed.replace(&format!("{obligation_id:?}"), label);
            scrubbed = scrubbed.replace(
                &serde_json::to_string_pretty(obligation_id).expect("obligation id should encode"),
                &format!("\"{label}\""),
            );
        }
        scrubbed
    }

    #[test]
    fn task_inspector_introspection_output_mixed_states_snapshot() {
        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(5)));
        state.now = Time::from_secs(5);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let root = state.create_root_region(Budget::INFINITE);
        let child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");

        let (created_id, _created_handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create created task");
        let (running_id, _running_handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create running task");
        let (cancel_requested_id, _cancel_handle) = state
            .create_task(child, Budget::INFINITE, async {})
            .expect("create cancelling task");
        let (completed_id, _completed_handle) = state
            .create_task(child, Budget::INFINITE, async {})
            .expect("create completed task");
        let (waiter_id, _waiter_handle) = state
            .create_task(child, Budget::INFINITE, async {})
            .expect("create waiter task");

        {
            let created = state.task_mut(created_id).expect("created task record");
            created.polls_remaining = 12;
        }

        let running_cx = {
            let running = state.task_mut(running_id).expect("running task record");
            running.state = TaskState::Running;
            running.phase.store(TaskPhase::Running);
            running.polls_remaining = 6;
            running.increment_polls();
            running.increment_polls();
            running.waiters.push(waiter_id);
            running.wake_state.notify();
            running.cx.as_ref().expect("running task cx").clone()
        };

        let cancel_effects = {
            let cancel_requested = state
                .task_mut(cancel_requested_id)
                .expect("cancel requested task record");
            cancel_requested.polls_remaining = 4;
            cancel_requested.increment_polls();
            cancel_requested.request_cancel(crate::types::CancelReason::timeout())
        };
        let (newly_cancelled, cancel_wakes) = cancel_effects.into_parts();
        cancel_wakes.dispatch();
        assert!(newly_cancelled);

        {
            let completed = state.task_mut(completed_id).expect("completed task record");
            completed.state = TaskState::Running;
            completed.phase.store(TaskPhase::Running);
            completed.polls_remaining = 0;
            completed.increment_polls();
            assert!(completed.complete(Outcome::Ok(())));
        }

        {
            let waiter = state.task_mut(waiter_id).expect("waiter task record");
            waiter.state = TaskState::Running;
            waiter.phase.store(TaskPhase::Running);
            waiter.polls_remaining = 9;
            waiter.increment_polls();
        }

        let pending_obligation = state
            .create_obligation(crate::record::ObligationKind::IoOp, running_id, root, None)
            .expect("create pending obligation");

        clock.advance_to(Time::from_secs(35));
        running_cx.checkpoint().expect("checkpoint");
        clock.advance_to(Time::from_secs(45));

        let inspector = TaskInspector::with_config(
            Arc::new(state),
            None,
            TaskInspectorConfig::default().with_stuck_threshold(Duration::from_secs(20)),
        );
        let summary = inspector.summary();
        let stuck = inspector.find_stuck_tasks_default();
        assert_eq!(
            stuck.iter().map(|task| task.id).collect::<Vec<_>>(),
            vec![created_id]
        );

        let rendered = TaskInspector::format_summary_output(&summary, &stuck, true);
        let wire = inspector
            .wire_snapshot_pretty_json()
            .expect("wire snapshot should encode");
        let scrubbed = scrub_task_inspector_snapshot(
            &format!("== Summary ==\n{rendered}\n== Wire ==\n{wire}\n"),
            &[(root, "<region-root>"), (child, "<region-child>")],
            &[
                (created_id, "<task-created>"),
                (running_id, "<task-running>"),
                (cancel_requested_id, "<task-cancel-requested>"),
                (completed_id, "<task-completed>"),
                (waiter_id, "<task-waiter>"),
            ],
            &[(pending_obligation, "<obligation-pending>")],
        );

        insta::assert_snapshot!("task_inspector_introspection_output_mixed_states", scrubbed);
    }

    #[test]
    fn format_summary_output_hides_stuck_section_when_highlight_disabled() {
        let mut summary = TaskSummary {
            total_tasks: 1,
            running: 1,
            stuck_count: 1,
            ..TaskSummary::default()
        };
        summary.by_region.insert(RegionId::new_for_test(7, 0), 1);
        let stuck = vec![TaskDetails {
            id: TaskId::new_for_test(11, 0),
            region_id: RegionId::new_for_test(7, 0),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 0,
            polls_remaining: 10,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        }];
        let task_label = format!("{:?}", stuck[0].id);

        let output = TaskInspector::format_summary_output(&summary, &stuck, false);
        assert!(output.contains("Stuck: 1"));
        assert!(!output.contains("POTENTIAL STUCK TASKS:"));
        assert!(!output.contains(&task_label));
    }

    #[test]
    fn format_summary_output_shows_stuck_section_when_highlight_enabled() {
        let mut summary = TaskSummary {
            total_tasks: 1,
            running: 1,
            stuck_count: 1,
            ..TaskSummary::default()
        };
        summary.by_region.insert(RegionId::new_for_test(7, 0), 1);
        let stuck = vec![TaskDetails {
            id: TaskId::new_for_test(11, 0),
            region_id: RegionId::new_for_test(7, 0),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 0,
            polls_remaining: 10,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        }];
        let task_label = format!("{:?}", stuck[0].id);

        let output = TaskInspector::format_summary_output(&summary, &stuck, true);
        assert!(output.contains("POTENTIAL STUCK TASKS:"));
        assert!(output.contains(&task_label));
    }

    #[test]
    fn inspector_uses_runtime_logical_time_without_timer_driver() {
        let mut state = RuntimeState::new();
        // Create the task at logical time zero so the age below is measured
        // against a known baseline (RuntimeState::new starts the logical clock
        // at 1s to keep timestamps valid for the obligation guard).
        state.now = Time::ZERO;
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        state.now = Time::from_secs(65);

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.age, Duration::from_secs(65));

        let summary = inspector.summary();
        assert_eq!(summary.stuck_count, 1);

        let wire = inspector.wire_snapshot();
        assert_eq!(wire.generated_at, Time::from_secs(65));
    }

    #[test]
    fn inspector_does_not_flag_old_polled_tasks_without_last_poll_duration() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let task = state.task_mut(task_id).expect("task record");
        task.state = TaskState::Running;
        task.increment_polls();
        state.now = Time::from_secs(65);

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.poll_count, 1);
        assert!(!details.is_potentially_stuck(Duration::from_secs(30)));
        assert!(inspector.find_stuck_tasks_default().is_empty());
        assert_eq!(inspector.summary().stuck_count, 0);
    }

    #[test]
    fn inspector_prefers_timer_driver_when_available() {
        let mut state = RuntimeState::new();
        // Create the task at logical time zero so the age below is measured
        // against a known baseline (RuntimeState::new starts the logical clock
        // at 1s to keep timestamps valid for the obligation guard).
        state.now = Time::ZERO;
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        state.now = Time::from_secs(5);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_secs(8)),
        )));

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.age, Duration::from_secs(8));

        let wire = inspector.wire_snapshot();
        assert_eq!(wire.generated_at, Time::from_secs(8));
    }

    #[test]
    fn inspector_reports_checkpoint_idle_time_from_timer_driver() {
        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(3)));
        state.now = Time::from_secs(3);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let cx = {
            let task = state.task_mut(task_id).expect("task record");
            task.state = TaskState::Running;
            task.increment_polls();
            task.cx.as_ref().expect("task cx").clone()
        };
        cx.checkpoint().expect("checkpoint");
        clock.advance_to(Time::from_secs(8));

        let inspector = TaskInspector::with_config(
            Arc::new(state),
            None,
            TaskInspectorConfig::default().with_stuck_threshold(Duration::from_secs(4)),
        );
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.time_since_last_poll, Some(Duration::from_secs(5)));
        assert!(details.is_potentially_stuck(Duration::from_secs(4)));
        assert_eq!(inspector.summary().stuck_count, 1);
        assert_eq!(
            inspector.wire_snapshot().tasks[0].time_since_last_poll_nanos,
            Some(duration_to_nanos(Duration::from_secs(5)))
        );
    }

    #[test]
    fn inspector_does_not_mix_wall_clock_checkpoint_idle_without_timer_driver() {
        let mut state = RuntimeState::new();
        // Create the task at logical time zero so the age below is measured
        // against a known baseline (RuntimeState::new starts the logical clock
        // at 1s to keep timestamps valid for the obligation guard).
        state.now = Time::ZERO;
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let task = state.task_mut(task_id).expect("task record");
        task.state = TaskState::Running;
        task.increment_polls();
        if let Some(inner) = &task.cx_inner {
            inner.write().checkpoint_state.record_at(Time::from_secs(3));
        }
        state.now = Time::from_secs(5);

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.age, Duration::from_secs(5));
        assert_eq!(details.time_since_last_poll, None);
        assert!(!details.is_potentially_stuck(Duration::from_secs(30)));
        assert_eq!(inspector.summary().stuck_count, 0);
        assert_eq!(
            inspector.wire_snapshot().tasks[0].time_since_last_poll_nanos,
            None
        );
    }

    #[test]
    fn inspector_does_not_mix_checkpoint_time_after_late_timer_driver_attachment() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let cx = {
            let task = state.task_mut(task_id).expect("task record");
            task.state = TaskState::Running;
            task.increment_polls();
            task.cx.as_ref().expect("task cx").clone()
        };
        cx.checkpoint().expect("checkpoint");
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_secs(60)),
        )));

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.time_since_last_poll, None);
        assert_eq!(inspector.summary().stuck_count, 0);
    }

    #[test]
    fn inspector_only_reports_only_pending_obligations() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let pending = state
            .create_obligation(crate::record::ObligationKind::IoOp, task_id, root, None)
            .expect("create pending obligation");
        let committed = state
            .create_obligation(crate::record::ObligationKind::Ack, task_id, root, None)
            .expect("create committed obligation");
        state
            .commit_obligation(committed)
            .expect("commit obligation");
        let aborted = state
            .create_obligation(crate::record::ObligationKind::Lease, task_id, root, None)
            .expect("create aborted obligation");
        state
            .abort_obligation(aborted, crate::record::ObligationAbortReason::Cancel)
            .expect("abort obligation");

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.obligations, vec![pending]);
    }
