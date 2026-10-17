    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn prelude_imports_compile() {
        init_test("prelude_imports_compile");

        // Verify all prelude types are accessible
        let _ = std::any::type_name::<prelude::AppSpec>();
        let _ = std::any::type_name::<prelude::AppHandle>();
        let _ = std::any::type_name::<prelude::StoppedApp>();
        let _ = std::any::type_name::<prelude::SupervisorBuilder>();
        let _ = std::any::type_name::<prelude::ChildSpec>();
        let _ = std::any::type_name::<prelude::RestartConfig>();
        let _ = std::any::type_name::<prelude::SupervisionStrategy>();
        let _ = std::any::type_name::<prelude::RestartPolicy>();
        let _ = std::any::type_name::<prelude::BackoffStrategy>();
        let _ = std::any::type_name::<prelude::NameRegistry>();
        let _ = std::any::type_name::<prelude::RegistryHandle>();
        let _ = std::any::type_name::<prelude::NameLease>();
        let _ = std::any::type_name::<prelude::GroupName>();
        let _ = std::any::type_name::<prelude::GroupMemberId>();
        let _ = std::any::type_name::<prelude::GroupMembership>();
        let _ = std::any::type_name::<prelude::GroupSnapshot>();
        let _ = std::any::type_name::<prelude::GroupEvent>();
        let _ = std::any::type_name::<prelude::GroupEventBatch>();
        let _ = std::any::type_name::<prelude::GroupEventSubscriber>();
        let _ = std::any::type_name::<prelude::ProcessGroupState>();
        let _ = std::any::type_name::<prelude::ProcessGroupError>();
        let _ = std::any::type_name::<prelude::GroupEventCursor>();
        let _ = std::any::type_name::<prelude::GroupBroadcastPlan>();
        let _ = std::any::type_name::<prelude::GroupBroadcastReport>();
        let _ = std::any::type_name::<prelude::GroupBroadcastSummary>();
        let _ = std::any::type_name::<prelude::GroupBroadcastRecipientReport>();
        let _ = std::any::type_name::<prelude::GroupBroadcastRecipientStatus>();
        let _ = std::any::type_name::<prelude::BroadcastBackpressurePolicy>();
        let _ = std::any::type_name::<prelude::GroupMonitorDelivery>();
        let _ = std::any::type_name::<prelude::GroupMonitorDeliveryError>();
        let _ = std::any::type_name::<prelude::MonitorRef>();
        let _ = std::any::type_name::<prelude::DownReason>();
        let _ = std::any::type_name::<prelude::DownNotification>();
        let _ = std::any::type_name::<prelude::DownMsg>();
        let _ = std::any::type_name::<prelude::ExitMsg>();
        let _ = std::any::type_name::<prelude::TimeoutMsg>();
        let _ = std::any::type_name::<prelude::ExitPolicy>();
        let _ = std::any::type_name::<prelude::LinkRef>();
        let _ = std::any::type_name::<prelude::CallError>();
        let _ = std::any::type_name::<prelude::CastError>();
        let _ = std::any::type_name::<prelude::AppStartError>();
        let _ = std::any::type_name::<prelude::AppCompileError>();
        let _ = std::any::type_name::<prelude::SupervisorCompileError>();

        crate::test_complete!("prelude_imports_compile");
    }

    #[test]
    fn submodule_types_accessible() {
        init_test("submodule_types_accessible");

        // App sub-module
        let _ = std::any::type_name::<app::CompiledApp>();
        let _ = std::any::type_name::<app::AppSpawnError>();
        let _ = std::any::type_name::<app::AppStopError>();

        // Supervisor sub-module
        let _ = std::any::type_name::<supervisor::CompiledSupervisor>();
        let _ = std::any::type_name::<supervisor::EscalationPolicy>();
        let _ = std::any::type_name::<supervisor::StartTieBreak>();
        let _ = std::any::type_name::<supervisor::SupervisorHandle>();
        let _ = std::any::type_name::<supervisor::StartedChild>();
        let _ = std::any::type_name::<supervisor::SupervisorSpawnError>();

        // GenServer sub-module
        let _ = std::any::type_name::<gen_server::CastOverflowPolicy>();
        let _ = std::any::type_name::<gen_server::InfoError>();
        let _ = std::any::type_name::<gen_server::ReplyOutcome>();
        let _ = std::any::type_name::<gen_server::DownMsg>();
        let _ = std::any::type_name::<gen_server::ExitMsg>();
        let _ = std::any::type_name::<gen_server::TimeoutMsg>();

        // Registry sub-module
        let _ = std::any::type_name::<registry::NameRegistry>();
        let _ = std::any::type_name::<registry::RegistryHandle>();
        let _ = std::any::type_name::<registry::NameLease>();
        let _ = std::any::type_name::<registry::NameCollisionPolicy>();

        // Process group sub-module
        let _ = std::any::type_name::<process_group::GroupName>();
        let _ = std::any::type_name::<process_group::GroupMemberId>();
        let _ = std::any::type_name::<process_group::GroupMembership>();
        let _ = std::any::type_name::<process_group::GroupMember>();
        let _ = std::any::type_name::<process_group::GroupSnapshot>();
        let _ = std::any::type_name::<process_group::GroupEvent>();
        let _ = std::any::type_name::<process_group::GroupEventBatch>();
        let _ = std::any::type_name::<process_group::GroupEventSubscriber>();
        let _ = std::any::type_name::<process_group::GroupEventCursor>();
        let _ = std::any::type_name::<process_group::GroupBroadcastPlan>();
        let _ = std::any::type_name::<process_group::GroupBroadcastReport>();
        let _ = std::any::type_name::<process_group::GroupBroadcastSummary>();
        let _ = std::any::type_name::<process_group::GroupBroadcastRecipientReport>();
        let _ = std::any::type_name::<process_group::GroupBroadcastRecipientStatus>();
        let _ = std::any::type_name::<process_group::GroupEventKind>();
        let _ = std::any::type_name::<process_group::GroupMonitorDelivery>();
        let _ = std::any::type_name::<process_group::GroupMonitorDeliveryError>();
        let _ = std::any::type_name::<process_group::ProcessGroupState>();
        let _ = std::any::type_name::<process_group::ProcessGroupError>();
        let _ = std::any::type_name::<process_group::BroadcastBackpressurePolicy>();

        // Monitor sub-module
        let _ = std::any::type_name::<monitor::MonitorRef>();

        // Link sub-module
        let _ = std::any::type_name::<link::ExitPolicy>();

        // Crash sub-module
        let _ = std::any::type_name::<crash::CrashPack>();
        let _ = std::any::type_name::<crash::CrashPackConfig>();
        let _ = std::any::type_name::<crash::ReplayCommand>();

        crate::test_complete!("submodule_types_accessible");
    }

    #[test]
    fn supervision_strategy_constructible() {
        init_test("supervision_strategy_constructible");

        // Verify the prelude types can actually be used to construct values
        let _stop = prelude::SupervisionStrategy::Stop;
        let _restart = prelude::SupervisionStrategy::Restart(prelude::RestartConfig::default());
        let _escalate = prelude::SupervisionStrategy::Escalate;

        let _one_for_one = prelude::RestartPolicy::OneForOne;
        let _one_for_all = prelude::RestartPolicy::OneForAll;
        let _rest_for_one = prelude::RestartPolicy::RestForOne;

        let _none = prelude::BackoffStrategy::None;

        crate::test_complete!("supervision_strategy_constructible");
    }

    #[test]
    fn down_reason_constructible() {
        init_test("down_reason_constructible");

        let _normal = prelude::DownReason::Normal;
        let _error = prelude::DownReason::Error("oops".to_string());

        crate::test_complete!("down_reason_constructible");
    }

    #[test]
    fn exit_policy_constructible() {
        init_test("exit_policy_constructible");

        let _prop = prelude::ExitPolicy::Propagate;
        let _trap = prelude::ExitPolicy::Trap;
        let _ignore = prelude::ExitPolicy::Ignore;

        crate::test_complete!("exit_policy_constructible");
    }

    fn test_task_id(index: u32) -> crate::types::TaskId {
        crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(index, 0))
    }

    fn test_member(node: &str, task_index: u32, sequence: u64) -> process_group::GroupMember {
        process_group::GroupMember::new(
            process_group::GroupMemberId::new(
                crate::remote::NodeId::new(node),
                test_task_id(task_index),
            ),
            crate::types::Time::from_nanos(sequence),
            sequence,
        )
    }

    #[test]
    fn process_group_name_validation_rejects_empty_and_nul() {
        init_test("process_group_name_validation_rejects_empty_and_nul");

        assert_eq!(
            process_group::GroupName::new("   ").unwrap_err(),
            process_group::GroupNameError::Empty
        );
        assert_eq!(
            process_group::GroupName::new("workers\0blue").unwrap_err(),
            process_group::GroupNameError::ContainsNul
        );
        assert_eq!(
            process_group::GroupName::new("workers").unwrap().as_str(),
            "workers"
        );

        crate::test_complete!("process_group_name_validation_rejects_empty_and_nul");
    }

    #[test]
    fn process_group_snapshot_orders_by_join_sequence_then_member_id() {
        init_test("process_group_snapshot_orders_by_join_sequence_then_member_id");

        let group = process_group::GroupName::new("workers").unwrap();
        let snapshot = process_group::GroupSnapshot::new(
            group,
            vec![
                test_member("node-b", 2, 20),
                test_member("node-c", 3, 10),
                test_member("node-a", 1, 10),
            ],
        );

        let ordered: Vec<String> = snapshot
            .member_ids()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            ordered,
            vec!["Node(node-a):T1", "Node(node-c):T3", "Node(node-b):T2"]
        );
        assert_eq!(snapshot.len(), 3);
        assert!(!snapshot.is_empty());

        crate::test_complete!("process_group_snapshot_orders_by_join_sequence_then_member_id");
    }

    #[test]
    fn process_group_event_preserves_down_reason() {
        init_test("process_group_event_preserves_down_reason");

        let group = process_group::GroupName::new("workers").unwrap();
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(7),
        );
        let event = process_group::GroupEvent::new(
            group,
            member,
            process_group::GroupEventKind::Down(monitor::DownReason::Error("boom".into())),
            crate::types::Time::from_millis(5),
        );

        assert_eq!(event.group().as_str(), "workers");
        assert_eq!(event.at(), crate::types::Time::from_millis(5));
        assert_eq!(event.sequence(), 0);
        assert!(matches!(
            event.kind(),
            process_group::GroupEventKind::Down(monitor::DownReason::Error(message))
                if message == "boom"
        ));

        crate::test_complete!("process_group_event_preserves_down_reason");
    }

    #[test]
    fn process_group_backpressure_default_waits() {
        init_test("process_group_backpressure_default_waits");

        assert_eq!(
            process_group::BroadcastBackpressurePolicy::default(),
            process_group::BroadcastBackpressurePolicy::Wait
        );

        crate::test_complete!("process_group_backpressure_default_waits");
    }

    #[test]
    fn process_group_broadcast_plan_preserves_join_order_and_policy() {
        init_test("process_group_broadcast_plan_preserves_join_order_and_policy");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        state
            .join(first, crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(second, crate::types::Time::from_nanos(10))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let recipients: Vec<String> = plan
            .recipients()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        assert_eq!(plan.group().as_str(), "workers");
        assert_eq!(
            plan.policy(),
            process_group::BroadcastBackpressurePolicy::Skip
        );
        assert_eq!(plan.len(), 2);
        assert_eq!(recipients, vec!["Node(node-b):T2", "Node(node-a):T1"]);

        crate::test_complete!("process_group_broadcast_plan_preserves_join_order_and_policy");
    }

    #[test]
    fn process_group_broadcast_plan_allows_empty_groups() {
        init_test("process_group_broadcast_plan_allows_empty_groups");

        let state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);

        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert_eq!(
            plan.policy(),
            process_group::BroadcastBackpressurePolicy::Error
        );

        crate::test_complete!("process_group_broadcast_plan_allows_empty_groups");
    }

    #[test]
    fn process_group_broadcast_report_preserves_plan_order_and_counts() {
        init_test("process_group_broadcast_report_preserves_plan_order_and_counts");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let third = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(third.clone(), crate::types::Time::from_nanos(30))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let report = process_group::GroupBroadcastReport::from_plan(
            &plan,
            vec![
                (
                    third,
                    process_group::GroupBroadcastRecipientStatus::Backpressured,
                ),
                (
                    first,
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    second,
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
            ],
        )
        .unwrap();
        let recipients: Vec<(String, process_group::GroupBroadcastRecipientStatus)> = report
            .recipients()
            .iter()
            .map(|recipient| (recipient.member().to_string(), recipient.status()))
            .collect();

        assert_eq!(report.group().as_str(), "workers");
        assert_eq!(
            report.policy(),
            process_group::BroadcastBackpressurePolicy::Skip
        );
        assert_eq!(report.len(), 3);
        assert_eq!(
            recipients,
            vec![
                (
                    "Node(node-b):T2".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    "Node(node-a):T1".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    "Node(node-c):T3".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Backpressured,
                ),
            ]
        );
        assert_eq!(
            report.count_status(process_group::GroupBroadcastRecipientStatus::Delivered),
            1
        );
        assert_eq!(
            report.count_status(process_group::GroupBroadcastRecipientStatus::Skipped),
            1
        );
        assert_eq!(
            report.count_status(process_group::GroupBroadcastRecipientStatus::Backpressured),
            1
        );

        crate::test_complete!("process_group_broadcast_report_preserves_plan_order_and_counts");
    }

    #[test]
    fn process_group_broadcast_summary_separates_policy_outcomes() {
        init_test("process_group_broadcast_summary_separates_policy_outcomes");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let third = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(third.clone(), crate::types::Time::from_nanos(30))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let report = process_group::GroupBroadcastReport::from_plan(
            &plan,
            vec![
                (
                    first.clone(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    second,
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    third,
                    process_group::GroupBroadcastRecipientStatus::Backpressured,
                ),
            ],
        )
        .unwrap();
        let summary = report.summary();

        assert_eq!(summary, process_group::GroupBroadcastSummary::new(1, 1, 1));
        assert_eq!(summary.delivered(), 1);
        assert_eq!(summary.skipped(), 1);
        assert_eq!(summary.backpressured(), 1);
        assert_eq!(summary.total(), 3);
        assert_eq!(report.delivered_count(), 1);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.backpressured_count(), 1);
        assert!(!report.is_all_delivered());
        assert!(!summary.is_all_delivered());
        assert!(summary.has_skipped_recipients());
        assert!(summary.has_backpressured_recipients());

        let all_delivered = process_group::GroupBroadcastReport::all_delivered(&plan);
        assert_eq!(
            all_delivered.summary(),
            process_group::GroupBroadcastSummary::new(3, 0, 0)
        );
        assert!(all_delivered.is_all_delivered());

        crate::test_complete!("process_group_broadcast_summary_separates_policy_outcomes");
    }

    #[test]
    fn process_group_broadcast_policy_reports_account_every_recipient() {
        init_test("process_group_broadcast_policy_reports_account_every_recipient");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        state
            .join(first, crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second, crate::types::Time::from_nanos(20))
            .unwrap();

        let skip_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let skipped = process_group::GroupBroadcastReport::all_skipped(&skip_plan);
        assert_eq!(
            skipped.policy(),
            process_group::BroadcastBackpressurePolicy::Skip
        );
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped.skipped_count(), 2);
        assert_eq!(
            skipped.summary(),
            process_group::GroupBroadcastSummary::new(0, 2, 0)
        );
        assert_eq!(
            skipped
                .recipients()
                .iter()
                .map(|recipient| (recipient.member().to_string(), recipient.status()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Node(node-a):T1".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    "Node(node-b):T2".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
            ]
        );

        let error_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);
        let backpressured = process_group::GroupBroadcastReport::all_backpressured(&error_plan);
        assert_eq!(
            backpressured.policy(),
            process_group::BroadcastBackpressurePolicy::Error
        );
        assert_eq!(backpressured.backpressured_count(), 2);
        assert_eq!(
            backpressured.summary(),
            process_group::GroupBroadcastSummary::new(0, 0, 2)
        );
        assert!(!backpressured.is_all_delivered());

        crate::test_complete!("process_group_broadcast_policy_reports_account_every_recipient");
    }

    #[test]
    fn process_group_broadcast_plan_reports_immediate_delivery_in_order() {
        init_test("process_group_broadcast_plan_reports_immediate_delivery_in_order");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let third = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(third.clone(), crate::types::Time::from_nanos(30))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let mut visited = Vec::new();
        let report = plan.immediate_delivery_report(|member| {
            visited.push(member.to_string());
            member != &second
        });

        assert_eq!(
            visited,
            vec![
                "Node(node-a):T1".to_string(),
                "Node(node-b):T2".to_string(),
                "Node(node-c):T3".to_string(),
            ]
        );
        assert_eq!(
            report
                .recipients()
                .iter()
                .map(|recipient| (recipient.member().to_string(), recipient.status()))
                .collect::<Vec<_>>(),
            vec![
                (
                    first.to_string(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    second.to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    third.to_string(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
            ]
        );
        assert_eq!(
            report.summary(),
            process_group::GroupBroadcastSummary::new(2, 1, 0)
        );

        crate::test_complete!("process_group_broadcast_plan_reports_immediate_delivery_in_order");
    }

    #[test]
    fn process_group_broadcast_plan_classifies_wait_and_error_backpressure() {
        init_test("process_group_broadcast_plan_classifies_wait_and_error_backpressure");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        state
            .join(first, crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second, crate::types::Time::from_nanos(20))
            .unwrap();

        let wait_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Wait);
        let wait_report = wait_plan.immediate_delivery_report(|_| false);
        assert_eq!(
            wait_report.summary(),
            process_group::GroupBroadcastSummary::new(0, 0, 2)
        );
        assert!(wait_report.summary().has_backpressured_recipients());

        let error_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);
        let error_report =
            error_plan.immediate_delivery_report(|member| member.to_string().ends_with(":T2"));
        assert_eq!(
            error_report.summary(),
            process_group::GroupBroadcastSummary::new(1, 0, 1)
        );
        assert_eq!(
            error_report
                .recipients()
                .iter()
                .map(process_group::GroupBroadcastRecipientReport::status)
                .collect::<Vec<_>>(),
            vec![
                process_group::GroupBroadcastRecipientStatus::Backpressured,
                process_group::GroupBroadcastRecipientStatus::Delivered,
            ]
        );

        crate::test_complete!(
            "process_group_broadcast_plan_classifies_wait_and_error_backpressure"
        );
    }

    #[test]
    fn process_group_broadcast_report_rejects_silent_accounting_gaps() {
        init_test("process_group_broadcast_report_rejects_silent_accounting_gaps");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let unknown = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);

        assert_eq!(
            process_group::GroupBroadcastReport::from_plan(
                &plan,
                vec![(
                    first.clone(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                )],
            )
            .unwrap_err(),
            process_group::ProcessGroupError::BroadcastRecipientMissing(second.clone())
        );
        assert_eq!(
            process_group::GroupBroadcastReport::from_plan(
                &plan,
                vec![
                    (
                        first.clone(),
                        process_group::GroupBroadcastRecipientStatus::Delivered,
                    ),
                    (
                        unknown.clone(),
                        process_group::GroupBroadcastRecipientStatus::Skipped,
                    ),
                ],
            )
            .unwrap_err(),
            process_group::ProcessGroupError::BroadcastRecipientUnknown(unknown)
        );
        assert_eq!(
            process_group::GroupBroadcastReport::from_plan(
                &plan,
                vec![
                    (
                        first.clone(),
                        process_group::GroupBroadcastRecipientStatus::Delivered,
                    ),
                    (
                        first.clone(),
                        process_group::GroupBroadcastRecipientStatus::Skipped,
                    ),
                    (
                        second,
                        process_group::GroupBroadcastRecipientStatus::Delivered,
                    ),
                ],
            )
            .unwrap_err(),
            process_group::ProcessGroupError::BroadcastRecipientDuplicate(first)
        );

        crate::test_complete!("process_group_broadcast_report_rejects_silent_accounting_gaps");
    }

    #[test]
    fn process_group_membership_handle_leaves_once() {
        init_test("process_group_membership_handle_leaves_once");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );

        let mut membership = state
            .join_membership(member.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        assert!(membership.is_active());
        assert_eq!(membership.group(), state.group());
        assert_eq!(membership.member(), &member);
        assert!(matches!(
            membership.joined_event().kind(),
            process_group::GroupEventKind::Joined
        ));
        assert!(state.contains_member(&member));

        let left = membership
            .leave(&mut state, crate::types::Time::from_nanos(20))
            .unwrap()
            .expect("first leave should emit an event");
        assert!(matches!(left.kind(), process_group::GroupEventKind::Left));
        assert_eq!(left.member(), &member);
        assert_eq!(left.sequence(), 1);
        assert!(!membership.is_active());
        assert!(!state.contains_member(&member));
        assert_eq!(state.event_log().len(), 2);

        assert_eq!(
            membership
                .leave(&mut state, crate::types::Time::from_nanos(30))
                .unwrap(),
            None
        );
        assert_eq!(state.event_log().len(), 2);

        crate::test_complete!("process_group_membership_handle_leaves_once");
    }

    #[test]
    fn process_group_membership_handle_marks_down_once() {
        init_test("process_group_membership_handle_marks_down_once");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let mut membership = state
            .join_membership(member.clone(), crate::types::Time::from_nanos(10))
            .unwrap();

        let down = membership
            .mark_down(
                &mut state,
                monitor::DownReason::Error("crashed".into()),
                crate::types::Time::from_nanos(20),
            )
            .unwrap()
            .expect("first down transition should emit an event");
        assert!(matches!(
            down.kind(),
            process_group::GroupEventKind::Down(monitor::DownReason::Error(message))
                if message == "crashed"
        ));
        assert_eq!(down.member(), &member);
        assert!(!membership.is_active());
        assert!(!state.contains_member(&member));

        assert_eq!(
            membership
                .mark_down(
                    &mut state,
                    monitor::DownReason::Normal,
                    crate::types::Time::from_nanos(30),
                )
                .unwrap(),
            None
        );
        assert_eq!(state.event_log().len(), 2);

        crate::test_complete!("process_group_membership_handle_marks_down_once");
    }

    #[test]
    fn process_group_membership_handle_rejects_wrong_group_state() {
        init_test("process_group_membership_handle_rejects_wrong_group_state");

        let mut workers = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let mut auditors = process_group::ProcessGroupState::new(
            process_group::GroupName::new("auditors").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let mut membership = workers
            .join_membership(member.clone(), crate::types::Time::from_nanos(10))
            .unwrap();

        assert_eq!(
            membership
                .leave(&mut auditors, crate::types::Time::from_nanos(20))
                .unwrap_err(),
            process_group::ProcessGroupError::GroupMismatch {
                handle: process_group::GroupName::new("workers").unwrap(),
                state: process_group::GroupName::new("auditors").unwrap(),
            }
        );
        assert!(membership.is_active());
        assert!(workers.contains_member(&member));
        assert!(!auditors.contains_member(&member));

        let left = membership
            .leave(&mut workers, crate::types::Time::from_nanos(30))
            .unwrap()
            .expect("membership should still be releasable from its owner group");
        assert!(matches!(left.kind(), process_group::GroupEventKind::Left));
        assert!(!membership.is_active());
        assert!(!workers.contains_member(&member));

        crate::test_complete!("process_group_membership_handle_rejects_wrong_group_state");
    }

    #[test]
    fn process_group_state_join_leave_and_down_events_are_exact() {
        init_test("process_group_state_join_leave_and_down_events_are_exact");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );

        let joined_first = state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        let joined_second = state
            .join(second.clone(), crate::types::Time::from_nanos(5))
            .unwrap();
        assert!(matches!(
            joined_first.kind(),
            process_group::GroupEventKind::Joined
        ));
        assert!(matches!(
            joined_second.kind(),
            process_group::GroupEventKind::Joined
        ));
        assert_eq!(state.next_join_sequence(), 2);
        assert_eq!(state.next_event_sequence(), 2);
        assert_eq!(joined_first.sequence(), 0);
        assert_eq!(joined_second.sequence(), 1);

        let ordered: Vec<String> = state
            .snapshot()
            .member_ids()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(ordered, vec!["Node(node-a):T1", "Node(node-b):T2"]);

        let left = state
            .leave(&first, crate::types::Time::from_nanos(30))
            .unwrap();
        assert!(matches!(left.kind(), process_group::GroupEventKind::Left));
        assert_eq!(left.sequence(), 2);
        assert!(!state.contains_member(&first));

        let down = state
            .mark_down(
                &second,
                monitor::DownReason::Error("crashed".into()),
                crate::types::Time::from_nanos(40),
            )
            .unwrap();
        assert!(matches!(
            down.kind(),
            process_group::GroupEventKind::Down(monitor::DownReason::Error(message))
                if message == "crashed"
        ));
        assert_eq!(down.sequence(), 3);
        assert!(state.is_empty());
        assert_eq!(state.event_log().len(), 4);

        crate::test_complete!("process_group_state_join_leave_and_down_events_are_exact");
    }

    #[test]
    fn process_group_event_cursor_replays_each_transition_once() {
        init_test("process_group_event_cursor_replays_each_transition_once");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let mut cursor = process_group::GroupEventCursor::new();

        assert!(state.events_since(&mut cursor).is_empty());
        assert_eq!(cursor.next_sequence(), 0);

        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        let initial_replay: Vec<(u64, String)> = state
            .events_since(&mut cursor)
            .iter()
            .map(|event| (event.sequence(), event.member().to_string()))
            .collect();
        assert_eq!(
            initial_replay,
            vec![
                (0, "Node(node-a):T1".to_string()),
                (1, "Node(node-b):T2".to_string()),
            ]
        );
        assert_eq!(cursor.next_sequence(), 2);
        assert!(state.events_since(&mut cursor).is_empty());
        assert_eq!(cursor.next_sequence(), 2);

        state
            .leave(&first, crate::types::Time::from_nanos(30))
            .unwrap();
        state
            .mark_down(
                &second,
                monitor::DownReason::Error("crashed".into()),
                crate::types::Time::from_nanos(40),
            )
            .unwrap();
        let second_replay: Vec<u64> = state
            .events_since(&mut cursor)
            .iter()
            .map(process_group::GroupEvent::sequence)
            .collect();
        assert_eq!(second_replay, vec![2, 3]);
        assert_eq!(cursor.next_sequence(), 4);

        let mut late_cursor = process_group::GroupEventCursor::from_next_sequence(3);
        let late_replay: Vec<u64> = state
            .events_since(&mut late_cursor)
            .iter()
            .map(process_group::GroupEvent::sequence)
            .collect();
        assert_eq!(late_replay, vec![3]);
        assert_eq!(late_cursor.next_sequence(), 4);

        crate::test_complete!("process_group_event_cursor_replays_each_transition_once");
    }

    #[test]
    fn process_group_event_batch_is_owned_and_cursor_safe() {
        init_test("process_group_event_batch_is_owned_and_cursor_safe");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let cursor = process_group::GroupEventCursor::new();

        let empty = state.event_batch(cursor);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.next_cursor().next_sequence(), 0);
        assert_eq!(cursor.next_sequence(), 0);

        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();

        let batch = state.event_batch(cursor);
        assert_eq!(cursor.next_sequence(), 0);
        assert_eq!(batch.next_cursor().next_sequence(), 2);
        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch
                .events()
                .iter()
                .map(process_group::GroupEvent::sequence)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let next_cursor = batch.next_cursor();
        let owned_events = batch.into_events();
        drop(state);

        assert_eq!(
            owned_events
                .iter()
                .map(|event| event.member().to_string())
                .collect::<Vec<_>>(),
            vec!["Node(node-a):T1".to_string(), "Node(node-b):T2".to_string()]
        );
        assert_eq!(next_cursor.next_sequence(), 2);

        crate::test_complete!("process_group_event_batch_is_owned_and_cursor_safe");
    }

    #[test]
    fn process_group_event_subscriber_commits_batches_monotonically() {
        init_test("process_group_event_subscriber_commits_batches_monotonically");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(first, crate::types::Time::from_nanos(10))
            .unwrap();
        let first_batch = subscriber.pending_batch(&state);
        assert_eq!(subscriber.cursor().next_sequence(), 0);
        assert_eq!(first_batch.len(), 1);
        assert_eq!(first_batch.next_cursor().next_sequence(), 1);

        assert!(subscriber.commit(&first_batch));
        assert_eq!(subscriber.cursor().next_sequence(), 1);
        assert!(!subscriber.commit(&first_batch));
        assert_eq!(subscriber.cursor().next_sequence(), 1);

        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        let second_batch = subscriber.pending_batch(&state);
        assert_eq!(second_batch.len(), 1);
        assert_eq!(second_batch.events()[0].member(), &second);
        assert_eq!(second_batch.next_cursor().next_sequence(), 2);
        assert!(subscriber.commit(&second_batch));
        assert_eq!(subscriber.cursor().next_sequence(), 2);

        let restored = process_group::GroupEventSubscriber::from_cursor(
            process_group::GroupEventCursor::new(),
        );
        let replay = restored.pending_batch(&state);
        assert_eq!(replay.len(), 2);
        assert_eq!(restored.cursor().next_sequence(), 0);

        crate::test_complete!("process_group_event_subscriber_commits_batches_monotonically");
    }

    #[test]
    fn process_group_event_subscriber_delivers_after_broadcast_commit() {
        init_test("process_group_event_subscriber_delivers_after_broadcast_commit");

        let cx = crate::Cx::for_testing();
        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let (tx, mut rx) = crate::channel::broadcast::channel(4);
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();

        let delivery = subscriber.deliver_pending_to(&cx, &state, &tx).unwrap();
        assert_eq!(delivery.delivered_receiver_count(), 1);
        assert!(delivery.cursor_advanced());
        assert_eq!(delivery.batch().len(), 2);
        assert_eq!(subscriber.cursor().next_sequence(), 2);

        let received = rx.try_recv().unwrap();
        assert_eq!(
            received
                .events()
                .iter()
                .map(|event| (event.sequence(), event.member().to_string()))
                .collect::<Vec<_>>(),
            vec![
                (0, "Node(node-a):T1".to_string()),
                (1, "Node(node-b):T2".to_string()),
            ]
        );

        let empty_delivery = subscriber.deliver_pending_to(&cx, &state, &tx).unwrap();
        assert!(empty_delivery.batch().is_empty());
        assert_eq!(empty_delivery.delivered_receiver_count(), 0);
        assert!(!empty_delivery.cursor_advanced());
        assert!(matches!(
            rx.try_recv(),
            Err(crate::channel::broadcast::TryRecvError::Empty)
        ));

        crate::test_complete!("process_group_event_subscriber_delivers_after_broadcast_commit");
    }

    #[test]
    fn process_group_event_subscriber_keeps_cursor_when_monitor_closed() {
        init_test("process_group_event_subscriber_keeps_cursor_when_monitor_closed");

        let cx = crate::Cx::for_testing();
        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let (tx, rx) = crate::channel::broadcast::channel(4);
        drop(rx);
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(member, crate::types::Time::from_nanos(10))
            .unwrap();

        let err = subscriber
            .deliver_pending_to(&cx, &state, &tx)
            .expect_err("closed monitor should not advance cursor");
        assert!(matches!(
            &err,
            process_group::GroupMonitorDeliveryError::Closed(_)
        ));
        assert_eq!(err.batch().len(), 1);
        assert_eq!(subscriber.cursor().next_sequence(), 0);

        crate::test_complete!("process_group_event_subscriber_keeps_cursor_when_monitor_closed");
    }

    #[test]
    fn process_group_event_subscriber_keeps_cursor_when_send_cancelled() {
        init_test("process_group_event_subscriber_keeps_cursor_when_send_cancelled");

        let cx = crate::Cx::for_testing();
        cx.cancel_with(
            crate::types::CancelKind::User,
            Some("process group monitor delivery test"),
        );
        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let (tx, mut rx) = crate::channel::broadcast::channel(4);
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(member, crate::types::Time::from_nanos(10))
            .unwrap();

        let err = subscriber
            .deliver_pending_to(&cx, &state, &tx)
            .expect_err("cancelled monitor send should not advance cursor");
        assert!(matches!(
            &err,
            process_group::GroupMonitorDeliveryError::Cancelled(_)
        ));
        assert_eq!(err.batch().len(), 1);
        assert_eq!(subscriber.cursor().next_sequence(), 0);
        assert!(matches!(
            rx.try_recv(),
            Err(crate::channel::broadcast::TryRecvError::Empty)
        ));

        crate::test_complete!("process_group_event_subscriber_keeps_cursor_when_send_cancelled");
    }

    #[test]
    fn process_group_state_rejects_duplicate_and_missing_members() {
        init_test("process_group_state_rejects_duplicate_and_missing_members");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        state
            .join(member.clone(), crate::types::Time::from_nanos(1))
            .unwrap();

        assert_eq!(
            state
                .join(member.clone(), crate::types::Time::from_nanos(2))
                .unwrap_err(),
            process_group::ProcessGroupError::DuplicateMember(member.clone())
        );
        state
            .leave(&member, crate::types::Time::from_nanos(3))
            .unwrap();
        assert_eq!(
            state
                .mark_down(
                    &member,
                    monitor::DownReason::Normal,
                    crate::types::Time::from_nanos(4)
                )
                .unwrap_err(),
            process_group::ProcessGroupError::MemberNotFound(member)
        );

        crate::test_complete!("process_group_state_rejects_duplicate_and_missing_members");
    }

    // =====================================================================
    // Unified Error Taxonomy tests (bd-2x5xc)
    // =====================================================================

    mod error_taxonomy {
        use crate::app::{AppCompileError, AppSpawnError, AppStartError, AppStopError};
        use crate::gen_server::{CallError, CastError, InfoError};
        use crate::runtime::{RegionCreateError, SpawnError};
        use crate::spork::error::{SporkError, SporkSeverity};
        use crate::supervision::{SupervisorCompileError, SupervisorSpawnError};
        use crate::types::RegionId;
        use crate::util::arena::ArenaIndex;

        fn test_region_id() -> RegionId {
            RegionId::from_arena(ArenaIndex::new(0, 1))
        }

        fn parent_capacity_error(region: RegionId) -> RegionCreateError {
            RegionCreateError::ParentAtCapacity {
                region,
                limit: 1,
                live: 1,
            }
        }

        fn region_task_capacity_error(region: RegionId) -> SpawnError {
            SpawnError::RegionAtCapacity {
                region,
                limit: 1,
                live: 1,
            }
        }

        fn init_test(name: &str) {
            crate::test_utils::init_test_logging();
            crate::test_phase!(name);
        }

        // -- From conversions --

        #[test]
        fn from_call_error() {
            init_test("from_call_error");
            let e: SporkError = CallError::ServerStopped.into();
            assert!(matches!(e, SporkError::Call(CallError::ServerStopped)));
            crate::test_complete!("from_call_error");
        }

        #[test]
        fn from_cast_error() {
            init_test("from_cast_error");
            let e: SporkError = CastError::Full.into();
            assert!(matches!(e, SporkError::Cast(CastError::Full)));
            crate::test_complete!("from_cast_error");
        }

        #[test]
        fn from_info_error() {
            init_test("from_info_error");
            let e: SporkError = InfoError::ServerStopped.into();
            assert!(matches!(e, SporkError::Info(InfoError::ServerStopped)));
            crate::test_complete!("from_info_error");
        }

        #[test]
        fn from_app_compile_error() {
            init_test("from_app_compile_error");
            let inner = AppCompileError::SupervisorCompile(
                SupervisorCompileError::DuplicateChildName("dup".into()),
            );
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Compile(_)));
            crate::test_complete!("from_app_compile_error");
        }

        #[test]
        fn from_supervisor_compile_error() {
            init_test("from_supervisor_compile_error");
            let inner = SupervisorCompileError::DuplicateChildName("x".into());
            let e: SporkError = inner.into();
            // Should wrap via AppCompileError::SupervisorCompile
            assert!(matches!(
                e,
                SporkError::Compile(AppCompileError::SupervisorCompile(_))
            ));
            crate::test_complete!("from_supervisor_compile_error");
        }

        #[test]
        fn from_app_start_error() {
            init_test("from_app_start_error");
            let inner = AppStartError::CompileFailed(AppCompileError::SupervisorCompile(
                SupervisorCompileError::DuplicateChildName("a".into()),
            ));
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Start(_)));
            crate::test_complete!("from_app_start_error");
        }

        #[test]
        fn from_app_stop_error() {
            init_test("from_app_stop_error");
            let inner = AppStopError::RegionNotFound(test_region_id());
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Stop(_)));
            crate::test_complete!("from_app_stop_error");
        }

        // -- Severity classification --

        #[test]
        fn severity_permanent_lifecycle() {
            init_test("severity_permanent_lifecycle");
            let e = SporkError::Start(AppStartError::CompileFailed(
                AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(
                    "a".into(),
                )),
            ));
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            assert!(e.is_permanent());
            assert!(!e.is_transient());
            crate::test_complete!("severity_permanent_lifecycle");
        }

        #[test]
        fn severity_permanent_call() {
            init_test("severity_permanent_call");
            let e = SporkError::Call(CallError::ServerStopped);
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            assert!(e.is_permanent());
            crate::test_complete!("severity_permanent_call");
        }

        #[test]
        fn severity_transient_cast_full() {
            init_test("severity_transient_cast_full");
            let e = SporkError::Cast(CastError::Full);
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            assert!(!e.is_permanent());
            crate::test_complete!("severity_transient_cast_full");
        }

        #[test]
        fn severity_transient_info_full() {
            init_test("severity_transient_info_full");
            let e = SporkError::Info(InfoError::Full);
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_info_full");
        }

        #[test]
        fn severity_permanent_cast_stopped() {
            init_test("severity_permanent_cast_stopped");
            let e = SporkError::Cast(CastError::ServerStopped);
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            crate::test_complete!("severity_permanent_cast_stopped");
        }

        #[test]
        fn severity_transient_spawn_parent_capacity() {
            init_test("severity_transient_spawn_parent_capacity");
            let region = test_region_id();
            let e = SporkError::Spawn(AppSpawnError::RegionCreate(parent_capacity_error(region)));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_spawn_parent_capacity");
        }

        #[test]
        fn severity_transient_start_parent_capacity() {
            init_test("severity_transient_start_parent_capacity");
            let region = test_region_id();
            let e = SporkError::Start(AppStartError::SpawnFailed(AppSpawnError::RegionCreate(
                parent_capacity_error(region),
            )));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_start_parent_capacity");
        }

        #[test]
        fn severity_transient_spawn_child_start_region_capacity() {
            init_test("severity_transient_spawn_child_start_region_capacity");
            let region = test_region_id();
            let e = SporkError::Spawn(AppSpawnError::SpawnFailed(
                SupervisorSpawnError::ChildStartFailed {
                    child: "worker".into(),
                    err: region_task_capacity_error(region),
                    region,
                },
            ));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_spawn_child_start_region_capacity");
        }

        #[test]
        fn severity_transient_spawn_dependency_unavailable_preserves_root_cause() {
            init_test("severity_transient_spawn_dependency_unavailable_preserves_root_cause");
            let region = test_region_id();
            let e = SporkError::Spawn(AppSpawnError::SpawnFailed(
                SupervisorSpawnError::DependencyUnavailable {
                    child: "api".into(),
                    dependency: "db".into(),
                    dependency_error: Some(region_task_capacity_error(region)),
                    region,
                },
            ));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!(
                "severity_transient_spawn_dependency_unavailable_preserves_root_cause"
            );
        }

        // -- Domain tags --

        #[test]
        fn domain_tags() {
            init_test("domain_tags");
            assert_eq!(
                SporkError::Start(AppStartError::CompileFailed(
                    AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(
                        "a".into()
                    ))
                ))
                .domain(),
                "start"
            );
            assert_eq!(
                SporkError::Stop(AppStopError::RegionNotFound(test_region_id())).domain(),
                "stop"
            );
            assert_eq!(
                SporkError::Compile(AppCompileError::SupervisorCompile(
                    SupervisorCompileError::DuplicateChildName("a".into())
                ))
                .domain(),
                "compile"
            );
            assert_eq!(SporkError::Call(CallError::ServerStopped).domain(), "call");
            assert_eq!(SporkError::Cast(CastError::Full).domain(), "cast");
            assert_eq!(SporkError::Info(InfoError::ServerStopped).domain(), "info");
            crate::test_complete!("domain_tags");
        }

        // -- Display --

        #[test]
        fn display_format() {
            init_test("display_format");
            let e = SporkError::Call(CallError::ServerStopped);
            let s = format!("{e}");
            assert!(s.starts_with("spork call:"), "got: {s}");

            let e2 = SporkError::Cast(CastError::Full);
            let s2 = format!("{e2}");
            assert!(s2.starts_with("spork cast:"), "got: {s2}");
            crate::test_complete!("display_format");
        }

        // -- Error source chain --

        #[test]
        fn error_source_chain() {
            init_test("error_source_chain");
            let e = SporkError::Call(CallError::NoReply);
            let source = std::error::Error::source(&e);
            assert!(source.is_some(), "SporkError should have a source");
            crate::test_complete!("error_source_chain");
        }

        // -- SporkSeverity ordering --

        #[test]
        fn severity_ordering() {
            init_test("severity_ordering");
            assert!(SporkSeverity::Transient < SporkSeverity::Permanent);
            crate::test_complete!("severity_ordering");
        }
    }
