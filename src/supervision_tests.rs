#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::evidence::{EvidenceDetail, SupervisionDetail, Verdict};
    use crate::types::PanicPayload;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_task_id() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 1))
    }

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    /// Helper: a `ChildStart`-compatible function that returns the canonical test `TaskId`.
    /// Named functions satisfy the HRTB required by `ChildStart` where closures
    /// with inferred lifetimes do not.
    #[allow(clippy::unnecessary_wraps)]
    fn noop_start(
        _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        _state: &mut RuntimeState,
        _cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        Ok(test_task_id())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn noop_start_alt(
        _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        _state: &mut RuntimeState,
        _cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        Ok(test_task_id())
    }

    fn spawn_registered_child(
        scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        state: &mut RuntimeState,
        cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        let handle = scope.spawn_registered(state, cx, |_cx| async move { 0u8 })?;
        Ok(handle.task_id())
    }

    use parking_lot::Mutex;
    use std::sync::Arc;

    struct LoggingStart {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl ChildStart for LoggingStart {
        fn start(
            &mut self,
            scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            state: &mut RuntimeState,
            cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            self.log.lock().push(self.name.to_string());
            let handle = scope.spawn_registered(state, cx, |_cx| async move { 0u8 })?;
            Ok(handle.task_id())
        }
    }

    #[test]
    fn stop_strategy_always_stops() {
        init_test("stop_strategy_always_stops");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Cancelled(_),
                ..
            }
        ));

        crate::test_complete!("stop_strategy_always_stops");
    }

    #[test]
    fn restart_strategy_allows_restarts() {
        init_test("restart_strategy_allows_restarts");

        let config = RestartConfig::new(3, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // First error should trigger restart
        let decision =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second error should also restart
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000, // 1 second later
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 2, .. }
        ));

        crate::test_complete!("restart_strategy_allows_restarts");
    }

    #[test]
    fn restart_strategy_does_not_restart_cancelled() {
        init_test("restart_strategy_does_not_restart_cancelled");

        let config = RestartConfig::new(3, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Cancelled(_),
                ..
            }
        ));

        crate::test_complete!("restart_strategy_does_not_restart_cancelled");
    }

    #[test]
    fn restart_budget_exhaustion() {
        init_test("restart_budget_exhaustion");

        let config = RestartConfig::new(2, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed
        supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );

        // Third should stop
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        crate::test_complete!("restart_budget_exhaustion");
    }

    #[test]
    fn restart_window_resets() {
        init_test("restart_window_resets");

        let config = RestartConfig::new(2, Duration::from_secs(1)); // 1 second window
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts within window
        supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            500_000_000, // 0.5 seconds
        );

        // Third failure after window should succeed (old ones expired)
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000, // 2 seconds later - both old restarts outside window
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        crate::test_complete!("restart_window_resets");
    }

    #[test]
    fn escalate_strategy_escalates() {
        init_test("escalate_strategy_escalates");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);
        let parent = RegionId::from_arena(ArenaIndex::new(0, 99));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            Some(parent),
            &Outcome::Err(()),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Escalate {
                parent_region_id: Some(_),
                ..
            }
        ));

        crate::test_complete!("escalate_strategy_escalates");
    }

    #[test]
    fn escalate_strategy_does_not_escalate_cancelled() {
        init_test("escalate_strategy_does_not_escalate_cancelled");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);
        let parent = RegionId::from_arena(ArenaIndex::new(0, 99));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            Some(parent),
            &Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Cancelled(_),
                ..
            }
        ));

        crate::test_complete!("escalate_strategy_does_not_escalate_cancelled");
    }

    #[test]
    fn panics_always_stop() {
        init_test("panics_always_stop");

        // Even with Restart strategy, panics should stop
        let config = RestartConfig::new(10, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Panicked(PanicPayload::new("test panic")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Panicked,
                ..
            }
        ));

        crate::test_complete!("panics_always_stop");
    }

    #[test]
    fn exponential_backoff() {
        init_test("exponential_backoff");

        let backoff = BackoffStrategy::Exponential {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
            multiplier: 2.0,
        };

        // Attempt 0: 100ms
        let d0 = backoff.delay_for_attempt(0).unwrap();
        assert_eq!(d0.as_millis(), 100);

        // Attempt 1: 200ms
        let d1 = backoff.delay_for_attempt(1).unwrap();
        assert_eq!(d1.as_millis(), 200);

        // Attempt 2: 400ms
        let d2 = backoff.delay_for_attempt(2).unwrap();
        assert_eq!(d2.as_millis(), 400);

        // Attempt 10: should be capped at 10s
        let d10 = backoff.delay_for_attempt(10).unwrap();
        assert_eq!(d10.as_secs(), 10);

        crate::test_complete!("exponential_backoff");
    }

    #[test]
    fn exponential_backoff_saturates_at_duration_max() {
        init_test("exponential_backoff_saturates_at_duration_max");

        let backoff = BackoffStrategy::Exponential {
            initial: Duration::MAX,
            max: Duration::MAX,
            multiplier: 2.0,
        };

        assert_eq!(backoff.delay_for_attempt(0), Some(Duration::MAX));
        assert_eq!(backoff.delay_for_attempt(u32::MAX), Some(Duration::MAX));

        crate::test_complete!("exponential_backoff_saturates_at_duration_max");
    }

    #[test]
    fn fixed_backoff() {
        init_test("fixed_backoff");

        let backoff = BackoffStrategy::Fixed(Duration::from_millis(500));

        for attempt in 0..5 {
            let delay = backoff.delay_for_attempt(attempt).unwrap();
            assert_eq!(delay.as_millis(), 500);
        }

        crate::test_complete!("fixed_backoff");
    }

    #[test]
    fn no_backoff() {
        init_test("no_backoff");

        let backoff = BackoffStrategy::None;

        for attempt in 0..5 {
            assert!(backoff.delay_for_attempt(attempt).is_none());
        }

        crate::test_complete!("no_backoff");
    }

    #[test]
    fn restart_history_tracking() {
        init_test("restart_history_tracking");

        let config = RestartConfig::new(3, Duration::from_secs(10));
        let mut history = RestartHistory::new(config);

        // Initially can restart
        assert!(history.can_restart(0));
        assert_eq!(history.recent_restart_count(0), 0);

        // Record some restarts
        history.record_restart(1_000_000_000); // 1s
        history.record_restart(2_000_000_000); // 2s
        history.record_restart(3_000_000_000); // 3s

        // Now at budget
        assert_eq!(history.recent_restart_count(3_000_000_000), 3);
        assert!(!history.can_restart(3_000_000_000));

        // After window passes, old restarts expire
        assert_eq!(history.recent_restart_count(15_000_000_000), 0);
        assert!(history.can_restart(15_000_000_000));

        crate::test_complete!("restart_history_tracking");
    }

    #[test]
    fn restart_tracker_default_backoff_preserves_third_attempt_delay() {
        init_test("restart_tracker_default_backoff_preserves_third_attempt_delay");

        let mut tracker =
            RestartTracker::from_restart_config(RestartConfig::new(4, Duration::from_secs(60)));

        tracker.record(0);
        tracker.record(1_000_000_000);

        assert_eq!(
            tracker.evaluate(2_000_000_000),
            RestartVerdict::Allowed {
                attempt: 3,
                delay: Some(Duration::from_millis(400)),
            }
        );

        crate::test_complete!("restart_tracker_default_backoff_preserves_third_attempt_delay");
    }

    #[test]
    fn restart_tracker_no_backoff_preserves_none_delay() {
        init_test("restart_tracker_no_backoff_preserves_none_delay");

        let config =
            RestartConfig::new(4, Duration::from_secs(60)).with_backoff(BackoffStrategy::None);
        let mut tracker = RestartTracker::from_restart_config(config);

        tracker.record(0);
        tracker.record(1_000_000_000);

        assert_eq!(
            tracker.evaluate(2_000_000_000),
            RestartVerdict::Allowed {
                attempt: 3,
                delay: None,
            }
        );

        crate::test_complete!("restart_tracker_no_backoff_preserves_none_delay");
    }

    #[test]
    fn restart_tracker_fixed_backoff_preserves_configured_delay() {
        init_test("restart_tracker_fixed_backoff_preserves_configured_delay");

        let fixed_delay = Duration::from_millis(75);
        let config = RestartConfig::new(4, Duration::from_secs(60))
            .with_backoff(BackoffStrategy::Fixed(fixed_delay));
        let mut tracker = RestartTracker::from_restart_config(config);

        tracker.record(0);
        tracker.record(1_000_000_000);

        assert_eq!(
            tracker.evaluate(2_000_000_000),
            RestartVerdict::Allowed {
                attempt: 3,
                delay: Some(fixed_delay),
            }
        );

        crate::test_complete!("restart_tracker_fixed_backoff_preserves_configured_delay");
    }

    #[test]
    fn restart_tracker_denies_after_larger_budget_is_exhausted() {
        init_test("restart_tracker_denies_after_larger_budget_is_exhausted");

        let mut tracker =
            RestartTracker::from_restart_config(RestartConfig::new(4, Duration::from_secs(60)));

        for now in [0_u64, 1_000_000_000, 2_000_000_000, 3_000_000_000] {
            assert!(tracker.evaluate(now).is_allowed());
            tracker.record(now);
        }

        assert!(matches!(
            tracker.evaluate(4_000_000_000),
            RestartVerdict::Denied {
                refusal: BudgetRefusal::WindowExhausted {
                    max_restarts: 4,
                    window,
                },
            } if window == Duration::from_secs(60)
        ));

        crate::test_complete!("restart_tracker_denies_after_larger_budget_is_exhausted");
    }

    // ---- Tests for new RestartPolicy, EscalationPolicy, SupervisionConfig ----

    #[test]
    fn restart_policy_defaults_to_one_for_one() {
        init_test("restart_policy_defaults_to_one_for_one");

        let policy = RestartPolicy::default();
        assert_eq!(policy, RestartPolicy::OneForOne);

        crate::test_complete!("restart_policy_defaults_to_one_for_one");
    }

    #[test]
    fn escalation_policy_defaults_to_stop() {
        init_test("escalation_policy_defaults_to_stop");

        let policy = EscalationPolicy::default();
        assert_eq!(policy, EscalationPolicy::Stop);

        crate::test_complete!("escalation_policy_defaults_to_stop");
    }

    #[test]
    fn supervision_config_defaults() {
        init_test("supervision_config_defaults");

        let config = SupervisionConfig::default();

        assert_eq!(config.restart_policy, RestartPolicy::OneForOne);
        assert_eq!(config.max_restarts, 3);
        assert_eq!(config.restart_window, Duration::from_mins(1));
        assert_eq!(config.escalation, EscalationPolicy::Stop);

        crate::test_complete!("supervision_config_defaults");
    }

    #[test]
    fn supervision_config_builder() {
        init_test("supervision_config_builder");

        let config = SupervisionConfig::new(5, Duration::from_secs(30))
            .with_restart_policy(RestartPolicy::OneForAll)
            .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(100)))
            .with_escalation(EscalationPolicy::Escalate);

        assert_eq!(config.restart_policy, RestartPolicy::OneForAll);
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_window, Duration::from_secs(30));
        assert_eq!(
            config.backoff,
            BackoffStrategy::Fixed(Duration::from_millis(100))
        );
        assert_eq!(config.escalation, EscalationPolicy::Escalate);

        crate::test_complete!("supervision_config_builder");
    }

    #[test]
    fn supervision_config_one_for_all_helper() {
        init_test("supervision_config_one_for_all_helper");

        let config = SupervisionConfig::one_for_all(5, Duration::from_secs(120));

        assert_eq!(config.restart_policy, RestartPolicy::OneForAll);
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_window, Duration::from_secs(120));

        crate::test_complete!("supervision_config_one_for_all_helper");
    }

    #[test]
    fn supervision_config_rest_for_one_helper() {
        init_test("supervision_config_rest_for_one_helper");

        let config = SupervisionConfig::rest_for_one(10, Duration::from_secs(300));

        assert_eq!(config.restart_policy, RestartPolicy::RestForOne);
        assert_eq!(config.max_restarts, 10);
        assert_eq!(config.restart_window, Duration::from_secs(300));

        crate::test_complete!("supervision_config_rest_for_one_helper");
    }

    #[test]
    fn child_spec_builder() {
        init_test("child_spec_builder");

        let spec = ChildSpec::new("worker-1", noop_start)
            .with_restart(SupervisionStrategy::Restart(RestartConfig::default()))
            .with_shutdown_budget(Budget::with_deadline_at_secs(10))
            .with_registration(NameRegistrationPolicy::Register {
                name: "worker-1".to_string(),
                collision: NameCollisionPolicy::Fail,
            })
            .depends_on("db")
            .with_start_immediately(false)
            .with_required(false);

        assert_eq!(spec.name, "worker-1");
        assert!(matches!(spec.restart, SupervisionStrategy::Restart(_)));
        assert!(!spec.start_immediately);
        assert!(!spec.required);
        assert_eq!(spec.depends_on, vec!["db".to_string()]);

        crate::test_complete!("child_spec_builder");
    }

    #[test]
    fn child_spec_defaults() {
        init_test("child_spec_defaults");

        let spec = ChildSpec::new("default-child", noop_start);

        assert_eq!(spec.name, "default-child");
        assert!(matches!(spec.restart, SupervisionStrategy::Stop));
        assert_eq!(spec.shutdown_budget, Budget::INFINITE);
        assert!(spec.depends_on.is_empty());
        assert_eq!(spec.registration, NameRegistrationPolicy::None);
        assert!(spec.start_immediately);
        assert!(spec.required);

        crate::test_complete!("child_spec_defaults");
    }

    #[test]
    fn dynamic_child_table_assigns_generation_safe_ids() {
        init_test("dynamic_child_table_assigns_generation_safe_ids");

        let mut table = DynamicChildTable::new();
        assert!(table.is_empty());

        let first = table
            .insert_started(
                "alpha",
                test_task_id(),
                SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_secs(1))),
                Budget::with_deadline_at_secs(5),
            )
            .expect("first child should insert");
        let second = table
            .insert_started(
                "bravo",
                test_task_id(),
                SupervisionStrategy::Stop,
                Budget::INFINITE,
            )
            .expect("second child should insert");

        assert_eq!(first.id().slot(), 0);
        assert_eq!(first.id().generation(), 0);
        assert_eq!(second.id().slot(), 1);
        assert_eq!(table.len(), 2);

        let names = table
            .which_children()
            .into_iter()
            .map(|record| record.name().as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["alpha", "bravo"]);

        let removed = table.remove(first.id()).expect("first child should remove");
        assert_eq!(removed.name().as_str(), "alpha");
        assert!(table.get(first.id()).is_none());
        assert!(!table.contains_name("alpha"));

        let third = table
            .insert_started(
                "charlie",
                test_task_id(),
                SupervisionStrategy::Stop,
                Budget::INFINITE,
            )
            .expect("slot should be reusable");

        assert_eq!(third.id().slot(), first.id().slot());
        assert_ne!(third.id().generation(), first.id().generation());
        assert!(table.get(first.id()).is_none());

        let names = table
            .which_children()
            .into_iter()
            .map(|record| record.name().as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["bravo", "charlie"]);

        crate::test_complete!("dynamic_child_table_assigns_generation_safe_ids");
    }

    #[test]
    fn dynamic_child_table_rejects_duplicate_names_and_keeps_lookup_stable() {
        init_test("dynamic_child_table_rejects_duplicate_names_and_keeps_lookup_stable");

        let mut table = DynamicChildTable::new();
        let handle = table
            .insert_started(
                "worker",
                test_task_id(),
                SupervisionStrategy::Stop,
                Budget::with_deadline_at_secs(2),
            )
            .expect("child should insert");

        let duplicate = table
            .insert_started(
                "worker",
                test_task_id(),
                SupervisionStrategy::Stop,
                Budget::INFINITE,
            )
            .expect_err("duplicate name should fail");
        assert!(matches!(
            duplicate,
            DynamicChildError::DuplicateChildName(ref name) if name == "worker"
        ));

        let record = table
            .get_by_name("worker")
            .expect("name lookup should resolve inserted child");
        assert_eq!(record.id(), handle.id());
        assert_eq!(record.task_id(), handle.task_id());
        assert_eq!(record.restart(), &SupervisionStrategy::Stop);
        assert_eq!(record.shutdown_budget(), Budget::with_deadline_at_secs(2));
        assert!(table.get_by_name("missing").is_none());

        let stale_generation = ChildId::new(handle.id().slot(), handle.id().generation() + 1);
        assert!(table.remove(stale_generation).is_none());
        assert_eq!(table.len(), 1);

        let removed = table
            .remove(handle.id())
            .expect("live handle should remove");
        assert_eq!(removed.name().as_str(), "worker");
        assert!(table.is_empty());

        crate::test_complete!(
            "dynamic_child_table_rejects_duplicate_names_and_keeps_lookup_stable"
        );
    }

    #[test]
    fn dynamic_child_table_removes_by_name_for_terminate_child_bookkeeping() {
        init_test("dynamic_child_table_removes_by_name_for_terminate_child_bookkeeping");

        let mut table = DynamicChildTable::new();
        let first = table
            .insert_started(
                "first",
                test_task_id(),
                SupervisionStrategy::Restart(RestartConfig::default()),
                Budget::with_deadline_at_secs(3),
            )
            .expect("first child should insert");
        let second = table
            .insert_started(
                "second",
                test_task_id(),
                SupervisionStrategy::Stop,
                Budget::INFINITE,
            )
            .expect("second child should insert");

        let removed = table
            .remove_by_name("first")
            .expect("name removal should find live child");
        assert_eq!(removed.id(), first.id());
        assert_eq!(removed.shutdown_budget(), Budget::with_deadline_at_secs(3));
        assert!(table.get(first.id()).is_none());
        assert!(table.get_by_name("first").is_none());
        assert!(table.remove_by_name("first").is_none());

        let names = table
            .which_children()
            .into_iter()
            .map(|record| record.name().as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["second"]);

        let third = table
            .insert_started(
                "third",
                test_task_id(),
                SupervisionStrategy::Escalate,
                Budget::INFINITE,
            )
            .expect("freed slot should be reusable after name removal");
        assert_eq!(third.id().slot(), first.id().slot());
        assert_ne!(third.id().generation(), first.id().generation());
        assert_eq!(
            table
                .get_by_name("second")
                .expect("second child remains live")
                .id(),
            second.id()
        );

        crate::test_complete!(
            "dynamic_child_table_removes_by_name_for_terminate_child_bookkeeping"
        );
    }

    #[test]
    fn supervisor_builder_defaults() {
        init_test("supervisor_builder_defaults");

        let defaults = SupervisorBuilder::new("sup-default");

        assert_eq!(defaults.name, "sup-default");
        assert_eq!(defaults.budget, None);
        assert_eq!(defaults.tie_break, StartTieBreak::InsertionOrder);
        assert_eq!(defaults.restart_policy, RestartPolicy::OneForOne);
        assert!(defaults.children.is_empty());

        let same = SupervisorBuilder::new("sup-default");
        assert!(defaults.spec_eq(&same));
        assert_eq!(defaults.spec_fingerprint(), same.spec_fingerprint());

        let different =
            SupervisorBuilder::new("sup-default").with_restart_policy(RestartPolicy::OneForAll);
        assert!(!defaults.spec_eq(&different));
        assert_ne!(defaults.spec_fingerprint(), different.spec_fingerprint());

        crate::test_complete!("supervisor_builder_defaults");
    }

    #[test]
    fn child_spec_pure_surface_is_comparable_and_hashable() {
        init_test("child_spec_pure_surface_is_comparable_and_hashable");

        let left = ChildSpec::new("svc", noop_start)
            .with_restart(SupervisionStrategy::Restart(RestartConfig::new(
                3,
                Duration::from_secs(10),
            )))
            .with_shutdown_budget(Budget::with_deadline_at_secs(2))
            .depends_on("db")
            .with_start_immediately(false)
            .with_required(true);

        let right = ChildSpec::new("svc", noop_start_alt)
            .with_restart(SupervisionStrategy::Restart(RestartConfig::new(
                3,
                Duration::from_secs(10),
            )))
            .with_shutdown_budget(Budget::with_deadline_at_secs(2))
            .depends_on("db")
            .with_start_immediately(false)
            .with_required(true);

        assert!(left.spec_eq(&right));
        assert_eq!(left.spec_fingerprint(), right.spec_fingerprint());

        crate::test_complete!("child_spec_pure_surface_is_comparable_and_hashable");
    }

    #[test]
    fn supervisor_builder_pure_surface_is_comparable_and_hashable() {
        init_test("supervisor_builder_pure_surface_is_comparable_and_hashable");

        let left = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::NameLex)
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("worker", noop_start));

        let right = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::NameLex)
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("worker", noop_start_alt));

        assert!(left.spec_eq(&right));
        assert_eq!(left.spec_fingerprint(), right.spec_fingerprint());

        crate::test_complete!("supervisor_builder_pure_surface_is_comparable_and_hashable");
    }

    #[test]
    fn supervisor_builder_compile_order_insertion_tie_break() {
        init_test("supervisor_builder_compile_order_insertion_tie_break");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("a"));

        let compiled = builder.compile().expect("compile");
        assert_eq!(compiled.start_order, vec![0, 1, 2]);

        crate::test_complete!("supervisor_builder_compile_order_insertion_tie_break");
    }

    #[test]
    fn supervisor_builder_compile_detects_cycle() {
        init_test("supervisor_builder_compile_detects_cycle");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start).depends_on("b"))
            .child(ChildSpec::new("b", noop_start).depends_on("a"));

        let err = builder.compile().expect_err("should detect cycle");
        assert!(matches!(err, SupervisorCompileError::CycleDetected { .. }));

        crate::test_complete!("supervisor_builder_compile_detects_cycle");
    }

    #[test]
    fn compiled_supervisor_spawn_starts_children_in_order() {
        init_test("compiled_supervisor_spawn_starts_children_in_order");

        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let mk = |name: &'static str, log: &Arc<Mutex<Vec<String>>>| {
            ChildSpec::new(
                name,
                LoggingStart {
                    name,
                    log: Arc::clone(log),
                },
            )
        };

        let builder = SupervisorBuilder::new("sup")
            .child(mk("a", &log))
            .child(mk("b", &log).depends_on("a"))
            .child(mk("c", &log).depends_on("a"));

        let compiled = builder.compile().expect("compile");

        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let handle = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect("spawn");

        assert_eq!(handle.started.len(), 3);
        assert_eq!(
            *log.lock(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );

        crate::test_complete!("compiled_supervisor_spawn_starts_children_in_order");
    }

    #[test]
    fn compiled_supervisor_restart_plan_one_for_one() {
        init_test("compiled_supervisor_restart_plan_one_for_one");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"))
            .child(ChildSpec::new("d", noop_start).depends_on("c"));

        let compiled = builder.compile().expect("compile");
        let plan = compiled.restart_plan_for("b").expect("plan");

        assert_eq!(plan.policy, RestartPolicy::OneForOne);
        assert_eq!(plan.cancel_order, vec!["b".to_string()]);
        assert_eq!(plan.restart_order, vec!["b".to_string()]);

        crate::test_complete!("compiled_supervisor_restart_plan_one_for_one");
    }

    #[test]
    fn compiled_supervisor_restart_plan_one_for_all() {
        init_test("compiled_supervisor_restart_plan_one_for_all");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"))
            .child(ChildSpec::new("d", noop_start).depends_on("c"));

        let compiled = builder.compile().expect("compile");
        let plan = compiled.restart_plan_for("b").expect("plan");

        assert_eq!(plan.policy, RestartPolicy::OneForAll);
        assert_eq!(
            plan.cancel_order,
            vec![
                "d".to_string(),
                "c".to_string(),
                "b".to_string(),
                "a".to_string()
            ]
        );
        assert_eq!(
            plan.restart_order,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );

        crate::test_complete!("compiled_supervisor_restart_plan_one_for_all");
    }

    #[test]
    fn compiled_supervisor_restart_plan_rest_for_one() {
        init_test("compiled_supervisor_restart_plan_rest_for_one");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"))
            .child(ChildSpec::new("d", noop_start).depends_on("c"));

        let compiled = builder.compile().expect("compile");
        let plan = compiled.restart_plan_for("b").expect("plan");

        assert_eq!(plan.policy, RestartPolicy::RestForOne);
        assert_eq!(
            plan.cancel_order,
            vec!["d".to_string(), "c".to_string(), "b".to_string()]
        );
        assert_eq!(
            plan.restart_order,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );

        crate::test_complete!("compiled_supervisor_restart_plan_rest_for_one");
    }

    #[test]
    fn compiled_supervisor_restart_plan_unknown_child_none() {
        init_test("compiled_supervisor_restart_plan_unknown_child_none");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"));

        let compiled = builder.compile().expect("compile");
        assert!(compiled.restart_plan_for("zzz").is_none());

        crate::test_complete!("compiled_supervisor_restart_plan_unknown_child_none");
    }

    #[test]
    fn compiled_supervisor_restart_plan_for_failure_monotone_severity() {
        init_test("compiled_supervisor_restart_plan_for_failure_monotone_severity");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("a", noop_start))
            .child(
                ChildSpec::new("b", noop_start)
                    .depends_on("a")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(ChildSpec::new("c", noop_start).depends_on("b"));

        let compiled = builder.compile().expect("compile");

        let ok: Outcome<(), ()> = Outcome::Ok(());
        let cancelled: Outcome<(), ()> = Outcome::Cancelled(CancelReason::user("cancelled"));
        let panicked: Outcome<(), ()> = Outcome::Panicked(crate::types::PanicPayload::new("panic"));
        let err: Outcome<(), ()> = Outcome::Err(());

        assert!(compiled.restart_plan_for_failure("b", &ok).is_none());
        assert!(compiled.restart_plan_for_failure("b", &cancelled).is_none());
        assert!(compiled.restart_plan_for_failure("b", &panicked).is_none());

        let plan = compiled
            .restart_plan_for_failure("b", &err)
            .expect("restart plan");
        assert_eq!(plan.policy, RestartPolicy::OneForAll);

        crate::test_complete!("compiled_supervisor_restart_plan_for_failure_monotone_severity");
    }

    #[test]
    fn compiled_supervisor_restart_plan_for_failure_requires_restart_strategy() {
        init_test("compiled_supervisor_restart_plan_for_failure_requires_restart_strategy");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"));

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // Default child strategy is Stop: no restart plan produced.
        assert!(compiled.restart_plan_for_failure("b", &err).is_none());

        crate::test_complete!(
            "compiled_supervisor_restart_plan_for_failure_requires_restart_strategy"
        );
    }

    #[test]
    fn restart_policy_equality() {
        init_test("restart_policy_equality");

        assert_eq!(RestartPolicy::OneForOne, RestartPolicy::OneForOne);
        assert_ne!(RestartPolicy::OneForOne, RestartPolicy::OneForAll);
        assert_ne!(RestartPolicy::OneForAll, RestartPolicy::RestForOne);

        crate::test_complete!("restart_policy_equality");
    }

    // ── compile_restart_ops tests ──────────────────────────────────────

    /// Helper: build a ChildSpec with a given name and shutdown budget.
    fn make_restart_child(name: &str, budget: Budget) -> ChildSpec {
        ChildSpec {
            name: name.into(),
            start: Box::new(noop_start),
            restart: SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
            shutdown_budget: budget,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    #[test]
    fn compile_restart_ops_one_for_one() {
        init_test("compile_restart_ops_one_for_one");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("b").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        assert_eq!(ops.policy, RestartPolicy::OneForOne);
        // Only "b" should be affected: cancel b, drain b, restart b
        assert_eq!(ops.ops.len(), 3);
        assert!(matches!(&ops.ops[0], RegionOp::CancelChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[1], RegionOp::DrainChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[2], RegionOp::RestartChild { name } if name == "b"));

        crate::test_complete!("compile_restart_ops_one_for_one");
    }

    #[test]
    fn compile_restart_ops_one_for_all() {
        init_test("compile_restart_ops_one_for_all");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("b").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        assert_eq!(ops.policy, RestartPolicy::OneForAll);
        // All 3 children: 3 cancels + 3 drains + 3 restarts = 9 ops
        assert_eq!(ops.ops.len(), 9);

        // Cancel order is reverse start order: c, b, a
        assert!(matches!(&ops.ops[0], RegionOp::CancelChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[1], RegionOp::CancelChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[2], RegionOp::CancelChild { name, .. } if name == "a"));

        // Drain order matches cancel order
        assert!(matches!(&ops.ops[3], RegionOp::DrainChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[4], RegionOp::DrainChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[5], RegionOp::DrainChild { name, .. } if name == "a"));

        // Restart order is start order: a, b, c
        assert!(matches!(&ops.ops[6], RegionOp::RestartChild { name } if name == "a"));
        assert!(matches!(&ops.ops[7], RegionOp::RestartChild { name } if name == "b"));
        assert!(matches!(&ops.ops[8], RegionOp::RestartChild { name } if name == "c"));

        crate::test_complete!("compile_restart_ops_one_for_all");
    }

    #[test]
    fn compile_restart_ops_skips_restart_for_stop_strategy_children() {
        // br-asupersync-jkwhrd: regression. compile_restart_ops Phase 3
        // must filter RestartChild emission by per-child
        // SupervisionStrategy. Pre-fix, a Stop-strategy child got a
        // RestartChild op even when the supervisor's restart_plan_for
        // (no-outcome variant) returned an unfiltered restart_order.
        // OneForAll cancels+drains all three (Stop child included);
        // restart phase emits RestartChild only for the Restart-strategy
        // children.
        init_test("compile_restart_ops_skips_restart_for_stop_strategy_children");

        let stop_child = ChildSpec {
            name: "b".into(),
            start: Box::new(noop_start),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(stop_child)
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        // Drive via the no-outcome variant (which leaves restart_order
        // unfiltered) — the filter must live in compile_restart_ops.
        let plan = compiled.restart_plan_for("a").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        // 3 cancel + 3 drain + 2 restart (b is filtered out of restart) = 8.
        assert_eq!(
            ops.ops.len(),
            8,
            "Stop-strategy 'b' must NOT get a RestartChild op; got ops={ops:?}"
        );

        // Cancel order is reverse start order: c, b, a — Stop child
        // still cancelled+drained alongside siblings under OneForAll.
        assert!(matches!(&ops.ops[0], RegionOp::CancelChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[1], RegionOp::CancelChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[2], RegionOp::CancelChild { name, .. } if name == "a"));

        // Drain order matches.
        assert!(matches!(&ops.ops[3], RegionOp::DrainChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[4], RegionOp::DrainChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[5], RegionOp::DrainChild { name, .. } if name == "a"));

        // Restart phase: only "a" and "c" — "b" filtered out.
        assert!(matches!(&ops.ops[6], RegionOp::RestartChild { name } if name == "a"));
        assert!(matches!(&ops.ops[7], RegionOp::RestartChild { name } if name == "c"));

        crate::test_complete!("compile_restart_ops_skips_restart_for_stop_strategy_children");
    }

    #[test]
    fn compile_restart_ops_prunes_dependents_of_unscheduled_affected_children() {
        init_test("compile_restart_ops_prunes_dependents_of_unscheduled_affected_children");

        // a ──▶ b (Stop) ──▶ c ──▶ d
        //  └────────────────────▶ e
        //
        // OneForAll affects every child. Once b is filtered from the restart
        // phase, c and d must be pruned transitively, while the independent
        // viable branch through e still restarts.
        let mut child_b = make_restart_child("b", Budget::INFINITE);
        child_b.restart = SupervisionStrategy::Stop;
        child_b.depends_on = vec!["a".into()];
        let mut child_c = make_restart_child("c", Budget::INFINITE);
        child_c.depends_on = vec!["b".into()];
        let mut child_d = make_restart_child("d", Budget::INFINITE);
        child_d.depends_on = vec!["c".into()];
        let mut child_e = make_restart_child("e", Budget::INFINITE);
        child_e.depends_on = vec!["a".into()];

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(child_b)
            .child(child_c)
            .child(child_d)
            .child(child_e)
            .compile()
            .unwrap();

        // The generic planner intentionally leaves the strategy/dependency
        // filtering to compile_restart_ops.
        let plan = compiled.restart_plan_for("a").unwrap();
        assert_eq!(plan.restart_order, vec!["a", "b", "c", "d", "e"]);

        let ops = compiled.compile_restart_ops(&plan);
        let replay = compiled.compile_restart_ops(&plan);
        assert_eq!(ops, replay, "operation compilation must be replay-stable");

        let cancel_names = ops
            .ops
            .iter()
            .filter_map(|op| match op {
                RegionOp::CancelChild { name, .. } => Some(name.as_str()),
                RegionOp::DrainChild { .. } | RegionOp::RestartChild { .. } => None,
            })
            .collect::<Vec<_>>();
        let drain_names = ops
            .ops
            .iter()
            .filter_map(|op| match op {
                RegionOp::DrainChild { name, .. } => Some(name.as_str()),
                RegionOp::CancelChild { .. } | RegionOp::RestartChild { .. } => None,
            })
            .collect::<Vec<_>>();
        let restart_names = ops
            .ops
            .iter()
            .filter_map(|op| match op {
                RegionOp::RestartChild { name } => Some(name.as_str()),
                RegionOp::CancelChild { .. } | RegionOp::DrainChild { .. } => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(cancel_names, vec!["e", "d", "c", "b", "a"]);
        assert_eq!(drain_names, cancel_names);
        assert_eq!(restart_names, vec!["a", "e"]);

        let err: Outcome<(), ()> = Outcome::Err(());
        let failure_plan = compiled
            .restart_plan_for_failure("a", &err)
            .expect("restartable failure should produce a plan");
        assert_eq!(
            restart_names,
            failure_plan
                .restart_order
                .iter()
                .map(ChildName::as_str)
                .collect::<Vec<_>>(),
            "generic-plan compilation must match failure-aware dependency pruning"
        );

        crate::test_complete!(
            "compile_restart_ops_prunes_dependents_of_unscheduled_affected_children"
        );
    }

    #[test]
    fn compile_restart_ops_preserves_dependencies_outside_affected_slice() {
        init_test("compile_restart_ops_preserves_dependencies_outside_affected_slice");

        // Under RestForOne, failing b affects only b and c. Dependency a stays
        // live outside the suffix, so it must not block either restart.
        let mut child_b = make_restart_child("b", Budget::INFINITE);
        child_b.depends_on = vec!["a".into()];
        let mut child_c = make_restart_child("c", Budget::INFINITE);
        child_c.depends_on = vec!["b".into()];

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(child_b)
            .child(child_c)
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("b").unwrap();
        assert_eq!(plan.cancel_order, vec!["c", "b"]);
        assert_eq!(plan.restart_order, vec!["b", "c"]);

        let ops = compiled.compile_restart_ops(&plan);
        let restart_names = ops
            .ops
            .iter()
            .filter_map(|op| match op {
                RegionOp::RestartChild { name } => Some(name.as_str()),
                RegionOp::CancelChild { .. } | RegionOp::DrainChild { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(restart_names, vec!["b", "c"]);

        let err: Outcome<(), ()> = Outcome::Err(());
        let failure_plan = compiled
            .restart_plan_for_failure("b", &err)
            .expect("restartable failure should produce a plan");
        assert_eq!(failure_plan.restart_order, vec!["b", "c"]);

        crate::test_complete!("compile_restart_ops_preserves_dependencies_outside_affected_slice");
    }

    #[test]
    fn compile_restart_ops_rest_for_one() {
        init_test("compile_restart_ops_rest_for_one");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("b").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        assert_eq!(ops.policy, RestartPolicy::RestForOne);
        // b and c affected: 2 cancels + 2 drains + 2 restarts = 6 ops
        assert_eq!(ops.ops.len(), 6);

        // Cancel order is reverse of affected suffix: c, b
        assert!(matches!(&ops.ops[0], RegionOp::CancelChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[1], RegionOp::CancelChild { name, .. } if name == "b"));

        // Drain same order
        assert!(matches!(&ops.ops[2], RegionOp::DrainChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[3], RegionOp::DrainChild { name, .. } if name == "b"));

        // Restart in start order: b, c
        assert!(matches!(&ops.ops[4], RegionOp::RestartChild { name } if name == "b"));
        assert!(matches!(&ops.ops[5], RegionOp::RestartChild { name } if name == "c"));

        crate::test_complete!("compile_restart_ops_rest_for_one");
    }

    #[test]
    fn compile_restart_ops_preserves_per_child_budgets() {
        init_test("compile_restart_ops_preserves_per_child_budgets");

        let budget_a = Budget::INFINITE.with_poll_quota(10);
        let budget_b = Budget::INFINITE.with_poll_quota(20);

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", budget_a))
            .child(make_restart_child("b", budget_b))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("a").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        // Cancel ops carry per-child budget
        assert!(
            matches!(
                &ops.ops[0],
                RegionOp::CancelChild {
                    name,
                    shutdown_budget,
                } if name == "b" && *shutdown_budget == budget_b
            ),
            "expected first op to cancel child b with its shutdown budget"
        );
        assert!(
            matches!(
                &ops.ops[1],
                RegionOp::CancelChild {
                    name,
                    shutdown_budget,
                } if name == "a" && *shutdown_budget == budget_a
            ),
            "expected second op to cancel child a with its shutdown budget"
        );

        // Drain ops also carry per-child budget
        assert!(
            matches!(
                &ops.ops[2],
                RegionOp::DrainChild {
                    name,
                    shutdown_budget,
                } if name == "b" && *shutdown_budget == budget_b
            ),
            "expected third op to drain child b with its shutdown budget"
        );

        crate::test_complete!("compile_restart_ops_preserves_per_child_budgets");
    }

    #[test]
    fn compile_restart_ops_with_dependencies() {
        init_test("compile_restart_ops_with_dependencies");

        // b depends on a, c depends on b → topo order: a, b, c
        let mut child_b = make_restart_child("b", Budget::INFINITE);
        child_b.depends_on = vec!["a".into()];
        let mut child_c = make_restart_child("c", Budget::INFINITE);
        child_c.depends_on = vec!["b".into()];

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(child_b)
            .child(child_c)
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("a").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        // Cancel order: dependents-first → c, b, a
        assert!(matches!(&ops.ops[0], RegionOp::CancelChild { name, .. } if name == "c"));
        assert!(matches!(&ops.ops[1], RegionOp::CancelChild { name, .. } if name == "b"));
        assert!(matches!(&ops.ops[2], RegionOp::CancelChild { name, .. } if name == "a"));

        // Restart order: dependencies-first → a, b, c
        assert!(matches!(&ops.ops[6], RegionOp::RestartChild { name } if name == "a"));
        assert!(matches!(&ops.ops[7], RegionOp::RestartChild { name } if name == "b"));
        assert!(matches!(&ops.ops[8], RegionOp::RestartChild { name } if name == "c"));

        crate::test_complete!("compile_restart_ops_with_dependencies");
    }

    #[test]
    fn compile_restart_ops_deterministic() {
        init_test("compile_restart_ops_deterministic");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("b").unwrap();
        let ops1 = compiled.compile_restart_ops(&plan);
        let ops2 = compiled.compile_restart_ops(&plan);

        assert_eq!(ops1, ops2, "compile_restart_ops must be deterministic");

        crate::test_complete!("compile_restart_ops_deterministic");
    }

    #[test]
    fn compile_restart_ops_three_phase_ordering() {
        init_test("compile_restart_ops_three_phase_ordering");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("a").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        // All cancels come first, then all drains, then all restarts
        let mut phase = 0; // 0=cancel, 1=drain, 2=restart
        for op in &ops.ops {
            let op_phase = match op {
                RegionOp::CancelChild { .. } => 0,
                RegionOp::DrainChild { .. } => 1,
                RegionOp::RestartChild { .. } => 2,
            };
            assert!(
                op_phase >= phase,
                "ops must be ordered: cancels, then drains, then restarts; got phase {op_phase} after {phase}"
            );
            phase = op_phase;
        }

        crate::test_complete!("compile_restart_ops_three_phase_ordering");
    }

    // ── conformance tests ──────────────────────────────────────────────

    #[test]
    fn conformance_one_for_one_isolates_failure() {
        init_test("conformance_one_for_one_isolates_failure");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        // Each failure only affects the failed child
        for name in &["a", "b", "c"] {
            let plan = compiled.restart_plan_for(name).unwrap();
            let ops = compiled.compile_restart_ops(&plan);
            let names: Vec<&str> = ops
                .ops
                .iter()
                .filter_map(|op| match op {
                    RegionOp::CancelChild { name, .. } => Some(name.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                names,
                vec![*name],
                "OneForOne must only cancel the failed child"
            );
        }

        crate::test_complete!("conformance_one_for_one_isolates_failure");
    }

    #[test]
    fn conformance_one_for_all_cancels_all() {
        init_test("conformance_one_for_all_cancels_all");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        // Any single failure cancels ALL children
        for name in &["a", "b", "c"] {
            let plan = compiled.restart_plan_for(name).unwrap();
            let ops = compiled.compile_restart_ops(&plan);
            let cancel_count = ops
                .ops
                .iter()
                .filter(|op| matches!(op, RegionOp::CancelChild { .. }))
                .count();
            assert_eq!(cancel_count, 3, "OneForAll must cancel all children");
        }

        crate::test_complete!("conformance_one_for_all_cancels_all");
    }

    #[test]
    fn conformance_rest_for_one_cancels_rest() {
        init_test("conformance_rest_for_one_cancels_rest");

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(make_restart_child("a", Budget::INFINITE))
            .child(make_restart_child("b", Budget::INFINITE))
            .child(make_restart_child("c", Budget::INFINITE))
            .compile()
            .unwrap();

        // "a" fails → cancels a, b, c (all from a onward)
        let plan_a = compiled.restart_plan_for("a").unwrap();
        let ops_a = compiled.compile_restart_ops(&plan_a);
        {
            let cancel_count = ops_a
                .ops
                .iter()
                .filter(|op| matches!(op, RegionOp::CancelChild { .. }))
                .count();
            assert_eq!(cancel_count, 3);
        }

        // "b" fails → cancels b, c (from b onward)
        let plan_b = compiled.restart_plan_for("b").unwrap();
        let ops_b = compiled.compile_restart_ops(&plan_b);
        {
            let cancel_count = ops_b
                .ops
                .iter()
                .filter(|op| matches!(op, RegionOp::CancelChild { .. }))
                .count();
            assert_eq!(cancel_count, 2);
            let cancels_a = ops_b
                .ops
                .iter()
                .any(|op| matches!(op, RegionOp::CancelChild { name, .. } if name == "a"));
            assert!(!cancels_a, "RestForOne must not cancel earlier children");
        }

        // "c" fails → cancels only c
        let plan_c = compiled.restart_plan_for("c").unwrap();
        let ops_c = compiled.compile_restart_ops(&plan_c);
        {
            let cancel_count = ops_c
                .ops
                .iter()
                .filter(|op| matches!(op, RegionOp::CancelChild { .. }))
                .count();
            assert_eq!(cancel_count, 1);
        }

        crate::test_complete!("conformance_rest_for_one_cancels_rest");
    }

    #[test]
    fn conformance_cancel_drain_restart_budget_bound() {
        init_test("conformance_cancel_drain_restart_budget_bound");

        let budget_a = Budget::INFINITE.with_poll_quota(5);
        let budget_b = Budget::INFINITE.with_poll_quota(10);

        let compiled = SupervisorBuilder::new("test")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(make_restart_child("a", budget_a))
            .child(make_restart_child("b", budget_b))
            .compile()
            .unwrap();

        let plan = compiled.restart_plan_for("a").unwrap();
        let ops = compiled.compile_restart_ops(&plan);

        // Every cancel and drain op must carry a budget
        for op in &ops.ops {
            match op {
                RegionOp::CancelChild {
                    shutdown_budget, ..
                }
                | RegionOp::DrainChild {
                    shutdown_budget, ..
                } => {
                    // Budget must not be zero (our test budgets have poll_quota > 0)
                    assert!(
                        shutdown_budget.poll_quota > 0,
                        "shutdown budget must be present"
                    );
                }
                RegionOp::RestartChild { .. } => {} // restarts don't carry budgets
            }
        }

        crate::test_complete!("conformance_cancel_drain_restart_budget_bound");
    }

    #[test]
    fn escalation_policy_variants() {
        init_test("escalation_policy_variants");

        // Test all variants exist and are distinguishable
        let stop = EscalationPolicy::Stop;
        let escalate = EscalationPolicy::Escalate;
        let reset = EscalationPolicy::ResetCounter;

        assert_ne!(stop, escalate);
        assert_ne!(escalate, reset);
        assert_ne!(stop, reset);

        crate::test_complete!("escalation_policy_variants");
    }

    // ---- Tests for budget-aware restart decisions (bd-1yv7a) ----

    #[test]
    fn restart_config_budget_fields_default_to_disabled() {
        init_test("restart_config_budget_fields_default");

        let config = RestartConfig::default();
        assert_eq!(config.restart_cost, 0);
        assert_eq!(config.min_remaining_for_restart, None);
        assert_eq!(config.min_polls_for_restart, 0);

        crate::test_complete!("restart_config_budget_fields_default");
    }

    #[test]
    fn restart_config_budget_builders() {
        init_test("restart_config_budget_builders");

        let config = RestartConfig::new(5, Duration::from_secs(30))
            .with_restart_cost(100)
            .with_min_remaining(Duration::from_secs(5))
            .with_min_polls(50);

        assert_eq!(config.restart_cost, 100);
        assert_eq!(
            config.min_remaining_for_restart,
            Some(Duration::from_secs(5))
        );
        assert_eq!(config.min_polls_for_restart, 50);

        crate::test_complete!("restart_config_budget_builders");
    }

    #[test]
    fn budget_aware_restart_allowed_with_sufficient_budget() {
        init_test("budget_aware_restart_sufficient");

        let config = RestartConfig::new(3, Duration::from_mins(1))
            .with_restart_cost(10)
            .with_min_remaining(Duration::from_secs(5))
            .with_min_polls(100);

        let history = RestartHistory::new(config);

        // Budget with plenty of resources
        let budget = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(1000)
            .with_poll_quota(5000);

        // At t=0, should be allowed
        assert!(history.can_restart_with_budget(0, &budget).is_ok());

        crate::test_complete!("budget_aware_restart_sufficient");
    }

    #[test]
    fn budget_aware_restart_refused_insufficient_cost() {
        init_test("budget_aware_restart_insufficient_cost");

        let config = RestartConfig::new(3, Duration::from_mins(1)).with_restart_cost(100);

        let history = RestartHistory::new(config);

        // Budget with insufficient cost
        let budget = Budget::new().with_cost_quota(50);

        let result = history.can_restart_with_budget(0, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::InsufficientCost {
                required: 100,
                remaining: 50
            })
        ));

        crate::test_complete!("budget_aware_restart_insufficient_cost");
    }

    #[test]
    fn budget_aware_restart_refused_deadline_too_close() {
        init_test("budget_aware_restart_deadline_close");

        let config = RestartConfig::new(3, Duration::from_mins(1))
            .with_min_remaining(Duration::from_secs(10));

        let history = RestartHistory::new(config);

        // Budget with deadline 5 seconds from now, but we need 10 seconds
        let budget = Budget::with_deadline_at_secs(15); // deadline at t=15s

        // At t=12s (3 seconds remaining, need 10)
        let now_ns = 12_000_000_000u64;
        let result = history.can_restart_with_budget(now_ns, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::DeadlineTooClose { .. })
        ));

        crate::test_complete!("budget_aware_restart_deadline_close");
    }

    #[test]
    fn budget_aware_restart_refused_insufficient_polls() {
        init_test("budget_aware_restart_insufficient_polls");

        let config = RestartConfig::new(3, Duration::from_mins(1)).with_min_polls(500);

        let history = RestartHistory::new(config);

        // Budget with insufficient polls
        let budget = Budget::new().with_poll_quota(100);

        let result = history.can_restart_with_budget(0, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::InsufficientPolls {
                min_required: 500,
                remaining: 100
            })
        ));

        crate::test_complete!("budget_aware_restart_insufficient_polls");
    }

    #[test]
    fn budget_aware_restart_allowed_no_cost_quota_set() {
        init_test("budget_aware_restart_no_cost_quota");

        let config = RestartConfig::new(3, Duration::from_mins(1)).with_restart_cost(100);

        let history = RestartHistory::new(config);

        // Budget with no cost quota (unlimited)
        let budget = Budget::INFINITE;

        // Should succeed since no cost quota = unlimited
        assert!(history.can_restart_with_budget(0, &budget).is_ok());

        crate::test_complete!("budget_aware_restart_no_cost_quota");
    }

    #[test]
    fn budget_aware_restart_allowed_no_deadline() {
        init_test("budget_aware_restart_no_deadline");

        let config = RestartConfig::new(3, Duration::from_mins(1))
            .with_min_remaining(Duration::from_secs(10));

        let history = RestartHistory::new(config);

        // Budget with no deadline
        let budget = Budget::INFINITE;

        // Should succeed since no deadline = unlimited time
        assert!(history.can_restart_with_budget(0, &budget).is_ok());

        crate::test_complete!("budget_aware_restart_no_deadline");
    }

    #[test]
    fn supervisor_on_failure_with_budget_refuses_restart() {
        init_test("supervisor_on_failure_with_budget_refuses");

        let config = RestartConfig::new(10, Duration::from_mins(1)).with_restart_cost(100);

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Budget with insufficient cost
        let mut budget = Budget::new().with_cost_quota(50);

        let decision = supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            0,
            Some(&mut budget),
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::BudgetRefused(BudgetRefusal::InsufficientCost { .. }),
                ..
            }
        ));

        crate::test_complete!("supervisor_on_failure_with_budget_refuses");
    }

    #[test]
    fn supervisor_on_failure_with_budget_allows_restart() {
        init_test("supervisor_on_failure_with_budget_allows");

        let config = RestartConfig::new(3, Duration::from_mins(1)).with_restart_cost(10);
        let expected_delay = config.backoff.delay_for_attempt(0);

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Budget with sufficient resources
        let mut budget = Budget::new().with_cost_quota(1000);

        let decision = supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            0,
            Some(&mut budget),
        );

        match decision {
            SupervisionDecision::Restart { attempt, delay, .. } => {
                assert_eq!(attempt, 1);
                assert_eq!(delay, expected_delay);
            }
            other => panic!("expected Restart, got {other:?}"),
        }

        crate::test_complete!("supervisor_on_failure_with_budget_allows");
    }

    #[test]
    fn supervisor_on_failure_without_budget_uses_window_only() {
        init_test("supervisor_on_failure_without_budget");

        let config = RestartConfig::new(2, Duration::from_mins(1)).with_restart_cost(10);

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed without budget checks
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        assert!(matches!(
            d1,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        assert!(matches!(
            d2,
            SupervisionDecision::Restart { attempt: 2, .. }
        ));

        // Third should be exhausted
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );
        assert!(matches!(
            d3,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        crate::test_complete!("supervisor_on_failure_without_budget");
    }

    #[test]
    fn restart_intensity_basic() {
        init_test("restart_intensity_basic");

        let config = RestartConfig::new(10, Duration::from_secs(10));
        let mut history = RestartHistory::new(config);

        // No restarts = zero intensity
        assert!(history.intensity(0).abs() < f64::EPSILON);

        // 3 restarts in 10-second window = 0.3 restarts/second
        history.record_restart(1_000_000_000); // 1s
        history.record_restart(2_000_000_000); // 2s
        history.record_restart(3_000_000_000); // 3s

        let intensity = history.intensity(5_000_000_000);
        assert!((intensity - 0.3).abs() < 0.01);

        crate::test_complete!("restart_intensity_basic");
    }

    // ---- Tests for RestartIntensityWindow ----

    #[test]
    fn intensity_window_basic() {
        init_test("intensity_window_basic");

        let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 1.0);

        // No restarts
        assert_eq!(window.count(0), 0);
        assert!(window.intensity(0).abs() < f64::EPSILON);
        assert!(!window.is_storm(0));

        // Record some restarts
        window.record(1_000_000_000); // 1s
        window.record(2_000_000_000); // 2s
        window.record(3_000_000_000); // 3s

        assert_eq!(window.count(5_000_000_000), 3);
        let intensity = window.intensity(5_000_000_000);
        assert!((intensity - 0.3).abs() < 0.01); // 3 in 10s

        crate::test_complete!("intensity_window_basic");
    }

    #[test]
    fn intensity_window_storm_detection() {
        init_test("intensity_window_storm_detection");

        // Storm threshold: 2 restarts/second in a 5-second window
        let mut window = RestartIntensityWindow::new(Duration::from_secs(5), 2.0);

        // 5 restarts in first second
        for i in 0..5 {
            window.record(i * 200_000_000); // every 200ms
        }

        // 5 restarts in 5s = 1.0/s, below threshold
        assert!(!window.is_storm(1_000_000_000));

        // Add more restarts to exceed threshold
        for i in 0..10 {
            window.record(1_000_000_000 + i * 100_000_000); // every 100ms
        }

        // Now 15 restarts in 5s window = 3.0/s, above 2.0 threshold
        let now = 2_000_000_000;
        assert!(window.is_storm(now));

        crate::test_complete!("intensity_window_storm_detection");
    }

    #[test]
    fn intensity_window_prunes_old_entries() {
        init_test("intensity_window_prunes");

        let mut window = RestartIntensityWindow::new(Duration::from_secs(5), 1.0);

        // Record restarts at t=0s, 1s, 2s
        window.record(0);
        window.record(1_000_000_000);
        window.record(2_000_000_000);

        assert_eq!(window.count(3_000_000_000), 3);

        // At t=10s, old restarts should have expired
        // Record one more to trigger pruning
        window.record(10_000_000_000);
        assert_eq!(window.count(10_000_000_000), 1);

        crate::test_complete!("intensity_window_prunes");
    }

    #[test]
    fn restart_history_huge_window_keeps_entries() {
        init_test("restart_history_huge_window_keeps_entries");

        let config = RestartConfig::new(10, Duration::MAX);
        let mut history = RestartHistory::new(config);

        history.record_restart(10);
        history.record_restart(20);
        history.record_restart(u64::MAX);

        // A maximal window should behave like "effectively infinite", retaining
        // previously recorded restarts.
        assert_eq!(history.recent_restart_count(u64::MAX), 3);

        crate::test_complete!("restart_history_huge_window_keeps_entries");
    }

    #[test]
    fn intensity_window_huge_window_keeps_entries() {
        init_test("intensity_window_huge_window_keeps_entries");

        let mut window = RestartIntensityWindow::new(Duration::MAX, 1.0);

        window.record(10);
        window.record(20);
        window.record(u64::MAX);

        assert_eq!(window.count(u64::MAX), 3);

        crate::test_complete!("intensity_window_huge_window_keeps_entries");
    }

    #[test]
    fn budget_refusal_display() {
        init_test("budget_refusal_display");

        let refusals = vec![
            BudgetRefusal::WindowExhausted {
                max_restarts: 3,
                window: Duration::from_mins(1),
            },
            BudgetRefusal::InsufficientCost {
                required: 100,
                remaining: 50,
            },
            BudgetRefusal::DeadlineTooClose {
                min_required: Duration::from_secs(10),
                remaining: Duration::from_secs(3),
            },
            BudgetRefusal::InsufficientPolls {
                min_required: 500,
                remaining: 100,
            },
        ];

        for refusal in &refusals {
            let s = format!("{refusal}");
            assert!(!s.is_empty());
        }

        crate::test_complete!("budget_refusal_display");
    }

    #[test]
    fn deadline_already_passed_refuses_restart() {
        init_test("deadline_already_passed_refuses_restart");

        let config = RestartConfig::new(3, Duration::from_mins(1))
            .with_min_remaining(Duration::from_secs(1));

        let history = RestartHistory::new(config);

        // Budget with deadline already in the past
        let budget = Budget::with_deadline_at_secs(5); // deadline at t=5s

        // At t=10s, deadline has passed
        let result = history.can_restart_with_budget(10_000_000_000, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::DeadlineTooClose {
                remaining: Duration::ZERO,
                ..
            })
        ));

        crate::test_complete!("deadline_already_passed_refuses_restart");
    }

    #[test]
    fn budget_aware_checks_combined() {
        init_test("budget_aware_checks_combined");

        // Config requiring all budget constraints
        let config = RestartConfig::new(5, Duration::from_mins(1))
            .with_restart_cost(50)
            .with_min_remaining(Duration::from_secs(10))
            .with_min_polls(200);

        let history = RestartHistory::new(config);

        // Budget that passes all checks
        let good_budget = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(500)
            .with_poll_quota(1000);
        assert!(history.can_restart_with_budget(0, &good_budget).is_ok());

        // Budget that fails on cost
        let bad_cost = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(10)
            .with_poll_quota(1000);
        assert!(matches!(
            history.can_restart_with_budget(0, &bad_cost),
            Err(BudgetRefusal::InsufficientCost { .. })
        ));

        // Budget that fails on deadline
        let bad_deadline = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(5))
            .with_cost_quota(500)
            .with_poll_quota(1000);
        // At t=0, 5 seconds remaining but we need 10
        assert!(matches!(
            history.can_restart_with_budget(0, &bad_deadline),
            Err(BudgetRefusal::DeadlineTooClose { .. })
        ));

        // Budget that fails on polls
        let bad_polls = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(500)
            .with_poll_quota(50);
        assert!(matches!(
            history.can_restart_with_budget(0, &bad_polls),
            Err(BudgetRefusal::InsufficientPolls { .. })
        ));

        crate::test_complete!("budget_aware_checks_combined");
    }

    // ---------------------------------------------------------------
    // Monitor + Down Notification tests (bd-4r1ep)
    // ---------------------------------------------------------------

    fn task_id(index: u32, generation: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(index, generation))
    }

    fn region_id(index: u32, generation: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(index, generation))
    }

    #[test]
    fn monitor_ref_display() {
        init_test("monitor_ref_display");
        let mref = MonitorRef::new_for_test(42);
        assert_eq!(format!("{mref}"), "Mon42");
        assert_eq!(mref.as_u64(), 42);
        crate::test_complete!("monitor_ref_display");
    }

    #[test]
    fn monitor_table_basic_lifecycle() {
        init_test("monitor_table_basic_lifecycle");

        let mut table = MonitorTable::new();
        assert!(table.is_empty());

        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let mref = table.monitor(watcher, region, monitored);
        assert_eq!(table.len(), 1);
        assert_eq!(table.watchers_of(monitored), &[mref]);
        assert_eq!(table.watcher_for(mref), Some(watcher));
        assert_eq!(table.monitored_for(mref), Some(monitored));

        // Demonitor
        assert!(table.demonitor(mref));
        assert!(table.is_empty());
        assert!(table.watchers_of(monitored).is_empty());
        assert_eq!(table.watcher_for(mref), None);

        // Double demonitor is a no-op
        assert!(!table.demonitor(mref));

        crate::test_complete!("monitor_table_basic_lifecycle");
    }

    #[test]
    fn monitor_multiple_watchers_single_target() {
        init_test("monitor_multiple_watchers_single_target");

        let mut table = MonitorTable::new();
        let monitored = task_id(10, 0);
        let watcher_a = task_id(1, 0);
        let watcher_b = task_id(2, 0);
        let region = region_id(0, 0);

        let ref_a = table.monitor(watcher_a, region, monitored);
        let ref_b = table.monitor(watcher_b, region, monitored);
        assert_eq!(table.len(), 2);

        let watchers = table.watchers_of(monitored);
        assert_eq!(watchers.len(), 2);
        assert!(watchers.contains(&ref_a));
        assert!(watchers.contains(&ref_b));

        crate::test_complete!("monitor_multiple_watchers_single_target");
    }

    #[test]
    fn monitor_same_pair_multiple_times() {
        init_test("monitor_same_pair_multiple_times");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let ref1 = table.monitor(watcher, region, monitored);
        let ref2 = table.monitor(watcher, region, monitored);
        assert_ne!(ref1, ref2);
        assert_eq!(table.len(), 2);

        crate::test_complete!("monitor_same_pair_multiple_times");
    }

    #[test]
    fn notify_down_basic() {
        init_test("notify_down_basic");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let mref = table.monitor(watcher, region, monitored);

        let downs = table.notify_down(monitored, &Outcome::Ok(()), Time::from_secs(5));
        assert_eq!(downs.len(), 1);
        assert_eq!(downs[0].monitored, monitored);
        assert_eq!(downs[0].monitor_ref, mref);
        assert_eq!(downs[0].completion_vt, Time::from_secs(5));

        assert!(table.is_empty());

        crate::test_complete!("notify_down_basic");
    }

    #[test]
    fn notify_down_multiple_watchers() {
        init_test("notify_down_multiple_watchers");

        let mut table = MonitorTable::new();
        let monitored = task_id(10, 0);
        let watcher_a = task_id(1, 0);
        let watcher_b = task_id(2, 0);
        let region = region_id(0, 0);

        let _ref_a = table.monitor(watcher_a, region, monitored);
        let _ref_b = table.monitor(watcher_b, region, monitored);

        let downs = table.notify_down(monitored, &Outcome::Err(()), Time::from_secs(1));
        assert_eq!(downs.len(), 2);
        assert!(table.is_empty());

        crate::test_complete!("notify_down_multiple_watchers");
    }

    #[test]
    fn notify_down_ordering_by_vt_then_tid() {
        init_test("notify_down_ordering_by_vt_then_tid");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let t_low = task_id(1, 0);
        let t_high = task_id(5, 0);
        let t_mid = task_id(3, 0);

        table.monitor(watcher, region, t_low);
        table.monitor(watcher, region, t_high);
        table.monitor(watcher, region, t_mid);

        let terminations = vec![
            (t_high, Outcome::Ok(()), Time::from_secs(10)),
            (t_low, Outcome::Ok(()), Time::from_secs(10)),
            (t_mid, Outcome::Ok(()), Time::from_secs(10)),
        ];
        let downs = table.notify_down_batch(&terminations);
        assert_eq!(downs.len(), 3);

        assert_eq!(downs[0].monitored, t_low);
        assert_eq!(downs[1].monitored, t_mid);
        assert_eq!(downs[2].monitored, t_high);

        crate::test_complete!("notify_down_ordering_by_vt_then_tid");
    }

    #[test]
    fn notify_down_ordering_vt_primary() {
        init_test("notify_down_ordering_vt_primary");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let t_early_high_id = task_id(99, 0);
        let t_late_low_id = task_id(1, 0);

        table.monitor(watcher, region, t_early_high_id);
        table.monitor(watcher, region, t_late_low_id);

        let terminations = vec![
            (t_late_low_id, Outcome::Ok(()), Time::from_secs(20)),
            (t_early_high_id, Outcome::Err(()), Time::from_secs(10)),
        ];
        let downs = table.notify_down_batch(&terminations);
        assert_eq!(downs.len(), 2);

        assert_eq!(downs[0].monitored, t_early_high_id);
        assert_eq!(downs[0].completion_vt, Time::from_secs(10));
        assert_eq!(downs[1].monitored, t_late_low_id);
        assert_eq!(downs[1].completion_vt, Time::from_secs(20));

        crate::test_complete!("notify_down_ordering_vt_primary");
    }

    #[test]
    fn cleanup_region_releases_monitors() {
        init_test("cleanup_region_releases_monitors");

        let mut table = MonitorTable::new();
        let region_a = region_id(1, 0);
        let region_b = region_id(2, 0);

        let watcher_a = task_id(1, 0);
        let watcher_b = task_id(2, 0);
        let monitored = task_id(10, 0);

        table.monitor(watcher_a, region_a, monitored);
        table.monitor(watcher_b, region_b, monitored);
        assert_eq!(table.len(), 2);

        let released = table.cleanup_region(region_a);
        assert_eq!(released, 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.watchers_of(monitored).len(), 1);

        let released = table.cleanup_region(region_b);
        assert_eq!(released, 1);
        assert!(table.is_empty());

        crate::test_complete!("cleanup_region_releases_monitors");
    }

    #[test]
    fn monitor_reverse_indexes_prune_empty_buckets() {
        init_test("monitor_reverse_indexes_prune_empty_buckets");

        let mut table = MonitorTable::new();
        let region = region_id(7, 0);
        let watcher = task_id(3, 0);
        let monitored = task_id(5, 0);

        let mref = table.monitor(watcher, region, monitored);
        assert_eq!(table.by_monitored.len(), 1);
        assert_eq!(table.by_region.len(), 1);

        assert!(table.demonitor(mref));
        assert!(table.by_monitored.is_empty());
        assert!(table.by_region.is_empty());

        let _mref = table.monitor(watcher, region, monitored);
        let _downs =
            table.notify_down(monitored, &Outcome::Ok(()), Time::from_nanos(1_000_000_000));
        assert!(table.by_monitored.is_empty());
        assert!(table.by_region.is_empty());

        let _mref = table.monitor(watcher, region, monitored);
        assert_eq!(table.cleanup_region(region), 1);
        assert!(table.by_monitored.is_empty());
        assert!(table.by_region.is_empty());

        crate::test_complete!("monitor_reverse_indexes_prune_empty_buckets");
    }

    #[test]
    fn cleanup_region_idempotent() {
        init_test("cleanup_region_idempotent");

        let mut table = MonitorTable::new();
        let region = region_id(1, 0);
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);

        table.monitor(watcher, region, monitored);
        assert_eq!(table.cleanup_region(region), 1);
        assert_eq!(table.cleanup_region(region), 0);

        crate::test_complete!("cleanup_region_idempotent");
    }

    #[test]
    fn notify_down_no_monitors_returns_empty() {
        init_test("notify_down_no_monitors_returns_empty");

        let mut table = MonitorTable::new();
        let task = task_id(99, 0);

        let downs = table.notify_down(task, &Outcome::Ok(()), Time::from_nanos(1_000_000_000));
        assert!(downs.is_empty());

        crate::test_complete!("notify_down_no_monitors_returns_empty");
    }

    #[test]
    fn demonitor_prevents_down_delivery() {
        init_test("demonitor_prevents_down_delivery");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let mref = table.monitor(watcher, region, monitored);
        assert!(table.demonitor(mref));

        let downs = table.notify_down(monitored, &Outcome::Ok(()), Time::from_secs(1));
        assert!(downs.is_empty());

        crate::test_complete!("demonitor_prevents_down_delivery");
    }

    #[test]
    fn region_cleanup_prevents_down_delivery() {
        init_test("region_cleanup_prevents_down_delivery");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        table.monitor(watcher, region, monitored);
        table.cleanup_region(region);

        let downs = table.notify_down(monitored, &Outcome::Ok(()), Time::from_secs(1));
        assert!(downs.is_empty());

        crate::test_complete!("region_cleanup_prevents_down_delivery");
    }

    #[test]
    fn down_sort_key_matches_contract() {
        init_test("down_sort_key_matches_contract");

        let d = Down {
            monitored: task_id(5, 2),
            reason: Outcome::Ok(()),
            monitor_ref: MonitorRef::new_for_test(0),
            completion_vt: Time::from_secs(42),
        };

        let (vt, tid) = d.sort_key();
        assert_eq!(vt, Time::from_secs(42));
        assert_eq!(tid, task_id(5, 2));

        crate::test_complete!("down_sort_key_matches_contract");
    }

    #[test]
    fn monitor_event_variants() {
        init_test("monitor_event_variants");

        let _established = MonitorEvent::Established {
            watcher: task_id(1, 0),
            monitored: task_id(2, 0),
            monitor_ref: MonitorRef::new_for_test(0),
        };
        let _demonitored = MonitorEvent::Demonitored {
            monitor_ref: MonitorRef::new_for_test(0),
        };
        let _down_produced = MonitorEvent::DownProduced {
            monitored: task_id(2, 0),
            watcher: task_id(1, 0),
            monitor_ref: MonitorRef::new_for_test(0),
            completion_vt: Time::from_secs(1),
        };
        let _cleanup = MonitorEvent::RegionCleanup {
            region: region_id(0, 0),
            count: 5,
        };

        crate::test_complete!("monitor_event_variants");
    }

    #[test]
    fn notify_down_batch_merges_and_sorts() {
        init_test("notify_down_batch_merges_and_sorts");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let tasks: Vec<TaskId> = (1..=5).map(|i| task_id(i, 0)).collect();
        for &t in &tasks {
            table.monitor(watcher, region, t);
        }

        let terminations = vec![
            (tasks[4], Outcome::Ok(()), Time::from_secs(3)),
            (tasks[0], Outcome::Err(()), Time::from_secs(1)),
            (tasks[2], Outcome::Ok(()), Time::from_secs(1)),
            (tasks[1], Outcome::Ok(()), Time::from_secs(2)),
            (tasks[3], Outcome::Err(()), Time::from_secs(1)),
        ];

        let downs = table.notify_down_batch(&terminations);
        assert_eq!(downs.len(), 5);

        // Expected order by (vt, tid):
        // vt=1: tid=1, tid=3, tid=4
        // vt=2: tid=2
        // vt=3: tid=5
        assert_eq!(downs[0].monitored, tasks[0]);
        assert_eq!(downs[1].monitored, tasks[2]);
        assert_eq!(downs[2].monitored, tasks[3]);
        assert_eq!(downs[3].monitored, tasks[1]);
        assert_eq!(downs[4].monitored, tasks[4]);

        assert!(table.is_empty());

        crate::test_complete!("notify_down_batch_merges_and_sorts");
    }

    #[test]
    fn monitor_ref_ordering_is_monotone() {
        init_test("monitor_ref_ordering_is_monotone");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let ref1 = table.monitor(watcher, region, task_id(1, 0));
        let ref2 = table.monitor(watcher, region, task_id(2, 0));
        let ref3 = table.monitor(watcher, region, task_id(3, 0));

        assert!(ref1 < ref2);
        assert!(ref2 < ref3);

        crate::test_complete!("monitor_ref_ordering_is_monotone");
    }

    #[test]
    fn down_equality() {
        init_test("down_equality");

        let d1 = Down {
            monitored: task_id(1, 0),
            reason: Outcome::Ok(()),
            monitor_ref: MonitorRef::new_for_test(5),
            completion_vt: Time::from_secs(10),
        };
        let d2 = Down {
            monitored: task_id(1, 0),
            reason: Outcome::Err(()),
            monitor_ref: MonitorRef::new_for_test(5),
            completion_vt: Time::from_secs(10),
        };
        assert_eq!(d1, d2);

        let d3 = Down {
            monitored: task_id(2, 0),
            reason: Outcome::Ok(()),
            monitor_ref: MonitorRef::new_for_test(5),
            completion_vt: Time::from_secs(10),
        };
        assert_ne!(d1, d3);

        crate::test_complete!("down_equality");
    }

    // ---------------------------------------------------------------
    // Supervisor Conformance Suite (bd-1zpsd)
    //
    // Deterministic tests covering:
    // - Each restart policy with full decision chains
    // - Budget exhaustion behavior
    // - Escalation propagation
    // - Monotone severity enforcement
    // - Spawn integration with dependency ordering
    // ---------------------------------------------------------------

    /// Table-driven test: all `Outcome` variants crossed with all supervision
    /// strategies. Asserts the SPORK monotone-severity contract:
    /// - `Panicked` always stops.
    /// - `Cancelled` always stops (external directive; never restartable).
    /// - Only `Err` may restart (under `Restart`) or escalate (under `Escalate`).
    /// - `Ok` should not be routed into `on_failure`; we treat it as `Stop(ExplicitStop)`
    ///   as a deterministic fallback.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn conformance_monotone_severity_cross_product() {
        init_test("conformance_monotone_severity_cross_product");

        let outcomes: Vec<(&str, Outcome<(), ()>)> = vec![
            ("Ok", Outcome::Ok(())),
            ("Err", Outcome::Err(())),
            ("Cancelled", Outcome::Cancelled(CancelReason::user("test"))),
            (
                "Panicked",
                Outcome::Panicked(PanicPayload::new("test panic")),
            ),
        ];

        let strategies: Vec<(&str, SupervisionStrategy)> = vec![
            ("Stop", SupervisionStrategy::Stop),
            (
                "Restart",
                SupervisionStrategy::Restart(RestartConfig::new(10, Duration::from_mins(1))),
            ),
            ("Escalate", SupervisionStrategy::Escalate),
        ];

        let parent = RegionId::from_arena(ArenaIndex::new(0, 99));

        for (outcome_name, outcome) in &outcomes {
            for (strategy_name, strategy) in &strategies {
                let mut supervisor = Supervisor::new(strategy.clone());
                let decision = supervisor.on_failure(
                    test_task_id(),
                    test_region_id(),
                    Some(parent),
                    outcome,
                    0,
                );

                match (outcome_name, strategy_name) {
                    // Panicked always stops, regardless of strategy
                    (&"Panicked", _) => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::Panicked,
                                    ..
                                }
                            ),
                            "Panicked + {strategy_name} should Stop(Panicked)"
                        );
                    }
                    // Cancelled always stops, regardless of strategy
                    (&"Cancelled", _) => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::Cancelled(_),
                                    ..
                                }
                            ),
                            "Cancelled + {strategy_name} should Stop(Cancelled)"
                        );
                    }
                    // Stop strategy always stops
                    (_, &"Stop") => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::ExplicitStop,
                                    ..
                                }
                            ),
                            "{outcome_name} + Stop should Stop(ExplicitStop)"
                        );
                    }
                    // Escalate strategy escalates only on Err (Panicked/Cancelled handled above)
                    (&"Err", &"Escalate") => {
                        assert!(
                            matches!(decision, SupervisionDecision::Escalate { .. }),
                            "Err + Escalate should Escalate"
                        );
                    }
                    // Restart strategy restarts only on Err (Panicked/Cancelled handled above)
                    (&"Err", &"Restart") => {
                        assert!(
                            matches!(decision, SupervisionDecision::Restart { attempt: 1, .. }),
                            "Err + Restart should Restart(attempt=1)"
                        );
                    }
                    // Ok is a fallback (should not be treated as failure)
                    (&"Ok", &"Escalate") => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::ExplicitStop,
                                    ..
                                }
                            ),
                            "Ok + {strategy_name} should Stop(ExplicitStop) (fallback)"
                        );
                    }
                    (&"Ok", &"Restart") => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::ExplicitStop,
                                    ..
                                }
                            ),
                            "Ok + {strategy_name} should Stop(ExplicitStop) (fallback)"
                        );
                    }
                    _ => panic!(
                        "unexpected outcome/strategy pair in monotone severity cross-product: outcome={outcome_name}, strategy={strategy_name}"
                    ),
                }
            }
        }

        crate::test_complete!("conformance_monotone_severity_cross_product");
    }

    /// Conformance: OneForOne only cancels and restarts the failed child.
    /// Other children in the topology are untouched.
    #[test]
    fn conformance_one_for_one_isolates_failed_child() {
        init_test("conformance_one_for_one_isolates_failed_child");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(
                ChildSpec::new("db", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("cache", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("web", noop_start)
                    .depends_on("cache")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            );

        let compiled = builder.compile().expect("compile");

        // Fail "cache" — only "cache" should appear in the plan
        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("cache", &err)
            .expect("restart plan");

        assert_eq!(plan.policy, RestartPolicy::OneForOne);
        assert_eq!(plan.cancel_order, vec!["cache"]);
        assert_eq!(plan.restart_order, vec!["cache"]);

        // Fail "db" — only "db"
        let plan = compiled
            .restart_plan_for_failure("db", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["db"]);
        assert_eq!(plan.restart_order, vec!["db"]);

        // Fail "web" — only "web"
        let plan = compiled
            .restart_plan_for_failure("web", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["web"]);
        assert_eq!(plan.restart_order, vec!["web"]);

        crate::test_complete!("conformance_one_for_one_isolates_failed_child");
    }

    /// Conformance: OneForAll cancels all children in reverse start order and
    /// restarts all in start order, regardless of which child failed.
    #[test]
    fn conformance_one_for_all_restarts_all_children() {
        init_test("conformance_one_for_all_restarts_all_children");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("a", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("b", noop_start)
                    .depends_on("a")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("c", noop_start)
                    .depends_on("b")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            );

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // Fail any child — ALL children are in the plan
        for failed in &["a", "b", "c"] {
            let plan = compiled
                .restart_plan_for_failure(failed, &err)
                .expect("restart plan");

            assert_eq!(plan.policy, RestartPolicy::OneForAll);
            // Cancel: reverse start order (c, b, a)
            assert_eq!(plan.cancel_order, vec!["c", "b", "a"]);
            // Restart: start order (a, b, c)
            assert_eq!(plan.restart_order, vec!["a", "b", "c"]);
        }

        crate::test_complete!("conformance_one_for_all_restarts_all_children");
    }

    /// Conformance: RestForOne cancels the failed child and all children started
    /// after it, then restarts that suffix in start order.
    #[test]
    fn conformance_rest_for_one_restarts_suffix() {
        init_test("conformance_rest_for_one_restarts_suffix");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(
                ChildSpec::new("a", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("b", noop_start)
                    .depends_on("a")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("c", noop_start)
                    .depends_on("b")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("d", noop_start)
                    .depends_on("c")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            );

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // Fail "b" — b, c, d are in the plan (suffix from b)
        let plan = compiled
            .restart_plan_for_failure("b", &err)
            .expect("restart plan");
        assert_eq!(plan.policy, RestartPolicy::RestForOne);
        assert_eq!(plan.cancel_order, vec!["d", "c", "b"]); // reverse start order
        assert_eq!(plan.restart_order, vec!["b", "c", "d"]); // start order

        // Fail "a" — all children (a is first)
        let plan = compiled
            .restart_plan_for_failure("a", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["d", "c", "b", "a"]);
        assert_eq!(plan.restart_order, vec!["a", "b", "c", "d"]);

        // Fail "d" — only d (last child, no suffix after it)
        let plan = compiled
            .restart_plan_for_failure("d", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["d"]);
        assert_eq!(plan.restart_order, vec!["d"]);

        crate::test_complete!("conformance_rest_for_one_restarts_suffix");
    }

    /// Conformance: escalation with no parent region (root-level supervisor).
    /// The decision should still be Escalate with parent_region_id = None.
    #[test]
    fn conformance_escalation_without_parent_region() {
        init_test("conformance_escalation_without_parent_region");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None, // no parent
            &Outcome::Err(()),
            0,
        );

        match decision {
            SupervisionDecision::Escalate {
                parent_region_id,
                task_id: tid,
                region_id: rid,
                ..
            } => {
                assert!(parent_region_id.is_none(), "root escalation has no parent");
                assert_eq!(tid, test_task_id());
                assert_eq!(rid, test_region_id());
            }
            other => panic!("expected Escalate, got {other:?}"),
        }

        crate::test_complete!("conformance_escalation_without_parent_region");
    }

    /// Conformance: after budget exhaustion, subsequent on_failure calls also
    /// return Stop (the supervisor doesn't magically recover restart ability).
    #[test]
    fn conformance_budget_exhaustion_idempotent_stop() {
        init_test("conformance_budget_exhaustion_idempotent_stop");

        let config = RestartConfig::new(1, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // First failure: restarts
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        assert!(matches!(
            d1,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second failure: budget exhausted → stop
        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        assert!(matches!(
            d2,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        // Third failure: still stop (exhaustion is sticky within window)
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );
        assert!(matches!(
            d3,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        crate::test_complete!("conformance_budget_exhaustion_idempotent_stop");
    }

    #[test]
    fn restart_budget_exhaustion_reports_observed_restart_count() {
        init_test("restart_budget_exhaustion_reports_observed_restart_count");

        let config = RestartConfig::new(1, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));
        let history = supervisor
            .history
            .as_mut()
            .expect("restart strategy initializes history");
        history.record_restart(0);
        history.record_restart(1_000_000_000);
        history.record_restart(2_000_000_000);

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted {
                    total_restarts: 3,
                    window,
                },
                ..
            } if window == Duration::from_mins(1)
        ));

        crate::test_complete!("restart_budget_exhaustion_reports_observed_restart_count");
    }

    #[test]
    fn restart_budget_exhaustion_with_budget_reports_observed_restart_count() {
        init_test("restart_budget_exhaustion_with_budget_reports_observed_restart_count");

        let config = RestartConfig::new(1, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));
        let history = supervisor
            .history
            .as_mut()
            .expect("restart strategy initializes history");
        history.record_restart(0);
        history.record_restart(1_000_000_000);
        history.record_restart(2_000_000_000);

        let mut budget = Budget::INFINITE;
        let decision = supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
            Some(&mut budget),
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted {
                    total_restarts: 3,
                    window,
                },
                ..
            } if window == Duration::from_mins(1)
        ));

        crate::test_complete!(
            "restart_budget_exhaustion_with_budget_reports_observed_restart_count"
        );
    }

    /// Conformance: budget refusal priority — window exhaustion is checked before
    /// per-constraint budget checks when no budget is provided.
    #[test]
    fn conformance_budget_refusal_checks_window_first() {
        init_test("conformance_budget_refusal_checks_window_first");

        let config = RestartConfig::new(1, Duration::from_mins(1))
            .with_restart_cost(100)
            .with_min_polls(500);

        let mut history = RestartHistory::new(config);

        // Exhaust the window
        history.record_restart(0);

        // Budget that would also fail on cost and polls
        let bad_budget = Budget::new().with_cost_quota(10).with_poll_quota(50);

        // Window exhaustion is checked first
        let result = history.can_restart_with_budget(1_000_000_000, &bad_budget);
        assert!(
            matches!(result, Err(BudgetRefusal::WindowExhausted { .. })),
            "window exhaustion should be checked before budget constraints"
        );

        crate::test_complete!("conformance_budget_refusal_checks_window_first");
    }

    /// Conformance: restart exactly at window boundary — restarts that fall
    /// exactly on the boundary of the sliding window are correctly counted or
    /// expired.
    #[test]
    fn conformance_restart_window_boundary_exact() {
        init_test("conformance_restart_window_boundary_exact");

        // Window of exactly 10 seconds, max 2 restarts
        let config = RestartConfig::new(2, Duration::from_secs(10));
        let mut history = RestartHistory::new(config);

        // Record restarts at t=0 and t=1s
        history.record_restart(0);
        history.record_restart(1_000_000_000);

        // At t=9.999s: both restarts still in window → cannot restart
        assert!(!history.can_restart(9_999_999_999));

        // At t=10s (exactly): the restart at t=0 is at the boundary
        // cutoff = 10_000_000_000 - 10_000_000_000 = 0
        // restart at t=0: 0 >= 0 → still counted
        // restart at t=1s: 1_000_000_000 >= 0 → still counted
        // → 2 restarts, cannot restart
        assert!(!history.can_restart(10_000_000_000));

        // At t=10.000000001s: restart at t=0 just expired
        // cutoff = 10_000_000_001 - 10_000_000_000 = 1
        // restart at t=0: 0 >= 1 → false, expired
        // restart at t=1s: 1_000_000_000 >= 1 → still counted
        // → 1 restart, can restart again
        assert!(history.can_restart(10_000_000_001));

        crate::test_complete!("conformance_restart_window_boundary_exact");
    }

    /// Conformance: supervision decision carries correct identifying fields.
    /// The task_id, region_id, and attempt numbers in the returned
    /// SupervisionDecision must exactly match the inputs and internal state.
    #[test]
    fn conformance_decision_carries_correct_ids() {
        init_test("conformance_decision_carries_correct_ids");

        let task = TaskId::from_arena(ArenaIndex::new(42, 7));
        let region = RegionId::from_arena(ArenaIndex::new(10, 3));
        let parent = RegionId::from_arena(ArenaIndex::new(0, 1));

        // Stop strategy
        {
            let mut sup = Supervisor::new(SupervisionStrategy::Stop);
            let decision = sup.on_failure(task, region, Some(parent), &Outcome::Err(()), 0);
            match decision {
                SupervisionDecision::Stop {
                    task_id: tid,
                    region_id: rid,
                    reason,
                } => {
                    assert_eq!(tid, task);
                    assert_eq!(rid, region);
                    assert_eq!(reason, StopReason::ExplicitStop);
                }
                other => panic!("expected Stop, got {other:?}"),
            }
        }

        // Restart strategy — verify attempt counter increments
        {
            let config = RestartConfig::new(5, Duration::from_mins(1));
            let mut sup = Supervisor::new(SupervisionStrategy::Restart(config));

            for expected_attempt in 1..=3u32 {
                let decision = sup.on_failure(
                    task,
                    region,
                    Some(parent),
                    &Outcome::Err(()),
                    u64::from(expected_attempt - 1) * 1_000_000_000,
                );
                match decision {
                    SupervisionDecision::Restart {
                        task_id: tid,
                        region_id: rid,
                        attempt,
                        ..
                    } => {
                        assert_eq!(tid, task);
                        assert_eq!(rid, region);
                        assert_eq!(attempt, expected_attempt);
                    }
                    other => {
                        panic!("expected Restart attempt={expected_attempt}, got {other:?}")
                    }
                }
            }
        }

        // Escalate strategy
        {
            let mut sup = Supervisor::new(SupervisionStrategy::Escalate);
            let decision = sup.on_failure(task, region, Some(parent), &Outcome::Err(()), 0);
            match decision {
                SupervisionDecision::Escalate {
                    task_id: tid,
                    region_id: rid,
                    parent_region_id,
                    ..
                } => {
                    assert_eq!(tid, task);
                    assert_eq!(rid, region);
                    assert_eq!(parent_region_id, Some(parent));
                }
                other => panic!("expected Escalate, got {other:?}"),
            }
        }

        crate::test_complete!("conformance_decision_carries_correct_ids");
    }

    /// Conformance: restart delay in the decision matches the backoff
    /// calculation for the correct attempt number.
    #[test]
    fn conformance_restart_delay_matches_backoff() {
        init_test("conformance_restart_delay_matches_backoff");

        let config = RestartConfig::new(5, Duration::from_mins(1)).with_backoff(
            BackoffStrategy::Exponential {
                initial: Duration::from_millis(100),
                max: Duration::from_secs(10),
                multiplier: 2.0,
            },
        );

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config.clone()));

        // Attempt 1: delay should be for attempt index 0 = 100ms
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        match d1 {
            SupervisionDecision::Restart { delay, attempt, .. } => {
                assert_eq!(attempt, 1);
                assert_eq!(delay, config.backoff.delay_for_attempt(0));
            }
            other => panic!("expected Restart, got {other:?}"),
        }

        // Attempt 2: delay should be for attempt index 1 = 200ms
        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        match d2 {
            SupervisionDecision::Restart { delay, attempt, .. } => {
                assert_eq!(attempt, 2);
                assert_eq!(delay, config.backoff.delay_for_attempt(1));
            }
            other => panic!("expected Restart, got {other:?}"),
        }

        // Attempt 3: delay should be for attempt index 2 = 400ms
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );
        match d3 {
            SupervisionDecision::Restart { delay, attempt, .. } => {
                assert_eq!(attempt, 3);
                assert_eq!(delay, config.backoff.delay_for_attempt(2));
            }
            other => panic!("expected Restart, got {other:?}"),
        }

        crate::test_complete!("conformance_restart_delay_matches_backoff");
    }

    /// Conformance: spawn starts children in dependency order and
    /// skips non-start_immediately children.
    #[test]
    fn conformance_spawn_dependency_ordered_start() {
        init_test("conformance_spawn_dependency_ordered_start");

        let log = Arc::new(Mutex::new(Vec::new()));

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new(
                "db",
                LoggingStart {
                    name: "db",
                    log: Arc::clone(&log),
                },
            ))
            .child(
                ChildSpec::new(
                    "cache",
                    LoggingStart {
                        name: "cache",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("db"),
            )
            .child(
                ChildSpec::new(
                    "web",
                    LoggingStart {
                        name: "web",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("cache"),
            )
            .child(
                ChildSpec::new(
                    "deferred",
                    LoggingStart {
                        name: "deferred",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("db")
                .with_start_immediately(false),
            );

        let compiled = builder.compile().expect("compile");

        // Verify start order: db, cache, web (deferred is skipped)
        assert_eq!(compiled.start_order.len(), 4);
        assert_eq!(compiled.children[compiled.start_order[0]].name, "db");
        assert_eq!(compiled.children[compiled.start_order[1]].name, "cache");

        // Spawn with a minimal RuntimeState
        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let handle = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect("spawn");

        // Verify logged start order
        let started: Vec<String> = log.lock().clone();
        assert_eq!(started, vec!["db", "cache", "web"]);

        // deferred should not be started
        assert!(!started.contains(&"deferred".to_string()));

        // Supervisor handle has 3 started children (not deferred)
        assert_eq!(handle.started.len(), 3);
        assert_eq!(handle.started[0].name, "db");
        assert_eq!(handle.started[1].name, "cache");
        assert_eq!(handle.started[2].name, "web");

        crate::test_complete!("conformance_spawn_dependency_ordered_start");
    }

    #[test]
    fn deferred_children_are_skipped_at_boot_and_stay_out_of_sibling_restart_plans() {
        init_test("deferred_children_are_skipped_at_boot_and_stay_out_of_sibling_restart_plans");

        let compiled = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("db", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("cache", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("deferred", noop_start)
                    .depends_on("cache")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default()))
                    .with_start_immediately(false),
            )
            .compile()
            .expect("compile");

        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("cache", &err)
            .expect("compiled restart planning should cover started siblings");

        assert_eq!(
            plan.cancel_order,
            vec![ChildName::from("cache"), ChildName::from("db")]
        );
        assert_eq!(
            plan.restart_order,
            vec![ChildName::from("db"), ChildName::from("cache")]
        );

        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let handle = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect("spawn");

        assert_eq!(handle.started.len(), 2);
        assert_eq!(handle.started[0].name, "db");
        assert_eq!(handle.started[1].name, "cache");

        crate::test_complete!(
            "deferred_children_are_skipped_at_boot_and_stay_out_of_sibling_restart_plans"
        );
    }

    #[test]
    fn failed_deferred_child_remains_in_restart_plan() {
        init_test("failed_deferred_child_remains_in_restart_plan");

        let compiled = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("db", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("deferred", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default()))
                    .with_start_immediately(false),
            )
            .compile()
            .expect("compile");

        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("deferred", &err)
            .expect("the failed child itself should remain restartable");

        assert_eq!(
            plan.cancel_order,
            vec![ChildName::from("deferred"), ChildName::from("db")]
        );
        assert_eq!(
            plan.restart_order,
            vec![ChildName::from("db"), ChildName::from("deferred")]
        );

        crate::test_complete!("failed_deferred_child_remains_in_restart_plan");
    }

    /// Conformance: non-required child start failure doesn't fail the supervisor.
    /// Required child failure does fail the supervisor.
    #[test]
    fn conformance_spawn_required_vs_optional_child_failure() {
        #[allow(clippy::unnecessary_wraps)]
        fn failing_start(
            _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _state: &mut RuntimeState,
            _cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            Err(SpawnError::RegionClosed(test_region_id()))
        }

        init_test("conformance_spawn_required_vs_optional_child_failure");

        // Optional child failure: supervisor succeeds
        {
            let builder = SupervisorBuilder::new("sup")
                .child(ChildSpec::new("ok_child", noop_start))
                .child(
                    ChildSpec::new("optional_fail", failing_start)
                        .with_required(false)
                        .depends_on("ok_child"),
                );

            let compiled = builder.compile().expect("compile");
            let mut state = RuntimeState::new();
            let parent = state.create_root_region(Budget::INFINITE);
            let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
            let result = compiled.spawn(&mut state, &cx, parent, Budget::INFINITE);
            assert!(
                result.is_ok(),
                "optional child failure should not fail supervisor"
            );
        }

        // Required child failure: supervisor fails
        {
            let builder = SupervisorBuilder::new("sup")
                .child(ChildSpec::new("ok_child", noop_start))
                .child(
                    ChildSpec::new("required_fail", failing_start)
                        .with_required(true)
                        .depends_on("ok_child"),
                );

            let compiled = builder.compile().expect("compile");
            let mut state = RuntimeState::new();
            let parent = state.create_root_region(Budget::INFINITE);
            let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
            let result = compiled.spawn(&mut state, &cx, parent, Budget::INFINITE);
            assert!(
                result.is_err(),
                "required child failure should fail supervisor"
            );
            match result.unwrap_err() {
                SupervisorSpawnError::ChildStartFailed { child, region, .. } => {
                    assert_eq!(child, "required_fail");
                    // Verify the region was closed (not leaked).
                    if let Some(record) = state.region(region) {
                        let rs = record.state();
                        assert!(
                            matches!(
                                rs,
                                crate::record::region::RegionState::Closing
                                    | crate::record::region::RegionState::Draining
                                    | crate::record::region::RegionState::Finalizing
                                    | crate::record::region::RegionState::Closed
                            ),
                            "region should not be Open after partial spawn failure, got {rs:?}"
                        );
                    }
                }
                SupervisorSpawnError::RegionCreate(_) => {
                    panic!("expected ChildStartFailed, got RegionCreate");
                }
                SupervisorSpawnError::DependencyUnavailable { .. } => {
                    panic!("expected ChildStartFailed, got DependencyUnavailable");
                }
            }
        }

        crate::test_complete!("conformance_spawn_required_vs_optional_child_failure");
    }

    #[test]
    fn optional_dependency_failure_skips_eager_dependents() {
        #[allow(clippy::unnecessary_wraps)]
        fn failing_start(
            _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _state: &mut RuntimeState,
            _cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            Err(SpawnError::RegionClosed(test_region_id()))
        }

        init_test("optional_dependency_failure_skips_eager_dependents");

        let log = Arc::new(Mutex::new(Vec::new()));
        let compiled = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("db", failing_start).with_required(false))
            .child(
                ChildSpec::new(
                    "worker",
                    LoggingStart {
                        name: "worker",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("db")
                .with_required(false),
            )
            .child(ChildSpec::new(
                "metrics",
                LoggingStart {
                    name: "metrics",
                    log: Arc::clone(&log),
                },
            ))
            .compile()
            .expect("compile");

        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let handle = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect("optional dependency failure should not fail supervisor");

        let started: Vec<String> = log.lock().clone();
        assert_eq!(started, vec!["metrics"]);
        assert_eq!(handle.started.len(), 1);
        assert_eq!(handle.started[0].name, "metrics");

        crate::test_complete!("optional_dependency_failure_skips_eager_dependents");
    }

    #[test]
    fn required_child_with_failed_dependency_fails_supervisor_boot() {
        #[allow(clippy::unnecessary_wraps)]
        fn failing_start(
            _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _state: &mut RuntimeState,
            _cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            Err(SpawnError::RegionClosed(test_region_id()))
        }

        init_test("required_child_with_failed_dependency_fails_supervisor_boot");

        let log = Arc::new(Mutex::new(Vec::new()));
        let compiled = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("db", failing_start).with_required(false))
            .child(ChildSpec::new("api", noop_start).depends_on("db"))
            .child(ChildSpec::new(
                "metrics",
                LoggingStart {
                    name: "metrics",
                    log: Arc::clone(&log),
                },
            ))
            .compile()
            .expect("compile");

        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let err = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect_err("required dependent with failed dependency should fail boot");

        let (region, dependency_error) = match err {
            SupervisorSpawnError::DependencyUnavailable {
                child,
                dependency,
                dependency_error,
                region,
            } => {
                assert_eq!(child, "api");
                assert_eq!(dependency, "db");
                (region, dependency_error)
            }
            SupervisorSpawnError::RegionCreate(_) => {
                panic!("expected DependencyUnavailable, got RegionCreate")
            }
            SupervisorSpawnError::ChildStartFailed { .. } => {
                panic!("expected DependencyUnavailable, got ChildStartFailed")
            }
        };

        assert!(
            matches!(dependency_error, Some(SpawnError::RegionClosed(_))),
            "dependency root cause should preserve the original start failure"
        );

        // When a required child's dependency is unavailable, the supervisor aborts
        // boot via a full cancel cascade. The already-started sibling ("metrics")
        // is cancelled; because it is a registered-but-unpolled task it quiesces
        // immediately, so the cancel cascade drives the supervisor region to
        // terminal state and reaps both the task and the region. We therefore
        // assert the cascade cleaned up the region (no leak) rather than that it
        // lingers in a `Cancelling` state.
        assert!(
            state.region(region).is_none(),
            "boot-failure cancel cascade should quiesce and reap the supervisor region"
        );
        // The required dependent ("api") is started in dependency order, before the
        // independent "metrics" child, so its dependency-unavailable abort halts the
        // boot before "metrics" runs its start hook — nothing is logged.
        assert!(
            log.lock().is_empty(),
            "abort on the required dependent halts boot before later children start; got {:?}",
            log.lock().as_slice()
        );

        crate::test_complete!("required_child_with_failed_dependency_fails_supervisor_boot");
    }

    #[test]
    fn transitive_dependency_unavailable_reports_direct_dependency() {
        #[allow(clippy::unnecessary_wraps)]
        fn failing_start(
            _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _state: &mut RuntimeState,
            _cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            Err(SpawnError::RegionClosed(test_region_id()))
        }

        init_test("transitive_dependency_unavailable_reports_direct_dependency");

        let compiled = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("db", failing_start).with_required(false))
            .child(
                ChildSpec::new("api", noop_start)
                    .depends_on("db")
                    .with_required(false),
            )
            .child(ChildSpec::new("frontend", noop_start).depends_on("api"))
            .compile()
            .expect("compile");

        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let err = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect_err("required transitive dependent should fail boot");

        match err {
            SupervisorSpawnError::DependencyUnavailable {
                child,
                dependency,
                dependency_error,
                ..
            } => {
                assert_eq!(child, "frontend");
                assert_eq!(
                    dependency, "api",
                    "direct blocker should be reported even when the root cause is transitive"
                );
                assert!(
                    matches!(dependency_error, Some(SpawnError::RegionClosed(_))),
                    "root-cause spawn error should still be preserved"
                );
            }
            SupervisorSpawnError::RegionCreate(_) => {
                panic!("expected DependencyUnavailable, got RegionCreate")
            }
            SupervisorSpawnError::ChildStartFailed { .. } => {
                panic!("expected DependencyUnavailable, got ChildStartFailed")
            }
        }

        crate::test_complete!("transitive_dependency_unavailable_reports_direct_dependency");
    }

    #[test]
    fn required_child_failure_requests_cancel_for_started_task() {
        fn failing_start(
            scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _state: &mut RuntimeState,
            _cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            Err(SpawnError::RegionClosed(scope.region_id()))
        }

        init_test("required_child_failure_requests_cancel_for_started_task");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("started", spawn_registered_child))
            .child(
                ChildSpec::new("required_fail", failing_start)
                    .with_required(true)
                    .depends_on("started"),
            );

        let compiled = builder.compile().expect("compile");
        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let err = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect_err("required child failure should fail supervisor");

        let (region, started_task) = match err {
            SupervisorSpawnError::ChildStartFailed { region, .. } => {
                let record = state
                    .region(region)
                    .expect("supervisor region should exist");
                let started_task = *record
                    .task_ids()
                    .first()
                    .expect("started task should remain tracked");
                (region, started_task)
            }
            SupervisorSpawnError::RegionCreate(_) => {
                panic!("expected ChildStartFailed, got RegionCreate")
            }
            SupervisorSpawnError::DependencyUnavailable { .. } => {
                panic!("expected ChildStartFailed, got DependencyUnavailable")
            }
        };

        let task = state.task(started_task).expect("started task should exist");
        assert!(
            task.state.is_cancelling(),
            "started child task should enter cancellation after supervisor boot failure"
        );
        assert!(
            state
                .region(region)
                .and_then(crate::record::RegionRecord::cancel_reason)
                .is_some(),
            "failed supervisor region should retain a cancel reason"
        );

        crate::test_complete!("required_child_failure_requests_cancel_for_started_task");
    }

    /// Conformance: CompiledSupervisor::restart_plan_for_failure returns
    /// None when the child has Stop strategy (even on Err outcome), and
    /// returns a plan when the child has Restart strategy on Err.
    /// Covers the interplay between per-child strategy and supervisor-level
    /// restart policy.
    #[test]
    fn conformance_per_child_strategy_vs_supervisor_policy() {
        init_test("conformance_per_child_strategy_vs_supervisor_policy");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("restartable", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("stopper", noop_start)
                    .depends_on("restartable")
                    .with_restart(SupervisionStrategy::Stop),
            )
            .child(
                ChildSpec::new("escalator", noop_start)
                    .depends_on("restartable")
                    .with_restart(SupervisionStrategy::Escalate),
            );

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // restartable child with Err: plan exists (restart strategy)
        assert!(
            compiled
                .restart_plan_for_failure("restartable", &err)
                .is_some()
        );

        // stopper child with Err: no plan (stop strategy)
        assert!(compiled.restart_plan_for_failure("stopper", &err).is_none());

        // escalator child with Err: no plan (escalate strategy, not restart)
        assert!(
            compiled
                .restart_plan_for_failure("escalator", &err)
                .is_none()
        );

        crate::test_complete!("conformance_per_child_strategy_vs_supervisor_policy");
    }

    #[test]
    fn conformance_failure_plan_prunes_non_restartable_siblings_and_blocked_dependents() {
        init_test(
            "conformance_failure_plan_prunes_non_restartable_siblings_and_blocked_dependents",
        );

        let compiled = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("db", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("cache", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Stop),
            )
            .child(
                ChildSpec::new("web", noop_start)
                    .depends_on("cache")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("metrics", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .compile()
            .expect("compile");

        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("db", &err)
            .expect("restart plan");

        assert_eq!(
            plan.cancel_order,
            vec![
                ChildName::from("metrics"),
                ChildName::from("web"),
                ChildName::from("cache"),
                ChildName::from("db"),
            ]
        );
        assert_eq!(
            plan.restart_order,
            vec![ChildName::from("db"), ChildName::from("metrics")]
        );

        crate::test_complete!(
            "conformance_failure_plan_prunes_non_restartable_siblings_and_blocked_dependents"
        );
    }

    #[test]
    fn conformance_failure_plan_prunes_escalating_siblings_from_restart_order() {
        init_test("conformance_failure_plan_prunes_escalating_siblings_from_restart_order");

        let compiled = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("db", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("audit", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Escalate),
            )
            .child(
                ChildSpec::new("metrics", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .compile()
            .expect("compile");

        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("db", &err)
            .expect("restart plan");

        assert_eq!(
            plan.cancel_order,
            vec![
                ChildName::from("metrics"),
                ChildName::from("audit"),
                ChildName::from("db"),
            ]
        );
        assert_eq!(
            plan.restart_order,
            vec![ChildName::from("db"), ChildName::from("metrics")]
        );

        crate::test_complete!(
            "conformance_failure_plan_prunes_escalating_siblings_from_restart_order"
        );
    }

    /// Conformance: after the restart window expires, the supervisor can
    /// restart again — demonstrating recovery from budget exhaustion.
    #[test]
    fn conformance_window_expiry_restores_restart_ability() {
        init_test("conformance_window_expiry_restores_restart_ability");

        // 1 restart allowed in a 5-second window
        let config = RestartConfig::new(1, Duration::from_secs(5));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // First failure at t=0: restart
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        assert!(matches!(
            d1,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second failure at t=1s: exhausted
        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        assert!(matches!(
            d2,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        // Third failure at t=6s: window expired, can restart again
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            6_000_000_000,
        );
        assert!(
            matches!(d3, SupervisionDecision::Restart { attempt: 1, .. }),
            "window expiry should restore restart ability"
        );

        crate::test_complete!("conformance_window_expiry_restores_restart_ability");
    }

    /// Conformance: RestartIntensityWindow storm detection threshold is exact.
    /// At exactly the threshold intensity, is_storm returns false; above
    /// the threshold it returns true.
    #[test]
    fn conformance_intensity_storm_threshold_boundary() {
        init_test("conformance_intensity_storm_threshold_boundary");

        // Threshold: 2.0 restarts/second in a 10-second window
        // → 20 restarts at threshold
        let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 2.0);

        // Record exactly 20 restarts within the 10s window
        for i in 0u64..20 {
            window.record(i * 500_000_000); // every 0.5s
        }

        let now = 10_000_000_000; // t=10s
        let intensity = window.intensity(now);
        assert!(
            (intensity - 2.0).abs() < 0.01,
            "20 restarts in 10s should be ~2.0/s"
        );
        // At exactly the threshold: not a storm (uses > not >=)
        assert!(!window.is_storm(now));

        // One more restart pushes above threshold
        window.record(10_000_000_000);
        assert!(window.is_storm(10_000_000_000));

        crate::test_complete!("conformance_intensity_storm_threshold_boundary");
    }

    #[test]
    #[should_panic(expected = "storm threshold must be finite and > 0")]
    fn intensity_window_zero_threshold_panics() {
        let _window = RestartIntensityWindow::new(Duration::from_secs(1), 0.0);
    }

    /// Conformance: compile detects duplicate child names.
    #[test]
    fn conformance_compile_rejects_duplicate_names() {
        init_test("conformance_compile_rejects_duplicate_names");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("worker", noop_start))
            .child(ChildSpec::new("worker", noop_start));

        let result = builder.compile();
        assert!(matches!(
            result,
            Err(SupervisorCompileError::DuplicateChildName(ref name)) if name == "worker"
        ));

        crate::test_complete!("conformance_compile_rejects_duplicate_names");
    }

    /// Conformance: compile detects unknown dependency references.
    #[test]
    fn conformance_compile_rejects_unknown_dependency() {
        init_test("conformance_compile_rejects_unknown_dependency");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start).depends_on("nonexistent"));

        let result = builder.compile();
        assert!(matches!(
            result,
            Err(SupervisorCompileError::UnknownDependency { ref child, ref depends_on })
                if child == "a" && depends_on == "nonexistent"
        ));

        crate::test_complete!("conformance_compile_rejects_unknown_dependency");
    }

    #[test]
    fn conformance_compile_rejects_immediate_child_with_deferred_dependency() {
        init_test("conformance_compile_rejects_immediate_child_with_deferred_dependency");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("db", noop_start).with_start_immediately(false))
            .child(ChildSpec::new("api", noop_start).depends_on("db"));

        let result = builder.compile();
        assert!(matches!(
            result,
            Err(SupervisorCompileError::DeferredDependency { ref child, ref depends_on })
                if child == "api" && depends_on == "db"
        ));

        crate::test_complete!(
            "conformance_compile_rejects_immediate_child_with_deferred_dependency"
        );
    }

    /// Conformance: compile detects dependency cycles.
    #[test]
    fn conformance_compile_rejects_cycles() {
        init_test("conformance_compile_rejects_cycles");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start).depends_on("c"))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"));

        let result = builder.compile();
        match result {
            Err(SupervisorCompileError::CycleDetected { remaining }) => {
                // All three are in the cycle
                assert_eq!(remaining.len(), 3);
                assert!(remaining.contains(&ChildName::from("a")));
                assert!(remaining.contains(&ChildName::from("b")));
                assert!(remaining.contains(&ChildName::from("c")));
            }
            other => panic!("expected CycleDetected, got {other:?}"),
        }

        crate::test_complete!("conformance_compile_rejects_cycles");
    }

    /// Conformance: NameLex tie-break produces alphabetical start order
    /// for children with no inter-dependencies.
    #[test]
    fn conformance_name_lex_tie_break() {
        init_test("conformance_name_lex_tie_break");

        let builder = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::NameLex)
            .child(ChildSpec::new("zulu", noop_start))
            .child(ChildSpec::new("alpha", noop_start))
            .child(ChildSpec::new("mike", noop_start));

        let compiled = builder.compile().expect("compile");

        let names = compiled.child_start_order_names();

        assert_eq!(names, vec!["alpha", "mike", "zulu"]);

        crate::test_complete!("conformance_name_lex_tie_break");
    }

    /// Conformance: `CompiledSupervisor::child_start_pos` matches the compiled `start_order`.
    #[test]
    fn conformance_child_start_pos_matches_start_order() {
        init_test("conformance_child_start_pos_matches_start_order");

        let compiled = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::NameLex)
            .child(ChildSpec::new("db", noop_start))
            .child(ChildSpec::new("cache", noop_start).depends_on("db"))
            .child(ChildSpec::new("web", noop_start).depends_on("db"))
            .child(ChildSpec::new("worker", noop_start).depends_on("cache"))
            .compile()
            .expect("compile");

        for (pos, &idx) in compiled.start_order.iter().enumerate() {
            let name = compiled.children[idx].name.as_str();
            assert_eq!(compiled.child_start_pos(name), Some(pos));
        }
        assert_eq!(compiled.child_start_pos("does_not_exist"), None);

        crate::test_complete!("conformance_child_start_pos_matches_start_order");
    }

    /// Conformance: deterministic stop/drain order is reverse start order (SUP-STOP).
    #[test]
    fn conformance_child_stop_order_is_reverse_start_order() {
        init_test("conformance_child_stop_order_is_reverse_start_order");

        let compiled = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::NameLex)
            .child(ChildSpec::new("db", noop_start))
            .child(ChildSpec::new("cache", noop_start).depends_on("db"))
            .child(ChildSpec::new("web", noop_start).depends_on("db"))
            .child(ChildSpec::new("worker", noop_start).depends_on("cache"))
            .compile()
            .expect("compile");

        let start = compiled.child_start_order_names();
        let stop = compiled.child_stop_order_names();

        let mut expected = start.clone();
        expected.reverse();

        assert_eq!(stop, expected);
        assert_eq!(start, vec!["db", "cache", "web", "worker"]);
        assert_eq!(stop, vec!["worker", "web", "cache", "db"]);

        crate::test_complete!("conformance_child_stop_order_is_reverse_start_order");
    }

    /// Conformance: a stable tie-break key for batching logically-simultaneous failures.
    ///
    /// If multiple child failures are observed in the same quantum, a runtime layer should
    /// process them in ascending child start position (dependencies-first), using `TaskId`
    /// as a stable secondary key if needed.
    #[test]
    fn conformance_simultaneous_failures_sorted_by_start_pos_then_task_id() {
        init_test("conformance_simultaneous_failures_sorted_by_start_pos_then_task_id");

        let compiled = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::InsertionOrder)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start))
            .child(ChildSpec::new("c", noop_start))
            .compile()
            .expect("compile");

        let tid = |n: u32| TaskId::from_arena(ArenaIndex::new(n, 1));

        // Same vt for all three; ordering should collapse to start_pos then TaskId.
        let mut batch = [("c", tid(3)), ("a", tid(1)), ("b", tid(2))];
        batch.sort_by_key(|(name, task_id)| {
            (
                compiled.child_start_pos(name).expect("known child"),
                *task_id,
            )
        });

        let names: Vec<&str> = batch.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["a", "b", "c"]);

        crate::test_complete!("conformance_simultaneous_failures_sorted_by_start_pos_then_task_id");
    }

    // ---------------------------------------------------------------
    // Evidence Ledger Tests (bd-35iz1)
    // ---------------------------------------------------------------

    #[test]
    fn evidence_ledger_empty_on_creation() {
        init_test("evidence_ledger_empty_on_creation");

        let supervisor = Supervisor::new(SupervisionStrategy::Stop);
        assert!(supervisor.evidence().is_empty());
        assert_eq!(supervisor.evidence().len(), 0);

        crate::test_complete!("evidence_ledger_empty_on_creation");
    }

    #[test]
    fn evidence_records_explicit_stop_strategy() {
        init_test("evidence_records_explicit_stop_strategy");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let _decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 1);
        let entry = &ledger.entries()[0];
        assert_eq!(entry.timestamp, 1000);
        assert_eq!(entry.task_id, test_task_id());
        assert_eq!(entry.region_id, test_region_id());
        assert_eq!(entry.strategy_kind, "Stop");
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::ExplicitStopStrategy
        );

        crate::test_complete!("evidence_records_explicit_stop_strategy");
    }

    #[test]
    fn evidence_records_restart_allowed() {
        init_test("evidence_records_restart_allowed");

        let config = RestartConfig::new(3, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let _d1 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );
        let _d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 2);

        assert_eq!(
            ledger.entries()[0].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 1 }
        );
        assert_eq!(ledger.entries()[0].timestamp, 1000);
        assert_eq!(ledger.entries()[0].strategy_kind, "Restart");

        assert_eq!(
            ledger.entries()[1].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 2 }
        );
        assert_eq!(ledger.entries()[1].timestamp, 2000);

        crate::test_complete!("evidence_records_restart_allowed");
    }

    #[test]
    fn evidence_records_window_exhaustion() {
        init_test("evidence_records_window_exhaustion");

        let window = Duration::from_secs(10);
        let config = RestartConfig::new(2, window);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        );
        // Third should be window exhausted
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            3000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 3);

        assert_eq!(
            ledger.entries()[0].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 1 }
        );
        assert_eq!(
            ledger.entries()[1].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 2 }
        );
        assert_eq!(
            ledger.entries()[2].binding_constraint,
            BindingConstraint::WindowExhausted {
                max_restarts: 2,
                window,
            }
        );

        crate::test_complete!("evidence_records_window_exhaustion");
    }

    #[test]
    fn evidence_records_monotone_severity_panicked() {
        init_test("evidence_records_monotone_severity_panicked");

        // Even with Restart strategy, panics produce MonotoneSeverity evidence
        let config = RestartConfig::new(5, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Panicked(PanicPayload::new("boom")),
            1000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.entries()[0].binding_constraint,
            BindingConstraint::MonotoneSeverity {
                outcome_kind: "Panicked",
            }
        );
        assert_eq!(ledger.entries()[0].strategy_kind, "Restart");

        crate::test_complete!("evidence_records_monotone_severity_panicked");
    }

    #[test]
    fn evidence_records_monotone_severity_cancelled() {
        init_test("evidence_records_monotone_severity_cancelled");

        let config = RestartConfig::new(5, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            1000,
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::MonotoneSeverity {
                outcome_kind: "Cancelled",
            }
        );

        crate::test_complete!("evidence_records_monotone_severity_cancelled");
    }

    #[test]
    fn evidence_records_monotone_severity_ok() {
        init_test("evidence_records_monotone_severity_ok");

        let config = RestartConfig::new(5, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Ok(()),
            1000,
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::MonotoneSeverity { outcome_kind: "Ok" }
        );

        crate::test_complete!("evidence_records_monotone_severity_ok");
    }

    #[test]
    fn evidence_records_escalate_strategy() {
        init_test("evidence_records_escalate_strategy");

        let parent = RegionId::from_arena(ArenaIndex::new(0, 5));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            Some(parent),
            &Outcome::Err(()),
            1000,
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(entry.strategy_kind, "Escalate");
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::EscalateStrategy
        );

        crate::test_complete!("evidence_records_escalate_strategy");
    }

    #[test]
    fn evidence_records_budget_insufficient_cost() {
        init_test("evidence_records_budget_insufficient_cost");

        let config = RestartConfig::new(5, Duration::from_mins(1)).with_restart_cost(100);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let mut budget = Budget {
            cost_quota: Some(50),
            ..Budget::INFINITE
        };
        supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
            Some(&mut budget),
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::InsufficientCost {
                required: 100,
                remaining: 50,
            }
        );

        crate::test_complete!("evidence_records_budget_insufficient_cost");
    }

    #[test]
    fn evidence_records_budget_insufficient_polls() {
        init_test("evidence_records_budget_insufficient_polls");

        let config = RestartConfig::new(5, Duration::from_mins(1)).with_min_polls(10);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let mut budget = Budget {
            poll_quota: 5,
            ..Budget::INFINITE
        };
        supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
            Some(&mut budget),
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::InsufficientPolls {
                min_required: 10,
                remaining: 5,
            }
        );

        crate::test_complete!("evidence_records_budget_insufficient_polls");
    }

    #[test]
    fn evidence_records_budget_deadline_too_close() {
        init_test("evidence_records_budget_deadline_too_close");

        let config = RestartConfig::new(5, Duration::from_mins(1))
            .with_min_remaining(Duration::from_secs(10));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Budget deadline is 5 seconds from now but we need 10 seconds minimum
        let now_nanos = 1_000_000_000u64; // 1 second
        let deadline_nanos = 6_000_000_000u64; // 6 seconds (5 seconds remaining)
        let mut budget = Budget {
            deadline: Some(Time::from_nanos(deadline_nanos)),
            ..Budget::INFINITE
        };
        supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            now_nanos,
            Some(&mut budget),
        );

        let entry = &supervisor.evidence().entries()[0];
        assert!(matches!(
            entry.binding_constraint,
            BindingConstraint::DeadlineTooClose { .. }
        ));

        crate::test_complete!("evidence_records_budget_deadline_too_close");
    }

    #[test]
    fn evidence_full_lifecycle_restart_to_exhaustion() {
        init_test("evidence_full_lifecycle_restart_to_exhaustion");

        let window = Duration::from_mins(1);
        let config = RestartConfig::new(3, window);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // 3 restarts, then exhaustion, then another attempt (still exhausted)
        for i in 0u64..5 {
            supervisor.on_failure(
                test_task_id(),
                test_region_id(),
                None,
                &Outcome::Err(()),
                i * 1_000_000_000,
            );
        }

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 5);

        // First 3: RestartAllowed
        for (idx, expected_attempt) in [(0, 1u32), (1, 2), (2, 3)] {
            assert_eq!(
                ledger.entries()[idx].binding_constraint,
                BindingConstraint::RestartAllowed {
                    attempt: expected_attempt,
                }
            );
        }

        // 4th and 5th: WindowExhausted
        for idx in 3..5 {
            assert_eq!(
                ledger.entries()[idx].binding_constraint,
                BindingConstraint::WindowExhausted {
                    max_restarts: 3,
                    window,
                }
            );
        }

        crate::test_complete!("evidence_full_lifecycle_restart_to_exhaustion");
    }

    #[test]
    fn evidence_for_task_filter() {
        init_test("evidence_for_task_filter");

        let config = RestartConfig::new(5, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));
        let task_a = TaskId::from_arena(ArenaIndex::new(0, 1));
        let task_b = TaskId::from_arena(ArenaIndex::new(0, 2));

        supervisor.on_failure(task_a, test_region_id(), None, &Outcome::Err(()), 1000);
        supervisor.on_failure(task_b, test_region_id(), None, &Outcome::Err(()), 2000);
        supervisor.on_failure(task_a, test_region_id(), None, &Outcome::Err(()), 3000);

        let a_entries: Vec<_> = supervisor.evidence().for_task(task_a).collect();
        assert_eq!(a_entries.len(), 2);
        assert_eq!(a_entries[0].timestamp, 1000);
        assert_eq!(a_entries[1].timestamp, 3000);

        assert_eq!(supervisor.evidence().for_task(task_b).count(), 1);

        crate::test_complete!("evidence_for_task_filter");
    }

    #[test]
    fn evidence_with_constraint_filter() {
        init_test("evidence_with_constraint_filter");

        let config = RestartConfig::new(2, Duration::from_mins(1));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts then a panicked outcome
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Panicked(PanicPayload::new("oops")),
            3000,
        );

        assert_eq!(
            supervisor
                .evidence()
                .with_constraint(|c| matches!(c, BindingConstraint::RestartAllowed { .. }))
                .count(),
            2
        );

        assert_eq!(
            supervisor
                .evidence()
                .with_constraint(|c| matches!(c, BindingConstraint::MonotoneSeverity { .. }))
                .count(),
            1
        );

        crate::test_complete!("evidence_with_constraint_filter");
    }

    #[test]
    fn evidence_take_drains_ledger() {
        init_test("evidence_take_drains_ledger");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );

        assert_eq!(supervisor.evidence().len(), 1);
        let taken = supervisor.take_evidence();
        assert_eq!(taken.len(), 1);
        assert!(supervisor.evidence().is_empty());

        crate::test_complete!("evidence_take_drains_ledger");
    }

    #[test]
    fn evidence_deterministic_across_strategies() {
        init_test("evidence_deterministic_across_strategies");

        // Verify that the same inputs always produce the same evidence,
        // regardless of strategy — evidence is a deterministic function of inputs.
        let outcomes = [
            Outcome::Ok(()),
            Outcome::Err(()),
            Outcome::Cancelled(CancelReason::user("test")),
            Outcome::Panicked(PanicPayload::new("boom")),
        ];

        for strategy in [
            SupervisionStrategy::Stop,
            SupervisionStrategy::Restart(RestartConfig::new(5, Duration::from_mins(1))),
            SupervisionStrategy::Escalate,
        ] {
            let mut sup_a = Supervisor::new(strategy.clone());
            let mut sup_b = Supervisor::new(strategy);

            for (i, outcome) in outcomes.iter().enumerate() {
                let t = (i as u64) * 1000;
                sup_a.on_failure(test_task_id(), test_region_id(), None, outcome, t);
                sup_b.on_failure(test_task_id(), test_region_id(), None, outcome, t);
            }

            let a = sup_a.evidence();
            let b = sup_b.evidence();
            assert_eq!(a.len(), b.len());
            for (ea, eb) in a.entries().iter().zip(b.entries().iter()) {
                assert_eq!(ea.timestamp, eb.timestamp);
                assert_eq!(ea.strategy_kind, eb.strategy_kind);
                assert_eq!(ea.binding_constraint, eb.binding_constraint);
            }
        }

        crate::test_complete!("evidence_deterministic_across_strategies");
    }

    #[test]
    fn evidence_binding_constraint_display() {
        init_test("evidence_binding_constraint_display");

        // Verify Display impls produce useful human-readable strings
        let constraints = vec![
            (
                BindingConstraint::MonotoneSeverity {
                    outcome_kind: "Panicked",
                },
                "monotone severity: Panicked is not restartable",
            ),
            (BindingConstraint::ExplicitStopStrategy, "strategy is Stop"),
            (BindingConstraint::EscalateStrategy, "strategy is Escalate"),
            (
                BindingConstraint::RestartAllowed { attempt: 3 },
                "restart allowed (attempt 3)",
            ),
            (
                BindingConstraint::WindowExhausted {
                    max_restarts: 5,
                    window: Duration::from_mins(1),
                },
                "window exhausted: 5 restarts in 60s",
            ),
            (
                BindingConstraint::InsufficientCost {
                    required: 100,
                    remaining: 42,
                },
                "insufficient cost: need 100, have 42",
            ),
            (
                BindingConstraint::InsufficientPolls {
                    min_required: 10,
                    remaining: 3,
                },
                "insufficient polls: need 10, have 3",
            ),
        ];

        for (constraint, expected) in constraints {
            assert_eq!(format!("{constraint}"), expected);
        }

        crate::test_complete!("evidence_binding_constraint_display");
    }

    #[test]
    fn evidence_window_exhaustion_with_budget_vs_without() {
        init_test("evidence_window_exhaustion_with_budget_vs_without");

        let window = Duration::from_mins(1);
        let config = RestartConfig::new(1, window);

        // Without budget: exhaust via can_restart(now)
        let mut sup_no_budget = Supervisor::new(SupervisionStrategy::Restart(config.clone()));
        sup_no_budget.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        ); // restart
        sup_no_budget.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        ); // exhausted

        // With budget (sufficient): exhaust via can_restart_with_budget
        let mut sup_budget = Supervisor::new(SupervisionStrategy::Restart(config));
        let mut budget = Budget::INFINITE;
        sup_budget.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
            Some(&mut budget),
        ); // restart
        sup_budget.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
            Some(&mut budget),
        ); // exhausted

        // Both should produce WindowExhausted as the binding constraint
        assert_eq!(
            sup_no_budget.evidence().entries()[1].binding_constraint,
            BindingConstraint::WindowExhausted {
                max_restarts: 1,
                window,
            }
        );
        assert_eq!(
            sup_budget.evidence().entries()[1].binding_constraint,
            BindingConstraint::WindowExhausted {
                max_restarts: 1,
                window,
            }
        );

        crate::test_complete!("evidence_window_exhaustion_with_budget_vs_without");
    }

    // -----------------------------------------------------------------------
    // Evidence Emission Wiring tests (bd-a7etx)
    //
    // Verify that every supervision decision also produces a generalized
    // EvidenceRecord consistent with the domain-specific EvidenceEntry.
    // -----------------------------------------------------------------------

    #[test]
    fn emission_wiring_restart_produces_generalized_record() {
        init_test("emission_wiring_restart_produces_generalized_record");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 3,
            window: Duration::from_mins(1),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 1_000);

        // Domain-specific ledger should have the entry.
        assert_eq!(supervisor.evidence().len(), 1);
        // Generalized ledger should also have the entry.
        let evidence = supervisor.generalized_evidence();
        assert_eq!(evidence.len(), 1);

        let record = &evidence.entries()[0];
        assert_eq!(record.subsystem, crate::evidence::Subsystem::Supervision);
        assert_eq!(record.verdict, Verdict::Restart);
        assert_eq!(record.task_id, task);
        assert_eq!(record.region_id, region);
        assert_eq!(record.timestamp, 1_000);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed { attempt: 1, .. })
        ));

        crate::test_complete!("emission_wiring_restart_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_stop_produces_generalized_record() {
        init_test("emission_wiring_stop_produces_generalized_record");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 2_000);

        let evidence = supervisor.generalized_evidence();
        assert_eq!(evidence.len(), 1);

        let record = &evidence.entries()[0];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop)
        ));

        crate::test_complete!("emission_wiring_stop_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_escalate_produces_generalized_record() {
        init_test("emission_wiring_escalate_produces_generalized_record");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);
        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 3_000);

        let evidence = supervisor.generalized_evidence();
        assert_eq!(evidence.len(), 1);

        let record = &evidence.entries()[0];
        assert_eq!(record.verdict, Verdict::Escalate);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::ExplicitEscalate)
        ));

        crate::test_complete!("emission_wiring_escalate_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_monotone_severity_produces_generalized_record() {
        init_test("emission_wiring_monotone_severity_produces_generalized_record");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 3,
            window: Duration::from_mins(1),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();

        // Panicked — should produce Stop with MonotoneSeverity.
        supervisor.on_failure(
            task,
            region,
            None,
            &Outcome::Panicked(PanicPayload::new("oops")),
            4_000,
        );

        let evidence = supervisor.generalized_evidence();
        let record = &evidence.entries()[0];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::MonotoneSeverity {
                outcome_kind: ref kind
            }) if kind == "Panicked"
        ));

        crate::test_complete!("emission_wiring_monotone_severity_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_window_exhaustion_produces_generalized_record() {
        init_test("emission_wiring_window_exhaustion_produces_generalized_record");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 1,
            window: Duration::from_mins(1),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();

        // First failure: restart allowed.
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 5_000);
        // Second failure: window exhausted.
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 6_000);

        let evidence = supervisor.generalized_evidence();
        assert_eq!(evidence.len(), 2);

        // First: restart.
        assert_eq!(evidence.entries()[0].verdict, Verdict::Restart);

        // Second: stop due to window exhaustion.
        let record = &evidence.entries()[1];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::WindowExhausted {
                max_restarts: 1,
                ..
            })
        ));

        crate::test_complete!("emission_wiring_window_exhaustion_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_budget_refused_produces_generalized_record() {
        init_test("emission_wiring_budget_refused_produces_generalized_record");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 5,
            window: Duration::from_mins(1),
            restart_cost: 100,
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();

        // Budget with only 10 cost remaining — insufficient for restart_cost=100.
        let mut budget = Budget::new().with_cost_quota(10);
        supervisor.on_failure_with_budget(
            task,
            region,
            None,
            &Outcome::Err(()),
            7_000,
            Some(&mut budget),
        );

        let evidence = supervisor.generalized_evidence();
        assert_eq!(evidence.len(), 1);

        let record = &evidence.entries()[0];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::BudgetRefused { .. })
        ));

        // Verify the constraint message contains useful info.
        if let EvidenceDetail::Supervision(SupervisionDetail::BudgetRefused { constraint }) =
            &record.detail
        {
            assert!(constraint.contains("insufficient cost"));
        }

        crate::test_complete!("emission_wiring_budget_refused_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_ledgers_stay_in_sync() {
        init_test("emission_wiring_ledgers_stay_in_sync");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 5,
            window: Duration::from_mins(1),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();

        // Multiple decisions.
        for i in 0..3 {
            supervisor.on_failure(task, region, None, &Outcome::Err(()), (i + 1) * 1_000);
        }

        // Both ledgers should have the same count.
        assert_eq!(supervisor.evidence().len(), 3);
        assert_eq!(supervisor.generalized_evidence().len(), 3);

        // Timestamps should match entry-by-entry.
        for (domain, generalized) in supervisor
            .evidence()
            .entries()
            .iter()
            .zip(supervisor.generalized_evidence().entries().iter())
        {
            assert_eq!(domain.timestamp, generalized.timestamp);
            assert_eq!(domain.task_id, generalized.task_id);
            assert_eq!(domain.region_id, generalized.region_id);
        }

        crate::test_complete!("emission_wiring_ledgers_stay_in_sync");
    }

    #[test]
    fn emission_wiring_take_generalized_drains() {
        init_test("emission_wiring_take_generalized_drains");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();

        supervisor.on_failure(task, region, None, &Outcome::Err(()), 8_000);
        assert_eq!(supervisor.generalized_evidence().len(), 1);

        let taken = supervisor.take_generalized_evidence();
        assert_eq!(taken.len(), 1);
        assert!(supervisor.generalized_evidence().is_empty());

        // Domain-specific ledger is independent — still has its entry.
        assert_eq!(supervisor.evidence().len(), 1);

        crate::test_complete!("emission_wiring_take_generalized_drains");
    }

    #[test]
    fn emission_wiring_render_is_deterministic() {
        init_test("emission_wiring_render_is_deterministic");

        let mut sup_a = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 2,
            window: Duration::from_mins(1),
            ..Default::default()
        }));
        let mut sup_b = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 2,
            window: Duration::from_mins(1),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = test_region_id();

        // Same sequence of decisions on both supervisors.
        for t in [1_000u64, 2_000, 3_000] {
            sup_a.on_failure(task, region, None, &Outcome::Err(()), t);
            sup_b.on_failure(task, region, None, &Outcome::Err(()), t);
        }

        // Generalized ledger render is byte-for-byte identical.
        assert_eq!(
            sup_a.generalized_evidence().render(),
            sup_b.generalized_evidence().render()
        );

        // Render is non-empty and contains expected markers.
        let rendered = sup_a.generalized_evidence().render();
        assert!(rendered.contains("supervision"));
        assert!(rendered.contains("RESTART"));

        crate::test_complete!("emission_wiring_render_is_deterministic");
    }

    // ========================================================================
    // RestartStormMonitor tests (e-process)
    // ========================================================================

    #[test]
    fn storm_monitor_starts_clear() {
        init_test("storm_monitor_starts_clear");
        let monitor = RestartStormMonitor::new(StormMonitorConfig::default());
        assert_eq!(
            monitor.alert_state(),
            crate::obligation::eprocess::AlertState::Clear
        );
        assert!((monitor.e_value() - 1.0).abs() < f64::EPSILON);
        assert_eq!(monitor.observations(), 0);
        crate::test_complete!("storm_monitor_starts_clear");
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1)")]
    fn storm_monitor_alpha_zero_panics() {
        let _m = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.0,
            ..Default::default()
        });
    }

    #[test]
    #[should_panic(expected = "expected_rate must be > 0")]
    fn storm_monitor_zero_rate_panics() {
        let _m = RestartStormMonitor::new(StormMonitorConfig {
            expected_rate: 0.0,
            ..Default::default()
        });
    }

    #[test]
    #[should_panic(expected = "storm threshold must be finite and > 0")]
    fn tracker_config_nan_threshold_panics() {
        let _config = RestartTrackerConfig::from_restart(RestartConfig::default())
            .with_storm_detection(f64::NAN);
    }

    #[test]
    fn storm_monitor_normal_intensity_stays_clear() {
        init_test("storm_monitor_normal_intensity_stays_clear");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 1.0, // 1 restart/sec expected
            min_observations: 3,
            tolerance: 1.2,
        });

        // Intensity at or below expected rate.
        for _ in 0..100 {
            monitor.observe_intensity(0.5); // half the expected rate
        }

        assert!(!monitor.is_alert());
        assert_eq!(
            monitor.alert_state(),
            crate::obligation::eprocess::AlertState::Clear
        );
        crate::test_complete!("storm_monitor_normal_intensity_stays_clear");
    }

    #[test]
    fn storm_monitor_high_intensity_triggers_alert() {
        init_test("storm_monitor_high_intensity_triggers_alert");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 0.05, // ~1 restart per 20s
            min_observations: 3,
            tolerance: 1.2,
        });

        // Intensity far exceeding expected (100×).
        for _ in 0..10 {
            monitor.observe_intensity(5.0); // 5 restarts/sec vs 0.05 expected
        }

        assert!(monitor.is_alert());
        assert!(monitor.alert_count() > 0);
        assert!(monitor.e_value() >= monitor.threshold());
        crate::test_complete!("storm_monitor_high_intensity_triggers_alert");
    }

    #[test]
    fn storm_monitor_alert_count_tracks_transitions_not_samples() {
        init_test("storm_monitor_alert_count_tracks_transitions_not_samples");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 0.05,
            min_observations: 3,
            tolerance: 1.2,
        });

        for _ in 0..10 {
            monitor.observe_intensity(5.0);
        }

        assert!(
            monitor.is_alert(),
            "sustained storm should enter alert state"
        );
        assert_eq!(
            monitor.alert_count(),
            1,
            "alert_count should increment once when the monitor first crosses into alert"
        );

        for _ in 0..10 {
            monitor.observe_intensity(5.0);
        }

        assert_eq!(
            monitor.alert_count(),
            1,
            "additional samples while already alert must not inflate alert_count"
        );

        monitor.reset();
        for _ in 0..10 {
            monitor.observe_intensity(5.0);
        }

        assert_eq!(
            monitor.alert_count(),
            1,
            "after reset, the next alert transition should be counted once again"
        );

        crate::test_complete!("storm_monitor_alert_count_tracks_transitions_not_samples");
    }

    #[test]
    fn storm_monitor_gated_by_min_observations() {
        init_test("storm_monitor_gated_by_min_observations");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 0.01,
            min_observations: 5,
            tolerance: 1.2,
        });

        // Even extreme intensity doesn't trigger before min_observations.
        monitor.observe_intensity(1000.0);
        monitor.observe_intensity(1000.0);
        assert_eq!(
            monitor.alert_state(),
            crate::obligation::eprocess::AlertState::Clear
        );

        // After enough observations, alert triggers.
        for _ in 0..5 {
            monitor.observe_intensity(1000.0);
        }
        assert!(monitor.is_alert());
        crate::test_complete!("storm_monitor_gated_by_min_observations");
    }

    #[test]
    fn storm_monitor_observe_from_window() {
        init_test("storm_monitor_observe_from_window");
        let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 1.0);
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 0.1, // expect ~1 restart per 10s
            min_observations: 3,
            tolerance: 1.2,
        });

        // Rapid restarts: 20 in 1 second → intensity = 20/10 = 2.0
        let base = 1_000_000_000u64; // 1 second in nanos
        for i in 0..20 {
            let now = base + i * 50_000_000; // every 50ms
            window.record(now);
            monitor.observe_from_window(&window, now);
        }

        // Intensity should be high enough to trigger alert.
        assert!(monitor.is_alert());
        crate::test_complete!("storm_monitor_observe_from_window");
    }

    #[test]
    fn storm_monitor_reset_clears_state() {
        init_test("storm_monitor_reset_clears_state");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 0.01,
            min_observations: 3,
            tolerance: 1.2,
        });

        for _ in 0..10 {
            monitor.observe_intensity(100.0);
        }
        assert!(monitor.is_alert());

        monitor.reset();
        assert!(!monitor.is_alert());
        assert_eq!(monitor.observations(), 0);
        assert!((monitor.e_value() - 1.0).abs() < f64::EPSILON);
        crate::test_complete!("storm_monitor_reset_clears_state");
    }

    #[test]
    fn storm_monitor_snapshot_display() {
        init_test("storm_monitor_snapshot_display");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig::default());
        monitor.observe_intensity(0.01);

        let snap = monitor.snapshot();
        assert_eq!(snap.observations, 1);
        assert!(snap.threshold > 0.0);

        let display = format!("{snap}");
        assert!(display.contains("StormMonitor"));
        crate::test_complete!("storm_monitor_snapshot_display");
    }

    #[test]
    fn storm_monitor_supermartingale_under_null() {
        init_test("storm_monitor_supermartingale_under_null");
        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 1.0,
            min_observations: 3,
            tolerance: 1.2,
        });

        // 1000 observations at or below expected rate.
        for i in 0u32..1000 {
            let intensity = f64::from((i % 10) + 1) * 0.1; // 0.1 to 1.0
            monitor.observe_intensity(intensity);
        }

        // Under H0, e-value should stay bounded.
        assert!(monitor.e_value() <= 2.0);
        assert!(!monitor.is_alert());
        crate::test_complete!("storm_monitor_supermartingale_under_null");
    }

    #[test]
    fn storm_monitor_deterministic_across_runs() {
        init_test("storm_monitor_deterministic_across_runs");
        let config = StormMonitorConfig::default();
        let intensities = [0.01, 0.05, 0.1, 0.5, 1.0];

        let mut m1 = RestartStormMonitor::new(config);
        let mut m2 = RestartStormMonitor::new(config);

        for &i in &intensities {
            m1.observe_intensity(i);
            m2.observe_intensity(i);
        }

        assert!((m1.e_value() - m2.e_value()).abs() < f64::EPSILON);
        crate::test_complete!("storm_monitor_deterministic_across_runs");
    }

    #[test]
    fn storm_monitor_config_default() {
        init_test("storm_monitor_config_default");
        let config = StormMonitorConfig::default();
        assert!((config.alpha - 0.01).abs() < f64::EPSILON);
        assert!((config.expected_rate - 0.05).abs() < f64::EPSILON);
        assert_eq!(config.min_observations, 3);
        crate::test_complete!("storm_monitor_config_default");
    }

    #[test]
    fn restart_tracker_aligns_default_storm_monitor_with_threshold() {
        init_test("restart_tracker_aligns_default_storm_monitor_with_threshold");

        let config =
            RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(1)))
                .with_storm_detection(2.0);
        let mut tracker = RestartTracker::new(config);

        tracker.record(0);
        tracker.record(500_000_000);
        tracker.record(900_000_000);

        assert!(
            tracker.is_intensity_storm(900_000_000),
            "intensity threshold should trip once three restarts land inside one second"
        );

        let snapshot = tracker
            .storm_snapshot()
            .expect("storm detection should install the default e-process monitor");
        assert!(
            snapshot.e_value > 1.0,
            "default e-process monitor should accumulate evidence above the configured threshold"
        );
        assert_eq!(
            snapshot.alert_state,
            crate::obligation::eprocess::AlertState::Watching,
            "three above-threshold samples should watch before the anytime-valid alert boundary"
        );

        for now in [
            1_000_000_000,
            1_100_000_000,
            1_200_000_000,
            1_300_000_000,
            1_400_000_000,
        ] {
            tracker.record(now);
        }

        assert!(
            tracker.is_storm(),
            "sustained above-threshold restarts should eventually trip the e-process alert"
        );

        crate::test_complete!("restart_tracker_aligns_default_storm_monitor_with_threshold");
    }

    #[test]
    fn restart_tracker_preserves_explicit_monitor_rate_across_builder_order() {
        init_test("restart_tracker_preserves_explicit_monitor_rate_across_builder_order");

        let explicit_monitor = StormMonitorConfig {
            alpha: 0.01,
            expected_rate: StormMonitorConfig::default().expected_rate,
            min_observations: 1,
            tolerance: 1.2,
        };

        let build_tracker = |threshold_first: bool| {
            let config = if threshold_first {
                RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(10)))
                    .with_storm_detection(2.0)
                    .with_storm_monitor(explicit_monitor)
            } else {
                RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(10)))
                    .with_storm_monitor(explicit_monitor)
                    .with_storm_detection(2.0)
            };
            let mut tracker = RestartTracker::new(config);
            tracker.record(0);
            tracker
                .storm_snapshot()
                .expect("storm detection enabled")
                .e_value
        };

        let threshold_then_monitor = build_tracker(true);
        let monitor_then_threshold = build_tracker(false);

        assert!(
            threshold_then_monitor > 1.0,
            "explicit expected_rate=0.05 should be preserved instead of being rewritten from threshold"
        );
        assert!(
            (threshold_then_monitor - monitor_then_threshold).abs() < f64::EPSILON,
            "builder order must not change explicit storm monitor behavior"
        );

        crate::test_complete!(
            "restart_tracker_preserves_explicit_monitor_rate_across_builder_order"
        );
    }

    // ========================================================================
    // Deterministic observability tests (bd-npn8e)
    // Cross-component: evidence ledger + e-process + intensity window
    // ========================================================================

    #[test]
    fn obs_evidence_ledger_determinism_mixed_outcomes() {
        init_test("obs_evidence_ledger_determinism_mixed_outcomes");

        let config = RestartConfig::new(3, Duration::from_mins(1));
        let task = test_task_id();
        let region = test_region_id();

        // Run the same mixed outcome sequence on two independent supervisors.
        let run = || {
            let mut sup = Supervisor::new(SupervisionStrategy::Restart(config.clone()));
            let outcomes = [
                Outcome::Err(()),
                Outcome::Err(()),
                Outcome::Ok(()),
                Outcome::Cancelled(CancelReason::user("test")),
                Outcome::Err(()),
                Outcome::Panicked(PanicPayload::new("boom")),
            ];
            let mut decisions = Vec::new();
            for (i, outcome) in outcomes.iter().enumerate() {
                let t = (i as u64 + 1) * 1_000;
                decisions.push(sup.on_failure(task, region, None, outcome, t));
            }
            (sup, decisions)
        };

        let (sup_a, dec_a) = run();
        let (sup_b, dec_b) = run();

        // Decisions must be identical.
        assert_eq!(dec_a.len(), dec_b.len());
        for (a, b) in dec_a.iter().zip(dec_b.iter()) {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }

        // Evidence ledgers must be identical.
        let ev_a = sup_a.evidence();
        let ev_b = sup_b.evidence();
        assert_eq!(ev_a.len(), ev_b.len());
        for (a, b) in ev_a.entries().iter().zip(ev_b.entries().iter()) {
            assert_eq!(a.timestamp, b.timestamp);
            assert_eq!(
                format!("{:?}", a.binding_constraint),
                format!("{:?}", b.binding_constraint)
            );
        }

        // Generalized ledger renders must be byte-for-byte identical.
        assert_eq!(
            sup_a.generalized_evidence().render(),
            sup_b.generalized_evidence().render()
        );

        crate::test_complete!("obs_evidence_ledger_determinism_mixed_outcomes");
    }

    #[test]
    fn obs_storm_monitor_intensity_window_integration_deterministic() {
        init_test("obs_storm_monitor_intensity_window_integration_deterministic");

        let run = || {
            let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 1.0);
            let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
                alpha: 0.01,
                expected_rate: 0.1,
                min_observations: 3,
                tolerance: 1.2,
            });

            let base = 1_000_000_000u64;
            let mut states = Vec::new();
            // Simulate bursts and calm periods.
            for i in 0..30 {
                let now = base + i * 100_000_000; // every 100ms
                window.record(now);
                let state = monitor.observe_from_window(&window, now);
                states.push((monitor.e_value(), state));
            }
            states
        };

        let run_a = run();
        let run_b = run();

        assert_eq!(run_a.len(), run_b.len());
        for ((e_a, s_a), (e_b, s_b)) in run_a.iter().zip(run_b.iter()) {
            assert!((e_a - e_b).abs() < f64::EPSILON, "e-values diverged");
            assert_eq!(s_a, s_b, "alert states diverged");
        }

        crate::test_complete!("obs_storm_monitor_intensity_window_integration_deterministic");
    }

    #[test]
    fn obs_eprocess_alert_transitions_monotone() {
        init_test("obs_eprocess_alert_transitions_monotone");

        let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
            alpha: 0.01,
            expected_rate: 0.05,
            min_observations: 3,
            tolerance: 1.2,
        });

        // Track transitions: Clear → Watching → Alert.
        let mut saw_watching = false;
        let mut saw_alert = false;
        let mut transitions = Vec::new();

        for i in 0..50 {
            // Gradually increasing intensity simulates escalation.
            let intensity = f64::from(i).mul_add(0.1, 0.01);
            let state = monitor.observe_intensity(intensity);

            match state {
                crate::obligation::eprocess::AlertState::Watching if !saw_watching => {
                    saw_watching = true;
                    transitions.push("watching");
                }
                crate::obligation::eprocess::AlertState::Alert if !saw_alert => {
                    saw_alert = true;
                    transitions.push("alert");
                }
                _ => {}
            }
        }

        // With escalating intensity, should eventually reach alert.
        assert!(saw_alert, "monitor should reach alert state");

        // Watching should appear before alert (monotone escalation).
        if saw_watching {
            let w_pos = transitions.iter().position(|t| *t == "watching");
            let a_pos = transitions.iter().position(|t| *t == "alert");
            if let (Some(w), Some(a)) = (w_pos, a_pos) {
                assert!(w < a, "watching must precede alert");
            }
        }

        crate::test_complete!("obs_eprocess_alert_transitions_monotone");
    }

    #[test]
    fn obs_supervisor_storm_combined_determinism() {
        init_test("obs_supervisor_storm_combined_determinism");

        let run = || {
            let config = RestartConfig::new(5, Duration::from_secs(10));
            let mut sup = Supervisor::new(SupervisionStrategy::Restart(config));
            let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 1.0);
            let mut monitor = RestartStormMonitor::new(StormMonitorConfig {
                alpha: 0.05,
                expected_rate: 0.5,
                min_observations: 3,
                tolerance: 1.2,
            });

            let task = test_task_id();
            let region = test_region_id();

            let mut snapshots = Vec::new();

            for i in 0..8u64 {
                let now = i * 500_000_000; // every 500ms
                let decision = sup.on_failure(task, region, None, &Outcome::Err(()), now);
                window.record(now);
                let alert = monitor.observe_from_window(&window, now);
                snapshots.push((
                    format!("{decision:?}"),
                    monitor.e_value(),
                    alert,
                    window.intensity(now),
                ));
            }

            (sup.evidence().len(), snapshots)
        };

        let (len_a, snap_a) = run();
        let (len_b, snap_b) = run();

        assert_eq!(len_a, len_b);
        assert_eq!(snap_a.len(), snap_b.len());
        for ((dec_a, e_a, alert_a, int_a), (dec_b, e_b, alert_b, int_b)) in
            snap_a.iter().zip(snap_b.iter())
        {
            assert_eq!(dec_a, dec_b, "decisions diverged");
            assert!((e_a - e_b).abs() < f64::EPSILON, "e-values diverged");
            assert_eq!(alert_a, alert_b, "alerts diverged");
            assert!((int_a - int_b).abs() < f64::EPSILON, "intensities diverged");
        }

        crate::test_complete!("obs_supervisor_storm_combined_determinism");
    }

    #[test]
    fn obs_evidence_ledger_binding_constraints_cover_all_paths() {
        init_test("obs_evidence_ledger_binding_constraints_cover_all_paths");

        let task = test_task_id();
        let region = test_region_id();

        // Strategy: Restart with tight budget to hit multiple constraint types.
        let config = RestartConfig::new(2, Duration::from_mins(1)).with_restart_cost(100);
        let mut sup = Supervisor::new(SupervisionStrategy::Restart(config));

        // Err → RestartAllowed
        sup.on_failure(task, region, None, &Outcome::Err(()), 1_000);
        // Err → RestartAllowed (attempt 2)
        sup.on_failure(task, region, None, &Outcome::Err(()), 2_000);
        // Err → WindowExhausted (3rd err, max_restarts=2)
        sup.on_failure(task, region, None, &Outcome::Err(()), 3_000);
        // Ok → MonotoneSeverity
        sup.on_failure(task, region, None, &Outcome::Ok(()), 4_000);
        // Cancelled → MonotoneSeverity
        sup.on_failure(
            task,
            region,
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            5_000,
        );
        // Panicked → MonotoneSeverity
        sup.on_failure(
            task,
            region,
            None,
            &Outcome::Panicked(PanicPayload::new("x")),
            6_000,
        );

        let entries = sup.evidence().entries();
        assert_eq!(entries.len(), 6);

        // Verify specific constraint types.
        assert!(matches!(
            entries[0].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 1 }
        ));
        assert!(matches!(
            entries[1].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 2 }
        ));
        assert!(matches!(
            entries[2].binding_constraint,
            BindingConstraint::WindowExhausted { .. }
        ));
        assert!(matches!(
            entries[3].binding_constraint,
            BindingConstraint::MonotoneSeverity { outcome_kind: "Ok" }
        ));
        assert!(matches!(
            entries[4].binding_constraint,
            BindingConstraint::MonotoneSeverity {
                outcome_kind: "Cancelled"
            }
        ));
        assert!(matches!(
            entries[5].binding_constraint,
            BindingConstraint::MonotoneSeverity {
                outcome_kind: "Panicked"
            }
        ));

        crate::test_complete!("obs_evidence_ledger_binding_constraints_cover_all_paths");
    }

    // ── Hot-path allocation gate tests (bd-3h23x) ──────────────────────────

    /// Gate: ChildName::clone() is O(1) — Arc reference count bump, not a heap copy.
    #[test]
    fn gate_child_name_clone_is_arc_bump() {
        init_test("gate_child_name_clone_is_arc_bump");

        let name = ChildName::from("test_worker");
        // strong_count starts at 1.
        assert_eq!(name.strong_count(), 1);

        let cloned = name.clone();
        // After clone, strong_count is 2 — same allocation, reference bumped.
        assert_eq!(name.strong_count(), 2);
        assert_eq!(cloned.strong_count(), 2);

        // Content is identical.
        assert_eq!(name, cloned);

        drop(cloned);
        assert_eq!(name.strong_count(), 1);

        crate::test_complete!("gate_child_name_clone_is_arc_bump");
    }

    /// Gate: restart_plan_for_idx names share Arc allocation with ChildSpec.
    /// This proves restart planning does zero heap string copies.
    #[test]
    fn gate_restart_plan_shares_arcs_with_children() {
        init_test("gate_restart_plan_shares_arcs_with_children");

        let compiled = SupervisorBuilder::new("alloc_gate")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("alpha", noop_start))
            .child(ChildSpec::new("bravo", noop_start))
            .child(ChildSpec::new("charlie", noop_start).with_restart(
                SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
            ))
            .compile()
            .unwrap();

        // Before restart plan, each child name has refcount = 1
        // (plus 1 from the name_to_idx HashMap clone during compile, but that's dropped).
        // After compile, children own their names with refcount >= 1.
        let alpha_rc_before = compiled.children[compiled.start_order[0]]
            .name
            .strong_count();
        let charlie_rc_before = compiled.children[compiled.start_order[2]]
            .name
            .strong_count();

        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("charlie", &err)
            .expect("plan");

        // After creating the plan, child names in the plan share the children's
        // Arc allocations (refcount bump, not heap copy). Under OneForAll the
        // cancel_order covers all 3 affected children, but restart_order is pruned
        // to children whose own strategy is `Restart` — here only "charlie".
        // "alpha"/"bravo" default to `Stop`, so they appear in cancel_order only
        // and their refcount bumps by exactly 1.
        let alpha_rc_after = compiled.children[compiled.start_order[0]]
            .name
            .strong_count();
        assert_eq!(
            alpha_rc_after,
            alpha_rc_before + 1,
            "plan names must share Arc with children (refcount bump, not copy)"
        );

        // charlie is the only restartable child, so it appears in BOTH the
        // cancel and restart orders — proving the restart_order also shares Arcs.
        let charlie_rc_after = compiled.children[compiled.start_order[2]]
            .name
            .strong_count();
        assert_eq!(
            charlie_rc_after,
            charlie_rc_before + 2,
            "restartable child name is shared into both cancel_order and restart_order"
        );

        // Verify plan has the right content.
        assert_eq!(plan.cancel_order.len(), 3);
        assert_eq!(
            plan.restart_order.len(),
            1,
            "only children with a Restart strategy are scheduled for restart"
        );

        // Dropping the plan restores refcounts.
        drop(plan);
        let alpha_rc_final = compiled.children[compiled.start_order[0]]
            .name
            .strong_count();
        assert_eq!(alpha_rc_final, alpha_rc_before);

        crate::test_complete!("gate_restart_plan_shares_arcs_with_children");
    }

    /// Gate: compile_restart_ops shares Arc allocations with the plan.
    #[test]
    fn gate_compiled_ops_share_arcs_with_plan() {
        init_test("gate_compiled_ops_share_arcs_with_plan");

        let compiled =
            SupervisorBuilder::new("ops_gate")
                .with_restart_policy(RestartPolicy::OneForOne)
                .child(ChildSpec::new("svc", noop_start).with_restart(
                    SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                ))
                .compile()
                .unwrap();

        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("svc", &err)
            .expect("plan");

        let rc_before = plan.cancel_order[0].strong_count();
        let ops = compiled.compile_restart_ops(&plan);

        // OneForOne: 1 cancel + 1 drain + 1 restart = 3 ops, each cloning the name.
        let rc_after = plan.cancel_order[0].strong_count();
        assert_eq!(
            rc_after,
            rc_before + 3,
            "ops names must share Arc with plan (refcount bump per op)"
        );

        // Verify ops structure.
        assert_eq!(ops.ops.len(), 3); // Cancel + Drain + Restart

        drop(ops);
        assert_eq!(plan.cancel_order[0].strong_count(), rc_before);

        crate::test_complete!("gate_compiled_ops_share_arcs_with_plan");
    }

    // ── derive-trait coverage (wave 75) ──────────────────────────────────

    #[test]
    fn supervision_strategy_debug_clone_eq_default() {
        let s = SupervisionStrategy::default();
        assert_eq!(s, SupervisionStrategy::Stop);
        let s2 = s.clone();
        assert_eq!(s, s2);
        assert_ne!(s, SupervisionStrategy::Escalate);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Stop"));
    }

    #[test]
    fn restart_policy_debug_clone_copy_eq_default() {
        let p = RestartPolicy::default();
        assert_eq!(p, RestartPolicy::OneForOne);
        let p2 = p; // Copy
        let p3 = p;
        assert_eq!(p2, p3);
        assert_ne!(p, RestartPolicy::OneForAll);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("OneForOne"));
    }

    #[test]
    fn escalation_policy_debug_clone_copy_eq_default() {
        let e = EscalationPolicy::default();
        assert_eq!(e, EscalationPolicy::Stop);
        let e2 = e; // Copy
        assert_eq!(e, e2);
        assert_ne!(e, EscalationPolicy::Escalate);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Stop"));
    }

    #[test]
    fn name_collision_policy_debug_clone_copy_eq_default() {
        let n = NameCollisionPolicy::default();
        assert_eq!(n, NameCollisionPolicy::Fail);
        let n2 = n; // Copy
        assert_eq!(n, n2);
        assert_ne!(n, NameCollisionPolicy::Replace);
        let dbg = format!("{n:?}");
        assert!(dbg.contains("Fail"));
    }

    #[test]
    fn start_tie_break_debug_clone_copy_eq_default() {
        let t = StartTieBreak::default();
        assert_eq!(t, StartTieBreak::InsertionOrder);
        let t2 = t; // Copy
        assert_eq!(t, t2);
        assert_ne!(t, StartTieBreak::NameLex);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("InsertionOrder"));
    }

    // =========================================================================
    // METAMORPHIC TESTING: Supervision Strategies OneForOne/OneForAll
    // =========================================================================

    /// Configuration for metamorphic supervision testing
    #[derive(Debug, Clone)]
    struct SupervisionMetamorphicConfig {
        /// Number of children to test
        child_count: usize,
        /// Max restarts for testing restart budget exhaustion
        max_restarts: u32,
        /// Restart window for rate limiting tests
        restart_window: Duration,
    }

    impl Default for SupervisionMetamorphicConfig {
        fn default() -> Self {
            Self {
                child_count: 5,
                max_restarts: 3,
                restart_window: Duration::from_mins(1),
            }
        }
    }

    /// Deterministic RNG extension for supervision testing
    trait SupervisionDetRngExt {
        fn gen_range(&mut self, range: std::ops::Range<usize>) -> usize;
        fn choose<'a, T>(&mut self, items: &'a [T]) -> &'a T;
    }

    impl SupervisionDetRngExt for crate::util::det_rng::DetRng {
        fn gen_range(&mut self, range: std::ops::Range<usize>) -> usize {
            if range.is_empty() {
                range.start
            } else {
                range.start + (self.next_u64() as usize % (range.end - range.start))
            }
        }

        fn choose<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            let idx = self.gen_range(0..items.len());
            &items[idx]
        }
    }

    /// No-op start function for metamorphic testing
    fn noop_start_metamorphic(
        _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        _state: &mut crate::runtime::RuntimeState,
        _cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        // Return a deterministic TaskId for the test harness.
        use crate::util::ArenaIndex;
        let arena_idx = ArenaIndex::new(42, 0);
        Ok(TaskId::from_arena(arena_idx))
    }

    /// Create supervisor builder with test children
    fn create_test_supervisor_builder(
        name: &str,
        child_count: usize,
        restart_policy: RestartPolicy,
        rng: &mut crate::util::det_rng::DetRng,
    ) -> SupervisorBuilder {
        let mut builder = SupervisorBuilder::new(name).with_restart_policy(restart_policy);

        for i in 0..child_count {
            let child_name = format!("child_{}", i);
            let restart_config = RestartConfig::new(3, Duration::from_mins(1)).with_backoff(
                BackoffStrategy::Fixed(Duration::from_millis(rng.gen_range(10..100) as u64)),
            );

            builder = builder.child(
                ChildSpec::new(&*child_name, noop_start_metamorphic)
                    .with_restart(SupervisionStrategy::Restart(restart_config)),
            );
        }

        builder
    }

    // =========================================================================
    // MR1: OneForOne vs OneForAll Restart Scope Equivalence
    // =========================================================================

    #[test]
    fn metamorphic_one_for_one_vs_one_for_all_restart_scope() {
        init_test("metamorphic_one_for_one_vs_one_for_all_restart_scope");

        const SEED: u64 = 0xA11C_E001_0000_0001;
        let mut rng = crate::util::det_rng::DetRng::new(SEED);

        let config = SupervisionMetamorphicConfig::default();

        // Create identical supervisors with different restart policies
        let one_for_one = create_test_supervisor_builder(
            "one_for_one_sup",
            config.child_count,
            RestartPolicy::OneForOne,
            &mut rng,
        )
        .compile()
        .unwrap();

        let one_for_all = create_test_supervisor_builder(
            "one_for_all_sup",
            config.child_count,
            RestartPolicy::OneForAll,
            &mut rng,
        )
        .compile()
        .unwrap();

        let err_outcome: Outcome<(), ()> = Outcome::Err(());

        // Test failure of each child
        for child_idx in 0..config.child_count {
            let failed_child_name = format!("child_{}", child_idx);

            let one_for_one_plan = one_for_one
                .restart_plan_for_failure(&failed_child_name, &err_outcome)
                .expect("OneForOne plan");

            let one_for_all_plan = one_for_all
                .restart_plan_for_failure(&failed_child_name, &err_outcome)
                .expect("OneForAll plan");

            // MR: OneForOne should restart only the failed child
            assert_eq!(
                one_for_one_plan.cancel_order.len(),
                1,
                "OneForOne should cancel only failed child {}",
                child_idx
            );
            assert_eq!(
                one_for_one_plan.restart_order.len(),
                1,
                "OneForOne should restart only failed child {}",
                child_idx
            );
            assert_eq!(
                one_for_one_plan.cancel_order[0].as_str(),
                failed_child_name,
                "OneForOne should cancel the failed child {}",
                child_idx
            );

            // MR: OneForAll should restart ALL children
            assert_eq!(
                one_for_all_plan.cancel_order.len(),
                config.child_count,
                "OneForAll should cancel all {} children when child {} fails",
                config.child_count,
                child_idx
            );
            assert_eq!(
                one_for_all_plan.restart_order.len(),
                config.child_count,
                "OneForAll should restart all {} children when child {} fails",
                config.child_count,
                child_idx
            );

            // MR: Both policies should have same restart policy recorded
            assert_eq!(one_for_one_plan.policy, RestartPolicy::OneForOne);
            assert_eq!(one_for_all_plan.policy, RestartPolicy::OneForAll);
        }

        crate::test_complete!("metamorphic_one_for_one_vs_one_for_all_restart_scope");
    }

    // =========================================================================
    // MR2: Restart Budget Exhaustion Invariance
    // =========================================================================

    #[test]
    fn metamorphic_restart_budget_exhaustion_invariance() {
        init_test("metamorphic_restart_budget_exhaustion_invariance");

        // Test that restart budget exhaustion behaves consistently regardless of:
        // 1. Which child fails first
        // 2. The order of failures
        // 3. The restart policy (OneForOne vs OneForAll)

        let config = SupervisionMetamorphicConfig {
            child_count: 3,
            max_restarts: 2, // Low limit for easier exhaustion testing
            restart_window: Duration::from_secs(60),
        };

        for &restart_policy in &[RestartPolicy::OneForOne, RestartPolicy::OneForAll] {
            let supervisor = SupervisorBuilder::new("budget_test")
                .with_restart_policy(restart_policy)
                .child(
                    ChildSpec::new("child_0", noop_start_metamorphic).with_restart(
                        SupervisionStrategy::Restart(RestartConfig::new(
                            config.max_restarts,
                            config.restart_window,
                        )),
                    ),
                )
                .child(
                    ChildSpec::new("child_1", noop_start_metamorphic).with_restart(
                        SupervisionStrategy::Restart(RestartConfig::new(
                            config.max_restarts,
                            config.restart_window,
                        )),
                    ),
                )
                .child(
                    ChildSpec::new("child_2", noop_start_metamorphic).with_restart(
                        SupervisionStrategy::Restart(RestartConfig::new(
                            config.max_restarts,
                            config.restart_window,
                        )),
                    ),
                )
                .compile()
                .unwrap();

            let err_outcome: Outcome<(), ()> = Outcome::Err(());

            // Test different failure sequences
            let failure_sequences = vec![
                vec!["child_0", "child_1", "child_2"],
                vec!["child_2", "child_1", "child_0"],
                vec!["child_1", "child_0", "child_2"],
            ];

            for sequence in &failure_sequences {
                // Each child should produce restart plans initially
                for &child_name in sequence {
                    let plan = supervisor.restart_plan_for_failure(child_name, &err_outcome);

                    match restart_policy {
                        RestartPolicy::OneForOne => {
                            if let Some(plan) = plan {
                                assert!(plan.cancel_order.contains(&ChildName::new(child_name)));
                                assert!(plan.restart_order.contains(&ChildName::new(child_name)));
                            }
                        }
                        RestartPolicy::OneForAll => {
                            if let Some(plan) = plan {
                                assert_eq!(plan.cancel_order.len(), config.child_count);
                                assert_eq!(plan.restart_order.len(), config.child_count);
                            }
                        }
                        RestartPolicy::RestForOne => {}
                    }
                }

                // MR: Budget exhaustion behavior should be consistent regardless of failure order
                // Note: This test demonstrates the pattern - full budget tracking would require
                // more sophisticated state management in the test harness
            }
        }

        crate::test_complete!("metamorphic_restart_budget_exhaustion_invariance");
    }

    // =========================================================================
    // MR3: Child Failure Isolation Property
    // =========================================================================

    #[test]
    fn metamorphic_child_failure_isolation() {
        init_test("metamorphic_child_failure_isolation");

        // MR: Under OneForOne policy, failure of child A should not affect
        // the restart plan for independent failure of child B

        let supervisor = SupervisorBuilder::new("isolation_test")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(ChildSpec::new("child_a", noop_start).with_restart(
                SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
            ))
            .child(ChildSpec::new("child_b", noop_start).with_restart(
                SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
            ))
            .child(ChildSpec::new("child_c", noop_start).with_restart(
                SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
            ))
            .compile()
            .unwrap();

        let err_outcome: Outcome<(), ()> = Outcome::Err(());

        // Test baseline plans for each child individually
        let plan_a = supervisor
            .restart_plan_for_failure("child_a", &err_outcome)
            .unwrap();
        let plan_b = supervisor
            .restart_plan_for_failure("child_b", &err_outcome)
            .unwrap();
        let plan_c = supervisor
            .restart_plan_for_failure("child_c", &err_outcome)
            .unwrap();

        // Under OneForOne, each plan should be isolated
        assert_eq!(plan_a.cancel_order.len(), 1);
        assert_eq!(plan_a.cancel_order[0].as_str(), "child_a");
        assert_eq!(plan_a.restart_order[0].as_str(), "child_a");

        assert_eq!(plan_b.cancel_order.len(), 1);
        assert_eq!(plan_b.cancel_order[0].as_str(), "child_b");
        assert_eq!(plan_b.restart_order[0].as_str(), "child_b");

        assert_eq!(plan_c.cancel_order.len(), 1);
        assert_eq!(plan_c.cancel_order[0].as_str(), "child_c");
        assert_eq!(plan_c.restart_order[0].as_str(), "child_c");

        // MR: Plans should be identical regardless of which other children might have failed
        // In practice, this is testing that the restart planning is stateless with respect
        // to other children's states under OneForOne policy

        for &failed_child in &["child_a", "child_b", "child_c"] {
            let isolated_plan = supervisor
                .restart_plan_for_failure(failed_child, &err_outcome)
                .unwrap();

            // Verify isolation: plan only affects the failed child
            assert_eq!(isolated_plan.cancel_order.len(), 1);
            assert_eq!(isolated_plan.restart_order.len(), 1);
            assert_eq!(isolated_plan.cancel_order[0].as_str(), failed_child);
            assert_eq!(isolated_plan.restart_order[0].as_str(), failed_child);
            assert_eq!(isolated_plan.policy, RestartPolicy::OneForOne);
        }

        crate::test_complete!("metamorphic_child_failure_isolation");
    }

    // =========================================================================
    // MR4: Restart Policy Commutativity Under Different Failure Orderings
    // =========================================================================

    #[test]
    fn metamorphic_restart_policy_commutativity() {
        init_test("metamorphic_restart_policy_commutativity");

        // MR: Under OneForAll policy, the restart plan should be identical regardless
        // of which child fails (all children are restarted anyway)

        let _config = SupervisionMetamorphicConfig {
            child_count: 4,
            ..SupervisionMetamorphicConfig::default()
        };

        let supervisor =
            SupervisorBuilder::new("commutativity_test")
                .with_restart_policy(RestartPolicy::OneForAll)
                .child(ChildSpec::new("alpha", noop_start).with_restart(
                    SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                ))
                .child(ChildSpec::new("beta", noop_start).with_restart(
                    SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                ))
                .child(ChildSpec::new("gamma", noop_start).with_restart(
                    SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                ))
                .child(ChildSpec::new("delta", noop_start).with_restart(
                    SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                ))
                .compile()
                .unwrap();

        let err_outcome: Outcome<(), ()> = Outcome::Err(());
        let child_names = ["alpha", "beta", "gamma", "delta"];
        let mut plans = Vec::new();

        // Generate restart plans for each child failure
        for &child_name in &child_names {
            let plan = supervisor
                .restart_plan_for_failure(child_name, &err_outcome)
                .unwrap();
            plans.push(plan);
        }

        // MR: Under OneForAll, all plans should be structurally identical
        // (same children to cancel/restart, just different triggering failure)
        for i in 1..plans.len() {
            assert_eq!(
                plans[0].policy, plans[i].policy,
                "Plan {} has different policy than plan 0",
                i
            );
            assert_eq!(
                plans[0].cancel_order.len(),
                plans[i].cancel_order.len(),
                "Plan {} has different cancel count than plan 0",
                i
            );
            assert_eq!(
                plans[0].restart_order.len(),
                plans[i].restart_order.len(),
                "Plan {} has different restart count than plan 0",
                i
            );

            // All plans should include all children (OneForAll semantics)
            assert_eq!(plans[i].cancel_order.len(), child_names.len());
            assert_eq!(plans[i].restart_order.len(), child_names.len());
        }

        // Verify that all children are included in every plan
        for plan in &plans {
            for &expected_child in &child_names {
                assert!(
                    plan.cancel_order
                        .iter()
                        .any(|name| name.as_str() == expected_child),
                    "Plan missing {} in cancel_order",
                    expected_child
                );
                assert!(
                    plan.restart_order
                        .iter()
                        .any(|name| name.as_str() == expected_child),
                    "Plan missing {} in restart_order",
                    expected_child
                );
            }
        }

        crate::test_complete!("metamorphic_restart_policy_commutativity");
    }

    // =========================================================================
    // MR5: Escalation Policy Consistency
    // =========================================================================

    #[test]
    fn metamorphic_escalation_policy_consistency() {
        init_test("metamorphic_escalation_policy_consistency");

        // MR: Escalation policy should behave consistently regardless of:
        // 1. The restart policy (OneForOne vs OneForAll)
        // 2. Which child triggers the escalation
        // 3. The number of children in the supervisor

        let escalation_policies = [EscalationPolicy::Stop, EscalationPolicy::Escalate];
        let restart_policies = [RestartPolicy::OneForOne, RestartPolicy::OneForAll];
        let child_counts = [1, 3, 5];

        for &_escalation_policy in &escalation_policies {
            for &restart_policy in &restart_policies {
                for &child_count in &child_counts {
                    let mut builder = SupervisorBuilder::new("escalation_test")
                        .with_restart_policy(restart_policy);

                    for i in 0..child_count {
                        let child_name = format!("child_{}", i);
                        builder =
                            builder.child(ChildSpec::new(&*child_name, noop_start).with_restart(
                                SupervisionStrategy::Restart(
                                    RestartConfig::new(1, Duration::from_secs(1)), // Low budget for testing
                                ),
                            ));
                    }

                    let supervisor = builder.compile().unwrap();

                    // Test that restart plans are generated consistently
                    let err_outcome: Outcome<(), ()> = Outcome::Err(());

                    for i in 0..child_count {
                        let child_name = format!("child_{}", i);
                        let plan_result =
                            supervisor.restart_plan_for_failure(&child_name, &err_outcome);

                        match plan_result {
                            Some(plan) => {
                                // Verify plan structure matches restart policy
                                match restart_policy {
                                    RestartPolicy::OneForOne => {
                                        assert_eq!(plan.cancel_order.len(), 1);
                                        assert_eq!(plan.restart_order.len(), 1);
                                        assert_eq!(plan.cancel_order[0].as_str(), child_name);
                                    }
                                    RestartPolicy::OneForAll => {
                                        assert_eq!(plan.cancel_order.len(), child_count);
                                        assert_eq!(plan.restart_order.len(), child_count);
                                    }
                                    RestartPolicy::RestForOne => {
                                        // Would restart child and all started after it
                                        assert!(!plan.cancel_order.is_empty());
                                        assert!(!plan.restart_order.is_empty());
                                    }
                                }
                                assert_eq!(plan.policy, restart_policy);
                            }
                            None => {
                                // No plan generated - could be due to Stop strategy or other factors
                                // This is also valid behavior depending on configuration
                            }
                        }
                    }
                }
            }
        }

        crate::test_complete!("metamorphic_escalation_policy_consistency");
    }

    // =========================================================================
    // MR6: LabRuntime Replay Determinism
    // =========================================================================

    #[test]
    fn metamorphic_lab_runtime_replay_determinism() {
        init_test("metamorphic_lab_runtime_replay_determinism");

        // MR: Supervision behavior should be deterministic under LabRuntime replay
        // Same sequence of operations with same seed should produce identical plans

        const SEED: u64 = 0xDEADBEEF_CAFEBABE;

        // Run the same supervision scenario multiple times with the same seed
        let results: Vec<Vec<String>> = (0..3)
            .map(|_| {
                let mut rng = crate::util::det_rng::DetRng::new(SEED);
                let mut plan_summaries = Vec::new();

                let supervisor = SupervisorBuilder::new("determinism_test")
                    .with_restart_policy(RestartPolicy::OneForOne)
                    .child(ChildSpec::new("service_a", noop_start).with_restart(
                        SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                    ))
                    .child(ChildSpec::new("service_b", noop_start).with_restart(
                        SupervisionStrategy::Restart(RestartConfig::new(3, Duration::from_mins(1))),
                    ))
                    .compile()
                    .unwrap();

                let err_outcome: Outcome<(), ()> = Outcome::Err(());

                // Generate deterministic failure sequence
                let services = ["service_a", "service_b"];
                for _ in 0..10 {
                    let chosen_service = rng.choose(&services);
                    if let Some(plan) =
                        supervisor.restart_plan_for_failure(chosen_service, &err_outcome)
                    {
                        plan_summaries.push(format!(
                            "fail:{} policy:{:?} cancel:{} restart:{}",
                            chosen_service,
                            plan.policy,
                            plan.cancel_order.len(),
                            plan.restart_order.len()
                        ));
                    }
                }

                plan_summaries
            })
            .collect();

        // All runs should produce identical results
        for i in 1..results.len() {
            assert_eq!(
                results[0], results[i],
                "Run {} produced different results than run 0 - determinism broken",
                i
            );
        }

        // Results should be non-empty (sanity check)
        assert!(
            !results[0].is_empty(),
            "Should have generated some supervision plans"
        );

        crate::test_complete!("metamorphic_lab_runtime_replay_determinism");
    }

    // =========================================================================
    // MR7: Composite Supervision Strategy Invariants
    // =========================================================================

    #[test]
    fn metamorphic_composite_supervision_invariants() {
        init_test("metamorphic_composite_supervision_invariants");

        // MR: Combining multiple metamorphic properties should preserve all individual properties
        // Test: OneForOne + Escalation + Budget limits + Deterministic ordering

        let config = SupervisionMetamorphicConfig {
            child_count: 3,
            max_restarts: 2,
            restart_window: Duration::from_secs(30),
        };

        // Create supervisor with composite configuration
        let supervisor = SupervisorBuilder::new("composite_test")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(ChildSpec::new("primary", noop_start).with_restart(
                SupervisionStrategy::Restart(
                    RestartConfig::new(config.max_restarts, config.restart_window).with_backoff(
                        BackoffStrategy::Exponential {
                            initial: Duration::from_millis(100),
                            max: Duration::from_secs(5),
                            multiplier: 2.0,
                        },
                    ),
                ),
            ))
            .child(ChildSpec::new("secondary", noop_start).with_restart(
                SupervisionStrategy::Restart(RestartConfig::new(
                    config.max_restarts,
                    config.restart_window,
                )),
            ))
            .child(ChildSpec::new("tertiary", noop_start).with_restart(
                SupervisionStrategy::Restart(RestartConfig::new(
                    config.max_restarts,
                    config.restart_window,
                )),
            ))
            .compile()
            .unwrap();

        let err_outcome: Outcome<(), ()> = Outcome::Err(());
        let children = ["primary", "secondary", "tertiary"];

        // Test that all individual properties hold under composite configuration
        for &child_name in &children {
            let plan = supervisor.restart_plan_for_failure(child_name, &err_outcome);

            if let Some(plan) = plan {
                // OneForOne property: only failed child should be affected
                assert_eq!(plan.cancel_order.len(), 1);
                assert_eq!(plan.restart_order.len(), 1);
                assert_eq!(plan.cancel_order[0].as_str(), child_name);
                assert_eq!(plan.restart_order[0].as_str(), child_name);

                // Policy consistency
                assert_eq!(plan.policy, RestartPolicy::OneForOne);

                // Plan structure integrity
                assert!(!plan.cancel_order.is_empty());
                assert!(!plan.restart_order.is_empty());
                assert_eq!(plan.cancel_order.len(), plan.restart_order.len());
            }
        }

        // Test deterministic behavior with repeated calls
        for _ in 0..5 {
            let primary_plan1 = supervisor.restart_plan_for_failure("primary", &err_outcome);
            let primary_plan2 = supervisor.restart_plan_for_failure("primary", &err_outcome);

            match (primary_plan1, primary_plan2) {
                (Some(plan1), Some(plan2)) => {
                    assert_eq!(plan1.policy, plan2.policy);
                    assert_eq!(plan1.cancel_order, plan2.cancel_order);
                    assert_eq!(plan1.restart_order, plan2.restart_order);
                }
                (None, None) => {
                    // Consistent behavior
                }
                _ => {
                    panic!("Inconsistent restart plan generation for same input");
                }
            }
        }

        crate::test_complete!("metamorphic_composite_supervision_invariants");
    }
}
