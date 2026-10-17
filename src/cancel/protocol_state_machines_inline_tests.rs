    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;

    fn region_context(region_id: RegionId) -> RegionContext {
        RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        }
    }

    fn task_context(task_id: TaskId, region_id: RegionId) -> TaskContext {
        TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        }
    }

    #[test]
    fn task_transition_without_logging_preserves_validation_accounting() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let task_id = TaskId::new_for_test(77, 0);
        let region_id = RegionId::new_for_test(78, 0);
        let result = validator.validate_task_transition_without_logging(
            task_id,
            TaskEvent::RequestCancel,
            &task_context(task_id, region_id),
        );

        assert!(matches!(result, TransitionResult::Invalid { .. }));
        assert_eq!(validator.violation_count(), 1);
    }

    #[test]
    fn lifecycle_transitions_without_logging_preserve_validation_accounting() {
        let mut direct = CancelProtocolValidator::new(ValidationLevel::Full);
        let mut deferred = CancelProtocolValidator::new(ValidationLevel::Full);
        let region = RegionId::new_for_test(81, 0);
        direct.register_region(region);
        deferred.register_region(region);
        for event in [
            RegionEvent::Activate,
            RegionEvent::TaskSpawned,
            RegionEvent::RequestClose,
            RegionEvent::TaskCompleted,
            RegionEvent::RequestClose,
        ] {
            assert_eq!(
                direct.validate_region_transition(region, event.clone(), &region_context(region)),
                deferred.validate_region_transition_without_logging(
                    region,
                    event,
                    &region_context(region)
                ),
            );
            assert_eq!(direct.region_state(region), deferred.region_state(region));
            assert_eq!(direct.violation_count(), deferred.violation_count());
        }
        assert_eq!(deferred.region_state(region), Some(&RegionState::Finalized));
        assert_eq!(
            deferred.violation_count(),
            1,
            "closing with a live task is still refused"
        );
        let obligation = ObligationId::new_for_test(82, 0);
        let context = ObligationContext {
            obligation_id: obligation,
            region_id: region,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        direct.register_obligation(obligation);
        deferred.register_obligation(obligation);
        for event in [
            ObligationEvent::Reserve { token: 8 },
            ObligationEvent::Commit,
            ObligationEvent::Abort {
                reason: "already committed".into(),
            },
        ] {
            assert_eq!(
                direct.validate_obligation_transition(obligation, event.clone(), &context),
                deferred
                    .validate_obligation_transition_without_logging(obligation, event, &context),
            );
            assert_eq!(direct.violation_count(), deferred.violation_count());
            assert_eq!(
                direct.obligation_machines[&obligation].current_state(),
                deferred.obligation_machines[&obligation].current_state()
            );
        }
        assert_eq!(
            deferred.violation_count(),
            2,
            "a committed obligation cannot be aborted"
        );
    }

    #[test]
    fn validator_remove_methods_drop_state_machines_no_leak() {
        // register_* runs on every spawn/region-open/obligation-reserve, and
        // TaskIds carry generations so recycled slots mint fresh keys. Without a
        // matching remove_*, task_machines/region_machines/obligation_machines
        // grow without bound — the leak fixed in
        // br-asupersync-cancelvalidator-leak-mdvuf9. Distinct generations here
        // model slot reuse minting fresh keys rather than overwriting.
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Basic);

        for i in 0..100u32 {
            let region_id = RegionId::new_for_test(1, i);
            validator.register_region(region_id);
            validator.register_task(TaskId::new_for_test(1, i), region_id);
            validator.register_obligation(ObligationId::new_for_test(1, i));
        }
        let (regions, tasks, obligations, ..) = validator.stats();
        assert_eq!(
            (regions, tasks, obligations),
            (100, 100, 100),
            "all registered entities are tracked"
        );

        for i in 0..100u32 {
            validator.remove_task(TaskId::new_for_test(1, i));
            validator.remove_region(RegionId::new_for_test(1, i));
            validator.remove_obligation(ObligationId::new_for_test(1, i));
        }
        let (regions, tasks, obligations, ..) = validator.stats();
        assert_eq!(
            (regions, tasks, obligations),
            (0, 0, 0),
            "remove_* must drop the state machines so the maps do not leak"
        );
    }

    /// The untracked validator (release runtime) keeps no state machines and
    /// reports every transition valid, including transitions the tracked
    /// validator would reject. The tracked validator is unchanged.
    #[test]
    fn untracked_validator_registers_nothing_and_reports_valid() {
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(1, 0);
        let context = task_context(task_id, region_id);

        let mut untracked = CancelProtocolValidator::untracked();
        assert!(!untracked.is_tracking());
        untracked.register_region(region_id);
        untracked.register_task(task_id, region_id);
        untracked.register_obligation(ObligationId::new_for_test(1, 0));
        let (regions, tasks, obligations, ..) = untracked.stats();
        assert_eq!((regions, tasks, obligations), (0, 0, 0));
        // Complete before Start is a protocol violation when tracked.
        assert_eq!(
            untracked.validate_task_transition_without_logging(
                task_id,
                TaskEvent::Complete,
                &context
            ),
            TransitionResult::Valid
        );
        assert_eq!(untracked.violation_count(), 0);
        untracked.remove_task(task_id);

        let mut tracked = CancelProtocolValidator::new(ValidationLevel::Basic);
        assert!(tracked.is_tracking());
        tracked.register_task(task_id, region_id);
        assert!(matches!(
            tracked.validate_task_transition_without_logging(
                task_id,
                TaskEvent::Complete,
                &context
            ),
            TransitionResult::Invalid { .. }
        ));
        assert_eq!(tracked.violation_count(), 1);
    }

    fn channel_context(channel_id: u64) -> ChannelContext {
        ChannelContext {
            channel_id,
            validation_level: ValidationLevel::Full,
        }
    }

    fn io_context(operation_id: u64, operation_type: &str) -> IoContext {
        IoContext {
            operation_id,
            operation_type: operation_type.to_string(),
            validation_level: ValidationLevel::Full,
        }
    }

    fn timer_context(timer_id: u64, current_time: Time) -> TimerContext {
        TimerContext {
            timer_id,
            current_time,
            validation_level: ValidationLevel::Full,
        }
    }

    fn prime_region_for_cancel(
        machine: &mut RegionStateMachine,
        context: &RegionContext,
        active_tasks: u8,
        pending_finalizers: u8,
    ) {
        machine.transition(RegionEvent::Activate, context).unwrap();
        for _ in 0..active_tasks {
            machine
                .transition(RegionEvent::TaskSpawned, context)
                .unwrap();
        }
        for _ in 0..pending_finalizers {
            machine
                .transition(RegionEvent::FinalizerRegistered, context)
                .unwrap();
        }
    }

    fn drive_region_cancel_projection(machine: &mut RegionStateMachine, context: &RegionContext) {
        loop {
            match machine.current_state().clone() {
                RegionState::Cancelling {
                    draining_tasks: 0,
                    pending_finalizers: 0,
                    ..
                }
                | RegionState::Finalized => break,
                RegionState::Cancelling {
                    draining_tasks: 0, ..
                } => machine
                    .transition(RegionEvent::FinalizerStarted, context)
                    .unwrap(),
                RegionState::Cancelling { .. } => machine
                    .transition(RegionEvent::TaskDrained, context)
                    .unwrap(),
                RegionState::Finalizing { .. } => machine
                    .transition(RegionEvent::FinalizerCompleted, context)
                    .unwrap(),
                state => {
                    panic!("unexpected region state while driving cancel projection: {state:?}") // ubs:ignore - test helper
                }
            }
        }
    }

    fn prime_channel_for_close(
        machine: &mut ChannelStateMachine,
        context: &ChannelContext,
        pending_ops: u8,
    ) {
        for _ in 0..pending_ops {
            machine
                .transition(ChannelEvent::OperationStarted, context)
                .unwrap();
        }
    }

    fn drive_channel_close_projection(machine: &mut ChannelStateMachine, context: &ChannelContext) {
        while let ChannelState::Closing { .. } = machine.current_state() {
            machine
                .transition(ChannelEvent::OperationCompleted, context)
                .unwrap();
        }
    }

    proptest! {
        #[test]
        fn metamorphic_cancel_then_cancel_is_identity_on_cancel_projection(
            active_tasks in 0u8..4,
            pending_finalizers in 0u8..4,
            task_started in any::<bool>(),
            channel_pending in 0u8..4,
        ) {
            prop_assume!(active_tasks > 0 || pending_finalizers > 0);

            let region_id = RegionId::new_for_test(101, 0);
            let region_context = region_context(region_id);
            let mut region_once = RegionStateMachine::new(region_id, ValidationLevel::Full);
            let mut region_twice = RegionStateMachine::new(region_id, ValidationLevel::Full);
            prime_region_for_cancel(&mut region_once, &region_context, active_tasks, pending_finalizers);
            prime_region_for_cancel(&mut region_twice, &region_context, active_tasks, pending_finalizers);
            let region_once_cancel = region_once.transition(
                RegionEvent::Cancel {
                    reason: "first".to_string(),
                },
                &region_context,
            );
            prop_assert!(region_once_cancel.is_valid());
            let region_twice_first_cancel = region_twice.transition(
                RegionEvent::Cancel {
                    reason: "first".to_string(),
                },
                &region_context,
            );
            prop_assert!(region_twice_first_cancel.is_valid());
            let region_after_first = region_twice.current_state().clone();
            let region_twice_second_cancel = region_twice.transition(
                RegionEvent::Cancel {
                    reason: "second".to_string(),
                },
                &region_context,
            );
            prop_assert!(region_twice_second_cancel.is_valid());
            prop_assert_eq!(
                region_once.current_state().clone(),
                region_after_first.clone()
            );
            prop_assert_eq!(region_twice.current_state().clone(), region_after_first);
            drive_region_cancel_projection(&mut region_once, &region_context);
            drive_region_cancel_projection(&mut region_twice, &region_context);
            prop_assert_eq!(region_once.current_state().clone(), region_twice.current_state().clone());

            let task_id = TaskId::new_for_test(202, 0);
            let task_context = task_context(task_id, region_id);
            let mut task_once = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
            let mut task_twice = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
            if task_started {
                let task_once_start = task_once.transition(TaskEvent::Start, &task_context);
                prop_assert!(task_once_start.is_valid());
                let task_twice_start = task_twice.transition(TaskEvent::Start, &task_context);
                prop_assert!(task_twice_start.is_valid());
            }
            let task_once_cancel = task_once.transition(TaskEvent::RequestCancel, &task_context);
            prop_assert!(task_once_cancel.is_valid());
            let task_twice_cancel = task_twice.transition(TaskEvent::RequestCancel, &task_context);
            prop_assert!(task_twice_cancel.is_valid());
            let task_after_first = task_twice.current_state().clone();
            let task_twice_second_cancel =
                task_twice.transition(TaskEvent::RequestCancel, &task_context);
            prop_assert!(task_twice_second_cancel.is_valid());
            prop_assert_eq!(
                task_once.current_state().clone(),
                task_after_first.clone()
            );
            prop_assert_eq!(task_twice.current_state().clone(), task_after_first);
            if matches!(task_once.current_state(), TaskState::CancelRequested) {
                let task_once_drain = task_once.transition(TaskEvent::DrainComplete, &task_context);
                prop_assert!(task_once_drain.is_valid());
                let task_twice_drain =
                    task_twice.transition(TaskEvent::DrainComplete, &task_context);
                prop_assert!(task_twice_drain.is_valid());
            }
            prop_assert_eq!(task_once.current_state().clone(), task_twice.current_state().clone());

            let channel_id = 303;
            let channel_context = channel_context(channel_id);
            let mut channel_once = ChannelStateMachine::new(channel_id, ValidationLevel::Full);
            let mut channel_twice = ChannelStateMachine::new(channel_id, ValidationLevel::Full);
            prime_channel_for_close(&mut channel_once, &channel_context, channel_pending);
            prime_channel_for_close(&mut channel_twice, &channel_context, channel_pending);
            let channel_once_close =
                channel_once.transition(ChannelEvent::InitiateClose, &channel_context);
            prop_assert!(channel_once_close.is_valid());
            let channel_twice_close =
                channel_twice.transition(ChannelEvent::InitiateClose, &channel_context);
            prop_assert!(channel_twice_close.is_valid());
            let channel_after_first = channel_twice.current_state().clone();
            let channel_twice_second_close =
                channel_twice.transition(ChannelEvent::InitiateClose, &channel_context);
            prop_assert!(channel_twice_second_close.is_valid());
            prop_assert_eq!(
                channel_once.current_state().clone(),
                channel_after_first.clone()
            );
            prop_assert_eq!(channel_twice.current_state().clone(), channel_after_first);
            drive_channel_close_projection(&mut channel_once, &channel_context);
            drive_channel_close_projection(&mut channel_twice, &channel_context);
            prop_assert_eq!(channel_once.current_state().clone(), channel_twice.current_state().clone());

            let io_context = io_context(404, "read");
            let mut io_once = IoStateMachine::new(404, 7, ValidationLevel::Full);
            let mut io_twice = IoStateMachine::new(404, 7, ValidationLevel::Full);
            let io_once_cancel = io_once.transition(IoEvent::Cancel, &io_context);
            prop_assert!(io_once_cancel.is_valid());
            let io_twice_cancel = io_twice.transition(IoEvent::Cancel, &io_context);
            prop_assert!(io_twice_cancel.is_valid());
            let io_after_first = io_twice.current_state().clone();
            let io_twice_second_cancel = io_twice.transition(IoEvent::Cancel, &io_context);
            prop_assert!(io_twice_second_cancel.is_valid());
            prop_assert_eq!(io_once.current_state().clone(), io_after_first.clone());
            prop_assert_eq!(io_twice.current_state().clone(), io_after_first);
            let io_once_cleanup = io_once.transition(IoEvent::CleanupComplete, &io_context);
            prop_assert!(io_once_cleanup.is_valid());
            let io_twice_cleanup = io_twice.transition(IoEvent::CleanupComplete, &io_context);
            prop_assert!(io_twice_cleanup.is_valid());
            prop_assert_eq!(io_once.current_state().clone(), io_twice.current_state().clone());

            let timer_context = timer_context(505, Time::ZERO);
            let mut timer_once =
                TimerStateMachine::new(505, Time::from_nanos(5), ValidationLevel::Full);
            let mut timer_twice =
                TimerStateMachine::new(505, Time::from_nanos(5), ValidationLevel::Full);
            let timer_once_cancel = timer_once.transition(TimerEvent::Cancel, &timer_context);
            prop_assert!(timer_once_cancel.is_valid());
            let timer_twice_cancel = timer_twice.transition(TimerEvent::Cancel, &timer_context);
            prop_assert!(timer_twice_cancel.is_valid());
            let timer_after_first = timer_twice.current_state().clone();
            let timer_twice_second_cancel =
                timer_twice.transition(TimerEvent::Cancel, &timer_context);
            prop_assert!(timer_twice_second_cancel.is_valid());
            prop_assert_eq!(
                timer_once.current_state().clone(),
                timer_after_first.clone()
            );
            prop_assert_eq!(timer_twice.current_state().clone(), timer_after_first);
        }
    }

    #[test]
    fn validator_repeated_cancel_requests_do_not_increment_violation_count() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let region_id = RegionId::new_for_test(901, 0);
        let task_id = TaskId::new_for_test(902, 0);
        let channel_id = 903;
        let operation_id = 904;
        let timer_id = 905;

        validator.register_region(region_id);
        validator.register_task(task_id, region_id);
        validator.register_channel(channel_id);
        validator.register_io_operation(operation_id, 7);
        validator.register_timer(timer_id, Time::from_nanos(5));

        let region_context = region_context(region_id);
        let task_context = task_context(task_id, region_id);
        let channel_context = channel_context(channel_id);
        let io_context = io_context(operation_id, "read");
        let timer_context = timer_context(timer_id, Time::ZERO);

        validator
            .validate_region_transition(region_id, RegionEvent::Activate, &region_context)
            .unwrap();
        validator
            .validate_region_transition(region_id, RegionEvent::TaskSpawned, &region_context)
            .unwrap();
        validator
            .validate_region_transition(
                region_id,
                RegionEvent::FinalizerRegistered,
                &region_context,
            )
            .unwrap();
        validator
            .validate_task_transition(task_id, TaskEvent::Start, &task_context)
            .unwrap();
        validator
            .validate_channel_transition(
                channel_id,
                ChannelEvent::OperationStarted,
                &channel_context,
            )
            .unwrap();

        validator
            .validate_region_transition(
                region_id,
                RegionEvent::Cancel {
                    reason: "first".to_string(),
                },
                &region_context,
            )
            .unwrap();
        validator
            .validate_task_transition(task_id, TaskEvent::RequestCancel, &task_context)
            .unwrap();
        validator
            .validate_channel_transition(channel_id, ChannelEvent::InitiateClose, &channel_context)
            .unwrap();
        validator
            .validate_io_transition(operation_id, IoEvent::Cancel, &io_context)
            .unwrap();
        validator
            .validate_timer_transition(timer_id, TimerEvent::Cancel, &timer_context)
            .unwrap();

        let baseline_violations = validator.violation_count();
        let baseline_region = validator
            .region_machines
            .get(&region_id)
            .expect("region machine")
            .current_state()
            .clone();
        let baseline_task = validator
            .task_machines
            .get(&task_id)
            .expect("task machine")
            .current_state()
            .clone();
        let baseline_channel = validator
            .channel_machines
            .get(&channel_id)
            .expect("channel machine")
            .current_state()
            .clone();
        let baseline_io = validator
            .io_machines
            .get(&operation_id)
            .expect("io machine")
            .current_state()
            .clone();
        let baseline_timer = validator
            .timer_machines
            .get(&timer_id)
            .expect("timer machine")
            .current_state()
            .clone();

        validator
            .validate_region_transition(
                region_id,
                RegionEvent::Cancel {
                    reason: "second".to_string(),
                },
                &region_context,
            )
            .unwrap();
        validator
            .validate_task_transition(task_id, TaskEvent::RequestCancel, &task_context)
            .unwrap();
        validator
            .validate_channel_transition(channel_id, ChannelEvent::InitiateClose, &channel_context)
            .unwrap();
        validator
            .validate_io_transition(operation_id, IoEvent::Cancel, &io_context)
            .unwrap();
        validator
            .validate_timer_transition(timer_id, TimerEvent::Cancel, &timer_context)
            .unwrap();

        assert_eq!(validator.violation_count(), baseline_violations);
        assert_eq!(
            validator
                .region_machines
                .get(&region_id)
                .expect("region machine")
                .current_state(),
            &baseline_region
        );
        assert_eq!(
            validator
                .task_machines
                .get(&task_id)
                .expect("task machine")
                .current_state(),
            &baseline_task
        );
        assert_eq!(
            validator
                .channel_machines
                .get(&channel_id)
                .expect("channel machine")
                .current_state(),
            &baseline_channel
        );
        assert_eq!(
            validator
                .io_machines
                .get(&operation_id)
                .expect("io machine")
                .current_state(),
            &baseline_io
        );
        assert_eq!(
            validator
                .timer_machines
                .get(&timer_id)
                .expect("timer machine")
                .current_state(),
            &baseline_timer
        );
    }

    #[test]
    fn test_region_is_quiesced() {
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Created region should be quiesced
        assert!(machine.is_quiesced());

        // Activate to empty Active state
        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        // Empty Active region should be quiesced
        assert!(machine.is_quiesced());

        // Spawn a task, no longer quiesced
        assert_eq!(
            machine.transition(RegionEvent::TaskSpawned, &context),
            TransitionResult::Valid
        );
        assert!(!machine.is_quiesced());

        // Complete the task, quiesced again
        assert_eq!(
            machine.transition(RegionEvent::TaskCompleted, &context),
            TransitionResult::Valid
        );
        assert!(machine.is_quiesced());
    }

    #[test]
    fn test_region_lifecycle() {
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Created -> Active
        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Active { .. }
        ));

        // Spawn and complete a task
        assert_eq!(
            machine.transition(RegionEvent::TaskSpawned, &context),
            TransitionResult::Valid
        );
        assert_eq!(machine.active_task_count(), 1);
        assert!(matches!(
            machine.transition(RegionEvent::RequestClose, &context),
            TransitionResult::Invalid { .. }
        ));
        assert_eq!(machine.active_task_count(), 1);

        assert_eq!(
            machine.transition(RegionEvent::TaskCompleted, &context),
            TransitionResult::Valid
        );
        assert_eq!(machine.active_task_count(), 0);

        // Close empty region
        assert_eq!(
            machine.transition(RegionEvent::RequestClose, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
        assert!(machine.is_terminal());
    }

    #[test]
    fn region_cancel_with_only_pending_finalizers_enters_finalizing() {
        let region_id = RegionId::new_for_test(12, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert_eq!(
            machine.transition(RegionEvent::FinalizerRegistered, &context),
            TransitionResult::Valid
        );
        assert_eq!(
            machine.transition(
                RegionEvent::Cancel {
                    reason: "test".to_owned(),
                },
                &context,
            ),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Finalizing {
                running_finalizers: 1
            }
        ));
        assert_eq!(
            machine.transition(RegionEvent::FinalizerCompleted, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
    }

    #[test]
    fn region_close_with_only_pending_finalizers_enters_finalizing() {
        let region_id = RegionId::new_for_test(13, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert_eq!(
            machine.transition(RegionEvent::FinalizerRegistered, &context),
            TransitionResult::Valid
        );
        assert_eq!(
            machine.transition(RegionEvent::RequestClose, &context),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Finalizing {
                running_finalizers: 1
            }
        ));
        assert_eq!(
            machine.transition(RegionEvent::FinalizerCompleted, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
    }

    #[test]
    fn test_region_activate_allows_empty_active_state() {
        let region_id = RegionId::new_for_test(10, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Active {
                active_tasks: 0,
                pending_finalizers: 0
            }
        ));
        assert_eq!(
            machine.transition(RegionEvent::RequestClose, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
    }

    #[test]
    fn test_region_empty_active_state_is_quiesced() {
        let region_id = RegionId::new_for_test(11, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert!(
            machine.is_quiesced(),
            "an active region with no tasks or finalizers should report quiescence"
        );
    }

    #[test]
    fn test_task_lifecycle() {
        let task_id = TaskId::new_for_test(1, 0);
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Spawned -> Running
        assert!(machine.is_cancellable());
        assert_eq!(
            machine.transition(TaskEvent::Start, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), TaskState::Running));

        // Running -> Completed
        assert_eq!(
            machine.transition(TaskEvent::Complete, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), TaskState::Completed));
        assert!(machine.is_complete());
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_task_cancellation() {
        let task_id = TaskId::new_for_test(2, 0);
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Spawned -> Running -> CancelRequested -> Cancelled
        machine.transition(TaskEvent::Start, &context).unwrap();
        machine
            .transition(TaskEvent::RequestCancel, &context)
            .unwrap();
        assert!(matches!(
            machine.current_state(),
            TaskState::CancelRequested
        ));

        machine
            .transition(TaskEvent::DrainComplete, &context)
            .unwrap();
        assert!(matches!(machine.current_state(), TaskState::Cancelled));
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_invalid_transitions() {
        let task_id = TaskId::new_for_test(3, 0);
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Try to complete without starting
        let result = machine.transition(TaskEvent::Complete, &context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));

        // Valid transition to running
        machine.transition(TaskEvent::Start, &context).unwrap();

        // Complete the task
        machine.transition(TaskEvent::Complete, &context).unwrap();

        // Try to transition from terminal state
        let result = machine.transition(TaskEvent::RequestCancel, &context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_obligation_lifecycle() {
        let obligation_id = ObligationId::new_for_test(1, 0);
        let mut machine = ObligationStateMachine::new(obligation_id, ValidationLevel::Full);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Created -> Reserved -> Committed
        assert_eq!(
            machine.transition(ObligationEvent::Reserve { token: 12345 }, &context),
            TransitionResult::Valid
        );
        assert!(machine.is_reserved());

        assert_eq!(
            machine.transition(ObligationEvent::Commit, &context),
            TransitionResult::Valid
        );
        assert!(machine.is_fulfilled());
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_obligation_zero_token_is_invariant_violation() {
        let obligation_id = ObligationId::new_for_test(7, 0);
        let mut machine = ObligationStateMachine::new(obligation_id, ValidationLevel::Full);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let result = machine.transition(ObligationEvent::Reserve { token: 0 }, &context);
        assert!(matches!(
            result,
            TransitionResult::InvariantViolation { .. }
        ));
        assert!(matches!(
            machine.current_state(),
            ObligationState::Error { .. }
        ));
    }

    #[test]
    fn test_obligation_state_transition_atomicity() {
        // Test that verifies state transitions are atomic under concurrent access
        // This addresses the race condition fix in br-asupersync-g4frfy
        use std::sync::{Arc, Mutex};
        use std::thread;

        let obligation_id = ObligationId::new_for_test(42, 0);
        let machine = Arc::new(Mutex::new(ObligationStateMachine::new(
            obligation_id,
            ValidationLevel::Full,
        )));
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // First, transition to Reserved state
        {
            let mut m = machine.lock().unwrap();
            let result = m.transition(ObligationEvent::Reserve { token: 12345 }, &context);
            assert_eq!(result, TransitionResult::Valid);
            assert!(m.is_reserved());
        }

        // Now test concurrent transitions from Reserved state
        let machine_clone = Arc::clone(&machine);
        let observed_states = Arc::new(Mutex::new(Vec::new()));
        let observed_states_clone = Arc::clone(&observed_states);

        // Spawn thread that continuously reads state during transition
        let reader_handle = thread::spawn(move || {
            for _ in 0..100 {
                if let Ok(m) = machine_clone.try_lock() {
                    let state = m.current_state().clone();
                    observed_states_clone.lock().unwrap().push(state);
                    // Yield to give transition thread a chance
                    thread::yield_now();
                } else {
                    thread::yield_now();
                }
            }
        });

        // Give reader thread time to start
        thread::sleep(std::time::Duration::from_millis(1));

        // Perform transition that should be atomic
        let result = {
            let mut m = machine.lock().unwrap();
            m.transition(ObligationEvent::Commit, &context)
        };
        assert_eq!(result, TransitionResult::Valid);

        // Wait for reader to finish
        reader_handle.join().unwrap();

        // Verify that all observed states are valid - no intermediate invalid states
        let states = observed_states.lock().unwrap();
        for state in states.iter() {
            match state {
                ObligationState::Created
                | ObligationState::Reserved { .. }
                | ObligationState::Committed
                | ObligationState::Aborted { .. }
                | ObligationState::Error { .. } => {
                    // All these states are valid - good!
                }
            }
        }

        // Verify final state is correct
        let final_machine = machine.lock().unwrap();
        assert!(matches!(
            final_machine.current_state(),
            ObligationState::Committed
        ));
        assert!(final_machine.is_fulfilled());
        assert!(final_machine.is_terminal());
    }

    #[test]
    fn test_obligation_invariant_violation_atomicity() {
        // Test that invariant violations are handled atomically
        // When invariants fail, state should go directly to Error without invalid intermediates
        let obligation_id = ObligationId::new_for_test(99, 0);
        let mut machine = ObligationStateMachine::new(obligation_id, ValidationLevel::Full);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Attempt transition that will fail invariant check (token = 0)
        let result = machine.transition(ObligationEvent::Reserve { token: 0 }, &context);

        // Should get invariant violation
        assert!(matches!(
            result,
            TransitionResult::InvariantViolation { .. }
        ));

        // State should be Error, not some intermediate invalid state
        assert!(matches!(
            machine.current_state(),
            ObligationState::Error { .. }
        ));

        // Machine should be in terminal state
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_channel_lifecycle() {
        let channel_id = 1;
        let mut machine = ChannelStateMachine::new(channel_id, ValidationLevel::Full);
        let context = ChannelContext {
            channel_id,
            validation_level: ValidationLevel::Full,
        };

        assert!(machine.is_accepting_ops());

        // Start some operations
        machine
            .transition(ChannelEvent::OperationStarted, &context)
            .unwrap();
        machine
            .transition(ChannelEvent::OperationStarted, &context)
            .unwrap();
        assert_eq!(machine.pending_ops(), 2);

        // Initiate close while operations are pending
        machine
            .transition(ChannelEvent::InitiateClose, &context)
            .unwrap();
        assert!(!machine.is_accepting_ops());

        // Complete operations
        machine
            .transition(ChannelEvent::OperationCompleted, &context)
            .unwrap();
        machine
            .transition(ChannelEvent::OperationCompleted, &context)
            .unwrap();

        assert!(machine.is_terminal());
        assert!(matches!(machine.current_state(), ChannelState::Closed));
    }

    #[test]
    fn test_io_operation_lifecycle() {
        let operation_id = 1;
        let io_handle = 42;
        let mut machine = IoStateMachine::new(operation_id, io_handle, ValidationLevel::Full);
        let context = IoContext {
            operation_id,
            operation_type: "read".to_string(),
            validation_level: ValidationLevel::Full,
        };

        assert!(machine.is_pending());

        // Complete successfully
        machine
            .transition(IoEvent::Complete { result_size: 1024 }, &context)
            .unwrap();
        assert!(machine.completed_successfully());
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_io_operation_cancellation() {
        let operation_id = 2;
        let io_handle = 43;
        let mut machine = IoStateMachine::new(operation_id, io_handle, ValidationLevel::Full);
        let context = IoContext {
            operation_id,
            operation_type: "write".to_string(),
            validation_level: ValidationLevel::Full,
        };

        // Cancel and cleanup
        machine.transition(IoEvent::Cancel, &context).unwrap();
        machine
            .transition(IoEvent::CleanupComplete, &context)
            .unwrap();

        assert!(machine.is_terminal());
        assert!(matches!(machine.current_state(), IoState::Cleanup));
    }

    #[test]
    fn test_timer_lifecycle() {
        let timer_id = 1;
        let deadline = Time::from_nanos(1000);
        let mut machine = TimerStateMachine::new(timer_id, deadline, ValidationLevel::Full);
        let context = TimerContext {
            timer_id,
            current_time: Time::from_nanos(999), // Before deadline
            validation_level: ValidationLevel::Full,
        };

        assert!(machine.is_scheduled());
        assert_eq!(machine.deadline(), Some(deadline));

        // Try to fire before deadline (should fail)
        let result = machine.transition(TimerEvent::Fire, &context);
        assert!(matches!(
            result,
            TransitionResult::InvariantViolation { .. }
        ));

        // Update context time and fire
        let context = TimerContext {
            timer_id,
            current_time: Time::from_nanos(1001), // After deadline
            validation_level: ValidationLevel::Full,
        };

        machine.transition(TimerEvent::Fire, &context).unwrap();
        assert!(machine.is_terminal());
        assert!(matches!(machine.current_state(), TimerState::Fired));
    }

    #[test]
    fn test_validator() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(1, 0);
        let obligation_id = ObligationId::new_for_test(1, 0);
        let channel_id = 1;

        validator.register_region(region_id);
        validator.register_task(task_id, region_id);
        validator.register_obligation(obligation_id);
        validator.register_channel(channel_id);

        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let obligation_context = ObligationContext {
            obligation_id,
            region_id,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let channel_context = ChannelContext {
            channel_id,
            validation_level: ValidationLevel::Full,
        };

        // Valid transitions
        assert!(matches!(
            validator.validate_region_transition(region_id, RegionEvent::Activate, &region_context),
            TransitionResult::Valid
        ));

        assert!(matches!(
            validator.validate_task_transition(task_id, TaskEvent::Start, &task_context),
            TransitionResult::Valid
        ));

        assert!(matches!(
            validator.validate_obligation_transition(
                obligation_id,
                ObligationEvent::Reserve { token: 123 },
                &obligation_context
            ),
            TransitionResult::Valid
        ));

        assert!(matches!(
            validator.validate_channel_transition(
                channel_id,
                ChannelEvent::OperationStarted,
                &channel_context
            ),
            TransitionResult::Valid
        ));

        assert_eq!(validator.violation_count(), 0);
        let (regions, tasks, obligations, channels, io_ops, timers, violations) = validator.stats();
        assert_eq!(regions, 1);
        assert_eq!(tasks, 1);
        assert_eq!(obligations, 1);
        assert_eq!(channels, 1);
        assert_eq!(io_ops, 0);
        assert_eq!(timers, 0);
        assert_eq!(violations, 0);
    }

    #[test]
    fn test_validator_counts_invalid_transition_without_panicking() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let task_id = TaskId::new_for_test(9, 0);
        let region_id = RegionId::new_for_test(1, 0);

        validator.register_task(task_id, region_id);

        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let result =
            validator.validate_task_transition(task_id, TaskEvent::Complete, &task_context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));
        assert_eq!(validator.violation_count(), 1);
    }

    #[test]
    fn test_validator_counts_unregistered_transition() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let task_id = TaskId::new_for_test(11, 0);
        let region_id = RegionId::new_for_test(1, 0);

        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let result =
            validator.validate_task_transition(task_id, TaskEvent::Complete, &task_context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));
        assert_eq!(validator.violation_count(), 1);
    }
