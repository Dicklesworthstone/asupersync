    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{Budget, Outcome};
    use crate::util::ArenaIndex;
    use serde_json::json;

    fn task_id(idx: usize) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(idx as u32, 0))
    }

    fn region_id(idx: usize) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(idx as u32, 0))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn scrub_cancellation_protocol_trace(
        scenario_id: &str,
        oracle: &CancellationProtocolOracle,
    ) -> serde_json::Value {
        let mut region_ids = oracle.region_parents.keys().copied().collect::<Vec<_>>();
        region_ids.sort();
        let regions = region_ids
            .into_iter()
            .map(|region| {
                let parent = oracle
                    .region_parents
                    .get(&region)
                    .copied()
                    .flatten()
                    .map(|parent| parent.to_string());
                let cancel_reason = oracle
                    .cancelled_regions
                    .get(&region)
                    .map(|reason| format!("{:?}", reason.kind));
                json!({
                    "region": region.to_string(),
                    "parent": parent,
                    "cancel_reason": cancel_reason,
                })
            })
            .collect::<Vec<_>>();

        let mut task_ids = oracle.tasks.keys().copied().collect::<Vec<_>>();
        task_ids.sort();
        let tasks = task_ids
            .into_iter()
            .map(|task| {
                let record = oracle.tasks.get(&task).expect("task record");
                let region = oracle
                    .task_regions
                    .get(&task)
                    .copied()
                    .expect("task region");
                let cancel_request = record.cancel_request.as_ref().map(|cancel| {
                    json!({
                        "requested_at_nanos": cancel.requested_at.as_nanos(),
                        "reason": format!("{:?}", cancel.reason.kind),
                        "acknowledged": cancel.acknowledged,
                        "polls_since": cancel.polls_since,
                    })
                });
                let transitions = record
                    .transitions
                    .iter()
                    .map(|(from, to, time)| {
                        json!({
                            "from": format!("{from:?}"),
                            "to": format!("{to:?}"),
                            "time_nanos": time.as_nanos(),
                        })
                    })
                    .collect::<Vec<_>>();

                json!({
                    "task": task.to_string(),
                    "region": region.to_string(),
                    "state": format!("{:?}", record.current_state),
                    "mask_depth": record.mask_depth,
                    "cancel_request": cancel_request,
                    "transitions": transitions,
                })
            })
            .collect::<Vec<_>>();

        let mut violations = oracle
            .all_violations()
            .into_iter()
            .map(|violation| violation.to_string())
            .collect::<Vec<_>>();
        violations.sort();

        let check = match oracle.check() {
            Ok(()) => "ok".to_string(),
            Err(violation) => violation.to_string(),
        };

        json!({
            "scenario_id": scenario_id,
            "check": check,
            "regions": regions,
            "tasks": tasks,
            "violations": violations,
        })
    }

    fn happy_cancellation_protocol_trace() -> serde_json::Value {
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);
        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );
        oracle.on_cancel_ack(task, Time::from_nanos(200));
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(400),
        );

        scrub_cancellation_protocol_trace("happy_path", &oracle)
    }

    fn late_cancel_cancellation_protocol_trace() -> serde_json::Value {
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);
        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );
        for _ in 0..=CANCEL_ACK_POLL_BOUND {
            oracle.on_task_poll(task);
        }

        scrub_cancellation_protocol_trace("late_cancel_ack", &oracle)
    }

    fn reentrant_cancellation_protocol_trace() -> serde_json::Value {
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);
        let cleanup_budget = Budget::INFINITE;
        let initial_reason = CancelReason::user("stop");
        let strengthened_reason = CancelReason::shutdown();

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);
        oracle.on_cancel_request(task, initial_reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: initial_reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );
        oracle.on_cancel_request(task, strengthened_reason.clone(), Time::from_nanos(150));
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: CancelReason::user("stop"),
                cleanup_budget,
            },
            &TaskState::CancelRequested {
                reason: strengthened_reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(150),
        );
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: strengthened_reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: strengthened_reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: strengthened_reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: strengthened_reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: strengthened_reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(strengthened_reason)),
            Time::from_nanos(400),
        );

        scrub_cancellation_protocol_trace("reentrant_cancel_strengthening", &oracle)
    }

    #[test]
    fn cancellation_protocol_trace_bundle_snapshot() {
        let bundle = vec![
            happy_cancellation_protocol_trace(),
            late_cancel_cancellation_protocol_trace(),
            reentrant_cancellation_protocol_trace(),
        ];

        insta::assert_json_snapshot!("cancellation_protocol_trace_bundle", bundle);
    }

    #[test]
    fn empty_oracle_passes() {
        init_test("empty_oracle_passes");
        let oracle = CancellationProtocolOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("empty_oracle_passes");
    }

    #[test]
    fn valid_normal_lifecycle_passes() {
        init_test("valid_normal_lifecycle_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Created -> Running -> CompletedOk
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::Completed(Outcome::Ok(())),
            Time::from_nanos(1000),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("valid_normal_lifecycle_passes");
    }

    #[test]
    fn valid_cancellation_protocol_passes() {
        init_test("valid_cancellation_protocol_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Created -> Running
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Running -> CancelRequested
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // CancelRequested -> Cancelling
        oracle.on_cancel_ack(task, Time::from_nanos(200));
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );

        // Cancelling -> Finalizing
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );

        // Finalizing -> CompletedCancelled
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(400),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("valid_cancellation_protocol_passes");
    }

    #[test]
    fn cancel_before_first_poll_passes() {
        init_test("cancel_before_first_poll_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Created -> CancelRequested (cancel before first poll)
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(50));
        oracle.on_transition(
            task,
            &TaskState::Created,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(50),
        );

        // Continue through protocol
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );

        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(300),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_before_first_poll_passes");
    }

    #[test]
    fn skipped_state_detected() {
        init_test("skipped_state_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // _reason unused here - test verifies skipped state detection doesn't need cancel request
        let _reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;
        let reason = CancelReason::timeout();

        // Running -> Finalizing (skipping CancelRequested and Cancelling!)
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::Finalizing {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let skipped = matches!(
            violation,
            CancellationProtocolViolation::SkippedState { .. }
        );
        crate::assert_with_log!(skipped, "skipped state", true, skipped);
        crate::test_complete!("skipped_state_detected");
    }

    #[test]
    fn cancel_strengthening_is_valid() {
        init_test("cancel_strengthening_is_valid");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let cleanup_budget = Budget::INFINITE;

        // First cancel request with User reason
        let reason1 = CancelReason::user("stop");
        oracle.on_cancel_request(task, reason1.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason1,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Second cancel request with stronger reason (Shutdown)
        let reason2 = CancelReason::shutdown();
        oracle.on_cancel_request(task, reason2.clone(), Time::from_nanos(150));
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: CancelReason::user("stop"),
                cleanup_budget,
            },
            &TaskState::CancelRequested {
                reason: reason2.clone(),
                cleanup_budget,
            },
            Time::from_nanos(150),
        );

        // No violations for strengthening
        let empty = oracle.violations.is_empty();
        crate::assert_with_log!(empty, "violations empty", true, empty);

        // Complete the cancellation
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason2.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason2.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason2.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason2.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason2.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason2)),
            Time::from_nanos(400),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_strengthening_is_valid");
    }

    #[test]
    fn cancel_propagation_violation_detected() {
        init_test("cancel_propagation_violation_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let parent = region_id(0);
        let child = region_id(1);

        oracle.on_region_create(parent, None);
        oracle.on_region_create(child, Some(parent));

        // Cancel parent but NOT child
        oracle.on_region_cancel(parent, CancelReason::timeout(), Time::from_nanos(100));
        // Note: child is NOT cancelled

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let not_propagated = matches!(
            violation,
            CancellationProtocolViolation::CancelNotPropagated { .. }
        );
        crate::assert_with_log!(
            not_propagated,
            "cancel not propagated",
            true,
            not_propagated
        );
        crate::test_complete!("cancel_propagation_violation_detected");
    }

    #[test]
    fn cancel_propagation_valid_when_all_descendants_cancelled() {
        init_test("cancel_propagation_valid_when_all_descendants_cancelled");
        let mut oracle = CancellationProtocolOracle::new();
        let root = region_id(0);
        let child1 = region_id(1);
        let child2 = region_id(2);
        let grandchild = region_id(3);

        oracle.on_region_create(root, None);
        oracle.on_region_create(child1, Some(root));
        oracle.on_region_create(child2, Some(root));
        oracle.on_region_create(grandchild, Some(child1));

        // Cancel all from root down
        oracle.on_region_cancel(root, CancelReason::shutdown(), Time::from_nanos(100));
        oracle.on_region_cancel(
            child1,
            CancelReason::parent_cancelled(),
            Time::from_nanos(100),
        );
        oracle.on_region_cancel(
            child2,
            CancelReason::parent_cancelled(),
            Time::from_nanos(100),
        );
        oracle.on_region_cancel(
            grandchild,
            CancelReason::parent_cancelled(),
            Time::from_nanos(100),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_propagation_valid_when_all_descendants_cancelled");
    }

    #[test]
    fn cancelled_task_not_completed_detected() {
        init_test("cancelled_task_not_completed_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Start cancellation but don't complete
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Task is stuck in CancelRequested
        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let not_completed = matches!(
            violation,
            CancellationProtocolViolation::CancelNotCompleted { .. }
        );
        crate::assert_with_log!(not_completed, "cancel not completed", true, not_completed);
        crate::test_complete!("cancelled_task_not_completed_detected");
    }

    #[test]
    fn cancel_not_acknowledged_detected_after_bounded_polls() {
        init_test("cancel_not_acknowledged_detected_after_bounded_polls");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        for _ in 0..=CANCEL_ACK_POLL_BOUND {
            oracle.on_task_poll(task);
        }

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let not_acknowledged = matches!(
            violation,
            CancellationProtocolViolation::CancelNotAcknowledged {
                polls_since_request,
                ..
            } if polls_since_request == CANCEL_ACK_POLL_BOUND + 1
        );
        crate::assert_with_log!(
            not_acknowledged,
            "cancel not acknowledged",
            true,
            not_acknowledged
        );
        crate::test_complete!("cancel_not_acknowledged_detected_after_bounded_polls");
    }

    #[test]
    fn cancel_acknowledgement_at_bound_remains_valid() {
        init_test("cancel_acknowledgement_at_bound_remains_valid");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        for _ in 0..CANCEL_ACK_POLL_BOUND {
            oracle.on_task_poll(task);
        }

        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(400),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_acknowledgement_at_bound_remains_valid");
    }

    #[test]
    fn error_during_cleanup_is_valid() {
        init_test("error_during_cleanup_is_valid");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Start cancellation
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: CancelReason::timeout(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: CancelReason::timeout(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );

        // Error during cleanup (valid)
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: CancelReason::timeout(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Err(crate::error::Error::new(
                crate::error::ErrorKind::User,
            ))),
            Time::from_nanos(300),
        );

        // This should pass - error during cleanup is allowed
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("error_during_cleanup_is_valid");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);
        oracle.on_cancel_request(task, CancelReason::timeout(), Time::ZERO);

        let has_request = oracle.has_cancel_request(task);
        crate::assert_with_log!(has_request, "has cancel request", true, has_request);

        oracle.reset();

        let has_request = oracle.has_cancel_request(task);
        crate::assert_with_log!(!has_request, "cancel request cleared", false, has_request);
        let tasks_empty = oracle.tasks.is_empty();
        crate::assert_with_log!(tasks_empty, "tasks empty", true, tasks_empty);
        let parents_empty = oracle.region_parents.is_empty();
        crate::assert_with_log!(parents_empty, "parents empty", true, parents_empty);
        let cancelled_empty = oracle.cancelled_regions.is_empty();
        crate::assert_with_log!(cancelled_empty, "cancelled empty", true, cancelled_empty);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn task_state_tracking() {
        init_test("task_state_tracking");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let created = oracle.task_state(task);
        crate::assert_with_log!(
            created == Some(TaskStateKind::Created),
            "task state created",
            Some(TaskStateKind::Created),
            created
        );

        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        let running = oracle.task_state(task);
        crate::assert_with_log!(
            running == Some(TaskStateKind::Running),
            "task state running",
            Some(TaskStateKind::Running),
            running
        );
        crate::test_complete!("task_state_tracking");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let v = CancellationProtocolViolation::SkippedState {
            task: task_id(0),
            from: TaskStateKind::Running,
            to: TaskStateKind::Finalizing,
            time: Time::from_nanos(100),
        };

        let display = format!("{v}");
        let has_skipped = display.contains("skipped state");
        crate::assert_with_log!(has_skipped, "contains skipped", true, has_skipped);
        let has_running = display.contains("Running");
        crate::assert_with_log!(has_running, "contains Running", true, has_running);
        let has_finalizing = display.contains("Finalizing");
        crate::assert_with_log!(has_finalizing, "contains Finalizing", true, has_finalizing);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn mask_depth_exceeded_detected() {
        init_test("mask_depth_exceeded_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Push mask depth past MAX_MASK_DEPTH
        for i in 0..=crate::types::MAX_MASK_DEPTH {
            oracle.on_mask_enter(task, Time::from_nanos(u64::from(i)));
        }

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let exceeded = matches!(
            violation,
            CancellationProtocolViolation::MaskDepthExceeded { .. }
        );
        crate::assert_with_log!(exceeded, "mask depth exceeded", true, exceeded);
        crate::test_complete!("mask_depth_exceeded_detected");
    }

    #[test]
    fn unmatched_mask_exit_detected() {
        // br-asupersync-kzhbt8: an exit without a matching enter must be
        // surfaced, not silently absorbed by saturating arithmetic.
        init_test("unmatched_mask_exit_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Exit without a prior enter — protocol violation.
        oracle.on_mask_exit(task, Time::from_nanos(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let unmatched = matches!(
            violation,
            CancellationProtocolViolation::UnmatchedMaskExit { .. }
        );
        crate::assert_with_log!(unmatched, "unmatched mask exit", true, unmatched);
        crate::test_complete!("unmatched_mask_exit_detected");
    }

    #[test]
    fn mask_within_bounds_passes() {
        init_test("mask_within_bounds_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Enter and exit mask 3 times (within bounds)
        for i in 0..3 {
            oracle.on_mask_enter(task, Time::from_nanos(i * 2));
            oracle.on_mask_exit(task, Time::from_nanos(i * 2 + 1));
        }

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("mask_within_bounds_passes");
    }

    #[test]
    fn cancel_ack_while_masked_detected() {
        init_test("cancel_ack_while_masked_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Running
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Enter masked section
        oracle.on_mask_enter(task, Time::from_nanos(50));

        // Cancel while masked
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Acknowledge cancel while STILL masked (violation!)
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(150),
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let ack_masked = matches!(
            violation,
            CancellationProtocolViolation::CancelAckWhileMasked { .. }
        );
        crate::assert_with_log!(ack_masked, "cancel ack while masked", true, ack_masked);
        crate::test_complete!("cancel_ack_while_masked_detected");
    }

    #[test]
    fn cancel_ack_after_unmask_passes() {
        init_test("cancel_ack_after_unmask_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Running
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Enter and exit masked section
        oracle.on_mask_enter(task, Time::from_nanos(50));
        oracle.on_mask_exit(task, Time::from_nanos(80));

        // Cancel and ack while unmasked (valid)
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(150),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(300),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_ack_after_unmask_passes");
    }

    #[test]
    fn cancel_requested_then_completed_ok_passes() {
        init_test("cancel_requested_then_completed_ok_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Cancel requested
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Then completes normally before acknowledging
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Ok(())),
            Time::from_nanos(200),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_requested_then_completed_ok_passes");
    }

    #[test]
    fn cancel_requested_then_completed_cancelled_passes() {
        init_test("cancel_requested_then_completed_cancelled_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::shutdown();
        let cleanup_budget = Budget::INFINITE;

        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(200),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_requested_then_completed_cancelled_passes");
    }

    #[test]
    fn mask_depth_violation_display() {
        init_test("mask_depth_violation_display");
        let v = CancellationProtocolViolation::MaskDepthExceeded {
            task: task_id(0),
            depth: 65,
            max: 64,
            time: Time::from_nanos(100),
        };
        let display = format!("{v}");
        let has_depth = display.contains("65");
        crate::assert_with_log!(has_depth, "contains depth", true, has_depth);
        let has_max = display.contains("64");
        crate::assert_with_log!(has_max, "contains max", true, has_max);
        crate::test_complete!("mask_depth_violation_display");
    }

    #[test]
    fn cancel_ack_masked_violation_display() {
        init_test("cancel_ack_masked_violation_display");
        let v = CancellationProtocolViolation::CancelAckWhileMasked {
            task: task_id(0),
            mask_depth: 2,
            time: Time::from_nanos(100),
        };
        let display = format!("{v}");
        let has_masked = display.contains("masked");
        crate::assert_with_log!(has_masked, "contains masked", true, has_masked);
        let has_depth = display.contains("depth=2");
        crate::assert_with_log!(has_depth, "contains depth", true, has_depth);
        crate::test_complete!("cancel_ack_masked_violation_display");
    }

    /// br-asupersync-9fjaqe / -f1zjwu — Two oracles wired to the same
    /// witness stream must produce equivalent epoch verdicts. The
    /// witness-based `CancelCorrectnessOracle` and the event-based
    /// `CancellationProtocolOracle` (via its `on_cancel_witness` hook)
    /// must both reject an initial witness using the reserved epoch 0.
    #[test]
    fn on_cancel_witness_rejects_zero_epoch_initial_witness() {
        init_test("on_cancel_witness_rejects_zero_epoch_initial_witness");
        let mut oracle = CancellationProtocolOracle::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Collect,
            ..CancelCorrectnessConfig::default()
        });
        let task = task_id(7);
        let region = region_id(1);
        let witness = CancelWitness::new(
            task,
            region,
            0,
            CancelPhase::Requested,
            CancelReason::new(CancelKind::User),
        );

        oracle.on_cancel_witness(witness, Time::from_nanos(0));

        let violations = oracle.all_violations();
        assert_eq!(
            violations.len(),
            1,
            "expected one violation, got {violations:?}"
        );
        match &violations[0] {
            CancellationProtocolViolation::InvalidInitialWitnessEpoch {
                task: t,
                epoch,
                phase,
                ..
            } => {
                assert_eq!(*t, task);
                assert_eq!(*epoch, 0);
                assert_eq!(*phase, CancelPhase::Requested);
            }
            other => panic!("expected InvalidInitialWitnessEpoch, got {other:?}"),
        }
        crate::test_complete!("on_cancel_witness_rejects_zero_epoch_initial_witness");
    }

    /// br-asupersync-9fjaqe / -f1zjwu — Phase regression in the
    /// witness stream must surface as `InvalidWitnessTransition`,
    /// keeping the protocol oracle's verdict aligned with the
    /// canonical `CancelWitness::validate_transition` rules used by
    /// `cancel_correctness`.
    #[test]
    fn on_cancel_witness_rejects_phase_regression() {
        init_test("on_cancel_witness_rejects_phase_regression");
        let mut oracle = CancellationProtocolOracle::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Collect,
            ..CancelCorrectnessConfig::default()
        });
        let task = task_id(11);
        let region = region_id(2);
        let reason = CancelReason::new(CancelKind::User);
        let w1 = CancelWitness::new(task, region, 5, CancelPhase::Cancelling, reason.clone());
        let w2 = CancelWitness::new(task, region, 5, CancelPhase::Requested, reason);

        oracle.on_cancel_witness(w1, Time::from_nanos(10));
        oracle.on_cancel_witness(w2, Time::from_nanos(20));

        let violations = oracle.all_violations();
        assert_eq!(
            violations.len(),
            1,
            "expected one violation, got {violations:?}"
        );
        match &violations[0] {
            CancellationProtocolViolation::InvalidWitnessTransition { task: t, error, .. } => {
                assert_eq!(*t, task);
                assert!(
                    matches!(error, CancelWitnessError::PhaseRegression { .. }),
                    "expected PhaseRegression, got {error:?}"
                );
            }
            other => panic!("expected InvalidWitnessTransition, got {other:?}"),
        }
        crate::test_complete!("on_cancel_witness_rejects_phase_regression");
    }

    /// br-asupersync-9fjaqe / -f1zjwu — Epoch mismatch between
    /// successive witnesses for the same task must be flagged. The
    /// scenario from the bead (epoch 5 then epoch 3) is rejected with
    /// `EpochMismatch`, keeping the protocol oracle's verdict
    /// consistent with `cancel_correctness::validate_transition`.
    #[test]
    fn on_cancel_witness_rejects_epoch_regression() {
        init_test("on_cancel_witness_rejects_epoch_regression");
        let mut oracle = CancellationProtocolOracle::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Collect,
            ..CancelCorrectnessConfig::default()
        });
        let task = task_id(13);
        let region = region_id(2);
        let reason = CancelReason::new(CancelKind::User);
        let w1 = CancelWitness::new(task, region, 5, CancelPhase::Requested, reason.clone());
        let w2 = CancelWitness::new(task, region, 3, CancelPhase::Cancelling, reason);

        oracle.on_cancel_witness(w1, Time::from_nanos(10));
        oracle.on_cancel_witness(w2, Time::from_nanos(20));

        let violations = oracle.all_violations();
        assert_eq!(
            violations.len(),
            1,
            "expected one violation, got {violations:?}"
        );
        match &violations[0] {
            CancellationProtocolViolation::InvalidWitnessTransition { error, .. } => {
                assert!(
                    matches!(error, CancelWitnessError::EpochMismatch),
                    "expected EpochMismatch, got {error:?}"
                );
            }
            other => panic!("expected InvalidWitnessTransition, got {other:?}"),
        }
        crate::test_complete!("on_cancel_witness_rejects_epoch_regression");
    }

    /// br-asupersync-9fjaqe / -f1zjwu — Cross-oracle agreement test.
    /// The witness-based `CancelCorrectnessOracle` and the event-based
    /// `CancellationProtocolOracle` (via `on_cancel_witness`) must both
    /// reject the same epoch-0 initial witness and both accept the
    /// same well-formed witness stream — the oracle-composition
    /// disagreement that motivated this bead.
    #[test]
    fn cancel_oracles_agree_on_epoch_invariants() {
        init_test("cancel_oracles_agree_on_epoch_invariants");
        use crate::lab::oracle::cancel_correctness::CancelCorrectnessOracle;

        // Case 1: epoch 0 initial witness — both reject.
        let bad = CancelWitness::new(
            task_id(21),
            region_id(3),
            0,
            CancelPhase::Requested,
            CancelReason::new(CancelKind::User),
        );

        let cc = CancelCorrectnessOracle::default();
        cc.notify_cancel_witness(bad.clone(), Time::from_nanos(0));
        let cc_stats = cc.get_statistics();
        assert!(
            cc_stats.violations_detected >= 1,
            "cancel_correctness should reject epoch=0 initial witness, stats={cc_stats:?}"
        );

        let mut cp = CancellationProtocolOracle::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Collect,
            ..CancelCorrectnessConfig::default()
        });
        cp.on_cancel_witness(bad, Time::from_nanos(0));
        let cp_violations = cp.all_violations();
        assert!(
            !cp_violations.is_empty(),
            "cancellation_protocol should reject epoch=0 initial witness"
        );

        // Case 2: well-formed stream — both accept.
        let good_task = task_id(22);
        let good_region = region_id(4);
        let reason = CancelReason::new(CancelKind::User);
        let stream = [
            CancelWitness::new(
                good_task,
                good_region,
                7,
                CancelPhase::Requested,
                reason.clone(),
            ),
            CancelWitness::new(
                good_task,
                good_region,
                7,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            CancelWitness::new(good_task, good_region, 7, CancelPhase::Finalizing, reason),
        ];

        let cc2 = CancelCorrectnessOracle::default();
        let mut cp2 = CancellationProtocolOracle::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Collect,
            ..CancelCorrectnessConfig::default()
        });
        for (i, w) in stream.iter().enumerate() {
            cc2.notify_cancel_witness(w.clone(), Time::from_nanos((i as u64 + 1) * 10));
            cp2.on_cancel_witness(w.clone(), Time::from_nanos((i as u64 + 1) * 10));
        }

        let cc2_stats = cc2.get_statistics();
        assert_eq!(
            cc2_stats.violations_detected, 0,
            "cancel_correctness should accept well-formed stream, stats={cc2_stats:?}"
        );
        let cp2_violations = cp2.all_violations();
        assert!(
            cp2_violations.is_empty(),
            "cancellation_protocol should accept well-formed stream, got {cp2_violations:?}"
        );
        crate::test_complete!("cancel_oracles_agree_on_epoch_invariants");
    }

    /// br-asupersync-2ybwmx: under `cfg(any(test, feature =
    /// "deterministic-mode"))` (which the `#[cfg(test)]` attribute
    /// implies for in-file unit tests) `violation_now()` MUST return
    /// `Time::ZERO`. Two consecutive calls must produce identical
    /// values — no wall-clock drift bleeds through. This is the
    /// invariant the lab golden-artifact run-twice-and-compare gate
    /// in tests/lab_runtime_seed_golden.rs depends on for
    /// cancellation-protocol violation traces.
    #[test]
    fn violation_now_is_byte_stable_under_test_cfg() {
        init_test("violation_now_is_byte_stable_under_test_cfg");
        let t1 = violation_now();
        let t2 = violation_now();
        let t3 = violation_now();
        assert_eq!(
            t1,
            Time::ZERO,
            "violation_now must return Time::ZERO under cfg(test)"
        );
        assert_eq!(t1, t2);
        assert_eq!(t2, t3);
        crate::test_complete!("violation_now_is_byte_stable_under_test_cfg");
    }

    /// br-asupersync-2ybwmx: ViolationRecord::new must propagate the
    /// deterministic stamp into the `detected_at` field. Construct
    /// two records back-to-back from identical inputs and assert
    /// the timestamps match — the only field that varies legitimately
    /// is `trace_id` (a monotone counter).
    #[test]
    fn violation_record_detected_at_is_deterministic_under_test_cfg() {
        init_test("violation_record_detected_at_is_deterministic_under_test_cfg");
        let cfg = CancelCorrectnessConfig::default();
        // Use a real variant from CancellationProtocolViolation — the
        // shape doesn't matter, only that ViolationRecord::new wraps
        // it and stamps detected_at via violation_now().
        let v = CancellationProtocolViolation::CancelNotPropagated {
            parent: region_id(0),
            uncancelled_child: region_id(1),
        };
        let r1 = ViolationRecord::new(v.clone(), &cfg);
        let r2 = ViolationRecord::new(v, &cfg);
        assert_eq!(
            r1.detected_at, r2.detected_at,
            "br-2ybwmx: detected_at must be byte-stable across replays"
        );
        assert_eq!(
            r1.detected_at,
            Time::ZERO,
            "under cfg(test) detected_at must be Time::ZERO"
        );
        crate::test_complete!("violation_record_detected_at_is_deterministic_under_test_cfg");
    }
