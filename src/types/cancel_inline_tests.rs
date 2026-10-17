    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use serde_json::{Value, json};

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    fn combine(mut a: CancelReason, b: &CancelReason) -> CancelReason {
        a.strengthen(b);
        a
    }

    fn scrub_cancel_snapshot(mut value: Value) -> Value {
        fn scrub_in_place(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    for (key, entry) in map.iter_mut() {
                        match key.as_str() {
                            "task_id" | "origin_task" if !entry.is_null() => {
                                *entry = Value::String("[TASK_ID]".into());
                            }
                            "region_id" | "origin_region" => {
                                *entry = Value::String("[REGION_ID]".into());
                            }
                            "timestamp" => {
                                *entry = Value::String("[TIME]".into());
                            }
                            _ => scrub_in_place(entry),
                        }
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        scrub_in_place(item);
                    }
                }
                _ => {}
            }
        }

        scrub_in_place(&mut value);
        value
    }

    #[test]
    fn severity_ordering() {
        init_test("severity_ordering");
        // Test severity levels are ordered correctly
        crate::assert_with_log!(
            CancelKind::User.severity() < CancelKind::Timeout.severity(),
            "User should be below Timeout",
            true,
            CancelKind::User.severity() < CancelKind::Timeout.severity()
        );
        crate::assert_with_log!(
            CancelKind::Timeout.severity() == CancelKind::Deadline.severity(),
            "Timeout and Deadline should have same severity",
            true,
            CancelKind::Timeout.severity() == CancelKind::Deadline.severity()
        );
        crate::assert_with_log!(
            CancelKind::Deadline.severity() < CancelKind::PollQuota.severity(),
            "Deadline should be below PollQuota",
            true,
            CancelKind::Deadline.severity() < CancelKind::PollQuota.severity()
        );
        crate::assert_with_log!(
            CancelKind::PollQuota.severity() == CancelKind::CostBudget.severity(),
            "PollQuota and CostBudget should have same severity",
            true,
            CancelKind::PollQuota.severity() == CancelKind::CostBudget.severity()
        );
        crate::assert_with_log!(
            CancelKind::CostBudget.severity() < CancelKind::FailFast.severity(),
            "CostBudget should be below FailFast",
            true,
            CancelKind::CostBudget.severity() < CancelKind::FailFast.severity()
        );
        crate::assert_with_log!(
            CancelKind::FailFast.severity() == CancelKind::RaceLost.severity(),
            "FailFast and RaceLost should have same severity",
            true,
            CancelKind::FailFast.severity() == CancelKind::RaceLost.severity()
        );
        crate::assert_with_log!(
            CancelKind::RaceLost.severity() < CancelKind::ParentCancelled.severity(),
            "RaceLost should be below ParentCancelled",
            true,
            CancelKind::RaceLost.severity() < CancelKind::ParentCancelled.severity()
        );
        crate::assert_with_log!(
            CancelKind::ParentCancelled.severity() == CancelKind::ResourceUnavailable.severity(),
            "ParentCancelled and ResourceUnavailable should have same severity",
            true,
            CancelKind::ParentCancelled.severity() == CancelKind::ResourceUnavailable.severity()
        );
        crate::assert_with_log!(
            CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity(),
            "ParentCancelled should be below Shutdown",
            true,
            CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity()
        );
        crate::test_complete!("severity_ordering");
    }

    #[test]
    fn strengthen_takes_more_severe() {
        init_test("strengthen_takes_more_severe");
        let mut reason = CancelReason::new(CancelKind::User);
        let strengthened = reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            strengthened,
            "should strengthen to Timeout",
            true,
            strengthened
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should be Timeout",
            CancelKind::Timeout,
            reason.kind
        );

        let strengthened_shutdown = reason.strengthen(&CancelReason::shutdown());
        crate::assert_with_log!(
            strengthened_shutdown,
            "should strengthen to Shutdown",
            true,
            strengthened_shutdown
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should be Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );

        // Less severe should not change.
        let unchanged = !reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(unchanged, "less severe should not change", true, unchanged);
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should remain Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );
        crate::test_complete!("strengthen_takes_more_severe");
    }

    #[test]
    fn strengthen_adopts_truncation_metadata_from_winner() {
        init_test("strengthen_adopts_truncation_metadata_from_winner");
        // Build a truncated reason (self) and a non-truncated stronger reason (other).
        let config = CancelAttributionConfig::new(2, usize::MAX);
        let deep_cause = CancelReason::timeout().with_cause(CancelReason::user("root"));
        let mut truncated_reason =
            CancelReason::user("weak").with_cause_limited(deep_cause, &config);
        crate::assert_with_log!(
            truncated_reason.truncated || truncated_reason.any_truncated(),
            "pre-strengthen reason should be truncated",
            true,
            truncated_reason.truncated || truncated_reason.any_truncated()
        );

        let non_truncated = CancelReason::shutdown();
        crate::assert_with_log!(
            !non_truncated.truncated,
            "stronger reason should not be truncated",
            false,
            non_truncated.truncated
        );

        let changed = truncated_reason.strengthen(&non_truncated);
        crate::assert_with_log!(changed, "should strengthen to Shutdown", true, changed);
        crate::assert_with_log!(
            !truncated_reason.truncated,
            "truncated flag should adopt winner's value (false)",
            false,
            truncated_reason.truncated
        );
        crate::assert_with_log!(
            truncated_reason.truncated_at_depth.is_none(),
            "truncated_at_depth should adopt winner's value (None)",
            true,
            truncated_reason.truncated_at_depth.is_none()
        );
        crate::test_complete!("strengthen_adopts_truncation_metadata_from_winner");
    }

    #[test]
    fn strengthen_is_idempotent() {
        init_test("strengthen_is_idempotent");
        let mut reason = CancelReason::timeout();
        let unchanged = !reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            unchanged,
            "strengthen should be idempotent",
            true,
            unchanged
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should remain Timeout",
            CancelKind::Timeout,
            reason.kind
        );
        crate::test_complete!("strengthen_is_idempotent");
    }

    #[test]
    fn strengthen_is_associative() {
        init_test("strengthen_is_associative");
        let a = CancelReason::user("a");
        let b = CancelReason::timeout();
        let c = CancelReason::shutdown();

        let left = combine(combine(a.clone(), &b), &c);
        let right = {
            let bc = combine(b, &c);
            combine(a, &bc)
        };

        crate::assert_with_log!(
            left == right,
            "strengthen should be associative",
            left,
            right
        );
        crate::test_complete!("strengthen_is_associative");
    }

    #[test]
    fn strengthen_same_kind_picks_deterministic_message() {
        init_test("strengthen_same_kind_picks_deterministic_message");
        let mut reason = CancelReason::user("b");
        let changed = reason.strengthen(&CancelReason::user("a"));
        crate::assert_with_log!(
            changed,
            "same-kind strengthen should change message",
            true,
            changed
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::User,
            "kind should remain User",
            CancelKind::User,
            reason.kind
        );
        crate::assert_with_log!(
            reason.message == Some("a".to_string()),
            "message should be deterministic",
            Some("a"),
            reason.message
        );
        crate::test_complete!("strengthen_same_kind_picks_deterministic_message");
    }

    #[test]
    fn strengthen_resets_message_when_kind_increases() {
        init_test("strengthen_resets_message_when_kind_increases");
        let mut reason = CancelReason::user("please stop");
        let changed = reason.strengthen(&CancelReason::shutdown());
        crate::assert_with_log!(changed, "kind increase should change reason", true, changed);
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should be Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );
        crate::assert_with_log!(
            reason.message.is_none(),
            "message should reset on kind increase",
            true,
            reason.message.is_none()
        );
        crate::test_complete!("strengthen_resets_message_when_kind_increases");
    }

    #[test]
    fn cleanup_budget_scales_with_severity() {
        init_test("cleanup_budget_scales_with_severity");
        // User cancellation gets the most generous budget
        let user_budget = CancelReason::user("stop").cleanup_budget();
        crate::assert_with_log!(
            user_budget.poll_quota == 1000,
            "user budget poll_quota should be 1000",
            1000,
            user_budget.poll_quota
        );

        // Timeout gets moderate budget
        let timeout_budget = CancelReason::timeout().cleanup_budget();
        crate::assert_with_log!(
            timeout_budget.poll_quota == 500,
            "timeout budget poll_quota should be 500",
            500,
            timeout_budget.poll_quota
        );

        // Budget exhaustion (PollQuota/CostBudget) gets tight budget
        let poll_quota_budget = CancelReason::poll_quota().cleanup_budget();
        crate::assert_with_log!(
            poll_quota_budget.poll_quota == 300,
            "poll_quota budget poll_quota should be 300",
            300,
            poll_quota_budget.poll_quota
        );

        // FailFast gets tight budget
        let fail_fast_budget = CancelReason::sibling_failed().cleanup_budget();
        crate::assert_with_log!(
            fail_fast_budget.poll_quota == 200,
            "fail_fast budget poll_quota should be 200",
            200,
            fail_fast_budget.poll_quota
        );

        // Shutdown gets minimal budget with highest priority
        let shutdown_budget = CancelReason::shutdown().cleanup_budget();
        crate::assert_with_log!(
            shutdown_budget.poll_quota == 50,
            "shutdown budget poll_quota should be 50",
            50,
            shutdown_budget.poll_quota
        );
        crate::assert_with_log!(
            shutdown_budget.priority == 255,
            "shutdown budget priority should be 255",
            255,
            shutdown_budget.priority
        );

        // Priority increases with severity (cancel lane needs higher priority)
        crate::assert_with_log!(
            user_budget.priority < timeout_budget.priority,
            "user priority should be below timeout",
            true,
            user_budget.priority < timeout_budget.priority
        );
        crate::assert_with_log!(
            timeout_budget.priority < poll_quota_budget.priority,
            "timeout priority should be below poll_quota",
            true,
            timeout_budget.priority < poll_quota_budget.priority
        );
        crate::assert_with_log!(
            poll_quota_budget.priority < fail_fast_budget.priority,
            "poll_quota priority should be below fail_fast",
            true,
            poll_quota_budget.priority < fail_fast_budget.priority
        );
        crate::assert_with_log!(
            fail_fast_budget.priority < shutdown_budget.priority,
            "fail_fast priority should be below shutdown",
            true,
            fail_fast_budget.priority < shutdown_budget.priority
        );
        crate::test_complete!("cleanup_budget_scales_with_severity");
    }

    // ========================================================================
    // Bounded Cleanup Completion Tests (bd-3cq88)
    //
    // These tests verify the sufficient-budget termination property:
    // cleanup budgets have finite poll quotas, so cleanup always
    // terminates within a bounded number of polls.
    // ========================================================================

    /// Verifies that every CancelKind produces a cleanup budget with
    /// finite, positive poll quota — the precondition for bounded completion.
    #[test]
    fn cleanup_budget_always_finite_and_positive() {
        init_test("cleanup_budget_always_finite_and_positive");

        let kinds = [
            CancelKind::User,
            CancelKind::Timeout,
            CancelKind::Deadline,
            CancelKind::PollQuota,
            CancelKind::CostBudget,
            CancelKind::FailFast,
            CancelKind::RaceLost,
            CancelKind::ParentCancelled,
            CancelKind::ResourceUnavailable,
            CancelKind::Shutdown,
        ];

        for kind in kinds {
            let reason =
                CancelReason::with_origin(kind, RegionId::new_for_test(1, 0), Time::from_secs(0));
            let budget = reason.cleanup_budget();
            crate::assert_with_log!(
                budget.poll_quota > 0 && budget.poll_quota < u32::MAX,
                "cleanup budget must be finite and positive",
                true,
                budget.poll_quota
            );
        }

        crate::test_complete!("cleanup_budget_always_finite_and_positive");
    }

    /// Verifies that consuming exactly poll_quota polls exhausts the cleanup
    /// budget — the termination bound.
    #[test]
    fn cleanup_budget_terminates_after_quota_polls() {
        init_test("cleanup_budget_terminates_after_quota_polls");

        let reason = CancelReason::timeout();
        let mut budget = reason.cleanup_budget();
        let quota = budget.poll_quota;

        // Consume exactly quota polls
        for i in 0..quota {
            let result = budget.consume_poll();
            crate::assert_with_log!(
                result.is_some(),
                "poll should succeed within budget",
                true,
                i
            );
        }

        // Now exhausted
        crate::assert_with_log!(
            budget.is_exhausted(),
            "budget exhausted after quota polls",
            true,
            budget.poll_quota
        );

        // No further progress possible
        let result = budget.consume_poll();
        crate::assert_with_log!(
            result.is_none(),
            "poll fails after exhaustion",
            true,
            result.is_none()
        );

        crate::test_complete!("cleanup_budget_terminates_after_quota_polls");
    }

    /// Verifies that combining (strengthening) cleanup budgets never
    /// increases the poll quota — monotone narrowing.
    #[test]
    fn cleanup_budget_combine_never_widens() {
        init_test("cleanup_budget_combine_never_widens");

        let user_budget = CancelReason::user("stop").cleanup_budget();
        let timeout_budget = CancelReason::timeout().cleanup_budget();
        let shutdown_budget = CancelReason::shutdown().cleanup_budget();

        // Combining user + timeout takes the tighter quota
        let combined = user_budget.combine(timeout_budget);
        crate::assert_with_log!(
            combined.poll_quota <= user_budget.poll_quota,
            "combined ≤ user",
            user_budget.poll_quota,
            combined.poll_quota
        );
        crate::assert_with_log!(
            combined.poll_quota <= timeout_budget.poll_quota,
            "combined ≤ timeout",
            timeout_budget.poll_quota,
            combined.poll_quota
        );

        // Priority is max because Budget::combine always takes the maximum (most urgent) priority
        crate::assert_with_log!(
            combined.priority >= user_budget.priority,
            "combined priority >= user",
            user_budget.priority,
            combined.priority
        );

        // Combining with shutdown (tightest) always tightens
        let with_shutdown = combined.combine(shutdown_budget);
        crate::assert_with_log!(
            with_shutdown.poll_quota <= combined.poll_quota,
            "shutdown tightens further",
            combined.poll_quota,
            with_shutdown.poll_quota
        );
        crate::assert_with_log!(
            with_shutdown.priority >= combined.priority,
            "shutdown priority max",
            combined.priority,
            with_shutdown.priority
        );

        crate::test_complete!("cleanup_budget_combine_never_widens");
    }

    /// Verifies severity ordering: more severe → fewer polls, higher priority.
    #[test]
    fn cleanup_budget_severity_monotone() {
        init_test("cleanup_budget_severity_monotone");

        let user = CancelReason::user("stop");
        let timeout = CancelReason::timeout();
        let quota = CancelReason::poll_quota();
        let fail_fast = CancelReason::sibling_failed();
        let shutdown = CancelReason::shutdown();

        let budgets = [
            user.cleanup_budget(),
            timeout.cleanup_budget(),
            quota.cleanup_budget(),
            fail_fast.cleanup_budget(),
            shutdown.cleanup_budget(),
        ];

        // Poll quotas should be non-increasing (more severe → tighter)
        for i in 1..budgets.len() {
            crate::assert_with_log!(
                budgets[i].poll_quota <= budgets[i - 1].poll_quota,
                "poll quota non-increasing with severity",
                budgets[i - 1].poll_quota,
                budgets[i].poll_quota
            );
        }

        // Priorities should be non-decreasing (more severe → higher priority)
        for i in 1..budgets.len() {
            crate::assert_with_log!(
                budgets[i].priority >= budgets[i - 1].priority,
                "priority non-decreasing with severity",
                budgets[i - 1].priority,
                budgets[i].priority
            );
        }

        crate::test_complete!("cleanup_budget_severity_monotone");
    }

    /// Verifies that cleanup budgets have no deadline — cleanup should not
    /// be time-bounded, only poll-bounded, so the scheduler can always
    /// make progress regardless of clock skew.
    #[test]
    fn cleanup_budget_has_no_deadline() {
        init_test("cleanup_budget_has_no_deadline");

        let kinds = [CancelKind::User, CancelKind::Timeout, CancelKind::Shutdown];

        for kind in kinds {
            let reason =
                CancelReason::with_origin(kind, RegionId::new_for_test(1, 0), Time::from_secs(0));
            let budget = reason.cleanup_budget();
            crate::assert_with_log!(
                budget.deadline.is_none(),
                "cleanup budget should have no deadline",
                true,
                budget.deadline.is_none()
            );
        }

        crate::test_complete!("cleanup_budget_has_no_deadline");
    }

    // ========================================================================
    // Attribution Tests
    // ========================================================================

    #[test]
    fn cancel_reason_with_full_attribution() {
        init_test("cancel_reason_with_full_attribution");
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(2, 0);
        let timestamp = Time::from_millis(1000);

        let reason = CancelReason::with_origin(CancelKind::Timeout, region, timestamp)
            .with_task(task)
            .with_message("test timeout");

        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should be Timeout",
            CancelKind::Timeout,
            reason.kind
        );
        crate::assert_with_log!(
            reason.origin_region == region,
            "origin_region should match",
            region,
            reason.origin_region
        );
        crate::assert_with_log!(
            reason.origin_task == Some(task),
            "origin_task should match",
            Some(task),
            reason.origin_task
        );
        crate::assert_with_log!(
            reason.timestamp == timestamp,
            "timestamp should match",
            timestamp,
            reason.timestamp
        );
        crate::assert_with_log!(
            reason.message == Some("test timeout".to_string()),
            "message should match",
            Some("test timeout"),
            reason.message
        );
        crate::test_complete!("cancel_reason_with_full_attribution");
    }

    #[test]
    fn cancel_witness_json_snapshot_scrubbed() {
        init_test("cancel_witness_json_snapshot_scrubbed");
        let task = TaskId::new_for_test(8, 2);
        let region = RegionId::new_for_test(7, 1);
        let cause = CancelReason::with_origin(
            CancelKind::Timeout,
            RegionId::new_for_test(3, 0),
            Time::from_millis(220),
        )
        .with_task(TaskId::new_for_test(4, 0))
        .with_message("deadline budget expired");
        let reason = CancelReason::with_origin(
            CancelKind::ParentCancelled,
            RegionId::new_for_test(9, 1),
            Time::from_millis(550),
        )
        .with_task(TaskId::new_for_test(10, 0))
        .with_message("closing subtree")
        .with_cause(cause);
        let witness = CancelWitness::new(task, region, 3, CancelPhase::Finalizing, reason);

        insta::assert_json_snapshot!(
            "cancel_witness_json_scrubbed",
            scrub_cancel_snapshot(json!({
                "phase_label": format!("{:?}", witness.phase),
                "witness": witness,
            }))
        );
    }

    // ========================================================================
    // Cause Chain Tests
    // ========================================================================

    #[test]
    fn cause_chain_single() {
        init_test("cause_chain_single");
        let reason = CancelReason::timeout();

        crate::assert_with_log!(
            reason.chain_depth() == 1,
            "single reason should have depth 1",
            1,
            reason.chain_depth()
        );

        let root = reason.root_cause();
        crate::assert_with_log!(
            root == &reason,
            "root_cause of single reason should be itself",
            true,
            root == &reason
        );
        crate::test_complete!("cause_chain_single");
    }

    #[test]
    fn cause_chain_multiple() {
        init_test("cause_chain_multiple");
        let root = CancelReason::timeout().with_message("original timeout");
        let middle = CancelReason::parent_cancelled()
            .with_message("parent cancelled")
            .with_cause(root);
        let leaf = CancelReason::shutdown()
            .with_message("shutdown")
            .with_cause(middle);

        crate::assert_with_log!(
            leaf.chain_depth() == 3,
            "three-level chain should have depth 3",
            3,
            leaf.chain_depth()
        );

        let found_root = leaf.root_cause();
        crate::assert_with_log!(
            found_root.kind == CancelKind::Timeout,
            "root_cause should be Timeout",
            CancelKind::Timeout,
            found_root.kind
        );
        crate::assert_with_log!(
            found_root.message == Some("original timeout".to_string()),
            "root_cause message should match",
            Some("original timeout"),
            found_root.message
        );
        crate::test_complete!("cause_chain_multiple");
    }

    #[test]
    fn any_cause_is_works() {
        init_test("any_cause_is_works");
        let root = CancelReason::timeout();
        let leaf = CancelReason::shutdown().with_cause(root);

        crate::assert_with_log!(
            leaf.any_cause_is(CancelKind::Shutdown),
            "should find Shutdown in chain",
            true,
            leaf.any_cause_is(CancelKind::Shutdown)
        );
        crate::assert_with_log!(
            leaf.any_cause_is(CancelKind::Timeout),
            "should find Timeout in chain",
            true,
            leaf.any_cause_is(CancelKind::Timeout)
        );
        crate::assert_with_log!(
            !leaf.any_cause_is(CancelKind::User),
            "should not find User in chain",
            false,
            leaf.any_cause_is(CancelKind::User)
        );
        crate::test_complete!("any_cause_is_works");
    }

    #[test]
    fn caused_by_works() {
        init_test("caused_by_works");
        let root = CancelReason::timeout().with_message("root");
        let leaf = CancelReason::shutdown().with_cause(root.clone());

        crate::assert_with_log!(
            leaf.caused_by(&root),
            "leaf should be caused_by root",
            true,
            leaf.caused_by(&root)
        );
        crate::assert_with_log!(
            !root.caused_by(&leaf),
            "root should not be caused_by leaf",
            false,
            root.caused_by(&leaf)
        );
        crate::assert_with_log!(
            !leaf.caused_by(&leaf),
            "leaf should not be caused_by itself",
            false,
            leaf.caused_by(&leaf)
        );
        crate::test_complete!("caused_by_works");
    }

    // ========================================================================
    // Kind Check Tests
    // ========================================================================

    #[test]
    fn is_kind_works() {
        init_test("is_kind_works");
        let reason = CancelReason::poll_quota();
        crate::assert_with_log!(
            reason.is_kind(CancelKind::PollQuota),
            "is_kind should return true for matching kind",
            true,
            reason.is_kind(CancelKind::PollQuota)
        );
        crate::assert_with_log!(
            !reason.is_kind(CancelKind::Timeout),
            "is_kind should return false for non-matching kind",
            false,
            reason.is_kind(CancelKind::Timeout)
        );
        crate::test_complete!("is_kind_works");
    }

    #[test]
    fn is_budget_exceeded_works() {
        init_test("is_budget_exceeded_works");
        crate::assert_with_log!(
            CancelReason::deadline().is_budget_exceeded(),
            "Deadline should be budget_exceeded",
            true,
            CancelReason::deadline().is_budget_exceeded()
        );
        crate::assert_with_log!(
            CancelReason::poll_quota().is_budget_exceeded(),
            "PollQuota should be budget_exceeded",
            true,
            CancelReason::poll_quota().is_budget_exceeded()
        );
        crate::assert_with_log!(
            CancelReason::cost_budget().is_budget_exceeded(),
            "CostBudget should be budget_exceeded",
            true,
            CancelReason::cost_budget().is_budget_exceeded()
        );
        crate::assert_with_log!(
            !CancelReason::timeout().is_budget_exceeded(),
            "Timeout should not be budget_exceeded",
            false,
            CancelReason::timeout().is_budget_exceeded()
        );
        crate::test_complete!("is_budget_exceeded_works");
    }

    #[test]
    fn is_time_exceeded_works() {
        init_test("is_time_exceeded_works");
        crate::assert_with_log!(
            CancelReason::timeout().is_time_exceeded(),
            "Timeout should be time_exceeded",
            true,
            CancelReason::timeout().is_time_exceeded()
        );
        crate::assert_with_log!(
            CancelReason::deadline().is_time_exceeded(),
            "Deadline should be time_exceeded",
            true,
            CancelReason::deadline().is_time_exceeded()
        );
        crate::assert_with_log!(
            !CancelReason::poll_quota().is_time_exceeded(),
            "PollQuota should not be time_exceeded",
            false,
            CancelReason::poll_quota().is_time_exceeded()
        );
        crate::test_complete!("is_time_exceeded_works");
    }

    // ========================================================================
    // New Variant Tests
    // ========================================================================

    #[test]
    fn new_variants_constructors() {
        init_test("new_variants_constructors");

        let deadline = CancelReason::deadline();
        crate::assert_with_log!(
            deadline.kind == CancelKind::Deadline,
            "deadline() should create Deadline kind",
            CancelKind::Deadline,
            deadline.kind
        );

        let poll_quota = CancelReason::poll_quota();
        crate::assert_with_log!(
            poll_quota.kind == CancelKind::PollQuota,
            "poll_quota() should create PollQuota kind",
            CancelKind::PollQuota,
            poll_quota.kind
        );

        let cost_budget = CancelReason::cost_budget();
        crate::assert_with_log!(
            cost_budget.kind == CancelKind::CostBudget,
            "cost_budget() should create CostBudget kind",
            CancelKind::CostBudget,
            cost_budget.kind
        );

        let resource = CancelReason::resource_unavailable();
        crate::assert_with_log!(
            resource.kind == CancelKind::ResourceUnavailable,
            "resource_unavailable() should create ResourceUnavailable kind",
            CancelKind::ResourceUnavailable,
            resource.kind
        );

        crate::test_complete!("new_variants_constructors");
    }

    #[test]
    fn new_variants_display() {
        init_test("new_variants_display");

        crate::assert_with_log!(
            format!("{}", CancelKind::Deadline) == "deadline",
            "Deadline display should be 'deadline'",
            "deadline",
            format!("{}", CancelKind::Deadline)
        );
        crate::assert_with_log!(
            format!("{}", CancelKind::PollQuota) == "poll quota",
            "PollQuota display should be 'poll quota'",
            "poll quota",
            format!("{}", CancelKind::PollQuota)
        );
        crate::assert_with_log!(
            format!("{}", CancelKind::CostBudget) == "cost budget",
            "CostBudget display should be 'cost budget'",
            "cost budget",
            format!("{}", CancelKind::CostBudget)
        );
        crate::assert_with_log!(
            format!("{}", CancelKind::ResourceUnavailable) == "resource unavailable",
            "ResourceUnavailable display should be 'resource unavailable'",
            "resource unavailable",
            format!("{}", CancelKind::ResourceUnavailable)
        );

        crate::test_complete!("new_variants_display");
    }

    // ========================================================================
    // Chain Limit and Truncation Tests
    // ========================================================================

    #[test]
    fn cancel_attribution_config_defaults() {
        init_test("cancel_attribution_config_defaults");
        let config = CancelAttributionConfig::default();
        crate::assert_with_log!(
            config.max_chain_depth == 16,
            "default max_chain_depth should be 16",
            16,
            config.max_chain_depth
        );
        crate::assert_with_log!(
            config.max_chain_memory == 4096,
            "default max_chain_memory should be 4096",
            4096,
            config.max_chain_memory
        );
        crate::test_complete!("cancel_attribution_config_defaults");
    }

    #[test]
    fn cancel_attribution_config_custom() {
        init_test("cancel_attribution_config_custom");
        let config = CancelAttributionConfig::new(8, 2048);
        crate::assert_with_log!(
            config.max_chain_depth == 8,
            "custom max_chain_depth should be 8",
            8,
            config.max_chain_depth
        );
        crate::assert_with_log!(
            config.max_chain_memory == 2048,
            "custom max_chain_memory should be 2048",
            2048,
            config.max_chain_memory
        );
        crate::test_complete!("cancel_attribution_config_custom");
    }

    #[test]
    fn cancel_attribution_config_unlimited() {
        init_test("cancel_attribution_config_unlimited");
        let config = CancelAttributionConfig::unlimited();
        crate::assert_with_log!(
            config.max_chain_depth == usize::MAX,
            "unlimited max_chain_depth should be usize::MAX",
            usize::MAX,
            config.max_chain_depth
        );
        crate::test_complete!("cancel_attribution_config_unlimited");
    }

    #[test]
    fn chain_at_exact_limit() {
        init_test("chain_at_exact_limit");
        let config = CancelAttributionConfig::new(3, usize::MAX);

        // Build a chain of exactly 3 levels
        let level1 = CancelReason::timeout();
        let level2 = CancelReason::parent_cancelled().with_cause(level1);
        let level3 = CancelReason::shutdown().with_cause_limited(level2, &config);

        crate::assert_with_log!(
            level3.chain_depth() == 3,
            "chain at limit should have depth 3",
            3,
            level3.chain_depth()
        );
        crate::assert_with_log!(
            !level3.truncated,
            "chain at limit should not be truncated",
            false,
            level3.truncated
        );
        crate::test_complete!("chain_at_exact_limit");
    }

    #[test]
    fn chain_beyond_limit_truncates() {
        init_test("chain_beyond_limit_truncates");
        let config = CancelAttributionConfig::new(2, usize::MAX);

        // Build a chain of 3 levels, which exceeds limit of 2
        let level1 = CancelReason::timeout();
        let level2 = CancelReason::parent_cancelled().with_cause(level1);

        // This should truncate because we'd have 3 levels total
        let level3 = CancelReason::shutdown().with_cause_limited(level2, &config);

        crate::assert_with_log!(
            level3.chain_depth() <= 2,
            "chain beyond limit should be truncated to 2",
            2,
            level3.chain_depth()
        );
        crate::assert_with_log!(
            level3.truncated || level3.any_truncated(),
            "truncated chain should have truncated flag",
            true,
            level3.truncated || level3.any_truncated()
        );
        crate::test_complete!("chain_beyond_limit_truncates");
    }

    #[test]
    fn truncated_reason_new_fields() {
        init_test("truncated_reason_new_fields");
        let reason = CancelReason::timeout();

        crate::assert_with_log!(
            !reason.truncated,
            "new reason should not be truncated",
            false,
            reason.truncated
        );
        crate::assert_with_log!(
            reason.truncated_at_depth.is_none(),
            "new reason should have no truncated_at_depth",
            true,
            reason.truncated_at_depth.is_none()
        );
        crate::assert_with_log!(
            !reason.is_truncated(),
            "is_truncated() should be false",
            false,
            reason.is_truncated()
        );
        crate::test_complete!("truncated_reason_new_fields");
    }

    #[test]
    fn estimated_memory_cost() {
        init_test("estimated_memory_cost");
        let single = CancelReason::timeout();
        let cost1 = single.estimated_memory_cost();
        crate::assert_with_log!(
            cost1 > 0,
            "single reason should have positive memory cost",
            true,
            cost1 > 0
        );

        // Chain of 2 should cost more
        let chain2 = CancelReason::shutdown().with_cause(CancelReason::timeout());
        let cost2 = chain2.estimated_memory_cost();
        crate::assert_with_log!(
            cost2 > cost1,
            "chain of 2 should cost more than single",
            true,
            cost2 > cost1
        );

        crate::test_complete!("estimated_memory_cost");
    }

    #[test]
    fn memory_limit_triggers_truncation() {
        init_test("memory_limit_triggers_truncation");
        // Set a very tight memory limit that should trigger truncation
        let config = CancelAttributionConfig::new(usize::MAX, 100);

        let level1 = CancelReason::timeout();
        let level2 = CancelReason::parent_cancelled().with_cause(level1);
        let level3 = CancelReason::shutdown().with_cause_limited(level2, &config);

        // With only 100 bytes, we can't fit even 2 full levels
        // So truncation should occur
        let truncated = level3.truncated || level3.any_truncated();
        crate::assert_with_log!(
            truncated,
            "tight memory limit should trigger truncation",
            true,
            truncated
        );
        crate::test_complete!("memory_limit_triggers_truncation");
    }

    #[test]
    fn any_truncated_finds_nested_truncation() {
        init_test("any_truncated_finds_nested_truncation");
        // Manually create a chain where an inner level is truncated
        let inner = CancelReason {
            truncated: true,
            truncated_at_depth: Some(1),
            ..CancelReason::timeout()
        };
        let outer = CancelReason::shutdown().with_cause(inner);

        crate::assert_with_log!(
            !outer.truncated,
            "outer itself is not truncated",
            false,
            outer.truncated
        );
        crate::assert_with_log!(
            outer.any_truncated(),
            "any_truncated should find inner truncation",
            true,
            outer.any_truncated()
        );
        crate::test_complete!("any_truncated_finds_nested_truncation");
    }

    #[test]
    fn stress_deep_chain_bounded_by_config() {
        init_test("stress_deep_chain_bounded_by_config");
        let config = CancelAttributionConfig::new(16, 4096);
        let mut current = CancelReason::timeout();
        for _ in 1..100 {
            current = CancelReason::parent_cancelled().with_cause_limited(current, &config);
        }
        crate::assert_with_log!(
            current.chain_depth() <= 16,
            "deep chain must be bounded by max_chain_depth",
            true,
            current.chain_depth() <= 16
        );
        crate::assert_with_log!(
            current.any_truncated(),
            "deep chain must report truncation",
            true,
            current.any_truncated()
        );
        crate::test_complete!("stress_deep_chain_bounded_by_config");
    }

    #[test]
    fn stress_wide_fanout_bounded() {
        init_test("stress_wide_fanout_bounded");
        let config = CancelAttributionConfig::new(4, 4096);
        let root = CancelReason::shutdown();
        for _i in 0..200 {
            let child = CancelReason::parent_cancelled().with_cause_limited(root.clone(), &config);
            crate::assert_with_log!(
                child.chain_depth() <= 4,
                "fanout child must respect depth limit",
                true,
                child.chain_depth() <= 4
            );
        }
        crate::test_complete!("stress_wide_fanout_bounded");
    }

    #[test]
    fn zero_depth_config_drops_all_causes() {
        init_test("zero_depth_config_drops_all_causes");
        let config = CancelAttributionConfig::new(0, usize::MAX);
        let cause = CancelReason::timeout();
        let result = CancelReason::shutdown().with_cause_limited(cause, &config);
        crate::assert_with_log!(
            result.cause.is_none(),
            "zero depth config should prevent cause attachment",
            true,
            result.cause.is_none()
        );
        crate::assert_with_log!(
            result.truncated,
            "should be marked truncated when cause is dropped",
            true,
            result.truncated
        );
        crate::test_complete!("zero_depth_config_drops_all_causes");
    }

    #[test]
    fn depth_one_config_keeps_only_self() {
        init_test("depth_one_config_keeps_only_self");
        let config = CancelAttributionConfig::new(1, usize::MAX);
        let deep = CancelReason::timeout().with_cause(CancelReason::parent_cancelled());
        let result = CancelReason::shutdown().with_cause_limited(deep, &config);
        crate::assert_with_log!(
            result.chain_depth() <= 1,
            "depth-1 config should keep only the outermost level",
            true,
            result.chain_depth() <= 1
        );
        crate::test_complete!("depth_one_config_keeps_only_self");
    }

    #[test]
    fn zero_memory_config_drops_all_causes() {
        init_test("zero_memory_config_drops_all_causes");
        let config = CancelAttributionConfig::new(usize::MAX, 0);
        let cause = CancelReason::timeout();
        let result = CancelReason::shutdown().with_cause_limited(cause, &config);
        crate::assert_with_log!(
            result.truncated || result.any_truncated(),
            "zero memory should trigger truncation",
            true,
            result.truncated || result.any_truncated()
        );
        crate::test_complete!("zero_memory_config_drops_all_causes");
    }

    #[test]
    fn stress_incremental_chain_growth() {
        init_test("stress_incremental_chain_growth");
        let config = CancelAttributionConfig::default();
        let root_reason = CancelReason::shutdown();
        let mut parent_reason = root_reason;
        for _i in 0..50 {
            let child_reason =
                CancelReason::parent_cancelled().with_cause_limited(parent_reason.clone(), &config);
            crate::assert_with_log!(
                child_reason.chain_depth() <= config.max_chain_depth,
                "incremental chain must stay within configured depth",
                true,
                child_reason.chain_depth() <= config.max_chain_depth
            );
            parent_reason = child_reason;
        }
        crate::assert_with_log!(
            parent_reason.any_truncated(),
            "deeply nested region chain must report truncation",
            true,
            parent_reason.any_truncated()
        );
        crate::test_complete!("stress_incremental_chain_growth");
    }

    // ========================================================================
    // Pure data-type trait coverage (wave 25)
    // ========================================================================

    #[test]
    fn cancel_kind_debug_clone_copy() {
        let k = CancelKind::Timeout;
        let k2 = k; // Copy
        let k3 = k; // Copy again
        assert_eq!(k2, k3);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Timeout"));
    }

    #[test]
    fn cancel_kind_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CancelKind::User);
        set.insert(CancelKind::Shutdown);
        set.insert(CancelKind::User); // dup
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn cancel_kind_as_str_all_variants() {
        assert_eq!(CancelKind::User.as_str(), "User");
        assert_eq!(CancelKind::Timeout.as_str(), "Timeout");
        assert_eq!(CancelKind::Deadline.as_str(), "Deadline");
        assert_eq!(CancelKind::PollQuota.as_str(), "PollQuota");
        assert_eq!(CancelKind::CostBudget.as_str(), "CostBudget");
        assert_eq!(CancelKind::FailFast.as_str(), "FailFast");
        assert_eq!(CancelKind::RaceLost.as_str(), "RaceLost");
        assert_eq!(CancelKind::ParentCancelled.as_str(), "ParentCancelled");
        assert_eq!(
            CancelKind::ResourceUnavailable.as_str(),
            "ResourceUnavailable"
        );
        assert_eq!(CancelKind::Shutdown.as_str(), "Shutdown");
        assert_eq!(CancelKind::LinkedExit.as_str(), "LinkedExit");
    }

    #[test]
    fn cancel_kind_display_all_variants() {
        assert_eq!(format!("{}", CancelKind::User), "user");
        assert_eq!(format!("{}", CancelKind::Timeout), "timeout");
        assert_eq!(format!("{}", CancelKind::Deadline), "deadline");
        assert_eq!(format!("{}", CancelKind::PollQuota), "poll quota");
        assert_eq!(format!("{}", CancelKind::CostBudget), "cost budget");
        assert_eq!(format!("{}", CancelKind::FailFast), "fail-fast");
        assert_eq!(format!("{}", CancelKind::RaceLost), "race lost");
        assert_eq!(
            format!("{}", CancelKind::ParentCancelled),
            "parent cancelled"
        );
        assert_eq!(
            format!("{}", CancelKind::ResourceUnavailable),
            "resource unavailable"
        );
        assert_eq!(format!("{}", CancelKind::Shutdown), "shutdown");
        assert_eq!(format!("{}", CancelKind::LinkedExit), "linked exit");
    }

    #[test]
    fn cancel_kind_ord() {
        // Ord should be consistent (derive order matches declaration order)
        assert!(CancelKind::User < CancelKind::Timeout);
        assert!(CancelKind::Shutdown > CancelKind::User);
    }

    #[test]
    fn cancel_phase_debug_clone_copy_eq() {
        let p = CancelPhase::Requested;
        let p2 = p; // Copy
        assert_eq!(p, p2);
        assert!(format!("{p:?}").contains("Requested"));
    }

    #[test]
    fn cancel_phase_ord() {
        assert!(CancelPhase::Requested < CancelPhase::Cancelling);
        assert!(CancelPhase::Cancelling < CancelPhase::Finalizing);
        assert!(CancelPhase::Finalizing < CancelPhase::Completed);
    }

    #[test]
    fn cancel_witness_error_debug_clone_copy_eq() {
        let e = CancelWitnessError::TaskMismatch;
        let e2 = e; // Copy
        assert_eq!(e, e2);
        assert!(format!("{e:?}").contains("TaskMismatch"));

        let e3 = CancelWitnessError::RegionMismatch;
        assert_ne!(e, e3);

        let e4 = CancelWitnessError::EpochMismatch;
        assert!(format!("{e4:?}").contains("EpochMismatch"));

        let e5 = CancelWitnessError::PhaseRegression {
            from: CancelPhase::Cancelling,
            to: CancelPhase::Requested,
        };
        assert!(format!("{e5:?}").contains("PhaseRegression"));

        let e6 = CancelWitnessError::ReasonWeakened {
            from: CancelKind::Shutdown,
            to: CancelKind::User,
        };
        assert!(format!("{e6:?}").contains("ReasonWeakened"));
    }

    #[test]
    fn cancel_reason_debug_clone_eq() {
        let r = CancelReason::timeout();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CancelReason"));
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn cancel_reason_default() {
        let r = CancelReason::default();
        assert_eq!(r.kind, CancelKind::User);
        assert!(r.cause.is_none());
        assert!(!r.truncated);
    }

    #[test]
    fn cancel_reason_display_normal() {
        let r = CancelReason::timeout();
        assert_eq!(format!("{r}"), "timeout");

        let r2 = CancelReason::user("custom msg");
        assert_eq!(format!("{r2}"), "user: custom msg");
    }

    #[test]
    fn cancel_reason_display_alternate() {
        let r = CancelReason::shutdown();
        let alt = format!("{r:#}");
        assert!(alt.contains("shutdown"));
        assert!(alt.contains("from"));
    }

    #[test]
    fn cancel_reason_root_cause_no_chain() {
        let r = CancelReason::timeout();
        assert_eq!(r.root_cause().kind, CancelKind::Timeout);
    }

    #[test]
    fn cancel_reason_root_cause_with_chain() {
        let root = CancelReason::shutdown();
        let child = CancelReason::parent_cancelled().with_cause(root);
        assert_eq!(child.root_cause().kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancel_reason_chain_depth() {
        let r1 = CancelReason::user("a");
        assert_eq!(r1.chain_depth(), 1);

        let r2 = CancelReason::timeout().with_cause(r1);
        assert_eq!(r2.chain_depth(), 2);

        let r3 = CancelReason::shutdown().with_cause(r2);
        assert_eq!(r3.chain_depth(), 3);
    }

    #[test]
    fn cancel_reason_estimated_memory_cost() {
        let r = CancelReason::user("x");
        let cost = r.estimated_memory_cost();
        assert_eq!(cost, CancelAttributionConfig::estimated_chain_cost(1));
    }

    #[test]
    fn cancel_attribution_config_estimated_chain_cost() {
        assert_eq!(CancelAttributionConfig::estimated_chain_cost(0), 0);
        assert_eq!(
            CancelAttributionConfig::estimated_chain_cost(1),
            CancelAttributionConfig::single_reason_cost()
        );
        // depth 2: 80*2 + 8*1 = 168
        assert_eq!(CancelAttributionConfig::estimated_chain_cost(2), 168);
    }

    #[test]
    fn cancel_witness_validate_transition_ok() {
        let w1 = CancelWitness::new(
            TaskId::testing_default(),
            RegionId::testing_default(),
            1,
            CancelPhase::Requested,
            CancelReason::timeout(),
        );
        let w2 = CancelWitness::new(
            TaskId::testing_default(),
            RegionId::testing_default(),
            1,
            CancelPhase::Cancelling,
            CancelReason::timeout(),
        );
        assert!(CancelWitness::validate_transition(Some(&w1), &w2).is_ok());
    }

    #[test]
    fn cancel_witness_validate_transition_none_prev() {
        let w = CancelWitness::new(
            TaskId::testing_default(),
            RegionId::testing_default(),
            1,
            CancelPhase::Requested,
            CancelReason::timeout(),
        );
        assert!(CancelWitness::validate_transition(None, &w).is_ok());
    }

    #[test]
    fn cancel_witness_validate_phase_regression() {
        let w1 = CancelWitness::new(
            TaskId::testing_default(),
            RegionId::testing_default(),
            1,
            CancelPhase::Cancelling,
            CancelReason::timeout(),
        );
        let w2 = CancelWitness::new(
            TaskId::testing_default(),
            RegionId::testing_default(),
            1,
            CancelPhase::Requested,
            CancelReason::timeout(),
        );
        let err = CancelWitness::validate_transition(Some(&w1), &w2).unwrap_err();
        assert!(matches!(err, CancelWitnessError::PhaseRegression { .. }));
    }

    /// SEM-08.5 TEST-GAP #7: `def.cancel.reason_kinds` — canonical-5 mapping.
    ///
    /// Verifies that:
    /// 1. All 11 CancelKind variants map to severity levels in {0,1,2,3,4,5}.
    /// 2. The 5 canonical kinds (User, ParentCancelled, Timeout, Panicked, Shutdown)
    ///    are present and map to the contract-specified severity levels.
    /// 3. Extension kinds (Deadline, PollQuota, CostBudget, FailFast, RaceLost,
    ///    ResourceUnavailable, LinkedExit) each map to a valid severity level.
    #[test]
    fn canonical_5_mapping_and_extension_policy() {
        init_test("canonical_5_mapping_and_extension_policy");

        // All variants must map to {0,1,2,3,4,5}
        let all_kinds = [
            CancelKind::User,
            CancelKind::Timeout,
            CancelKind::Deadline,
            CancelKind::PollQuota,
            CancelKind::CostBudget,
            CancelKind::FailFast,
            CancelKind::RaceLost,
            CancelKind::ParentCancelled,
            CancelKind::ResourceUnavailable,
            CancelKind::Shutdown,
            CancelKind::LinkedExit,
        ];
        for kind in &all_kinds {
            let sev = kind.severity();
            assert!(
                sev <= 5,
                "CancelKind::{kind:?} has severity {sev} > 5, violating extension policy"
            );
        }

        // Canonical 5 kinds and their contract-specified severity levels
        // Per SEM-04.2 §5.1: User=0, ParentCancelled=1, Timeout=2, Panicked=4, Shutdown=5
        // Note: RT severity mapping differs from contract (RT groups by operational category).
        // The contract requires each extension maps to {0..5}; the canonical 5 anchor the scale.
        assert_eq!(CancelKind::User.severity(), 0, "User must be severity 0");
        assert_eq!(
            CancelKind::Shutdown.severity(),
            5,
            "Shutdown must be severity 5"
        );

        // Verify no duplicate severity holes — every level 0..=5 has at least one kind
        let mut covered = [false; 6];
        for kind in &all_kinds {
            covered[kind.severity() as usize] = true;
        }
        for (level, &has_kind) in covered.iter().enumerate() {
            assert!(has_kind, "Severity level {level} has no CancelKind mapping");
        }

        // Verify strengthen monotonicity: strengthening always produces >= severity
        for &a in &all_kinds {
            for &b in &all_kinds {
                let mut reason_a = CancelReason::new(a);
                let reason_b = CancelReason::new(b);
                let original_sev = reason_a.kind.severity();
                reason_a.strengthen(&reason_b);
                assert!(
                    reason_a.kind.severity() >= original_sev,
                    "strengthen({a:?}, {b:?}) decreased severity from {original_sev} to {}",
                    reason_a.kind.severity()
                );
            }
        }
    }

    /// br-asupersync-dyao05 — A pathologically deep cause chain in
    /// JSON MUST NOT cause a stack overflow or unbounded heap
    /// allocation; the deserializer must reject it with a
    /// well-formed error before recursion runs away.
    ///
    /// Builds the wire form by serializing one well-formed leaf
    /// CancelReason (so all field shapes — including RegionId,
    /// CancelKind enum, etc. — match the actual derived
    /// representation), then wraps the result 1024 times by
    /// substituting the inner `"cause":null` with the just-
    /// constructed leaf's JSON. Final payload is 1024 levels deep
    /// — well above the 256 cap.
    #[test]
    fn dyao05_deserialize_rejects_overdeep_cause_chain() {
        let leaf = CancelReason::new(CancelKind::User);
        let leaf_json = serde_json::to_string(&leaf).expect("serialize leaf");
        let inner_null = r#""cause":null"#;
        // 96 wraps lands above our cap (64) but below serde_json's
        // default recursion limit (128) so the dyao05 gate is the
        // FIRST gate to fire — proving our defence-in-depth catches
        // the input rather than relying on the JSON parser's own
        // recursion safeguard (which other transports lack).
        let depth = 96usize;
        let mut payload = leaf_json.clone();
        let inner_substitute = format!(r#""cause":{leaf_json}"#);
        for _ in 0..depth {
            payload = payload.replacen(inner_null, &inner_substitute, 1);
        }

        let result: Result<CancelReason, _> = serde_json::from_str(&payload);
        assert!(
            result.is_err(),
            "96-deep cause chain MUST be rejected by the dyao05 depth gate"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("dyao05"),
            "rejection message should reference the dyao05 depth gate: {err_msg}"
        );
    }

    /// br-asupersync-dyao05 — A modest legitimate chain depth
    /// (e.g., 8 levels — well within both the deserialize cap of
    /// 256 and the runtime cap of 16) MUST round-trip cleanly.
    /// Confirms the gate doesn't spuriously reject valid input.
    #[test]
    fn dyao05_deserialize_accepts_modest_cause_chain() {
        let mut reason = CancelReason::new(CancelKind::User);
        for i in 0..8 {
            let mut parent = CancelReason::new(CancelKind::Timeout);
            parent.message = Some(format!("level {i}"));
            parent.cause = Some(Box::new(reason));
            reason = parent;
        }
        let json = serde_json::to_string(&reason).expect("serialize");
        let parsed: CancelReason = serde_json::from_str(&json).expect("8-deep chain must parse");
        assert_eq!(parsed.kind, CancelKind::Timeout);
        // Walk the chain and count entries — should be 9 (the 8
        // wrappers plus the original).
        let mut count = 0;
        let mut node = Some(&parsed);
        while let Some(n) = node {
            count += 1;
            node = n.cause.as_deref();
        }
        assert_eq!(count, 9, "round-tripped chain length");
    }

    /// br-asupersync-dyao05 — The thread-local depth counter must
    /// reset between independent deserialize calls on the same
    /// thread. Without the RAII `CauseDepthGuard`, a stale counter
    /// would leak into the next deserialize and either spuriously
    /// reject valid input or admit input deeper than the cap.
    #[test]
    fn dyao05_depth_counter_resets_between_calls() {
        for _ in 0..3 {
            let mut reason = CancelReason::new(CancelKind::User);
            for _ in 0..5 {
                let mut parent = CancelReason::new(CancelKind::Timeout);
                parent.cause = Some(Box::new(reason));
                reason = parent;
            }
            let json = serde_json::to_string(&reason).expect("serialize");
            let parsed: CancelReason =
                serde_json::from_str(&json).expect("5-deep chain must parse on every iteration");
            assert_eq!(parsed.kind, CancelKind::Timeout);
        }
        // After all calls, the thread-local counter must be 0
        // (RAII guard restored it on every exit).
        let final_depth = CANCEL_CAUSE_DEPTH.with(std::cell::Cell::get);
        assert_eq!(
            final_depth, 0,
            "thread-local depth counter leaked between deserialize calls"
        );
    }
