    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::TaskId;
    use crate::util::ArenaIndex;

    fn actor(n: u32) -> ActorId {
        ActorId::from_task(TaskId::from_arena(ArenaIndex::new(n, 0)))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // ActorLeakOracle tests
    mod actor_leak {
        use super::*;

        #[test]
        fn no_actors_passes() {
            init_test("no_actors_passes");
            let oracle = ActorLeakOracle::new();
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("no_actors_passes");
        }

        #[test]
        fn all_actors_stopped_passes() {
            init_test("all_actors_stopped_passes");
            let mut oracle = ActorLeakOracle::new();

            oracle.on_spawn(actor(1), region(0), t(10));
            oracle.on_spawn(actor(2), region(0), t(20));

            oracle.on_stop(actor(1), t(50));
            oracle.on_stop(actor(2), t(60));

            oracle.on_region_close(region(0), t(100));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("all_actors_stopped_passes");
        }

        #[test]
        fn leaked_actor_fails() {
            init_test("leaked_actor_fails");
            let mut oracle = ActorLeakOracle::new();

            oracle.on_spawn(actor(1), region(0), t(10));
            oracle.on_spawn(actor(2), region(0), t(20));

            // Only actor 1 stops
            oracle.on_stop(actor(1), t(50));

            oracle.on_region_close(region(0), t(100));

            let result = oracle.check(t(100));
            let err = result.is_err();
            crate::assert_with_log!(err, "err", true, err);

            let violation = result.unwrap_err();
            crate::assert_with_log!(
                violation.region == region(0),
                "region",
                region(0),
                violation.region
            );
            crate::assert_with_log!(
                violation.leaked_actors == vec![actor(2)],
                "leaked_actors",
                vec![actor(2)],
                violation.leaked_actors
            );
            crate::test_complete!("leaked_actor_fails");
        }

        #[test]
        fn reset_clears_state() {
            init_test("reset_clears_state");
            let mut oracle = ActorLeakOracle::new();

            oracle.on_spawn(actor(1), region(0), t(10));
            oracle.on_region_close(region(0), t(100));

            // Would fail
            let err = oracle.check(t(100)).is_err();
            crate::assert_with_log!(err, "err", true, err);

            oracle.reset();

            // After reset, no violations
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("reset_clears_state");
        }
    }

    // SupervisionOracle tests
    mod supervision {
        use super::*;

        #[test]
        fn no_failures_passes() {
            init_test("no_failures_passes");
            let oracle = SupervisionOracle::new();
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("no_failures_passes");
        }

        #[test]
        fn restart_within_limit_passes() {
            init_test("restart_within_limit_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForOne,
                3,
                EscalationPolicy::Escalate,
            );
            oracle.register_child(actor(0), actor(1));

            oracle.on_child_failed(actor(0), actor(1), t(10), "error".into());
            oracle.on_restart(actor(1), 1, t(20));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("restart_within_limit_passes");
        }

        #[test]
        fn restart_limit_escalation_from_supervisor_passes() {
            init_test("restart_limit_escalation_from_supervisor_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForOne,
                1,
                EscalationPolicy::Escalate,
            );
            oracle.register_child(actor(0), actor(1));

            oracle.on_child_failed(actor(0), actor(1), t(10), "error".into());
            oracle.on_restart(actor(1), 2, t(20));
            oracle.on_escalation(actor(0), actor(9), t(30), "restart limit".into());

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("restart_limit_escalation_from_supervisor_passes");
        }

        #[test]
        fn later_escalation_does_not_mask_prior_one_for_all_violation() {
            init_test("later_escalation_does_not_mask_prior_one_for_all_violation");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForAll,
                1,
                EscalationPolicy::Escalate,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));

            // First failure violates OneForAll because siblings never restart.
            oracle.on_child_failed(actor(0), actor(2), t(10), "first failure".into());
            oracle.on_restart(actor(2), 1, t(20));

            // A later restart-limit escalation from the same supervisor must not
            // whitewash the earlier sibling-restart violation.
            oracle.on_child_failed(actor(0), actor(3), t(30), "second failure".into());
            oracle.on_restart(actor(3), 2, t(40));
            oracle.on_escalation(actor(0), actor(9), t(50), "restart limit".into());

            let violation = oracle
                .check(t(100))
                .expect_err("earlier OneForAll violation must still surface");
            let kind_matches = matches!(
                violation.kind,
                SupervisionViolationKind::OneForAllNotFollowed {
                    failed_actor,
                    ref unrestarted_siblings,
                } if failed_actor == actor(2)
                    && unrestarted_siblings == &vec![actor(1), actor(3)]
            );
            crate::assert_with_log!(
                kind_matches,
                "kind_matches",
                true,
                format!("{:?}", violation.kind)
            );
            crate::test_complete!("later_escalation_does_not_mask_prior_one_for_all_violation");
        }

        #[test]
        fn later_restart_does_not_mask_prior_rest_for_one_violation() {
            init_test("later_restart_does_not_mask_prior_rest_for_one_violation");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::RestForOne,
                2,
                EscalationPolicy::Stop,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));
            oracle.register_child(actor(0), actor(4));

            // First failure requires actors 3 and 4 to restart before any later
            // child failure is processed by the same supervisor.
            oracle.on_child_failed(actor(0), actor(2), t(10), "first failure".into());
            oracle.on_restart(actor(2), 1, t(20));

            // Actor 4 restarts only because it fails later itself; that must not
            // satisfy the earlier RestForOne obligation for actor 2's failure.
            oracle.on_child_failed(actor(0), actor(4), t(30), "second failure".into());
            oracle.on_restart(actor(4), 1, t(40));

            let violation = oracle
                .check(t(100))
                .expect_err("earlier RestForOne violation must still surface");
            let kind_matches = matches!(
                violation.kind,
                SupervisionViolationKind::RestForOneNotFollowed {
                    failed_actor,
                    ref unrestarted_successors,
                } if failed_actor == actor(2)
                    && unrestarted_successors == &vec![actor(3), actor(4)]
            );
            crate::assert_with_log!(
                kind_matches,
                "kind_matches",
                true,
                format!("{:?}", violation.kind)
            );
            crate::test_complete!("later_restart_does_not_mask_prior_rest_for_one_violation");
        }

        // br-asupersync-l7ni1s: regression for the
        // `if escalated { continue }` short-circuit. Previously, *any*
        // escalation that landed inside a failure's window made the
        // oracle skip that failure's sibling-restart check entirely,
        // even when the failure's own restart_count was still under
        // budget and the sibling-restart obligation was unmet. This
        // test wires up exactly that situation: F1 has 1 of 2 allowed
        // restarts (under budget), siblings are never restarted, and
        // an unrelated escalation lands inside F1's window. The fixed
        // oracle must still surface OneForAllNotFollowed for F1.
        #[test]
        fn escalation_inside_window_does_not_mask_one_for_all_violation_l7ni1s() {
            init_test("escalation_inside_window_does_not_mask_one_for_all_violation_l7ni1s");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForAll,
                2, // generous budget so restart_count <= max_restarts
                EscalationPolicy::Escalate,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));

            // F1: child 2 fails at t=10. Window is [10, 20) because F2
            // closes it. Restart child 2 alone (siblings 1 and 3
            // never restart) — a OneForAll violation.
            oracle.on_child_failed(actor(0), actor(2), t(10), "F1".into());
            oracle.on_restart(actor(2), 1, t(12));

            // Unrelated escalation lands inside F1's window. Under the
            // pre-fix logic this caused the oracle to short-circuit the
            // OneForAll check for F1 and silently accept the violation.
            oracle.on_escalation(actor(0), actor(9), t(15), "unrelated".into());

            // F2 closes F1's window. F2 is properly handled (just child
            // 3 restarting itself; we don't care about F2's own
            // OneForAll for this test — F1's violation must surface
            // first because the loop iterates failures in order).
            oracle.on_child_failed(actor(0), actor(3), t(20), "F2".into());
            oracle.on_restart(actor(1), 1, t(22));
            oracle.on_restart(actor(2), 2, t(22));
            oracle.on_restart(actor(3), 1, t(22));

            let violation = oracle
                .check(t(100))
                .expect_err("OneForAll violation for F1 must surface despite escalation in window");
            let kind_matches = matches!(
                violation.kind,
                SupervisionViolationKind::OneForAllNotFollowed {
                    failed_actor,
                    ref unrestarted_siblings,
                } if failed_actor == actor(2)
                    && unrestarted_siblings == &vec![actor(1), actor(3)]
            );
            crate::assert_with_log!(
                kind_matches,
                "kind_matches",
                true,
                format!("{:?}", violation.kind)
            );
            crate::test_complete!(
                "escalation_inside_window_does_not_mask_one_for_all_violation_l7ni1s"
            );
        }

        // br-asupersync-l7ni1s: same regression for RestForOne. An
        // escalation inside the window must not mask the missing
        // successor-restart obligation when the failure itself is
        // under restart-budget.
        #[test]
        fn escalation_inside_window_does_not_mask_rest_for_one_violation_l7ni1s() {
            init_test("escalation_inside_window_does_not_mask_rest_for_one_violation_l7ni1s");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::RestForOne,
                2, // generous budget
                EscalationPolicy::Escalate,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));
            oracle.register_child(actor(0), actor(4));

            // F1: child 2 fails at t=10. Window [10, 30). Successors of
            // 2 are [3, 4]. Only child 2 itself is restarted; the
            // RestForOne obligation for [3, 4] is unmet.
            oracle.on_child_failed(actor(0), actor(2), t(10), "F1".into());
            oracle.on_restart(actor(2), 1, t(12));

            // Escalation inside F1's window. Pre-fix, this short-
            // circuited the RestForOne check.
            oracle.on_escalation(actor(0), actor(9), t(20), "unrelated".into());

            // Close F1's window with a downstream failure that's
            // properly handled (restart 4 + its successors — none).
            oracle.on_child_failed(actor(0), actor(4), t(30), "F2".into());
            oracle.on_restart(actor(4), 1, t(32));

            let violation = oracle.check(t(100)).expect_err(
                "RestForOne violation for F1 must surface despite escalation in window",
            );
            let kind_matches = matches!(
                violation.kind,
                SupervisionViolationKind::RestForOneNotFollowed {
                    failed_actor,
                    ref unrestarted_successors,
                } if failed_actor == actor(2)
                    && unrestarted_successors == &vec![actor(3), actor(4)]
            );
            crate::assert_with_log!(
                kind_matches,
                "kind_matches",
                true,
                format!("{:?}", violation.kind)
            );
            crate::test_complete!(
                "escalation_inside_window_does_not_mask_rest_for_one_violation_l7ni1s"
            );
        }

        #[test]
        fn one_for_all_siblings_restarted_passes() {
            init_test("one_for_all_siblings_restarted_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForAll,
                3,
                EscalationPolicy::Stop,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));

            // Actor 2 fails
            oracle.on_child_failed(actor(0), actor(2), t(10), "error".into());

            // All siblings restart (including the failed one)
            oracle.on_restart(actor(1), 1, t(20));
            oracle.on_restart(actor(2), 1, t(20));
            oracle.on_restart(actor(3), 1, t(20));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("one_for_all_siblings_restarted_passes");
        }

        #[test]
        fn rest_for_one_successors_restarted_passes() {
            init_test("rest_for_one_successors_restarted_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::RestForOne,
                3,
                EscalationPolicy::Stop,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));

            // Actor 2 fails - actors 2 and 3 should restart
            oracle.on_child_failed(actor(0), actor(2), t(10), "error".into());
            oracle.on_restart(actor(2), 1, t(20));
            oracle.on_restart(actor(3), 1, t(20));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("rest_for_one_successors_restarted_passes");
        }

        #[test]
        fn reset_clears_state() {
            init_test("supervision_reset_clears_state");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForOne,
                1,
                EscalationPolicy::Escalate,
            );
            oracle.on_child_failed(actor(0), actor(1), t(10), "error".into());

            oracle.reset();

            let count = oracle.failure_count();
            crate::assert_with_log!(count == 0, "failure_count", 0, count);
            crate::test_complete!("supervision_reset_clears_state");
        }
    }

    // MailboxOracle tests
    mod mailbox {
        use super::*;

        #[test]
        fn no_messages_passes() {
            init_test("no_messages_passes");
            let oracle = MailboxOracle::new();
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("no_messages_passes");
        }

        #[test]
        fn balanced_send_receive_passes() {
            init_test("balanced_send_receive_passes");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);

            oracle.on_send(actor(1), t(10));
            oracle.on_send(actor(1), t(20));
            oracle.on_receive(actor(1), t(30));
            oracle.on_receive(actor(1), t(40));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("balanced_send_receive_passes");
        }

        #[test]
        fn capacity_exceeded_fails() {
            init_test("capacity_exceeded_fails");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 2, false);

            oracle.on_send(actor(1), t(10));
            oracle.on_send(actor(1), t(20));
            oracle.on_send(actor(1), t(30)); // Exceeds capacity

            let result = oracle.check(t(100));
            let err = result.is_err();
            crate::assert_with_log!(err, "err", true, err);
            crate::test_complete!("capacity_exceeded_fails");
        }

        #[test]
        fn tracks_high_water_mark() {
            init_test("tracks_high_water_mark");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);

            oracle.on_send(actor(1), t(10));
            oracle.on_send(actor(1), t(20));
            oracle.on_send(actor(1), t(30));
            oracle.on_receive(actor(1), t(40));
            oracle.on_receive(actor(1), t(50));
            oracle.on_receive(actor(1), t(60));

            let stats = oracle.stats(actor(1));
            let hwm = stats.map_or(0, |(_, _, h)| h);
            crate::assert_with_log!(hwm == 3, "high_water_mark", 3, hwm);
            crate::test_complete!("tracks_high_water_mark");
        }

        #[test]
        fn reset_clears_state() {
            init_test("mailbox_reset_clears_state");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);
            oracle.on_send(actor(1), t(10));

            oracle.reset();

            let count = oracle.mailbox_count();
            crate::assert_with_log!(count == 0, "mailbox_count", 0, count);
            crate::test_complete!("mailbox_reset_clears_state");
        }

        #[test]
        fn stopped_with_pending_messages_fails() {
            init_test("stopped_with_pending_messages_fails");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);
            oracle.on_send(actor(1), t(10));
            oracle.on_stop(actor(1), t(20));

            let result = oracle.check(t(100));
            let err = result.is_err();
            crate::assert_with_log!(err, "err", true, err);

            let violation = result.unwrap_err();
            match violation.kind {
                MailboxViolationKind::MessageLost { sent, received } => {
                    crate::assert_with_log!(sent == 1, "sent", 1, sent);
                    crate::assert_with_log!(received == 0, "received", 0, received);
                }
                other => {
                    crate::assert_with_log!(false, "kind", "MessageLost", other);
                }
            }

            crate::test_complete!("stopped_with_pending_messages_fails");
        }
    }
