    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::policy::{CollectAll, FailFast};
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum JoinCase {
        Ok(i32),
        Err,
        CancelUser,
        CancelTimeout,
        CancelShutdown,
        Panic,
    }

    impl JoinCase {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Ok(value) => Outcome::Ok(value),
                Self::Err => Outcome::Err("err"),
                Self::CancelUser => Outcome::Cancelled(CancelReason::user("user")),
                Self::CancelTimeout => Outcome::Cancelled(CancelReason::timeout()),
                Self::CancelShutdown => Outcome::Cancelled(CancelReason::shutdown()),
                Self::Panic => Outcome::Panicked(PanicPayload::new("boom")),
            }
        }
    }

    fn join_case_strategy() -> impl Strategy<Value = JoinCase> {
        prop_oneof![
            any::<i16>().prop_map(|value| JoinCase::Ok(i32::from(value))),
            Just(JoinCase::Err),
            Just(JoinCase::CancelUser),
            Just(JoinCase::CancelTimeout),
            Just(JoinCase::CancelShutdown),
            Just(JoinCase::Panic),
        ]
    }

    fn decision_signature(
        decision: &AggregateDecision<&'static str>,
    ) -> (&'static str, Option<u8>) {
        match decision {
            AggregateDecision::AllOk => ("ok", None),
            AggregateDecision::FirstError(_) => ("err", None),
            AggregateDecision::Cancelled(reason) => ("cancelled", Some(reason.severity())),
            AggregateDecision::Panicked { .. } => ("panic", None),
        }
    }

    #[test]
    fn join2_both_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_ok());
        assert!(v1.is_none()); // Values are in the result tuple
        assert!(v2.is_none());
        if let Outcome::Ok((a, b)) = result {
            assert_eq!(a, 1);
            assert_eq!(b, 2);
        }
    }

    #[test]
    fn join2_first_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("error1");
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_err());
        assert!(v1.is_none());
        assert_eq!(v2, Some(2)); // Second value preserved
    }

    #[test]
    fn join2_second_err() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Err("error2");
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_err());
        assert_eq!(v1, Some(1)); // First value preserved
        assert!(v2.is_none());
    }

    #[test]
    fn join2_cancelled_over_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("error");
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let (result, _, _) = join2_outcomes(o1, o2);

        assert!(result.is_cancelled());
    }

    #[test]
    fn join2_panic_over_cancelled() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let o2: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("boom"));
        let (result, _, _) = join2_outcomes(o1, o2);

        assert!(result.is_panicked());
    }

    #[test]
    fn join_all_all_ok() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let (decision, successes) = join_all_outcomes(outcomes);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(successes.len(), 3);
        assert_eq!(successes[0], (0, 1));
        assert_eq!(successes[1], (1, 2));
        assert_eq!(successes[2], (2, 3));
    }

    #[test]
    fn join_all_one_err() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("error"), Outcome::Ok(3)];
        let (decision, successes) = join_all_outcomes(outcomes);

        assert!(matches!(decision, AggregateDecision::FirstError(_)));
        assert_eq!(successes.len(), 2);
        assert_eq!(successes[0], (0, 1));
        assert_eq!(successes[1], (2, 3));
    }

    #[test]
    fn join_all_panic_collects_all_successes() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let (decision, successes) = join_all_outcomes(outcomes);

        match decision {
            AggregateDecision::Panicked {
                payload: _,
                first_panic_index,
            } => assert_eq!(first_panic_index, 1),
            _ => panic!("Expected Panicked decision"),
        }
        // All successful values collected (join waits for all branches)
        assert_eq!(successes.len(), 2);
        assert_eq!(successes[0], (0, 1));
        assert_eq!(successes[1], (2, 3));
    }

    #[test]
    fn join2_to_result_both_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let result = join2_to_result(o1, o2);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (1, 2));
    }

    #[test]
    fn join2_to_result_first_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("error1");
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let result = join2_to_result(o1, o2);

        assert!(matches!(result, Err(JoinError::First("error1"))));
    }

    #[test]
    fn join2_to_result_cancelled() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let result = join2_to_result(o1, o2);

        assert!(matches!(result, Err(JoinError::Cancelled(_))));
    }

    #[test]
    fn aggregate_with_fail_fast_policy() {
        let policy = FailFast;
        let outcomes: Vec<Outcome<(), crate::error::Error>> =
            vec![Outcome::Ok(()), Outcome::Ok(())];
        let decision = aggregate_outcomes(&policy, &outcomes);

        assert!(matches!(decision, AggregateDecision::AllOk));
    }

    #[test]
    fn aggregate_with_collect_all_policy() {
        let policy = CollectAll;
        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let outcomes = vec![Outcome::Ok(()), err];
        let decision = aggregate_outcomes(&policy, &outcomes);

        assert!(matches!(decision, AggregateDecision::FirstError(_)));
    }

    #[test]
    fn join_error_display() {
        let err: JoinError<&str> = JoinError::First("test error");
        assert!(err.to_string().contains("first branch failed"));

        let err: JoinError<&str> = JoinError::Second("test error");
        assert!(err.to_string().contains("second branch failed"));

        let err: JoinError<&str> = JoinError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: JoinError<&str> = JoinError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));
    }

    // Algebraic property tests
    #[test]
    fn join_severity_is_monotone() {
        // Severity should only increase, never decrease
        // Ok(1) join Ok(2) = Ok
        // Ok(1) join Err = Err
        // Err join Cancelled = Cancelled
        // Cancelled join Panicked = Panicked

        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("e");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("p"));

        // Each step up the lattice should produce the higher severity
        let (r1, _, _) = join2_outcomes(ok.clone(), err.clone());
        assert!(r1.severity() >= ok.severity());

        let (r2, _, _) = join2_outcomes(err.clone(), cancelled.clone());
        assert!(r2.severity() >= err.severity());

        let (r3, _, _) = join2_outcomes(cancelled.clone(), panicked.clone());
        assert!(r3.severity() >= cancelled.severity());
    }

    #[test]
    fn join_is_commutative_in_severity() {
        // join(a, b) and join(b, a) should have same severity
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("e");

        let (r1, _, _) = join2_outcomes(ok.clone(), err.clone());
        let (r2, _, _) = join2_outcomes(err, ok);

        assert_eq!(r1.severity(), r2.severity());
    }

    // ============================================================
    // JoinAll tests
    // ============================================================

    #[test]
    fn join_all_marker_is_copy() {
        let marker: JoinAll<i32> = JoinAll::new();
        let copy = marker;
        let _ = marker; // Still usable after copy
        let _ = copy;
    }

    #[test]
    fn join_all_marker_default() {
        let marker: JoinAll<i32> = JoinAll::default();
        let _ = marker;
    }

    #[test]
    fn join_all_result_all_succeed() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.failure_count(), 0);
        assert_eq!(result.total_count, 3);

        // Verify ordered values
        let ordered = result.into_ordered_values();
        assert_eq!(ordered, vec![Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn join_all_result_partial_failure() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("fail"), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);

        assert!(!result.all_succeeded());
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 1);
        assert_eq!(result.total_count, 3);

        // Verify ordered values (None for failed index)
        let ordered = result.into_ordered_values();
        assert_eq!(ordered, vec![Some(1), None, Some(3)]);
    }

    #[test]
    fn join_all_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded()); // Vacuously true
        assert_eq!(result.success_count(), 0);
        assert_eq!(result.failure_count(), 0);
        assert_eq!(result.total_count, 0);
    }

    #[test]
    fn join_all_result_single_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 1);
        let ordered = result.into_ordered_values();
        assert_eq!(ordered, vec![Some(42)]);
    }

    #[test]
    fn join_all_result_single_failure() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fail")];
        let result = make_join_all_result(outcomes);

        assert!(!result.all_succeeded());
        assert_eq!(result.success_count(), 0);
        assert_eq!(result.failure_count(), 1);
    }

    #[test]
    fn join_all_to_result_all_succeed() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);
        let values = join_all_to_result(result);

        assert!(values.is_ok());
        assert_eq!(values.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn join_all_to_result_with_error() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("middle-fail"), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);
        let err = join_all_to_result(result);

        assert!(err.is_err());
        match err.unwrap_err() {
            JoinAllError::Error {
                error,
                index,
                total_failures,
            } => {
                assert_eq!(error, "middle-fail");
                assert_eq!(index, 1); // Middle branch failed
                assert_eq!(total_failures, 1);
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[test]
    fn join_all_to_result_with_cancellation() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(3),
        ];
        let result = make_join_all_result(outcomes);
        let err = join_all_to_result(result);

        assert!(matches!(err, Err(JoinAllError::Cancelled(_))));
    }

    #[test]
    fn join_all_to_result_with_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let result = make_join_all_result(outcomes);
        let err = join_all_to_result(result);

        match err {
            Err(JoinAllError::Panicked { payload, index }) => {
                assert_eq!(payload.message(), "boom");
                assert_eq!(index, 1);
            }
            _ => panic!("Expected Panicked error"),
        }
    }

    #[test]
    fn join_all_to_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = make_join_all_result(outcomes);
        let values = join_all_to_result(result);

        assert!(values.is_ok());
        assert_eq!(values.unwrap(), Vec::<i32>::new());
    }

    #[test]
    fn join_all_error_display() {
        let err: JoinAllError<&str> = JoinAllError::Error {
            error: "test error",
            index: 2,
            total_failures: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("branch 2 failed"));
        assert!(msg.contains("test error"));
        assert!(msg.contains("3 total failures"));

        let err: JoinAllError<&str> = JoinAllError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: JoinAllError<&str> = JoinAllError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 4,
        };
        assert!(err.to_string().contains("branch 4 panicked"));
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn join_all_respects_severity_lattice() {
        // Panic > Cancel > Error > Ok
        // Test that the worst outcome is selected

        // Error + Cancel = Cancel
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Err("error"),
            Outcome::Cancelled(CancelReason::timeout()),
        ];
        let result = make_join_all_result(outcomes);
        assert!(matches!(result.decision, AggregateDecision::Cancelled(_)));

        // Cancel + Panic = Panic (panic short-circuits)
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let result = make_join_all_result(outcomes);
        match result.decision {
            AggregateDecision::Panicked {
                payload: _,
                first_panic_index,
            } => assert_eq!(first_panic_index, 1),
            _ => panic!("Expected Panicked decision"),
        }
    }

    #[test]
    fn join_all_many_branches() {
        // Test with many branches to verify scaling
        let outcomes: Vec<Outcome<i32, &str>> = (0..100).map(Outcome::Ok).collect();
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 100);

        let values = join_all_to_result(result).unwrap();
        assert_eq!(values.len(), 100);
        for (i, v) in values.iter().enumerate() {
            assert_eq!(*v, i32::try_from(i).unwrap());
        }
    }

    #[test]
    fn join_all_preserves_order_with_mixed_outcomes() {
        // Verify that successful values maintain their original indices
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(10),    // index 0
            Outcome::Err("e1"), // index 1
            Outcome::Ok(30),    // index 2
            Outcome::Err("e2"), // index 3
            Outcome::Ok(50),    // index 4
        ];
        let result = make_join_all_result(outcomes);

        assert_eq!(result.successes.len(), 3);
        assert_eq!(result.successes[0], (0, 10));
        assert_eq!(result.successes[1], (2, 30));
        assert_eq!(result.successes[2], (4, 50));
    }

    #[test]
    fn join2_both_cancelled_strengthens_to_worst_reason() {
        // Regression: join2_outcomes must use strengthen() when both branches
        // are cancelled, matching join_all_outcomes' severity lattice behavior.
        // User(severity 0) + Shutdown(severity 5) → Shutdown wins.
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_cancelled());
        assert!(v1.is_none());
        assert!(v2.is_none());
        if let Outcome::Cancelled(r) = &result {
            assert_eq!(
                r.kind(),
                crate::types::cancel::CancelKind::Shutdown,
                "join2_outcomes should strengthen to Shutdown (severity 5), not User (severity 0)"
            );
        }

        // Also test the reverse order: Shutdown + User → still Shutdown
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let (result, _, _) = join2_outcomes(o1, o2);

        if let Outcome::Cancelled(r) = &result {
            assert_eq!(
                r.kind(),
                crate::types::cancel::CancelKind::Shutdown,
                "join2_outcomes should be commutative in cancel severity"
            );
        }
    }

    #[test]
    fn join2_to_result_both_cancelled_strengthens() {
        // Same regression test for join2_to_result
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let result = join2_to_result(o1, o2);

        match result {
            Err(JoinError::Cancelled(r)) => {
                assert_eq!(
                    r.kind(),
                    crate::types::cancel::CancelKind::Shutdown,
                    "join2_to_result should strengthen to Shutdown"
                );
            }
            other => panic!("Expected Cancelled, got {other:?}"),
        }
    }

    #[test]
    fn join_all_result_debug() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = make_join_all_result(outcomes);
        let debug = format!("{result:?}");
        assert!(debug.contains("JoinAllResult"));
        assert!(debug.contains("AllOk"));
    }

    proptest! {
        #[test]
        fn metamorphic_join_all_rotation_preserves_decision_and_projection(
            cases in prop::collection::vec(join_case_strategy(), 1..12),
            raw_shift in 0usize..32,
        ) {
            let shift = raw_shift % cases.len();

            let base_result = make_join_all_result(
                cases
                    .iter()
                    .cloned()
                    .map(JoinCase::into_outcome)
                    .collect::<Vec<_>>(),
            );

            let mut rotated_cases = cases.clone();
            rotated_cases.rotate_left(shift);
            let rotated_result = make_join_all_result(
                rotated_cases
                    .iter()
                    .cloned()
                    .map(JoinCase::into_outcome)
                    .collect::<Vec<_>>(),
            );

            prop_assert_eq!(base_result.total_count, rotated_result.total_count);
            prop_assert_eq!(
                decision_signature(&base_result.decision),
                decision_signature(&rotated_result.decision),
                "rotating branch order must not change the aggregate decision class"
            );

            let mut base_success_values =
                base_result.successes.iter().map(|(_, value)| *value).collect::<Vec<_>>();
            let mut rotated_success_values = rotated_result
                .successes
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>();
            base_success_values.sort_unstable();
            rotated_success_values.sort_unstable();
            prop_assert_eq!(
                base_success_values,
                rotated_success_values,
                "rotating branch order must preserve the success multiset"
            );

            let mut expected_rotated_projection = base_result.into_ordered_values();
            expected_rotated_projection.rotate_left(shift);
            prop_assert_eq!(
                rotated_result.into_ordered_values(),
                expected_rotated_projection,
                "a quiescent join must preserve the ordered branch projection under the same rotation"
            );
        }
    }
