    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn first_ok_first_succeeds() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        let success = result.success.unwrap();
        assert_eq!(success.index, 0);
        assert_eq!(success.value, 1);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn first_ok_middle_succeeds() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(42), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        let success = result.success.unwrap();
        assert_eq!(success.index, 1);
        assert_eq!(success.value, 42);
        assert_eq!(result.failures.len(), 1); // Only first failure collected
    }

    #[test]
    fn first_ok_last_succeeds() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Err("e2"), Outcome::Ok(99)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        let success = result.success.unwrap();
        assert_eq!(success.index, 2);
        assert_eq!(success.value, 99);
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn first_ok_all_fail() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Err("e2"), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert!(result.success.is_none());
        assert_eq!(result.failures.len(), 3);
    }

    #[test]
    fn first_ok_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert_eq!(result.total, 0);
    }

    #[test]
    fn first_ok_single_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        assert_eq!(result.success.unwrap().value, 42);
    }

    #[test]
    fn first_ok_single_failure() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fail")];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert_eq!(result.failures.len(), 1);
    }

    #[test]
    fn first_ok_cancellation_stops() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(42), // Never reached
        ];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert!(result.was_cancelled);
        // The Ok at index 2 is not processed
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn first_ok_panic_stops() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(42), // Never reached
        ];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert!(result.had_panic);
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn first_ok_to_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("e1"), Outcome::Ok(42)];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_ok());
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    fn first_ok_to_result_all_failed() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("e1"), Outcome::Err("e2")];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        match value.unwrap_err() {
            FirstOkError::AllFailed { errors, attempted } => {
                assert_eq!(errors.len(), 2);
                assert_eq!(attempted, 2);
            }
            _ => panic!("Expected AllFailed"),
        }
    }

    #[test]
    fn first_ok_to_result_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Cancelled(CancelReason::timeout()),
        ];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        match value.unwrap_err() {
            FirstOkError::Cancelled {
                errors_before_cancel,
                attempted_before_cancel,
                ..
            } => {
                assert_eq!(errors_before_cancel.len(), 1);
                assert_eq!(attempted_before_cancel, 1);
            }
            _ => panic!("Expected Cancelled"),
        }
    }

    #[test]
    fn first_ok_to_result_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Panicked(PanicPayload::new("boom"))];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        assert!(matches!(value.unwrap_err(), FirstOkError::Panicked(_)));
    }

    #[test]
    fn first_ok_to_result_panic_precedes_cancel_and_errors() {
        let result: FirstOkResult<i32, &str> = FirstOkResult::failure(
            vec![
                (0, FirstOkFailure::Error("e0")),
                (1, FirstOkFailure::Cancelled(CancelReason::timeout())),
                (2, FirstOkFailure::Panicked(PanicPayload::new("boom"))),
            ],
            3,
        );

        let value = first_ok_to_result(result);
        assert!(matches!(value, Err(FirstOkError::Panicked(_))));
    }

    #[test]
    fn mr_first_ok_cancel_aggregation_ignores_later_errors() {
        let labels = ["e0", "e1", "e2", "e3"];

        for cancel_pos in 0..=labels.len() {
            let mut failures = Vec::new();
            for (index, label) in labels.iter().take(cancel_pos).enumerate() {
                failures.push((index, FirstOkFailure::Error(*label)));
            }
            failures.push((
                cancel_pos,
                FirstOkFailure::Cancelled(CancelReason::timeout()),
            ));
            for (offset, label) in labels.iter().skip(cancel_pos).enumerate() {
                failures.push((cancel_pos + 1 + offset, FirstOkFailure::Error(*label)));
            }

            let result: FirstOkResult<i32, &str> =
                FirstOkResult::failure(failures, labels.len() + 1);
            let value = first_ok_to_result(result);

            match value {
                Err(FirstOkError::Cancelled {
                    errors_before_cancel,
                    attempted_before_cancel,
                    ..
                }) => {
                    assert_eq!(attempted_before_cancel, cancel_pos);
                    assert_eq!(
                        errors_before_cancel,
                        labels[..cancel_pos],
                        "only errors before cancellation should be aggregated"
                    );
                }
                other => panic!("expected cancellation aggregate, got {other:?}"),
            }
        }
    }

    #[test]
    fn first_ok_to_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        assert!(matches!(value.unwrap_err(), FirstOkError::Empty));
    }

    #[test]
    fn first_ok_error_display() {
        let err: FirstOkError<&str> = FirstOkError::AllFailed {
            errors: vec!["e1", "e2"],
            attempted: 2,
        };
        assert!(err.to_string().contains("2 operations failed"));

        let err: FirstOkError<&str> = FirstOkError::Cancelled {
            reason: CancelReason::timeout(),
            errors_before_cancel: vec!["e1"],
            attempted_before_cancel: 2,
        };
        assert!(err.to_string().contains("cancelled"));

        let err: FirstOkError<&str> = FirstOkError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));

        let err: FirstOkError<&str> = FirstOkError::Empty;
        assert!(err.to_string().contains("no operations"));
    }

    #[test]
    fn first_ok_still_possible_test() {
        // Not cancelled, not panicked, has remaining
        assert!(first_ok_still_possible(false, false, 3));

        // Not cancelled, not panicked, no remaining
        assert!(!first_ok_still_possible(false, false, 0));

        // Cancelled
        assert!(!first_ok_still_possible(true, false, 3));

        // Panicked
        assert!(!first_ok_still_possible(false, true, 3));

        // Both
        assert!(!first_ok_still_possible(true, true, 3));
    }

    #[test]
    fn first_ok_attempts_count() {
        // Success at index 1 means 2 attempts
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(42), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);
        assert_eq!(result.attempts(), 2);

        // All fail means attempts == failures.len()
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("e1"), Outcome::Err("e2")];
        let result = first_ok_outcomes(outcomes);
        assert_eq!(result.attempts(), 2);
    }

    #[test]
    fn first_ok_preserves_failure_indices() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e0"), Outcome::Err("e1"), Outcome::Ok(2)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        assert_eq!(result.failures.len(), 2);
        assert_eq!(result.failures[0].0, 0);
        assert_eq!(result.failures[1].0, 1);
    }

    // Semantic property tests
    #[test]
    fn first_ok_short_circuits() {
        // After first success, later outcomes don't affect result
        let outcomes1: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e"), Outcome::Ok(1), Outcome::Ok(2)];
        let outcomes2: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e"), Outcome::Ok(1), Outcome::Err("ignored")];

        let r1 = first_ok_outcomes(outcomes1);
        let r2 = first_ok_outcomes(outcomes2);

        // Both should have same success
        assert_eq!(
            r1.success.as_ref().unwrap().value,
            r2.success.as_ref().unwrap().value
        );
        assert_eq!(
            r1.success.as_ref().unwrap().index,
            r2.success.as_ref().unwrap().index
        );
    }

    #[test]
    fn first_ok_macro_returns_first_success() {
        let result = futures_lite::future::block_on(first_ok!(
            async { Outcome::<i32, &str>::Err("e1") },
            async { Outcome::<i32, &str>::Ok(42) },
            async { Outcome::<i32, &str>::Err("never reached") },
        ));

        assert!(result.is_success());
        let success = result.success.expect("success expected");
        assert_eq!(success.index, 1);
        assert_eq!(success.value, 42);
        assert_eq!(result.failures.len(), 1);
    }

    #[test]
    fn first_ok_macro_short_circuits_late_operations() {
        let touched = Arc::new(AtomicUsize::new(0));
        let touched_late = Arc::clone(&touched);
        let result = futures_lite::future::block_on(first_ok!(
            async { Outcome::<i32, &str>::Err("e1") },
            async { Outcome::<i32, &str>::Ok(7) },
            async move {
                touched_late.fetch_add(1, Ordering::Relaxed);
                Outcome::<i32, &str>::Err("late")
            },
        ));

        assert!(result.is_success());
        assert_eq!(touched.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn first_ok_macro_stops_on_cancelled() {
        let result = futures_lite::future::block_on(first_ok!(
            async { Outcome::<i32, &str>::Err("e1") },
            async { Outcome::<i32, &str>::Cancelled(CancelReason::timeout()) },
            async { Outcome::<i32, &str>::Ok(99) },
        ));

        assert!(!result.is_success());
        assert!(result.was_cancelled);
        assert_eq!(result.failures.len(), 2);
    }

    /// The macro never looked at the caller's cancellation, so a cancelled
    /// task went on through the whole fallback chain.
    #[test]
    fn first_ok_macro_starts_no_attempt_after_the_caller_is_cancelled() {
        let cx = crate::cx::Cx::for_testing();
        let _current = crate::cx::Cx::set_current(Some(cx.clone()));
        let started = Arc::new(AtomicUsize::new(0));
        let second = Arc::clone(&started);

        let result = futures_lite::future::block_on(first_ok!(
            async move {
                cx.set_cancel_reason(CancelReason::shutdown());
                Outcome::<i32, &str>::Err("e1")
            },
            async move {
                second.fetch_add(1, Ordering::Relaxed);
                Outcome::<i32, &str>::Ok(2)
            },
        ));

        assert_eq!(
            started.load(Ordering::Relaxed),
            0,
            "the second attempt ran after the cancellation"
        );
        assert!(!result.is_success());
        assert!(result.was_cancelled);
        assert_eq!(result.failures.len(), 2);
        assert!(matches!(
            result.failures[0],
            (0, FirstOkFailure::Error("e1"))
        ));
        assert!(matches!(
            &result.failures[1],
            (1, FirstOkFailure::Cancelled(reason)) if *reason == CancelReason::shutdown()
        ));
    }

    #[test]
    fn first_ok_err_after_success_not_collected() {
        // Errors after the first success are not collected
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e2"), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        // No failures collected because first succeeded
        assert!(result.failures.is_empty());
    }

    #[test]
    fn first_ok_vs_race_semantic_difference() {
        // In first_ok, a failing operation before success doesn't win
        // This is different from race where first completion wins
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fast_error"), Outcome::Ok(42)];

        let result = first_ok_outcomes(outcomes);

        // first_ok: second operation wins because it's Ok
        assert!(result.is_success());
        assert_eq!(result.success.unwrap().value, 42);

        // In race, the first to complete (Err) would win
        // This test documents the semantic difference
    }

    // --- wave 79 trait coverage ---

    #[test]
    fn first_ok_error_debug_clone() {
        let e: FirstOkError<&str> = FirstOkError::AllFailed {
            errors: vec!["e1", "e2"],
            attempted: 2,
        };
        let e2 = e.clone();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("AllFailed"));
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("AllFailed"));
    }

    #[test]
    fn first_ok_failure_debug_clone() {
        let f: FirstOkFailure<&str> = FirstOkFailure::Error("msg");
        let f2 = f.clone();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("Error"));
        let dbg2 = format!("{f2:?}");
        assert!(dbg2.contains("Error"));
    }
