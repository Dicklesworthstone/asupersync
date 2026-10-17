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

    #[derive(Debug, Clone)]
    enum QuorumCase {
        Ok(i32),
        ErrAlpha,
        ErrBeta,
        CancelUser,
        CancelTimeout,
        CancelShutdown,
        Panic,
    }

    impl QuorumCase {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Ok(value) => Outcome::Ok(value),
                Self::ErrAlpha => Outcome::Err("err-alpha"),
                Self::ErrBeta => Outcome::Err("err-beta"),
                Self::CancelUser => Outcome::Cancelled(CancelReason::user("user")),
                Self::CancelTimeout => Outcome::Cancelled(CancelReason::timeout()),
                Self::CancelShutdown => Outcome::Cancelled(CancelReason::shutdown()),
                Self::Panic => Outcome::Panicked(PanicPayload::new("boom")),
            }
        }
    }

    fn quorum_case_strategy() -> impl Strategy<Value = QuorumCase> {
        prop_oneof![
            any::<i16>().prop_map(|value| QuorumCase::Ok(i32::from(value))),
            Just(QuorumCase::ErrAlpha),
            Just(QuorumCase::ErrBeta),
            Just(QuorumCase::CancelUser),
            Just(QuorumCase::CancelTimeout),
            Just(QuorumCase::CancelShutdown),
            Just(QuorumCase::Panic),
        ]
    }

    fn failure_signature(
        failure: &QuorumFailure<&'static str>,
    ) -> (&'static str, Option<u8>, Option<&'static str>) {
        match failure {
            QuorumFailure::Error(error) => ("err", None, Some(*error)),
            QuorumFailure::Cancelled(reason) => ("cancelled", Some(reason.severity()), None),
            QuorumFailure::Panicked(_) => ("panic", None, None),
        }
    }

    fn ordered_projection(
        result: &QuorumResult<i32, &'static str>,
    ) -> Vec<(&'static str, Option<i32>, Option<u8>, Option<&'static str>)> {
        let mut projection = vec![("unassigned", None, None, None); result.total()];

        for (index, value) in &result.successes {
            projection[*index] = ("ok", Some(*value), None, None);
        }

        for (index, failure) in &result.failures {
            projection[*index] = match failure {
                QuorumFailure::Error(error) => ("err", None, None, Some(*error)),
                QuorumFailure::Cancelled(reason) => {
                    ("cancelled", None, Some(reason.severity()), None)
                }
                QuorumFailure::Panicked(_) => ("panic", None, None, None),
            };
        }

        projection
    }

    fn quorum_to_result_signature(
        result: QuorumResult<i32, &'static str>,
    ) -> (&'static str, usize, Vec<i32>, Vec<&'static str>) {
        match quorum_to_result(result) {
            Ok(mut values) => {
                values.sort_unstable();
                ("ok", values.len(), values, Vec::new())
            }
            Err(QuorumError::InvalidQuorum { required, total }) => {
                ("invalid", required + total, Vec::new(), Vec::new())
            }
            Err(QuorumError::Panicked(_)) => ("panic", 0, Vec::new(), Vec::new()),
            Err(QuorumError::Cancelled(_)) => ("cancelled", 0, Vec::new(), Vec::new()),
            Err(QuorumError::InsufficientSuccesses {
                achieved,
                mut errors,
                ..
            }) => {
                errors.sort_unstable();
                ("insufficient", achieved, Vec::new(), errors)
            }
        }
    }

    #[test]
    fn quorum_all_succeed() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.failure_count(), 0);
    }

    #[test]
    fn quorum_exact_meet() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e1"), Outcome::Ok(2)];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 1);
    }

    #[test]
    fn quorum_not_met() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e1"), Outcome::Err("e2")];
        let result = quorum_outcomes(2, outcomes);

        assert!(!result.quorum_met);
        assert_eq!(result.success_count(), 1);
        assert_eq!(result.failure_count(), 2);
    }

    #[test]
    fn quorum_zero_required() {
        // quorum(0, N) is trivially met
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(0, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 0);
        // All outcomes become "failures" (cancelled because quorum trivially met)
        assert_eq!(result.failure_count(), 3);
    }

    #[test]
    fn quorum_zero_to_result_returns_empty_even_if_losers_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Cancelled(CancelReason::timeout()),
        ];
        let result = quorum_outcomes(0, outcomes);

        let values = quorum_to_result(result).expect("quorum(0, N) should succeed");
        assert!(values.is_empty());
    }

    #[test]
    fn quorum_n_of_n_is_join() {
        // quorum(N, N) is equivalent to join: all must succeed
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 3);
    }

    #[test]
    fn quorum_n_of_n_one_fails() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e"), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes);

        assert!(!result.quorum_met);
        assert_eq!(result.success_count(), 2);
    }

    #[test]
    fn quorum_1_of_n_is_race() {
        // quorum(1, N) is equivalent to race: first success wins
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(2), Outcome::Err("e2")];
        let result = quorum_outcomes(1, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 1);
    }

    #[test]
    fn quorum_invalid_m_greater_than_n() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = quorum_outcomes(5, outcomes);

        // Invalid quorum cannot be met
        assert!(!result.quorum_met);

        // Fail-fast conversion should surface invalid parameters explicitly.
        let err = quorum_to_result(result).unwrap_err();
        assert!(matches!(err, QuorumError::InvalidQuorum { .. }));
    }

    #[test]
    fn quorum_with_cancellation() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(2),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert!(result.has_cancellation);
    }

    /// Among cancellations that are not quorum losers, the strongest is
    /// reported, whatever its index (br-asupersync-1sngsf).
    #[test]
    fn quorum_to_result_reports_the_strongest_cancellation() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::user("user")),
            Outcome::Cancelled(CancelReason::shutdown()),
            Outcome::Err("e"),
        ];
        let err = quorum_to_result(quorum_outcomes(2, outcomes)).unwrap_err();
        assert!(
            matches!(
                &err,
                QuorumError::Cancelled(reason)
                    if reason.kind() == crate::types::cancel::CancelKind::Shutdown
            ),
            "the shutdown outranks the earlier user cancel, got {err}"
        );
    }

    #[test]
    fn quorum_with_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(2),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert!(result.has_panic);
    }

    #[test]
    fn quorum_to_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Err("e")];
        let result = quorum_outcomes(2, outcomes);
        let values = quorum_to_result(result);

        assert!(values.is_ok());
        let v = values.unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&1));
        assert!(v.contains(&2));
    }

    #[test]
    fn quorum_to_result_insufficient() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e1"), Outcome::Err("e2")];
        let result = quorum_outcomes(2, outcomes);
        let values = quorum_to_result(result);

        assert!(values.is_err());
        match values.unwrap_err() {
            QuorumError::InsufficientSuccesses {
                required,
                achieved,
                errors,
                ..
            } => {
                assert_eq!(required, 2);
                assert_eq!(achieved, 1);
                assert_eq!(errors.len(), 2);
            }
            _ => panic!("Expected InsufficientSuccesses"),
        }
    }

    #[test]
    fn quorum_to_result_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Err("e"),
        ];
        let result = quorum_outcomes(3, outcomes);
        let values = quorum_to_result(result);

        assert!(values.is_err());
        assert!(matches!(values.unwrap_err(), QuorumError::Panicked(_)));
    }

    #[test]
    fn asupersync_8mp6md_quorum_loser_panic_fails_closed() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Panicked(PanicPayload::new("drained loser panicked")),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met, "the numerical quorum was reached");
        assert!(matches!(
            quorum_to_result(result),
            Err(QuorumError::Panicked(_))
        ));
    }

    #[test]
    fn quorum_still_possible_test() {
        // 2-of-3, 0 successes, 0 failures -> possible
        assert!(quorum_still_possible(2, 3, 0, 0));

        // 2-of-3, 1 success, 0 failures -> possible
        assert!(quorum_still_possible(2, 3, 1, 0));

        // 2-of-3, 2 successes, 0 failures -> possible (already met)
        assert!(quorum_still_possible(2, 3, 2, 0));

        // 2-of-3, 0 successes, 2 failures -> not possible (only 1 remaining)
        assert!(!quorum_still_possible(2, 3, 0, 2));

        // 2-of-3, 1 success, 1 failure -> possible (1 remaining)
        assert!(quorum_still_possible(2, 3, 1, 1));
    }

    #[test]
    fn quorum_achieved_test() {
        assert!(!quorum_achieved(2, 0));
        assert!(!quorum_achieved(2, 1));
        assert!(quorum_achieved(2, 2));
        assert!(quorum_achieved(2, 3));
        assert!(quorum_achieved(0, 0)); // Trivial quorum
    }

    #[test]
    fn quorum_error_display() {
        let err: QuorumError<&str> = QuorumError::InsufficientSuccesses {
            required: 2,
            total: 3,
            achieved: 1,
            errors: vec!["e1", "e2"],
        };
        assert!(err.to_string().contains("needed 2/3"));
        assert!(err.to_string().contains("got 1 successes"));

        let err: QuorumError<&str> = QuorumError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: QuorumError<&str> = QuorumError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));

        let err: QuorumError<&str> = QuorumError::InvalidQuorum {
            required: 5,
            total: 3,
        };
        assert!(err.to_string().contains("invalid quorum"));

        // needed == 0 (refused by Scope::quorum) said "required 0 exceeds total 3".
        let err: QuorumError<&str> = QuorumError::InvalidQuorum {
            required: 0,
            total: 3,
        };
        let text = err.to_string();
        assert!(text.contains("invalid quorum"), "{text}");
        assert!(!text.contains("exceeds"), "{text}");
    }

    #[test]
    fn quorum_preserves_indices() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e0"),
            Outcome::Ok(10),
            Outcome::Err("e2"),
            Outcome::Ok(30),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        // Check that indices are preserved
        assert!(result.successes.iter().any(|(i, v)| *i == 1 && *v == 10));
        assert!(result.successes.iter().any(|(i, v)| *i == 3 && *v == 30));
        assert!(result.failures.iter().any(|(i, _)| *i == 0));
        assert!(result.failures.iter().any(|(i, _)| *i == 2));
    }

    // Algebraic property tests
    #[test]
    fn quorum_1_equals_race_semantics() {
        // quorum(1, N) should succeed if ANY operation succeeds
        let outcomes_success: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(2), Outcome::Err("e3")];
        let result = quorum_outcomes(1, outcomes_success);
        assert!(result.quorum_met);

        let outcomes_fail: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Err("e2"), Outcome::Err("e3")];
        let result = quorum_outcomes(1, outcomes_fail);
        assert!(!result.quorum_met);
    }

    #[test]
    fn quorum_n_equals_join_semantics() {
        // quorum(N, N) should succeed only if ALL operations succeed
        let outcomes_success: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes_success);
        assert!(result.quorum_met);

        let outcomes_fail: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e"), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes_fail);
        assert!(!result.quorum_met);
    }

    #[test]
    fn quorum_monotone_in_required() {
        // If quorum(M, outcomes) succeeds, then quorum(M-1, outcomes) also succeeds
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Err("e")];

        let result_2 = quorum_outcomes(2, outcomes.clone());
        let result_1 = quorum_outcomes(1, outcomes.clone());
        let result_3 = quorum_outcomes(3, outcomes);

        assert!(result_1.quorum_met);
        assert!(result_2.quorum_met);
        assert!(!result_3.quorum_met);
    }

    #[test]
    fn metamorphic_appending_error_losers_preserves_met_quorum_result() {
        let base_outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(10), Outcome::Err("e1"), Outcome::Ok(20)];
        let extended_outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(10),
            Outcome::Err("e1"),
            Outcome::Ok(20),
            Outcome::Err("e2"),
            Outcome::Err("e3"),
        ];

        let base_result = quorum_outcomes(2, base_outcomes);
        let extended_result = quorum_outcomes(2, extended_outcomes);

        assert!(base_result.quorum_met);
        assert!(extended_result.quorum_met);

        let mut base_success_values = base_result
            .successes
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        let mut extended_success_values = extended_result
            .successes
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        base_success_values.sort_unstable();
        extended_success_values.sort_unstable();

        assert_eq!(base_success_values, vec![10, 20]);
        assert_eq!(extended_success_values, base_success_values);
        assert_eq!(
            quorum_to_result_signature(base_result),
            quorum_to_result_signature(extended_result)
        );
    }

    #[test]
    fn quorum_empty_outcomes() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];

        // quorum(0, []) is trivially met
        let result = quorum_outcomes(0, outcomes.clone());
        assert!(result.quorum_met);

        // quorum(1, []) cannot be met
        let result = quorum_outcomes(1, outcomes);
        assert!(!result.quorum_met);
    }

    // --- wave 79 trait coverage ---

    #[test]
    fn quorum_error_debug_clone() {
        let e: QuorumError<&str> = QuorumError::InsufficientSuccesses {
            required: 3,
            total: 5,
            achieved: 1,
            errors: vec!["e1"],
        };
        let e2 = e.clone();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("InsufficientSuccesses"));
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("InsufficientSuccesses"));
    }

    #[test]
    fn quorum_failure_debug_clone() {
        let f: QuorumFailure<&str> = QuorumFailure::Error("bad");
        let f2 = f.clone();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("Error"));
        let dbg2 = format!("{f2:?}");
        assert!(dbg2.contains("Error"));
    }

    proptest! {
        #[test]
        fn metamorphic_quorum_rotation_preserves_projection_and_verdict(
            cases in prop::collection::vec(quorum_case_strategy(), 1..12),
            raw_required in 0usize..16,
            raw_shift in 0usize..32,
        ) {
            let shift = raw_shift % cases.len();
            let required = raw_required % (cases.len() + 3);

            let base_result = quorum_outcomes(
                required,
                cases
                    .iter()
                    .cloned()
                    .map(QuorumCase::into_outcome)
                    .collect::<Vec<_>>(),
            );

            let mut rotated_cases = cases.clone();
            rotated_cases.rotate_left(shift);
            let rotated_result = quorum_outcomes(
                required,
                rotated_cases
                    .iter()
                    .cloned()
                    .map(QuorumCase::into_outcome)
                    .collect::<Vec<_>>(),
            );

            prop_assert_eq!(base_result.quorum_met, rotated_result.quorum_met);
            prop_assert_eq!(base_result.required, rotated_result.required);
            prop_assert_eq!(base_result.total(), rotated_result.total());
            prop_assert_eq!(base_result.has_cancellation, rotated_result.has_cancellation);
            prop_assert_eq!(base_result.has_panic, rotated_result.has_panic);

            let mut base_success_values = base_result
                .successes
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>();
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
                "rotating branch order must preserve the quorum success multiset"
            );

            let mut base_failure_signatures = base_result
                .failures
                .iter()
                .map(|(_, failure)| failure_signature(failure))
                .collect::<Vec<_>>();
            let mut rotated_failure_signatures = rotated_result
                .failures
                .iter()
                .map(|(_, failure)| failure_signature(failure))
                .collect::<Vec<_>>();
            base_failure_signatures.sort_unstable();
            rotated_failure_signatures.sort_unstable();
            prop_assert_eq!(
                base_failure_signatures,
                rotated_failure_signatures,
                "rotating branch order must preserve the quorum failure multiset"
            );

            let mut expected_rotated_projection = ordered_projection(&base_result);
            expected_rotated_projection.rotate_left(shift);
            prop_assert_eq!(
                ordered_projection(&rotated_result),
                expected_rotated_projection,
                "a quiescent quorum must preserve the branch projection under the same rotation"
            );

            prop_assert_eq!(
                quorum_to_result_signature(base_result),
                quorum_to_result_signature(rotated_result),
                "rotating branch order must preserve the fail-fast quorum verdict class"
            );
        }
    }

    // =========================================================================
    // Decisiveness metamorphic relations for quorum_outcomes.
    //
    // The existing rotation proptest covers cyclic permutation invariance
    // of the verdict + multiset. These MRs go further: arbitrary
    // permutation, monotonicity in required, monotonicity in Ok-count,
    // boundary conditions at required=0 / required=N(Ok) / required=N(Ok)+1,
    // and decomposition under append. Together they pin down the
    // verdict surface — any refactor that preserves rotation but breaks
    // e.g. monotonicity would be caught here.
    // =========================================================================

    mod decisiveness_mr {
        use super::*;

        fn outcomes_from(cases: &[QuorumCase]) -> Vec<Outcome<i32, &'static str>> {
            cases
                .iter()
                .cloned()
                .map(QuorumCase::into_outcome)
                .collect()
        }

        fn count_ok(cases: &[QuorumCase]) -> usize {
            cases
                .iter()
                .filter(|c| matches!(c, QuorumCase::Ok(_)))
                .count()
        }

        proptest! {
            /// MR — Arbitrary permutation preserves verdict + multiset.
            /// Stronger than the existing rotation MR because any
            /// permutation is reachable; rotation is a narrow subgroup.
            #[test]
            fn mr_quorum_permutation_preserves_verdict_and_multiset(
                cases in prop::collection::vec(quorum_case_strategy(), 1..10),
                raw_required in 0usize..12,
                perm_seed in any::<u64>(),
            ) {
                let required = raw_required % (cases.len() + 2);

                let base = quorum_outcomes(required, outcomes_from(&cases));

                // Fisher-Yates shuffle driven by the seed — any permutation.
                let mut permuted = cases.clone();
                let mut state = perm_seed.max(1);
                for i in (1..permuted.len()).rev() {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let j = (state as usize) % (i + 1);
                    permuted.swap(i, j);
                }
                let permuted_result = quorum_outcomes(required, outcomes_from(&permuted));

                prop_assert_eq!(base.quorum_met, permuted_result.quorum_met);
                prop_assert_eq!(base.success_count(), permuted_result.success_count());
                prop_assert_eq!(base.failure_count(), permuted_result.failure_count());
                prop_assert_eq!(base.total(), permuted_result.total());

                let mut base_ok: Vec<i32> = base.successes.iter().map(|(_, v)| *v).collect();
                let mut perm_ok: Vec<i32> =
                    permuted_result.successes.iter().map(|(_, v)| *v).collect();
                base_ok.sort_unstable();
                perm_ok.sort_unstable();
                prop_assert_eq!(base_ok, perm_ok, "permutation changed the success multiset");
            }

            /// MR — Monotonicity in required (downward).
            /// If quorum(k+1, xs).quorum_met, then quorum(k, xs).quorum_met.
            /// Equivalently: the set of required values for which a given
            /// Ok-count satisfies the quorum is downward-closed.
            #[test]
            fn mr_quorum_monotonic_downward_in_required(
                cases in prop::collection::vec(quorum_case_strategy(), 1..10),
                raw_k in 0usize..10,
            ) {
                let k_hi = raw_k % (cases.len() + 1);
                let hi = quorum_outcomes(k_hi, outcomes_from(&cases));
                if !hi.quorum_met {
                    // Vacuously true when hi is not met.
                    return Ok(());
                }
                for k_lo in 0..k_hi {
                    let lo = quorum_outcomes(k_lo, outcomes_from(&cases));
                    prop_assert!(
                        lo.quorum_met,
                        "quorum_met at required={k_hi} but not at required={k_lo} (downward closure violated)",
                    );
                }
            }

            /// MR — Monotonicity in Ok-count (upward).
            /// Replacing the first non-Ok outcome with an Ok can only
            /// preserve or improve quorum_met; it can never flip met→unmet.
            #[test]
            fn mr_quorum_monotonic_upward_in_ok_count(
                cases in prop::collection::vec(quorum_case_strategy(), 1..10),
                raw_required in 0usize..10,
            ) {
                let required = raw_required % (cases.len() + 1);
                let before = quorum_outcomes(required, outcomes_from(&cases));

                // Promote the first non-Ok to an Ok.
                let mut upgraded = cases.clone();
                for c in upgraded.iter_mut() {
                    if !matches!(c, QuorumCase::Ok(_)) {
                        *c = QuorumCase::Ok(99);
                        break;
                    }
                }
                let after = quorum_outcomes(required, outcomes_from(&upgraded));

                if before.quorum_met {
                    prop_assert!(
                        after.quorum_met,
                        "promoting a failure to success flipped quorum_met true → false",
                    );
                }
                prop_assert!(
                    after.success_count() >= before.success_count(),
                    "success_count must be non-decreasing when upgrading a failure",
                );
            }

            /// MR — Exact-threshold boundary. For any multiset of outcomes,
            /// quorum_met holds iff required ≤ count_ok(cases).
            #[test]
            fn mr_quorum_exact_threshold(
                cases in prop::collection::vec(quorum_case_strategy(), 0..10),
            ) {
                let n_ok = count_ok(&cases);
                // required = n_ok must be met (when n_ok > 0); or special
                // case required = 0 which is always met per the code.
                let at_thresh = quorum_outcomes(n_ok, outcomes_from(&cases));
                prop_assert!(
                    at_thresh.quorum_met,
                    "required = count_ok must be met (n_ok={n_ok})",
                );
                // required = n_ok + 1 must be unmet.
                let over = quorum_outcomes(n_ok + 1, outcomes_from(&cases));
                prop_assert!(
                    !over.quorum_met,
                    "required = count_ok + 1 must be unmet (n_ok={n_ok})",
                );
            }

            /// MR — Appending a failure preserves verdict.
            /// quorum(k, xs).quorum_met implies quorum(k, xs ++ [failure]).quorum_met.
            #[test]
            fn mr_appending_failure_preserves_met(
                cases in prop::collection::vec(quorum_case_strategy(), 1..10),
                raw_required in 0usize..10,
                failure_variant in 0u8..5,
            ) {
                let required = raw_required % (cases.len() + 1);
                let base = quorum_outcomes(required, outcomes_from(&cases));
                if !base.quorum_met {
                    return Ok(());
                }
                let appended_failure = match failure_variant % 5 {
                    0 => QuorumCase::ErrAlpha,
                    1 => QuorumCase::CancelUser,
                    2 => QuorumCase::CancelTimeout,
                    3 => QuorumCase::CancelShutdown,
                    _ => QuorumCase::Panic,
                };
                let mut appended = cases.clone();
                appended.push(appended_failure);
                let after = quorum_outcomes(required, outcomes_from(&appended));
                prop_assert!(
                    after.quorum_met,
                    "appending a failure flipped met → unmet",
                );
                prop_assert_eq!(base.success_count(), after.success_count());
                prop_assert_eq!(after.failure_count(), base.failure_count() + 1);
            }
        }

        /// required=0 is the additive identity — always met regardless of
        /// outcome composition — and produces zero successes (all
        /// outcomes become failure entries per the code at lines 267-279).
        #[test]
        fn mr_quorum_required_zero_is_additive_identity() {
            let outcomes: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Err("e"),
                Outcome::Cancelled(CancelReason::timeout()),
                Outcome::Panicked(PanicPayload::new("p")),
            ];
            let result = quorum_outcomes(0, outcomes);
            assert!(result.quorum_met, "required=0 must always be met");
            assert_eq!(
                result.success_count(),
                0,
                "required=0 reports zero successes"
            );
            assert_eq!(
                result.failure_count(),
                4,
                "all inputs drained into failures"
            );
        }

        /// quorum_still_possible has a precise algebraic identity:
        ///   possible ⇔ (total - failures) ≥ required
        /// when successes + failures ≤ total (the only valid input shape).
        #[test]
        fn mr_quorum_still_possible_matches_algebra() {
            for total in 0..=6usize {
                for successes in 0..=total {
                    for failures in 0..=(total - successes) {
                        for required in 0..=(total + 2) {
                            let got = quorum_still_possible(required, total, successes, failures);
                            let remaining = total - successes - failures;
                            let want = successes + remaining >= required;
                            assert_eq!(
                                got, want,
                                "quorum_still_possible({required}, {total}, {successes}, {failures}) \
                                 = {got}, algebra says {want}",
                            );
                        }
                    }
                }
            }
        }
    }
