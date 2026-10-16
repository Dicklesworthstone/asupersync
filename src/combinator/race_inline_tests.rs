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
    enum RaceWinnerCase {
        Ok(i32),
        Err,
        CancelTimeout,
        CancelShutdown,
        Panic,
    }

    #[derive(Debug, Clone)]
    enum RaceLoserCase {
        Ok(i32),
        Err,
        CancelRaceLost,
        CancelParent,
        CancelShutdown,
    }

    impl RaceWinnerCase {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Ok(value) => Outcome::Ok(value),
                Self::Err => Outcome::Err("winner-error"),
                Self::CancelTimeout => Outcome::Cancelled(CancelReason::timeout()),
                Self::CancelShutdown => Outcome::Cancelled(CancelReason::shutdown()),
                Self::Panic => Outcome::Panicked(PanicPayload::new("winner-panic")),
            }
        }
    }

    impl RaceLoserCase {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Ok(value) => Outcome::Ok(value),
                Self::Err => Outcome::Err("loser-error"),
                Self::CancelRaceLost => Outcome::Cancelled(CancelReason::race_loser()),
                Self::CancelParent => Outcome::Cancelled(CancelReason::new(
                    crate::types::cancel::CancelKind::ParentCancelled,
                )),
                Self::CancelShutdown => Outcome::Cancelled(CancelReason::shutdown()),
            }
        }
    }

    fn race_winner_case_strategy() -> impl Strategy<Value = RaceWinnerCase> {
        prop_oneof![
            any::<i16>().prop_map(|value| RaceWinnerCase::Ok(i32::from(value))),
            Just(RaceWinnerCase::Err),
            Just(RaceWinnerCase::CancelTimeout),
            Just(RaceWinnerCase::CancelShutdown),
            Just(RaceWinnerCase::Panic),
        ]
    }

    fn race_loser_case_strategy() -> impl Strategy<Value = RaceLoserCase> {
        prop_oneof![
            any::<i16>().prop_map(|value| RaceLoserCase::Ok(i32::from(value))),
            Just(RaceLoserCase::Err),
            Just(RaceLoserCase::CancelRaceLost),
            Just(RaceLoserCase::CancelParent),
            Just(RaceLoserCase::CancelShutdown),
        ]
    }

    fn non_empty_cancel_storm_padding_strategy() -> impl Strategy<
        Value = (
            Vec<Outcome<i32, &'static str>>,
            Vec<Outcome<i32, &'static str>>,
        ),
    > {
        prop_oneof![
            (
                prop::collection::vec(race_cancel_storm_loser_strategy(), 1usize..6),
                prop::collection::vec(race_cancel_storm_loser_strategy(), 0usize..6),
            ),
            (
                prop::collection::vec(race_cancel_storm_loser_strategy(), 0usize..6),
                prop::collection::vec(race_cancel_storm_loser_strategy(), 1usize..6),
            ),
        ]
    }

    fn race_cancel_storm_loser_strategy() -> impl Strategy<Value = Outcome<i32, &'static str>> {
        prop_oneof![
            Just(Outcome::Cancelled(CancelReason::race_loser())),
            Just(Outcome::Cancelled(CancelReason::new(
                crate::types::cancel::CancelKind::ParentCancelled,
            ))),
            Just(Outcome::Cancelled(CancelReason::shutdown())),
        ]
    }

    fn race_outcome_signature(
        outcome: &Outcome<i32, &'static str>,
    ) -> (&'static str, Option<i32>, Option<u8>) {
        match outcome {
            Outcome::Ok(value) => ("ok", Some(*value), None),
            Outcome::Err(_) => ("err", None, None),
            Outcome::Cancelled(reason) => ("cancelled", None, Some(reason.severity())),
            Outcome::Panicked(_) => ("panic", None, None),
        }
    }

    fn race_error_signature(error: &RaceError<&'static str>) -> (&'static str, usize, Option<u8>) {
        match error {
            RaceError::First(_) => ("err", 0, None),
            RaceError::Second(_) => ("err", 1, None),
            RaceError::Cancelled(reason) => ("cancelled", 0, Some(reason.severity())),
            RaceError::Panicked(_) => ("panic", 0, None),
        }
    }

    fn race2_result_signature(
        result: &Result<i32, RaceError<&'static str>>,
    ) -> (&'static str, Option<i32>, usize, Option<u8>) {
        match result {
            Ok(value) => ("ok", Some(*value), 0, None),
            Err(error) => {
                let (kind, winner_index, severity) = race_error_signature(error);
                (kind, None, winner_index, severity)
            }
        }
    }

    fn race_all_error_signature(
        error: &RaceAllError<&'static str>,
    ) -> (&'static str, usize, Option<u8>) {
        match error {
            RaceAllError::Error { winner_index, .. } => ("err", *winner_index, None),
            RaceAllError::Cancelled {
                winner_index,
                reason,
            } => ("cancelled", *winner_index, Some(reason.severity())),
            RaceAllError::Panicked { index, .. } => ("panic", *index, None),
        }
    }

    fn race_all_result_signature(
        result: &Result<i32, RaceAllError<&'static str>>,
    ) -> (&'static str, Option<i32>, usize, Option<u8>) {
        match result {
            Ok(value) => ("ok", Some(*value), 0, None),
            Err(error) => {
                let (kind, index, severity) = race_all_error_signature(error);
                (kind, None, index, severity)
            }
        }
    }

    #[test]
    fn race_result_is_first() {
        let result: RaceResult<i32, &str> = RaceResult::First(42);
        assert!(result.is_first());
        assert!(!result.is_second());
    }

    #[test]
    fn race_result_is_second() {
        let result: RaceResult<i32, &str> = RaceResult::Second("hello");
        assert!(!result.is_first());
        assert!(result.is_second());
    }

    #[test]
    fn race_result_map_first() {
        let result: RaceResult<i32, &str> = RaceResult::First(42);
        let mapped = result.map_first(|x| x * 2);
        assert!(matches!(mapped, RaceResult::First(84)));
    }

    #[test]
    fn race_result_map_second() {
        let result: RaceResult<i32, &str> = RaceResult::Second("hello");
        let mapped = result.map_second(str::len);
        assert!(matches!(mapped, RaceResult::Second(5)));
    }

    #[test]
    fn race_winner_predicates() {
        assert!(RaceWinner::First.is_first());
        assert!(!RaceWinner::First.is_second());
        assert!(!RaceWinner::Second.is_first());
        assert!(RaceWinner::Second.is_second());
    }

    #[test]
    fn race2_outcomes_first_wins_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(42);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (winner, which, loser) = race2_outcomes(RaceWinner::First, o1, o2);

        assert!(winner.is_ok());
        assert!(which.is_first());
        assert!(loser.is_cancelled());
    }

    #[test]
    fn race2_outcomes_second_wins_ok() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let o2: Outcome<i32, &str> = Outcome::Ok(99);

        let (winner, which, loser) = race2_outcomes(RaceWinner::Second, o1, o2);

        assert!(winner.is_ok());
        assert!(which.is_second());
        assert!(loser.is_cancelled());
    }

    #[test]
    fn race2_outcomes_first_wins_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("failed");
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (winner, which, loser) = race2_outcomes(RaceWinner::First, o1, o2);

        assert!(winner.is_err());
        assert!(which.is_first());
        assert!(loser.is_cancelled());
    }

    #[test]
    fn race2_to_result_winner_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(42);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn race2_to_result_winner_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("failed");
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert!(matches!(result, Err(RaceError::First("failed"))));
    }

    #[test]
    fn race2_to_result_winner_cancelled() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert!(matches!(result, Err(RaceError::Cancelled(_))));
    }

    #[test]
    fn race2_to_result_winner_panicked() {
        let o1: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("boom"));
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert!(matches!(result, Err(RaceError::Panicked(_))));
    }

    #[test]
    fn race_all_outcomes_first_wins() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = race_all_outcomes(0, outcomes);

        assert!(result.winner_succeeded());
        assert_eq!(result.winner_index, 0);
        assert_eq!(result.loser_outcomes.len(), 2);
        assert_eq!(result.loser_outcomes[0].0, 1);
        assert_eq!(result.loser_outcomes[1].0, 2);
    }

    #[test]
    fn race_all_outcomes_middle_wins() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = race_all_outcomes(1, outcomes);

        assert!(result.winner_succeeded());
        assert_eq!(result.winner_index, 1);
        assert_eq!(result.loser_outcomes.len(), 2);
        assert_eq!(result.loser_outcomes[0].0, 0);
        assert_eq!(result.loser_outcomes[1].0, 2);
    }

    #[test]
    fn race_all_to_result_success() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Ok(42),
            0,
            vec![(1, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    fn race_all_to_result_error() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Err("failed"),
            2,
            vec![
                (0, Outcome::Cancelled(CancelReason::race_loser())),
                (1, Outcome::Cancelled(CancelReason::race_loser())),
            ],
        );

        let value = race_all_to_result(result);
        match value {
            Err(RaceAllError::Error {
                error,
                winner_index,
            }) => {
                assert_eq!(error, "failed");
                assert_eq!(winner_index, 2);
            }
            _ => panic!("expected RaceAllError::Error"),
        }
    }

    #[test]
    fn loser_drain_violation_panic_has_asup_e302() {
        let panic = std::panic::catch_unwind(|| {
            let winner: Outcome<i32, &str> = Outcome::Ok(42);
            let loser =
                Outcome::Cancelled(CancelReason::new(crate::types::cancel::CancelKind::User));
            let _ = race2_outcomes(RaceWinner::First, winner, loser);
        })
        .expect_err("weak loser cancel kind must panic");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("panic payload should be text");

        assert!(message.starts_with("[ASUP-E302]"));
        assert!(message.contains("L-LOSER-DRAINED invariant violated"));
    }

    #[test]
    fn race_error_display() {
        let err: RaceError<&str> = RaceError::First("test error");
        assert!(err.to_string().contains("first branch won"));

        let err: RaceError<&str> = RaceError::Second("test error");
        assert!(err.to_string().contains("second branch won"));

        let err: RaceError<&str> = RaceError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: RaceError<&str> = RaceError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));
    }

    #[test]
    fn loser_is_always_tracked() {
        // This test verifies that the loser outcome is captured in the result,
        // which is necessary for verifying the "losers always drained" invariant.
        let o1: Outcome<i32, &str> = Outcome::Ok(42);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (_, _, loser) = race2_outcomes(RaceWinner::First, o1, o2);

        // The loser was cancelled (as expected when losing a race)
        assert!(loser.is_cancelled());
        if let Outcome::Cancelled(reason) = loser {
            // The reason should indicate it was a race loser
            assert!(matches!(
                reason.kind(),
                crate::types::cancel::CancelKind::RaceLost
            ));
        }
    }

    #[test]
    fn race_is_commutative_in_winner_value() {
        // race(a, b) and race(b, a) should return the same winner value
        // when the same branch wins (regardless of position).
        let val_a = 42;

        // A wins in first position
        let o1a: Outcome<i32, &str> = Outcome::Ok(val_a);
        let o1b: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let (w1, _, _) = race2_outcomes(RaceWinner::First, o1a, o1b);

        // A wins in second position (swapped)
        let o2b: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let o2a: Outcome<i32, &str> = Outcome::Ok(val_a);
        let (w2, _, _) = race2_outcomes(RaceWinner::Second, o2b, o2a);

        // Both should have the same winner value
        if let (Outcome::Ok(v1), Outcome::Ok(v2)) = (w1, w2) {
            assert_eq!(v1, v2);
        } else {
            panic!("Expected both winners to be Ok");
        }
    }

    // ========== RaceAll tests ==========

    #[test]
    fn race_all_marker_type() {
        let _race: RaceAll<i32> = RaceAll::new();
        let _race_default: RaceAll<String> = RaceAll::default();

        // Test Clone and Copy
        let r1: RaceAll<i32> = RaceAll::new();
        let r2 = r1;
        let r3 = r1; // Copy, not clone
        assert!(std::mem::size_of_val(&r1) == std::mem::size_of_val(&r2));
        assert!(std::mem::size_of_val(&r1) == std::mem::size_of_val(&r3));
    }

    // ========== RaceAllError tests ==========

    #[test]
    fn race_all_error_predicates() {
        let err: RaceAllError<&str> = RaceAllError::Error {
            error: "test",
            winner_index: 2,
        };
        assert!(err.is_error());
        assert!(!err.is_cancelled());
        assert!(!err.is_panicked());
        assert_eq!(err.winner_index(), 2);

        let err: RaceAllError<&str> = RaceAllError::Cancelled {
            reason: CancelReason::timeout(),
            winner_index: 1,
        };
        assert!(!err.is_error());
        assert!(err.is_cancelled());
        assert!(!err.is_panicked());
        assert_eq!(err.winner_index(), 1);

        let err: RaceAllError<&str> = RaceAllError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 0,
        };
        assert!(!err.is_error());
        assert!(!err.is_cancelled());
        assert!(err.is_panicked());
        assert_eq!(err.winner_index(), 0);
    }

    #[test]
    fn race_all_error_display() {
        let err: RaceAllError<&str> = RaceAllError::Error {
            error: "test error",
            winner_index: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("index 3"));
        assert!(msg.contains("test error"));

        let err: RaceAllError<&str> = RaceAllError::Cancelled {
            reason: CancelReason::timeout(),
            winner_index: 1,
        };
        assert!(err.to_string().contains("cancelled"));
        assert!(err.to_string().contains("index 1"));

        let err: RaceAllError<&str> = RaceAllError::Panicked {
            payload: PanicPayload::new("crash"),
            index: 0,
        };
        assert!(err.to_string().contains("panicked"));
        assert!(err.to_string().contains("index 0"));
    }

    // ========== make_race_all_result tests ==========

    #[test]
    fn make_race_all_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = make_race_all_result(1, outcomes);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn make_race_all_result_error_preserves_index() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Err("failed at index 2"),
        ];

        let result = make_race_all_result(2, outcomes);
        match result {
            Err(RaceAllError::Error {
                error,
                winner_index,
            }) => {
                assert_eq!(error, "failed at index 2");
                assert_eq!(winner_index, 2);
            }
            _ => panic!("expected RaceAllError::Error"),
        }
    }

    #[test]
    fn make_race_all_result_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = make_race_all_result(0, outcomes);
        assert!(matches!(result, Err(RaceAllError::Cancelled { .. })));
        if let Err(RaceAllError::Cancelled { winner_index, .. }) = result {
            assert_eq!(winner_index, 0);
        } else {
            panic!("Expected Cancelled");
        }
    }

    #[test]
    fn make_race_all_result_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = make_race_all_result(0, outcomes);
        assert!(matches!(result, Err(RaceAllError::Panicked { .. })));
        if let Err(RaceAllError::Panicked { index, .. }) = result {
            assert_eq!(index, 0);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn race_all_to_result_cancelled() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Cancelled(CancelReason::timeout()),
            0,
            vec![(1, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert!(matches!(value, Err(RaceAllError::Cancelled { .. })));
        if let Err(RaceAllError::Cancelled { winner_index, .. }) = value {
            assert_eq!(winner_index, 0);
        }
    }

    #[test]
    fn race_all_to_result_panicked() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Panicked(PanicPayload::new("crash")),
            1,
            vec![(0, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert!(matches!(value, Err(RaceAllError::Panicked { .. })));
        if let Err(RaceAllError::Panicked { index, .. }) = value {
            assert_eq!(index, 1);
        }
    }

    #[test]
    fn race_all_last_wins() {
        // Test when the last index wins
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(999),
        ];

        let result = race_all_outcomes(3, outcomes);
        assert_eq!(result.winner_index, 3);
        assert!(result.winner_succeeded());
        assert_eq!(result.loser_outcomes.len(), 3);

        // All loser indices should be 0, 1, 2
        let loser_indices: Vec<usize> = result.loser_outcomes.iter().map(|(i, _)| *i).collect();
        assert_eq!(loser_indices, vec![0, 1, 2]);
    }

    #[test]
    fn race_all_single_entry() {
        // Edge case: racing a single future
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];

        let result = race_all_outcomes(0, outcomes);
        assert_eq!(result.winner_index, 0);
        assert!(result.winner_succeeded());
        assert!(result.loser_outcomes.is_empty());

        let value = race_all_to_result(result);
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    #[should_panic(expected = "winner_index out of bounds")]
    fn race_all_outcomes_panics_on_invalid_index() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let _ = race_all_outcomes(5, outcomes);
    }

    #[test]
    fn race_result_eq() {
        let a: RaceResult<i32, &str> = RaceResult::First(42);
        let b: RaceResult<i32, &str> = RaceResult::First(42);
        let c: RaceResult<i32, &str> = RaceResult::Second("x");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn race_marker_clone_copy() {
        let r1: Race<i32, &str> = Race::new();
        let r2 = r1; // Copy
        let r3 = r1; // still valid after Copy
        assert_eq!(std::mem::size_of_val(&r1), std::mem::size_of_val(&r2));
        assert_eq!(std::mem::size_of_val(&r1), std::mem::size_of_val(&r3));
    }

    #[test]
    fn race_result_map_first_passthrough() {
        // map_first on Second variant should pass through unchanged
        let result: RaceResult<i32, &str> = RaceResult::Second("hello");
        let mapped = result.map_first(|x| x * 2);
        assert!(matches!(mapped, RaceResult::Second("hello")));
    }

    #[test]
    fn race_result_map_second_passthrough() {
        // map_second on First variant should pass through unchanged
        let result: RaceResult<i32, &str> = RaceResult::First(42);
        let mapped = result.map_second(str::len);
        assert!(matches!(mapped, RaceResult::First(42)));
    }

    #[test]
    fn race2_to_result_second_wins_err() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let o2: Outcome<i32, &str> = Outcome::Err("second failed");

        let result = race2_to_result(RaceWinner::Second, o1, o2);
        assert!(matches!(result, Err(RaceError::Second("second failed"))));
    }

    #[test]
    #[ignore = "macro emits compile_error!"]
    fn race_macro_compiles_and_runs() {
        // Test ignored
    }

    proptest! {
        #[test]
        fn metamorphic_race2_drained_loser_substitution_preserves_fail_fast_result(
            first_wins in any::<bool>(),
            winner_case in race_winner_case_strategy(),
            mutated_loser_case in race_loser_case_strategy(),
        ) {
            let winner = if first_wins {
                RaceWinner::First
            } else {
                RaceWinner::Second
            };

            let winner_outcome = winner_case.clone().into_outcome();
            let baseline_loser = Outcome::Cancelled(CancelReason::race_loser());
            let substituted_loser = mutated_loser_case.into_outcome();

            let baseline_result = match winner {
                RaceWinner::First => {
                    race2_to_result(winner, winner_outcome.clone(), baseline_loser)
                }
                RaceWinner::Second => {
                    race2_to_result(winner, baseline_loser, winner_outcome.clone())
                }
            };

            let substituted_result = match winner {
                RaceWinner::First => {
                    race2_to_result(winner, winner_outcome.clone(), substituted_loser)
                }
                RaceWinner::Second => {
                    race2_to_result(winner, substituted_loser, winner_outcome.clone())
                }
            };

            prop_assert_eq!(
                race2_result_signature(&baseline_result),
                race2_result_signature(&substituted_result),
                "non-panicking drained loser substitution must not perturb the race2 fail-fast result"
            );
        }

        #[test]
        fn metamorphic_race_all_rotation_preserves_winner_and_loser_projection(
            branch_count in 1usize..12,
            raw_winner_index in 0usize..24,
            raw_shift in 0usize..24,
            winner_case in race_winner_case_strategy(),
        ) {
            let winner_index = raw_winner_index % branch_count;
            let shift = raw_shift % branch_count;

            let mut base_outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            base_outcomes[winner_index] = winner_case.clone().into_outcome();

            let base_result = race_all_outcomes(winner_index, base_outcomes.clone());
            prop_assert_eq!(base_result.winner_index, winner_index);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&winner_case.clone().into_outcome()),
            );

            let mut rotated_outcomes = base_outcomes.clone();
            rotated_outcomes.rotate_left(shift);
            let expected_rotated_winner = (winner_index + branch_count - shift) % branch_count;

            let rotated_result = race_all_outcomes(expected_rotated_winner, rotated_outcomes.clone());
            prop_assert_eq!(rotated_result.winner_index, expected_rotated_winner);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&rotated_result.winner_outcome),
                "rotating branches must preserve the winner outcome class"
            );

            let mut base_loser_indices = base_result
                .loser_outcomes
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let mut rotated_loser_indices = rotated_result
                .loser_outcomes
                .iter()
                .map(|(index, _)| (*index + shift) % branch_count)
                .collect::<Vec<_>>();
            base_loser_indices.sort_unstable();
            rotated_loser_indices.sort_unstable();
            prop_assert_eq!(
                base_loser_indices,
                rotated_loser_indices,
                "inverse-rotating loser indices must recover the original loser set"
            );

            let base_final = make_race_all_result(winner_index, base_outcomes);
            let rotated_final = make_race_all_result(expected_rotated_winner, rotated_outcomes);
            match (&base_final, &rotated_final) {
                (Ok(base_value), Ok(rotated_value)) => {
                    prop_assert_eq!(base_value, rotated_value);
                }
                (Err(base_error), Err(rotated_error)) => {
                    let base_sig = race_all_error_signature(base_error);
                    let rotated_sig = race_all_error_signature(rotated_error);
                    prop_assert_eq!(base_sig.0, rotated_sig.0);
                    prop_assert_eq!(base_sig.2, rotated_sig.2);
                    prop_assert_eq!(rotated_sig.1, expected_rotated_winner);
                }
                _ => prop_assert!(false, "rotation changed race_all terminal class"),
            }
        }

        #[test]
        fn metamorphic_race_all_arbitrary_permutation_preserves_projection(
            branch_count in 1usize..12,
            raw_winner_index in 0usize..24,
            permutation_seed in any::<u64>(),
            winner_case in race_winner_case_strategy(),
        ) {
            let winner_index = raw_winner_index % branch_count;

            let mut base_outcomes =
                vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            base_outcomes[winner_index] = winner_case.clone().into_outcome();

            let base_result = race_all_outcomes(winner_index, base_outcomes.clone());
            prop_assert_eq!(base_result.winner_index, winner_index);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&winner_case.clone().into_outcome()),
            );

            let mut permutation = (0..branch_count).collect::<Vec<_>>();
            let mut state = permutation_seed;
            for i in (1..branch_count).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let j = (state as usize) % (i + 1);
                permutation.swap(i, j);
            }

            let permuted_outcomes = permutation
                .iter()
                .map(|&old_index| base_outcomes[old_index].clone())
                .collect::<Vec<_>>();
            let permuted_winner_index = permutation
                .iter()
                .position(|&old_index| old_index == winner_index)
                .expect("winner must remain present after permutation");

            let permuted_result =
                race_all_outcomes(permuted_winner_index, permuted_outcomes.clone());
            prop_assert_eq!(permuted_result.winner_index, permuted_winner_index);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&permuted_result.winner_outcome),
                "arbitrary branch permutation must preserve the winner outcome class"
            );

            let mut base_loser_projection = base_result
                .loser_outcomes
                .iter()
                .map(|(index, outcome)| (*index, race_outcome_signature(outcome)))
                .collect::<Vec<_>>();
            let mut permuted_loser_projection = permuted_result
                .loser_outcomes
                .iter()
                .map(|(index, outcome)| (permutation[*index], race_outcome_signature(outcome)))
                .collect::<Vec<_>>();
            base_loser_projection.sort_unstable_by_key(|(index, _)| *index);
            permuted_loser_projection.sort_unstable_by_key(|(index, _)| *index);
            prop_assert_eq!(
                base_loser_projection,
                permuted_loser_projection,
                "inverse-permuting loser indices must recover the original loser projection"
            );

            let base_final = make_race_all_result(winner_index, base_outcomes);
            let permuted_final = make_race_all_result(permuted_winner_index, permuted_outcomes);
            match (&base_final, &permuted_final) {
                (Ok(base_value), Ok(permuted_value)) => {
                    prop_assert_eq!(base_value, permuted_value);
                }
                (Err(base_error), Err(permuted_error)) => {
                    let base_sig = race_all_error_signature(base_error);
                    let permuted_sig = race_all_error_signature(permuted_error);
                    prop_assert_eq!(base_sig.0, permuted_sig.0);
                    prop_assert_eq!(base_sig.2, permuted_sig.2);
                    prop_assert_eq!(permuted_sig.1, permuted_winner_index);
                }
                _ => prop_assert!(false, "arbitrary permutation changed race_all terminal class"),
            }
        }

        #[test]
        fn metamorphic_drained_loser_substitution_preserves_race_all_result(
            branch_count in 1usize..12,
            raw_winner_index in 0usize..24,
            winner_case in race_winner_case_strategy(),
            mutated_loser_cases in prop::collection::vec(race_loser_case_strategy(), 0usize..11),
        ) {
            let winner_index = raw_winner_index % branch_count;

            let mut baseline_outcomes =
                vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            baseline_outcomes[winner_index] = winner_case.clone().into_outcome();

            let loser_indices = (0..branch_count)
                .filter(|index| *index != winner_index)
                .collect::<Vec<_>>();
            let mut substituted_outcomes = baseline_outcomes.clone();
            for (slot, loser_index) in loser_indices.into_iter().enumerate() {
                let loser_case = mutated_loser_cases
                    .get(slot)
                    .cloned()
                    .unwrap_or(RaceLoserCase::CancelRaceLost);
                substituted_outcomes[loser_index] = loser_case.into_outcome();
            }

            let baseline_result = make_race_all_result(winner_index, baseline_outcomes);
            let substituted_result = make_race_all_result(winner_index, substituted_outcomes);

            prop_assert_eq!(
                race_all_result_signature(&baseline_result),
                race_all_result_signature(&substituted_result),
                "non-panicking drained loser substitution must not perturb the race_all result"
            );
        }

        #[test]
        fn metamorphic_race_all_cancel_storm_permutation_preserves_first_success(
            branch_count in 2usize..12,
            raw_winner_index in 0usize..24,
            permutation_seed in any::<u64>(),
            winner_value in any::<i16>(),
            cancel_storm_losers in prop::collection::vec(
                race_cancel_storm_loser_strategy(),
                1usize..11,
            ),
        ) {
            let winner_index = raw_winner_index % branch_count;
            let winner_value = i32::from(winner_value);

            let mut base_outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            let mut loser_slot = 0usize;
            for (index, outcome) in base_outcomes.iter_mut().enumerate() {
                if index == winner_index {
                    *outcome = Outcome::Ok(winner_value);
                } else {
                    *outcome = cancel_storm_losers
                        .get(loser_slot)
                        .cloned()
                        .unwrap_or_else(|| Outcome::Cancelled(CancelReason::race_loser()));
                    loser_slot += 1;
                }
            }

            let base_result = race_all_outcomes(winner_index, base_outcomes.clone());
            prop_assert_eq!(base_result.winner_index, winner_index);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&Outcome::Ok(winner_value)),
            );
            let base_final = make_race_all_result(winner_index, base_outcomes.clone());
            match &base_final {
                Ok(value) => prop_assert_eq!(*value, winner_value),
                Err(_) => prop_assert!(false, "cancel storm changed the first-success winner"),
            }

            let mut permutation = (0..branch_count).collect::<Vec<_>>();
            let mut state = permutation_seed;
            for i in (1..branch_count).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let j = (state as usize) % (i + 1);
                permutation.swap(i, j);
            }

            let permuted_outcomes = permutation
                .iter()
                .map(|&old_index| base_outcomes[old_index].clone())
                .collect::<Vec<_>>();
            let permuted_winner_index = permutation
                .iter()
                .position(|&old_index| old_index == winner_index)
                .expect("winner must remain present after permutation");

            let permuted_result =
                race_all_outcomes(permuted_winner_index, permuted_outcomes.clone());
            prop_assert_eq!(permuted_result.winner_index, permuted_winner_index);
            prop_assert_eq!(
                race_outcome_signature(&permuted_result.winner_outcome),
                race_outcome_signature(&Outcome::Ok(winner_value)),
                "permuting a cancel storm must preserve the first-success winner"
            );

            let mut base_loser_projection = base_result
                .loser_outcomes
                .iter()
                .map(|(index, outcome)| (*index, race_outcome_signature(outcome)))
                .collect::<Vec<_>>();
            let mut permuted_loser_projection = permuted_result
                .loser_outcomes
                .iter()
                .map(|(index, outcome)| (permutation[*index], race_outcome_signature(outcome)))
                .collect::<Vec<_>>();
            base_loser_projection.sort_unstable_by_key(|(index, _)| *index);
            permuted_loser_projection.sort_unstable_by_key(|(index, _)| *index);
            prop_assert_eq!(
                base_loser_projection,
                permuted_loser_projection,
                "inverse-permuting cancel-storm loser indices must recover the original projection"
            );

            let permuted_final = make_race_all_result(permuted_winner_index, permuted_outcomes);
            match (&base_final, &permuted_final) {
                (Ok(base_value), Ok(permuted_value)) => {
                    prop_assert_eq!(base_value, permuted_value);
                }
                _ => prop_assert!(false, "branch permutation changed the first-success result"),
            }
        }

        #[test]
        fn metamorphic_race_all_cancel_storm_padding_preserves_first_success_unique_winner(
            branch_count in 2usize..12,
            raw_winner_index in 0usize..24,
            winner_value in any::<i16>(),
            cancel_storm_losers in prop::collection::vec(
                race_cancel_storm_loser_strategy(),
                1usize..11,
            ),
            (prefix_cancelled, suffix_cancelled) in non_empty_cancel_storm_padding_strategy(),
        ) {
            let winner_index = raw_winner_index % branch_count;
            let winner_value = i32::from(winner_value);

            let mut base_outcomes =
                vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            let mut loser_slot = 0usize;
            for (index, outcome) in base_outcomes.iter_mut().enumerate() {
                if index == winner_index {
                    *outcome = Outcome::Ok(winner_value);
                } else {
                    *outcome = cancel_storm_losers
                        .get(loser_slot)
                        .cloned()
                        .unwrap_or_else(|| Outcome::Cancelled(CancelReason::race_loser()));
                    loser_slot += 1;
                }
            }

            let base_result = race_all_outcomes(winner_index, base_outcomes.clone());
            prop_assert_eq!(base_result.winner_index, winner_index);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&Outcome::Ok(winner_value)),
            );
            let base_final = make_race_all_result(winner_index, base_outcomes.clone());
            match &base_final {
                Ok(value) => prop_assert_eq!(*value, winner_value),
                Err(_) => prop_assert!(false, "cancel storm changed the first-success winner"),
            }

            let padded_winner_index = winner_index + prefix_cancelled.len();
            let mut padded_outcomes = Vec::with_capacity(
                prefix_cancelled.len() + base_outcomes.len() + suffix_cancelled.len(),
            );
            padded_outcomes.extend(prefix_cancelled.iter().cloned());
            padded_outcomes.extend(base_outcomes.iter().cloned());
            padded_outcomes.extend(suffix_cancelled.iter().cloned());

            let padded_result = race_all_outcomes(padded_winner_index, padded_outcomes.clone());
            prop_assert_eq!(padded_result.winner_index, padded_winner_index);
            prop_assert_eq!(
                race_outcome_signature(&padded_result.winner_outcome),
                race_outcome_signature(&Outcome::Ok(winner_value)),
                "injecting extra cancelled losers must preserve the first-success winner"
            );

            let mut base_loser_projection = base_result
                .loser_outcomes
                .iter()
                .map(|(index, outcome)| (*index, race_outcome_signature(outcome)))
                .collect::<Vec<_>>();
            let mut retained_projection = padded_result
                .loser_outcomes
                .iter()
                .filter_map(|(index, outcome)| {
                    let shifted = *index;
                    ((prefix_cancelled.len()..prefix_cancelled.len() + branch_count)
                        .contains(&shifted))
                    .then(|| (
                        shifted - prefix_cancelled.len(),
                        race_outcome_signature(outcome),
                    ))
                })
                .collect::<Vec<_>>();
            base_loser_projection.sort_unstable_by_key(|(index, _)| *index);
            retained_projection.sort_unstable_by_key(|(index, _)| *index);
            prop_assert_eq!(
                base_loser_projection,
                retained_projection,
                "stripping padded cancelled losers must recover the original loser projection"
            );

            let padded_final = make_race_all_result(padded_winner_index, padded_outcomes);
            match (&base_final, &padded_final) {
                (Ok(base_value), Ok(padded_value)) => {
                    prop_assert_eq!(base_value, padded_value);
                }
                _ => prop_assert!(false, "cancel-storm padding changed the first-success result"),
            }
        }
    }

    // =========================================================================
    // Metamorphic Relations for Loser Drain Correctness (asupersync-uuzryk)
    // =========================================================================

    /// MR1: Winner cancellation propagates to all losers
    ///
    /// When the winner is cancelled, all losers must also be cancelled.
    /// The specific cancel reason for losers should be RaceLost.
    #[test]
    fn metamorphic_winner_cancellation_propagates_to_losers() {
        proptest!(|(
            branch_count in 2usize..8,
            raw_winner_index in 0usize..16,
        )| {
            let winner_index = raw_winner_index % branch_count;

            // Winner is cancelled with timeout
            let mut outcomes = vec![Outcome::<i32, &str>::Cancelled(CancelReason::race_loser()); branch_count];
            outcomes[winner_index] = Outcome::Cancelled(CancelReason::timeout());

            let result = race_all_outcomes(winner_index, outcomes);

            // Verify winner was cancelled with timeout
            prop_assert!(result.winner_outcome.is_cancelled());
            if let Outcome::Cancelled(reason) = &result.winner_outcome {
                prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::Timeout));
            }

            // Verify all losers are cancelled with race_loser reason
            for (_, loser_outcome) in &result.loser_outcomes {
                prop_assert!(loser_outcome.is_cancelled(),
                    "All losers must be cancelled when winner is cancelled");
                if let Outcome::Cancelled(reason) = loser_outcome {
                    prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::RaceLost),
                        "Losers should be cancelled with RaceLost reason");
                }
            }
        });
    }

    /// MR2: Loser obligation release consistency
    ///
    /// Regardless of the winner's outcome type, losers should always be
    /// in a "released" state (Cancelled with RaceLost) after draining.
    #[test]
    fn metamorphic_loser_obligations_always_released() {
        proptest!(|(
            branch_count in 2usize..8,
            raw_winner_index in 0usize..16,
            winner_case in race_winner_case_strategy(),
        )| {
            let winner_index = raw_winner_index % branch_count;

            let mut outcomes = vec![Outcome::<i32, &str>::Cancelled(CancelReason::race_loser()); branch_count];
            outcomes[winner_index] = winner_case.into_outcome();

            let result = race_all_outcomes(winner_index, outcomes);

            // All losers must be properly drained (cancelled with RaceLost)
            prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1);

            for (loser_index, loser_outcome) in &result.loser_outcomes {
                prop_assert!(*loser_index != winner_index, "Loser index must differ from winner");
                prop_assert!(loser_outcome.is_cancelled(),
                    "Loser at index {} must be cancelled after draining", loser_index);

                if let Outcome::Cancelled(reason) = loser_outcome {
                    prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::RaceLost),
                        "Loser at index {} must be cancelled with RaceLost reason", loser_index);
                }
            }
        });
    }

    /// MR3: Concurrent race invariant preservation
    ///
    /// Running multiple races with the same branch outcomes should preserve
    /// the drain invariant - each race should independently drain its losers.
    #[test]
    fn metamorphic_concurrent_races_preserve_drain_invariants() {
        proptest!(|(
            race_count in 2usize..5,
            branch_count in 2usize..6,
            winner_cases in prop::collection::vec(race_winner_case_strategy(), 2..5),
            winner_indices in prop::collection::vec(0usize..16, 2..5),
        )| {
            let actual_race_count = race_count.min(winner_cases.len()).min(winner_indices.len());

            let mut race_results = Vec::with_capacity(actual_race_count);

            for race_idx in 0..actual_race_count {
                let winner_index = winner_indices[race_idx] % branch_count;
                let winner_case = &winner_cases[race_idx];

                let mut outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
                outcomes[winner_index] = winner_case.clone().into_outcome();

                let result = race_all_outcomes(winner_index, outcomes);
                race_results.push((race_idx, result));
            }

            // Verify each race independently maintains drain invariants
            for (race_idx, result) in &race_results {
                prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1,
                    "Race {} must have all losers drained", race_idx);

                for (loser_index, loser_outcome) in &result.loser_outcomes {
                    prop_assert!(loser_outcome.is_cancelled(),
                        "Race {} loser at index {} must be cancelled", race_idx, loser_index);
                }
            }

            // Verify independence: each race's drain behavior is unaffected by others
            let drain_signatures: Vec<_> = race_results.iter()
                .map(|(_, result)| {
                    let mut loser_signatures = result.loser_outcomes.iter()
                        .map(|(idx, outcome)| (*idx, outcome.is_cancelled()))
                        .collect::<Vec<_>>();
                    loser_signatures.sort_by_key(|(idx, _)| *idx);
                    loser_signatures
                })
                .collect();

            // All races with the same branch count should have identical drain patterns
            if let Some(first_signature) = drain_signatures.first() {
                for (race_idx, signature) in drain_signatures.iter().enumerate().skip(1) {
                    prop_assert_eq!(signature.len(), first_signature.len(),
                        "Race {} drain pattern length differs", race_idx);
                }
            }
        });
    }

    /// MR4: Deterministic race outcome in virtual time
    ///
    /// In deterministic virtual time (LabRuntime), races with identical
    /// configurations should produce identical outcomes and drain patterns.
    #[test]
    fn metamorphic_virtual_time_deterministic_drain() {
        proptest!(|(
            branch_count in 2usize..8,
            raw_winner_index in 0usize..16,
            winner_case in race_winner_case_strategy(),
            _seed_a in any::<u64>(),
            _seed_b in any::<u64>(),
        )| {
            let winner_index = raw_winner_index % branch_count;

            // Simulate deterministic LabRuntime behavior by using consistent inputs
            let create_outcomes = || {
                let mut outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
                outcomes[winner_index] = winner_case.clone().into_outcome();
                outcomes
            };

            // Run the same race configuration twice
            let result_a = race_all_outcomes(winner_index, create_outcomes());
            let result_b = race_all_outcomes(winner_index, create_outcomes());

            // Verify deterministic outcomes
            prop_assert_eq!(result_a.winner_index, result_b.winner_index);
            prop_assert_eq!(
                race_outcome_signature(&result_a.winner_outcome),
                race_outcome_signature(&result_b.winner_outcome),
                "Winner outcomes must be deterministic"
            );

            // Verify deterministic drain patterns
            prop_assert_eq!(result_a.loser_outcomes.len(), result_b.loser_outcomes.len());

            for ((idx_a, outcome_a), (idx_b, outcome_b)) in
                result_a.loser_outcomes.iter().zip(result_b.loser_outcomes.iter()) {
                prop_assert_eq!(idx_a, idx_b, "Loser indices must be deterministic");
                prop_assert_eq!(
                    race_outcome_signature(outcome_a),
                    race_outcome_signature(outcome_b),
                    "Loser outcomes must be deterministic"
                );
            }

            // Both runs should maintain the drain invariant
            prop_assert!(result_a.loser_outcomes.iter().all(|(_, outcome)| outcome.is_cancelled()));
            prop_assert!(result_b.loser_outcomes.iter().all(|(_, outcome)| outcome.is_cancelled()));
        });
    }

    /// MR5: Race commutativity with drain preservation
    ///
    /// When swapping branch positions, the drain invariant should be preserved
    /// even though winner indices change.
    #[test]
    fn metamorphic_race_commutativity_preserves_drain() {
        proptest!(|(
            winner_case in race_winner_case_strategy(),
            loser_case in race_loser_case_strategy(),
        )| {
            // Race A vs B
            let outcomes_ab = vec![
                winner_case.clone().into_outcome(),
                loser_case.clone().into_outcome(),
            ];

            // Race B vs A (swapped)
            let outcomes_ba = vec![
                loser_case.clone().into_outcome(),
                winner_case.clone().into_outcome(),
            ];

            let result_ab = race_all_outcomes(0, outcomes_ab);
            let result_ba = race_all_outcomes(1, outcomes_ba);

            // Both should have exactly 1 loser (drained)
            prop_assert_eq!(result_ab.loser_outcomes.len(), 1);
            prop_assert_eq!(result_ba.loser_outcomes.len(), 1);

            prop_assert_eq!(
                race_outcome_signature(&result_ab.winner_outcome),
                race_outcome_signature(&result_ba.winner_outcome),
                "swapping branch positions must preserve the winning outcome"
            );

            let (_, loser_ab) = &result_ab.loser_outcomes[0];
            let (_, loser_ba) = &result_ba.loser_outcomes[0];

            prop_assert!(verify_losers_drained(&[loser_ab]).is_ok(), "AB loser must satisfy the drain invariant");
            prop_assert!(verify_losers_drained(&[loser_ba]).is_ok(), "BA loser must satisfy the drain invariant");
            prop_assert_eq!(
                race_outcome_signature(loser_ab),
                race_outcome_signature(loser_ba),
                "swapping branch positions must preserve the drained-loser outcome"
            );
        });
    }

    /// MR6: Panic propagation with loser drain
    ///
    /// When a branch panics, losers should still be properly drained.
    #[test]
    fn metamorphic_panic_propagation_preserves_loser_drain() {
        proptest!(|(
            branch_count in 2usize..6,
            raw_panic_index in 0usize..16,
        )| {
            let panic_index = raw_panic_index % branch_count;

            let mut outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            outcomes[panic_index] = Outcome::Panicked(PanicPayload::new("test panic"));

            let result = race_all_outcomes(panic_index, outcomes);

            // Winner should be the panicked branch
            prop_assert!(result.winner_outcome.is_panicked());
            prop_assert_eq!(result.winner_index, panic_index);

            // All losers should still be properly drained
            prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1);

            for (loser_index, loser_outcome) in &result.loser_outcomes {
                prop_assert!(*loser_index != panic_index);
                prop_assert!(loser_outcome.is_cancelled(),
                    "Loser {} should be drained even when winner panics", loser_index);

                if let Outcome::Cancelled(reason) = loser_outcome {
                    prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::RaceLost),
                        "Loser {} should be cancelled with RaceLost", loser_index);
                }
            }

            // Converting to fail-fast result should preserve panic but still track drained losers
            let fail_fast = race_all_to_result(result);
            prop_assert!(fail_fast.is_err());

            if let Err(RaceAllError::Panicked { index, .. }) = fail_fast {
                prop_assert_eq!(index, panic_index);
            } else {
                prop_assert!(false, "Expected panicked error");
            }
        });
    }

    // =========================================================================
    // Wave 58 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn polling_order_debug_clone_copy_eq_default() {
        let order = PollingOrder::default();
        let dbg = format!("{order:?}");
        assert!(dbg.contains("Biased"), "{dbg}");
        let copied = order;
        let cloned = order;
        assert_eq!(copied, cloned);
        assert_ne!(PollingOrder::Biased, PollingOrder::Unbiased);
    }

    #[test]
    fn race3_debug_clone_eq() {
        let r: Race3<i32, &str, bool> = Race3::First(42);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("First"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_eq!(r.winner_index(), 0);

        let r2: Race3<i32, &str, bool> = Race3::Second("hi");
        assert_ne!(r, r2);
        assert_eq!(r2.winner_index(), 1);
    }

    #[test]
    fn race4_debug_clone_eq() {
        let r: Race4<i32, i32, i32, i32> = Race4::Fourth(4);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Fourth"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_eq!(r.winner_index(), 3);
    }

    // ========================================================================
    // L-LOSER-DRAINED enforcement (br-asupersync-ttoyaz)
    // ========================================================================

    #[test]
    fn losers_drained_witness_accepts_terminal_outcomes_with_race_loser_cancel() {
        let losers: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(7),
            Outcome::Err("err"),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Panicked(PanicPayload::new("p")),
        ];
        let refs: Vec<&Outcome<i32, &str>> = losers.iter().collect();
        let witness = verify_losers_drained::<i32, &str>(&refs).expect("must accept");
        assert_eq!(witness.losers_checked(), 4);
    }

    #[test]
    fn losers_drained_witness_accepts_stronger_than_race_loser_kinds() {
        // Per §4.2 lemma L-LOSER-DRAINED, kinds at or above RaceLost severity
        // are valid for race losers. ParentCancelled (severity 4) is stronger
        // than RaceLost (severity 3) and must be accepted.
        let losers: Vec<Outcome<i32, &str>> = vec![Outcome::Cancelled(CancelReason::new(
            crate::types::cancel::CancelKind::ParentCancelled,
        ))];
        let refs: Vec<&Outcome<i32, &str>> = losers.iter().collect();
        let _ =
            verify_losers_drained::<i32, &str>(&refs).expect("ParentCancelled must be accepted");
    }

    #[test]
    fn losers_drained_witness_rejects_weaker_than_race_loser_cancel() {
        // User-cancel has severity 0; RaceLost requires severity >= 3.
        let losers: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::user("manual")),
        ];
        let refs: Vec<&Outcome<i32, &str>> = losers.iter().collect();
        let err =
            verify_losers_drained::<i32, &str>(&refs).expect_err("User-cancel loser must reject");
        match err {
            LoserDrainViolation::CancelKindTooWeak {
                index,
                seen_severity,
                required_severity,
            } => {
                assert_eq!(index, 1, "second loser is the violating one");
                assert!(seen_severity < required_severity);
            }
        }
    }

    #[test]
    fn losers_drained_witness_empty_slice_is_ok() {
        // Single-branch race has no losers — invariant trivially holds.
        let refs: Vec<&Outcome<i32, &str>> = Vec::new();
        let witness = verify_losers_drained::<i32, &str>(&refs).expect("must accept empty");
        assert_eq!(witness.losers_checked(), 0);
    }

    #[test]
    #[should_panic(expected = "L-LOSER-DRAINED invariant violated")]
    fn race2_outcomes_panics_on_loser_with_weak_cancel_kind() {
        // race2_outcomes now contains the explicit drain check. A driver that
        // hands in a loser cancelled with too weak a kind must crash here
        // rather than silently returning a result that violates §4.2.
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("not a race-loser"));
        let _ = race2_outcomes(RaceWinner::First, o1, o2);
    }

    #[test]
    #[should_panic(expected = "L-LOSER-DRAINED invariant violated")]
    fn race_all_outcomes_panics_on_loser_with_weak_cancel_kind() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(0),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::user("weak")),
        ];
        let _ = race_all_outcomes(0, outcomes);
    }
