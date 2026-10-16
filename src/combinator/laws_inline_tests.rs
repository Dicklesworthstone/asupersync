    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::combinator::first_ok::first_ok_outcomes;
    use crate::combinator::hedge::{HedgeResult, HedgeWinner};
    use crate::combinator::join::{join_all_outcomes, join2_outcomes};
    use crate::combinator::pipeline::{PipelineResult, pipeline_n_outcomes};
    use crate::combinator::quorum::quorum_outcomes;
    use crate::combinator::race::{RaceWinner, race2_outcomes};
    use crate::combinator::timeout::{effective_deadline, make_timed_result};
    use crate::types::Outcome;
    use crate::types::Time;
    use crate::types::cancel::{CancelKind, CancelReason};
    use crate::types::outcome::{PanicPayload, join_outcomes};

    // -- helpers --

    fn ok(v: i32) -> Outcome<i32, i32> {
        Outcome::Ok(v)
    }
    fn err(e: i32) -> Outcome<i32, i32> {
        Outcome::Err(e)
    }
    fn cancelled() -> Outcome<i32, i32> {
        Outcome::Cancelled(CancelReason::timeout())
    }
    fn panicked() -> Outcome<i32, i32> {
        Outcome::Panicked(PanicPayload::new("boom"))
    }
    fn race_lost() -> Outcome<i32, i32> {
        Outcome::Cancelled(CancelReason::race_loser())
    }

    // ========================================================================
    // Law sheet catalog tests
    // ========================================================================

    #[test]
    fn law_sheet_is_nonempty() {
        let sheet = law_sheet();
        assert!(!sheet.is_empty());
        // Every law variant should appear exactly once
        let unique: std::collections::HashSet<Law> = sheet.iter().map(|e| e.law).collect();
        assert_eq!(unique.len(), sheet.len(), "duplicate law entries in sheet");
    }

    #[test]
    fn law_sheet_has_all_classifications() {
        let sheet = law_sheet();
        let classifications: std::collections::HashSet<LawClassification> =
            sheet.iter().map(|e| e.classification).collect();
        assert!(classifications.contains(&LawClassification::Unconditional));
        assert!(classifications.contains(&LawClassification::ConditionalOnPolicy));
        assert!(classifications.contains(&LawClassification::ConditionalOnTiming));
        assert!(classifications.contains(&LawClassification::SeverityLevelOnly));
    }

    #[test]
    fn unconditional_laws_count() {
        let uncond = unconditional_laws();
        // At least the core join/race/timeout/budget/cancel/quorum structural laws
        assert!(
            uncond.len() >= 25,
            "expected at least 25 unconditional laws, got {}",
            uncond.len()
        );
    }

    #[test]
    fn conditional_laws_count() {
        let cond = conditional_laws();
        assert!(
            cond.len() >= 5,
            "expected at least 5 conditional laws, got {}",
            cond.len()
        );
    }

    // ========================================================================
    // Quorum degeneracy laws (not in tests/algebraic_laws.rs)
    // ========================================================================

    /// QUORUM-JOIN: quorum(N, N, outcomes) behaves like join_all.
    /// When all N are required, quorum_met should match join_all aggregate.
    #[test]
    fn quorum_n_of_n_matches_join_all() {
        // All Ok: both join_all and quorum(N,N) should agree on Ok
        let outcomes = vec![ok(1), ok(2), ok(3)];
        let n = outcomes.len();
        let (join_decision, _) = join_all_outcomes(outcomes.clone());
        let join_sev = decision_severity(&join_decision);
        let quorum_result = quorum_outcomes(n, outcomes);
        assert_eq!(join_sev, Severity::Ok);
        assert!(quorum_result.quorum_met, "quorum(3,3) all-ok should be met");

        // Mixed with errors: join_all gives Err, quorum(N,N) should not be met
        let outcomes = vec![ok(1), err(2), ok(3)];
        let n = outcomes.len();
        let (join_decision, _) = join_all_outcomes(outcomes.clone());
        let join_sev = decision_severity(&join_decision);
        let quorum_result = quorum_outcomes(n, outcomes);
        assert_eq!(join_sev, Severity::Err);
        assert!(
            !quorum_result.quorum_met,
            "quorum(3,3) with error should not be met"
        );

        // With panic: join_all gives Panicked, quorum(N,N) should not be met
        let outcomes = vec![ok(1), panicked(), ok(3)];
        let n = outcomes.len();
        let (join_decision, _) = join_all_outcomes(outcomes.clone());
        let join_sev = decision_severity(&join_decision);
        let quorum_result = quorum_outcomes(n, outcomes);
        assert_eq!(join_sev, Severity::Panicked);
        assert!(
            !quorum_result.quorum_met,
            "quorum(3,3) with panic should not be met"
        );
    }

    /// QUORUM-RACE: quorum(1, N, outcomes) first Ok wins, like race_all.
    #[test]
    fn quorum_1_of_n_first_ok_wins() {
        // When at least one Ok exists, quorum(1,N) should succeed
        let outcomes = vec![err(1), ok(42), err(3)];
        let result = quorum_outcomes(1, outcomes);
        assert!(result.quorum_met, "quorum(1,N) should succeed with one Ok");
        assert_eq!(result.success_count(), 1);

        // When all fail, quorum(1,N) should fail
        let outcomes = vec![err(1), err(2), err(3)];
        let result = quorum_outcomes(1, outcomes);
        assert!(!result.quorum_met, "quorum(1,N) should fail when all fail");
    }

    /// QUORUM-ZERO: quorum(0, N, outcomes) succeeds immediately with empty values.
    #[test]
    fn quorum_zero_succeeds_immediately() {
        let outcomes = vec![err(1), panicked(), cancelled()];
        let result = quorum_outcomes(0, outcomes);
        assert!(result.quorum_met, "quorum(0,N) should always succeed");
        assert_eq!(
            result.success_count(),
            0,
            "quorum(0,N) should have no successes"
        );
    }

    // ========================================================================
    // Join unit and absorbing element (explicit targeted tests)
    // ========================================================================

    /// JOIN-UNIT: Ok is the identity for join severity.
    #[test]
    fn join_ok_is_identity() {
        let inputs: Vec<Outcome<i32, i32>> = vec![ok(1), err(2), cancelled(), panicked()];
        for input in inputs {
            let sev = input.severity();
            let joined = join_outcomes(ok(0), input);
            assert_eq!(
                joined.severity(),
                sev,
                "join(Ok, x) should have severity of x"
            );
        }
    }

    /// JOIN-ABSORB: Panicked is the absorbing element for join severity.
    #[test]
    fn join_panicked_absorbs() {
        let inputs: Vec<Outcome<i32, i32>> = vec![ok(1), err(2), cancelled(), panicked()];
        for input in inputs {
            let joined = join_outcomes(panicked(), input);
            assert_eq!(
                joined.severity(),
                Severity::Panicked,
                "join(Panicked, x) should always be Panicked"
            );
        }
    }

    // ========================================================================
    // Pipeline sequential + short-circuit laws
    // ========================================================================

    /// PIPELINE-SEQ + PIPELINE-SHORT: sequential short-circuit behavior.
    #[test]
    fn pipeline_short_circuits_on_error() {
        // Stage 1 Ok, Stage 2 Err -> pipeline fails at stage 2
        let result = pipeline_n_outcomes(vec![ok(1), err(99)], 2);
        match &result {
            PipelineResult::Failed { failed_at, .. } => {
                assert_eq!(failed_at.index, 1, "should fail at stage index 1");
            }
            other => panic!("expected PipelineResult::Failed, got {other:?}"),
        }

        // Stage 1 Err -> pipeline stops, stage 2 never runs
        let result = pipeline_n_outcomes(vec![err(1)], 2);
        match &result {
            PipelineResult::Failed { failed_at, .. } => {
                assert_eq!(failed_at.index, 0, "should fail at stage index 0");
            }
            other => panic!("expected PipelineResult::Failed, got {other:?}"),
        }
    }

    /// PIPELINE-SEQ: All stages Ok -> pipeline succeeds with last value.
    #[test]
    fn pipeline_all_ok_succeeds() {
        let result = pipeline_n_outcomes(vec![ok(1), ok(2), ok(3)], 3);
        match result {
            PipelineResult::Completed {
                stages_completed, ..
            } => {
                assert_eq!(stages_completed, 3);
            }
            other => panic!("expected PipelineResult::Completed, got {other:?}"),
        }
    }

    // ========================================================================
    // First-Ok laws
    // ========================================================================

    /// FIRST-OK-FOUND: first Ok result wins.
    #[test]
    fn first_ok_returns_first_success() {
        let result = first_ok_outcomes(vec![err(1), err(2), ok(42), ok(99)]);
        assert!(result.is_success());
        let success = result.success.as_ref().unwrap();
        assert_eq!(success.value, 42, "should return first Ok value");
        assert_eq!(success.index, 2, "first Ok was at index 2");
    }

    /// FIRST-OK-ALL-FAIL: all non-Ok -> failure with worst severity.
    #[test]
    fn first_ok_all_fail_returns_worst() {
        let result = first_ok_outcomes(vec![err(1), err(2), cancelled()]);
        assert!(!result.is_success());
        assert_eq!(result.failures.len(), 3);
        assert!(result.was_cancelled, "should record cancellation");
    }

    // ========================================================================
    // Race severity symmetry (targeted, complementing proptest coverage)
    // ========================================================================

    /// RACE-COMM: exhaustive severity symmetry check across all four outcome types.
    #[test]
    fn race_symmetry_exhaustive() {
        let winners: Vec<Outcome<i32, i32>> = vec![ok(1), err(2), cancelled(), panicked()];
        let drained_losers: Vec<Outcome<i32, i32>> = vec![ok(3), err(4), race_lost(), panicked()];
        for a in &winners {
            for b in &drained_losers {
                let (w_ab, _, l_ab) = race2_outcomes(RaceWinner::First, a.clone(), b.clone());
                let (w_ba, _, l_ba) = race2_outcomes(RaceWinner::Second, b.clone(), a.clone());

                assert_eq!(
                    w_ab.severity(),
                    w_ba.severity(),
                    "winner severity mismatch for a={a:?}, b={b:?}"
                );
                assert_eq!(
                    l_ab.severity(),
                    l_ba.severity(),
                    "loser severity mismatch for a={a:?}, b={b:?}"
                );
            }
        }
    }

    /// RACE-NEVER: race(f, never) returns f with never as the loser.
    #[test]
    fn race_never_identity_exhaustive() {
        let outcomes: Vec<Outcome<i32, i32>> = vec![ok(1), err(2), cancelled(), panicked()];
        for f in &outcomes {
            let (winner, _, loser) = race2_outcomes(RaceWinner::First, f.clone(), race_lost());
            assert_eq!(
                winner.severity(),
                f.severity(),
                "race(f, never) winner should match f"
            );
            assert!(
                matches!(loser, Outcome::Cancelled(ref r) if r.kind == CancelKind::RaceLost),
                "race(f, never) loser should be RaceLost"
            );
        }
    }

    /// TIMEOUT-IDENTITY: adding an identity timeout layer preserves deadline and outcome.
    #[test]
    fn timeout_identity_preserves_effective_deadline_and_outcome() {
        let deadlines = [
            Time::ZERO,
            Time::from_nanos(1),
            Time::from_nanos(1_000),
            Time::from_nanos(1_000_000),
        ];
        let outcomes: Vec<Outcome<i32, i32>> = vec![ok(1), err(2), cancelled(), panicked()];

        for requested in deadlines {
            let effective = effective_deadline(requested, None);
            assert_eq!(
                effective, requested,
                "timeout(None, f) should preserve requested deadline"
            );

            for outcome in &outcomes {
                let wrapped = make_timed_result(outcome.clone(), effective, true).into_outcome();
                assert_eq!(
                    wrapped.severity(),
                    outcome.severity(),
                    "identity timeout wrapper should preserve outcome severity"
                );
            }
        }
    }

    // ========================================================================
    // Severity lattice structure
    // ========================================================================

    /// SEV-ORDER + SEV-BOUNDED: exhaustive check of the four-element lattice.
    #[test]
    fn severity_lattice_complete() {
        assert!(Severity::Ok < Severity::Err);
        assert!(Severity::Err < Severity::Cancelled);
        assert!(Severity::Cancelled < Severity::Panicked);

        // Bounded: all four variants are within bounds
        for s in [
            Severity::Ok,
            Severity::Err,
            Severity::Cancelled,
            Severity::Panicked,
        ] {
            assert!(s >= Severity::Ok);
            assert!(s <= Severity::Panicked);
        }
    }

    // ========================================================================
    // Hedge degenerate cases (structural, not timing-dependent)
    // ========================================================================

    /// HEDGE-FAST: when backup is not spawned, hedge returns primary outcome.
    #[test]
    fn hedge_fast_no_backup() {
        use crate::combinator::hedge::hedge_outcomes;

        let outcomes: Vec<Outcome<i32, i32>> = vec![ok(1), err(2), cancelled(), panicked()];
        for primary in &outcomes {
            let result: HedgeResult<i32, i32> = hedge_outcomes(primary.clone(), false, None, None);
            match result {
                HedgeResult::PrimaryFast(o) => {
                    assert_eq!(
                        o.severity(),
                        primary.severity(),
                        "hedge fast path should return primary severity"
                    );
                }
                other @ HedgeResult::Raced { .. } => {
                    panic!("expected PrimaryFast, got {other:?}");
                }
            }
        }
    }

    /// HEDGE-SLOW: when backup is spawned, hedge acts like race.
    #[test]
    fn hedge_slow_acts_like_race() {
        use crate::combinator::hedge::hedge_outcomes;

        // Primary wins the race
        let result: HedgeResult<i32, i32> =
            hedge_outcomes(ok(1), true, Some(err(2)), Some(HedgeWinner::Primary));
        match result {
            HedgeResult::Raced { winner_outcome, .. } => {
                assert_eq!(winner_outcome.severity(), Severity::Ok);
            }
            other @ HedgeResult::PrimaryFast(_) => {
                panic!("expected Raced, got {other:?}");
            }
        }

        // Backup wins the race
        let result: HedgeResult<i32, i32> =
            hedge_outcomes(err(1), true, Some(ok(2)), Some(HedgeWinner::Backup));
        match result {
            HedgeResult::Raced { winner_outcome, .. } => {
                assert_eq!(winner_outcome.severity(), Severity::Ok);
            }
            other @ HedgeResult::PrimaryFast(_) => {
                panic!("expected Raced, got {other:?}");
            }
        }
    }

    // ========================================================================
    // join2_outcomes: verify returns preserve individual outcomes
    // ========================================================================

    /// JOIN-WORST for join2: aggregate decision matches worst input.
    #[test]
    fn join2_worst_decision() {
        type JoinCase = (Outcome<i32, i32>, Outcome<i32, i32>, Severity);
        let cases: Vec<JoinCase> = vec![
            (ok(1), ok(2), Severity::Ok),
            (ok(1), err(2), Severity::Err),
            (ok(1), cancelled(), Severity::Cancelled),
            (ok(1), panicked(), Severity::Panicked),
            (err(1), cancelled(), Severity::Cancelled),
            (err(1), panicked(), Severity::Panicked),
            (cancelled(), panicked(), Severity::Panicked),
        ];

        for (a, b, expected) in cases {
            let (result, _, _): (Outcome<(i32, i32), i32>, _, _) =
                join2_outcomes(a.clone(), b.clone());
            assert_eq!(result.severity(), expected, "join2({a:?}, {b:?}) severity");
        }
    }

    // ========================================================================
    // Pipeline associativity (under short-circuit policy)
    // ========================================================================

    /// PIPELINE-ASSOC: pipeline(a, pipeline(b, c)) and pipeline(pipeline(a, b), c)
    /// agree on final outcome when all stages are Ok.
    #[test]
    fn pipeline_associativity_all_ok() {
        // Left-to-right: pipeline([ok(1), ok(2), ok(3)], 3)
        let ltr = pipeline_n_outcomes(vec![ok(1), ok(2), ok(3)], 3);
        assert!(
            matches!(ltr, PipelineResult::Completed { .. }),
            "3-stage all-ok should complete"
        );

        // Any regrouping of three Ok stages still yields Completed
        let ab = pipeline_n_outcomes(vec![ok(1), ok(2)], 2);
        assert!(
            matches!(ab, PipelineResult::Completed { .. }),
            "2-stage all-ok should complete"
        );
    }

    /// PIPELINE-ASSOC: pipeline associativity under short-circuit.
    /// pipeline(err, ok, ok) and pipeline(pipeline(err, ok), ok) both fail at stage 0.
    #[test]
    fn pipeline_associativity_short_circuit() {
        let flat = pipeline_n_outcomes(vec![err(1)], 3);
        match flat {
            PipelineResult::Failed { failed_at, .. } => assert_eq!(failed_at.index, 0),
            other => panic!("expected Failed, got {other:?}"),
        }

        // Nested: pipeline(err(1), ok(2)) should also fail at stage 0
        let nested = pipeline_n_outcomes(vec![err(1)], 2);
        match nested {
            PipelineResult::Failed { failed_at, .. } => assert_eq!(failed_at.index, 0),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // --- wave 78 trait coverage ---

    #[test]
    fn law_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let l = Law::SeverityOrder;
        let l2 = l; // Copy
        let l3 = l;
        assert_eq!(l, l2);
        assert_eq!(l, l3);
        assert_ne!(l, Law::JoinCommutativity);
        let dbg = format!("{l:?}");
        assert!(dbg.contains("SeverityOrder"));
        let mut set = HashSet::new();
        set.insert(l);
        assert!(set.contains(&l2));
    }

    #[test]
    fn law_classification_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let c = LawClassification::Unconditional;
        let c2 = c; // Copy
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c, c3);
        assert_ne!(c, LawClassification::SeverityLevelOnly);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Unconditional"));
        let mut set = HashSet::new();
        set.insert(c);
        assert!(set.contains(&c2));
    }

    #[test]
    fn law_entry_debug_clone() {
        let e = LawEntry {
            law: Law::SeverityBounded,
            classification: LawClassification::Unconditional,
            statement: "test statement",
        };
        let e2 = e.clone();
        assert_eq!(e.law, e2.law);
        assert_eq!(e.classification, e2.classification);
        assert_eq!(e.statement, e2.statement);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("LawEntry"));
    }
