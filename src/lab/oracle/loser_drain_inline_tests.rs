    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;
    use serde_json::{Value, json};

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
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

    fn scrub_loser_drain_trace(scenario_id: &str, oracle: &LoserDrainOracle) -> serde_json::Value {
        let active_races = oracle
            .active_races
            .iter()
            .map(|(race_id, record)| {
                json!({
                    "race_id": race_id,
                    "region": record.region.to_string(),
                    "participants": record
                        .participants
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    "start_time_nanos": record.start_time.as_nanos(),
                })
            })
            .collect::<Vec<_>>();

        let completed_races = oracle
            .completed_races
            .iter()
            .map(|(race_id, record)| {
                json!({
                    "race_id": race_id,
                    "winner": record.winner.to_string(),
                    "participants": record
                        .participants
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    "complete_time_nanos": record.complete_time.as_nanos(),
                })
            })
            .collect::<Vec<_>>();

        let unknown_completions = oracle
            .unknown_completions
            .iter()
            .map(|(race_id, record)| {
                json!({
                    "race_id": race_id,
                    "winner": record.winner.to_string(),
                    "complete_time_nanos": record.complete_time.as_nanos(),
                })
            })
            .collect::<Vec<_>>();

        let task_completions = oracle
            .task_completions
            .iter()
            .map(|(task, time)| {
                json!({
                    "task": task.to_string(),
                    "completed_at_nanos": time.as_nanos(),
                })
            })
            .collect::<Vec<_>>();

        let check = match oracle.check() {
            Ok(()) => json!({"status": "ok"}),
            Err(LoserDrainViolation::UndrainedLosers {
                race_id,
                winner,
                undrained_losers,
                race_complete_time,
            }) => json!({
                "status": "undrained_losers",
                "race_id": race_id,
                "winner": winner.to_string(),
                "undrained_losers": undrained_losers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "race_complete_time_nanos": race_complete_time.as_nanos(),
            }),
            Err(LoserDrainViolation::ActiveRaceNotCompleted {
                race_id,
                participants,
                race_start_time,
            }) => json!({
                "status": "active_race_not_completed",
                "race_id": race_id,
                "participants": participants
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "race_start_time_nanos": race_start_time.as_nanos(),
            }),
            Err(LoserDrainViolation::UnknownRaceCompletion {
                race_id,
                winner,
                race_complete_time,
            }) => json!({
                "status": "unknown_race_completion",
                "race_id": race_id,
                "winner": winner.to_string(),
                "race_complete_time_nanos": race_complete_time.as_nanos(),
            }),
            Err(LoserDrainViolation::InconsistentRaceCompletion { .. }) => json!({
                "violation": "inconsistent_race_completion",
            }),
        };

        json!({
            "scenario_id": scenario_id,
            "counts": {
                "race_count": oracle.race_count(),
                "active_race_count": oracle.active_race_count(),
                "completed_race_count": oracle.completed_race_count(),
            },
            "active_races": active_races,
            "completed_races": completed_races,
            "unknown_completions": unknown_completions,
            "task_completions": task_completions,
            "check": check,
        })
    }

    fn drained_three_way_loser_trace() -> Value {
        let mut oracle = LoserDrainOracle::new();
        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2), task(3)], t(10));

        oracle.on_task_complete(task(1), t(40));
        oracle.on_task_complete(task(2), t(60));
        oracle.on_task_complete(task(3), t(70));
        oracle.on_race_complete(race_id, task(1), t(80));

        scrub_loser_drain_trace("drained_three_way", &oracle)
    }

    fn undrained_multi_loser_trace() -> Value {
        let mut oracle = LoserDrainOracle::new();
        let race_id = oracle.on_race_start(
            region(1),
            vec![task(10), task(11), task(12), task(13)],
            t(100),
        );

        oracle.on_task_complete(task(10), t(140));
        oracle.on_task_complete(task(11), t(145));
        oracle.on_race_complete(race_id, task(10), t(150));
        oracle.on_task_complete(task(12), t(220));

        scrub_loser_drain_trace("undrained_multi_loser", &oracle)
    }

    fn unknown_completion_trace() -> Value {
        let mut oracle = LoserDrainOracle::new();
        oracle.on_race_complete(77, task(21), t(900));
        oracle.on_task_complete(task(21), t(880));

        scrub_loser_drain_trace("unknown_completion", &oracle)
    }

    #[test]
    fn loser_drain_trace_bundle_snapshot() {
        let bundle = vec![
            drained_three_way_loser_trace(),
            undrained_multi_loser_trace(),
            unknown_completion_trace(),
        ];

        insta::assert_json_snapshot!("loser_drain_trace_bundle", bundle);
    }

    #[test]
    fn no_races_passes() {
        init_test("no_races_passes");
        let oracle = LoserDrainOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("no_races_passes");
    }

    #[test]
    fn properly_drained_race_passes() {
        init_test("properly_drained_race_passes");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));

        // Both tasks complete before race completes
        oracle.on_task_complete(task(1), t(50)); // Winner
        oracle.on_task_complete(task(2), t(60)); // Loser drained

        oracle.on_race_complete(race_id, task(1), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("properly_drained_race_passes");
    }

    #[test]
    fn owner_cancelled_race_requires_every_participant_to_drain() {
        init_test("owner_cancelled_race_requires_every_participant_to_drain");
        let owner = task(9);
        let participants = vec![task(1), task(2), task(3)];

        for &missing in &participants {
            let mut oracle = LoserDrainOracle::new();
            let race_id = oracle.on_race_start(region(0), participants.clone(), t(0));
            for &participant in &participants {
                if participant != missing {
                    oracle.on_task_complete(participant, t(50));
                }
            }
            oracle.on_race_complete(race_id, owner, t(100));

            // In particular, the first branch cannot be labelled a synthetic
            // winner and thereby escape the all-participant drain requirement.
            for completion in [None, Some(t(150))] {
                if let Some(time) = completion {
                    oracle.on_task_complete(missing, time);
                }
                match oracle.check() {
                    Err(LoserDrainViolation::UndrainedLosers {
                        race_id: actual_race,
                        winner,
                        undrained_losers,
                        race_complete_time,
                    }) => {
                        crate::assert_with_log!(
                            actual_race == race_id,
                            "race",
                            race_id,
                            actual_race
                        );
                        crate::assert_with_log!(winner == owner, "owner", owner, winner);
                        crate::assert_with_log!(
                            undrained_losers == vec![missing],
                            "undrained participant",
                            vec![missing],
                            undrained_losers
                        );
                        crate::assert_with_log!(
                            race_complete_time == t(100),
                            "completion boundary",
                            t(100),
                            race_complete_time
                        );
                    }
                    other => panic!(
                        "owner-cancelled race must reject participant {missing:?} with completion {completion:?}: {other:?}"
                    ),
                }
            }
        }
        crate::test_complete!("owner_cancelled_race_requires_every_participant_to_drain");
    }

    #[test]
    fn owner_cancelled_race_passes_after_every_participant_drains() {
        init_test("owner_cancelled_race_passes_after_every_participant_drains");
        let mut oracle = LoserDrainOracle::new();
        let participants = vec![task(1), task(2), task(3)];
        let owner = task(9);
        let race_id = oracle.on_race_start(region(0), participants.clone(), t(0));
        for participant in participants {
            oracle.on_task_complete(participant, t(100));
        }
        // The race's owner is still running: only its branches must retire
        // before the cancelled race can return to it.
        oracle.on_race_complete(race_id, owner, t(100));

        let result = oracle.check();
        crate::assert_with_log!(result.is_ok(), "all participants drained", "Ok", result);
        crate::assert_with_log!(
            oracle.active_race_count() == 0,
            "active races",
            0,
            oracle.active_race_count()
        );
        crate::assert_with_log!(
            oracle.completed_race_count() == 1,
            "completed races",
            1,
            oracle.completed_race_count()
        );
        crate::test_complete!("owner_cancelled_race_passes_after_every_participant_drains");
    }

    #[test]
    fn undrained_loser_fails() {
        init_test("undrained_loser_fails");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));

        // Only winner completes before race completes
        oracle.on_task_complete(task(1), t(50));
        oracle.on_race_complete(race_id, task(1), t(100));

        // Loser completes after race (violation)
        oracle.on_task_complete(task(2), t(150));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        match violation {
            LoserDrainViolation::UndrainedLosers {
                winner,
                undrained_losers,
                ..
            } => {
                crate::assert_with_log!(winner == task(1), "winner", task(1), winner);
                crate::assert_with_log!(
                    undrained_losers == vec![task(2)],
                    "undrained_losers",
                    vec![task(2)],
                    undrained_losers
                );
            }
            other => panic!("expected UndrainedLosers, got {other:?}"),
        }
        crate::test_complete!("undrained_loser_fails");
    }

    #[test]
    fn loser_never_completes_fails() {
        init_test("loser_never_completes_fails");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));

        oracle.on_task_complete(task(1), t(50));
        oracle.on_race_complete(race_id, task(1), t(100));

        // task(2) never completes

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        match violation {
            LoserDrainViolation::UndrainedLosers {
                undrained_losers, ..
            } => {
                crate::assert_with_log!(
                    undrained_losers == vec![task(2)],
                    "undrained_losers",
                    vec![task(2)],
                    undrained_losers
                );
            }
            other => panic!("expected UndrainedLosers, got {other:?}"),
        }
        crate::test_complete!("loser_never_completes_fails");
    }

    #[test]
    fn three_way_race_all_drained_passes() {
        init_test("three_way_race_all_drained_passes");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2), task(3)], t(0));

        // All complete before race completes
        oracle.on_task_complete(task(1), t(50)); // Winner
        oracle.on_task_complete(task(2), t(60)); // Loser 1
        oracle.on_task_complete(task(3), t(70)); // Loser 2

        oracle.on_race_complete(race_id, task(1), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("three_way_race_all_drained_passes");
    }

    #[test]
    fn loser_completes_at_same_time_as_race_passes() {
        init_test("loser_completes_at_same_time_as_race_passes");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));

        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(100)); // Same time as race complete

        oracle.on_race_complete(race_id, task(1), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("loser_completes_at_same_time_as_race_passes");
    }

    #[test]
    fn multiple_races_independent() {
        init_test("multiple_races_independent");
        let mut oracle = LoserDrainOracle::new();

        // Race 1: properly drained
        let race1 = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(60));
        oracle.on_race_complete(race1, task(1), t(100));

        // Race 2: not drained
        let race2 = oracle.on_race_start(region(0), vec![task(3), task(4)], t(100));
        oracle.on_task_complete(task(3), t(150));
        oracle.on_race_complete(race2, task(3), t(200));
        // task(4) not completed

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        match violation {
            LoserDrainViolation::UndrainedLosers { race_id, .. } => {
                crate::assert_with_log!(race_id == race2, "race_id", race2, race_id);
            }
            other => panic!("expected UndrainedLosers, got {other:?}"),
        }
        crate::test_complete!("multiple_races_independent");
    }

    #[test]
    fn completed_race_is_retired_from_active_tracking() {
        init_test("completed_race_is_retired_from_active_tracking");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(60));
        oracle.on_race_complete(race_id, task(1), t(100));

        let active = oracle.active_race_count();
        crate::assert_with_log!(active == 0, "active_race_count", 0, active);
        let completed = oracle.completed_race_count();
        crate::assert_with_log!(completed == 1, "completed_race_count", 1, completed);
        let total = oracle.race_count();
        crate::assert_with_log!(total == 1, "race_count", 1, total);

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("completed_race_is_retired_from_active_tracking");
    }

    #[test]
    fn duplicate_race_complete_preserves_original_participants() {
        init_test("duplicate_race_complete_preserves_original_participants");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_race_complete(race_id, task(1), t(100));

        // Exact duplicate completion events must not erase the original
        // participant set.
        oracle.on_race_complete(race_id, task(1), t(100));

        let violation = oracle
            .check()
            .expect_err("duplicate complete must not erase the undrained loser");
        match violation {
            LoserDrainViolation::UndrainedLosers {
                race_id: violation_race_id,
                winner,
                undrained_losers,
                race_complete_time,
            } => {
                crate::assert_with_log!(
                    violation_race_id == race_id,
                    "race_id",
                    race_id,
                    violation_race_id
                );
                crate::assert_with_log!(winner == task(1), "winner", task(1), winner);
                crate::assert_with_log!(
                    undrained_losers == vec![task(2)],
                    "undrained_losers",
                    vec![task(2)],
                    undrained_losers
                );
                crate::assert_with_log!(
                    race_complete_time == t(100),
                    "race_complete_time",
                    t(100),
                    race_complete_time
                );
            }
            other => panic!("expected UndrainedLosers, got {other:?}"),
        }
        crate::test_complete!("duplicate_race_complete_preserves_original_participants");
    }

    #[test]
    fn active_race_without_completion_fails() {
        init_test("active_race_without_completion_fails");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(10));
        oracle.on_task_complete(task(1), t(50));

        let violation = oracle
            .check()
            .expect_err("active race must not be silently ignored");
        match violation {
            LoserDrainViolation::ActiveRaceNotCompleted {
                race_id: violation_race_id,
                participants,
                race_start_time,
            } => {
                crate::assert_with_log!(
                    violation_race_id == race_id,
                    "race_id",
                    race_id,
                    violation_race_id
                );
                crate::assert_with_log!(
                    participants == vec![task(1), task(2)],
                    "participants",
                    vec![task(1), task(2)],
                    participants
                );
                crate::assert_with_log!(
                    race_start_time == t(10),
                    "race_start_time",
                    t(10),
                    race_start_time
                );
            }
            other => panic!("expected ActiveRaceNotCompleted, got {other:?}"),
        }
        crate::test_complete!("active_race_without_completion_fails");
    }

    #[test]
    fn unknown_race_completion_fails() {
        init_test("unknown_race_completion_fails");
        let mut oracle = LoserDrainOracle::new();

        oracle.on_race_complete(42, task(9), t(100));

        let violation = oracle
            .check()
            .expect_err("completion without start must not be silently accepted");
        match violation {
            LoserDrainViolation::UnknownRaceCompletion {
                race_id,
                winner,
                race_complete_time,
            } => {
                crate::assert_with_log!(race_id == 42, "race_id", 42, race_id);
                crate::assert_with_log!(winner == task(9), "winner", task(9), winner);
                crate::assert_with_log!(
                    race_complete_time == t(100),
                    "race_complete_time",
                    t(100),
                    race_complete_time
                );
            }
            other => panic!("expected UnknownRaceCompletion, got {other:?}"),
        }
        crate::test_complete!("unknown_race_completion_fails");
    }

    #[test]
    fn duplicate_race_complete_with_same_winner_and_time_is_idempotent() {
        // br-asupersync-htqzu1: a duplicate completion that exactly matches
        // the prior outcome is a benign retry — no violation.
        init_test("duplicate_race_complete_with_same_winner_and_time_is_idempotent");
        let mut oracle = LoserDrainOracle::new();
        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(80));
        oracle.on_race_complete(race_id, task(1), t(100));
        // Exact duplicate.
        oracle.on_race_complete(race_id, task(1), t(100));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "idempotent duplicate", true, ok);
        crate::test_complete!("duplicate_race_complete_with_same_winner_and_time_is_idempotent");
    }

    #[test]
    fn duplicate_race_complete_with_different_winner_flags_violation() {
        // br-asupersync-htqzu1: the second completion of the same race with
        // a different winner is a runtime bug. The oracle previously
        // silently dropped this; now it must surface as
        // InconsistentRaceCompletion.
        init_test("duplicate_race_complete_with_different_winner_flags_violation");
        let mut oracle = LoserDrainOracle::new();
        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(80));
        oracle.on_race_complete(race_id, task(1), t(100));
        // Conflicting duplicate — different winner.
        oracle.on_race_complete(race_id, task(2), t(100));
        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "violation surfaced", true, err);
        let violation = result.unwrap_err();
        let inconsistent = matches!(
            violation,
            LoserDrainViolation::InconsistentRaceCompletion { .. }
        );
        crate::assert_with_log!(
            inconsistent,
            "InconsistentRaceCompletion",
            true,
            inconsistent
        );
        crate::test_complete!("duplicate_race_complete_with_different_winner_flags_violation");
    }

    #[test]
    fn duplicate_race_complete_with_different_time_flags_violation() {
        // br-asupersync-htqzu1: same winner but a contradictory completion
        // time is also a runtime inconsistency the oracle must report.
        init_test("duplicate_race_complete_with_different_time_flags_violation");
        let mut oracle = LoserDrainOracle::new();
        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(80));
        oracle.on_race_complete(race_id, task(1), t(100));
        oracle.on_race_complete(race_id, task(1), t(150));
        let violation = oracle.check().expect_err("violation expected");
        let inconsistent = matches!(
            violation,
            LoserDrainViolation::InconsistentRaceCompletion { .. }
        );
        crate::assert_with_log!(
            inconsistent,
            "InconsistentRaceCompletion",
            true,
            inconsistent
        );
        crate::test_complete!("duplicate_race_complete_with_different_time_flags_violation");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = LoserDrainOracle::new();

        let race_id = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
        oracle.on_task_complete(task(1), t(50));
        oracle.on_race_complete(race_id, task(1), t(100));

        // Would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let active = oracle.active_race_count();
        crate::assert_with_log!(active == 0, "active_race_count", 0, active);
        let completed = oracle.completed_race_count();
        crate::assert_with_log!(completed == 0, "completed_race_count", 0, completed);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = LoserDrainViolation::UndrainedLosers {
            race_id: 42,
            winner: task(1),
            undrained_losers: vec![task(2), task(3)],
            race_complete_time: t(100),
        };

        let s = violation.to_string();
        let has_race = s.contains("Race 42");
        crate::assert_with_log!(has_race, "race text", true, has_race);
        let has_undrained = s.contains("undrained");
        crate::assert_with_log!(has_undrained, "undrained text", true, has_undrained);
        let has_two = s.contains('2');
        crate::assert_with_log!(has_two, "contains 2", true, has_two);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn nested_race_tracking() {
        init_test("nested_race_tracking");
        let mut oracle = LoserDrainOracle::new();

        // Outer race starts
        let outer = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));

        // Inner race (task 1 spawns subtasks)
        let inner = oracle.on_race_start(region(1), vec![task(3), task(4)], t(10));

        // Inner race completes properly
        oracle.on_task_complete(task(3), t(30));
        oracle.on_task_complete(task(4), t(35));
        oracle.on_race_complete(inner, task(3), t(40));

        // Outer race completes properly
        oracle.on_task_complete(task(1), t(50));
        oracle.on_task_complete(task(2), t(60));
        oracle.on_race_complete(outer, task(1), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("nested_race_tracking");
    }

    // =========================================================================
    // Wave 49 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn loser_drain_violation_debug_clone() {
        let v = LoserDrainViolation::UndrainedLosers {
            race_id: 1,
            winner: task(1),
            undrained_losers: vec![task(2), task(3)],
            race_complete_time: t(100),
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("UndrainedLosers"), "{dbg}");
        let cloned = v;
        match cloned {
            LoserDrainViolation::UndrainedLosers {
                race_id,
                undrained_losers,
                ..
            } => {
                assert_eq!(race_id, 1);
                assert_eq!(undrained_losers.len(), 2);
            }
            other => panic!("expected UndrainedLosers, got {other:?}"),
        }
    }

    #[test]
    fn loser_drain_oracle_default() {
        let def = LoserDrainOracle::default();
        let dbg = format!("{def:?}");
        assert!(dbg.contains("LoserDrainOracle"), "{dbg}");
        assert!(def.check().is_ok());
    }
