//! Loser drain oracle for verifying invariant #4: losers are always drained.
//!
//! This oracle verifies that in race combinators, all losing tasks are
//! cancelled AND drained to completion before the race returns.
//!
//! # Invariant
//!
//! From asupersync_plan_v4.md:
//! > Losers are drained: races must cancel and fully drain losers
//!
//! Formally: `∀race: ∀loser ∈ race.losers: loser.state = Completed`
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = LoserDrainOracle::new();
//!
//! // During execution, record events:
//! let race_id = oracle.on_race_start(region, vec![t1, t2], time);
//! oracle.on_task_complete(t1, time);  // winner
//! oracle.on_task_complete(t2, time);  // loser drained
//! oracle.on_race_complete(race_id, t1, time);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use crate::types::{RegionId, TaskId, Time};
use std::collections::BTreeMap;
use std::fmt;

/// A loser drain violation.
///
/// This indicates either that a completed race failed to drain its losers, or
/// that the oracle observed impossible race instrumentation (for example, a
/// completion without a matching start).
#[derive(Debug, Clone)]
pub enum LoserDrainViolation {
    /// A completed race returned before one or more losers drained.
    UndrainedLosers {
        /// The race identifier.
        race_id: u64,
        /// The winning task.
        winner: TaskId,
        /// Tasks that were not drained when the race completed.
        undrained_losers: Vec<TaskId>,
        /// The time when the race completed.
        race_complete_time: Time,
    },
    /// A race was started but never completed by the time the oracle checked.
    ActiveRaceNotCompleted {
        /// The race identifier.
        race_id: u64,
        /// All participants in the still-active race.
        participants: Vec<TaskId>,
        /// The time when the race started.
        race_start_time: Time,
    },
    /// A race completion was recorded without a matching prior start.
    UnknownRaceCompletion {
        /// The race identifier.
        race_id: u64,
        /// The recorded winning task.
        winner: TaskId,
        /// The time when the race completed.
        race_complete_time: Time,
    },
}

impl fmt::Display for LoserDrainViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndrainedLosers {
                race_id,
                race_complete_time,
                undrained_losers,
                ..
            } => write!(
                f,
                "Race {} completed at {:?} with {} undrained loser(s): {:?}",
                race_id,
                race_complete_time,
                undrained_losers.len(),
                undrained_losers
            ),
            Self::ActiveRaceNotCompleted {
                race_id,
                participants,
                race_start_time,
            } => write!(
                f,
                "Race {race_id} started at {race_start_time:?} never completed; participants: {participants:?}"
            ),
            Self::UnknownRaceCompletion {
                race_id,
                winner,
                race_complete_time,
            } => write!(
                f,
                "Race {race_id} completed at {race_complete_time:?} with winner {winner:?} but was never started"
            ),
        }
    }
}

impl std::error::Error for LoserDrainViolation {}

/// Record of an active race.
#[derive(Debug, Clone)]
struct RaceRecord {
    /// The region containing the race.
    #[allow(dead_code)]
    region: RegionId,
    /// All participants in the race.
    participants: Vec<TaskId>,
    /// When the race started.
    #[allow(dead_code)]
    start_time: Time,
}

/// Record of a completed race.
#[derive(Debug, Clone)]
struct RaceCompleteRecord {
    /// All participants in the completed race.
    participants: Vec<TaskId>,
    /// The winning task.
    winner: TaskId,
    /// When the race completed.
    complete_time: Time,
}

/// Record of a completion event that had no matching active race.
#[derive(Debug, Clone)]
struct UnknownCompletionRecord {
    /// The reported winner for the unknown race.
    winner: TaskId,
    /// When the completion was reported.
    complete_time: Time,
}

/// Oracle for detecting loser drain violations.
///
/// Tracks race starts, completions, and task completions to verify that
/// all losers are drained before a race returns.
#[derive(Debug, Default)]
pub struct LoserDrainOracle {
    /// Active races: race_id -> RaceRecord.
    active_races: BTreeMap<u64, RaceRecord>,
    /// Completed races: race_id -> RaceCompleteRecord.
    completed_races: BTreeMap<u64, RaceCompleteRecord>,
    /// Completion events with no matching prior start.
    unknown_completions: BTreeMap<u64, UnknownCompletionRecord>,
    /// Task completion times: task -> completion_time.
    task_completions: BTreeMap<TaskId, Time>,
    /// Next race ID.
    next_race_id: u64,
}

impl LoserDrainOracle {
    /// Creates a new loser drain oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the start of a race combinator.
    ///
    /// Returns a race ID that should be passed to `on_race_complete`.
    pub fn on_race_start(
        &mut self,
        region: RegionId,
        participants: Vec<TaskId>,
        time: Time,
    ) -> u64 {
        let id = self.next_race_id;
        self.next_race_id += 1;
        self.active_races.insert(
            id,
            RaceRecord {
                region,
                participants,
                start_time: time,
            },
        );
        id
    }

    /// Records that a race has completed.
    pub fn on_race_complete(&mut self, race_id: u64, winner: TaskId, time: Time) {
        if self.completed_races.contains_key(&race_id)
            || self.unknown_completions.contains_key(&race_id)
        {
            return;
        }

        let Some(race) = self.active_races.remove(&race_id) else {
            self.unknown_completions.insert(
                race_id,
                UnknownCompletionRecord {
                    winner,
                    complete_time: time,
                },
            );
            return;
        };
        self.completed_races.insert(
            race_id,
            RaceCompleteRecord {
                participants: race.participants,
                winner,
                complete_time: time,
            },
        );
    }

    /// Records a task completion event.
    pub fn on_task_complete(&mut self, task: TaskId, time: Time) {
        self.task_completions.insert(task, time);
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that:
    /// - every observed race completion had a matching prior start,
    /// - no races remain active when verification runs, and
    /// - for every completed race, all losing tasks completed before or at the
    ///   race completion time.
    ///
    /// Returns an error with the first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(LoserDrainViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), LoserDrainViolation> {
        let mut unknown_race_ids: Vec<u64> = self.unknown_completions.keys().copied().collect();
        unknown_race_ids.sort_unstable();
        if let Some(race_id) = unknown_race_ids.first().copied() {
            let record = self
                .unknown_completions
                .get(&race_id)
                .expect("unknown completion missing from oracle");
            return Err(LoserDrainViolation::UnknownRaceCompletion {
                race_id,
                winner: record.winner,
                race_complete_time: record.complete_time,
            });
        }

        let mut active_race_ids: Vec<u64> = self.active_races.keys().copied().collect();
        active_race_ids.sort_unstable();
        if let Some(race_id) = active_race_ids.first().copied() {
            let record = self
                .active_races
                .get(&race_id)
                .expect("active race missing from oracle");
            return Err(LoserDrainViolation::ActiveRaceNotCompleted {
                race_id,
                participants: record.participants.clone(),
                race_start_time: record.start_time,
            });
        }

        let mut race_ids: Vec<u64> = self.completed_races.keys().copied().collect();
        race_ids.sort_unstable();
        for race_id in race_ids {
            let Some(complete_record) = self.completed_races.get(&race_id) else {
                continue;
            };
            let mut undrained = Vec::new();

            for &participant in &complete_record.participants {
                // Skip the winner
                if participant == complete_record.winner {
                    continue;
                }

                // Check if the loser was drained (completed before or at race complete)
                match self.task_completions.get(&participant) {
                    Some(&task_complete_time)
                        if task_complete_time <= complete_record.complete_time =>
                    {
                        // Loser was properly drained
                    }
                    _ => {
                        // Loser not drained
                        undrained.push(participant);
                    }
                }
            }

            if !undrained.is_empty() {
                return Err(LoserDrainViolation::UndrainedLosers {
                    race_id,
                    winner: complete_record.winner,
                    undrained_losers: undrained,
                    race_complete_time: complete_record.complete_time,
                });
            }
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.active_races.clear();
        self.completed_races.clear();
        self.unknown_completions.clear();
        self.task_completions.clear();
        // Don't reset next_race_id to avoid ID collisions across tests
    }

    /// Returns the total number of tracked races and race-like error states.
    #[must_use]
    pub fn race_count(&self) -> usize {
        self.active_races.len() + self.completed_races.len() + self.unknown_completions.len()
    }

    /// Returns the number of active races.
    #[must_use]
    pub fn active_race_count(&self) -> usize {
        self.active_races.len()
    }

    /// Returns the number of completed races.
    #[must_use]
    pub fn completed_race_count(&self) -> usize {
        self.completed_races.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
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

        // Duplicate completion events must not erase the original participant set.
        oracle.on_race_complete(race_id, task(1), t(200));

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
}
