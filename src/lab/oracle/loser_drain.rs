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
use std::collections::HashMap;
use std::fmt;

/// A loser drain violation.
///
/// This indicates that a race completed without fully draining its losers,
/// violating the cancel-correctness invariant.
#[derive(Debug, Clone)]
pub struct LoserDrainViolation {
    /// The race identifier.
    pub race_id: u64,
    /// The winning task.
    pub winner: TaskId,
    /// Tasks that were not drained when the race completed.
    pub undrained_losers: Vec<TaskId>,
    /// The time when the race completed.
    pub race_complete_time: Time,
}

impl fmt::Display for LoserDrainViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Race {} completed at {:?} with {} undrained loser(s): {:?}",
            self.race_id,
            self.race_complete_time,
            self.undrained_losers.len(),
            self.undrained_losers
        )
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
    /// The winning task.
    winner: TaskId,
    /// When the race completed.
    complete_time: Time,
}

/// Oracle for detecting loser drain violations.
///
/// Tracks race starts, completions, and task completions to verify that
/// all losers are drained before a race returns.
#[derive(Debug, Default)]
pub struct LoserDrainOracle {
    /// Active races: race_id -> RaceRecord.
    active_races: HashMap<u64, RaceRecord>,
    /// Completed races: race_id -> RaceCompleteRecord.
    completed_races: HashMap<u64, RaceCompleteRecord>,
    /// Task completion times: task -> completion_time.
    task_completions: HashMap<TaskId, Time>,
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
        self.completed_races.insert(
            race_id,
            RaceCompleteRecord {
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
    /// Checks that for every completed race, all losing tasks were completed
    /// before or at the race completion time. Returns an error with the
    /// first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(LoserDrainViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), LoserDrainViolation> {
        let mut race_ids: Vec<u64> = self.completed_races.keys().copied().collect();
        race_ids.sort_unstable();
        for race_id in race_ids {
            let Some(complete_record) = self.completed_races.get(&race_id) else {
                continue;
            };
            let Some(race_record) = self.active_races.get(&race_id) else {
                continue;
            };

            let mut undrained = Vec::new();

            for &participant in &race_record.participants {
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
                return Err(LoserDrainViolation {
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
        self.task_completions.clear();
        // Don't reset next_race_id to avoid ID collisions across tests
    }

    /// Returns the total number of races (active + completed).
    #[must_use]
    pub fn race_count(&self) -> usize {
        self.active_races.len() + self.completed_races.len()
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
    use super::*;
    use crate::util::ArenaIndex;

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
        crate::assert_with_log!(
            violation.winner == task(1),
            "winner",
            task(1),
            violation.winner
        );
        crate::assert_with_log!(
            violation.undrained_losers == vec![task(2)],
            "undrained_losers",
            vec![task(2)],
            violation.undrained_losers
        );
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
        crate::assert_with_log!(
            violation.undrained_losers == vec![task(2)],
            "undrained_losers",
            vec![task(2)],
            violation.undrained_losers
        );
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
        crate::assert_with_log!(
            violation.race_id == race2,
            "race_id",
            race2,
            violation.race_id
        );
        crate::test_complete!("multiple_races_independent");
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
        let violation = LoserDrainViolation {
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
}
