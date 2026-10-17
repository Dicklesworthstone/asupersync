//! Loser drain oracle for verifying invariant #4: losers are always drained.
//!
//! This oracle verifies that in race combinators, all losing tasks are
//! cancelled AND drained to completion before the race returns.
//! If the owner cancels a race before any branch wins, every participant must
//! drain. Its completion records the owner, outside the participant list, in
//! the historical `winner` field so no branch is exempted from this check.
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
    /// The same `race_id` was completed twice with different winner or
    /// completion time. Previously the oracle silently ignored the second
    /// completion, masking real bugs in the runtime where a race was
    /// resolved twice with conflicting outcomes (br-asupersync-htqzu1).
    InconsistentRaceCompletion {
        /// The race identifier.
        race_id: u64,
        /// The first-recorded winning task.
        original_winner: TaskId,
        /// The first-recorded completion time.
        original_time: Time,
        /// The duplicate completion's winning task.
        duplicate_winner: TaskId,
        /// The duplicate completion's reported time.
        duplicate_time: Time,
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
            Self::InconsistentRaceCompletion {
                race_id,
                original_winner,
                original_time,
                duplicate_winner,
                duplicate_time,
            } => write!(
                f,
                "Race {race_id} completed twice with inconsistent outcomes: \
                 original (winner={original_winner:?}, time={original_time:?}) vs \
                 duplicate (winner={duplicate_winner:?}, time={duplicate_time:?})"
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
    /// The winning participant, or the cancelling owner outside the participants.
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
    /// Violations recorded during event ingestion (e.g., inconsistent
    /// duplicate completions). Drained from `check()` ahead of the
    /// invariants computed at end-of-run (br-asupersync-htqzu1).
    runtime_violations: Vec<LoserDrainViolation>,
    /// Whether the events came from replaying the runtime state's history,
    /// which every later hydration replays again (br-asupersync-vcu2oz).
    hydrated_from_state: bool,
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
        self.on_race_start_with_id(id, region, participants, time);
        id
    }

    pub(crate) fn on_race_start_with_id(
        &mut self,
        race_id: u64,
        region: RegionId,
        participants: Vec<TaskId>,
        time: Time,
    ) {
        self.next_race_id = self.next_race_id.max(race_id.saturating_add(1));
        // A replayed history starts races that already completed here.
        if self.completed_races.contains_key(&race_id)
            || self.unknown_completions.contains_key(&race_id)
        {
            return;
        }
        self.active_races.entry(race_id).or_insert(RaceRecord {
            region,
            participants,
            start_time: time,
        });
    }

    /// Records that a race has completed.
    ///
    /// For owner cancellation with no winning branch, `winner` is the owner's
    /// task ID, which must be outside the participant list. Every participant
    /// must then complete before this event; the owner itself need not finish.
    /// This representation preserves the existing completion event format.
    ///
    /// br-asupersync-htqzu1: a duplicate completion is no longer silently
    /// swallowed. If the duplicate carries the same `winner` and `time` as
    /// the first record we treat it as an idempotent retry; otherwise we
    /// record an `InconsistentRaceCompletion` violation so the conflicting
    /// outcomes surface in `check()`.
    pub fn on_race_complete(&mut self, race_id: u64, winner: TaskId, time: Time) {
        if let Some(prior) = self.completed_races.get(&race_id) {
            if prior.winner != winner || prior.complete_time != time {
                self.runtime_violations
                    .push(LoserDrainViolation::InconsistentRaceCompletion {
                        race_id,
                        original_winner: prior.winner,
                        original_time: prior.complete_time,
                        duplicate_winner: winner,
                        duplicate_time: time,
                    });
            }
            return;
        }
        if let Some(prior) = self.unknown_completions.get(&race_id) {
            if prior.winner != winner || prior.complete_time != time {
                self.runtime_violations
                    .push(LoserDrainViolation::InconsistentRaceCompletion {
                        race_id,
                        original_winner: prior.winner,
                        original_time: prior.complete_time,
                        duplicate_winner: winner,
                        duplicate_time: time,
                    });
            }
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

    /// Whether a hydration may replay the runtime state's history into this
    /// oracle: it replayed that history before, or it holds no events.
    /// Events fed by hand are not mixed with the state's, whose race ids can
    /// collide with theirs. An id allocated before a [`Self::reset`] is not
    /// an event.
    #[must_use]
    pub(crate) fn accepts_state_history(&self) -> bool {
        self.hydrated_from_state
            || (self.active_races.is_empty()
                && self.completed_races.is_empty()
                && self.unknown_completions.is_empty()
                && self.task_completions.is_empty()
                && self.runtime_violations.is_empty())
    }

    /// Records that the events came from the runtime state's history, so the
    /// next hydration replays it again (it is idempotent).
    pub(crate) fn mark_hydrated_from_state(&mut self) {
        self.hydrated_from_state = true;
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that:
    /// - every observed race completion had a matching prior start,
    /// - no races remain active when verification runs, and
    /// - for every completed race, all losing tasks completed before or at the
    ///   race completion time, including every participant of an owner-cancelled
    ///   race.
    ///
    /// Returns an error with the first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(LoserDrainViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), LoserDrainViolation> {
        // br-asupersync-htqzu1: surface inconsistent duplicate completions
        // recorded during event ingestion before the structural checks. A
        // contradictory race-complete is itself a protocol violation, even
        // if the eventual aggregate state happens to look consistent.
        if let Some(v) = self.runtime_violations.first() {
            return Err(v.clone());
        }

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
                // A branch winner is exempt. An owner cancellation records a
                // decision identity outside this list, so every branch is checked.
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
        self.runtime_violations.clear();
        self.hydrated_from_state = false;
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
#[path = "loser_drain_inline_tests.rs"]
mod tests;
