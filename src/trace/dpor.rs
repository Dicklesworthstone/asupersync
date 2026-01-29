//! Dynamic Partial Order Reduction (DPOR) race detection and backtracking.
//!
//! DPOR identifies *races* in a trace — pairs of dependent events that were
//! executed in a particular order but could have been reordered. Each race
//! represents a **backtrack point**: an alternative schedule that may reveal
//! different program behavior.
//!
//! # Definitions
//!
//! - **Race**: A pair of events (i, j) where i < j in the trace, the events
//!   are dependent, and no event between them is dependent on both. This means
//!   swapping i and j is a "minimal" reordering.
//!
//! - **Backtrack set**: The set of alternative schedules that DPOR identifies
//!   for exploration. Each backtrack point specifies which event should be
//!   executed first at a given decision point.
//!
//! - **Sleep set**: Events that have already been explored and need not be
//!   re-explored at a given state. Reduces redundant exploration.
//!
//! # Algorithm sketch
//!
//! 1. Execute a trace T
//! 2. For each pair of events (e_i, e_j) in T:
//!    - If dependent(e_i, e_j) and no event between them depends on both
//!      → this is a race
//! 3. For each race, add a backtrack point: explore the schedule where e_j
//!    executes before e_i
//!
//! # References
//!
//! - Flanagan & Godefroid, "Dynamic partial-order reduction" (POPL 2005)
//! - Abdulla et al., "Optimal dynamic partial order reduction" (POPL 2014)

use crate::trace::event::TraceEvent;
use crate::trace::independence::independent;

/// A race: two dependent events that are adjacent in the happens-before
/// (no intervening event depends on both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    /// Index of the earlier event in the trace.
    pub earlier: usize,
    /// Index of the later event in the trace.
    pub later: usize,
}

/// A backtrack point derived from a race.
#[derive(Debug, Clone)]
pub struct BacktrackPoint {
    /// The race that generated this backtrack point.
    pub race: Race,
    /// Index in the trace where the alternative schedule diverges.
    pub divergence_index: usize,
}

/// Result of DPOR race analysis on a trace.
#[derive(Debug)]
pub struct RaceAnalysis {
    /// All races found in the trace.
    pub races: Vec<Race>,
    /// Backtrack points to explore.
    pub backtrack_points: Vec<BacktrackPoint>,
}

impl RaceAnalysis {
    /// Number of races found.
    #[must_use]
    pub fn race_count(&self) -> usize {
        self.races.len()
    }

    /// True if no races were found (trace is sequential or fully ordered).
    #[must_use]
    pub fn is_race_free(&self) -> bool {
        self.races.is_empty()
    }
}

/// Detect all races in a trace.
///
/// A race between events at positions `i` and `j` (i < j) exists when:
/// 1. The events are dependent (`!independent(e_i, e_j)`)
/// 2. No event at position k (i < k < j) is dependent on **both** e_i and e_j
///
/// Condition 2 ensures we only detect *immediate* races (no transitive
/// dependencies hide them). These are the races that DPOR can exploit.
///
/// # Complexity
///
/// O(n³) in the worst case (for each pair, check all intermediaries).
/// For typical traces this is acceptable; large traces can use the
/// seed-sweep explorer instead.
#[must_use]
pub fn detect_races(events: &[TraceEvent]) -> RaceAnalysis {
    let n = events.len();
    let mut races = Vec::new();

    for i in 0..n {
        for j in (i + 1)..n {
            // Condition 1: events are dependent.
            if independent(&events[i], &events[j]) {
                continue;
            }

            // Condition 2: no intervening event depends on both.
            let has_intervening = (i + 1..j).any(|k| {
                !independent(&events[i], &events[k]) && !independent(&events[k], &events[j])
            });

            if !has_intervening {
                races.push(Race {
                    earlier: i,
                    later: j,
                });
            }
        }
    }

    // Each race generates a backtrack point at the earlier event's position.
    let backtrack_points = races
        .iter()
        .map(|race| BacktrackPoint {
            race: race.clone(),
            divergence_index: race.earlier,
        })
        .collect();

    RaceAnalysis {
        races,
        backtrack_points,
    }
}

/// Compute the set of events involved in at least one race.
///
/// These are the "interesting" decision points for schedule exploration.
#[must_use]
pub fn racing_events(events: &[TraceEvent]) -> Vec<usize> {
    let analysis = detect_races(events);
    let mut indices: Vec<usize> = analysis
        .races
        .iter()
        .flat_map(|r| [r.earlier, r.later])
        .collect();
    indices.sort_unstable();
    indices.dedup();
    indices
}

/// Estimate the number of distinct equivalence classes reachable by
/// exploring all backtrack points.
///
/// This is a lower bound: the actual number may be higher if backtrack
/// points interact.
#[must_use]
pub fn estimated_classes(events: &[TraceEvent]) -> usize {
    let analysis = detect_races(events);
    // Each race can double the number of classes (in the worst case).
    // But many races are "overlapping" and don't multiply independently.
    // Conservative estimate: 1 + number of non-overlapping races.
    if analysis.races.is_empty() {
        return 1;
    }

    // Count non-overlapping races (greedy: sort by later index, pick
    // races whose earlier index > previous race's later index).
    let mut sorted: Vec<&Race> = analysis.races.iter().collect();
    sorted.sort_by_key(|r| (r.later, r.earlier));

    let mut non_overlapping = 1usize;
    let mut last_later = 0;
    for race in &sorted {
        if race.earlier >= last_later {
            non_overlapping += 1;
            last_later = race.later;
        }
    }

    non_overlapping
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn no_races_in_independent_trace() {
        // Two independent spawns: no races.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let analysis = detect_races(&events);
        assert!(analysis.is_race_free());
        assert_eq!(estimated_classes(&events), 1);
    }

    #[test]
    fn race_between_dependent_events() {
        // Two events on the same task: they're dependent and adjacent.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let analysis = detect_races(&events);
        assert_eq!(analysis.race_count(), 1);
        assert_eq!(analysis.races[0].earlier, 0);
        assert_eq!(analysis.races[0].later, 1);
    }

    #[test]
    fn no_race_with_transitive_dependency() {
        // A -> B -> C: A and C are dependent but B intervenes.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        ];
        let analysis = detect_races(&events);
        // Races: (0,1) and (1,2) are immediate.
        // (0,2) has intervening event 1 that depends on both -> NOT a race.
        assert_eq!(analysis.race_count(), 2);
        // Verify (0,2) is not in the races list.
        assert!(!analysis
            .races
            .iter()
            .any(|r| r.earlier == 0 && r.later == 2));
    }

    #[test]
    fn races_in_concurrent_task_region_interaction() {
        // Region create writes R1; spawn in R1 reads R1 -> dependent.
        // Two such spawns in R1: no direct dependency between spawns.
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        ];
        let analysis = detect_races(&events);
        // (0,1): dependent (write R1 vs read R1), no intervening -> race
        // (0,2): dependent (write R1 vs read R1), but (1) also depends on (0)
        //        AND (1) is independent of (2) (different tasks, same region read)
        //        So no intervening event depends on BOTH (0) and (2) -> race
        // (1,2): independent (different tasks, both only read R1) -> no race
        let race_pairs: Vec<(usize, usize)> = analysis
            .races
            .iter()
            .map(|r| (r.earlier, r.later))
            .collect();
        assert!(race_pairs.contains(&(0, 1)));
        assert!(race_pairs.contains(&(0, 2)));
        assert!(!race_pairs.contains(&(1, 2)));
    }

    #[test]
    fn racing_events_deduplicates() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let indices = racing_events(&events);
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn empty_trace_no_races() {
        let analysis = detect_races(&[]);
        assert!(analysis.is_race_free());
    }

    #[test]
    fn estimated_classes_grows_with_races() {
        // More races -> more potential classes.
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        ];
        let est = estimated_classes(&events);
        assert!(est >= 2);
    }

    #[test]
    fn backtrack_points_correspond_to_races() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let analysis = detect_races(&events);
        assert_eq!(analysis.backtrack_points.len(), analysis.race_count());
        assert_eq!(analysis.backtrack_points[0].divergence_index, 0);
    }
}
