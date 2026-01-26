//! Three-lane priority scheduler.
//!
//! The scheduler uses three lanes:
//! 1. Cancel lane (highest priority) - tasks with pending cancellation
//! 2. Timed lane (EDF) - tasks with deadlines
//! 3. Ready lane - all other ready tasks
//!
//! Within each lane, tasks are ordered by their priority (or deadline).

use crate::types::{TaskId, Time};
use std::collections::VecDeque;

/// A task entry in a scheduler lane ordered by priority.
#[derive(Debug, Clone)]
struct SchedulerEntry {
    task: TaskId,
    priority: u8,
}

/// A task entry in a scheduler lane ordered by deadline (EDF).
#[derive(Debug, Clone)]
struct TimedEntry {
    task: TaskId,
    deadline: Time,
}

fn insert_by_priority(lane: &mut VecDeque<SchedulerEntry>, entry: SchedulerEntry) {
    // Higher priority first. Stable for equal priority (insert after existing equals).
    let pos = lane
        .iter()
        .position(|e| entry.priority > e.priority)
        .unwrap_or(lane.len());
    lane.insert(pos, entry);
}

fn insert_by_deadline(lane: &mut VecDeque<TimedEntry>, entry: TimedEntry) {
    // Earlier deadline first (EDF). Stable for equal deadlines.
    let pos = lane
        .iter()
        .position(|e| entry.deadline < e.deadline)
        .unwrap_or(lane.len());
    lane.insert(pos, entry);
}

/// Pop from a priority-based lane with RNG tie-breaking among equal-priority tasks.
fn pop_from_priority_lane_with_hint(
    lane: &mut VecDeque<SchedulerEntry>,
    rng_hint: u64,
) -> Option<TaskId> {
    if lane.is_empty() {
        return None;
    }

    // Find how many tasks share the highest priority at the front
    let front_priority = lane.front().unwrap().priority;
    let tie_count = lane
        .iter()
        .take_while(|e| e.priority == front_priority)
        .count();

    if tie_count == 1 {
        // No tie, just pop the front
        return lane.pop_front().map(|e| e.task);
    }

    // Use rng_hint to select among the tied tasks
    let selected_idx = (rng_hint as usize) % tie_count;
    let entry = lane.remove(selected_idx).unwrap();
    Some(entry.task)
}

/// Pop from a timed lane with RNG tie-breaking for equal deadlines.
fn pop_from_timed_lane_with_hint(lane: &mut VecDeque<TimedEntry>, rng_hint: u64) -> Option<TaskId> {
    if lane.is_empty() {
        return None;
    }

    // Find how many tasks share the earliest deadline at the front
    let front_deadline = lane.front().unwrap().deadline;
    let tie_count = lane
        .iter()
        .take_while(|e| e.deadline == front_deadline)
        .count();

    if tie_count == 1 {
        // No tie, just pop the front
        return lane.pop_front().map(|e| e.task);
    }

    // Use rng_hint to select among the tied tasks
    let selected_idx = (rng_hint as usize) % tie_count;
    let entry = lane.remove(selected_idx).unwrap();
    Some(entry.task)
}

/// The three-lane scheduler.
#[derive(Debug, Default)]
pub struct Scheduler {
    /// Cancel lane: tasks with pending cancellation (highest priority).
    cancel_lane: VecDeque<SchedulerEntry>,
    /// Timed lane: tasks with deadlines (EDF ordering).
    timed_lane: VecDeque<TimedEntry>,
    /// Ready lane: general ready tasks.
    ready_lane: VecDeque<SchedulerEntry>,
    /// Set of tasks currently in the scheduler (for dedup).
    scheduled: std::collections::HashSet<TaskId>,
}

impl Scheduler {
    /// Creates a new empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of scheduled tasks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scheduled.len()
    }

    /// Returns true if no tasks are scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scheduled.is_empty()
    }

    /// Schedules a task in the ready lane.
    ///
    /// Does nothing if the task is already scheduled.
    pub fn schedule(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            insert_by_priority(&mut self.ready_lane, SchedulerEntry { task, priority });
        }
    }

    /// Schedules a task in the cancel lane.
    ///
    /// Does nothing if the task is already scheduled.
    pub fn schedule_cancel(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            insert_by_priority(&mut self.cancel_lane, SchedulerEntry { task, priority });
        }
    }

    /// Schedules a task in the timed lane.
    ///
    /// Does nothing if the task is already scheduled.
    pub fn schedule_timed(&mut self, task: TaskId, deadline: Time) {
        if self.scheduled.insert(task) {
            insert_by_deadline(&mut self.timed_lane, TimedEntry { task, deadline });
        }
    }

    /// Pops the next task to run.
    ///
    /// Order: cancel lane > timed lane > ready lane.
    pub fn pop(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.cancel_lane.pop_front() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        if let Some(entry) = self.timed_lane.pop_front() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        if let Some(entry) = self.ready_lane.pop_front() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        None
    }

    /// Pops the next task to run, using `rng_hint` for tie-breaking among equal-priority tasks.
    ///
    /// This method provides deterministic but seed-varying scheduling for the lab runtime.
    /// When multiple tasks have the same priority at the head of a lane, the `rng_hint`
    /// determines which one is selected, enabling different seeds to produce different
    /// execution orderings while remaining deterministic for the same seed.
    ///
    /// Order: cancel lane > timed lane > ready lane.
    pub fn pop_with_rng_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        // Try cancel lane first
        if let Some(task) = pop_from_priority_lane_with_hint(&mut self.cancel_lane, rng_hint) {
            self.scheduled.remove(&task);
            return Some(task);
        }

        // Try timed lane (EDF - equal deadlines get tie-broken)
        if let Some(task) = pop_from_timed_lane_with_hint(&mut self.timed_lane, rng_hint) {
            self.scheduled.remove(&task);
            return Some(task);
        }

        // Try ready lane
        if let Some(task) = pop_from_priority_lane_with_hint(&mut self.ready_lane, rng_hint) {
            self.scheduled.remove(&task);
            return Some(task);
        }

        None
    }

    /// Removes a specific task from the scheduler.
    pub fn remove(&mut self, task: TaskId) {
        if self.scheduled.remove(&task) {
            self.cancel_lane.retain(|e| e.task != task);
            self.timed_lane.retain(|e| e.task != task);
            self.ready_lane.retain(|e| e.task != task);
        }
    }

    /// Moves a task to the cancel lane (highest priority).
    ///
    /// If the task is not currently scheduled, it will be added to the cancel lane.
    /// If the task is already in the cancel lane, its priority may be updated.
    ///
    /// This is the key operation for ensuring cancelled tasks get priority:
    /// the cancel lane is always drained before timed and ready lanes.
    pub fn move_to_cancel_lane(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            // Not scheduled, add directly to cancel lane
            insert_by_priority(&mut self.cancel_lane, SchedulerEntry { task, priority });
            return;
        }

        // Task is scheduled. Check where it is.
        // We optimize by returning early once found.

        // 1. Check Cancel Lane (target destination)
        if let Some(pos) = self.cancel_lane.iter().position(|e| e.task == task) {
            // Update priority if new priority is higher
            if self.cancel_lane[pos].priority < priority {
                self.cancel_lane.remove(pos);
                insert_by_priority(&mut self.cancel_lane, SchedulerEntry { task, priority });
            }
            return;
        }

        // 2. Check Timed Lane
        if let Some(pos) = self.timed_lane.iter().position(|e| e.task == task) {
            self.timed_lane.remove(pos);
            insert_by_priority(&mut self.cancel_lane, SchedulerEntry { task, priority });
            return;
        }

        // 3. Check Ready Lane
        if let Some(pos) = self.ready_lane.iter().position(|e| e.task == task) {
            self.ready_lane.remove(pos);
            insert_by_priority(&mut self.cancel_lane, SchedulerEntry { task, priority });
            return;
        }

        // If we reach here, the task is in `scheduled` set but not in any lane.
        // This should not happen if invariants are maintained.
        // We'll re-add it to be safe, but this implies a bug elsewhere.
        insert_by_priority(&mut self.cancel_lane, SchedulerEntry { task, priority });
    }

    /// Returns true if a task is in the cancel lane.
    #[must_use]
    pub fn is_in_cancel_lane(&self, task: TaskId) -> bool {
        self.cancel_lane.iter().any(|e| e.task == task)
    }

    /// Pops only from the cancel lane.
    ///
    /// Use this for strict cancel-first processing in multi-worker scenarios.
    #[must_use]
    pub fn pop_cancel_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.cancel_lane.pop_front() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the cancel lane with RNG tie-breaking.
    #[must_use]
    pub fn pop_cancel_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        if let Some(task) = pop_from_priority_lane_with_hint(&mut self.cancel_lane, rng_hint) {
            self.scheduled.remove(&task);
            return Some(task);
        }
        None
    }

    /// Pops only from the timed lane.
    ///
    /// Use this for strict lane ordering in multi-worker scenarios.
    #[must_use]
    pub fn pop_timed_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.timed_lane.pop_front() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the timed lane with RNG tie-breaking.
    #[must_use]
    pub fn pop_timed_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        if let Some(task) = pop_from_timed_lane_with_hint(&mut self.timed_lane, rng_hint) {
            self.scheduled.remove(&task);
            return Some(task);
        }
        None
    }

    /// Pops only from the ready lane.
    ///
    /// Use this for strict lane ordering in multi-worker scenarios.
    #[must_use]
    pub fn pop_ready_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.ready_lane.pop_front() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the ready lane with RNG tie-breaking.
    #[must_use]
    pub fn pop_ready_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        if let Some(task) = pop_from_priority_lane_with_hint(&mut self.ready_lane, rng_hint) {
            self.scheduled.remove(&task);
            return Some(task);
        }
        None
    }

    /// Steals a batch of ready tasks for another worker.
    ///
    /// Only steals from the ready lane to preserve cancel/timed priority semantics.
    /// Returns the number of tasks stolen.
    pub fn steal_ready_batch(&mut self, max_steal: usize) -> Vec<(TaskId, u8)> {
        let steal_count = (self.ready_lane.len() / 2).min(max_steal).max(1);
        let mut stolen = Vec::with_capacity(steal_count);

        for _ in 0..steal_count {
            if let Some(entry) = self.ready_lane.pop_front() {
                self.scheduled.remove(&entry.task);
                stolen.push((entry.task, entry.priority));
            } else {
                break;
            }
        }

        stolen
    }

    /// Returns true if the cancel lane has pending tasks.
    #[must_use]
    pub fn has_cancel_work(&self) -> bool {
        !self.cancel_lane.is_empty()
    }

    /// Returns true if the timed lane has pending tasks.
    #[must_use]
    pub fn has_timed_work(&self) -> bool {
        !self.timed_lane.is_empty()
    }

    /// Returns true if the ready lane has pending tasks.
    #[must_use]
    pub fn has_ready_work(&self) -> bool {
        !self.ready_lane.is_empty()
    }

    /// Clears all scheduled tasks.
    pub fn clear(&mut self) {
        self.cancel_lane.clear();
        self.timed_lane.clear();
        self.ready_lane.clear();
        self.scheduled.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn cancel_lane_has_priority() {
        init_test("cancel_lane_has_priority");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 100);
        sched.schedule_cancel(task(2), 50);

        // Cancel lane should come first despite lower priority
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "cancel lane pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "ready lane pops second",
            Some(task(1)),
            second
        );
        crate::test_complete!("cancel_lane_has_priority");
    }

    #[test]
    fn dedup_prevents_double_schedule() {
        init_test("dedup_prevents_double_schedule");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 100);
        sched.schedule(task(1), 100);

        crate::assert_with_log!(
            sched.len() == 1,
            "duplicate schedule is deduped",
            1usize,
            sched.len()
        );
        crate::test_complete!("dedup_prevents_double_schedule");
    }

    #[test]
    fn move_to_cancel_lane_from_ready() {
        init_test("move_to_cancel_lane_from_ready");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 100);

        // Move task 2 to cancel lane
        sched.move_to_cancel_lane(task(2), 100);

        // Task 2 should come first now (cancel lane priority)
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "moved task pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "remaining ready task pops next",
            Some(task(1)),
            second
        );
        crate::test_complete!("move_to_cancel_lane_from_ready");
    }

    #[test]
    fn move_to_cancel_lane_from_timed() {
        init_test("move_to_cancel_lane_from_timed");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(10));

        // Move task 2 to cancel lane
        sched.move_to_cancel_lane(task(2), 100);

        // Task 2 should come first now (cancel lane priority)
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "moved timed task pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "ready task pops second",
            Some(task(1)),
            second
        );
        crate::test_complete!("move_to_cancel_lane_from_timed");
    }

    #[test]
    fn move_to_cancel_lane_unscheduled_task() {
        init_test("move_to_cancel_lane_unscheduled_task");
        let mut sched = Scheduler::new();

        // Move unscheduled task to cancel lane
        sched.move_to_cancel_lane(task(1), 100);

        crate::assert_with_log!(
            sched.len() == 1,
            "unscheduled task inserted",
            1usize,
            sched.len()
        );
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task(1)),
            "task is in cancel lane",
            true,
            sched.is_in_cancel_lane(task(1))
        );
        let first = sched.pop();
        crate::assert_with_log!(
            first == Some(task(1)),
            "cancel lane pops task",
            Some(task(1)),
            first
        );
        crate::test_complete!("move_to_cancel_lane_unscheduled_task");
    }

    #[test]
    fn move_to_cancel_lane_updates_priority() {
        init_test("move_to_cancel_lane_updates_priority");
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 50);
        sched.schedule_cancel(task(2), 100);

        // Move task 1 to cancel lane with higher priority
        sched.move_to_cancel_lane(task(1), 150);

        // Task 1 should now come first due to higher priority
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(1)),
            "higher priority task pops first",
            Some(task(1)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(2)),
            "lower priority task pops next",
            Some(task(2)),
            second
        );
        crate::test_complete!("move_to_cancel_lane_updates_priority");
    }

    #[test]
    fn is_in_cancel_lane() {
        init_test("is_in_cancel_lane");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);

        crate::assert_with_log!(
            !sched.is_in_cancel_lane(task(1)),
            "ready task not in cancel lane",
            false,
            sched.is_in_cancel_lane(task(1))
        );
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task(2)),
            "cancel task is in cancel lane",
            true,
            sched.is_in_cancel_lane(task(2))
        );
        crate::test_complete!("is_in_cancel_lane");
    }

    #[test]
    fn timed_lane_edf_ordering() {
        init_test("timed_lane_edf_ordering");
        let mut sched = Scheduler::new();

        // Schedule task 1 with later deadline (T=100)
        sched.schedule_timed(task(1), Time::from_secs(100));

        // Schedule task 2 with earlier deadline (T=10)
        sched.schedule_timed(task(2), Time::from_secs(10));

        // Task 2 should come first (EDF)
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "earlier deadline pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "later deadline pops second",
            Some(task(1)),
            second
        );
        crate::test_complete!("timed_lane_edf_ordering");
    }

    #[test]
    fn timed_lane_priority_over_ready() {
        init_test("timed_lane_priority_over_ready");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 255); // Highest priority ready
        sched.schedule_timed(task(2), Time::from_secs(100)); // Timed

        // Timed lane should come before ready lane
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "timed lane pops before ready",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "ready lane pops after timed",
            Some(task(1)),
            second
        );
        crate::test_complete!("timed_lane_priority_over_ready");
    }

    #[test]
    fn cancel_lane_priority_over_timed() {
        init_test("cancel_lane_priority_over_timed");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(10)); // Urgent deadline
        sched.schedule_cancel(task(2), 1); // Low priority cancel

        // Cancel lane should still come first
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "cancel lane pops before timed",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "timed lane pops after cancel",
            Some(task(1)),
            second
        );
        crate::test_complete!("cancel_lane_priority_over_timed");
    }
}
