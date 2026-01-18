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
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn cancel_lane_has_priority() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 100);
        sched.schedule_cancel(task(2), 50);

        // Cancel lane should come first despite lower priority
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(1)));
    }

    #[test]
    fn dedup_prevents_double_schedule() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 100);
        sched.schedule(task(1), 100);

        assert_eq!(sched.len(), 1);
    }

    #[test]
    fn move_to_cancel_lane_from_ready() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 100);

        // Move task 2 to cancel lane
        sched.move_to_cancel_lane(task(2), 100);

        // Task 2 should come first now (cancel lane priority)
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(1)));
    }

    #[test]
    fn move_to_cancel_lane_from_timed() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(10));

        // Move task 2 to cancel lane
        sched.move_to_cancel_lane(task(2), 100);

        // Task 2 should come first now (cancel lane priority)
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(1)));
    }

    #[test]
    fn move_to_cancel_lane_unscheduled_task() {
        let mut sched = Scheduler::new();

        // Move unscheduled task to cancel lane
        sched.move_to_cancel_lane(task(1), 100);

        assert_eq!(sched.len(), 1);
        assert!(sched.is_in_cancel_lane(task(1)));
        assert_eq!(sched.pop(), Some(task(1)));
    }

    #[test]
    fn move_to_cancel_lane_updates_priority() {
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 50);
        sched.schedule_cancel(task(2), 100);

        // Move task 1 to cancel lane with higher priority
        sched.move_to_cancel_lane(task(1), 150);

        // Task 1 should now come first due to higher priority
        assert_eq!(sched.pop(), Some(task(1)));
        assert_eq!(sched.pop(), Some(task(2)));
    }

    #[test]
    fn is_in_cancel_lane() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);

        assert!(!sched.is_in_cancel_lane(task(1)));
        assert!(sched.is_in_cancel_lane(task(2)));
    }

    #[test]
    fn timed_lane_edf_ordering() {
        let mut sched = Scheduler::new();

        // Schedule task 1 with later deadline (T=100)
        sched.schedule_timed(task(1), Time::from_secs(100));

        // Schedule task 2 with earlier deadline (T=10)
        sched.schedule_timed(task(2), Time::from_secs(10));

        // Task 2 should come first (EDF)
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(1)));
    }

    #[test]
    fn timed_lane_priority_over_ready() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 255); // Highest priority ready
        sched.schedule_timed(task(2), Time::from_secs(100)); // Timed

        // Timed lane should come before ready lane
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(1)));
    }

    #[test]
    fn cancel_lane_priority_over_timed() {
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(10)); // Urgent deadline
        sched.schedule_cancel(task(2), 1); // Low priority cancel

        // Cancel lane should still come first
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(1)));
    }
}
