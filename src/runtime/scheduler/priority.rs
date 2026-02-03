//! Three-lane priority scheduler.
//!
//! The scheduler uses three lanes:
//! 1. Cancel lane (highest priority) - tasks with pending cancellation
//! 2. Timed lane (EDF) - tasks with deadlines
//! 3. Ready lane - all other ready tasks
//!
//! Within each lane, tasks are ordered by their priority (or deadline).
//! Uses binary heaps for O(log n) insertion instead of O(n) VecDeque insertion.

use crate::types::{TaskId, Time};
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::collections::BinaryHeap;
use std::hash::{Hash, Hasher};

/// A task entry in a scheduler lane ordered by priority.
///
/// Ordering: higher priority first, then earlier generation (FIFO within same priority).
#[derive(Debug, Clone, Eq, PartialEq)]
struct SchedulerEntry {
    task: TaskId,
    priority: u8,
    /// Insertion order for FIFO tie-breaking among equal priorities.
    generation: u64,
}

impl Ord for SchedulerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first (BinaryHeap is max-heap)
        // For equal priorities, earlier generation (lower number) comes first
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.generation.cmp(&self.generation))
    }
}

impl PartialOrd for SchedulerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A task entry in a scheduler lane ordered by deadline (EDF).
///
/// Ordering: earlier deadline first, then earlier generation (FIFO within same deadline).
#[derive(Debug, Clone, Eq, PartialEq)]
struct TimedEntry {
    task: TaskId,
    deadline: Time,
    /// Insertion order for FIFO tie-breaking among equal deadlines.
    generation: u64,
}

impl Ord for TimedEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Earlier deadline first (reverse comparison for min-heap behavior via max-heap)
        // For equal deadlines, earlier generation comes first
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.generation.cmp(&self.generation))
    }
}

impl PartialOrd for TimedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The three-lane scheduler.
///
/// Uses binary heaps for O(log n) insertion instead of O(n) VecDeque insertion.
/// Generation counters provide FIFO ordering within same priority/deadline.
#[derive(Debug, Default)]
pub struct Scheduler {
    /// Cancel lane: tasks with pending cancellation (highest priority).
    cancel_lane: BinaryHeap<SchedulerEntry>,
    /// Timed lane: tasks with deadlines (EDF ordering).
    timed_lane: BinaryHeap<TimedEntry>,
    /// Ready lane: general ready tasks.
    ready_lane: BinaryHeap<SchedulerEntry>,
    /// Set of tasks currently in the scheduler (for dedup).
    scheduled: std::collections::HashSet<TaskId>,
    /// Next generation number for FIFO ordering.
    next_generation: u64,
    /// Scratch space for RNG tie-breaking (ready/cancel lanes).
    scratch_entries: Vec<SchedulerEntry>,
    /// Scratch space for RNG tie-breaking (timed lane).
    scratch_timed: Vec<TimedEntry>,
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

    /// Allocates and returns the next generation number for FIFO ordering.
    fn next_gen(&mut self) -> u64 {
        let gen = self.next_generation;
        self.next_generation += 1;
        gen
    }

    /// Schedules a task in the ready lane.
    ///
    /// Does nothing if the task is already scheduled.
    /// O(log n) insertion via binary heap.
    pub fn schedule(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            let generation = self.next_gen();
            self.ready_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
        }
    }

    /// Schedules a task in the cancel lane.
    ///
    /// Does nothing if the task is already scheduled.
    /// O(log n) insertion via binary heap.
    pub fn schedule_cancel(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            let generation = self.next_gen();
            self.cancel_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
        }
    }

    /// Schedules a task in the timed lane.
    ///
    /// Does nothing if the task is already scheduled.
    /// O(log n) insertion via binary heap.
    pub fn schedule_timed(&mut self, task: TaskId, deadline: Time) {
        if self.scheduled.insert(task) {
            let generation = self.next_gen();
            self.timed_lane.push(TimedEntry {
                task,
                deadline,
                generation,
            });
        }
    }

    /// Pops the next task to run.
    ///
    /// Order: cancel lane > timed lane > ready lane.
    /// O(log n) pop via binary heap.
    pub fn pop(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.cancel_lane.pop() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        if let Some(entry) = self.timed_lane.pop() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        if let Some(entry) = self.ready_lane.pop() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        None
    }

    /// Pops the next task to run, using `rng_hint` for tie-breaking among equal-priority tasks.
    ///
    /// Order: cancel lane > timed lane > ready lane.
    /// O(log n) pop via binary heap.
    pub fn pop_with_rng_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        // For lab determinism, we want tie-breaking to vary with a seed while still being fully
        // deterministic for a given `rng_hint` sequence. We do this by selecting uniformly among
        // the set of max-priority (or earliest-deadline) tasks in the chosen lane.
        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        if let Some(entry) =
            Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
        {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }

        None
    }

    fn pop_entry_with_rng(
        lane: &mut BinaryHeap<SchedulerEntry>,
        rng_hint: u64,
        scratch: &mut Vec<SchedulerEntry>,
    ) -> Option<SchedulerEntry> {
        let first = lane.pop()?;
        let priority = first.priority;
        scratch.clear();
        scratch.push(first);

        while let Some(peek) = lane.peek() {
            if peek.priority != priority {
                break;
            }
            // `peek` guarantees the next `pop` is `Some`.
            scratch.push(lane.pop().expect("popped after peek"));
        }

        let idx = (rng_hint as usize) % scratch.len();
        let chosen = scratch.swap_remove(idx);
        for entry in scratch.drain(..) {
            lane.push(entry);
        }
        Some(chosen)
    }

    fn pop_timed_with_rng(
        lane: &mut BinaryHeap<TimedEntry>,
        rng_hint: u64,
        scratch: &mut Vec<TimedEntry>,
    ) -> Option<TimedEntry> {
        let first = lane.pop()?;
        let deadline = first.deadline;
        scratch.clear();
        scratch.push(first);

        while let Some(peek) = lane.peek() {
            if peek.deadline != deadline {
                break;
            }
            scratch.push(lane.pop().expect("popped after peek"));
        }

        let idx = (rng_hint as usize) % scratch.len();
        let chosen = scratch.swap_remove(idx);
        for entry in scratch.drain(..) {
            lane.push(entry);
        }
        Some(chosen)
    }

    /// Removes a specific task from the scheduler.
    ///
    /// O(n) rebuild of affected lane. This is acceptable since removal is rare
    /// compared to schedule/pop operations.
    pub fn remove(&mut self, task: TaskId) {
        if self.scheduled.remove(&task) {
            // Rebuild heaps without the removed task
            self.cancel_lane = self
                .cancel_lane
                .drain()
                .filter(|e| e.task != task)
                .collect();
            self.timed_lane = self.timed_lane.drain().filter(|e| e.task != task).collect();
            self.ready_lane = self.ready_lane.drain().filter(|e| e.task != task).collect();
        }
    }

    /// Moves a task to the cancel lane (highest priority).
    ///
    /// If the task is not currently scheduled, it will be added to the cancel lane.
    /// If the task is already in the cancel lane, its priority may be updated.
    ///
    /// This is the key operation for ensuring cancelled tasks get priority:
    /// the cancel lane is always drained before timed and ready lanes.
    ///
    /// O(n) for finding and removing from other lanes, O(log n) for insertion.
    pub fn move_to_cancel_lane(&mut self, task: TaskId, priority: u8) {
        let generation = self.next_gen();

        if self.scheduled.insert(task) {
            // Not scheduled, add directly to cancel lane
            self.cancel_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
            return;
        }

        // Task is scheduled. Check where it is.
        // Check if already in cancel lane
        let in_cancel = self.cancel_lane.iter().any(|e| e.task == task);
        if in_cancel {
            // Rebuild cancel lane, updating priority if higher
            self.cancel_lane = self
                .cancel_lane
                .drain()
                .map(|e| {
                    if e.task == task && priority > e.priority {
                        SchedulerEntry {
                            task,
                            priority,
                            generation,
                        }
                    } else {
                        e
                    }
                })
                .collect();
            return;
        }

        // Check timed lane
        let in_timed = self.timed_lane.iter().any(|e| e.task == task);
        if in_timed {
            self.timed_lane = self.timed_lane.drain().filter(|e| e.task != task).collect();
            self.cancel_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
            return;
        }

        // Check ready lane
        let in_ready = self.ready_lane.iter().any(|e| e.task == task);
        if in_ready {
            self.ready_lane = self.ready_lane.drain().filter(|e| e.task != task).collect();
            self.cancel_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
            return;
        }

        // Task is in `scheduled` set but not in any lane - add to cancel lane
        self.cancel_lane.push(SchedulerEntry {
            task,
            priority,
            generation,
        });
    }

    /// Returns true if a task is in the cancel lane.
    #[must_use]
    pub fn is_in_cancel_lane(&self, task: TaskId) -> bool {
        self.cancel_lane.iter().any(|e| e.task == task)
    }

    /// Pops only from the cancel lane.
    ///
    /// Use this for strict cancel-first processing in multi-worker scenarios.
    /// O(log n) pop via binary heap.
    #[must_use]
    pub fn pop_cancel_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.cancel_lane.pop() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the cancel lane with RNG tie-breaking.
    ///
    /// Note: With heap-based implementation, FIFO ordering is used instead of RNG.
    #[must_use]
    pub fn pop_cancel_only_with_hint(&mut self, _rng_hint: u64) -> Option<TaskId> {
        self.pop_cancel_only()
    }

    /// Pops only from the timed lane.
    ///
    /// Use this for strict lane ordering in multi-worker scenarios.
    /// O(log n) pop via binary heap.
    #[must_use]
    pub fn pop_timed_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.timed_lane.pop() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the timed lane with RNG tie-breaking.
    ///
    /// Note: With heap-based implementation, FIFO ordering is used instead of RNG.
    #[must_use]
    pub fn pop_timed_only_with_hint(&mut self, _rng_hint: u64) -> Option<TaskId> {
        self.pop_timed_only()
    }

    /// Pops only from the ready lane.
    ///
    /// Use this for strict lane ordering in multi-worker scenarios.
    /// O(log n) pop via binary heap.
    #[must_use]
    pub fn pop_ready_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.ready_lane.pop() {
            self.scheduled.remove(&entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the ready lane with RNG tie-breaking.
    ///
    /// Note: With heap-based implementation, FIFO ordering is used instead of RNG.
    #[must_use]
    pub fn pop_ready_only_with_hint(&mut self, _rng_hint: u64) -> Option<TaskId> {
        self.pop_ready_only()
    }

    /// Steals a batch of ready tasks for another worker.
    ///
    /// Only steals from the ready lane to preserve cancel/timed priority semantics.
    /// Returns the stolen tasks with their priorities.
    ///
    /// O(k log n) where k is the number of tasks stolen.
    pub fn steal_ready_batch(&mut self, max_steal: usize) -> Vec<(TaskId, u8)> {
        let mut stolen = Vec::new();
        let _ = self.steal_ready_batch_into(max_steal, &mut stolen);
        stolen
    }

    /// Steals ready tasks into a caller-provided buffer.
    ///
    /// Returns the number of tasks stolen.
    pub fn steal_ready_batch_into(
        &mut self,
        max_steal: usize,
        out: &mut Vec<(TaskId, u8)>,
    ) -> usize {
        out.clear();
        let steal_count = (self.ready_lane.len() / 2).min(max_steal).max(1);
        if out.capacity() < steal_count {
            out.reserve(steal_count - out.capacity());
        }

        for _ in 0..steal_count {
            if let Some(entry) = self.ready_lane.pop() {
                self.scheduled.remove(&entry.task);
                out.push((entry.task, entry.priority));
            } else {
                break;
            }
        }

        out.len()
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

/// Scheduler operating mode.
///
/// Controls whether the scheduler uses deterministic or throughput-optimized
/// scheduling. The deterministic mode is used by the lab runtime for
/// reproducible testing; the throughput mode is used in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchedulerMode {
    /// Deterministic mode: same seed → identical schedule.
    ///
    /// Uses RNG-seeded tie-breaking for reproducibility. Suitable for:
    /// - Lab runtime testing
    /// - DPOR exploration
    /// - Replay debugging
    /// - Proof-carrying trace generation
    #[default]
    Deterministic,

    /// Throughput mode: optimized for wall-clock performance.
    ///
    /// May use non-deterministic optimizations (e.g., batch wakeups,
    /// relaxed ordering). Not suitable for DPOR or replay.
    Throughput,
}

/// A schedule certificate: a hash of the sequence of scheduling decisions.
///
/// Two runs with the same seed should produce identical certificates if the
/// scheduler is deterministic. A divergence in certificates indicates
/// non-determinism or a bug.
///
/// # Construction
///
/// The certificate is built incrementally by hashing each scheduling decision:
/// - Task ID popped
/// - Lane from which it was popped (cancel=0, timed=1, ready=2, stolen=3)
/// - Step number
///
/// # Verification
///
/// To verify determinism, run the same test twice with the same seed and
/// compare certificates. Divergence at step N means the schedule diverged
/// at that point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleCertificate {
    /// Running hash of all schedule decisions.
    hash: u64,
    /// Number of decisions recorded.
    decisions: u64,
    /// Step at which the first decision diverged from a reference (if any).
    divergence_step: Option<u64>,
}

/// The lane from which a task was dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchLane {
    /// Task was in cancellation state.
    Cancel,
    /// Task had a deadline.
    Timed,
    /// Task was in the general ready queue.
    Ready,
    /// Task was stolen from another worker.
    Stolen,
}

impl ScheduleCertificate {
    /// Creates a new empty certificate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hash: 0,
            decisions: 0,
            divergence_step: None,
        }
    }

    /// Record a scheduling decision: task dispatched from a lane at a step.
    pub fn record(&mut self, task: TaskId, lane: DispatchLane, step: u64) {
        let mut hasher = DefaultHasher::new();
        self.hash.hash(&mut hasher);
        // Pack the arena index for deterministic hashing.
        let idx = task.0;
        (idx.index(), idx.generation()).hash(&mut hasher);
        lane.hash(&mut hasher);
        step.hash(&mut hasher);
        self.hash = hasher.finish();
        self.decisions += 1;
    }

    /// Returns the current certificate hash.
    #[must_use]
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Returns the number of decisions recorded.
    #[must_use]
    pub fn decisions(&self) -> u64 {
        self.decisions
    }

    /// Compare with a reference certificate and detect divergence.
    ///
    /// Returns `true` if the certificates match.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.hash == other.hash && self.decisions == other.decisions
    }

    /// Mark a divergence at the given step.
    pub fn mark_divergence(&mut self, step: u64) {
        if self.divergence_step.is_none() {
            self.divergence_step = Some(step);
        }
    }

    /// Returns the step at which divergence was first detected.
    #[must_use]
    pub fn divergence_step(&self) -> Option<u64> {
        self.divergence_step
    }
}

impl Default for ScheduleCertificate {
    fn default() -> Self {
        Self::new()
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

    // ========== Additional Three-Lane Tests ==========

    #[test]
    fn test_three_lane_push_pop_basic() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        assert_eq!(sched.pop(), Some(task(1)));
        assert_eq!(sched.pop(), None);
    }

    #[test]
    fn test_three_lane_fifo_ordering() {
        let mut sched = Scheduler::new();
        // Same priority, should be FIFO
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 50);
        sched.schedule(task(3), 50);

        assert_eq!(sched.pop(), Some(task(1)), "first in, first out");
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(3)));
    }

    #[test]
    fn test_three_lane_priority_lanes_strict() {
        let mut sched = Scheduler::new();
        // Add in reverse order
        sched.schedule(task(1), 100); // ready
        sched.schedule_timed(task(2), Time::from_secs(1)); // timed
        sched.schedule_cancel(task(3), 50); // cancel

        // Strict ordering: cancel > timed > ready
        assert_eq!(sched.pop(), Some(task(3)), "cancel first");
        assert_eq!(sched.pop(), Some(task(2)), "timed second");
        assert_eq!(sched.pop(), Some(task(1)), "ready last");
    }

    #[test]
    fn test_three_lane_empty_detection() {
        let mut sched = Scheduler::new();
        assert!(sched.is_empty());

        sched.schedule(task(1), 50);
        assert!(!sched.is_empty());

        sched.pop();
        assert!(sched.is_empty());
    }

    #[test]
    fn test_three_lane_length_tracking() {
        let mut sched = Scheduler::new();
        assert_eq!(sched.len(), 0);

        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 50);
        sched.schedule_timed(task(3), Time::from_secs(1));

        assert_eq!(sched.len(), 3);

        sched.pop();
        assert_eq!(sched.len(), 2);
    }

    #[test]
    fn test_cancel_lane_priority_ordering() {
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 50);
        sched.schedule_cancel(task(2), 100); // higher priority
        sched.schedule_cancel(task(3), 75);

        assert_eq!(sched.pop(), Some(task(2)), "highest priority first");
        assert_eq!(sched.pop(), Some(task(3)), "middle priority second");
        assert_eq!(sched.pop(), Some(task(1)), "lowest priority last");
    }

    #[test]
    fn test_ready_lane_priority_ordering() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 100);
        sched.schedule(task(3), 75);

        assert_eq!(sched.pop(), Some(task(2)), "highest priority first");
        assert_eq!(sched.pop(), Some(task(3)), "middle priority second");
        assert_eq!(sched.pop(), Some(task(1)), "lowest priority last");
    }

    #[test]
    fn test_steal_ready_batch_basic() {
        let mut sched = Scheduler::new();
        for i in 0..8 {
            sched.schedule(task(i), 50);
        }

        let stolen = sched.steal_ready_batch(4);
        assert!(!stolen.is_empty());
        assert!(stolen.len() <= 4);

        // Verify stolen tasks have correct format
        for (task_id, priority) in &stolen {
            assert_eq!(*priority, 50);
            assert!(task_id.0.index() < 8);
        }
    }

    #[test]
    fn test_steal_only_from_ready() {
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(1));
        sched.schedule(task(3), 50);

        let stolen = sched.steal_ready_batch(10);
        // Only ready task should be stolen
        assert_eq!(stolen.len(), 1);
        assert_eq!(stolen[0].0, task(3));

        // Cancel and timed should still be in scheduler
        assert!(sched.has_cancel_work());
        assert!(sched.has_timed_work());
    }

    #[test]
    fn test_pop_only_methods() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);
        sched.schedule_timed(task(3), Time::from_secs(1));

        // pop_cancel_only should only get cancel task
        assert_eq!(sched.pop_cancel_only(), Some(task(2)));
        assert_eq!(sched.pop_cancel_only(), None);

        // pop_timed_only should only get timed task
        assert_eq!(sched.pop_timed_only(), Some(task(3)));
        assert_eq!(sched.pop_timed_only(), None);

        // pop_ready_only should only get ready task
        assert_eq!(sched.pop_ready_only(), Some(task(1)));
        assert_eq!(sched.pop_ready_only(), None);
    }

    #[test]
    fn test_remove_from_scheduler() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 50);
        sched.schedule(task(3), 50);

        sched.remove(task(2));

        assert_eq!(sched.len(), 2);
        assert_eq!(sched.pop(), Some(task(1)));
        assert_eq!(sched.pop(), Some(task(3)));
    }

    #[test]
    fn test_clear_scheduler() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);
        sched.schedule_timed(task(3), Time::from_secs(1));

        sched.clear();

        assert!(sched.is_empty());
        assert_eq!(sched.len(), 0);
        assert!(!sched.has_cancel_work());
        assert!(!sched.has_timed_work());
        assert!(!sched.has_ready_work());
    }

    #[test]
    fn test_has_work_methods() {
        let mut sched = Scheduler::new();
        assert!(!sched.has_cancel_work());
        assert!(!sched.has_timed_work());
        assert!(!sched.has_ready_work());

        sched.schedule(task(1), 50);
        assert!(sched.has_ready_work());

        sched.schedule_cancel(task(2), 100);
        assert!(sched.has_cancel_work());

        sched.schedule_timed(task(3), Time::from_secs(1));
        assert!(sched.has_timed_work());
    }

    #[test]
    fn test_high_volume_scheduling() {
        let mut sched = Scheduler::new();
        let count = 1000;

        for i in 0..count {
            sched.schedule(task(i), (i % 256) as u8);
        }

        assert_eq!(sched.len(), count as usize);

        let mut popped = 0;
        while sched.pop().is_some() {
            popped += 1;
        }

        assert_eq!(popped, count);
        assert!(sched.is_empty());
    }

    // ── ScheduleCertificate tests ───────────────────────────────────────

    #[test]
    fn certificate_empty() {
        let cert = ScheduleCertificate::new();
        assert_eq!(cert.decisions(), 0);
        assert_eq!(cert.divergence_step(), None);
    }

    #[test]
    fn certificate_deterministic_same_sequence() {
        let mut c1 = ScheduleCertificate::new();
        let mut c2 = ScheduleCertificate::new();

        c1.record(task(1), DispatchLane::Ready, 0);
        c1.record(task(2), DispatchLane::Cancel, 1);
        c1.record(task(3), DispatchLane::Timed, 2);

        c2.record(task(1), DispatchLane::Ready, 0);
        c2.record(task(2), DispatchLane::Cancel, 1);
        c2.record(task(3), DispatchLane::Timed, 2);

        assert!(c1.matches(&c2));
        assert_eq!(c1.hash(), c2.hash());
        assert_eq!(c1.decisions(), 3);
    }

    #[test]
    fn certificate_different_sequences_diverge() {
        let mut c1 = ScheduleCertificate::new();
        let mut c2 = ScheduleCertificate::new();

        c1.record(task(1), DispatchLane::Ready, 0);
        c1.record(task(2), DispatchLane::Ready, 1);

        c2.record(task(2), DispatchLane::Ready, 0);
        c2.record(task(1), DispatchLane::Ready, 1);

        assert!(!c1.matches(&c2));
    }

    #[test]
    fn certificate_lane_matters() {
        let mut c1 = ScheduleCertificate::new();
        let mut c2 = ScheduleCertificate::new();

        c1.record(task(1), DispatchLane::Ready, 0);
        c2.record(task(1), DispatchLane::Cancel, 0);

        assert!(!c1.matches(&c2));
    }

    #[test]
    fn certificate_divergence_tracking() {
        let mut cert = ScheduleCertificate::new();
        cert.record(task(1), DispatchLane::Ready, 0);
        assert_eq!(cert.divergence_step(), None);

        cert.mark_divergence(5);
        assert_eq!(cert.divergence_step(), Some(5));

        // First divergence is sticky.
        cert.mark_divergence(10);
        assert_eq!(cert.divergence_step(), Some(5));
    }

    #[test]
    fn scheduler_mode_default_is_deterministic() {
        assert_eq!(SchedulerMode::default(), SchedulerMode::Deterministic);
    }
}
