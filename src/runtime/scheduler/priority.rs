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
use crate::util::{ArenaIndex, DetBuildHasher, DetHashSet, DetHasher};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::hash::{Hash, Hasher};

/// A task entry in a scheduler lane ordered by priority.
///
/// Ordering: higher priority first, then earlier generation (FIFO within same priority).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct SchedulerEntry {
    task: TaskId,
    priority: u8,
    /// Insertion order for FIFO tie-breaking among equal priorities.
    generation: u64,
}

impl Ord for SchedulerEntry {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first (BinaryHeap is max-heap)
        // For equal priorities, earlier generation (lower number) comes first
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.generation.cmp(&self.generation))
    }
}

impl PartialOrd for SchedulerEntry {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A task entry in a scheduler lane ordered by deadline (EDF).
///
/// Ordering: earlier deadline first, then earlier generation (FIFO within same deadline).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct TimedEntry {
    task: TaskId,
    deadline: Time,
    /// Insertion order for FIFO tie-breaking among equal deadlines.
    generation: u64,
}

impl Ord for TimedEntry {
    #[inline]
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
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct ScheduledSet {
    // Fast path: for the common case where task IDs are dense (arena-backed),
    // store a generation tag per index to avoid hashing.
    //
    // Tag encoding:
    // - 0 => not scheduled
    // - (gen as u64) + 1 => scheduled with that generation
    // - DENSE_COLLISION => membership tracked in `overflow`
    dense: Vec<u64>,
    overflow: DetHashSet<TaskId>,
    len: usize,
}

impl ScheduledSet {
    const DENSE_COLLISION: u64 = u64::MAX;
    // Hard cap to avoid pathological allocations if someone schedules a very high-index TaskId.
    const MAX_DENSE_LEN: usize = 1 << 20; // 1,048,576 slots => 8 MiB
    const MIN_DENSE_LEN: usize = 64;

    #[inline]
    fn with_capacity(capacity: usize) -> Self {
        let overflow = DetHashSet::with_capacity_and_hasher(capacity, DetBuildHasher);

        let dense_len = capacity
            .max(1)
            .next_power_of_two()
            .clamp(Self::MIN_DENSE_LEN, Self::MAX_DENSE_LEN);
        Self {
            dense: vec![0; dense_len],
            overflow,
            len: 0,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn insert(&mut self, task: TaskId) -> bool {
        let idx = task.0.index() as usize;
        let tag = u64::from(task.0.generation()) + 1;

        if idx < Self::MAX_DENSE_LEN && idx >= self.dense.len() {
            self.grow_dense_to_fit(idx);
        }

        if idx >= self.dense.len() {
            // Out of dense range: fall back to deterministic hashing.
            let inserted = self.overflow.insert(task);
            if inserted {
                self.len += 1;
            }
            return inserted;
        }

        match self.dense[idx] {
            0 => {
                self.dense[idx] = tag;
                self.len += 1;
                true
            }
            existing if existing == tag => false,
            Self::DENSE_COLLISION => {
                let inserted = self.overflow.insert(task);
                if inserted {
                    self.len += 1;
                }
                inserted
            }
            existing => {
                // Collision on arena index across generations. This should be extremely rare in a
                // correct runtime (it implies re-use while still scheduled), but we preserve exact
                // set semantics by moving this index to overflow tracking.
                self.dense[idx] = Self::DENSE_COLLISION;
                let old_gen = u32::try_from(existing - 1).expect("dense tag fits u32");
                let old_task = TaskId(ArenaIndex::new(
                    u32::try_from(idx).expect("idx fits u32"),
                    old_gen,
                ));
                let was_new = self.overflow.insert(old_task);
                debug_assert!(was_new);

                let inserted = self.overflow.insert(task);
                if inserted {
                    self.len += 1;
                }
                inserted
            }
        }
    }

    #[inline]
    fn remove(&mut self, task: TaskId) -> bool {
        let idx = task.0.index() as usize;
        let tag = u64::from(task.0.generation()) + 1;

        if idx >= self.dense.len() {
            let removed = self.overflow.remove(&task);
            if removed {
                self.len -= 1;
            }
            return removed;
        }

        match self.dense[idx] {
            0 => false,
            existing if existing == tag => {
                self.dense[idx] = 0;
                self.len -= 1;
                true
            }
            Self::DENSE_COLLISION => {
                let removed = self.overflow.remove(&task);
                if removed {
                    self.len -= 1;
                    // Only keep collision-mode bookkeeping while multiple generations for this
                    // arena index are live. Collapse back to dense tracking when possible.
                    self.collapse_collision_slot(idx);
                }
                removed
            }
            _ => false,
        }
    }

    #[inline]
    fn clear(&mut self) {
        for slot in &mut self.dense {
            *slot = 0;
        }
        self.overflow.clear();
        self.len = 0;
    }

    #[inline]
    fn grow_dense_to_fit(&mut self, idx: usize) {
        debug_assert!(idx < Self::MAX_DENSE_LEN);
        let needed = idx + 1;
        let mut new_len = self.dense.len().max(1);
        while new_len < needed {
            new_len = new_len.saturating_mul(2);
        }
        new_len = new_len.clamp(Self::MIN_DENSE_LEN, Self::MAX_DENSE_LEN);
        if new_len > self.dense.len() {
            self.dense.resize(new_len, 0);
        }
    }

    /// Rebuild a collision-marked dense slot when generations drain.
    ///
    /// Collision slots are required only while two or more generations for the
    /// same arena index are live in the set. When that count drops to one (or
    /// zero), we restore the dense fast path.
    fn collapse_collision_slot(&mut self, idx: usize) {
        debug_assert!(idx < self.dense.len());
        if self.dense[idx] != Self::DENSE_COLLISION {
            return;
        }

        let mut remaining: Option<TaskId> = None;
        let mut multiple = false;
        for candidate in &self.overflow {
            if candidate.0.index() as usize != idx {
                continue;
            }
            if remaining.is_some() {
                multiple = true;
                break;
            }
            remaining = Some(*candidate);
        }

        if multiple {
            return;
        }

        match remaining {
            None => {
                self.dense[idx] = 0;
            }
            Some(task) => {
                let removed = self.overflow.remove(&task);
                debug_assert!(removed, "task discovered in overflow should remove");
                self.dense[idx] = u64::from(task.0.generation()) + 1;
            }
        }
    }
}

/// The three-lane scheduler.
///
/// Uses binary heaps for O(log n) insertion instead of O(n) VecDeque insertion.
/// Generation counters provide FIFO ordering within same priority/deadline.
#[derive(Debug)]
pub struct Scheduler {
    /// Cancel lane: tasks with pending cancellation (highest priority).
    cancel_lane: BinaryHeap<SchedulerEntry>,
    /// Timed lane: tasks with deadlines (EDF ordering).
    timed_lane: BinaryHeap<TimedEntry>,
    /// Ready lane: general ready tasks.
    ready_lane: BinaryHeap<SchedulerEntry>,
    /// Set of tasks currently in the scheduler (for dedup).
    scheduled: ScheduledSet,
    /// Next generation number for FIFO ordering.
    next_generation: u64,
    /// Scratch space for RNG tie-breaking (ready/cancel lanes).
    scratch_entries: Vec<SchedulerEntry>,
    /// Scratch space for RNG tie-breaking (timed lane).
    scratch_timed: Vec<TimedEntry>,
}

// Keep `Scheduler::new()` lightweight for tests and tiny local schedulers.
// Production worker schedulers can opt into larger preallocation via
// `Scheduler::with_capacity` at construction sites.
const DEFAULT_SCHEDULER_CAPACITY: usize = 64;
const DEFAULT_SCRATCH_CAPACITY: usize = 8;
const MAX_SCRATCH_CAPACITY: usize = 64;

impl Default for Scheduler {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_SCHEDULER_CAPACITY)
    }
}

impl Scheduler {
    #[inline]
    fn tie_break_index(rng_hint: u64, len: usize) -> usize {
        debug_assert!(len > 0);
        let len_u64 = u64::try_from(len).expect("len should fit in u64");
        (rng_hint % len_u64) as usize
    }

    /// Creates a new empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a scheduler with pre-allocated capacity for lanes and dedup set.
    ///
    /// The capacity is applied per lane to reduce heap growth on bursty workloads.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let scratch_capacity = capacity.clamp(DEFAULT_SCRATCH_CAPACITY, MAX_SCRATCH_CAPACITY);
        Self {
            cancel_lane: BinaryHeap::with_capacity(capacity),
            timed_lane: BinaryHeap::with_capacity(capacity),
            ready_lane: BinaryHeap::with_capacity(capacity),
            scheduled: ScheduledSet::with_capacity(capacity),
            next_generation: 0,
            scratch_entries: Vec::with_capacity(scratch_capacity),
            scratch_timed: Vec::with_capacity(scratch_capacity),
        }
    }

    /// Returns the total number of scheduled tasks.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.scheduled.len()
    }

    /// Returns true if no tasks are scheduled.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scheduled.is_empty()
    }

    /// Returns true if there is work that can be executed immediately.
    ///
    /// Returns true if:
    /// - Cancel lane is not empty
    /// - Ready lane is not empty
    /// - Timed lane has a task with `deadline <= now`
    #[inline]
    #[must_use]
    pub fn has_runnable_work(&self, now: Time) -> bool {
        if !self.cancel_lane.is_empty() || !self.ready_lane.is_empty() {
            return true;
        }
        self.timed_lane.peek().is_some_and(|t| t.deadline <= now)
    }

    /// Returns the earliest deadline from the timed lane, if any.
    #[inline]
    #[must_use]
    pub fn next_deadline(&self) -> Option<Time> {
        self.timed_lane.peek().map(|t| t.deadline)
    }

    /// Allocates and returns the next generation number for FIFO ordering.
    fn next_gen(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation += 1;
        generation
    }

    /// Schedules a task in the ready lane.
    ///
    /// Does nothing if the task is already scheduled.
    /// O(log n) insertion via binary heap.
    #[inline]
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

    /// Schedules or promotes a task into the cancel lane.
    ///
    /// If the task is already scheduled, it is moved to the cancel lane to
    /// ensure cancellation preempts timed/ready work.
    /// O(log n) insertion for new tasks; O(n) for promotions.
    #[inline]
    pub fn schedule_cancel(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            let generation = self.next_gen();
            self.cancel_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
            return;
        }
        self.move_to_cancel_lane(task, priority);
    }

    /// Schedules a task in the timed lane.
    ///
    /// Does nothing if the task is already scheduled.
    /// O(log n) insertion via binary heap.
    #[inline]
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
    #[inline]
    pub fn pop(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.cancel_lane.pop() {
            self.scheduled.remove(entry.task);
            return Some(entry.task);
        }

        if let Some(entry) = self.timed_lane.pop() {
            self.scheduled.remove(entry.task);
            return Some(entry.task);
        }

        if let Some(entry) = self.ready_lane.pop() {
            self.scheduled.remove(entry.task);
            return Some(entry.task);
        }

        None
    }

    /// Pops the next task to run, using `rng_hint` for tie-breaking among equal-priority tasks.
    ///
    /// Order: cancel lane > timed lane > ready lane.
    /// O(log n) pop via binary heap.
    #[inline]
    pub fn pop_with_rng_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        self.pop_with_lane(rng_hint).map(|(task, _)| task)
    }

    /// Pop the highest-priority task across all three lanes, returning both
    /// the task and the lane it was dispatched from.
    ///
    /// Lane priority: Cancel > Timed > Ready (same as `pop_with_rng_hint`).
    ///
    /// This method is deadline-agnostic for timed tasks. If your caller keeps
    /// future timed tasks in the scheduler, use [`Self::pop_with_lane_if_due`]
    /// instead to prevent dispatch before deadline.
    #[inline]
    pub fn pop_with_lane(&mut self, rng_hint: u64) -> Option<(TaskId, DispatchLane)> {
        // For lab determinism, we want tie-breaking to vary with a seed while still being fully
        // deterministic for a given `rng_hint` sequence. We do this by selecting uniformly among
        // the set of max-priority (or earliest-deadline) tasks in the chosen lane.
        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Cancel));
        }

        if let Some(entry) =
            Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Timed));
        }

        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Ready));
        }

        None
    }

    /// Pop across all three lanes while enforcing timed deadline readiness.
    ///
    /// Lane priority remains Cancel > Timed > Ready, but timed tasks are
    /// dispatched only when `deadline <= now`.
    #[inline]
    pub fn pop_with_lane_if_due(
        &mut self,
        rng_hint: u64,
        now: Time,
    ) -> Option<(TaskId, DispatchLane)> {
        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Cancel));
        }

        let timed_due = self
            .timed_lane
            .peek()
            .is_some_and(|entry| entry.deadline <= now);
        if timed_due {
            if let Some(entry) =
                Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
            {
                self.scheduled.remove(entry.task);
                return Some((entry.task, DispatchLane::Timed));
            }
        }

        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Ready));
        }

        None
    }

    /// Pop a task from the cancel lane using deterministic RNG tie-breaking.
    #[inline]
    pub fn pop_cancel_with_rng(&mut self, rng_hint: u64) -> Option<(TaskId, DispatchLane)> {
        let entry =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)?;
        self.scheduled.remove(entry.task);
        Some((entry.task, DispatchLane::Cancel))
    }

    /// Pop a task from timed or ready lanes (excluding cancel lane).
    ///
    /// Timed lane has priority over ready lane.
    ///
    /// This method is deadline-agnostic for timed tasks. If your caller keeps
    /// future timed tasks in the scheduler, use
    /// [`Self::pop_non_cancel_with_rng_if_due`] to prevent early dispatch.
    #[inline]
    pub fn pop_non_cancel_with_rng(&mut self, rng_hint: u64) -> Option<(TaskId, DispatchLane)> {
        if let Some(entry) =
            Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Timed));
        }

        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Ready));
        }

        None
    }

    /// Pop from timed or ready lanes while enforcing timed deadline readiness.
    ///
    /// Timed lane retains priority over ready lane, but timed tasks are
    /// dispatched only when `deadline <= now`.
    #[inline]
    pub fn pop_non_cancel_with_rng_if_due(
        &mut self,
        rng_hint: u64,
        now: Time,
    ) -> Option<(TaskId, DispatchLane)> {
        let timed_due = self
            .timed_lane
            .peek()
            .is_some_and(|entry| entry.deadline <= now);
        if timed_due {
            if let Some(entry) =
                Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
            {
                self.scheduled.remove(entry.task);
                return Some((entry.task, DispatchLane::Timed));
            }
        }

        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((entry.task, DispatchLane::Ready));
        }

        None
    }

    fn pop_entry_with_rng(
        lane: &mut BinaryHeap<SchedulerEntry>,
        rng_hint: u64,
        scratch: &mut Vec<SchedulerEntry>,
    ) -> Option<SchedulerEntry> {
        let first = lane.pop()?;
        if lane.is_empty() {
            return Some(first);
        }
        let priority = first.priority;
        if lane.peek().is_some_and(|peek| peek.priority != priority) {
            return Some(first);
        }
        scratch.clear();
        scratch.push(first);

        while let Some(peek) = lane.peek() {
            if peek.priority != priority {
                break;
            }
            // `peek` guarantees the next `pop` is `Some`.
            scratch.push(lane.pop().expect("popped after peek"));
        }

        let idx = Self::tie_break_index(rng_hint, scratch.len());
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
        if lane.is_empty() {
            return Some(first);
        }
        let deadline = first.deadline;
        if lane.peek().is_some_and(|peek| peek.deadline != deadline) {
            return Some(first);
        }
        scratch.clear();
        scratch.push(first);

        while let Some(peek) = lane.peek() {
            if peek.deadline != deadline {
                break;
            }
            scratch.push(lane.pop().expect("popped after peek"));
        }

        let idx = Self::tie_break_index(rng_hint, scratch.len());
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
        if self.scheduled.remove(task) {
            // Remove in-place without heap allocation
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
        // Check if already in cancel lane.
        if let Some(existing_priority) = self
            .cancel_lane
            .iter()
            .find(|entry| entry.task == task)
            .map(|entry| entry.priority)
        {
            // Fast path: same-or-lower priority re-promotion is a no-op.
            // Keep generation consumption above for deterministic sequencing.
            if priority <= existing_priority {
                return;
            }
            // Remove old entry and re-insert with new priority, avoiding allocation.
            self.cancel_lane.retain(|e| e.task != task);
            self.cancel_lane.push(SchedulerEntry {
                task,
                priority,
                generation,
            });
            return;
        }

        // Check timed lane
        let in_timed = self.timed_lane.iter().any(|e| e.task == task);
        if in_timed {
            self.timed_lane.retain(|e| e.task != task);
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
            self.ready_lane.retain(|e| e.task != task);
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
    #[inline]
    #[must_use]
    pub fn pop_cancel_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.cancel_lane.pop() {
            self.scheduled.remove(entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the cancel lane with RNG tie-breaking.
    #[inline]
    #[must_use]
    pub fn pop_cancel_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        let entry =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)?;
        self.scheduled.remove(entry.task);
        Some(entry.task)
    }

    /// Pops only from the timed lane if the earliest deadline is due.
    ///
    /// Returns `None` if no timed tasks exist or the earliest deadline
    /// has not yet been reached. This prevents timed tasks from firing
    /// before their deadline when in the local scheduler.
    ///
    /// O(log n) pop via binary heap.
    #[inline]
    #[must_use]
    pub fn pop_timed_only(&mut self, now: Time) -> Option<TaskId> {
        if let Some(entry) = self.timed_lane.peek() {
            if entry.deadline <= now {
                let entry = self.timed_lane.pop().expect("peeked entry should exist");
                self.scheduled.remove(entry.task);
                return Some(entry.task);
            }
        }
        None
    }

    /// Pops only from the timed lane if the earliest deadline is due,
    /// with RNG tie-breaking among tasks sharing the earliest deadline.
    #[inline]
    #[must_use]
    pub fn pop_timed_only_with_hint(&mut self, rng_hint: u64, now: Time) -> Option<TaskId> {
        let earliest = self.timed_lane.peek()?;
        if earliest.deadline > now {
            return None;
        }
        let entry =
            Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
                .expect("timed_lane peeked non-empty");
        self.scheduled.remove(entry.task);
        Some(entry.task)
    }

    /// Pops only from the ready lane.
    ///
    /// Use this for strict lane ordering in multi-worker scenarios.
    /// O(log n) pop via binary heap.
    #[inline]
    #[must_use]
    pub fn pop_ready_only(&mut self) -> Option<TaskId> {
        if let Some(entry) = self.ready_lane.pop() {
            self.scheduled.remove(entry.task);
            return Some(entry.task);
        }
        None
    }

    /// Pops only from the ready lane with RNG tie-breaking among equal priorities.
    #[inline]
    #[must_use]
    pub fn pop_ready_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        let entry =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)?;
        self.scheduled.remove(entry.task);
        Some(entry.task)
    }

    /// Checks all local lanes in priority order (cancel > timed > ready)
    /// in a single call, avoiding repeated lock acquisitions when the
    /// caller would check each lane sequentially.
    ///
    /// Returns `(lane_tag, task_id)` where lane_tag is 0=cancel, 1=timed, 2=ready.
    #[inline]
    #[must_use]
    pub fn pop_any_lane_with_hint(&mut self, rng_hint: u64, now: Time) -> Option<(u8, TaskId)> {
        // Cancel lane first (highest priority).
        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((0, entry.task));
        }
        // Timed lane (EDF, only if deadline is due).
        if let Some(earliest) = self.timed_lane.peek() {
            if earliest.deadline <= now {
                if let Some(entry) = Self::pop_timed_with_rng(
                    &mut self.timed_lane,
                    rng_hint,
                    &mut self.scratch_timed,
                ) {
                    self.scheduled.remove(entry.task);
                    return Some((1, entry.task));
                }
            }
        }
        // Ready lane.
        if let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            self.scheduled.remove(entry.task);
            return Some((2, entry.task));
        }
        None
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
        if max_steal == 0 || self.ready_lane.is_empty() {
            return 0;
        }
        let steal_count = (self.ready_lane.len() / 2).min(max_steal).max(1);
        if out.capacity() < steal_count {
            out.reserve(steal_count - out.capacity());
        }

        for _ in 0..steal_count {
            if let Some(entry) = self.ready_lane.pop() {
                self.scheduled.remove(entry.task);
                out.push((entry.task, entry.priority));
            } else {
                break;
            }
        }

        out.len()
    }

    /// Returns true if the cancel lane has pending tasks.
    #[inline]
    #[must_use]
    pub fn has_cancel_work(&self) -> bool {
        !self.cancel_lane.is_empty()
    }

    /// Returns true if the timed lane has pending tasks.
    #[inline]
    #[must_use]
    pub fn has_timed_work(&self) -> bool {
        !self.timed_lane.is_empty()
    }

    /// Returns true if the ready lane has pending tasks.
    #[inline]
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
        let mut hasher = DetHasher::default();
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
    fn scheduler_with_capacity_preallocates_overflow_set() {
        init_test("scheduler_with_capacity_preallocates_overflow_set");
        let sched = Scheduler::with_capacity(1024);
        let has_capacity = sched.scheduled.overflow.capacity() >= 1024;
        crate::assert_with_log!(has_capacity, "overflow preallocation", true, has_capacity);
        crate::test_complete!("scheduler_with_capacity_preallocates_overflow_set");
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

        // pop_timed_only should only get timed task (deadline is 1s, so pass now >= 1s)
        let now = Time::from_secs(1);
        assert_eq!(sched.pop_timed_only(now), Some(task(3)));
        assert_eq!(sched.pop_timed_only(now), None);

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

    // ── pop_with_lane tests ───────────────────────────────────────────────

    #[test]
    fn pop_with_lane_returns_cancel_lane() {
        init_test("pop_with_lane_returns_cancel_lane");
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 100);

        let result = sched.pop_with_lane(0);
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Cancel)),
            "cancel task dispatches from Cancel lane",
            Some((task(1), DispatchLane::Cancel)),
            result
        );
        crate::test_complete!("pop_with_lane_returns_cancel_lane");
    }

    #[test]
    fn pop_with_lane_returns_timed_lane() {
        init_test("pop_with_lane_returns_timed_lane");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(10));

        let result = sched.pop_with_lane(0);
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Timed)),
            "timed task dispatches from Timed lane",
            Some((task(1), DispatchLane::Timed)),
            result
        );
        crate::test_complete!("pop_with_lane_returns_timed_lane");
    }

    #[test]
    fn pop_with_lane_returns_ready_lane() {
        init_test("pop_with_lane_returns_ready_lane");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);

        let result = sched.pop_with_lane(0);
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Ready)),
            "ready task dispatches from Ready lane",
            Some((task(1), DispatchLane::Ready)),
            result
        );
        crate::test_complete!("pop_with_lane_returns_ready_lane");
    }

    #[test]
    fn pop_with_lane_respects_lane_ordering() {
        init_test("pop_with_lane_respects_lane_ordering");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(10));
        sched.schedule_cancel(task(3), 10);

        let first = sched.pop_with_lane(0);
        let second = sched.pop_with_lane(0);
        let third = sched.pop_with_lane(0);
        let fourth = sched.pop_with_lane(0);

        crate::assert_with_log!(
            first.map(|(_, l)| l) == Some(DispatchLane::Cancel),
            "cancel dispatches first",
            Some(DispatchLane::Cancel),
            first.map(|(_, l)| l)
        );
        crate::assert_with_log!(
            second.map(|(_, l)| l) == Some(DispatchLane::Timed),
            "timed dispatches second",
            Some(DispatchLane::Timed),
            second.map(|(_, l)| l)
        );
        crate::assert_with_log!(
            third.map(|(_, l)| l) == Some(DispatchLane::Ready),
            "ready dispatches third",
            Some(DispatchLane::Ready),
            third.map(|(_, l)| l)
        );
        crate::assert_with_log!(
            fourth.is_none(),
            "empty scheduler returns None",
            Option::<(TaskId, DispatchLane)>::None,
            fourth
        );
        crate::test_complete!("pop_with_lane_respects_lane_ordering");
    }

    #[test]
    fn pop_with_lane_if_due_skips_future_timed_for_ready() {
        init_test("pop_with_lane_if_due_skips_future_timed_for_ready");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(100));

        let result = sched.pop_with_lane_if_due(0, Time::from_secs(50));
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Ready)),
            "ready task dispatches while timed task is not due",
            Some((task(1), DispatchLane::Ready)),
            result
        );
        crate::test_complete!("pop_with_lane_if_due_skips_future_timed_for_ready");
    }

    #[test]
    fn pop_with_lane_if_due_dispatches_timed_when_due() {
        init_test("pop_with_lane_if_due_dispatches_timed_when_due");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(100));

        let result = sched.pop_with_lane_if_due(0, Time::from_secs(100));
        crate::assert_with_log!(
            result == Some((task(2), DispatchLane::Timed)),
            "timed task dispatches once deadline is due",
            Some((task(2), DispatchLane::Timed)),
            result
        );
        crate::test_complete!("pop_with_lane_if_due_dispatches_timed_when_due");
    }

    #[test]
    fn pop_non_cancel_with_rng_if_due_skips_future_timed() {
        init_test("pop_non_cancel_with_rng_if_due_skips_future_timed");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(100));

        let result = sched.pop_non_cancel_with_rng_if_due(0, Time::from_secs(50));
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Ready)),
            "non-cancel pop dispatches ready when timed is not due",
            Some((task(1), DispatchLane::Ready)),
            result
        );
        crate::test_complete!("pop_non_cancel_with_rng_if_due_skips_future_timed");
    }

    #[test]
    fn pop_with_lane_rng_tiebreak_among_equal_priority() {
        init_test("pop_with_lane_rng_tiebreak_among_equal_priority");
        let run_with_hints = |hints: &[u64]| -> Vec<TaskId> {
            let mut sched = Scheduler::new();
            for i in 0..4 {
                sched.schedule(task(i), 50);
            }

            let mut popped = Vec::new();
            for &hint in hints {
                if let Some((t, lane)) = sched.pop_with_lane(hint) {
                    crate::assert_with_log!(
                        matches!(lane, DispatchLane::Ready),
                        "equal-priority dispatch stays in ready lane",
                        true,
                        true
                    );
                    popped.push(t);
                }
            }
            popped
        };

        let hints_a = [0, 1, 2, 3];
        let hints_b = [0, 1, 2, 3];
        let hints_c = [42, 43, 44, 45];
        let hints_d = [42, 43, 44, 45];

        let order_a = run_with_hints(&hints_a);
        let order_b = run_with_hints(&hints_b);
        let order_c = run_with_hints(&hints_c);
        let order_d = run_with_hints(&hints_d);

        // Same hints from same initial state must be deterministic.
        crate::assert_with_log!(
            order_a == order_b,
            "same hint sequence yields same pop order",
            true,
            order_a == order_b
        );
        // Distinct hints should perturb tie-breaking among equal priorities.
        crate::assert_with_log!(
            order_a != order_c,
            "different hint sequence yields different pop order",
            true,
            order_a != order_c
        );
        crate::assert_with_log!(
            order_c == order_d,
            "alternate hint sequence is also deterministic",
            true,
            order_c == order_d
        );

        // Each run must pop each task exactly once.
        for order in [&order_a, &order_b, &order_c, &order_d] {
            crate::assert_with_log!(
                order.len() == 4,
                "all tasks dispatched",
                4usize,
                order.len()
            );
            let mut sorted = order.clone();
            sorted.sort_by_key(|t| t.arena_index().index());
            let expected = vec![task(0), task(1), task(2), task(3)];
            crate::assert_with_log!(
                sorted == expected,
                "pop order is a permutation of scheduled tasks",
                true,
                sorted == expected
            );
        }
        crate::test_complete!("pop_with_lane_rng_tiebreak_among_equal_priority");
    }

    // ── steal_ready_batch_into tests ──────────────────────────────────────

    #[test]
    fn steal_ready_batch_into_fills_buffer() {
        init_test("steal_ready_batch_into_fills_buffer");
        let mut sched = Scheduler::new();
        for i in 0..10 {
            sched.schedule(task(i), 50);
        }

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(5, &mut buf);

        crate::assert_with_log!(
            count == buf.len(),
            "returned count matches buffer length",
            count,
            buf.len()
        );
        crate::assert_with_log!(count <= 5, "does not exceed max_steal", true, count <= 5);
        crate::assert_with_log!(count > 0, "steals at least one task", true, count > 0);
        crate::test_complete!("steal_ready_batch_into_fills_buffer");
    }

    #[test]
    fn steal_ready_batch_into_does_not_steal_cancel_or_timed() {
        init_test("steal_ready_batch_into_does_not_steal_cancel_or_timed");
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(10));

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(10, &mut buf);

        crate::assert_with_log!(
            count == 0,
            "nothing stolen when ready lane is empty",
            0usize,
            count
        );
        // Cancel and timed tasks should still be present
        crate::assert_with_log!(
            sched.has_cancel_work(),
            "cancel task preserved",
            true,
            sched.has_cancel_work()
        );
        crate::assert_with_log!(
            sched.has_timed_work(),
            "timed task preserved",
            true,
            sched.has_timed_work()
        );
        crate::test_complete!("steal_ready_batch_into_does_not_steal_cancel_or_timed");
    }

    #[test]
    fn steal_ready_batch_into_respects_zero_max() {
        init_test("steal_ready_batch_into_respects_zero_max");
        let mut sched = Scheduler::new();
        for i in 0..4 {
            sched.schedule(task(i), 50);
        }

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(0, &mut buf);

        crate::assert_with_log!(count == 0, "zero max_steal returns zero", 0usize, count);
        crate::assert_with_log!(
            buf.is_empty(),
            "buffer cleared when max_steal is zero",
            true,
            buf.is_empty()
        );
        crate::assert_with_log!(sched.len() == 4, "no tasks removed", 4usize, sched.len());
        crate::test_complete!("steal_ready_batch_into_respects_zero_max");
    }

    #[test]
    fn steal_ready_batch_into_clears_buffer() {
        init_test("steal_ready_batch_into_clears_buffer");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);

        let mut buf = vec![(task(99), 255)]; // Pre-existing junk
        let count = sched.steal_ready_batch_into(10, &mut buf);

        crate::assert_with_log!(count == 1, "stole exactly one task", 1usize, count);
        crate::assert_with_log!(
            buf.len() == 1,
            "buffer cleared before filling",
            1usize,
            buf.len()
        );
        crate::assert_with_log!(
            buf[0].0 == task(1),
            "correct task in buffer",
            task(1),
            buf[0].0
        );
        crate::test_complete!("steal_ready_batch_into_clears_buffer");
    }

    // ── pop_timed_only edge cases ─────────────────────────────────────────

    #[test]
    fn pop_timed_only_respects_deadline_boundary() {
        init_test("pop_timed_only_respects_deadline_boundary");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(100));

        // Before deadline: should not dispatch
        let before = sched.pop_timed_only(Time::from_secs(99));
        crate::assert_with_log!(
            before.is_none(),
            "timed task not due before deadline",
            Option::<TaskId>::None,
            before
        );

        // Exactly at deadline: should dispatch
        let at = sched.pop_timed_only(Time::from_secs(100));
        crate::assert_with_log!(
            at == Some(task(1)),
            "timed task dispatches at deadline",
            Some(task(1)),
            at
        );
        crate::test_complete!("pop_timed_only_respects_deadline_boundary");
    }

    #[test]
    fn pop_timed_only_edf_with_mixed_due_status() {
        init_test("pop_timed_only_edf_with_mixed_due_status");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(50)); // due
        sched.schedule_timed(task(2), Time::from_secs(200)); // not due
        sched.schedule_timed(task(3), Time::from_secs(75)); // due

        let now = Time::from_secs(100);

        // Should return earliest deadline first
        let first = sched.pop_timed_only(now);
        crate::assert_with_log!(
            first == Some(task(1)),
            "earliest deadline dispatches first",
            Some(task(1)),
            first
        );

        let second = sched.pop_timed_only(now);
        crate::assert_with_log!(
            second == Some(task(3)),
            "second earliest deadline dispatches next",
            Some(task(3)),
            second
        );

        // Task 2 is not due (deadline 200 > now 100)
        let third = sched.pop_timed_only(now);
        crate::assert_with_log!(
            third.is_none(),
            "not-due task is not dispatched",
            Option::<TaskId>::None,
            third
        );
        crate::test_complete!("pop_timed_only_edf_with_mixed_due_status");
    }

    // ---- Cancel preemption: cancel drains before any timed/ready --------

    #[test]
    fn cancel_drains_completely_before_timed_and_ready() {
        init_test("cancel_drains_completely_before_timed_and_ready");
        let mut sched = Scheduler::new();

        // Schedule ready, timed, and cancel tasks in mixed order.
        sched.schedule(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(1));
        sched.schedule_cancel(task(3), 50);
        sched.schedule(task(4), 200);
        sched.schedule_cancel(task(5), 100);
        sched.schedule_timed(task(6), Time::from_secs(2));

        // First two pops must be from cancel lane.
        let (_first, lane1) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane1, DispatchLane::Cancel),
            "first from cancel",
            true,
            true
        );

        let (_second, lane2) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Cancel),
            "second from cancel",
            true,
            true
        );

        // Now timed lane should drain (EDF order).
        let (_third, lane3) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane3, DispatchLane::Timed),
            "third from timed",
            true,
            true
        );

        let (_fourth, lane4) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane4, DispatchLane::Timed),
            "fourth from timed",
            true,
            true
        );

        // Finally ready lane.
        let (_fifth, lane5) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane5, DispatchLane::Ready),
            "fifth from ready",
            true,
            true
        );

        let (_sixth, lane6) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane6, DispatchLane::Ready),
            "sixth from ready",
            true,
            true
        );

        // Scheduler should now be empty.
        crate::assert_with_log!(
            sched.is_empty(),
            "empty after drain",
            true,
            sched.is_empty()
        );
        crate::test_complete!("cancel_drains_completely_before_timed_and_ready");
    }

    // ---- Move to cancel preserves other ready work ----------------------

    #[test]
    fn move_to_cancel_preserves_ready_work() {
        init_test("move_to_cancel_preserves_ready_work");
        let mut sched = Scheduler::new();

        // Schedule three ready tasks.
        sched.schedule(task(1), 100);
        sched.schedule(task(2), 100);
        sched.schedule(task(3), 100);
        let len_before = sched.len();
        crate::assert_with_log!(len_before == 3, "before move", 3, len_before);

        // Move task(2) to cancel lane.
        sched.move_to_cancel_lane(task(2), 200);

        // Total count should remain 3.
        let len_after = sched.len();
        crate::assert_with_log!(len_after == 3, "after move", 3, len_after);

        // First pop should be task(2) from cancel lane.
        let (first, lane) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(first == task(2), "cancel first", task(2), first);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Cancel),
            "from cancel lane",
            true,
            true
        );

        // Remaining two should be from ready lane.
        let (_, lane2) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Ready),
            "second from ready",
            true,
            true
        );

        let (_, lane3) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane3, DispatchLane::Ready),
            "third from ready",
            true,
            true
        );

        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("move_to_cancel_preserves_ready_work");
    }

    // ---- Interleaved schedule/pop maintains invariants -------------------

    #[test]
    fn interleaved_schedule_pop_correct() {
        init_test("interleaved_schedule_pop_correct");
        let mut sched = Scheduler::new();

        // Schedule and pop interleaved — scheduler should always return
        // highest priority lane first.
        sched.schedule(task(1), 50);
        let first = sched.pop();
        crate::assert_with_log!(first == Some(task(1)), "pop ready", Some(task(1)), first);

        sched.schedule_cancel(task(2), 100);
        sched.schedule(task(3), 200); // higher ready priority but cancel wins

        let second = sched.pop();
        crate::assert_with_log!(
            second == Some(task(2)),
            "cancel preempts",
            Some(task(2)),
            second
        );

        let third = sched.pop();
        crate::assert_with_log!(
            third == Some(task(3)),
            "ready dispatches after cancel drain",
            Some(task(3)),
            third
        );

        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("interleaved_schedule_pop_correct");
    }

    // ---- EDF with many same-deadline tasks is stable --------------------

    #[test]
    fn edf_same_deadline_fifo_stable() {
        init_test("edf_same_deadline_fifo_stable");
        let mut sched = Scheduler::new();
        let deadline = Time::from_secs(100);

        // Schedule 10 tasks with the same deadline — should dispatch in FIFO order
        // (by generation) when using basic pop.
        for i in 0..10 {
            sched.schedule_timed(task(i), deadline);
        }

        let mut order = Vec::new();
        while let Some(t) = sched.pop() {
            order.push(t);
        }

        crate::assert_with_log!(order.len() == 10, "all dispatched", 10, order.len());

        // Verify FIFO ordering (earlier index = lower task number).
        for window in order.windows(2) {
            let a_idx = window[0].arena_index().index();
            let b_idx = window[1].arena_index().index();
            crate::assert_with_log!(a_idx < b_idx, "FIFO order", true, true);
        }
        crate::test_complete!("edf_same_deadline_fifo_stable");
    }

    // ---- Remove from specific lane doesn't corrupt other lanes ----------

    #[test]
    fn remove_does_not_corrupt_other_lanes() {
        init_test("remove_does_not_corrupt_other_lanes");
        let mut sched = Scheduler::new();

        sched.schedule(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(10));
        sched.schedule_cancel(task(3), 200);

        // Remove timed task.
        sched.remove(task(2));
        let len = sched.len();
        crate::assert_with_log!(len == 2, "after remove", 2, len);

        // Cancel and ready should still work.
        let (first, lane1) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(first == task(3), "cancel intact", task(3), first);
        crate::assert_with_log!(
            matches!(lane1, DispatchLane::Cancel),
            "cancel lane",
            true,
            true
        );

        let (second, lane2) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(second == task(1), "ready intact", task(1), second);
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Ready),
            "ready lane",
            true,
            true
        );

        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("remove_does_not_corrupt_other_lanes");
    }

    // ---- High-volume cancel/ready interleaving --------------------------

    #[test]
    fn high_volume_cancel_ready_interleaving() {
        init_test("high_volume_cancel_ready_interleaving");
        let mut sched = Scheduler::new();

        // Schedule 50 cancel + 50 ready tasks.
        for i in 0..50 {
            sched.schedule_cancel(task(i), 100);
        }
        for i in 50..100 {
            sched.schedule(task(i), 100);
        }

        let total = sched.len();
        crate::assert_with_log!(total == 100, "total", 100, total);

        // All cancel tasks must dispatch before any ready task.
        let mut cancel_count = 0;
        let mut ready_seen = false;
        while let Some((_, lane)) = sched.pop_with_lane(0) {
            match lane {
                DispatchLane::Cancel => {
                    crate::assert_with_log!(
                        !ready_seen,
                        "no ready before cancel drains",
                        true,
                        true
                    );
                    cancel_count += 1;
                }
                DispatchLane::Ready => {
                    ready_seen = true;
                }
                DispatchLane::Timed | DispatchLane::Stolen => {}
            }
        }

        crate::assert_with_log!(cancel_count == 50, "cancel count", 50, cancel_count);
        crate::assert_with_log!(ready_seen, "ready seen", true, ready_seen);
        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("high_volume_cancel_ready_interleaving");
    }

    // ── Cancel promotion parity regression tests (bd-1zaql) ─────────────

    #[test]
    fn move_to_cancel_promotes_from_ready() {
        init_test("move_to_cancel_promotes_from_ready");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(1, 0);

        // Schedule in ready lane
        sched.schedule(task, 50);
        crate::assert_with_log!(
            !sched.is_in_cancel_lane(task),
            "not in cancel before promotion",
            true,
            true
        );

        // Promote to cancel lane
        sched.move_to_cancel_lane(task, 100);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "in cancel after promotion",
            true,
            true
        );

        // Pop should come from cancel lane
        let (popped, lane) = sched.pop_with_lane(0).expect("should have task");
        crate::assert_with_log!(popped == task, "correct task", task, popped);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Cancel),
            "dispatched from cancel lane",
            true,
            true
        );

        // Ready lane should be empty (task was removed during promotion)
        crate::assert_with_log!(
            sched.pop_ready_only().is_none(),
            "ready lane empty after promotion",
            true,
            true
        );
        crate::test_complete!("move_to_cancel_promotes_from_ready");
    }

    #[test]
    fn move_to_cancel_promotes_from_timed() {
        init_test("move_to_cancel_promotes_from_timed");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(2, 0);

        // Schedule in timed lane
        sched.schedule_timed(task, Time::from_nanos(5000));
        crate::assert_with_log!(
            !sched.is_in_cancel_lane(task),
            "not in cancel before promotion",
            true,
            true
        );

        // Promote to cancel lane
        sched.move_to_cancel_lane(task, 80);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "in cancel after promotion",
            true,
            true
        );

        // Pop should come from cancel lane
        let (popped, lane) = sched.pop_with_lane(0).expect("should have task");
        crate::assert_with_log!(popped == task, "correct task", task, popped);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Cancel),
            "dispatched from cancel lane",
            true,
            true
        );
        crate::test_complete!("move_to_cancel_promotes_from_timed");
    }

    #[test]
    fn move_to_cancel_idempotent_updates_priority() {
        init_test("move_to_cancel_idempotent_updates_priority");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(3, 0);

        // Schedule in cancel lane at low priority
        sched.schedule_cancel(task, 10);
        crate::assert_with_log!(sched.is_in_cancel_lane(task), "in cancel lane", true, true);

        // Promote again with higher priority (idempotent, updates priority)
        sched.move_to_cancel_lane(task, 200);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "still in cancel lane",
            true,
            true
        );

        // Only one task should be in scheduler
        crate::assert_with_log!(sched.len() == 1, "exactly one task", 1usize, sched.len());
        crate::test_complete!("move_to_cancel_idempotent_updates_priority");
    }

    #[test]
    fn schedule_cancel_promotes_from_ready() {
        init_test("schedule_cancel_promotes_from_ready");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(4, 0);

        // Schedule in ready lane
        sched.schedule(task, 50);

        // schedule_cancel should promote to cancel lane when already scheduled
        sched.schedule_cancel(task, 100);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "schedule_cancel promotes from ready",
            true,
            true
        );
        crate::test_complete!("schedule_cancel_promotes_from_ready");
    }

    #[test]
    fn repeated_cancel_requests_are_idempotent() {
        init_test("repeated_cancel_requests_are_idempotent");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(5, 0);

        // First cancel
        sched.move_to_cancel_lane(task, 50);
        crate::assert_with_log!(
            sched.len() == 1,
            "one task after first cancel",
            1usize,
            sched.len()
        );

        // Repeated cancel (same priority)
        sched.move_to_cancel_lane(task, 50);
        crate::assert_with_log!(
            sched.len() == 1,
            "still one task after repeat",
            1usize,
            sched.len()
        );

        // Repeated cancel (higher priority)
        sched.move_to_cancel_lane(task, 200);
        crate::assert_with_log!(
            sched.len() == 1,
            "still one task after priority bump",
            1usize,
            sched.len()
        );
        crate::test_complete!("repeated_cancel_requests_are_idempotent");
    }

    #[test]
    fn scheduled_set_collision_slot_clears_when_generations_drain() {
        init_test("scheduled_set_collision_slot_clears_when_generations_drain");
        let mut sched = Scheduler::new();
        let idx = 777_u32;
        let g0 = TaskId::from_arena(ArenaIndex::new(idx, 0));
        let g1 = TaskId::from_arena(ArenaIndex::new(idx, 1));
        let g2 = TaskId::from_arena(ArenaIndex::new(idx, 2));

        // Trigger dense collision tracking for this index.
        sched.schedule(g0, 10);
        sched.schedule(g1, 20);
        assert_eq!(
            sched.scheduled.dense[idx as usize],
            ScheduledSet::DENSE_COLLISION
        );

        // Remove both colliding generations. The slot should collapse back to empty dense state.
        sched.remove(g0);
        sched.remove(g1);
        assert_eq!(sched.scheduled.dense[idx as usize], 0);
        assert!(sched.scheduled.overflow.iter().all(|t| t.0.index() != idx));

        // New generation should use dense storage directly (not overflow fallback).
        sched.schedule(g2, 30);
        assert_ne!(
            sched.scheduled.dense[idx as usize],
            ScheduledSet::DENSE_COLLISION
        );
        assert!(!sched.scheduled.overflow.contains(&g2));
    }

    #[test]
    fn scheduled_set_collision_slot_collapses_to_single_remaining_generation() {
        init_test("scheduled_set_collision_slot_collapses_to_single_remaining_generation");
        let mut sched = Scheduler::new();
        let idx = 314_u32;
        let g0 = TaskId::from_arena(ArenaIndex::new(idx, 0));
        let g1 = TaskId::from_arena(ArenaIndex::new(idx, 1));

        sched.schedule(g0, 10);
        sched.schedule(g1, 20);
        assert_eq!(
            sched.scheduled.dense[idx as usize],
            ScheduledSet::DENSE_COLLISION
        );

        // Remove one generation; the remaining one should be restored to dense tracking.
        sched.remove(g1);
        let expected_tag = u64::from(g0.0.generation()) + 1;
        assert_eq!(sched.scheduled.dense[idx as usize], expected_tag);
        assert!(!sched.scheduled.overflow.contains(&g0));
    }

    // ── Audit regression tests (asupersync-10x0x.78) ─────────────────────

    #[test]
    fn schedule_timed_does_not_move_existing_ready_task() {
        init_test("schedule_timed_does_not_move_existing_ready_task");
        let mut sched = Scheduler::new();

        // Schedule task in ready lane first.
        sched.schedule(task(1), 100);
        assert!(sched.has_ready_work());

        // Attempt to schedule the same task in timed lane — should be a no-op.
        sched.schedule_timed(task(1), Time::from_secs(50));
        crate::assert_with_log!(sched.len() == 1, "still one task", 1usize, sched.len());
        crate::assert_with_log!(
            sched.has_ready_work(),
            "task remains in ready lane",
            true,
            sched.has_ready_work()
        );
        crate::assert_with_log!(
            !sched.has_timed_work(),
            "timed lane stays empty",
            true,
            !sched.has_timed_work()
        );

        // Pop should come from ready lane, not timed.
        let (popped, lane) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(popped == task(1), "correct task", task(1), popped);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Ready),
            "dispatched from ready lane",
            true,
            true
        );
        crate::test_complete!("schedule_timed_does_not_move_existing_ready_task");
    }

    #[test]
    fn steal_ready_batch_maintains_scheduled_set_invariant() {
        init_test("steal_ready_batch_maintains_scheduled_set_invariant");
        let mut sched = Scheduler::new();
        for i in 0..6 {
            sched.schedule(task(i), 50);
        }
        let before = sched.len();
        crate::assert_with_log!(before == 6, "6 tasks before steal", 6usize, before);

        let stolen = sched.steal_ready_batch(3);
        let after = sched.len();

        // len must decrease by exactly the number stolen.
        crate::assert_with_log!(
            before - after == stolen.len(),
            "len decreases by stolen count",
            stolen.len(),
            before - after
        );

        // None of the stolen tasks should be in the scheduler anymore.
        for (t, _) in &stolen {
            crate::assert_with_log!(
                !sched.is_in_cancel_lane(*t),
                "stolen task not in cancel",
                true,
                true
            );
        }

        // Remaining tasks should still pop correctly.
        let mut remaining = 0;
        while sched.pop().is_some() {
            remaining += 1;
        }
        crate::assert_with_log!(
            remaining == after,
            "remaining tasks pop correctly",
            after,
            remaining
        );
        crate::test_complete!("steal_ready_batch_maintains_scheduled_set_invariant");
    }

    #[test]
    fn dense_tag_at_max_generation_does_not_collide_with_sentinel() {
        init_test("dense_tag_at_max_generation_does_not_collide_with_sentinel");
        let mut sched = Scheduler::new();
        let max_gen = u32::MAX;
        let t = TaskId::from_arena(ArenaIndex::new(0, max_gen));

        // The tag for u32::MAX generation is u32::MAX + 1 = 4294967296.
        // This must NOT equal DENSE_COLLISION (u64::MAX).
        let tag = u64::from(max_gen) + 1;
        assert_ne!(tag, ScheduledSet::DENSE_COLLISION, "tag != sentinel");

        sched.schedule(t, 100);
        crate::assert_with_log!(sched.len() == 1, "inserted", 1usize, sched.len());

        let popped = sched.pop();
        crate::assert_with_log!(popped == Some(t), "popped correctly", Some(t), popped);
        crate::assert_with_log!(sched.is_empty(), "empty after pop", true, sched.is_empty());
        crate::test_complete!("dense_tag_at_max_generation_does_not_collide_with_sentinel");
    }

    #[test]
    fn move_to_cancel_lower_priority_is_noop() {
        init_test("move_to_cancel_lower_priority_is_noop");
        let mut sched = Scheduler::new();

        // Place task in cancel lane with high priority.
        sched.schedule_cancel(task(1), 200);
        sched.schedule_cancel(task(2), 50);

        // Try to "promote" task(1) with lower priority — should be a no-op.
        sched.move_to_cancel_lane(task(1), 100);

        // Task(1) should still come first (higher original priority).
        let first = sched.pop().unwrap();
        let second = sched.pop().unwrap();
        crate::assert_with_log!(
            first == task(1),
            "original high-priority task first",
            task(1),
            first
        );
        crate::assert_with_log!(
            second == task(2),
            "lower-priority task second",
            task(2),
            second
        );
        crate::test_complete!("move_to_cancel_lower_priority_is_noop");
    }

    #[test]
    fn certificate_uses_deterministic_hasher() {
        // Regression: ScheduleCertificate must produce identical hashes across
        // Rust versions. Previously used std DefaultHasher which is not
        // guaranteed stable; now uses DetHasher with a fixed seed.
        let mut c1 = ScheduleCertificate::new();
        c1.record(task(42), DispatchLane::Cancel, 0);
        c1.record(task(7), DispatchLane::Ready, 1);
        c1.record(task(13), DispatchLane::Timed, 2);

        // The hash must be non-zero (meaningful accumulation).
        assert_ne!(c1.hash(), 0, "certificate hash should be non-zero");

        // Running the same sequence again must produce the exact same hash.
        let mut c2 = ScheduleCertificate::new();
        c2.record(task(42), DispatchLane::Cancel, 0);
        c2.record(task(7), DispatchLane::Ready, 1);
        c2.record(task(13), DispatchLane::Timed, 2);

        assert_eq!(
            c1.hash(),
            c2.hash(),
            "identical sequences must produce identical hashes"
        );
        assert!(c1.matches(&c2));
    }

    #[test]
    fn pop_timed_only_with_hint_groups_by_deadline_not_now() {
        init_test("pop_timed_only_with_hint_groups_by_deadline_not_now");
        let mut sched = Scheduler::new();
        let deadline = Time::from_secs(10);

        // Schedule 3 tasks with the same deadline.
        sched.schedule_timed(task(1), deadline);
        sched.schedule_timed(task(2), deadline);
        sched.schedule_timed(task(3), deadline);

        let now = Time::from_secs(100); // well past deadline

        // Pop all three with different rng hints.
        let mut popped = Vec::new();
        for hint in 0..3 {
            if let Some(t) = sched.pop_timed_only_with_hint(hint, now) {
                popped.push(t);
            }
        }

        crate::assert_with_log!(
            popped.len() == 3,
            "all three dispatched",
            3usize,
            popped.len()
        );
        crate::assert_with_log!(
            sched.is_empty(),
            "empty after all pops",
            true,
            sched.is_empty()
        );
        crate::test_complete!("pop_timed_only_with_hint_groups_by_deadline_not_now");
    }

    #[test]
    fn tie_break_index_uses_full_u64_entropy() {
        // Regression: tie-break index must use all 64 bits so scheduling remains
        // deterministic across 32-bit and 64-bit targets.
        let idx = Scheduler::tie_break_index(1u64 << 32, 3);
        assert_eq!(idx, 1);
    }
}
