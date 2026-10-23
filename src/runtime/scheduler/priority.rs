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
            .then_with(|| {
                // Safe comparison without overflow: earlier generation wins
                self.generation.cmp(&other.generation).reverse()
            })
            .then_with(|| other.task.cmp(&self.task))
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
            .then_with(|| {
                let diff = other.generation.wrapping_sub(self.generation).cast_signed();
                diff.cmp(&0)
            })
            .then_with(|| other.task.cmp(&self.task))
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
        let overflow = DetHashSet::with_capacity_and_hasher(capacity, DetBuildHasher::default());

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
    fn contains(&self, task: TaskId) -> bool {
        let idx = task.0.index() as usize;
        let generation = u64::from(task.0.generation());
        // Avoid overflow collision with DENSE_COLLISION sentinel
        let tag = if generation == u64::MAX {
            Self::DENSE_COLLISION // Force overflow handling for max generation
        } else {
            generation + 1
        };

        if idx >= self.dense.len() {
            return self.overflow.contains(&task);
        }

        match self.dense[idx] {
            existing if existing == tag => true,
            Self::DENSE_COLLISION => self.overflow.contains(&task),
            _ => false,
        }
    }

    #[inline]
    fn insert(&mut self, task: TaskId) -> bool {
        let idx = task.0.index() as usize;
        let generation = u64::from(task.0.generation());
        // Avoid overflow collision with DENSE_COLLISION sentinel
        let tag = if generation == u64::MAX {
            Self::DENSE_COLLISION // Force overflow handling for max generation
        } else {
            generation + 1
        };

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

    fn remove(&mut self, task: TaskId) -> bool {
        let idx = task.0.index() as usize;
        let generation = u64::from(task.0.generation());
        // Avoid overflow collision with DENSE_COLLISION sentinel
        let tag = if generation == u64::MAX {
            Self::DENSE_COLLISION // Force overflow handling for max generation
        } else {
            generation + 1
        };

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
const DEFAULT_SCHEDULER_CAPACITY: usize = 256;
const DEFAULT_SCRATCH_CAPACITY: usize = 32;
const MAX_SCRATCH_CAPACITY: usize = 256;

impl Default for Scheduler {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_SCHEDULER_CAPACITY)
    }
}

impl Scheduler {
    #[inline]
    fn prune_cancel_head(&mut self) {
        while self
            .cancel_lane
            .peek()
            .is_some_and(|entry| !self.scheduled.contains(entry.task))
        {
            let _ = self.cancel_lane.pop();
        }
    }

    #[inline]
    fn next_valid_cancel_entry(&mut self) -> Option<SchedulerEntry> {
        self.prune_cancel_head();
        self.cancel_lane.peek().copied()
    }

    #[inline]
    fn prune_timed_head(&mut self) {
        while self
            .timed_lane
            .peek()
            .is_some_and(|entry| !self.scheduled.contains(entry.task))
        {
            let _ = self.timed_lane.pop();
        }
    }

    #[inline]
    fn next_valid_timed_entry(&mut self) -> Option<TimedEntry> {
        self.prune_timed_head();
        self.timed_lane.peek().copied()
    }

    #[inline]
    fn prune_ready_head(&mut self) {
        while self
            .ready_lane
            .peek()
            .is_some_and(|entry| !self.scheduled.contains(entry.task))
        {
            let _ = self.ready_lane.pop();
        }
    }

    #[inline]
    fn next_valid_ready_entry(&mut self) -> Option<SchedulerEntry> {
        self.prune_ready_head();
        self.ready_lane.peek().copied()
    }

    #[inline]
    fn ready_entry_is_stealable(&self, task: TaskId) -> bool {
        self.scheduled.contains(task)
            && !self.cancel_lane.iter().any(|entry| entry.task == task)
            && !self.timed_lane.iter().any(|entry| entry.task == task)
    }

    #[inline]
    fn live_ready_len(&self) -> usize {
        self.ready_lane
            .iter()
            .filter(|entry| self.ready_entry_is_stealable(entry.task))
            .count()
    }

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
    pub fn has_runnable_work(&mut self, now: Time) -> bool {
        if self.next_valid_cancel_entry().is_some() || self.next_valid_ready_entry().is_some() {
            return true;
        }
        self.next_valid_timed_entry()
            .is_some_and(|entry| entry.deadline <= now)
    }

    /// Returns the earliest deadline from the timed lane, if any.
    #[inline]
    #[must_use]
    pub fn next_deadline(&mut self) -> Option<Time> {
        self.next_valid_timed_entry().map(|entry| entry.deadline)
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
        while let Some(entry) = self.cancel_lane.pop() {
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
        }

        while let Some(entry) = self.timed_lane.pop() {
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
        }

        while let Some(entry) = self.ready_lane.pop() {
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
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
        // the bounded equal-priority (or equal-deadline) frontier materialized in scratch space.
        loop {
            if let Some(entry) =
                Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Cancel));
                }
                continue;
            }

            if let Some(entry) =
                Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Timed));
                }
                continue;
            }

            if let Some(entry) =
                Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Ready));
                }
                continue;
            }

            return None;
        }
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
        loop {
            if let Some(entry) =
                Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Cancel));
                }
                continue;
            }

            let timed_due = self
                .next_valid_timed_entry()
                .is_some_and(|entry| entry.deadline <= now);
            if timed_due {
                if let Some(entry) = Self::pop_timed_with_rng(
                    &mut self.timed_lane,
                    rng_hint,
                    &mut self.scratch_timed,
                ) {
                    if self.scheduled.remove(entry.task) {
                        return Some((entry.task, DispatchLane::Timed));
                    }
                    continue;
                }
            }

            if let Some(entry) =
                Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Ready));
                }
                continue;
            }

            return None;
        }
    }

    /// Pop a task from the cancel lane using deterministic RNG tie-breaking.
    #[inline]
    pub fn pop_cancel_with_rng(&mut self, rng_hint: u64) -> Option<(TaskId, DispatchLane)> {
        loop {
            let entry = Self::pop_entry_with_rng(
                &mut self.cancel_lane,
                rng_hint,
                &mut self.scratch_entries,
            )?;
            if self.scheduled.remove(entry.task) {
                return Some((entry.task, DispatchLane::Cancel));
            }
        }
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
        loop {
            if let Some(entry) =
                Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Timed));
                }
                continue;
            }

            if let Some(entry) =
                Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Ready));
                }
                continue;
            }

            return None;
        }
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
        loop {
            let timed_due = self
                .next_valid_timed_entry()
                .is_some_and(|entry| entry.deadline <= now);
            if timed_due {
                if let Some(entry) = Self::pop_timed_with_rng(
                    &mut self.timed_lane,
                    rng_hint,
                    &mut self.scratch_timed,
                ) {
                    if self.scheduled.remove(entry.task) {
                        return Some((entry.task, DispatchLane::Timed));
                    }
                    continue;
                }
            }

            if let Some(entry) =
                Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
            {
                if self.scheduled.remove(entry.task) {
                    return Some((entry.task, DispatchLane::Ready));
                }
                continue;
            }

            return None;
        }
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
            if peek.priority != priority || scratch.len() >= scratch.capacity() {
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
            if peek.deadline != deadline || scratch.len() >= scratch.capacity() {
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
    /// **Complexity: O(log n)** via lazy promotion (br-asupersync-cancel-
    /// promote-logn). The function pushes a new entry into `cancel_lane`
    /// without scanning or removing entries from `timed_lane` /
    /// `ready_lane`. The original entry (if any) becomes a TOMBSTONE that
    /// survives in its source lane until it bubbles to the top of that
    /// heap; the dispatcher's `pop` already gates every dispatch on
    /// `scheduled.remove(task)` and skips entries whose task has already
    /// been claimed by an earlier lane — so the stale entry is silently
    /// discarded on its eventual pop.
    ///
    /// This trades a small, bounded amount of dead heap memory (at most
    /// one stale entry per task per lane it ever occupied) for a
    /// dramatically better cancel-arrival latency under load: with 1000
    /// tasks in `timed_lane`, the pre-fix O(n) scan + retain-rebuild
    /// produced ~1ms-class cancel latency; the lazy-promote path
    /// produces ~µs-class latency regardless of lane depth.
    pub fn move_to_cancel_lane(&mut self, task: TaskId, priority: u8) {
        let generation = self.next_gen();

        // Always insert into `scheduled` (idempotent — `insert` is set-
        // semantics: if the task is already present, this is a no-op
        // and we just push another entry into cancel_lane). We do NOT
        // bail out on the already-scheduled branch the way the pre-fix
        // code did; pushing a duplicate cancel-lane entry is harmless
        // because `pop` lazy-skips stale entries.
        let _was_new = self.scheduled.insert(task);

        // Push the new high-priority cancel entry. If the task already
        // had an entry in cancel_lane / timed_lane / ready_lane, that
        // entry remains as a tombstone and is discarded on its
        // eventual pop. The new entry's priority controls the
        // dispatch order — a re-cancel with higher priority will
        // bubble to the top of the cancel-heap and be popped first;
        // the older lower-priority entry pops later and is silently
        // skipped because `scheduled.remove` already returned false.
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
        while let Some(entry) = self.cancel_lane.pop() {
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
        }
        None
    }

    /// Pops only from the cancel lane with RNG tie-breaking.
    #[inline]
    #[must_use]
    pub fn pop_cancel_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        loop {
            let entry = Self::pop_entry_with_rng(
                &mut self.cancel_lane,
                rng_hint,
                &mut self.scratch_entries,
            )?;
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
        }
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
        loop {
            if let Some(entry) = self.next_valid_timed_entry() {
                if entry.deadline <= now {
                    let entry = self.timed_lane.pop().expect("peeked entry should exist");
                    if self.scheduled.remove(entry.task) {
                        return Some(entry.task);
                    }
                    continue;
                }
            }
            return None;
        }
    }

    /// Pops only from the timed lane if the earliest deadline is due,
    /// with RNG tie-breaking among tasks sharing the earliest deadline.
    #[inline]
    #[must_use]
    pub fn pop_timed_only_with_hint(&mut self, rng_hint: u64, now: Time) -> Option<TaskId> {
        loop {
            let earliest = self.next_valid_timed_entry()?;
            if earliest.deadline > now {
                return None;
            }
            let entry =
                Self::pop_timed_with_rng(&mut self.timed_lane, rng_hint, &mut self.scratch_timed)
                    .expect("timed_lane peeked non-empty");
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
        }
    }

    /// Pops only from the ready lane.
    ///
    /// Use this for strict lane ordering in multi-worker scenarios.
    /// O(log n) pop via binary heap.
    #[inline]
    #[must_use]
    pub fn pop_ready_only(&mut self) -> Option<TaskId> {
        while let Some(entry) = self.ready_lane.pop() {
            if self.scheduled.remove(entry.task) {
                return Some(entry.task);
            }
        }
        None
    }

    /// Pops only from the ready lane with RNG tie-breaking among equal priorities.
    #[inline]
    #[must_use]
    pub fn pop_ready_only_with_hint(&mut self, rng_hint: u64) -> Option<TaskId> {
        loop {
            let entry = Self::pop_entry_with_rng(
                &mut self.ready_lane,
                rng_hint,
                &mut self.scratch_entries,
            )?;
            let task_id = entry.task;
            let removed = self.scheduled.remove(task_id);
            if removed {
                return Some(task_id);
            }
        }
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
        while let Some(entry) =
            Self::pop_entry_with_rng(&mut self.cancel_lane, rng_hint, &mut self.scratch_entries)
        {
            if self.scheduled.remove(entry.task) {
                return Some((0, entry.task));
            }
        }
        // Timed lane (EDF, only if deadline is due).
        while let Some(earliest) = self.next_valid_timed_entry() {
            if earliest.deadline <= now {
                if let Some(entry) = Self::pop_timed_with_rng(
                    &mut self.timed_lane,
                    rng_hint,
                    &mut self.scratch_timed,
                ) {
                    if self.scheduled.remove(entry.task) {
                        return Some((1, entry.task));
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        // Ready lane.
        while let Some(entry) =
            Self::pop_entry_with_rng(&mut self.ready_lane, rng_hint, &mut self.scratch_entries)
        {
            if self.scheduled.remove(entry.task) {
                return Some((2, entry.task));
            }
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
        if max_steal == 0 {
            return 0;
        }
        let live_ready = self.live_ready_len();
        if live_ready == 0 {
            return 0;
        }
        let steal_count = (live_ready / 2).min(max_steal).max(1);
        if out.capacity() < steal_count {
            out.reserve(steal_count - out.capacity());
        }

        let mut stolen = 0;
        // Pop up to steal_count valid entries. Stale entries (already
        // removed from `scheduled` by cancel/remove, or shadowed by a lazy
        // cancel/timed promotion) are silently discarded. Shadowed entries must
        // not clear `scheduled`, because their live higher-priority lane entry
        // still owns that task.
        while stolen < steal_count {
            let Some(entry) = self.ready_lane.pop() else {
                break;
            };
            if self.ready_entry_is_stealable(entry.task) && self.scheduled.remove(entry.task) {
                out.push((entry.task, entry.priority));
                stolen += 1;
            }
        }

        #[cfg(debug_assertions)]
        {
            debug_assert!(
                out.windows(2).all(|pair| pair[0].1 >= pair[1].1),
                "stolen ready batch must preserve non-increasing priority order"
            );
            let mut seen = std::collections::BTreeSet::new();
            let duplicate_free = out.iter().all(|(task, _)| seen.insert(*task));
            debug_assert!(
                duplicate_free,
                "stolen ready batch must not contain duplicate task ids"
            );
        }

        stolen
    }

    /// Returns true if the cancel lane has pending tasks.
    #[inline]
    #[must_use]
    pub fn has_cancel_work(&mut self) -> bool {
        self.next_valid_cancel_entry().is_some()
    }

    /// Returns true if the timed lane has pending tasks.
    #[inline]
    #[must_use]
    pub fn has_timed_work(&mut self) -> bool {
        self.next_valid_timed_entry().is_some()
    }

    /// Returns true if the ready lane has pending tasks.
    #[inline]
    #[must_use]
    pub fn has_ready_work(&mut self) -> bool {
        self.next_valid_ready_entry().is_some()
    }

    /// Returns an approximate count of queued ready-lane entries.
    ///
    /// This is intentionally ready-lane-only. It may include stale heap
    /// entries awaiting pruning after a promotion into another lane, so it is
    /// suitable for scheduler heuristics and observability but not for exact
    /// invariant checks.
    #[inline]
    #[must_use]
    pub fn approx_ready_len(&self) -> usize {
        self.ready_lane.len()
    }

    /// Returns an approximate count of queued cancel-lane entries.
    ///
    /// This may include stale heap entries awaiting pruning after the task was
    /// removed elsewhere, so it is suitable for scheduler heuristics and
    /// observability but not for exact invariant checks.
    #[inline]
    #[must_use]
    pub fn approx_cancel_len(&self) -> usize {
        self.cancel_lane.len()
    }

    /// Returns the current ready-lane head without removing it.
    #[inline]
    #[must_use]
    pub fn peek_ready_task(&mut self) -> Option<(TaskId, u8)> {
        self.next_valid_ready_entry()
            .map(|entry| (entry.task, entry.priority))
    }

    /// Returns the highest ready-lane priority currently pending.
    #[inline]
    #[must_use]
    pub fn peek_ready_priority(&mut self) -> Option<u8> {
        self.next_valid_ready_entry().map(|entry| entry.priority)
    }

    /// Clears all scheduled tasks.
    pub fn clear(&mut self) {
        self.cancel_lane.clear();
        self.timed_lane.clear();
        self.ready_lane.clear();
        self.scheduled.clear();
    }

    /// Enumerates the complete next eligible tie group without mutating queues.
    ///
    /// Exact exploration deliberately rejects lazy entries and oversized tie
    /// groups: removing tombstones or widening the normal RNG selection window
    /// would silently change the scheduler's policy.
    pub(crate) fn exact_exploration_choices(
        &self,
        now: Time,
        cancel_first: bool,
        max_entries: usize,
    ) -> Result<Vec<(TaskId, DispatchLane)>, &'static str> {
        let entries = self
            .cancel_lane
            .len()
            .saturating_add(self.timed_lane.len())
            .saturating_add(self.ready_lane.len());
        if entries > max_entries {
            return Err("scheduler inventory exceeds its entry budget");
        }
        let mut tasks: Vec<_> = self
            .cancel_lane
            .iter()
            .map(|entry| entry.task)
            .chain(self.timed_lane.iter().map(|entry| entry.task))
            .chain(self.ready_lane.iter().map(|entry| entry.task))
            .collect();
        tasks.sort_unstable();
        if tasks.len() != self.scheduled.len()
            || tasks.windows(2).any(|pair| pair[0] == pair[1])
            || tasks.iter().any(|task| !self.scheduled.contains(*task))
        {
            return Err("lazy or inconsistent scheduler entries are unsupported");
        }

        let lane = if cancel_first && !self.cancel_lane.is_empty() {
            DispatchLane::Cancel
        } else if self
            .timed_lane
            .peek()
            .is_some_and(|entry| entry.deadline <= now)
        {
            DispatchLane::Timed
        } else if !self.ready_lane.is_empty() {
            DispatchLane::Ready
        } else if !self.cancel_lane.is_empty() {
            DispatchLane::Cancel
        } else {
            return Ok(Vec::new());
        };
        let (mut choices, window): (Vec<_>, _) = match lane {
            DispatchLane::Cancel | DispatchLane::Ready => {
                let heap = if lane == DispatchLane::Cancel {
                    &self.cancel_lane
                } else {
                    &self.ready_lane
                };
                let priority = heap.peek().map(|entry| entry.priority);
                (
                    heap.iter()
                        .filter(|entry| Some(entry.priority) == priority)
                        .map(|entry| (entry.task, lane))
                        .collect(),
                    self.scratch_entries.capacity().max(1),
                )
            }
            DispatchLane::Timed => {
                let deadline = self.timed_lane.peek().map(|entry| entry.deadline);
                (
                    self.timed_lane
                        .iter()
                        .filter(|entry| Some(entry.deadline) == deadline)
                        .map(|entry| (entry.task, lane))
                        .collect(),
                    self.scratch_timed.capacity().max(1),
                )
            }
            DispatchLane::Stolen => unreachable!("single-worker inventory has no stolen lane"),
        };
        if choices.len() > window {
            return Err("scheduler tie group exceeds the legacy selection window");
        }
        choices.sort_unstable_by_key(|(task, _)| *task);
        Ok(choices)
    }

    /// Takes one exact task from its authoritative lane without consulting the
    /// normal scheduler selector.
    ///
    /// Lazy cancel promotion can leave tombstones in the timed or ready heaps,
    /// so lane discovery deliberately resolves `Cancel > Timed > Ready` before
    /// mutating any queue. A lane mismatch or future timed deadline leaves the
    /// scheduler byte-for-byte unchanged.
    pub(crate) fn take_exact(
        &mut self,
        task: TaskId,
        expected_lane: DispatchLane,
        now: Time,
    ) -> Result<(), ExactDispatchError> {
        if !self.scheduled.contains(task) {
            return Err(ExactDispatchError::NotScheduled);
        }

        let timed_deadline = self
            .timed_lane
            .iter()
            .filter(|entry| entry.task == task)
            .map(|entry| entry.deadline)
            .min();
        let actual_lane = if self.cancel_lane.iter().any(|entry| entry.task == task) {
            DispatchLane::Cancel
        } else if timed_deadline.is_some() {
            DispatchLane::Timed
        } else if self.ready_lane.iter().any(|entry| entry.task == task) {
            DispatchLane::Ready
        } else {
            return Err(ExactDispatchError::QueueInvariant);
        };

        if actual_lane != expected_lane {
            return Err(ExactDispatchError::LaneMismatch {
                actual: actual_lane,
            });
        }
        if actual_lane == DispatchLane::Timed {
            if let Some(deadline) = timed_deadline {
                if deadline > now {
                    return Err(ExactDispatchError::TimedNotDue { deadline });
                }
            }
        }

        let removed = self.scheduled.remove(task);
        debug_assert!(removed, "exact task was checked as scheduled");
        self.cancel_lane.retain(|entry| entry.task != task);
        self.timed_lane.retain(|entry| entry.task != task);
        self.ready_lane.retain(|entry| entry.task != task);
        Ok(())
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

/// Why an exact lab-only dispatch could not be taken from this scheduler.
///
/// This stays crate-private: production schedulers choose work according to
/// their normal policy. The deterministic lab runtime uses it to force a
/// previously recorded choice without falling back to a different task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactDispatchError {
    /// The full task generation is not scheduled.
    NotScheduled,
    /// The task is scheduled in the timed lane but its deadline is in the future.
    TimedNotDue {
        /// Earliest recorded deadline for this task.
        deadline: Time,
    },
    /// The task is runnable, but through a different lane than the receipt requires.
    LaneMismatch {
        /// Actual authoritative lane after lazy-promotion resolution.
        actual: DispatchLane,
    },
    /// The dedup set says the task is scheduled, but no authoritative lane entry exists.
    QueueInvariant,
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
        let mut hasher = DetHasher::for_lab();
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

#[cfg(test)]
#[path = "priority_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "priority_exact_exploration_tests.rs"]
mod exact_exploration_tests;
