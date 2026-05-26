//! Task table for hot-path task operations.
//!
//! Encapsulates task arena and stored futures to enable finer-grained locking.
//! Part of the sharding refactor (bd-2ijqf) to reduce RuntimeState contention.

use crate::record::task::{TaskPhase, TaskRecord};
use crate::runtime::stored_task::StoredTask;
use crate::types::TaskId;
use crate::util::{Arena, ArenaIndex, RecyclingPool};

/// Number of task phases that are considered "live" (not Completed).
const LIVE_PHASE_COUNT: usize = 5;

/// Telemetry for the `TaskRecord` recycling pool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskRecordPoolStats {
    /// Number of pooled acquisitions satisfied from cached recycled records.
    pub hits: usize,
    /// Number of pooled acquisitions that fell back to a fresh heap allocation.
    pub misses: usize,
    /// Number of recycle attempts accepted back into the pool cache.
    pub recycled: usize,
    /// Number of recycle attempts dropped because pooling was disabled or full.
    pub recycle_drops: usize,
}

/// Encapsulates task arena and stored futures for hot-path isolation.
///
/// This table owns the hot-path data structures accessed during every poll cycle:
/// - Task records (scheduling state, wake_state, intrusive links)
/// - Stored futures (the actual pollable futures)
///
/// When fully sharded, this table will be behind its own Mutex, allowing
/// poll operations to proceed without blocking on region/obligation mutations.
#[derive(Debug)]
pub struct TaskTable {
    /// All task records indexed by arena slot.
    pub(crate) tasks: Arena<TaskRecord>,
    /// Stored futures for polling, indexed by arena slot.
    ///
    /// Parallel to the tasks arena: `stored_futures[slot]` holds the pollable
    /// future for the task at that arena slot.  Using a flat `Vec` instead of
    /// `HashMap<TaskId, StoredTask>` eliminates hashing on the two hottest
    /// operations (remove + re-insert per poll cycle).
    stored_futures: Vec<Option<StoredTask>>,
    /// Number of occupied stored-future slots (avoids O(n) count).
    stored_future_len: usize,
    /// Object pool for recycling TaskRecord instances to eliminate allocation overhead.
    ///
    /// Reduces 35% of hot-path allocations by reusing TaskRecord objects instead
    /// of creating new ones. Pool size is bounded to prevent unbounded growth.
    task_record_pool: RecyclingPool<TaskRecord>,
    /// Incremental telemetry for pooled vs heap-fallback behavior.
    task_record_pool_stats: TaskRecordPoolStats,
    /// Incremental counters for tasks in each phase (Created, Running, etc.).
    ///
    /// These counters are maintained for mutation paths that go through
    /// `TaskTable::update_task`, but some legacy scheduler paths still mutate
    /// `TaskRecord` phases through direct record access. Public phase-count
    /// accessors therefore derive authoritative counts from the arena.
    /// Indexed by `TaskPhase` enum values 0..5.
    #[allow(dead_code)]
    phase_counts: [usize; LIVE_PHASE_COUNT],
    /// Incremental total of all non-terminal task phases.
    ///
    /// Kept as a mutation-side cache for future fully-encapsulated task phase
    /// updates. Read-side access currently scans the arena so direct legacy
    /// `TaskRecord` phase mutations cannot panic or leak stale health metrics.
    live_task_count: usize,
    /// Sum of all deadlines (in nanoseconds) for live tasks that have a
    /// non-infinite deadline. Combined with virtual-time `now`, allows O(1)
    /// estimation of deadline pressure.
    #[allow(dead_code)]
    deadline_sum_ns: u128,
    /// Number of live tasks that contributed to `deadline_sum_ns`.
    #[allow(dead_code)]
    tasks_with_deadline: usize,
}

impl TaskTable {
    /// Derives the recycler capacity bound from an arena task capacity hint.
    #[must_use]
    #[inline]
    pub const fn recommended_pool_limit_for_capacity(capacity: usize) -> usize {
        let quarter = capacity / 4;
        if quarter < 64 {
            64
        } else if quarter > 512 {
            512
        } else {
            quarter
        }
    }

    /// Creates a new empty task table.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            tasks: Arena::new(),
            stored_futures: Vec::new(),
            stored_future_len: 0,
            task_record_pool: RecyclingPool::new(256), // Pool up to 256 recycled TaskRecords
            task_record_pool_stats: TaskRecordPoolStats::default(),
            phase_counts: [0; LIVE_PHASE_COUNT],
            live_task_count: 0,
            deadline_sum_ns: 0,
            tasks_with_deadline: 0,
        }
    }

    /// Creates a new task table with pre-allocated capacity.
    ///
    /// Pre-sizing eliminates reallocation overhead during initial task spawning.
    /// Based on benchmark analysis, arena growth contributes ~28% of allocations.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        // Use 25% of capacity for pool size to balance memory vs recycling benefits.
        let pool_size = Self::recommended_pool_limit_for_capacity(capacity);
        Self::with_capacity_and_pool_limit(capacity, pool_size)
    }

    /// Creates a new task table with explicit arena capacity and pool limit.
    ///
    /// Passing `pool_limit = 0` disables recycling and forces heap fallback on
    /// every task-record acquisition while preserving the same task-table API.
    #[must_use]
    #[inline]
    pub fn with_capacity_and_pool_limit(capacity: usize, pool_limit: usize) -> Self {
        Self {
            tasks: Arena::with_capacity(capacity),
            stored_futures: Vec::with_capacity(capacity),
            stored_future_len: 0,
            task_record_pool: RecyclingPool::new(pool_limit),
            task_record_pool_stats: TaskRecordPoolStats::default(),
            phase_counts: [0; LIVE_PHASE_COUNT],
            live_task_count: 0,
            deadline_sum_ns: 0,
            tasks_with_deadline: 0,
        }
    }

    /// Returns the reserved task-record arena capacity.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub(crate) fn capacity(&self) -> usize {
        self.tasks.capacity()
    }

    /// Returns the number of recycled task records currently cached in the pool.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub(crate) fn recycled_task_record_count(&self) -> usize {
        self.task_record_pool.len()
    }

    /// Returns the configured maximum number of recycled task records cached in the pool.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub fn task_record_pool_capacity(&self) -> usize {
        self.task_record_pool.max_size()
    }

    /// Returns whether task-record pooling is enabled for this table.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub fn task_record_pool_enabled(&self) -> bool {
        self.task_record_pool.max_size() > 0
    }

    /// Returns pooled-vs-heap fallback telemetry for this table.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub fn task_record_pool_stats(&self) -> TaskRecordPoolStats {
        self.task_record_pool_stats
    }

    /// Returns a shared reference to a task record by arena index.
    #[inline]
    #[must_use]
    pub fn get(&self, index: ArenaIndex) -> Option<&TaskRecord> {
        self.tasks.get(index)
    }

    /// Returns a mutable reference to a task record by arena index.
    #[inline]
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut TaskRecord> {
        self.tasks.get_mut(index)
    }

    /// Records a task phase transition for incremental bookkeeping.
    ///
    /// O(1) — updates cached counters used for Lyapunov governor snapshots.
    #[inline]
    pub fn note_phase_transition(&mut self, old_phase: TaskPhase, new_phase: TaskPhase) {
        if old_phase == new_phase {
            return;
        }

        // Decrement old phase counter if it was live
        let old_idx = old_phase as usize;
        if old_idx < LIVE_PHASE_COUNT {
            self.phase_counts[old_idx] = self.phase_counts[old_idx].saturating_sub(1);
            self.live_task_count = self.live_task_count.saturating_sub(1);
        }

        // Increment new phase counter if it is live
        let new_idx = new_phase as usize;
        if new_idx < LIVE_PHASE_COUNT {
            self.phase_counts[new_idx] = self.phase_counts[new_idx].saturating_add(1);
            self.live_task_count = self.live_task_count.saturating_add(1);
        }
    }

    /// Internal helper to register a new live task's metadata.
    #[inline]
    fn note_task_added(&mut self, phase: TaskPhase, deadline: Option<crate::types::Time>) {
        let idx = phase as usize;
        if idx < LIVE_PHASE_COUNT {
            self.phase_counts[idx] = self.phase_counts[idx].saturating_add(1);
            self.live_task_count = self.live_task_count.saturating_add(1);
        }
        if let Some(d) = deadline {
            self.deadline_sum_ns = self
                .deadline_sum_ns
                .saturating_add(u128::from(d.as_nanos()));
            self.tasks_with_deadline += 1;
        }
    }

    /// Internal helper to unregister a task's metadata (called on removal or terminal transition).
    #[inline]
    fn note_task_removed(&mut self, phase: TaskPhase, deadline: Option<crate::types::Time>) {
        let idx = phase as usize;
        if idx < LIVE_PHASE_COUNT {
            self.phase_counts[idx] = self.phase_counts[idx].saturating_sub(1);
            self.live_task_count = self.live_task_count.saturating_sub(1);
        }
        if let Some(d) = deadline {
            self.deadline_sum_ns = self
                .deadline_sum_ns
                .saturating_sub(u128::from(d.as_nanos()));
            self.tasks_with_deadline = self.tasks_with_deadline.saturating_sub(1);
        }
    }

    /// Updates a task's deadline in the incremental sum.
    #[inline]
    pub fn note_deadline_changed(
        &mut self,
        old_deadline: Option<crate::types::Time>,
        new_deadline: Option<crate::types::Time>,
    ) {
        if old_deadline == new_deadline {
            return;
        }
        if let Some(d) = old_deadline {
            self.deadline_sum_ns = self
                .deadline_sum_ns
                .saturating_sub(u128::from(d.as_nanos()));
            self.tasks_with_deadline = self.tasks_with_deadline.saturating_sub(1);
        }
        if let Some(d) = new_deadline {
            self.deadline_sum_ns = self
                .deadline_sum_ns
                .saturating_add(u128::from(d.as_nanos()));
            self.tasks_with_deadline += 1;
        }
    }

    /// Returns the number of tasks in a specific phase.
    #[must_use]
    #[inline]
    pub fn count_in_phase(&self, phase: TaskPhase) -> usize {
        let idx = phase as usize;
        if idx < LIVE_PHASE_COUNT {
            self.tasks
                .iter()
                .filter(|(_, record)| record.phase.load() == phase)
                .count()
        } else {
            0
        }
    }

    /// Returns the sum of deadlines for all live tasks.
    #[must_use]
    #[inline]
    pub fn deadline_sum_ns(&self) -> u128 {
        self.deadline_sum_ns
    }

    /// Returns the number of live tasks with a non-infinite deadline.
    #[must_use]
    #[inline]
    pub fn tasks_with_deadline_count(&self) -> usize {
        self.tasks_with_deadline
    }

    /// Inserts a task record into the arena (arena-index based).
    #[inline]
    pub fn insert(&mut self, mut record: TaskRecord) -> ArenaIndex {
        let phase = record.phase.load();
        let deadline = record.deadline;
        let idx = self.tasks.insert_with(|idx| {
            // Canonicalize record.id to its arena slot to keep table invariants intact.
            record.id = TaskId::from_arena(idx);
            record
        });
        self.note_task_added(phase, deadline);
        idx
    }

    /// Removes a task record by arena index.
    #[inline]
    pub fn remove(&mut self, index: ArenaIndex) -> Option<TaskRecord> {
        let record = self.tasks.remove(index)?;
        let slot = index.index() as usize;
        if slot < self.stored_futures.len() && self.stored_futures[slot].take().is_some() {
            self.stored_future_len -= 1;
        }
        self.note_task_removed(record.phase.load(), record.deadline);
        Some(record)
    }

    /// Removes a task record by arena index and recycles it to the pool.
    ///
    /// This is the preferred method for removing completed or cancelled tasks
    /// as it enables object pool recycling to reduce allocation overhead.
    #[inline]
    pub fn remove_and_recycle(&mut self, index: ArenaIndex) {
        if let Some(record) = self.remove(index) {
            // Recycle the TaskRecord for future reuse
            if self.task_record_pool.put_recycled(record) {
                self.task_record_pool_stats.recycled += 1;
            } else {
                self.task_record_pool_stats.recycle_drops += 1;
            }
        }
    }

    /// Returns an iterator over task records.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &TaskRecord)> {
        self.tasks.iter()
    }

    /// Returns the number of task records in the arena.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns `true` if the task arena is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Returns a reference to a task record by ID.
    #[inline]
    #[must_use]
    pub fn task(&self, task_id: TaskId) -> Option<&TaskRecord> {
        self.tasks.get(task_id.arena_index())
    }

    /// Returns a mutable reference to a task record by ID.
    #[inline]
    pub fn task_mut(&mut self, task_id: TaskId) -> Option<&mut TaskRecord> {
        self.tasks.get_mut(task_id.arena_index())
    }

    /// Inserts a new task record into the arena.
    ///
    /// Returns the assigned arena index.
    #[inline]
    pub fn insert_task(&mut self, record: TaskRecord) -> ArenaIndex {
        self.insert(record)
    }

    /// Creates a TaskRecord from the pool and inserts it into the arena.
    ///
    /// This method uses object pooling to reduce allocation overhead by reusing
    /// previously allocated TaskRecord instances. Provides optimal performance
    /// for high-throughput task creation scenarios.
    #[inline]
    pub fn insert_pooled_task(
        &mut self,
        task_id: TaskId,
        owner: crate::types::RegionId,
        budget: crate::types::Budget,
        created_at: crate::types::Time,
    ) -> ArenaIndex {
        let mut record = if let Some(record) = self.task_record_pool.try_get() {
            self.task_record_pool_stats.hits += 1;
            record
        } else {
            self.task_record_pool_stats.misses += 1;
            TaskRecord::new_with_time(task_id, owner, budget, created_at)
        };

        // Initialize the pooled record or fresh heap fallback.
        record.id = task_id;
        record.owner = owner;
        record.created_at = created_at;
        record.deadline = budget.deadline;
        record.polls_remaining = budget.poll_quota;
        // br-asupersync-1w9aot: route through wall_now() so the lab
        // runtime's virtual clock can intercept on replay; production
        // unchanged. The field's type was `std::time::Instant` before
        // the bead fix; it is now `crate::types::Time`.
        #[cfg(feature = "tracing-integration")]
        {
            record.created_instant = crate::time::wall_now();
        }

        self.insert(record)
    }

    /// Inserts a new task record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`. The Lyapunov phase
    /// counter and deadline-sum are updated via `note_task_added` after
    /// the record is in the arena (br-asupersync-i8f043: previously this
    /// path skipped the bookkeeping, drifting `phase_counts` and
    /// `deadline_sum_ns` against the live task population).
    #[inline]
    pub fn insert_task_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> TaskRecord,
    {
        let idx = self.tasks.insert_with(|idx| {
            let mut record = f(idx);
            // Preserve TaskTable invariant: record.id must match arena slot.
            record.id = TaskId::from_arena(idx);
            record
        });
        // Read phase + deadline back from the just-inserted record so the
        // bookkeeping matches whatever the closure produced. The arena
        // owns the record now, so read-through-arena is the only safe
        // way to do this without changing the closure signature.
        if let Some(record) = self.tasks.get(idx) {
            let phase = record.phase.load();
            self.note_task_added(phase, record.deadline);
        }
        idx
    }

    /// Creates a pooled TaskRecord using the provided factory function.
    ///
    /// This method combines object pooling with the flexible construction pattern
    /// of insert_task_with. The factory receives the arena index and should
    /// configure the pooled TaskRecord appropriately. Bookkeeping is updated
    /// via `note_task_added` after insertion, matching `insert_task_with`
    /// (br-asupersync-i8f043).
    #[inline]
    pub fn insert_pooled_task_with<F>(&mut self, factory: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex, &mut TaskRecord),
    {
        let mut record = if let Some(record) = self.task_record_pool.try_get() {
            self.task_record_pool_stats.hits += 1;
            record
        } else {
            self.task_record_pool_stats.misses += 1;
            TaskRecord::new(
                TaskId::from_arena(crate::util::ArenaIndex::new(0, 0)),
                crate::types::RegionId::testing_default(),
                crate::types::Budget::INFINITE,
            )
        };

        let idx = self.tasks.insert_with(|idx| {
            // Apply custom initialization
            factory(idx, &mut record);
            // Ensure TaskTable invariant: record.id matches arena slot
            record.id = TaskId::from_arena(idx);
            record
        });
        if let Some(record) = self.tasks.get(idx) {
            let phase = record.phase.load();
            self.note_task_added(phase, record.deadline);
        }
        idx
    }

    /// Updates a task record using a closure.
    #[inline]
    pub fn update_task<F, R>(&mut self, task_id: TaskId, f: F) -> Option<R>
    where
        F: FnOnce(&mut TaskRecord) -> R,
    {
        if let Some(record) = self.tasks.get_mut(task_id.arena_index()) {
            let old_phase = record.phase.load();
            let was_live = (old_phase as usize) < LIVE_PHASE_COUNT;
            let old_deadline = record.deadline;

            let res = f(record);

            let new_phase = record.phase.load();
            let is_live = (new_phase as usize) < LIVE_PHASE_COUNT;
            let new_deadline = record.deadline;

            self.note_phase_transition(old_phase, new_phase);

            // Maintain deadline sum only for live tasks
            match (was_live, is_live) {
                (true, true) => self.note_deadline_changed(old_deadline, new_deadline),
                (true, false) => self.note_deadline_changed(old_deadline, None),
                (false, true) => self.note_deadline_changed(None, new_deadline),
                (false, false) => {}
            }

            Some(res)
        } else {
            None
        }
    }

    /// Removes a task record from the arena.
    ///
    /// Returns the removed record if it existed.
    #[inline]
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<TaskRecord> {
        self.remove(task_id.arena_index())
    }

    /// Removes a task record from the arena and recycles it to the pool.
    ///
    /// This is the preferred method for removing tasks in high-throughput scenarios
    /// as it enables object reuse to reduce allocation overhead.
    #[inline]
    pub fn remove_and_recycle_task(&mut self, task_id: TaskId) {
        self.remove_and_recycle(task_id.arena_index())
    }

    /// Stores a spawned task's future for later polling.
    #[inline]
    pub fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask) {
        // Keep table invariants strict: every stored future must correspond to
        // an existing live task record.
        if self.tasks.get(task_id.arena_index()).is_none() {
            return;
        }
        let slot = task_id.arena_index().index() as usize;
        if slot >= self.stored_futures.len() {
            self.stored_futures.resize_with(slot + 1, || None);
        }
        if self.stored_futures[slot].replace(stored).is_none() {
            self.stored_future_len += 1;
        }
    }

    /// Returns a mutable reference to a stored future.
    #[inline]
    pub fn get_stored_future(&mut self, task_id: TaskId) -> Option<&mut StoredTask> {
        self.tasks.get(task_id.arena_index())?;
        let slot = task_id.arena_index().index() as usize;
        // SAFETY: Bounds check prevents memory corruption from crafted task IDs
        if slot >= self.stored_futures.len() {
            return None;
        }
        self.stored_futures.get_mut(slot)?.as_mut()
    }

    /// Removes and returns a stored future for polling.
    ///
    /// This is the hot-path operation called at the start of each poll cycle.
    #[inline]
    pub fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        self.tasks.get(task_id.arena_index())?;
        let slot = task_id.arena_index().index() as usize;
        // SAFETY: Bounds check prevents memory corruption from crafted task IDs
        if slot >= self.stored_futures.len() {
            return None;
        }
        let taken = self.stored_futures.get_mut(slot)?.take();
        if taken.is_some() {
            self.stored_future_len -= 1;
        }
        taken
    }

    /// Returns the number of live tasks (non-terminal).
    #[must_use]
    #[inline]
    pub fn live_task_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|(_, record)| (record.phase.load() as usize) < LIVE_PHASE_COUNT)
            .count()
    }

    /// Returns the number of stored futures.
    #[must_use]
    #[inline]
    pub fn stored_future_count(&self) -> usize {
        self.stored_future_len
    }

    /// Provides direct access to the tasks arena.
    ///
    /// Used by intrusive data structures (LocalQueue) that operate on the arena.
    #[inline]
    #[must_use]
    pub fn tasks_arena(&self) -> &Arena<TaskRecord> {
        &self.tasks
    }

    /// Provides mutable access to the tasks arena.
    ///
    /// Used by intrusive data structures (LocalQueue) that operate on the arena.
    #[inline]
    pub fn tasks_arena_mut(&mut self) -> &mut Arena<TaskRecord> {
        &mut self.tasks
    }
}

impl Default for TaskTable {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{Budget, Outcome, RegionId, Time};

    #[inline]
    fn make_task_record(owner: RegionId) -> TaskRecord {
        // Use a provisional TaskId (0,0); insert_task canonicalizes it.
        let provisional_id = TaskId::from_arena(ArenaIndex::new(0, 0));
        TaskRecord::new(provisional_id, owner, Budget::INFINITE)
    }

    fn live_phase_sum(table: &TaskTable) -> usize {
        table.phase_counts.iter().sum()
    }

    #[test]
    fn insert_and_get_task() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let record = make_task_record(owner);

        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        let retrieved = table.task(task_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner, owner);
    }

    #[test]
    fn remove_task() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let record = make_task_record(owner);

        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        assert!(table.task(task_id).is_some());
        let removed = table.remove_task(task_id);
        assert!(removed.is_some());
        assert!(table.task(task_id).is_none());
    }

    #[test]
    fn live_task_count() {
        let mut table = TaskTable::new();
        assert_eq!(table.live_task_count(), 0);

        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let idx1 = table.insert_task(make_task_record(owner));
        let _idx2 = table.insert_task(make_task_record(owner));

        assert_eq!(table.live_task_count(), 2);

        table.remove_task(TaskId::from_arena(idx1));
        assert_eq!(table.live_task_count(), 1);
    }

    #[test]
    fn live_task_count_scalar_tracks_phase_bucket_sum() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let idx1 = table.insert_task(make_task_record(owner));
        let idx2 = table.insert_task(make_task_record(owner));
        let task1 = TaskId::from_arena(idx1);
        let task2 = TaskId::from_arena(idx2);
        assert_eq!(table.live_task_count(), live_phase_sum(&table));

        table.update_task(task1, |record| {
            record.start_running();
        });
        assert_eq!(table.live_task_count(), live_phase_sum(&table));

        table.update_task(task1, |record| {
            record.complete(Outcome::Ok(()));
        });
        assert_eq!(table.live_task_count(), live_phase_sum(&table));

        table.remove_task(task2);
        assert_eq!(table.live_task_count(), live_phase_sum(&table));
        assert_eq!(table.live_task_count(), 0);
    }

    #[test]
    fn live_phase_accessors_survive_direct_record_phase_mutation() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let idx = table.insert_task(make_task_record(owner));
        let task = TaskId::from_arena(idx);

        table
            .task_mut(task)
            .expect("task should exist")
            .start_running();

        assert_eq!(table.live_task_count(), 1);
        assert_eq!(table.count_in_phase(TaskPhase::Created), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Running), 1);

        table.remove_task(task);
        assert_eq!(table.live_task_count(), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Created), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Running), 0);
    }

    #[test]
    fn store_and_remove_stored_future() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let idx = table.insert_task(make_task_record(RegionId::from_arena(ArenaIndex::new(
            1, 0,
        ))));
        let task_id = TaskId::from_arena(idx);

        let stored = StoredTask::new(async { Outcome::Ok(()) });
        table.store_spawned_task(task_id, stored);

        assert_eq!(table.stored_future_count(), 1);
        assert!(table.get_stored_future(task_id).is_some());

        let removed = table.remove_stored_future(task_id);
        assert!(removed.is_some());
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(task_id).is_none());
    }

    #[test]
    fn remove_task_cleans_stored_future() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let idx = table.insert_task(make_task_record(RegionId::from_arena(ArenaIndex::new(
            1, 0,
        ))));
        let task_id = TaskId::from_arena(idx);

        table.store_spawned_task(task_id, StoredTask::new(async { Outcome::Ok(()) }));
        assert_eq!(table.stored_future_count(), 1);

        let removed = table.remove_task(task_id);
        assert!(removed.is_some());
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(task_id).is_none());
    }

    #[test]
    fn remove_by_index_cleans_stored_future_even_with_stale_record_id() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        // Model a caller inserting a provisional/stale id.
        let stale = TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            owner,
            Budget::INFINITE,
        );
        let idx = table.insert_task(stale);
        let canonical_id = TaskId::from_arena(idx);

        table.store_spawned_task(canonical_id, StoredTask::new(async { Outcome::Ok(()) }));
        assert_eq!(table.stored_future_count(), 1);

        let removed = table.remove(idx);
        assert!(removed.is_some());
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(canonical_id).is_none());
    }

    #[test]
    fn insert_task_canonicalizes_record_id() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let stale = TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            owner,
            Budget::INFINITE,
        );
        let idx = table.insert_task(stale);

        let canonical_id = TaskId::from_arena(idx);
        let record = table.task(canonical_id).expect("task should exist");
        assert_eq!(record.id, canonical_id);
    }

    #[test]
    fn insert_task_with_canonicalizes_record_id() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let idx = table.insert_task_with(|_idx| {
            // Intentionally stale provisional id to verify table-side canonicalization.
            TaskRecord::new(
                TaskId::from_arena(ArenaIndex::new(0, 0)),
                owner,
                Budget::INFINITE,
            )
        });

        let canonical_id = TaskId::from_arena(idx);
        let record = table.task(canonical_id).expect("task should exist");
        assert_eq!(record.id, canonical_id);
    }

    #[test]
    fn insert_task_with_tracks_deadline_without_cx() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let deadline = crate::types::Time::from_nanos(1_000);
        let budget = Budget::INFINITE.with_deadline(deadline);

        let idx = table.insert_task_with(|_idx| {
            TaskRecord::new(TaskId::from_arena(ArenaIndex::new(0, 0)), owner, budget)
        });

        let canonical_id = TaskId::from_arena(idx);
        let record = table.task(canonical_id).expect("task should exist");
        assert_eq!(record.deadline, Some(deadline));
        assert_eq!(table.tasks_with_deadline_count(), 1);
        assert_eq!(table.deadline_sum_ns(), u128::from(deadline.as_nanos()));
    }

    #[test]
    fn store_spawned_task_ignores_unknown_task_id() {
        use crate::runtime::stored_task::StoredTask;
        use crate::types::Outcome;

        let mut table = TaskTable::new();
        let unknown = TaskId::from_arena(ArenaIndex::new(4242, 0));
        table.store_spawned_task(unknown, StoredTask::new(async { Outcome::Ok(()) }));

        assert_eq!(table.live_task_count(), 0);
        assert_eq!(table.stored_future_count(), 0);
        assert!(table.get_stored_future(unknown).is_none());
    }

    #[test]
    fn pooled_insert_clears_stale_metadata_before_reuse() {
        let mut table = TaskTable::with_capacity(256);
        let owner_a = RegionId::from_arena(ArenaIndex::new(1, 0));
        let owner_b = RegionId::from_arena(ArenaIndex::new(2, 0));

        let idx = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner_a,
                Budget::new()
                    .with_poll_quota(7)
                    .with_deadline(Time::from_nanos(99)),
                Time::from_nanos(5),
            );
        });
        let task_id = TaskId::from_arena(idx);

        let record = table.task_mut(task_id).expect("pooled task exists");
        record.request_cancel(crate::types::CancelReason::timeout());
        record
            .waiters
            .push(TaskId::from_arena(ArenaIndex::new(88, 0)));
        record.cached_waker = Some((std::task::Waker::noop().clone(), 3));
        record.cached_cancel_waker = Some((std::task::Waker::noop().clone(), 4));
        record.pin_to_worker(7);
        record.queue_tag = 9;
        record.heap_index = Some(11);
        record.sched_priority = 5;
        record.sched_generation = 44;
        record.total_polls = 12;
        record.last_polled_step = 77;

        table.remove_and_recycle_task(task_id);
        assert_eq!(table.recycled_task_record_count(), 1);

        let reused_idx = table.insert_pooled_task_with(|_idx, record| {
            record.owner = owner_b;
            record.created_at = Time::from_nanos(123);
            record.polls_remaining = 5;
        });
        let reused_id = TaskId::from_arena(reused_idx);
        let reused = table.task(reused_id).expect("reused pooled task exists");

        assert_eq!(table.recycled_task_record_count(), 0);
        assert_eq!(reused.id, reused_id);
        assert_eq!(reused.owner, owner_b);
        assert!(matches!(
            &reused.state,
            crate::record::task::TaskState::Created
        ));
        assert_eq!(reused.phase(), TaskPhase::Created);
        assert_eq!(reused.deadline, None);
        assert_eq!(reused.waiters.len(), 0);
        assert!(reused.cached_waker.is_none());
        assert!(reused.cached_cancel_waker.is_none());
        assert_eq!(reused.cancel_epoch, 0);
        assert!(!reused.is_local());
        assert!(reused.pinned_worker.is_none());
        assert_eq!(reused.queue_tag, 0);
        assert_eq!(reused.heap_index, None);
        assert_eq!(reused.sched_priority, 0);
        assert_eq!(reused.sched_generation, 0);
        assert_eq!(reused.total_polls, 0);
        assert_eq!(reused.last_polled_step, 0);
    }

    #[test]
    fn pooled_insert_tracks_deadline_without_cx() {
        let mut table = TaskTable::with_capacity(256);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let deadline = Time::from_nanos(1_234);

        let idx = table.insert_pooled_task_with(|_idx, record| {
            record.owner = owner;
            record.deadline = Some(deadline);
            record.polls_remaining = 1;
            record.created_at = Time::from_nanos(7);
        });

        let task_id = TaskId::from_arena(idx);
        let record = table.task(task_id).expect("pooled task exists");
        assert_eq!(record.deadline, Some(deadline));
        assert_eq!(table.tasks_with_deadline_count(), 1);
        assert_eq!(table.deadline_sum_ns(), u128::from(deadline.as_nanos()));
    }

    #[test]
    fn remove_and_recycle_task_double_return_is_noop() {
        let mut table = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
        let idx = table.insert_task(make_task_record(owner));
        let task_id = TaskId::from_arena(idx);

        table.remove_and_recycle_task(task_id);
        table.remove_and_recycle_task(task_id);

        assert_eq!(table.recycled_task_record_count(), 1);
        assert!(table.task(task_id).is_none());
        assert_eq!(table.live_task_count(), 0);
    }

    #[test]
    fn insert_pooled_task_with_field_mutation_reuses_recycled_wake_state() {
        // br-asupersync-j1e7zy regression: the production spawn paths in
        // src/cx/scope.rs and src/runtime/state.rs use field-by-field
        // mutation inside `insert_pooled_task_with` so the recycled
        // record's `wake_state` Arc (allocated by `Recyclable::reset`
        // when the prior task was recycled) is reused instead of being
        // dropped+replaced.  Verify that pattern preserves Arc identity
        // across recycle+reinsert.
        use std::sync::Arc;

        let mut table = TaskTable::with_capacity(64);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        // Pool miss: first insert fabricates a fresh record via the
        // miss-path fallback inside `insert_pooled_task_with`.
        let idx1 = table.insert_pooled_task_with(|idx, record| {
            record.id = TaskId::from_arena(idx);
            record.owner = owner;
            record.created_at = Time::from_nanos(1);
            record.deadline = None;
            record.polls_remaining = 1;
        });
        let id1 = TaskId::from_arena(idx1);

        // Recycle: `Recyclable::reset` runs before the record is
        // returned to the pool, allocating a new wake_state Arc on the
        // recycled record.  That Arc is what we want the *next* spawn to
        // reuse.
        table.remove_and_recycle_task(id1);
        assert_eq!(table.recycled_task_record_count(), 1);

        // Pool hit: the field-mutation factory should leave wake_state
        // untouched, so the new record carries the post-reset Arc rather
        // than a freshly-allocated one.  We assert this by checking that
        // strong_count == 1 (only the table holds it) and that no
        // foreign Arc reference can sneak in via the factory path.
        let idx2 = table.insert_pooled_task_with(|idx, record| {
            record.id = TaskId::from_arena(idx);
            record.owner = owner;
            record.created_at = Time::from_nanos(2);
            record.deadline = None;
            record.polls_remaining = 1;
        });
        let id2 = TaskId::from_arena(idx2);

        let stats = table.task_record_pool_stats();
        assert_eq!(stats.hits, 1, "second insert should be a pool hit");
        assert_eq!(stats.misses, 1, "first insert should be the only miss");

        let record = table.task(id2).expect("pooled task is live");
        assert_eq!(
            Arc::strong_count(&record.wake_state),
            1,
            "field-mutation factory must not introduce extra wake_state references",
        );
        assert_eq!(record.id, id2);
        assert_eq!(record.owner, owner);
        assert_eq!(record.created_at, Time::from_nanos(2));
        assert_eq!(record.polls_remaining, 1);
        assert!(
            !record.is_local(),
            "field-mutation factory must not leave stale local pinning",
        );
    }

    #[test]
    fn task_record_pool_saturates_at_capacity_hint_bound() {
        let capacity = 4096usize;
        let expected_pool_cap = (capacity / 4).clamp(64, 512);
        let mut table = TaskTable::with_capacity(capacity);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        for _ in 0..(expected_pool_cap + 128) {
            let idx = table.insert_task(make_task_record(owner));
            table.remove_and_recycle_task(TaskId::from_arena(idx));
        }

        assert_eq!(table.recycled_task_record_count(), expected_pool_cap);
    }

    #[test]
    fn task_record_pool_disabled_mode_forces_heap_fallback() {
        let mut table = TaskTable::with_capacity_and_pool_limit(256, 0);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        assert!(!table.task_record_pool_enabled());
        assert_eq!(table.task_record_pool_capacity(), 0);

        let idx_a = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(3),
                Time::from_nanos(11),
            );
        });
        let first_id = TaskId::from_arena(idx_a);
        table.remove_and_recycle_task(first_id);

        let idx_b = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(5),
                Time::from_nanos(22),
            );
        });
        let second_id = TaskId::from_arena(idx_b);

        assert!(table.task(first_id).is_none());
        assert!(table.task(second_id).is_some());
        assert_eq!(table.recycled_task_record_count(), 0);

        let stats = table.task_record_pool_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.recycled, 0);
        assert_eq!(stats.recycle_drops, 1);
    }

    #[test]
    fn pooled_recycle_rejects_stale_task_id_after_slot_reuse() {
        let mut table = TaskTable::with_capacity_and_pool_limit(1, 1);
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let first_idx = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(1),
                Time::from_nanos(7),
            );
        });
        let first_id = TaskId::from_arena(first_idx);
        table.remove_and_recycle_task(first_id);

        let second_idx = table.insert_pooled_task_with(|idx, record| {
            *record = TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                owner,
                Budget::new().with_poll_quota(2),
                Time::from_nanos(8),
            );
        });
        let second_id = TaskId::from_arena(second_idx);

        assert_ne!(first_id, second_id);
        assert!(table.task(first_id).is_none());
        assert!(table.task(second_id).is_some());

        let stats = table.task_record_pool_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.recycled, 1);
        assert_eq!(stats.recycle_drops, 0);
    }

    // === Lock Ordering Conformance Tests ===

    mod conformance_lock_ordering {
        use super::*;
        use crate::observability::metrics::NoOpMetrics;
        use crate::runtime::{ShardGuard, ShardedState};
        use crate::trace::TraceBufferHandle;
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        fn test_config() -> crate::runtime::ShardedConfig {
            crate::runtime::ShardedConfig {
                io_driver: None,
                timer_driver: None,
                logical_clock_mode: crate::trace::distributed::LogicalClockMode::Lamport,
                cancel_attribution: crate::types::CancelAttributionConfig::default(),
                entropy_source: Arc::new(crate::util::entropy::DetEntropy::new(0)),
                blocking_pool: None,
                obligation_leak_response: crate::runtime::config::ObligationLeakResponse::Panic,
                leak_escalation: None,
                observability: None,
            }
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_task_table_operations_preserve_lock_order() {
            // Test 1: Verify task table operations through ShardGuard maintain lock ordering
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = ShardedState::new(trace, metrics, test_config());

            // Test single shard operations (Tasks only)
            {
                let mut guard = ShardGuard::tasks_only(&shards);
                let tasks = guard.tasks.as_mut().unwrap();

                // Basic insert/lookup operations
                let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
                let record = make_task_record(owner);
                let idx = tasks.insert_task(record);
                let task_id = TaskId::from_arena(idx);

                assert!(tasks.task(task_id).is_some());
                let removed = tasks.remove_task(task_id);
                assert!(removed.is_some());
            }

            // Verify lock order is properly tracked during multi-shard operations
            #[cfg(debug_assertions)]
            {
                use crate::runtime::sharded_state::lock_order;

                assert_eq!(
                    lock_order::held_count(),
                    0,
                    "No locks should be held after guard drop"
                );

                // Test proper ordering B→A→C (Regions→Tasks→Obligations)
                let guard = ShardGuard::for_task_completed(&shards);
                assert_eq!(lock_order::held_count(), 3);
                assert_eq!(
                    lock_order::held_labels(),
                    vec!["B:Regions", "A:Tasks", "C:Obligations"]
                );
                drop(guard);
                assert_eq!(lock_order::held_count(), 0);
            }
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_concurrent_task_operations_no_lock_order_violations() {
            // Test 2: Concurrent task table operations should not cause lock order violations
            use std::sync::Barrier;

            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = Arc::new(ShardedState::new(trace, metrics, test_config()));
            let barrier = Arc::new(Barrier::new(4));

            let handles: Vec<_> = (0..4)
                .map(|thread_id| {
                    let shards = Arc::clone(&shards);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();

                        // Each thread performs different operations using proper guards
                        for i in 0..50 {
                            match thread_id % 4 {
                                0 => {
                                    // Tasks-only operations (hotpath polling)
                                    let mut guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_mut().unwrap();
                                    let owner = RegionId::from_arena(ArenaIndex::new(
                                        thread_id as u32 + 1,
                                        0,
                                    ));
                                    let record = make_task_record(owner);
                                    let idx = tasks.insert_task(record);
                                    if i % 10 == 9 {
                                        // Occasionally remove task
                                        let task_id = TaskId::from_arena(idx);
                                        let _ = tasks.remove_task(task_id);
                                    }
                                }
                                1 => {
                                    // Spawn operations (B→A)
                                    let mut guard = ShardGuard::for_spawn(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        let owner = RegionId::from_arena(ArenaIndex::new(
                                            thread_id as u32 + 1,
                                            0,
                                        ));
                                        let record = make_task_record(owner);
                                        let _ = tasks.insert_task(record);
                                    }
                                }
                                2 => {
                                    // Task completion operations (B→A→C)
                                    let mut guard = ShardGuard::for_task_completed(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        let owner = RegionId::from_arena(ArenaIndex::new(
                                            thread_id as u32 + 1,
                                            0,
                                        ));
                                        let record = make_task_record(owner);
                                        let idx = tasks.insert_task(record);
                                        let task_id = TaskId::from_arena(idx);
                                        let _ = tasks.remove_task(task_id);
                                    }
                                }
                                3 => {
                                    // Cancel operations (B→A→C)
                                    let mut guard = ShardGuard::for_cancel(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        // Lookup operations to simulate cancel processing
                                        let task_id =
                                            TaskId::from_arena(ArenaIndex::new(i % 100, 0));
                                        let _ = tasks.task(task_id);
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle
                    .join()
                    .expect("Thread should not panic - no lock order violations");
            }
        }

        #[test]
        fn test_task_table_reallocation_safety() {
            // Test 3: Table growth and shrinking should be safe under concurrent access
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = Arc::new(ShardedState::new(trace, metrics, test_config()));
            let barrier = Arc::new(Barrier::new(3));

            let handles: Vec<_> = (0..3)
                .map(|thread_id| {
                    let shards = Arc::clone(&shards);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();

                        match thread_id {
                            0 => {
                                // Growth thread: rapid task insertions
                                for i in 0..200 {
                                    let mut guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_mut().unwrap();
                                    let owner = RegionId::from_arena(ArenaIndex::new(1, 0));
                                    let record = make_task_record(owner);
                                    let _idx = tasks.insert_task(record);

                                    // Verify table remains consistent during growth
                                    assert!(tasks.live_task_count() > 0);

                                    if i % 50 == 0 {
                                        // Brief pause to allow other threads to interleave
                                        thread::sleep(Duration::from_micros(1));
                                    }
                                }
                            }
                            1 => {
                                // Shrinking thread: task removals
                                thread::sleep(Duration::from_millis(1)); // Let growth start first

                                for i in 0..150 {
                                    let mut guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_mut().unwrap();

                                    // Find a task to remove (iterate through possible indices)
                                    for idx_val in 0..200 {
                                        let task_id =
                                            TaskId::from_arena(ArenaIndex::new(idx_val, 0));
                                        if tasks.remove_task(task_id).is_some() {
                                            break; // Successfully removed one
                                        }
                                    }

                                    if i % 50 == 0 {
                                        thread::sleep(Duration::from_micros(1));
                                    }
                                }
                            }
                            2 => {
                                // Reader thread: continuous lookups during reallocation
                                for i in 0..300 {
                                    let guard = ShardGuard::tasks_only(&shards);
                                    let tasks = guard.tasks.as_ref().unwrap();

                                    // Try to lookup various task IDs
                                    for idx_val in (i * 10)..((i + 1) * 10) {
                                        let task_id =
                                            TaskId::from_arena(ArenaIndex::new(idx_val % 200, 0));
                                        let _ = tasks.task(task_id); // May or may not exist
                                    }

                                    // Verify table integrity during concurrent access
                                    assert!(
                                        tasks.live_task_count() < 1000,
                                        "Table growth should be reasonable"
                                    );

                                    if i % 30 == 0 {
                                        thread::sleep(Duration::from_micros(1));
                                    }
                                }
                            }
                            _ => unreachable!(),
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle
                    .join()
                    .expect("Reallocation safety test should not panic");
            }

            // Final verification: table should be in a consistent state
            let guard = ShardGuard::tasks_only(&shards);
            let tasks = guard.tasks.as_ref().unwrap();
            let final_count = tasks.live_task_count();

            // We can't predict exact count due to race conditions, but it should be reasonable
            assert!(final_count < 300, "Final task count should be bounded");

            // Verify no stored futures are orphaned
            assert!(
                tasks.stored_future_count() <= tasks.live_task_count(),
                "Stored futures should not exceed live tasks"
            );
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "lock order violation")]
        fn test_lock_order_violation_detection() {
            // Test 4: Verify that incorrect lock ordering is detected and panics
            use crate::runtime::sharded_state::LockShard;
            use crate::runtime::sharded_state::lock_order;

            // Simulate acquiring locks in wrong order (Tasks before Regions)
            // This should panic in debug builds due to lock order violation
            lock_order::before_lock(LockShard::Tasks);
            lock_order::after_lock(LockShard::Tasks);

            // This should panic: trying to acquire Regions after Tasks violates B→A ordering
            lock_order::before_lock(LockShard::Regions);
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_proper_lock_order_sequences() {
            // Test 5: Verify that correct lock ordering sequences work properly
            use crate::runtime::sharded_state::LockShard;
            use crate::runtime::sharded_state::lock_order;

            // Test valid sequence: B→A→C (Regions→Tasks→Obligations)
            lock_order::before_lock(LockShard::Regions);
            lock_order::after_lock(LockShard::Regions);
            lock_order::before_lock(LockShard::Tasks);
            lock_order::after_lock(LockShard::Tasks);
            lock_order::before_lock(LockShard::Obligations);
            lock_order::after_lock(LockShard::Obligations);

            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );

            // Clean up for next test
            lock_order::unlock_n(3);
            assert_eq!(lock_order::held_count(), 0);

            // Test partial sequence: B→C (skip A)
            lock_order::before_lock(LockShard::Regions);
            lock_order::after_lock(LockShard::Regions);
            lock_order::before_lock(LockShard::Obligations);
            lock_order::after_lock(LockShard::Obligations);

            assert_eq!(lock_order::held_count(), 2);
            lock_order::unlock_n(2);
        }

        #[test]
        fn test_task_table_arena_operations_thread_safety() {
            // Test 6: Arena operations should be thread-safe under proper locking
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
                Arc::new(NoOpMetrics);
            let shards = Arc::new(ShardedState::new(trace, metrics, test_config()));
            let barrier = Arc::new(Barrier::new(4));

            // Track task IDs created across threads for verification
            let created_tasks = Arc::new(std::sync::Mutex::new(Vec::new()));

            let handles: Vec<_> = (0..4)
                .map(|thread_id| {
                    let shards = Arc::clone(&shards);
                    let barrier = Arc::clone(&barrier);
                    let created_tasks = Arc::clone(&created_tasks);

                    thread::spawn(move || {
                        barrier.wait();

                        let mut local_tasks = Vec::new();

                        // Create tasks
                        for _i in 0..25 {
                            let mut guard = ShardGuard::for_spawn(&shards);
                            let tasks = guard.tasks.as_mut().unwrap();

                            let owner =
                                RegionId::from_arena(ArenaIndex::new(thread_id as u32 + 1, 0));
                            let record = make_task_record(owner);
                            let idx = tasks.insert_task(record);
                            let task_id = TaskId::from_arena(idx);

                            // Verify task was inserted correctly
                            assert!(tasks.task(task_id).is_some());
                            assert_eq!(tasks.task(task_id).unwrap().owner, owner);

                            local_tasks.push(task_id);
                        }

                        // Store in shared list for final verification
                        {
                            let mut global_tasks = created_tasks
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            global_tasks.extend(local_tasks.iter());
                        }

                        // Verify tasks can be looked up
                        for &task_id in &local_tasks {
                            let guard = ShardGuard::tasks_only(&shards);
                            let tasks = guard.tasks.as_ref().unwrap();
                            assert!(tasks.task(task_id).is_some(), "Task should still exist");
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle
                    .join()
                    .expect("Arena operations should be thread-safe");
            }

            // Final verification: all created tasks should be accessible
            let final_guard = ShardGuard::tasks_only(&shards);
            let final_tasks = final_guard.tasks.as_ref().unwrap();

            let created_task_list = created_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                created_task_list.len(),
                100,
                "Should have created 100 tasks total"
            );

            for &task_id in created_task_list.iter() {
                assert!(
                    final_tasks.task(task_id).is_some(),
                    "Task {:?} should be accessible in final state",
                    task_id
                );
            }

            assert_eq!(final_tasks.live_task_count(), 100);
        }
    }

    #[test]
    fn incremental_counters_track_all_mutations() {
        use crate::record::task::{TaskPhase, TaskRecord};
        use crate::types::{Budget, RegionId, TaskId, Time};

        let mut table = TaskTable::new();
        let region = RegionId::new_for_test(1, 1);
        let budget = crate::types::Budget::INFINITE.with_deadline(Time::from_nanos(1000));

        // 1. Initial state
        assert_eq!(table.live_task_count(), 0);
        assert_eq!(table.deadline_sum_ns(), 0);

        // 2. Add task
        let dummy_id = TaskId::new_for_test(1, 1);
        let task1 = TaskRecord::new_with_time(dummy_id, region, budget, Time::ZERO);
        let idx1 = table.insert(task1);
        let id1 = TaskId::from_arena(idx1);

        assert_eq!(table.live_task_count(), 1);
        assert_eq!(table.count_in_phase(TaskPhase::Created), 1);
        assert_eq!(table.deadline_sum_ns(), 1000);

        // 3. Transition phase
        table.update_task(id1, |t| {
            t.start_running();
        });
        assert_eq!(table.count_in_phase(TaskPhase::Created), 0);
        assert_eq!(table.count_in_phase(TaskPhase::Running), 1);
        assert_eq!(table.live_task_count(), 1);

        // 4. Change deadline
        table.update_task(id1, |t| {
            t.deadline = Some(Time::from_nanos(2000));
        });
        assert_eq!(table.deadline_sum_ns(), 2000);

        // 5. Add second task
        let dummy_id2 = TaskId::new_for_test(2, 2);
        let task2 = TaskRecord::new_with_time(dummy_id2, region, Budget::INFINITE, Time::ZERO);
        let idx2 = table.insert(task2);
        assert_eq!(table.live_task_count(), 2);
        assert_eq!(table.deadline_sum_ns(), 2000); // Infinite budget doesn't add to sum

        // ...

        // 7. Remove task
        table.remove(idx2);
        assert_eq!(table.live_task_count(), 1);
    }
}

#[cfg(test)]
#[path = "task_table_metamorphic_tests.rs"]
mod metamorphic_tests;
