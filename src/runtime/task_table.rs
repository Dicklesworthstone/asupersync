//! Task table for hot-path task operations.
//!
//! Encapsulates task arena and stored futures to enable finer-grained locking.
//! Part of the sharding refactor (bd-2ijqf) to reduce RuntimeState contention.

use crate::record::task::{TaskPhase, TaskRecord};
use crate::runtime::stored_task::StoredTask;
use crate::types::TaskId;
use crate::util::{Arena, ArenaIndex, RecyclingPool};
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Number of task phases that are considered "live" (not Completed).
const LIVE_PHASE_COUNT: usize = 5;

/// Debug builds compare the live count with an arena scan on every read of a
/// table this small...
#[cfg(debug_assertions)]
const LIVE_COUNT_CHECK_ALWAYS_UP_TO: usize = 64;

/// ...and on every this-many reads of a larger one, so that the check does
/// not make a run quadratic in its task count again.
#[cfg(debug_assertions)]
const LIVE_COUNT_CHECK_INTERVAL: usize = 4096;

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
    /// updates. Read-side access uses `phase_tracker` instead, which direct
    /// legacy `TaskRecord` phase mutations cannot drift.
    #[allow(dead_code)]
    live_task_count: usize,
    /// Records in the arena whose phase is not terminal. Each record's
    /// `TaskPhaseCell` holds this tracker while the record is in the table and
    /// adjusts it on every phase store, so `live_task_count` and `count_in_phase`
    /// are O(1) and exact on every mutation path (br-asupersync-bzict6).
    phase_tracker: Arc<crate::record::task::TaskPhaseTracker>,
    /// Reads of `live_task_count`, for the sampled debug cross-check.
    #[cfg(debug_assertions)]
    live_count_reads: std::sync::atomic::AtomicUsize,
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
            phase_tracker: Arc::new(crate::record::task::TaskPhaseTracker::default()),
            #[cfg(debug_assertions)]
            live_count_reads: std::sync::atomic::AtomicUsize::new(0),
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
            phase_tracker: Arc::new(crate::record::task::TaskPhaseTracker::default()),
            #[cfg(debug_assertions)]
            live_count_reads: std::sync::atomic::AtomicUsize::new(0),
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
        // The deadline sum tracks LIVE tasks only (matching `note_deadline_changed`,
        // which subtracts on the live→terminal transition). Gate the deadline
        // branch on liveness so it stays symmetric with `note_task_removed` — a
        // task added directly in a terminal phase contributes no live deadline
        // pressure and must not be counted.
        if idx < LIVE_PHASE_COUNT {
            if let Some(d) = deadline {
                self.deadline_sum_ns = self
                    .deadline_sum_ns
                    .saturating_add(u128::from(d.as_nanos()));
                self.tasks_with_deadline += 1;
            }
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
        // Subtract the deadline ONLY if the task is still live at removal. A task
        // that already transitioned to a terminal phase had its deadline removed
        // from the sum by `note_deadline_changed(Some(D), None)` in `update_task`
        // (which leaves `record.deadline == Some(D)`); subtracting again here on
        // the terminal-phase `remove` double-counts, driving `tasks_with_deadline`
        // and `deadline_sum_ns` toward zero while other live tasks still hold
        // deadlines — corrupting the governor's deadline-pressure signal.
        if idx < LIVE_PHASE_COUNT {
            if let Some(d) = deadline {
                self.deadline_sum_ns = self
                    .deadline_sum_ns
                    .saturating_sub(u128::from(d.as_nanos()));
                self.tasks_with_deadline = self.tasks_with_deadline.saturating_sub(1);
            }
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
            let count = self.phase_tracker.phase_counts[idx].load(Ordering::Acquire);
            #[cfg(debug_assertions)]
            self.debug_check_phase_count(phase, count);
            count
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
        self.count_live(idx);
        idx
    }

    /// Makes the record at `idx` count toward `live_task_count` while it
    /// stays in the table.
    #[inline]
    fn count_live(&mut self, idx: ArenaIndex) {
        let tracker = Arc::clone(&self.phase_tracker);
        if let Some(record) = self.tasks.get_mut(idx) {
            record.phase.attach_phase_tracker(tracker);
        }
    }

    /// Removes a task record by arena index.
    #[inline]
    pub fn remove(&mut self, index: ArenaIndex) -> Option<TaskRecord> {
        let mut record = self.tasks.remove(index)?;
        record.phase.detach_phase_tracker();
        if let Some(cx) = &record.cx {
            cx.revoke_obligation_admission();
        }
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
        self.count_live(idx);
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
        self.count_live(idx);
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
    ///
    /// O(1). A scan of the arena made this O(tasks) and every lab step with
    /// it, because `RuntimeState::is_quiescent` reads it (br-asupersync-bzict6).
    #[must_use]
    #[inline]
    pub fn live_task_count(&self) -> usize {
        let count = self.phase_tracker.live_count.load(Ordering::Acquire);
        #[cfg(debug_assertions)]
        self.debug_check_live_count(count);
        count
    }

    /// Debug builds: the counted live tasks must equal an arena scan.
    #[cfg(debug_assertions)]
    fn debug_check_live_count(&self, count: usize) {
        let reads = self.live_count_reads.fetch_add(1, Ordering::Relaxed);
        if self.tasks.len() <= LIVE_COUNT_CHECK_ALWAYS_UP_TO
            || reads.is_multiple_of(LIVE_COUNT_CHECK_INTERVAL)
        {
            let scanned = self
                .tasks
                .iter()
                .filter(|(_, record)| (record.phase.load() as usize) < LIVE_PHASE_COUNT)
                .count();
            debug_assert_eq!(
                count, scanned,
                "live task count drifted from the task records"
            );
        }
    }

    /// Debug builds: sampled check that the cached phase count matches an arena scan.
    #[cfg(debug_assertions)]
    fn debug_check_phase_count(&self, phase: TaskPhase, count: usize) {
        let reads = self.live_count_reads.fetch_add(1, Ordering::Relaxed);
        if self.tasks.len() <= LIVE_COUNT_CHECK_ALWAYS_UP_TO
            || reads.is_multiple_of(LIVE_COUNT_CHECK_INTERVAL)
        {
            let scanned = self
                .tasks
                .iter()
                .filter(|(_, record)| record.phase.load() == phase)
                .count();
            debug_assert_eq!(
                count, scanned,
                "phase {phase:?} count drifted from the task records"
            );
        }
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

impl Drop for TaskTable {
    fn drop(&mut self) {
        // The table is the final owner of admitted tasks, including in the lab.
        // Native teardown detaches it after worker joins, outside state/shard
        // locks. Keep barriers alive while destroying futures and records;
        // opening them sooner would expose completion before retirement.
        fn isolate(cleanup: impl FnOnce()) {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)) {
                // An arbitrary panic payload may itself panic on destruction.
                std::mem::forget(payload);
            }
        }

        let mut barriers = Vec::new();
        for (_, record) in self.tasks.iter_mut() {
            if let Some(barrier) = record
                .cx_inner
                .as_ref()
                .and_then(|inner| inner.read().retirement_barrier.clone())
            {
                barriers.push(barrier);
            }
            isolate(|| {
                let (_, wakes) = record
                    .request_cancel(crate::types::CancelReason::shutdown())
                    .into_parts();
                // Workers have stopped; retire registrations without enqueueing
                // more work or delivering cancellation observers during Drop.
                wakes.retire_without_dispatch();
            });
        }
        for slot in &mut self.stored_futures {
            if let Some(stored) = slot.take() {
                isolate(|| drop(stored));
            }
        }
        self.stored_future_len = 0;
        for mut record in self.tasks.drain_values() {
            isolate(|| {
                record.complete(crate::types::Outcome::Cancelled(
                    crate::types::CancelReason::shutdown(),
                ));
                drop(record);
            });
        }
        for barrier in barriers {
            // One hostile consumer must not strand the remaining consumers.
            isolate(|| barrier.open_after_shutdown());
        }
    }
}

impl Default for TaskTable {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "task_table_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "task_table_metamorphic_tests.rs"]
mod metamorphic_tests;
