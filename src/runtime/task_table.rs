//! Task table for hot-path task operations.
//!
//! Encapsulates task arena and stored futures to enable finer-grained locking.
//! Part of the sharding refactor (bd-2ijqf) to reduce RuntimeState contention.

use crate::record::TaskRecord;
use crate::runtime::stored_task::StoredTask;
use crate::types::TaskId;
use crate::util::{Arena, ArenaIndex};

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
}

impl TaskTable {
    /// Creates a new empty task table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tasks: Arena::new(),
            stored_futures: Vec::new(),
            stored_future_len: 0,
        }
    }

    /// Returns a reference to a task record by arena index.
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

    /// Inserts a task record into the arena (arena-index based).
    pub fn insert(&mut self, mut record: TaskRecord) -> ArenaIndex {
        self.tasks.insert_with(|idx| {
            // Canonicalize record.id to its arena slot to keep table invariants intact.
            record.id = TaskId::from_arena(idx);
            record
        })
    }

    /// Removes a task record by arena index.
    pub fn remove(&mut self, index: ArenaIndex) -> Option<TaskRecord> {
        let record = self.tasks.remove(index)?;
        let slot = index.index() as usize;
        if slot < self.stored_futures.len() && self.stored_futures[slot].take().is_some() {
            self.stored_future_len -= 1;
        }
        Some(record)
    }

    /// Returns an iterator over task records.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &TaskRecord)> {
        self.tasks.iter()
    }

    /// Returns the number of task records in the arena.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns `true` if the task arena is empty.
    #[must_use]
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
    pub fn insert_task(&mut self, record: TaskRecord) -> ArenaIndex {
        self.insert(record)
    }

    /// Inserts a new task record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    pub fn insert_task_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> TaskRecord,
    {
        self.tasks.insert_with(|idx| {
            let mut record = f(idx);
            // Preserve TaskTable invariant: record.id must match arena slot.
            record.id = TaskId::from_arena(idx);
            record
        })
    }

    /// Removes a task record from the arena.
    ///
    /// Returns the removed record if it existed.
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<TaskRecord> {
        let record = self.tasks.remove(task_id.arena_index())?;
        let slot = task_id.arena_index().index() as usize;
        if slot < self.stored_futures.len() && self.stored_futures[slot].take().is_some() {
            self.stored_future_len -= 1;
        }
        Some(record)
    }

    /// Stores a spawned task's future for later polling.
    pub fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask) {
        let slot = task_id.arena_index().index() as usize;
        if slot >= self.stored_futures.len() {
            self.stored_futures.resize_with(slot + 1, || None);
        }
        if self.stored_futures[slot].replace(stored).is_none() {
            self.stored_future_len += 1;
        }
    }

    /// Returns a mutable reference to a stored future.
    pub fn get_stored_future(&mut self, task_id: TaskId) -> Option<&mut StoredTask> {
        let slot = task_id.arena_index().index() as usize;
        self.stored_futures.get_mut(slot)?.as_mut()
    }

    /// Removes and returns a stored future for polling.
    ///
    /// This is the hot-path operation called at the start of each poll cycle.
    #[inline]
    pub fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        let slot = task_id.arena_index().index() as usize;
        let taken = self.stored_futures.get_mut(slot)?.take();
        if taken.is_some() {
            self.stored_future_len -= 1;
        }
        taken
    }

    /// Returns the number of live tasks (tasks in the arena).
    #[must_use]
    pub fn live_task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Returns the number of stored futures.
    #[must_use]
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
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, RegionId};

    fn make_task_record(owner: RegionId) -> TaskRecord {
        // Use placeholder TaskId (0,0) - will be updated after insertion
        let placeholder = TaskId::from_arena(ArenaIndex::new(0, 0));
        TaskRecord::new(placeholder, owner, Budget::INFINITE)
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

        // Model a caller inserting a placeholder/stale id.
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
            // Intentionally stale placeholder to verify table-side canonicalization.
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
}
