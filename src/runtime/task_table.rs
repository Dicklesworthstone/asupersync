//! Task table for hot-path task operations.
//!
//! Encapsulates task arena and stored futures to enable finer-grained locking.
//! Part of the sharding refactor (bd-2ijqf) to reduce RuntimeState contention.

use crate::record::TaskRecord;
use crate::runtime::stored_task::StoredTask;
use crate::types::TaskId;
use crate::util::{Arena, ArenaIndex};
use std::collections::HashMap;

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
    /// Stored futures for polling.
    ///
    /// Maps task IDs to their pollable futures. When a task is created via
    /// `spawn()`, its wrapped future is stored here for the executor to poll.
    pub(crate) stored_futures: HashMap<TaskId, StoredTask>,
}

impl TaskTable {
    /// Creates a new empty task table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tasks: Arena::new(),
            stored_futures: HashMap::new(),
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
        // Use slot-derived TaskId so cleanup stays correct even if record.id
        // was stale/placeholder at insertion time.
        self.stored_futures.remove(&TaskId::from_arena(index));
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
        self.tasks.insert_with(f)
    }

    /// Removes a task record from the arena.
    ///
    /// Returns the removed record if it existed.
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<TaskRecord> {
        let record = self.tasks.remove(task_id.arena_index())?;
        self.stored_futures.remove(&task_id);
        Some(record)
    }

    /// Stores a spawned task's future for later polling.
    pub fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask) {
        self.stored_futures.insert(task_id, stored);
    }

    /// Returns a mutable reference to a stored future.
    pub fn get_stored_future(&mut self, task_id: TaskId) -> Option<&mut StoredTask> {
        self.stored_futures.get_mut(&task_id)
    }

    /// Removes and returns a stored future for polling.
    ///
    /// This is the hot-path operation called at the start of each poll cycle.
    pub fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        self.stored_futures.remove(&task_id)
    }

    /// Returns the number of live tasks (tasks in the arena).
    #[must_use]
    pub fn live_task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Returns the number of stored futures.
    #[must_use]
    pub fn stored_future_count(&self) -> usize {
        self.stored_futures.len()
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
}
