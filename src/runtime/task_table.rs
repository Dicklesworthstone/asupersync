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
    #[inline]
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
    #[inline]
    pub fn insert(&mut self, mut record: TaskRecord) -> ArenaIndex {
        self.tasks.insert_with(|idx| {
            // Canonicalize record.id to its arena slot to keep table invariants intact.
            record.id = TaskId::from_arena(idx);
            record
        })
    }

    /// Removes a task record by arena index.
    #[inline]
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

    /// Inserts a new task record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    #[inline]
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
    #[inline]
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<TaskRecord> {
        let record = self.tasks.remove(task_id.arena_index())?;
        let slot = task_id.arena_index().index() as usize;
        if slot < self.stored_futures.len() && self.stored_futures[slot].take().is_some() {
            self.stored_future_len -= 1;
        }
        Some(record)
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
        self.stored_futures.get_mut(slot)?.as_mut()
    }

    /// Removes and returns a stored future for polling.
    ///
    /// This is the hot-path operation called at the start of each poll cycle.
    #[inline]
    pub fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        self.tasks.get(task_id.arena_index())?;
        let slot = task_id.arena_index().index() as usize;
        let taken = self.stored_futures.get_mut(slot)?.take();
        if taken.is_some() {
            self.stored_future_len -= 1;
        }
        taken
    }

    /// Returns the number of live tasks (tasks in the arena).
    #[must_use]
    #[inline]
    pub fn live_task_count(&self) -> usize {
        self.tasks.len()
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
    use super::*;
    use crate::types::{Budget, RegionId};

    #[inline]
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

    // === Lock Ordering Conformance Tests ===

    mod conformance_lock_ordering {
        use super::*;
        use crate::runtime::{ShardedState, ShardGuard};
        use crate::observability::metrics::NoOpMetrics;
        use crate::observability::ObservabilityConfig;
        use crate::runtime::config::RuntimeConfig;
        use crate::trace::TraceBufferHandle;
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        fn test_config() -> Arc<crate::runtime::ShardedConfig> {
            Arc::new(crate::runtime::ShardedConfig {
                runtime: RuntimeConfig::default(),
                observability: ObservabilityConfig::default(),
            })
        }

        #[cfg(debug_assertions)]
        #[test]
        fn test_task_table_operations_preserve_lock_order() {
            // Test 1: Verify task table operations through ShardGuard maintain lock ordering
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> = Arc::new(NoOpMetrics);
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

                assert_eq!(lock_order::held_count(), 0, "No locks should be held after guard drop");

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
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> = Arc::new(NoOpMetrics);
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
                                    let owner = RegionId::from_arena(ArenaIndex::new(thread_id as u32 + 1, 0));
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
                                        let owner = RegionId::from_arena(ArenaIndex::new(thread_id as u32 + 1, 0));
                                        let record = make_task_record(owner);
                                        let _ = tasks.insert_task(record);
                                    }
                                }
                                2 => {
                                    // Task completion operations (B→A→C)
                                    let mut guard = ShardGuard::for_task_completed(&shards);
                                    if let Some(tasks) = guard.tasks.as_mut() {
                                        let owner = RegionId::from_arena(ArenaIndex::new(thread_id as u32 + 1, 0));
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
                                        let task_id = TaskId::from_arena(ArenaIndex::new(i % 100, 0));
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
                handle.join().expect("Thread should not panic - no lock order violations");
            }
        }

        #[test]
        fn test_task_table_reallocation_safety() {
            // Test 3: Table growth and shrinking should be safe under concurrent access
            let trace = TraceBufferHandle::new(1024);
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> = Arc::new(NoOpMetrics);
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
                                        let task_id = TaskId::from_arena(ArenaIndex::new(idx_val, 0));
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
                                        let task_id = TaskId::from_arena(ArenaIndex::new(idx_val % 200, 0));
                                        let _ = tasks.task(task_id); // May or may not exist
                                    }

                                    // Verify table integrity during concurrent access
                                    assert!(tasks.live_task_count() < 1000, "Table growth should be reasonable");

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
                handle.join().expect("Reallocation safety test should not panic");
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
            use crate::runtime::sharded_state::lock_order;
            use crate::runtime::sharded_state::LockShard;

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
            use crate::runtime::sharded_state::lock_order;
            use crate::runtime::sharded_state::LockShard;

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
            let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> = Arc::new(NoOpMetrics);
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
                        for i in 0..25 {
                            let mut guard = ShardGuard::for_spawn(&shards);
                            let tasks = guard.tasks.as_mut().unwrap();

                            let owner = RegionId::from_arena(ArenaIndex::new(thread_id as u32 + 1, 0));
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
                            let mut global_tasks = created_tasks.lock().unwrap();
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
                handle.join().expect("Arena operations should be thread-safe");
            }

            // Final verification: all created tasks should be accessible
            let final_guard = ShardGuard::tasks_only(&shards);
            let final_tasks = final_guard.tasks.as_ref().unwrap();

            let created_task_list = created_tasks.lock().unwrap();
            assert_eq!(created_task_list.len(), 100, "Should have created 100 tasks total");

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
}
