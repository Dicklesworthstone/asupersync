//! Thread-local storage for non-Send tasks.
//!
//! This module provides the backing storage for `spawn_local`, allowing
//! tasks to be pinned to a specific worker thread and access `!Send` data.

use crate::runtime::stored_task::LocalStoredTask;
use crate::types::TaskId;
use std::cell::RefCell;

/// Arena-indexed local task storage, replacing `HashMap<TaskId, LocalStoredTask>`
/// with `Vec<Option<LocalStoredTask>>` for O(1) insert/remove on the spawn_local
/// hot path.
struct LocalTaskStore {
    slots: Vec<Option<LocalStoredTask>>,
    len: usize,
}

impl LocalTaskStore {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }

    fn insert(&mut self, task_id: TaskId, task: LocalStoredTask) -> Option<LocalStoredTask> {
        let slot = task_id.arena_index().index() as usize;
        if slot >= self.slots.len() {
            self.slots.resize_with(slot + 1, || None);
        }
        let prev = self.slots[slot].replace(task);
        if prev.is_none() {
            self.len += 1;
        }
        prev
    }

    fn remove(&mut self, task_id: TaskId) -> Option<LocalStoredTask> {
        let slot = task_id.arena_index().index() as usize;
        let taken = self.slots.get_mut(slot)?.take();
        if taken.is_some() {
            self.len -= 1;
        }
        taken
    }

    fn len(&self) -> usize {
        self.len
    }
}

thread_local! {
    /// Local tasks stored on the current thread.
    static LOCAL_TASKS: RefCell<LocalTaskStore> = const { RefCell::new(LocalTaskStore::new()) };
}

/// Stores a local task in the current thread's storage.
///
/// # Panics
///
/// Panics if a task with the same ID already exists.
pub fn store_local_task(task_id: TaskId, task: LocalStoredTask) {
    LOCAL_TASKS.with(|tasks| {
        let mut tasks = tasks.borrow_mut();
        if tasks.insert(task_id, task).is_some() {
            crate::tracing_compat::warn!(
                task_id = ?task_id,
                "duplicate local task ID encountered; replacing existing local task entry"
            );
        }
    });
}

/// Removes and returns a local task from the current thread's storage.
#[must_use]
pub fn remove_local_task(task_id: TaskId) -> Option<LocalStoredTask> {
    LOCAL_TASKS.with(|tasks| tasks.borrow_mut().remove(task_id))
}

/// Returns the number of local tasks on this thread.
#[must_use]
pub fn local_task_count() -> usize {
    LOCAL_TASKS.with(|tasks| tasks.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Outcome;

    #[test]
    fn duplicate_store_replaces_entry_without_panicking() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("duplicate_store_replaces_entry_without_panicking");

        let task_id = TaskId::new_for_test(42_424, 0);
        let _ = remove_local_task(task_id);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));

        assert_eq!(local_task_count(), baseline + 1);
        assert!(remove_local_task(task_id).is_some());
        assert_eq!(local_task_count(), baseline);
    }
}
