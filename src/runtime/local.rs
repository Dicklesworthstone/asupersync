//! Thread-local storage for non-Send tasks.
//!
//! This module provides the backing storage for `spawn_local`, allowing
//! tasks to be pinned to a specific worker thread and access `!Send` data.

use crate::runtime::stored_task::LocalStoredTask;
use crate::types::TaskId;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    /// Local tasks stored on the current thread.
    static LOCAL_TASKS: RefCell<HashMap<TaskId, LocalStoredTask>> = RefCell::new(HashMap::new());
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
            panic!("duplicate local task ID: {:?}", task_id);
        }
    });
}

/// Removes and returns a local task from the current thread's storage.
pub fn remove_local_task(task_id: TaskId) -> Option<LocalStoredTask> {
    LOCAL_TASKS.with(|tasks| tasks.borrow_mut().remove(&task_id))
}

/// Returns the number of local tasks on this thread.
pub fn local_task_count() -> usize {
    LOCAL_TASKS.with(|tasks| tasks.borrow().len())
}
