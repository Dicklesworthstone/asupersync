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
        let slot_ref = &mut self.slots[slot];
        if let Some(existing) = slot_ref.as_ref() {
            let existing_id = existing.task_id();
            assert!(
                existing_id == Some(task_id),
                "local task slot reuse conflict: slot {slot} holds {existing_id:?}, cannot insert {task_id:?}",
            );
        }
        let prev = slot_ref.replace(task);
        if prev.is_none() {
            self.len += 1;
        }
        prev
    }

    fn remove(&mut self, task_id: TaskId) -> Option<LocalStoredTask> {
        let slot = task_id.arena_index().index() as usize;
        let slot_ref = self.slots.get_mut(slot)?;
        if slot_ref.as_ref()?.task_id() == Some(task_id) {
            let taken = slot_ref.take();
            self.len -= 1;
            taken
        } else {
            None
        }
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
/// If a task with the same ID already exists, it is replaced and a warning is emitted.
/// Reusing the same arena slot with a different generation fails closed.
pub fn store_local_task(task_id: TaskId, mut task: LocalStoredTask) {
    task.set_task_id(task_id);
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
#[inline]
#[must_use]
pub fn remove_local_task(task_id: TaskId) -> Option<LocalStoredTask> {
    LOCAL_TASKS.with(|tasks| tasks.borrow_mut().remove(task_id))
}

/// Returns the number of local tasks on this thread.
#[inline]
#[must_use]
pub fn local_task_count() -> usize {
    LOCAL_TASKS.with(|tasks| tasks.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Outcome;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn duplicate_store_replaces_entry_without_panicking() {
        init_test("duplicate_store_replaces_entry_without_panicking");

        let task_id = TaskId::new_for_test(42_424, 0);
        let _ = remove_local_task(task_id);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));

        assert_eq!(local_task_count(), baseline + 1);
        assert!(remove_local_task(task_id).is_some());
        assert_eq!(local_task_count(), baseline);
    }

    /// Invariant: store + remove cycle leaves count unchanged.
    #[test]
    fn store_remove_cycle() {
        init_test("store_remove_cycle");

        let task_id = TaskId::new_for_test(42_425, 0);
        let _ = remove_local_task(task_id);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        crate::assert_with_log!(
            local_task_count() == baseline + 1,
            "count after store",
            baseline + 1,
            local_task_count()
        );

        let removed = remove_local_task(task_id);
        crate::assert_with_log!(removed.is_some(), "removed exists", true, removed.is_some());
        crate::assert_with_log!(
            local_task_count() == baseline,
            "count after remove",
            baseline,
            local_task_count()
        );
        crate::test_complete!("store_remove_cycle");
    }

    /// Invariant: removing a non-existent task returns None.
    #[test]
    fn remove_nonexistent_returns_none() {
        init_test("remove_nonexistent_returns_none");

        let task_id = TaskId::new_for_test(99_999, 0);
        // Ensure it doesn't exist
        let _ = remove_local_task(task_id);

        let result = remove_local_task(task_id);
        crate::assert_with_log!(
            result.is_none(),
            "nonexistent returns None",
            true,
            result.is_none()
        );
        crate::test_complete!("remove_nonexistent_returns_none");
    }

    #[test]
    fn cross_generation_slot_reuse_panics_and_preserves_existing_task() {
        init_test("cross_generation_slot_reuse_panics_and_preserves_existing_task");

        let task_id = TaskId::new_for_test(42_426, 0);
        let reused_slot = TaskId::new_for_test(42_426, 1);
        let _ = remove_local_task(task_id);
        let _ = remove_local_task(reused_slot);
        let baseline = local_task_count();

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store_local_task(reused_slot, LocalStoredTask::new(async { Outcome::Ok(()) }));
        }));
        let reused_missing = remove_local_task(reused_slot).is_none();
        let original_preserved = remove_local_task(task_id).is_some();

        crate::assert_with_log!(
            panic.is_err(),
            "cross-generation insert panics",
            true,
            panic.is_err()
        );
        crate::assert_with_log!(
            reused_missing,
            "new generation was not inserted",
            true,
            reused_missing
        );
        crate::assert_with_log!(
            original_preserved,
            "original task preserved",
            true,
            original_preserved
        );
        crate::assert_with_log!(
            local_task_count() == baseline,
            "count restored after cleanup",
            baseline,
            local_task_count()
        );
        crate::test_complete!("cross_generation_slot_reuse_panics_and_preserves_existing_task");
    }
}
