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

    #[inline]
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

    #[inline]
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

    #[inline]
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
#[inline]
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

    #[test]
    fn metamorphic_local_task_store_is_thread_affine() {
        init_test("metamorphic_local_task_store_is_thread_affine");

        let task_id = TaskId::new_for_test(42_427, 0);
        let _ = remove_local_task(task_id);
        let main_baseline = local_task_count();
        let (stored_tx, stored_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let thread_baseline = local_task_count();
            let thread_missing_before_store = remove_local_task(task_id).is_none();

            store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));

            stored_tx
                .send((
                    thread_baseline,
                    thread_missing_before_store,
                    local_task_count(),
                ))
                .expect("send thread-local store state");

            release_rx.recv().expect("wait for main thread checks");

            let thread_removed = remove_local_task(task_id).is_some();
            (thread_removed, local_task_count(), thread_baseline)
        });

        let (thread_baseline, thread_missing_before_store, thread_after_store_count) =
            stored_rx.recv().expect("receive thread-local store state");

        crate::assert_with_log!(
            thread_missing_before_store,
            "new worker starts without task",
            true,
            thread_missing_before_store
        );
        crate::assert_with_log!(
            thread_after_store_count == thread_baseline + 1,
            "worker-local count increments independently",
            thread_baseline + 1,
            thread_after_store_count
        );

        let main_missing_while_worker_holds_task = remove_local_task(task_id).is_none();
        crate::assert_with_log!(
            main_missing_while_worker_holds_task,
            "worker-owned task invisible on main thread",
            true,
            main_missing_while_worker_holds_task
        );
        crate::assert_with_log!(
            local_task_count() == main_baseline,
            "main thread count unaffected by worker-local store",
            main_baseline,
            local_task_count()
        );

        store_local_task(task_id, LocalStoredTask::new(async { Outcome::Ok(()) }));
        crate::assert_with_log!(
            local_task_count() == main_baseline + 1,
            "same task id can be stored independently on main thread",
            main_baseline + 1,
            local_task_count()
        );
        let main_removed = remove_local_task(task_id).is_some();
        crate::assert_with_log!(
            main_removed,
            "main thread removes only its own local task",
            true,
            main_removed
        );
        crate::assert_with_log!(
            local_task_count() == main_baseline,
            "main thread count restored after local cleanup",
            main_baseline,
            local_task_count()
        );

        release_tx
            .send(())
            .expect("allow worker thread to clean up local task");
        let (thread_removed, thread_final_count, thread_join_baseline) =
            handle.join().expect("join worker thread");

        crate::assert_with_log!(
            thread_removed,
            "worker removes its own local task",
            true,
            thread_removed
        );
        crate::assert_with_log!(
            thread_final_count == thread_join_baseline,
            "worker-local count restored after cleanup",
            thread_join_baseline,
            thread_final_count
        );
        crate::assert_with_log!(
            local_task_count() == main_baseline,
            "main thread remains restored after worker cleanup",
            main_baseline,
            local_task_count()
        );
        crate::test_complete!("metamorphic_local_task_store_is_thread_affine");
    }
}
