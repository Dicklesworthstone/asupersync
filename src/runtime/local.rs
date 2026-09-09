//! Thread-local storage for non-Send tasks.
//!
//! This module provides the backing storage for `spawn_local`, allowing
//! tasks to be pinned to a specific worker thread and access `!Send` data.

use crate::runtime::stored_task::LocalStoredTask;
use crate::types::TaskId;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::marker::PhantomData;

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

/// Next per-runtime local-store key. Keys are process-unique and never
/// reused, so a store left on a thread by a runtime that has since been
/// dropped can never be mistaken for a later runtime's store (a heap address
/// used to serve as the key, and allocator reuse made that aliasing likely;
/// asupersync-1fyc8f).
static NEXT_LOCAL_STORE_KEY: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(1);

/// Inclusive intervals of retired keys. Adjacent retirements coalesce, while
/// gaps preserve keys belonging to live runtimes. Retirement is never forgotten:
/// a thread can remain idle across arbitrarily many later runtime lifetimes.
#[derive(Clone)]
struct RetiredLocalStoreKeys(BTreeMap<usize, usize>);

impl RetiredLocalStoreKeys {
    const fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn contains(&self, key: usize) -> bool {
        self.0
            .range(..=key)
            .next_back()
            .is_some_and(|(_, end)| *end >= key)
    }

    /// Returns whether this is the first retirement of `key`.
    fn insert(&mut self, key: usize) -> bool {
        let mut start = key;
        let mut end = key;
        if let Some((&previous_start, &previous_end)) = self.0.range(..=key).next_back() {
            if previous_end >= key {
                return false;
            }
            if previous_end.checked_add(1) == Some(key) {
                start = previous_start;
                self.0.remove(&previous_start);
            }
        }
        if let Some(next_key) = key.checked_add(1)
            && let Some(next_end) = self.0.remove(&next_key)
        {
            end = next_end;
        }
        self.0.insert(start, end);
        true
    }
}

/// Retirements published to all threads, compressed by contiguous key range.
static RETIRED_LOCAL_STORE_KEYS: std::sync::Mutex<RetiredLocalStoreKeys> =
    std::sync::Mutex::new(RetiredLocalStoreKeys::new());
/// Bumped on every retirement; threads compare it against their last-seen
/// value so the purge check on the store hot path is one atomic load.
static RETIRED_LOCAL_STORE_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Allocates a fresh, process-unique local-store key for a runtime.
#[must_use]
pub(crate) fn allocate_local_store_key() -> usize {
    allocate_local_store_key_from(&NEXT_LOCAL_STORE_KEY)
}

fn allocate_local_store_key_from(next: &std::sync::atomic::AtomicUsize) -> usize {
    use std::sync::atomic::Ordering;

    let mut key = next.load(Ordering::Relaxed);
    loop {
        let successor = key
            .checked_add(1)
            .expect("process-wide local-store key space exhausted");
        match next.compare_exchange_weak(key, successor, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return key,
            Err(observed) => key = observed,
        }
    }
}

/// Marks `key` retired process-wide: every thread drops the store it holds
/// for that key (with the tasks still parked in it) on its next local-store
/// operation. The default store (`key == 0`) is never retired.
pub(crate) fn publish_retired_local_store_key(key: usize) {
    if key == 0 {
        return;
    }
    let mut retired = RETIRED_LOCAL_STORE_KEYS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !retired.insert(key) {
        return;
    }
    drop(retired);
    RETIRED_LOCAL_STORE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Release);
}

/// Drops this thread's stores whose keys were retired since the last check.
/// Task destructors run after the store borrow is released.
fn purge_retired_local_stores() {
    let generation = RETIRED_LOCAL_STORE_GENERATION.load(std::sync::atomic::Ordering::Acquire);
    let seen = SEEN_RETIRED_LOCAL_STORE_GENERATION.with(Cell::get);
    if seen == generation {
        return;
    }
    SEEN_RETIRED_LOCAL_STORE_GENERATION.with(|last| last.set(generation));
    let retired = RETIRED_LOCAL_STORE_KEYS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let dropped = KEYED_LOCAL_TASKS.with(|stores| {
        let mut stores = stores.borrow_mut();
        let mut dropped = Vec::new();
        let mut index = 0;
        while index < stores.len() {
            if retired.contains(stores[index].0) {
                dropped.push(stores.swap_remove(index));
            } else {
                index += 1;
            }
        }
        dropped
    });
    drop(dropped);
}

thread_local! {
    /// Retirement generation this thread has already purged.
    static SEEN_RETIRED_LOCAL_STORE_GENERATION: Cell<u64> = const { Cell::new(0) };
    /// Local tasks stored on the current thread (the default store, selected
    /// while no [`ScopedLocalStoreKey`] is installed).
    static LOCAL_TASKS: RefCell<LocalTaskStore> = const { RefCell::new(LocalTaskStore::new()) };
    /// Per-runtime stores selected by [`ScopedLocalStoreKey`] (GH#58). Task
    /// ids are per-runtime arena indices, so a thread that drives more than
    /// one runtime's worker keeps their `!Send` futures apart.
    static KEYED_LOCAL_TASKS: RefCell<Vec<(usize, LocalTaskStore)>> =
        const { RefCell::new(Vec::new()) };
    /// Store key selected on this thread; `0` is the default store.
    static CURRENT_LOCAL_STORE_KEY: Cell<usize> = const { Cell::new(0) };
}

/// Selects which local-task store this thread operates on.
///
/// Workers install their runtime's key for the guard's lifetime before
/// admitting, polling, or counting local tasks; nested installs restore the
/// previous key on drop. The guard is `!Send`: it restores the key of the
/// thread that created it, so it must be dropped on that thread.
pub(crate) struct ScopedLocalStoreKey {
    prev: usize,
    _thread_affine: PhantomData<*const ()>,
}

impl ScopedLocalStoreKey {
    #[must_use]
    pub(crate) fn new(key: usize) -> Self {
        let prev = CURRENT_LOCAL_STORE_KEY.with(|current| current.replace(key));
        Self {
            prev,
            _thread_affine: PhantomData,
        }
    }
}

/// Drops the current thread's store for `key` together with every task still
/// parked in it (runtime teardown: abort-by-drop of this thread's `!Send`
/// tasks of that runtime). The default store (`key == 0`) is never retired.
pub(crate) fn retire_local_store(key: usize) {
    if key == 0 {
        return;
    }
    // Other threads that drove this runtime purge their copy lazily.
    publish_retired_local_store_key(key);
    let retired = KEYED_LOCAL_TASKS
        .try_with(|stores| {
            let mut stores = stores.borrow_mut();
            stores
                .iter()
                .position(|(stored_key, _)| *stored_key == key)
                .map(|index| stores.swap_remove(index))
        })
        .ok()
        .flatten();
    // Task destructors run after the store borrow is released.
    drop(retired);
}

/// Number of per-runtime local-task stores currently held by this thread.
#[cfg(any(test, feature = "test-internals"))]
#[must_use]
pub fn keyed_local_store_count() -> usize {
    KEYED_LOCAL_TASKS.with(|stores| stores.borrow().len())
}

impl Drop for ScopedLocalStoreKey {
    fn drop(&mut self) {
        let prev = self.prev;
        let _ = CURRENT_LOCAL_STORE_KEY.try_with(|current| current.set(prev));
    }
}

fn with_current_store<R>(f: impl FnOnce(&mut LocalTaskStore) -> R) -> R {
    // Runs before the default-store shortcut on purpose: a thread that left
    // a runtime's keyed store behind (its `block_on` returned with `!Send`
    // tasks parked) usually has no key installed when the runtime is dropped
    // elsewhere, and this is where it learns of the retirement.
    purge_retired_local_stores();
    let key = CURRENT_LOCAL_STORE_KEY.with(Cell::get);
    if key == 0 {
        return LOCAL_TASKS.with(|tasks| f(&mut tasks.borrow_mut()));
    }
    KEYED_LOCAL_TASKS.with(|stores| {
        let mut stores = stores.borrow_mut();
        let index = match stores.iter().position(|(stored_key, _)| *stored_key == key) {
            Some(index) => index,
            None => {
                stores.push((key, LocalTaskStore::new()));
                stores.len() - 1
            }
        };
        f(&mut stores[index].1)
    })
}

/// Stores a local task in the current thread's storage.
///
/// If a task with the same ID already exists, it is replaced and a warning is emitted.
/// Reusing the same arena slot with a different generation fails closed.
#[inline]
pub fn store_local_task(task_id: TaskId, mut task: LocalStoredTask) {
    task.set_task_id(task_id);
    with_current_store(|tasks| {
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
    with_current_store(|tasks| tasks.remove(task_id))
}

/// Returns the number of local tasks on this thread (in the selected store).
#[inline]
#[must_use]
pub fn local_task_count() -> usize {
    with_current_store(|tasks| tasks.len())
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
    use crate::types::Outcome;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn retirement_intervals_preserve_live_gaps_and_merge_out_of_order() {
        let mut retired = RetiredLocalStoreKeys::new();
        for key in [8, 4, 6, 2, 7, 3] {
            assert!(retired.insert(key));
        }
        assert_eq!(retired.0, BTreeMap::from([(2, 4), (6, 8)]));
        for key in [0, 1, 5, 9, usize::MAX] {
            assert!(!retired.contains(key), "live key {key} must survive");
        }
        for key in [2, 3, 4, 6, 7, 8] {
            assert!(retired.contains(key));
            assert!(!retired.insert(key), "duplicate retirement {key}");
        }
        assert!(retired.insert(5));
        assert_eq!(retired.0, BTreeMap::from([(2, 8)]));
        assert!(retired.insert(usize::MAX));
        assert!(retired.insert(usize::MAX - 1));
        assert!(!retired.insert(usize::MAX));
        assert!(retired.contains(usize::MAX));
        assert!(!retired.contains(usize::MAX - 2));
        assert_eq!(
            retired.0,
            BTreeMap::from([(2, 8), (usize::MAX - 1, usize::MAX)])
        );
    }

    #[test]
    fn retirement_history_survives_more_than_the_old_key_cap() {
        let mut retired = RetiredLocalStoreKeys::new();
        assert!(retired.insert(2));
        for key in 4..=10_000 {
            assert!(retired.insert(key));
        }
        assert!(retired.contains(2), "the oldest retirement must survive");
        assert!(!retired.contains(1), "an older live runtime must survive");
        assert!(
            !retired.contains(3),
            "a live runtime between ranges survives"
        );
        assert_eq!(retired.0, BTreeMap::from([(2, 2), (4, 10_000)]));
    }

    #[test]
    fn local_store_key_exhaustion_never_wraps_or_reuses_a_key() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let next = AtomicUsize::new(usize::MAX - 1);
        assert_eq!(allocate_local_store_key_from(&next), usize::MAX - 1);
        for _ in 0..2 {
            let exhausted = std::panic::catch_unwind(|| allocate_local_store_key_from(&next));
            assert!(exhausted.is_err(), "exhaustion must fail closed each time");
            assert_eq!(next.load(Ordering::Relaxed), usize::MAX);
        }
    }

    /// asupersync-1fyc8f: keys are process-unique and never reused.
    #[test]
    fn allocated_local_store_keys_are_unique_and_never_zero() {
        init_test("allocated_local_store_keys_are_unique_and_never_zero");
        let first = allocate_local_store_key();
        let second = allocate_local_store_key();
        assert_ne!(first, 0, "zero is the default store");
        assert!(
            second > first,
            "keys grow monotonically: {first} then {second}"
        );
        let from_other_thread = std::thread::spawn(allocate_local_store_key)
            .join()
            .expect("allocator thread");
        assert!(from_other_thread > second, "one process-wide sequence");
    }

    /// asupersync-1fyc8f: a retirement published by any thread drops the
    /// store (and the tasks parked in it) on every thread's next local-store
    /// operation, including threads that currently use the default store.
    #[test]
    fn retired_store_is_purged_on_next_touch_from_any_thread() {
        init_test("retired_store_is_purged_on_next_touch_from_any_thread");
        let key = allocate_local_store_key();
        let task_id = TaskId::new_for_test(42_777, 0);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel::<&'static str>();
        struct DropSignal(std::sync::mpsc::Sender<&'static str>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                let _ = self.0.send("parked task dropped");
            }
        }

        let (stored_tx, stored_rx) = std::sync::mpsc::channel::<usize>();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel::<()>();
        let (after_tx, after_rx) = std::sync::mpsc::channel::<usize>();
        let holder = std::thread::spawn(move || {
            {
                let _key = ScopedLocalStoreKey::new(key);
                let signal = DropSignal(dropped_tx);
                store_local_task(
                    task_id,
                    LocalStoredTask::new(async move {
                        let _signal = signal;
                        std::future::pending::<()>().await;
                        Outcome::Ok(())
                    }),
                );
                stored_tx
                    .send(keyed_local_store_count())
                    .expect("report store count");
            }
            retired_rx.recv().expect("wait for the retirement");
            // Default store selected (no key installed): the touch still
            // observes the retirement.
            let _ = local_task_count();
            after_tx
                .send(keyed_local_store_count())
                .expect("report store count after purge");
        });

        assert_eq!(stored_rx.recv().expect("stored"), 1);
        publish_retired_local_store_key(key);
        retired_tx.send(()).expect("release the holder");
        assert_eq!(after_rx.recv().expect("after"), 0, "retired store purged");
        assert_eq!(
            dropped_rx.recv().expect("drop signal"),
            "parked task dropped",
            "the parked task is dropped with its store"
        );
        holder.join().expect("holder thread");
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
