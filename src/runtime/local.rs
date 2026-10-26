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

impl Drop for LocalTaskStore {
    fn drop(&mut self) {
        // A current-thread runtime can outlive the thread that last drove it.
        // Destroy !Send futures here, on their owner thread, then let a live
        // worker retire their records and obligations. Never lock runtime
        // state or read Cx/TLS from this TLS destructor (asupersync-kopidb L3).
        for slot in &mut self.slots {
            let Some(mut task) = slot.take() else {
                continue;
            };
            let task_id = task.task_id();
            let gateway = task.take_retirement_gateway();
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(task)))
                .err()
                .map(|payload| {
                    let message = crate::cx::scope::payload_to_string(&payload);
                    // An opaque panic payload may itself panic when dropped.
                    // One hostile destructor must not strand the other slots.
                    std::mem::forget(payload);
                    crate::types::PanicPayload::new(message)
                });
            if let (Some(task_id), Some(gateway)) =
                (task_id, gateway.and_then(|gateway| gateway.upgrade()))
            {
                gateway.enqueue_local_task_retirement(
                    crate::runtime::spawn_mailbox::LocalTaskRetirement { task_id, panic },
                );
            }
        }
        self.len = 0;
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
    let outcome = KEYED_LOCAL_TASKS.with(|stores| {
        let mut stores = stores.borrow_mut();
        let index = match stores.iter().position(|(stored_key, _)| *stored_key == key) {
            Some(index) => index,
            None if is_retired_local_store_key(key) => return Err(f),
            None => {
                stores.push((key, LocalTaskStore::new()));
                stores.len() - 1
            }
        };
        Ok(f(&mut stores[index].1))
    });
    match outcome {
        Ok(result) => result,
        Err(f) => {
            // The runtime behind this key was retired after the purge above:
            // never revive its store, which no later purge would drop. Work on
            // a throwaway store; whatever it holds drops here, outside every
            // store borrow.
            let mut retired = LocalTaskStore::new();
            let result = f(&mut retired);
            drop(retired);
            result
        }
    }
}

fn is_retired_local_store_key(key: usize) -> bool {
    RETIRED_LOCAL_STORE_KEYS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(key)
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
#[path = "local_inline_tests.rs"]
mod tests;
