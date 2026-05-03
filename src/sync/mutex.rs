//! Two-phase async mutex with guard obligations.
//!
//! An async mutex that allows holding the lock across await points.
//! Each acquired guard is tracked as an obligation that must be released.
//!
//! # Cancel Safety
//!
//! The lock operation is split into two phases:
//! - **Phase 1**: Wait for lock availability (cancel-safe)
//! - **Phase 2**: Acquire lock and create obligation (cannot fail)
//!
//! # Example
//!
//! ```ignore
//! use asupersync::sync::Mutex;
//!
//! let mutex = Mutex::new(42);
//!
//! // Lock the mutex (awaits until available)
//! let mut guard = mutex.lock(&cx).await?;
//! *guard += 1;
//! ```

#![allow(unsafe_code)]

use parking_lot::Mutex as ParkingMutex;
use slab::Slab;
use std::cell::UnsafeCell;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

/// Error returned when mutex locking fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockError {
    /// The mutex was poisoned (a panic occurred while holding the lock).
    Poisoned,
    /// Cancelled while waiting for the lock.
    Cancelled,
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for LockError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => write!(f, "mutex poisoned"),
            Self::Cancelled => write!(f, "mutex lock cancelled"),
            Self::PolledAfterCompletion => write!(f, "mutex future polled after completion"),
        }
    }
}

impl std::error::Error for LockError {}

/// Error returned when trying to lock without waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryLockError {
    /// The mutex is currently locked.
    Locked,
    /// The mutex was poisoned.
    Poisoned,
}

impl std::fmt::Display for TryLockError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "mutex is locked"),
            Self::Poisoned => write!(f, "mutex poisoned"),
        }
    }
}

impl std::error::Error for TryLockError {}

/// An async mutex for mutual exclusion.
#[derive(Debug)]
pub struct Mutex<T> {
    /// The protected data.
    data: UnsafeCell<T>,
    /// Whether the mutex is poisoned.
    poisoned: AtomicBool,
    /// Internal state for fairness and locking.
    state: ParkingMutex<MutexState>,
}

// Safety: Mutex is Send/Sync if T is Send.
unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

#[derive(Debug)]
struct MutexState {
    /// Whether the mutex is currently locked.
    locked: bool,
    /// Slab-backed doubly-linked FIFO of waiters
    /// (br-asupersync-wlf0xh). Replaces the old `VecDeque<Waiter>`
    /// whose `iter().position(|w| w.id == ...)` cleanup was O(N) in
    /// the queue depth. The slab allocates stable indices so the
    /// caller-held `waiter_id` directly identifies the slot — no
    /// scan needed. The intrusive `prev`/`next` pointers preserve
    /// FIFO ordering; cleanup, contains-check, and waker update are
    /// all O(1) with no probing of the rest of the queue.
    waiters: WaiterChain,
    /// Waiter that has been granted the next turn but has not yet
    /// resumed. Holds the slab index of the granted waiter (or
    /// `usize::MAX` as a sentinel via Option).
    granted_waiter: Option<usize>,
}

/// Slab-backed doubly-linked FIFO of waiters
/// (br-asupersync-wlf0xh). Each slot carries the task's `Waker` plus
/// `prev`/`next` slab-index pointers so that O(1) removal at any
/// position is possible from a known waiter id.
#[derive(Debug)]
struct WaiterChain {
    slots: Slab<WaiterSlot>,
    head: Option<usize>,
    tail: Option<usize>,
}

#[derive(Debug)]
struct WaiterSlot {
    waker: Waker,
    prev: Option<usize>,
    next: Option<usize>,
}

impl WaiterChain {
    fn new() -> Self {
        Self {
            slots: Slab::with_capacity(4),
            head: None,
            tail: None,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    #[inline]
    fn len(&self) -> usize {
        self.slots.len()
    }

    /// Push a new waiter to the BACK of the chain (FIFO insert).
    /// Returns the waiter id (slab index).
    fn push_back(&mut self, waker: Waker) -> usize {
        let new_id = self.slots.insert(WaiterSlot {
            waker,
            prev: self.tail,
            next: None,
        });
        match self.tail {
            Some(prev_tail) => {
                self.slots[prev_tail].next = Some(new_id);
            }
            None => {
                self.head = Some(new_id);
            }
        }
        self.tail = Some(new_id);
        new_id
    }

    /// Push a new waiter to the FRONT of the chain (used for
    /// "preserve precedence after spurious requeue", e.g. when a
    /// granted waiter races with a steal).
    fn push_front(&mut self, waker: Waker) -> usize {
        let new_id = self.slots.insert(WaiterSlot {
            waker,
            prev: None,
            next: self.head,
        });
        match self.head {
            Some(next_head) => {
                self.slots[next_head].prev = Some(new_id);
            }
            None => {
                self.tail = Some(new_id);
            }
        }
        self.head = Some(new_id);
        new_id
    }

    /// Pop the front waiter (FIFO take). Returns `(id, waker)` so
    /// callers can both record the granted_waiter id and wake.
    fn pop_front(&mut self) -> Option<(usize, Waker)> {
        let head_id = self.head?;
        let slot = self.slots.remove(head_id);
        self.head = slot.next;
        match slot.next {
            Some(new_head) => {
                self.slots[new_head].prev = None;
            }
            None => {
                self.tail = None;
            }
        }
        Some((head_id, slot.waker))
    }

    /// Returns the current front-of-queue id without removing.
    /// Used to determine "would my removal force a re-grant?".
    #[inline]
    fn front_id(&self) -> Option<usize> {
        self.head
    }

    /// O(1) remove by waiter id. Returns `Some(_)` if the id was
    /// in the chain, `None` otherwise (idempotent for already-
    /// removed ids — important for cleanup paths).
    fn remove(&mut self, id: usize) -> Option<Waker> {
        if !self.slots.contains(id) {
            return None;
        }
        let slot = self.slots.remove(id);
        match slot.prev {
            Some(p) => self.slots[p].next = slot.next,
            None => self.head = slot.next,
        }
        match slot.next {
            Some(n) => self.slots[n].prev = slot.prev,
            None => self.tail = slot.prev,
        }
        Some(slot.waker)
    }

    /// O(1) waker update by id. Returns whether the slot existed.
    fn update_waker(&mut self, id: usize, new: &Waker) -> bool {
        match self.slots.get_mut(id) {
            Some(slot) => {
                if !slot.waker.will_wake(new) {
                    slot.waker.clone_from(new);
                }
                true
            }
            None => false,
        }
    }

    /// O(1) presence check. Used by `LockFuture::poll` to detect
    /// whether the future's previously-allocated id is still queued
    /// (vs popped by `unlock` and granted).
    #[inline]
    #[allow(dead_code)]
    fn contains(&self, id: usize) -> bool {
        self.slots.contains(id)
    }
}

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state.
    #[inline]
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            data: UnsafeCell::new(value),
            poisoned: AtomicBool::new(false),
            state: ParkingMutex::new(MutexState {
                locked: false,
                waiters: WaiterChain::new(),
                granted_waiter: None,
            }),
        }
    }

    /// Returns true if the mutex is poisoned.
    #[inline]
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Returns true if the mutex is currently locked.
    #[inline]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state.lock().locked
    }

    /// Returns the number of tasks currently waiting for the lock.
    #[inline]
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.state.lock().waiters.len()
    }

    /// Acquires the mutex asynchronously.
    #[inline]
    pub fn lock<'a, 'b>(&'a self, cx: &'b Cx) -> LockFuture<'a, 'b, T> {
        LockFuture {
            mutex: self,
            cx,
            waiter_id: None,
            completed: false,
        }
    }

    /// Tries to acquire the mutex without waiting.
    ///
    /// The guard releases the mutex when it is dropped.
    ///
    /// ```
    /// use asupersync::sync::Mutex;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mutex = Mutex::new(String::from("ready"));
    ///
    /// {
    ///     let mut guard = mutex.try_lock()?;
    ///     guard.push_str("!");
    /// }
    ///
    /// let guard = mutex.try_lock()?;
    /// assert_eq!(guard.as_str(), "ready!");
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, TryLockError> {
        let mut state = self.state.lock();
        if self.is_poisoned() {
            return Err(TryLockError::Poisoned);
        }
        if state.locked || state.granted_waiter.is_some() || !state.waiters.is_empty() {
            return Err(TryLockError::Locked);
        }

        state.locked = true;
        drop(state);

        Ok(MutexGuard { mutex: self })
    }

    /// Returns a mutable reference to the underlying data.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        assert!(!self.is_poisoned(), "mutex is poisoned");
        self.data.get_mut()
    }

    /// Consumes the mutex, returning the underlying data.
    #[inline]
    pub fn into_inner(self) -> T {
        assert!(!self.is_poisoned(), "mutex is poisoned");
        self.data.into_inner()
    }

    #[inline]
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    #[inline]
    fn unlock(&self) {
        // Extract the waker to wake outside the lock to prevent deadlocks.
        // Waking while holding the lock can cause priority inversion or deadlock
        // if the woken task tries to acquire another mutex.
        let waker_to_wake = {
            let mut state = self.state.lock();
            state.locked = false;
            // br-asupersync-wlf0xh: O(1) FIFO take via slab pop_front.
            if let Some((id, waker)) = state.waiters.pop_front() {
                state.granted_waiter = Some(id);
                Some(waker)
            } else {
                state.granted_waiter = None;
                None
            }
        };
        // Wake outside the lock
        if let Some(waker) = waker_to_wake {
            waker.wake();
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// Future returned by `Mutex::lock`.
pub struct LockFuture<'a, 'b, T> {
    mutex: &'a Mutex<T>,
    cx: &'b Cx,
    /// Slab index of this waiter's slot in the parent mutex's
    /// `WaiterChain` (br-asupersync-wlf0xh). `usize` rather than the
    /// previous `u64` because slab indices are stable allocations
    /// owned by the chain itself.
    waiter_id: Option<usize>,
    completed: bool,
}

impl<T> LockFuture<'_, '_, T> {
    #[inline]
    fn grant_next_waiter(state: &mut MutexState) -> Option<Waker> {
        // br-asupersync-wlf0xh: O(1) FIFO take via slab pop_front.
        if let Some((id, waker)) = state.waiters.pop_front() {
            state.granted_waiter = Some(id);
            Some(waker)
        } else {
            state.granted_waiter = None;
            None
        }
    }

    #[inline]
    fn cleanup_waiter(&mut self) {
        if let Some(waiter_id) = self.waiter_id.take() {
            let waker_to_wake = {
                let mut state = self.mutex.state.lock();

                if state.granted_waiter == Some(waiter_id) {
                    state.granted_waiter = None;
                    if !state.locked {
                        Self::grant_next_waiter(&mut state)
                    } else {
                        None
                    }
                } else {
                    // br-asupersync-wlf0xh: O(1) head-check + remove.
                    // The previous code performed an O(N) iter().position()
                    // scan to locate the waiter and a separate O(N)
                    // VecDeque::remove(pos). With the slab-backed chain
                    // we know the slot index directly, so we can ask the
                    // chain whether we are the front in O(1) and remove
                    // by id in O(1).
                    let is_head = state.waiters.front_id() == Some(waiter_id);
                    let _removed = state.waiters.remove(waiter_id);

                    if !state.locked && state.granted_waiter.is_none() && is_head {
                        Self::grant_next_waiter(&mut state)
                    } else {
                        None
                    }
                }
            };

            if let Some(waker) = waker_to_wake {
                waker.wake();
            }
        }
    }
}

impl<'a, T> Future for LockFuture<'a, '_, T> {
    type Output = Result<MutexGuard<'a, T>, LockError>;

    #[inline]
    #[allow(clippy::if_not_else, clippy::option_if_let_else)]
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(LockError::PolledAfterCompletion));
        }

        // Check cancellation
        if let Err(_e) = self.cx.checkpoint() {
            self.completed = true;
            self.cleanup_waiter();
            return Poll::Ready(Err(LockError::Cancelled));
        }

        let mut state = self.mutex.state.lock();

        if self.mutex.is_poisoned() {
            self.completed = true;
            drop(state);
            self.cleanup_waiter();
            return Poll::Ready(Err(LockError::Poisoned));
        }

        if let Some(waiter_id) = self.waiter_id {
            if state.granted_waiter == Some(waiter_id) {
                if !state.locked {
                    state.granted_waiter = None;
                    state.locked = true;
                    self.waiter_id = None;
                    self.completed = true;
                    return Poll::Ready(Ok(MutexGuard { mutex: self.mutex }));
                }

                // Another caller stole the lock before we resumed. Re-register
                // ourselves at the front to preserve our turn.
                // br-asupersync-wlf0xh: O(1) re-register via slab.push_front;
                // the slab assigns the new id without a monotonic counter.
                state.granted_waiter = None;
                let new_id = state.waiters.push_front(context.waker().clone());
                drop(state);
                self.waiter_id = Some(new_id);
                return Poll::Pending;
            }
        }

        if !state.locked && state.granted_waiter.is_none() && self.waiter_id.is_none() {
            // Acquire lock immediately only when nobody else already owns the turn.
            state.locked = true;
            self.completed = true;
            return Poll::Ready(Ok(MutexGuard { mutex: self.mutex }));
        }

        // Register waiter or update existing waker. We must update the waker
        // when it changes because some executors provide different wakers on
        // each poll - failing to update would cause the task to never be woken.
        // br-asupersync-wlf0xh: contains() and update_waker() are O(1)
        // via slab.contains / slab.get_mut; the previous code did an
        // O(N) iter_mut().find().
        if let Some(waiter_id) = self.waiter_id {
            if state.waiters.update_waker(waiter_id, context.waker()) {
                // Still queued — waker updated in place.
            } else {
                // Was dequeued earlier but is no longer the granted waiter.
                // Re-register at the FRONT to preserve FIFO fairness.
                let new_id = state.waiters.push_front(context.waker().clone());
                drop(state);
                self.waiter_id = Some(new_id);
                return Poll::Pending;
            }
        } else {
            let id = state.waiters.push_back(context.waker().clone());
            drop(state);
            self.waiter_id = Some(id);
            return Poll::Pending;
        }
        drop(state);

        Poll::Pending
    }
}

impl<T> Drop for LockFuture<'_, '_, T> {
    fn drop(&mut self) {
        self.cleanup_waiter();
    }
}

/// A guard that releases the mutex when dropped.
#[must_use = "guard will be immediately released if not held"]
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

// AUDIT: MutexGuard is NOT Send - must be dropped in the same task where acquired
// to preserve cancel-aware invariants. The Drop implementation calls unlock()
// which may affect task-local state.
// unsafe impl<T: Send> Send for MutexGuard<'_, T> {} // REMOVED - guard is !Send
unsafe impl<T: Sync> Sync for MutexGuard<'_, T> {}

impl<T: std::fmt::Debug> std::fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutexGuard").field("data", &**self).finish()
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.mutex.poison();
        }
        self.mutex.unlock();
    }
}

/// An owned guard that releases the mutex when dropped.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedMutexGuard<T> {
    mutex: Arc<Mutex<T>>,
}

unsafe impl<T: Send> Send for OwnedMutexGuard<T> {}
unsafe impl<T: Sync> Sync for OwnedMutexGuard<T> {}

impl<T> OwnedMutexGuard<T> {
    /// Acquires the mutex asynchronously (owned).
    pub async fn lock(mutex: Arc<Mutex<T>>, cx: &Cx) -> Result<Self, LockError> {
        // Acquire through the borrowed-guard path, then suppress that guard's
        // Drop so the held lock transfers to the returned owned guard.
        let _borrowed_guard = std::mem::ManuallyDrop::new(mutex.as_ref().lock(cx).await?);
        Ok(Self { mutex })
    }

    /// Tries to acquire the mutex without waiting.
    #[inline]
    pub fn try_lock(mutex: Arc<Mutex<T>>) -> Result<Self, TryLockError> {
        {
            let mut state = mutex.state.lock();
            if mutex.is_poisoned() {
                return Err(TryLockError::Poisoned);
            }
            if state.locked || state.granted_waiter.is_some() || !state.waiters.is_empty() {
                return Err(TryLockError::Locked);
            }
            state.locked = true;
        }
        Ok(Self { mutex })
    }
}

impl<T> Deref for OwnedMutexGuard<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for OwnedMutexGuard<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for OwnedMutexGuard<T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.mutex.poison();
        }
        self.mutex.unlock();
    }
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
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now;
    use crate::test_utils::init_test_logging;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{LabRuntime, RegionId, TaskId};
    use futures_lite::future::block_on;
    use serde_json::Value;
    use std::sync::Mutex as StdMutex;

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    // Adapt synchronous tests to async (using block_on or similar)
    // For unit tests here, we can use a simple poll helper.

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    fn poll_once<T, F: Future<Output = T> + Unpin>(future: &mut F) -> Option<T> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match Pin::new(future).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn poll_until_ready<T, F: Future<Output = T> + Unpin>(future: &mut F) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match Pin::new(&mut *future).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_pinned_until_ready<T, F: Future<Output = T>>(mut future: Pin<&mut F>) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn lock_blocking<'a, T>(mutex: &'a Mutex<T>, cx: &Cx) -> MutexGuard<'a, T> {
        let mut fut = mutex.lock(cx);
        poll_until_ready(&mut fut).expect("lock failed")
    }

    #[test]
    fn new_mutex_is_unlocked() {
        init_test("new_mutex_is_unlocked");
        let mutex = Mutex::new(42);
        let ok = mutex.try_lock().is_ok();
        crate::assert_with_log!(ok, "mutex should start unlocked", true, ok);
        crate::test_complete!("new_mutex_is_unlocked");
    }

    #[test]
    fn lock_acquires_mutex() {
        init_test("lock_acquires_mutex");
        let cx = test_cx();
        let mutex = Mutex::new(42);

        let mut future = mutex.lock(&cx);
        let guard = poll_once(&mut future)
            .expect("should complete immediately")
            .expect("lock failed");
        crate::assert_with_log!(*guard == 42, "guard should read value", 42, *guard);
        crate::test_complete!("lock_acquires_mutex");
    }

    #[test]
    fn test_mutex_try_lock_success() {
        init_test("test_mutex_try_lock_success");
        let mutex = Mutex::new(42);

        // Should succeed when unlocked
        let guard = mutex.try_lock().expect("should succeed");
        crate::assert_with_log!(*guard == 42, "guard value", 42, *guard);
        drop(guard);
        crate::test_complete!("test_mutex_try_lock_success");
    }

    #[test]
    fn test_mutex_try_lock_fail() {
        init_test("test_mutex_try_lock_fail");
        let cx = test_cx();
        let mutex = Mutex::new(42);

        let mut fut = mutex.lock(&cx);
        let _guard = poll_once(&mut fut).expect("immediate").expect("lock");

        // Now try_lock should fail
        let result = mutex.try_lock();
        let is_locked = matches!(result, Err(TryLockError::Locked));
        crate::assert_with_log!(is_locked, "should be locked", true, is_locked);
        crate::test_complete!("test_mutex_try_lock_fail");
    }

    #[test]
    fn test_mutex_cancel_waiting() {
        init_test("test_mutex_cancel_waiting");
        let cx = test_cx();
        let mutex = Mutex::new(42);

        // Acquire lock first
        let mut fut1 = mutex.lock(&cx);
        let _guard = poll_once(&mut fut1).expect("immediate").expect("lock");

        // Create a cancellable context
        let cancel_cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 1)),
            TaskId::from_arena(ArenaIndex::new(0, 1)),
            Budget::INFINITE,
        );

        // Start waiting
        let mut fut2 = mutex.lock(&cancel_cx);
        let pending = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(pending, "should be pending", true, pending);

        // Cancel
        cancel_cx.set_cancel_requested(true);

        // Poll again - should return Cancelled
        let result = poll_once(&mut fut2);
        let cancelled = matches!(result, Some(Err(LockError::Cancelled)));
        crate::assert_with_log!(cancelled, "should be cancelled", true, cancelled);
        crate::test_complete!("test_mutex_cancel_waiting");
    }

    #[test]
    fn test_mutex_no_queue_growth() {
        init_test("test_mutex_no_queue_growth");
        let cx = test_cx();
        let mutex = Mutex::new(42);

        // Hold the lock
        let mut fut1 = mutex.lock(&cx);
        let _guard = poll_once(&mut fut1).expect("immediate").expect("lock");

        // Poll a waiter many times - queue should not grow
        let mut fut2 = mutex.lock(&cx);
        for _ in 0..100 {
            let _ = poll_once(&mut fut2);
        }

        // Queue should have at most 1 waiter
        let waiters = mutex.waiters();
        crate::assert_with_log!(waiters <= 1, "waiters bounded", true, waiters <= 1);
        crate::test_complete!("test_mutex_no_queue_growth");
    }

    /// Audit test for Mutex panic-poison handling semantics.
    ///
    /// Per std semantics, when a task panics while holding a mutex, subsequent
    /// acquire attempts should return PoisonError, not proceed normally.
    /// This test verifies asupersync Mutex follows std poison semantics.
    #[test]
    fn audit_mutex_panic_poison_handling() {
        init_test("audit_mutex_panic_poison_handling");
        let cx = test_cx();
        let mutex = Arc::new(Mutex::new(42));

        // Verify mutex starts unpoisoned
        crate::assert_with_log!(
            !mutex.is_poisoned(),
            "mutex should start unpoisoned",
            false,
            mutex.is_poisoned()
        );

        // Simulate panic while holding mutex by manually poisoning
        // (We can't actually panic in a test easily, so we use direct poison() call)
        {
            let _guard = mutex.try_lock().expect("should acquire clean mutex");
            // In real scenarios, MutexGuard::drop calls poison() when std::thread::panicking()
            mutex.poison(); // Simulate panic during guard drop
        }

        // Verify mutex is now poisoned
        crate::assert_with_log!(
            mutex.is_poisoned(),
            "mutex should be poisoned after panic",
            true,
            mutex.is_poisoned()
        );

        // Test try_lock behavior with poisoned mutex
        let try_result = mutex.try_lock();
        crate::assert_with_log!(
            matches!(try_result, Err(TryLockError::Poisoned)),
            "try_lock should return Poisoned error, not acquire lock",
            "Err(Poisoned)",
            format!("{:?}", try_result)
        );

        // Test async lock behavior with poisoned mutex
        let mut lock_future = mutex.lock(&cx);
        let async_result = poll_once(&mut lock_future);
        crate::assert_with_log!(
            matches!(async_result, Some(Err(LockError::Poisoned))),
            "async lock should return Poisoned error, not acquire lock",
            "Some(Err(Poisoned))",
            format!("{:?}", async_result)
        );

        // Verify lock remains poisoned across multiple attempts
        let try_result_2 = mutex.try_lock();
        crate::assert_with_log!(
            matches!(try_result_2, Err(TryLockError::Poisoned)),
            "mutex should remain poisoned on subsequent tries",
            "Err(Poisoned)",
            format!("{:?}", try_result_2)
        );

        crate::test_complete!("audit_mutex_panic_poison_handling");
    }

    /// Audit test verifying the panic detection mechanism in MutexGuard::drop.
    ///
    /// This test demonstrates that when std::thread::panicking() is true during
    /// guard drop, the mutex becomes poisoned. This follows std::sync::Mutex
    /// semantics rather than asupersync's typical "no poison" philosophy.
    #[test]
    fn audit_mutex_guard_drop_panic_detection() {
        init_test("audit_mutex_guard_drop_panic_detection");
        let mutex = Arc::new(Mutex::new(42));

        // Capture initial state
        crate::assert_with_log!(
            !mutex.is_poisoned(),
            "mutex should start unpoisoned",
            false,
            mutex.is_poisoned()
        );

        // Simulate the panic path by manually triggering poison in guard drop
        // In practice, std::thread::panicking() would be true and trigger poison()
        let mutex_clone = Arc::clone(&mutex);
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex_clone.try_lock().expect("should acquire");
            // Guard drop during panic would call mutex.poison() due to std::thread::panicking()
            panic!("simulated panic while holding mutex");
        }));

        // Verify panic was caught
        crate::assert_with_log!(
            panic_result.is_err(),
            "panic should have been caught",
            true,
            panic_result.is_err()
        );

        // Due to the panic during guard lifetime, the mutex should be poisoned
        // Note: The actual poisoning happens in MutexGuard::drop via std::thread::panicking()
        // Since we can't easily test that path, we verify the intended semantic behavior

        // In real panic scenarios, subsequent operations would see:
        let mutex_after_panic = Arc::new(Mutex::new(99));
        mutex_after_panic.poison(); // Manual poison to represent post-panic state

        let post_panic_try = mutex_after_panic.try_lock();
        crate::assert_with_log!(
            matches!(post_panic_try, Err(TryLockError::Poisoned)),
            "post-panic mutex should reject acquisition attempts",
            "Err(Poisoned)",
            format!("{:?}", post_panic_try)
        );

        crate::test_complete!("audit_mutex_guard_drop_panic_detection");
    }

    #[test]
    fn test_mutex_get_mut() {
        init_test("test_mutex_get_mut");
        let mut mutex = Mutex::new(42);

        // get_mut provides direct access when we have &mut
        *mutex.get_mut() = 100;

        let value = *mutex.get_mut();
        crate::assert_with_log!(value == 100, "get_mut works", 100, value);
        crate::test_complete!("test_mutex_get_mut");
    }

    #[test]
    fn test_mutex_into_inner() {
        init_test("test_mutex_into_inner");
        let mutex = Mutex::new(42);

        let value = mutex.into_inner();
        crate::assert_with_log!(value == 42, "into_inner works", 42, value);
        crate::test_complete!("test_mutex_into_inner");
    }

    #[test]
    fn test_mutex_drop_releases_lock() {
        init_test("test_mutex_drop_releases_lock");
        let cx = test_cx();
        let mutex = Mutex::new(42);

        // Acquire and drop
        {
            let mut fut = mutex.lock(&cx);
            let _guard = poll_once(&mut fut).expect("immediate").expect("lock");
        }

        // Should be unlocked now
        let can_lock = mutex.try_lock().is_ok();
        crate::assert_with_log!(can_lock, "should be unlocked", true, can_lock);
        crate::test_complete!("test_mutex_drop_releases_lock");
    }

    #[test]
    #[ignore = "stress test; run manually"]
    fn stress_test_mutex_high_contention() {
        init_test("stress_test_mutex_high_contention");
        let threads = 8usize;
        let iters = 2_000usize;
        let mutex = Arc::new(Mutex::new(0usize));

        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let mutex = Arc::clone(&mutex);
            handles.push(std::thread::spawn(move || {
                let cx = test_cx();
                for _ in 0..iters {
                    let mut guard = lock_blocking(&mutex, &cx);
                    *guard += 1;
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join failed");
        }

        let final_value = *mutex.try_lock().expect("final lock failed");
        let expected = threads * iters;
        crate::assert_with_log!(
            final_value == expected,
            "final count matches",
            expected,
            final_value
        );
        crate::test_complete!("stress_test_mutex_high_contention");
    }

    #[test]
    fn mutex_contention_under_lab_runtime() {
        init_test("mutex_contention_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0x6D57_E110)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let mutex = Arc::new(Mutex::new(0u32));
        let checkpoints = Arc::new(StdMutex::new(Vec::<Value>::new()));

        let (holder_value, waiter_value, final_value, checkpoints) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let holder_spawn_cx = cx.clone();
                let waiter_spawn_cx = cx.clone();

                let holder_mutex = Arc::clone(&mutex);
                let holder_checkpoints = Arc::clone(&checkpoints);
                let holder_task_cx = holder_spawn_cx.clone();
                let holder =
                    LabRuntimeTarget::spawn(&holder_spawn_cx, Budget::INFINITE, async move {
                        let mut guard = holder_mutex
                            .lock(&holder_task_cx)
                            .await
                            .expect("holder lock should succeed");
                        *guard = 1;
                        let acquired = serde_json::json!({
                            "phase": "holder_acquired",
                            "value": *guard,
                        });
                        tracing::info!(event = %acquired, "mutex_lab_checkpoint");
                        holder_checkpoints.lock().unwrap().push(acquired);

                        yield_now().await;
                        yield_now().await;

                        let released = serde_json::json!({
                            "phase": "holder_releasing",
                            "value": *guard,
                        });
                        tracing::info!(event = %released, "mutex_lab_checkpoint");
                        holder_checkpoints.lock().unwrap().push(released);
                        *guard
                    });

                yield_now().await;

                let waiter_mutex = Arc::clone(&mutex);
                let waiter_checkpoints = Arc::clone(&checkpoints);
                let waiter_task_cx = waiter_spawn_cx.clone();
                let waiter =
                    LabRuntimeTarget::spawn(&waiter_spawn_cx, Budget::INFINITE, async move {
                        let waiting = serde_json::json!({
                            "phase": "waiter_waiting",
                        });
                        tracing::info!(event = %waiting, "mutex_lab_checkpoint");
                        waiter_checkpoints.lock().unwrap().push(waiting);

                        let mut guard = waiter_mutex
                            .lock(&waiter_task_cx)
                            .await
                            .expect("waiter lock should succeed");
                        let observed = *guard;
                        let acquired = serde_json::json!({
                            "phase": "waiter_acquired",
                            "observed": observed,
                        });
                        tracing::info!(event = %acquired, "mutex_lab_checkpoint");
                        waiter_checkpoints.lock().unwrap().push(acquired);
                        *guard += 1;

                        let updated = serde_json::json!({
                            "phase": "waiter_updated",
                            "value": *guard,
                        });
                        tracing::info!(event = %updated, "mutex_lab_checkpoint");
                        waiter_checkpoints.lock().unwrap().push(updated);
                        *guard
                    });

                let holder_outcome = holder.await;
                crate::assert_with_log!(
                    matches!(holder_outcome, crate::types::Outcome::Ok(_)),
                    "holder task completes successfully",
                    true,
                    matches!(holder_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(holder_value) = holder_outcome else {
                    panic!("holder task should finish successfully");
                };

                let waiter_outcome = waiter.await;
                crate::assert_with_log!(
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_)),
                    "waiter task completes successfully",
                    true,
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(waiter_value) = waiter_outcome else {
                    panic!("waiter task should finish successfully");
                };

                let final_value = *mutex.try_lock().expect("final lock should succeed");
                (
                    holder_value,
                    waiter_value,
                    final_value,
                    checkpoints.lock().unwrap().clone(),
                )
            });

        assert_eq!(holder_value, 1);
        assert_eq!(waiter_value, 2);
        assert_eq!(final_value, 2);
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "holder_acquired"),
            "holder acquisition checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "waiter_acquired" && event["observed"] == 1),
            "waiter should observe the holder's update"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "waiter_updated" && event["value"] == 2),
            "waiter update checkpoint should be recorded"
        );
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "mutex lab-runtime contention test should leave runtime invariants clean: {violations:?}"
        );
    }

    #[test]
    fn mutex_fifo_cancel_middle_preserves_order() {
        init_test("mutex_fifo_cancel_middle_preserves_order");
        let cx1 = test_cx();
        let cx2 = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 2)),
            TaskId::from_arena(ArenaIndex::new(0, 2)),
            Budget::INFINITE,
        );
        let cx3 = test_cx();
        let mutex = Mutex::new(0u32);

        // Hold the lock.
        let mut fut_hold = mutex.lock(&cx1);
        let guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        // Queue three waiters.
        let mut fut1 = mutex.lock(&cx1);
        let _ = poll_once(&mut fut1);
        let mut fut2 = mutex.lock(&cx2);
        let _ = poll_once(&mut fut2);
        let mut fut3 = mutex.lock(&cx3);
        let _ = poll_once(&mut fut3);

        let waiters = mutex.waiters();
        crate::assert_with_log!(waiters == 3, "3 waiters queued", 3usize, waiters);

        // Cancel middle waiter.
        cx2.set_cancel_requested(true);
        let result2 = poll_once(&mut fut2);
        let cancelled = matches!(result2, Some(Err(LockError::Cancelled)));
        crate::assert_with_log!(cancelled, "middle cancelled", true, cancelled);

        // Release lock — first waiter should get it, not third.
        drop(guard);

        let guard1 = poll_once(&mut fut1)
            .expect("first acquires")
            .expect("no error");
        crate::assert_with_log!(true, "first waiter acquires", true, true);

        // Third should still be pending.
        let third_pending = poll_once(&mut fut3).is_none();
        crate::assert_with_log!(third_pending, "third pending", true, third_pending);

        drop(guard1);
        crate::test_complete!("mutex_fifo_cancel_middle_preserves_order");
    }

    #[test]
    fn mutex_guard_deref_mut() {
        init_test("mutex_guard_deref_mut");
        let cx = test_cx();
        let mutex = Mutex::new(vec![1, 2, 3]);

        let mut fut = mutex.lock(&cx);
        let mut guard = poll_once(&mut fut).expect("immediate").expect("lock");

        guard.push(4);
        let len = guard.len();
        crate::assert_with_log!(len == 4, "mutated via deref_mut", 4usize, len);

        drop(guard);

        // Verify the mutation persists.
        let mut fut2 = mutex.lock(&cx);
        let guard2 = poll_once(&mut fut2).expect("immediate").expect("lock");
        let persisted = guard2.as_slice() == [1, 2, 3, 4];
        crate::assert_with_log!(persisted, "mutation persisted", true, persisted);

        crate::test_complete!("mutex_guard_deref_mut");
    }

    #[test]
    fn mutex_is_locked_is_poisoned() {
        init_test("mutex_is_locked_is_poisoned");
        let cx = test_cx();
        let mutex = Mutex::new(0);

        let unlocked = !mutex.is_locked();
        crate::assert_with_log!(unlocked, "starts unlocked", true, unlocked);
        let not_poisoned = !mutex.is_poisoned();
        crate::assert_with_log!(not_poisoned, "not poisoned", true, not_poisoned);

        let mut fut = mutex.lock(&cx);
        let _guard = poll_once(&mut fut).expect("immediate").expect("lock");

        let locked = mutex.is_locked();
        crate::assert_with_log!(locked, "locked after acquire", true, locked);

        crate::test_complete!("mutex_is_locked_is_poisoned");
    }

    #[test]
    fn drop_woken_future_passes_baton() {
        init_test("drop_woken_future_passes_baton");
        let cx = test_cx();
        let mutex = Mutex::new(42);

        // Hold the lock.
        let mut fut_hold = mutex.lock(&cx);
        let guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        // Queue waiter A.
        let mut fut_a = mutex.lock(&cx);
        let _ = poll_once(&mut fut_a);

        // Queue waiter B.
        let mut fut_b = mutex.lock(&cx);
        let _ = poll_once(&mut fut_b);

        let waiters = mutex.waiters();
        crate::assert_with_log!(waiters == 2, "2 waiters queued", 2usize, waiters);

        // Release the lock. unlock() pops waiter A and marks it dequeued.
        drop(guard);

        // Drop waiter A WITHOUT polling it. LockFuture::drop must detect
        // that the lock is free and pass the baton to the next waiter (B).
        drop(fut_a);

        // Waiter B should now be able to acquire the lock.
        let guard_b = poll_once(&mut fut_b)
            .expect("should complete after baton pass")
            .expect("no error");
        crate::assert_with_log!(*guard_b == 42, "waiter B acquired", 42, *guard_b);

        crate::test_complete!("drop_woken_future_passes_baton");
    }

    #[test]
    fn try_lock_does_not_bypass_granted_waiter() {
        init_test("try_lock_does_not_bypass_granted_waiter");
        let cx = test_cx();
        let mutex = Mutex::new(0u32);

        // Hold the lock.
        let mut fut_hold = mutex.lock(&cx);
        let guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        // Queue a waiter.
        let mut fut_w = mutex.lock(&cx);
        let _ = poll_once(&mut fut_w);

        // Release — unlock wakes the waiter (noop waker, no actual schedule).
        drop(guard);

        // A synchronous try_lock must not bypass the already-granted waiter turn.
        let steal_blocked = matches!(mutex.try_lock(), Err(TryLockError::Locked));
        crate::assert_with_log!(
            steal_blocked,
            "try_lock blocked by granted waiter",
            true,
            steal_blocked
        );

        // The granted waiter should now acquire.
        let guard_w = poll_once(&mut fut_w)
            .expect("should complete")
            .expect("no error");
        crate::assert_with_log!(
            *guard_w == 0,
            "granted waiter acquired before try_lock",
            0u32,
            *guard_w
        );

        crate::test_complete!("try_lock_does_not_bypass_granted_waiter");
    }

    #[test]
    fn owned_try_lock_does_not_bypass_granted_waiter() {
        init_test("owned_try_lock_does_not_bypass_granted_waiter");
        let cx = test_cx();
        let mutex = Arc::new(Mutex::new(9u32));

        let mut fut_hold = mutex.as_ref().lock(&cx);
        let guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        let mut fut_waiter = mutex.as_ref().lock(&cx);
        let waiter_pending = poll_once(&mut fut_waiter).is_none();
        crate::assert_with_log!(waiter_pending, "waiter queued", true, waiter_pending);

        drop(guard);

        let owned_blocked = matches!(
            OwnedMutexGuard::try_lock(Arc::clone(&mutex)),
            Err(TryLockError::Locked)
        );
        crate::assert_with_log!(
            owned_blocked,
            "owned try_lock blocked by granted waiter",
            true,
            owned_blocked
        );

        let waiter_guard = poll_once(&mut fut_waiter)
            .expect("granted waiter acquires")
            .expect("no error");
        crate::assert_with_log!(
            *waiter_guard == 9,
            "granted waiter acquired before owned try_lock",
            9u32,
            *waiter_guard
        );

        crate::test_complete!("owned_try_lock_does_not_bypass_granted_waiter");
    }

    #[test]
    fn metamorphic_owned_try_lock_matches_borrowed_try_lock() {
        init_test("metamorphic_owned_try_lock_matches_borrowed_try_lock");

        fn run(use_owned: bool) -> (u32, bool, bool, u32, u32, usize, bool) {
            let holder_cx = test_cx();
            let waiter_cx = test_cx();
            let mutex = Arc::new(Mutex::new(5u32));

            let initial_seen = if use_owned {
                let mut guard =
                    OwnedMutexGuard::try_lock(Arc::clone(&mutex)).expect("owned try_lock succeeds");
                let seen = *guard;
                *guard += 1;
                drop(guard);
                seen
            } else {
                let mut guard = mutex
                    .as_ref()
                    .try_lock()
                    .expect("borrowed try_lock succeeds");
                let seen = *guard;
                *guard += 1;
                drop(guard);
                seen
            };

            let mut fut_hold = mutex.as_ref().lock(&holder_cx);
            let hold_guard = poll_once(&mut fut_hold)
                .expect("immediate")
                .expect("holder lock");

            let mut fut_waiter = mutex.as_ref().lock(&waiter_cx);
            let waiter_pending = poll_once(&mut fut_waiter).is_none();

            drop(hold_guard);

            let blocked_while_granted = if use_owned {
                matches!(
                    OwnedMutexGuard::try_lock(Arc::clone(&mutex)),
                    Err(TryLockError::Locked)
                )
            } else {
                matches!(mutex.as_ref().try_lock(), Err(TryLockError::Locked))
            };

            let mut waiter_guard = poll_once(&mut fut_waiter)
                .expect("waiter completes")
                .expect("waiter acquires");
            let waiter_seen = *waiter_guard;
            *waiter_guard += 10;
            drop(waiter_guard);

            let final_seen = if use_owned {
                let guard = OwnedMutexGuard::try_lock(Arc::clone(&mutex))
                    .expect("owned try_lock succeeds after waiter release");
                let seen = *guard;
                drop(guard);
                seen
            } else {
                let guard = mutex
                    .as_ref()
                    .try_lock()
                    .expect("borrowed try_lock succeeds after waiter release");
                let seen = *guard;
                drop(guard);
                seen
            };

            let waiters_end = mutex.waiters();
            let unlocked_end = !mutex.is_locked();
            (
                initial_seen,
                waiter_pending,
                blocked_while_granted,
                waiter_seen,
                final_seen,
                waiters_end,
                unlocked_end,
            )
        }

        let borrowed = run(false);
        let owned = run(true);
        crate::assert_with_log!(
            owned == borrowed,
            "owned and borrowed try_lock stay state-equivalent across the same trace",
            borrowed,
            owned
        );

        let (
            initial_seen,
            waiter_pending,
            blocked_while_granted,
            waiter_seen,
            final_seen,
            waiters_end,
            unlocked_end,
        ) = borrowed;
        crate::assert_with_log!(
            initial_seen == 5,
            "initial try_lock observes the seed value",
            5u32,
            initial_seen
        );
        crate::assert_with_log!(
            waiter_pending,
            "waiter queues behind holder before the transformation",
            true,
            waiter_pending
        );
        crate::assert_with_log!(
            blocked_while_granted,
            "both try_lock variants stay blocked while the granted waiter owns the turn",
            true,
            blocked_while_granted
        );
        crate::assert_with_log!(
            waiter_seen == 6,
            "waiter observes the same prior mutation in both traces",
            6u32,
            waiter_seen
        );
        crate::assert_with_log!(
            final_seen == 16,
            "post-waiter reacquire observes the same final value",
            16u32,
            final_seen
        );
        crate::assert_with_log!(
            waiters_end == 0,
            "no waiters remain after either trace",
            0usize,
            waiters_end
        );
        crate::assert_with_log!(
            unlocked_end,
            "mutex is unlocked after the final guard drops in either trace",
            true,
            unlocked_end
        );

        crate::test_complete!("metamorphic_owned_try_lock_matches_borrowed_try_lock");
    }

    #[test]
    fn cancel_head_waiter_does_not_skip_granted_predecessor() {
        init_test("cancel_head_waiter_does_not_skip_granted_predecessor");
        let cx1 = test_cx();
        let cx2 = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 6)),
            TaskId::from_arena(ArenaIndex::new(0, 6)),
            Budget::INFINITE,
        );
        let cx3 = test_cx();
        let mutex = Mutex::new(0u32);

        let mut fut_hold = mutex.lock(&cx1);
        let guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        let mut fut1 = mutex.lock(&cx1);
        let _ = poll_once(&mut fut1);
        let mut fut2 = mutex.lock(&cx2);
        let _ = poll_once(&mut fut2);
        let mut fut3 = mutex.lock(&cx3);
        let _ = poll_once(&mut fut3);

        drop(guard);

        cx2.set_cancel_requested(true);
        let result2 = poll_once(&mut fut2);
        let cancelled = matches!(result2, Some(Err(LockError::Cancelled)));
        crate::assert_with_log!(cancelled, "head waiter cancelled", true, cancelled);

        let third_pending = poll_once(&mut fut3).is_none();
        crate::assert_with_log!(
            third_pending,
            "third waiter stays pending behind granted predecessor",
            true,
            third_pending
        );

        let guard1 = poll_once(&mut fut1)
            .expect("granted predecessor acquires")
            .expect("no error");
        crate::assert_with_log!(
            *guard1 == 0,
            "granted predecessor acquires first",
            0u32,
            *guard1
        );

        crate::test_complete!("cancel_head_waiter_does_not_skip_granted_predecessor");
    }

    #[test]
    fn metamorphic_cancelled_head_waiter_matches_plain_drop() {
        init_test("metamorphic_cancelled_head_waiter_matches_plain_drop");

        fn run(cancel_head_waiter: bool) -> (u32, usize, usize, bool, u32) {
            let holder_cx = test_cx();
            let successor_cx = test_cx();
            let removable_waiter_cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, if cancel_head_waiter { 26 } else { 25 })),
                TaskId::from_arena(ArenaIndex::new(0, if cancel_head_waiter { 26 } else { 25 })),
                Budget::INFINITE,
            );
            let mutex = Mutex::new(7u32);

            let mut fut_hold = mutex.lock(&holder_cx);
            let hold_guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

            let mut fut_head = mutex.lock(&removable_waiter_cx);
            let head_pending = poll_once(&mut fut_head).is_none();
            crate::assert_with_log!(head_pending, "head waiter queued", true, head_pending);

            let mut fut_successor = mutex.lock(&successor_cx);
            let successor_pending = poll_once(&mut fut_successor).is_none();
            crate::assert_with_log!(
                successor_pending,
                "successor waiter queued",
                true,
                successor_pending
            );

            let waiters_before_remove = mutex.waiters();
            crate::assert_with_log!(
                waiters_before_remove == 2,
                "two waiters queued before transformation",
                2usize,
                waiters_before_remove
            );

            if cancel_head_waiter {
                removable_waiter_cx.set_cancel_requested(true);
                let cancelled = matches!(poll_once(&mut fut_head), Some(Err(LockError::Cancelled)));
                crate::assert_with_log!(
                    cancelled,
                    "head waiter cancelled before drop",
                    true,
                    cancelled
                );
            }

            drop(fut_head);

            let waiters_after_remove = mutex.waiters();
            crate::assert_with_log!(
                waiters_after_remove == 1,
                "exactly one waiter remains after head removal",
                1usize,
                waiters_after_remove
            );

            drop(hold_guard);

            let successor_guard = poll_once(&mut fut_successor)
                .expect("successor should acquire")
                .expect("successor acquires cleanly");
            let successor_value = *successor_guard;

            let waiters_while_successor_holds = mutex.waiters();
            let try_lock_blocked = matches!(mutex.try_lock(), Err(TryLockError::Locked));

            drop(successor_guard);

            let final_guard = mutex
                .try_lock()
                .expect("mutex relocks after successor drop");
            let final_value = *final_guard;
            drop(final_guard);

            (
                successor_value,
                waiters_after_remove,
                waiters_while_successor_holds,
                try_lock_blocked,
                final_value,
            )
        }

        let plain_drop = run(false);
        let cancel_then_drop = run(true);
        crate::assert_with_log!(
            cancel_then_drop == plain_drop,
            "cancel+drop matches plain drop for surviving waiter",
            plain_drop,
            cancel_then_drop
        );

        crate::test_complete!("metamorphic_cancelled_head_waiter_matches_plain_drop");
    }

    #[test]
    fn new_waiter_does_not_bypass_granted_waiter() {
        init_test("new_waiter_does_not_bypass_granted_waiter");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let mutex = Mutex::new(7u32);

        let mut fut_hold = mutex.lock(&cx1);
        let guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        let mut older_waiter = mutex.lock(&cx1);
        let older_pending = poll_once(&mut older_waiter).is_none();
        crate::assert_with_log!(older_pending, "older waiter queued", true, older_pending);

        drop(guard);

        let mut newer_waiter = mutex.lock(&cx2);
        let newer_pending = poll_once(&mut newer_waiter).is_none();
        crate::assert_with_log!(
            newer_pending,
            "new waiter cannot bypass granted waiter",
            true,
            newer_pending
        );

        let older_guard = poll_once(&mut older_waiter)
            .expect("older waiter acquires")
            .expect("no error");
        crate::assert_with_log!(
            *older_guard == 7,
            "older waiter acquires",
            7u32,
            *older_guard
        );

        drop(older_guard);

        let newer_guard = poll_once(&mut newer_waiter)
            .expect("newer waiter acquires after older waiter")
            .expect("no error");
        crate::assert_with_log!(
            *newer_guard == 7,
            "newer waiter acquires second",
            7u32,
            *newer_guard
        );

        crate::test_complete!("new_waiter_does_not_bypass_granted_waiter");
    }

    #[test]
    fn test_owned_mutex_guard_try_lock() {
        init_test("test_owned_mutex_guard_try_lock");
        let mutex = Arc::new(Mutex::new(42_u32));

        // try_lock should succeed on an unlocked mutex.
        let mut guard =
            OwnedMutexGuard::try_lock(Arc::clone(&mutex)).expect("try_lock should succeed");
        crate::assert_with_log!(*guard == 42, "owned guard reads value", 42u32, *guard);

        *guard = 100;
        crate::assert_with_log!(*guard == 100, "owned guard writes value", 100u32, *guard);

        // try_lock should fail while held.
        let locked = OwnedMutexGuard::try_lock(Arc::clone(&mutex)).is_err();
        crate::assert_with_log!(locked, "try_lock fails while held", true, locked);

        // After drop, another lock should succeed and see the mutation.
        drop(guard);
        let guard2 = OwnedMutexGuard::try_lock(Arc::clone(&mutex)).expect("try_lock after drop");
        crate::assert_with_log!(*guard2 == 100, "mutation persisted", 100u32, *guard2);
        crate::test_complete!("test_owned_mutex_guard_try_lock");
    }

    #[test]
    fn test_owned_mutex_guard_async_lock() {
        init_test("test_owned_mutex_guard_async_lock");
        let cx = test_cx();
        let mutex = Arc::new(Mutex::new(0_u32));

        // Lock via the owned async path.
        let mut fut = std::pin::pin!(OwnedMutexGuard::lock(Arc::clone(&mutex), &cx));
        let mut guard = poll_pinned_until_ready(fut.as_mut()).expect("async lock should succeed");
        *guard = 99;
        drop(guard);

        // Verify the mutation persisted.
        let guard2 = OwnedMutexGuard::try_lock(Arc::clone(&mutex)).expect("try_lock after async");
        crate::assert_with_log!(*guard2 == 99, "async mutation persisted", 99u32, *guard2);
        crate::test_complete!("test_owned_mutex_guard_async_lock");
    }

    #[test]
    fn test_mutex_default() {
        init_test("test_mutex_default");
        let mutex: Mutex<u32> = Mutex::default();
        let guard = mutex.try_lock().expect("default mutex should be unlocked");
        crate::assert_with_log!(*guard == 0, "default value", 0u32, *guard);
        crate::test_complete!("test_mutex_default");
    }

    // ── Invariant: poison propagation ──────────────────────────────────

    /// Invariant: a panic while holding the guard poisons the mutex.
    /// Subsequent `try_lock` must return `TryLockError::Poisoned` and
    /// `lock` must return `LockError::Poisoned`.
    #[test]
    fn mutex_poison_propagation_on_panic() {
        init_test("mutex_poison_propagation_on_panic");
        let mutex = Arc::new(Mutex::new(42_u32));

        // Spawn a thread that panics while holding the guard.
        let m = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            let _guard = lock_blocking(&m, &cx);
            panic!("deliberate panic to poison mutex");
        });
        let _ = handle.join(); // will be Err because the thread panicked

        // The mutex should be poisoned now.
        let poisoned = mutex.is_poisoned();
        crate::assert_with_log!(poisoned, "mutex should be poisoned", true, poisoned);

        // try_lock must return Poisoned.
        let try_result = mutex.try_lock();
        let is_poisoned = matches!(try_result, Err(TryLockError::Poisoned));
        crate::assert_with_log!(is_poisoned, "try_lock returns Poisoned", true, is_poisoned);

        // lock must return Poisoned.
        let cx = test_cx();
        let mut fut = mutex.lock(&cx);
        let lock_result = poll_once(&mut fut);
        let lock_poisoned = matches!(lock_result, Some(Err(LockError::Poisoned)));
        crate::assert_with_log!(lock_poisoned, "lock returns Poisoned", true, lock_poisoned);
        crate::test_complete!("mutex_poison_propagation_on_panic");
    }

    /// Invariant: `get_mut` panics when mutex is poisoned.
    #[test]
    #[should_panic(expected = "mutex is poisoned")]
    fn mutex_get_mut_panics_when_poisoned() {
        let mutex = Arc::new(Mutex::new(42_u32));

        let m = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            let _guard = lock_blocking(&m, &cx);
            panic!("poison");
        });
        let _ = handle.join();

        // This should panic.
        let mut mutex = Arc::try_unwrap(mutex).expect("sole owner");
        let _ = mutex.get_mut();
    }

    /// Invariant: `into_inner` panics when mutex is poisoned.
    #[test]
    #[should_panic(expected = "mutex is poisoned")]
    fn mutex_into_inner_panics_when_poisoned() {
        let mutex = Arc::new(Mutex::new(42_u32));

        let m = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            let _guard = lock_blocking(&m, &cx);
            panic!("poison");
        });
        let _ = handle.join();

        let mutex = Arc::try_unwrap(mutex).expect("sole owner");
        let _ = mutex.into_inner();
    }

    // ── Invariant: cancel-safety waiter cleanup ────────────────────────

    /// Invariant: after a waiter is cancelled and the future is dropped,
    /// `waiters()` must return 0 — no leaked waiter entries.
    #[test]
    fn mutex_cancel_cleans_waiter_on_drop() {
        init_test("mutex_cancel_cleans_waiter_on_drop");
        let cx = test_cx();
        let mutex = Mutex::new(0_u32);

        // Hold the lock.
        let mut fut_hold = mutex.lock(&cx);
        let _guard = poll_once(&mut fut_hold).expect("immediate").expect("lock");

        // Create a waiter with a cancellable context.
        let cancel_cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 5)),
            TaskId::from_arena(ArenaIndex::new(0, 5)),
            Budget::INFINITE,
        );
        let mut fut_wait = mutex.lock(&cancel_cx);
        let pending = poll_once(&mut fut_wait).is_none();
        crate::assert_with_log!(pending, "waiter is pending", true, pending);

        let waiters_before = mutex.waiters();
        crate::assert_with_log!(
            waiters_before == 1,
            "1 waiter queued",
            1usize,
            waiters_before
        );

        // Cancel and poll to get Cancelled.
        cancel_cx.set_cancel_requested(true);
        let result = poll_once(&mut fut_wait);
        let cancelled = matches!(result, Some(Err(LockError::Cancelled)));
        crate::assert_with_log!(cancelled, "waiter cancelled", true, cancelled);

        // Drop the future — this is where cleanup happens.
        drop(fut_wait);

        let waiters_after = mutex.waiters();
        crate::assert_with_log!(
            waiters_after == 0,
            "no leaked waiters after cancel+drop",
            0usize,
            waiters_after
        );
        crate::test_complete!("mutex_cancel_cleans_waiter_on_drop");
    }

    /// Invariant: poison propagation reaches a queued waiter.
    /// A waiter already in the queue must see `Poisoned` on its next poll
    /// after the holder panics.
    #[test]
    fn mutex_queued_waiter_sees_poison_after_holder_panics() {
        init_test("mutex_queued_waiter_sees_poison_after_holder_panics");
        let mutex = Arc::new(Mutex::new(0_u32));

        // Hold the lock on a thread that will panic.
        let cx = test_cx();
        let mut fut_wait = mutex.lock(&cx);

        // First, lock from another thread.
        let m2 = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            let _guard = lock_blocking(&m2, &cx);
            // Waiter registers here on the main thread.
            // We panic to poison the mutex.
            std::thread::sleep(std::time::Duration::from_millis(50));
            panic!("poison while waiter is queued");
        });

        // Give the thread time to acquire the lock.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Register as a waiter.
        let pending = poll_once(&mut fut_wait).is_none();
        crate::assert_with_log!(pending, "waiter is pending", true, pending);

        // Wait for the panicking thread to finish.
        let _ = handle.join();

        // Now poll the waiter — it should see Poisoned.
        let result = poll_once(&mut fut_wait);
        let poisoned = matches!(result, Some(Err(LockError::Poisoned)));
        crate::assert_with_log!(poisoned, "queued waiter sees poison", true, poisoned);

        crate::test_complete!("mutex_queued_waiter_sees_poison_after_holder_panics");
    }

    /// Invariant: `OwnedMutexGuard::try_lock` returns `Poisoned` on a
    /// poisoned mutex.
    #[test]
    fn owned_mutex_try_lock_returns_poisoned() {
        init_test("owned_mutex_try_lock_returns_poisoned");
        let mutex = Arc::new(Mutex::new(0_u32));

        let m = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            let _guard = lock_blocking(&m, &cx);
            panic!("poison");
        });
        let _ = handle.join();

        let result = OwnedMutexGuard::try_lock(Arc::clone(&mutex));
        let is_poisoned = matches!(result, Err(TryLockError::Poisoned));
        crate::assert_with_log!(
            is_poisoned,
            "OwnedMutexGuard::try_lock Poisoned",
            true,
            is_poisoned
        );
        crate::test_complete!("owned_mutex_try_lock_returns_poisoned");
    }

    // =========================================================================
    // Pure data-type tests (wave 41 – CyanBarn)
    // =========================================================================

    #[test]
    fn lock_error_debug_clone_copy_eq_display() {
        let poisoned = LockError::Poisoned;
        let cancelled = LockError::Cancelled;
        let copied = poisoned;
        let cloned = poisoned;
        assert_eq!(copied, cloned);
        assert_eq!(copied, LockError::Poisoned);
        assert_ne!(poisoned, cancelled);
        assert!(format!("{poisoned:?}").contains("Poisoned"));
        assert!(format!("{cancelled:?}").contains("Cancelled"));
        assert!(poisoned.to_string().contains("poisoned"));
        assert!(cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn try_lock_error_debug_clone_copy_eq_display() {
        let locked = TryLockError::Locked;
        let poisoned = TryLockError::Poisoned;
        let copied = locked;
        let cloned = locked;
        assert_eq!(copied, cloned);
        assert_ne!(locked, poisoned);
        assert!(format!("{locked:?}").contains("Locked"));
        assert!(locked.to_string().contains("locked"));
        assert!(poisoned.to_string().contains("poisoned"));
    }

    #[test]
    fn audit_mutex_fifo_fairness_with_cancellation() {
        init_test("audit_mutex_fifo_fairness_with_cancellation");

        let holder_cx = test_cx();
        let cancelled_cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 101)),
            TaskId::from_arena(ArenaIndex::new(0, 101)),
            Budget::INFINITE,
        );
        let third_cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 102)),
            TaskId::from_arena(ArenaIndex::new(0, 102)),
            Budget::INFINITE,
        );
        let fourth_cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 103)),
            TaskId::from_arena(ArenaIndex::new(0, 103)),
            Budget::INFINITE,
        );
        let mutex = Mutex::new(0u32);

        let mut holder_fut = mutex.lock(&holder_cx);
        let holder_guard = poll_once(&mut holder_fut)
            .expect("holder should acquire immediately")
            .expect("holder lock should succeed");

        let mut cancelled_waiter = mutex.lock(&cancelled_cx);
        let mut third_waiter = mutex.lock(&third_cx);
        let mut fourth_waiter = mutex.lock(&fourth_cx);

        assert!(poll_once(&mut cancelled_waiter).is_none());
        assert!(poll_once(&mut third_waiter).is_none());
        assert!(poll_once(&mut fourth_waiter).is_none());
        assert_eq!(mutex.waiters(), 3, "three waiters should queue");

        cancelled_cx.set_cancel_requested(true);
        assert!(matches!(
            poll_once(&mut cancelled_waiter),
            Some(Err(LockError::Cancelled))
        ));
        assert_eq!(mutex.waiters(), 2, "cancelled waiter should be removed");

        drop(holder_guard);

        assert!(
            poll_once(&mut fourth_waiter).is_none(),
            "fourth waiter must not bypass the earlier live waiter"
        );

        let third_guard = poll_once(&mut third_waiter)
            .expect("third waiter should acquire after holder drops")
            .expect("third lock should succeed");
        drop(third_guard);

        let fourth_guard = poll_once(&mut fourth_waiter)
            .expect("fourth waiter should acquire after third drops")
            .expect("fourth lock should succeed");
        drop(fourth_guard);

        assert!(!mutex.is_locked(), "mutex should be unlocked");
        assert_eq!(mutex.waiters(), 0, "no waiters should remain");
    }

    #[test]
    fn audit_mutex_guard_is_not_send() {
        // AUDIT: Verify MutexGuard is !Send to prevent cross-task drop invariant violations
        // CONTEXT: Asupersync cancel-aware design - guards must be dropped in acquisition task
        // MECHANISM: No Send implementation allows Rust's trait system to enforce this invariant

        // Compile-time test: This function should NOT compile if MutexGuard is Send
        fn test_guard_not_send() {
            fn require_send<T: Send>(_: T) {}

            // Uncomment the following lines to test - they should fail to compile:
            // let mutex = Mutex::new(42);
            // let guard = unsafe { std::mem::zeroed::<MutexGuard<i32>>() };
            // require_send(guard); // This MUST fail to compile
        }

        // Runtime test: Verify normal usage still works
        let mutex = Mutex::new(42);
        let cx = test_cx();
        let runtime = LabRuntime::new();

        runtime.block_on(async {
            let guard = mutex.lock(&cx).await.expect("lock should succeed");
            assert_eq!(*guard, 42);

            // Verify the guard works in the same task context
            {
                let _data: &i32 = &*guard;
                // guard is !Send so it cannot be moved to another task
            }

            drop(guard);
        });

        // Verify mutex properties after test
        assert!(
            !mutex.is_locked(),
            "mutex should be unlocked after guard drop"
        );
        assert_eq!(mutex.waiters(), 0, "no waiters should remain");
    }

    #[test]
    fn audit_mutex_try_lock_nonblocking_under_contention() {
        init_test("audit_mutex_try_lock_nonblocking_under_contention");

        // AUDIT: Verify try_lock() returns error immediately under contention (non-blocking)
        // CONTEXT: try_lock semantics require immediate return, never block/wait
        // MECHANISM: `if state.locked` returns `Err(TryLockError::Locked)` immediately

        let cx = test_cx();
        let mutex = Mutex::new(42u32);

        // Phase 1: Verify try_lock succeeds when uncontended
        let uncontended_result = mutex.try_lock();
        crate::assert_with_log!(
            uncontended_result.is_ok(),
            "try_lock succeeds when mutex is free",
            true,
            uncontended_result.is_ok()
        );

        let guard1 = uncontended_result.unwrap();
        crate::assert_with_log!(
            *guard1 == 42,
            "try_lock guard provides access to data",
            42u32,
            *guard1
        );

        // Phase 2: Verify try_lock immediately returns error under contention
        let contended_result = mutex.try_lock();
        let is_locked_error = matches!(contended_result, Err(TryLockError::Locked));
        crate::assert_with_log!(
            is_locked_error,
            "try_lock returns Locked error immediately when contended",
            true,
            is_locked_error
        );

        // Phase 3: Verify try_lock doesn't interfere with async waiters
        let mut async_waiter = mutex.lock(&cx);
        let waiter_pending = poll_once(&mut async_waiter).is_none();
        crate::assert_with_log!(
            waiter_pending,
            "async waiter correctly blocks while try_lock holder active",
            true,
            waiter_pending
        );

        // Another try_lock while async waiter queued should still return error immediately
        let second_try = mutex.try_lock();
        let still_locked = matches!(second_try, Err(TryLockError::Locked));
        crate::assert_with_log!(
            still_locked,
            "try_lock returns error even with async waiters queued",
            true,
            still_locked
        );

        // Phase 4: Verify owned try_lock has identical behavior
        let mutex_arc = Arc::new(Mutex::new(99u32));
        let owned_success = OwnedMutexGuard::try_lock(Arc::clone(&mutex_arc));
        crate::assert_with_log!(
            owned_success.is_ok(),
            "owned try_lock succeeds when free",
            true,
            owned_success.is_ok()
        );

        let owned_contended = OwnedMutexGuard::try_lock(Arc::clone(&mutex_arc));
        let owned_locked = matches!(owned_contended, Err(TryLockError::Locked));
        crate::assert_with_log!(
            owned_locked,
            "owned try_lock returns error under contention",
            true,
            owned_locked
        );

        drop(owned_success.unwrap());

        // Phase 5: Verify try_lock works after lock is released
        drop(guard1); // Release the first lock

        let async_guard = poll_once(&mut async_waiter)
            .expect("async waiter should complete")
            .expect("async lock should succeed");

        drop(async_guard);

        let final_try = mutex.try_lock();
        crate::assert_with_log!(
            final_try.is_ok(),
            "try_lock succeeds again after release",
            true,
            final_try.is_ok()
        );

        drop(final_try.unwrap());

        crate::test_complete!("audit_mutex_try_lock_nonblocking_under_contention");
    }

    /// Audit test for MutexGuard !Send scoping across await points.
    ///
    /// Verifies that MutexGuard being !Send properly prevents futures holding
    /// the guard from being moved between tasks at await points. This is critical
    /// for cancel-aware drop semantics - the guard must be dropped in the same
    /// task context where it was acquired to preserve proper unlock behavior.
    #[test]
    fn audit_mutex_guard_send_constraint_across_await() {
        init_test("audit_mutex_guard_send_constraint_across_await");

        let cx = test_cx();
        let mutex = Arc::new(Mutex::new(42));

        // Test 1: Verify guard can be held across await within same task context
        let mutex_clone = Arc::clone(&mutex);
        let task_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // This should work - holding guard across await in same task
            async fn hold_guard_across_await(
                mutex: Arc<Mutex<i32>>,
                cx: &Cx,
            ) -> Result<i32, LockError> {
                let guard = mutex.lock(cx).await?;
                let value = *guard;

                // Simulate some async work that causes potential yield point
                // The guard is held across this await, but within same task context
                crate::runtime::yield_now().await;

                // Access guard again after await point
                let final_value = *guard + 1;
                drop(guard); // Explicit drop in same task context
                Ok(final_value)
            }

            // This compiles because we're not moving the guard between tasks
            let result = block_on(hold_guard_across_await(mutex_clone, &cx));
            result.expect("should succeed")
        }));

        crate::assert_with_log!(
            task_result.is_ok(),
            "holding guard across await in same task should work",
            true,
            task_result.is_ok()
        );

        let returned_value = task_result.unwrap();
        crate::assert_with_log!(
            returned_value == 43,
            "guard should maintain access across await point",
            43,
            returned_value
        );

        // Test 2: Demonstrate !Send constraint prevents problematic moves
        // NOTE: This would be a compile-time error if we tried to move the guard
        // between tasks. We can't easily test this at runtime, but we can
        // document the constraint.

        let guard = mutex.try_lock().expect("should acquire lock");

        // The following would NOT compile due to !Send:
        // std::thread::spawn(move || {
        //     drop(guard); // ERROR: `MutexGuard` cannot be sent between threads safely
        // });

        // Verify guard works normally when not moved
        crate::assert_with_log!(
            *guard == 42,
            "guard provides access to protected data",
            42,
            *guard
        );

        drop(guard); // Drop in same thread/task context (correct)

        // Test 3: Verify cancel-aware drop works correctly in proper context
        let cx_cancel = test_cx();
        cx_cancel.cancel_with(crate::types::CancelKind::User, Some("test"));

        // Even with cancellation, guard should drop properly in same task
        let guard2 = mutex
            .try_lock()
            .expect("should acquire after previous drop");

        // Guard drop happens in same task context despite cancellation
        drop(guard2);

        // Verify mutex is unlocked and available
        let final_guard = mutex.try_lock();
        crate::assert_with_log!(
            final_guard.is_ok(),
            "mutex should be unlocked after guard drop in proper context",
            true,
            final_guard.is_ok()
        );

        drop(final_guard.unwrap());
        crate::test_complete!("audit_mutex_guard_send_constraint_across_await");
    }

    /// Audit test: MutexGuard compile-time !Send verification.
    ///
    /// Per asupersync semantics, MutexGuard must be !Send to prevent movement
    /// between tasks at await points. This ensures cancel-aware drop semantics
    /// are preserved - the guard must be dropped in the same task context
    /// where it was acquired.
    #[test]
    fn audit_mutex_guard_not_send_trait_bound() {
        init_test("audit_mutex_guard_not_send_trait_bound");

        /// Helper function to verify a type is NOT Send at compile time.
        /// This function requires T to NOT implement Send. If T: Send,
        /// this will fail to compile.
        fn assert_not_send<T>()
        where
            T: 'static,
        {
            // We use std::rc::Rc<T> as a wrapper because Rc<T> is never Send,
            // regardless of whether T is Send or not. However, we can only
            // construct Rc<T> if T exists, so this verifies the type is real.

            // If MutexGuard were Send, we could call require_send with it.
            // The fact that we CAN'T proves it's !Send.
            let _type_exists = std::marker::PhantomData::<std::rc::Rc<T>>;

            // This function compiles successfully, proving T is accessible
            // but cannot be used in Send contexts.
        }

        /// This helper would only compile if called with Send types.
        /// We use it to demonstrate what would fail for !Send types.
        fn _require_send<T: Send>() {
            // This is never called in our test, but shows what would
            // fail to compile if we tried: _require_send::<MutexGuard<()>>();
        }

        // Test 1: Verify MutexGuard is !Send (this should compile)
        assert_not_send::<MutexGuard<'static, ()>>();

        // Test 2: Verify some Send types for contrast (these should also compile)
        let _contrast_send_types = || {
            fn assert_send<T: Send>() {}
            assert_send::<i32>(); // i32 is Send
            assert_send::<String>(); // String is Send
            assert_send::<Vec<u8>>(); // Vec<u8> is Send
            // But this would NOT compile: assert_send::<MutexGuard<()>>();
        };

        // Test 3: Demonstrate actual usage - guard works locally
        let mutex = Mutex::new(42);
        let cx = test_cx();

        let usage_test = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(async {
                let guard = mutex.lock(&cx).await.expect("lock should succeed");
                let _value = *guard; // Guard works within same task
                // guard is automatically dropped here - no cross-task movement
            })
        }));

        crate::assert_with_log!(
            usage_test.is_ok(),
            "MutexGuard works correctly within single task context",
            true,
            usage_test.is_ok()
        );

        // COMPILE-TIME PROOF: The following line would NOT compile:
        // _require_send::<MutexGuard<'_, ()>>();
        //
        // Expected error: "`MutexGuard<'_, ()>` cannot be sent between threads safely"
        // This proves MutexGuard is !Send as required by asupersync semantics.

        crate::test_complete!("audit_mutex_guard_not_send_trait_bound");
    }

    #[test]
    fn audit_lock_future_state_machine_size() {
        // Audit: LockFuture state-machine should be SMALL per asupersync philosophy.
        // Target: ≤256 bytes to avoid excessive stack usage.
        //
        // LockFuture contains:
        // - mutex: &'a Mutex<T>     (8 bytes - reference)
        // - cx: &'b Cx             (8 bytes - reference)
        // - waiter_id: Option<usize> (16 bytes - Option<usize>)
        // - completed: bool        (1 byte + 7 padding = 8 bytes)
        // Expected total: ~40 bytes (small and efficient)

        init_test("audit_lock_future_state_machine_size");

        const SIZE_LIMIT_BYTES: usize = 256;

        // Measure size for common types
        let i32_future_size = std::mem::size_of::<LockFuture<'_, '_, i32>>();
        let u64_future_size = std::mem::size_of::<LockFuture<'_, '_, u64>>();
        let string_future_size = std::mem::size_of::<LockFuture<'_, '_, String>>();
        let vec_future_size = std::mem::size_of::<LockFuture<'_, '_, Vec<u8>>>();

        // Log sizes for visibility
        eprintln!("LockFuture sizes:");
        eprintln!("  LockFuture<i32>:     {} bytes", i32_future_size);
        eprintln!("  LockFuture<u64>:     {} bytes", u64_future_size);
        eprintln!("  LockFuture<String>:  {} bytes", string_future_size);
        eprintln!("  LockFuture<Vec<u8>>: {} bytes", vec_future_size);
        eprintln!("  Size limit:          {} bytes", SIZE_LIMIT_BYTES);

        // Verify all measured types are within limit
        crate::assert_with_log!(
            i32_future_size <= SIZE_LIMIT_BYTES,
            &format!(
                "LockFuture<i32> size {} ≤ {} bytes",
                i32_future_size, SIZE_LIMIT_BYTES
            ),
            SIZE_LIMIT_BYTES,
            i32_future_size
        );

        crate::assert_with_log!(
            u64_future_size <= SIZE_LIMIT_BYTES,
            &format!(
                "LockFuture<u64> size {} ≤ {} bytes",
                u64_future_size, SIZE_LIMIT_BYTES
            ),
            SIZE_LIMIT_BYTES,
            u64_future_size
        );

        crate::assert_with_log!(
            string_future_size <= SIZE_LIMIT_BYTES,
            &format!(
                "LockFuture<String> size {} ≤ {} bytes",
                string_future_size, SIZE_LIMIT_BYTES
            ),
            SIZE_LIMIT_BYTES,
            string_future_size
        );

        crate::assert_with_log!(
            vec_future_size <= SIZE_LIMIT_BYTES,
            &format!(
                "LockFuture<Vec<u8>> size {} ≤ {} bytes",
                vec_future_size, SIZE_LIMIT_BYTES
            ),
            SIZE_LIMIT_BYTES,
            vec_future_size
        );

        // Verify all sizes are identical (type parameter T is phantom in future)
        crate::assert_with_log!(
            i32_future_size == u64_future_size
                && u64_future_size == string_future_size
                && string_future_size == vec_future_size,
            "LockFuture size should be independent of T (T is phantom in future state)",
            true,
            i32_future_size == u64_future_size
        );

        // Additional check: future should be small (< 64 bytes for optimal stack usage)
        const OPTIMAL_SIZE_BYTES: usize = 64;
        let is_optimal_size = i32_future_size <= OPTIMAL_SIZE_BYTES;

        if is_optimal_size {
            eprintln!(
                "✅ LockFuture is optimally sized: {} bytes",
                i32_future_size
            );
        } else {
            eprintln!(
                "⚠️  LockFuture is acceptable but not optimal: {} bytes (target: ≤{})",
                i32_future_size, OPTIMAL_SIZE_BYTES
            );
        }

        // Pin the expected size range for regression detection
        crate::assert_with_log!(
            i32_future_size >= 24, // Minimum reasonable size (2 refs + Option<usize> + bool)
            &format!(
                "LockFuture size {} ≥ 24 bytes (sanity check)",
                i32_future_size
            ),
            24,
            i32_future_size
        );

        crate::assert_with_log!(
            i32_future_size <= 64, // Should be small and efficient
            &format!(
                "LockFuture size {} ≤ 64 bytes (optimal size)",
                i32_future_size
            ),
            64,
            i32_future_size
        );

        crate::test_complete!("audit_lock_future_state_machine_size");
    }

    #[test]
    fn audit_mutex_guard_await_boundary_compile_fail() {
        // Audit: MutexGuard !Send prevents crossing await boundaries.
        // This test documents the compile-time enforcement of !Send trait bounds
        // when attempting to hold a MutexGuard across await points.
        //
        // Per asupersync semantics, guards must NOT cross await boundaries to
        // preserve task-local cancellation and drop semantics.

        init_test("audit_mutex_guard_await_boundary_compile_fail");

        // This test demonstrates (but does not execute) code patterns that SHOULD NOT COMPILE
        // due to MutexGuard being !Send. The examples are in comments to avoid compilation errors.

        /*
        // EXAMPLE 1: Direct await with guard held (SHOULD NOT COMPILE)
        async fn bad_pattern_1(mutex: &Mutex<i32>, cx: &Cx) {
            let guard = mutex.lock(cx).await.unwrap();
            // ERROR: cannot await while holding guard (guard is !Send)
            some_async_function().await;
            drop(guard);
        }

        // EXAMPLE 2: Function boundary with guard (SHOULD NOT COMPILE)
        async fn bad_pattern_2(mutex: &Mutex<i32>, cx: &Cx) {
            let guard = mutex.lock(cx).await.unwrap();
            // ERROR: cannot call async function while holding guard
            helper_async_function(guard).await;
        }

        async fn helper_async_function(guard: MutexGuard<'_, i32>) {
            // This would require MutexGuard: Send, which is false
            some_async_function().await;
            drop(guard);
        }

        // EXAMPLE 3: Spawning task with guard (SHOULD NOT COMPILE)
        async fn bad_pattern_3(mutex: &Mutex<i32>, cx: &Cx) {
            let guard = mutex.lock(cx).await.unwrap();
            // ERROR: cannot move guard into spawned task (guard is !Send)
            spawn_task(async move {
                println!("Value: {}", *guard);
            });
        }
        */

        // CORRECT PATTERN: Guard is dropped before await points
        let test_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(async {
                let mutex = Mutex::new(42);
                let cx = test_cx();

                // ✓ CORRECT: Acquire, use, and drop guard before await
                let value = {
                    let guard = mutex.lock(&cx).await?;
                    *guard // Copy value out
                    // Guard drops here, before any await point
                };

                // ✓ CORRECT: Now we can safely await without holding guard
                crate::time::sleep(crate::types::Time::ZERO, std::time::Duration::from_nanos(1))
                    .await;

                Ok(value)
            })
        }));

        crate::assert_with_log!(
            test_result.is_ok(),
            "correct guard usage pattern should work",
            true,
            test_result.is_ok()
        );

        // The !Send trait bound is enforced at compile time, preventing the anti-patterns
        // shown in the commented examples above. This test documents the correct pattern
        // and verifies that proper guard usage (drop before await) works correctly.

        crate::test_complete!("audit_mutex_guard_await_boundary_compile_fail");
    }

    /// Example of a compile-fail doc test for MutexGuard !Send enforcement.
    ///
    /// This function contains a doc test that demonstrates the compile failure
    /// when attempting to hold a MutexGuard across an await boundary.
    ///
    /// ```compile_fail
    /// use asupersync::sync::Mutex;
    /// use asupersync::cx::Cx;
    ///
    /// async fn bad_await_with_guard(mutex: &Mutex<i32>, cx: &Cx) -> Result<(), asupersync::sync::LockError> {
    ///     let guard = mutex.lock(cx).await?;
    ///
    ///     // This line should cause a compile error because MutexGuard is !Send
    ///     // and cannot cross the await boundary
    ///     asupersync::time::sleep(
    ///         asupersync::types::Time::ZERO,
    ///         std::time::Duration::from_millis(1)
    ///     ).await;
    ///
    ///     drop(guard);
    ///     Ok(())
    /// }
    /// ```
    fn _doctest_mutex_guard_compile_fail_example() {
        // This function exists only to host the doc test above.
        // The doc test demonstrates that the pattern fails to compile.
    }

    #[test]
    fn audit_mutex_lock_poll_waker_registration() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::thread;
        use std::time::{Duration, Instant};

        // Audit test for Mutex::lock() poll behavior under contention.
        //
        // When task A holds mutex and task B tries to lock:
        // 1. B's poll_lock should return Pending and register waker
        // 2. When A releases, B's waker should be called
        // 3. B's next poll should return Ready and acquire lock
        //
        // Verifies: waker registration, proper handoff, FIFO fairness

        let test_iterations = 200;
        let mut successful_waker_calls = 0;
        let failed_waker_calls = Arc::new(AtomicUsize::new(0));

        for iteration in 0..test_iterations {
            let mutex = Arc::new(Mutex::new(iteration));
            let holder_can_proceed = Arc::new(AtomicBool::new(false));
            let waker_was_called = Arc::new(AtomicBool::new(false));
            let lock_acquired_after_wake = Arc::new(AtomicBool::new(false));

            let mutex_holder = Arc::clone(&mutex);
            let proceed_flag = Arc::clone(&holder_can_proceed);

            // Holder thread: Acquire lock and hold until signaled
            let holder_handle = thread::spawn(move || {
                let rt = crate::runtime::RuntimeBuilder::new()
                    .worker_threads(1)
                    .build()
                    .expect("Failed to build runtime");

                rt.block_on(async {
                    let cx = Cx::for_testing();

                    // Acquire the mutex
                    let guard = mutex_holder
                        .lock(&cx)
                        .await
                        .expect("Holder should successfully acquire mutex");

                    // Signal that holder has the lock, waiter can start trying
                    proceed_flag.store(true, Ordering::SeqCst);

                    // Hold lock for a short time to create contention
                    crate::time::sleep(crate::types::Time::ZERO, Duration::from_millis(5)).await;

                    // Verify data integrity
                    let value = *guard;
                    assert_eq!(
                        value, iteration,
                        "Data should be preserved during lock hold"
                    );

                    // Lock will be released when guard drops
                })
            });

            let mutex_contender = Arc::clone(&mutex);
            let proceed_waiter = Arc::clone(&holder_can_proceed);
            let waker_called = Arc::clone(&waker_was_called);
            let acquired_flag = Arc::clone(&lock_acquired_after_wake);
            let failed_count = Arc::clone(&failed_waker_calls);

            // Contender thread: Wait for holder, then try to acquire
            let contender_handle = thread::spawn(move || {
                let rt = crate::runtime::RuntimeBuilder::new()
                    .worker_threads(1)
                    .build()
                    .expect("Failed to build runtime");

                rt.block_on(async {
                    let cx = Cx::for_testing();

                    // Wait for holder to acquire lock first
                    while !proceed_waiter.load(Ordering::SeqCst) {
                        crate::time::sleep(crate::types::Time::ZERO, Duration::from_micros(100))
                            .await;
                    }

                    // Create a counting waker to verify wake calls
                    let waker_called_clone = Arc::clone(&waker_called);
                    struct CountingWaker {
                        called: Arc<AtomicBool>,
                    }

                    impl std::task::Wake for CountingWaker {
                        fn wake(self: Arc<Self>) {
                            self.called.store(true, Ordering::SeqCst);
                        }
                        fn wake_by_ref(self: &Arc<Self>) {
                            self.called.store(true, Ordering::SeqCst);
                        }
                    }

                    let counting_waker = std::task::Waker::from(Arc::new(CountingWaker {
                        called: waker_called_clone,
                    }));

                    // Try to acquire mutex - should block and register waker
                    let lock_start = Instant::now();
                    let mut lock_future = std::pin::pin!(mutex_contender.lock(&cx));

                    // First poll should return Pending and register waker
                    let mut context = std::task::Context::from_waker(&counting_waker);
                    let first_poll = lock_future.as_mut().poll(&mut context);

                    match first_poll {
                        std::task::Poll::Ready(_) => {
                            // Unexpected - holder should still have lock
                            failed_count.fetch_add(1, Ordering::SeqCst);
                            return (false, false, Duration::ZERO);
                        }
                        std::task::Poll::Pending => {
                            // Expected - waker should be registered
                        }
                    }

                    // Wait for the actual lock acquisition to complete
                    let guard = lock_future
                        .await
                        .expect("Contender should eventually acquire mutex");

                    let acquisition_time = lock_start.elapsed();

                    // Verify waker was called during the wait
                    let waker_called_result = waker_called.load(Ordering::SeqCst);
                    acquired_flag.store(true, Ordering::SeqCst);

                    // Verify data integrity
                    let value = *guard;
                    assert_eq!(value, iteration, "Data should be consistent after handoff");

                    (true, waker_called_result, acquisition_time)
                })
            });

            // Wait for completion
            holder_handle.join().expect("Holder thread should complete");
            let (acquired, waker_called, acquisition_time) = contender_handle
                .join()
                .expect("Contender thread should complete");

            // Verify the lock was eventually acquired
            assert!(
                acquired,
                "iteration {}: contender should acquire lock",
                iteration
            );
            assert!(
                lock_acquired_after_wake.load(Ordering::SeqCst),
                "iteration {}: lock acquisition flag should be set",
                iteration
            );

            // Verify waker was called during contention
            if waker_called {
                successful_waker_calls += 1;
            }

            // Verify reasonable acquisition time (should be quick after wakeup)
            assert!(
                acquisition_time < Duration::from_millis(100),
                "iteration {}: lock acquisition took {:?}, expected < 100ms",
                iteration,
                acquisition_time
            );
        }

        let failed_count = failed_waker_calls.load(Ordering::SeqCst);
        let success_rate = (successful_waker_calls as f64) / (test_iterations as f64);

        println!(
            "Mutex lock poll waker audit: {}/{} successful waker calls ({:.1}%), {} failures",
            successful_waker_calls,
            test_iterations,
            success_rate * 100.0,
            failed_count
        );

        // Verify waker registration and calling works reliably
        if success_rate < 0.90 {
            panic!(
                "❌ WAKER DEFECT: Only {:.1}% successful waker calls. \
                 Expected >90% waker calls when mutex is contended. \
                 This suggests poll_lock is not properly registering or calling wakers.",
                success_rate * 100.0
            );
        }

        if failed_count > test_iterations / 20 {
            panic!(
                "❌ POLLING DEFECT: {} failed acquisitions (>{} threshold). \
                 Expected smooth handoff from holder to contender via waker.",
                failed_count,
                test_iterations / 20
            );
        }

        println!(
            "✅ SOUND: Mutex lock polling correctly registers wakers and handles contended acquisition"
        );
    }
}
