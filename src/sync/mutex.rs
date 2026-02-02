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

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

/// Error returned when mutex locking fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockError {
    /// The mutex was poisoned (a panic occurred while holding the lock).
    Poisoned,
    /// Cancelled while waiting for the lock.
    Cancelled,
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => write!(f, "mutex poisoned"),
            Self::Cancelled => write!(f, "mutex lock cancelled"),
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
    state: StdMutex<MutexState>,
}

// Safety: Mutex is Send/Sync if T is Send.
unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

#[derive(Debug)]
struct MutexState {
    /// Whether the mutex is currently locked.
    locked: bool,
    /// Queue of waiters.
    waiters: VecDeque<Waiter>,
}

#[derive(Debug)]
struct Waiter {
    waker: Waker,
    queued: Arc<AtomicBool>,
}

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            data: UnsafeCell::new(value),
            poisoned: AtomicBool::new(false),
            state: StdMutex::new(MutexState {
                locked: false,
                waiters: VecDeque::new(),
            }),
        }
    }

    /// Returns true if the mutex is poisoned.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Returns true if the mutex is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state.lock().expect("mutex state lock poisoned").locked
    }

    /// Returns the number of tasks currently waiting for the lock.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.state
            .lock()
            .expect("mutex state lock poisoned")
            .waiters
            .len()
    }

    /// Acquires the mutex asynchronously.
    pub fn lock<'a, 'b>(&'a self, cx: &'b Cx) -> LockFuture<'a, 'b, T> {
        LockFuture {
            mutex: self,
            cx,
            waiter: None,
        }
    }

    /// Tries to acquire the mutex without waiting.
    pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, TryLockError> {
        if self.is_poisoned() {
            return Err(TryLockError::Poisoned);
        }

        let mut state = self.state.lock().expect("mutex state lock poisoned");
        if state.locked {
            return Err(TryLockError::Locked);
        }

        state.locked = true;
        drop(state);

        Ok(MutexGuard { mutex: self })
    }

    /// Returns a mutable reference to the underlying data.
    pub fn get_mut(&mut self) -> &mut T {
        assert!(!self.is_poisoned(), "mutex is poisoned");
        self.data.get_mut()
    }

    /// Consumes the mutex, returning the underlying data.
    pub fn into_inner(self) -> T {
        assert!(!self.is_poisoned(), "mutex is poisoned");
        self.data.into_inner()
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn unlock(&self) {
        // Extract the waker to wake outside the lock to prevent deadlocks.
        // Waking while holding the lock can cause priority inversion or deadlock
        // if the woken task tries to acquire another mutex.
        let waker_to_wake = {
            let mut state = self.state.lock().expect("mutex state lock poisoned");
            state.locked = false;
            loop {
                match state.waiters.pop_front() {
                    Some(waiter) if waiter.queued.swap(false, Ordering::AcqRel) => {
                        break Some(waiter.waker);
                    }
                    Some(_) => {}
                    None => break None,
                }
            }
        };
        // Wake outside the lock
        if let Some(waker) = waker_to_wake {
            waker.wake();
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// Future returned by `Mutex::lock`.
pub struct LockFuture<'a, 'b, T> {
    mutex: &'a Mutex<T>,
    cx: &'b Cx,
    waiter: Option<Arc<AtomicBool>>,
}

impl<'a, T> Future for LockFuture<'a, '_, T> {
    type Output = Result<MutexGuard<'a, T>, LockError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        // Check cancellation
        if let Err(_e) = self.cx.checkpoint() {
            return Poll::Ready(Err(LockError::Cancelled));
        }

        if self.mutex.is_poisoned() {
            return Poll::Ready(Err(LockError::Poisoned));
        }

        let mut state = self.mutex.state.lock().expect("mutex state lock poisoned");

        if !state.locked {
            // Acquire lock
            state.locked = true;
            if let Some(waiter) = self.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            return Poll::Ready(Ok(MutexGuard { mutex: self.mutex }));
        }

        // Register waiter or update existing waker. We must update the waker
        // when it changes because some executors provide different wakers on
        // each poll - failing to update would cause the task to never be woken.
        let mut new_waiter = None;
        match self.waiter.as_ref() {
            Some(waiter) if !waiter.load(Ordering::Acquire) => {
                // Was dequeued by unlock() but we're still waiting - re-register
                waiter.store(true, Ordering::Release);
                state.waiters.push_back(Waiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(waiter),
                });
            }
            Some(waiter) => {
                // Already queued - update the waker in case it changed.
                // This is critical for correctness with executors that provide
                // new wakers on each poll.
                if let Some(existing) = state
                    .waiters
                    .iter_mut()
                    .find(|w| Arc::ptr_eq(&w.queued, waiter))
                {
                    existing.waker.clone_from(context.waker());
                }
            }
            None => {
                let waiter = Arc::new(AtomicBool::new(true));
                state.waiters.push_back(Waiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(&waiter),
                });
                new_waiter = Some(waiter);
            }
        }
        drop(state);
        if let Some(waiter) = new_waiter {
            self.waiter = Some(waiter);
        }

        Poll::Pending
    }
}

/// A guard that releases the mutex when dropped.
#[must_use = "guard will be immediately released if not held"]
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

unsafe impl<T: Send> Send for MutexGuard<'_, T> {}
unsafe impl<T: Sync> Sync for MutexGuard<'_, T> {}

impl<T: std::fmt::Debug> std::fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutexGuard").field("data", &**self).finish()
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
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
        // Reuse the logic from LockFuture or reimplement?
        // Since we need to return OwnedMutexGuard, we can't use LockFuture directly
        // unless we change it to be generic over the guard type or use a helper.
        // Re-implementing for simplicity (or use a shared internal lock async fn).

        struct OwnedLockFuture<T> {
            mutex: Arc<Mutex<T>>,
            cx: Cx, // clone of cx
            waiter: Option<Arc<AtomicBool>>,
        }

        impl<T> Future for OwnedLockFuture<T> {
            type Output = Result<OwnedMutexGuard<T>, LockError>;
            fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
                if self.cx.checkpoint().is_err() {
                    return Poll::Ready(Err(LockError::Cancelled));
                }
                if self.mutex.is_poisoned() {
                    return Poll::Ready(Err(LockError::Poisoned));
                }
                let mut state = self.mutex.state.lock().expect("mutex state poisoned");
                if !state.locked {
                    state.locked = true;
                    if let Some(waiter) = self.waiter.as_ref() {
                        waiter.store(false, Ordering::Release);
                    }
                    return Poll::Ready(Ok(OwnedMutexGuard {
                        mutex: self.mutex.clone(),
                    }));
                }
                let mut new_waiter = None;
                match self.waiter.as_ref() {
                    Some(waiter) if !waiter.load(Ordering::Acquire) => {
                        // Was dequeued by unlock() but we're still waiting - re-register
                        waiter.store(true, Ordering::Release);
                        state.waiters.push_back(Waiter {
                            waker: context.waker().clone(),
                            queued: Arc::clone(waiter),
                        });
                    }
                    Some(waiter) => {
                        // Already queued - update the waker in case it changed.
                        if let Some(existing) = state
                            .waiters
                            .iter_mut()
                            .find(|w| Arc::ptr_eq(&w.queued, waiter))
                        {
                            existing.waker.clone_from(context.waker());
                        }
                    }
                    None => {
                        let waiter = Arc::new(AtomicBool::new(true));
                        state.waiters.push_back(Waiter {
                            waker: context.waker().clone(),
                            queued: Arc::clone(&waiter),
                        });
                        new_waiter = Some(waiter);
                    }
                }
                drop(state);
                if let Some(waiter) = new_waiter {
                    self.waiter = Some(waiter);
                }
                Poll::Pending
            }
        }

        OwnedLockFuture {
            mutex,
            cx: cx.clone(),
            waiter: None,
        }
        .await
    }

    /// Tries to acquire the mutex without waiting.
    pub fn try_lock(mutex: Arc<Mutex<T>>) -> Result<Self, TryLockError> {
        if mutex.is_poisoned() {
            return Err(TryLockError::Poisoned);
        }
        {
            let mut state = mutex.state.lock().expect("mutex state poisoned");
            if state.locked {
                return Err(TryLockError::Locked);
            }
            state.locked = true;
        }
        Ok(Self { mutex })
    }
}

impl<T> Deref for OwnedMutexGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for OwnedMutexGuard<T> {
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
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};

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

    fn poll_once<T>(future: &mut impl Future<Output = T>) -> Option<T> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match unsafe { Pin::new_unchecked(future) }.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn poll_until_ready<T>(future: &mut impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match unsafe { Pin::new_unchecked(&mut *future) }.poll(&mut cx) {
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
}
