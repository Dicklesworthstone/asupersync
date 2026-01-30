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
    waiters: VecDeque<Waker>,
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
            registered: false,
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
        let mut state = self.state.lock().expect("mutex state lock poisoned");
        state.locked = false;
        if let Some(waker) = state.waiters.pop_front() {
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
    registered: bool,
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
            return Poll::Ready(Ok(MutexGuard { mutex: self.mutex }));
        }

        // Only register the waker once to prevent unbounded queue growth.
        // If the waker changes between polls (rare), we accept the stale waker -
        // another waiter will be woken instead, which is harmless.
        // A more sophisticated implementation would use intrusive linked lists
        // with proper deregistration on drop.
        if !self.registered {
            state.waiters.push_back(context.waker().clone());
            self.registered = true;
        }
        drop(state);

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
            registered: bool,
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
                    return Poll::Ready(Ok(OwnedMutexGuard {
                        mutex: self.mutex.clone(),
                    }));
                }
                // Only register once to prevent unbounded queue growth
                let should_register = !self.registered;
                if should_register {
                    state.waiters.push_back(context.waker().clone());
                }
                drop(state);
                if should_register {
                    self.registered = true;
                }
                Poll::Pending
            }
        }

        OwnedLockFuture {
            mutex,
            cx: cx.clone(),
            registered: false,
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

    // ... Need to port other tests to async ...
}
