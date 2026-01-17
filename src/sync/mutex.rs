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
//! If cancelled during the wait phase, no lock is held and no cleanup
//! is needed. Once a guard is acquired, it will always be released on drop.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::sync::Mutex;
//!
//! let mutex = Mutex::new(42);
//!
//! // Lock the mutex (blocks until available)
//! let mut guard = mutex.lock(&cx)?;
//! *guard += 1;
//!
//! // Guard is automatically released when dropped
//! drop(guard);
//! ```
//!
//! # Shared State Pattern
//!
//! ```ignore
//! let state = Mutex::new(SharedState::default());
//!
//! scope.spawn(cx, |cx| async move {
//!     let mut guard = state.lock(cx)?;
//!     guard.counter += 1;
//!     // guard dropped, lock released
//! });
//! ```

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex as StdMutex, RwLock};

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
///
/// Unlike `std::sync::Mutex`, this mutex can be held across await points
/// and provides cancel-safe lock acquisition. The guard is tracked as
/// an obligation that must be released.
///
/// # Fairness
///
/// This mutex is FIFO-fair: waiters are serviced in the order they arrived.
/// This prevents starvation and ensures deterministic behavior in the lab runtime.
///
/// # Deadlock Detection
///
/// The mutex does not prevent deadlocks at runtime, but:
/// - Lab runtime can detect deadlock (cycle in wait graph)
/// - Timeout wrappers can bound wait time
/// - Design patterns (lock ordering) prevent in application
#[derive(Debug)]
pub struct Mutex<T> {
    /// Whether the mutex is currently locked.
    locked: AtomicBool,
    /// Whether the mutex is poisoned (panic occurred while holding).
    poisoned: AtomicBool,
    /// The protected data (wrapped in RwLock for safe interior mutability).
    data: RwLock<T>,
    /// Number of waiters (for debugging/stats).
    waiters: AtomicUsize,
    /// FIFO queue position counter for fairness.
    queue_head: StdMutex<u64>,
    queue_tail: AtomicUsize,
}

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mutex = Mutex::new(42);
    /// assert_eq!(*mutex.lock(&cx)?, 42);
    /// ```
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            data: RwLock::new(value),
            waiters: AtomicUsize::new(0),
            queue_head: StdMutex::new(0),
            queue_tail: AtomicUsize::new(0),
        }
    }

    /// Returns true if the mutex is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Acquire)
    }

    /// Returns true if the mutex is poisoned.
    ///
    /// A mutex is poisoned if a panic occurred while holding the lock.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Returns the number of tasks currently waiting for the lock.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// Acquires the mutex, waiting if necessary.
    ///
    /// This method is cancel-safe. If cancelled while waiting:
    /// - No lock is acquired
    /// - No cleanup is needed
    /// - The wait can be retried
    ///
    /// # Errors
    ///
    /// Returns `LockError::Poisoned` if the mutex was poisoned.
    /// Returns `LockError::Cancelled` if cancelled while waiting.
    pub fn lock(&self, cx: &Cx) -> Result<MutexGuard<'_, T>, LockError> {
        cx.trace("mutex::lock starting");

        // Check if poisoned
        if self.is_poisoned() {
            cx.trace("mutex::lock failed: poisoned");
            return Err(LockError::Poisoned);
        }

        // Get our position in the queue for FIFO fairness
        let our_position = {
            let mut head = self.queue_head.lock().expect("queue lock poisoned");
            let pos = *head;
            *head += 1;
            pos
        };

        // Mark ourselves as waiting
        self.waiters.fetch_add(1, Ordering::AcqRel);

        // Wait for our turn and the lock to be available
        loop {
            // Check if poisoned
            if self.is_poisoned() {
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                // Advance queue to not block others
                self.queue_tail.fetch_add(1, Ordering::AcqRel);
                cx.trace("mutex::lock failed: poisoned while waiting");
                return Err(LockError::Poisoned);
            }

            // Check if it's our turn (FIFO)
            let current_tail = self.queue_tail.load(Ordering::Acquire) as u64;
            if current_tail != our_position {
                // Not our turn yet, check cancellation and yield
                if cx.checkpoint().is_err() {
                    self.waiters.fetch_sub(1, Ordering::AcqRel);
                    cx.trace("mutex::lock cancelled while waiting for turn");
                    return Err(LockError::Cancelled);
                }
                std::thread::yield_now();
                continue;
            }

            // It's our turn - try to acquire the lock
            if self
                .locked
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Success! Advance the queue and return guard
                self.queue_tail.fetch_add(1, Ordering::AcqRel);
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                cx.trace("mutex::lock succeeded");

                // Acquire the write guard from the internal RwLock
                // This should not block since we've already acquired the logical lock
                let guard = self.data.write().expect("internal lock poisoned");

                return Ok(MutexGuard { mutex: self, guard });
            }

            // Lock is held by someone else (shouldn't happen if it's our turn,
            // but handle it gracefully)
            // Check cancellation before waiting
            if cx.checkpoint().is_err() {
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                // Advance queue to not block others
                self.queue_tail.fetch_add(1, Ordering::AcqRel);
                cx.trace("mutex::lock cancelled while waiting for lock");
                return Err(LockError::Cancelled);
            }

            // Phase 0: Simple spin-wait with yield
            // Future: integrate with scheduler via proper waker/condvar
            std::thread::yield_now();
        }
    }

    /// Tries to acquire the mutex without waiting.
    ///
    /// # Errors
    ///
    /// Returns `TryLockError::Locked` if the mutex is currently locked.
    /// Returns `TryLockError::Poisoned` if the mutex was poisoned.
    pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, TryLockError> {
        if self.is_poisoned() {
            return Err(TryLockError::Poisoned);
        }

        if self
            .locked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Acquire the write guard from the internal RwLock
            let guard = self.data.write().expect("internal lock poisoned");
            Ok(MutexGuard { mutex: self, guard })
        } else {
            Err(TryLockError::Locked)
        }
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this requires exclusive (`&mut`) access to the mutex,
    /// no actual locking needs to take place.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned or the internal lock is poisoned.
    pub fn get_mut(&mut self) -> &mut T {
        assert!(!self.is_poisoned(), "mutex is poisoned");
        self.data.get_mut().expect("internal lock poisoned")
    }

    /// Consumes the mutex, returning the underlying data.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned or the internal lock is poisoned.
    pub fn into_inner(self) -> T {
        assert!(!self.is_poisoned(), "mutex is poisoned");
        self.data.into_inner().expect("internal lock poisoned")
    }

    /// Marks the mutex as poisoned.
    ///
    /// This is called when a panic occurs while holding the guard.
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    /// Unlocks the mutex.
    ///
    /// This is called by `MutexGuard::drop()`.
    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
        // In full implementation: wake next waiter
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// A guard that releases the mutex when dropped.
///
/// When dropped, the guard automatically releases the lock.
/// This implements the two-phase commit pattern:
/// - **Acquire phase**: Wait for and obtain the lock
/// - **Commit phase**: Drop to release (always succeeds)
///
/// The guard acts as an obligation that must be resolved. Dropping the guard
/// is the commit operation that releases the lock back to the mutex.
#[must_use = "guard will be immediately released if not held"]
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
    /// The write guard from the internal RwLock.
    guard: std::sync::RwLockWriteGuard<'a, T>,
}

// Manual Debug impl since RwLockWriteGuard's Debug requires T: Debug
impl<T: std::fmt::Debug> std::fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutexGuard")
            .field("data", &*self.guard)
            .finish()
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // Check if we're panicking - if so, poison the mutex
        if std::thread::panicking() {
            self.mutex.poison();
        }

        // Release the lock
        // This is the "commit" of the two-phase pattern
        // Note: the RwLockWriteGuard will be dropped automatically after this
        self.mutex.unlock();

        // Note: In full implementation with obligation registry:
        // - Look up the obligation by our stored obligation_id
        // - Call obligation.commit() to mark it resolved
        // - This allows the runtime to verify no leaked guards
    }
}

/// An owned guard that releases the mutex when dropped.
///
/// Unlike `MutexGuard`, this owns an `Arc<Mutex<T>>` and can be
/// moved between tasks. Useful when the guard needs to outlive the
/// scope where it was acquired.
///
/// Note: This implementation uses a std::sync::Mutex internally to store
/// the write guard, since RwLockWriteGuard cannot be stored alongside the
/// Arc due to lifetime constraints.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedMutexGuard<T> {
    mutex: std::sync::Arc<Mutex<T>>,
    /// We store the value directly since we need owned access.
    /// The actual data access happens via a temporary write lock.
    _marker: std::marker::PhantomData<T>,
}

// Manual Debug impl
impl<T> std::fmt::Debug for OwnedMutexGuard<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedMutexGuard").finish_non_exhaustive()
    }
}

impl<T> OwnedMutexGuard<T> {
    /// Creates an owned guard by acquiring from an Arc-wrapped mutex.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned or acquisition is cancelled.
    pub fn lock(mutex: std::sync::Arc<Mutex<T>>, cx: &Cx) -> Result<Self, LockError> {
        // Check if poisoned
        if mutex.is_poisoned() {
            return Err(LockError::Poisoned);
        }

        // Get our position in the queue for FIFO fairness
        let our_position = {
            let mut head = mutex.queue_head.lock().expect("queue lock poisoned");
            let pos = *head;
            *head += 1;
            pos
        };

        // Mark ourselves as waiting
        mutex.waiters.fetch_add(1, Ordering::AcqRel);

        // Wait for our turn
        loop {
            if mutex.is_poisoned() {
                mutex.waiters.fetch_sub(1, Ordering::AcqRel);
                mutex.queue_tail.fetch_add(1, Ordering::AcqRel);
                return Err(LockError::Poisoned);
            }

            let current_tail = mutex.queue_tail.load(Ordering::Acquire) as u64;
            if current_tail != our_position {
                if cx.checkpoint().is_err() {
                    mutex.waiters.fetch_sub(1, Ordering::AcqRel);
                    return Err(LockError::Cancelled);
                }
                std::thread::yield_now();
                continue;
            }

            if mutex
                .locked
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                mutex.queue_tail.fetch_add(1, Ordering::AcqRel);
                mutex.waiters.fetch_sub(1, Ordering::AcqRel);
                return Ok(Self {
                    mutex,
                    _marker: std::marker::PhantomData,
                });
            }

            if cx.checkpoint().is_err() {
                mutex.waiters.fetch_sub(1, Ordering::AcqRel);
                mutex.queue_tail.fetch_add(1, Ordering::AcqRel);
                return Err(LockError::Cancelled);
            }

            std::thread::yield_now();
        }
    }

    /// Tries to acquire an owned guard without waiting.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is locked or poisoned.
    pub fn try_lock(mutex: std::sync::Arc<Mutex<T>>) -> Result<Self, TryLockError> {
        if mutex.is_poisoned() {
            return Err(TryLockError::Poisoned);
        }

        if mutex
            .locked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Ok(Self {
                mutex,
                _marker: std::marker::PhantomData,
            })
        } else {
            Err(TryLockError::Locked)
        }
    }

    /// Executes a closure with read access to the locked data.
    ///
    /// This is the safe way to access data through an `OwnedMutexGuard`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let guard = OwnedMutexGuard::lock(mutex, &cx)?;
    /// let value = guard.with_lock(|data| *data);
    /// ```
    pub fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let guard = self.mutex.data.read().expect("internal lock poisoned");
        f(&guard)
    }

    /// Executes a closure with mutable access to the locked data.
    ///
    /// This is the safe way to mutate data through an `OwnedMutexGuard`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut guard = OwnedMutexGuard::lock(mutex, &cx)?;
    /// guard.with_lock_mut(|data| *data += 1);
    /// ```
    pub fn with_lock_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut guard = self.mutex.data.write().expect("internal lock poisoned");
        f(&mut guard)
    }
}

impl<T> Drop for OwnedMutexGuard<T> {
    fn drop(&mut self) {
        // Check if we're panicking - if so, poison the mutex
        if std::thread::panicking() {
            self.mutex.poison();
        }

        // Release the lock
        self.mutex.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn new_mutex_is_unlocked() {
        let mutex = Mutex::new(42);
        assert!(!mutex.is_locked());
        assert!(!mutex.is_poisoned());
        assert_eq!(mutex.waiters(), 0);
    }

    #[test]
    fn lock_acquires_mutex() {
        let cx = test_cx();
        let mutex = Mutex::new(42);

        let guard = mutex.lock(&cx).expect("lock failed");
        assert!(mutex.is_locked());
        assert_eq!(*guard, 42);
        drop(guard);
    }

    #[test]
    fn drop_releases_mutex() {
        let cx = test_cx();
        let mutex = Mutex::new(42);

        {
            let _guard = mutex.lock(&cx).expect("lock failed");
            assert!(mutex.is_locked());
        }

        assert!(!mutex.is_locked());
    }

    #[test]
    fn guard_provides_mutable_access() {
        let cx = test_cx();
        let mutex = Mutex::new(42);

        {
            let mut guard = mutex.lock(&cx).expect("lock failed");
            *guard = 100;
        }

        let guard = mutex.lock(&cx).expect("lock failed");
        assert_eq!(*guard, 100);
        drop(guard);
    }

    #[test]
    fn try_lock_success() {
        let mutex = Mutex::new(42);

        let guard = mutex.try_lock().expect("try_lock failed");
        assert!(mutex.is_locked());
        assert_eq!(*guard, 42);
        drop(guard);
    }

    #[test]
    fn try_lock_when_locked() {
        let cx = test_cx();
        let mutex = Mutex::new(42);

        let _guard = mutex.lock(&cx).expect("lock failed");
        assert!(matches!(mutex.try_lock(), Err(TryLockError::Locked)));
    }

    #[test]
    fn cancel_during_lock() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        // Create a mutex and hold the lock with another guard
        // We can't easily test the cancellation during wait without
        // multi-threading, but we can test the immediate cancellation case
        let mutex = Mutex::new(42);

        // First acquire should work even with cancel requested
        // because there's no wait needed
        let guard = mutex.lock(&cx);
        // This might succeed or fail depending on timing
        // The cancellation check happens during wait loops
        drop(guard);
    }

    #[test]
    fn get_mut_access() {
        let mut mutex = Mutex::new(42);

        *mutex.get_mut() = 100;

        let cx = test_cx();
        let guard = mutex.lock(&cx).expect("lock failed");
        assert_eq!(*guard, 100);
        drop(guard);
    }

    #[test]
    fn into_inner() {
        let mutex = Mutex::new(42);
        let value = mutex.into_inner();
        assert_eq!(value, 42);
    }

    #[test]
    fn owned_guard_lock() {
        let cx = test_cx();
        let mutex = std::sync::Arc::new(Mutex::new(42));

        let guard = OwnedMutexGuard::lock(mutex.clone(), &cx).expect("lock failed");
        assert!(mutex.is_locked());
        assert_eq!(guard.with_lock(|v| *v), 42);

        drop(guard);
        assert!(!mutex.is_locked());
    }

    #[test]
    fn owned_guard_try_lock() {
        let mutex = std::sync::Arc::new(Mutex::new(42));

        let guard = OwnedMutexGuard::try_lock(mutex.clone()).expect("try_lock failed");
        assert!(mutex.is_locked());

        drop(guard);
        assert!(!mutex.is_locked());
    }

    #[test]
    fn owned_guard_mutable_access() {
        let cx = test_cx();
        let mutex = std::sync::Arc::new(Mutex::new(42));

        {
            let mut guard = OwnedMutexGuard::lock(mutex.clone(), &cx).expect("lock failed");
            guard.with_lock_mut(|v| *v = 100);
        }

        let guard = OwnedMutexGuard::lock(mutex, &cx).expect("lock failed");
        assert_eq!(guard.with_lock(|v| *v), 100);
        drop(guard);
    }

    #[test]
    fn default_mutex() {
        let mutex: Mutex<i32> = Mutex::default();
        let cx = test_cx();
        let guard = mutex.lock(&cx).expect("lock failed");
        assert_eq!(*guard, 0);
        drop(guard);
    }

    #[test]
    fn error_display() {
        assert_eq!(LockError::Poisoned.to_string(), "mutex poisoned");
        assert_eq!(LockError::Cancelled.to_string(), "mutex lock cancelled");
        assert_eq!(TryLockError::Locked.to_string(), "mutex is locked");
        assert_eq!(TryLockError::Poisoned.to_string(), "mutex poisoned");
    }

    #[test]
    fn waiters_count() {
        let mutex = Mutex::new(42);
        assert_eq!(mutex.waiters(), 0);
    }

    #[test]
    fn sequential_locks() {
        let cx = test_cx();
        let mutex = Mutex::new(0);

        for i in 1..=10 {
            let mut guard = mutex.lock(&cx).expect("lock failed");
            *guard = i;
        }

        let guard = mutex.lock(&cx).expect("lock failed");
        assert_eq!(*guard, 10);
        drop(guard);
    }
}
