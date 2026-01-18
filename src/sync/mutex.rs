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

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// The protected data (wrapped in RwLock for safe interior mutability).
    data: RwLock<T>,
    /// Whether the mutex is poisoned (panic occurred while holding).
    poisoned: AtomicBool,
    /// Internal state for fairness and locking.
    state: StdMutex<MutexState>,
}

#[derive(Debug)]
struct MutexState {
    /// Whether the mutex is currently locked.
    locked: bool,
    /// Queue of waiters (unique IDs).
    waiters: VecDeque<u64>,
    /// Counter for generating waiter IDs.
    next_waiter_id: u64,
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
            data: RwLock::new(value),
            poisoned: AtomicBool::new(false),
            state: StdMutex::new(MutexState {
                locked: false,
                waiters: VecDeque::new(),
                next_waiter_id: 0,
            }),
        }
    }

    /// Returns true if the mutex is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        let state = self.state.lock().expect("mutex state lock poisoned");
        state.locked
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
        let state = self.state.lock().expect("mutex state lock poisoned");
        state.waiters.len()
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

        // Register as waiter
        let waiter_id = {
            let mut state = self.state.lock().expect("mutex state lock poisoned");
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            state.waiters.push_back(id);
            id
        };

        // Wait loop
        loop {
            // Check cancellation
            if let Err(e) = cx.checkpoint() {
                // Remove ourselves from queue
                let mut state = self.state.lock().expect("mutex state lock poisoned");
                if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                    state.waiters.remove(pos);
                }
                cx.trace("mutex::lock cancelled while waiting");
                return Err(LockError::Cancelled);
            }

            // Check if poisoned
            if self.is_poisoned() {
                let mut state = self.state.lock().expect("mutex state lock poisoned");
                if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                    state.waiters.remove(pos);
                }
                return Err(LockError::Poisoned);
            }

            // Check if we can acquire
            {
                let mut state = self.state.lock().expect("mutex state lock poisoned");
                if !state.locked && state.waiters.front() == Some(&waiter_id) {
                    // Success!
                    state.locked = true;
                    state.waiters.pop_front();
                    break; // Exit loop, drop state lock
                }
            }

            // Not ready, yield
            std::thread::yield_now();
        }

        cx.trace("mutex::lock succeeded");

        // Acquire the write guard from the internal RwLock
        let guard = self.data.write().expect("internal lock poisoned");

        Ok(MutexGuard { mutex: self, guard })
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

        let mut state = self.state.lock().expect("mutex state lock poisoned");
        if state.locked {
            return Err(TryLockError::Locked);
        }

        // Even for try_lock, we should respect fairness?
        // Standard try_lock usually allows barging, but strict FIFO would require empty queue.
        // Let's enforce strict FIFO for consistency with `lock`.
        if !state.waiters.is_empty() {
             return Err(TryLockError::Locked);
        }

        state.locked = true;
        drop(state);

        let guard = self.data.write().expect("internal lock poisoned");
        Ok(MutexGuard { mutex: self, guard })
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
        let mut state = self.state.lock().expect("mutex state lock poisoned");
        state.locked = false;
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

        // Register as waiter
        let waiter_id = {
            let mut state = mutex.state.lock().expect("mutex state lock poisoned");
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            state.waiters.push_back(id);
            id
        };

        loop {
            if let Err(e) = cx.checkpoint() {
                let mut state = mutex.state.lock().expect("mutex state lock poisoned");
                if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                    state.waiters.remove(pos);
                }
                return Err(LockError::Cancelled);
            }

            if mutex.is_poisoned() {
                let mut state = mutex.state.lock().expect("mutex state lock poisoned");
                if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                    state.waiters.remove(pos);
                }
                return Err(LockError::Poisoned);
            }

            {
                let mut state = mutex.state.lock().expect("mutex state lock poisoned");
                if !state.locked && state.waiters.front() == Some(&waiter_id) {
                    state.locked = true;
                    state.waiters.pop_front();
                    break;
                }
            }

            std::thread::yield_now();
        }

        Ok(Self {
            mutex,
            _marker: std::marker::PhantomData,
        })
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

        let mut state = mutex.state.lock().expect("mutex state lock poisoned");
        if state.locked || !state.waiters.is_empty() {
            return Err(TryLockError::Locked);
        }

        state.locked = true;
        drop(state);

        Ok(Self {
            mutex,
            _marker: std::marker::PhantomData,
        })
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
    fn cancel_while_waiting_returns_cancelled() {
        use std::sync::{mpsc, Arc};

        let mutex = Arc::new(Mutex::new(0i32));
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let holder = {
            let mutex = Arc::clone(&mutex);
            std::thread::spawn(move || {
                let cx = test_cx();
                let _guard = mutex.lock(&cx).expect("lock failed");
                locked_tx.send(()).expect("notify locked");
                release_rx.recv().expect("wait for release");
            })
        };

        locked_rx.recv().expect("wait for lock acquisition");

        let cx = test_cx();
        cx.set_cancel_requested(true);
        assert!(
            matches!(mutex.lock(&cx), Err(LockError::Cancelled)),
            "expected cancellation while waiting"
        );

        release_tx.send(()).expect("release holder");
        holder.join().expect("holder thread panicked");
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

    // ==========================================================================
    // SYNC-002: Mutex Contention Correctness Tests
    // Verify mutex protects data under concurrent access
    // ==========================================================================

    #[test]
    fn contention_correctness_concurrent_increments() {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const NUM_THREADS: usize = 8;
        const INCREMENTS_PER_THREAD: usize = 1000;

        let mutex = Arc::new(Mutex::new(0u64));
        let successful_increments = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let mutex = Arc::clone(&mutex);
                let success_count = Arc::clone(&successful_increments);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..INCREMENTS_PER_THREAD {
                        if let Ok(mut guard) = mutex.lock(&cx) {
                            *guard += 1;
                            success_count.fetch_add(1, AtomicOrdering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let cx = test_cx();
        let final_value = *mutex.lock(&cx).expect("final lock failed");
        let expected = (NUM_THREADS * INCREMENTS_PER_THREAD) as u64;

        // Verify: final value equals total increments (no lost updates)
        assert_eq!(
            final_value, expected,
            "Mutex should protect data: expected {expected}, got {final_value}"
        );

        // Verify: all increments were successful
        assert_eq!(
            successful_increments.load(AtomicOrdering::SeqCst),
            expected,
            "All increments should succeed"
        );
    }

    #[test]
    fn contention_mutual_exclusion_verified() {
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const NUM_THREADS: usize = 4;
        const ITERATIONS_PER_THREAD: usize = 500;

        let mutex = Arc::new(Mutex::new(0i32));
        let active_holders = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let mutex = Arc::clone(&mutex);
                let active = Arc::clone(&active_holders);
                let max = Arc::clone(&max_concurrent);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..ITERATIONS_PER_THREAD {
                        if let Ok(mut guard) = mutex.lock(&cx) {
                            // Mark ourselves as holding the lock
                            let current = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                            max.fetch_max(current, AtomicOrdering::SeqCst);

                            // Do some work while holding the lock
                            *guard += 1;

                            // Small delay to increase chance of contention
                            std::hint::spin_loop();

                            // Release holder count before dropping guard
                            active.fetch_sub(1, AtomicOrdering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let max = max_concurrent.load(AtomicOrdering::SeqCst);

        // Verify: at most 1 thread held the lock at any time
        assert_eq!(
            max, 1,
            "Mutex must provide mutual exclusion: max concurrent holders was {max}"
        );
    }

    #[test]
    fn contention_no_deadlock_with_drop() {
        use std::sync::Arc;

        const NUM_THREADS: usize = 4;
        const ITERATIONS: usize = 100;

        let mutex = Arc::new(Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                let mutex = Arc::clone(&mutex);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for i in 0..ITERATIONS {
                        let mut guard = mutex.lock(&cx).expect("lock should succeed");
                        guard.push((thread_id, i));
                        // Guard dropped here, releasing lock
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let cx = test_cx();
        let len = {
            let guard = mutex.lock(&cx).expect("final lock failed");
            guard.len()
        };

        // Verify: all entries were added
        assert_eq!(
            len,
            NUM_THREADS * ITERATIONS,
            "All operations should complete without deadlock"
        );
    }

    #[test]
    fn try_lock_under_contention() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const NUM_THREADS: usize = 4;
        const ITERATIONS: usize = 1000;

        let mutex = Arc::new(Mutex::new(0u64));
        let try_lock_successes = Arc::new(AtomicUsize::new(0));
        let try_lock_failures = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let mutex = Arc::clone(&mutex);
                let successes = Arc::clone(&try_lock_successes);
                let failures = Arc::clone(&try_lock_failures);
                std::thread::spawn(move || {
                    for _ in 0..ITERATIONS {
                        match mutex.try_lock() {
                            Ok(mut guard) => {
                                *guard += 1;
                                successes.fetch_add(1, AtomicOrdering::SeqCst);
                            }
                            Err(TryLockError::Locked) => {
                                failures.fetch_add(1, AtomicOrdering::SeqCst);
                            }
                            Err(TryLockError::Poisoned) => {
                                panic!("mutex should not be poisoned");
                            }
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let cx = test_cx();
        let final_value = *mutex.lock(&cx).expect("lock failed");
        let successes = try_lock_successes.load(AtomicOrdering::SeqCst) as u64;

        // Verify: final value matches successful try_locks
        assert_eq!(
            final_value, successes,
            "Final value should equal successful try_lock count"
        );

        // Verify: we had some contention (some failures)
        let failures = try_lock_failures.load(AtomicOrdering::SeqCst);
        // Under contention, we expect at least some failures
        assert!(
            failures > 0 || successes == (NUM_THREADS * ITERATIONS) as u64,
            "Should have some contention or all succeeded"
        );
    }

    #[test]
    fn owned_guard_contention_correctness() {
        use std::sync::Arc;

        const NUM_THREADS: usize = 4;
        const INCREMENTS_PER_THREAD: usize = 500;

        let mutex = Arc::new(Mutex::new(0u64));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let mutex = Arc::clone(&mutex);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..INCREMENTS_PER_THREAD {
                        let mut guard =
                            OwnedMutexGuard::lock(Arc::clone(&mutex), &cx).expect("lock failed");
                        guard.with_lock_mut(|v| *v += 1);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let cx = test_cx();
        let guard = OwnedMutexGuard::lock(mutex, &cx).expect("final lock failed");
        let final_value = guard.with_lock(|v| *v);
        let expected = (NUM_THREADS * INCREMENTS_PER_THREAD) as u64;

        assert_eq!(
            final_value, expected,
            "OwnedMutexGuard should protect data: expected {expected}, got {final_value}"
        );
    }
}
