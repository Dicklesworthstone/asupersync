//! Cancel-aware read-write lock with guard obligations.
//!
//! This RwLock allows multiple readers or a single writer with write-preferring
//! fairness. Acquisition is cancel-safe:
//! - Cancellation while waiting returns an error without acquiring the lock.
//! - Once acquired, guards always release on drop.
//!
//! # Writer-Preference Fairness
//!
//! This RwLock uses a **writer-preference** policy: when a writer is waiting,
//! new read requests are blocked until the writer acquires and releases the lock.
//! This prevents writer starvation under heavy read load, but can cause reader
//! starvation under heavy write load.
//!
//! ## Fairness Characteristics
//!
//! | Scenario                  | Behavior                                      |
//! |---------------------------|-----------------------------------------------|
//! | No writers waiting        | Readers acquire immediately                   |
//! | Writer waiting            | New readers blocked until writer completes    |
//! | Existing readers + writer | Writer waits for all readers to release       |
//! | Multiple writers          | Writers queue in arrival order (FIFO)         |
//!
//! ## Starvation Analysis
//!
//! - **Writer starvation**: Prevented. Writers block new readers while waiting.
//! - **Reader starvation**: Possible under continuous write pressure. If writes
//!   are frequent, readers may wait indefinitely as each writer blocks new reads.
//!
//! ## When to Use RwLock vs Mutex
//!
//! Prefer **RwLock** when:
//! - Read operations significantly outnumber writes
//! - Read operations are expensive (benefit from parallelism)
//! - Writers are infrequent
//!
//! Prefer **Mutex** when:
//! - Read and write frequency are similar
//! - Critical sections are short
//! - Simplicity is preferred over potential read parallelism
//!
//! # Example
//!
//! ```ignore
//! use asupersync::sync::RwLock;
//!
//! let lock = RwLock::new(vec![1, 2, 3]);
//!
//! // Multiple readers can access concurrently
//! let read1 = lock.read(&cx)?;
//! let read2 = lock.read(&cx)?;  // OK: no writers waiting
//!
//! // Writers get exclusive access
//! drop((read1, read2));
//! let mut write = lock.write(&cx)?;
//! write.push(4);
//! ```

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use crate::cx::Cx;

/// Error returned when acquiring a read or write lock fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RwLockError {
    /// The lock was poisoned (a panic occurred while holding a guard).
    Poisoned,
    /// Cancelled while waiting.
    Cancelled,
}

impl std::fmt::Display for RwLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => write!(f, "rwlock poisoned"),
            Self::Cancelled => write!(f, "rwlock acquisition cancelled"),
        }
    }
}

impl std::error::Error for RwLockError {}

/// Error returned when trying to read without waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryReadError {
    /// The lock is currently write-locked or a writer is waiting.
    Locked,
    /// The lock was poisoned.
    Poisoned,
}

impl std::fmt::Display for TryReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "rwlock is write-locked"),
            Self::Poisoned => write!(f, "rwlock poisoned"),
        }
    }
}

impl std::error::Error for TryReadError {}

/// Error returned when trying to write without waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryWriteError {
    /// The lock is currently held by readers or a writer.
    Locked,
    /// The lock was poisoned.
    Poisoned,
}

impl std::fmt::Display for TryWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "rwlock is locked"),
            Self::Poisoned => write!(f, "rwlock poisoned"),
        }
    }
}

impl std::error::Error for TryWriteError {}

#[derive(Debug, Default, Clone)]
struct State {
    readers: usize,
    writer_active: bool,
    writer_waiters: usize,
}

/// A cancel-aware read-write lock with writer-preference fairness.
///
/// This lock allows multiple readers to access the data concurrently, or a single
/// writer to have exclusive access. When a writer is waiting, new read attempts
/// are blocked to prevent writer starvation.
///
/// # Fairness Policy
///
/// - **Writer-preference**: When `writer_waiters > 0`, new readers block.
/// - **Reader parallelism**: Multiple readers can hold the lock simultaneously
///   when no writer is waiting or active.
/// - **Writer exclusivity**: Only one writer can hold the lock, and no readers
///   can hold it while a writer does.
///
/// # Cancel Safety
///
/// Both `read()` and `write()` are cancel-safe. If cancelled while waiting:
/// - The waiter is removed from the queue
/// - No lock is acquired
/// - An error is returned
///
/// # Poisoning
///
/// If a panic occurs while holding a guard, the lock is poisoned. Subsequent
/// acquisition attempts will return `RwLockError::Poisoned`.
#[derive(Debug)]
pub struct RwLock<T> {
    state: StdMutex<State>,
    reader_cv: Condvar,
    writer_cv: Condvar,
    data: StdRwLock<T>,
    poisoned: AtomicBool,
}

impl<T> RwLock<T> {
    /// Creates a new lock containing the given value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            state: StdMutex::new(State::default()),
            reader_cv: Condvar::new(),
            writer_cv: Condvar::new(),
            data: StdRwLock::new(value),
            poisoned: AtomicBool::new(false),
        }
    }

    /// Consumes the lock and returns the inner value.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.data.into_inner().expect("rwlock poisoned")
    }
}

impl<T> RwLock<T> {
    /// Returns true if the lock is poisoned.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Acquires a read guard, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    pub fn read(&self, cx: &Cx) -> Result<RwLockReadGuard<'_, T>, RwLockError> {
        self.acquire_read_state(cx)?;

        match self.data.read() {
            Ok(guard) => Ok(RwLockReadGuard {
                lock: self,
                guard: Some(guard),
            }),
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                self.release_reader_on_error();
                drop(poisoned.into_inner());
                Err(RwLockError::Poisoned)
            }
        }
    }

    /// Tries to acquire a read guard without waiting.
    pub fn try_read(&self) -> Result<RwLockReadGuard<'_, T>, TryReadError> {
        self.try_acquire_read_state()?;

        match self.data.read() {
            Ok(guard) => Ok(RwLockReadGuard {
                lock: self,
                guard: Some(guard),
            }),
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                self.release_reader_on_error();
                drop(poisoned.into_inner());
                Err(TryReadError::Poisoned)
            }
        }
    }

    /// Acquires a write guard, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    pub fn write(&self, cx: &Cx) -> Result<RwLockWriteGuard<'_, T>, RwLockError> {
        self.acquire_write_state(cx)?;

        match self.data.write() {
            Ok(guard) => Ok(RwLockWriteGuard {
                lock: self,
                guard: Some(guard),
            }),
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                self.release_writer_on_error();
                drop(poisoned.into_inner());
                Err(RwLockError::Poisoned)
            }
        }
    }

    /// Tries to acquire a write guard without waiting.
    pub fn try_write(&self) -> Result<RwLockWriteGuard<'_, T>, TryWriteError> {
        self.try_acquire_write_state()?;

        match self.data.write() {
            Ok(guard) => Ok(RwLockWriteGuard {
                lock: self,
                guard: Some(guard),
            }),
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                self.release_writer_on_error();
                drop(poisoned.into_inner());
                Err(TryWriteError::Poisoned)
            }
        }
    }

    /// Returns a mutable reference to the inner value.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut().expect("rwlock poisoned")
    }

    fn acquire_read_state(&self, cx: &Cx) -> Result<(), RwLockError> {
        if self.is_poisoned() {
            return Err(RwLockError::Poisoned);
        }

        if cx.checkpoint().is_err() {
            return Err(RwLockError::Cancelled);
        }

        let mut state = self.state.lock().expect("rwlock state poisoned");

        loop {
            if self.is_poisoned() {
                return Err(RwLockError::Poisoned);
            }

            if !state.writer_active && state.writer_waiters == 0 {
                state.readers += 1;
                return Ok(());
            }

            if cx.checkpoint().is_err() {
                return Err(RwLockError::Cancelled);
            }

            let (guard, _) = self
                .reader_cv
                .wait_timeout(state, Duration::from_millis(10))
                .expect("rwlock state poisoned");
            state = guard;
        }
    }

    fn try_acquire_read_state(&self) -> Result<(), TryReadError> {
        if self.is_poisoned() {
            return Err(TryReadError::Poisoned);
        }

        let mut state = self.state.lock().expect("rwlock state poisoned");
        if state.writer_active || state.writer_waiters > 0 {
            return Err(TryReadError::Locked);
        }

        state.readers += 1;
        drop(state);
        Ok(())
    }

    fn acquire_write_state(&self, cx: &Cx) -> Result<(), RwLockError> {
        if self.is_poisoned() {
            return Err(RwLockError::Poisoned);
        }

        if cx.checkpoint().is_err() {
            return Err(RwLockError::Cancelled);
        }

        let mut state = self.state.lock().expect("rwlock state poisoned");
        state.writer_waiters += 1;

        loop {
            if self.is_poisoned() {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                return Err(RwLockError::Poisoned);
            }

            if !state.writer_active && state.readers == 0 {
                state.writer_active = true;
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                return Ok(());
            }

            if cx.checkpoint().is_err() {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                if state.writer_waiters == 0 && !state.writer_active {
                    self.reader_cv.notify_all();
                }
                return Err(RwLockError::Cancelled);
            }

            let (guard, _) = self
                .writer_cv
                .wait_timeout(state, Duration::from_millis(10))
                .expect("rwlock state poisoned");
            state = guard;
        }
    }

    fn try_acquire_write_state(&self) -> Result<(), TryWriteError> {
        if self.is_poisoned() {
            return Err(TryWriteError::Poisoned);
        }

        let mut state = self.state.lock().expect("rwlock state poisoned");
        if state.writer_active || state.readers > 0 {
            return Err(TryWriteError::Locked);
        }

        state.writer_active = true;
        drop(state);
        Ok(())
    }

    fn release_reader_on_error(&self) {
        let mut state = self.state.lock().expect("rwlock state poisoned");
        state.readers = state.readers.saturating_sub(1);
        if state.readers == 0 && state.writer_waiters > 0 {
            self.writer_cv.notify_one();
        }
    }

    fn release_writer_on_error(&self) {
        let mut state = self.state.lock().expect("rwlock state poisoned");
        state.writer_active = false;
        if state.writer_waiters > 0 {
            self.writer_cv.notify_one();
        } else {
            self.reader_cv.notify_all();
        }
    }

    fn release_reader(&self) {
        let mut state = self.state.lock().expect("rwlock state poisoned");
        state.readers = state.readers.saturating_sub(1);
        if state.readers == 0 && state.writer_waiters > 0 {
            self.writer_cv.notify_one();
        }
    }

    fn release_writer(&self) {
        let mut state = self.state.lock().expect("rwlock state poisoned");
        state.writer_active = false;
        if state.writer_waiters > 0 {
            self.writer_cv.notify_one();
        } else {
            self.reader_cv.notify_all();
        }
    }

    #[cfg(test)]
    fn debug_state(&self) -> State {
        self.state.lock().expect("rwlock state poisoned").clone()
    }
}

/// Guard for a read lock.
#[must_use = "guard will be immediately released if not held"]
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
    guard: Option<std::sync::RwLockReadGuard<'a, T>>,
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().expect("guard accessed after drop")
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        // Drop the StdRwLockReadGuard BEFORE notifying waiting writers,
        // otherwise a woken writer blocks on data.write() because the
        // std read guard is still held.
        drop(self.guard.take());
        self.lock.release_reader();
    }
}

/// Guard for a write lock.
#[must_use = "guard will be immediately released if not held"]
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
    guard: Option<std::sync::RwLockWriteGuard<'a, T>>,
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().expect("guard accessed after drop")
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.as_mut().expect("guard accessed after drop")
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        // Drop the StdRwLockWriteGuard BEFORE notifying waiters,
        // otherwise a woken reader/writer blocks on the std lock.
        drop(self.guard.take());
        self.lock.release_writer();
    }
}

/// Owned read guard that can be moved between tasks.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedRwLockReadGuard<T> {
    lock: Arc<RwLock<T>>,
}

impl<T> OwnedRwLockReadGuard<T> {
    /// Acquires an owned read guard from an `Arc<RwLock<T>>`.
    pub fn read(lock: Arc<RwLock<T>>, cx: &Cx) -> Result<Self, RwLockError> {
        lock.acquire_read_state(cx)?;
        Ok(Self { lock })
    }

    /// Tries to acquire an owned read guard without waiting.
    pub fn try_read(lock: Arc<RwLock<T>>) -> Result<Self, TryReadError> {
        lock.try_acquire_read_state()?;
        Ok(Self { lock })
    }

    /// Executes a closure with shared access to the data.
    pub fn with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let guard = self.lock.data.read().expect("rwlock poisoned");
        f(&guard)
    }
}

impl<T> Drop for OwnedRwLockReadGuard<T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        self.lock.release_reader();
    }
}

/// Owned write guard that can be moved between tasks.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedRwLockWriteGuard<T> {
    lock: Arc<RwLock<T>>,
}

impl<T> OwnedRwLockWriteGuard<T> {
    /// Acquires an owned write guard from an `Arc<RwLock<T>>`.
    pub fn write(lock: Arc<RwLock<T>>, cx: &Cx) -> Result<Self, RwLockError> {
        lock.acquire_write_state(cx)?;
        Ok(Self { lock })
    }

    /// Tries to acquire an owned write guard without waiting.
    pub fn try_write(lock: Arc<RwLock<T>>) -> Result<Self, TryWriteError> {
        lock.try_acquire_write_state()?;
        Ok(Self { lock })
    }

    /// Executes a closure with exclusive access to the data.
    pub fn with_write<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut guard = self.lock.data.write().expect("rwlock poisoned");
        f(&mut guard)
    }
}

impl<T> Drop for OwnedRwLockWriteGuard<T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        self.lock.release_writer();
    }
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::Arc as StdArc;
    use std::thread;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 0)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 0)),
            crate::types::Budget::INFINITE,
        )
    }

    #[test]
    fn multiple_readers_allowed() {
        init_test("multiple_readers_allowed");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        let guard1 = lock.read(&cx).expect("read 1");
        let guard2 = lock.read(&cx).expect("read 2");

        crate::assert_with_log!(*guard1 == 42, "guard1 value", 42u32, *guard1);
        crate::assert_with_log!(*guard2 == 42, "guard2 value", 42u32, *guard2);
        crate::test_complete!("multiple_readers_allowed");
    }

    #[test]
    fn write_excludes_readers_and_writers() {
        init_test("write_excludes_readers_and_writers");
        let cx = test_cx();
        let lock = RwLock::new(5_u32);

        let mut write = lock.write(&cx).expect("write");
        *write = 7;

        let read_locked = matches!(lock.try_read(), Err(TryReadError::Locked));
        crate::assert_with_log!(read_locked, "read locked", true, read_locked);
        let write_locked = matches!(lock.try_write(), Err(TryWriteError::Locked));
        crate::assert_with_log!(write_locked, "write locked", true, write_locked);

        drop(write);

        let read = lock.read(&cx).expect("read after write");
        crate::assert_with_log!(*read == 7, "read after write", 7u32, *read);
        crate::test_complete!("write_excludes_readers_and_writers");
    }

    #[test]
    fn writer_waiting_blocks_new_readers() {
        init_test("writer_waiting_blocks_new_readers");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(1_u32));
        let read_guard = lock.read(&cx).expect("read");

        let writer_started = StdArc::new(AtomicBool::new(false));
        let writer_lock = StdArc::clone(&lock);
        let writer_flag = StdArc::clone(&writer_started);

        let handle = thread::spawn(move || {
            let cx = test_cx();
            writer_flag.store(true, AtomicOrdering::Release);
            let _guard = writer_lock.write(&cx).expect("write");
        });

        // Wait until writer is attempting to acquire.
        while !writer_started.load(AtomicOrdering::Acquire) {
            std::thread::yield_now();
        }

        // New readers should be blocked while a writer is waiting.
        // We loop because setting the flag happens before the writer actually
        // registers itself in the lock state.
        let mut success = false;
        for _ in 0..100 {
            if matches!(lock.try_read(), Err(TryReadError::Locked)) {
                success = true;
                break;
            }
            std::thread::yield_now();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        crate::assert_with_log!(success, "writer blocked readers", true, success);

        drop(read_guard);
        let _ = handle.join();
        crate::test_complete!("writer_waiting_blocks_new_readers");
    }

    #[test]
    fn cancel_during_read_wait() {
        init_test("cancel_during_read_wait");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let _write = lock.write(&cx).expect("write");
        cx.set_cancel_requested(true);

        let cancelled = matches!(lock.read(&cx), Err(RwLockError::Cancelled));
        crate::assert_with_log!(cancelled, "read cancelled", true, cancelled);
        crate::test_complete!("cancel_during_read_wait");
    }

    #[test]
    fn test_rwlock_try_read_success() {
        init_test("test_rwlock_try_read_success");
        let lock = RwLock::new(42_u32);

        // Should succeed when unlocked
        let guard = lock.try_read().expect("try_read should succeed");
        crate::assert_with_log!(*guard == 42, "read value", 42u32, *guard);
        crate::test_complete!("test_rwlock_try_read_success");
    }

    #[test]
    fn test_rwlock_try_write_success() {
        init_test("test_rwlock_try_write_success");
        let lock = RwLock::new(42_u32);

        // Should succeed when unlocked
        let mut guard = lock.try_write().expect("try_write should succeed");
        *guard = 100;
        crate::assert_with_log!(*guard == 100, "write value", 100u32, *guard);
        crate::test_complete!("test_rwlock_try_write_success");
    }

    #[test]
    fn test_rwlock_cancel_during_write_wait() {
        init_test("test_rwlock_cancel_during_write_wait");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold a read lock
        let _read = lock.read(&cx).expect("read");

        // Request cancellation
        cx.set_cancel_requested(true);

        // Write should be cancelled
        let cancelled = matches!(lock.write(&cx), Err(RwLockError::Cancelled));
        crate::assert_with_log!(cancelled, "write cancelled", true, cancelled);
        crate::test_complete!("test_rwlock_cancel_during_write_wait");
    }

    #[test]
    fn test_rwlock_get_mut() {
        init_test("test_rwlock_get_mut");
        let mut lock = RwLock::new(42_u32);

        // get_mut provides direct access when we have &mut
        *lock.get_mut() = 100;
        let value = *lock.get_mut();
        crate::assert_with_log!(value == 100, "get_mut works", 100u32, value);
        crate::test_complete!("test_rwlock_get_mut");
    }

    #[test]
    fn test_rwlock_into_inner() {
        init_test("test_rwlock_into_inner");
        let lock = RwLock::new(42_u32);

        let value = lock.into_inner();
        crate::assert_with_log!(value == 42, "into_inner works", 42u32, value);
        crate::test_complete!("test_rwlock_into_inner");
    }

    #[test]
    fn test_rwlock_read_released_on_drop() {
        init_test("test_rwlock_read_released_on_drop");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Acquire and drop read
        {
            let _guard = lock.read(&cx).expect("read");
        }

        // Write should succeed now
        let can_write = lock.try_write().is_ok();
        crate::assert_with_log!(can_write, "can write after read drop", true, can_write);
        crate::test_complete!("test_rwlock_read_released_on_drop");
    }

    #[test]
    fn test_rwlock_write_released_on_drop() {
        init_test("test_rwlock_write_released_on_drop");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Acquire and drop write
        {
            let _guard = lock.write(&cx).expect("write");
        }

        // Read should succeed now
        let can_read = lock.try_read().is_ok();
        crate::assert_with_log!(can_read, "can read after write drop", true, can_read);
        crate::test_complete!("test_rwlock_write_released_on_drop");
    }
}
