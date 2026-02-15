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
//! let read1 = lock.read(&cx).await?;
//! let read2 = lock.read(&cx).await?;  // OK: no writers waiting
//!
//! // Writers get exclusive access
//! drop((read1, read2));
//! let mut write = lock.write(&cx).await?;
//! write.push(4);
//! ```

use parking_lot::Mutex as ParkingMutex;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::task::{Context, Poll, Waker};

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
    reader_waiters: VecDeque<Waiter>,
    writer_queue: VecDeque<Waiter>,
}

#[derive(Debug, Clone)]
struct Waiter {
    waker: Waker,
    queued: Arc<AtomicBool>,
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
    state: ParkingMutex<State>,
    data: StdRwLock<T>,
    poisoned: AtomicBool,
}

impl<T> RwLock<T> {
    /// Creates a new lock containing the given value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            state: ParkingMutex::new(State::default()),
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

    /// Acquires a read guard asynchronously, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    pub fn read<'a, 'b>(&'a self, cx: &'b Cx) -> ReadFuture<'a, 'b, T> {
        ReadFuture {
            lock: self,
            cx,
            waiter: None,
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
                self.release_reader();
                drop(poisoned.into_inner());
                Err(TryReadError::Poisoned)
            }
        }
    }

    /// Acquires a write guard asynchronously, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    pub fn write<'a, 'b>(&'a self, cx: &'b Cx) -> WriteFuture<'a, 'b, T> {
        WriteFuture {
            lock: self,
            cx,
            waiter: None,
            counted: false,
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
                self.release_writer();
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

    fn try_acquire_read_state(&self) -> Result<(), TryReadError> {
        if self.is_poisoned() {
            return Err(TryReadError::Poisoned);
        }

        let mut state = self.state.lock();
        if state.writer_active || state.writer_waiters > 0 {
            return Err(TryReadError::Locked);
        }

        state.readers += 1;
        drop(state);
        Ok(())
    }

    fn try_acquire_write_state(&self) -> Result<(), TryWriteError> {
        if self.is_poisoned() {
            return Err(TryWriteError::Poisoned);
        }

        let mut state = self.state.lock();
        // Do not let try_write() bypass queued async writers. If there are
        // waiters, preserve queue order and report Locked.
        if state.writer_active || state.readers > 0 || state.writer_waiters > 0 {
            return Err(TryWriteError::Locked);
        }

        state.writer_active = true;
        drop(state);
        Ok(())
    }

    fn pop_writer_waiter(state: &mut State) -> Option<Waker> {
        loop {
            match state.writer_queue.pop_front() {
                Some(waiter) if waiter.queued.swap(false, Ordering::AcqRel) => {
                    return Some(waiter.waker);
                }
                Some(_) => {}
                None => return None,
            }
        }
    }

    fn drain_reader_waiters(state: &mut State) -> SmallVec<[Waker; 4]> {
        let mut wakers = SmallVec::new();
        while let Some(waiter) = state.reader_waiters.pop_front() {
            if waiter.queued.swap(false, Ordering::AcqRel) {
                wakers.push(waiter.waker);
            }
        }
        wakers
    }

    fn release_reader(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.readers = state.readers.saturating_sub(1);
            if state.readers == 0 && state.writer_waiters > 0 {
                Self::pop_writer_waiter(&mut state)
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn release_writer(&self) {
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            state.writer_active = false;
            if state.writer_waiters > 0 {
                (Self::pop_writer_waiter(&mut state), SmallVec::new())
            } else {
                (None, Self::drain_reader_waiters(&mut state))
            }
        };
        if let Some(waker) = writer_waker {
            waker.wake();
        }
        for waker in reader_wakers {
            waker.wake();
        }
    }

    #[cfg(test)]
    fn debug_state(&self) -> State {
        self.state.lock().clone()
    }
}

// Guards used during acquisition to restore counters if the underlying std lock panics.
struct ReaderCountGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Drop for ReaderCountGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.release_reader();
    }
}

struct WriterActiveGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Drop for WriterActiveGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.release_writer();
    }
}

/// Future returned by `RwLock::read`.
pub struct ReadFuture<'a, 'b, T> {
    lock: &'a RwLock<T>,
    cx: &'b Cx,
    waiter: Option<Arc<AtomicBool>>,
}

impl<'a, T> Future for ReadFuture<'a, '_, T> {
    type Output = Result<RwLockReadGuard<'a, T>, RwLockError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.lock.is_poisoned() {
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if self.cx.checkpoint().is_err() {
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = self.lock.state.lock();

        if !state.writer_active && state.writer_waiters == 0 {
            state.readers += 1;
            if let Some(waiter) = self.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            drop(state);

            let guard = ReaderCountGuard { lock: self.lock };

            let result = match self.lock.data.read() {
                Ok(read_guard) => Poll::Ready(Ok(RwLockReadGuard {
                    lock: self.lock,
                    guard: Some(read_guard),
                })),
                Err(poisoned) => {
                    self.lock.poisoned.store(true, Ordering::Release);
                    // release_reader is called by guard drop
                    drop(poisoned.into_inner());
                    Poll::Ready(Err(RwLockError::Poisoned))
                }
            };

            // If success, forget guard so it doesn't decrement (RwLockReadGuard will do it)
            // If error (Poisoned), guard drops and calls release_reader.
            // But RwLockReadGuard calls release_reader on drop.
            // If we return Ready(Ok), we transfer responsibility to RwLockReadGuard.
            // If we return Ready(Err), we must decrement.

            if matches!(&result, Poll::Ready(Ok(_))) {
                std::mem::forget(guard);
            }
            // If Err(Poisoned), guard drops and decrements.
            // Correct.

            return result;
        }

        let mut new_waiter = None;
        match self.waiter.as_ref() {
            Some(waiter) if !waiter.load(Ordering::Acquire) => {
                waiter.store(true, Ordering::Release);
                state.reader_waiters.push_front(Waiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(waiter),
                });
            }
            Some(waiter) => {
                if let Some(existing) = state
                    .reader_waiters
                    .iter_mut()
                    .find(|w| Arc::ptr_eq(&w.queued, waiter))
                {
                    if !existing.waker.will_wake(context.waker()) {
                        existing.waker.clone_from(context.waker());
                    }
                }
            }
            None => {
                let waiter = Arc::new(AtomicBool::new(true));
                state.reader_waiters.push_back(Waiter {
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

impl<T> Drop for ReadFuture<'_, '_, T> {
    fn drop(&mut self) {
        let mut writer_waker = None;
        if let Some(waiter) = self.waiter.as_ref() {
            let mut state = self.lock.state.lock();
            let initial_len = state.reader_waiters.len();
            state
                .reader_waiters
                .retain(|w| !Arc::ptr_eq(&w.queued, waiter));
            let removed = initial_len != state.reader_waiters.len();

            if !removed {
                let dequeued = !waiter.load(Ordering::Acquire);
                if dequeued
                    && state.readers == 0
                    && !state.writer_active
                    && state.writer_waiters > 0
                {
                    writer_waker = RwLock::<T>::pop_writer_waiter(&mut state);
                }
            }
        }

        if let Some(waker) = writer_waker {
            waker.wake();
        }
    }
}

/// Future returned by `RwLock::write`.
pub struct WriteFuture<'a, 'b, T> {
    lock: &'a RwLock<T>,
    cx: &'b Cx,
    waiter: Option<Arc<AtomicBool>>,
    counted: bool,
}

impl<'a, T> Future for WriteFuture<'a, '_, T> {
    type Output = Result<RwLockWriteGuard<'a, T>, RwLockError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.lock.is_poisoned() {
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if self.cx.checkpoint().is_err() {
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = self.lock.state.lock();
        if !self.counted {
            state.writer_waiters += 1;
            self.counted = true;
        }

        let dequeued = self
            .waiter
            .as_ref()
            .is_some_and(|w| !w.load(Ordering::Acquire));
        let can_acquire =
            !state.writer_active && state.readers == 0 && (dequeued || state.writer_waiters == 1);

        if can_acquire {
            state.writer_active = true;
            if self.counted {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                self.counted = false;
            }
            if let Some(waiter) = self.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            drop(state);

            let guard = WriterActiveGuard { lock: self.lock };

            let result = match self.lock.data.write() {
                Ok(write_guard) => Poll::Ready(Ok(RwLockWriteGuard {
                    lock: self.lock,
                    guard: Some(write_guard),
                })),
                Err(poisoned) => {
                    self.lock.poisoned.store(true, Ordering::Release);
                    // release_writer is called by guard drop
                    drop(poisoned.into_inner());
                    Poll::Ready(Err(RwLockError::Poisoned))
                }
            };

            if matches!(&result, Poll::Ready(Ok(_))) {
                std::mem::forget(guard);
            }

            return result;
        }

        let mut new_waiter = None;
        match self.waiter.as_ref() {
            Some(waiter) if !waiter.load(Ordering::Acquire) => {
                waiter.store(true, Ordering::Release);
                state.writer_queue.push_front(Waiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(waiter),
                });
            }
            Some(waiter) => {
                if let Some(existing) = state
                    .writer_queue
                    .iter_mut()
                    .find(|w| Arc::ptr_eq(&w.queued, waiter))
                {
                    if !existing.waker.will_wake(context.waker()) {
                        existing.waker.clone_from(context.waker());
                    }
                }
            }
            None => {
                let waiter = Arc::new(AtomicBool::new(true));
                state.writer_queue.push_back(Waiter {
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

impl<T> Drop for WriteFuture<'_, '_, T> {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }

        let mut writer_waker = None;
        let mut reader_wakers: SmallVec<[Waker; 4]> = SmallVec::new();
        let mut state = self.lock.state.lock();

        if let Some(waiter) = self.waiter.as_ref() {
            let initial_len = state.writer_queue.len();
            state
                .writer_queue
                .retain(|w| !Arc::ptr_eq(&w.queued, waiter));
            let removed = initial_len != state.writer_queue.len();

            state.writer_waiters = state.writer_waiters.saturating_sub(1);

            if !removed {
                let dequeued = !waiter.load(Ordering::Acquire);
                if dequeued
                    && !state.writer_active
                    && state.readers == 0
                    && state.writer_waiters > 0
                {
                    writer_waker = RwLock::<T>::pop_writer_waiter(&mut state);
                }
            }
        } else {
            state.writer_waiters = state.writer_waiters.saturating_sub(1);
        }

        if state.writer_waiters == 0 && !state.writer_active {
            reader_wakers = RwLock::<T>::drain_reader_waiters(&mut state);
        }
        drop(state);

        if let Some(waker) = writer_waker {
            waker.wake();
        }
        for waker in reader_wakers {
            waker.wake();
        }
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

    #[inline]
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

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().expect("guard accessed after drop")
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    #[inline]
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
    pub fn read(lock: Arc<RwLock<T>>, cx: &Cx) -> OwnedReadFuture<'_, T> {
        OwnedReadFuture {
            lock,
            cx,
            waiter: None,
        }
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
    pub fn write(lock: Arc<RwLock<T>>, cx: &Cx) -> OwnedWriteFuture<'_, T> {
        OwnedWriteFuture {
            lock,
            cx,
            waiter: None,
            counted: false,
        }
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

/// Future returned by `OwnedRwLockReadGuard::read`.
pub struct OwnedReadFuture<'b, T> {
    lock: Arc<RwLock<T>>,
    cx: &'b Cx,
    waiter: Option<Arc<AtomicBool>>,
}

impl<T> Future for OwnedReadFuture<'_, T> {
    type Output = Result<OwnedRwLockReadGuard<T>, RwLockError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.lock.is_poisoned() {
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if self.cx.checkpoint().is_err() {
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = self.lock.state.lock();
        if !state.writer_active && state.writer_waiters == 0 {
            state.readers += 1;
            if let Some(waiter) = self.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            drop(state);
            return Poll::Ready(Ok(OwnedRwLockReadGuard {
                lock: Arc::clone(&self.lock),
            }));
        }

        let mut new_waiter = None;
        match self.waiter.as_ref() {
            Some(waiter) if !waiter.load(Ordering::Acquire) => {
                waiter.store(true, Ordering::Release);
                state.reader_waiters.push_front(Waiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(waiter),
                });
            }
            Some(waiter) => {
                if let Some(existing) = state
                    .reader_waiters
                    .iter_mut()
                    .find(|w| Arc::ptr_eq(&w.queued, waiter))
                {
                    if !existing.waker.will_wake(context.waker()) {
                        existing.waker.clone_from(context.waker());
                    }
                }
            }
            None => {
                let waiter = Arc::new(AtomicBool::new(true));
                state.reader_waiters.push_back(Waiter {
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

impl<T> Drop for OwnedReadFuture<'_, T> {
    fn drop(&mut self) {
        let mut writer_waker = None;
        if let Some(waiter) = self.waiter.as_ref() {
            let mut state = self.lock.state.lock();
            let initial_len = state.reader_waiters.len();
            state
                .reader_waiters
                .retain(|w| !Arc::ptr_eq(&w.queued, waiter));
            let removed = initial_len != state.reader_waiters.len();

            if !removed {
                let dequeued = !waiter.load(Ordering::Acquire);
                if dequeued
                    && state.readers == 0
                    && !state.writer_active
                    && state.writer_waiters > 0
                {
                    writer_waker = RwLock::<T>::pop_writer_waiter(&mut state);
                }
            }
        }

        if let Some(waker) = writer_waker {
            waker.wake();
        }
    }
}

/// Future returned by `OwnedRwLockWriteGuard::write`.
pub struct OwnedWriteFuture<'b, T> {
    lock: Arc<RwLock<T>>,
    cx: &'b Cx,
    waiter: Option<Arc<AtomicBool>>,
    counted: bool,
}

impl<T> Future for OwnedWriteFuture<'_, T> {
    type Output = Result<OwnedRwLockWriteGuard<T>, RwLockError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.lock.is_poisoned() {
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if self.cx.checkpoint().is_err() {
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        // Clone the Arc to avoid borrow conflict with self.counted
        let lock = Arc::clone(&self.lock);
        let mut state = lock.state.lock();
        if !self.counted {
            state.writer_waiters += 1;
            self.counted = true;
        }

        let dequeued = self
            .waiter
            .as_ref()
            .is_some_and(|w| !w.load(Ordering::Acquire));
        let can_acquire =
            !state.writer_active && state.readers == 0 && (dequeued || state.writer_waiters == 1);

        if can_acquire {
            state.writer_active = true;
            if self.counted {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                self.counted = false;
            }
            if let Some(waiter) = self.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            drop(state);
            return Poll::Ready(Ok(OwnedRwLockWriteGuard { lock }));
        }

        let mut new_waiter = None;
        match self.waiter.as_ref() {
            Some(waiter) if !waiter.load(Ordering::Acquire) => {
                waiter.store(true, Ordering::Release);
                state.writer_queue.push_front(Waiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(waiter),
                });
            }
            Some(waiter) => {
                if let Some(existing) = state
                    .writer_queue
                    .iter_mut()
                    .find(|w| Arc::ptr_eq(&w.queued, waiter))
                {
                    if !existing.waker.will_wake(context.waker()) {
                        existing.waker.clone_from(context.waker());
                    }
                }
            }
            None => {
                let waiter = Arc::new(AtomicBool::new(true));
                state.writer_queue.push_back(Waiter {
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

impl<T> Drop for OwnedWriteFuture<'_, T> {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }

        let mut writer_waker = None;
        let mut reader_wakers: SmallVec<[Waker; 4]> = SmallVec::new();
        let mut state = self.lock.state.lock();

        if let Some(waiter) = self.waiter.as_ref() {
            let already_dequeued = !waiter.load(Ordering::Acquire);
            let removed = if already_dequeued {
                false
            } else {
                let initial_len = state.writer_queue.len();
                state
                    .writer_queue
                    .retain(|w| !Arc::ptr_eq(&w.queued, waiter));
                initial_len != state.writer_queue.len()
            };

            state.writer_waiters = state.writer_waiters.saturating_sub(1);

            if !removed {
                let dequeued = already_dequeued || !waiter.load(Ordering::Acquire);
                if dequeued
                    && !state.writer_active
                    && state.readers == 0
                    && state.writer_waiters > 0
                {
                    writer_waker = RwLock::<T>::pop_writer_waiter(&mut state);
                }
            }
        } else {
            state.writer_waiters = state.writer_waiters.saturating_sub(1);
        }

        if state.writer_waiters == 0 && !state.writer_active {
            reader_wakers = RwLock::<T>::drain_reader_waiters(&mut state);
        }
        drop(state);

        if let Some(waker) = writer_waker {
            waker.wake();
        }
        for waker in reader_wakers {
            waker.wake();
        }
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

    fn poll_once<T>(future: &mut (impl Future<Output = T> + Unpin)) -> Option<T> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match std::pin::Pin::new(future).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn poll_until_ready<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn read_blocking<'a, T>(lock: &'a RwLock<T>, cx: &Cx) -> RwLockReadGuard<'a, T> {
        poll_until_ready(lock.read(cx)).expect("read failed")
    }

    fn write_blocking<'a, T>(lock: &'a RwLock<T>, cx: &Cx) -> RwLockWriteGuard<'a, T> {
        poll_until_ready(lock.write(cx)).expect("write failed")
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

        let guard1 = read_blocking(&lock, &cx);
        let guard2 = read_blocking(&lock, &cx);

        crate::assert_with_log!(*guard1 == 42, "guard1 value", 42u32, *guard1);
        crate::assert_with_log!(*guard2 == 42, "guard2 value", 42u32, *guard2);
        crate::test_complete!("multiple_readers_allowed");
    }

    #[test]
    fn write_excludes_readers_and_writers() {
        init_test("write_excludes_readers_and_writers");
        let cx = test_cx();
        let lock = RwLock::new(5_u32);

        let mut write = write_blocking(&lock, &cx);
        *write = 7;

        let read_locked = matches!(lock.try_read(), Err(TryReadError::Locked));
        crate::assert_with_log!(read_locked, "read locked", true, read_locked);
        let write_locked = matches!(lock.try_write(), Err(TryWriteError::Locked));
        crate::assert_with_log!(write_locked, "write locked", true, write_locked);

        drop(write);

        let read = read_blocking(&lock, &cx);
        crate::assert_with_log!(*read == 7, "read after write", 7u32, *read);
        crate::test_complete!("write_excludes_readers_and_writers");
    }

    #[test]
    fn writer_waiting_blocks_new_readers() {
        init_test("writer_waiting_blocks_new_readers");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(1_u32));
        let read_guard = read_blocking(&lock, &cx);

        let writer_started = StdArc::new(AtomicBool::new(false));
        let writer_lock = StdArc::clone(&lock);
        let writer_flag = StdArc::clone(&writer_started);

        let handle = thread::spawn(move || {
            let cx = test_cx();
            writer_flag.store(true, AtomicOrdering::Release);
            let _guard = write_blocking(&writer_lock, &cx);
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
    fn try_write_does_not_bypass_waiting_writer_turn() {
        init_test("try_write_does_not_bypass_waiting_writer_turn");
        let cx = test_cx();
        let lock = RwLock::new(1_u32);

        // Hold a read lock so the writer must queue first.
        let read_guard = read_blocking(&lock, &cx);
        let mut queued_writer = lock.write(&cx);
        let pending = poll_once(&mut queued_writer).is_none();
        crate::assert_with_log!(pending, "writer queued while reader held", true, pending);

        // Releasing the reader wakes the queued writer, but before that writer
        // is polled again, try_write() must not barge ahead.
        drop(read_guard);

        let try_write_locked = matches!(lock.try_write(), Err(TryWriteError::Locked));
        crate::assert_with_log!(
            try_write_locked,
            "try_write must not bypass queued writer",
            true,
            try_write_locked
        );

        let queued_guard = poll_until_ready(queued_writer).expect("queued writer should acquire");
        drop(queued_guard);
        crate::test_complete!("try_write_does_not_bypass_waiting_writer_turn");
    }

    #[test]
    fn cancel_during_read_wait() {
        init_test("cancel_during_read_wait");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let _write = write_blocking(&lock, &cx);
        let mut fut = lock.read(&cx);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "read waits while writer held", true, pending);

        cx.set_cancel_requested(true);

        let cancelled = matches!(poll_once(&mut fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "read cancelled", true, cancelled);
        drop(fut);

        let state = lock.debug_state();
        let waiters = state.reader_waiters.len();
        crate::assert_with_log!(waiters == 0, "reader waiters cleaned", 0usize, waiters);
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
        let _read = read_blocking(&lock, &cx);

        let mut fut = lock.write(&cx);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "write waits while reader held", true, pending);

        // Request cancellation
        cx.set_cancel_requested(true);

        // Write should be cancelled
        let cancelled = matches!(poll_once(&mut fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "write cancelled", true, cancelled);
        drop(fut);

        let state = lock.debug_state();
        let waiters = state.writer_queue.len();
        let writer_count = state.writer_waiters;
        crate::assert_with_log!(
            waiters == 0 && writer_count == 0,
            "writer waiters cleaned",
            true,
            waiters == 0 && writer_count == 0
        );
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
            let _guard = read_blocking(&lock, &cx);
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
            let _guard = write_blocking(&lock, &cx);
        }

        // Read should succeed now
        let can_read = lock.try_read().is_ok();
        crate::assert_with_log!(can_read, "can read after write drop", true, can_read);
        crate::test_complete!("test_rwlock_write_released_on_drop");
    }

    #[test]
    fn test_writer_fifo_ordering() {
        // Verifies that queued writers acquire in FIFO order.
        init_test("test_writer_fifo_ordering");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(Vec::<u32>::new()));
        let order = StdArc::new(std::sync::Mutex::new(Vec::new()));

        // Hold a read lock so writers must queue.
        let read_guard = read_blocking(&lock, &cx);

        let mut handles = Vec::new();
        for id in 1..=3_u32 {
            let lock_c = StdArc::clone(&lock);
            let order_c = StdArc::clone(&order);
            handles.push(thread::spawn(move || {
                let cx = test_cx();
                let mut guard = write_blocking(&lock_c, &cx);
                order_c.lock().unwrap().push(id);
                guard.push(id);
            }));
            // Small delay to ensure writers queue in id order.
            thread::sleep(std::time::Duration::from_millis(10));
        }

        // Release reader — writers should now acquire one by one in queue order.
        drop(read_guard);
        for h in handles {
            let _ = h.join();
        }

        let final_order = order.lock().unwrap().clone();
        let data = lock.try_read().unwrap();
        // Both the acquisition order and data should match FIFO.
        crate::assert_with_log!(
            final_order == *data,
            "writer FIFO order matches data",
            true,
            final_order == *data
        );
        crate::test_complete!("test_writer_fifo_ordering");
    }

    #[test]
    fn test_write_future_drop_wakes_readers_when_last_writer() {
        // When the last queued WriteFuture is dropped without acquiring,
        // pending readers must be woken.
        init_test("test_write_future_drop_wakes_readers_when_last_writer");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Queue a writer (it will count itself in writer_waiters).
        let _write_guard = write_blocking(&lock, &cx);
        let mut write_fut = lock.write(&cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "write future pending", true, pending);

        // Queue a reader (blocked because writer_waiters > 0).
        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "read future pending", true, read_pending);

        // Release the active writer.
        drop(_write_guard);

        // Drop the queued write future. This decrements writer_waiters to 0,
        // which should wake the queued reader.
        drop(write_fut);

        // The reader should now acquire.
        let read_result = poll_once(&mut read_fut);
        let acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            acquired,
            "reader acquired after writer drop",
            true,
            acquired
        );

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0,
            "no writer waiters left",
            0usize,
            state.writer_waiters
        );
        crate::test_complete!("test_write_future_drop_wakes_readers_when_last_writer");
    }

    #[test]
    fn test_read_future_drop_forwards_wake_to_writer() {
        // When a dequeued ReadFuture is dropped without acquiring, it must
        // forward its wake to a waiting writer.
        init_test("test_read_future_drop_forwards_wake_to_writer");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(0_u32));

        // Writer holds the lock.
        let write_guard = write_blocking(&lock, &cx);

        // Queue a reader.
        let mut read_fut = lock.read(&cx);
        let pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(pending, "read pending while writer active", true, pending);

        // Queue a second writer.
        let writer_lock = StdArc::clone(&lock);
        let writer_done = StdArc::new(AtomicBool::new(false));
        let writer_done_c = StdArc::clone(&writer_done);
        let handle = thread::spawn(move || {
            let cx = test_cx();
            let _guard = write_blocking(&writer_lock, &cx);
            writer_done_c.store(true, AtomicOrdering::Release);
        });

        // Wait for the second writer to register.
        thread::sleep(std::time::Duration::from_millis(20));

        // Release active writer. This wakes the reader (drain_reader_waiters),
        // NOT the second writer (writer_waiters > 0 is checked, but
        // release_writer wakes writers first when writer_waiters > 0).
        drop(write_guard);

        // Drop the read future without polling. If it was dequeued, its drop
        // should forward the wake to the second writer.
        drop(read_fut);

        let _ = handle.join();
        let done = writer_done.load(AtomicOrdering::Acquire);
        crate::assert_with_log!(done, "second writer eventually acquired", true, done);
        crate::test_complete!("test_read_future_drop_forwards_wake_to_writer");
    }

    #[test]
    fn test_owned_read_guard_basic() {
        init_test("test_owned_read_guard_basic");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let guard =
            OwnedRwLockReadGuard::try_read(StdArc::clone(&lock)).expect("try_read should succeed");
        let value = guard.with_read(|v| *v);
        crate::assert_with_log!(value == 42, "owned read guard value", 42u32, value);
        drop(guard);

        // After drop, write should succeed.
        let can_write = lock.try_write().is_ok();
        crate::assert_with_log!(can_write, "write after owned read drop", true, can_write);
        crate::test_complete!("test_owned_read_guard_basic");
    }

    #[test]
    fn test_owned_write_guard_basic() {
        init_test("test_owned_write_guard_basic");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let mut guard = OwnedRwLockWriteGuard::try_write(StdArc::clone(&lock))
            .expect("try_write should succeed");
        guard.with_write(|v| *v = 100);
        drop(guard);

        let read_guard = lock.try_read().expect("read after write drop");
        crate::assert_with_log!(
            *read_guard == 100,
            "owned write persisted",
            100u32,
            *read_guard
        );
        crate::test_complete!("test_owned_write_guard_basic");
    }

    #[test]
    fn test_multiple_writer_cascade() {
        // Multiple writers queue behind an active writer and acquire sequentially.
        init_test("test_multiple_writer_cascade");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let write1 = write_blocking(&lock, &cx);

        // Queue two more writers.
        let mut write2_fut = lock.write(&cx);
        let w2_pending = poll_once(&mut write2_fut).is_none();
        crate::assert_with_log!(w2_pending, "writer 2 pending", true, w2_pending);

        let mut write3_fut = lock.write(&cx);
        let w3_pending = poll_once(&mut write3_fut).is_none();
        crate::assert_with_log!(w3_pending, "writer 3 pending", true, w3_pending);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 2,
            "two writers waiting",
            2usize,
            state.writer_waiters
        );

        // Release first writer — writer 2 should be next.
        drop(write1);

        let w2_result = poll_once(&mut write2_fut);
        let w2_acquired = matches!(w2_result, Some(Ok(_)));
        crate::assert_with_log!(w2_acquired, "writer 2 acquired", true, w2_acquired);

        // Writer 3 should still be pending.
        let w3_still_pending = poll_once(&mut write3_fut).is_none();
        crate::assert_with_log!(
            w3_still_pending,
            "writer 3 still pending",
            true,
            w3_still_pending
        );

        // Release writer 2 — writer 3 should acquire.
        if let Some(Ok(guard)) = w2_result {
            drop(guard);
        }

        let w3_result = poll_once(&mut write3_fut);
        let w3_acquired = matches!(w3_result, Some(Ok(_)));
        crate::assert_with_log!(w3_acquired, "writer 3 acquired", true, w3_acquired);
        crate::test_complete!("test_multiple_writer_cascade");
    }

    #[test]
    fn test_try_read_blocked_by_writer_waiters() {
        // try_read must fail when writers are queued, even if no writer is active.
        init_test("test_try_read_blocked_by_writer_waiters");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold a read lock, then queue a writer.
        let _read = read_blocking(&lock, &cx);
        let mut write_fut = lock.write(&cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "writer queued", true, pending);

        // try_read should fail because writer_waiters > 0.
        let blocked = matches!(lock.try_read(), Err(TryReadError::Locked));
        crate::assert_with_log!(blocked, "try_read blocked by writer waiter", true, blocked);
        crate::test_complete!("test_try_read_blocked_by_writer_waiters");
    }
}
