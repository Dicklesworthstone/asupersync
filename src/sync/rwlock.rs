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

#![allow(unsafe_code)]

use parking_lot::Mutex as ParkingMutex;
use smallvec::SmallVec;
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

/// Error returned when acquiring a read or write lock fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RwLockError {
    /// The lock was poisoned (a panic occurred while holding a guard).
    Poisoned,
    /// Cancelled while waiting.
    Cancelled,
    /// The future was polled again after it already returned `Ready`.
    PolledAfterCompletion,
}

impl std::fmt::Display for RwLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => write!(f, "rwlock poisoned"),
            Self::Cancelled => write!(f, "rwlock acquisition cancelled"),
            Self::PolledAfterCompletion => write!(f, "rwlock future polled after completion"),
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
    next_waiter_id: u64,
}

#[derive(Debug, Clone)]
struct Waiter {
    waker: Waker,
    id: u64,
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
/// If a panic occurs while holding a **write** guard, the lock is poisoned.
/// Subsequent acquisition attempts will return `RwLockError::Poisoned`.
/// Read guards do not poison the lock since they cannot corrupt data.
#[derive(Debug)]
pub struct RwLock<T> {
    state: ParkingMutex<State>,
    data: UnsafeCell<T>,
    poisoned: AtomicBool,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Creates a new lock containing the given value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            state: ParkingMutex::new(State::default()),
            data: UnsafeCell::new(value),
            poisoned: AtomicBool::new(false),
        }
    }

    /// Consumes the lock and returns the inner value.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> T {
        assert!(!self.is_poisoned(), "rwlock poisoned");
        self.data.into_inner()
    }
}

impl<T> RwLock<T> {
    /// Returns true if the lock is poisoned.
    #[inline]
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Acquires a read guard asynchronously, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    #[inline]
    pub fn read<'a, 'b>(&'a self, cx: &'b Cx) -> ReadFuture<'a, 'b, T> {
        ReadFuture {
            lock: self,
            cx,
            waiter_id: None,
            completed: false,
        }
    }

    /// Tries to acquire a read guard without waiting.
    #[inline]
    pub fn try_read(&self) -> Result<RwLockReadGuard<'_, T>, TryReadError> {
        self.try_acquire_read_state()?;
        Ok(RwLockReadGuard { lock: self })
    }

    /// Acquires a write guard asynchronously, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    #[inline]
    pub fn write<'a, 'b>(&'a self, cx: &'b Cx) -> WriteFuture<'a, 'b, T> {
        WriteFuture {
            lock: self,
            cx,
            waiter_id: None,
            counted: false,
            completed: false,
        }
    }

    /// Tries to acquire a write guard without waiting.
    #[inline]
    pub fn try_write(&self) -> Result<RwLockWriteGuard<'_, T>, TryWriteError> {
        self.try_acquire_write_state()?;
        Ok(RwLockWriteGuard { lock: self })
    }

    /// Returns a mutable reference to the inner value.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        assert!(!self.is_poisoned(), "rwlock poisoned");
        self.data.get_mut()
    }

    #[inline]
    fn try_acquire_read_state(&self) -> Result<(), TryReadError> {
        let mut state = self.state.lock();
        if self.is_poisoned() {
            return Err(TryReadError::Poisoned);
        }

        if state.writer_active || state.writer_waiters > 0 {
            return Err(TryReadError::Locked);
        }

        state.readers += 1;
        drop(state);
        Ok(())
    }

    #[inline]
    fn try_acquire_write_state(&self) -> Result<(), TryWriteError> {
        let mut state = self.state.lock();
        if self.is_poisoned() {
            return Err(TryWriteError::Poisoned);
        }

        if state.writer_active || state.readers > 0 || state.writer_waiters > 0 {
            return Err(TryWriteError::Locked);
        }

        state.writer_active = true;
        drop(state);
        Ok(())
    }

    #[inline]
    fn pop_writer_waiter(state: &mut State) -> Option<Waker> {
        state.writer_queue.pop_front().map(|w| w.waker)
    }

    #[inline]
    fn drain_reader_waiters(state: &mut State) -> SmallVec<[Waker; 4]> {
        state.reader_waiters.drain(..).map(|w| w.waker).collect()
    }

    #[inline]
    fn should_wake_writer(state: &State) -> bool {
        if state.writer_queue.is_empty() {
            return false;
        }
        if state.reader_waiters.is_empty() {
            return true;
        }

        // Both queues are non-empty. Wake whichever waiter arrived first.
        // Wrapping arithmetic keeps ordering stable across waiter-id wraparound.
        match (state.writer_queue.front(), state.reader_waiters.front()) {
            (Some(writer), Some(reader)) => writer.id.wrapping_sub(reader.id).cast_signed() < 0,
            _ => false,
        }
    }

    #[inline]
    fn release_reader(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.readers = state.readers.saturating_sub(1);
            if state.readers == 0 && state.writer_waiters > 0 {
                let waker = Self::pop_writer_waiter(&mut state);
                if waker.is_some() {
                    state.writer_active = true;
                }
                waker
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    #[inline]
    fn release_writer(&self) {
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            state.writer_active = false;

            let wake_writer = Self::should_wake_writer(&state);
            if wake_writer {
                let waker = Self::pop_writer_waiter(&mut state);
                if waker.is_some() {
                    state.writer_active = true;
                }
                (waker, SmallVec::new())
            } else {
                let wakers = Self::drain_reader_waiters(&mut state);
                state.readers += wakers.len();
                drop(state);
                (None, wakers)
            }
        };
        if let Some(waker) = writer_waker {
            waker.wake();
        }
        for waker in reader_wakers {
            waker.wake();
        }
    }

    #[inline]
    fn abandon_read_waiter(&self, waiter_id: &mut Option<u64>) {
        let Some(waiter_id) = waiter_id.take() else {
            return;
        };

        let writer_waker = {
            let mut state = self.state.lock();
            if let Some(pos) = state.reader_waiters.iter().position(|w| w.id == waiter_id) {
                state.reader_waiters.remove(pos);
                None
            } else {
                // We were granted the lock but never took the guard.
                state.readers = state.readers.saturating_sub(1);
                if state.readers == 0 && state.writer_waiters > 0 {
                    let waker = Self::pop_writer_waiter(&mut state);
                    if waker.is_some() {
                        state.writer_active = true;
                    }
                    waker
                } else {
                    None
                }
            }
        };

        if let Some(waker) = writer_waker {
            waker.wake();
        }
    }

    #[inline]
    fn abandon_write_waiter(&self, waiter_id: &mut Option<u64>, counted: &mut bool) {
        if !*counted {
            return;
        }

        let waiter_id = waiter_id.take();
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            let result = if let Some(waiter_id) = waiter_id {
                if let Some(pos) = state.writer_queue.iter().position(|w| w.id == waiter_id) {
                    state.writer_queue.remove(pos);
                    state.writer_waiters = state.writer_waiters.saturating_sub(1);
                    if state.writer_waiters == 0 && !state.writer_active {
                        let wakers = Self::drain_reader_waiters(&mut state);
                        state.readers += wakers.len();
                        (None, wakers)
                    } else {
                        (None, SmallVec::<[Waker; 4]>::new())
                    }
                } else {
                    // We were granted the lock but never took the guard.
                    state.writer_waiters = state.writer_waiters.saturating_sub(1);
                    state.writer_active = false;

                    let wake_writer = Self::should_wake_writer(&state);
                    if wake_writer {
                        let waker = Self::pop_writer_waiter(&mut state);
                        if waker.is_some() {
                            state.writer_active = true;
                        }
                        (waker, SmallVec::<[Waker; 4]>::new())
                    } else {
                        let wakers = Self::drain_reader_waiters(&mut state);
                        state.readers += wakers.len();
                        (None, wakers)
                    }
                }
            } else {
                // We incremented writer_waiters but never enqueued successfully.
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                if state.writer_waiters == 0 && !state.writer_active {
                    let wakers = Self::drain_reader_waiters(&mut state);
                    state.readers += wakers.len();
                    (None, wakers)
                } else {
                    (None, SmallVec::<[Waker; 4]>::new())
                }
            };
            drop(state);
            result
        };

        *counted = false;

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

// Guards removed.

/// Future returned by `RwLock::read`.
pub struct ReadFuture<'a, 'b, T> {
    lock: &'a RwLock<T>,
    cx: &'b Cx,
    waiter_id: Option<u64>,
    completed: bool,
}

impl<'a, T> Future for ReadFuture<'a, '_, T> {
    type Output = Result<RwLockReadGuard<'a, T>, RwLockError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(RwLockError::PolledAfterCompletion));
        }
        if this.cx.checkpoint().is_err() {
            this.lock.abandon_read_waiter(&mut this.waiter_id);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = this.lock.state.lock();

        if this.lock.is_poisoned() {
            drop(state);
            this.lock.abandon_read_waiter(&mut this.waiter_id);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if let Some(waiter_id) = this.waiter_id {
            if let Some(existing) = state.reader_waiters.iter_mut().find(|w| w.id == waiter_id) {
                if !existing.waker.will_wake(context.waker()) {
                    existing.waker.clone_from(context.waker());
                }
                drop(state);
                return Poll::Pending;
            }
            // Dequeued - we were pre-granted the lock by release_writer!
            // `state.readers` was already incremented for us.
            this.waiter_id = None;
            drop(state);
            this.completed = true;
            return Poll::Ready(Ok(RwLockReadGuard { lock: this.lock }));
        }

        if !state.writer_active && state.writer_waiters == 0 {
            state.readers += 1;
            drop(state);
            this.completed = true;
            return Poll::Ready(Ok(RwLockReadGuard { lock: this.lock }));
        }

        let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        state.reader_waiters.push_back(Waiter {
            waker: context.waker().clone(),
            id,
        });
        drop(state);
        this.waiter_id = Some(id);
        Poll::Pending
    }
}

impl<T> Drop for ReadFuture<'_, '_, T> {
    fn drop(&mut self) {
        self.lock.abandon_read_waiter(&mut self.waiter_id);
    }
}

/// Future returned by `RwLock::write`.
pub struct WriteFuture<'a, 'b, T> {
    lock: &'a RwLock<T>,
    cx: &'b Cx,
    waiter_id: Option<u64>,
    counted: bool,
    completed: bool,
}

impl<'a, T> Future for WriteFuture<'a, '_, T> {
    type Output = Result<RwLockWriteGuard<'a, T>, RwLockError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(RwLockError::PolledAfterCompletion));
        }
        if this.cx.checkpoint().is_err() {
            this.lock
                .abandon_write_waiter(&mut this.waiter_id, &mut this.counted);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = this.lock.state.lock();

        if this.lock.is_poisoned() {
            drop(state);
            this.lock
                .abandon_write_waiter(&mut this.waiter_id, &mut this.counted);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if !this.counted {
            state.writer_waiters += 1;
            this.counted = true;
        }

        if let Some(waiter_id) = this.waiter_id {
            if let Some(existing) = state.writer_queue.iter_mut().find(|w| w.id == waiter_id) {
                if !existing.waker.will_wake(context.waker()) {
                    existing.waker.clone_from(context.waker());
                }
                drop(state);
                return Poll::Pending;
            }
            // Dequeued - we were pre-granted the lock!
            this.waiter_id = None;
            if this.counted {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                this.counted = false;
            }
            drop(state);
            this.completed = true;
            return Poll::Ready(Ok(RwLockWriteGuard { lock: this.lock }));
        }

        let can_acquire =
            !state.writer_active && state.readers == 0 && state.writer_queue.is_empty();

        if can_acquire {
            state.writer_active = true;
            if this.counted {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                this.counted = false;
            }
            drop(state);
            this.completed = true;
            return Poll::Ready(Ok(RwLockWriteGuard { lock: this.lock }));
        }

        let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        state.writer_queue.push_back(Waiter {
            waker: context.waker().clone(),
            id,
        });
        drop(state);
        this.waiter_id = Some(id);
        Poll::Pending
    }
}

impl<T> Drop for WriteFuture<'_, '_, T> {
    fn drop(&mut self) {
        self.lock
            .abandon_write_waiter(&mut self.waiter_id, &mut self.counted);
    }
}

/// Guard for a read lock.
#[must_use = "guard will be immediately released if not held"]
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

unsafe impl<T: Send + Sync> Send for RwLockReadGuard<'_, T> {}
unsafe impl<T: Send + Sync> Sync for RwLockReadGuard<'_, T> {}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for RwLockReadGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.release_reader();
    }
}

/// Guard for a write lock.
#[must_use = "guard will be immediately released if not held"]
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

unsafe impl<T: Send> Send for RwLockWriteGuard<'_, T> {}
// RwLockWriteGuard provides &mut T via DerefMut, so sharing the guard
// across threads (Sync) requires T: Send + Sync — same as std.
unsafe impl<T: Send + Sync> Sync for RwLockWriteGuard<'_, T> {}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for RwLockWriteGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
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
            waiter_id: None,
            completed: false,
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
        assert!(!self.lock.is_poisoned(), "rwlock poisoned");
        f(unsafe { &*self.lock.data.get() })
    }
}

impl<T> Deref for OwnedRwLockReadGuard<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for OwnedRwLockReadGuard<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl<T> Drop for OwnedRwLockReadGuard<T> {
    #[inline]
    fn drop(&mut self) {
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
            waiter_id: None,
            counted: false,
            completed: false,
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
        assert!(!self.lock.is_poisoned(), "rwlock poisoned");
        f(unsafe { &mut *self.lock.data.get() })
    }
}

impl<T> Deref for OwnedRwLockWriteGuard<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for OwnedRwLockWriteGuard<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for OwnedRwLockWriteGuard<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl<T> Drop for OwnedRwLockWriteGuard<T> {
    #[inline]
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
    waiter_id: Option<u64>,
    completed: bool,
}

impl<T> Future for OwnedReadFuture<'_, T> {
    type Output = Result<OwnedRwLockReadGuard<T>, RwLockError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(RwLockError::PolledAfterCompletion));
        }
        if this.cx.checkpoint().is_err() {
            this.lock.abandon_read_waiter(&mut this.waiter_id);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = this.lock.state.lock();

        if this.lock.is_poisoned() {
            drop(state);
            this.lock.abandon_read_waiter(&mut this.waiter_id);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if let Some(waiter_id) = this.waiter_id {
            if let Some(existing) = state.reader_waiters.iter_mut().find(|w| w.id == waiter_id) {
                if !existing.waker.will_wake(context.waker()) {
                    existing.waker.clone_from(context.waker());
                }
                drop(state);
                return Poll::Pending;
            }
            // Dequeued - we were pre-granted the lock by release_writer!
            // `state.readers` was already incremented for us.
            drop(state);
            this.waiter_id = None;
            this.completed = true;
            return Poll::Ready(Ok(OwnedRwLockReadGuard {
                lock: Arc::clone(&this.lock),
            }));
        }

        if !state.writer_active && state.writer_waiters == 0 {
            state.readers += 1;
            drop(state);
            this.completed = true;
            return Poll::Ready(Ok(OwnedRwLockReadGuard {
                lock: Arc::clone(&this.lock),
            }));
        }

        let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        state.reader_waiters.push_back(Waiter {
            waker: context.waker().clone(),
            id,
        });
        drop(state);
        this.waiter_id = Some(id);
        Poll::Pending
    }
}

impl<T> Drop for OwnedReadFuture<'_, T> {
    fn drop(&mut self) {
        self.lock.abandon_read_waiter(&mut self.waiter_id);
    }
}

/// Future returned by `OwnedRwLockWriteGuard::write`.
pub struct OwnedWriteFuture<'b, T> {
    lock: Arc<RwLock<T>>,
    cx: &'b Cx,
    waiter_id: Option<u64>,
    counted: bool,
    completed: bool,
}

impl<T> Future for OwnedWriteFuture<'_, T> {
    type Output = Result<OwnedRwLockWriteGuard<T>, RwLockError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(RwLockError::PolledAfterCompletion));
        }

        if this.cx.checkpoint().is_err() {
            this.lock
                .abandon_write_waiter(&mut this.waiter_id, &mut this.counted);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Cancelled));
        }

        let mut state = this.lock.state.lock();

        if this.lock.is_poisoned() {
            drop(state);
            this.lock
                .abandon_write_waiter(&mut this.waiter_id, &mut this.counted);
            this.completed = true;
            return Poll::Ready(Err(RwLockError::Poisoned));
        }

        if !this.counted {
            state.writer_waiters += 1;
            this.counted = true;
        }

        if let Some(waiter_id) = this.waiter_id {
            if let Some(existing) = state.writer_queue.iter_mut().find(|w| w.id == waiter_id) {
                if !existing.waker.will_wake(context.waker()) {
                    existing.waker.clone_from(context.waker());
                }
                drop(state);
                return Poll::Pending;
            }
            // Dequeued - we were pre-granted the lock!
            if this.counted {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
            }
            drop(state);
            this.waiter_id = None;
            this.counted = false;
            this.completed = true;
            return Poll::Ready(Ok(OwnedRwLockWriteGuard {
                lock: Arc::clone(&this.lock),
            }));
        }

        let can_acquire =
            !state.writer_active && state.readers == 0 && state.writer_queue.is_empty();

        if can_acquire {
            state.writer_active = true;
            if this.counted {
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
            }
            drop(state);
            this.counted = false;
            this.completed = true;
            return Poll::Ready(Ok(OwnedRwLockWriteGuard {
                lock: Arc::clone(&this.lock),
            }));
        }

        let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        state.writer_queue.push_back(Waiter {
            waker: context.waker().clone(),
            id,
        });
        drop(state);
        this.waiter_id = Some(id);
        Poll::Pending
    }
}

impl<T> Drop for OwnedWriteFuture<'_, T> {
    fn drop(&mut self) {
        self.lock
            .abandon_write_waiter(&mut self.waiter_id, &mut self.counted);
    }
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
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
        test_cx_with_slot(0)
    }

    fn test_cx_with_slot(slot: u32) -> Cx {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, slot)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, slot)),
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
    fn cancel_queued_write_waiter_cleans_state_before_drop() {
        init_test("cancel_queued_write_waiter_cleans_state_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(10);
        let lock = RwLock::new(42_u32);

        let read_guard = read_blocking(&lock, &cx);

        let mut write_fut = lock.write(&cancel_cx);
        let write_pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(write_pending, "write waiter pending", true, write_pending);

        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(
            read_pending,
            "reader blocked by queued writer",
            true,
            read_pending
        );

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut write_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "write waiter cancelled", true, cancelled);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0 && state.writer_queue.is_empty(),
            "write waiter removed without drop",
            true,
            state.writer_waiters == 0 && state.writer_queue.is_empty()
        );

        let read_result = poll_once(&mut read_fut);
        let reader_acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "reader unblocked before cancelled writer future is dropped",
            true,
            reader_acquired
        );

        if let Some(Ok(guard)) = read_result {
            drop(guard);
        }
        drop(read_guard);
        drop(write_fut);
        crate::test_complete!("cancel_queued_write_waiter_cleans_state_before_drop");
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
    fn cancel_pregranted_read_waiter_wakes_writer_before_drop() {
        init_test("cancel_pregranted_read_waiter_wakes_writer_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(11);
        let lock = RwLock::new(0_u32);

        let active_writer = write_blocking(&lock, &cx);

        let mut read_fut = lock.read(&cancel_cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "reader queued", true, read_pending);

        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(writer_pending, "writer queued", true, writer_pending);

        drop(active_writer);

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut read_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "pre-granted reader cancelled", true, cancelled);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.readers == 0 && state.reader_waiters.is_empty() && state.writer_active,
            "pre-granted reader cleanup forwarded turn to writer",
            true,
            state.readers == 0 && state.reader_waiters.is_empty() && state.writer_active
        );

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "writer acquires before cancelled reader future is dropped",
            true,
            writer_acquired
        );

        if let Some(Ok(guard)) = writer_result {
            drop(guard);
        }
        drop(read_fut);
        crate::test_complete!("cancel_pregranted_read_waiter_wakes_writer_before_drop");
    }

    #[test]
    fn read_future_second_poll_fails_closed() {
        init_test("read_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        let mut fut = lock.read(&cx);
        let first = poll_once(&mut fut);
        let Some(Ok(guard)) = first else {
            panic!("expected ready read guard");
        };

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(done, "read future second poll fails closed", true, done);

        drop(guard);
        crate::test_complete!("read_future_second_poll_fails_closed");
    }

    #[test]
    fn write_future_second_poll_fails_closed() {
        init_test("write_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        let mut fut = lock.write(&cx);
        let first = poll_once(&mut fut);
        let Some(Ok(mut guard)) = first else {
            panic!("expected ready write guard");
        };
        *guard = 55;

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(done, "write future second poll fails closed", true, done);

        drop(guard);
        crate::test_complete!("write_future_second_poll_fails_closed");
    }

    #[test]
    fn owned_read_future_second_poll_fails_closed() {
        init_test("owned_read_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let mut fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
        let first = poll_once(&mut fut);
        let Some(Ok(guard)) = first else {
            panic!("expected ready owned read guard");
        };

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(
            done,
            "owned read future second poll fails closed",
            true,
            done
        );

        drop(guard);
        crate::test_complete!("owned_read_future_second_poll_fails_closed");
    }

    #[test]
    fn owned_write_future_second_poll_fails_closed() {
        init_test("owned_write_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let mut fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
        let first = poll_once(&mut fut);
        let Some(Ok(mut guard)) = first else {
            panic!("expected ready owned write guard");
        };
        *guard = 77;

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(
            done,
            "owned write future second poll fails closed",
            true,
            done
        );

        drop(guard);
        crate::test_complete!("owned_write_future_second_poll_fails_closed");
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
        let order = StdArc::new(parking_lot::Mutex::new(Vec::new()));

        // Hold a read lock so writers must queue.
        let read_guard = read_blocking(&lock, &cx);

        let mut handles = Vec::new();
        for id in 1..=3_u32 {
            let lock_c = StdArc::clone(&lock);
            let order_c = StdArc::clone(&order);
            handles.push(thread::spawn(move || {
                let cx = test_cx();
                let mut guard = write_blocking(&lock_c, &cx);
                order_c.lock().push(id);
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

        let final_order = order.lock().clone();
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
    fn release_writer_prefers_older_writer_over_reader() {
        init_test("release_writer_prefers_older_writer_over_reader");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold active writer so both waiters queue.
        let active_writer = write_blocking(&lock, &cx);

        // Queue writer first (older), then reader.
        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_pending,
            "queued writer is pending",
            true,
            writer_pending
        );

        let mut reader_fut = lock.read(&cx);
        let reader_pending = poll_once(&mut reader_fut).is_none();
        crate::assert_with_log!(
            reader_pending,
            "queued reader is pending",
            true,
            reader_pending
        );

        // Releasing active writer should wake the older queued writer first.
        drop(active_writer);

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "older writer acquires before reader",
            true,
            writer_acquired
        );

        let reader_still_pending = poll_once(&mut reader_fut).is_none();
        crate::assert_with_log!(
            reader_still_pending,
            "reader remains pending while writer holds lock",
            true,
            reader_still_pending
        );

        if let Some(Ok(writer_guard)) = writer_result {
            drop(writer_guard);
        }

        let reader_result = poll_once(&mut reader_fut);
        let reader_acquired = matches!(reader_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "reader acquires after writer releases",
            true,
            reader_acquired
        );
        crate::test_complete!("release_writer_prefers_older_writer_over_reader");
    }

    #[test]
    fn release_writer_prefers_older_reader_over_writer() {
        init_test("release_writer_prefers_older_reader_over_writer");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold active writer so both waiters queue.
        let active_writer = write_blocking(&lock, &cx);

        // Queue reader first (older), then writer.
        let mut reader_fut = lock.read(&cx);
        let reader_pending = poll_once(&mut reader_fut).is_none();
        crate::assert_with_log!(
            reader_pending,
            "queued reader is pending",
            true,
            reader_pending
        );

        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_pending,
            "queued writer is pending",
            true,
            writer_pending
        );

        // Releasing active writer should wake the older queued reader first.
        drop(active_writer);

        let reader_result = poll_once(&mut reader_fut);
        let reader_acquired = matches!(reader_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "older reader acquires before writer",
            true,
            reader_acquired
        );

        let writer_still_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_still_pending,
            "writer remains pending while reader holds lock",
            true,
            writer_still_pending
        );

        if let Some(Ok(reader_guard)) = reader_result {
            drop(reader_guard);
        }

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "writer acquires after reader releases",
            true,
            writer_acquired
        );
        crate::test_complete!("release_writer_prefers_older_reader_over_writer");
    }

    #[test]
    fn test_write_future_drop_wakes_readers_when_last_writer() {
        // When the last queued WriteFuture is dropped without acquiring,
        // pending readers must be woken.
        init_test("test_write_future_drop_wakes_readers_when_last_writer");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Queue a writer (it will count itself in writer_waiters).
        let write_guard = write_blocking(&lock, &cx);
        let mut write_fut = lock.write(&cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "write future pending", true, pending);

        // Queue a reader (blocked because writer_waiters > 0).
        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "read future pending", true, read_pending);

        // Release the active writer.
        drop(write_guard);

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

        // Release active writer. Since writer_waiters > 0, this wakes the second
        // writer directly and DOES NOT dequeue the reader.
        drop(write_guard);

        // Drop the read future without polling. It simply removes itself from the queue.
        // The second writer is already woken and will acquire the lock.
        drop(read_fut);

        let _ = handle.join();
        let done = writer_done.load(AtomicOrdering::Acquire);
        crate::assert_with_log!(done, "second writer eventually acquired", true, done);
        crate::test_complete!("test_read_future_drop_forwards_wake_to_writer");
    }

    #[test]
    fn test_owned_read_guard_basic() {
        init_test("test_owned_read_guard_basic");
        let _cx = test_cx();
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
        let _cx = test_cx();
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
    fn owned_cancel_queued_read_waiter_cleans_state_before_drop() {
        init_test("owned_cancel_queued_read_waiter_cleans_state_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(12);
        let lock = StdArc::new(RwLock::new(0_u32));

        let active_writer = write_blocking(lock.as_ref(), &cx);

        let mut read_fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cancel_cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "owned reader queued", true, read_pending);

        let mut writer_fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(writer_pending, "owned writer queued", true, writer_pending);

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut read_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "owned reader cancelled", true, cancelled);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.reader_waiters.is_empty(),
            "owned reader waiter removed without drop",
            true,
            state.reader_waiters.is_empty()
        );

        drop(active_writer);

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "owned writer acquires before cancelled reader future is dropped",
            true,
            writer_acquired
        );

        if let Some(Ok(guard)) = writer_result {
            drop(guard);
        }
        drop(read_fut);
        crate::test_complete!("owned_cancel_queued_read_waiter_cleans_state_before_drop");
    }

    #[test]
    fn owned_cancel_pregranted_write_waiter_unblocks_readers_before_drop() {
        init_test("owned_cancel_pregranted_write_waiter_unblocks_readers_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(13);
        let lock = StdArc::new(RwLock::new(42_u32));

        let read_guard = read_blocking(lock.as_ref(), &cx);

        let mut write_fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cancel_cx);
        let write_pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(write_pending, "owned writer queued", true, write_pending);

        let mut read_fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(
            read_pending,
            "owned reader blocked by queued writer",
            true,
            read_pending
        );

        drop(read_guard);

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut write_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(
            cancelled,
            "pre-granted owned writer cancelled",
            true,
            cancelled
        );

        let state = lock.debug_state();
        crate::assert_with_log!(
            !state.writer_active && state.writer_waiters == 0,
            "pre-granted owned writer cleanup released writer slot",
            true,
            !state.writer_active && state.writer_waiters == 0
        );

        let read_result = poll_once(&mut read_fut);
        let reader_acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "owned reader acquires before cancelled writer future is dropped",
            true,
            reader_acquired
        );

        if let Some(Ok(guard)) = read_result {
            drop(guard);
        }
        drop(write_fut);
        crate::test_complete!("owned_cancel_pregranted_write_waiter_unblocks_readers_before_drop");
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
        let read = read_blocking(&lock, &cx);
        let mut write_fut = lock.write(&cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "writer queued", true, pending);

        // try_read should fail because writer_waiters > 0.
        let try_read_guard = lock.try_read();
        crate::assert_with_log!(
            try_read_guard.is_err(),
            "try_read blocked by writer waiter",
            true,
            try_read_guard.is_err()
        );

        drop(read);
        crate::test_complete!("test_try_read_blocked_by_writer_waiters");
    }

    // ── Invariant: cancel write waiter unblocks readers ────────────────

    /// Invariant: when the only write waiter is cancelled and dropped,
    /// `writer_waiters` drops to 0 and blocked readers must be able to
    /// acquire the lock.  This tests the `WriteFuture::drop` path that
    /// drains `reader_waiters` when `writer_waiters == 0`.
    #[test]
    fn cancel_only_write_waiter_unblocks_readers() {
        init_test("cancel_only_write_waiter_unblocks_readers");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Hold a read lock so a write waiter must queue.
        let read_guard = read_blocking(&lock, &cx);

        // Create a write waiter with a cancellable context.
        let cancel_cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 10)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 10)),
            crate::types::Budget::INFINITE,
        );
        let mut write_fut = lock.write(&cancel_cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "write waiter pending", true, pending);

        // Now try to read — should be blocked by writer_waiters > 0.
        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(
            read_pending,
            "reader blocked by writer waiter",
            true,
            read_pending
        );

        // Cancel and drop the write waiter.
        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut write_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "write waiter cancelled", true, cancelled);
        drop(write_fut);

        // Verify writer_waiters is 0.
        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0,
            "writer_waiters cleared",
            0usize,
            state.writer_waiters
        );

        // The blocked reader should now be able to acquire.
        let read_result = poll_once(&mut read_fut);
        let reader_acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "reader unblocked after write cancel",
            true,
            reader_acquired
        );

        drop(read_guard);
        crate::test_complete!("cancel_only_write_waiter_unblocks_readers");
    }

    /// Invariant: dropping a `WriteFuture` that was polled once (counted=true,
    /// waiter_id assigned) correctly decrements `writer_waiters` and removes
    /// from `writer_queue`.  This simulates a `select!` drop.
    #[test]
    fn drop_write_future_cleans_writer_waiters_counter() {
        init_test("drop_write_future_cleans_writer_waiters_counter");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold a read lock so writers must queue.
        let _read = read_blocking(&lock, &cx);

        // Create two write waiters.
        let mut w1 = lock.write(&cx);
        let _ = poll_once(&mut w1);
        let mut w2 = lock.write(&cx);
        let _ = poll_once(&mut w2);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 2,
            "2 writer waiters",
            2usize,
            state.writer_waiters
        );

        // Drop w1 (simulating select! cancel).
        drop(w1);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 1,
            "1 writer waiter after drop",
            1usize,
            state.writer_waiters
        );
        crate::assert_with_log!(
            state.writer_queue.len() == 1,
            "1 in writer queue after drop",
            1usize,
            state.writer_queue.len()
        );

        // Drop w2.
        drop(w2);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0,
            "0 writer waiters after both dropped",
            0usize,
            state.writer_waiters
        );
        crate::test_complete!("drop_write_future_cleans_writer_waiters_counter");
    }

    /// Invariant: poison propagation through read/write/try_read/try_write.
    /// A panic while holding a write guard poisons the lock; subsequent
    /// operations must return the appropriate Poisoned error.
    #[test]
    fn rwlock_poison_propagation() {
        init_test("rwlock_poison_propagation");
        let lock = StdArc::new(RwLock::new(0_u32));

        let l = StdArc::clone(&lock);
        let handle = thread::spawn(move || {
            let cx = test_cx();
            let _guard = write_blocking(&l, &cx);
            panic!("poison rwlock");
        });
        let _ = handle.join();

        let poisoned = lock.is_poisoned();
        crate::assert_with_log!(poisoned, "rwlock is poisoned", true, poisoned);

        let try_read = lock.try_read();
        let read_is_poisoned = matches!(try_read, Err(TryReadError::Poisoned));
        crate::assert_with_log!(
            read_is_poisoned,
            "try_read Poisoned",
            true,
            read_is_poisoned
        );

        let try_write = lock.try_write();
        let write_is_poisoned = matches!(try_write, Err(TryWriteError::Poisoned));
        crate::assert_with_log!(
            write_is_poisoned,
            "try_write Poisoned",
            true,
            write_is_poisoned
        );

        let cx = test_cx();
        let mut read_fut = lock.read(&cx);
        let read_result = poll_once(&mut read_fut);
        let read_poisoned = matches!(read_result, Some(Err(RwLockError::Poisoned)));
        crate::assert_with_log!(read_poisoned, "read() Poisoned", true, read_poisoned);

        let mut write_fut = lock.write(&cx);
        let write_result = poll_once(&mut write_fut);
        let write_poisoned = matches!(write_result, Some(Err(RwLockError::Poisoned)));
        crate::assert_with_log!(write_poisoned, "write() Poisoned", true, write_poisoned);

        crate::test_complete!("rwlock_poison_propagation");
    }

    // Pure data-type tests (wave 38 – CyanBarn)

    #[test]
    fn rwlock_error_debug_clone_copy_eq_display() {
        let poisoned = RwLockError::Poisoned;
        let cancelled = RwLockError::Cancelled;
        let polled_after_completion = RwLockError::PolledAfterCompletion;

        let dbg = format!("{poisoned:?}");
        assert!(dbg.contains("Poisoned"));

        let cloned = poisoned;
        assert_eq!(cloned, RwLockError::Poisoned);
        assert_ne!(poisoned, cancelled);
        assert_ne!(poisoned, polled_after_completion);

        assert!(poisoned.to_string().contains("poisoned"));
        assert!(cancelled.to_string().contains("cancelled"));
        assert!(
            polled_after_completion
                .to_string()
                .contains("polled after completion")
        );
    }

    #[test]
    fn try_read_error_debug_clone_copy_eq_display() {
        let locked = TryReadError::Locked;
        let poisoned = TryReadError::Poisoned;

        let dbg = format!("{locked:?}");
        assert!(dbg.contains("Locked"));

        let copied = locked;
        assert_eq!(copied, TryReadError::Locked);
        assert_ne!(locked, poisoned);

        assert!(locked.to_string().contains("write-locked"));
        assert!(poisoned.to_string().contains("poisoned"));
    }

    #[test]
    fn try_write_error_debug_clone_copy_eq_display() {
        let locked = TryWriteError::Locked;
        let poisoned = TryWriteError::Poisoned;

        let dbg = format!("{locked:?}");
        assert!(dbg.contains("Locked"));

        let copied = locked;
        assert_eq!(copied, TryWriteError::Locked);
        assert_ne!(locked, poisoned);

        assert!(locked.to_string().contains("locked"));
        assert!(poisoned.to_string().contains("poisoned"));
    }

    #[test]
    fn rwlock_debug() {
        let lock = RwLock::new(42_i32);
        let dbg = format!("{lock:?}");
        assert!(dbg.contains("RwLock"));
    }

    struct CountWaker(StdArc<std::sync::atomic::AtomicUsize>);
    impl std::task::Wake for CountWaker {
        fn wake(self: StdArc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_drop_queued_writer_wakes_readers_when_readers_active() {
        init_test("test_drop_queued_writer_wakes_readers_when_readers_active");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let wake_state = StdArc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = Waker::from(StdArc::new(CountWaker(wake_state.clone())));
        let mut task_cx = Context::from_waker(&waker);

        // 1. Hold a read lock.
        let mut fut_read1 = lock.read(&cx);
        let Poll::Ready(Ok(_guard1)) = std::pin::Pin::new(&mut fut_read1).poll(&mut task_cx) else {
            panic!("Expected Ready")
        };

        // 2. Queue a writer.
        let mut fut_write = lock.write(&cx);
        let pending_write = std::pin::Pin::new(&mut fut_write).poll(&mut task_cx);
        assert!(pending_write.is_pending());

        // 3. Queue a second reader. It blocks because of the writer.
        let mut fut_read2 = lock.read(&cx);
        let pending_read = std::pin::Pin::new(&mut fut_read2).poll(&mut task_cx);
        assert!(pending_read.is_pending());

        wake_state.store(0, AtomicOrdering::SeqCst);

        // 4. Drop the writer. This should wake the second reader because writer_waiters becomes 0,
        // and even though there is an active reader, multiple readers can run concurrently.
        drop(fut_write);

        let wake_count = wake_state.load(AtomicOrdering::SeqCst);
        crate::assert_with_log!(
            wake_count > 0,
            "reader woken after writer drop",
            true,
            wake_count > 0
        );
        crate::test_complete!("test_drop_queued_writer_wakes_readers_when_readers_active");
    }
}
