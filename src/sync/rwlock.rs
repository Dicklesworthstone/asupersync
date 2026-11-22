//! Cancel-aware read-write lock with guard cleanup.
//!
//! This RwLock allows multiple readers or a single writer with write-preferring
//! fairness. Acquisition is cancel-safe:
//! - Cancellation while waiting returns an error without acquiring the lock.
//! - Once acquired, guards always release on drop.
//!
//! # Writer-Preference Fairness
//!
//! This RwLock uses a **bounded writer-preference** policy: new read requests
//! normally queue behind a waiting writer, but a long enough queued-writer run
//! forces a FIFO turn for the oldest queued reader. This prevents writer
//! starvation under heavy read load while also bounding reader admission by
//! queue position under continued progress.
//!
//! ## Fairness Characteristics
//!
//! | Scenario                    | Behavior                                        |
//! |-----------------------------|-------------------------------------------------|
//! | No writer active or waiting | Readers acquire immediately                     |
//! | Writer waiting              | New readers queue, subject to forced FIFO turns |
//! | Existing readers + writer   | Writer waits for all readers to release         |
//! | Multiple writers            | Writers queue in arrival order (FIFO)           |
//!
//! ## Starvation Analysis
//!
//! - **Writer starvation**: Prevented. Waiting writers normally block new
//!   readers, and the head writer resumes after any forced FIFO reader turn.
//! - **Reader starvation**: Bounded by FIFO queue position, measured in
//!   queued-writer hand-offs. Let `N` be
//!   [`MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH`]. For an unpoisoned lock and
//!   a subject reader that remains queued, continued release and polling progress
//!   forces a turn for exactly the oldest queued reader after every `N`
//!   consecutive writer hand-offs while a further writer remains queued. A
//!   reader with `p` older queued readers is therefore admitted after at most
//!   `(p + 1) * N` additional queued-writer hand-offs. Writer-queue drain or
//!   cancellation of older waiters may admit it earlier; cancelling the subject
//!   ends its acquisition. This is not a wall-clock bound: guard duration and task
//!   scheduling or polling delays are outside the claim (br-asupersync-4j40bb).
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

use crate::sync::pl::Mutex as ParkingMutex;
use smallvec::SmallVec;
use std::cell::UnsafeCell;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use super::waiter::{WaiterChain, WaiterId};
use crate::cx::Cx;
use crate::sync::lock_ordering::{self, LockRank};
use crate::trace::distributed::{LogicalClockHandle, LogicalTime};

/// br-asupersync-4j40bb: maximum gap, in queued-writer hand-offs, between
/// forced FIFO reader turns while readers and further writers remain queued.
/// Each threshold crossing admits exactly the oldest queued reader before the
/// head writer resumes. Writing `N` for this constant, an unpoisoned lock with a
/// subject reader that remains queued admits that reader, under continued
/// release and polling progress, after at most `(p + 1) * N` additional
/// queued-writer hand-offs when `p` older readers are queued. Queue drain or
/// cancellation of older waiters may admit it earlier; cancelling the subject
/// ends its acquisition. Guard duration and scheduling or polling delays are not
/// bounded.
///
/// Tuning: 16 preserves long writer runs while still placing a finite hand-off
/// bound on successive forced reader turns.
const MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH: usize = 16;

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
    #[inline]
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
    #[inline]
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
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "rwlock is locked"),
            Self::Poisoned => write!(f, "rwlock poisoned"),
        }
    }
}

impl std::error::Error for TryWriteError {}

#[derive(Debug, Clone, Default)]
struct State {
    readers: usize,
    writer_active: bool,
    writer_waiters: usize,
    reader_waiters: WaiterChain<u64>,
    writer_queue: WaiterChain<u64>,
    next_waiter_id: u64,
    /// br-asupersync-4j40bb: count of consecutive writer hand-offs from
    /// the queue while readers were also queued. Reset to 0 whenever a
    /// reader admission runs (a forced turn or a natural batch).
    consecutive_writers_served: usize,
    /// Allocated only after a release from an opt-in task-causality runtime.
    causality: Option<Box<RwLockCausality>>,
}

/// A cancel-aware read-write lock with bounded writer-preference fairness.
///
/// This lock allows multiple readers to access the data concurrently, or a single
/// writer to have exclusive access. New read attempts normally queue behind a
/// waiting writer, with periodic FIFO reader turns bounding admission under
/// continued queued-writer pressure.
///
/// # Fairness Policy
///
/// - **Writer-preference**: When `writer_waiters > 0`, new readers normally
///   queue behind the head writer.
/// - **Bounded reader admission**: Under sustained queued-writer pressure, each
///   threshold-length writer run gives exactly the oldest queued reader a turn.
/// - **Reader parallelism**: Multiple readers can hold the lock simultaneously
///   when no writer is waiting or active; a forced turn admits one reader.
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
/// A panic while a **write** guard is held poisons the lock: later acquisitions return
/// `RwLockError::Poisoned`. Read guards never poison. A write guard acquired while its thread was
/// already panicking never poisons, even if it is moved to another thread or task and panics there.
#[derive(Debug)]
pub struct RwLock<T> {
    state: ParkingMutex<State>,
    data: UnsafeCell<T>,
    poisoned: AtomicBool,
    /// Human-readable name for lock ordering (e.g., "tasks", "regions").
    name: &'static str,
    /// Lock rank for deadlock prevention.
    rank: Option<LockRank>,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Creates a new lock. Under `lock-metrics`, panics if `name` violates lock policy.
    #[inline]
    #[must_use]
    pub fn with_name(name: &'static str, value: T) -> Self {
        let rank = lock_ordering::rank_for_lock_name(name);
        Self {
            state: ParkingMutex::new(State::default()),
            data: UnsafeCell::new(value),
            poisoned: AtomicBool::new(false),
            name,
            rank,
        }
    }

    /// Creates a new lock containing the given value with default naming.
    ///
    /// Note: For proper deadlock prevention, prefer `with_name()` to specify
    /// the lock's role in the lock hierarchy (e.g., "tasks", "regions").
    #[inline]
    #[must_use]
    pub fn new(value: T) -> Self {
        Self::with_name("unknown", value)
    }

    /// Consumes the lock and returns the inner value.
    ///
    /// Consumes this lock, returning the underlying data.
    ///
    /// Returns an error if the lock is poisoned.
    #[inline]
    pub fn into_inner(self) -> Result<T, RwLockError> {
        if self.is_poisoned() {
            return Err(RwLockError::Poisoned);
        }
        Ok(self.data.into_inner())
    }
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
    pub fn read<'a, 'b, Caps>(&'a self, cx: &'b Cx<Caps>) -> ReadFuture<'a, 'b, T, Caps> {
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
        let (lock_order, causal_owner) = self.try_acquire_read_state()?;
        Ok(RwLockReadGuard {
            lock: self,
            lock_order,
            causal_owner,
        })
    }

    /// Acquires a write guard asynchronously, waiting if necessary.
    ///
    /// This is cancel-safe: cancellation while waiting returns an error
    /// without acquiring the lock.
    #[inline]
    pub fn write<'a, 'b, Caps>(&'a self, cx: &'b Cx<Caps>) -> WriteFuture<'a, 'b, T, Caps> {
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
        let (lock_order, causal_owner) = self.try_acquire_write_state()?;
        Ok(RwLockWriteGuard {
            lock: self,
            lock_order,
            causal_owner,
            panicking_at_acquire: std::thread::panicking(),
        })
    }

    /// Returns a mutable reference to the inner value.
    ///
    /// Returns an error if the lock is poisoned.
    #[inline]
    pub fn get_mut(&mut self) -> Result<&mut T, RwLockError> {
        if self.is_poisoned() {
            return Err(RwLockError::Poisoned);
        }
        Ok(self.data.get_mut())
    }

    #[inline]
    fn try_acquire_read_state(
        &self,
    ) -> Result<(lock_ordering::GuardLockOrder, Option<RwLockCausalOwner>), TryReadError> {
        let mut state = self.state.lock();
        if self.is_poisoned() {
            return Err(TryReadError::Poisoned);
        }

        if state.writer_active || state.writer_waiters > 0 {
            return Err(TryReadError::Locked);
        }

        // Enforce lock ordering only on the success path, under the state guard
        // and immediately before the transition, mirroring the async read
        // acquisition. A failed try_read must return Err rather than panic with
        // ASUP-E205 or record a phantom acquisition edge (br-asupersync-1dydby).
        if let Some(rank) = self.rank {
            lock_ordering::check_acquire(self.name, rank);
        }

        let causal_owner =
            state.acquire_read_causality(Cx::with_current(RwLockCausalOwner::from_cx).flatten());
        state.readers += 1;
        drop(state);

        // Record lock acquisition for ordering tracking
        Ok((
            lock_ordering::record_guard_acquire(self.name, self.rank),
            causal_owner,
        ))
    }

    #[inline]
    fn try_acquire_write_state(
        &self,
    ) -> Result<(lock_ordering::GuardLockOrder, Option<RwLockCausalOwner>), TryWriteError> {
        let mut state = self.state.lock();
        if self.is_poisoned() {
            return Err(TryWriteError::Poisoned);
        }

        if state.writer_active || state.readers > 0 || state.writer_waiters > 0 {
            return Err(TryWriteError::Locked);
        }

        // Enforce lock ordering only on the success path, under the state guard
        // and immediately before the transition, mirroring the async write
        // acquisition. A failed try_write must return Err rather than panic with
        // ASUP-E205 or record a phantom acquisition edge (br-asupersync-1dydby).
        if let Some(rank) = self.rank {
            lock_ordering::check_acquire(self.name, rank);
        }

        let causal_owner =
            state.acquire_write_causality(Cx::with_current(RwLockCausalOwner::from_cx).flatten());
        state.writer_active = true;
        drop(state);

        // Record lock acquisition for ordering tracking
        Ok((
            lock_ordering::record_guard_acquire(self.name, self.rank),
            causal_owner,
        ))
    }

    #[inline]
    fn pop_writer_waiter(state: &mut State) -> Option<Waker> {
        state.writer_queue.pop_front().map(|(_, waker, _)| waker)
    }

    #[inline]
    fn drain_reader_waiters(state: &mut State) -> SmallVec<[Waker; 4]> {
        let mut wakers = SmallVec::new();
        while let Some((_, waker, _)) = state.reader_waiters.pop_front() {
            wakers.push(waker);
        }
        wakers
    }

    /// Wakes a released batch of waiters -- an optional writer baton followed by
    /// the eligible readers -- with per-wake panic isolation, so one hostile
    /// safe Waker cannot strand the peers whose reader slots were already
    /// reserved under the state lock (br-asupersync-dkubr0). The first panic is
    /// retained, the fanout completes, then it is resumed once -- unless this
    /// runs inside an existing unwind (a guard Drop during a panic), where the
    /// wakes have already been delivered and resuming would abort, so the
    /// payload is dropped instead.
    fn wake_released_waiters(writer_waker: Option<Waker>, reader_wakers: SmallVec<[Waker; 4]>) {
        let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
        let mut isolate = |waker: Waker| {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    waker.wake();
                }))
                && first_panic.is_none()
            {
                first_panic = Some(payload);
            }
        };
        if let Some(waker) = writer_waker {
            isolate(waker);
        }
        for waker in reader_wakers {
            isolate(waker);
        }
        // `isolate` holds the only mutable borrow of `first_panic`; NLL ends it
        // at the last call above, so the payload is readable here. A `drop` call
        // would be a no-op on a closure and trips `drop_non_drop`.
        if let Some(payload) = first_panic {
            if std::thread::panicking() {
                drop(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }

    #[inline]
    fn queued_waiter_wakers(state: &mut State) -> SmallVec<[Waker; 4]> {
        let mut wakers = SmallVec::new();
        wakers.extend(state.reader_waiters.clone_wakers_deferred());
        wakers.extend(state.writer_queue.clone_wakers_deferred());
        wakers
    }

    #[inline]
    fn reader_arrived_before_writer(reader_id: u64, writer_id: u64) -> bool {
        // AUDIT: Potential fairness issue on wraparound. This logic assumes
        // IDs are close in value, but after billions of operations, wraparound
        // could cause incorrect ordering when mixing very old and very new IDs.
        // Risk is low due to the huge ID space (2^64).
        reader_id.wrapping_sub(writer_id).cast_signed() < 0
    }

    #[inline]
    fn take_eligible_reader_waiters(state: &mut State) -> SmallVec<[Waker; 4]> {
        let Some(first_writer_id) = state.writer_queue.front_tag().copied() else {
            return Self::drain_reader_waiters(state);
        };

        let mut wakers = SmallVec::new();
        while state.reader_waiters.front_tag().is_some_and(|reader_id| {
            Self::reader_arrived_before_writer(*reader_id, first_writer_id)
        }) {
            if let Some((_, waker, _)) = state.reader_waiters.pop_front() {
                wakers.push(waker);
            }
        }
        wakers
    }

    #[inline]
    fn take_forced_reader_turn(state: &mut State) -> SmallVec<[Waker; 4]> {
        let mut wakers = SmallVec::new();
        if let Some((_, waker, _)) = state.reader_waiters.pop_front() {
            wakers.push(waker);
        }
        wakers
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
        match (
            state.writer_queue.front_tag().copied(),
            state.reader_waiters.front_tag().copied(),
        ) {
            (Some(writer_id), Some(reader_id)) => {
                !Self::reader_arrived_before_writer(reader_id, writer_id)
            }
            _ => false,
        }
    }

    /// Reserves the next turn after the last active or pregranted slot is
    /// released. Every handoff must compare the remaining queues: cancelling
    /// an older writer can leave readers ahead of the next writer even when
    /// the released slot belonged to a reader (asupersync-c11v6v, item 8).
    #[inline]
    fn grant_next_waiters(&self, state: &mut State) -> (Option<Waker>, SmallVec<[Waker; 4]>) {
        debug_assert_eq!(state.readers, 0);
        debug_assert!(!state.writer_active);

        if self.is_poisoned() {
            // Poisoned waiters must observe the error while their queue
            // registrations remain intact; do not reserve acquisition slots.
            return (None, Self::queued_waiter_wakers(state));
        }

        // br-asupersync-4j40bb: after N writer handoffs while readers waited,
        // admit exactly one oldest reader. With no queued writer, admit all
        // readers instead, preserving their ability to run concurrently.
        let force_reader_turn = state.consecutive_writers_served
            >= MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH
            && !state.reader_waiters.is_empty()
            && !state.writer_queue.is_empty();

        if !force_reader_turn && Self::should_wake_writer(state) {
            let waker = Self::pop_writer_waiter(state);
            if waker.is_some() {
                state.writer_active = true;
                // Only count writer handoffs while readers actually wait.
                if state.reader_waiters.is_empty() {
                    state.consecutive_writers_served = 0;
                } else {
                    state.consecutive_writers_served =
                        state.consecutive_writers_served.saturating_add(1);
                }
            }
            (waker, SmallVec::new())
        } else {
            let wakers = if force_reader_turn {
                Self::take_forced_reader_turn(state)
            } else {
                // Readers younger than the head writer remain queued, so a
                // cancelled predecessor cannot let them bypass that writer.
                Self::take_eligible_reader_waiters(state)
            };
            state.readers += wakers.len();
            if !wakers.is_empty() {
                state.consecutive_writers_served = 0;
            }
            (None, wakers)
        }
    }

    #[inline]
    fn release_reader(&self, causal_owner: Option<RwLockCausalOwner>) {
        let causal_owner = RwLockCausalOwner::for_release(causal_owner);
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            state.release_read_causality(causal_owner.as_ref());
            state.readers = state.readers.saturating_sub(1);
            if state.readers == 0 {
                self.grant_next_waiters(&mut state)
            } else {
                (None, SmallVec::new())
            }
        };
        Self::wake_released_waiters(writer_waker, reader_wakers);
    }

    #[inline]
    fn release_writer(&self, causal_owner: Option<RwLockCausalOwner>) {
        let causal_owner = RwLockCausalOwner::for_release(causal_owner);
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            state.release_write_causality(causal_owner.as_ref());
            state.writer_active = false;
            self.grant_next_waiters(&mut state)
        };
        Self::wake_released_waiters(writer_waker, reader_wakers);
    }

    #[inline]
    fn abandon_read_waiter(&self, waiter_id: &mut Option<WaiterId>) {
        let Some(waiter_id) = waiter_id.take() else {
            return;
        };

        // Declared before the state guard so unwinding always releases the
        // guard before destroying a user-controlled RawWaker payload.
        let retired_waker;
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            retired_waker = state.reader_waiters.remove(waiter_id);
            if retired_waker.is_some() {
                (None, SmallVec::new())
            } else {
                // We were granted the lock but never took the guard.
                // Lock-order acquisition is recorded only when the future
                // observes this grant on its next poll, so nothing is released here.
                state.readers = state.readers.saturating_sub(1);

                if state.readers == 0 {
                    self.grant_next_waiters(&mut state)
                } else {
                    (None, SmallVec::new())
                }
            }
        };

        Self::wake_released_waiters(writer_waker, reader_wakers);
        drop(retired_waker);
    }

    #[inline]
    fn abandon_write_waiter(&self, waiter_id: &mut Option<WaiterId>, counted: &mut bool) {
        if !*counted {
            return;
        }

        let waiter_id = waiter_id.take();
        let poisoned = self.is_poisoned();
        // Declared before the state guard so unwinding always releases the
        // guard before destroying a user-controlled RawWaker payload.
        let retired_waker;
        let (writer_waker, reader_wakers) = {
            let mut state = self.state.lock();
            retired_waker = waiter_id.and_then(|id| state.writer_queue.remove(id));
            let result = if waiter_id.is_some() {
                if retired_waker.is_some() {
                    state.writer_waiters = state.writer_waiters.saturating_sub(1);
                    if state.writer_waiters == 0 && !state.writer_active {
                        if poisoned {
                            (None, SmallVec::<[Waker; 4]>::new())
                        } else {
                            let wakers = Self::drain_reader_waiters(&mut state);
                            state.readers += wakers.len();
                            (None, wakers)
                        }
                    } else {
                        (None, SmallVec::<[Waker; 4]>::new())
                    }
                } else {
                    // We were granted the lock but never took the guard.
                    // Lock-order acquisition is recorded only when the future
                    // observes this grant on its next poll, so nothing is released here.
                    state.writer_waiters = state.writer_waiters.saturating_sub(1);
                    state.writer_active = false;

                    self.grant_next_waiters(&mut state)
                }
            } else {
                // We incremented writer_waiters but never enqueued successfully.
                state.writer_waiters = state.writer_waiters.saturating_sub(1);
                if state.writer_waiters == 0 && !state.writer_active {
                    if poisoned {
                        (None, SmallVec::<[Waker; 4]>::new())
                    } else {
                        let wakers = Self::drain_reader_waiters(&mut state);
                        state.readers += wakers.len();
                        (None, wakers)
                    }
                } else {
                    (None, SmallVec::<[Waker; 4]>::new())
                }
            };
            drop(state);
            result
        };

        *counted = false;

        Self::wake_released_waiters(writer_waker, reader_wakers);
        drop(retired_waker);
    }

    #[cfg(test)]
    fn debug_state(&self) -> State {
        (*self.state.lock()).clone()
    }
}

// Guards removed.

/// Future returned by `RwLock::read`.
pub struct ReadFuture<'a, 'b, T, Caps = crate::cx::cap::All> {
    lock: &'a RwLock<T>,
    cx: &'b Cx<Caps>,
    waiter_id: Option<WaiterId>,
    completed: bool,
}

impl<'a, T, Caps> Future for ReadFuture<'a, '_, T, Caps> {
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

        let mut queued_waker = None;
        loop {
            let mut state = this.lock.state.lock();

            if this.lock.is_poisoned() {
                drop(state);
                this.lock.abandon_read_waiter(&mut this.waiter_id);
                this.completed = true;
                return Poll::Ready(Err(RwLockError::Poisoned));
            }

            if let Some(waiter_id) = this.waiter_id {
                if queued_waker.is_none() {
                    drop(state);
                    queued_waker = Some(context.waker().clone());
                    continue;
                }

                let new_waker = queued_waker.take().expect("queued read cloned a waker");
                match state.reader_waiters.replace_waker(waiter_id, new_waker) {
                    Ok(retired_waker) => {
                        drop(state);
                        drop(retired_waker);
                        return Poll::Pending;
                    }
                    Err(unused_waker) => {
                        // Dequeued - we were pre-granted the lock by release_writer!
                        // `state.readers` was already incremented for us.

                        drop(state);
                        drop(unused_waker);

                        // Check and record lock acquisition for ordering tracking.
                        // Queued handoffs must enforce the same E->D->B->A->C
                        // ordering as immediate acquisition.
                        if let Some(rank) = this.lock.rank {
                            lock_ordering::check_acquire(this.lock.name, rank);
                        }
                        let causal_owner = this
                            .lock
                            .state
                            .lock()
                            .acquire_read_causality(RwLockCausalOwner::for_acquire(this.cx));
                        let lock_order =
                            lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);
                        this.waiter_id = None;
                        this.completed = true;
                        return Poll::Ready(Ok(RwLockReadGuard {
                            lock: this.lock,
                            lock_order,
                            causal_owner,
                        }));
                    }
                }
            }

            if !state.writer_active && state.writer_waiters == 0 {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = this.lock.rank {
                    lock_ordering::check_acquire(this.lock.name, rank);
                }

                let causal_owner =
                    state.acquire_read_causality(RwLockCausalOwner::for_acquire(this.cx));
                state.readers += 1;
                drop(state);

                // Record lock acquisition for ordering tracking
                let lock_order =
                    lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);

                this.completed = true;
                return Poll::Ready(Ok(RwLockReadGuard {
                    lock: this.lock,
                    lock_order,
                    causal_owner,
                }));
            }

            if queued_waker.is_none() {
                drop(state);
                queued_waker = Some(context.waker().clone());
                continue;
            }

            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let waiter_id = state
                .reader_waiters
                .push_back_tagged(queued_waker.take().expect("queued read cloned a waker"), id);
            drop(state);
            this.waiter_id = Some(waiter_id);
            return Poll::Pending;
        }
    }
}

impl<T, Caps> Drop for ReadFuture<'_, '_, T, Caps> {
    fn drop(&mut self) {
        self.lock.abandon_read_waiter(&mut self.waiter_id);
    }
}

/// Future returned by `RwLock::write`.
pub struct WriteFuture<'a, 'b, T, Caps = crate::cx::cap::All> {
    lock: &'a RwLock<T>,
    cx: &'b Cx<Caps>,
    waiter_id: Option<WaiterId>,
    counted: bool,
    completed: bool,
}

impl<'a, T, Caps> Future for WriteFuture<'a, '_, T, Caps> {
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

        let mut queued_waker = None;
        loop {
            let mut state = this.lock.state.lock();

            if this.lock.is_poisoned() {
                drop(state);
                this.lock
                    .abandon_write_waiter(&mut this.waiter_id, &mut this.counted);
                this.completed = true;
                return Poll::Ready(Err(RwLockError::Poisoned));
            }

            if let Some(waiter_id) = this.waiter_id {
                if queued_waker.is_none() {
                    drop(state);
                    queued_waker = Some(context.waker().clone());
                    continue;
                }

                let new_waker = queued_waker.take().expect("queued write cloned a waker");
                match state.writer_queue.replace_waker(waiter_id, new_waker) {
                    Ok(retired_waker) => {
                        drop(state);
                        drop(retired_waker);
                        return Poll::Pending;
                    }
                    Err(unused_waker) => {
                        // Dequeued - we were pre-granted the lock!

                        drop(state);
                        drop(unused_waker);

                        // Check and record lock acquisition for ordering tracking.
                        // Queued handoffs must enforce the same E->D->B->A->C
                        // ordering as immediate acquisition.
                        if let Some(rank) = this.lock.rank {
                            lock_ordering::check_acquire(this.lock.name, rank);
                        }
                        let mut state = this.lock.state.lock();
                        let causal_owner =
                            state.acquire_write_causality(RwLockCausalOwner::for_acquire(this.cx));
                        let lock_order =
                            lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);
                        this.waiter_id = None;
                        if this.counted {
                            state.writer_waiters = state.writer_waiters.saturating_sub(1);
                            this.counted = false;
                        }
                        drop(state);
                        this.completed = true;
                        return Poll::Ready(Ok(RwLockWriteGuard {
                            lock: this.lock,
                            lock_order,
                            causal_owner,
                            panicking_at_acquire: std::thread::panicking(),
                        }));
                    }
                }
            }

            let can_acquire =
                !state.writer_active && state.readers == 0 && state.writer_queue.is_empty();

            if can_acquire {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = this.lock.rank {
                    lock_ordering::check_acquire(this.lock.name, rank);
                }

                let causal_owner =
                    state.acquire_write_causality(RwLockCausalOwner::for_acquire(this.cx));
                state.writer_active = true;
                // Only count as waiting writer if we actually queue
                drop(state);

                // Record lock acquisition for ordering tracking
                let lock_order =
                    lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);

                this.completed = true;
                return Poll::Ready(Ok(RwLockWriteGuard {
                    lock: this.lock,
                    lock_order,
                    causal_owner,
                    panicking_at_acquire: std::thread::panicking(),
                }));
            }

            if queued_waker.is_none() {
                drop(state);
                queued_waker = Some(context.waker().clone());
                continue;
            }

            // Only increment writer_waiters when we must actually queue.
            if !this.counted {
                state.writer_waiters += 1;
                this.counted = true;
            }
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let waiter_id = state.writer_queue.push_back_tagged(
                queued_waker.take().expect("queued write cloned a waker"),
                id,
            );
            drop(state);
            this.waiter_id = Some(waiter_id);
            return Poll::Pending;
        }
    }
}

impl<T, Caps> Drop for WriteFuture<'_, '_, T, Caps> {
    fn drop(&mut self) {
        self.lock
            .abandon_write_waiter(&mut self.waiter_id, &mut self.counted);
    }
}

/// Guard for a read lock.
#[must_use = "guard will be immediately released if not held"]
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
    lock_order: lock_ordering::GuardLockOrder,
    causal_owner: Option<RwLockCausalOwner>,
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
        // End diagnostic ownership before release_reader can invoke a user-controlled Waker that panics.
        lock_ordering::record_guard_release(&mut self.lock_order);
        self.lock.release_reader(self.causal_owner.take());
    }
}

/// Guard for a write lock.
#[must_use = "guard will be immediately released if not held"]
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
    lock_order: lock_ordering::GuardLockOrder,
    causal_owner: Option<RwLockCausalOwner>,
    panicking_at_acquire: bool,
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
        if !self.panicking_at_acquire && std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        lock_ordering::record_guard_release(&mut self.lock_order);
        self.lock.release_writer(self.causal_owner.take());
    }
}

impl<'a, T> RwLockWriteGuard<'a, T> {
    /// Atomically downgrades the write lock to a read lock.
    ///
    /// This operation is atomic - there is no race window where the lock
    /// is unlocked between releasing the write lock and acquiring the read lock.
    /// Any waiting readers will be woken up since the exclusive access is relaxed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut write_guard = lock.write(&cx).await?;
    /// *write_guard = 42;
    ///
    /// let read_guard = write_guard.downgrade();
    /// assert_eq!(*read_guard, 42);
    /// ```
    pub fn downgrade(mut self) -> RwLockReadGuard<'a, T> {
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        let causal_owner = RwLockCausalOwner::for_release(self.causal_owner.take());
        let md = std::mem::ManuallyDrop::new(self);
        let read_guard = RwLockReadGuard {
            lock: md.lock,
            lock_order,
            causal_owner,
        };

        // Atomically transition from writer to reader
        let reader_wakers = {
            let mut state = md.lock.state.lock();

            // Atomic transition: writer_active -> reader
            debug_assert!(state.writer_active, "downgrade called but no active writer");
            state.release_write_causality(read_guard.causal_owner.as_ref());
            state.writer_active = false;
            state.readers = 1; // This downgraded reader

            // Wake only readers that are not queued behind the first writer.
            // Downgrade relaxes exclusivity for the current writer, but it must
            // preserve the same writer-preference boundary as release_writer().
            let wakers = RwLock::<T>::take_eligible_reader_waiters(&mut state);
            state.readers += wakers.len();
            if !wakers.is_empty() {
                state.consecutive_writers_served = 0;
            }

            wakers
        };

        // Wake readers outside the lock
        RwLock::<T>::wake_released_waiters(None, reader_wakers);

        read_guard
    }
}

/// Owned read guard that can be moved between tasks.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedRwLockReadGuard<T> {
    lock: Arc<RwLock<T>>,
    lock_order: lock_ordering::GuardLockOrder,
    causal_owner: Option<RwLockCausalOwner>,
}

impl<T> OwnedRwLockReadGuard<T> {
    /// Acquires an owned read guard from an `Arc<RwLock<T>>`.
    pub fn read<Caps>(lock: Arc<RwLock<T>>, cx: &Cx<Caps>) -> OwnedReadFuture<'_, T, Caps> {
        OwnedReadFuture {
            lock,
            cx,
            waiter_id: None,
            completed: false,
        }
    }

    /// Tries to acquire an owned read guard without waiting.
    pub fn try_read(lock: Arc<RwLock<T>>) -> Result<Self, TryReadError> {
        let (lock_order, causal_owner) = lock.try_acquire_read_state()?;
        Ok(Self {
            lock,
            lock_order,
            causal_owner,
        })
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
        lock_ordering::record_guard_release(&mut self.lock_order);
        self.lock.release_reader(self.causal_owner.take());
    }
}

/// Owned write guard that can be moved between tasks.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedRwLockWriteGuard<T> {
    lock: Arc<RwLock<T>>,
    lock_order: lock_ordering::GuardLockOrder,
    causal_owner: Option<RwLockCausalOwner>,
    panicking_at_acquire: bool,
}

impl<T> OwnedRwLockWriteGuard<T> {
    /// Acquires an owned write guard from an `Arc<RwLock<T>>`.
    pub fn write<Caps>(lock: Arc<RwLock<T>>, cx: &Cx<Caps>) -> OwnedWriteFuture<'_, T, Caps> {
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
        let (lock_order, causal_owner) = lock.try_acquire_write_state()?;
        Ok(Self {
            lock,
            lock_order,
            causal_owner,
            panicking_at_acquire: std::thread::panicking(),
        })
    }

    /// Executes a closure with exclusive access to the data.
    pub fn with_write<F: FnOnce(&mut T) -> R, R>(&mut self, f: F) -> R {
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
        if !self.panicking_at_acquire && std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        lock_ordering::record_guard_release(&mut self.lock_order);
        self.lock.release_writer(self.causal_owner.take());
    }
}

impl<T> OwnedRwLockWriteGuard<T> {
    /// Atomically downgrades the owned write lock to an owned read lock.
    ///
    /// This operation is atomic - there is no race window where the lock
    /// is unlocked between releasing the write lock and acquiring the read lock.
    /// Any waiting readers will be woken up since the exclusive access is relaxed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut write_guard = OwnedRwLockWriteGuard::write(lock, &cx).await?;
    /// write_guard.with_write(|data| *data = 42);
    ///
    /// let read_guard = write_guard.downgrade();
    /// read_guard.with_read(|data| assert_eq!(*data, 42));
    /// ```
    pub fn downgrade(mut self) -> OwnedRwLockReadGuard<T> {
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        let causal_owner = RwLockCausalOwner::for_release(self.causal_owner.take());
        let md = std::mem::ManuallyDrop::new(self);
        let lock = unsafe { std::ptr::read(&md.lock) };

        let read_guard = OwnedRwLockReadGuard {
            lock,
            lock_order,
            causal_owner,
        };

        // Atomically transition from writer to reader
        let reader_wakers = {
            let mut state = read_guard.lock.state.lock();

            // Atomic transition: writer_active -> reader
            debug_assert!(state.writer_active, "downgrade called but no active writer");
            state.release_write_causality(read_guard.causal_owner.as_ref());
            state.writer_active = false;
            state.readers = 1; // This downgraded reader

            // Wake only readers that are not queued behind the first writer.
            // Downgrade relaxes exclusivity for the current writer, but it must
            // preserve the same writer-preference boundary as release_writer().
            let wakers = RwLock::<T>::take_eligible_reader_waiters(&mut state);
            state.readers += wakers.len();
            if !wakers.is_empty() {
                state.consecutive_writers_served = 0;
            }

            wakers
        };

        // Wake readers outside the lock
        RwLock::<T>::wake_released_waiters(None, reader_wakers);

        read_guard
    }
}

/// Future returned by `OwnedRwLockReadGuard::read`.
pub struct OwnedReadFuture<'b, T, Caps = crate::cx::cap::All> {
    lock: Arc<RwLock<T>>,
    cx: &'b Cx<Caps>,
    waiter_id: Option<WaiterId>,
    completed: bool,
}

impl<T, Caps> Future for OwnedReadFuture<'_, T, Caps> {
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

        let mut queued_waker = None;
        loop {
            let mut state = this.lock.state.lock();

            if this.lock.is_poisoned() {
                drop(state);
                this.lock.abandon_read_waiter(&mut this.waiter_id);
                this.completed = true;
                return Poll::Ready(Err(RwLockError::Poisoned));
            }

            if let Some(waiter_id) = this.waiter_id {
                if queued_waker.is_none() {
                    drop(state);
                    queued_waker = Some(context.waker().clone());
                    continue;
                }

                let new_waker = queued_waker
                    .take()
                    .expect("queued owned read cloned a waker");
                match state.reader_waiters.replace_waker(waiter_id, new_waker) {
                    Ok(retired_waker) => {
                        drop(state);
                        drop(retired_waker);
                        return Poll::Pending;
                    }
                    Err(unused_waker) => {
                        // Dequeued - we were pre-granted the lock by release_writer!
                        // `state.readers` was already incremented for us.

                        drop(state);
                        drop(unused_waker);

                        // Check and record lock acquisition for ordering tracking.
                        // Queued handoffs must enforce the same E->D->B->A->C
                        // ordering as immediate acquisition.
                        if let Some(rank) = this.lock.rank {
                            lock_ordering::check_acquire(this.lock.name, rank);
                        }
                        let causal_owner = this
                            .lock
                            .state
                            .lock()
                            .acquire_read_causality(RwLockCausalOwner::for_acquire(this.cx));
                        let lock_order =
                            lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);
                        this.waiter_id = None;
                        this.completed = true;
                        return Poll::Ready(Ok(OwnedRwLockReadGuard {
                            lock: Arc::clone(&this.lock),
                            lock_order,
                            causal_owner,
                        }));
                    }
                }
            }

            if !state.writer_active && state.writer_waiters == 0 {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = this.lock.rank {
                    lock_ordering::check_acquire(this.lock.name, rank);
                }

                let causal_owner =
                    state.acquire_read_causality(RwLockCausalOwner::for_acquire(this.cx));
                state.readers += 1;
                drop(state);

                // Record lock acquisition for ordering tracking
                let lock_order =
                    lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);

                this.completed = true;
                return Poll::Ready(Ok(OwnedRwLockReadGuard {
                    lock: Arc::clone(&this.lock),
                    lock_order,
                    causal_owner,
                }));
            }

            if queued_waker.is_none() {
                drop(state);
                queued_waker = Some(context.waker().clone());
                continue;
            }

            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let waiter_id = state.reader_waiters.push_back_tagged(
                queued_waker
                    .take()
                    .expect("queued owned read cloned a waker"),
                id,
            );
            drop(state);
            this.waiter_id = Some(waiter_id);
            return Poll::Pending;
        }
    }
}

impl<T, Caps> Drop for OwnedReadFuture<'_, T, Caps> {
    fn drop(&mut self) {
        self.lock.abandon_read_waiter(&mut self.waiter_id);
    }
}

/// Future returned by `OwnedRwLockWriteGuard::write`.
pub struct OwnedWriteFuture<'b, T, Caps = crate::cx::cap::All> {
    lock: Arc<RwLock<T>>,
    cx: &'b Cx<Caps>,
    waiter_id: Option<WaiterId>,
    counted: bool,
    completed: bool,
}

impl<T, Caps> Future for OwnedWriteFuture<'_, T, Caps> {
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

        let mut queued_waker = None;
        loop {
            let mut state = this.lock.state.lock();

            if this.lock.is_poisoned() {
                drop(state);
                this.lock
                    .abandon_write_waiter(&mut this.waiter_id, &mut this.counted);
                this.completed = true;
                return Poll::Ready(Err(RwLockError::Poisoned));
            }

            if let Some(waiter_id) = this.waiter_id {
                if queued_waker.is_none() {
                    drop(state);
                    queued_waker = Some(context.waker().clone());
                    continue;
                }

                let new_waker = queued_waker
                    .take()
                    .expect("queued owned write cloned a waker");
                match state.writer_queue.replace_waker(waiter_id, new_waker) {
                    Ok(retired_waker) => {
                        drop(state);
                        drop(retired_waker);
                        return Poll::Pending;
                    }
                    Err(unused_waker) => {
                        // Dequeued - we were pre-granted the lock!

                        drop(state);
                        drop(unused_waker);

                        // Check and record lock acquisition for ordering tracking.
                        // Queued handoffs must enforce the same E->D->B->A->C
                        // ordering as immediate acquisition.
                        if let Some(rank) = this.lock.rank {
                            lock_ordering::check_acquire(this.lock.name, rank);
                        }
                        let mut state = this.lock.state.lock();
                        let causal_owner =
                            state.acquire_write_causality(RwLockCausalOwner::for_acquire(this.cx));
                        let lock_order =
                            lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);
                        this.waiter_id = None;
                        if this.counted {
                            state.writer_waiters = state.writer_waiters.saturating_sub(1);
                            this.counted = false;
                        }
                        drop(state);
                        this.completed = true;
                        return Poll::Ready(Ok(OwnedRwLockWriteGuard {
                            lock: Arc::clone(&this.lock),
                            lock_order,
                            causal_owner,
                            panicking_at_acquire: std::thread::panicking(),
                        }));
                    }
                }
            }

            let can_acquire =
                !state.writer_active && state.readers == 0 && state.writer_queue.is_empty();

            if can_acquire {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = this.lock.rank {
                    lock_ordering::check_acquire(this.lock.name, rank);
                }

                let causal_owner =
                    state.acquire_write_causality(RwLockCausalOwner::for_acquire(this.cx));
                state.writer_active = true;
                // Only count as waiting writer if we actually queue
                drop(state);

                // Record lock acquisition for ordering tracking
                let lock_order =
                    lock_ordering::record_guard_acquire(this.lock.name, this.lock.rank);

                this.completed = true;
                return Poll::Ready(Ok(OwnedRwLockWriteGuard {
                    lock: Arc::clone(&this.lock),
                    lock_order,
                    causal_owner,
                    panicking_at_acquire: std::thread::panicking(),
                }));
            }

            if queued_waker.is_none() {
                drop(state);
                queued_waker = Some(context.waker().clone());
                continue;
            }

            // Only increment writer_waiters when we must actually queue.
            if !this.counted {
                state.writer_waiters += 1;
                this.counted = true;
            }

            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let waiter_id = state.writer_queue.push_back_tagged(
                queued_waker
                    .take()
                    .expect("queued owned write cloned a waker"),
                id,
            );
            drop(state);
            this.waiter_id = Some(waiter_id);
            return Poll::Pending;
        }
    }
}

impl<T, Caps> Drop for OwnedWriteFuture<'_, T, Caps> {
    fn drop(&mut self) {
        self.lock
            .abandon_write_waiter(&mut self.waiter_id, &mut self.counted);
    }
}

/// Evidence for the optional task-vector lab mode (asupersync-bi2462.97).
/// Readers observe only the last writer; their releases are joined separately
/// for the next writer, without imposing an order on sibling readers.
#[derive(Debug, Clone, Default)]
struct RwLockCausality {
    writer_released: Option<(u64, LogicalTime)>,
    readers_released: Option<(u64, LogicalTime)>,
}

#[derive(Debug)]
struct RwLockCausalOwner {
    runtime: u64,
    clock: LogicalClockHandle,
    allow_host_fallback: bool,
}

impl RwLockCausalOwner {
    fn from_cx<Caps>(cx: &Cx<Caps>) -> Option<Self> {
        cx.task_causality_runtime().map(|runtime| Self {
            runtime,
            clock: cx.logical_clock_handle(),
            allow_host_fallback: false,
        })
    }

    fn for_acquire<Caps>(cx: &Cx<Caps>) -> Option<Self> {
        // A future can be moved: the actual poller owns the critical section.
        // Only an explicitly host-driven acquisition may use its Cx on drop.
        Cx::with_current(Self::from_cx).unwrap_or_else(|| {
            Self::from_cx(cx).map(|mut owner| {
                owner.allow_host_fallback = true;
                owner
            })
        })
    }

    fn for_release(owner: Option<Self>) -> Option<Self> {
        // An untracked ambient task is still an authoritative dropper. Never
        // sample a former task's live clock after its guard has moved away.
        Cx::with_current(Self::from_cx)
            .unwrap_or_else(|| owner.filter(|owner| owner.allow_host_fallback))
    }

    fn observe(&self, released: Option<&(u64, LogicalTime)>) {
        if let Some((runtime, time)) = released
            && *runtime == self.runtime
        {
            let _ = self.clock.receive(time);
        }
    }
}

impl State {
    fn acquire_read_causality(
        &self,
        owner: Option<RwLockCausalOwner>,
    ) -> Option<RwLockCausalOwner> {
        if let Some(owner) = &owner {
            owner.observe(
                self.causality
                    .as_ref()
                    .and_then(|causality| causality.writer_released.as_ref()),
            );
        }
        owner
    }

    fn acquire_write_causality(
        &mut self,
        owner: Option<RwLockCausalOwner>,
    ) -> Option<RwLockCausalOwner> {
        if let Some(causality) = &mut self.causality {
            if let Some(owner) = &owner {
                owner.observe(causality.writer_released.as_ref());
                owner.observe(causality.readers_released.as_ref());
            }
            // Only an actual acquisition retires the reader cohort. A
            // cancelled or abandoned pre-grant must leave its evidence intact.
            causality.readers_released = None;
        }
        owner
    }

    fn release_read_causality(&mut self, owner: Option<&RwLockCausalOwner>) {
        let Some(owner) = owner else {
            return;
        };
        // Freeze evidence before making this reader's release visible. No
        // tick here: overflowing a task counter must not panic in guard Drop.
        let released = owner.clock.now();
        let causality = self.causality.get_or_insert_with(Default::default);
        if let Some((runtime, LogicalTime::Vector(readers))) = &mut causality.readers_released
            && *runtime == owner.runtime
            && let LogicalTime::Vector(reader) = &released
        {
            readers.merge_in(reader);
        } else {
            // Keep one joined snapshot, not an unbounded list of readers or
            // runtimes. Foreign-runtime evidence is conservatively replaced,
            // never merged into matching task IDs from another runtime.
            causality.readers_released = Some((owner.runtime, released));
        }
    }

    fn release_write_causality(&mut self, owner: Option<&RwLockCausalOwner>) {
        if let Some(owner) = owner {
            let released = (owner.runtime, owner.clock.now());
            let causality = self.causality.get_or_insert_with(Default::default);
            causality.writer_released = Some(released);
            causality.readers_released = None;
        } else if let Some(causality) = &mut self.causality {
            // Unknown ownership cannot republish a previous writer's evidence
            // as though it described this critical section.
            causality.writer_released = None;
            causality.readers_released = None;
        }
    }
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
#[allow(dead_code)]
#[path = "rwlock_inline_tests.rs"]
mod tests;

// ============================================================================
// Metamorphic Property Tests for RwLock Writer-Preference Fairness
// ============================================================================

/// Metamorphic property tests for RwLock writer-preference fairness behavior.
///
/// These tests verify RwLock invariants related to writer preference, reader concurrency,
/// cancellation behavior, and ref counting. Unlike unit tests that check exact outcomes,
/// metamorphic tests verify relationships between different execution scenarios.
#[cfg(test)]
#[path = "rwlock_metamorphic_tests_inline_tests.rs"]
mod metamorphic_tests;
