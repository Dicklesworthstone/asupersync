//! Two-phase async mutex with cancel-aware guard cleanup.
//!
//! An async mutex that allows holding the lock across await points.
//! Each acquired guard releases the mutex on drop; waiter cleanup is
//! cancel-safe while the lock future is still pending.
//!
//! # Cancel Safety
//!
//! The lock operation is split into two phases:
//! - **Phase 1**: Wait for lock availability (cancel-safe)
//! - **Phase 2**: Acquire lock and return a guard (cannot fail)
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
use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;
use crate::sync::lock_ordering::{self, LockRank};
use crate::time::Sleep;
use crate::types::Time;

/// Error returned when mutex locking fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockError {
    /// The mutex was poisoned (a panic occurred while holding the lock).
    Poisoned,
    /// Cancelled while waiting for the lock.
    Cancelled,
    /// The requested deadline elapsed before the lock could be acquired.
    TimedOut(Time),
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for LockError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => write!(f, "mutex poisoned"),
            Self::Cancelled => write!(f, "mutex lock cancelled"),
            Self::TimedOut(deadline) => write!(f, "mutex lock timed out at {deadline:?}"),
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
    /// Human-readable name for lock ordering (e.g., "tasks", "regions").
    name: &'static str,
    /// Lock rank for deadlock prevention.
    rank: Option<LockRank>,
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
    /// Waiter that has been granted the next turn but has not yet resumed.
    /// Holds the stable waiter id, not the reusable slab index.
    granted_waiter: Option<WaiterId>,
}

use super::waiter::{WaiterChain, WaiterId};

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state with the given name for lock ordering.
    #[inline]
    #[must_use]
    pub fn with_name(name: &'static str, value: T) -> Self {
        let rank = lock_ordering::rank_for_lock_name(name);
        Self {
            data: UnsafeCell::new(value),
            poisoned: AtomicBool::new(false),
            state: ParkingMutex::new(MutexState {
                locked: false,
                waiters: WaiterChain::new(),
                granted_waiter: None,
            }),
            name,
            rank,
        }
    }

    /// Creates a new mutex in an unlocked state with default naming.
    ///
    /// Note: For proper deadlock prevention, prefer `with_name()` to specify
    /// the mutex's role in the lock hierarchy (e.g., "tasks", "regions").
    #[inline]
    #[must_use]
    pub fn new(value: T) -> Self {
        Self::with_name("unknown", value)
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
    pub fn lock<'a, 'b, Caps>(&'a self, cx: &'b Cx<Caps>) -> LockFuture<'a, 'b, T, Caps> {
        LockFuture {
            mutex: self,
            cx,
            waiter_id: None,
            deadline_sleep: None,
            completed: false,
        }
    }

    /// Acquires the mutex asynchronously until the given deadline.
    ///
    /// Returns [`LockError::TimedOut`] if the deadline elapses before the lock
    /// can be acquired.
    #[inline]
    pub fn lock_until<'a, 'b, Caps>(
        &'a self,
        cx: &'b Cx<Caps>,
        deadline: Time,
    ) -> LockFuture<'a, 'b, T, Caps>
    where
        Caps: crate::cx::cap::HasTime,
    {
        LockFuture {
            mutex: self,
            cx,
            waiter_id: None,
            deadline_sleep: Some(cx.timer_driver().map_or_else(
                || Sleep::new(deadline),
                |timer| Sleep::with_timer_driver(deadline, timer),
            )),
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

        // Enforce lock ordering only on the success path, under the state guard
        // and immediately before the transition, mirroring the async
        // acquisition path. A failed try_lock must return Err rather than panic
        // with ASUP-E205 or record a phantom acquisition edge
        // (br-asupersync-1dydby).
        if let Some(rank) = self.rank {
            lock_ordering::check_acquire(self.name, rank);
        }

        state.locked = true;
        drop(state);

        // Record lock acquisition for ordering tracking
        let lock_order = lock_ordering::record_guard_acquire(self.name, self.rank);

        Ok(MutexGuard {
            mutex: self,
            lock_order,
            _not_send: PhantomData,
        })
    }

    /// Tries to acquire the mutex without waiting, returning an owned guard.
    ///
    /// The returned guard keeps an [`Arc`] to the mutex so it can move across
    /// scopes without borrowing the original handle.
    ///
    /// ```
    /// use asupersync::sync::Mutex;
    /// use std::sync::Arc;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mutex = Arc::new(Mutex::new(String::from("ready")));
    ///
    /// {
    ///     let mut guard = mutex.try_lock_owned()?;
    ///     guard.push_str("!");
    /// }
    ///
    /// let guard = mutex.try_lock_owned()?;
    /// assert_eq!(guard.as_str(), "ready!");
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_lock_owned(self: &Arc<Self>) -> Result<OwnedMutexGuard<T>, TryLockError> {
        OwnedMutexGuard::try_lock(Arc::clone(self))
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Returns an error if the mutex is poisoned.
    #[inline]
    pub fn get_mut(&mut self) -> Result<&mut T, LockError> {
        if self.is_poisoned() {
            return Err(LockError::Poisoned);
        }
        Ok(self.data.get_mut())
    }

    /// Consumes the mutex, returning the underlying data.
    ///
    /// Returns an error if the mutex is poisoned.
    #[inline]
    pub fn into_inner(self) -> Result<T, LockError> {
        if self.is_poisoned() {
            return Err(LockError::Poisoned);
        }
        Ok(self.data.into_inner())
    }

    #[inline]
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    /// Marks the mutex poisoned for tests and fuzz harnesses that need to model
    /// post-panic state without intentionally panicking inside the harness.
    #[cfg(any(test, feature = "test-internals"))]
    #[doc(hidden)]
    #[inline]
    pub fn poison_for_testing(&self) {
        self.poison();
    }

    #[inline]
    fn unlock(&self, mut lock_order: lock_ordering::GuardLockOrder) {
        // Extract the waker to wake outside the lock to prevent deadlocks.
        // Waking while holding the lock can cause priority inversion or deadlock
        // if the woken task tries to acquire another mutex.
        let granted = {
            let mut state = self.state.lock();
            state.locked = false;
            // br-asupersync-wlf0xh: O(1) FIFO take via slab pop_front.
            if let Some((id, waker, _)) = state.waiters.pop_front() {
                state.granted_waiter = Some(id);
                Some((id, waker))
            } else {
                state.granted_waiter = None;
                None
            }
        };

        // The mutex is no longer held, so update task-owned lock-order state
        // before invoking user-controlled wake code. A synchronous Waker may
        // re-enter a lower-ranked mutex, and a panicking Waker must not leave a
        // phantom held rank behind.
        lock_ordering::record_guard_release(&mut lock_order);

        // Wake outside the lock and after recording the rank release.
        if let Some((id, waker)) = granted {
            self.wake_granted(id, waker);
        }
    }

    /// Delivers a baton wake to the waiter pinned by `granted_waiter`,
    /// exception-safely (br-asupersync-mutex-panicking-grantee-freezes-fifo-l4sgpj).
    ///
    /// A panicking grantee `Waker` would otherwise leave the mutex unlocked
    /// with the grant still pinned to a task that was never woken: the fast
    /// path and `try_lock` both refuse while a grant is outstanding, so every
    /// later waiter would wait forever on a baton nobody holds. On a wake
    /// panic the failed grant is revoked — only if it is still pinned to the
    /// failed waiter, since a concurrent `cleanup_waiter` may already have
    /// resolved it — and the baton passes to the next eligible waiter. The
    /// first panic payload is resumed once the baton lands, unless this
    /// thread is already unwinding (every `unlock` is a guard drop, and
    /// `cleanup_waiter` also runs from `LockFuture::drop`): a second panic
    /// there would abort the process, so it is suppressed, matching the
    /// `Notify` drop fanout policy (br-asupersync-b3td9n).
    fn wake_granted(&self, id: crate::sync::waiter::WaiterId, waker: Waker) {
        let mut pending = Some((id, waker));
        let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
        while let Some((failed_id, waker)) = pending.take() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || waker.wake())) {
                Ok(()) => break,
                Err(payload) => {
                    if first_panic.is_none() {
                        first_panic = Some(payload);
                    }
                    let mut state = self.state.lock();
                    if state.granted_waiter == Some(failed_id) {
                        state.granted_waiter = None;
                        if !state.locked {
                            // br-asupersync-wlf0xh: O(1) FIFO take via slab
                            // pop_front.
                            if let Some((next_id, next_waker, _)) = state.waiters.pop_front() {
                                state.granted_waiter = Some(next_id);
                                pending = Some((next_id, next_waker));
                            }
                        }
                    }
                    // else: a concurrent cleanup already resolved the failed
                    // grant; the baton is no longer ours to pass.
                }
            }
        }
        if let Some(payload) = first_panic {
            if !std::thread::panicking() {
                std::panic::resume_unwind(payload);
            }
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
pub struct LockFuture<'a, 'b, T, Caps = crate::cx::cap::All> {
    mutex: &'a Mutex<T>,
    cx: &'b Cx<Caps>,
    /// Slab index of this waiter's slot in the parent mutex's
    /// `WaiterChain` (br-asupersync-wlf0xh).
    waiter_id: Option<crate::sync::waiter::WaiterId>,
    deadline_sleep: Option<Sleep>,
    completed: bool,
}

impl<T, Caps> LockFuture<'_, '_, T, Caps> {
    #[inline]
    fn poll_deadline_sleep(&mut self, context: &mut Context<'_>) -> Option<Time> {
        let sleep = self.deadline_sleep.as_mut()?;
        let deadline = sleep.deadline();
        match Pin::new(&mut *sleep).poll(context) {
            Poll::Ready(()) => Some(deadline),
            Poll::Pending => None,
        }
    }

    #[inline]
    fn grant_next_waiter(state: &mut MutexState) -> Option<(crate::sync::waiter::WaiterId, Waker)> {
        // br-asupersync-wlf0xh: O(1) FIFO take via slab pop_front.
        if let Some((id, waker, _)) = state.waiters.pop_front() {
            state.granted_waiter = Some(id);
            Some((id, waker))
        } else {
            state.granted_waiter = None;
            None
        }
    }

    #[inline]
    fn cleanup_waiter(&mut self) {
        if let Some(waiter_id) = self.waiter_id.take() {
            let (waker_to_wake, retired_waker) = {
                let mut state = self.mutex.state.lock();

                if state.granted_waiter == Some(waiter_id) {
                    state.granted_waiter = None;
                    if !state.locked {
                        (Self::grant_next_waiter(&mut state), None)
                    } else {
                        (None, None)
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
                    let retired_waker = state.waiters.remove(waiter_id);

                    let waker_to_wake =
                        if !state.locked && state.granted_waiter.is_none() && is_head {
                            Self::grant_next_waiter(&mut state)
                        } else {
                            None
                        };
                    (waker_to_wake, retired_waker)
                }
            };

            if let Some((id, waker)) = waker_to_wake {
                // Exception-safe baton pass; see `Mutex::wake_granted`
                // (br-asupersync-mutex-panicking-grantee-freezes-fifo-l4sgpj).
                self.mutex.wake_granted(id, waker);
            }
            // A RawWaker destructor may run arbitrary user code. Retire the
            // removed queue owner only after the state guard is gone.
            drop(retired_waker);
        }
    }
}

impl<'a, T, Caps> Future for LockFuture<'a, '_, T, Caps> {
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

        if let Some(deadline) = self.poll_deadline_sleep(context) {
            self.completed = true;
            self.cleanup_waiter();
            return Poll::Ready(Err(LockError::TimedOut(deadline)));
        }

        // Lazily clone only on the contended path, and always before acquiring
        // the state lock. RawWaker::clone is user-controlled and may re-enter
        // this mutex.
        let mut queued_waker = None;

        loop {
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
                        // Check lock ordering before acquisition (debug builds only)
                        if let Some(rank) = self.mutex.rank {
                            lock_ordering::check_acquire(self.mutex.name, rank);
                        }

                        state.granted_waiter = None;
                        state.locked = true;
                        self.waiter_id = None;
                        self.completed = true;

                        // Record lock acquisition for ordering tracking
                        let lock_order =
                            lock_ordering::record_guard_acquire(self.mutex.name, self.mutex.rank);

                        return Poll::Ready(Ok(MutexGuard {
                            mutex: self.mutex,
                            lock_order,
                            _not_send: PhantomData,
                        }));
                    }

                    if queued_waker.is_none() {
                        drop(state);
                        queued_waker = Some(context.waker().clone());
                        continue;
                    }

                    // Another caller stole the lock before we resumed. Re-register
                    // ourselves at the front to preserve our turn.
                    // br-asupersync-wlf0xh: O(1) re-register via slab.push_front;
                    // the slab assigns the new id without a monotonic counter.
                    state.granted_waiter = None;
                    let new_id = state.waiters.push_front_tagged(
                        queued_waker.take().expect("contended path cloned a waker"),
                        (),
                    );
                    drop(state);
                    self.waiter_id = Some(new_id);
                    return Poll::Pending;
                }
            }

            if !state.locked && state.granted_waiter.is_none() && self.waiter_id.is_none() {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = self.mutex.rank {
                    lock_ordering::check_acquire(self.mutex.name, rank);
                }

                // Acquire lock immediately only when nobody else already owns the turn.
                state.locked = true;
                self.completed = true;

                // Record lock acquisition for ordering tracking
                let lock_order =
                    lock_ordering::record_guard_acquire(self.mutex.name, self.mutex.rank);

                return Poll::Ready(Ok(MutexGuard {
                    mutex: self.mutex,
                    lock_order,
                    _not_send: PhantomData,
                }));
            }

            if queued_waker.is_none() {
                drop(state);
                queued_waker = Some(context.waker().clone());
                continue;
            }

            // Register waiter or update existing waker. We must update the waker
            // when it changes because some executors provide different wakers on
            // each poll - failing to update would cause the task to never be woken.
            // The owned replacement API returns the retired waker so its destructor
            // runs only after the state lock is released.
            let retired_waker = if let Some(waiter_id) = self.waiter_id {
                let new_waker = queued_waker.take().expect("contended path cloned a waker");
                match state.waiters.replace_waker(waiter_id, new_waker) {
                    Ok(retired_waker) => Some(retired_waker),
                    Err(new_waker) => {
                        // Was dequeued earlier but is no longer the granted waiter.
                        // Re-register at the FRONT to preserve FIFO fairness.
                        let new_id = state.waiters.push_front_tagged(new_waker, ());
                        self.waiter_id = Some(new_id);
                        None
                    }
                }
            } else {
                let id = state.waiters.push_back_tagged(
                    queued_waker.take().expect("contended path cloned a waker"),
                    (),
                );
                self.waiter_id = Some(id);
                None
            };
            drop(state);
            drop(retired_waker);
            break;
        }

        if let Some(deadline) = self.poll_deadline_sleep(context) {
            self.completed = true;
            self.cleanup_waiter();
            return Poll::Ready(Err(LockError::TimedOut(deadline)));
        }

        Poll::Pending
    }
}

impl<T, Caps> Drop for LockFuture<'_, '_, T, Caps> {
    fn drop(&mut self) {
        self.cleanup_waiter();
    }
}

/// A guard that releases the mutex when dropped.
///
/// A borrowed guard remains deliberately not [`Send`] as part of the shipped
/// 0.4.x contract and to keep cross-worker ownership explicit. Use
/// [`OwnedMutexGuard`] when a guard must move with a task. Lock-order tracking
/// for movable owned guards is task-owned and migration-safe.
///
/// ```compile_fail,E0277
/// use asupersync::sync::Mutex;
///
/// fn require_send<T: Send>(_: T) {}
///
/// let mutex = Mutex::new(42);
/// let guard = mutex.try_lock().expect("mutex should be unlocked");
/// require_send(guard);
/// ```
#[must_use = "guard will be immediately released if not held"]
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
    lock_order: lock_ordering::GuardLockOrder,
    // Raw-pointer ownership markers are neither Send nor Sync. The explicit
    // Sync impl below restores only the sharing property that is sound here.
    _not_send: PhantomData<*mut ()>,
}

// Safety: shared access through a guard is equivalent to `&T`. The guard still
// cannot move to another thread because `_not_send` suppresses the Send auto trait.
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
        self.mutex
            .unlock(lock_ordering::take_guard_lock_order(&mut self.lock_order));
    }
}

impl<'a, T> MutexGuard<'a, T> {
    /// Projects this guard onto a subcomponent while keeping the mutex locked.
    #[inline]
    pub fn map<U: ?Sized, F>(mut self, f: F) -> MappedMutexGuard<'a, T, U>
    where
        F: FnOnce(&mut T) -> &mut U,
    {
        let data = NonNull::from(f(&mut *self));
        let mutex = self.mutex;
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        let _guard = ManuallyDrop::new(self);
        MappedMutexGuard {
            mutex,
            data,
            lock_order,
            _marker: PhantomData,
        }
    }

    /// Projects this guard onto an optional subcomponent without releasing the lock
    /// when the projection is absent.
    #[inline]
    pub fn try_map<U: ?Sized, F>(mut self, f: F) -> Result<MappedMutexGuard<'a, T, U>, Self>
    where
        F: FnOnce(&mut T) -> Option<&mut U>,
    {
        let data = f(&mut *self).map(NonNull::from);
        if let Some(data) = data {
            let mutex = self.mutex;
            let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
            let _guard = ManuallyDrop::new(self);
            Ok(MappedMutexGuard {
                mutex,
                data,
                lock_order,
                _marker: PhantomData,
            })
        } else {
            Err(self)
        }
    }
}

/// A mapped guard that releases the mutex when dropped.
#[must_use = "guard will be immediately released if not held"]
pub struct MappedMutexGuard<'a, T, U: ?Sized> {
    mutex: &'a Mutex<T>,
    data: NonNull<U>,
    lock_order: lock_ordering::GuardLockOrder,
    _marker: PhantomData<&'a mut U>,
}

// Safety: mapped guards inherit the borrowed guard's !Send contract and are
// Sync exactly when the projected field can be shared immutably.
unsafe impl<T, U: ?Sized + Sync> Sync for MappedMutexGuard<'_, T, U> {}

impl<T, U: ?Sized + std::fmt::Debug> std::fmt::Debug for MappedMutexGuard<'_, T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedMutexGuard")
            .field("data", &&**self)
            .finish()
    }
}

impl<T, U: ?Sized> Deref for MappedMutexGuard<'_, T, U> {
    type Target = U;

    #[inline]
    fn deref(&self) -> &U {
        unsafe { self.data.as_ref() }
    }
}

impl<T, U: ?Sized> DerefMut for MappedMutexGuard<'_, T, U> {
    #[inline]
    fn deref_mut(&mut self) -> &mut U {
        unsafe { self.data.as_mut() }
    }
}

impl<T, U: ?Sized> Drop for MappedMutexGuard<'_, T, U> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.mutex.poison();
        }
        self.mutex
            .unlock(lock_ordering::take_guard_lock_order(&mut self.lock_order));
    }
}

impl<'a, T, U: ?Sized> MappedMutexGuard<'a, T, U> {
    /// Further projects an already-mapped guard without releasing the mutex.
    #[inline]
    pub fn map<V: ?Sized, F>(mut self, f: F) -> MappedMutexGuard<'a, T, V>
    where
        F: FnOnce(&mut U) -> &mut V,
    {
        let data = NonNull::from(f(&mut *self));
        let mutex = self.mutex;
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        let _guard = ManuallyDrop::new(self);
        MappedMutexGuard {
            mutex,
            data,
            lock_order,
            _marker: PhantomData,
        }
    }

    /// Fallibly projects an already-mapped guard without releasing the mutex
    /// when the projection is absent.
    #[inline]
    pub fn try_map<V: ?Sized, F>(mut self, f: F) -> Result<MappedMutexGuard<'a, T, V>, Self>
    where
        F: FnOnce(&mut U) -> Option<&mut V>,
    {
        let data = f(&mut *self).map(NonNull::from);
        if let Some(data) = data {
            let mutex = self.mutex;
            let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
            let _guard = ManuallyDrop::new(self);
            Ok(MappedMutexGuard {
                mutex,
                data,
                lock_order,
                _marker: PhantomData,
            })
        } else {
            Err(self)
        }
    }
}

/// An owned guard that releases the mutex when dropped.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedMutexGuard<T> {
    mutex: Arc<Mutex<T>>,
    lock_order: lock_ordering::GuardLockOrder,
}

unsafe impl<T: Send> Send for OwnedMutexGuard<T> {}
unsafe impl<T: Sync> Sync for OwnedMutexGuard<T> {}

impl<T> OwnedMutexGuard<T> {
    /// Acquires the mutex asynchronously (owned).
    pub async fn lock<Caps>(mutex: Arc<Mutex<T>>, cx: &Cx<Caps>) -> Result<Self, LockError> {
        // Acquire through the borrowed-guard path, then suppress that guard's
        // Drop so the held lock transfers to the returned owned guard.
        let mut borrowed_guard = mutex.as_ref().lock(cx).await?;
        let lock_order = lock_ordering::take_guard_lock_order(&mut borrowed_guard.lock_order);
        let _borrowed_guard = std::mem::ManuallyDrop::new(borrowed_guard);
        Ok(Self { mutex, lock_order })
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

            // Enforce lock ordering only on the success path, under the state
            // guard and immediately before the transition. A failed try_lock
            // must return Err rather than panic with ASUP-E205 or record a
            // phantom acquisition edge (br-asupersync-1dydby).
            if let Some(rank) = mutex.rank {
                lock_ordering::check_acquire(mutex.name, rank);
            }

            state.locked = true;
        }

        // Record lock acquisition for ordering tracking
        let lock_order = lock_ordering::record_guard_acquire(mutex.name, mutex.rank);

        Ok(Self { mutex, lock_order })
    }

    /// Projects this owned guard onto a subcomponent while keeping the mutex locked.
    #[inline]
    pub fn map<U: ?Sized, F>(mut self, f: F) -> OwnedMappedMutexGuard<T, U>
    where
        F: FnOnce(&mut T) -> &mut U,
    {
        let data = NonNull::from(f(&mut *self));
        let mutex = unsafe { std::ptr::read(&self.mutex) };
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        let _guard = ManuallyDrop::new(self);
        OwnedMappedMutexGuard {
            mutex,
            data,
            lock_order,
            _marker: PhantomData,
        }
    }

    /// Projects this owned guard onto an optional subcomponent without releasing
    /// the lock when the projection is absent.
    #[inline]
    pub fn try_map<U: ?Sized, F>(mut self, f: F) -> Result<OwnedMappedMutexGuard<T, U>, Self>
    where
        F: FnOnce(&mut T) -> Option<&mut U>,
    {
        let data = f(&mut *self).map(NonNull::from);
        if let Some(data) = data {
            let mutex = unsafe { std::ptr::read(&self.mutex) };
            let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
            let _guard = ManuallyDrop::new(self);
            Ok(OwnedMappedMutexGuard {
                mutex,
                data,
                lock_order,
                _marker: PhantomData,
            })
        } else {
            Err(self)
        }
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
        self.mutex
            .unlock(lock_ordering::take_guard_lock_order(&mut self.lock_order));
    }
}

/// An owned mapped guard that releases the mutex when dropped.
#[must_use = "guard will be immediately released if not held"]
pub struct OwnedMappedMutexGuard<T, U: ?Sized> {
    mutex: Arc<Mutex<T>>,
    data: NonNull<U>,
    lock_order: lock_ordering::GuardLockOrder,
    _marker: PhantomData<*mut U>,
}

unsafe impl<T: Send, U: ?Sized + Send> Send for OwnedMappedMutexGuard<T, U> {}
unsafe impl<T: Send, U: ?Sized + Sync> Sync for OwnedMappedMutexGuard<T, U> {}

impl<T, U: ?Sized + std::fmt::Debug> std::fmt::Debug for OwnedMappedMutexGuard<T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedMappedMutexGuard")
            .field("data", &&**self)
            .finish()
    }
}

impl<T, U: ?Sized> Deref for OwnedMappedMutexGuard<T, U> {
    type Target = U;

    #[inline]
    fn deref(&self) -> &U {
        unsafe { self.data.as_ref() }
    }
}

impl<T, U: ?Sized> DerefMut for OwnedMappedMutexGuard<T, U> {
    #[inline]
    fn deref_mut(&mut self) -> &mut U {
        unsafe { self.data.as_mut() }
    }
}

impl<T, U: ?Sized> Drop for OwnedMappedMutexGuard<T, U> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.mutex.poison();
        }
        self.mutex
            .unlock(lock_ordering::take_guard_lock_order(&mut self.lock_order));
    }
}

impl<T, U: ?Sized> OwnedMappedMutexGuard<T, U> {
    /// Further projects an already-mapped owned guard without releasing the mutex.
    #[inline]
    pub fn map<V: ?Sized, F>(mut self, f: F) -> OwnedMappedMutexGuard<T, V>
    where
        F: FnOnce(&mut U) -> &mut V,
    {
        let data = NonNull::from(f(&mut *self));
        let mutex = unsafe { std::ptr::read(&self.mutex) };
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        let _guard = ManuallyDrop::new(self);
        OwnedMappedMutexGuard {
            mutex,
            data,
            lock_order,
            _marker: PhantomData,
        }
    }

    /// Fallibly projects an already-mapped owned guard without releasing the
    /// lock when the projection is absent.
    #[inline]
    pub fn try_map<V: ?Sized, F>(mut self, f: F) -> Result<OwnedMappedMutexGuard<T, V>, Self>
    where
        F: FnOnce(&mut U) -> Option<&mut V>,
    {
        let data = f(&mut *self).map(NonNull::from);
        if let Some(data) = data {
            let mutex = unsafe { std::ptr::read(&self.mutex) };
            let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
            let _guard = ManuallyDrop::new(self);
            Ok(OwnedMappedMutexGuard {
                mutex,
                data,
                lock_order,
                _marker: PhantomData,
            })
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
include!("mutex_tests.rs");
