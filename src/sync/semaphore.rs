//! Two-phase semaphore with permit obligations.
//!
//! A semaphore controls access to a finite number of resources through permits.
//! Each acquired permit is tracked as an obligation that must be released.
//!
//! # Cancel Safety
//!
//! The acquire operation is split into two phases:
//! - **Phase 1**: Wait for permit availability (cancel-safe)
//! - **Phase 2**: Acquire permit and create obligation (cannot fail)
//!
//! # Example
//!
//! ```ignore
//! use asupersync::sync::Semaphore;
//!
//! // Create semaphore with 10 permits
//! let sem = Semaphore::new(10);
//!
//! // Acquire a permit (awaits until available)
//! let permit = sem.acquire(&cx, 1).await?;
//!
//! // Permit is automatically released when dropped
//! drop(permit);
//! ```

use parking_lot::Mutex as ParkingMutex;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;
use crate::obligation::graded::{ObligationToken, SemaphorePermitKind};

/// Error returned when semaphore acquisition fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// The semaphore was closed.
    Closed,
    /// Cancelled while waiting.
    Cancelled,
    /// The acquire future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for AcquireError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "semaphore closed"),
            Self::Cancelled => write!(f, "semaphore acquire cancelled"),
            Self::PolledAfterCompletion => {
                write!(f, "semaphore acquire future polled after completion")
            }
        }
    }
}

impl std::error::Error for AcquireError {}

/// Error returned when trying to acquire more permits than available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryAcquireError;

impl std::fmt::Display for TryAcquireError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no semaphore permits available")
    }
}

impl std::error::Error for TryAcquireError {}

/// A counting semaphore for limiting concurrent access.
#[derive(Debug)]
pub struct Semaphore {
    /// Internal state for permits and waiters.
    state: ParkingMutex<SemaphoreState>,
    /// Lock-free shadow of available permits for read-heavy diagnostics.
    permits_shadow: AtomicUsize,
    /// Lock-free shadow of closed state for read-heavy checks.
    closed_shadow: AtomicBool,
    /// Maximum permits (initial count).
    max_permits: usize,
}

#[derive(Debug)]
struct SemaphoreState {
    /// Number of available permits.
    permits: usize,
    /// Whether the semaphore is closed.
    closed: bool,
    /// Queue of waiters.
    waiters: VecDeque<Waiter>,
    /// Next waiter id for de-duplication.
    next_waiter_id: u64,
    /// Whether waiter IDs have wrapped and now require collision checks.
    waiter_ids_wrapped: bool,
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    count: usize,
    waker: Waker,
}

#[inline]
fn waiter_waker_if_runnable(state: &SemaphoreState, index: usize) -> Option<Waker> {
    let waiter = state.waiters.get(index)?;
    (state.permits >= waiter.count).then(|| waiter.waker.clone())
}

#[inline]
fn front_waiter_waker_if_runnable(state: &SemaphoreState) -> Option<Waker> {
    waiter_waker_if_runnable(state, 0)
}

#[inline]
fn allocate_waiter_id(state: &mut SemaphoreState) -> u64 {
    loop {
        let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        if state.next_waiter_id == 0 {
            state.waiter_ids_wrapped = true;
        }

        if !state.waiter_ids_wrapped || !state.waiters.iter().any(|waiter| waiter.id == id) {
            return id;
        }
    }
}

#[inline]
fn remove_waiter_and_take_next_waker(state: &mut SemaphoreState, waiter_id: u64) -> Option<Waker> {
    if state
        .waiters
        .front()
        .is_some_and(|waiter| waiter.id == waiter_id)
    {
        // Exception safety: Clone the next waker before popping ourselves so that
        // if clone() panics, our waiter remains in the queue for Drop cleanup.
        let next_waker = waiter_waker_if_runnable(state, 1);
        state.waiters.pop_front();
        next_waker
    } else {
        // Non-front waiter: targeted removal stops at first match instead of
        // scanning the entire deque like retain() would.
        if let Some(pos) = state.waiters.iter().position(|w| w.id == waiter_id) {
            state.waiters.remove(pos);
        }
        None
    }
}

impl Semaphore {
    /// Creates a new semaphore with the given number of permits.
    #[inline]
    #[must_use]
    pub fn new(permits: usize) -> Self {
        Self {
            state: ParkingMutex::new(SemaphoreState {
                permits,
                closed: false,
                waiters: VecDeque::with_capacity(4),
                next_waiter_id: 0,
                waiter_ids_wrapped: false,
            }),
            permits_shadow: AtomicUsize::new(permits),
            closed_shadow: AtomicBool::new(false),
            max_permits: permits,
        }
    }

    /// Returns the number of currently available permits.
    #[inline]
    #[must_use]
    pub fn available_permits(&self) -> usize {
        // Relaxed: advisory fast-path hint only. Stale reads are benign —
        // callers fall back to the mutex-protected path for correctness.
        self.permits_shadow.load(Ordering::Relaxed)
    }

    /// Returns the maximum number of permits (initial count).
    #[inline]
    #[must_use]
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Returns true if the semaphore is closed.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed_shadow.load(Ordering::Acquire)
    }

    /// Closes the semaphore.
    #[inline]
    pub fn close(&self) {
        let taken = {
            let mut state = self.state.lock();
            state.closed = true;
            // Closed semaphores do not advertise reusable capacity.
            state.permits = 0;
            self.closed_shadow.store(true, Ordering::Release);
            self.permits_shadow.store(0, Ordering::Relaxed);
            std::mem::take(&mut state.waiters)
        };
        for waiter in taken {
            waiter.waker.wake();
        }
    }

    /// Acquires the given number of permits asynchronously.
    #[inline]
    pub fn acquire<'a, 'b>(&'a self, cx: &'b Cx, count: usize) -> AcquireFuture<'a, 'b> {
        assert!(count > 0, "cannot acquire 0 permits");
        AcquireFuture {
            semaphore: self,
            cx,
            count,
            waiter_id: None,
            completed: false,
        }
    }

    /// Tries to acquire the given number of permits without waiting.
    #[inline]
    pub fn try_acquire(&self, count: usize) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        assert!(count > 0, "cannot acquire 0 permits");

        let mut state = self.state.lock();
        let result = if state.closed {
            Err(TryAcquireError)
        } else if !state.waiters.is_empty() {
            // Strict FIFO
            Err(TryAcquireError)
        } else if state.permits >= count {
            state.permits -= count;
            // Relaxed: permits_shadow is an advisory fast-path hint. A stale
            // read in available_permits() just skips the fast path or causes a
            // benign try_acquire miss — the real count is protected by the lock.
            // On ARM this avoids a store-release barrier per acquisition.
            self.permits_shadow.store(state.permits, Ordering::Relaxed);
            Ok(SemaphorePermit {
                obligation: Some(ObligationToken::reserve(format!(
                    "semaphore-permit-{}",
                    count
                ))),
                semaphore: self,
                count,
            })
        } else {
            Err(TryAcquireError)
        };
        drop(state);
        result
    }

    /// Adds permits back to the semaphore.
    ///
    /// Saturates at `usize::MAX` if adding would overflow.
    #[inline]
    pub fn add_permits(&self, count: usize) {
        if count == 0 {
            return;
        }
        let mut state = self.state.lock();
        if state.closed {
            return;
        }
        state.permits = state.permits.saturating_add(count);
        self.permits_shadow.store(state.permits, Ordering::Relaxed);
        // Only wake the first waiter since FIFO ordering means only it can acquire.
        // Waking all waiters wastes CPU when only the front can make progress.
        // If the first waiter acquires and releases, it will wake the next.
        let waiter_to_wake = front_waiter_waker_if_runnable(&state);
        drop(state);
        if let Some(waiter) = waiter_to_wake {
            waiter.wake();
        }
    }
}

/// Future returned by `Semaphore::acquire`.
pub struct AcquireFuture<'a, 'b> {
    semaphore: &'a Semaphore,
    cx: &'b Cx,
    count: usize,
    waiter_id: Option<u64>,
    completed: bool,
}

impl Drop for AcquireFuture<'_, '_> {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            let next_waker = {
                let mut state = self.semaphore.state.lock();
                // If we are at the front, we need to wake the next waiter when we leave,
                // otherwise the signal (permits available) might be lost.
                remove_waiter_and_take_next_waker(&mut state, waiter_id)
            };
            if let Some(next) = next_waker {
                next.wake();
            }
        }
    }
}

impl<'a> Future for AcquireFuture<'a, '_> {
    type Output = Result<SemaphorePermit<'a>, AcquireError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(AcquireError::PolledAfterCompletion));
        }

        if self.cx.checkpoint().is_err() {
            if let Some(waiter_id) = self.waiter_id {
                let next_waker = {
                    let mut state = self.semaphore.state.lock();
                    // If we are at the front, we need to wake the next waiter when we leave,
                    // otherwise the signal (permits available) might be lost.
                    remove_waiter_and_take_next_waker(&mut state, waiter_id)
                };
                // Clear waiter_id so Drop doesn't try to remove it again
                self.waiter_id = None;
                if let Some(next) = next_waker {
                    next.wake();
                }
            }
            self.completed = true;
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        // Single lock acquisition: allocate waiter_id inside the same
        // critical section if this is our first wait, avoiding the previous
        // double-lock (lock to get id, drop, re-lock to check state).
        let mut state = self.semaphore.state.lock();

        let waiter_id = if let Some(id) = self.waiter_id {
            id
        } else {
            let id = allocate_waiter_id(&mut state);
            self.waiter_id = Some(id);
            id
        };

        if state.closed {
            if let Some(pos) = state.waiters.iter().position(|w| w.id == waiter_id) {
                state.waiters.remove(pos);
            }
            drop(state);
            self.waiter_id = None;
            self.completed = true;
            return Poll::Ready(Err(AcquireError::Closed));
        }

        // FIFO fairness: only acquire if queue is empty or we are at the front.
        // This prevents queue jumping where a new arrival grabs permits before
        // earlier-waiting tasks get their turn.
        let is_next_in_line = state.waiters.front().is_none_or(|w| w.id == waiter_id);

        if is_next_in_line && state.permits >= self.count {
            state.permits -= self.count;
            self.semaphore
                .permits_shadow
                .store(state.permits, Ordering::Relaxed);

            // Optimization: Since we verified we are next in line, we are either
            // at the front of the queue or the queue is empty. We can just pop
            // the front instead of scanning the whole deque with retain (O(N)).
            if !state.waiters.is_empty() {
                debug_assert_eq!(
                    state.waiters.front().map(|waiter| waiter.id),
                    Some(waiter_id)
                );
                state.waiters.pop_front();
            }

            // Wake next waiter if there are still permits available.
            // Without this, add_permits(N) where N satisfies multiple waiters
            // would only wake the first, leaving others sleeping indefinitely.
            let next_waker = front_waiter_waker_if_runnable(&state);
            drop(state);
            // Clear waiter_id after releasing state guard to avoid borrow conflicts.
            self.waiter_id = None;
            self.completed = true;
            if let Some(next) = next_waker {
                next.wake();
            }
            return Poll::Ready(Ok(SemaphorePermit {
                obligation: Some(ObligationToken::reserve(format!(
                    "semaphore-permit-{}",
                    self.count
                ))),
                semaphore: self.semaphore,
                count: self.count,
            }));
        }

        if let Some(existing) = state
            .waiters
            .iter_mut()
            .find(|waiter| waiter.id == waiter_id)
        {
            debug_assert_eq!(existing.count, self.count);
            if !existing.waker.will_wake(context.waker()) {
                existing.waker.clone_from(context.waker());
            }
        } else {
            state.waiters.push_back(Waiter {
                id: waiter_id,
                count: self.count,
                waker: context.waker().clone(),
            });
        }
        Poll::Pending
    }
}

/// A permit from a semaphore.
///
/// Fields are ordered so that `obligation` drops first (firing the panic if leaked)
/// and then semaphore drops (releasing permits back to the semaphore).
#[must_use = "permit will be immediately released if not held"]
pub struct SemaphorePermit<'a> {
    obligation: Option<ObligationToken<SemaphorePermitKind>>,
    semaphore: &'a Semaphore,
    count: usize,
}

impl SemaphorePermit<'_> {
    /// Returns the number of permits held.
    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Forgets the permit without releasing it back to the semaphore.
    /// This aborts the underlying obligation to indicate the permit was intentionally leaked.
    #[inline]
    pub fn forget(mut self) {
        self.count = 0;
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.abort();
        }
    }

    /// Extracts the obligation token without releasing the permit back to the semaphore.
    /// This transfers ownership of the obligation to the caller.
    /// The permit is consumed and will not release permits back to the semaphore.
    #[inline]
    pub(crate) fn into_parts(mut self) -> (usize, Option<ObligationToken<SemaphorePermitKind>>) {
        let count = self.count;
        let obligation = self.obligation.take();
        self.count = 0; // Prevent Drop from releasing permits
        (count, obligation)
    }

    /// Commits the permit explicitly, releasing it back to the semaphore.
    /// This consumes the permit and commits the underlying obligation, preventing
    /// the drop bomb from firing.
    #[inline]
    pub fn commit(mut self) {
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.commit();
        }
        // Drop will now release the semaphore permits without panicking
        drop(self);
    }
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.commit();
        }
        if self.count > 0 {
            self.semaphore.add_permits(self.count);
        }
        // Ordinary RAII drop is the normal release path for semaphore permits.
    }
}

/// An owned permit from a semaphore.
///
/// Fields are ordered so that `obligation` drops first (firing the panic if leaked)
/// and then semaphore drops (releasing permits back to the semaphore).
#[derive(Debug)]
#[must_use = "permit will be immediately released if not held"]
pub struct OwnedSemaphorePermit {
    obligation: Option<ObligationToken<SemaphorePermitKind>>,
    semaphore: std::sync::Arc<Semaphore>,
    count: usize,
}

impl OwnedSemaphorePermit {
    /// Acquires an owned permit asynchronously.
    pub async fn acquire(
        semaphore: std::sync::Arc<Semaphore>,
        cx: &Cx,
        count: usize,
    ) -> Result<Self, AcquireError> {
        assert!(count > 0, "cannot acquire 0 permits");
        OwnedAcquireFuture {
            semaphore,
            cx: Some(cx.clone()),
            count,
            waiter_id: None,
            completed: false,
        }
        .await
    }

    /// Tries to acquire an owned permit without waiting.
    #[inline]
    pub fn try_acquire(
        semaphore: std::sync::Arc<Semaphore>,
        count: usize,
    ) -> Result<Self, TryAcquireError> {
        let permit = semaphore.try_acquire(count)?;
        // Transfer ownership: extract the obligation token so the OwnedSemaphorePermit
        // will handle both permit release and obligation lifecycle in its own Drop.
        let (count, obligation) = permit.into_parts();
        Ok(Self {
            obligation,
            semaphore,
            count,
        })
    }

    /// Tries to acquire an owned permit without waiting, cloning the `Arc`
    /// only on success.
    ///
    /// This avoids an `Arc::clone` + refcount round-trip when the semaphore
    /// has no available permits (the common contended case).
    #[inline]
    pub fn try_acquire_arc(
        semaphore: &std::sync::Arc<Semaphore>,
        count: usize,
    ) -> Result<Self, TryAcquireError> {
        // Acquire permits via the semaphore's internal state directly.
        // We extract the obligation token from the SemaphorePermit to avoid its Drop
        // releasing permits, since OwnedSemaphorePermit's Drop will handle the release instead.
        let permit = semaphore.try_acquire(count)?;
        // Transfer ownership: extract the obligation token so the OwnedSemaphorePermit
        // will handle both permit release and obligation lifecycle in its own Drop.
        let (count, obligation) = permit.into_parts();
        Ok(Self {
            obligation,
            semaphore: semaphore.clone(),
            count,
        })
    }

    /// Returns the number of permits held.
    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Forgets the permit without releasing it back to the semaphore.
    #[inline]
    pub fn forget(mut self) {
        self.count = 0;
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.abort();
        }
    }

    /// Commits the permit explicitly, releasing it back to the semaphore.
    /// This is equivalent to dropping the permit but provides explicit control.
    #[inline]
    pub fn commit(self) {
        // The Drop implementation will handle both permit release and obligation commit
        drop(self);
    }
}

impl Drop for OwnedSemaphorePermit {
    fn drop(&mut self) {
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.commit();
        }
        if self.count > 0 {
            self.semaphore.add_permits(self.count);
        }
    }
}

/// Future returned by `OwnedSemaphorePermit::acquire`.
pub struct OwnedAcquireFuture {
    semaphore: Arc<Semaphore>,
    cx: Option<Cx>,
    count: usize,
    waiter_id: Option<u64>,
    completed: bool,
}

impl OwnedAcquireFuture {
    /// Construct a new acquire future with an owned `Cx`.
    ///
    /// This avoids the lifetime issue with the `async fn acquire` signature
    /// which borrows `&Cx` (and thus ties the future's lifetime to the borrow).
    pub(crate) fn new(semaphore: Arc<Semaphore>, cx: Cx, count: usize) -> Self {
        assert!(count > 0, "cannot acquire 0 permits");
        Self {
            semaphore,
            cx: Some(cx),
            count,
            waiter_id: None,
            completed: false,
        }
    }

    /// Construct a new acquire future that waits without cancellation support.
    ///
    /// This is used by `Service::poll_ready` middleware paths that must still
    /// register a real semaphore waiter even when no task-local [`Cx`] is
    /// available.
    pub(crate) fn new_uncancelable(semaphore: Arc<Semaphore>, count: usize) -> Self {
        assert!(count > 0, "cannot acquire 0 permits");
        Self {
            semaphore,
            cx: None,
            count,
            waiter_id: None,
            completed: false,
        }
    }
}

impl Drop for OwnedAcquireFuture {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            let next_waker = {
                let mut state = self.semaphore.state.lock();
                // If we are at the front, we need to wake the next waiter when we leave,
                // otherwise the signal (permits available) might be lost.
                remove_waiter_and_take_next_waker(&mut state, waiter_id)
            };
            if let Some(next) = next_waker {
                next.wake();
            }
        }
    }
}

impl Future for OwnedAcquireFuture {
    type Output = Result<OwnedSemaphorePermit, AcquireError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(AcquireError::PolledAfterCompletion));
        }

        if this.cx.as_ref().is_some_and(|cx| cx.checkpoint().is_err()) {
            if let Some(waiter_id) = this.waiter_id {
                let next_waker = {
                    let mut state = this.semaphore.state.lock();
                    // If we are at the front, we need to wake the next waiter when we leave,
                    // otherwise the signal (permits available) might be lost.
                    remove_waiter_and_take_next_waker(&mut state, waiter_id)
                };
                this.waiter_id = None;
                if let Some(next) = next_waker {
                    next.wake();
                }
            }
            this.completed = true;
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        let mut state = this.semaphore.state.lock();

        let waiter_id = if let Some(id) = this.waiter_id {
            id
        } else {
            let id = allocate_waiter_id(&mut state);
            this.waiter_id = Some(id);
            id
        };

        if state.closed {
            if let Some(pos) = state.waiters.iter().position(|w| w.id == waiter_id) {
                state.waiters.remove(pos);
            }
            drop(state);
            this.waiter_id = None;
            this.completed = true;
            return Poll::Ready(Err(AcquireError::Closed));
        }

        // FIFO fairness: only acquire if queue is empty or we are at the front.
        let is_next_in_line = state.waiters.front().is_none_or(|w| w.id == waiter_id);

        if is_next_in_line && state.permits >= this.count {
            state.permits -= this.count;
            this.semaphore
                .permits_shadow
                .store(state.permits, Ordering::Relaxed);

            // Optimization: O(1) removal instead of O(N) retain
            if !state.waiters.is_empty() {
                debug_assert_eq!(
                    state.waiters.front().map(|waiter| waiter.id),
                    Some(waiter_id)
                );
                state.waiters.pop_front();
            }

            // Wake next waiter if there are still permits available.
            // Without this, add_permits(N) where N satisfies multiple waiters
            // would only wake the first, leaving others sleeping indefinitely.
            let next_waker = front_waiter_waker_if_runnable(&state);
            drop(state);
            // Prevent redundant Drop cleanup after releasing state guard.
            this.waiter_id = None;
            this.completed = true;
            if let Some(next) = next_waker {
                next.wake();
            }
            return Poll::Ready(Ok(OwnedSemaphorePermit {
                obligation: Some(ObligationToken::reserve(format!(
                    "semaphore-permit-{}",
                    this.count
                ))),
                semaphore: this.semaphore.clone(),
                count: this.count,
            }));
        }

        if let Some(existing) = state
            .waiters
            .iter_mut()
            .find(|waiter| waiter.id == waiter_id)
        {
            debug_assert_eq!(existing.count, this.count);
            if !existing.waker.will_wake(context.waker()) {
                existing.waker.clone_from(context.waker());
            }
        } else {
            state.waiters.push_back(Waiter {
                id: waiter_id,
                count: this.count,
                waker: context.waker().clone(),
            });
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn poll_once<T, F>(future: &mut F) -> Option<T>
    where
        F: Future<Output = T> + Unpin,
    {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match Pin::new(future).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn poll_until_ready<T, F>(future: &mut F) -> T
    where
        F: Future<Output = T> + Unpin,
    {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match Pin::new(&mut *future).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_once_with_waker<T, F>(future: &mut F, waker: &Waker) -> Option<T>
    where
        F: Future<Output = T> + Unpin,
    {
        let mut cx = Context::from_waker(waker);
        match Pin::new(future).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn poll_until_ready_with_waker<T, F>(future: &mut F, waker: &Waker) -> T
    where
        F: Future<Output = T> + Unpin,
    {
        let mut cx = Context::from_waker(waker);
        loop {
            match Pin::new(&mut *future).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Debug)]
    struct CountingWaker(std::sync::atomic::AtomicUsize);

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self(std::sync::atomic::AtomicUsize::new(0)))
        }

        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct ReentrantSemaphoreWaker {
        semaphore: Arc<Semaphore>,
        wake_tx: std::sync::mpsc::Sender<()>,
    }

    impl std::task::Wake for ReentrantSemaphoreWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let _ = self.semaphore.available_permits();
            let _ = self.wake_tx.send(());
        }
    }

    fn acquire_blocking<'a>(
        semaphore: &'a Semaphore,
        cx: &Cx,
        count: usize,
    ) -> SemaphorePermit<'a> {
        let mut fut = semaphore.acquire(cx, count);
        poll_until_ready(&mut fut).expect("acquire failed")
    }

    fn waiter_cx(slot: u32) -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, slot)),
            TaskId::from_arena(ArenaIndex::new(0, slot)),
            Budget::INFINITE,
        )
    }

    fn observe_waiter_service_order(
        waiter_count: usize,
        cancelled: &[usize],
        base_slot: u32,
    ) -> Vec<usize> {
        let sem = Semaphore::new(0);
        let contexts: Vec<Cx> = (0..waiter_count)
            .map(|index| {
                let index = u32::try_from(index).expect("test waiter index fits in u32");
                waiter_cx(base_slot.checked_add(index).expect("test slot range"))
            })
            .collect();
        let mut futures: Vec<_> = contexts.iter().map(|cx| sem.acquire(cx, 1)).collect();
        let mut still_waiting = vec![true; waiter_count];
        let mut held_permits = Vec::with_capacity(waiter_count.saturating_sub(cancelled.len()));

        for future in &mut futures {
            assert!(
                poll_once(future).is_none(),
                "waiters should queue initially"
            );
        }

        for &index in cancelled {
            contexts[index].set_cancel_requested(true);
            match poll_once(&mut futures[index]).expect("cancelled waiter should complete") {
                Err(AcquireError::Cancelled) => {}
                Err(error) => panic!("cancelled waiter {index} returned {error:?}"),
                Ok(_) => panic!("cancelled waiter {index} unexpectedly acquired a permit"),
            }
            still_waiting[index] = false;
        }

        let survivor_count = still_waiting.iter().filter(|&&waiting| waiting).count();
        let mut observed = Vec::with_capacity(survivor_count);

        for _ in 0..survivor_count {
            sem.add_permits(1);

            let mut woken = None;
            for (index, future) in futures.iter_mut().enumerate() {
                if !still_waiting[index] {
                    continue;
                }

                match poll_once(future) {
                    Some(Ok(permit)) => {
                        still_waiting[index] = false;
                        held_permits.push(permit);
                        woken = Some(index);
                        break;
                    }
                    Some(Err(error)) => panic!("waiter {index} unexpectedly errored: {error:?}"),
                    None => {}
                }
            }

            observed.push(woken.expect("one waiter should acquire after each permit addition"));
        }

        drop(held_permits);
        observed
    }

    #[test]
    fn new_semaphore_has_correct_permits() {
        init_test("new_semaphore_has_correct_permits");
        let sem = Semaphore::new(5);
        crate::assert_with_log!(
            sem.available_permits() == 5,
            "available permits",
            5usize,
            sem.available_permits()
        );
        crate::assert_with_log!(
            sem.max_permits() == 5,
            "max permits",
            5usize,
            sem.max_permits()
        );
        crate::assert_with_log!(!sem.is_closed(), "not closed", false, sem.is_closed());
        crate::test_complete!("new_semaphore_has_correct_permits");
    }

    #[test]
    fn acquire_decrements_permits() {
        init_test("acquire_decrements_permits");
        let cx = test_cx();
        let sem = Semaphore::new(5);

        let mut fut = sem.acquire(&cx, 2);
        let _permit = poll_once(&mut fut)
            .expect("acquire failed")
            .expect("acquire failed");
        crate::assert_with_log!(
            sem.available_permits() == 3,
            "available permits after acquire",
            3usize,
            sem.available_permits()
        );
        crate::test_complete!("acquire_decrements_permits");
    }

    #[test]
    fn cancel_removes_waiter() {
        init_test("cancel_removes_waiter");
        let cx = test_cx();
        let sem = Semaphore::new(1);
        let _held = sem.try_acquire(1).expect("initial acquire");

        let mut fut = sem.acquire(&cx, 1);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "acquire pending", true, pending);
        let waiter_len = sem.state.lock().waiters.len();
        crate::assert_with_log!(waiter_len == 1, "waiter queued", 1usize, waiter_len);

        cx.set_cancel_requested(true);
        let result = poll_once(&mut fut).expect("cancel poll");
        let cancelled = matches!(result, Err(AcquireError::Cancelled));
        crate::assert_with_log!(cancelled, "cancelled error", true, cancelled);
        let waiter_len = sem.state.lock().waiters.len();
        crate::assert_with_log!(waiter_len == 0, "waiter removed", 0usize, waiter_len);
        crate::test_complete!("cancel_removes_waiter");
    }

    #[test]
    fn drop_removes_waiter() {
        init_test("drop_removes_waiter");
        let cx = test_cx();
        let sem = Semaphore::new(1);
        let _held = sem.try_acquire(1).expect("initial acquire");

        let mut fut = sem.acquire(&cx, 1);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "acquire pending", true, pending);
        let waiter_len = sem.state.lock().waiters.len();
        crate::assert_with_log!(waiter_len == 1, "waiter queued", 1usize, waiter_len);

        drop(fut);
        let waiter_len = sem.state.lock().waiters.len();
        crate::assert_with_log!(waiter_len == 0, "waiter removed", 0usize, waiter_len);
        crate::test_complete!("drop_removes_waiter");
    }

    #[test]
    fn add_permits_wakes_without_holding_lock() {
        init_test("add_permits_wakes_without_holding_lock");
        let cx = test_cx();
        let sem = Arc::new(Semaphore::new(1));
        let held = sem.try_acquire(1).expect("initial acquire");

        let mut fut = sem.acquire(&cx, 1);
        let (wake_tx, wake_rx) = std::sync::mpsc::channel();
        let waker = Waker::from(Arc::new(ReentrantSemaphoreWaker {
            semaphore: Arc::clone(&sem),
            wake_tx,
        }));

        let pending = poll_once_with_waker(&mut fut, &waker).is_none();
        crate::assert_with_log!(pending, "waiter pending", true, pending);

        let sem_for_thread = Arc::clone(&sem);
        let join = std::thread::spawn(move || {
            sem_for_thread.add_permits(1);
        });

        let woke = wake_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_ok();
        crate::assert_with_log!(woke, "wake signal received", true, woke);
        join.join().expect("add_permits thread join");

        let permit = poll_once_with_waker(&mut fut, &waker)
            .expect("acquire ready")
            .expect("acquire ok");
        drop(permit);
        drop(held);
        crate::test_complete!("add_permits_wakes_without_holding_lock");
    }

    #[test]
    fn test_semaphore_fifo_basic() {
        init_test("test_semaphore_fifo_basic");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(1);

        // First waiter arrives when permit is held
        let held = sem.try_acquire(1).expect("initial acquire");

        let mut fut1 = sem.acquire(&cx1, 1);
        let pending1 = poll_once(&mut fut1).is_none();
        crate::assert_with_log!(pending1, "first waiter pending", true, pending1);

        // Second waiter arrives
        let mut fut2 = sem.acquire(&cx2, 1);
        let pending2 = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(pending2, "second waiter pending", true, pending2);

        // Release the held permit
        drop(held);

        // First waiter should acquire (FIFO)
        let result1 = poll_once(&mut fut1);
        let permit1 = result1.expect("first should acquire").expect("no error");
        crate::assert_with_log!(true, "first waiter acquires", true, true);

        // Second waiter should still be pending (permit1 still held)
        let still_pending = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(still_pending, "second still pending", true, still_pending);

        drop(permit1); // explicitly drop to document lifetime
        crate::test_complete!("test_semaphore_fifo_basic");
    }

    #[test]
    fn test_semaphore_no_queue_jump() {
        init_test("test_semaphore_no_queue_jump");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(2);

        // First waiter needs 2 permits, only 1 available after this
        let held = sem.try_acquire(1).expect("initial acquire");

        // First waiter requests 2 (only 1 available, must wait)
        let mut fut1 = sem.acquire(&cx1, 2);
        let pending1 = poll_once(&mut fut1).is_none();
        crate::assert_with_log!(pending1, "first waiter pending", true, pending1);

        // Release permit - now 2 available
        drop(held);

        // Second waiter arrives requesting just 1
        let mut fut2 = sem.acquire(&cx2, 1);

        // Poll second waiter - should NOT jump queue even though 1 is available
        let pending2 = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(pending2, "second cannot jump queue", true, pending2);

        // First waiter should now be able to acquire (it's at front, 2 permits available)
        let result1 = poll_once(&mut fut1);
        let first_acquired = result1.is_some() && result1.unwrap().is_ok();
        crate::assert_with_log!(
            first_acquired,
            "first waiter acquires",
            true,
            first_acquired
        );

        crate::test_complete!("test_semaphore_no_queue_jump");
    }

    #[test]
    fn test_semaphore_cancel_preserves_order() {
        init_test("test_semaphore_cancel_preserves_order");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let cx3 = test_cx();
        let sem = Semaphore::new(1);

        let held = sem.try_acquire(1).expect("initial acquire");

        // Three waiters queue up
        let mut fut1 = sem.acquire(&cx1, 1);
        let _ = poll_once(&mut fut1);

        let mut fut2 = sem.acquire(&cx2, 1);
        let _ = poll_once(&mut fut2);

        let mut fut3 = sem.acquire(&cx3, 1);
        let _ = poll_once(&mut fut3);

        // Middle waiter cancels
        cx2.set_cancel_requested(true);
        let result2 = poll_once(&mut fut2);
        let cancelled = matches!(result2, Some(Err(AcquireError::Cancelled)));
        crate::assert_with_log!(cancelled, "second waiter cancelled", true, cancelled);

        // Release permit
        drop(held);

        // First waiter should acquire (not third, even though second cancelled)
        let result1 = poll_once(&mut fut1);
        let permit1 = result1.expect("first should acquire").expect("no error");
        crate::assert_with_log!(true, "first waiter acquires", true, true);

        // Third should still be pending (permit1 still held)
        let third_pending = poll_once(&mut fut3).is_none();
        crate::assert_with_log!(third_pending, "third still pending", true, third_pending);

        drop(permit1); // explicitly drop to document lifetime
        crate::test_complete!("test_semaphore_cancel_preserves_order");
    }

    #[test]
    fn owned_acquire_cascades_wakeup_when_permits_remain() {
        init_test("owned_acquire_cascades_wakeup_when_permits_remain");

        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Arc::new(Semaphore::new(2));

        // Exhaust permits so both owned acquires register as waiters.
        let held = sem.try_acquire(2).expect("initial acquire");

        let w1 = CountingWaker::new();
        let w2 = CountingWaker::new();
        let waker1 = Waker::from(Arc::clone(&w1));
        let waker2 = Waker::from(Arc::clone(&w2));

        let mut fut1 = Box::pin(OwnedSemaphorePermit::acquire(Arc::clone(&sem), &cx1, 1));
        let mut fut2 = Box::pin(OwnedSemaphorePermit::acquire(Arc::clone(&sem), &cx2, 1));

        let pending1 = poll_once_with_waker(&mut fut1, &waker1).is_none();
        let pending2 = poll_once_with_waker(&mut fut2, &waker2).is_none();
        crate::assert_with_log!(pending1, "fut1 pending", true, pending1);
        crate::assert_with_log!(pending2, "fut2 pending", true, pending2);

        // Release 2 permits. This should wake only the front waiter (fut1) directly.
        drop(held);
        crate::assert_with_log!(w1.count() > 0, "front waiter woken", true, w1.count() > 0);
        crate::assert_with_log!(
            w2.count() == 0,
            "second waiter not woken yet",
            0usize,
            w2.count()
        );

        // When fut1 acquires while permits remain, it must wake fut2.
        let permit1 = poll_until_ready_with_waker(&mut fut1, &waker1).expect("owned acquire 1");
        crate::assert_with_log!(
            w2.count() > 0,
            "second waiter woken by cascade",
            true,
            w2.count() > 0
        );

        // fut2 should be able to acquire without waiting for permit1 to drop.
        let permit2 = poll_until_ready_with_waker(&mut fut2, &waker2).expect("owned acquire 2");

        drop(permit1);
        drop(permit2);

        crate::test_complete!("owned_acquire_cascades_wakeup_when_permits_remain");
    }

    #[test]
    #[ignore = "stress test; run manually"]
    fn stress_test_semaphore_fairness() {
        init_test("stress_test_semaphore_fairness");
        let threads = 8usize;
        let iters = 2_000usize;
        let semaphore = Arc::new(Semaphore::new(1));

        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let semaphore = Arc::clone(&semaphore);
            handles.push(std::thread::spawn(move || {
                let cx = test_cx();
                let mut acquired = 0usize;
                for _ in 0..iters {
                    let permit = acquire_blocking(&semaphore, &cx, 1);
                    acquired += 1;
                    drop(permit);
                }
                acquired
            }));
        }

        let mut counts = Vec::with_capacity(threads);
        for handle in handles {
            counts.push(handle.join().expect("thread join failed"));
        }

        let total: usize = counts.iter().sum();
        let expected = threads * iters;
        let min = counts.iter().copied().min().unwrap_or(0);
        crate::assert_with_log!(total == expected, "total acquisitions", expected, total);
        crate::assert_with_log!(min > 0, "no starvation", true, min > 0);
        crate::test_complete!("stress_test_semaphore_fairness");
    }

    #[test]
    fn close_wakes_all_waiters_with_error() {
        init_test("close_wakes_all_waiters_with_error");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(1);
        let _held = sem.try_acquire(1).expect("initial acquire");

        let mut fut1 = sem.acquire(&cx1, 1);
        let pending1 = poll_once(&mut fut1).is_none();
        crate::assert_with_log!(pending1, "waiter 1 pending", true, pending1);

        let mut fut2 = sem.acquire(&cx2, 1);
        let pending2 = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(pending2, "waiter 2 pending", true, pending2);

        sem.close();

        let result1 = poll_once(&mut fut1);
        let closed1 = matches!(result1, Some(Err(AcquireError::Closed)));
        crate::assert_with_log!(closed1, "waiter 1 closed", true, closed1);

        let result2 = poll_once(&mut fut2);
        let closed2 = matches!(result2, Some(Err(AcquireError::Closed)));
        crate::assert_with_log!(closed2, "waiter 2 closed", true, closed2);

        crate::test_complete!("close_wakes_all_waiters_with_error");
    }

    #[test]
    fn acquire_future_second_poll_fails_closed() {
        init_test("acquire_future_second_poll_fails_closed");
        let cx = test_cx();
        let sem = Semaphore::new(1);

        let mut fut = sem.acquire(&cx, 1);
        let permit = poll_once(&mut fut)
            .expect("first poll ready")
            .expect("first poll acquires");
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "permit consumed once",
            0usize,
            sem.available_permits()
        );

        let second = poll_once(&mut fut);
        let failed_closed = matches!(second, Some(Err(AcquireError::PolledAfterCompletion)));
        crate::assert_with_log!(
            failed_closed,
            "second poll fails closed",
            true,
            failed_closed
        );
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "second poll does not consume more permits",
            0usize,
            sem.available_permits()
        );

        drop(permit);
        crate::assert_with_log!(
            sem.available_permits() == 1,
            "dropping original permit restores capacity",
            1usize,
            sem.available_permits()
        );
        crate::test_complete!("acquire_future_second_poll_fails_closed");
    }

    #[test]
    fn owned_acquire_future_second_poll_fails_closed() {
        init_test("owned_acquire_future_second_poll_fails_closed");
        let cx = test_cx();
        let sem = Arc::new(Semaphore::new(1));

        let mut fut = OwnedAcquireFuture::new(Arc::clone(&sem), cx, 1);
        let permit = poll_once(&mut fut)
            .expect("first poll ready")
            .expect("first poll acquires");
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "owned permit consumed once",
            0usize,
            sem.available_permits()
        );

        let second = poll_once(&mut fut);
        let failed_closed = matches!(second, Some(Err(AcquireError::PolledAfterCompletion)));
        crate::assert_with_log!(
            failed_closed,
            "owned second poll fails closed",
            true,
            failed_closed
        );
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "owned second poll does not consume more permits",
            0usize,
            sem.available_permits()
        );

        drop(permit);
        crate::assert_with_log!(
            sem.available_permits() == 1,
            "dropping original owned permit restores capacity",
            1usize,
            sem.available_permits()
        );
        crate::test_complete!("owned_acquire_future_second_poll_fails_closed");
    }

    #[test]
    fn try_acquire_fails_when_closed() {
        init_test("try_acquire_fails_when_closed");
        let sem = Semaphore::new(5);
        sem.close();

        let result = sem.try_acquire(1);
        crate::assert_with_log!(
            result.is_err(),
            "try_acquire on closed",
            true,
            result.is_err()
        );
        crate::assert_with_log!(sem.is_closed(), "is_closed", true, sem.is_closed());
        crate::test_complete!("try_acquire_fails_when_closed");
    }

    #[test]
    fn close_zeroes_available_permits_and_keeps_them_zero() {
        init_test("close_zeroes_available_permits_and_keeps_them_zero");
        let sem = Semaphore::new(2);
        let permit = sem.try_acquire(1).expect("acquire before close");
        crate::assert_with_log!(
            sem.available_permits() == 1,
            "available before close",
            1usize,
            sem.available_permits()
        );

        sem.close();
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "available after close",
            0usize,
            sem.available_permits()
        );

        // Releasing held permits after close should not revive capacity.
        drop(permit);
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "available after dropping held permit",
            0usize,
            sem.available_permits()
        );
        crate::test_complete!("close_zeroes_available_permits_and_keeps_them_zero");
    }

    #[test]
    fn add_permits_is_noop_after_close() {
        init_test("add_permits_is_noop_after_close");
        let sem = Semaphore::new(0);
        sem.close();
        sem.add_permits(10);

        crate::assert_with_log!(
            sem.available_permits() == 0,
            "add_permits ignored after close",
            0usize,
            sem.available_permits()
        );
        crate::assert_with_log!(
            sem.try_acquire(1).is_err(),
            "closed semaphore still rejects acquire",
            true,
            sem.try_acquire(1).is_err()
        );
        crate::test_complete!("add_permits_is_noop_after_close");
    }

    #[test]
    fn permit_forget_leaks_permits() {
        init_test("permit_forget_leaks_permits");
        let sem = Semaphore::new(3);

        let permit = sem.try_acquire(2).expect("acquire 2");
        let avail_after = sem.available_permits();
        crate::assert_with_log!(avail_after == 1, "after acquire", 1usize, avail_after);

        permit.forget();

        // Permits should NOT be returned — still 1 available.
        let avail_leaked = sem.available_permits();
        crate::assert_with_log!(avail_leaked == 1, "after forget", 1usize, avail_leaked);
        crate::test_complete!("permit_forget_leaks_permits");
    }

    #[test]
    fn add_permits_increases_available() {
        init_test("add_permits_increases_available");
        let sem = Semaphore::new(2);
        let _p = sem.try_acquire(2).expect("acquire all");
        crate::assert_with_log!(
            sem.available_permits() == 0,
            "zero",
            0usize,
            sem.available_permits()
        );

        sem.add_permits(3);
        let avail = sem.available_permits();
        crate::assert_with_log!(avail == 3, "after add", 3usize, avail);
        crate::test_complete!("add_permits_increases_available");
    }

    #[test]
    fn drop_permit_restores_count() {
        init_test("drop_permit_restores_count");
        let sem = Semaphore::new(4);

        let p1 = sem.try_acquire(1).expect("p1");
        let p2 = sem.try_acquire(2).expect("p2");
        crate::assert_with_log!(
            sem.available_permits() == 1,
            "after two acquires",
            1usize,
            sem.available_permits()
        );

        let count1 = p1.count();
        crate::assert_with_log!(count1 == 1, "p1 count", 1usize, count1);
        let count2 = p2.count();
        crate::assert_with_log!(count2 == 2, "p2 count", 2usize, count2);

        drop(p1);
        crate::assert_with_log!(
            sem.available_permits() == 2,
            "after drop p1",
            2usize,
            sem.available_permits()
        );

        drop(p2);
        crate::assert_with_log!(
            sem.available_permits() == 4,
            "after drop p2",
            4usize,
            sem.available_permits()
        );
        crate::test_complete!("drop_permit_restores_count");
    }

    // =========================================================================
    // Audit regression tests (asupersync-10x0x.50)
    // =========================================================================

    #[test]
    fn add_permits_saturates_at_usize_max() {
        init_test("add_permits_saturates_at_usize_max");
        let sem = Semaphore::new(1);
        sem.add_permits(usize::MAX);
        let avail = sem.available_permits();
        crate::assert_with_log!(avail == usize::MAX, "saturated at MAX", usize::MAX, avail);

        // Adding more should still stay at MAX (saturating).
        sem.add_permits(100);
        let avail2 = sem.available_permits();
        crate::assert_with_log!(
            avail2 == usize::MAX,
            "still MAX after add",
            usize::MAX,
            avail2
        );
        crate::test_complete!("add_permits_saturates_at_usize_max");
    }

    #[test]
    fn try_acquire_can_exceed_initial_permit_count_after_add_permits() {
        init_test("try_acquire_can_exceed_initial_permit_count_after_add_permits");
        let sem = Semaphore::new(1);
        sem.add_permits(4);

        let permit = sem.try_acquire(5).expect("acquire after add_permits");
        let count = permit.count();
        crate::assert_with_log!(count == 5, "permit count", 5usize, count);

        let avail_after = sem.available_permits();
        crate::assert_with_log!(
            avail_after == 0,
            "available after acquire",
            0usize,
            avail_after
        );
        drop(permit);
        crate::test_complete!("try_acquire_can_exceed_initial_permit_count_after_add_permits");
    }

    #[test]
    fn semaphore_with_zero_initial_permits_works_after_add_permits() {
        init_test("semaphore_with_zero_initial_permits_works_after_add_permits");
        let sem = Semaphore::new(0);
        sem.add_permits(2);

        let permit = sem
            .try_acquire(2)
            .expect("acquire after add on zero-initial");
        let count = permit.count();
        crate::assert_with_log!(count == 2, "permit count", 2usize, count);
        drop(permit);
        crate::test_complete!("semaphore_with_zero_initial_permits_works_after_add_permits");
    }

    #[test]
    fn close_during_owned_acquire_returns_error() {
        init_test("close_during_owned_acquire_returns_error");
        let cx1 = test_cx();
        let sem = Arc::new(Semaphore::new(1));
        let _held = sem.try_acquire(1).expect("initial acquire");

        let mut fut = Box::pin(OwnedSemaphorePermit::acquire(Arc::clone(&sem), &cx1, 1));
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "owned acquire pending", true, pending);

        sem.close();

        let result = poll_once(&mut fut);
        let closed = matches!(result, Some(Err(AcquireError::Closed)));
        crate::assert_with_log!(closed, "owned acquire closed", true, closed);
        crate::test_complete!("close_during_owned_acquire_returns_error");
    }

    #[test]
    fn try_acquire_respects_fifo_with_available_permits() {
        init_test("try_acquire_respects_fifo_with_available_permits");
        let cx1 = test_cx();
        let sem = Semaphore::new(3);

        // Waiter queues for 3 permits, only 2 available after held.
        let held = sem.try_acquire(1).expect("initial acquire");

        let mut fut = sem.acquire(&cx1, 3);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "waiter pending for 3", true, pending);

        // Even though 2 permits are available, try_acquire must fail because
        // there is a waiter in the queue (FIFO enforcement).
        let try_result = sem.try_acquire(1);
        crate::assert_with_log!(
            try_result.is_err(),
            "try_acquire blocked by FIFO",
            true,
            try_result.is_err()
        );

        drop(held);
        let ready = poll_once(&mut fut);
        let waiter_acquired = matches!(ready, Some(Ok(_)));
        crate::assert_with_log!(
            waiter_acquired,
            "waiter acquires after release",
            true,
            waiter_acquired
        );
        crate::test_complete!("try_acquire_respects_fifo_with_available_permits");
    }

    #[test]
    fn owned_permit_try_acquire_and_drop() {
        init_test("owned_permit_try_acquire_and_drop");
        let sem = Arc::new(Semaphore::new(3));

        let permit = OwnedSemaphorePermit::try_acquire(Arc::clone(&sem), 2).expect("try_acquire");
        let count = permit.count();
        crate::assert_with_log!(count == 2, "owned permit count", 2usize, count);

        let avail = sem.available_permits();
        crate::assert_with_log!(avail == 1, "after owned acquire", 1usize, avail);

        drop(permit);
        let avail_after = sem.available_permits();
        crate::assert_with_log!(avail_after == 3, "after owned drop", 3usize, avail_after);
        crate::test_complete!("owned_permit_try_acquire_and_drop");
    }

    #[test]
    #[should_panic(expected = "cannot acquire 0 permits")]
    fn owned_acquire_panics_on_zero_count() {
        init_test("owned_acquire_panics_on_zero_count");
        let sem = Arc::new(Semaphore::new(1));
        let cx = test_cx();
        let mut fut = Box::pin(OwnedSemaphorePermit::acquire(sem, &cx, 0));
        let _ = poll_once(&mut fut);
    }

    #[test]
    fn cancel_front_waiter_wakes_next() {
        init_test("cancel_front_waiter_wakes_next");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(2);
        let _held = sem.try_acquire(1).expect("initial acquire");

        // Two waiters queue up.
        let w1 = CountingWaker::new();
        let w2 = CountingWaker::new();
        let waker1 = Waker::from(Arc::clone(&w1));
        let waker2 = Waker::from(Arc::clone(&w2));

        let mut fut1 = sem.acquire(&cx1, 2);
        let mut fut2 = sem.acquire(&cx2, 1);
        let pending1 = poll_once_with_waker(&mut fut1, &waker1).is_none();
        let pending2 = poll_once_with_waker(&mut fut2, &waker2).is_none();
        crate::assert_with_log!(pending1, "fut1 pending", true, pending1);
        crate::assert_with_log!(pending2, "fut2 pending", true, pending2);

        // Cancel the front waiter. It must wake the next waiter so it doesn't
        // sleep forever.
        cx1.set_cancel_requested(true);
        let result1 = poll_once_with_waker(&mut fut1, &waker1);
        let cancelled = matches!(result1, Some(Err(AcquireError::Cancelled)));
        crate::assert_with_log!(cancelled, "front waiter cancelled", true, cancelled);

        // The second waiter should have been woken.
        let w2_woken = w2.count() > 0;
        crate::assert_with_log!(w2_woken, "second waiter woken", true, w2_woken);
        crate::test_complete!("cancel_front_waiter_wakes_next");
    }

    #[test]
    fn insufficient_add_permits_does_not_spuriously_wake_front_waiter() {
        init_test("insufficient_add_permits_does_not_spuriously_wake_front_waiter");
        let cx = test_cx();
        let sem = Semaphore::new(0);

        let wakes = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wakes));

        let mut fut = sem.acquire(&cx, 2);
        let pending = poll_once_with_waker(&mut fut, &waker).is_none();
        crate::assert_with_log!(pending, "waiter pending", true, pending);

        sem.add_permits(1);
        let wake_count = wakes.count();
        crate::assert_with_log!(wake_count == 0, "no spurious wake", 0usize, wake_count);

        sem.add_permits(1);
        let wake_count = wakes.count();
        crate::assert_with_log!(
            wake_count > 0,
            "wake after enough permits",
            true,
            wake_count > 0
        );

        let permit = poll_once_with_waker(&mut fut, &waker)
            .expect("acquire ready")
            .expect("acquire ok");
        crate::assert_with_log!(permit.count() == 2, "permit count", 2usize, permit.count());
        drop(permit);
        crate::test_complete!("insufficient_add_permits_does_not_spuriously_wake_front_waiter");
    }

    #[test]
    fn cancelling_front_waiter_only_batons_when_next_is_runnable() {
        init_test("cancelling_front_waiter_only_batons_when_next_is_runnable");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(0);

        let w1 = CountingWaker::new();
        let w2 = CountingWaker::new();
        let waker1 = Waker::from(Arc::clone(&w1));
        let waker2 = Waker::from(Arc::clone(&w2));

        let mut fut1 = sem.acquire(&cx1, 2);
        let mut fut2 = sem.acquire(&cx2, 2);
        let pending1 = poll_once_with_waker(&mut fut1, &waker1).is_none();
        let pending2 = poll_once_with_waker(&mut fut2, &waker2).is_none();
        crate::assert_with_log!(pending1, "fut1 pending", true, pending1);
        crate::assert_with_log!(pending2, "fut2 pending", true, pending2);

        sem.add_permits(1);
        let wake_count = w2.count();
        crate::assert_with_log!(
            wake_count == 0,
            "next waiter not woken before runnable",
            0usize,
            wake_count
        );

        cx1.set_cancel_requested(true);
        let result1 = poll_once_with_waker(&mut fut1, &waker1);
        let cancelled = matches!(result1, Some(Err(AcquireError::Cancelled)));
        crate::assert_with_log!(cancelled, "front waiter cancelled", true, cancelled);

        let wake_count = w2.count();
        crate::assert_with_log!(
            wake_count == 0,
            "next waiter still not woken after cancel",
            0usize,
            wake_count
        );

        sem.add_permits(1);
        let wake_count = w2.count();
        crate::assert_with_log!(
            wake_count > 0,
            "next waiter woken once runnable",
            true,
            wake_count > 0
        );

        let permit2 = poll_once_with_waker(&mut fut2, &waker2)
            .expect("acquire ready")
            .expect("acquire ok");
        crate::assert_with_log!(
            permit2.count() == 2,
            "permit count",
            2usize,
            permit2.count()
        );
        drop(permit2);
        crate::test_complete!("cancelling_front_waiter_only_batons_when_next_is_runnable");
    }

    #[test]
    fn drop_front_waiter_wakes_next() {
        init_test("drop_front_waiter_wakes_next");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(2);
        let _held = sem.try_acquire(1).expect("initial acquire");

        let w2 = CountingWaker::new();
        let waker2 = Waker::from(Arc::clone(&w2));

        let mut fut1 = sem.acquire(&cx1, 2);
        let mut fut2 = sem.acquire(&cx2, 1);
        let pending1 = poll_once(&mut fut1).is_none();
        let pending2 = poll_once_with_waker(&mut fut2, &waker2).is_none();
        crate::assert_with_log!(pending1, "fut1 pending", true, pending1);
        crate::assert_with_log!(pending2, "fut2 pending", true, pending2);

        // Drop the front waiter without cancelling. It must wake the next waiter.
        drop(fut1);
        let w2_woken = w2.count() > 0;
        crate::assert_with_log!(w2_woken, "second waiter woken on drop", true, w2_woken);
        crate::test_complete!("drop_front_waiter_wakes_next");
    }

    #[test]
    fn waker_update_on_repoll() {
        init_test("waker_update_on_repoll");
        let cx1 = test_cx();
        let sem = Semaphore::new(1);
        let held = sem.try_acquire(1).expect("initial acquire");

        let w1 = CountingWaker::new();
        let w2 = CountingWaker::new();
        let waker1 = Waker::from(Arc::clone(&w1));
        let waker2 = Waker::from(Arc::clone(&w2));

        let mut fut = sem.acquire(&cx1, 1);

        // First poll registers waker1.
        let pending = poll_once_with_waker(&mut fut, &waker1).is_none();
        crate::assert_with_log!(pending, "pending with waker1", true, pending);

        // Second poll with a different waker should update the stored waker.
        let still_pending = poll_once_with_waker(&mut fut, &waker2).is_none();
        crate::assert_with_log!(still_pending, "pending with waker2", true, still_pending);

        // Release permit - should wake waker2 (the updated one), not waker1.
        drop(held);
        // The semaphore wakes the front waiter's stored waker.
        let w2_woken = w2.count() > 0;
        crate::assert_with_log!(w2_woken, "updated waker woken", true, w2_woken);
        crate::test_complete!("waker_update_on_repoll");
    }

    #[test]
    fn waiter_id_wraparound_avoids_live_queue_collisions() {
        init_test("waiter_id_wraparound_avoids_live_queue_collisions");
        let cx1 = test_cx();
        let cx2 = test_cx();
        let sem = Semaphore::new(0);

        {
            let mut state = sem.state.lock();
            state.next_waiter_id = u64::MAX;
        }

        let mut fut1 = sem.acquire(&cx1, 1);
        let mut fut2 = sem.acquire(&cx2, 1);
        let pending1 = poll_once(&mut fut1).is_none();
        let pending2 = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(pending1, "fut1 pending", true, pending1);
        crate::assert_with_log!(pending2, "fut2 pending", true, pending2);

        {
            let state = sem.state.lock();
            let ids: Vec<u64> = state.waiters.iter().map(|waiter| waiter.id).collect();
            crate::assert_with_log!(ids.len() == 2, "two waiters queued", 2usize, ids.len());
            crate::assert_with_log!(
                ids[0] == u64::MAX,
                "first waiter gets MAX id",
                u64::MAX,
                ids[0]
            );
            crate::assert_with_log!(
                ids[1] != ids[0],
                "waiter ids unique",
                true,
                ids[1] != ids[0]
            );
            crate::assert_with_log!(
                state.waiter_ids_wrapped,
                "waiter ids marked wrapped",
                true,
                state.waiter_ids_wrapped
            );
        }

        cx1.set_cancel_requested(true);
        let result1 = poll_once(&mut fut1);
        let cancelled = matches!(result1, Some(Err(AcquireError::Cancelled)));
        crate::assert_with_log!(cancelled, "front waiter cancelled", true, cancelled);

        sem.add_permits(1);
        let permit2 = poll_once(&mut fut2)
            .expect("second waiter ready")
            .expect("second waiter acquired");
        crate::assert_with_log!(
            permit2.count() == 1,
            "permit count",
            1usize,
            permit2.count()
        );
        drop(permit2);
        crate::test_complete!("waiter_id_wraparound_avoids_live_queue_collisions");
    }

    // ── Invariant: zero-permit semaphore acquire blocks then wakes ─────

    /// Invariant: a zero-permit semaphore blocks on `acquire()`, and
    /// wakes the waiter when `add_permits()` is called.  This tests the
    /// full roundtrip: new(0) → acquire pending → add_permits → wake → acquire.
    #[test]
    fn semaphore_zero_initial_acquire_blocks_then_wakes_on_add_permits() {
        init_test("semaphore_zero_initial_acquire_blocks_then_wakes_on_add_permits");
        let cx = test_cx();
        let sem = Semaphore::new(0);

        let zero = sem.available_permits();
        crate::assert_with_log!(zero == 0, "starts at zero permits", 0usize, zero);

        // Acquire should block.
        let mut fut = sem.acquire(&cx, 1);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "acquire blocks on zero-permit sem", true, pending);

        // Add one permit — should wake the waiter.
        sem.add_permits(1);

        let result = poll_once(&mut fut);
        let acquired = matches!(result, Some(Ok(_)));
        crate::assert_with_log!(
            acquired,
            "acquire completes after add_permits",
            true,
            acquired
        );

        crate::test_complete!("semaphore_zero_initial_acquire_blocks_then_wakes_on_add_permits");
    }

    /// Invariant: dropping an `AcquireFuture` after cancel does not leak
    /// permits or corrupt the waiter queue.  After cancel + drop, a new
    /// waiter can still acquire when permits become available.
    #[test]
    fn semaphore_cancel_then_drop_does_not_leak() {
        init_test("semaphore_cancel_then_drop_does_not_leak");
        let cancel_cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 7)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 7)),
            crate::types::Budget::INFINITE,
        );
        let cx = test_cx();
        let sem = Semaphore::new(1);
        let held = sem.try_acquire(1).expect("initial acquire");

        // Queue a waiter.
        let mut fut = sem.acquire(&cancel_cx, 1);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "waiter pending", true, pending);

        // Cancel.
        cancel_cx.set_cancel_requested(true);
        let result = poll_once(&mut fut);
        let cancelled = result.is_some();
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);

        // Drop the cancelled future.
        drop(fut);

        // Permits should still be 0 (held by `held`).
        let avail = sem.available_permits();
        crate::assert_with_log!(avail == 0, "permits unchanged", 0usize, avail);

        // Release the held permit.
        drop(held);

        // A new waiter should be able to acquire — proving no phantom
        // waiter was left in the queue blocking it.
        let mut fut2 = sem.acquire(&cx, 1);
        let acquired = poll_once(&mut fut2);
        let got_permit = matches!(acquired, Some(Ok(_)));
        crate::assert_with_log!(
            got_permit,
            "new waiter acquires after cancel+drop",
            true,
            got_permit
        );

        crate::test_complete!("semaphore_cancel_then_drop_does_not_leak");
    }

    // =========================================================================
    // Pure data-type tests (wave 41 – CyanBarn)
    // =========================================================================

    #[test]
    fn acquire_error_debug_clone_copy_eq_display() {
        let closed = AcquireError::Closed;
        let cancelled = AcquireError::Cancelled;
        let done = AcquireError::PolledAfterCompletion;
        let copied = closed;
        let closed_copy = closed;
        assert_eq!(copied, closed_copy);
        assert_eq!(copied, AcquireError::Closed);
        assert_ne!(closed, cancelled);
        assert!(format!("{closed:?}").contains("Closed"));
        assert!(format!("{cancelled:?}").contains("Cancelled"));
        assert!(format!("{done:?}").contains("PolledAfterCompletion"));
        assert!(closed.to_string().contains("closed"));
        assert!(cancelled.to_string().contains("cancelled"));
        assert!(done.to_string().contains("polled after completion"));
    }

    #[test]
    fn owned_permit_forget_leaks_permits_but_not_arc() {
        init_test("owned_permit_forget_leaks_permits_but_not_arc");
        let sem = std::sync::Arc::new(Semaphore::new(2));
        let permit = OwnedSemaphorePermit::try_acquire_arc(&sem, 1).expect("should acquire");
        permit.forget();

        let avail_leaked = sem.available_permits();
        crate::assert_with_log!(avail_leaked == 1, "after forget", 1usize, avail_leaked);

        let strong = std::sync::Arc::strong_count(&sem);
        crate::assert_with_log!(strong == 1, "arc count", 1usize, strong);
        crate::test_complete!("owned_permit_forget_leaks_permits_but_not_arc");
    }

    // =========================================================================
    // Metamorphic fairness tests (bead asupersync-79xgip)
    // =========================================================================

    /// MR1: No permit underflow - permit count never goes negative
    /// Property: failed or cancelled acquires do not consume permits, and
    /// dropping permits restores the exact expected count.
    #[test]
    fn metamorphic_no_permit_underflow() {
        init_test("metamorphic_no_permit_underflow");
        let _cx = test_cx();
        let sem = Semaphore::new(3);

        // Initial state check
        let initial = sem.available_permits();
        crate::assert_with_log!(initial == 3, "initial permit count", 3usize, initial);

        // Acquire permits up to limit
        let p1 = sem.try_acquire(1).expect("acquire 1");
        let p2 = sem.try_acquire(2).expect("acquire 2");
        let remaining = sem.available_permits();
        crate::assert_with_log!(
            remaining == 0,
            "exactly 0 permits remaining",
            0usize,
            remaining
        );

        // Try to acquire more - should fail, not underflow
        let overflow = sem.try_acquire(1);
        crate::assert_with_log!(
            overflow.is_err(),
            "acquire overflow fails",
            true,
            overflow.is_err()
        );
        let still_zero = sem.available_permits();
        crate::assert_with_log!(still_zero == 0, "permits still zero", 0usize, still_zero);

        // Set up async acquire that will be cancelled
        let cancel_cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 8)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 8)),
            crate::types::Budget::INFINITE,
        );
        let mut fut = sem.acquire(&cancel_cx, 1);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "acquire waits when no permits", true, pending);

        // Cancel the waiting acquisition
        cancel_cx.set_cancel_requested(true);
        let result = poll_once(&mut fut);
        crate::assert_with_log!(
            result.is_some(),
            "cancellation completes",
            true,
            result.is_some()
        );

        // Cancelled acquires must not consume permits.
        let after_cancel = sem.available_permits();
        crate::assert_with_log!(
            after_cancel == 0,
            "permits unchanged by cancel",
            0usize,
            after_cancel
        );

        // Release permits and verify no underflow
        drop(p1);
        let after_drop1 = sem.available_permits();
        crate::assert_with_log!(after_drop1 == 1, "one permit released", 1usize, after_drop1);

        drop(p2);
        let after_drop2 = sem.available_permits();
        crate::assert_with_log!(
            after_drop2 == 3,
            "all permits released",
            3usize,
            after_drop2
        );

        crate::test_complete!("metamorphic_no_permit_underflow");
    }

    /// MR2: Cancel preserves permit count - cancelling an acquisition doesn't
    /// affect the available permit count, since permits are only decremented
    /// on successful acquisition.
    #[test]
    fn metamorphic_cancel_preserves_permit_count() {
        init_test("metamorphic_cancel_preserves_permit_count");
        let sem = Semaphore::new(2);

        // Hold one permit, leaving one available
        let _held = sem.try_acquire(1).expect("acquire 1");
        let before_cancel = sem.available_permits();
        crate::assert_with_log!(
            before_cancel == 1,
            "one permit available",
            1usize,
            before_cancel
        );

        // Create multiple cancel contexts for concurrent cancellation test
        let cancel_cx1 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 9)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 9)),
            crate::types::Budget::INFINITE,
        );
        let cancel_cx2 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 10)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 10)),
            crate::types::Budget::INFINITE,
        );

        // Start multiple waiters
        let mut fut1 = sem.acquire(&cancel_cx1, 1);
        let mut fut2 = sem.acquire(&cancel_cx2, 1);

        // First waiter should acquire immediately
        let result1 = poll_once(&mut fut1);
        crate::assert_with_log!(
            result1.is_some(),
            "first waiter acquires",
            true,
            result1.is_some()
        );

        // Second waiter should block
        let pending2 = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(pending2, "second waiter blocks", true, pending2);

        // Permit count should be zero now
        let after_acquire = sem.available_permits();
        crate::assert_with_log!(
            after_acquire == 0,
            "no permits after full acquisition",
            0usize,
            after_acquire
        );

        // Cancel the blocked waiter
        cancel_cx2.set_cancel_requested(true);
        let result2 = poll_once(&mut fut2);
        crate::assert_with_log!(
            result2.is_some(),
            "cancellation completes",
            true,
            result2.is_some()
        );

        // Permit count should be unchanged by cancellation
        let after_cancel = sem.available_permits();
        crate::assert_with_log!(
            after_cancel == 0,
            "permits unchanged by cancel",
            0usize,
            after_cancel
        );

        // Transform: add permits then cancel more waiters - count should only
        // reflect successful operations, not cancelled ones
        sem.add_permits(3);
        let after_add = sem.available_permits();
        crate::assert_with_log!(
            after_add == 3,
            "permits added successfully",
            3usize,
            after_add
        );

        // Start more waiters and cancel them
        let cancel_cx3 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 11)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 11)),
            crate::types::Budget::INFINITE,
        );
        let mut fut3 = sem.acquire(&cancel_cx3, 2);
        let result3 = poll_once(&mut fut3);
        crate::assert_with_log!(
            result3.is_some(),
            "large acquire succeeds",
            true,
            result3.is_some()
        );

        let remaining = sem.available_permits();
        crate::assert_with_log!(
            remaining == 1,
            "one permit left after large acquire",
            1usize,
            remaining
        );

        crate::test_complete!("metamorphic_cancel_preserves_permit_count");
    }

    /// MR3: FIFO order with concurrent cancellation - when some waiters are
    /// cancelled, remaining waiters should still be served in FIFO order.
    /// Property: order(service_without_cancellation) ⊆ order(service_with_cancellation)
    #[test]
    fn metamorphic_fifo_order_under_cancellation() {
        init_test("metamorphic_fifo_order_under_cancellation");
        let sem = Semaphore::new(0); // Start empty to force queueing

        // Create contexts for ordered waiters
        let cx1 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 12)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 12)),
            crate::types::Budget::INFINITE,
        );
        let cx2 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 13)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 13)),
            crate::types::Budget::INFINITE,
        );
        let cx3 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 14)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 14)),
            crate::types::Budget::INFINITE,
        );
        let cx4 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 15)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 15)),
            crate::types::Budget::INFINITE,
        );

        // Queue waiters in order: 1, 2, 3, 4
        let mut fut1 = sem.acquire(&cx1, 1);
        let mut fut2 = sem.acquire(&cx2, 1);
        let mut fut3 = sem.acquire(&cx3, 1);
        let mut fut4 = sem.acquire(&cx4, 1);

        // All should be pending
        crate::assert_with_log!(poll_once(&mut fut1).is_none(), "fut1 pending", true, true);
        crate::assert_with_log!(poll_once(&mut fut2).is_none(), "fut2 pending", true, true);
        crate::assert_with_log!(poll_once(&mut fut3).is_none(), "fut3 pending", true, true);
        crate::assert_with_log!(poll_once(&mut fut4).is_none(), "fut4 pending", true, true);

        // Cancel waiters 2 and 4 (middle cancellations)
        cx2.set_cancel_requested(true);
        cx4.set_cancel_requested(true);

        let result2 = poll_once(&mut fut2);
        let result4 = poll_once(&mut fut4);
        crate::assert_with_log!(result2.is_some(), "fut2 cancelled", true, result2.is_some());
        crate::assert_with_log!(result4.is_some(), "fut4 cancelled", true, result4.is_some());

        // Add permits one at a time - should wake remaining waiters in FIFO order
        sem.add_permits(1);
        let result1_first = poll_once(&mut fut1);
        crate::assert_with_log!(
            result1_first.is_some(),
            "fut1 wakes first",
            true,
            result1_first.is_some()
        );

        // fut3 should still be waiting
        crate::assert_with_log!(
            poll_once(&mut fut3).is_none(),
            "fut3 still pending",
            true,
            true
        );

        sem.add_permits(1);
        let result3_second = poll_once(&mut fut3);
        crate::assert_with_log!(
            result3_second.is_some(),
            "fut3 wakes second",
            true,
            result3_second.is_some()
        );

        // Transform: Test that FIFO order is preserved even with permit count variations
        let sem2 = Semaphore::new(0);

        // Create 6 contexts outside the loop to avoid lifetime issues
        let contexts = vec![
            Cx::new(
                crate::types::RegionId::from_arena(ArenaIndex::new(0, 16)),
                crate::types::TaskId::from_arena(ArenaIndex::new(0, 16)),
                crate::types::Budget::INFINITE,
            ),
            Cx::new(
                crate::types::RegionId::from_arena(ArenaIndex::new(0, 17)),
                crate::types::TaskId::from_arena(ArenaIndex::new(0, 17)),
                crate::types::Budget::INFINITE,
            ),
            Cx::new(
                crate::types::RegionId::from_arena(ArenaIndex::new(0, 18)),
                crate::types::TaskId::from_arena(ArenaIndex::new(0, 18)),
                crate::types::Budget::INFINITE,
            ),
            Cx::new(
                crate::types::RegionId::from_arena(ArenaIndex::new(0, 19)),
                crate::types::TaskId::from_arena(ArenaIndex::new(0, 19)),
                crate::types::Budget::INFINITE,
            ),
            Cx::new(
                crate::types::RegionId::from_arena(ArenaIndex::new(0, 20)),
                crate::types::TaskId::from_arena(ArenaIndex::new(0, 20)),
                crate::types::Budget::INFINITE,
            ),
            Cx::new(
                crate::types::RegionId::from_arena(ArenaIndex::new(0, 21)),
                crate::types::TaskId::from_arena(ArenaIndex::new(0, 21)),
                crate::types::Budget::INFINITE,
            ),
        ];

        let mut futures = Vec::new();
        for ctx in &contexts {
            futures.push(sem2.acquire(ctx, 1));
        }

        // All should be pending
        for (i, fut) in futures.iter_mut().enumerate() {
            crate::assert_with_log!(
                poll_once(fut).is_none(),
                &format!("waiter {} pending", i),
                true,
                true
            );
        }

        // Cancel odd-indexed waiters (1, 3, 5)
        contexts[1].set_cancel_requested(true);
        contexts[3].set_cancel_requested(true);
        contexts[5].set_cancel_requested(true);

        let result1 = poll_once(&mut futures[1]);
        let result3 = poll_once(&mut futures[3]);
        let result5 = poll_once(&mut futures[5]);
        crate::assert_with_log!(
            result1.is_some(),
            "waiter 1 cancelled",
            true,
            result1.is_some()
        );
        crate::assert_with_log!(
            result3.is_some(),
            "waiter 3 cancelled",
            true,
            result3.is_some()
        );
        crate::assert_with_log!(
            result5.is_some(),
            "waiter 5 cancelled",
            true,
            result5.is_some()
        );

        // Add permits and verify FIFO order: 0, then 2, then 4
        sem2.add_permits(1);
        let result0 = poll_once(&mut futures[0]);
        crate::assert_with_log!(
            result0.is_some(),
            "waiter 0 wakes first",
            true,
            result0.is_some()
        );
        crate::assert_with_log!(
            poll_once(&mut futures[2]).is_none(),
            "waiter 2 still pending",
            true,
            true
        );
        crate::assert_with_log!(
            poll_once(&mut futures[4]).is_none(),
            "waiter 4 still pending",
            true,
            true
        );

        sem2.add_permits(1);
        let result2 = poll_once(&mut futures[2]);
        crate::assert_with_log!(
            result2.is_some(),
            "waiter 2 wakes second",
            true,
            result2.is_some()
        );
        crate::assert_with_log!(
            poll_once(&mut futures[4]).is_none(),
            "waiter 4 still pending",
            true,
            true
        );

        sem2.add_permits(1);
        let result4_final = poll_once(&mut futures[4]);
        crate::assert_with_log!(
            result4_final.is_some(),
            "waiter 4 wakes third",
            true,
            result4_final.is_some()
        );

        crate::test_complete!("metamorphic_fifo_order_under_cancellation");
    }

    #[test]
    fn metamorphic_fifo_survivors_match_baseline_across_n_waiters() {
        init_test("metamorphic_fifo_survivors_match_baseline_across_n_waiters");

        let waiter_count = 8;
        let baseline = observe_waiter_service_order(waiter_count, &[], 40);
        assert_eq!(baseline, (0..waiter_count).collect::<Vec<_>>());

        let cancellation_patterns: [&[usize]; 4] = [&[1], &[0, 3, 5], &[2, 4, 7], &[0, 1, 6]];
        for (case_idx, cancelled) in cancellation_patterns.iter().enumerate() {
            let observed = observe_waiter_service_order(
                waiter_count,
                cancelled,
                80 + u32::try_from(case_idx * 16).expect("case offset fits in u32"),
            );
            let expected: Vec<_> = baseline
                .iter()
                .copied()
                .filter(|index| !cancelled.contains(index))
                .collect();

            assert_eq!(
                observed, expected,
                "case {case_idx} survivor order should match baseline FIFO projection"
            );
        }

        crate::test_complete!("metamorphic_fifo_survivors_match_baseline_across_n_waiters");
    }

    /// MR4: try_acquire non-blocking behavior - try_acquire should never block
    /// regardless of semaphore state, available permits, or concurrent operations.
    /// Property: try_acquire is always O(1) and immediate
    #[test]
    fn metamorphic_try_acquire_never_blocks() {
        init_test("metamorphic_try_acquire_never_blocks");

        // Test across different initial states
        let test_states = [
            (0, "zero permits"),
            (1, "one permit"),
            (5, "multiple permits"),
            (100, "many permits"),
        ];

        for (initial_permits, desc) in test_states {
            let sem = Semaphore::new(initial_permits);

            // try_acquire should be immediate regardless of success/failure
            let start_time = std::time::Instant::now();
            let result1 = sem.try_acquire(1);
            let elapsed1 = start_time.elapsed();

            // Should complete very quickly (< 1ms in practice, but allow 10ms for CI)
            let quick1 = elapsed1.as_millis() < 10;
            crate::assert_with_log!(
                quick1,
                &format!("try_acquire quick on {}", desc),
                true,
                quick1
            );

            if initial_permits > 0 {
                crate::assert_with_log!(
                    result1.is_ok(),
                    &format!("try_acquire succeeds on {}", desc),
                    true,
                    result1.is_ok()
                );
            }

            // try_acquire should be immediate even when acquiring all permits
            if initial_permits > 1 {
                let start_time = std::time::Instant::now();
                let _result_all = sem.try_acquire(initial_permits.saturating_sub(1));
                let elapsed_all = start_time.elapsed();

                let quick_all = elapsed_all.as_millis() < 10;
                crate::assert_with_log!(
                    quick_all,
                    &format!("try_acquire_all quick on {}", desc),
                    true,
                    quick_all
                );
            }

            // try_acquire should be immediate even when overcommitting
            let start_time = std::time::Instant::now();
            let result_over = sem.try_acquire(initial_permits + 10);
            let elapsed_over = start_time.elapsed();

            let quick_over = elapsed_over.as_millis() < 10;
            crate::assert_with_log!(
                quick_over,
                &format!("try_acquire_over quick on {}", desc),
                true,
                quick_over
            );
            crate::assert_with_log!(
                result_over.is_err(),
                &format!("try_acquire_over fails on {}", desc),
                true,
                result_over.is_err()
            );
        }

        // Transform: test try_acquire behavior during concurrent async operations
        let sem = Semaphore::new(1);
        let cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 17)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 17)),
            crate::types::Budget::INFINITE,
        );

        // Hold the permit with async acquire
        let _permit = sem.try_acquire(1).expect("initial acquire");

        // Start a waiting async acquire
        let mut fut = sem.acquire(&cx, 1);
        crate::assert_with_log!(
            poll_once(&mut fut).is_none(),
            "async acquire waits",
            true,
            true
        );

        // try_acquire should still be immediate even with waiters
        let start_time = std::time::Instant::now();
        let result_with_waiter = sem.try_acquire(1);
        let elapsed_with_waiter = start_time.elapsed();

        let quick_with_waiter = elapsed_with_waiter.as_millis() < 10;
        crate::assert_with_log!(
            quick_with_waiter,
            "try_acquire quick with waiters",
            true,
            quick_with_waiter
        );
        crate::assert_with_log!(
            result_with_waiter.is_err(),
            "try_acquire fails with waiters",
            true,
            result_with_waiter.is_err()
        );

        // Transform: test try_acquire on closed semaphore
        sem.close();
        let start_time = std::time::Instant::now();
        let result_closed = sem.try_acquire(1);
        let elapsed_closed = start_time.elapsed();

        let quick_closed = elapsed_closed.as_millis() < 10;
        crate::assert_with_log!(
            quick_closed,
            "try_acquire quick when closed",
            true,
            quick_closed
        );
        crate::assert_with_log!(
            result_closed.is_err(),
            "try_acquire fails when closed",
            true,
            result_closed.is_err()
        );

        crate::test_complete!("metamorphic_try_acquire_never_blocks");
    }

    /// MR5: Partitioning an acquisition preserves downstream observables.
    /// Property: acquiring `k` permits in one chunk or in multiple chunks whose
    /// sum is `k` leaves the same remaining capacity and the same readiness for
    /// a later waiter of size `w`.
    #[test]
    fn metamorphic_partitioned_acquire_preserves_capacity_and_waiter_readiness() {
        init_test("metamorphic_partitioned_acquire_preserves_capacity_and_waiter_readiness");

        let aggregate = Semaphore::new(6);
        let partitioned = Semaphore::new(6);

        let aggregate_permit = aggregate.try_acquire(4).expect("aggregate acquire");
        let partitioned_first = partitioned.try_acquire(1).expect("partitioned acquire 1");
        let partitioned_second = partitioned.try_acquire(3).expect("partitioned acquire 3");

        let aggregate_remaining = aggregate.available_permits();
        let partitioned_remaining = partitioned.available_permits();
        crate::assert_with_log!(
            aggregate_remaining == 2,
            "aggregate remaining capacity",
            2usize,
            aggregate_remaining
        );
        crate::assert_with_log!(
            partitioned_remaining == 2,
            "partitioned remaining capacity",
            2usize,
            partitioned_remaining
        );

        let aggregate_cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 22)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 22)),
            crate::types::Budget::INFINITE,
        );
        let partitioned_cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 23)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 23)),
            crate::types::Budget::INFINITE,
        );

        let mut aggregate_waiter = aggregate.acquire(&aggregate_cx, 3);
        let mut partitioned_waiter = partitioned.acquire(&partitioned_cx, 3);

        crate::assert_with_log!(
            poll_once(&mut aggregate_waiter).is_none(),
            "aggregate waiter pending before transform",
            true,
            true
        );
        crate::assert_with_log!(
            poll_once(&mut partitioned_waiter).is_none(),
            "partitioned waiter pending before transform",
            true,
            true
        );

        aggregate.add_permits(1);
        partitioned.add_permits(1);

        let aggregate_waiter_permit = poll_once(&mut aggregate_waiter)
            .expect("aggregate waiter ready")
            .expect("aggregate waiter acquired");
        let partitioned_waiter_permit = poll_once(&mut partitioned_waiter)
            .expect("partitioned waiter ready")
            .expect("partitioned waiter acquired");

        let aggregate_after_waiter = aggregate.available_permits();
        let partitioned_after_waiter = partitioned.available_permits();
        crate::assert_with_log!(
            aggregate_after_waiter == 0,
            "aggregate waiter consumes transformed capacity",
            0usize,
            aggregate_after_waiter
        );
        crate::assert_with_log!(
            partitioned_after_waiter == 0,
            "partitioned waiter consumes transformed capacity",
            0usize,
            partitioned_after_waiter
        );

        drop(aggregate_waiter_permit);
        drop(partitioned_waiter_permit);

        let aggregate_after_waiter_drop = aggregate.available_permits();
        let partitioned_after_waiter_drop = partitioned.available_permits();
        crate::assert_with_log!(
            aggregate_after_waiter_drop == 3,
            "aggregate waiter release restores transformed capacity",
            3usize,
            aggregate_after_waiter_drop
        );
        crate::assert_with_log!(
            partitioned_after_waiter_drop == 3,
            "partitioned waiter release restores transformed capacity",
            3usize,
            partitioned_after_waiter_drop
        );

        drop(aggregate_permit);
        drop(partitioned_first);
        drop(partitioned_second);

        let aggregate_final = aggregate.available_permits();
        let partitioned_final = partitioned.available_permits();
        crate::assert_with_log!(
            aggregate_final == 7,
            "aggregate final capacity includes transformed permit injection",
            7usize,
            aggregate_final
        );
        crate::assert_with_log!(
            partitioned_final == 7,
            "partitioned final capacity includes transformed permit injection",
            7usize,
            partitioned_final
        );

        crate::test_complete!(
            "metamorphic_partitioned_acquire_preserves_capacity_and_waiter_readiness"
        );
    }

    fn observe_middle_cancellation_schedule(
        cancel_before_first_permit: bool,
        seed_offset: u32,
    ) -> (Vec<usize>, usize, usize) {
        let sem = Semaphore::new(0);

        let cx1 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 30 + seed_offset)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 30 + seed_offset)),
            crate::types::Budget::INFINITE,
        );
        let cx2 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 31 + seed_offset)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 31 + seed_offset)),
            crate::types::Budget::INFINITE,
        );
        let cx3 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 32 + seed_offset)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 32 + seed_offset)),
            crate::types::Budget::INFINITE,
        );

        let mut fut1 = sem.acquire(&cx1, 1);
        let mut fut2 = sem.acquire(&cx2, 1);
        let mut fut3 = sem.acquire(&cx3, 1);

        assert!(poll_once(&mut fut1).is_none(), "waiter 1 should queue");
        assert!(poll_once(&mut fut2).is_none(), "waiter 2 should queue");
        assert!(poll_once(&mut fut3).is_none(), "waiter 3 should queue");

        if cancel_before_first_permit {
            cx2.set_cancel_requested(true);
            assert!(
                poll_once(&mut fut2).is_some(),
                "middle waiter cancellation should complete before permits"
            );
        }

        sem.add_permits(1);
        let permit1 = poll_once(&mut fut1)
            .expect("first waiter should wake after first permit")
            .expect("first waiter should acquire permit");
        assert!(
            poll_once(&mut fut3).is_none(),
            "single permit should not wake the third waiter"
        );

        if !cancel_before_first_permit {
            cx2.set_cancel_requested(true);
            assert!(
                poll_once(&mut fut2).is_some(),
                "middle waiter cancellation should complete after first permit"
            );
        }

        assert!(
            poll_once(&mut fut3).is_none(),
            "third waiter should still be pending until the second permit"
        );

        sem.add_permits(1);
        let permit3 = poll_once(&mut fut3)
            .expect("third waiter should wake after second permit")
            .expect("third waiter should acquire permit");

        let while_held = sem.available_permits();
        assert_eq!(
            while_held, 0,
            "two injected permits should be fully consumed"
        );

        drop(permit1);
        let after_first_drop = sem.available_permits();

        drop(permit3);
        let final_available = sem.available_permits();

        (vec![1, 3], after_first_drop, final_available)
    }

    fn observe_head_cancelled_drain_schedule(
        cancel_before_partial_permit: bool,
        seed_offset: u32,
    ) -> (Vec<usize>, usize, usize) {
        let sem = Semaphore::new(0);

        let cx1 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 40 + seed_offset)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 40 + seed_offset)),
            crate::types::Budget::INFINITE,
        );
        let cx2 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 41 + seed_offset)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 41 + seed_offset)),
            crate::types::Budget::INFINITE,
        );
        let cx3 = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 42 + seed_offset)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 42 + seed_offset)),
            crate::types::Budget::INFINITE,
        );

        let mut fut1 = sem.acquire(&cx1, 2);
        let mut fut2 = sem.acquire(&cx2, 1);
        let mut fut3 = sem.acquire(&cx3, 1);

        assert!(poll_once(&mut fut1).is_none(), "head waiter should queue");
        assert!(poll_once(&mut fut2).is_none(), "second waiter should queue");
        assert!(poll_once(&mut fut3).is_none(), "third waiter should queue");

        if cancel_before_partial_permit {
            cx1.set_cancel_requested(true);
            assert!(
                poll_once(&mut fut1).is_some(),
                "head waiter cancellation should complete before permit injection"
            );
        }

        sem.add_permits(1);

        if cancel_before_partial_permit {
            let permit2 = poll_once(&mut fut2)
                .expect("second waiter should wake after head cancellation")
                .expect("second waiter should acquire permit");
            assert!(
                poll_once(&mut fut3).is_none(),
                "third waiter should remain queued until another permit arrives"
            );

            sem.add_permits(1);
            let permit3 = poll_once(&mut fut3)
                .expect("third waiter should wake after second permit")
                .expect("third waiter should acquire permit");

            let while_held = sem.available_permits();
            assert_eq!(while_held, 0, "both injected permits should be consumed");

            drop(permit2);
            let after_first_drop = sem.available_permits();
            drop(permit3);
            let final_available = sem.available_permits();
            (vec![2, 3], after_first_drop, final_available)
        } else {
            assert!(
                poll_once(&mut fut2).is_none(),
                "second waiter must stay blocked behind large head waiter"
            );
            assert!(
                poll_once(&mut fut3).is_none(),
                "third waiter must stay blocked behind large head waiter"
            );
            assert_eq!(
                sem.available_permits(),
                1,
                "partial permit remains available until head waiter cancels"
            );

            cx1.set_cancel_requested(true);
            assert!(
                poll_once(&mut fut1).is_some(),
                "head waiter cancellation should complete after partial permit injection"
            );

            let permit2 = poll_once(&mut fut2)
                .expect("second waiter should wake once head waiter cancels")
                .expect("second waiter should acquire queued permit");
            assert!(
                poll_once(&mut fut3).is_none(),
                "third waiter should remain queued until another permit arrives"
            );

            sem.add_permits(1);
            let permit3 = poll_once(&mut fut3)
                .expect("third waiter should wake after second permit")
                .expect("third waiter should acquire permit");

            let while_held = sem.available_permits();
            assert_eq!(while_held, 0, "both injected permits should be consumed");

            drop(permit2);
            let after_first_drop = sem.available_permits();
            drop(permit3);
            let final_available = sem.available_permits();
            (vec![2, 3], after_first_drop, final_available)
        }
    }

    #[test]
    fn metamorphic_middle_cancellation_timing_preserves_wake_order_and_capacity() {
        init_test("metamorphic_middle_cancellation_timing_preserves_wake_order_and_capacity");

        let cancel_before = observe_middle_cancellation_schedule(true, 0);
        let cancel_after = observe_middle_cancellation_schedule(false, 10);

        crate::assert_with_log!(
            cancel_before.0 == cancel_after.0,
            "survivor wake order preserved",
            &cancel_before.0,
            &cancel_after.0
        );
        crate::assert_with_log!(
            cancel_before.0 == vec![1, 3],
            "survivors wake in FIFO projection",
            vec![1, 3],
            cancel_before.0.clone()
        );
        crate::assert_with_log!(
            cancel_before.1 == cancel_after.1,
            "post-drop permit count preserved",
            cancel_before.1,
            cancel_after.1
        );
        crate::assert_with_log!(
            cancel_before.1 == 1,
            "dropping first survivor releases exactly one permit",
            1usize,
            cancel_before.1
        );
        crate::assert_with_log!(
            cancel_before.2 == cancel_after.2,
            "final permit count preserved",
            cancel_before.2,
            cancel_after.2
        );
        crate::assert_with_log!(
            cancel_before.2 == 2,
            "cancelled waiter does not consume injected permits",
            2usize,
            cancel_before.2
        );

        crate::test_complete!(
            "metamorphic_middle_cancellation_timing_preserves_wake_order_and_capacity"
        );
    }

    #[test]
    fn metamorphic_head_cancellation_releases_blocked_followers_in_fifo_order() {
        init_test("metamorphic_head_cancellation_releases_blocked_followers_in_fifo_order");

        let cancel_before = observe_head_cancelled_drain_schedule(true, 0);
        let cancel_after = observe_head_cancelled_drain_schedule(false, 10);

        crate::assert_with_log!(
            cancel_before.0 == cancel_after.0,
            "survivor wake order preserved across head cancellation timing",
            &cancel_before.0,
            &cancel_after.0
        );
        crate::assert_with_log!(
            cancel_before.0 == vec![2, 3],
            "smaller followers drain in FIFO order after head cancellation",
            vec![2, 3],
            cancel_before.0.clone()
        );
        crate::assert_with_log!(
            cancel_before.1 == cancel_after.1,
            "first drop restores one permit regardless of cancellation timing",
            cancel_before.1,
            cancel_after.1
        );
        crate::assert_with_log!(
            cancel_before.1 == 1,
            "dropping the first surviving waiter releases exactly one permit",
            1usize,
            cancel_before.1
        );
        crate::assert_with_log!(
            cancel_before.2 == cancel_after.2,
            "final permit count preserved across head cancellation timing",
            cancel_before.2,
            cancel_after.2
        );
        crate::assert_with_log!(
            cancel_before.2 == 2,
            "cancelled large waiter does not consume injected permits",
            2usize,
            cancel_before.2
        );

        crate::test_complete!(
            "metamorphic_head_cancellation_releases_blocked_followers_in_fifo_order"
        );
    }

    #[test]
    fn test_semaphore_permit_obligation_structure() {
        init_test("test_semaphore_permit_obligation_structure");
        let sem = Semaphore::new(2);

        // Test that permits have obligation tracking fields
        let permit = sem.try_acquire(1).expect("should acquire permit");

        // Verify the permit can be committed explicitly
        permit.commit();

        // Test owned permit as well
        let owned_permit = OwnedSemaphorePermit::try_acquire(Arc::new(sem), 1)
            .expect("should acquire owned permit");

        // Verify owned permit can be committed
        owned_permit.commit();

        crate::test_complete!("test_semaphore_permit_obligation_structure");
    }

    #[test]
    fn dropping_semaphore_permit_releases_capacity_without_panic() {
        init_test("dropping_semaphore_permit_releases_capacity_without_panic");
        let sem = Semaphore::new(1);

        let permit = sem.try_acquire(1).expect("should acquire permit");
        let unavailable = sem.available_permits();
        crate::assert_with_log!(unavailable == 0, "capacity consumed", 0usize, unavailable);

        drop(permit);

        let available = sem.available_permits();
        crate::assert_with_log!(available == 1, "capacity restored", 1usize, available);
        crate::test_complete!("dropping_semaphore_permit_releases_capacity_without_panic");
    }

    #[test]
    fn dropping_owned_semaphore_permit_releases_capacity_without_panic() {
        init_test("dropping_owned_semaphore_permit_releases_capacity_without_panic");
        let sem = Arc::new(Semaphore::new(1));

        let permit =
            OwnedSemaphorePermit::try_acquire(Arc::clone(&sem), 1).expect("should acquire permit");
        let unavailable = sem.available_permits();
        crate::assert_with_log!(unavailable == 0, "capacity consumed", 0usize, unavailable);

        drop(permit);

        let available = sem.available_permits();
        crate::assert_with_log!(available == 1, "capacity restored", 1usize, available);
        crate::test_complete!("dropping_owned_semaphore_permit_releases_capacity_without_panic");
    }
}
