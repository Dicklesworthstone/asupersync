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

#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

/// Error returned when semaphore acquisition fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// The semaphore was closed.
    Closed,
    /// Cancelled while waiting.
    Cancelled,
}

impl std::fmt::Display for AcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "semaphore closed"),
            Self::Cancelled => write!(f, "semaphore acquire cancelled"),
        }
    }
}

impl std::error::Error for AcquireError {}

/// Error returned when trying to acquire more permits than available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryAcquireError;

impl std::fmt::Display for TryAcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no semaphore permits available")
    }
}

impl std::error::Error for TryAcquireError {}

/// A counting semaphore for limiting concurrent access.
#[derive(Debug)]
pub struct Semaphore {
    /// Internal state for permits and waiters.
    state: StdMutex<SemaphoreState>,
    /// Maximum permits (initial count).
    max_permits: usize,
}

unsafe impl Send for Semaphore {}
unsafe impl Sync for Semaphore {}

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
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    waker: Waker,
}

impl Semaphore {
    /// Creates a new semaphore with the given number of permits.
    #[must_use]
    pub fn new(permits: usize) -> Self {
        Self {
            state: StdMutex::new(SemaphoreState {
                permits,
                closed: false,
                waiters: VecDeque::new(),
                next_waiter_id: 0,
            }),
            max_permits: permits,
        }
    }

    /// Returns the number of currently available permits.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.state.lock().expect("semaphore lock poisoned").permits
    }

    /// Returns the maximum number of permits (initial count).
    #[must_use]
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Returns true if the semaphore is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("semaphore lock poisoned").closed
    }

    /// Closes the semaphore.
    pub fn close(&self) {
        let mut state = self.state.lock().expect("semaphore lock poisoned");
        state.closed = true;
        for waiter in state.waiters.drain(..) {
            waiter.waker.wake();
        }
    }

    /// Acquires the given number of permits asynchronously.
    pub fn acquire<'a, 'b>(&'a self, cx: &'b Cx, count: usize) -> AcquireFuture<'a, 'b> {
        assert!(count > 0, "cannot acquire 0 permits");
        assert!(
            count <= self.max_permits,
            "cannot acquire more permits than semaphore capacity"
        );
        AcquireFuture {
            semaphore: self,
            cx,
            count,
            waiter_id: None,
        }
    }

    /// Tries to acquire the given number of permits without waiting.
    pub fn try_acquire(&self, count: usize) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        assert!(count > 0, "cannot acquire 0 permits");
        assert!(
            count <= self.max_permits,
            "cannot acquire more permits than semaphore capacity"
        );

        let mut state = self.state.lock().expect("semaphore lock poisoned");
        let result = if state.closed {
            Err(TryAcquireError)
        } else if !state.waiters.is_empty() {
            // Strict FIFO
            Err(TryAcquireError)
        } else if state.permits >= count {
            state.permits -= count;
            Ok(SemaphorePermit {
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
    pub fn add_permits(&self, count: usize) {
        let mut state = self.state.lock().expect("semaphore lock poisoned");
        state.permits = state.permits.saturating_add(count);
        for waiter in &state.waiters {
            waiter.waker.wake_by_ref();
        }
    }
}

/// Future returned by `Semaphore::acquire`.
pub struct AcquireFuture<'a, 'b> {
    semaphore: &'a Semaphore,
    cx: &'b Cx,
    count: usize,
    waiter_id: Option<u64>,
}

impl Drop for AcquireFuture<'_, '_> {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            let mut state = self
                .semaphore
                .state
                .lock()
                .expect("semaphore lock poisoned");
            state.waiters.retain(|waiter| waiter.id != waiter_id);
        }
    }
}

impl<'a> Future for AcquireFuture<'a, '_> {
    type Output = Result<SemaphorePermit<'a>, AcquireError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            if let Some(waiter_id) = self.waiter_id {
                let mut state = self
                    .semaphore
                    .state
                    .lock()
                    .expect("semaphore lock poisoned");
                state.waiters.retain(|waiter| waiter.id != waiter_id);
            }
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        let waiter_id = if let Some(id) = self.waiter_id {
            id
        } else {
            let id = {
                let mut state = self
                    .semaphore
                    .state
                    .lock()
                    .expect("semaphore lock poisoned");
                let id = state.next_waiter_id;
                state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                id
            };
            self.waiter_id = Some(id);
            id
        };

        let mut state = self
            .semaphore
            .state
            .lock()
            .expect("semaphore lock poisoned");

        if state.closed {
            state.waiters.retain(|waiter| waiter.id != waiter_id);
            return Poll::Ready(Err(AcquireError::Closed));
        }

        // FIFO fairness: only acquire if queue is empty or we are at the front.
        // This prevents queue jumping where a new arrival grabs permits before
        // earlier-waiting tasks get their turn.
        let is_next_in_line = state.waiters.front().is_none_or(|w| w.id == waiter_id);

        if is_next_in_line && state.permits >= self.count {
            state.permits -= self.count;
            state.waiters.retain(|waiter| waiter.id != waiter_id);
            return Poll::Ready(Ok(SemaphorePermit {
                semaphore: self.semaphore,
                count: self.count,
            }));
        }

        if let Some(existing) = state
            .waiters
            .iter_mut()
            .find(|waiter| waiter.id == waiter_id)
        {
            existing.waker.clone_from(context.waker());
        } else {
            state.waiters.push_back(Waiter {
                id: waiter_id,
                waker: context.waker().clone(),
            });
        }
        Poll::Pending
    }
}

/// A permit from a semaphore.
#[must_use = "permit will be immediately released if not held"]
pub struct SemaphorePermit<'a> {
    semaphore: &'a Semaphore,
    count: usize,
}

impl SemaphorePermit<'_> {
    /// Returns the number of permits held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Forgets the permit without releasing it back to the semaphore.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        self.semaphore.add_permits(self.count);
    }
}

/// An owned permit from a semaphore.
#[derive(Debug)]
#[must_use = "permit will be immediately released if not held"]
pub struct OwnedSemaphorePermit {
    semaphore: std::sync::Arc<Semaphore>,
    count: usize,
}

unsafe impl Send for OwnedSemaphorePermit {}
unsafe impl Sync for OwnedSemaphorePermit {}

impl OwnedSemaphorePermit {
    /// Acquires an owned permit asynchronously.
    pub async fn acquire(
        semaphore: std::sync::Arc<Semaphore>,
        cx: &Cx,
        count: usize,
    ) -> Result<Self, AcquireError> {
        OwnedAcquireFuture {
            semaphore,
            cx: cx.clone(),
            count,
            waiter_id: None,
        }
        .await
    }

    /// Tries to acquire an owned permit without waiting.
    pub fn try_acquire(
        semaphore: std::sync::Arc<Semaphore>,
        count: usize,
    ) -> Result<Self, TryAcquireError> {
        let permit = semaphore.try_acquire(count)?;
        std::mem::forget(permit);
        Ok(Self { semaphore, count })
    }

    /// Returns the number of permits held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Drop for OwnedSemaphorePermit {
    fn drop(&mut self) {
        self.semaphore.add_permits(self.count);
    }
}

struct OwnedAcquireFuture {
    semaphore: Arc<Semaphore>,
    cx: Cx, // Clone of Cx
    count: usize,
    waiter_id: Option<u64>,
}

impl Drop for OwnedAcquireFuture {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            let mut state = self
                .semaphore
                .state
                .lock()
                .expect("semaphore lock poisoned");
            state.waiters.retain(|waiter| waiter.id != waiter_id);
        }
    }
}

impl Future for OwnedAcquireFuture {
    type Output = Result<OwnedSemaphorePermit, AcquireError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            if let Some(waiter_id) = self.waiter_id {
                let mut state = self
                    .semaphore
                    .state
                    .lock()
                    .expect("semaphore lock poisoned");
                state.waiters.retain(|waiter| waiter.id != waiter_id);
            }
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        let waiter_id = if let Some(id) = self.waiter_id {
            id
        } else {
            let id = {
                let mut state = self
                    .semaphore
                    .state
                    .lock()
                    .expect("semaphore lock poisoned");
                let id = state.next_waiter_id;
                state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                id
            };
            self.waiter_id = Some(id);
            id
        };

        let mut state = self
            .semaphore
            .state
            .lock()
            .expect("semaphore lock poisoned");

        if state.closed {
            state.waiters.retain(|waiter| waiter.id != waiter_id);
            return Poll::Ready(Err(AcquireError::Closed));
        }

        // FIFO fairness: only acquire if queue is empty or we are at the front.
        let is_next_in_line = state.waiters.front().is_none_or(|w| w.id == waiter_id);

        if is_next_in_line && state.permits >= self.count {
            state.permits -= self.count;
            state.waiters.retain(|waiter| waiter.id != waiter_id);
            return Poll::Ready(Ok(OwnedSemaphorePermit {
                semaphore: self.semaphore.clone(),
                count: self.count,
            }));
        }

        if let Some(existing) = state
            .waiters
            .iter_mut()
            .find(|waiter| waiter.id == waiter_id)
        {
            existing.waker.clone_from(context.waker());
        } else {
            state.waiters.push_back(Waiter {
                id: waiter_id,
                waker: context.waker().clone(),
            });
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
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

    fn poll_once<T>(future: &mut impl Future<Output = T>) -> Option<T> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match unsafe { Pin::new_unchecked(future) }.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
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
        let waiter_len = sem.state.lock().unwrap().waiters.len();
        crate::assert_with_log!(waiter_len == 1, "waiter queued", 1usize, waiter_len);

        cx.set_cancel_requested(true);
        let result = poll_once(&mut fut).expect("cancel poll");
        let cancelled = matches!(result, Err(AcquireError::Cancelled));
        crate::assert_with_log!(cancelled, "cancelled error", true, cancelled);
        let waiter_len = sem.state.lock().unwrap().waiters.len();
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
        let waiter_len = sem.state.lock().unwrap().waiters.len();
        crate::assert_with_log!(waiter_len == 1, "waiter queued", 1usize, waiter_len);

        drop(fut);
        let waiter_len = sem.state.lock().unwrap().waiters.len();
        crate::assert_with_log!(waiter_len == 0, "waiter removed", 0usize, waiter_len);
        crate::test_complete!("drop_removes_waiter");
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
        let _permit1 = result1.expect("first should acquire").expect("no error");
        crate::assert_with_log!(true, "first waiter acquires", true, true);

        // Second waiter should still be pending (permit1 still held)
        let still_pending = poll_once(&mut fut2).is_none();
        crate::assert_with_log!(still_pending, "second still pending", true, still_pending);

        drop(_permit1); // explicitly drop to document lifetime
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
        let _permit1 = result1.expect("first should acquire").expect("no error");
        crate::assert_with_log!(true, "first waiter acquires", true, true);

        // Third should still be pending (permit1 still held)
        let third_pending = poll_once(&mut fut3).is_none();
        crate::assert_with_log!(third_pending, "third still pending", true, third_pending);

        drop(_permit1); // explicitly drop to document lifetime
        crate::test_complete!("test_semaphore_cancel_preserves_order");
    }
}
