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
    state: ParkingMutex<SemaphoreState>,
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
            state: ParkingMutex::new(SemaphoreState {
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
        self.state.lock().permits
    }

    /// Returns the maximum number of permits (initial count).
    #[must_use]
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Returns true if the semaphore is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    /// Closes the semaphore.
    pub fn close(&self) {
        let mut state = self.state.lock();
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

        let mut state = self.state.lock();
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
        let mut state = self.state.lock();
        state.permits = state.permits.saturating_add(count);
        // Only wake the first waiter since FIFO ordering means only it can acquire.
        // Waking all waiters wastes CPU when only the front can make progress.
        // If the first waiter acquires and releases, it will wake the next.
        if let Some(first) = state.waiters.front() {
            first.waker.wake_by_ref();
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
            let mut state = self.semaphore.state.lock();

            // If we are at the front, we need to wake the next waiter when we leave,
            // otherwise the signal (permits available) might be lost.
            let was_front = state.waiters.front().is_some_and(|w| w.id == waiter_id);

            state.waiters.retain(|waiter| waiter.id != waiter_id);

            if was_front {
                if let Some(next) = state.waiters.front() {
                    next.waker.wake_by_ref();
                }
            }
        }
    }
}

impl<'a> Future for AcquireFuture<'a, '_> {
    type Output = Result<SemaphorePermit<'a>, AcquireError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            if let Some(waiter_id) = self.waiter_id {
                let mut state = self.semaphore.state.lock();

                // If we are at the front, we need to wake the next waiter when we leave,
                // otherwise the signal (permits available) might be lost.
                let was_front = state.waiters.front().is_some_and(|w| w.id == waiter_id);

                state.waiters.retain(|waiter| waiter.id != waiter_id);

                if was_front {
                    if let Some(next) = state.waiters.front() {
                        next.waker.wake_by_ref();
                    }
                }
                // Clear waiter_id so Drop doesn't try to remove it again
                self.waiter_id = None;
            }
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        let waiter_id = if let Some(id) = self.waiter_id {
            id
        } else {
            let id = {
                let mut state = self.semaphore.state.lock();
                let id = state.next_waiter_id;
                state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                id
            };
            self.waiter_id = Some(id);
            id
        };

        let mut state = self.semaphore.state.lock();

        if state.closed {
            state.waiters.retain(|waiter| waiter.id != waiter_id);
            drop(state);
            self.waiter_id = None;
            return Poll::Ready(Err(AcquireError::Closed));
        }

        // FIFO fairness: only acquire if queue is empty or we are at the front.
        // This prevents queue jumping where a new arrival grabs permits before
        // earlier-waiting tasks get their turn.
        let is_next_in_line = state.waiters.front().is_none_or(|w| w.id == waiter_id);

        if is_next_in_line && state.permits >= self.count {
            state.permits -= self.count;

            // Optimization: Since we verified we are next in line, we are either
            // at the front of the queue or the queue is empty. We can just pop
            // the front instead of scanning the whole deque with retain (O(N)).
            if !state.waiters.is_empty() {
                state.waiters.pop_front();
            }

            // Wake next waiter if there are still permits available.
            // Without this, add_permits(N) where N satisfies multiple waiters
            // would only wake the first, leaving others sleeping indefinitely.
            if state.permits > 0 {
                if let Some(next) = state.waiters.front() {
                    next.waker.wake_by_ref();
                }
            }
            drop(state);
            // Clear waiter_id after releasing state guard to avoid borrow conflicts.
            self.waiter_id = None;
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
            if !existing.waker.will_wake(context.waker()) {
                existing.waker.clone_from(context.waker());
            }
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
        // Acquire permits via the semaphore's internal state directly.
        // We forget the SemaphorePermit to avoid its Drop releasing permits,
        // since OwnedSemaphorePermit's Drop will handle the release instead.
        let permit = semaphore.try_acquire(count)?;
        // Transfer ownership: forget the borrow-based permit so it doesn't
        // release on drop; the OwnedSemaphorePermit will release in its own Drop.
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
            let mut state = self.semaphore.state.lock();

            // If we are at the front, we need to wake the next waiter when we leave,
            // otherwise the signal (permits available) might be lost.
            let was_front = state.waiters.front().is_some_and(|w| w.id == waiter_id);

            state.waiters.retain(|waiter| waiter.id != waiter_id);

            if was_front {
                if let Some(next) = state.waiters.front() {
                    next.waker.wake_by_ref();
                }
            }
        }
    }
}

impl Future for OwnedAcquireFuture {
    type Output = Result<OwnedSemaphorePermit, AcquireError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            if let Some(waiter_id) = self.waiter_id {
                {
                    let mut state = self.semaphore.state.lock();
                    let was_front = state.waiters.front().is_some_and(|w| w.id == waiter_id);
                    state.waiters.retain(|waiter| waiter.id != waiter_id);
                    if was_front {
                        if let Some(next) = state.waiters.front() {
                            next.waker.wake_by_ref();
                        }
                    }
                }
                // Clear waiter_id so Drop doesn't try to remove it again.
                // Must happen after `state` is dropped (end of block above)
                // to satisfy the borrow checker.
                self.waiter_id = None;
            }
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        let waiter_id = if let Some(id) = self.waiter_id {
            id
        } else {
            let id = {
                let mut state = self.semaphore.state.lock();
                let id = state.next_waiter_id;
                state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                id
            };
            self.waiter_id = Some(id);
            id
        };

        let mut state = self.semaphore.state.lock();

        if state.closed {
            state.waiters.retain(|waiter| waiter.id != waiter_id);
            drop(state);
            self.waiter_id = None;
            return Poll::Ready(Err(AcquireError::Closed));
        }

        // FIFO fairness: only acquire if queue is empty or we are at the front.
        let is_next_in_line = state.waiters.front().is_none_or(|w| w.id == waiter_id);

        if is_next_in_line && state.permits >= self.count {
            state.permits -= self.count;

            // Optimization: O(1) removal instead of O(N) retain
            if !state.waiters.is_empty() {
                state.waiters.pop_front();
            }

            // Wake next waiter if there are still permits available.
            // Without this, add_permits(N) where N satisfies multiple waiters
            // would only wake the first, leaving others sleeping indefinitely.
            if state.permits > 0 {
                if let Some(next) = state.waiters.front() {
                    next.waker.wake_by_ref();
                }
            }
            drop(state);
            // Prevent redundant Drop cleanup after releasing state guard.
            self.waiter_id = None;
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
            if !existing.waker.will_wake(context.waker()) {
                existing.waker.clone_from(context.waker());
            }
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

    fn acquire_blocking<'a>(
        semaphore: &'a Semaphore,
        cx: &Cx,
        count: usize,
    ) -> SemaphorePermit<'a> {
        let mut fut = semaphore.acquire(cx, count);
        poll_until_ready(&mut fut).expect("acquire failed")
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
}
