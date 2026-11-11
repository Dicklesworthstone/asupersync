//! Clone-shared admission held through transport-future destruction.

use super::RemoteSymbolError;
use crate::cx::Cx;
use crate::sync::{AcquireError, CheckedAcquireError, Semaphore, SemaphorePermit};
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

pub(super) struct Admission {
    active: AtomicUsize,
    limit: usize,
    queue: Option<QueuedAdmission>,
}

impl Admission {
    pub(super) const fn new(limit: usize) -> Self {
        Self { active: AtomicUsize::new(0), limit, queue: None }
    }

    pub(super) fn active(&self) -> usize { self.active.load(Ordering::Acquire) }
    pub(super) const fn limit(&self) -> usize { self.limit }

    pub(super) fn enable_queue(&mut self, max_waiters: usize) {
        self.queue = Some(QueuedAdmission {
            permits: Semaphore::new(self.limit),
            waiting: AtomicUsize::new(0),
            max_waiters,
        });
    }

    pub(super) const fn is_queued(&self) -> bool { self.queue.is_some() }

    pub(super) fn waiting(&self) -> usize {
        self.queue.as_ref().map_or(0, |queue| queue.waiting.load(Ordering::Acquire))
    }

    pub(super) fn max_waiters(&self) -> usize {
        self.queue.as_ref().map_or(0, |queue| queue.max_waiters)
    }

    pub(super) async fn run_with<T, F, Fut>(&self, cx: &Cx, make: F) -> Result<T, RemoteSymbolError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, RemoteSymbolError>>,
    {
        let Some(queue) = &self.queue else { return self.run(make).await; };
        // Zero active capacity is a deliberate refusal, never an infinite wait.
        if self.limit == 0 { return Err(RemoteSymbolError::Admission); }
        let permit = queue.acquire(cx).await?;
        // The grant can run user waker/obligation callbacks. Recheck before the
        // factory can allocate, encode, or dispatch using a cancelled owner.
        check_owner(cx)?;
        let result = self.run(make).await;
        // run() retires its inner future and active credit before waking the
        // next FIFO waiter, including on drop or unwind.
        drop(permit);
        result
    }

    fn acquire(&self) -> Result<Credit<'_>, RemoteSymbolError> {
        let mut active = self.active();
        loop {
            if active >= self.limit { return Err(RemoteSymbolError::Admission); }
            // active < limit <= usize::MAX proves increment cannot overflow.
            match self.active.compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Credit(self)),
                Err(current) => active = current,
            }
        }
    }

    // A factory, not an already-constructed future: eager encoding/network work
    // cannot run before admission. The inner scope destroys even a Ready future
    // before the credit is returned. Drop/unwind retain the same ownership order.
    pub(super) async fn run<T, F, Fut>(&self, make: F) -> Result<T, RemoteSymbolError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, RemoteSymbolError>>,
    {
        let credit = self.acquire()?;
        let result = {
            let mut future = std::pin::pin!(make());
            poll_fn(|task| future.as_mut().poll(task)).await
        };
        drop(credit);
        result
    }
}

struct QueuedAdmission {
    permits: Semaphore,
    waiting: AtomicUsize,
    max_waiters: usize,
}

impl QueuedAdmission {
    fn reserve_waiter(&self) -> Result<WaitingCredit<'_>, RemoteSymbolError> {
        let mut waiting = self.waiting.load(Ordering::Acquire);
        loop {
            if waiting >= self.max_waiters { return Err(RemoteSymbolError::Admission); }
            match self.waiting.compare_exchange_weak(waiting, waiting + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(WaitingCredit(&self.waiting)),
                Err(current) => waiting = current,
            }
        }
    }

    async fn acquire(&self, cx: &Cx) -> Result<SemaphorePermit<'_>, RemoteSymbolError> {
        check_owner(cx)?;
        match self.permits.try_acquire_checked(cx, 1) {
            Ok(permit) => return Ok(permit),
            Err(CheckedAcquireError::Unavailable(_)) => {},
            Err(error) => return Err(acquire_error(error)),
        }
        // Reserve metadata BEFORE the semaphore or cancellation observer may
        // register a waker. Keep it charged until both futures are destroyed.
        let waiter = self.reserve_waiter()?;
        let result = {
            let timer = if let Some(deadline) = cx.budget().deadline {
                let driver = cx.timer_driver().ok_or(RemoteSymbolError::Configuration)?;
                Some(crate::time::Sleep::with_timer_driver(deadline, driver))
            } else { None };
            let mut timer = std::pin::pin!(timer);
            let mut cancelled = std::pin::pin!(cx.cancelled());
            let mut acquire = std::pin::pin!(self.permits.acquire_checked(cx, 1));
            poll_fn(|task| {
                if timer.as_mut().as_pin_mut().is_some_and(|timer| timer.poll_deadline(task).is_ready()) {
                    let _ = cx.checkpoint();
                    return Poll::Ready(Err(RemoteSymbolError::Deadline));
                }
                if cancelled.as_mut().poll(task).is_ready() {
                    let _ = cx.checkpoint();
                    return Poll::Ready(Err(RemoteSymbolError::Cancelled));
                }
                acquire.as_mut().poll(task).map(|result| result.map_err(acquire_error))
            }).await
        };
        drop(waiter);
        result
    }
}

fn check_owner(cx: &Cx) -> Result<(), RemoteSymbolError> {
    if cx.is_cancel_requested() {
        let _ = cx.checkpoint();
        return Err(RemoteSymbolError::Cancelled);
    }
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
        let _ = cx.checkpoint();
        return Err(RemoteSymbolError::Deadline);
    }
    Ok(())
}

fn acquire_error(error: CheckedAcquireError) -> RemoteSymbolError {
    match error {
        CheckedAcquireError::Semaphore(AcquireError::Cancelled) => RemoteSymbolError::Cancelled,
        _ => RemoteSymbolError::Admission,
    }
}

struct WaitingCredit<'a>(&'a AtomicUsize);
impl Drop for WaitingCredit<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
}

struct Credit<'a>(&'a Admission);
impl Drop for Credit<'_> {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::AcqRel); }
}

#[cfg(test)]
mod tests;
