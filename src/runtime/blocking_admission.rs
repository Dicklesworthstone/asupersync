//! Opt-in bounded admission for the blocking pool.
//!
//! Capacity counts queued jobs across all routing queues. Running jobs do not
//! consume queue capacity. A waiting submission owns its closure until it can
//! publish it; dropping that future removes its waiter and returns no work to
//! the pool.

use super::{
    BlockingPool, BlockingPoolHandle, BlockingPoolInner, BlockingTask, BlockingTaskCompletion,
    BlockingTaskHandle, enqueue_task_locked, maybe_spawn_thread_on_inner,
};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

/// Admission limit, independent of FIFO/priority selection and cohort routing.
///
/// Existing constructors and runtime builders use `Unbounded`. A bound limits
/// pending jobs across every pool queue, excluding jobs already claimed by a
/// worker. Waiting submission futures retain ownership of their work outside
/// the pool until admission succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BlockingAdmissionPolicy {
    /// Accept queued work without a capacity limit.
    #[default]
    Unbounded,
    /// Admit at most this many queued jobs across all cohorts and the global queue.
    Bounded {
        /// Maximum queued jobs; running jobs do not count toward this limit.
        max_queued: NonZeroUsize,
    },
}

/// Why a blocking submission was refused before its closure was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockingSpawnErrorKind {
    /// Every configured queue slot is occupied.
    Saturated,
    /// Pool shutdown closed admission.
    Shutdown,
}

/// Refused work, retaining the exact closure for retry or caller-owned disposal.
///
/// No part of the closure has run. Recovery and destruction occur outside pool
/// locks, so captured values may safely reenter the pool from `Drop`.
pub struct BlockingSpawnError<F> {
    kind: BlockingSpawnErrorKind,
    work: F,
}

impl<F> BlockingSpawnError<F> {
    /// Returns the admission failure.
    #[must_use]
    pub fn kind(&self) -> BlockingSpawnErrorKind {
        self.kind
    }

    /// Recovers the original, uninvoked closure.
    #[must_use]
    pub fn into_inner(self) -> F {
        self.work
    }
}

impl<F> fmt::Debug for BlockingSpawnError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingSpawnError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl<F> fmt::Display for BlockingSpawnError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            BlockingSpawnErrorKind::Saturated => f.write_str("blocking queue is saturated"),
            BlockingSpawnErrorKind::Shutdown => f.write_str("blocking pool is shut down"),
        }
    }
}

impl<F> std::error::Error for BlockingSpawnError<F> {}

pub(super) struct BlockingAdmission {
    pub(super) policy: BlockingAdmissionPolicy,
    waiters: Mutex<BTreeMap<usize, Waker>>,
}

impl BlockingAdmission {
    pub(super) fn new(policy: BlockingAdmissionPolicy) -> Self {
        Self {
            policy,
            waiters: Mutex::new(BTreeMap::new()),
        }
    }

    /// Called under the pool coordination mutex for definitive admission.
    pub(super) fn refusal(&self, inner: &BlockingPoolInner) -> Option<BlockingSpawnErrorKind> {
        if inner.shutdown.load(Ordering::Acquire) {
            return Some(BlockingSpawnErrorKind::Shutdown);
        }
        if let BlockingAdmissionPolicy::Bounded { max_queued } = self.policy
            && inner.pending_count.load(Ordering::Acquire) >= max_queued.get()
        {
            return Some(BlockingSpawnErrorKind::Saturated);
        }
        None
    }

    /// Dispatch outside every pool lock. A bad waker must not kill the worker
    /// that has just claimed a job, leak its busy count, or strand other waiters.
    pub(super) fn notify(&self) {
        if self.policy == BlockingAdmissionPolicy::Unbounded {
            return;
        }
        let waiters = std::mem::take(&mut *self.waiters.lock());
        for (_, waker) in waiters {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || waker.wake()))
            {
                // An opaque panic payload can itself panic on destruction.
                // Work and the remaining wakeups must still make progress.
                std::mem::forget(payload);
            }
        }
    }

    fn remove(&self, id: usize) {
        let retired = self.waiters.lock().remove(&id);
        drop(retired);
    }
}

fn try_spawn<F>(
    inner: &Arc<BlockingPoolInner>,
    work: F,
    priority: u8,
    preferred_cohort: Option<usize>,
) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
where
    F: FnOnce() + Send + 'static,
{
    let guard = inner.mutex.lock();
    if let Some(kind) = inner.admission.refusal(inner) {
        drop(guard);
        return Err(BlockingSpawnError { kind, work });
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let completion = Arc::new(BlockingTaskCompletion::new(inner.time_getter));
    let handle = BlockingTaskHandle {
        task_id: inner.next_task_id.fetch_add(1, Ordering::Relaxed),
        cancelled: Arc::clone(&cancelled),
        completion: Arc::clone(&completion),
    };
    enqueue_task_locked(
        inner,
        BlockingTask {
            work: Box::new(work),
            priority,
            preferred_cohort,
            cancelled,
            completion,
        },
    );
    drop(guard);
    maybe_spawn_thread_on_inner(inner);
    {
        let _guard = inner.mutex.lock();
        inner.condvar.notify_one();
    }
    Ok(handle)
}

/// An owned submission that waits asynchronously for queue capacity.
///
/// The closure is never invoked on the polling thread. Saturation parks the
/// future; shutdown returns the original work in `BlockingSpawnError`.
/// Dropping a pending future unregisters its waker and drops its unsubmitted
/// closure on the dropping thread. No slot is reserved while it is waiting.
///
/// Cancellation is by dropping this future. Region-owned drained blocking work
/// additionally keeps a cancelled envelope alive until a worker can retire its
/// captures. Queue selection priority applies after admission; waiting
/// submitters compete for released capacity without a fairness guarantee.
#[must_use = "blocking work is not submitted unless the future is polled"]
pub struct BlockingSubmission<F> {
    pool: BlockingPoolHandle,
    work: Option<F>,
    priority: u8,
    preferred_cohort: Option<usize>,
    // Allocated only if this submission must wait. Its stable, live allocation
    // is a unique key even after arbitrarily many waiter registrations.
    waiter_key: Option<Box<u8>>,
}

// The closure is stored but never structurally pinned or polled.
impl<F> Unpin for BlockingSubmission<F> {}

impl<F> fmt::Debug for BlockingSubmission<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingSubmission")
            .field("pending", &self.work.is_some())
            .field("priority", &self.priority)
            .field("preferred_cohort", &self.preferred_cohort)
            .finish_non_exhaustive()
    }
}

impl<F> BlockingSubmission<F> {
    fn remove_waiter(&self) {
        if let Some(key) = self.waiter_key.as_ref() {
            self.pool
                .inner
                .admission
                .remove(std::ptr::from_ref(key.as_ref()).addr());
        }
    }

    fn new(
        pool: BlockingPoolHandle,
        work: F,
        priority: u8,
        preferred_cohort: Option<usize>,
    ) -> Self {
        Self {
            pool,
            work: Some(work),
            priority,
            preferred_cohort,
            waiter_key: None,
        }
    }
}

impl<F> Future for BlockingSubmission<F>
where
    F: FnOnce() + Send + 'static,
{
    type Output = Result<BlockingTaskHandle, BlockingSpawnError<F>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let work = this
            .work
            .take()
            .expect("blocking submission polled after completion");
        match try_spawn(&this.pool.inner, work, this.priority, this.preferred_cohort) {
            Ok(handle) => {
                this.remove_waiter();
                return Poll::Ready(Ok(handle));
            }
            Err(error) if error.kind == BlockingSpawnErrorKind::Shutdown => {
                this.remove_waiter();
                return Poll::Ready(Err(error));
            }
            Err(error) => this.work = Some(error.into_inner()),
        }

        // Prepare and retire RawWakers outside the waiter mutex: either
        // callback may reenter pool admission.
        let key = this.waiter_key.get_or_insert_with(|| Box::new(0));
        let waiter_id = std::ptr::from_ref(key.as_ref()).addr();
        let incoming = cx.waker().clone();
        let retired = this
            .pool
            .inner
            .admission
            .waiters
            .lock()
            .insert(waiter_id, incoming);
        drop(retired);

        // A worker can free the last slot before registration. Retry after
        // publishing our waker so that either we claim capacity now or a
        // later dequeue/shutdown wakes us. There is no wake-under-lock path.
        let work = this
            .work
            .take()
            .expect("waiting submission retains its closure");
        match try_spawn(&this.pool.inner, work, this.priority, this.preferred_cohort) {
            Ok(handle) => {
                this.remove_waiter();
                Poll::Ready(Ok(handle))
            }
            Err(error) if error.kind == BlockingSpawnErrorKind::Shutdown => {
                this.remove_waiter();
                Poll::Ready(Err(error))
            }
            Err(error) => {
                this.work = Some(error.into_inner());
                Poll::Pending
            }
        }
    }
}

impl<F> Drop for BlockingSubmission<F> {
    fn drop(&mut self) {
        self.remove_waiter();
    }
}

impl BlockingPool {
    /// Returns the admission policy selected when the pool was constructed.
    #[must_use]
    pub fn admission_policy(&self) -> BlockingAdmissionPolicy {
        self.inner.admission.policy
    }

    /// Attempts submission, returning ownership on saturation or shutdown.
    pub fn try_spawn<F>(&self, work: F) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, 128, None)
    }

    /// Attempts submission with an explicit selection priority.
    pub fn try_spawn_with_priority<F>(
        &self,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, None)
    }

    /// Attempts submission with a cohort hint and explicit selection priority.
    pub fn try_spawn_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, Some(cohort))
    }

    /// Waits asynchronously for capacity without running work on the caller.
    pub fn submit<F>(&self, work: F) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, 128, None)
    }

    /// Waits for capacity, then enqueues with the supplied selection priority.
    pub fn submit_with_priority<F>(&self, work: F, priority: u8) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, priority, None)
    }

    /// Waits for capacity, then routes with a cohort hint and selection priority.
    pub fn submit_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, priority, Some(cohort))
    }
}

impl BlockingPoolHandle {
    /// Returns the admission policy selected when the pool was constructed.
    #[must_use]
    pub fn admission_policy(&self) -> BlockingAdmissionPolicy {
        self.inner.admission.policy
    }

    /// Attempts submission, returning ownership on saturation or shutdown.
    pub fn try_spawn<F>(&self, work: F) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, 128, None)
    }

    /// Attempts submission with an explicit selection priority.
    pub fn try_spawn_with_priority<F>(
        &self,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, None)
    }

    /// Attempts submission with a cohort hint and explicit selection priority.
    pub fn try_spawn_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, Some(cohort))
    }

    /// Waits asynchronously for capacity without running work on the caller.
    pub fn submit<F>(&self, work: F) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, 128, None)
    }

    /// Waits for capacity, then enqueues with the supplied selection priority.
    pub fn submit_with_priority<F>(&self, work: F, priority: u8) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, priority, None)
    }

    /// Waits for capacity, then routes with a cohort hint and selection priority.
    pub fn submit_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, priority, Some(cohort))
    }
}

#[cfg(test)]
#[path = "blocking_admission_inline_tests.rs"]
mod tests;
