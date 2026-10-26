//! Stored task type for runtime future storage.
//!
//! `StoredTask` wraps a type-erased future that can be polled by the executor.
//! Each stored task is associated with a `TaskId` and can be polled to completion.

use crate::tracing_compat::trace;
use crate::types::{Outcome, TaskId};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Poll tracing is an observer boundary, not part of task execution. A hostile
/// subscriber must not prevent the stored future's first poll (which may own a
/// deferred spawn-publication receipt) or turn a completed poll into a panic.
#[inline]
fn emit_poll_trace(diagnostic: impl FnOnce()) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(diagnostic)) {
        std::mem::forget(payload);
    }
}

/// A type-erased future stored in the runtime.
///
/// This type holds a boxed future that has been wrapped to send its result
/// through a oneshot channel. The actual output type is erased to allow
/// storing heterogeneous futures in a single collection.
pub struct StoredTask {
    /// The pinned, boxed future to poll.
    future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + Send>>,
    /// The task ID (for tracing).
    task_id: Option<TaskId>,
    /// Poll counter (for tracing).
    poll_count: u64,
    /// Budget polls remaining (set by executor before each poll, for tracing).
    polls_remaining: Option<u32>,
}

impl StoredTask {
    /// Creates a new stored task from a future.
    ///
    /// The future should already be wrapped to handle its result (typically
    /// by sending through a oneshot channel).
    #[inline]
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Outcome<(), ()>> + Send + 'static,
    {
        Self {
            future: Box::pin(future),
            task_id: None,
            poll_count: 0,
            polls_remaining: None,
        }
    }

    /// Creates a new stored task from a future with a task ID.
    ///
    /// The task ID is used for tracing poll events.
    #[inline]
    pub fn new_with_id<F>(future: F, task_id: TaskId) -> Self
    where
        F: Future<Output = Outcome<(), ()>> + Send + 'static,
    {
        Self {
            future: Box::pin(future),
            task_id: Some(task_id),
            poll_count: 0,
            polls_remaining: None,
        }
    }

    /// Sets the task ID for tracing.
    #[inline]
    pub fn set_task_id(&mut self, task_id: TaskId) {
        self.task_id = Some(task_id);
    }

    /// Sets the budget polls remaining for the next poll trace.
    ///
    /// The executor should call this before each `poll()` to include
    /// budget information in the trace output.
    #[inline]
    pub fn set_polls_remaining(&mut self, remaining: u32) {
        self.polls_remaining = Some(remaining);
    }

    /// Polls the stored task.
    ///
    /// Returns `Poll::Ready(Outcome)` when the task is complete, or `Poll::Pending`
    /// if it needs to be polled again.
    #[inline]
    #[allow(clippy::used_underscore_binding)]
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome<(), ()>> {
        self.poll_count += 1;
        let poll_number = self.poll_count;
        let budget_remaining = self.polls_remaining.take().unwrap_or(0);

        if let Some(task_id) = self.task_id {
            emit_poll_trace(|| {
                trace!(
                    task_id = ?task_id,
                    poll_number = poll_number,
                    budget_remaining = budget_remaining,
                    "task poll started"
                );
            });
            let _ = (task_id, poll_number, budget_remaining);
        }

        let result = self.future.as_mut().poll(cx);

        if let Some(task_id) = self.task_id {
            let poll_result = match &result {
                Poll::Ready(_) => "Ready",
                Poll::Pending => "Pending",
            };
            emit_poll_trace(|| {
                trace!(
                    task_id = ?task_id,
                    poll_number = poll_number,
                    poll_result = poll_result,
                    "task poll completed"
                );
            });
            let _ = (task_id, poll_number, poll_result);
        }

        result
    }

    /// Returns the number of times this task has been polled.
    #[inline]
    #[must_use]
    pub fn poll_count(&self) -> u64 {
        self.poll_count
    }
}

impl std::fmt::Debug for StoredTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredTask").finish_non_exhaustive()
    }
}

/// A local (non-Send) type-erased future stored in the runtime.
///
/// This is identical to `StoredTask` but allows `!Send` futures, pinned to
/// a specific worker thread.
pub struct LocalStoredTask {
    /// The pinned, boxed future to poll.
    future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + 'static>>,
    /// The task ID (for tracing).
    task_id: Option<TaskId>,
    /// Poll counter (for tracing).
    poll_count: u64,
    /// Budget polls remaining (set by executor before each poll, for tracing).
    polls_remaining: Option<u32>,
    /// Weak ownership route used only when the owner's local store retires.
    /// A parked local future must not keep its runtime alive through this
    /// backstop, and ordinary scheduler completion does not publish it.
    retirement_gateway: Option<std::sync::Weak<crate::runtime::spawn_mailbox::SpawnGateway>>,
}

impl LocalStoredTask {
    /// Creates a new local stored task from a future.
    #[inline]
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Outcome<(), ()>> + 'static,
    {
        Self {
            future: Box::pin(future),
            task_id: None,
            poll_count: 0,
            polls_remaining: None,
            retirement_gateway: None,
        }
    }

    /// Creates a new local stored task with a task ID.
    #[inline]
    pub fn new_with_id<F>(future: F, task_id: TaskId) -> Self
    where
        F: Future<Output = Outcome<(), ()>> + 'static,
    {
        Self {
            future: Box::pin(future),
            task_id: Some(task_id),
            poll_count: 0,
            polls_remaining: None,
            retirement_gateway: None,
        }
    }

    pub(crate) fn with_retirement_gateway(
        mut self,
        gateway: Option<&std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    ) -> Self {
        self.retirement_gateway = gateway.map(std::sync::Arc::downgrade);
        self
    }

    pub(crate) fn take_retirement_gateway(
        &mut self,
    ) -> Option<std::sync::Weak<crate::runtime::spawn_mailbox::SpawnGateway>> {
        self.retirement_gateway.take()
    }

    /// Sets the task ID for tracing.
    #[inline]
    pub fn set_task_id(&mut self, task_id: TaskId) {
        self.task_id = Some(task_id);
    }

    /// Returns the task ID associated with this task.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> Option<TaskId> {
        self.task_id
    }

    /// Sets the budget polls remaining.
    #[inline]
    pub fn set_polls_remaining(&mut self, remaining: u32) {
        self.polls_remaining = Some(remaining);
    }

    /// Polls the stored task.
    #[inline]
    #[allow(clippy::used_underscore_binding)]
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome<(), ()>> {
        self.poll_count += 1;
        let poll_number = self.poll_count;
        let budget_remaining = self.polls_remaining.take().unwrap_or(0);

        if let Some(task_id) = self.task_id {
            emit_poll_trace(|| {
                trace!(
                    task_id = ?task_id,
                    poll_number = poll_number,
                    budget_remaining = budget_remaining,
                    "local task poll started"
                );
            });
            let _ = (task_id, poll_number, budget_remaining);
        }

        let result = self.future.as_mut().poll(cx);

        if let Some(task_id) = self.task_id {
            let poll_result = match &result {
                Poll::Ready(_) => "Ready",
                Poll::Pending => "Pending",
            };
            emit_poll_trace(|| {
                trace!(
                    task_id = ?task_id,
                    poll_number = poll_number,
                    poll_result = poll_result,
                    "local task poll completed"
                );
            });
            let _ = (task_id, poll_number, poll_result);
        }

        result
    }

    /// Returns the number of times this local task has been polled.
    #[inline]
    #[must_use]
    pub fn poll_count(&self) -> u64 {
        self.poll_count
    }
}

impl std::fmt::Debug for LocalStoredTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStoredTask").finish_non_exhaustive()
    }
}

/// Enum wrapping either a global or local stored task.
#[derive(Debug)]
pub enum AnyStoredTask {
    /// A `Send` task stored in the global state.
    Global(StoredTask),
    /// A `!Send` task stored in thread-local storage.
    Local(LocalStoredTask),
}

impl AnyStoredTask {
    /// Polls the inner task.
    #[inline]
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome<(), ()>> {
        match self {
            Self::Global(t) => t.poll(cx),
            Self::Local(t) => t.poll(cx),
        }
    }

    /// Returns the number of times the inner task has been polled.
    #[inline]
    #[must_use]
    pub fn poll_count(&self) -> u64 {
        match self {
            Self::Global(t) => t.poll_count(),
            Self::Local(t) => t.poll_count(),
        }
    }

    /// Returns `true` when this is a `!Send` local task.
    #[inline]
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// Sets budget info on the inner task.
    #[inline]
    pub fn set_polls_remaining(&mut self, remaining: u32) {
        match self {
            Self::Global(t) => t.set_polls_remaining(remaining),
            Self::Local(t) => t.set_polls_remaining(remaining),
        }
    }
}

#[cfg(test)]
#[path = "stored_task_inline_tests.rs"]
mod tests;
