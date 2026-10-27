//! Bounded admission for native unary exchanges.
//!
//! The total semaphore is nonwaiting; the active semaphore owns the FIFO
//! queue. A drop-owned cancellation observer wakes a parked caller even when
//! cancellation is requested directly on its context. Both semaphores use
//! checked obligation admission, so refusal rolls back physical capacity.

use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};

use crate::cx::Cx;
use crate::runtime::obligation_mailbox::ObligationAdmissionError;
use crate::sync::semaphore::{AcquireError, CheckedAcquireError, Semaphore, SemaphorePermit};

use super::super::native_stream::check_cancellation;
use super::super::status::Status;

/// Finite active and waiting budgets for a channel's native unary exchanges.
///
/// Clones of the channel share both budgets. Streaming and deterministic
/// loopback calls do not use them. Interceptors and message encoding run
/// before admission, so these limits bound exchanges and admitted waiters,
/// rather than all memory allocated by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnaryAdmissionLimits {
    max_active: NonZeroUsize,
    max_queued: usize,
}

impl UnaryAdmissionLimits {
    /// Create limits with at least one active exchange and a finite queue.
    ///
    /// A zero queue rejects excess concurrency immediately with
    /// `RESOURCE_EXHAUSTED`. Returns `INVALID_ARGUMENT` if the sum of the
    /// active and queued limits cannot be represented by `usize`.
    pub fn new(max_active: NonZeroUsize, max_queued: usize) -> Result<Self, Status> {
        max_active.get().checked_add(max_queued).ok_or_else(|| {
            Status::invalid_argument("native gRPC unary admission capacity overflows usize")
        })?;
        Ok(Self {
            max_active,
            max_queued,
        })
    }

    /// Maximum native unary exchanges holding transport ownership.
    #[must_use]
    pub const fn max_active(self) -> usize {
        self.max_active.get()
    }

    /// Maximum calls waiting for an active exchange slot.
    #[must_use]
    pub const fn max_queued(self) -> usize {
        self.max_queued
    }
}

#[derive(Debug)]
pub(super) struct UnaryAdmission {
    limits: UnaryAdmissionLimits,
    total: Semaphore,
    active: Semaphore,
}

impl UnaryAdmission {
    pub(super) fn new(limits: UnaryAdmissionLimits) -> Self {
        Self {
            limits,
            total: Semaphore::new(limits.max_active() + limits.max_queued()),
            active: Semaphore::new(limits.max_active()),
        }
    }

    pub(super) fn limits(&self) -> UnaryAdmissionLimits {
        self.limits
    }

    pub(super) async fn acquire<'a>(&'a self, cx: &Cx) -> Result<UnaryPermit<'a>, Status> {
        // This never waits: calls beyond active + queued consume no waiter,
        // connection, DNS work, or TLS handshake.
        let total = self
            .total
            .try_acquire_checked(cx, 1)
            .map_err(|error| admission_status(cx, error))?;
        let mut acquiring = pin!(self.active.acquire_checked(cx, 1));
        let mut cancelled = pin!(cx.cancelled());
        let active = poll_fn(|task| match acquiring.as_mut().poll(task) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                // Registration and recheck close cancellation during the
                // first Pending poll. Dropping the wait unregisters it.
                if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                    Poll::Ready(Err(CheckedAcquireError::Semaphore(AcquireError::Cancelled)))
                } else {
                    Poll::Pending
                }
            }
        })
        .await
        .map_err(|error| admission_status(cx, error))?;
        // Cancellation can race capacity delivery. Do not start a transport
        // for a caller that was cancelled while its waiter was being granted.
        check_cancellation(cx)?;
        Ok(UnaryPermit {
            _active: active,
            _total: total,
        })
    }
}

fn admission_status(cx: &Cx, error: CheckedAcquireError) -> Status {
    match error {
        CheckedAcquireError::Semaphore(AcquireError::Cancelled) => {
            check_cancellation(cx).err().unwrap_or_else(|| {
                Status::cancelled("native gRPC unary admission cancelled by the caller")
            })
        }
        CheckedAcquireError::Unavailable(_) => {
            Status::resource_exhausted("native gRPC unary admission queue is full")
        }
        CheckedAcquireError::Admission(
            error @ (ObligationAdmissionError::LimitReached { .. }
            | ObligationAdmissionError::CapacityExhausted),
        ) => Status::resource_exhausted(format!("native gRPC unary admission refused: {error}")),
        CheckedAcquireError::Admission(error) => {
            Status::failed_precondition(format!("native gRPC unary admission refused: {error}"))
        }
        CheckedAcquireError::Semaphore(error) => {
            Status::internal(format!("native gRPC unary admission failed: {error}"))
        }
    }
}

/// Active capacity is returned before total capacity, so a newly arriving
/// caller cannot occupy a queue slot still owned by a retiring exchange.
pub(super) struct UnaryPermit<'a> {
    _active: SemaphorePermit<'a>,
    _total: SemaphorePermit<'a>,
}

/// Field order is intentional: dropping or timing out a call destroys its
/// entire I/O future (and owned connection) before waking the next caller.
/// The same permit spans every existing pooled-connection attempt.
pub(super) struct AdmittedUnary<'a, F> {
    io: Pin<Box<F>>,
    _permit: UnaryPermit<'a>,
}

impl<'a, F> AdmittedUnary<'a, F> {
    pub(super) fn new(io: F, permit: UnaryPermit<'a>) -> Self {
        Self {
            io: Box::pin(io),
            _permit: permit,
        }
    }
}

impl<F: Future> Future for AdmittedUnary<'_, F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().io.as_mut().poll(cx)
    }
}

#[cfg(test)]
#[path = "unary_admission_tests.rs"]
mod tests;
