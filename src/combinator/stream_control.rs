//! External-stop observation for region-owned stream execution.
//!
//! A stop signal must initiate cancellation and drain, not simply win a race
//! that drops the work future. The caller's context is never cancelled here.

use super::stream_collect::ScopedStreamError;
use crate::cx::{ChildRegionSpec, Cx};
use crate::stream::Stream;
use crate::types::{CancelReason, Outcome, PanicPayload};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

/// Runs scoped stream work until completion or an explicit external stop.
///
/// `stop` returns the error that should explain termination, for example after
/// a destination closes or a caller-owned deadline expires. It is observed
/// while the source is idle AND while all item slots are busy. Once observed,
/// new source polls cease, the entire work subtree is cancelled, and direct
/// tasks, descendants, and finalizers are drained before returning the error.
/// This does not cancel `cx` or unrelated tasks in its region.
///
/// The ordinary scoped driver's admission, concurrency limit, source/clone
/// panic containment, and joins remain authoritative. A ready stop is checked
/// before region creation and again after mint acknowledgement, so no source
/// or mapper is invoked for those refusals. During work, a ready direct result
/// wins a same-poll tie; otherwise the stop error initiates drain. Item completion
/// does not end observation while the source is still open. A stop selected
/// during work is not replaced by cancellations caused by its own drain. A work
/// error already selected by the driver survives a stop during its drain;
/// descendant/finalizer panics and cleanup failures also retain precedence.
///
/// The stop future may borrow and need not be `Send` or `Unpin`. It is dropped
/// before final region close begins, so an unused observer cannot retain a
/// notification or timer subscription throughout cleanup. Stop-poll unwinds
/// also initiate drain and return `Panicked`; the stop is never polled again.
/// A signal arriving only after direct work completes does not change that
/// result. Owner cancellation is still observed by the driver and after close.
///
/// Dropping this outer future requests region closure but cannot await it.
/// Uncooperative tasks, panicking destructors, abort-on-panic builds, and effects
/// using an outer context retain the ordinary scoped execution limitations.
/// This bounds direct task count, not arbitrary descendants or source memory.
///
/// # Panics
/// Panics if `limit` is zero, before polling either source or stop.
pub async fn try_for_each_concurrent_scoped_until<S, F, Fut, E, Stop>(
    cx: &Cx,
    stream: S,
    limit: usize,
    stop: Stop,
    f: F,
) -> Outcome<(), ScopedStreamError<E>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Send + 'static,
    Stop: Future<Output = E>,
{
    assert!(limit > 0, "scoped stream concurrency limit must be non-zero");
    if cx.is_cancel_requested() {
        return Outcome::Cancelled(owner_reason(cx));
    }
    let (region, work) = {
        let mut stop = pin!(stop);
        if let Some(stopped) = poll_fn(|task| Poll::Ready(match poll_stop(stop.as_mut(), task) {
            Poll::Ready(outcome) => Some(outcome),
            Poll::Pending => None,
        })).await {
            return scope_error(stopped);
        }
        // Do not abandon a mint that may have succeeded. Once it is observed,
        // the owned region can always take its explicit close path.
        let region = match cx.open_child_region(ChildRegionSpec::inherit()).await {
            Ok(region) => region,
            Err(error) => return Outcome::Err(ScopedStreamError::Region(error)),
        };
        let stopped = poll_fn(|task| Poll::Ready(match poll_stop(stop.as_mut(), task) {
            Poll::Ready(outcome) => Some(outcome),
            Poll::Pending => None,
        })).await;
        let outcome = if let Some(stopped) = stopped {
            stopped
        } else {
            let fence = Arc::new(AtomicBool::new(false));
            let source = StopSource { inner: stream, stopped: Arc::clone(&fence) };
            let mut work = pin!(region.for_each_stream(cx, source, limit, f));
            let selected = poll_fn(|task| {
                if let Poll::Ready(outcome) = work.as_mut().poll(task) {
                    return Poll::Ready(Ok(outcome));
                }
                poll_stop(stop.as_mut(), task).map(Err)
            }).await;
            match selected {
                Ok(outcome) => outcome,
                Err(stopped) => {
                    // Fence source admission BEFORE invoking any cancellation
                    // callback. The driver can observe EOF even with no members
                    // and a source that would otherwise never wake again.
                    fence.store(true, Ordering::Release);
                    // Descendant cleanup may unblock a direct member's join.
                    // Runtime loss is reported by close, not by skipping joins.
                    let _ = region.cancel(CancelReason::fail_fast());
                    match work.await {
                        failure @ (Outcome::Err(_) | Outcome::Panicked(_)) => failure,
                        _ => stopped,
                    }
                }
            }
        };
        (region, outcome)
        // Both the stop observer and the borrowed work future retire here.
    };
    let close = match region.close_with_outcome().await {
        Ok(close) => close,
        Err(error) => return Outcome::Err(ScopedStreamError::Region(error)),
    };
    // Same scoped severity rules: intentional descendant cancellation during
    // close does not fabricate a failure, but failed cleanup cannot be success.
    let outcome = match (work, close.outcome, close.cleanup_outcome) {
        (_, _, Some(Outcome::Panicked(payload)))
        | (_, Outcome::Panicked(payload), _)
        | (Outcome::Panicked(payload), _, _) => Outcome::Panicked(payload),
        (_, _, Some(Outcome::Cancelled(reason))) => Outcome::Cancelled(reason),
        (_, _, Some(Outcome::Err(error))) => Outcome::Err(ScopedStreamError::Cleanup(error)),
        (Outcome::Ok(()), Outcome::Err(error), _) => Outcome::Err(ScopedStreamError::Cleanup(error)),
        (work, _, _) => scope_error(work),
    };
    if outcome.is_ok() && cx.is_cancel_requested() {
        Outcome::Cancelled(owner_reason(cx))
    } else {
        outcome
    }
}

fn owner_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason().unwrap_or_else(|| CancelReason::user("scoped stream owner cancelled"))
}

fn scope_error<E>(work: Outcome<(), E>) -> Outcome<(), ScopedStreamError<E>> {
    match work {
        Outcome::Ok(()) => Outcome::Ok(()),
        Outcome::Err(error) => Outcome::Err(ScopedStreamError::Item(error)),
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => Outcome::Panicked(payload),
    }
}

fn poll_stop<E>(mut stop: Pin<&mut impl Future<Output = E>>, task: &mut Context<'_>) -> Poll<Outcome<(), E>> {
    match catch_unwind(AssertUnwindSafe(|| stop.as_mut().poll(task))) {
        Ok(poll) => poll.map(Outcome::Err),
        Err(payload) => {
            let message = if let Some(message) = payload.downcast_ref::<String>() {
                message.clone()
            } else if let Some(message) = payload.downcast_ref::<&str>() {
                (*message).to_owned()
            } else {
                "stream stop observer panicked with a non-string payload".to_owned()
            };
            if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
                std::mem::forget(secondary);
            }
            Poll::Ready(Outcome::Panicked(PanicPayload::new(message)))
        }
    }
}

struct StopSource<S> {
    inner: S,
    stopped: Arc<AtomicBool>,
}

impl<S: Stream + Unpin> Stream for StopSource<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.stopped.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            Pin::new(&mut this.inner).poll_next(task)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.stopped.load(Ordering::Acquire) { (0, Some(0)) } else { self.inner.size_hint() }
    }
}

#[cfg(test)]
mod tests;
