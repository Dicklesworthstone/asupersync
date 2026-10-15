//! Polling and admission for the retry state machine.

use super::*;

// Re-read at admission boundaries: both the attempt and the retry predicate
// are user code and can publish cancellation during their invocation. Use a
// checkpoint rather than the raw flag so bounded cancellation masks still work.
fn retry_cancel_reason() -> Option<CancelReason> {
    Cx::current().and_then(|current| {
        current
            .checkpoint()
            .is_err()
            .then(|| current.cancel_reason().unwrap_or_default())
    })
}

/// # Scheduling and cancellation
///
/// At most 64 immediately-ready attempts are processed per poll. When another
/// retry is admitted after that batch, the future wakes its caller and yields
/// before starting the next attempt. Terminal outcomes do not add a yield.
/// This is a cooperative bound: user callbacks, polls, and destructors must
/// themselves return.
///
/// After a failed attempt drains, unmasked cancellation takes precedence over
/// its error. Cancellation is checked before and after the retry predicate,
/// before consuming a shared retry-budget token. An in-flight attempt is never
/// force-dropped, and a successful or panicked outcome is still returned as-is.
impl<F, Fut, P, Pred, T, E> Future for Retry<F, Fut, P, Pred>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Outcome<T, E>>,
    P: Clone + Into<RetryPolicy>,
    Pred: RetryPredicate<E>,
{
    type Output = RetryResult<T, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut ready_attempts = 0;
        loop {
            // Check cancellation from the context
            // WARNING: We must NOT force-drop the inner future if we are in Polling state,
            // because asupersync requires futures to be drained to Outcome::Cancelled.
            let cancel_reason = retry_cancel_reason();

            let mut this = self.as_mut().project();

            match this.inner.as_mut().project() {
                RetryInnerProj::Completed => {
                    return Poll::Ready(RetryResult::Cancelled(CancelReason::user(
                        "polled after completion",
                    )));
                }
                RetryInnerProj::Idle => {
                    if let Some(r) = cancel_reason {
                        this.inner.set(RetryInner::Completed);
                        return Poll::Ready(RetryResult::Cancelled(r));
                    }

                    // Start next attempt or sleep
                    // Use Cx entropy if available
                    let mut rng = Cx::current().map(|c| DetRng::new(c.random_u64()));

                    if let Some(delay) = this.state.next_attempt(rng.as_mut()) {
                        if delay == Duration::ZERO {
                            // Start immediately
                            let fut = (this.factory)();
                            this.inner.set(RetryInner::Polling(fut));
                        } else {
                            // Sleep before starting
                            // Cx::current() will be used by Sleep internally
                            // We need to construct Sleep with a relative duration from "now"
                            // Sleep::after handles getting the time source correctly
                            let sleep = Sleep::after(retry_clock_now(), delay);
                            this.inner.set(RetryInner::Sleeping(sleep));
                        }
                    } else {
                        // This case is unreachable because we only transition to Idle
                        // if has_attempts_remaining() is true, or initially (attempt=0)
                        // where max_attempts >= 1.
                        unreachable!(
                            "Retry logic invariant violated: Idle state with no remaining attempts"
                        );
                    }
                }
                RetryInnerProj::Sleeping(sleep) => {
                    if let Some(r) = cancel_reason {
                        this.inner.set(RetryInner::Completed);
                        return Poll::Ready(RetryResult::Cancelled(r));
                    }
                    match sleep.poll(cx) {
                        Poll::Ready(()) => {
                            // A Sleep also completes early when its task is
                            // cancelled; that must not start another attempt.
                            if let Some(r) = retry_cancel_reason() {
                                this.inner.set(RetryInner::Completed);
                                return Poll::Ready(RetryResult::Cancelled(r));
                            }
                            // Sleep done, start factory
                            let fut = (this.factory)();
                            this.inner.set(RetryInner::Polling(fut));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RetryInnerProj::Polling(fut) => {
                    match fut.poll(cx) {
                        Poll::Ready(outcome) => {
                            match outcome {
                                Outcome::Ok(val) => {
                                    this.inner.set(RetryInner::Completed);
                                    return Poll::Ready(RetryResult::Ok(val));
                                }
                                Outcome::Err(e) => {
                                    // The attempt has drained to a terminal
                                    // error. Cancellation now stops admission;
                                    // it must not invoke a retry callback or
                                    // consume a shared dependency's token.
                                    if let Some(reason) =
                                        retry_cancel_reason().or(cancel_reason)
                                    {
                                        this.inner.set(RetryInner::Completed);
                                        return Poll::Ready(RetryResult::Cancelled(reason));
                                    }
                                    let attempt = this.state.attempt;
                                    let should_retry = this.predicate.should_retry(&e, attempt)
                                        && this.state.has_attempts_remaining();
                                    // A predicate can itself request cancel,
                                    // including when it declines the retry.
                                    if let Some(reason) = retry_cancel_reason() {
                                        this.inner.set(RetryInner::Completed);
                                        return Poll::Ready(RetryResult::Cancelled(reason));
                                    }
                                    if should_retry
                                        && this.budget.as_ref().is_none_or(|budget| {
                                            budget.try_acquire(retry_clock_now())
                                        })
                                    {
                                        // Retry
                                        this.inner.set(RetryInner::Idle);
                                        ready_attempts += 1;
                                        if ready_attempts == MAX_READY_ATTEMPTS_PER_POLL {
                                            // The previous attempt is terminal and
                                            // has been dropped; no new attempt or
                                            // sleep has been created yet. Publish
                                            // Idle before invoking the executor's
                                            // waker and never drop a pending child
                                            // just to obtain a scheduling boundary.
                                            cx.waker().wake_by_ref();
                                            return Poll::Pending;
                                        }
                                        // Loop will handle Idle -> Sleeping/Polling
                                    } else {
                                        // Final failure
                                        this.inner.set(RetryInner::Completed);
                                        return Poll::Ready(RetryResult::Failed(
                                            this.state.clone().into_error(e),
                                        ));
                                    }
                                }
                                Outcome::Cancelled(r) => {
                                    this.inner.set(RetryInner::Completed);
                                    return Poll::Ready(RetryResult::Cancelled(r));
                                }
                                Outcome::Panicked(p) => {
                                    this.inner.set(RetryInner::Completed);
                                    return Poll::Ready(RetryResult::Panicked(p));
                                }
                            }
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}
