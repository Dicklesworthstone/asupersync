//! Fallible sleep operations driven by an explicitly supplied context.

use super::{Sleep, TimerDriverHandle};
use crate::cx::{Cx, cap::HasTime};
use crate::types::{CancelReason, Time};
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

/// A context-driven sleep could not complete.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SleepError {
    /// The context acknowledged cancellation before the sleep completed.
    Cancelled(CancelReason),
    /// The supplied context has no authorized timer driver.
    TimerUnavailable,
}

impl std::fmt::Display for SleepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled(reason) => write!(f, "sleep cancelled: {reason:?}"),
            Self::TimerUnavailable => {
                f.write_str("sleep requires time capability and a timer driver")
            }
        }
    }
}

impl std::error::Error for SleepError {}

impl SleepError {
    fn cancelled<Caps>(cx: &Cx<Caps>) -> Self {
        Self::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("sleep cancelled")),
        )
    }
}

/// Wait for a duration using the supplied context's authorized timer.
///
/// The duration starts when this future is first polled. Its deadline saturates
/// at [`Time::MAX`]. The context's timer determines the clock domain, including
/// virtual time in a lab runtime; an ambient context cannot redirect this wait.
///
/// Cancellation, including timeout and deadline cancellation, returns
/// [`SleepError::Cancelled`] with the context's reason. Propagating that error
/// with `?` lets an operation stop before performing subsequent effects.
/// Cancellation masks follow [`Cx::checkpoint`]: a masked request remains
/// deferred, and a sleep may finish normally while cancellation is masked.
/// An unmasked request observed on the same poll as expiry takes precedence.
///
/// Dropping or completing the future removes its timer and its owned
/// cancellation-waker registration without affecting other waits on the task.
///
/// # Errors
///
/// Returns [`SleepError::Cancelled`] when cancellation is acknowledged, or
/// [`SleepError::TimerUnavailable`] if the context cannot provide an authorized
/// timer. Even a zero duration requires that authority. Cancellation is checked
/// before timer availability.
///
/// # Example
///
/// ```
/// use asupersync::Cx;
/// use asupersync::time::{SleepError, sleep_cx};
/// use std::time::Duration;
///
/// async fn delayed_value(cx: &Cx) -> Result<u32, SleepError> {
///     sleep_cx(cx, Duration::from_millis(100)).await?;
///     Ok(42)
/// }
/// ```
///
/// A context without the time capability cannot start the wait:
///
/// ```compile_fail
/// use asupersync::{Cx, cx::cap};
/// use asupersync::time::sleep_cx;
/// use std::time::Duration;
///
/// async fn no_time(cx: &Cx<cap::None>) {
///     sleep_cx(cx, Duration::ZERO).await.unwrap();
/// }
/// ```
pub async fn sleep_cx<Caps>(cx: &Cx<Caps>, duration: Duration) -> Result<(), SleepError>
where
    Caps: HasTime,
{
    cx.checkpoint().map_err(|_| SleepError::cancelled(cx))?;
    let driver = cx.timer_driver().ok_or(SleepError::TimerUnavailable)?;
    let deadline = driver.now() + duration;
    wait_until(cx, driver, deadline).await
}

/// Wait until an absolute deadline using the supplied context's authorized timer.
///
/// `deadline` must be in that timer's clock domain. This has the same
/// cancellation, masking, authority, and cleanup guarantees as [`sleep_cx`].
/// An elapsed deadline completes immediately after those checks; it still
/// requires an authorized timer, and pending unmasked cancellation wins.
///
/// # Errors
///
/// Returns [`SleepError::Cancelled`] when cancellation is acknowledged, or
/// [`SleepError::TimerUnavailable`] if the context cannot provide an authorized
/// timer.
pub async fn sleep_until_cx<Caps>(cx: &Cx<Caps>, deadline: Time) -> Result<(), SleepError>
where
    Caps: HasTime,
{
    cx.checkpoint().map_err(|_| SleepError::cancelled(cx))?;
    let driver = cx.timer_driver().ok_or(SleepError::TimerUnavailable)?;
    wait_until(cx, driver, deadline).await
}

async fn wait_until<Caps>(
    cx: &Cx<Caps>,
    driver: TimerDriverHandle,
    deadline: Time,
) -> Result<(), SleepError>
where
    Caps: HasTime,
{
    let mut cancelled = std::pin::pin!(cx.cancelled());
    loop {
        let now = driver.now();
        // Check after the clock snapshot so crossing an owner deadline cannot
        // turn a cancellation into successful expiry.
        cx.checkpoint().map_err(|_| SleepError::cancelled(cx))?;
        if now >= deadline {
            return Ok(());
        }

        // A future owner deadline is also a progress source. Once it has
        // elapsed under a cancellation mask, park on the sleep's own deadline
        // instead of repeatedly polling an already-ready timer.
        let wake_at = cx
            .budget()
            .deadline
            .filter(|owner_deadline| *owner_deadline > now)
            .map_or(deadline, |owner_deadline| deadline.min(owner_deadline));
        let mut timer = std::pin::pin!(Sleep::with_timer_driver(wake_at, driver.clone()));
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                return Poll::Ready(());
            }
            if timer.as_mut().poll_deadline(task).is_ready() {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "sleep_cx_inline_tests.rs"]
mod tests;
