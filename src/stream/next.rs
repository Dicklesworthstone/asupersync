//! Next combinator for streams.
//!
//! The `Next` future returns the next item from a stream.

use super::Stream;
use crate::cx::{CancelWakerToken, Cx};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// A future that returns the next item from a stream.
///
/// Created by [`StreamExt::next`](super::StreamExt::next).
///
/// This convenience future requires the underlying stream to be
/// [`Unpin`](std::marker::Unpin).
/// Dropping it before completion releases its mutable borrow and leaves the
/// stream available for another poll, but does not undo state changes made by
/// the underlying [`Stream::poll_next`] call. A completed `Next` is fused: an
/// accidental later poll returns `None` without polling the stream again.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Next<'a, S: ?Sized> {
    stream: &'a mut S,
    done: bool,
}

impl<'a, S: ?Sized> Next<'a, S> {
    /// Creates a new `Next` future.
    #[inline]
    pub(crate) fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            done: false,
        }
    }

    /// Waits for the next item with cooperative cancellation and owned wakeups.
    ///
    /// Unlike plain [`Next`], this wakes when `cx` is cancelled even if the
    /// source produces no event. Checkpoints honor cancellation masks. A request
    /// observed before polling the source returns an error without consuming an
    /// item. If the source returns an item while concurrently requesting
    /// cancellation, the item wins: it is returned rather than discarded.
    ///
    /// Dropping the returned future removes only its cancellation registration
    /// and releases the source borrow. It cannot undo internal source effects
    /// from an earlier `poll_next`, or remove a waker retained by that source.
    /// No `Send`, `Sync`, `Clone`, or `'static` bound is added.
    ///
    /// ```no_run
    /// # async fn example(cx: &asupersync::Cx) -> Result<(), asupersync::Error> {
    /// use asupersync::stream::{iter, StreamExt};
    /// let mut source = iter([1, 2, 3]);
    /// assert_eq!(source.next().with_cx(cx).await?, Some(1));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_cx<Caps>(mut self, cx: &Cx<Caps>) -> Result<Option<S::Item>, crate::Error>
    where
        S: Stream + Unpin,
    {
        let mut cancellation = NextCancellation {
            cx,
            registration: None,
        };
        poll_fn(|task| {
            if self.done {
                cancellation.clear();
                return Poll::Ready(Ok(None));
            }
            if let Err(error) = cx.checkpoint() {
                self.done = true;
                cancellation.clear();
                return Poll::Ready(Err(error));
            }
            match Pin::new(&mut self).poll(task) {
                Poll::Ready(item) => {
                    cancellation.clear();
                    Poll::Ready(Ok(item))
                }
                Poll::Pending => {
                    cancellation.refresh(task.waker());
                    // Registration and waker retirement can publish cancellation.
                    // Never park after missing that check/register race.
                    if cx.is_cancel_requested() {
                        if let Err(error) = cx.checkpoint() {
                            self.done = true;
                            cancellation.clear();
                            return Poll::Ready(Err(error));
                        }
                    }
                    Poll::Pending
                }
            }
        })
        .await
    }
}

// Keep an executor-Waker owner outside the Cx registry, as Cx::cancelled()
// does. Refresh and cleanup may run arbitrary Waker callbacks, never under a
// registry lock, and must not replace another observer's registration.
struct NextRegistration {
    waker: Waker,
    token: CancelWakerToken,
}

struct NextCancellation<'a, Caps> {
    cx: &'a Cx<Caps>,
    registration: Option<NextRegistration>,
}

impl<Caps> NextCancellation<'_, Caps> {
    fn refresh(&mut self, waker: &Waker) {
        let unchanged = self
            .registration
            .as_ref()
            .is_some_and(|entry| entry.waker.will_wake(waker));
        let incoming = if unchanged { None } else { Some(waker.clone()) };
        let previous = self.registration.as_ref().map(|entry| entry.token);
        let token = self.cx.refresh_cancel_waker(previous, waker);
        let retired = if let Some(waker) = incoming {
            self.registration.replace(NextRegistration { waker, token })
        } else {
            self.registration
                .as_mut()
                .expect("unchanged waker has an owned cancellation registration")
                .token = token;
            None
        };
        drop(retired);
    }

    fn clear(&mut self) {
        if let Some(registered) = self.registration.take() {
            self.cx.clear_cancel_waker(registered.token);
            drop(registered);
        }
    }
}

impl<Caps> Drop for NextCancellation<'_, Caps> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<S: ?Sized + Unpin> Unpin for Next<'_, S> {}

impl<S> Future for Next<'_, S>
where
    S: Stream + Unpin + ?Sized,
{
    type Output = Option<S::Item>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        let poll = Pin::new(&mut *self.stream).poll_next(cx);
        if poll.is_ready() {
            self.done = true;
        }
        poll
    }
}

#[cfg(test)]
#[path = "next_cancel_tests.rs"]
mod cancellation_tests;

#[cfg(test)]
#[path = "next_inline_tests.rs"]
mod tests;
