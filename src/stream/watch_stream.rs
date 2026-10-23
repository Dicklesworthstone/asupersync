//! Stream adapter for watch receivers.

use crate::channel::{OwnedCancelRegistration, watch};
use crate::cx::Cx;
use crate::stream::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream that yields when watch value changes.
///
/// The stream ends (`None`) when the sender is dropped and also when the
/// stream's `Cx` is cancelled, including before the initial value is yielded.
/// A consumer that must tell the two apart checks `cx.is_cancel_requested()`
/// after the stream ends.
#[derive(Debug)]
pub struct WatchStream<T> {
    inner: watch::Receiver<T>,
    cx: OwnedCancelRegistration,
    has_seen_initial: bool,
    terminated: bool,
}

impl<T: Clone> WatchStream<T> {
    /// Create from watch receiver.
    #[inline]
    #[must_use]
    pub fn new(cx: Cx, recv: watch::Receiver<T>) -> Self {
        Self {
            inner: recv,
            cx: OwnedCancelRegistration::new(cx),
            has_seen_initial: false,
            terminated: false,
        }
    }

    /// Create, skipping the initial value.
    #[inline]
    #[must_use]
    pub fn from_changes(cx: Cx, recv: watch::Receiver<T>) -> Self {
        let mut stream = Self::new(cx, recv);
        // Skip whatever value/version is current at construction time.
        stream.inner.mark_seen();
        stream.has_seen_initial = true;
        stream
    }

    /// Returns a reference to the underlying watch receiver.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &watch::Receiver<T> {
        &self.inner
    }

    /// Returns a mutable reference to the underlying watch receiver.
    #[inline]
    pub fn get_mut(&mut self) -> &mut watch::Receiver<T> {
        self.inner.clear_waiter_registration(false);
        self.cx.clear();
        &mut self.inner
    }

    /// Consumes the stream, returning the underlying watch receiver.
    #[inline]
    #[must_use]
    pub fn into_inner(mut self) -> watch::Receiver<T> {
        self.inner.clear_waiter_registration(false);
        self.cx.clear();
        self.inner
    }
}

impl<T: Clone> Stream for WatchStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminated {
            return Poll::Ready(None);
        }

        // Keep the initial snapshot path consistent with the change-wait path:
        // a pre-requested cancellation terminates the stream instead of yielding
        // one last snapshot.
        if !this.has_seen_initial {
            if this.cx.cx().checkpoint().is_err() {
                this.terminated = true;
                this.inner.clear_waiter_registration(false);
                this.cx.clear();
                return Poll::Ready(None);
            }
            this.has_seen_initial = true;
            this.inner.clear_waiter_registration(false);
            this.cx.clear();
            // The initial snapshot counts as observed by this stream.
            return Poll::Ready(Some(
                this.inner.borrow_and_update_clone_with_cx(this.cx.cx()),
            ));
        }

        let mut result = this.inner.poll_changed(this.cx.cx(), context);
        if result.is_pending() {
            this.cx.refresh(context.waker());
            // A registration callback can request cancellation. Re-enter the
            // channel's checkpoint path before returning Pending in that case.
            if this.cx.cx().is_cancel_requested() {
                result = this.inner.poll_changed(this.cx.cx(), context);
            }
        }
        if result.is_ready() {
            this.inner.clear_waiter_registration(false);
            this.cx.clear();
        }
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(Some(
                this.inner.borrow_and_update_clone_with_cx(this.cx.cx()),
            )),
            Poll::Ready(Err(_)) => {
                this.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[path = "watch_stream_inline_tests.rs"]
mod tests;
