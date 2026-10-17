//! Receiver-closure observation without reserving channel capacity.

use super::{ChannelShared, Sender, UnboundedSender};
use crate::sync::Notify;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;

/// A channel that never observes closure pays no Notify allocation.
#[derive(Debug, Default)]
pub(super) struct ClosedSignal {
    notify: OnceLock<Box<Notify>>,
}

impl<T> Sender<T> {
    /// Waits until the receiver closes the channel or is dropped.
    ///
    /// This observes the same monotone state as [`Self::is_closed`]. It does
    /// not reserve capacity, publish a value, consume queued messages, or wait
    /// for the queue to drain. It can interrupt an upstream producer even when
    /// that producer has no message ready to send. Existing permits can still
    /// be outstanding when this resolves; their sends will be refused.
    ///
    /// Each pending call owns its notification registration. Dropping the
    /// future removes that registration without changing the channel or other
    /// observers, including observers polled with the same task waker. No
    /// runtime, timer, background task, or periodic poll is required. This wait
    /// observes channel closure, not context cancellation; race it with
    /// `cx.cancelled()` when both events matter.
    ///
    /// ```
    /// # futures_lite::future::block_on(async {
    /// use asupersync::channel::mpsc;
    /// let (sender, mut receiver) = mpsc::channel(1);
    /// sender.try_send(7).unwrap();
    /// receiver.close();
    /// sender.closed().await;
    /// assert_eq!(receiver.try_recv(), Ok(7));
    /// # });
    /// ```
    pub async fn closed(&self) {
        if self.is_closed() {
            return;
        }
        let notify = self
            .shared
            .closed
            .notify
            .get_or_init(|| Box::new(Notify::new()));
        // Synchronize with any racing closer on weak-memory architectures:
        // Taking the channel mutex and issuing SeqCst fences guarantees that
        // notify initialization is visible to the closer and receiver_dropped
        // is visible to this waiter, preventing store-buffering missed wakeups.
        drop(self.shared.inner.lock());
        std::sync::atomic::fence(Ordering::SeqCst);
        // Notify::wait_until samples its broadcast generation BEFORE checking
        // the persistent flag. Closure before initialization is seen by the
        // predicate; closure between check and registration is a replayed edge.
        notify.wait_until(|| self.is_closed()).await;
    }
}

impl<T> UnboundedSender<T> {
    /// Waits for receiver closure without sending or allocating queue capacity.
    ///
    /// See [`Sender::closed`] for cancellation and queue-draining semantics.
    pub async fn closed(&self) {
        self.inner.closed().await;
    }
}

/// Construct only after publishing receiver_dropped and releasing the channel
/// mutex. Declaring this after extracted queue values makes it run before their
/// destruction, even if an existing detached sender wake unwinds. Closure does
/// not claim that queued values have been destroyed or permits have settled.
pub(super) struct WakeClosed<'a, T>(pub(super) &'a ChannelShared<T>);

impl<T> Drop for WakeClosed<'_, T> {
    fn drop(&mut self) {
        std::sync::atomic::fence(Ordering::SeqCst);
        let Some(notify) = self.0.closed.notify.get() else {
            return;
        };
        let unwinding = std::thread::panicking();
        // Notify fanout isolates individual wakes. Do not turn an already
        // propagating sender-wake panic into a process-aborting double unwind.
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            notify.notify_waiters();
        })) {
            if unwinding {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

#[cfg(test)]
#[path = "mpsc_closed_inline_tests.rs"]
mod tests;
