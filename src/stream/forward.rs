//! Helpers for forwarding streams to channels.

use crate::channel::mpsc;
use crate::channel::mpsc::SendError;
use crate::cx::Cx;
use crate::runtime::yield_now;
use crate::stream::{Stream, StreamExt};

/// Cooperative budget for successful sends in a single executor turn.
///
/// Without this cap, forwarding from an always-ready stream into a receiver
/// with spare capacity can monopolize a poll until the input is fully drained.
const FORWARD_SEND_BUDGET: usize = 1024;

/// Sink wrapper for mpsc sender.
pub struct SinkStream<T> {
    sender: mpsc::Sender<T>,
}

impl<T> SinkStream<T> {
    /// Create a new SinkStream.
    #[inline]
    #[must_use]
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self { sender }
    }

    /// Send item through the channel.
    #[inline]
    pub async fn send(&self, cx: &Cx, item: T) -> Result<(), SendError<T>> {
        self.sender.send(cx, item).await
    }

    /// Send all items from stream.
    #[inline]
    pub async fn send_all<S>(&self, cx: &Cx, stream: S) -> Result<(), SendError<S::Item>>
    where
        S: Stream<Item = T> + Unpin,
    {
        forward(cx, stream, self.sender.clone()).await
    }

    /// Forwards using caller-owned retry state and checked two-phase sends.
    ///
    /// `pending` holds at most one item extracted from `stream` but not yet
    /// committed to the channel. Dropping this borrowing future, cooperative
    /// cancellation, disconnection, or obligation-admission refusal leaves that
    /// item in `pending`. Retry with the same stream and slot; a new sink may be
    /// used after disconnection. A supplied pending item is sent before another
    /// source item is requested. Values need not be cloned.
    ///
    /// The wait wakes on cancellation even while the source is idle. Channel
    /// capacity is reserved before taking the pending value, and commit is
    /// synchronous: there is no await holding an extracted value only in this
    /// disposable future. At most one item is read ahead, and always-ready
    /// pipelines yield cooperatively. No background task is spawned.
    ///
    /// Success means EOF was observed and every extracted item was accepted by
    /// the channel, not that a consumer processed it. Do not retry after success
    /// unless the source supports polling after EOF. Dropping `stream` or the
    /// pending slot can still discard their contents. Source side effects while
    /// returning Pending and panicking user code are outside the retry guarantee.
    ///
    /// ```no_run
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::{channel::mpsc, stream::{into_sink, iter}};
    /// let (sender, _receiver) = mpsc::channel(8);
    /// let sink = into_sink(sender);
    /// let mut source = iter([1, 2, 3]);
    /// let mut pending = None;
    /// let result = sink.send_all_recoverable(cx, &mut source, &mut pending).await;
    /// // On error, retain BOTH source and pending for recovery.
    /// assert!(result.is_ok());
    /// assert!(pending.is_none());
    /// # }
    /// ```
    pub async fn send_all_recoverable<S>(
        &self,
        cx: &Cx,
        stream: &mut S,
        pending: &mut Option<T>,
    ) -> Result<(), mpsc::CheckedSendError<()>>
    where
        S: Stream<Item = T> + Unpin + ?Sized,
    {
        let mut sent_since_yield = 0usize;
        loop {
            if pending.is_none() {
                match crate::stream::Next::new(stream).with_cx(cx).await {
                    Ok(Some(item)) => *pending = Some(item),
                    Ok(None) => return Ok(()),
                    Err(_) => {
                        return Err(mpsc::CheckedSendError::Channel(SendError::Cancelled(())));
                    }
                }
            }

            let permit = self.sender.reserve_checked(cx).await?;
            if cx.checkpoint().is_err() {
                // RAII aborts the permit; the staged value has not moved.
                return Err(mpsc::CheckedSendError::Channel(SendError::Cancelled(())));
            }
            let item = pending
                .take()
                .expect("source or caller supplied a pending item");
            let (result, notification) = permit.try_send_deferred_wake(item);
            if let Err(error) = result {
                // Receiver closure may race the reservation. Restore ownership
                // before notifying arbitrary user code, not merely before return:
                // a panicking settlement notifier must not destroy an unsent item.
                let error = match error {
                    SendError::Disconnected(value) => {
                        *pending = Some(value);
                        SendError::Disconnected(())
                    }
                    SendError::Cancelled(value) => {
                        *pending = Some(value);
                        SendError::Cancelled(())
                    }
                    SendError::Full(value) => {
                        *pending = Some(value);
                        SendError::Full(())
                    }
                };
                notification.wake();
                return Err(mpsc::CheckedSendError::Channel(error));
            }
            // Publication and quota settlement are synchronous. Notify only
            // after the channel owns the value (or the slot above recovered it).
            notification.wake();

            sent_since_yield += 1;
            if sent_since_yield >= FORWARD_SEND_BUDGET {
                sent_since_yield = 0;
                yield_now().await;
            }
        }
    }
}

/// Convert a stream into a channel sender.
#[inline]
#[must_use]
pub fn into_sink<T>(sender: mpsc::Sender<T>) -> SinkStream<T> {
    SinkStream::new(sender)
}

/// Forward stream to channel.
///
/// For idle-source cancellation and recovery after dropping a pending
/// forwarding future, use [`SinkStream::send_all_recoverable`] instead.
///
/// # Cancel semantics
///
/// On a successful `stream.next().await`, this function checks `cx` BEFORE
/// the `sender.send`. If `cx` has been cancelled, the in-flight item is
/// returned to the caller via `Err(SendError::Cancelled(item))` — the
/// stream will NOT see this item again on a subsequent call to
/// `stream.next()`. Callers that must not lose items on cancellation are
/// responsible for handling `SendError::Cancelled` and either re-feeding
/// the value into a fresh `forward` invocation or persisting it to a
/// recovery queue. Dropping the returned error variant silently drops
/// the value. (Pass-3 / cancel-correctness invariant — re-stated here
/// after the /multi-pass-bug-hunting re-audit, batch-363 SOUND.)
#[inline]
pub async fn forward<S, T>(
    cx: &Cx,
    mut stream: S,
    sender: mpsc::Sender<T>,
) -> Result<(), SendError<T>>
where
    S: Stream<Item = T> + Unpin,
{
    let mut sent_since_yield = 0usize;
    while let Some(item) = stream.next().await {
        if cx.checkpoint().is_err() {
            return Err(SendError::Cancelled(item));
        }
        sender.send(cx, item).await?;

        sent_since_yield += 1;
        if sent_since_yield >= FORWARD_SEND_BUDGET {
            sent_since_yield = 0;
            yield_now().await;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "forward_recover_tests.rs"]
mod recover_tests;

#[cfg(test)]
#[path = "forward_inline_tests.rs"]
mod tests;
