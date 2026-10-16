//! Bounded output pipelines over region-owned concurrent stream work.
//!
//! A mapped output keeps its task slot until checked channel publication.
//! Unlike collecting a `Vec`, this permits a long-lived source without retaining
//! every result. The destination consumer must run concurrently with the sender.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (bounded stream task composition).

use super::stream_collect::ScopedStreamError;
use super::stream_control::try_for_each_concurrent_scoped_until;
use crate::channel::mpsc::{CheckedSendError, SendError, Sender};
use crate::cx::Cx;
use crate::stream::{Stream, StreamExt};
use crate::sync::Notify;
use crate::types::Outcome;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

/// A mapping failure, checked delivery refusal, or closed destination.
#[derive(Debug)]
#[non_exhaustive]
pub enum StreamSendError<E, T> {
    /// The item mapper failed before producing an output.
    Map(E),
    /// The channel or runtime refused publication, retaining that output.
    Delivery(CheckedSendError<T>),
    /// The receiver closed before a delivery failure or completion was observed.
    /// No particular output is returned; admitted work is cancelled and drained.
    DestinationClosed,
}

impl<E: std::fmt::Display, T> std::fmt::Display for StreamSendError<E, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Map(error) => write!(f, "stream mapping failed: {error}"),
            Self::Delivery(error) => write!(f, "stream output refused: {error}"),
            Self::DestinationClosed => f.write_str("stream destination closed"),
        }
    }
}

impl<E, T> std::error::Error for StreamSendError<E, T>
where
    E: std::error::Error + 'static,
    T: std::fmt::Debug + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Map(error) => Some(error),
            Self::Delivery(error) => Some(error),
            Self::DestinationClosed => None,
        }
    }
}

/// Maps an asynchronous source concurrently into a bounded MPSC destination.
///
/// At most `limit` direct tasks own input, mapping work, or an unpublished
/// output. A task waiting for destination capacity STILL occupies its slot:
/// backpressure therefore reaches the source instead of growing a result vector.
/// With destination capacity C, this operation retains at most `limit` outputs
/// outside the channel, plus the channel's C queued values. This is an item-count
/// bound, not a byte bound on user values, mapper allocations, descendants, or
/// values retained by the consumer. No extra producer/coordinator task is spawned.
///
/// Publication order is unconstrained. The destination must be consumed
/// concurrently; awaiting this operation before draining a full channel cannot
/// make progress. The caller retains the sender, so success does not close the
/// channel or mean that the consumer processed its contents.
///
/// Each mapper receives its admitted child context. Checked sends use that
/// context's authoritative obligation admission and preserve the rejected value
/// in a `Delivery` error. The first observed failure stops new admission, cancels
/// the work subtree, and joins direct tasks, descendants, and finalizers before
/// returning, following [`try_for_each_concurrent_scoped_until`]. Cleanup failure may
/// supersede the original item error. Other unpublished outputs are discarded
/// during drain; this is not a recovery log for every item.
///
/// Receiver closure is independently observed even with no source item ready or
/// all mappers blocked. It stops admission and requests cooperative subtree
/// cancellation, returning `DestinationClosed` unless a work/cleanup failure
/// takes precedence. An already-closed destination refuses BEFORE source polling
/// or mapper invocation, including for an empty source. A delivery failure that
/// the task driver has already selected keeps its rejected value. Closure only
/// after direct work completes does not retroactively fail accepted output.
///
/// Already accepted outputs are never rolled back, even on later failure. They
/// may be received BEFORE subtree cleanup finishes and must not depend on a
/// mapper-owned obligation or region resource remaining live. Moving a value
/// through this API does not transfer runtime holder liability. Dropping the
/// operation requests subtree close but cannot synchronously await it. Effects
/// using a captured outer context are outside this operation's cleanup boundary.
///
/// The source may borrow caller state and need not be `Send`. The mapper is
/// cloned per item; its inputs, future, outputs and errors are `Send + 'static`.
/// No `Clone` bound is added to inputs or outputs.
///
/// # Panics
/// Panics if `limit` is zero. Source and factory-clone unwinds take the scoped
/// driver's drain path; non-cooperative work, arbitrary panicking destructors,
/// and abort-on-panic builds retain that driver's documented limitations.
pub async fn try_map_send_concurrent_scoped<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    sender: &Sender<T>,
    map: F,
) -> Outcome<(), ScopedStreamError<StreamSendError<E, T>>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    drive(cx, stream, limit, sender, map, false).await
}

/// Concurrent mapping with bounded, source-order output publication.
///
/// This has [`try_map_send_concurrent_scoped`]'s subtree-drain and checked-send
/// contract, but an output cannot reserve channel capacity until its predecessor
/// has been accepted. Completed outputs waiting for their turn STILL occupy
/// direct-task slots. A stalled early mapper therefore stops read-ahead after
/// `limit` inputs instead of growing an unbounded reorder buffer. The tradeoff
/// is head-of-line blocking, not additional retained-result memory.
///
/// Mapping failures are observed without waiting for the failed item's turn.
/// A failed/cancelled predecessor never authorizes a successor to publish: the
/// driver cancels the subtree, and independent cancellation wakeups retire the
/// parked successors. There is no polling loop or output-order coordinator task.
/// The successfully published outputs of this operation form a source-order
/// prefix, including on failure. Other senders may interleave their own values.
///
/// Output publication is not transactional with later subtree cleanup. Already
/// accepted values remain visible, and other unpublished values are discarded
/// during cancellation/drain. Receiver closure also cancels unfinished mappers
/// and ordered-publication waits even when no send is attempted. This is
/// cooperative cancellation, not forced preemption. The item and resource-
/// lifetime bounds of the unordered variant apply unchanged.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::{Outcome, channel::mpsc, stream::iter};
/// use asupersync::combinator::stream_send::try_map_send_ordered_concurrent_scoped;
/// let (sender, mut receiver) = mpsc::channel(2);
/// let mut producer = cx.spawn(move |owner| async move {
///     try_map_send_ordered_concurrent_scoped(
///         &owner, iter([3, 1, 2]), 2, &sender,
///         |_child, n| async move { Ok::<_, &'static str>(n * 10) },
///     ).await
/// }).expect("spawn producer");
/// // Consume concurrently: do not join the producer before draining its output.
/// let mut values = Vec::new();
/// while let Ok(value) = receiver.recv(cx).await { values.push(value); }
/// assert!(matches!(producer.join(cx).await, Ok(Outcome::Ok(()))));
/// assert_eq!(values, [30, 10, 20]);
/// # }
/// ```
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn try_map_send_ordered_concurrent_scoped<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    sender: &Sender<T>,
    map: F,
) -> Outcome<(), ScopedStreamError<StreamSendError<E, T>>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    drive(cx, stream, limit, sender, map, true).await
}

/// One publication edge, not a linked list: completed predecessors are freed
/// when the direct successors finish. At most O(limit) edges remain owned.
#[derive(Default)]
struct Published {
    committed: AtomicBool,
    changed: Notify,
}

impl Published {
    fn publish(&self) {
        self.committed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait(&self, cx: &Cx) -> bool {
        if self.committed.load(Ordering::Acquire) {
            return true;
        }
        let mut changed = pin!(self.changed.wait_until(|| {
            self.committed.load(Ordering::Acquire)
        }));
        let mut cancelled = pin!(cx.cancelled());
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() {
                Poll::Ready(false)
            } else {
                changed.as_mut().poll(task).map(|()| true)
            }
        }).await
    }
}

async fn drive<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    sender: &Sender<T>,
    mut map: F,
    ordered: bool,
) -> Outcome<(), ScopedStreamError<StreamSendError<E, T>>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let closed = async move {
        sender.closed().await;
        StreamSendError::DestinationClosed
    };
    let sender = sender.clone();
    let mut previous = None;
    let stream = UntilClosed {
        inner: stream,
        destination: sender.clone(),
    };
    let stream = stream.map(move |item| {
        let published = ordered.then(|| Arc::new(Published::default()));
        let predecessor = std::mem::replace(&mut previous, published.clone());
        (item, predecessor, published)
    });
    try_for_each_concurrent_scoped_until(cx, stream, limit, closed, move |child, (item, before, after)| {
        let sender = sender.clone();
        let mapped = map(child.clone(), item);
        async move {
            let value = mapped.await.map_err(StreamSendError::Map)?;
            if let Some(before) = before {
                if !before.wait(&child).await {
                    return Err(StreamSendError::Delivery(CheckedSendError::Channel(
                        SendError::Cancelled(value),
                    )));
                }
            }
            sender
                .send_checked(&child, value)
                .await
                .map_err(StreamSendError::Delivery)?;
            // Do not reserve before this item's turn: later reservations could
            // otherwise consume every slot and prevent the predecessor sending.
            // Only acceptance, never Drop or an error, opens the successor gate.
            if let Some(after) = after {
                after.publish();
            }
            Ok(())
        }
    })
    .await
}

/// The source as `drive` sees it: once the destination has closed, it is not
/// polled again. An item taken then could only be dropped, and an item already
/// waiting in a borrowed source would be lost to its caller. The closure stop
/// is polled in the same poll, after the work, and is then ready; so this
/// Pending cannot stall the drive. It is Pending, not the end of the source,
/// so the work cannot finish with Ok ahead of `DestinationClosed`.
struct UntilClosed<S, T> {
    inner: S,
    destination: Sender<T>,
}

impl<S: Stream + Unpin, T> Stream for UntilClosed<S, T> {
    type Item = S::Item;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
    ) -> Poll<Option<S::Item>> {
        let this = self.get_mut();
        if this.destination.is_closed() {
            return Poll::Pending;
        }
        std::pin::Pin::new(&mut this.inner).poll_next(task)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.destination.is_closed() {
            (0, None)
        } else {
            self.inner.size_hint()
        }
    }
}

#[cfg(test)]
#[path = "stream_send_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stream_send_ordered_tests_inline_tests.rs"]
mod ordered_tests;

#[cfg(test)]
#[path = "stream_send/closed_tests.rs"]
mod closed_tests;
