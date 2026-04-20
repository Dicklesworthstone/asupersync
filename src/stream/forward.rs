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
}

/// Convert a stream into a channel sender.
#[inline]
#[must_use]
pub fn into_sink<T>(sender: mpsc::Sender<T>) -> SinkStream<T> {
    SinkStream::new(sender)
}

/// Forward stream to channel.
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
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Wake, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// Invariant: `into_sink` wraps an mpsc::Sender in a SinkStream.
    #[test]
    fn into_sink_creates_sink_stream() {
        init_test("into_sink_creates_sink_stream");
        let (tx, _rx) = mpsc::channel::<i32>(4);
        let _sink = into_sink(tx);
        // Construction succeeded — SinkStream wraps the sender.
        crate::test_complete!("into_sink_creates_sink_stream");
    }

    /// Invariant: `forward` delivers all stream items to the channel.
    #[test]
    fn forward_sends_all_items() {
        init_test("forward_sends_all_items");
        let cx: Cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel::<i32>(8);
        let stream = iter(vec![10, 20, 30]);

        let mut future = std::pin::pin!(forward(&cx, stream, tx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // iter() yields synchronously, channel has capacity — should complete in one poll.
        let poll = future.as_mut().poll(&mut task_cx);
        let completed = matches!(poll, std::task::Poll::Ready(Ok(())));
        crate::assert_with_log!(completed, "forward completes", true, completed);

        // All items should be in the channel.
        let v1 = rx.try_recv();
        let ok1 = matches!(v1, Ok(10));
        crate::assert_with_log!(ok1, "received 10", true, ok1);
        let v2 = rx.try_recv();
        let ok2 = matches!(v2, Ok(20));
        crate::assert_with_log!(ok2, "received 20", true, ok2);
        let v3 = rx.try_recv();
        let ok3 = matches!(v3, Ok(30));
        crate::assert_with_log!(ok3, "received 30", true, ok3);

        crate::test_complete!("forward_sends_all_items");
    }

    /// Invariant: forwarding an empty stream completes immediately with Ok.
    #[test]
    fn forward_empty_stream_ok() {
        init_test("forward_empty_stream_ok");
        let cx: Cx = Cx::for_testing();
        let (tx, _rx) = mpsc::channel::<i32>(4);
        let stream = iter(Vec::<i32>::new());

        let mut future = std::pin::pin!(forward(&cx, stream, tx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = future.as_mut().poll(&mut task_cx);
        let completed = matches!(poll, std::task::Poll::Ready(Ok(())));
        crate::assert_with_log!(completed, "empty forward completes", true, completed);

        crate::test_complete!("forward_empty_stream_ok");
    }

    #[test]
    fn forward_yields_after_budget_on_always_ready_stream() {
        init_test("forward_yields_after_budget_on_always_ready_stream");
        let cx: Cx = Cx::for_testing();
        let item_count = FORWARD_SEND_BUDGET + 1;
        let (tx, mut rx) = mpsc::channel::<usize>(item_count + 1);
        let stream = iter(0..item_count);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woke))));
        let mut task_cx = Context::from_waker(&waker);
        let mut future = std::pin::pin!(forward(&cx, stream, tx));

        let first_poll = future.as_mut().poll(&mut task_cx);
        let first_pending = matches!(first_poll, std::task::Poll::Pending);
        crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);
        let woke_after_budget = woke.load(Ordering::SeqCst);
        crate::assert_with_log!(
            woke_after_budget,
            "self wake scheduled",
            true,
            woke_after_budget
        );

        let second_poll = future.as_mut().poll(&mut task_cx);
        let second_ready = matches!(second_poll, std::task::Poll::Ready(Ok(())));
        crate::assert_with_log!(second_ready, "second poll ready", true, second_ready);

        let mut received = Vec::with_capacity(item_count);
        while let Ok(item) = rx.try_recv() {
            received.push(item);
        }
        let expected: Vec<_> = (0..item_count).collect();
        crate::assert_with_log!(
            received == expected,
            "all forwarded items",
            expected,
            received
        );

        crate::test_complete!("forward_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    fn forward_cancelled_before_first_send_returns_unsent_item() {
        init_test("forward_cancelled_before_first_send_returns_unsent_item");
        let cx: Cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel::<i32>(8);
        let stream = iter(vec![10, 20, 30]);

        cx.set_cancel_requested(true);

        let mut future = std::pin::pin!(forward(&cx, stream, tx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = future.as_mut().poll(&mut task_cx);
        let cancelled = matches!(poll, std::task::Poll::Ready(Err(SendError::Cancelled(10))));
        crate::assert_with_log!(
            cancelled,
            "cancellation returns first unsent item",
            true,
            cancelled
        );

        let receiver_empty = rx.try_recv().is_err();
        crate::assert_with_log!(
            receiver_empty,
            "no items forwarded after pre-send cancellation",
            true,
            receiver_empty
        );

        crate::test_complete!("forward_cancelled_before_first_send_returns_unsent_item");
    }

    #[test]
    fn forward_full_path_reports_cancelled_not_disconnected() {
        init_test("forward_full_path_reports_cancelled_not_disconnected");
        let cx: Cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel::<i32>(1);
        let stream = iter(vec![1, 2]);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woke))));
        let mut task_cx = Context::from_waker(&waker);
        let mut future = std::pin::pin!(forward(&cx, stream, tx));

        let first_poll = future.as_mut().poll(&mut task_cx);
        let first_pending = matches!(first_poll, std::task::Poll::Pending);
        crate::assert_with_log!(
            first_pending,
            "first poll blocks on full channel",
            true,
            first_pending
        );

        let first_item = rx.try_recv();
        let first_forwarded = matches!(first_item, Ok(1));
        crate::assert_with_log!(
            first_forwarded,
            "first item forwarded",
            true,
            first_forwarded
        );

        cx.set_cancel_requested(true);

        let second_poll = future.as_mut().poll(&mut task_cx);
        let cancelled = matches!(
            second_poll,
            std::task::Poll::Ready(Err(SendError::Cancelled(2)))
        );
        crate::assert_with_log!(
            cancelled,
            "full-path cancellation preserves cancelled error kind",
            true,
            cancelled
        );

        let no_extra_item = rx.try_recv().is_err();
        crate::assert_with_log!(
            no_extra_item,
            "second item not forwarded after cancellation",
            true,
            no_extra_item
        );

        crate::test_complete!("forward_full_path_reports_cancelled_not_disconnected");
    }
}
