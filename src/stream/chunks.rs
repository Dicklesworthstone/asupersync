//! Chunking combinators for streams.
//!
//! `Chunks` yields fixed-size batches, while `ReadyChunks` yields whatever is
//! immediately available without waiting for a full batch.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items drained in a single poll.
///
/// Without this bound, large chunk capacities combined with always-ready
/// upstream streams can monopolize an executor turn.
const CHUNKS_COOPERATIVE_BUDGET: usize = 1024;

/// A stream that yields items in fixed-size chunks.
///
/// Created by [`StreamExt::chunks`](super::StreamExt::chunks).
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Chunks<S: Stream> {
    #[pin]
    stream: S,
    items: Vec<S::Item>,
    cap: usize,
}

impl<S: Stream> Chunks<S> {
    /// Creates a new `Chunks` stream.
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            items: Vec::with_capacity(cap),
            cap,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> Stream for Chunks<S>
where
    S: Stream,
{
    type Item = Vec<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let mut drained_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    this.items.push(item);
                    if this.items.len() >= *this.cap {
                        return Poll::Ready(Some(std::mem::take(this.items)));
                    }
                    drained_this_poll += 1;
                    if drained_this_poll >= CHUNKS_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    if this.items.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(std::mem::take(this.items)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = self.items.len();
        let (lower, upper) = self.stream.size_hint();
        let total_lower = lower.saturating_add(buffered);
        let lower = total_lower.div_ceil(self.cap);
        let upper = upper.map(|u| u.saturating_add(buffered).div_ceil(self.cap));
        (lower, upper)
    }
}

/// A stream that yields chunks of immediately available items.
///
/// Created by [`StreamExt::ready_chunks`](super::StreamExt::ready_chunks).
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct ReadyChunks<S: Stream> {
    #[pin]
    stream: S,
    cap: usize,
    items: Vec<S::Item>,
}

impl<S: Stream> ReadyChunks<S> {
    /// Creates a new `ReadyChunks` stream.
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            cap,
            items: Vec::with_capacity(cap),
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> Stream for ReadyChunks<S>
where
    S: Stream,
{
    type Item = Vec<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        // Reuse the buffer across polls; ensure capacity after a previous take.
        let cap = *this.cap;
        let need = cap.saturating_sub(this.items.capacity());
        if need > 0 {
            this.items.reserve(need);
        }

        let mut drained_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    this.items.push(item);
                    if this.items.len() >= cap {
                        return Poll::Ready(Some(std::mem::take(this.items)));
                    }
                    drained_this_poll += 1;
                    if drained_this_poll >= CHUNKS_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    if this.items.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(std::mem::take(this.items)));
                }
                Poll::Pending => {
                    if this.items.is_empty() {
                        return Poll::Pending;
                    }
                    return Poll::Ready(Some(std::mem::take(this.items)));
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = self.items.len();
        let (lower_items, upper_items) = self.stream.size_hint();
        let total_lower_items = lower_items.saturating_add(buffered);
        let lower = if total_lower_items == 0 {
            0
        } else {
            total_lower_items.div_ceil(self.cap)
        };
        let upper =
            upper_items.map(|upper_items| upper_items.saturating_add(usize::from(buffered > 0)));
        (lower, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::StreamExt;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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

    #[test]
    fn chunks_groups_items() {
        init_test("chunks_groups_items");
        let mut stream = Chunks::new(iter(vec![1, 2, 3, 4, 5, 6, 7]), 3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![1, 2, 3]);
        crate::assert_with_log!(ok, "chunk 1", "Poll::Ready(Some([1,2,3]))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![4, 5, 6]);
        crate::assert_with_log!(ok, "chunk 2", "Poll::Ready(Some([4,5,6]))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![7]);
        crate::assert_with_log!(ok, "chunk 3", "Poll::Ready(Some([7]))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("chunks_groups_items");
    }

    struct PendingOnce {
        yielded: bool,
        pending: bool,
    }

    impl Stream for PendingOnce {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.pending {
                self.pending = true;
                return Poll::Pending;
            }
            if !self.yielded {
                self.yielded = true;
                return Poll::Ready(Some(1));
            }
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct HintOnlyStream {
        lower: usize,
        upper: Option<usize>,
    }

    impl Stream for HintOnlyStream {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.lower, self.upper)
        }
    }

    #[test]
    fn ready_chunks_returns_immediate_items() {
        init_test("ready_chunks_returns_immediate_items");
        let stream = iter(vec![1, 2]).chain(PendingOnce {
            yielded: false,
            pending: false,
        });
        let mut stream = ReadyChunks::new(stream, 10);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![1, 2]);
        crate::assert_with_log!(ok, "ready chunk", "Poll::Ready(Some([1,2]))", poll);
        crate::test_complete!("ready_chunks_returns_immediate_items");
    }

    #[test]
    fn ready_chunks_size_hint_counts_buffered_partial_chunk() {
        init_test("ready_chunks_size_hint_counts_buffered_partial_chunk");
        let stream = ReadyChunks {
            stream: iter(Vec::<i32>::new()),
            cap: 4,
            items: vec![1, 2],
        };

        let hint = stream.size_hint();
        crate::assert_with_log!(
            hint == (1, Some(1)),
            "buffered partial chunk remains visible in size_hint",
            (1, Some(1)),
            hint
        );
        crate::test_complete!("ready_chunks_size_hint_counts_buffered_partial_chunk");
    }

    #[test]
    fn ready_chunks_size_hint_counts_guaranteed_upstream_items() {
        init_test("ready_chunks_size_hint_counts_guaranteed_upstream_items");
        let stream = ReadyChunks::new(
            HintOnlyStream {
                lower: 5,
                upper: Some(5),
            },
            4,
        );

        let hint = stream.size_hint();
        crate::assert_with_log!(
            hint == (2, Some(5)),
            "guaranteed upstream items imply at least two chunks and at most five flushes",
            (2, Some(5)),
            hint
        );
        crate::test_complete!("ready_chunks_size_hint_counts_guaranteed_upstream_items");
    }

    #[test]
    fn ready_chunks_size_hint_upper_allows_per_item_flushes() {
        init_test("ready_chunks_size_hint_upper_allows_per_item_flushes");
        let stream = ReadyChunks {
            stream: HintOnlyStream {
                lower: 0,
                upper: Some(2),
            },
            cap: 4,
            items: vec![1, 2],
        };

        let hint = stream.size_hint();
        crate::assert_with_log!(
            hint == (1, Some(3)),
            "buffered partial chunk plus two future items can still flush as three chunks",
            (1, Some(3)),
            hint
        );
        crate::test_complete!("ready_chunks_size_hint_upper_allows_per_item_flushes");
    }

    /// Invariant: empty stream produces `None` with no chunks.
    #[test]
    fn chunks_empty_stream_returns_none() {
        init_test("chunks_empty_stream_returns_none");
        let mut stream = Chunks::new(iter(Vec::<i32>::new()), 3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "empty stream yields None", true, is_none);
        crate::test_complete!("chunks_empty_stream_returns_none");
    }

    /// Invariant: chunk size 1 yields each item as a single-element vec.
    #[test]
    fn chunks_size_one_yields_individual_items() {
        init_test("chunks_size_one_yields_individual_items");
        let mut stream = Chunks::new(iter(vec![10, 20, 30]), 1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref c)) if c == &vec![10]);
        crate::assert_with_log!(ok, "chunk [10]", true, ok);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref c)) if c == &vec![20]);
        crate::assert_with_log!(ok, "chunk [20]", true, ok);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref c)) if c == &vec![30]);
        crate::assert_with_log!(ok, "chunk [30]", true, ok);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "stream done", true, is_none);
        crate::test_complete!("chunks_size_one_yields_individual_items");
    }

    /// Invariant: when stream length is exactly divisible by chunk size,
    /// no partial chunk is produced.
    #[test]
    fn chunks_exact_divisible_no_partial() {
        init_test("chunks_exact_divisible_no_partial");
        let mut stream = Chunks::new(iter(vec![1, 2, 3, 4, 5, 6]), 3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref c)) if c == &vec![1, 2, 3]);
        crate::assert_with_log!(ok, "chunk [1,2,3]", true, ok);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref c)) if c == &vec![4, 5, 6]);
        crate::assert_with_log!(ok, "chunk [4,5,6]", true, ok);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "no partial chunk", true, is_none);
        crate::test_complete!("chunks_exact_divisible_no_partial");
    }

    #[derive(Debug, Default)]
    struct AlwaysReadyCounter {
        next: usize,
    }

    impl Stream for AlwaysReadyCounter {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let item = self.next;
            self.next = self.next.saturating_add(1);
            Poll::Ready(Some(item))
        }
    }

    #[test]
    fn chunks_yield_after_budget_on_always_ready_stream() {
        init_test("chunks_yield_after_budget_on_always_ready_stream");
        let mut stream = Chunks::new(AlwaysReadyCounter::default(), CHUNKS_COOPERATIVE_BUDGET + 5);
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(first, Poll::Pending);
        crate::assert_with_log!(ok, "first poll yields cooperatively", true, ok);
        let ok = stream.items.len() == CHUNKS_COOPERATIVE_BUDGET;
        crate::assert_with_log!(
            ok,
            "buffered items preserved across yield",
            CHUNKS_COOPERATIVE_BUDGET,
            stream.items.len()
        );
        let ok = stream.stream.next == CHUNKS_COOPERATIVE_BUDGET;
        crate::assert_with_log!(
            ok,
            "upstream advanced only to budget",
            CHUNKS_COOPERATIVE_BUDGET,
            stream.stream.next
        );
        let ok = woke.load(Ordering::SeqCst);
        crate::assert_with_log!(ok, "self-wake requested", true, ok);

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        let ok =
            matches!(second, Poll::Ready(Some(ref c)) if c.len() == CHUNKS_COOPERATIVE_BUDGET + 5);
        crate::assert_with_log!(
            ok,
            "second poll completes buffered chunk",
            CHUNKS_COOPERATIVE_BUDGET + 5,
            second
        );
        crate::test_complete!("chunks_yield_after_budget_on_always_ready_stream");
    }

    #[test]
    fn ready_chunks_flush_after_budget_on_always_ready_stream() {
        init_test("ready_chunks_flush_after_budget_on_always_ready_stream");
        let mut stream =
            ReadyChunks::new(AlwaysReadyCounter::default(), CHUNKS_COOPERATIVE_BUDGET + 5);
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(first, Poll::Pending);
        crate::assert_with_log!(
            ok,
            "first poll yields cooperatively",
            "Poll::Pending",
            first
        );
        let ok = stream.items.len() == CHUNKS_COOPERATIVE_BUDGET;
        crate::assert_with_log!(
            ok,
            "buffered items preserved across yield",
            CHUNKS_COOPERATIVE_BUDGET,
            stream.items.len()
        );
        let ok = stream.stream.next == CHUNKS_COOPERATIVE_BUDGET;
        crate::assert_with_log!(
            ok,
            "upstream advanced only to budget",
            CHUNKS_COOPERATIVE_BUDGET,
            stream.stream.next
        );
        let ok = woke.load(Ordering::SeqCst);
        crate::assert_with_log!(ok, "self-wake requested", true, ok);

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        let ok =
            matches!(second, Poll::Ready(Some(ref c)) if c.len() == CHUNKS_COOPERATIVE_BUDGET + 5);
        crate::assert_with_log!(
            ok,
            "second poll completes buffered chunk",
            CHUNKS_COOPERATIVE_BUDGET + 5,
            second
        );
        crate::test_complete!("ready_chunks_flush_after_budget_on_always_ready_stream");
    }
}
