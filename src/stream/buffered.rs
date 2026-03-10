//! Buffered combinators for streams of futures.
//!
//! `Buffered` preserves output order, while `BufferUnordered` yields results
//! as soon as futures complete.

use super::Stream;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for admitting new futures from the source stream.
///
/// Without this cap, large buffer limits plus always-ready upstream streams can
/// monopolize one executor turn while filling the in-flight queue.
const BUFFERED_ADMISSION_BUDGET: usize = 1024;

/// Cooperative budget for polling buffered futures in a single call.
///
/// Without this cap, large in-flight buffers can monopolize one executor turn
/// when every future is ready or repeatedly returns `Poll::Pending`.
const BUFFERED_POLL_BUDGET: usize = 1024;

struct BufferedEntry<Fut: Future> {
    fut: Fut,
    output: Option<Fut::Output>,
}

impl<Fut: Future> BufferedEntry<Fut> {
    fn new(fut: Fut) -> Self {
        Self { fut, output: None }
    }
}

/// A stream that buffers and polls futures, preserving order.
///
/// Created by [`StreamExt::buffered`](super::StreamExt::buffered).
#[must_use = "streams do nothing unless polled"]
pub struct Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<BufferedEntry<S::Item>>,
    limit: usize,
    done: bool,
    next_poll_index: usize,
}

impl<S> Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `Buffered` stream with the given limit.
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "buffered limit must be non-zero");
        Self {
            stream,
            in_flight: VecDeque::with_capacity(limit),
            limit,
            done: false,
            next_poll_index: 0,
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

impl<S> Unpin for Buffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> Stream for Buffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
    type Item = <S::Item as Future>::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut budget_exhausted = false;
        let mut admitted_this_poll = 0usize;
        while !self.done && self.in_flight.len() < self.limit {
            if admitted_this_poll >= BUFFERED_ADMISSION_BUDGET {
                budget_exhausted = true;
                break;
            }
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => {
                    self.in_flight.push_back(BufferedEntry::new(fut));
                    admitted_this_poll += 1;
                }
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        if matches!(self.in_flight.front(), Some(front) if front.output.is_some()) {
            let mut entry = self.in_flight.pop_front().expect("front exists");
            self.next_poll_index = self.next_poll_index.saturating_sub(1);
            if self.in_flight.is_empty() {
                self.next_poll_index = 0;
            } else {
                self.next_poll_index %= self.in_flight.len();
            }
            return Poll::Ready(entry.output.take());
        }

        let len = self.in_flight.len();
        if len > 0 {
            let mut index = self.next_poll_index.min(len.saturating_sub(1));
            let scan_budget = len.min(BUFFERED_POLL_BUDGET);
            for _ in 0..scan_budget {
                if let Some(entry) = self.in_flight.get_mut(index) {
                    if entry.output.is_none() {
                        if let Poll::Ready(output) = Pin::new(&mut entry.fut).poll(cx) {
                            entry.output = Some(output);
                        }
                    }
                }
                index += 1;
                if index >= len {
                    index = 0;
                }
            }
            self.next_poll_index = index;
            if len > BUFFERED_POLL_BUDGET {
                budget_exhausted = true;
            }
        }

        if matches!(self.in_flight.front(), Some(front) if front.output.is_some()) {
            let mut entry = self.in_flight.pop_front().expect("front exists");
            self.next_poll_index = self.next_poll_index.saturating_sub(1);
            if self.in_flight.is_empty() {
                self.next_poll_index = 0;
            } else {
                self.next_poll_index %= self.in_flight.len();
            }
            return Poll::Ready(entry.output.take());
        }

        if self.done && self.in_flight.is_empty() {
            Poll::Ready(None)
        } else {
            if budget_exhausted {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let in_flight = self.in_flight.len();

        let lower = lower.saturating_add(in_flight);
        let upper = upper.and_then(|u| u.checked_add(in_flight));

        (lower, upper)
    }
}

/// A stream that buffers and polls futures, yielding results as they complete.
///
/// Created by [`StreamExt::buffer_unordered`](super::StreamExt::buffer_unordered).
#[must_use = "streams do nothing unless polled"]
pub struct BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<S::Item>,
    limit: usize,
    done: bool,
}

impl<S> fmt::Debug for Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S> fmt::Debug for BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferUnordered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S> BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `BufferUnordered` stream with the given limit.
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "buffer_unordered limit must be non-zero");
        Self {
            stream,
            in_flight: VecDeque::with_capacity(limit),
            limit,
            done: false,
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

impl<S> Unpin for BufferUnordered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> Stream for BufferUnordered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
    type Item = <S::Item as Future>::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut budget_exhausted = false;
        let mut admitted_this_poll = 0usize;
        while !self.done && self.in_flight.len() < self.limit {
            if admitted_this_poll >= BUFFERED_ADMISSION_BUDGET {
                budget_exhausted = true;
                break;
            }
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => {
                    self.in_flight.push_back(fut);
                    admitted_this_poll += 1;
                }
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        let len = self.in_flight.len();
        let poll_budget = len.min(BUFFERED_POLL_BUDGET);
        for _ in 0..poll_budget {
            let mut fut = self.in_flight.pop_front().expect("length checked");
            match Pin::new(&mut fut).poll(cx) {
                Poll::Ready(output) => return Poll::Ready(Some(output)),
                Poll::Pending => self.in_flight.push_back(fut),
            }
        }
        if len > BUFFERED_POLL_BUDGET {
            budget_exhausted = true;
        }

        if self.done && self.in_flight.is_empty() {
            Poll::Ready(None)
        } else {
            if budget_exhausted {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let in_flight = self.in_flight.len();

        let lower = lower.saturating_add(in_flight);
        let upper = upper.and_then(|u| u.checked_add(in_flight));

        (lower, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

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

    #[derive(Debug)]
    struct PendingOnceFuture {
        value: usize,
        poll_counter: Arc<AtomicUsize>,
        polled_once: bool,
    }

    impl PendingOnceFuture {
        fn new(value: usize, poll_counter: Arc<AtomicUsize>) -> Self {
            Self {
                value,
                poll_counter,
                polled_once: false,
            }
        }
    }

    impl Future for PendingOnceFuture {
        type Output = usize;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.poll_counter.fetch_add(1, Ordering::SeqCst);
            if self.polled_once {
                Poll::Ready(self.value)
            } else {
                self.polled_once = true;
                Poll::Pending
            }
        }
    }

    #[derive(Debug)]
    struct AlwaysReadyPendingFutureStream {
        next: usize,
        end: usize,
        poll_counter: Arc<AtomicUsize>,
    }

    impl AlwaysReadyPendingFutureStream {
        fn new(end: usize, poll_counter: Arc<AtomicUsize>) -> Self {
            Self {
                next: 0,
                end,
                poll_counter,
            }
        }
    }

    impl Stream for AlwaysReadyPendingFutureStream {
        type Item = PendingOnceFuture;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.next >= self.end {
                return Poll::Ready(None);
            }

            let item = PendingOnceFuture::new(self.next, self.poll_counter.clone());
            self.next += 1;
            Poll::Ready(Some(item))
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn buffered_preserves_order() {
        init_test("buffered_preserves_order");
        let stream = iter(vec![
            std::future::ready(1),
            std::future::ready(2),
            std::future::ready(3),
        ]);
        let mut stream = Buffered::new(stream, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("buffered_preserves_order");
    }

    #[test]
    fn buffer_unordered_yields_all() {
        init_test("buffer_unordered_yields_all");
        let stream = iter(vec![
            std::future::ready(1),
            std::future::ready(2),
            std::future::ready(3),
        ]);
        let mut stream = BufferUnordered::new(stream, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        items.sort_unstable();
        let ok = items == vec![1, 2, 3];
        crate::assert_with_log!(ok, "items", vec![1, 2, 3], items);
        crate::test_complete!("buffer_unordered_yields_all");
    }

    /// Invariant: `Buffered` never holds more than `limit` futures in flight.
    #[test]
    fn buffered_respects_in_flight_limit() {
        init_test("buffered_respects_in_flight_limit");
        let stream = iter(vec![
            std::future::ready(1),
            std::future::ready(2),
            std::future::ready(3),
            std::future::ready(4),
            std::future::ready(5),
        ]);
        let mut stream = Buffered::new(stream, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // After first poll, at most `limit` items should be in flight.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", true, ok);

        // in_flight should never exceed limit (2) at any point.
        let in_flight = stream.in_flight.len();
        let within_limit = in_flight <= 2;
        crate::assert_with_log!(within_limit, "in_flight <= limit", true, within_limit);

        // Drain remaining items.
        let mut count = 1; // already got 1
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(_)) => {
                    count += 1;
                    let in_flight = stream.in_flight.len();
                    let ok = in_flight <= 2;
                    crate::assert_with_log!(ok, "in_flight <= limit during drain", true, ok);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }
        crate::assert_with_log!(count == 5, "all items yielded", 5usize, count);
        crate::test_complete!("buffered_respects_in_flight_limit");
    }

    /// Invariant: `Buffered` on an empty stream yields `None` immediately.
    #[test]
    fn buffered_empty_stream_terminates() {
        init_test("buffered_empty_stream_terminates");
        let stream = iter(Vec::<std::future::Ready<i32>>::new());
        let mut stream = Buffered::new(stream, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "empty stream yields None", true, is_none);
        crate::test_complete!("buffered_empty_stream_terminates");
    }

    /// Invariant: `BufferUnordered` on an empty stream yields `None` immediately.
    #[test]
    fn buffer_unordered_empty_stream_terminates() {
        init_test("buffer_unordered_empty_stream_terminates");
        let stream = iter(Vec::<std::future::Ready<i32>>::new());
        let mut stream = BufferUnordered::new(stream, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "empty stream yields None", true, is_none);
        crate::test_complete!("buffer_unordered_empty_stream_terminates");
    }

    #[test]
    fn buffered_yields_pending_after_budget_on_large_pending_batch() {
        init_test("buffered_yields_pending_after_budget_on_large_pending_batch");
        let poll_counter = Arc::new(AtomicUsize::new(0));
        let mut stream = Buffered::new(
            AlwaysReadyPendingFutureStream::new(
                BUFFERED_ADMISSION_BUDGET + 5,
                poll_counter.clone(),
            ),
            BUFFERED_ADMISSION_BUDGET + 5,
        );
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields pending after cooperative budget",
            "Poll::Pending",
            first
        );
        crate::assert_with_log!(
            stream.stream.next == BUFFERED_ADMISSION_BUDGET,
            "admission capped at budget",
            BUFFERED_ADMISSION_BUDGET,
            stream.stream.next
        );
        crate::assert_with_log!(
            stream.in_flight.len() == BUFFERED_ADMISSION_BUDGET,
            "in-flight queue capped at admission budget on first poll",
            BUFFERED_ADMISSION_BUDGET,
            stream.in_flight.len()
        );
        crate::assert_with_log!(
            poll_counter.load(Ordering::SeqCst) == BUFFERED_POLL_BUDGET,
            "future polling capped at cooperative budget",
            BUFFERED_POLL_BUDGET,
            poll_counter.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested after budget exhaustion",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            second == Poll::Ready(Some(0)),
            "second poll resumes and yields the front output",
            Poll::Ready(Some(0)),
            second
        );
        crate::test_complete!("buffered_yields_pending_after_budget_on_large_pending_batch");
    }

    #[test]
    fn buffer_unordered_yields_pending_after_budget_on_large_pending_batch() {
        init_test("buffer_unordered_yields_pending_after_budget_on_large_pending_batch");
        let poll_counter = Arc::new(AtomicUsize::new(0));
        let mut stream = BufferUnordered::new(
            AlwaysReadyPendingFutureStream::new(
                BUFFERED_ADMISSION_BUDGET + 5,
                poll_counter.clone(),
            ),
            BUFFERED_ADMISSION_BUDGET + 5,
        );
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields pending after cooperative budget",
            "Poll::Pending",
            first
        );
        crate::assert_with_log!(
            stream.stream.next == BUFFERED_ADMISSION_BUDGET,
            "admission capped at budget",
            BUFFERED_ADMISSION_BUDGET,
            stream.stream.next
        );
        crate::assert_with_log!(
            stream.in_flight.len() == BUFFERED_ADMISSION_BUDGET,
            "in-flight queue capped at admission budget on first poll",
            BUFFERED_ADMISSION_BUDGET,
            stream.in_flight.len()
        );
        crate::assert_with_log!(
            poll_counter.load(Ordering::SeqCst) == BUFFERED_POLL_BUDGET,
            "future polling capped at cooperative budget",
            BUFFERED_POLL_BUDGET,
            poll_counter.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested after budget exhaustion",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            second == Poll::Ready(Some(0)),
            "second poll resumes and yields the first completed output",
            Poll::Ready(Some(0)),
            second
        );
        crate::test_complete!(
            "buffer_unordered_yields_pending_after_budget_on_large_pending_batch"
        );
    }
}
