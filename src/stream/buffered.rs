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
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
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

    #[inline]
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

    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
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

    #[inline]
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

    #[inline]
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
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::stream::iter;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
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

    // =========================================================================
    // Backpressure conformance laws for Buffered / BufferUnordered.
    //
    // Spec: doc comments on Buffered + BufferUnordered + BUFFERED_ADMISSION_BUDGET
    // + BUFFERED_POLL_BUDGET constants. These MUST clauses are enforced across
    // every admission / drain cycle. Per-case tests above cover individual
    // scenarios; these encode the *contract* that any refactor must preserve.
    // =========================================================================

    mod backpressure_conformance {
        use super::*;
        use std::future::{ready, Ready};

        fn drain_ready<S>(mut stream: S) -> Vec<<S as Stream>::Item>
        where
            S: Stream + Unpin,
        {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut out = Vec::new();
            loop {
                match Pin::new(&mut stream).poll_next(&mut cx) {
                    Poll::Ready(Some(item)) => out.push(item),
                    Poll::Ready(None) => break,
                    Poll::Pending => break,
                }
            }
            out
        }

        fn ready_futures(n: usize) -> impl Stream<Item = Ready<usize>> + Unpin {
            iter((0..n).map(ready))
        }

        /// MUST-L1: `in_flight.len() ≤ limit` at every visible state. Admission
        /// cap is the core backpressure invariant — a refactor that admitted
        /// one extra future per poll would still pass most per-case tests.
        #[test]
        fn conformance_buffered_never_exceeds_limit() {
            for &limit in &[1usize, 2, 4, 8, 16] {
                let stream = ready_futures(64);
                let mut buf = Buffered::new(stream, limit);
                let waker = noop_waker();
                let mut cx = Context::from_waker(&waker);
                for _ in 0..256 {
                    let _ = Pin::new(&mut buf).poll_next(&mut cx);
                    assert!(
                        buf.in_flight.len() <= limit,
                        "in_flight {} exceeded limit {} after poll",
                        buf.in_flight.len(),
                        limit,
                    );
                }
            }
        }

        /// MUST-L2: Output order of Buffered equals admission order.
        /// For a stream of fully-ready futures this collapses to the input
        /// sequence exactly.
        #[test]
        fn conformance_buffered_preserves_order_for_ready_futures() {
            for &limit in &[1usize, 2, 4, 8] {
                let stream = ready_futures(16);
                let buf = Buffered::new(stream, limit);
                let got = drain_ready(buf);
                let expected: Vec<usize> = (0..16).collect();
                assert_eq!(
                    got, expected,
                    "Buffered(limit={limit}) did not preserve order for ready input",
                );
            }
        }

        /// MUST-L3: `limit == 1` degenerates to strict serial poll order —
        /// exactly one in-flight future at a time. Equivalent to stream-of-
        /// futures awaited one-by-one.
        #[test]
        fn conformance_buffered_limit_one_is_strictly_serial() {
            let stream = ready_futures(8);
            let mut buf = Buffered::new(stream, 1);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            for i in 0..8 {
                // Each poll must either be Ready(Some(i)) or Pending; never
                // yield two items while admitting only one.
                loop {
                    match Pin::new(&mut buf).poll_next(&mut cx) {
                        Poll::Ready(Some(v)) => {
                            assert_eq!(v, i, "serial order violated at step {i}");
                            assert!(
                                buf.in_flight.is_empty(),
                                "limit=1 should have 0 in-flight after yield",
                            );
                            break;
                        }
                        Poll::Ready(None) => panic!("early termination at step {i}"),
                        Poll::Pending => (),
                    }
                }
            }
        }

        /// MUST-L4: Empty upstream → first poll yields Ready(None), no
        /// further polls needed. No phantom in-flight futures get queued.
        #[test]
        fn conformance_buffered_empty_terminates_immediately() {
            let buf = Buffered::new(iter(Vec::<Ready<usize>>::new()), 4);
            let got = drain_ready(buf);
            assert!(
                got.is_empty(),
                "Buffered on empty upstream should produce no items, got {got:?}",
            );
        }

        /// MUST-L5: size_hint is monotone across admission — the lower bound
        /// accounts for in-flight futures that have been admitted but not yet
        /// emitted. An accurate lower bound is what lets downstream
        /// collectors pre-allocate.
        #[test]
        fn conformance_buffered_size_hint_counts_in_flight() {
            let stream = ready_futures(10);
            let mut buf = Buffered::new(stream, 4);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            // First poll admits up to limit=4 and yields 1.
            let _ = Pin::new(&mut buf).poll_next(&mut cx);
            let (lower, upper) = buf.size_hint();
            assert!(
                lower >= buf.in_flight.len(),
                "size_hint.lower ({lower}) must be >= in_flight ({})",
                buf.in_flight.len(),
            );
            // Upstream has 9 items remaining after 1 emitted (and 4 admitted),
            // so upper bound includes those plus in_flight.
            if let Some(u) = upper {
                assert!(
                    u >= lower,
                    "size_hint.upper ({u}) must be >= lower ({lower})",
                );
            }
        }

        /// MUST-L6: Buffered and BufferUnordered on a ready-stream produce
        /// the *same multiset* of outputs. Unordered differs only in
        /// yield-order, never in set-of-values.
        #[test]
        fn conformance_buffered_and_unordered_agree_on_multiset() {
            for &limit in &[1usize, 2, 4, 8] {
                let ordered_out = drain_ready(Buffered::new(ready_futures(20), limit));
                let mut unordered_out =
                    drain_ready(BufferUnordered::new(ready_futures(20), limit));
                unordered_out.sort_unstable();
                let mut ordered_sorted = ordered_out.clone();
                ordered_sorted.sort_unstable();
                assert_eq!(
                    ordered_sorted, unordered_out,
                    "Buffered/BufferUnordered(limit={limit}) yielded different multisets",
                );
                // Ordered version additionally must be strictly ascending.
                assert_eq!(
                    ordered_out,
                    (0..20usize).collect::<Vec<_>>(),
                    "Buffered(limit={limit}) lost input order",
                );
            }
        }

        /// MUST-L7: Upstream-done + in_flight-empty → Ready(None), and the
        /// result does not regress to Pending after that terminal state.
        /// Poll-after-completion must remain Ready(None).
        #[test]
        fn conformance_buffered_terminal_state_is_sticky() {
            let mut buf = Buffered::new(ready_futures(3), 2);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut seen = 0usize;
            loop {
                match Pin::new(&mut buf).poll_next(&mut cx) {
                    Poll::Ready(Some(_)) => seen += 1,
                    Poll::Ready(None) => break,
                    Poll::Pending => (),
                }
            }
            assert_eq!(seen, 3);
            // Two additional polls after termination must still be None.
            for _ in 0..2 {
                assert!(matches!(
                    Pin::new(&mut buf).poll_next(&mut cx),
                    Poll::Ready(None),
                ), "terminal state regressed after exhaustion");
            }
        }

        /// MUST-L8: `buffered(limit ≥ n)` on an n-item ready stream admits
        /// everything (up to BUFFERED_ADMISSION_BUDGET per poll) and drains
        /// completely. At a limit higher than the workload size, the cap
        /// should never become the bottleneck.
        #[test]
        fn conformance_buffered_large_limit_drains_all() {
            let n = 16;
            let buf = Buffered::new(ready_futures(n), n * 2);
            let got = drain_ready(buf);
            assert_eq!(got.len(), n, "large-limit buffered must drain all inputs");
        }
    }
}
