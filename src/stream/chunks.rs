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
    #[inline]
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            items: Vec::with_capacity(cap),
            cap,
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

impl<S> Stream for Chunks<S>
where
    S: Stream,
{
    type Item = Vec<S::Item>;

    #[inline]
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

    #[inline]
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
    #[inline]
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            cap,
            items: Vec::with_capacity(cap),
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

impl<S> Stream for ReadyChunks<S>
where
    S: Stream,
{
    type Item = Vec<S::Item>;

    #[inline]
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

    #[inline]
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
    use std::task::Waker;

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

    // =========================================================================
    // Metamorphic relations for Chunks::chunks(cap):
    // conservation, count preservation, order, chunk-size bounds.
    //
    // Per-case tests cover individual scenarios (cap=1, exact divisibility,
    // empty input). These MRs encode the *contract* across arbitrary
    // (xs, cap) pairs — the core invariants a refactor must preserve.
    // =========================================================================

    mod chunks_count_mr {
        use super::*;

        fn drain_chunks<S>(mut stream: S) -> Vec<Vec<i32>>
        where
            S: Stream<Item = Vec<i32>> + Unpin,
        {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut out = Vec::new();
            loop {
                match Pin::new(&mut stream).poll_next(&mut cx) {
                    Poll::Ready(Some(chunk)) => out.push(chunk),
                    Poll::Ready(None) => break,
                    Poll::Pending => {}
                }
            }
            out
        }

        /// MR — Conservation: flatten(chunks(cap, xs)) == xs.
        /// No items lost, no items duplicated, order preserved.
        /// This is the single strongest invariant for a chunking adapter.
        #[test]
        fn mr_chunks_conservation_flat_equals_input() {
            let inputs: Vec<Vec<i32>> = vec![
                vec![],
                vec![42],
                (0..7).collect(),
                (0..8).collect(),
                (0..100).collect(),
            ];
            for xs in inputs {
                for cap in 1..=8usize {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    let flat: Vec<i32> = chunks.iter().flatten().copied().collect();
                    assert_eq!(
                        flat, xs,
                        "conservation violated for cap={cap}, xs.len()={}",
                        xs.len(),
                    );
                }
            }
        }

        /// MR — Count preservation: Σ chunk.len() == xs.len().
        /// Follows from conservation but isolated as a cheap assertion
        /// that a refactor touching Vec capacity handling would fail.
        #[test]
        fn mr_chunks_total_length_matches_input() {
            for n in 0..=32usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                for cap in 1..=8usize {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    let total: usize = chunks.iter().map(Vec::len).sum();
                    assert_eq!(
                        total, n,
                        "total len {total} != input len {n} at cap={cap}",
                    );
                }
            }
        }

        /// MR — Chunk-count law: ceil(xs.len() / cap) chunks for non-empty
        /// xs; 0 chunks for empty xs.
        #[test]
        fn mr_chunks_count_is_div_ceil() {
            for n in 0..=32usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                for cap in 1..=8usize {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    let expected = if n == 0 { 0 } else { n.div_ceil(cap) };
                    assert_eq!(
                        chunks.len(),
                        expected,
                        "chunk count {} != ceil({}/{}) = {} for input len {n}",
                        chunks.len(),
                        n,
                        cap,
                        expected,
                    );
                }
            }
        }

        /// MR — Chunk-size bound: every non-final chunk has len == cap; the
        /// final chunk has len in (0, cap]. No chunk is empty.
        #[test]
        fn mr_chunks_size_bound_non_empty_and_at_most_cap() {
            for n in 1..=32usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                for cap in 1..=8usize {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    let last_idx = chunks.len().saturating_sub(1);
                    for (i, chunk) in chunks.iter().enumerate() {
                        assert!(!chunk.is_empty(), "empty chunk at index {i}");
                        assert!(chunk.len() <= cap, "chunk len > cap at index {i}");
                        if i < last_idx {
                            assert_eq!(
                                chunk.len(),
                                cap,
                                "non-final chunk {i} has len != cap",
                            );
                        }
                    }
                }
            }
        }

        /// MR — Final-chunk remainder: when xs.len() is not a multiple of
        /// cap, the last chunk's length equals xs.len() % cap; otherwise
        /// it equals cap (exact divisibility).
        #[test]
        fn mr_chunks_final_chunk_length_is_remainder_or_cap() {
            for n in 1..=32usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                for cap in 1..=8usize {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    let last = chunks.last().expect("non-empty input has at least one chunk");
                    let remainder = n % cap;
                    let expected = if remainder == 0 { cap } else { remainder };
                    assert_eq!(
                        last.len(),
                        expected,
                        "final chunk len {} != expected {expected} for n={n}, cap={cap}",
                        last.len(),
                    );
                }
            }
        }

        /// MR — Order preservation: chunks[i][j] == xs[i*cap + j].
        /// The exact positional contract — a bug that reorders or
        /// duplicates items would pass conservation (same multiset) but
        /// fail this law.
        #[test]
        fn mr_chunks_positional_order() {
            for n in 0..=20usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                for cap in 1..=5usize {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    for (chunk_idx, chunk) in chunks.iter().enumerate() {
                        for (item_idx, item) in chunk.iter().enumerate() {
                            let expected = xs[chunk_idx * cap + item_idx];
                            assert_eq!(
                                *item, expected,
                                "position (chunk={chunk_idx}, idx={item_idx}) has item {item} != expected {expected}",
                            );
                        }
                    }
                }
            }
        }

        /// MR — cap=1 is a singleton-lifter: chunks(1, xs) produces
        /// exactly `xs.len()` chunks each containing one item matching xs
        /// at the same index.
        #[test]
        fn mr_chunks_cap_one_is_singleton_lift() {
            for n in 0..=16usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                let chunks = drain_chunks(Chunks::new(iter(xs.clone()), 1));
                assert_eq!(chunks.len(), n);
                for (i, chunk) in chunks.iter().enumerate() {
                    assert_eq!(chunk.as_slice(), &[xs[i]]);
                }
            }
        }

        /// MR — Empty input → empty output (never a lone empty chunk).
        /// Important: a naive implementation could flush an empty `items`
        /// vec as a chunk at end-of-stream; the spec forbids it.
        #[test]
        fn mr_chunks_empty_input_emits_no_chunks() {
            for cap in 1..=8usize {
                let chunks = drain_chunks(Chunks::new(iter(Vec::<i32>::new()), cap));
                assert!(
                    chunks.is_empty(),
                    "empty input produced chunks at cap={cap}: {chunks:?}",
                );
            }
        }

        /// MR — cap ≥ xs.len() yields exactly one chunk equal to xs
        /// (when xs is non-empty) or zero chunks (when xs is empty).
        #[test]
        fn mr_chunks_cap_at_or_above_len_yields_single_chunk() {
            for n in 1..=8usize {
                let xs: Vec<i32> = (0..n as i32).collect();
                for cap in n..=(n + 4) {
                    let chunks = drain_chunks(Chunks::new(iter(xs.clone()), cap));
                    assert_eq!(
                        chunks.len(),
                        1,
                        "cap={cap} >= len={n} should produce exactly one chunk",
                    );
                    assert_eq!(
                        chunks[0], xs,
                        "the single chunk must equal the full input",
                    );
                }
            }
        }
    }
}
