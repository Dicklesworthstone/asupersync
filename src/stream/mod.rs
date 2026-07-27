//! Async stream processing primitives.
//!
//! This module provides the [`Stream`] trait and related combinators for
//! processing asynchronous sequences of values.
//!
//! # Core Traits
//!
//! - [`Stream`]: The async equivalent of [`Iterator`], producing values over time
//! - [`StreamExt`]: Extension trait providing combinator methods
//!
//! # Combinators
//!
//! ## Transformation
//! - [`Map`]: Transforms each item with a closure
//! - [`Filter`]: Yields only items matching a predicate
//! - [`FilterMap`]: Combines filter and map in one step
//! - [`Then`]: Async map (runs future per item)
//! - [`Enumerate`]: Adds index to items
//! - [`Inspect`]: Runs closure on items without consuming
//!
//! ## Selection
//! - [`Take`]: Limits stream to n items
//! - [`TakeWhile`]: Limits stream while predicate is true
//! - [`Skip`]: Skips n items
//! - [`SkipWhile`]: Skips while predicate is true
//! - [`Fuse`]: Fuses the stream
//!
//! ## Combination
//! - [`Chain`]: Yields all items from one stream then another
//! - [`Zip`]: Pairs items from two streams
//! - [`Merge`]: Interleaves items from multiple streams
//!
//! ## Splitting
//! - [`Partition`]: Splits one stream into two by a predicate, with a bounded
//!   per-lane buffer and an explicit head-of-line backpressure contract
//!
//! ## Stateful
//! - [`Scan`]: Yields intermediate accumulator values (like `Iterator::scan`)
//! - [`Peekable`]: Look at the next item without consuming it
//!
//! ## Rate Control
//! - [`Throttle`]: Rate-limits to at most one item per period
//! - [`Debounce`]: Suppresses rapid bursts, yielding after a quiet period
//!
//! ## Buffering
//! - [`Buffered`]: Runs multiple futures while preserving order
//! - [`BufferUnordered`]: Runs multiple futures without ordering guarantees
//! - [`TryBuffered`]: Ordered buffering of fallible futures, stopping at the first `Err`
//! - [`Chunks`]: Groups items into fixed-size batches
//! - [`ReadyChunks`]: Returns immediately available items
//!
//! The three future-buffering combinators expose deterministic pressure
//! telemetry via `telemetry_snapshot(id)`, returning a
//! [`StreamTelemetrySnapshot`] in the same idiom as
//! [`SyncTelemetrySnapshot`](crate::sync::SyncTelemetrySnapshot).
//!
//! ## Terminal Operations
//! - [`Collect`]: Collects all items into a collection
//! - [`StreamExt::collect_into`]: Collects into a caller-supplied collection, reusing its allocation
//! - [`Fold`]: Reduces items into a single value
//! - [`ForEach`]: Executes a closure for each item
//! - [`Count`]: Counts the number of items
//! - [`Any`]: Checks if any item matches a predicate
//! - [`All`]: Checks if all items match a predicate
//!
//! ## Bounded Concurrency
//!
//! These take a [`Cx`](crate::Cx) and run each item as a **region task**, so
//! in-flight work is drained rather than dropped on cancellation or error.
//! Prefer [`BufferUnordered`] when the per-item work is pure and holds no
//! obligation — it is lighter and needs no `Send + 'static` bounds.
//!
//! - [`for_each_concurrent`]: Applies an async function with at most `limit` items in flight
//! - [`try_for_each_concurrent`]: Same, stopping at the first failure and draining the rest
//!
//! ## Error Handling
//! - [`TryCollect`]: Collects items from a stream of Results
//! - [`TryFold`]: Folds a stream of Results
//! - [`TryForEach`]: Executes a fallible closure for each item
//!
//! # Examples
//!
//! ```ignore
//! use asupersync::stream::{iter, StreamExt};
//!
//! async fn example() {
//!     let sum = iter(vec![1, 2, 3, 4, 5])
//!         .filter(|x| *x % 2 == 0)
//!         .map(|x| x * 2)
//!         .fold(0, |acc, x| acc + x)
//!         .await;
//!     assert_eq!(sum, 12); // (2*2) + (4*2) = 12
//! }
//! ```

/// Redacted, deterministic pressure telemetry for future-buffering stream
/// combinators.
///
/// The caller supplies `combinator_id`, so the runtime does not need ambient
/// global registration — the same rule as
/// [`SyncTelemetrySnapshot`](crate::sync::SyncTelemetrySnapshot). Snapshots
/// report only aggregate pressure and lifecycle state, never item values.
///
/// # Determinism
///
/// Every field is derived from combinator state that the polling schedule fully
/// determines. Under the lab runtime, the same seed therefore produces the same
/// sequence of snapshots at the same observation points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTelemetrySnapshot {
    /// Caller-provided stable combinator identifier.
    pub combinator_id: u64,
    /// Combinator kind: `"buffered"`, `"buffer_unordered"`, or `"try_buffered"`.
    pub combinator_kind: &'static str,
    /// Maximum number of futures the combinator will run concurrently.
    pub limit: usize,
    /// Futures currently admitted and not yet yielded.
    pub in_flight: usize,
    /// Slots immediately available for new admissions.
    pub available: usize,
    /// Completed results parked behind head-of-line ordering: futures that
    /// have resolved but whose output cannot be yielded yet because an earlier
    /// future is still pending. Structurally zero for `buffer_unordered`,
    /// which yields completions immediately.
    pub ready_results: usize,
    /// Monotonic count of distinct polling-task wakers observed. Rapid growth
    /// is the waker-churn signal: the combinator is being moved between tasks
    /// or executors instead of being polled from a stable home.
    pub waker_epoch: u64,
    /// Whether the combinator will admit no further futures: the source is
    /// exhausted, or (for `try_buffered`) the stream already yielded its
    /// terminal `Err`.
    pub closed: bool,
}

mod any_all;
mod broadcast_stream;
mod buffered;
mod chain;
mod chunks;
mod collect;
mod count;
mod debounce;
mod enumerate;
mod filter;
mod fold;
mod for_each;
mod for_each_concurrent;
mod forward;
mod fuse;
mod inspect;
mod iter;
mod map;
mod merge;
mod next;
mod partition;
mod peekable;
mod receiver_stream;
mod scan;
mod skip;
mod stream;
mod take;
mod then;
mod throttle;
mod try_buffered;
mod try_stream;
mod watch_stream;
mod zip;

pub use any_all::{All, Any};
pub use broadcast_stream::{BroadcastStream, BroadcastStreamRecvError};
pub use buffered::{BufferUnordered, Buffered};
pub use chain::Chain;
pub use chunks::{Chunks, ReadyChunks};
pub use collect::Collect;
pub use count::Count;
pub use debounce::Debounce;
pub use enumerate::Enumerate;
pub use filter::{Filter, FilterMap};
pub use fold::Fold;
pub use for_each::{ForEach, ForEachAsync};
pub use for_each_concurrent::{for_each_concurrent, try_for_each_concurrent};
pub use forward::{SinkStream, forward, into_sink};
pub use fuse::Fuse;
pub use inspect::Inspect;
pub use iter::{Iter, iter};
pub use map::Map;
pub use merge::{Merge, merge};
pub use next::Next;
pub use partition::{Partition, partition};
pub use peekable::Peekable;
pub use receiver_stream::ReceiverStream;
pub use scan::Scan;
pub use skip::{Skip, SkipWhile};
pub use stream::Stream;
pub use take::{Take, TakeWhile};
pub use then::Then;
pub use throttle::Throttle;
pub use try_buffered::TryBuffered;
pub use try_stream::{TryCollect, TryFold, TryForEach, TryStreamError};
pub use watch_stream::WatchStream;
pub use zip::Zip;

use std::future::Future;
use std::time::Duration;

/// Extension trait providing combinator methods for streams.
///
/// This trait is automatically implemented for all types that implement [`Stream`].
pub trait StreamExt: Stream {
    /// Returns the next item from the stream.
    fn next(&mut self) -> Next<'_, Self>
    where
        Self: Unpin,
    {
        Next::new(self)
    }

    /// Transforms each item using a closure.
    fn map<T, F>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> T,
    {
        Map::new(self, f)
    }

    /// Transforms each item using an async closure.
    fn then<Fut, F>(self, f: F) -> Then<Self, Fut, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Fut,
        Fut: Future,
    {
        Then::new(self, f)
    }

    /// Chains this stream with another stream.
    fn chain<S2>(self, other: S2) -> Chain<Self, S2>
    where
        Self: Sized,
        S2: Stream<Item = Self::Item>,
    {
        Chain::new(self, other)
    }

    /// Interleaves this stream with another stream of the same concrete type.
    ///
    /// For heterogeneous stream types, use [`chain`](Self::chain), [`zip`](Self::zip),
    /// or the free [`merge`] function with an iterator of streams.
    fn merge(self, other: Self) -> Merge<Self>
    where
        Self: Sized,
    {
        merge([self, other])
    }

    /// Zips this stream with another stream, yielding pairs.
    fn zip<S2>(self, other: S2) -> Zip<Self, S2>
    where
        Self: Sized,
        S2: Stream,
    {
        Zip::new(self, other)
    }

    /// Yields only items that match the predicate.
    fn filter<P>(self, predicate: P) -> Filter<Self, P>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        Filter::new(self, predicate)
    }

    /// Filters and transforms items in one step.
    fn filter_map<T, F>(self, f: F) -> FilterMap<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Option<T>,
    {
        FilterMap::new(self, f)
    }

    /// Splits this stream into two by `predicate`.
    ///
    /// The first returned stream yields items for which `predicate` returned
    /// `true`, the second yields the rest. Each item is delivered to exactly
    /// one half; the predicate runs once per item.
    ///
    /// `lane_capacity` bounds how many items may be buffered for the half that
    /// is not currently being polled. Once that buffer is full, the polling
    /// half stalls until its peer drains — so **both halves must be consumed**,
    /// or the unwanted one dropped. See [`partition`] for the full backpressure
    /// and wakeup contract.
    ///
    /// # Panics
    ///
    /// Panics if `lane_capacity` is zero.
    fn partition<P>(
        self,
        predicate: P,
        lane_capacity: usize,
    ) -> (Partition<Self, P>, Partition<Self, P>)
    where
        Self: Sized + Unpin,
        P: FnMut(&Self::Item) -> bool,
    {
        partition(self, predicate, lane_capacity)
    }

    /// Takes the first `n` items.
    fn take(self, n: usize) -> Take<Self>
    where
        Self: Sized,
    {
        Take::new(self, n)
    }

    /// Takes items while the predicate is true.
    fn take_while<P>(self, predicate: P) -> TakeWhile<Self, P>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        TakeWhile::new(self, predicate)
    }

    /// Skips the first `n` items.
    fn skip(self, n: usize) -> Skip<Self>
    where
        Self: Sized,
    {
        Skip::new(self, n)
    }

    /// Skips items while the predicate is true.
    fn skip_while<P>(self, predicate: P) -> SkipWhile<Self, P>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        SkipWhile::new(self, predicate)
    }

    /// Enumerates items with their index.
    fn enumerate(self) -> Enumerate<Self>
    where
        Self: Sized,
    {
        Enumerate::new(self)
    }

    /// Fuses the stream to handle None gracefully.
    fn fuse(self) -> Fuse<Self>
    where
        Self: Sized,
    {
        Fuse::new(self)
    }

    /// Inspects items without modifying the stream.
    fn inspect<F>(self, f: F) -> Inspect<Self, F>
    where
        Self: Sized,
        F: FnMut(&Self::Item),
    {
        Inspect::new(self, f)
    }

    /// Buffers up to `n` futures, preserving output order.
    fn buffered(self, n: usize) -> Buffered<Self>
    where
        Self: Sized,
        Self::Item: std::future::Future,
    {
        Buffered::new(self, n)
    }

    /// Buffers up to `n` futures, yielding results as they complete.
    fn buffer_unordered(self, n: usize) -> BufferUnordered<Self>
    where
        Self: Sized,
        Self::Item: std::future::Future,
    {
        BufferUnordered::new(self, n)
    }

    /// Buffers up to `n` fallible futures in order, stopping at the first `Err`.
    ///
    /// Outputs are yielded in **source order**, so the terminating error is the
    /// first `Err` in the source sequence rather than the first to complete.
    /// That makes the outcome independent of completion timing.
    ///
    /// In-flight futures are dropped when the stream short-circuits; they are
    /// plain futures, not region tasks. Use
    /// [`try_for_each_concurrent`] when the per-item work
    /// holds obligations and must be drained instead of dropped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::stream::{iter, StreamExt};
    ///
    /// async fn first_four(jobs: Vec<Job>) -> Result<Vec<Out>, Error> {
    ///     // 4 jobs run at once; results arrive in job order, and the first
    ///     // failing job in that order ends the stream.
    ///     iter(jobs).map(run).try_buffered(4).try_collect().await
    /// }
    /// # struct Job; struct Out; struct Error;
    /// # async fn run(_j: Job) -> Result<Out, Error> { unimplemented!() }
    /// ```
    fn try_buffered(self, n: usize) -> TryBuffered<Self>
    where
        Self: Sized,
        Self::Item: std::future::Future,
    {
        TryBuffered::new(self, n)
    }

    /// Collects all items into a collection.
    fn collect<C>(self) -> Collect<Self, C>
    where
        Self: Sized,
        C: Default + Extend<Self::Item>,
    {
        Collect::new(self, C::default())
    }

    /// Collects all items into `collection`, reusing its existing allocation.
    ///
    /// This is [`collect`](Self::collect) with a caller-supplied starting
    /// collection instead of `C::default()`. Use it to append to an existing
    /// buffer, or to recycle one allocation across repeated drains rather than
    /// allocating a fresh collection each time.
    ///
    /// Items already present in `collection` are preserved; stream items are
    /// appended via [`Extend`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::stream::{iter, StreamExt};
    ///
    /// async fn drain_into(buf: Vec<i32>) -> Vec<i32> {
    ///     // Reuses `buf`'s allocation instead of allocating a fresh Vec, and
    ///     // appends after whatever it already held.
    ///     iter(vec![4, 5, 6]).collect_into(buf).await
    /// }
    /// ```
    fn collect_into<C>(self, collection: C) -> Collect<Self, C>
    where
        Self: Sized,
        C: Default + Extend<Self::Item>,
    {
        Collect::new(self, collection)
    }

    /// Collects items into fixed-size chunks.
    fn chunks(self, size: usize) -> Chunks<Self>
    where
        Self: Sized,
    {
        Chunks::new(self, size)
    }

    /// Yields immediately available items up to a maximum chunk size.
    fn ready_chunks(self, size: usize) -> ReadyChunks<Self>
    where
        Self: Sized,
    {
        ReadyChunks::new(self, size)
    }

    /// Folds all items into a single value.
    fn fold<Acc, F>(self, init: Acc, f: F) -> Fold<Self, F, Acc>
    where
        Self: Sized,
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        Fold::new(self, init, f)
    }

    /// Executes a closure for each item.
    fn for_each<F>(self, f: F) -> ForEach<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item),
    {
        ForEach::new(self, f)
    }

    /// Executes an async closure for each item.
    fn for_each_async<F, Fut>(self, f: F) -> ForEachAsync<Self, F, Fut>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Fut,
        Fut: Future<Output = ()>,
    {
        ForEachAsync::new(self, f)
    }

    /// Counts the number of items in the stream.
    fn count(self) -> Count<Self>
    where
        Self: Sized,
    {
        Count::new(self)
    }

    /// Checks if any item matches the predicate.
    fn any<P>(self, predicate: P) -> Any<Self, P>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        Any::new(self, predicate)
    }

    /// Checks if all items match the predicate.
    fn all<P>(self, predicate: P) -> All<Self, P>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        All::new(self, predicate)
    }

    /// Collects items from a stream of Results, short-circuiting on error.
    fn try_collect<T, E, C>(self) -> TryCollect<Self, C>
    where
        Self: Stream<Item = Result<T, E>> + Sized,
        C: Default + Extend<T>,
    {
        TryCollect::new(self, C::default())
    }

    /// Folds a stream of Results, short-circuiting on error.
    fn try_fold<T, E, Acc, F>(self, init: Acc, f: F) -> TryFold<Self, F, Acc>
    where
        Self: Stream<Item = Result<T, E>> + Sized,
        F: FnMut(Acc, T) -> Result<Acc, E>,
    {
        TryFold::new(self, init, f)
    }

    /// Executes a fallible closure for each item, short-circuiting on error.
    fn try_for_each<F, E>(self, f: F) -> TryForEach<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Result<(), E>,
    {
        TryForEach::new(self, f)
    }

    /// Yields intermediate accumulator values, like [`Iterator::scan`].
    ///
    /// For each item, calls `f(&mut state, item)`. If `f` returns
    /// `Some(value)`, the value is yielded. If `f` returns `None`,
    /// the stream terminates.
    fn scan<St, B, F>(self, initial_state: St, f: F) -> Scan<Self, St, F>
    where
        Self: Sized,
        F: FnMut(&mut St, Self::Item) -> Option<B>,
    {
        Scan::new(self, initial_state, f)
    }

    /// Creates a peekable stream that supports looking at the next
    /// item without consuming it.
    fn peekable(self) -> Peekable<Self>
    where
        Self: Sized,
    {
        Peekable::new(self)
    }

    /// Rate-limits the stream to at most one item per `period`.
    ///
    /// The first item passes through immediately. Subsequent items
    /// that arrive within the suppression window are dropped.
    fn throttle(self, period: Duration) -> Throttle<Self>
    where
        Self: Sized,
    {
        Throttle::new(self, period)
    }

    /// Debounces the stream, emitting only after a quiet period.
    ///
    /// When items arrive, they are buffered. If no new item arrives
    /// for `period`, the most recent item is yielded. When the
    /// underlying stream ends, any buffered item is flushed immediately.
    fn debounce(self, period: Duration) -> Debounce<Self>
    where
        Self: Sized,
        Self::Item: Unpin,
    {
        Debounce::new(self, period)
    }
}

// Blanket implementation for all Stream types
impl<S: Stream + ?Sized> StreamExt for S {}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::channel::{broadcast, mpsc, watch};
    use crate::cx::Cx;
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::Pin;

    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn stream_ext_chaining() {
        init_test("stream_ext_chaining");

        // Test that combinators can be chained
        let stream = iter(vec![1i32, 2, 3, 4, 5, 6])
            .filter(|&x: &i32| x % 2 == 0)
            .map(|x: i32| x * 10);

        let mut collect = stream.collect::<Vec<_>>();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut collect).poll(&mut cx) {
            Poll::Ready(result) => {
                let ok = result == vec![20, 40, 60];
                crate::assert_with_log!(ok, "collected", vec![20, 40, 60], result);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("stream_ext_chaining");
    }

    #[test]
    fn stream_ext_fold_chain() {
        init_test("stream_ext_fold_chain");

        let stream = iter(vec![1i32, 2, 3, 4, 5]).map(|x: i32| x * 2);

        let mut fold = stream.fold(0i32, |acc, x| acc + x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut fold).poll(&mut cx) {
            Poll::Ready(sum) => {
                let ok = sum == 30;
                crate::assert_with_log!(ok, "sum", 30, sum);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("stream_ext_fold_chain");
    }

    #[test]
    fn test_stream_next() {
        init_test("test_stream_next");
        let mut stream = iter(vec![1, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "next 1",
            Poll::Ready(Some(1)),
            poll
        );

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "next 2",
            Poll::Ready(Some(2)),
            poll
        );

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "next 3",
            Poll::Ready(Some(3)),
            poll
        );

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "next done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_next");
    }

    #[test]
    fn test_stream_map() {
        init_test("test_stream_map");
        let stream = iter(vec![1, 2, 3]);
        let mut mapped = stream.map(|x| x * 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "map 1",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(4)),
            "map 2",
            Poll::Ready(Some(4)),
            poll
        );
        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(6)),
            "map 3",
            Poll::Ready(Some(6)),
            poll
        );
        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "map done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_map");
    }

    #[test]
    fn test_stream_filter() {
        init_test("test_stream_filter");
        let stream = iter(vec![1, 2, 3, 4, 5, 6]);
        let mut filtered = stream.filter(|x| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "filter 1",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(4)),
            "filter 2",
            Poll::Ready(Some(4)),
            poll
        );
        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(6)),
            "filter 3",
            Poll::Ready(Some(6)),
            poll
        );
        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "filter done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_filter");
    }

    #[test]
    fn test_stream_filter_map() {
        init_test("test_stream_filter_map");
        let stream = iter(vec!["1", "two", "3", "four"]);
        let mut parsed = stream.filter_map(|s| s.parse::<i32>().ok());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut parsed).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "filter_map 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut parsed).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "filter_map 2",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut parsed).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "filter_map done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_filter_map");
    }

    #[test]
    fn test_stream_take() {
        init_test("test_stream_take");
        let stream = iter(vec![1, 2, 3, 4, 5]);
        let mut taken = stream.take(3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "take 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "take 2",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "take 3",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "take done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_take");
    }

    #[test]
    fn test_stream_skip() {
        init_test("test_stream_skip");
        let stream = iter(vec![1, 2, 3, 4, 5]);
        let mut skipped = stream.skip(2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "skip 1",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(4)),
            "skip 2",
            Poll::Ready(Some(4)),
            poll
        );
        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(5)),
            "skip 3",
            Poll::Ready(Some(5)),
            poll
        );
        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "skip done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_skip");
    }

    #[test]
    fn test_stream_enumerate() {
        init_test("test_stream_enumerate");
        let stream = iter(vec!["a", "b", "c"]);
        let mut enumerated = stream.enumerate();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some((0, "a"))),
            "enum 0",
            Poll::Ready(Some((0, "a"))),
            poll
        );
        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some((1, "b"))),
            "enum 1",
            Poll::Ready(Some((1, "b"))),
            poll
        );
        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some((2, "c"))),
            "enum 2",
            Poll::Ready(Some((2, "c"))),
            poll
        );
        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<(usize, &str)>),
            "enum done",
            Poll::Ready(None::<(usize, &str)>),
            poll
        );
        crate::test_complete!("test_stream_enumerate");
    }

    #[test]
    fn test_stream_then() {
        init_test("test_stream_then");
        // We need a runtime or manual polling for async map.
        // But Then combinator returns a Stream.
        // We can poll it manually.

        let stream = iter(vec![1, 2]);
        let mut processed = Box::pin(stream.then(|x| async move { x * 10 }));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item
        let poll = processed.as_mut().poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(10)));
        crate::assert_with_log!(ok, "then 1", "Poll::Ready(Some(10))", poll);

        // Second item
        let poll = processed.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(20)),
            "then 2",
            Poll::Ready(Some(20)),
            poll
        );

        // End
        let poll = processed.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "then done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_then");
    }

    #[test]
    fn test_stream_inspect() {
        init_test("test_stream_inspect");
        let stream = iter(vec![1, 2, 3]);
        let items = RefCell::new(Vec::new());
        let mut inspected = stream.inspect(|x| items.borrow_mut().push(*x));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "inspect 1",
            Poll::Ready(Some(1)),
            poll
        );
        let items_now = items.borrow().clone();
        crate::assert_with_log!(items_now == vec![1], "items", vec![1], items_now);

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "inspect 2",
            Poll::Ready(Some(2)),
            poll
        );
        let items_now = items.borrow().clone();
        crate::assert_with_log!(items_now == vec![1, 2], "items", vec![1, 2], items_now);

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "inspect 3",
            Poll::Ready(Some(3)),
            poll
        );
        let items_now = items.borrow().clone();
        crate::assert_with_log!(
            items_now == vec![1, 2, 3],
            "items",
            vec![1, 2, 3],
            items_now
        );

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "inspect done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_inspect");
    }

    #[test]
    fn test_receiver_stream() {
        init_test("test_receiver_stream");

        let cx: Cx = Cx::for_testing();
        let (tx, rx) = mpsc::channel(10);
        let mut stream = ReceiverStream::new(cx, rx);

        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        drop(tx);

        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "recv 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "recv 2",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "recv done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_receiver_stream");
    }

    #[test]
    fn test_watch_stream() {
        init_test("test_watch_stream");

        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let mut stream = WatchStream::new(cx, rx);
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        // Initial value
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(0)),
            "watch 0",
            Poll::Ready(Some(0)),
            poll
        );

        // Update value
        tx.send(1).unwrap();
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "watch 1",
            Poll::Ready(Some(1)),
            poll
        );
        crate::test_complete!("test_watch_stream");
    }

    #[test]
    fn test_broadcast_stream() {
        init_test("test_broadcast_stream");

        let cx: Cx = Cx::for_testing();
        let (tx, rx) = broadcast::channel(10);
        let mut stream = BroadcastStream::new(cx.clone(), rx);
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();

        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(1))),
            "broadcast 1",
            Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(1))),
            poll
        );
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(2))),
            "broadcast 2",
            Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(2))),
            poll
        );
        crate::test_complete!("test_broadcast_stream");
    }

    #[test]
    fn test_forward() {
        init_test("test_forward");

        let cx: Cx = Cx::for_testing();
        let (tx_out, rx_out) = mpsc::channel(10);
        let input = iter(vec![1, 2, 3]);

        futures_lite::future::block_on(async {
            forward(&cx, input, tx_out).await.unwrap();
        });

        let mut output = ReceiverStream::new(cx, rx_out);
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "forward 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "forward 2",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "forward 3",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "forward done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_forward");
    }

    #[test]
    fn test_stream_merge_method() {
        init_test("test_stream_merge_method");

        let mut merged = iter(vec![1, 2, 3]).merge(iter(vec![10, 20, 30]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "merge first",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(10)),
            "merge second",
            Poll::Ready(Some(10)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "merge third",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(20)),
            "merge fourth",
            Poll::Ready(Some(20)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "merge fifth",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(30)),
            "merge sixth",
            Poll::Ready(Some(30)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "merge done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_merge_method");
    }
}
