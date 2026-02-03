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
//! ## Buffering
//! - [`Buffered`]: Runs multiple futures while preserving order
//! - [`BufferUnordered`]: Runs multiple futures without ordering guarantees
//! - [`Chunks`]: Groups items into fixed-size batches
//! - [`ReadyChunks`]: Returns immediately available items
//!
//! ## Terminal Operations
//! - [`Collect`]: Collects all items into a collection
//! - [`Fold`]: Reduces items into a single value
//! - [`ForEach`]: Executes a closure for each item
//! - [`Count`]: Counts the number of items
//! - [`Any`]: Checks if any item matches a predicate
//! - [`All`]: Checks if all items match a predicate
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

mod any_all;
mod broadcast_stream;
mod buffered;
mod chain;
mod chunks;
mod collect;
mod count;
mod enumerate;
mod filter;
mod fold;
mod for_each;
mod forward;
mod fuse;
mod inspect;
mod iter;
mod map;
mod merge;
mod next;
mod receiver_stream;
mod skip;
mod stream;
mod take;
mod then;
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
pub use enumerate::Enumerate;
pub use filter::{Filter, FilterMap};
pub use fold::Fold;
pub use for_each::{ForEach, ForEachAsync};
pub use forward::{forward, into_sink, SinkStream};
pub use fuse::Fuse;
pub use inspect::Inspect;
pub use iter::{iter, Iter};
pub use map::Map;
pub use merge::{merge, Merge};
pub use next::Next;
pub use receiver_stream::ReceiverStream;
pub use skip::{Skip, SkipWhile};
pub use stream::Stream;
pub use take::{Take, TakeWhile};
pub use then::Then;
pub use try_stream::{TryCollect, TryFold, TryForEach};
pub use watch_stream::WatchStream;
pub use zip::Zip;

use std::future::Future;

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

    /// Collects all items into a collection.
    fn collect<C>(self) -> Collect<Self, C>
    where
        Self: Sized,
        C: Default + Extend<Self::Item>,
    {
        Collect::new(self, C::default())
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
}

// Blanket implementation for all Stream types
impl<S: Stream + ?Sized> StreamExt for S {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{broadcast, mpsc, watch};
    use crate::cx::Cx;
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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
        let mut processed = stream.then(|x| async move { x * 10 });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item
        let mut next = processed.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(10)));
        crate::assert_with_log!(ok, "then 1", "Poll::Ready(Some(10))", poll);

        // Second item
        let mut next = processed.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(20)),
            "then 2",
            Poll::Ready(Some(20)),
            poll
        );

        // End
        let mut next = processed.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
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
}
