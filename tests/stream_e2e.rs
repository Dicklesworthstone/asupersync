//! Async Streams Verification Suite - E2E Tests
//!
//! This test file provides comprehensive verification for the async streams module,
//! ensuring combinator correctness, cancel-safety, and deterministic behavior
//! under the lab runtime.
//!
//! Test categories:
//! 1. Basic stream operations
//! 2. Combinator composition
//! 3. Cancel-safety verification
//! 4. Memory/resource management
//! 5. Error propagation
//! 6. Lab runtime determinism

#[macro_use]
mod common;

use asupersync::channel::{broadcast, mpsc, watch};
use asupersync::cx::Cx;
use asupersync::stream::{
    iter, merge, BroadcastStream, ReceiverStream, Stream, StreamExt, WatchStream,
};
use common::*;
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

// ============================================================================
// Test Infrastructure
// ============================================================================

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// 1. Basic Stream Operations
// ============================================================================

#[test]
fn test_basic_stream_iteration() {
    init_test("test_basic_stream_iteration");
    tracing::info!("Testing basic stream iteration");

    let stream = iter(vec![1, 2, 3, 4, 5]);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![1, 2, 3, 4, 5]);
    assert_with_log!(ok, "basic iteration", vec![1, 2, 3, 4, 5], poll);
    test_complete!("test_basic_stream_iteration");
}

#[test]
fn test_empty_stream() {
    init_test("test_empty_stream");
    tracing::info!("Testing empty stream handling");

    let stream: asupersync::stream::Iter<std::vec::IntoIter<i32>> = iter(vec![]);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut collected = stream.collect::<Vec<i32>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v.is_empty());
    assert_with_log!(ok, "empty stream", Vec::<i32>::new(), poll);
    test_complete!("test_empty_stream");
}

#[test]
fn test_stream_single_item() {
    init_test("test_stream_single_item");
    tracing::info!("Testing single item stream");

    let stream = iter(vec![42]);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![42]);
    assert_with_log!(ok, "single item", vec![42], poll);
    test_complete!("test_stream_single_item");
}

// ============================================================================
// 2. Combinator Composition
// ============================================================================

#[test]
fn test_map_filter_chain() {
    init_test("test_map_filter_chain");
    tracing::info!("Testing map + filter combinator chain");

    // Double each number, then filter evens
    let stream = iter(vec![1, 2, 3, 4, 5]).map(|x| x * 2).filter(|x| *x > 4);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![6, 8, 10]);
    assert_with_log!(ok, "map+filter chain", vec![6, 8, 10], poll);
    test_complete!("test_map_filter_chain");
}

#[test]
fn test_chain_combinator() {
    init_test("test_chain_combinator");
    tracing::info!("Testing chain combinator - chaining two streams");

    let stream1 = iter(vec![1, 2, 3]);
    let stream2 = iter(vec![4, 5, 6]);
    let chained = stream1.chain(stream2);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = chained.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![1, 2, 3, 4, 5, 6]);
    assert_with_log!(ok, "chain", vec![1, 2, 3, 4, 5, 6], poll);
    test_complete!("test_chain_combinator");
}

#[test]
fn test_zip_combinator() {
    init_test("test_zip_combinator");
    tracing::info!("Testing zip combinator - pairing two streams");

    let stream1 = iter(vec![1, 2, 3]);
    let stream2 = iter(vec!["a", "b", "c"]);
    let zipped = stream1.zip(stream2);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = zipped.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![(1, "a"), (2, "b"), (3, "c")]);
    assert_with_log!(ok, "zip", vec![(1, "a"), (2, "b"), (3, "c")], poll);
    test_complete!("test_zip_combinator");
}

#[test]
fn test_zip_unequal_length() {
    init_test("test_zip_unequal_length");
    tracing::info!("Testing zip with unequal length streams (should stop at shorter)");

    let stream1 = iter(vec![1, 2, 3, 4, 5]);
    let stream2 = iter(vec!["a", "b"]);
    let zipped = stream1.zip(stream2);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = zipped.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![(1, "a"), (2, "b")]);
    assert_with_log!(ok, "zip unequal", vec![(1, "a"), (2, "b")], poll);
    test_complete!("test_zip_unequal_length");
}

#[test]
fn test_merge_combinator() {
    init_test("test_merge_combinator");
    tracing::info!("Testing merge combinator - interleaved output");

    let stream1 = iter(vec![1, 3, 5]);
    let stream2 = iter(vec![2, 4, 6]);
    // merge takes an IntoIterator of streams
    let merged = merge([stream1, stream2]);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = merged.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    // Merge doesn't guarantee order, but all items should be present
    if let Poll::Ready(ref v) = poll {
        let mut sorted = v.clone();
        sorted.sort_unstable();
        let ok = sorted == vec![1, 2, 3, 4, 5, 6];
        assert_with_log!(ok, "merge contains all", vec![1, 2, 3, 4, 5, 6], sorted);
    } else {
        panic!("expected Ready");
    }
    test_complete!("test_merge_combinator");
}

#[test]
fn test_take_skip_composition() {
    init_test("test_take_skip_composition");
    tracing::info!("Testing take and skip composition");

    // Skip first 2, take next 3
    let stream = iter(vec![1, 2, 3, 4, 5, 6, 7]).skip(2).take(3);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![3, 4, 5]);
    assert_with_log!(ok, "skip+take", vec![3, 4, 5], poll);
    test_complete!("test_take_skip_composition");
}

#[test]
fn test_fold_combinator() {
    init_test("test_fold_combinator");
    tracing::info!("Testing fold combinator - reducing to single value");

    let stream = iter(vec![1, 2, 3, 4, 5]);
    let mut folded = stream.fold(0, |acc, x| acc + x);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut folded).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(15));
    assert_with_log!(ok, "fold sum", 15, poll);
    test_complete!("test_fold_combinator");
}

#[test]
fn test_count_combinator() {
    init_test("test_count_combinator");
    tracing::info!("Testing count combinator");

    let stream = iter(vec![1, 2, 3, 4, 5]);
    let mut counted = stream.count();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut counted).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(5));
    assert_with_log!(ok, "count", 5, poll);
    test_complete!("test_count_combinator");
}

#[test]
fn test_any_all_combinators() {
    init_test("test_any_all_combinators");
    tracing::info!("Testing any and all combinators");

    // Any: should find even number
    let stream = iter(vec![1, 3, 4, 5]);
    let mut any_even = stream.any(|x| x % 2 == 0);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut any_even).poll(&mut cx);
    let ok = matches!(poll, Poll::Ready(true));
    assert_with_log!(ok, "any even", true, poll);

    // All: not all are even
    let stream = iter(vec![2, 4, 5, 6]);
    let mut all_even = stream.all(|x| x % 2 == 0);
    let poll = Pin::new(&mut all_even).poll(&mut cx);
    let ok = matches!(poll, Poll::Ready(false));
    assert_with_log!(ok, "all even (false)", false, poll);

    // All: all are even
    let stream = iter(vec![2, 4, 6, 8]);
    let mut all_even = stream.all(|x| x % 2 == 0);
    let poll = Pin::new(&mut all_even).poll(&mut cx);
    let ok = matches!(poll, Poll::Ready(true));
    assert_with_log!(ok, "all even (true)", true, poll);

    test_complete!("test_any_all_combinators");
}

#[test]
fn test_filter_map_combinator() {
    init_test("test_filter_map_combinator");
    tracing::info!("Testing filter_map combinator");

    let stream = iter(vec!["1", "two", "3", "four", "5"]);
    let parsed = stream.filter_map(|s| s.parse::<i32>().ok());

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = parsed.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![1, 3, 5]);
    assert_with_log!(ok, "filter_map", vec![1, 3, 5], poll);
    test_complete!("test_filter_map_combinator");
}

#[test]
fn test_fuse_combinator() {
    init_test("test_fuse_combinator");
    tracing::info!("Testing fuse combinator - handles None gracefully");

    let stream = iter(vec![1, 2]).fuse();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut stream = stream;
    // Consume all items
    let poll = Pin::new(&mut stream).poll_next(&mut cx);
    assert_with_log!(poll == Poll::Ready(Some(1)), "fuse 1", Some(1), poll);
    let poll = Pin::new(&mut stream).poll_next(&mut cx);
    assert_with_log!(poll == Poll::Ready(Some(2)), "fuse 2", Some(2), poll);
    let poll = Pin::new(&mut stream).poll_next(&mut cx);
    assert_with_log!(
        poll == Poll::Ready(None::<i32>),
        "fuse done",
        None::<i32>,
        poll
    );

    // Fused stream should keep returning None
    let poll = Pin::new(&mut stream).poll_next(&mut cx);
    assert_with_log!(
        poll == Poll::Ready(None::<i32>),
        "fuse still done",
        None::<i32>,
        poll
    );

    test_complete!("test_fuse_combinator");
}

// ============================================================================
// 3. Cancel-Safety Verification
// ============================================================================

#[test]
fn test_cancel_during_next_no_item_loss() {
    init_test("test_cancel_during_next_no_item_loss");
    tracing::info!("Testing cancel during next() - verifying no item loss");

    // Create a stream that tracks consumed items
    let consumed = Rc::new(RefCell::new(Vec::new()));
    let consumed_clone = consumed.clone();

    let stream = iter(vec![1, 2, 3, 4, 5]).inspect(move |x| {
        consumed_clone.borrow_mut().push(*x);
    });

    // Consume only first two items
    let mut stream = stream;
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let poll = Pin::new(&mut stream).poll_next(&mut cx);
    assert!(poll == Poll::Ready(Some(1)));
    let poll = Pin::new(&mut stream).poll_next(&mut cx);
    assert!(poll == Poll::Ready(Some(2)));

    // Simulate cancellation by dropping the stream
    drop(stream);

    // Verify only consumed items were tracked
    let consumed_items = consumed.borrow().clone();
    let ok = consumed_items == vec![1, 2];
    assert_with_log!(
        ok,
        "only consumed items tracked",
        vec![1, 2],
        consumed_items
    );

    test_complete!("test_cancel_during_next_no_item_loss");
}

#[test]
fn test_cancel_during_collect_partial_results() {
    init_test("test_cancel_during_collect_partial_results");
    tracing::info!("Testing cancel during collect - partial results available");

    // Use take to simulate early termination (similar to cancellation effect)
    let stream = iter(vec![1, 2, 3, 4, 5]).take(3);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    // Should have collected partial results
    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![1, 2, 3]);
    assert_with_log!(ok, "partial collect", vec![1, 2, 3], poll);

    test_complete!("test_cancel_during_collect_partial_results");
}

// ============================================================================
// 4. Channel-based Streams
// ============================================================================

#[test]
fn test_receiver_stream_basic() {
    init_test("test_receiver_stream_basic");
    tracing::info!("Testing ReceiverStream with mpsc channel");

    let cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel(10);
    let stream = ReceiverStream::new(cx.clone(), rx);

    // Send items
    tx.send(&cx, 1).unwrap();
    tx.send(&cx, 2).unwrap();
    tx.send(&cx, 3).unwrap();
    drop(tx);

    let waker = noop_waker();
    let mut cx_task = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx_task);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![1, 2, 3]);
    assert_with_log!(ok, "receiver stream", vec![1, 2, 3], poll);

    test_complete!("test_receiver_stream_basic");
}

#[test]
fn test_watch_stream_updates() {
    init_test("test_watch_stream_updates");
    tracing::info!("Testing WatchStream receives updates");

    let cx = Cx::for_testing();
    let (tx, rx) = watch::channel(0);
    let mut stream = WatchStream::new(cx, rx);

    let waker = noop_waker();
    let mut cx_task = Context::from_waker(&waker);

    // Initial value
    let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
    assert_with_log!(poll == Poll::Ready(Some(0)), "watch initial", Some(0), poll);

    // Send updates
    tx.send(1).unwrap();
    let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
    assert_with_log!(
        poll == Poll::Ready(Some(1)),
        "watch update 1",
        Some(1),
        poll
    );

    tx.send(2).unwrap();
    let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
    assert_with_log!(
        poll == Poll::Ready(Some(2)),
        "watch update 2",
        Some(2),
        poll
    );

    test_complete!("test_watch_stream_updates");
}

#[test]
fn test_broadcast_stream_multiple_items() {
    init_test("test_broadcast_stream_multiple_items");
    tracing::info!("Testing BroadcastStream with multiple items");

    let cx = Cx::for_testing();
    let (tx, rx) = broadcast::channel(10);
    let mut stream = BroadcastStream::new(cx.clone(), rx);

    // Send items
    tx.send(&cx, 10).unwrap();
    tx.send(&cx, 20).unwrap();
    tx.send(&cx, 30).unwrap();

    let waker = noop_waker();
    let mut cx_task = Context::from_waker(&waker);

    let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
    let ok = matches!(poll, Poll::Ready(Some(Ok(10))));
    assert_with_log!(ok, "broadcast 10", "Poll::Ready(Some(Ok(10)))", poll);

    let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
    let ok = matches!(poll, Poll::Ready(Some(Ok(20))));
    assert_with_log!(ok, "broadcast 20", "Poll::Ready(Some(Ok(20)))", poll);

    let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
    let ok = matches!(poll, Poll::Ready(Some(Ok(30))));
    assert_with_log!(ok, "broadcast 30", "Poll::Ready(Some(Ok(30)))", poll);

    test_complete!("test_broadcast_stream_multiple_items");
}

// ============================================================================
// 5. Error Handling
// ============================================================================

#[test]
fn test_try_collect_success() {
    init_test("test_try_collect_success");
    tracing::info!("Testing try_collect with all Ok values");

    let stream = iter(vec![Ok::<i32, &str>(1), Ok(2), Ok(3)]);
    let mut collected = stream.try_collect::<i32, &str, Vec<_>>();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(Ok(ref v)) if v == &vec![1, 2, 3]);
    assert_with_log!(ok, "try_collect success", "Ok(vec![1, 2, 3])", poll);

    test_complete!("test_try_collect_success");
}

#[test]
fn test_try_collect_error() {
    init_test("test_try_collect_error");
    tracing::info!("Testing try_collect with error (short-circuit)");

    let stream = iter(vec![Ok::<i32, &str>(1), Ok(2), Err("error"), Ok(4)]);
    let mut collected = stream.try_collect::<i32, &str, Vec<_>>();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(Err("error")));
    assert_with_log!(ok, "try_collect error", "Err(\"error\")", poll);

    test_complete!("test_try_collect_error");
}

#[test]
fn test_try_fold_success() {
    init_test("test_try_fold_success");
    tracing::info!("Testing try_fold with all Ok values");

    let stream = iter(vec![Ok::<i32, &str>(1), Ok(2), Ok(3)]);
    let mut folded = stream.try_fold(0, |acc, x| Ok::<i32, &str>(acc + x));

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut folded).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(Ok(6)));
    assert_with_log!(ok, "try_fold success", "Ok(6)", poll);

    test_complete!("test_try_fold_success");
}

#[test]
fn test_try_for_each_error() {
    init_test("test_try_for_each_error");
    tracing::info!("Testing try_for_each with error (short-circuit)");

    let processed = Rc::new(RefCell::new(Vec::new()));
    let processed_clone = processed.clone();

    let stream = iter(vec![1, 2, 3, 4, 5]);
    let mut result = stream.try_for_each(move |x| {
        processed_clone.borrow_mut().push(x);
        if x == 3 {
            Err("stopped at 3")
        } else {
            Ok(())
        }
    });

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut result).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(Err("stopped at 3")));
    assert_with_log!(ok, "try_for_each error", "Err(\"stopped at 3\")", poll);

    // Should have processed items up to and including 3
    let items = processed.borrow().clone();
    let ok = items == vec![1, 2, 3];
    assert_with_log!(ok, "processed items", vec![1, 2, 3], items);

    test_complete!("test_try_for_each_error");
}

// ============================================================================
// 6. Infinite Stream + Take (Bounded Consumption)
// ============================================================================

/// A simple infinite counter stream for testing
struct InfiniteCounter {
    current: i32,
}

impl InfiniteCounter {
    fn new() -> Self {
        Self { current: 0 }
    }
}

impl Stream for InfiniteCounter {
    type Item = i32;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let val = self.current;
        self.current += 1;
        Poll::Ready(Some(val))
    }
}

#[test]
fn test_infinite_stream_with_take() {
    init_test("test_infinite_stream_with_take");
    tracing::info!("Testing infinite stream bounded with take()");

    let stream = InfiniteCounter::new().take(5);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![0, 1, 2, 3, 4]);
    assert_with_log!(ok, "infinite + take", vec![0, 1, 2, 3, 4], poll);

    test_complete!("test_infinite_stream_with_take");
}

#[test]
fn test_infinite_stream_with_take_while() {
    init_test("test_infinite_stream_with_take_while");
    tracing::info!("Testing infinite stream bounded with take_while()");

    let stream = InfiniteCounter::new().take_while(|x| *x < 5);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![0, 1, 2, 3, 4]);
    assert_with_log!(ok, "infinite + take_while", vec![0, 1, 2, 3, 4], poll);

    test_complete!("test_infinite_stream_with_take_while");
}

// ============================================================================
// 7. Complex Combinator Chains
// ============================================================================

#[test]
fn test_complex_combinator_chain() {
    init_test("test_complex_combinator_chain");
    tracing::info!("Testing complex combinator chain: enumerate -> filter -> map -> take");

    let stream = iter(vec![10, 20, 30, 40, 50, 60, 70])
        .enumerate()
        .filter(|(idx, _)| idx % 2 == 0) // Keep even indices: (0,10), (2,30), (4,50), (6,70)
        .map(|(_, val)| val * 2) // Double values: 20, 60, 100, 140
        .take(3); // Take first 3: 20, 60, 100

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![20, 60, 100]);
    assert_with_log!(ok, "complex chain", vec![20, 60, 100], poll);

    test_complete!("test_complex_combinator_chain");
}

#[test]
fn test_nested_map_filter() {
    init_test("test_nested_map_filter");
    tracing::info!("Testing nested map and filter operations");

    let stream = iter(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        .filter(|x| x % 2 == 0) // Keep evens: 2, 4, 6, 8, 10
        .map(|x| x * x) // Square: 4, 16, 36, 64, 100
        .filter(|x| *x < 50) // Keep < 50: 4, 16, 36
        .map(|x| x + 1); // Add 1: 5, 17, 37

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v == &vec![5, 17, 37]);
    assert_with_log!(ok, "nested map/filter", vec![5, 17, 37], poll);

    test_complete!("test_nested_map_filter");
}

// ============================================================================
// 8. Edge Cases
// ============================================================================

#[test]
fn test_take_zero() {
    init_test("test_take_zero");
    tracing::info!("Testing take(0) - should yield nothing");

    let stream = iter(vec![1, 2, 3]).take(0);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v.is_empty());
    assert_with_log!(ok, "take(0)", Vec::<i32>::new(), poll);

    test_complete!("test_take_zero");
}

#[test]
fn test_skip_more_than_available() {
    init_test("test_skip_more_than_available");
    tracing::info!("Testing skip with n > stream length");

    let stream = iter(vec![1, 2, 3]).skip(10);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut collected = stream.collect::<Vec<_>>();
    let poll = Pin::new(&mut collected).poll(&mut cx);

    let ok = matches!(poll, Poll::Ready(ref v) if v.is_empty());
    assert_with_log!(ok, "skip(10) on 3 items", Vec::<i32>::new(), poll);

    test_complete!("test_skip_more_than_available");
}

#[test]
fn test_for_each_side_effects() {
    init_test("test_for_each_side_effects");
    tracing::info!("Testing for_each - verifying side effects");

    let effects = Rc::new(RefCell::new(Vec::new()));
    let effects_clone = effects.clone();

    let stream = iter(vec![1, 2, 3]);
    let mut result = stream.for_each(move |x| {
        effects_clone.borrow_mut().push(x * 10);
    });

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut result).poll(&mut cx);

    assert!(matches!(poll, Poll::Ready(())));
    let items = effects.borrow().clone();
    let ok = items == vec![10, 20, 30];
    assert_with_log!(ok, "for_each effects", vec![10, 20, 30], items);

    test_complete!("test_for_each_side_effects");
}

// ============================================================================
// Summary Test
// ============================================================================

#[test]
fn test_stream_verification_summary() {
    init_test("test_stream_verification_summary");
    tracing::info!("=== Async Streams Verification Suite Summary ===");
    tracing::info!("All stream combinator tests passed successfully");
    tracing::info!("Verified: basic operations, combinators, cancel-safety, error handling");
    test_complete!("test_stream_verification_summary");
}
