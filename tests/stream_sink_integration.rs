#![allow(clippy::all)]
//! Stream/Sink Integration Tests — E.3
//!
//! End-to-end tests verifying that stream combinator pipelines correctly
//! feed into sinks via `forward()` and `SinkStream::send_all()`, including
//! the E.2 combinators (scan, peekable, throttle, debounce).
//!
//! Test categories:
//! 1. Basic forward() pipeline
//! 2. Combinator chains → forward
//! 3. New E.2 combinators in pipelines (scan, peekable, throttle, debounce)
//! 4. SinkStream::send_all with combinator chains
//! 5. ReceiverStream → combinator → forward round-trip
//! 6. Error propagation through try_* combinators with sinks
//! 7. Multi-stage pipelines (stream → transform → sink → stream → transform)

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::stream::{
    ReceiverStream, SinkStream, Stream, StreamExt, TryStreamError, forward, into_sink, iter,
};
use common::*;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

// ============================================================================
// Test Infrastructure
// ============================================================================

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

/// Helper: collect all items from a stream synchronously.
fn collect_sync<S: Stream + Unpin>(mut stream: S) -> Vec<S::Item> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut items = Vec::new();
    while let Poll::Ready(Some(item)) = Pin::new(&mut stream).poll_next(&mut cx) {
        items.push(item);
    }
    items
}

// ============================================================================
// 1. Basic forward() pipeline
// ============================================================================

#[test]
fn forward_iter_to_channel() {
    init_test("forward_iter_to_channel");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);
    let input = iter(vec![10, 20, 30, 40, 50]);

    futures_lite::future::block_on(async {
        forward(&cx, input, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![10, 20, 30, 40, 50];
    assert_with_log!(
        ok,
        "forward iter→channel",
        vec![10, 20, 30, 40, 50],
        collected
    );
    test_complete!("forward_iter_to_channel");
}

#[test]
fn forward_empty_stream_to_channel() {
    init_test("forward_empty_stream_to_channel");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(4);

    futures_lite::future::block_on(async {
        forward(&cx, iter(Vec::<i32>::new()), tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected.is_empty();
    assert_with_log!(ok, "forward empty", Vec::<i32>::new(), collected);
    test_complete!("forward_empty_stream_to_channel");
}

// ============================================================================
// 2. Combinator chains → forward
// ============================================================================

#[test]
fn forward_filter_map_chain() {
    init_test("forward_filter_map_chain");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // Pipeline: [1..10] → filter(even) → map(*3) → sink
    let pipeline = iter(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        .filter(|x| x % 2 == 0)
        .map(|x| x * 3);

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    // evens: 2,4,6,8,10 → *3: 6,12,18,24,30
    let ok = collected == vec![6, 12, 18, 24, 30];
    assert_with_log!(ok, "filter+map→forward", vec![6, 12, 18, 24, 30], collected);
    test_complete!("forward_filter_map_chain");
}

#[test]
fn forward_take_skip_chain() {
    init_test("forward_take_skip_chain");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // Pipeline: [1..10] → skip(3) → take(4) → sink
    let pipeline = iter(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).skip(3).take(4);

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![4, 5, 6, 7];
    assert_with_log!(ok, "skip+take→forward", vec![4, 5, 6, 7], collected);
    test_complete!("forward_take_skip_chain");
}

#[test]
fn forward_enumerate_filter_map() {
    init_test("forward_enumerate_filter_map");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<String>(16);

    // Pipeline: ["a","b","c","d"] → enumerate → filter(odd idx) → map(format)
    let pipeline = iter(vec!["a", "b", "c", "d"])
        .enumerate()
        .filter(|(idx, _)| idx % 2 == 1) // indices 1, 3
        .map(|(idx, val)| format!("{idx}:{val}"));

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let expected = vec!["1:b".to_string(), "3:d".to_string()];
    let ok = collected == expected;
    assert_with_log!(ok, "enumerate+filter+map→forward", expected, collected);
    test_complete!("forward_enumerate_filter_map");
}

#[test]
fn forward_chain_two_streams() {
    init_test("forward_chain_two_streams");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    let pipeline = iter(vec![1, 2, 3]).chain(iter(vec![4, 5, 6]));

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![1, 2, 3, 4, 5, 6];
    assert_with_log!(ok, "chain→forward", vec![1, 2, 3, 4, 5, 6], collected);
    test_complete!("forward_chain_two_streams");
}

#[test]
fn forward_filter_map_combinator() {
    init_test("forward_filter_map_combinator");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // filter_map: parse strings, keep only valid ints
    let pipeline = iter(vec!["1", "two", "3", "four", "5"]).filter_map(|s| s.parse::<i32>().ok());

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![1, 3, 5];
    assert_with_log!(ok, "filter_map→forward", vec![1, 3, 5], collected);
    test_complete!("forward_filter_map_combinator");
}

// ============================================================================
// 3. E.2 combinators in pipelines (scan, peekable, throttle, debounce)
// ============================================================================

#[test]
fn forward_scan_running_sum() {
    init_test("forward_scan_running_sum");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // scan: running sum [1,2,3,4,5] → [1,3,6,10,15]
    let pipeline = iter(vec![1, 2, 3, 4, 5]).scan(0i32, |acc: &mut i32, x: i32| {
        *acc += x;
        Some(*acc)
    });

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![1, 3, 6, 10, 15];
    assert_with_log!(ok, "scan→forward", vec![1, 3, 6, 10, 15], collected);
    test_complete!("forward_scan_running_sum");
}

#[test]
fn forward_scan_early_termination() {
    init_test("forward_scan_early_termination");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // scan that terminates when accumulator > 5
    let pipeline = iter(vec![1, 2, 3, 4, 5]).scan(0i32, |acc: &mut i32, x: i32| {
        *acc += x;
        if *acc > 5 { None } else { Some(*acc) }
    });

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    // 1→1, 1+2→3, 3+3→6 > 5 → None
    let ok = collected == vec![1, 3];
    assert_with_log!(ok, "scan early term→forward", vec![1, 3], collected);
    test_complete!("forward_scan_early_termination");
}

#[test]
fn scan_then_filter_then_forward() {
    init_test("scan_then_filter_then_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // scan(running sum) → filter(>3) → forward
    let pipeline = iter(vec![1, 2, 3, 4, 5])
        .scan(0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        })
        .filter(|x| *x > 3); // running sums: 1,3,6,10,15 → keep >3: 6,10,15

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![6, 10, 15];
    assert_with_log!(ok, "scan+filter→forward", vec![6, 10, 15], collected);
    test_complete!("scan_then_filter_then_forward");
}

#[test]
fn peekable_consume_all_to_forward() {
    init_test("peekable_consume_all_to_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // Peekable wrapping → peek at first, then forward the rest
    let mut stream = iter(vec![10, 20, 30, 40]).peekable();
    let waker = noop_waker();
    let mut task_cx = Context::from_waker(&waker);

    // Peek at the first item without consuming it.
    let peeked = Pin::new(&mut stream).poll_peek(&mut task_cx);
    let ok = matches!(peeked, Poll::Ready(Some(&10)));
    assert_with_log!(ok, "peek first", "Some(&10)", peeked);

    // Now forward the entire peekable stream (including the peeked item).
    futures_lite::future::block_on(async {
        forward(&cx, stream, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![10, 20, 30, 40];
    assert_with_log!(ok, "peekable→forward", vec![10, 20, 30, 40], collected);
    test_complete!("peekable_consume_all_to_forward");
}

#[test]
fn throttle_zero_duration_forward() {
    init_test("throttle_zero_duration_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // With zero duration, all items pass through.
    let pipeline = iter(vec![1, 2, 3, 4, 5]).throttle(Duration::ZERO);

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![1, 2, 3, 4, 5];
    assert_with_log!(ok, "throttle(0)→forward", vec![1, 2, 3, 4, 5], collected);
    test_complete!("throttle_zero_duration_forward");
}

#[test]
fn throttle_suppresses_then_forward() {
    init_test("throttle_suppresses_then_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // With a large period, only the first sync item passes.
    let pipeline = iter(vec![1, 2, 3, 4, 5]).throttle(Duration::from_secs(10));

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    // Only first item passes; the rest are synchronously delivered within 10s window.
    let ok = collected == vec![1];
    assert_with_log!(ok, "throttle(10s)→forward", vec![1], collected);
    test_complete!("throttle_suppresses_then_forward");
}

#[test]
fn debounce_flushes_on_end_forward() {
    init_test("debounce_flushes_on_end_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // With a large period, debounce buffers all sync items.
    // When the stream ends, the last buffered item is flushed.
    let pipeline = iter(vec![1, 2, 3]).debounce(Duration::from_secs(999));

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    // Only the last item (3) is flushed on stream end.
    let ok = collected == vec![3];
    assert_with_log!(ok, "debounce→forward", vec![3], collected);
    test_complete!("debounce_flushes_on_end_forward");
}

#[test]
fn debounce_zero_duration_forward() {
    init_test("debounce_zero_duration_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);

    // With zero duration + sync stream ending, the last item flushes.
    let pipeline = iter(vec![10, 20, 30]).debounce(Duration::ZERO);

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    // All items arrive synchronously; stream ends → last item flushed.
    let ok = collected == vec![30];
    assert_with_log!(ok, "debounce(0)→forward", vec![30], collected);
    test_complete!("debounce_zero_duration_forward");
}

// ============================================================================
// 4. SinkStream::send_all with combinator chains
// ============================================================================

#[test]
fn sink_stream_send_all_basic() {
    init_test("sink_stream_send_all_basic");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);
    let sink = into_sink(tx);

    let input = iter(vec![100, 200, 300]);

    futures_lite::future::block_on(async {
        sink.send_all(&cx, input).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![100, 200, 300];
    assert_with_log!(ok, "send_all basic", vec![100, 200, 300], collected);
    test_complete!("sink_stream_send_all_basic");
}

#[test]
fn sink_stream_send_all_with_map() {
    init_test("sink_stream_send_all_with_map");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);
    let sink = into_sink(tx);

    let input = iter(vec![1, 2, 3]).map(|x| x * 100);

    futures_lite::future::block_on(async {
        sink.send_all(&cx, input).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![100, 200, 300];
    assert_with_log!(ok, "send_all+map", vec![100, 200, 300], collected);
    test_complete!("sink_stream_send_all_with_map");
}

#[test]
fn sink_stream_send_all_scan_pipeline() {
    init_test("sink_stream_send_all_scan_pipeline");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<String>(16);
    let sink = into_sink(tx);

    // scan: build cumulative CSV string
    let input = iter(vec!["a", "b", "c"]).scan(String::new(), |acc: &mut String, item: &str| {
        if !acc.is_empty() {
            acc.push(',');
        }
        acc.push_str(item);
        Some(acc.clone())
    });

    futures_lite::future::block_on(async {
        sink.send_all(&cx, input).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let expected = vec!["a".to_string(), "a,b".to_string(), "a,b,c".to_string()];
    let ok = collected == expected;
    assert_with_log!(ok, "send_all+scan", expected, collected);
    test_complete!("sink_stream_send_all_scan_pipeline");
}

#[test]
fn sink_stream_send_individual_items() {
    init_test("sink_stream_send_individual_items");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);
    let sink = SinkStream::new(tx);

    futures_lite::future::block_on(async {
        sink.send(&cx, 1).await.unwrap();
        sink.send(&cx, 2).await.unwrap();
        sink.send(&cx, 3).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![1, 2, 3];
    assert_with_log!(ok, "send individual", vec![1, 2, 3], collected);
    test_complete!("sink_stream_send_individual_items");
}

// ============================================================================
// 5. ReceiverStream → combinator → forward round-trip
// ============================================================================

#[test]
fn receiver_stream_map_forward_roundtrip() {
    init_test("receiver_stream_map_forward_roundtrip");
    let cx: Cx = Cx::for_testing();

    // Stage 1: put items into a channel.
    let (tx_in, rx_in) = mpsc::channel::<i32>(16);
    tx_in.try_send(10).unwrap();
    tx_in.try_send(20).unwrap();
    tx_in.try_send(30).unwrap();
    drop(tx_in);

    // Stage 2: read from channel, transform, forward to second channel.
    let (tx_out, rx_out) = mpsc::channel::<i32>(16);
    let input_stream = ReceiverStream::new(cx.clone(), rx_in);
    let transformed = input_stream.map(|x| x + 1);

    futures_lite::future::block_on(async {
        forward(&cx, transformed, tx_out).await.unwrap();
    });

    // Stage 3: verify output.
    let output = ReceiverStream::new(cx, rx_out);
    let collected = collect_sync(output);
    let ok = collected == vec![11, 21, 31];
    assert_with_log!(ok, "receiver→map→forward", vec![11, 21, 31], collected);
    test_complete!("receiver_stream_map_forward_roundtrip");
}

#[test]
fn receiver_stream_filter_scan_forward() {
    init_test("receiver_stream_filter_scan_forward");
    let cx: Cx = Cx::for_testing();

    let (tx_in, rx_in) = mpsc::channel::<i32>(16);
    for v in [1, 2, 3, 4, 5, 6, 7, 8] {
        tx_in.try_send(v).unwrap();
    }
    drop(tx_in);

    let (tx_out, rx_out) = mpsc::channel::<i32>(16);
    let pipeline = ReceiverStream::new(cx.clone(), rx_in)
        .filter(|x| x % 2 == 0) // 2, 4, 6, 8
        .scan(0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        }); // running sum: 2, 6, 12, 20

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx_out).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx_out);
    let collected = collect_sync(output);
    let ok = collected == vec![2, 6, 12, 20];
    assert_with_log!(
        ok,
        "receiver→filter→scan→forward",
        vec![2, 6, 12, 20],
        collected
    );
    test_complete!("receiver_stream_filter_scan_forward");
}

// ============================================================================
// 6. Error propagation through try_* combinators
// ============================================================================

#[test]
fn try_collect_after_map_in_pipeline() {
    init_test("try_collect_after_map_in_pipeline");
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // map to Result, then try_collect
    let pipeline = iter(vec![1, 2, 3, 4, 5])
        .map(|x: i32| -> Result<i32, &str> {
            if x == 4 { Err("four") } else { Ok(x * 10) }
        })
        .try_collect::<i32, &str, Vec<_>>();

    let mut future = pipeline;
    let poll = Pin::new(&mut future).poll(&mut cx);
    let ok = matches!(poll, Poll::Ready(Err(TryStreamError::Inner("four"))));
    assert_with_log!(
        ok,
        "try_collect short-circuits",
        "Err(TryStreamError::Inner(\"four\"))",
        poll
    );
    test_complete!("try_collect_after_map_in_pipeline");
}

#[test]
fn try_fold_with_filter_map_pipeline() {
    init_test("try_fold_with_filter_map_pipeline");
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // filter_map → wrap in Ok → try_fold(sum)
    let pipeline = iter(vec!["1", "two", "3", "four", "5"])
        .filter_map(|s| s.parse::<i32>().ok()) // 1, 3, 5
        .map(Ok::<i32, &str>)
        .try_fold(0i32, |acc, x| Ok::<i32, &str>(acc + x));

    let mut future = pipeline;
    let poll = Pin::new(&mut future).poll(&mut cx);
    let ok = matches!(poll, Poll::Ready(Ok(9)));
    assert_with_log!(ok, "try_fold sum", "Ok(9)", poll);
    test_complete!("try_fold_with_filter_map_pipeline");
}

#[test]
fn try_for_each_with_scan_pipeline() {
    init_test("try_for_each_with_scan_pipeline");
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut seen = Vec::new();
    let pipeline = iter(vec![1, 2, 3, 4, 5])
        .scan(0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        }) // 1, 3, 6, 10, 15
        .try_for_each(|x| -> Result<(), &str> {
            if x > 8 {
                Err("too big")
            } else {
                seen.push(x);
                Ok(())
            }
        });

    let mut future = pipeline;
    let poll = Pin::new(&mut future).poll(&mut cx);
    let ok = matches!(poll, Poll::Ready(Err(TryStreamError::Inner("too big"))));
    assert_with_log!(
        ok,
        "try_for_each stops",
        "Err(TryStreamError::Inner(\"too big\"))",
        poll
    );
    let ok = seen == vec![1, 3, 6];
    assert_with_log!(ok, "seen before error", vec![1, 3, 6], seen);
    test_complete!("try_for_each_with_scan_pipeline");
}

// ============================================================================
// 7. Multi-stage pipelines (stream → sink → stream → sink)
// ============================================================================

#[test]
fn two_stage_pipeline() {
    init_test("two_stage_pipeline");
    let cx: Cx = Cx::for_testing();

    // Stage 1: [1..5] → filter(odd) → channel_1
    let (tx1, rx1) = mpsc::channel::<i32>(16);
    let stage1 = iter(vec![1, 2, 3, 4, 5]).filter(|x| x % 2 == 1);

    futures_lite::future::block_on(async {
        forward(&cx, stage1, tx1).await.unwrap();
    });

    // Stage 2: channel_1 → map(*10) → channel_2
    let (tx2, rx2) = mpsc::channel::<i32>(16);
    let stage2 = ReceiverStream::new(cx.clone(), rx1).map(|x| x * 10);

    futures_lite::future::block_on(async {
        forward(&cx, stage2, tx2).await.unwrap();
    });

    // Verify: odd values [1,3,5] * 10 = [10,30,50]
    let output = ReceiverStream::new(cx, rx2);
    let collected = collect_sync(output);
    let ok = collected == vec![10, 30, 50];
    assert_with_log!(ok, "two-stage pipeline", vec![10, 30, 50], collected);
    test_complete!("two_stage_pipeline");
}

#[test]
fn three_stage_scan_filter_map_pipeline() {
    init_test("three_stage_scan_filter_map_pipeline");
    let cx: Cx = Cx::for_testing();

    // Stage 1: [1..6] → scan(running sum) → channel_1
    let (tx1, rx1) = mpsc::channel::<i32>(16);
    let stage1 = iter(vec![1, 2, 3, 4, 5]).scan(0i32, |acc: &mut i32, x: i32| {
        *acc += x;
        Some(*acc)
    }); // 1, 3, 6, 10, 15

    futures_lite::future::block_on(async {
        forward(&cx, stage1, tx1).await.unwrap();
    });

    // Stage 2: channel_1 → filter(>5) → channel_2
    let (tx2, rx2) = mpsc::channel::<i32>(16);
    let stage2 = ReceiverStream::new(cx.clone(), rx1).filter(|x| *x > 5);

    futures_lite::future::block_on(async {
        forward(&cx, stage2, tx2).await.unwrap();
    });

    // Stage 3: channel_2 → map(to_string) → channel_3
    let (tx3, rx3) = mpsc::channel::<String>(16);
    let stage3 = ReceiverStream::new(cx.clone(), rx2).map(|x| format!("sum={x}"));

    futures_lite::future::block_on(async {
        forward(&cx, stage3, tx3).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx3);
    let collected = collect_sync(output);
    let expected = vec![
        "sum=6".to_string(),
        "sum=10".to_string(),
        "sum=15".to_string(),
    ];
    let ok = collected == expected;
    assert_with_log!(ok, "three-stage pipeline", expected, collected);
    test_complete!("three_stage_scan_filter_map_pipeline");
}

// ============================================================================
// 8. Edge cases
// ============================================================================

#[test]
fn forward_single_item() {
    init_test("forward_single_item");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(4);

    futures_lite::future::block_on(async {
        forward(&cx, iter(vec![42]), tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![42];
    assert_with_log!(ok, "forward single", vec![42], collected);
    test_complete!("forward_single_item");
}

#[test]
fn forward_large_stream() {
    init_test("forward_large_stream");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(256);

    let input: Vec<i32> = (0..200).collect();
    let expected = input.clone();

    futures_lite::future::block_on(async {
        forward(&cx, iter(input), tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == expected;
    assert_with_log!(ok, "forward 200 items", "200 items", collected.len());
    test_complete!("forward_large_stream");
}

#[test]
fn scan_type_change_forward() {
    init_test("scan_type_change_forward");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<usize>(16);

    // scan that changes type: &str → usize (accumulated length)
    let pipeline = iter(vec!["hello", "world", "!"]).scan(0usize, |acc: &mut usize, item: &str| {
        *acc += item.len();
        Some(*acc)
    }); // 5, 10, 11

    futures_lite::future::block_on(async {
        forward(&cx, pipeline, tx).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![5, 10, 11];
    assert_with_log!(
        ok,
        "scan type change→forward",
        vec![5usize, 10, 11],
        collected
    );
    test_complete!("scan_type_change_forward");
}

#[test]
fn sink_send_then_send_all_same_channel() {
    init_test("sink_send_then_send_all_same_channel");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(16);
    let sink = SinkStream::new(tx);

    futures_lite::future::block_on(async {
        // Send individual items first.
        sink.send(&cx, 1).await.unwrap();
        sink.send(&cx, 2).await.unwrap();
        // Then send_all from a stream.
        sink.send_all(&cx, iter(vec![3, 4, 5])).await.unwrap();
    });

    let output = ReceiverStream::new(cx, rx);
    let collected = collect_sync(output);
    let ok = collected == vec![1, 2, 3, 4, 5];
    assert_with_log!(ok, "send+send_all", vec![1, 2, 3, 4, 5], collected);
    test_complete!("sink_send_then_send_all_same_channel");
}

#[test]
fn forward_disconnected_receiver_returns_error() {
    init_test("forward_disconnected_receiver_returns_error");
    let cx: Cx = Cx::for_testing();
    let (tx, rx) = mpsc::channel::<i32>(4);

    // Drop the receiver before forwarding.
    drop(rx);

    let result =
        futures_lite::future::block_on(async { forward(&cx, iter(vec![1, 2, 3]), tx).await });

    let ok = result.is_err();
    assert_with_log!(ok, "forward to dropped rx errors", true, ok);
    test_complete!("forward_disconnected_receiver_returns_error");
}
