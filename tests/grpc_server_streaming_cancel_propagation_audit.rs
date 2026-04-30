//! Audit + regression test for `src/grpc/streaming.rs` +
//! `src/grpc/client.rs` server-side stream cancellation
//! propagation (tick #160).
//!
//! Operator's question: "verify server-side cancel reaches all
//! in-flight items, no leaked items."
//!
//! Audit findings:
//!
//!   (a) **`StreamingRequest::cancel_with_error` is drain-then-
//!       cancel.** `cancel_with_error` (streaming.rs:553) sets
//!       `closed = true` and stores the cancellation Status as
//!       `terminal_status`. `poll_next` (streaming.rs:571-588)
//!       pops items from the VecDeque FIRST, only returning the
//!       terminal Status when the buffer is empty. Buffered
//!       items are NOT dropped — they drain in FIFO order
//!       before the consumer observes the cancel signal.
//!
//!   (b) **`ResponseStream` (production, client.rs:787) has TWO
//!       cancellation modes** that pin the audit-relevant
//!       distinction:
//!         * `cancel(status)` / `cancel_with_metadata(status, m)`
//!           — ABRUPT cancellation. `discard_buffered = true`
//!           (client.rs:881) clears the queued items so the
//!           consumer observes the terminal Status BEFORE any
//!           stale buffered payload. This is the right
//!           semantics for "cancel reaches all in-flight items
//!           and the consumer sees the cancel cause first."
//!         * `finish_with_metadata(status, m)` — DRAIN-then-
//!           status. Models the gRPC trailers path where
//!           already-received response data remains visible
//!           before the final status/trailers are observed
//!           (`discard_buffered = false`, client.rs:889).
//!
//!   (c) **No item leaks on stream drop.** Items are owned
//!       `T` values inside the VecDeque inside the
//!       `Arc<Mutex<...>>` state. When the last `Clone` of the
//!       Arc'd `ResponseStream` drops, the VecDeque drops, and
//!       every buffered item gets its Drop impl run. There is
//!       no obligation-tracking per item — items are values,
//!       not handles.
//!
//!   (d) **Push after cancel returns
//!       `FailedPrecondition("cannot push to a closed response
//!       stream")`** (client.rs:822-826). A producer that races
//!       cancel cannot smuggle an item into a cancelled stream.
//!
//!   (e) **Cancel is set-once.** `set_terminal_status`
//!       (client.rs:858-874) only writes `terminal_status` if
//!       `state.terminal_status.is_none()`. A second cancel
//!       call with a different status is a no-op — the first
//!       cancel cause wins. This matches the analogous
//!       behavior on the test-side `StreamingRequest`
//!       (streaming.rs:555).
//!
//! Regression tests below pin (a)-(e) at the public API surface.

use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::{Metadata, Streaming, StreamingRequest};
use asupersync::grpc::{ResponseStream, Status};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A no-op waker for poll-driving tests that don't need
/// scheduler integration. Uses the stable `Waker::noop()`
/// available in Rust 2024 edition / 1.85+.
fn null_waker() -> std::task::Waker {
    std::task::Waker::noop().clone()
}

#[test]
fn streaming_request_drains_buffered_items_then_yields_cancel_status() {
    // Pin (a): in-flight items survive cancel and are delivered
    // to the consumer in FIFO order before the cancellation
    // Status is yielded.
    let mut stream = StreamingRequest::<u32>::open();
    stream.push(1).expect("push 1");
    stream.push(2).expect("push 2");
    stream.push(3).expect("push 3");

    stream.cancel_with_error(Status::cancelled("server cancelled stream"));

    let waker = null_waker();
    let mut cx = Context::from_waker(&waker);

    for expected in [1u32, 2, 3] {
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(v))) => assert_eq!(
                v, expected,
                "buffered items must drain in FIFO order before cancel signal",
            ),
            other => panic!("expected Ready(Some(Ok({expected}))), got {other:?}"),
        }
    }

    match Pin::new(&mut stream).poll_next(&mut cx) {
        Poll::Ready(Some(Err(s))) => {
            assert_eq!(s.code(), Code::Cancelled);
            assert!(s.message().contains("server cancelled stream"));
        }
        other => panic!("expected Cancelled Err after drain, got {other:?}"),
    }
}

#[test]
fn response_stream_cancel_is_abrupt_discards_buffered_items() {
    // Pin (b): the production-side ResponseStream::cancel
    // DISCARDS buffered items (`discard_buffered = true` at
    // client.rs:881). This is the audit-relevant property: a
    // server-side cancel REACHES THE CONSUMER FIRST. A regression
    // that switched cancel to drain-then-status would let the
    // consumer process stale items past the cancel deadline,
    // potentially violating the cancel contract.
    let mut stream = ResponseStream::<u32>::open();
    stream.push(Ok(11)).expect("push 11");
    stream.push(Ok(22)).expect("push 22");
    stream.push(Ok(33)).expect("push 33");

    // Abrupt cancel.
    stream.cancel(Status::cancelled("abrupt cancel"));

    let waker = null_waker();
    let mut cx = Context::from_waker(&waker);

    // First poll surfaces the cancel — buffered items DROPPED.
    match Pin::new(&mut stream).poll_next(&mut cx) {
        Poll::Ready(Some(Err(s))) => {
            assert_eq!(s.code(), Code::Cancelled);
            assert!(s.message().contains("abrupt cancel"));
        }
        other => panic!(
            "abrupt cancel must surface BEFORE any buffered item — got {other:?}",
        ),
    }
}

#[test]
fn response_stream_finish_with_metadata_drains_buffered_items_first() {
    // Pin (b) the OTHER semantics: `finish_with_metadata` keeps
    // buffered items (`discard_buffered = false` at client.rs:889).
    // Models the gRPC trailers path where the server has already
    // sent N message frames and is now sending the final
    // status+trailers; the consumer reads through the message
    // frames first, then sees the terminal status.
    let mut stream = ResponseStream::<u32>::open();
    stream.push(Ok(100)).expect("push 100");
    stream.push(Ok(200)).expect("push 200");

    stream.finish_with_metadata(Status::ok(), Metadata::new());

    let waker = null_waker();
    let mut cx = Context::from_waker(&waker);

    // The two buffered items drain first.
    for expected in [100u32, 200] {
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(v))) => assert_eq!(v, expected),
            other => panic!("expected drain-first, got {other:?}"),
        }
    }
    // The Ok status is the graceful end-of-stream — consumer
    // observes None.
    match Pin::new(&mut stream).poll_next(&mut cx) {
        Poll::Ready(None) => {}
        Poll::Ready(Some(Ok(_))) => panic!("expected EOS after drain"),
        Poll::Ready(Some(Err(s))) => {
            // finish_with_metadata(Status::ok()) may surface as
            // Ok-EOS via None, OR as a final Ok status — both are
            // graceful completions.
            assert_eq!(s.code(), Code::Ok, "graceful finish must be Ok");
        }
        Poll::Pending => panic!("expected Ready"),
    }
}

#[test]
fn push_after_cancel_is_rejected_with_failed_precondition() {
    // Pin (d): a producer that races cancel cannot smuggle items
    // into the closed stream. The Err shape is FailedPrecondition
    // with a grep'able message.
    let mut stream = ResponseStream::<u32>::open();
    stream.cancel(Status::cancelled("test cancel"));

    let err = stream
        .push(Ok(42))
        .expect_err("push to cancelled stream must Err");
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "post-cancel push must surface as FailedPrecondition; got {:?}",
        err.code(),
    );
    assert!(
        err.message().contains("closed") || err.message().contains("cannot push"),
        "post-cancel push error message must be operator-grep'able; got {:?}",
        err.message(),
    );
}

#[test]
fn cancel_idempotent_first_status_wins_on_response_stream() {
    // Pin (e): a second cancel call with a different status does
    // NOT overwrite the first. terminal_status is set-once
    // (client.rs:862 — `if state.terminal_status.is_none()`).
    let mut stream = ResponseStream::<u32>::open();
    stream.cancel(Status::cancelled("first cancel"));
    stream.cancel(Status::deadline_exceeded("second cancel — must lose"));

    let waker = null_waker();
    let mut cx = Context::from_waker(&waker);

    match Pin::new(&mut stream).poll_next(&mut cx) {
        Poll::Ready(Some(Err(s))) => {
            assert_eq!(
                s.code(),
                Code::Cancelled,
                "first cancel wins — second cancel must not overwrite",
            );
            assert!(s.message().contains("first cancel"));
        }
        other => panic!("expected first-cancel Err, got {other:?}"),
    }
}

#[test]
fn cancel_idempotent_first_status_wins_on_streaming_request() {
    // Pin (a) extension on StreamingRequest: same set-once
    // semantics on the request side (streaming.rs:555).
    let mut stream = StreamingRequest::<u32>::open();
    stream.cancel_with_error(Status::cancelled("first"));
    stream.cancel_with_error(Status::aborted("second — must lose"));

    let waker = null_waker();
    let mut cx = Context::from_waker(&waker);

    match Pin::new(&mut stream).poll_next(&mut cx) {
        Poll::Ready(Some(Err(s))) => assert_eq!(s.code(), Code::Cancelled),
        other => panic!("expected first-cancel Err, got {other:?}"),
    }
}

#[test]
fn drop_after_cancel_releases_all_buffered_items_streaming_request() {
    // Pin (c) on StreamingRequest: dropping the stream after
    // cancel runs every buffered item's Drop impl exactly once.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct DropCounter(Arc<AtomicUsize>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let counter = Arc::new(AtomicUsize::new(0));
    {
        let mut stream = StreamingRequest::<DropCounter>::open();
        stream.push(DropCounter(counter.clone())).unwrap();
        stream.push(DropCounter(counter.clone())).unwrap();
        stream.push(DropCounter(counter.clone())).unwrap();
        stream.cancel_with_error(Status::cancelled("drop test"));
        // stream goes out of scope here — VecDeque drops every item.
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "every buffered item must be dropped exactly once on stream-drop \
         after cancel; got {} drops",
        counter.load(Ordering::SeqCst),
    );
}

#[test]
fn drop_after_abrupt_cancel_releases_buffered_items_response_stream() {
    // Pin (c) on ResponseStream: the abrupt-cancel path
    // explicitly clears `state.items` (client.rs:864 — `if
    // discard_buffered { state.items.clear(); }`). After that
    // call, every previously-buffered item has been dropped.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct DropCounter(Arc<AtomicUsize>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let mut stream = ResponseStream::<DropCounter>::open();
    stream
        .push(Ok(DropCounter(counter.clone())))
        .expect("push 1");
    stream
        .push(Ok(DropCounter(counter.clone())))
        .expect("push 2");

    // Abrupt cancel — items.clear() runs inside, dropping both
    // counters AT THE CANCEL POINT (not later, on stream drop).
    stream.cancel(Status::cancelled("clear-on-cancel"));
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "abrupt cancel must clear buffered items immediately, dropping \
         each exactly once; got {} drops",
        counter.load(Ordering::SeqCst),
    );

    drop(stream);
    // No additional drops — items were already cleared.
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "stream-drop after abrupt cancel must not double-drop",
    );
}
