//! Audit + regression test for server-streaming TRAILERS ordering on
//! `asupersync::grpc::ResponseStream`.
//!
//! gRPC-over-HTTP/2 contract for server-streaming RPCs:
//!
//!   1. Server sends HEADERS (initial metadata).
//!   2. Server sends 0..N DATA frames (response messages).
//!   3. Server sends TRAILERS (`grpc-status` + optional
//!      `grpc-message` + trailing metadata).
//!
//! Trailers MUST be sent — even when the handler errors mid-stream
//! — otherwise the connection is left half-closed: the client has
//! buffered DATA frames but no terminal status, which a tonic /
//! grpc-go peer cannot interpret. The classic regression here is
//! "skip trailers on error" — the wire looks like a successful
//! drain to the consumer until the connection eventually times out.
//!
//! Audit (tick #133): `src/grpc/server.rs` does not directly emit
//! HTTP/2 trailers; that's the transport adapter's job. The
//! production server-streaming surface is
//! `asupersync::grpc::ResponseStream<T>` (defined in
//! `src/grpc/client.rs` despite the name — it's the consumer-side
//! read end that the server-side producer pushes into via
//! `push` / `finish_with_metadata` / `cancel_with_metadata`).
//!
//! The trailer-ordering CONTRACT is therefore expressed as a poll
//! invariant on `ResponseStream::poll_next`:
//!
//!   * Buffered items drain BEFORE the terminal status — i.e. a
//!     consumer that polls until terminal observes every item the
//!     producer pushed before `finish_with_metadata` was called.
//!   * `finish_with_metadata(status, metadata)` is the
//!     drain-then-status path (status surfaces only after items
//!     are consumed).
//!   * `cancel_with_metadata(status, metadata)` is the
//!     abrupt-discard path (status surfaces immediately, buffered
//!     items are dropped — that's the gRPC ABORT semantic for
//!     RST_STREAM-style cancellation).
//!   * `close()` produces the graceful `None` terminator with no
//!     trailing status.
//!
//! Why this regression test exists: the in-tree
//! `tests/grpc_streaming_*.rs` tests cover broader cancellation
//! scenarios; this file specifically pins the TRAILER-ORDERING
//! invariant that a server-streaming handler erroring after
//! pushing N items must result in the consumer observing those N
//! items followed by the error trailer — never trailer-then-data,
//! never trailer-skipped.

use asupersync::bytes::Bytes;
use asupersync::grpc::ResponseStream;
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::{Metadata, Streaming};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}
fn make_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fn drain<T: Send + Unpin>(stream: &mut ResponseStream<T>) -> Vec<Result<T, Status>> {
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = Vec::new();
    loop {
        match Pin::new(&mut *stream).poll_next(&mut cx) {
            Poll::Ready(Some(result)) => out.push(result),
            Poll::Ready(None) => return out,
            Poll::Pending => return out,
        }
    }
}

#[test]
fn finish_with_metadata_drains_items_before_emitting_trailer_status() {
    // Server-side: handler pushes 5 items, then errors mid-stream.
    // The trailer (grpc-status=Internal) MUST be sent AFTER the 5
    // items, never before — that's the documented gRPC server-
    // streaming wire ordering.
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..5 {
        stream.push(Ok(i)).expect("push");
    }
    stream.finish_with_metadata(
        Status::new(Code::Internal, "boom"),
        Metadata::new(),
    );

    let drained = drain(&mut stream);
    assert_eq!(drained.len(), 6, "5 items + 1 terminal status");
    for (i, result) in drained.iter().take(5).enumerate() {
        match result {
            Ok(item) => assert_eq!(*item, i as u32, "items must drain in order"),
            Err(status) => panic!(
                "trailer arrived BEFORE buffered item {i} — wire-ordering violation: {status:?}",
            ),
        }
    }
    let terminal = drained.last().expect("at least 6 elements");
    let status = terminal
        .as_ref()
        .expect_err("the 6th element MUST be the terminal Err");
    assert_eq!(
        status.code(),
        Code::Internal,
        "trailer status code must match what the handler called finish_with_metadata with",
    );
    assert_eq!(status.message(), "boom");
}

#[test]
fn finish_with_metadata_with_ok_status_still_emits_trailer_after_items() {
    // gRPC requires trailers ALWAYS — even for the success path.
    // A handler that completes normally calls finish_with_metadata
    // with Code::Ok, and the consumer sees: items..., Err(Ok-status).
    // (The consumer SHOULD treat Code::Ok in trailers as graceful
    // completion; an interop check that asserted "Err means error"
    // would be wrong.)
    //
    // Pinned: the wire-ordering invariant is the same regardless
    // of success / failure. Ok-status trailers behave like
    // error-status trailers structurally.
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..3 {
        stream.push(Ok(i)).expect("push");
    }
    stream.finish_with_metadata(
        Status::new(Code::Ok, ""),
        Metadata::new(),
    );

    let drained = drain(&mut stream);
    assert_eq!(drained.len(), 4, "3 items + 1 terminal Ok-trailer");
    for (i, result) in drained.iter().take(3).enumerate() {
        assert_eq!(
            result.as_ref().ok().copied(),
            Some(i as u32),
            "item at index {i} must be Ok({i})",
        );
    }
    let terminal = drained.last().unwrap().as_ref().expect_err("Err marker");
    assert_eq!(terminal.code(), Code::Ok);
}

#[test]
fn cancel_with_metadata_discards_buffered_items_per_abrupt_semantic() {
    // Documented divergence from finish_with_metadata: cancel is the
    // RST_STREAM-style abrupt path. Buffered items MUST be discarded
    // and the consumer's NEXT poll yields the cancel status
    // immediately. This is the "trailer-without-data" semantic for
    // abrupt cancellation — distinct from finish_with_metadata.
    //
    // Pinned so a future refactor that conflated cancel and finish
    // (both setting closed=true + terminal_status) would trip here:
    // post-fix the buffered items must NOT be visible to the
    // consumer after cancel.
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..5 {
        stream.push(Ok(i)).expect("push");
    }
    stream.cancel_with_metadata(
        Status::new(Code::Cancelled, "abrupt"),
        Metadata::new(),
    );

    let drained = drain(&mut stream);
    // Per cancel_with_metadata's doc:
    //   'queued response items are discarded so the caller observes
    //    the terminal status before any stale buffered payloads.'
    // So the drain returns exactly ONE element: the cancel status.
    assert_eq!(
        drained.len(),
        1,
        "cancel_with_metadata must discard buffered items per its abrupt-discard \
         doc contract; got drain.len()={}",
        drained.len(),
    );
    let terminal = drained.first().unwrap().as_ref().expect_err("Err marker");
    assert_eq!(terminal.code(), Code::Cancelled);
}

#[test]
fn close_yields_graceful_none_terminator_after_buffered_items() {
    // The third terminal: graceful close. No trailer/status.
    // Consumer drains buffered items then sees None.
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..2 {
        stream.push(Ok(i)).expect("push");
    }
    stream.close();

    let drained = drain(&mut stream);
    assert_eq!(drained.len(), 2, "items only — no trailer on graceful close");
    for (i, result) in drained.iter().enumerate() {
        assert_eq!(result.as_ref().ok().copied(), Some(i as u32));
    }
    // Final Ready(None) is consumed by `drain` returning, not stored
    // in the Vec; assert by polling once more and observing None.
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);
    match Pin::new(&mut stream).poll_next(&mut cx) {
        Poll::Ready(None) => {}
        other => panic!("graceful close must yield Ready(None), got {other:?}"),
    }
}

#[test]
fn finish_after_partial_drain_still_appends_trailer_after_remaining_items() {
    // Realistic scenario: consumer polls some items, then handler
    // errors mid-stream. The remaining buffered items MUST drain
    // before the trailer appears. A regression that flushed the
    // terminal status as soon as `finish_with_metadata` was called
    // (regardless of buffer state) would surface here.
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..6 {
        stream.push(Ok(i)).expect("push");
    }

    // Consumer polls the first 3 items.
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);
    let mut early = Vec::new();
    for _ in 0..3 {
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(v))) => early.push(v),
            other => panic!("expected Ready(Some(Ok)), got {other:?}"),
        }
    }
    assert_eq!(early, vec![0, 1, 2]);

    // Handler errors NOW with 3 items still in the buffer.
    stream.finish_with_metadata(
        Status::new(Code::Aborted, "mid-stream"),
        Metadata::new(),
    );

    // Drain: remaining 3 items first, THEN the trailer status.
    let drained = drain(&mut stream);
    assert_eq!(
        drained.len(),
        4,
        "expected 3 remaining items + 1 trailer; got {}",
        drained.len(),
    );
    assert_eq!(drained[0].as_ref().ok().copied(), Some(3));
    assert_eq!(drained[1].as_ref().ok().copied(), Some(4));
    assert_eq!(drained[2].as_ref().ok().copied(), Some(5));
    assert_eq!(
        drained[3].as_ref().expect_err("trailer Err").code(),
        Code::Aborted,
    );
}

#[test]
fn finish_terminal_metadata_is_observable_after_drain() {
    // The wire-level TRAILERS frame carries grpc-status + metadata.
    // Pin that the trailing metadata supplied to finish_with_metadata
    // is observable on the ResponseStream's terminal_metadata accessor
    // after drain — so the gRPC trailer-bearing path correctly
    // propagates trailer key/value pairs alongside the status.
    let mut stream = ResponseStream::<u32>::open();
    stream.push(Ok(1)).expect("push");
    let mut trailing = Metadata::new();
    let _ = trailing.insert("x-tenant", "acme");
    let _ = trailing.insert("x-trace-id", "trace-123");
    stream.finish_with_metadata(
        Status::new(Code::Ok, ""),
        trailing.clone(),
    );

    let _drained = drain(&mut stream);
    let observed = stream.terminal_metadata();
    let tenant = observed
        .get("x-tenant")
        .expect("trailing x-tenant must round-trip");
    match tenant {
        asupersync::grpc::MetadataValue::Ascii(s) => assert_eq!(s, "acme"),
        other => panic!("x-tenant must be ASCII, got {other:?}"),
    }
}

#[test]
fn first_terminal_wins_double_finish_does_not_overwrite() {
    // Idempotence under doubled terminal calls. If the handler
    // accidentally calls finish_with_metadata TWICE (e.g. once on
    // the happy path, once in a Drop guard), the SECOND call must
    // not overwrite the first terminal status. The wire-level
    // contract is that the terminal trailer is sent exactly once.
    let mut stream = ResponseStream::<u32>::open();
    stream.push(Ok(1)).expect("push");
    stream.finish_with_metadata(
        Status::new(Code::Ok, "first"),
        Metadata::new(),
    );
    // Second call: must be a no-op on the terminal.
    stream.finish_with_metadata(
        Status::new(Code::Internal, "second"),
        Metadata::new(),
    );

    let drained = drain(&mut stream);
    assert_eq!(drained.len(), 2);
    let terminal = drained[1].as_ref().expect_err("trailer");
    assert_eq!(
        terminal.code(),
        Code::Ok,
        "first terminal call wins; double-finish must not overwrite — got {:?}",
        terminal.code(),
    );
    assert_eq!(terminal.message(), "first");
}

/// Bonus pin: a handler that fails BEFORE pushing any items still
/// produces a trailer-bearing terminal — the consumer's first poll
/// is the terminal Err. Exercises the "error-only response" path
/// (server-streaming RPC that errors immediately).
#[test]
fn error_before_any_items_produces_immediate_terminal() {
    let mut stream = ResponseStream::<u32>::open();
    stream.finish_with_metadata(
        Status::new(Code::PermissionDenied, "no items, just err"),
        Metadata::new(),
    );

    let drained = drain(&mut stream);
    assert_eq!(
        drained.len(),
        1,
        "error-only response: just the terminal trailer",
    );
    assert_eq!(
        drained[0].as_ref().expect_err("trailer").code(),
        Code::PermissionDenied,
    );
}
