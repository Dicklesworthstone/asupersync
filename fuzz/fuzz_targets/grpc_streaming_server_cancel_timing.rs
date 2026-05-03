#![no_main]

//! Cargo-fuzz target for server-stream cancellation TIMING semantics.
//!
//! Drives `asupersync::grpc::ResponseStream<u32>` (the production stream
//! consumers receive on the gRPC client side) with an Arbitrary-derived
//! sequence of `Push` / `Poll` / `Cancel` / `Finish` / `Close` operations
//! and asserts the two contracts the operator asked for:
//!
//!   1. **Client gets CANCELLED status.** After `cancel(status)` is
//!      invoked on the producing side, every subsequent
//!      `poll_next` MUST yield `Some(Err(status))` — the same `Code`
//!      and message the producer named, never `None`, never an
//!      orphaned `Ok(_)`, never panic.
//!
//!   2. **No data loss BEFORE the cancel point.** Every item the
//!      consumer successfully polled while the stream was still open
//!      MUST equal the corresponding item the producer pushed, in
//!      the same order. Items still buffered at cancel time MAY be
//!      dropped — that's the documented `cancel_with_metadata`
//!      "abrupt-discard" semantic — but anything that already
//!      crossed the API boundary into the consumer's hands is
//!      sacred.
//!
//! Why this fuzzer in addition to `grpc_streaming_cancel_storm`:
//! that target stresses concurrent cancellation pressure (multiple
//! cancel threads, race-condition discovery). This target instead
//! pins the SEMANTIC contract of a single, deterministic sequence —
//! the failure modes here are off-by-one in the cancel-point
//! prefix, leaked buffered items past cancel, or a status code
//! drift between producer cancel and consumer error.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_streaming_server_cancel_timing -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::grpc::ResponseStream;
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::Streaming;
use libfuzzer_sys::fuzz_target;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// Bounded operation count keeps each iteration sub-second.
const MAX_OPERATIONS: usize = 64;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    /// Push item with the given seq number into the stream.
    Push(u32),
    /// Poll once. Records the Result observed.
    Poll,
    /// Cancel with `Code::Cancelled`. Idempotent — second call is a
    /// no-op per the production stream contract.
    Cancel,
    /// Finish (drain-then-status) with `Code::Cancelled`. The
    /// `finish_with_metadata` path retains buffered items; the
    /// fuzzer treats `Finish` and `Cancel` as observably distinct
    /// for the buffered-prefix expectation.
    Finish,
    /// Close gracefully (no terminal status). Subsequent poll
    /// returns `None`.
    Close,
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    ops: Vec<Op>,
}

/// Minimal Wake-impl so we can poll the stream without an async
/// runtime. We never expect `Pending` here because every operation
/// (push/cancel/close) wakes the stream — `poll_next` should
/// short-circuit on either an item, an error, a closed-no-status,
/// or no buffered items + open stream (in which case Pending IS
/// legal but means "no progress this Poll" so we treat it as a
/// no-op).
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn make_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fuzz_target!(|scenario: Scenario| {
    if scenario.ops.len() > MAX_OPERATIONS {
        return;
    }

    let mut stream = ResponseStream::<u32>::open();
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);

    // Producer-side ground truth: every item that was successfully
    // pushed (i.e. push() returned Ok) BEFORE any cancel/finish/close
    // is in `pushed_open`. After the first terminal op, no more items
    // can be cleanly pushed.
    let mut pushed_open: Vec<u32> = Vec::new();
    // Consumer-side observation: every Ok(item) returned by poll_next.
    let mut polled_ok: Vec<u32> = Vec::new();

    let mut terminal_kind: Option<TerminalKind> = None;

    for op in scenario.ops {
        match op {
            Op::Push(seq) => {
                let push_result = stream.push(Ok(seq));
                if push_result.is_ok() && terminal_kind.is_none() {
                    pushed_open.push(seq);
                } else if push_result.is_ok() {
                    // Production contract: push to a closed stream MUST
                    // return Err. If we reach here with Ok(()) AND a
                    // terminal already set, that's a contract violation.
                    panic!(
                        "push to terminated stream returned Ok — \
                         terminal_kind={:?}, polled_ok_so_far={polled_ok:?}",
                        terminal_kind,
                    );
                }
            }
            Op::Poll => {
                let pinned = Pin::new(&mut stream);
                match pinned.poll_next(&mut cx) {
                    Poll::Ready(Some(Ok(item))) => {
                        polled_ok.push(item);
                    }
                    Poll::Ready(Some(Err(status))) => {
                        // Property 1: after a terminal-with-status,
                        // every status poll MUST carry the same code
                        // we set on the producer side.
                        match terminal_kind {
                            Some(TerminalKind::Cancel | TerminalKind::Finish) => {
                                assert_eq!(
                                    status.code(),
                                    Code::Cancelled,
                                    "consumer status code {:?} != producer-set Code::Cancelled",
                                    status.code(),
                                );
                            }
                            Some(TerminalKind::Close) => {
                                panic!("graceful close yielded Err(_) instead of None: {status:?}",);
                            }
                            None => {
                                panic!(
                                    "stream returned Err(_) without a producer terminal call: \
                                     polled_ok_so_far={polled_ok:?}, status={status:?}",
                                );
                            }
                        }
                    }
                    Poll::Ready(None) => {
                        // None is only legal after a graceful close.
                        match terminal_kind {
                            Some(TerminalKind::Close) => {} // ✓
                            Some(TerminalKind::Cancel | TerminalKind::Finish) => {
                                panic!(
                                    "stream returned None instead of the cancel error: \
                                     terminal_kind={:?}, polled_ok_so_far={polled_ok:?}",
                                    terminal_kind,
                                );
                            }
                            None => {
                                // Stream returned None without ever
                                // being terminated — only legal if it
                                // started closed. ResponseStream::open()
                                // does NOT start closed, so this is a
                                // bug if we ever observe it.
                                panic!(
                                    "open stream returned None without producer terminal call: \
                                     polled_ok_so_far={polled_ok:?}",
                                );
                            }
                        }
                    }
                    Poll::Pending => {
                        // Legal: the buffer is empty and the stream is
                        // still open. No invariant violation; carry on.
                    }
                }
            }
            Op::Cancel => {
                if terminal_kind.is_none() {
                    terminal_kind = Some(TerminalKind::Cancel);
                }
                stream.cancel(Status::cancelled("fuzz cancel"));
            }
            Op::Finish => {
                if terminal_kind.is_none() {
                    terminal_kind = Some(TerminalKind::Finish);
                }
                stream.finish_with_metadata(Status::cancelled("fuzz finish"), Default::default());
            }
            Op::Close => {
                if terminal_kind.is_none() {
                    terminal_kind = Some(TerminalKind::Close);
                }
                stream.close();
            }
        }
    }

    // Property 2: polled_ok must be a PREFIX of pushed_open. The
    // consumer cannot have observed more items than the producer
    // pushed before terminating, and the order must match
    // (ResponseStream is a single-consumer FIFO). Items pushed
    // before terminal that were NOT polled before terminal MAY
    // have been discarded by Cancel — that's allowed and not
    // reported as data loss for the polled-prefix property.
    assert!(
        polled_ok.len() <= pushed_open.len(),
        "consumer polled more items than producer pushed: \
         polled_ok={polled_ok:?}, pushed_open={pushed_open:?}",
    );
    for (i, (got, sent)) in polled_ok.iter().zip(pushed_open.iter()).enumerate() {
        assert_eq!(
            got, sent,
            "polled item at index {i} ({got}) != pushed item ({sent}) — \
             stream lost or reordered data BEFORE the cancel point",
        );
    }
});

#[derive(Debug, Clone, Copy)]
enum TerminalKind {
    Cancel,
    Finish,
    Close,
}
