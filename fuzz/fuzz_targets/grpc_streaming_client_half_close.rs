#![no_main]

//! Cargo-fuzz target for client-streaming half-close: when the
//! client side of a `StreamingRequest<T>` calls `close()`, the
//! server side must observe all previously-pushed messages BEFORE
//! the terminal `None`/error marker — never any truncation.
//!
//! Models the request half of a gRPC client-streaming call as the
//! production `asupersync::grpc::streaming::StreamingRequest<u32>`.
//! Drives an Arbitrary-derived sequence of (Push|Poll|Close) ops
//! followed by a final drain, and asserts:
//!
//!   1. **No panic.** Any op sequence — even
//!      Close→Push→Push→Push (push-after-close) — must complete
//!      without unwinding.
//!
//!   2. **Push-after-close is rejected.** Once `close()` has been
//!      called, subsequent `push(..)` calls return Err — items
//!      pushed after close MUST NOT enter the buffer. (This is the
//!      gRPC client-streaming contract: half-close is a terminal
//!      end-of-stream signal from the client.)
//!
//!   3. **No truncation before half-close.** The server's polled
//!      sequence is a PREFIX of the items pushed before close().
//!      Specifically: at the end of the scenario, after draining
//!      the stream, the server has observed EXACTLY every item the
//!      client pushed before close() (in order), then the
//!      None/graceful-close marker.
//!
//!   4. **Graceful close yields None, not Err.** When the only
//!      terminal op is `close()` (no `cancel`), the drain MUST
//!      produce `Ready(None)` after the buffered items — NEVER
//!      `Ready(Some(Err(_)))`. A regression that turned graceful
//!      close into an error would force every well-behaved client-
//!      streaming RPC into the error path.
//!
//! Why this fuzzer in addition to grpc_streaming_bidi_cancel:
//! that target couples request+response and stresses cancellation
//! from either side; this target ISOLATES the request half and
//! pins the half-close (graceful end-of-stream) contract that
//! client-streaming RPCs depend on. A divergence here would make
//! every grpc-go / tonic peer that closes its request stream see
//! either a spurious CANCELLED or a truncated message sequence.
//!
//! Bounded envelope (MAX_OPS=128) keeps each iteration sub-second.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_streaming_client_half_close -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::grpc::streaming::{Streaming, StreamingRequest};
use libfuzzer_sys::fuzz_target;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

const MAX_OPS: usize = 128;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    /// Client pushes a u32 into the request stream.
    Push(u32),
    /// Server polls the stream once.
    Poll,
    /// Client half-closes the request stream gracefully.
    Close,
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    ops: Vec<Op>,
}

struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}
fn make_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fuzz_target!(|scenario: Scenario| {
    if scenario.ops.len() > MAX_OPS {
        return;
    }

    let mut stream = StreamingRequest::<u32>::open();
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);

    // Producer ground truth: every item that successfully pushed
    // BEFORE close() returned Ok.
    let mut pushed_open: Vec<u32> = Vec::new();
    // Consumer observation: every Ok(item) returned by poll_next.
    let mut polled_ok: Vec<u32> = Vec::new();
    let mut closed = false;

    for op in scenario.ops {
        match op {
            Op::Push(seq) => {
                let r = stream.push(seq);
                if !closed {
                    if r.is_ok() {
                        pushed_open.push(seq);
                    }
                    // r.is_err() under !closed only happens when the
                    // buffer cap is hit (resource_exhausted) — not a
                    // half-close violation.
                } else {
                    // Property 2: push-after-close MUST be Err. A
                    // silent Ok would smuggle an item into the buffer
                    // past the half-close marker.
                    assert!(
                        r.is_err(),
                        "push-after-close returned Ok — half-close was \
                         not enforced as terminal",
                    );
                }
            }
            Op::Poll => {
                let pinned = Pin::new(&mut stream);
                match pinned.poll_next(&mut cx) {
                    Poll::Ready(Some(Ok(item))) => polled_ok.push(item),
                    Poll::Ready(Some(Err(status))) => {
                        // Property 4: graceful close must NOT yield
                        // Err. The only way to legally see Err here
                        // is if cancel_with_error was called; we
                        // never call it in this fuzzer, so any Err
                        // is a contract violation.
                        panic!(
                            "graceful client-streaming yielded Err: status={status:?}, \
                             closed={closed}, polled_ok={polled_ok:?}",
                        );
                    }
                    Poll::Ready(None) => {
                        // None is only legal after close() has been
                        // called — the wire-level half-close marker.
                        assert!(
                            closed,
                            "stream returned None before close() — early \
                             truncation. polled_ok={polled_ok:?}",
                        );
                    }
                    Poll::Pending => {
                        // Legal: empty buffer, still open.
                    }
                }
            }
            Op::Close => {
                if !closed {
                    closed = true;
                    stream.close();
                }
                // Repeated close is idempotent; no assertion to make.
            }
        }
    }

    // Final drain: pull every remaining item, then the terminal
    // marker. After draining, polled_ok MUST equal pushed_open
    // (Property 3 — no truncation, no reorder).
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..MAX_OPS * 2 {
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(item))) => polled_ok.push(item),
            Poll::Ready(Some(Err(status))) => {
                panic!("drain yielded Err on graceful-close-only scenario: {status:?}");
            }
            Poll::Ready(None) => {
                // Reached the half-close marker.
                assert!(
                    closed,
                    "drain returned None without close() being called — \
                     graceful end-of-stream cannot appear from nowhere",
                );
                break;
            }
            Poll::Pending => break, // open with empty buffer
        }
    }

    // Property 3: zero truncation across the half-close boundary.
    if closed {
        assert_eq!(
            polled_ok, pushed_open,
            "client-streaming truncation: polled (server-side observation) \
             differs from pushed_open (items the client successfully sent \
             before close). polled={polled_ok:?}, pushed_open={pushed_open:?}",
        );
    } else {
        // No close happened — server may have polled fewer items than
        // pushed (some still in the buffer). polled_ok must still be
        // a strict prefix of pushed_open.
        assert!(
            polled_ok.len() <= pushed_open.len(),
            "consumer polled more than producer pushed",
        );
        for (i, (got, sent)) in polled_ok.iter().zip(pushed_open.iter()).enumerate() {
            assert_eq!(
                got, sent,
                "polled[{i}]={got} != pushed_open[{i}]={sent} — out-of-order \
                 or duplicate delivery",
            );
        }
    }
});
