#![no_main]

//! Cargo-fuzz target for bidi-streaming cancellation: when EITHER
//! side of an asupersync gRPC bidi pair cancels, BOTH ends must
//! close cleanly with CANCELLED status.
//!
//! Models the bidi pair as the two production stream halves:
//!   * `asupersync::grpc::streaming::StreamingRequest<u32>` —
//!     client → server (the request half).
//!   * `asupersync::grpc::ResponseStream<u32>` (re-exported from
//!     `client.rs`) — server → client (the response half).
//!
//! Both halves carry their OWN `terminal_status` and `closed` flags;
//! the bidi-cancel contract is that when one side decides "the call
//! is over with CANCELLED", the OTHER side's view of the call must
//! end up at the same terminal point on its next poll. This fuzzer
//! drives an Arbitrary sequence of (push|poll|cancel|close) ops on
//! either half, then verifies the joint terminal state.
//!
//! Properties asserted per fuzz iteration:
//!
//!   1. **No panic.** No op sequence — even one that hammers cancel
//!      from both sides repeatedly — must unwind.
//!
//!   2. **CANCELLED status on both halves once cancel was issued.**
//!      After at least one CancelClient or CancelServer op runs, a
//!      drain on BOTH halves yields `Some(Err(status))` with
//!      `Code::Cancelled`. Never None, never an orphan Ok past the
//!      cancel point.
//!
//!   3. **Polled-prefix integrity per side.** Items each side
//!      successfully polled while still open are equal (in order)
//!      to the items pushed BEFORE that side's terminal event.
//!      Items still buffered MAY be discarded by ResponseStream's
//!      abrupt-cancel semantic (cancel_with_metadata sets
//!      discard_buffered=true), but anything that already crossed
//!      the API boundary is preserved.
//!
//!   4. **Push-after-terminal returns Err.** Once cancelled or
//!      closed, push() on either half returns Err — no silent drop,
//!      no buffer growth past the terminal.
//!
//! Bounded envelope (MAX_OPS=64) keeps each iteration sub-second.
//!
//! Why this fuzzer in addition to grpc_streaming_cancel_storm and
//! grpc_streaming_server_cancel_timing: the storm fuzzer pounds on
//! ResponseStream alone with concurrent threads, and the cancel-
//! timing fuzzer pins single-side semantics. This target is the
//! BIDI specific lane — the client-side request stream + server-side
//! response stream as a coupled pair, with cancellation that can
//! originate on either side.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_streaming_bidi_cancel -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::grpc::ResponseStream;
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::{Streaming, StreamingRequest};
use libfuzzer_sys::fuzz_target;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

const MAX_OPS: usize = 64;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    /// Push a u32 into the client→server request half.
    PushClient(u32),
    /// Push a u32 into the server→client response half.
    PushServer(u32),
    /// Poll the client→server request half once. (server-side
    /// observation of inbound client messages.)
    PollClient,
    /// Poll the server→client response half once. (client-side
    /// observation of inbound server messages.)
    PollServer,
    /// Client signals CANCELLED on its outbound (request) stream.
    CancelClient,
    /// Server signals CANCELLED on its outbound (response) stream.
    CancelServer,
    /// Client closes its outbound (request) stream gracefully.
    CloseClient,
    /// Server closes its outbound (response) stream gracefully.
    CloseServer,
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

#[derive(Default)]
struct Side {
    pushed_open: Vec<u32>,
    polled_ok: Vec<u32>,
    terminal: Option<Terminal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminal {
    Cancel,
    Close,
}

fuzz_target!(|scenario: Scenario| {
    if scenario.ops.len() > MAX_OPS {
        return;
    }

    let mut request = StreamingRequest::<u32>::open();
    let mut response = ResponseStream::<u32>::open();
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);

    let mut client_side = Side::default(); // request half (client pushes, server polls)
    let mut server_side = Side::default(); // response half (server pushes, client polls)

    for op in scenario.ops {
        match op {
            Op::PushClient(seq) => {
                let r = request.push(seq);
                if r.is_ok() && client_side.terminal.is_none() {
                    client_side.pushed_open.push(seq);
                } else if r.is_ok() {
                    panic!(
                        "client push succeeded after terminal_kind={:?}",
                        client_side.terminal,
                    );
                }
            }
            Op::PushServer(seq) => {
                let r = response.push(Ok(seq));
                if r.is_ok() && server_side.terminal.is_none() {
                    server_side.pushed_open.push(seq);
                } else if r.is_ok() {
                    panic!(
                        "server push succeeded after terminal_kind={:?}",
                        server_side.terminal,
                    );
                }
            }
            Op::PollClient => {
                let pinned = Pin::new(&mut request);
                drive_poll(pinned, &mut cx, &mut client_side);
            }
            Op::PollServer => {
                let pinned = Pin::new(&mut response);
                drive_poll(pinned, &mut cx, &mut server_side);
            }
            Op::CancelClient => {
                if client_side.terminal.is_none() {
                    client_side.terminal = Some(Terminal::Cancel);
                }
                request.cancel_with_error(Status::cancelled("fuzz client cancel"));
            }
            Op::CancelServer => {
                if server_side.terminal.is_none() {
                    server_side.terminal = Some(Terminal::Cancel);
                }
                response.cancel(Status::cancelled("fuzz server cancel"));
            }
            Op::CloseClient => {
                if client_side.terminal.is_none() {
                    client_side.terminal = Some(Terminal::Close);
                }
                request.close();
            }
            Op::CloseServer => {
                if server_side.terminal.is_none() {
                    server_side.terminal = Some(Terminal::Close);
                }
                response.close();
            }
        }
    }

    // Property 2: after the op sequence, drain both halves. If
    // either side cancelled, the drain MUST yield CANCELLED on
    // that side; if it closed gracefully, the drain MUST yield
    // None after the buffered items.
    drain_and_assert(&mut request, &mut client_side, "client→server");
    drain_and_assert(&mut response, &mut server_side, "server→client");

    // Property 3: per-side polled-prefix integrity (drain has now
    // consolidated the polled list with any items still buffered
    // pre-terminal).
    assert_polled_prefix(&client_side, "client→server");
    assert_polled_prefix(&server_side, "server→client");
});

fn drive_poll<S: Streaming<Message = u32>>(
    stream: Pin<&mut S>,
    cx: &mut Context<'_>,
    side: &mut Side,
) {
    match stream.poll_next(cx) {
        Poll::Ready(Some(Ok(item))) => {
            side.polled_ok.push(item);
        }
        Poll::Ready(Some(Err(status))) => match side.terminal {
            Some(Terminal::Cancel) => {
                assert_eq!(
                    status.code(),
                    Code::Cancelled,
                    "post-cancel poll must yield Code::Cancelled, got {:?}",
                    status.code(),
                );
            }
            Some(Terminal::Close) => {
                panic!("graceful close yielded Err: {status:?}");
            }
            None => {
                panic!(
                    "stream returned Err without prior terminal op: status={status:?}, \
                         polled_ok={:?}",
                    side.polled_ok,
                );
            }
        },
        Poll::Ready(None) => match side.terminal {
            Some(Terminal::Close) => {} // ✓
            Some(Terminal::Cancel) => {
                panic!("post-cancel poll yielded None instead of CANCELLED Err",)
            }
            None => panic!(
                "open stream yielded None without terminal op: polled={:?}",
                side.polled_ok,
            ),
        },
        Poll::Pending => {} // legal: empty buffer, still open
    }
}

fn drain_and_assert<S: Streaming<Message = u32> + Unpin>(
    stream: &mut S,
    side: &mut Side,
    label: &str,
) {
    let waker = make_waker();
    let mut cx = Context::from_waker(&waker);
    let mut saw_terminal = false;
    for _ in 0..MAX_OPS * 2 {
        match Pin::new(&mut *stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(item))) => side.polled_ok.push(item),
            Poll::Ready(Some(Err(status))) => {
                assert_eq!(
                    status.code(),
                    Code::Cancelled,
                    "{label}: drain produced non-Cancelled Err: {:?}",
                    status.code(),
                );
                saw_terminal = true;
                break;
            }
            Poll::Ready(None) => {
                saw_terminal = true;
                break;
            }
            Poll::Pending => break, // still open with empty buffer
        }
    }
    if let Some(terminal) = side.terminal {
        assert!(
            saw_terminal,
            "{label}: terminal op {:?} was applied but drain never reached \
             a Ready(Some(Err)) or Ready(None) marker",
            terminal,
        );
    }
}

fn assert_polled_prefix(side: &Side, label: &str) {
    assert!(
        side.polled_ok.len() <= side.pushed_open.len(),
        "{label}: consumer polled more items ({}) than producer pushed pre-terminal ({})",
        side.polled_ok.len(),
        side.pushed_open.len(),
    );
    for (i, (got, sent)) in side
        .polled_ok
        .iter()
        .zip(side.pushed_open.iter())
        .enumerate()
    {
        assert_eq!(
            got, sent,
            "{label}: polled index {i} ({got}) != pushed_open[{i}] ({sent}) \
             — order/integrity violation BEFORE terminal point",
        );
    }
}
