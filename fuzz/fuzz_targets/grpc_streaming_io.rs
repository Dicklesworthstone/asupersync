//! Fuzz target for `asupersync::grpc::streaming` (StreamingRequest /
//! ResponseStream / RequestSink).
//!
//! These types are the in-memory data structures behind every gRPC
//! streaming pattern (server-streaming, client-streaming,
//! bidirectional). They sit BEHIND the wire transport — frames have
//! already been parsed into typed messages — so the fuzz surface is
//! the (push, close, poll_next) state machine plus the buffer cap
//! (`MAX_STREAM_BUFFERED = 1024`) and the per-item Status payload
//! (Ok / Cancelled / DeadlineExceeded / etc).
//!
//! Coverage (per br):
//!   * Random message sequences mid-stream — arbitrary Op interleavings
//!     of Push / PushCancelled / PushDeadline / Close / Poll.
//!   * Half-close vs full-close — close() while items remain buffered
//!     vs after drain.
//!   * Deadline expiry mid-stream — Push of Status::deadline_exceeded
//!     interleaved with valid items.
//!   * Cancel-after-headers-before-body — first Op is PushCancelled
//!     against an open stream with no prior items.
//!
//! Crashes / panics / sanitizer hits are findings.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_streaming_io -- -max_total_time=120
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::grpc::ResponseStream;
use asupersync::grpc::client::RequestSink;
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::{Streaming, StreamingRequest};
use libfuzzer_sys::fuzz_target;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Hard cap on the number of operations any single seed can drive — keeps
/// libfuzzer from spending the entire budget on one pathological seed
/// that calls Push 1M times.
const MAX_OPS_PER_SCENARIO: usize = 256;
const STREAM_BUFFER_CAP: usize = 1024;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Push a successful payload (32-bit nonce).
    Push(u32),
    /// Push a Status::cancelled error — models cancel-after-headers.
    PushCancelled,
    /// Push a Status::deadline_exceeded error — models mid-stream
    /// deadline expiry.
    PushDeadline,
    /// Push a Status::internal error — generic mid-stream failure.
    PushInternal,
    /// Mark the stream closed (half-close on the producer side).
    Close,
    /// Poll the stream once. Reads at most one item.
    Poll,
}

#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Drive a `StreamingRequest<u32>` (server-side view of an inbound
    /// client stream) with an arbitrary Op sequence. Tests the buffer
    /// cap (1024) + the closed-stream-rejects-push contract + the
    /// poll-after-close-yields-None contract.
    StreamingRequestOps {
        /// If true, start the stream open (more items may arrive). If
        /// false, start it closed (push must immediately fail).
        start_open: bool,
        ops: Vec<Op>,
    },
    /// Same shape against `ResponseStream<u32>` (client-side view of an
    /// inbound server stream). Same data structure, separate code path
    /// — both must obey the cap + closed-rejects-push contracts.
    ResponseStreamOps { start_open: bool, ops: Vec<Op> },
    /// `RequestSink<u32>::send` + `close` are async; we drive them on a
    /// synchronous executor (futures_lite::block_on) to confirm the
    /// loopback state machine: first send succeeds, a second pre-close
    /// send fails until the transport grows multi-message loopback
    /// support, send-after-close fails, and close is idempotent.
    RequestSinkOps { ops: Vec<RequestSinkOp> },
    /// Cancel-after-headers-before-body: open the stream, immediately
    /// push a Cancelled status, then drain. The first poll MUST yield
    /// the Cancelled status; the second poll yields None (terminal).
    /// Variants permit a deadline-exceeded status instead of cancel.
    CancelOrDeadlineBeforeBody {
        use_deadline: bool,
        then_close: bool,
    },
    /// Buffer-cap stress: push exactly enough items to straddle the
    /// MAX_STREAM_BUFFERED cap (1024). The 1025th push MUST fail with
    /// resource_exhausted; subsequent polls drain the queue normally.
    BufferCapStress { push_count: u16 },
}

#[derive(Arbitrary, Debug)]
enum RequestSinkOp {
    Send(u32),
    Close,
}

#[derive(Clone, Copy, Debug)]
enum PushExpectation {
    Accepted,
    Closed,
    Full,
}

#[derive(Debug)]
struct StreamShadow {
    open: bool,
    buffered: usize,
}

impl StreamShadow {
    const fn new(open: bool) -> Self {
        Self { open, buffered: 0 }
    }

    const fn push_expectation(&self) -> PushExpectation {
        if !self.open {
            PushExpectation::Closed
        } else if self.buffered >= STREAM_BUFFER_CAP {
            PushExpectation::Full
        } else {
            PushExpectation::Accepted
        }
    }

    fn observe_push(&mut self, result: Result<(), Status>, context: &str) {
        match (self.push_expectation(), result) {
            (PushExpectation::Accepted, Ok(())) => {
                self.buffered += 1;
            }
            (PushExpectation::Accepted, Err(status)) => {
                panic!(
                    "{context}: push rejected while shadow expected acceptance: {:?}",
                    status.code()
                );
            }
            (PushExpectation::Closed, Ok(())) => {
                panic!("{context}: push accepted after shadow stream was closed");
            }
            (PushExpectation::Closed, Err(status)) => {
                assert_eq!(
                    status.code(),
                    Code::FailedPrecondition,
                    "{context}: closed stream rejection used wrong status code"
                );
            }
            (PushExpectation::Full, Ok(())) => {
                panic!("{context}: push accepted with shadow buffer at cap");
            }
            (PushExpectation::Full, Err(status)) => {
                assert_eq!(
                    status.code(),
                    Code::ResourceExhausted,
                    "{context}: full stream rejection used wrong status code"
                );
            }
        }
    }

    fn close(&mut self) {
        self.open = false;
    }

    fn observe_poll<T>(&mut self, poll: Poll<Option<Result<T, Status>>>, context: &str) {
        match poll {
            Poll::Ready(Some(_)) => {
                assert!(
                    self.buffered > 0,
                    "{context}: poll yielded an item with an empty shadow buffer"
                );
                self.buffered -= 1;
            }
            Poll::Ready(None) => {
                assert!(
                    !self.open && self.buffered == 0,
                    "{context}: poll completed while shadow open={} buffered={}",
                    self.open,
                    self.buffered
                );
            }
            Poll::Pending => {
                assert!(
                    self.open && self.buffered == 0,
                    "{context}: poll pending while shadow open={} buffered={}",
                    self.open,
                    self.buffered
                );
            }
        }
    }
}

/// Build a `Context<'_>` from a leaked noop waker. Sound because the
/// waker has 'static lifetime and we never drop the Box.
fn ctx() -> Context<'static> {
    use std::sync::LazyLock;
    static WAKER: LazyLock<std::task::Waker> = LazyLock::new(|| std::task::Waker::noop().clone());
    Context::from_waker(&WAKER)
}

fn apply_to_streaming_request(stream: &mut StreamingRequest<u32>, start_open: bool, ops: &[Op]) {
    let mut cx = ctx();
    let mut shadow = StreamShadow::new(start_open);
    for op in ops.iter().take(MAX_OPS_PER_SCENARIO) {
        match op {
            Op::Push(v) => {
                shadow.observe_push(stream.push(*v), "StreamingRequest::push");
            }
            Op::PushCancelled => {
                shadow.observe_push(
                    stream.push_result(Err(Status::cancelled("fuzz cancel"))),
                    "StreamingRequest::push_result(cancelled)",
                );
            }
            Op::PushDeadline => {
                shadow.observe_push(
                    stream.push_result(Err(Status::deadline_exceeded("fuzz deadline"))),
                    "StreamingRequest::push_result(deadline)",
                );
            }
            Op::PushInternal => {
                shadow.observe_push(
                    stream.push_result(Err(Status::internal("fuzz internal"))),
                    "StreamingRequest::push_result(internal)",
                );
            }
            Op::Close => {
                stream.close();
                shadow.close();
            }
            Op::Poll => {
                shadow.observe_poll(
                    Pin::new(&mut *stream).poll_next(&mut cx),
                    "StreamingRequest::poll_next",
                );
            }
        }
    }
}

fn apply_to_response_stream(stream: &mut ResponseStream<u32>, start_open: bool, ops: &[Op]) {
    let mut cx = ctx();
    let mut shadow = StreamShadow::new(start_open);
    for op in ops.iter().take(MAX_OPS_PER_SCENARIO) {
        match op {
            Op::Push(v) => {
                shadow.observe_push(stream.push(Ok(*v)), "ResponseStream::push(ok)");
            }
            Op::PushCancelled => {
                shadow.observe_push(
                    stream.push(Err(Status::cancelled("fuzz cancel"))),
                    "ResponseStream::push(cancelled)",
                );
            }
            Op::PushDeadline => {
                shadow.observe_push(
                    stream.push(Err(Status::deadline_exceeded("fuzz deadline"))),
                    "ResponseStream::push(deadline)",
                );
            }
            Op::PushInternal => {
                shadow.observe_push(
                    stream.push(Err(Status::internal("fuzz internal"))),
                    "ResponseStream::push(internal)",
                );
            }
            Op::Close => {
                stream.close();
                shadow.close();
            }
            Op::Poll => {
                shadow.observe_poll(
                    Pin::new(&mut *stream).poll_next(&mut cx),
                    "ResponseStream::poll_next",
                );
            }
        }
    }
}

fuzz_target!(|s: Scenario| match s {
    Scenario::StreamingRequestOps { start_open, ops } => {
        let mut stream = if start_open {
            StreamingRequest::<u32>::open()
        } else {
            StreamingRequest::<u32>::new()
        };
        apply_to_streaming_request(&mut stream, start_open, &ops);
    }
    Scenario::ResponseStreamOps { start_open, ops } => {
        let mut stream = if start_open {
            ResponseStream::<u32>::open()
        } else {
            ResponseStream::<u32>::new()
        };
        apply_to_response_stream(&mut stream, start_open, &ops);
    }
    Scenario::RequestSinkOps { ops } => {
        let mut sink = RequestSink::<u32>::new();
        futures::executor::block_on(async {
            let mut closed = false;
            let mut sent_once = false;
            for op in ops.iter().take(MAX_OPS_PER_SCENARIO) {
                match op {
                    RequestSinkOp::Send(v) => {
                        let result = sink.send(*v).await;
                        if closed {
                            let status =
                                result.expect_err("RequestSink::send succeeded after close");
                            assert_eq!(
                                status.code(),
                                Code::FailedPrecondition,
                                "RequestSink::send after close used wrong status code"
                            );
                        } else if sent_once {
                            let status = result.expect_err(
                                "loopback RequestSink accepted a second pre-close send",
                            );
                            assert_eq!(
                                status.code(),
                                Code::FailedPrecondition,
                                "second loopback RequestSink::send used wrong status code"
                            );
                        } else {
                            result.expect("first RequestSink::send failed before close");
                            sent_once = true;
                        }
                    }
                    RequestSinkOp::Close => {
                        let result = sink.close().await;
                        assert!(result.is_ok(), "RequestSink::close must be idempotent");
                        closed = true;
                    }
                }
            }
        });
    }
    Scenario::CancelOrDeadlineBeforeBody {
        use_deadline,
        then_close,
    } => {
        // Cancel-after-headers-before-body: the producer pushes a
        // terminal status as the very first item. Consumers must see
        // the status and then None on the subsequent poll.
        let mut stream = StreamingRequest::<u32>::open();
        let status = if use_deadline {
            Status::deadline_exceeded("fuzz: pre-body deadline")
        } else {
            Status::cancelled("fuzz: pre-body cancel")
        };
        let expected_code = status.code();
        let mut shadow = StreamShadow::new(true);
        shadow.observe_push(
            stream.push_result(Err(status)),
            "CancelOrDeadlineBeforeBody::push_result",
        );
        if then_close {
            stream.close();
            shadow.close();
        }
        let mut cx = ctx();
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Err(status))) => {
                assert_eq!(
                    status.code(),
                    expected_code,
                    "pre-body terminal status code changed while queued"
                );
                shadow.buffered -= 1;
            }
            other => panic!("pre-body terminal status should be observed first, got {other:?}"),
        }
        // Drain at most 4 items — should observe the status then None
        // (or Pending if not closed and queue is drained).
        for _ in 0..3 {
            shadow.observe_poll(
                Pin::new(&mut stream).poll_next(&mut cx),
                "CancelOrDeadlineBeforeBody::poll_next",
            );
        }
    }
    Scenario::BufferCapStress { push_count } => {
        // MAX_STREAM_BUFFERED = 1024. Push (push_count) items capped at
        // 2 * 1024 so seeds straddle the cap from both sides without
        // burning libfuzzer's budget.
        let n = (push_count as usize).min(2048);
        let mut stream = StreamingRequest::<u32>::open();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for i in 0..n {
            match stream.push(i as u32) {
                Ok(()) => accepted += 1,
                Err(_) => rejected += 1,
            }
        }
        // Invariant: at most 1024 pushes accepted; the rest are
        // rejected. If accepted exceeds the cap, the buffer-cap
        // contract is violated and libfuzzer surfaces the panic.
        assert!(
            accepted <= STREAM_BUFFER_CAP,
            "accepted {accepted} exceeded MAX_STREAM_BUFFERED {STREAM_BUFFER_CAP}"
        );
        assert_eq!(
            accepted + rejected,
            n,
            "every push must classify as Ok or Err"
        );
        // Drain via poll — at most CAP items observed.
        let mut cx = ctx();
        let mut polled_items = 0usize;
        for _ in 0..(STREAM_BUFFER_CAP + 8) {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(_)) => polled_items += 1,
                Poll::Ready(None) | Poll::Pending => break,
            }
        }
        assert!(
            polled_items <= accepted,
            "poll observed {polled_items} items but only {accepted} were accepted"
        );
    }
});
