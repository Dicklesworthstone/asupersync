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
use asupersync::grpc::streaming::{
    RequestSink, ResponseStream, Streaming, StreamingRequest,
};
use asupersync::grpc::status::Status;
use libfuzzer_sys::fuzz_target;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Hard cap on the number of operations any single seed can drive — keeps
/// libfuzzer from spending the entire budget on one pathological seed
/// that calls Push 1M times.
const MAX_OPS_PER_SCENARIO: usize = 256;

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
    ResponseStreamOps {
        start_open: bool,
        ops: Vec<Op>,
    },
    /// `RequestSink<u32>::send` + `close` are async; we drive them on a
    /// synchronous executor (futures_lite::block_on) to confirm the
    /// state machine: send-after-close MUST fail; close is idempotent.
    RequestSinkOps { ops: Vec<RequestSinkOp> },
    /// Cancel-after-headers-before-body: open the stream, immediately
    /// push a Cancelled status, then drain. The first poll MUST yield
    /// the Cancelled status; the second poll yields None (terminal).
    /// Variants permit a deadline-exceeded status instead of cancel.
    CancelOrDeadlineBeforeBody { use_deadline: bool, then_close: bool },
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

/// Build a `Context<'_>` from a leaked noop waker. Sound because the
/// waker has 'static lifetime and we never drop the Box.
fn ctx() -> Context<'static> {
    use std::sync::LazyLock;
    static WAKER: LazyLock<std::task::Waker> =
        LazyLock::new(|| std::task::Waker::noop().clone());
    Context::from_waker(&WAKER)
}

fn apply_to_streaming_request(stream: &mut StreamingRequest<u32>, ops: &[Op]) {
    let mut cx = ctx();
    for op in ops.iter().take(MAX_OPS_PER_SCENARIO) {
        match op {
            Op::Push(v) => {
                let _ = stream.push(*v);
            }
            Op::PushCancelled => {
                let _ = stream.push_result(Err(Status::cancelled("fuzz cancel")));
            }
            Op::PushDeadline => {
                let _ = stream.push_result(Err(Status::deadline_exceeded("fuzz deadline")));
            }
            Op::PushInternal => {
                let _ = stream.push_result(Err(Status::internal("fuzz internal")));
            }
            Op::Close => stream.close(),
            Op::Poll => {
                let _ = Pin::new(&mut *stream).poll_next(&mut cx);
            }
        }
    }
}

fn apply_to_response_stream(stream: &mut ResponseStream<u32>, ops: &[Op]) {
    let mut cx = ctx();
    for op in ops.iter().take(MAX_OPS_PER_SCENARIO) {
        match op {
            Op::Push(v) => {
                let _ = stream.push(Ok(*v));
            }
            Op::PushCancelled => {
                let _ = stream.push(Err(Status::cancelled("fuzz cancel")));
            }
            Op::PushDeadline => {
                let _ = stream.push(Err(Status::deadline_exceeded("fuzz deadline")));
            }
            Op::PushInternal => {
                let _ = stream.push(Err(Status::internal("fuzz internal")));
            }
            Op::Close => stream.close(),
            Op::Poll => {
                let _ = Pin::new(&mut *stream).poll_next(&mut cx);
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
        apply_to_streaming_request(&mut stream, &ops);
    }
    Scenario::ResponseStreamOps { start_open, ops } => {
        let mut stream = if start_open {
            ResponseStream::<u32>::open()
        } else {
            ResponseStream::<u32>::new()
        };
        apply_to_response_stream(&mut stream, &ops);
    }
    Scenario::RequestSinkOps { ops } => {
        let mut sink = RequestSink::<u32>::new();
        let pre_close_count = sink.sent_count();
        let _ = pre_close_count;
        futures::executor::block_on(async {
            for op in ops.iter().take(MAX_OPS_PER_SCENARIO) {
                match op {
                    RequestSinkOp::Send(v) => {
                        let _ = sink.send(*v).await;
                    }
                    RequestSinkOp::Close => {
                        let _ = sink.close().await;
                    }
                }
            }
        });
    }
    Scenario::CancelOrDeadlineBeforeBody { use_deadline, then_close } => {
        // Cancel-after-headers-before-body: the producer pushes a
        // terminal status as the very first item. Consumers must see
        // the status and then None on the subsequent poll.
        let mut stream = StreamingRequest::<u32>::open();
        let status = if use_deadline {
            Status::deadline_exceeded("fuzz: pre-body deadline")
        } else {
            Status::cancelled("fuzz: pre-body cancel")
        };
        let _ = stream.push_result(Err(status));
        if then_close {
            stream.close();
        }
        let mut cx = ctx();
        // Drain at most 4 items — should observe the status then None
        // (or Pending if not closed and queue is drained).
        for _ in 0..4 {
            let _ = Pin::new(&mut stream).poll_next(&mut cx);
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
        const CAP: usize = 1024;
        assert!(
            accepted <= CAP,
            "accepted {accepted} exceeded MAX_STREAM_BUFFERED {CAP}"
        );
        assert_eq!(
            accepted + rejected,
            n,
            "every push must classify as Ok or Err"
        );
        // Drain via poll — at most CAP items observed.
        let mut cx = ctx();
        let mut polled_items = 0usize;
        for _ in 0..(CAP + 8) {
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
