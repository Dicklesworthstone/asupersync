//! Fuzz target for `src/grpc/streaming.rs` client-streaming flow control.
//!
//! Exercises the client-side request buffer and request sink against:
//! 1. Buffer saturation returning `ResourceExhausted`
//! 2. Draining queued items preserving FIFO order and error/value boundaries
//! 3. Refilling drained capacity without dropping flow-control enforcement
//! 4. Closing while buffered items remain and rejecting later pushes fail-closed
//! 5. `RequestSink` send/close sequencing preserving `sent_count`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::grpc::{
    streaming::{RequestSink, Streaming, StreamingRequest},
    Code, GrpcError, Status,
};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const MAX_FILL_ATTEMPTS: usize = 1536;
const MAX_AFTER_CLOSE_ATTEMPTS: usize = 32;
const MAX_SINK_OPS: usize = 96;

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    stream: StreamScenario,
    sink: SinkScenario,
}

#[derive(Debug, Clone, Arbitrary)]
struct StreamScenario {
    error_stride: u8,
    drain_count: u16,
    refill_values: Vec<u16>,
    close_before_drain: bool,
    close_after_refill: bool,
    after_close_values: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
struct SinkScenario {
    ops: Vec<SinkOp>,
}

#[derive(Debug, Clone, Arbitrary)]
enum SinkOp {
    Send(u16),
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedItem {
    Value(u16),
    Cancelled,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_grpc_client_streaming_flow_control(input);
});

fn fuzz_grpc_client_streaming_flow_control(input: FuzzInput) {
    exercise_streaming_request(input.stream);
    exercise_request_sink(input.sink);
}

fn exercise_streaming_request(mut scenario: StreamScenario) {
    scenario.after_close_values.truncate(MAX_AFTER_CLOSE_ATTEMPTS);

    let mut stream = StreamingRequest::<u16>::open();
    assert!(
        matches!(poll_request(&mut stream), Poll::Pending),
        "open request stream with no items must remain pending"
    );

    let error_stride = usize::from(scenario.error_stride).saturating_add(2);
    let mut queued = VecDeque::new();
    let mut saturated = false;

    for idx in 0..MAX_FILL_ATTEMPTS {
        let payload = u16::try_from(idx).expect("fill attempts fit into u16");
        let result = if (idx + 1) % error_stride == 0 {
            stream.push_result(Err(Status::cancelled(format!("prefill-{idx}"))))
        } else {
            stream.push(payload)
        };

        match result {
            Ok(()) => {
                queued.push_back(if (idx + 1) % error_stride == 0 {
                    ExpectedItem::Cancelled
                } else {
                    ExpectedItem::Value(payload)
                });
            }
            Err(status) => {
                assert_eq!(
                    status.code(),
                    Code::ResourceExhausted,
                    "request buffer saturation must fail with ResourceExhausted"
                );
                saturated = true;
                break;
            }
        }
    }

    assert!(
        saturated,
        "client-streaming request buffer should saturate before MAX_FILL_ATTEMPTS"
    );

    let mut closed = false;
    if scenario.close_before_drain {
        stream.close();
        closed = true;
        assert_after_close_pushes(&mut stream, &scenario.after_close_values);
    }

    let drain_count = usize::from(scenario.drain_count).min(queued.len());
    for _ in 0..drain_count {
        let expected = queued.pop_front().expect("drain must have queued item");
        assert_next_item(&mut stream, expected);
    }

    if queued.is_empty() && !closed {
        assert!(
            matches!(poll_request(&mut stream), Poll::Pending),
            "open stream with drained buffer should remain pending"
        );
    }

    if !closed {
        for step in 0..=drain_count {
            let payload = scenario.refill_values.get(step).copied().unwrap_or_else(|| {
                20_000_u16.wrapping_add(u16::try_from(step).expect("step fits in u16"))
            });
            let use_error = (usize::from(payload) + step + 1) % error_stride == 0;
            let result = if use_error {
                stream.push_result(Err(Status::cancelled(format!("refill-{step}"))))
            } else {
                stream.push(payload)
            };

            if step < drain_count {
                result.expect("refilling drained slots must succeed");
                queued.push_back(if use_error {
                    ExpectedItem::Cancelled
                } else {
                    ExpectedItem::Value(payload)
                });
            } else {
                let err = result.expect_err("refill past drained capacity must fail");
                assert_eq!(
                    err.code(),
                    Code::ResourceExhausted,
                    "refill past recovered capacity must still enforce backpressure"
                );
            }
        }
    }

    if !closed && scenario.close_after_refill {
        stream.close();
        closed = true;
        assert_after_close_pushes(&mut stream, &scenario.after_close_values);
    }

    if !closed {
        stream.close();
        closed = true;
        assert_after_close_pushes(&mut stream, &scenario.after_close_values);
    }

    while let Some(expected) = queued.pop_front() {
        assert_next_item(&mut stream, expected);
    }

    assert!(
        matches!(poll_request(&mut stream), Poll::Ready(None)),
        "closed and drained stream must terminate with None"
    );

    stream.close();
    assert!(
        matches!(poll_request(&mut stream), Poll::Ready(None)),
        "re-closing an already drained stream must stay terminal"
    );
}

fn exercise_request_sink(mut scenario: SinkScenario) {
    scenario.ops.truncate(MAX_SINK_OPS);

    futures_lite::future::block_on(async move {
        let mut sink = RequestSink::<u16>::new();
        let mut expected_sent = 0usize;
        let mut closed = false;

        for op in scenario.ops {
            match op {
                SinkOp::Send(value) => {
                    let result = sink.send(value).await;
                    if closed {
                        let err = result.expect_err("send after close must fail");
                        assert!(
                            matches!(err, GrpcError::Protocol(_)),
                            "closed sink must reject sends with protocol error"
                        );
                        assert_eq!(
                            sink.sent_count(),
                            expected_sent,
                            "failed send must not advance sent_count"
                        );
                    } else {
                        result.expect("open sink send must succeed");
                        expected_sent += 1;
                        assert_eq!(
                            sink.sent_count(),
                            expected_sent,
                            "successful send must advance sent_count"
                        );
                    }
                }
                SinkOp::Close => {
                    sink.close().await.expect("close must succeed");
                    closed = true;
                    assert_eq!(
                        sink.sent_count(),
                        expected_sent,
                        "closing the sink must preserve sent_count"
                    );
                }
            }
        }

        if !closed {
            sink.close().await.expect("final close must succeed");
        }

        let err = sink
            .send(u16::MAX)
            .await
            .expect_err("post-close send must fail");
        assert!(
            matches!(err, GrpcError::Protocol(_)),
            "post-close send must stay fail-closed"
        );
        assert_eq!(
            sink.sent_count(),
            expected_sent,
            "post-close send must not advance sent_count"
        );
    });
}

fn poll_request(stream: &mut StreamingRequest<u16>) -> Poll<Option<Result<u16, Status>>> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    Pin::new(stream).poll_next(&mut cx)
}

fn assert_after_close_pushes(stream: &mut StreamingRequest<u16>, values: &[u16]) {
    for (idx, value) in values.iter().copied().enumerate() {
        let result = if idx % 2 == 0 {
            stream.push(value)
        } else {
            stream.push_result(Err(Status::cancelled(format!("after-close-{idx}"))))
        };
        let err = result.expect_err("push after close must fail");
        assert_eq!(
            err.code(),
            Code::FailedPrecondition,
            "push after close must fail with FailedPrecondition"
        );
    }

    let err = stream
        .push_result(Err(Status::cancelled("after-close-sentinel")))
        .expect_err("closed stream must reject sentinel push");
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "closed stream must keep rejecting new items"
    );
}

fn assert_next_item(stream: &mut StreamingRequest<u16>, expected: ExpectedItem) {
    match (poll_request(stream), expected) {
        (Poll::Ready(Some(Ok(value))), ExpectedItem::Value(expected)) => {
            assert_eq!(value, expected, "stream must preserve queued value order");
        }
        (Poll::Ready(Some(Err(status))), ExpectedItem::Cancelled) => {
            assert_eq!(
                status.code(),
                Code::Cancelled,
                "queued error results must survive round-trip through the buffer"
            );
        }
        (actual, expected) => panic!(
            "unexpected client-streaming poll result: actual={actual:?} expected={expected:?}"
        ),
    }
}
