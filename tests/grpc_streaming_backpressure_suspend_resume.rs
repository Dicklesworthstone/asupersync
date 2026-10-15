//! Conformance test for gRPC server-streaming backpressure SUSPEND/RESUME
//! (`asupersync-server-stack-hardening-eeexl1.10` AC2).
//!
//! The pre-existing `grpc_streaming_flow_control.rs` audit pins the
//! *fail-fast* backpressure signal: once the bounded buffer
//! (`MAX_STREAM_BUFFERED`) is full, `push` returns
//! `Err(Code::ResourceExhausted)`. That proves "no infinite buffering," but
//! it is only half of AC2. AC2's headline is *flow control*:
//!
//!   > the handler's outbound Stream is polled only within available window
//!   > credit ... a slow-client fixture shows handler stream **suspension at
//!   > window exhaustion** (no unbounded buffering — memory ceiling asserted)
//!   > and **resumption on window update**.
//!
//! In the lab/conformance model the bounded buffer IS the flow-control
//! window: window exhaustion == buffer full, window update == the consumer
//! draining an item. This file pins the suspend/resume primitive
//! `poll_reserve` that realizes that semantic on both production stream
//! halves — `StreamingRequest` (the request half, client → server) and
//! `client::ResponseStream` (the response half, server → client, which is the
//! AC2 server-streaming direction).
//!
//! Properties pinned (each on BOTH halves):
//!
//!   (a) **Suspension at window exhaustion.** When the buffer is full,
//!       `poll_reserve` returns `Poll::Pending` and registers the producer's
//!       waker — the producer parks instead of erroring or spinning.
//!
//!   (b) **Resumption on window update.** When the consumer drains exactly
//!       one item (`poll_next`), the parked producer's waker fires, and the
//!       subsequent `poll_reserve` returns `Poll::Ready(Ok(()))` — exactly
//!       one freed slot, no spurious early wake.
//!
//!   (c) **Memory ceiling under reserve-gated production.** A producer that
//!       gates every push behind `poll_reserve` never drives the buffer past
//!       `MAX_STREAM_BUFFERED`, even across many produce/drain cycles.
//!
//!   (d) **Fail-closed on close.** A producer parked on `poll_reserve` is
//!       woken when the stream closes/cancels and then observes
//!       `Poll::Ready(Err(FailedPrecondition))`, so a slow consumer that goes
//!       away cannot wedge the producer forever.
//!
//!   (e) **No suspension below the window.** With free capacity,
//!       `poll_reserve` is immediately `Ready(Ok)` and registers no waker.

use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::{CallCancellation, Streaming, StreamingRequest};
use asupersync::grpc::{MAX_STREAM_BUFFERED, ResponseStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const CAP: usize = MAX_STREAM_BUFFERED;

/// A waker that counts how many times it was woken, so a test can assert
/// that a window update (or close) actually unparked the producer.
struct CountingWaker {
    woken: AtomicUsize,
}

impl CountingWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            woken: AtomicUsize::new(0),
        })
    }

    fn count(&self) -> usize {
        self.woken.load(Ordering::SeqCst)
    }
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.woken.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.fetch_add(1, Ordering::SeqCst);
    }
}

/// A consumer-side waker that does nothing — the consumer drives drains
/// synchronously here, so it never needs to be re-polled.
fn noop_waker() -> Waker {
    Waker::noop().clone()
}

// ---------------------------------------------------------------------------
// StreamingRequest — request half (client → server)
// ---------------------------------------------------------------------------

#[test]
fn streaming_request_producer_suspends_at_window_then_resumes_on_drain() {
    let mut stream = StreamingRequest::<u32>::open();
    for i in 0..(CAP as u32) {
        stream.push(i).expect("fill to window");
    }
    assert!(stream.is_full(), "buffer must be at the window ceiling");

    // (a) Window exhausted: poll_reserve parks the producer.
    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    assert!(
        matches!(stream.poll_reserve(&mut pcx), Poll::Pending),
        "full buffer must suspend the producer, not admit a push",
    );
    assert_eq!(
        producer.count(),
        0,
        "producer must stay parked until a real window update",
    );

    // (b) Consumer drains exactly one item — the window update.
    let cw = noop_waker();
    let mut ccx = Context::from_waker(&cw);
    match Pin::new(&mut stream).poll_next(&mut ccx) {
        Poll::Ready(Some(Ok(0))) => {}
        other => panic!("expected FIFO drain of item 0, got {other:?}"),
    }
    assert_eq!(
        producer.count(),
        1,
        "draining one item must wake the parked producer exactly once",
    );

    // poll_reserve now reports the freed slot.
    assert!(
        matches!(stream.poll_reserve(&mut pcx), Poll::Ready(Ok(()))),
        "after a window update the producer must be admitted",
    );
    // ...and the slot is real: exactly one push fits, then back to the window.
    stream
        .push(CAP as u32)
        .expect("reserved slot accepts one push");
    assert!(stream.is_full(), "buffer back at the window after one push");
    assert!(
        matches!(stream.poll_reserve(&mut pcx), Poll::Pending),
        "window exhausted again after consuming the freed slot",
    );
}

#[test]
fn streaming_request_poll_reserve_ready_below_window_registers_no_waker() {
    let mut stream = StreamingRequest::<u32>::open();
    stream.push(1).expect("one item, far below window");

    // (e) Capacity available → immediate Ready, no parking.
    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Ready(Ok(()))));

    // Drain the only item; a producer that never parked must not be woken
    // by the drain (no spurious wakes leaking from the capacity slot).
    let cw = noop_waker();
    let mut ccx = Context::from_waker(&cw);
    let _ = Pin::new(&mut stream).poll_next(&mut ccx);
    assert_eq!(
        producer.count(),
        0,
        "a producer that was never parked must not receive a wake",
    );
}

#[test]
fn streaming_request_parked_producer_is_woken_and_fails_closed_on_close() {
    let mut stream = StreamingRequest::<u32>::open();
    for i in 0..(CAP as u32) {
        stream.push(i).expect("fill to window");
    }

    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Pending));

    // (d) A consumer that goes away closes the stream; the parked producer
    // must be unparked so it does not hang on a window that never reopens.
    stream.close();
    assert!(
        producer.count() >= 1,
        "closing the stream must wake the parked producer",
    );
    match stream.poll_reserve(&mut pcx) {
        Poll::Ready(Err(status)) => assert_eq!(
            status.code(),
            Code::FailedPrecondition,
            "closed-stream reserve must fail closed",
        ),
        other => panic!("expected Ready(Err(FailedPrecondition)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// client::ResponseStream — response half (server → client; AC2 direction)
// ---------------------------------------------------------------------------

#[test]
fn response_stream_producer_suspends_at_window_then_resumes_on_drain() {
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..(CAP as u32) {
        stream.push(Ok(i)).expect("fill to window");
    }
    assert!(stream.is_full());

    // (a) Window exhausted → producer parks.
    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Pending));
    assert_eq!(producer.count(), 0);

    // (b) Consumer drains one → window update wakes the producer.
    let cw = noop_waker();
    let mut ccx = Context::from_waker(&cw);
    match Pin::new(&mut stream).poll_next(&mut ccx) {
        Poll::Ready(Some(Ok(0))) => {}
        other => panic!("expected FIFO drain of item 0, got {other:?}"),
    }
    assert_eq!(
        producer.count(),
        1,
        "draining one item must wake the parked producer exactly once",
    );
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Ready(Ok(()))));
    stream
        .push(Ok(CAP as u32))
        .expect("reserved slot accepts one push");
    assert!(stream.is_full());
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Pending));
}

#[test]
fn response_stream_parked_producer_is_woken_and_fails_closed_on_cancel() {
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..(CAP as u32) {
        stream.push(Ok(i)).expect("fill to window");
    }

    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Pending));

    // (d) Cancelling the call (terminal status) must wake the parked producer
    // and then surface a fail-closed reserve result.
    stream.cancel(asupersync::grpc::status::Status::cancelled("client gone"));
    assert!(
        producer.count() >= 1,
        "cancelling the stream must wake the parked producer",
    );
    match stream.poll_reserve(&mut pcx) {
        Poll::Ready(Err(status)) => assert_eq!(status.code(), Code::FailedPrecondition),
        other => panic!("expected Ready(Err(FailedPrecondition)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Memory ceiling under reserve-gated production (both halves)
// ---------------------------------------------------------------------------

#[test]
fn streaming_request_memory_ceiling_holds_under_reserve_gated_production() {
    let mut stream = StreamingRequest::<u32>::open();
    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    let cw = noop_waker();
    let mut ccx = Context::from_waker(&cw);

    // A flow-controlled producer: push only while poll_reserve admits it.
    // Interleave with a deliberately slow consumer that drains one item per
    // round, simulating a slow client. The buffer must never exceed the
    // window across the whole run.
    let mut next: u32 = 0;
    let mut max_seen = 0usize;
    for _round in 0..(CAP * 2) {
        // Producer fills up to the window (reserve gates each push).
        while matches!(stream.poll_reserve(&mut pcx), Poll::Ready(Ok(()))) {
            stream
                .push(next)
                .expect("reserve-admitted push must succeed");
            next += 1;
            max_seen = max_seen.max(stream.buffer_len());
            if stream.buffer_len() >= CAP {
                break;
            }
        }
        assert!(
            stream.buffer_len() <= CAP,
            "buffer must never exceed the window ceiling",
        );
        // Slow consumer drains exactly one.
        let _ = Pin::new(&mut stream).poll_next(&mut ccx);
    }
    assert_eq!(
        max_seen, CAP,
        "reserve-gated production should reach — but never exceed — the window",
    );
}

#[test]
fn response_stream_memory_ceiling_holds_under_reserve_gated_production() {
    let mut stream = ResponseStream::<u32>::open();
    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    let cw = noop_waker();
    let mut ccx = Context::from_waker(&cw);

    let mut next: u32 = 0;
    let mut max_seen = 0usize;
    for _round in 0..(CAP * 2) {
        while matches!(stream.poll_reserve(&mut pcx), Poll::Ready(Ok(()))) {
            stream
                .push(Ok(next))
                .expect("reserve-admitted push must succeed");
            next += 1;
            max_seen = max_seen.max(stream.buffer_len());
            if stream.buffer_len() >= CAP {
                break;
            }
        }
        assert!(stream.buffer_len() <= CAP);
        let _ = Pin::new(&mut stream).poll_next(&mut ccx);
    }
    assert_eq!(max_seen, CAP);
}

// ---------------------------------------------------------------------------
// AC1 × AC2 composition: one call-scoped cancel drives the producer half too
// ---------------------------------------------------------------------------

#[test]
fn streaming_request_parked_producer_fails_closed_on_call_scoped_cancel() {
    // The AC1 `CallCancellation` couples both halves of a call. A producer
    // parked on `poll_reserve` at a full window must observe that SAME cancel
    // (not just the consumer's `poll_next`), so one cancel drives the whole
    // call: the producer fails closed instead of hanging on a window that will
    // never reopen.
    let cc = CallCancellation::new();
    let mut stream = StreamingRequest::<u32>::open_in_call(cc.clone());
    for i in 0..(CAP as u32) {
        stream.push(i).expect("fill to window");
    }

    let producer = CountingWaker::new();
    let pw = Waker::from(producer.clone());
    let mut pcx = Context::from_waker(&pw);
    assert!(matches!(stream.poll_reserve(&mut pcx), Poll::Pending));
    assert_eq!(producer.count(), 0);

    // One call-scoped cancel — the same op a client RST_STREAM / deadline /
    // server-Cx cancel drives — must unpark the parked producer.
    cc.cancel(asupersync::grpc::status::Status::cancelled(
        "peer RST_STREAM",
    ));
    assert!(
        producer.count() >= 1,
        "call-scoped cancel must wake the parked producer",
    );
    match stream.poll_reserve(&mut pcx) {
        Poll::Ready(Err(status)) => assert_eq!(
            status.code(),
            Code::Cancelled,
            "producer must fail closed with the call's terminal status",
        ),
        other => panic!("expected Ready(Err(Cancelled)), got {other:?}"),
    }
}
