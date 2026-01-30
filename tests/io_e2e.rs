//! Async I/O Traits Verification Suite - E2E Tests
//!
//! These tests exercise adapter composition and end-to-end I/O flows using the
//! asupersync async I/O traits and extension methods.

#[macro_use]
mod common;

use asupersync::io::{
    copy, copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, BufReader, ReadBuf, SplitStream,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::reactor::{Event, Interest};
use asupersync::runtime::IoOp;
use asupersync::trace::ReplayTrace;
use asupersync::types::{Budget, CancelReason, Outcome, RegionId, TaskId};
use common::*;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
#[cfg(unix)]
use std::{os::unix::io::AsRawFd, os::unix::net::UnixStream};

// ============================================================================
// Test Infrastructure
// ============================================================================

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn poll_once<F: std::future::Future>(fut: &mut Pin<&mut F>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    fut.as_mut().poll(&mut cx)
}

fn poll_ready<F: std::future::Future>(
    fut: &mut Pin<&mut F>,
    max_polls: usize,
) -> Option<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..max_polls {
        if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
            return Some(output);
        }
    }
    None
}

#[cfg(unix)]
struct TestSource {
    stream: UnixStream,
    _peer: UnixStream,
}

#[cfg(unix)]
impl TestSource {
    fn new() -> Self {
        let (stream, peer) = UnixStream::pair().expect("unix stream pair");
        stream.set_nonblocking(true).expect("set nonblocking");
        peer.set_nonblocking(true).expect("set nonblocking");
        Self {
            stream,
            _peer: peer,
        }
    }
}

#[cfg(unix)]
impl AsRawFd for TestSource {
    fn as_raw_fd(&self) -> i32 {
        self.stream.as_raw_fd()
    }
}

#[cfg(unix)]
fn spawn_cancellable_task(runtime: &mut LabRuntime, region: RegionId) -> TaskId {
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {
            loop {
                let Some(cx) = asupersync::cx::Cx::current() else {
                    return;
                };
                if cx.checkpoint().is_err() {
                    return;
                }
                asupersync::runtime::yield_now().await;
            }
        })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    task_id
}

#[cfg(unix)]
fn cancel_region(runtime: &mut LabRuntime, region: RegionId, reason: &CancelReason) {
    let tasks = runtime.state.cancel_request(region, reason, None);
    let mut scheduler = runtime.scheduler.lock().unwrap();
    for (task, priority) in tasks {
        scheduler.schedule_cancel(task, priority);
    }
}

#[cfg(unix)]
fn record_io_replay_trace(seed: u64) -> ReplayTrace {
    let config = LabConfig::new(seed).with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let task_id = spawn_cancellable_task(&mut runtime, region);

    let io_op = IoOp::submit(
        &mut runtime.state,
        task_id,
        region,
        Some("e2e io op".to_string()),
    )
    .expect("submit io op");

    let source = TestSource::new();
    let waker = noop_waker();
    let registration = runtime
        .state
        .io_driver_handle()
        .expect("io driver handle")
        .register(&source, Interest::READABLE, waker)
        .expect("register io");
    let token = registration.token();

    runtime
        .lab_reactor()
        .inject_event(token, Event::readable(token), Duration::from_millis(1));
    runtime.advance_time(1_000_000);
    runtime.step_for_test();

    let cancel_reason = CancelReason::shutdown();
    cancel_region(&mut runtime, region, &cancel_reason);
    io_op.cancel(&mut runtime.state).expect("cancel io op");
    runtime.run_until_quiescent();

    let pending = runtime.state.pending_obligation_count();
    let violations = runtime.check_invariants();
    assert!(
        pending == 0,
        "expected no pending obligations after cancel: {pending}"
    );
    assert!(
        violations.is_empty(),
        "expected no invariant violations after cancel: {violations:?}"
    );

    runtime.finish_replay_trace().expect("replay trace")
}

// ============================================================================
// Test Streams
// ============================================================================

#[derive(Debug)]
struct TestStream {
    read_data: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
}

impl TestStream {
    fn new(read_data: &[u8]) -> Self {
        Self {
            read_data: read_data.to_vec(),
            read_pos: 0,
            written: Vec::new(),
        }
    }

    fn written(&self) -> &[u8] {
        &self.written
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_pos >= this.read_data.len() {
            return Poll::Ready(Ok(()));
        }
        let remaining = this.read_data.len() - this.read_pos;
        let to_copy = std::cmp::min(remaining, buf.remaining());
        buf.put_slice(&this.read_data[this.read_pos..this.read_pos + to_copy]);
        this.read_pos += to_copy;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct StallingReader {
    chunks: Vec<Vec<u8>>,
    index: usize,
    pending_next: bool,
}

impl StallingReader {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks,
            index: 0,
            pending_next: false,
        }
    }
}

impl AsyncRead for StallingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending_next {
            this.pending_next = false;
            return Poll::Pending;
        }
        if this.index >= this.chunks.len() {
            return Poll::Ready(Ok(()));
        }
        let chunk = &this.chunks[this.index];
        let to_copy = std::cmp::min(chunk.len(), buf.remaining());
        buf.put_slice(&chunk[..to_copy]);
        this.index += 1;
        this.pending_next = true;
        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// E2E Scenarios
// ============================================================================

#[test]
fn io_e2e_copy_stream() {
    init_test("io_e2e_copy_stream");
    let mut reader: &[u8] = b"hello io";
    let mut writer = Vec::new();
    let mut fut = copy(&mut reader, &mut writer);
    let mut fut = Pin::new(&mut fut);
    let n = poll_ready(&mut fut, 64)
        .expect("copy future did not resolve")
        .unwrap();
    assert_with_log!(n == 8, "bytes copied", 8, n);
    assert_with_log!(writer == b"hello io", "writer", b"hello io", writer);
    test_complete!("io_e2e_copy_stream");
}

#[test]
fn io_e2e_buffered_read_chain() {
    init_test("io_e2e_buffered_read_chain");
    let first: &[u8] = b"hello ";
    let second: &[u8] = b"world";
    let chained = first.chain(second);
    let mut reader = BufReader::new(chained);
    let mut out = Vec::new();
    let mut fut = reader.read_to_end(&mut out);
    let mut fut = Pin::new(&mut fut);
    let n = poll_ready(&mut fut, 64)
        .expect("read_to_end did not resolve")
        .unwrap();
    assert_with_log!(n == 11, "bytes read", 11, n);
    assert_with_log!(out == b"hello world", "out", b"hello world", out);
    test_complete!("io_e2e_buffered_read_chain");
}

#[test]
fn io_e2e_cancel_read_to_end_partial() {
    init_test("io_e2e_cancel_read_to_end_partial");
    let chunks = vec![b"hello".to_vec(), b" world".to_vec()];
    let mut reader = StallingReader::new(chunks);
    let mut out = Vec::new();
    let mut fut = reader.read_to_end(&mut out);
    let mut fut = Pin::new(&mut fut);
    let poll = poll_once(&mut fut);
    let pending = matches!(poll, Poll::Pending);
    assert_with_log!(pending, "first poll pending", true, pending);
    assert_with_log!(out == b"hello", "partial buffer", b"hello", out);
    // Drop future to simulate cancellation; buffer should retain partial data.
    test_complete!("io_e2e_cancel_read_to_end_partial");
}

#[test]
fn io_e2e_fault_injection_partial_read_then_cancel() {
    init_test("io_e2e_fault_injection_partial_read_then_cancel");
    let chunks = vec![b"partial".to_vec(), b" payload".to_vec()];
    let mut reader = StallingReader::new(chunks);
    let mut out = Vec::new();
    let mut fut = reader.read_to_end(&mut out);
    let mut fut = Pin::new(&mut fut);

    let poll = poll_once(&mut fut);
    let pending = matches!(poll, Poll::Pending);
    assert_with_log!(pending, "first poll pending", true, pending);
    assert_with_log!(out == b"partial", "partial buffer", b"partial", out);

    // Drop to simulate cancellation after partial read and fault stall.
    test_complete!("io_e2e_fault_injection_partial_read_then_cancel");
}

#[test]
fn io_e2e_copy_bidirectional() {
    init_test("io_e2e_copy_bidirectional");
    let mut stream_a = TestStream::new(b"ping");
    let mut stream_b = TestStream::new(b"pong");

    let mut fut = copy_bidirectional(&mut stream_a, &mut stream_b);
    let mut fut = Pin::new(&mut fut);
    let result = poll_ready(&mut fut, 64).expect("copy_bidirectional did not resolve");
    let (a_to_b, b_to_a) = result.unwrap();

    assert_with_log!(a_to_b == 4, "a->b bytes", 4, a_to_b);
    assert_with_log!(b_to_a == 4, "b->a bytes", 4, b_to_a);
    assert_with_log!(
        stream_b.written() == b"ping",
        "b written",
        b"ping",
        stream_b.written()
    );
    assert_with_log!(
        stream_a.written() == b"pong",
        "a written",
        b"pong",
        stream_a.written()
    );
    test_complete!("io_e2e_copy_bidirectional");
}

#[test]
fn io_e2e_split_read_write() {
    init_test("io_e2e_split_read_write");
    let stream = TestStream::new(b"read");
    let wrapper = SplitStream::new(stream);
    let (mut read_half, mut write_half) = wrapper.split();

    let mut buf = [0u8; 8];
    let mut read_buf = ReadBuf::new(&mut buf);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let read_poll = Pin::new(&mut read_half).poll_read(&mut cx, &mut read_buf);
    let read_ok = matches!(read_poll, Poll::Ready(Ok(())));
    assert_with_log!(read_ok, "read half poll", true, read_ok);
    assert_with_log!(
        read_buf.filled() == b"read",
        "read bytes",
        b"read",
        read_buf.filled()
    );

    let write_poll = Pin::new(&mut write_half).poll_write(&mut cx, b"write");
    let write_ok = matches!(write_poll, Poll::Ready(Ok(5)));
    assert_with_log!(write_ok, "write half poll", true, write_ok);

    let _ = read_half;
    let _ = write_half;

    let inner = wrapper.get_ref();
    assert_with_log!(
        inner.written() == b"write",
        "inner written",
        b"write",
        inner.written()
    );
    test_complete!("io_e2e_split_read_write");
}

// ============================================================================
// Deterministic I/O E2E Scenarios (asupersync-ds8.4.1)
// ============================================================================

#[cfg(unix)]
#[test]
fn io_e2e_lab_cancel_inflight_io_op() {
    init_test("io_e2e_lab_cancel_inflight_io_op");
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let task_id = spawn_cancellable_task(&mut runtime, region);

    let io_op = IoOp::submit(
        &mut runtime.state,
        task_id,
        region,
        Some("inflight read".to_string()),
    )
    .expect("submit io op");

    let cancel_reason = CancelReason::parent_cancelled();
    cancel_region(&mut runtime, region, &cancel_reason);
    io_op.cancel(&mut runtime.state).expect("cancel io op");
    runtime.run_until_quiescent();

    let pending = runtime.state.pending_obligation_count();
    let violations = runtime.check_invariants();
    assert!(
        pending == 0,
        "expected no pending obligations after cancel: {pending}"
    );
    assert!(
        violations.is_empty(),
        "expected no invariant violations after cancel: {violations:?}"
    );
    assert!(runtime.state.is_quiescent(), "runtime should be quiescent");
    test_complete!("io_e2e_lab_cancel_inflight_io_op");
}

#[cfg(unix)]
#[test]
fn io_e2e_lab_region_close_waits_for_io_op() {
    init_test("io_e2e_lab_region_close_waits_for_io_op");
    let mut runtime = LabRuntime::new(LabConfig::new(7));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let task_id = spawn_cancellable_task(&mut runtime, region);

    let io_op = IoOp::submit(
        &mut runtime.state,
        task_id,
        region,
        Some("region close io".to_string()),
    )
    .expect("submit io op");

    let cancel_reason = CancelReason::shutdown();
    {
        let region_record = runtime.state.region_mut(region).expect("region");
        region_record.begin_close(Some(cancel_reason.clone()));
        region_record.begin_finalize();
    }

    if let Some(task) = runtime.state.task_mut(task_id) {
        task.complete(Outcome::Cancelled(cancel_reason));
    }

    let can_close_with_pending = runtime.state.can_region_complete_close(region);
    assert!(
        !can_close_with_pending,
        "region close should wait for io obligations"
    );

    io_op.cancel(&mut runtime.state).expect("cancel io op");
    let can_close_after = runtime.state.can_region_complete_close(region);
    assert!(
        can_close_after,
        "region close should complete after io op cancel"
    );

    test_complete!("io_e2e_lab_region_close_waits_for_io_op");
}

#[cfg(unix)]
#[test]
fn io_e2e_lab_replay_determinism_for_io_events() {
    init_test("io_e2e_lab_replay_determinism_for_io_events");
    let trace_a = record_io_replay_trace(123);
    let trace_b = record_io_replay_trace(123);

    assert_with_log!(
        trace_a.metadata.seed == trace_b.metadata.seed,
        "seed match",
        trace_a.metadata.seed,
        trace_b.metadata.seed
    );
    assert_with_log!(
        trace_a.events == trace_b.events,
        "replay events deterministic",
        trace_a.events.len(),
        trace_b.events.len()
    );
    test_complete!("io_e2e_lab_replay_determinism_for_io_events");
}
