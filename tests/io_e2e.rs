//! Async I/O Traits Verification Suite - E2E Tests
//!
//! These tests exercise adapter composition and end-to-end I/O flows using the
//! asupersync async I/O traits and extension methods.

#[macro_use]
mod common;

use asupersync::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, BufReader, ReadBuf, SplitStream, copy, copy_bidirectional,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::IoOp;
use asupersync::runtime::reactor::{Event, Interest};
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
    fn new() -> io::Result<Self> {
        let (stream, peer) = UnixStream::pair()?;
        stream.set_nonblocking(true)?;
        peer.set_nonblocking(true)?;
        Ok(Self {
            stream,
            _peer: peer,
        })
    }
}

#[cfg(unix)]
impl AsRawFd for TestSource {
    fn as_raw_fd(&self) -> i32 {
        self.stream.as_raw_fd()
    }
}

#[cfg(unix)]
fn spawn_cancellable_task(runtime: &mut LabRuntime, region: RegionId) -> Option<TaskId> {
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
        .ok()?;
    {
        let mut scheduler = runtime.scheduler.lock();
        scheduler.schedule(task_id, 0);
    }
    Some(task_id)
}

#[cfg(unix)]
fn cancel_region(runtime: &mut LabRuntime, region: RegionId, reason: &CancelReason) -> bool {
    let tasks = runtime.state.cancel_request(region, reason, None);
    {
        let mut scheduler = runtime.scheduler.lock();
        for (task, priority) in tasks {
            scheduler.schedule_cancel(task, priority);
        }
    }
    true
}

#[cfg(unix)]
fn record_io_replay_trace(seed: u64) -> Option<ReplayTrace> {
    let config = LabConfig::new(seed).with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let task_id = spawn_cancellable_task(&mut runtime, region)?;

    let io_op = IoOp::submit(
        &mut runtime.state,
        task_id,
        region,
        Some("e2e io op".to_string()),
    )
    .ok()?;

    let source = TestSource::new().ok()?;
    let waker = noop_waker();
    let handle = runtime.state.io_driver_handle()?;
    let registration = handle.register(&source, Interest::READABLE, waker).ok()?;

    let registration_id = registration.token();
    runtime.lab_reactor().inject_event(
        registration_id,
        Event::readable(registration_id),
        Duration::from_millis(1),
    );
    runtime.advance_time(1_000_000);
    runtime.step_for_test();

    let cancel_reason = CancelReason::shutdown();
    if !cancel_region(&mut runtime, region, &cancel_reason) {
        return None;
    }
    if io_op.cancel(&mut runtime.state).is_err() {
        return None;
    }
    runtime.run_until_quiescent();

    let pending = runtime.state.pending_obligation_count();
    let violations = runtime.check_invariants();
    assert_with_log!(
        pending == 0,
        "no pending obligations after cancel",
        0usize,
        pending
    );
    assert_with_log!(
        violations.is_empty(),
        "no invariant violations after cancel",
        true,
        violations.is_empty()
    );

    runtime.finish_replay_trace()
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
    let Some(result) = poll_ready(&mut fut, 64) else {
        assert_with_log!(false, "copy future resolved", true, false);
        return;
    };
    let n = match result {
        Ok(n) => n,
        Err(err) => {
            assert_with_log!(false, "copy result ok", "Ok", format!("{err:?}"));
            return;
        }
    };
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
    let Some(result) = poll_ready(&mut fut, 64) else {
        assert_with_log!(false, "read_to_end resolved", true, false);
        return;
    };
    let n = match result {
        Ok(n) => n,
        Err(err) => {
            assert_with_log!(false, "read_to_end ok", "Ok", format!("{err:?}"));
            return;
        }
    };
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
    let Some(result) = poll_ready(&mut fut, 64) else {
        assert_with_log!(false, "copy_bidirectional resolved", true, false);
        return;
    };
    let (a_to_b, b_to_a) = match result {
        Ok(values) => values,
        Err(err) => {
            assert_with_log!(false, "copy_bidirectional ok", "Ok", format!("{err:?}"));
            return;
        }
    };

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
    let Some(task_id) = spawn_cancellable_task(&mut runtime, region) else {
        assert_with_log!(false, "spawn task", "Some", "None");
        return;
    };

    let io_op = IoOp::submit(
        &mut runtime.state,
        task_id,
        region,
        Some("inflight read".to_string()),
    );
    let io_op = match io_op {
        Ok(op) => op,
        Err(err) => {
            assert_with_log!(false, "submit io op", "Ok", format!("{err:?}"));
            return;
        }
    };

    let cancel_reason = CancelReason::parent_cancelled();
    let cancelled = cancel_region(&mut runtime, region, &cancel_reason);
    assert_with_log!(cancelled, "cancel region", true, cancelled);
    let cancel_ok = io_op.cancel(&mut runtime.state).is_ok();
    assert_with_log!(cancel_ok, "cancel io op", true, cancel_ok);
    runtime.run_until_quiescent();

    let pending = runtime.state.pending_obligation_count();
    let violations = runtime.check_invariants();
    assert_with_log!(
        pending == 0,
        "no pending obligations after cancel",
        0usize,
        pending
    );
    assert_with_log!(
        violations.is_empty(),
        "no invariant violations after cancel",
        true,
        violations.is_empty()
    );
    assert_with_log!(
        runtime.state.is_quiescent(),
        "runtime quiescent",
        true,
        runtime.state.is_quiescent()
    );
    test_complete!("io_e2e_lab_cancel_inflight_io_op");
}

#[cfg(unix)]
#[test]
fn io_e2e_lab_region_close_waits_for_io_op() {
    init_test("io_e2e_lab_region_close_waits_for_io_op");
    let mut runtime = LabRuntime::new(LabConfig::new(7));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let Some(task_id) = spawn_cancellable_task(&mut runtime, region) else {
        assert_with_log!(false, "spawn task", "Some", "None");
        return;
    };

    let io_op = IoOp::submit(
        &mut runtime.state,
        task_id,
        region,
        Some("region close io".to_string()),
    );
    let io_op = match io_op {
        Ok(op) => op,
        Err(err) => {
            assert_with_log!(false, "submit io op", "Ok", format!("{err:?}"));
            return;
        }
    };

    let cancel_reason = CancelReason::shutdown();
    let Some(region_record) = runtime.state.region_mut(region) else {
        assert_with_log!(false, "region record", "Some", "None");
        return;
    };
    let close_started = region_record.begin_close(Some(cancel_reason.clone()));
    assert_with_log!(close_started, "begin_close", true, close_started);
    let finalize_started = region_record.begin_finalize();
    assert_with_log!(finalize_started, "begin_finalize", true, finalize_started);

    let task_completed = runtime.state.task_mut(task_id).is_some_and(|task| {
        task.complete(Outcome::Cancelled(cancel_reason.clone()));
        true
    });
    assert_with_log!(task_completed, "task completed", true, task_completed);

    let can_close_with_pending = runtime.state.can_region_complete_close(region);
    assert_with_log!(
        !can_close_with_pending,
        "region close waits for io obligations",
        true,
        !can_close_with_pending
    );

    let cancel_ok = io_op.cancel(&mut runtime.state).is_ok();
    assert_with_log!(cancel_ok, "cancel io op", true, cancel_ok);

    // Now clean up the task from the region, which triggers advance_region_state and allows the region to close.
    runtime.state.task_completed(task_id);

    // `advance_region_state` completes the close and removes the region from the arena.
    let region_state = runtime
        .state
        .region(region)
        .map(asupersync::record::RegionRecord::state);
    let closed = region_state == Some(asupersync::record::region::RegionState::Closed)
        || region_state.is_none();
    assert_with_log!(
        closed,
        "region close completes after io op cancel",
        true,
        closed
    );

    test_complete!("io_e2e_lab_region_close_waits_for_io_op");
}

#[cfg(unix)]
#[test]
fn io_e2e_lab_replay_determinism_for_io_events() {
    init_test("io_e2e_lab_replay_determinism_for_io_events");
    let Some(trace_a) = record_io_replay_trace(123) else {
        assert_with_log!(false, "record trace A", "Some", "None");
        return;
    };
    let Some(trace_b) = record_io_replay_trace(123) else {
        assert_with_log!(false, "record trace B", "Some", "None");
        return;
    };

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
